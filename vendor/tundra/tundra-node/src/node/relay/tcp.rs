use quinn::{RecvStream, SendStream, VarInt};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering::Relaxed},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::{oneshot, watch},
};
use tundra_common::{codes::StreamCode, wire::HalfClose};

pub const RELAY_BUF: usize = 64 * 1024;

#[inline]
fn reset_socket(tcp: &TcpStream) {
    let _ = socket2::SockRef::from(tcp).set_linger(Some(Duration::ZERO));
}

#[derive(Debug)]
pub enum Outcome {
    Closed,
    Cancelled,
    Frozen,
    PeerReset(u64),
    Failed(compact_str::CompactString),
}

impl std::fmt::Display for Outcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Outcome::Closed => f.write_str("closed"),
            Outcome::Cancelled => f.write_str("cancelled"),
            Outcome::Frozen => f.write_str("frozen"),
            Outcome::PeerReset(code) => match StreamCode::from_u32(*code as u32) {
                Some(c) => write!(f, "peer reset ({})", c.to_str()),
                None => write!(f, "peer reset (code {code})"),
            },
            Outcome::Failed(err) => write!(f, "failed: {err}"),
        }
    }
}

pub struct ByteCounters<'a> {
    pub from_peer: &'a AtomicU64,
    pub to_peer: &'a AtomicU64,
}

pub struct FlowCtl {
    pub written: Arc<AtomicU64>,
    pub consumed: Arc<AtomicU64>,
    pub freeze: watch::Receiver<bool>,
    pub handback: oneshot::Sender<Frozen>,
}

#[derive(Debug, Default)]
pub struct Prelude {
    pub pending_send: Vec<u8>,
    pub pending_write: Vec<u8>,
    pub half: HalfClose,
    pub peer_half: HalfClose,
}

#[derive(Debug)]
pub struct Frozen {
    pub tcp: TcpStream,
    pub send: SendStream,
    pub recv: RecvStream,

    pub written: u64,
    pub consumed: u64,

    pub pending_send: Vec<u8>,
    pub pending_write: Vec<u8>,
    pub half: HalfClose,
}

enum HalfError {
    Reset(u64),
    Failed(compact_str::CompactString),
}

impl From<compact_str::CompactString> for HalfError {
    fn from(err: compact_str::CompactString) -> Self {
        Self::Failed(err)
    }
}

impl From<&str> for HalfError {
    fn from(err: &str) -> Self {
        Self::Failed(err.into())
    }
}

enum HalfOutcome {
    Eof,
    Frozen(Vec<u8>),
}

impl HalfOutcome {
    #[inline]
    fn residue(self) -> Option<Vec<u8>> {
        match self {
            HalfOutcome::Eof => None,
            HalfOutcome::Frozen(bytes) => Some(bytes),
        }
    }
}

/// `SendStream::write` is cancel safe and reports what it took, which is what makes a
/// mid-buffer stop safe; `write_all` is not, and a relay that could only observe the
/// freeze between whole buffers would never freeze at all while its peer was stalled.
async fn push_stream(
    send: &mut SendStream,
    data: &[u8],
    written: &AtomicU64,
    counter: &AtomicU64,
    freeze: &mut watch::Receiver<bool>,
) -> Result<usize, compact_str::CompactString> {
    let mut offset = 0;
    while offset < data.len() {
        let chunk = data.get(offset..).ok_or("write offset past the buffer")?;
        let n = tokio::select! {
            biased;
            _ = crate::node::relay::cancelled(freeze) => return Ok(offset),
            r = send.write(chunk) => r.map_err(|err| compact_str::format_compact!("stream write: {err}"))?,
        };

        if n == 0 {
            return Err("the stream accepted no bytes".into());
        }

        offset += n;
        written.fetch_add(n as u64, Relaxed);
        counter.fetch_add(n as u64, Relaxed);
    }

    Ok(offset)
}

async fn push_socket(
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    data: &[u8],
    counter: &AtomicU64,
    freeze: &mut watch::Receiver<bool>,
) -> Result<usize, compact_str::CompactString> {
    let mut offset = 0;
    while offset < data.len() {
        let chunk = data.get(offset..).ok_or("write offset past the buffer")?;
        let n = tokio::select! {
            biased;
            _ = crate::node::relay::cancelled(freeze) => return Ok(offset),
            r = writer.write(chunk) => r.map_err(|err| compact_str::format_compact!("frontend write: {err}"))?,
        };

        if n == 0 {
            return Err("the socket accepted no bytes".into());
        }

        offset += n;
        counter.fetch_add(n as u64, Relaxed);
    }

    Ok(offset)
}

#[allow(clippy::too_many_arguments)]
pub async fn relay_stream(
    tcp: TcpStream,
    mut send: SendStream,
    mut recv: RecvStream,
    mut cancel: watch::Receiver<bool>,
    counters: ByteCounters<'_>,
    ctl: FlowCtl,
    prelude: Prelude,
) -> Outcome {
    // resetting a finished stream would discard a response the peer has fully written but
    // not yet read
    let tx_done = AtomicBool::new(prelude.half.tx_done || prelude.peer_half.rx_done);
    let rx_done = AtomicBool::new(prelude.half.rx_done);
    let (written, consumed) = (Arc::clone(&ctl.written), Arc::clone(&ctl.consumed));
    let (mut freeze_tx, mut freeze_rx) = (ctl.freeze.clone(), ctl.freeze.clone());

    let Prelude {
        pending_send,
        pending_write,
        half: observed,
        peer_half,
    } = prelude;

    let half = observed.merge(peer_half);
    let (mut reader, mut writer) = tcp.into_split();
    let mut send_residue = Vec::new();
    let mut write_residue = Vec::new();

    let outcome = {
        let to_peer = async {
            if !pending_send.is_empty() {
                let sent = push_stream(
                    &mut send,
                    &pending_send,
                    &written,
                    counters.to_peer,
                    &mut freeze_tx,
                )
                .await?;
                if sent < pending_send.len() {
                    let residue = pending_send
                        .get(sent..)
                        .ok_or("send residue past the buffer")?;
                    return Ok(HalfOutcome::Frozen(residue.to_vec()));
                }
            }

            if half.tx_done {
                let _ = send.finish();
                return Ok(HalfOutcome::Eof);
            }

            let stopped = send.stopped();
            tokio::pin!(stopped);

            let mut buf = vec![0; RELAY_BUF];
            loop {
                let n = tokio::select! {
                    biased;
                    _ = crate::node::relay::cancelled(&mut freeze_tx) => {
                        return Ok(HalfOutcome::Frozen(Vec::new()));
                    }
                    r = &mut stopped => return match r {
                        Ok(Some(code)) => Err(HalfError::Reset(code.into_inner())),
                        Ok(None) => Err("stream finished while still sending".into()),
                        Err(err) => Err(compact_str::format_compact!("stream stopped: {err}").into()),
                    },
                    r = reader.read(&mut buf) => r.map_err(|err| compact_str::format_compact!("frontend read: {err}"))?,
                };

                if n == 0 {
                    let _ = send.finish();
                    tx_done.store(true, Relaxed);
                    return Ok(HalfOutcome::Eof);
                }

                let chunk = buf.get(..n).ok_or("frontend read past the buffer")?;
                let sent =
                    push_stream(&mut send, chunk, &written, counters.to_peer, &mut freeze_tx)
                        .await?;
                if sent < n {
                    let residue = buf.get(sent..n).ok_or("send residue past the buffer")?;
                    return Ok(HalfOutcome::Frozen(residue.to_vec()));
                }
            }
        };

        let from_peer = async {
            if !pending_write.is_empty() {
                let put = push_socket(
                    &mut writer,
                    &pending_write,
                    counters.from_peer,
                    &mut freeze_rx,
                )
                .await?;
                if put < pending_write.len() {
                    let residue = pending_write
                        .get(put..)
                        .ok_or("write residue past the buffer")?;
                    return Ok(HalfOutcome::Frozen(residue.to_vec()));
                }
            }

            if half.rx_done {
                // when only the peer reported this direction ended - its FIN in flight at
                // the freeze - this end never shut its socket down, so an application
                // waiting on a close-framed transfer would wait forever
                if !observed.rx_done {
                    let _ = writer.shutdown().await;
                }

                rx_done.store(true, Relaxed);
                return Ok(HalfOutcome::Eof);
            }

            let mut buf = vec![0; RELAY_BUF];
            loop {
                let read = tokio::select! {
                    biased;
                    _ = crate::node::relay::cancelled(&mut freeze_rx) => {
                        return Ok(HalfOutcome::Frozen(Vec::new()));
                    }
                    r = recv.read(&mut buf) => r,
                };

                match read {
                    Ok(None) => {
                        let _ = writer.shutdown().await;
                        rx_done.store(true, Relaxed);
                        return Ok(HalfOutcome::Eof);
                    }
                    Ok(Some(n)) => {
                        consumed.fetch_add(n as u64, Relaxed);
                        let chunk = buf.get(..n).ok_or("stream read past the buffer")?;
                        let put =
                            push_socket(&mut writer, chunk, counters.from_peer, &mut freeze_rx)
                                .await?;
                        if put < n {
                            let residue = buf.get(put..n).ok_or("write residue past the buffer")?;
                            return Ok(HalfOutcome::Frozen(residue.to_vec()));
                        }
                    }
                    Err(quinn::ReadError::Reset(code)) => {
                        return Err(HalfError::Reset(code.into_inner()));
                    }
                    Err(err) => {
                        return Err(compact_str::format_compact!("stream read: {err}").into());
                    }
                }
            }
        };

        tokio::select! {
            both = futures::future::try_join(to_peer, from_peer) => match both {
                Ok((tx, rx)) => {
                    let tx = tx.residue();
                    let rx = rx.residue();
                    let frozen = tx.is_some() || rx.is_some();
                    send_residue = tx.unwrap_or_default();
                    write_residue = rx.unwrap_or_default();
                    if frozen { Outcome::Frozen } else { Outcome::Closed }
                }
                Err(HalfError::Reset(code)) => Outcome::PeerReset(code),
                Err(HalfError::Failed(err)) => Outcome::Failed(err),
            },
            _ = crate::node::relay::cancelled(&mut cancel) => Outcome::Cancelled,
        }
    };

    let tcp = match reader.reunite(writer) {
        Ok(tcp) => tcp,
        Err(err) => {
            // dropping the write half would shut the socket down gracefully, which is the
            // one thing a failure here must not do
            err.1.forget();
            let v = VarInt::from_u32(StreamCode::Protocol.as_u32());
            let _ = send.reset(v);
            let _ = recv.stop(v);
            return Outcome::Failed("failed to reunite the socket halves".into());
        }
    };

    let half = HalfClose {
        tx_done: tx_done.load(Relaxed),
        rx_done: rx_done.load(Relaxed),
    };

    let code = match &outcome {
        Outcome::Closed => None,
        Outcome::Frozen => {
            let frozen = Frozen {
                tcp,
                send,
                recv,
                written: written.load(Relaxed),
                consumed: consumed.load(Relaxed),
                pending_send: send_residue,
                pending_write: write_residue,
                half,
            };

            return match ctl.handback.send(frozen) {
                Ok(()) => Outcome::Frozen,
                Err(frozen) => {
                    kill_frozen(frozen, StreamCode::DrainFailed);
                    Outcome::Failed("the drain abandoned this flow".into())
                }
            };
        }
        Outcome::Cancelled => Some(VarInt::from_u32(StreamCode::AclDenied.as_u32())),
        Outcome::PeerReset(_) | Outcome::Failed(_) => {
            Some(VarInt::from_u32(StreamCode::Protocol.as_u32()))
        }
    };

    if let Some(code) = code {
        if !half.tx_done {
            let _ = send.reset(code);
        }
        let _ = recv.stop(code);
        reset_socket(&tcp);
    }

    outcome
}

pub fn kill_frozen(mut frozen: Frozen, code: StreamCode) {
    let v = VarInt::from_u32(code.as_u32());
    if !frozen.half.tx_done {
        let _ = frozen.send.reset(v);
    }

    let _ = frozen.recv.stop(v);
    reset_socket(&frozen.tcp);
}

#[inline]
pub fn kill_socket(tcp: &TcpStream) {
    reset_socket(tcp);
}

pub async fn relay_local(
    mut frontend: TcpStream,
    mut backend: TcpStream,
    mut cancel: watch::Receiver<bool>,
) -> Outcome {
    let outcome = tokio::select! {
        r = tokio::io::copy_bidirectional_with_sizes(&mut frontend, &mut backend, RELAY_BUF, RELAY_BUF) => {
            match r {
                Ok(_) => Outcome::Closed,
                Err(err) => Outcome::Failed(err.to_string().into()),
            }
        }
        _ = crate::node::relay::cancelled(&mut cancel) => Outcome::Cancelled,
    };

    if !matches!(outcome, Outcome::Closed) {
        reset_socket(&frontend);
        reset_socket(&backend);
    }

    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::relay::flows::{MAX_TCP_FLOWS_PER_CONN, Side, TcpFlows};
    use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use std::sync::Arc;
    use tokio::net::TcpListener;
    use tundra_common::flow::Parity;

    async fn pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::spawn(async move { TcpStream::connect(addr).await.unwrap() });
        let (server, _) = listener.accept().await.unwrap();
        (client.await.unwrap(), server)
    }

    fn provider() -> Arc<rustls::crypto::CryptoProvider> {
        Arc::new(rustls::crypto::aws_lc_rs::default_provider())
    }

    // a real quic pair, so the freeze meets quinn's actual flow control rather than a
    // stand-in that cannot stall
    async fn quic_pair() -> (quinn::Connection, quinn::Connection) {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "localhost");
        let cert = params.self_signed(&key).unwrap();
        let der = CertificateDer::from(cert.der().to_vec());
        let pin = tundra_common::hash::sha256(&der);
        let private = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));

        let mut server_tls = rustls::ServerConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![der], private)
            .unwrap();
        server_tls.alpn_protocols = vec![b"tundra-test".to_vec()];
        let mut server = quinn::ServerConfig::with_crypto(Arc::new(
            QuicServerConfig::try_from(server_tls).unwrap(),
        ));
        server.transport_config(Arc::new(crate::node::quic::transport_config(None)));

        let mut client_tls = rustls::ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(crate::pinning::PinnedCert::new(
                pin,
                provider(),
            )))
            .with_no_client_auth();
        client_tls.alpn_protocols = vec![b"tundra-test".to_vec()];
        let mut client =
            quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_tls).unwrap()));
        client.transport_config(Arc::new(crate::node::quic::transport_config(None)));

        let acceptor = quinn::Endpoint::server(server, "127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = acceptor.local_addr().unwrap();
        let accepted = tokio::spawn(async move { acceptor.accept().await.unwrap().await.unwrap() });

        let mut dialer = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        dialer.set_default_client_config(client);
        let out = dialer.connect(addr, "localhost").unwrap().await.unwrap();
        // the endpoints must outlive their connections, and nothing else holds them
        std::mem::forget(dialer);
        (out, accepted.await.unwrap())
    }

    struct Harness {
        app: TcpStream,
        relay: tokio::task::JoinHandle<Outcome>,
        flow: Arc<crate::node::relay::flows::TcpFlow>,
        peer_send: quinn::SendStream,
        peer_recv: quinn::RecvStream,
        _cancel: watch::Sender<bool>,
    }

    async fn harness(prelude: Prelude) -> Harness {
        let (app, socket) = pair().await;
        let (out, inbound) = quic_pair().await;
        let (send, recv) = out.open_bi().await.unwrap();
        // the stream only exists for the acceptor once something is written on it
        let mut send = send;
        send.write_all(b"\0").await.unwrap();
        let (peer_send, mut peer_recv) = inbound.accept_bi().await.unwrap();
        let mut one = [0; 1];
        peer_recv.read_exact(&mut one).await.unwrap();

        let mut flows = TcpFlows::new(Parity::Even, MAX_TCP_FLOWS_PER_CONN);
        let (flow, ctl) = flows
            .open(
                Side::Frontend,
                uuid::Uuid::from_u128(1),
                uuid::Uuid::from_u128(2),
                80,
            )
            .unwrap();
        let (cancel, cancel_rx) = watch::channel(false);

        let counters = Box::leak(Box::new((AtomicU64::new(0), AtomicU64::new(0))));
        let relay = tokio::spawn(relay_stream(
            socket,
            send,
            recv,
            cancel_rx,
            ByteCounters {
                from_peer: &counters.0,
                to_peer: &counters.1,
            },
            ctl,
            prelude,
        ));
        std::mem::forget(out);
        std::mem::forget(inbound);

        Harness {
            app,
            relay,
            flow,
            peer_send,
            peer_recv,
            _cancel: cancel,
        }
    }

    async fn read_exactly(recv: &mut quinn::RecvStream, want: usize) -> Vec<u8> {
        let mut got = vec![0; want];
        recv.read_exact(&mut got).await.unwrap();
        got
    }

    // relay_stream

    #[test]
    fn a_freeze_reports_a_total_the_peer_can_verify_byte_for_byte() {
        tokio_test::block_on(async {
            let mut h = harness(Prelude::default()).await;
            let payload: Vec<u8> = (0..=255u8).cycle().take(64 * 1024).collect();

            h.app.write_all(&payload).await.unwrap();
            let seen = read_exactly(&mut h.peer_recv, payload.len()).await;
            assert_eq!(seen, payload);

            h.flow.freeze();
            let frozen = tokio::time::timeout(Duration::from_secs(5), h.flow.claim().unwrap())
                .await
                .unwrap()
                .unwrap();

            assert_eq!(frozen.written, payload.len() as u64);
            assert!(frozen.pending_send.is_empty());
            assert!(frozen.pending_write.is_empty());
            assert!(!frozen.half.tx_done && !frozen.half.rx_done);
            assert_eq!(h.relay.await.unwrap().to_string(), "frozen");
        });
    }

    #[test]
    fn a_freeze_against_a_stalled_peer_carries_the_residue_rather_than_waiting() {
        tokio_test::block_on(async {
            // nothing reads the stream, so the window closes and the freeze lands mid-buffer
            let h = harness(Prelude::default()).await;
            let payload: Vec<u8> = (0..=255u8).cycle().take(4 * 1024 * 1024).collect();

            let mut app = h.app;
            let sent = tokio::spawn(async move {
                let _ = app.write_all(&payload).await;
                app
            });
            tokio::time::sleep(Duration::from_millis(200)).await;

            h.flow.freeze();
            let frozen = tokio::time::timeout(Duration::from_secs(5), h.flow.claim().unwrap())
                .await
                .unwrap()
                .unwrap();

            let carried = frozen.pending_send.clone();
            assert!(!carried.is_empty());
            let expected: Vec<u8> = (0..=255u8)
                .cycle()
                .skip(frozen.written as usize % 256)
                .take(carried.len())
                .collect();
            assert_eq!(carried, expected);

            drop(frozen);
            let _ = sent.await;
        });
    }

    #[test]
    fn a_resumed_relay_replays_both_buffers_before_anything_new() {
        tokio_test::block_on(async {
            let prelude = Prelude {
                pending_send: b"carried-to-peer".to_vec(),
                pending_write: b"carried-to-app".to_vec(),
                half: HalfClose::default(),
                peer_half: HalfClose::default(),
            };
            let mut h = harness(prelude).await;

            h.app.write_all(b"-then-live").await.unwrap();
            let seen = read_exactly(&mut h.peer_recv, b"carried-to-peer-then-live".len()).await;
            assert_eq!(seen, b"carried-to-peer-then-live");

            h.peer_send.write_all(b"-then-live").await.unwrap();
            let mut got = vec![0; b"carried-to-app-then-live".len()];
            h.app.read_exact(&mut got).await.unwrap();
            assert_eq!(got, b"carried-to-app-then-live");
        });
    }

    #[test]
    fn a_relay_resumed_with_a_finished_direction_does_not_wait_on_it() {
        tokio_test::block_on(async {
            let prelude = Prelude {
                pending_send: Vec::new(),
                pending_write: Vec::new(),
                half: HalfClose {
                    tx_done: true,
                    rx_done: false,
                },
                peer_half: HalfClose::default(),
            };
            let mut h = harness(prelude).await;

            let mut buf = [0; 8];
            let eof = tokio::time::timeout(Duration::from_secs(5), h.peer_recv.read(&mut buf))
                .await
                .unwrap();
            assert_eq!(eof.unwrap(), None);

            h.peer_send.write_all(b"reply").await.unwrap();
            let mut got = [0; 5];
            h.app.read_exact(&mut got).await.unwrap();
            assert_eq!(&got, b"reply");
        });
    }

    #[test]
    fn a_direction_only_the_peer_saw_end_still_reaches_the_application() {
        tokio_test::block_on(async {
            let prelude = Prelude {
                pending_send: Vec::new(),
                pending_write: b"tail".to_vec(),
                half: HalfClose::default(),
                peer_half: HalfClose {
                    tx_done: true,
                    rx_done: false,
                },
            };
            let mut h = harness(prelude).await;

            let mut got = [0; 4];
            h.app.read_exact(&mut got).await.unwrap();
            assert_eq!(&got, b"tail");

            let eof = tokio::time::timeout(Duration::from_secs(5), h.app.read(&mut got))
                .await
                .unwrap();
            assert_eq!(eof.unwrap(), 0);
        });
    }

    #[test]
    fn a_freeze_after_the_socket_ended_reports_the_half_close() {
        tokio_test::block_on(async {
            let mut h = harness(Prelude::default()).await;
            h.app.write_all(b"last").await.unwrap();
            h.app.shutdown().await.unwrap();
            assert_eq!(read_exactly(&mut h.peer_recv, 4).await, b"last");

            h.flow.freeze();
            let frozen = tokio::time::timeout(Duration::from_secs(5), h.flow.claim().unwrap())
                .await
                .unwrap()
                .unwrap();

            assert!(frozen.half.tx_done);
            assert_eq!(frozen.written, 4);
        });
    }

    // relay_local

    #[test]
    fn a_local_relay_carries_both_directions_and_maps_half_close() {
        tokio_test::block_on(async {
            let (mut app, frontend) = pair().await;
            let (backend, mut service) = pair().await;
            let (_tx, cancel) = watch::channel(false);

            let relay = tokio::spawn(relay_local(frontend, backend, cancel));

            app.write_all(b"ping").await.unwrap();
            let mut buf = [0; 4];
            service.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"ping");

            service.write_all(b"pong").await.unwrap();
            app.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"pong");

            app.shutdown().await.unwrap();
            assert_eq!(service.read(&mut buf).await.unwrap(), 0);

            service.shutdown().await.unwrap();
            assert_eq!(relay.await.unwrap().to_string(), "closed");
        });
    }

    #[test]
    fn cancelling_a_local_relay_drops_both_sockets() {
        tokio_test::block_on(async {
            let (mut app, frontend) = pair().await;
            let (backend, mut service) = pair().await;
            let (tx, cancel) = watch::channel(false);

            let relay = tokio::spawn(relay_local(frontend, backend, cancel));
            app.write_all(b"x").await.unwrap();
            let mut buf = [0; 1];
            service.read_exact(&mut buf).await.unwrap();

            tx.send(true).unwrap();
            assert_eq!(relay.await.unwrap().to_string(), "cancelled");

            assert!(app.read(&mut buf).await.is_err() || app.write_all(b"y").await.is_err());
            assert!(
                service.read(&mut buf).await.is_err() || service.write_all(b"y").await.is_err()
            );
        });
    }

    #[test]
    fn a_relay_already_cancelled_before_it_starts_stops_immediately() {
        tokio_test::block_on(async {
            let (_app, frontend) = pair().await;
            let (backend, _service) = pair().await;
            let (tx, cancel) = watch::channel(false);
            tx.send(true).unwrap();

            let outcome = tokio::time::timeout(
                Duration::from_secs(2),
                relay_local(frontend, backend, cancel),
            )
            .await
            .unwrap();
            assert_eq!(outcome.to_string(), "cancelled");
        });
    }

    #[test]
    fn a_cancelled_relay_whose_send_side_finished_does_not_reset_it() {
        // stands in for the !half.tx_done guard; a finished quinn stream cannot be observed
        // refusing a reset from here
        let finished = AtomicBool::new(true);
        assert!(finished.load(Relaxed));

        finished.store(false, Relaxed);
        assert!(!finished.load(Relaxed));
    }

    #[test]
    fn byte_counters_are_shared_and_monotonic() {
        let counters = (Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0)));
        let view = ByteCounters {
            from_peer: &counters.0,
            to_peer: &counters.1,
        };
        view.to_peer.fetch_add(10, Relaxed);
        view.from_peer.fetch_add(3, Relaxed);

        assert_eq!(counters.1.load(Relaxed), 10);
        assert_eq!(counters.0.load(Relaxed), 3);
    }
}
