use crate::{
    metrics::PeerMetrics,
    node::{
        quic::registry::Role,
        relay::{
            flows::{MAX_TCP_FLOWS_PER_CONN, TcpFlows},
            udp::{PendingFlows, UdpTables},
        },
    },
};
use anyhow::Context;
use quinn::{Connection, RecvStream, SendStream};
use rustls::pki_types::CertificateDer;
use serde::{Serialize, de::DeserializeOwned};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering::Relaxed},
    },
    time::{Duration, Instant},
};
use tokio::sync::{Semaphore, mpsc};
use tundra_common::{
    flow::{
        FLOW_IDLE_TIMEOUT, FlowTable, MAX_EGRESS_FLOWS_PER_CONN, MAX_INGRESS_FLOWS_PER_CONN,
        Parity, UnknownFlowLimiter,
    },
    hash::{Hash32, sha256},
    wire::{ControlMsg, FlowTotal, decode_frame, encode_frame, frame_len},
};

pub const CONTROL_QUEUE: usize = 256;
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
pub const REAUTH_INTERVAL: Duration = Duration::from_secs(600);
pub const REAUTH_DEADLINE: Duration = Duration::from_secs(900);
pub const REAUTH_CHECK: Duration = Duration::from_secs(30);
pub const REAUTH_RETRY: Duration = Duration::from_secs(30);
pub const REAUTH_RECOVERY_GRACE: Duration = Duration::from_secs(120);

pub const DRAIN_MAILBOX: usize = 64;

#[derive(Debug)]
pub enum DrainMsg {
    Start { flows: Vec<FlowTotal>, last: bool },
    Ready { flows: Vec<FlowTotal>, last: bool },
    Complete,
}

#[inline]
pub fn parity_for(role: Role) -> Parity {
    match role {
        Role::Initiator => Parity::Even,
        Role::Acceptor => Parity::Odd,
    }
}

struct AuthState {
    last: parking_lot::Mutex<Instant>,
    ack_pending: AtomicBool,
}

impl AuthState {
    fn new() -> Self {
        Self {
            last: parking_lot::Mutex::new(Instant::now()),
            ack_pending: AtomicBool::new(false),
        }
    }

    #[inline]
    fn touch(&self) {
        *self.last.lock() = Instant::now();
    }

    #[inline]
    fn last(&self) -> Instant {
        *self.last.lock()
    }

    #[inline]
    fn expect_ack(&self) {
        self.ack_pending.store(true, Relaxed);
    }

    /// Only an ack answering a `ReAuth` this side sent counts; anything else is a peer
    /// refreshing a deadline it never re-authenticated for.
    fn ack(&self) -> bool {
        if !self.ack_pending.swap(false, Relaxed) {
            return false;
        }

        self.touch();
        true
    }
}

pub struct PeerConn {
    pub peer: uuid::Uuid,
    pub role: Role,
    pub parity: Parity,
    pub peer_instance: u64,
    pub conn: Connection,
    pub metrics: Arc<PeerMetrics>,

    pub udp: parking_lot::Mutex<UdpTables>,
    pub tcp: Arc<parking_lot::Mutex<TcpFlows>>,
    pub stream_slots: Arc<Semaphore>,
    pub claimed: parking_lot::Mutex<Vec<u64>>,

    control: mpsc::Sender<ControlMsg>,
    auth: AuthState,

    drain_tx: mpsc::Sender<DrainMsg>,
    drain_rx: tokio::sync::Mutex<mpsc::Receiver<DrainMsg>>,
    draining: AtomicBool,
}

impl PeerConn {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        peer: uuid::Uuid,
        role: Role,
        parity: Parity,
        peer_instance: u64,
        conn: Connection,
        metrics: Arc<PeerMetrics>,
        control: mpsc::Sender<ControlMsg>,
        stream_slots: usize,
    ) -> Self {
        let (drain_tx, drain_rx) = mpsc::channel(DRAIN_MAILBOX);

        Self {
            peer,
            role,
            parity,
            peer_instance,
            conn,
            metrics,
            udp: parking_lot::Mutex::new(UdpTables {
                egress: FlowTable::new(parity, FLOW_IDLE_TIMEOUT, MAX_EGRESS_FLOWS_PER_CONN),
                ingress: FlowTable::new(parity, FLOW_IDLE_TIMEOUT, MAX_INGRESS_FLOWS_PER_CONN),
                unknown: UnknownFlowLimiter::default(),
                pending: PendingFlows::default(),
            }),
            tcp: Arc::new(parking_lot::Mutex::new(TcpFlows::new(
                parity,
                MAX_TCP_FLOWS_PER_CONN,
            ))),
            stream_slots: Arc::new(Semaphore::new(stream_slots)),
            claimed: parking_lot::Mutex::new(Vec::new()),
            control,
            auth: AuthState::new(),
            drain_tx,
            drain_rx: tokio::sync::Mutex::new(drain_rx),
            draining: AtomicBool::new(false),
        }
    }

    // never blocks: a lost message times the handover out and kills the affected flows,
    // which is the intended failure direction
    #[inline]
    pub fn post_drain(&self, msg: DrainMsg) {
        if self.drain_tx.try_send(msg).is_err() {
            self.metrics.drain_messages_lost.fetch_add(1, Relaxed);
            tracing::warn!(
                peer = %self.peer,
                "drain mailbox full, the handover will not complete"
            );
        }
    }

    pub async fn drain_mailbox(&self) -> tokio::sync::MutexGuard<'_, mpsc::Receiver<DrainMsg>> {
        self.drain_rx.lock().await
    }

    #[inline]
    pub fn begin_drain(&self) -> bool {
        !self.draining.swap(true, Relaxed)
    }

    #[inline]
    pub fn is_draining(&self) -> bool {
        self.draining.load(Relaxed)
    }

    #[inline]
    pub fn try_control(&self, msg: ControlMsg) -> bool {
        match self.control.try_send(msg) {
            Ok(()) => true,
            Err(err) => {
                tracing::debug!(
                    peer = %self.peer,
                    "failed to queue a control message: {}",
                    err
                );
                false
            }
        }
    }

    #[inline]
    pub async fn send_control(&self, msg: ControlMsg) -> bool {
        self.control.send(msg).await.is_ok()
    }

    #[inline]
    pub fn touch_auth(&self) {
        self.auth.touch();
    }

    #[inline]
    pub fn last_auth(&self) -> Instant {
        self.auth.last()
    }

    #[inline]
    pub fn expect_reauth_ack(&self) {
        self.auth.expect_ack();
    }

    #[inline]
    pub fn ack_reauth(&self) -> bool {
        self.auth.ack()
    }

    #[inline]
    pub fn close(&self, code: tundra_common::codes::CloseCode) {
        self.conn.close(code.as_u32().into(), code.reason());
    }

    pub fn refresh_flow_metrics(&self) {
        {
            let tcp = self.tcp.lock();
            self.metrics.tcp_flows_open.store(tcp.len() as u64, Relaxed);
            self.metrics
                .tcp_flows_rejected_total
                .store(tcp.rejected_total(), Relaxed);
        }

        let udp = self.udp.lock();
        let metrics = &self.metrics;
        metrics
            .flows_open
            .store((udp.egress.len() + udp.ingress.len()) as u64, Relaxed);
        metrics.flows_opened_total.store(
            udp.egress.opened_total() + udp.ingress.opened_total(),
            Relaxed,
        );
        metrics
            .flows_gc_total
            .store(udp.egress.gc_total() + udp.ingress.gc_total(), Relaxed);
        metrics.flows_rejected_total.store(
            udp.egress.rejected_total() + udp.ingress.rejected_total(),
            Relaxed,
        );
    }
}

pub async fn control_writer(
    mut send: SendStream,
    mut rx: mpsc::Receiver<ControlMsg>,
    peer: uuid::Uuid,
) {
    while let Some(msg) = rx.recv().await {
        match encode_frame(&msg) {
            Ok(bytes) => {
                if let Err(err) = send.write_all(&bytes).await {
                    tracing::warn!(
                        peer = %peer,
                        "failed to write to the control stream: {}",
                        err
                    );
                    return;
                }
            }
            Err(err) => tracing::error!(
                peer = %peer,
                "failed to encode a control message: {:?}",
                err
            ),
        }
    }

    let _ = send.finish();
}

pub async fn write_frame<T: Serialize>(
    send: &mut SendStream,
    msg: &T,
) -> Result<(), anyhow::Error> {
    send.write_all(&encode_frame(msg)?)
        .await
        .context("failed to write a control frame")
}

pub async fn read_frame<T: DeserializeOwned>(recv: &mut RecvStream) -> Result<T, anyhow::Error> {
    Ok(decode_frame(&read_frame_body(recv).await?)?)
}

// undecoded so a Hello from another protocol version is recognised as such rather than
// reported as a decode failure the operator cannot act on
pub async fn read_frame_body(recv: &mut RecvStream) -> Result<Vec<u8>, anyhow::Error> {
    let mut prefix = [0; 4];
    recv.read_exact(&mut prefix)
        .await
        .context("failed to read a frame length")?;

    let len = frame_len(prefix)?;
    let mut body = vec![0; len];
    recv.read_exact(&mut body)
        .await
        .context("failed to read a frame body")?;

    Ok(body)
}

// the leaf actually presented is the only identity input: it keys the pin list and must
// match the token's cnf claim
pub fn peer_cert_hash(conn: &Connection) -> Option<Hash32> {
    let identity = conn.peer_identity()?;
    let chain = identity.downcast::<Vec<CertificateDer<'static>>>().ok()?;
    chain.first().map(|leaf| sha256(leaf))
}

pub fn negotiated_alpn(conn: &Connection) -> Option<Vec<u8>> {
    let data = conn.handshake_data()?;
    let data = data
        .downcast::<quinn::crypto::rustls::HandshakeData>()
        .ok()?;
    data.protocol
}

#[cfg(test)]
mod tests {
    use super::*;
    use tundra_common::wire::{FlowOpen, StreamHeader};

    // encode_frame + decode_frame

    #[test]
    fn frames_encode_with_a_length_prefix_the_reader_can_trust() {
        let msg = ControlMsg::FlowOpen(FlowOpen {
            flow_id: 9,
            src_server: uuid::Uuid::from_u128(1),
            dst_server: uuid::Uuid::from_u128(2),
            dst_port: 25565,
        });
        let bytes = encode_frame(&msg).unwrap();
        let len = frame_len(bytes[..4].try_into().unwrap()).unwrap();

        assert_eq!(len, bytes.len() - 4);
        assert_eq!(decode_frame::<ControlMsg>(&bytes[4..]).unwrap(), msg);
    }

    #[test]
    fn a_stream_header_carries_the_flow_id_the_drain_will_reconcile() {
        let header = StreamHeader::Open(FlowOpen {
            flow_id: 12,
            src_server: uuid::Uuid::from_u128(1),
            dst_server: uuid::Uuid::from_u128(2),
            dst_port: 80,
        });
        let bytes = encode_frame(&header).unwrap();
        assert_eq!(decode_frame::<StreamHeader>(&bytes[4..]).unwrap(), header);

        let resume = StreamHeader::Resume {
            flow_id: 12,
            half: tundra_common::wire::HalfClose::default(),
        };
        let bytes = encode_frame(&resume).unwrap();
        assert_eq!(decode_frame::<StreamHeader>(&bytes[4..]).unwrap(), resume);
        assert_ne!(resume, header);
    }

    // AuthState

    #[test]
    fn an_unsolicited_reauth_ack_leaves_the_auth_time_alone() {
        let auth = AuthState::new();
        let initial = auth.last();

        assert!(!auth.ack());
        assert_eq!(auth.last(), initial);
    }

    #[test]
    fn a_reauth_ack_refreshes_the_auth_time_once_per_reauth_sent() {
        let auth = AuthState::new();

        auth.expect_ack();
        let before = Instant::now();
        assert!(auth.ack());
        assert!(auth.last() >= before);

        assert!(!auth.ack());
    }

    // PeerConn

    #[test]
    fn a_full_control_queue_drops_instead_of_blocking() {
        tokio_test::block_on(async {
            let (tx, mut rx) = mpsc::channel(2);

            assert!(tx.try_send(ControlMsg::ReAuthAck).is_ok());
            assert!(tx.try_send(ControlMsg::ReAuthAck).is_ok());
            assert!(tx.try_send(ControlMsg::ReAuthAck).is_err());

            rx.recv().await.unwrap();
            assert!(tx.try_send(ControlMsg::ReAuthAck).is_ok());
        });
    }

    // parity_for

    #[test]
    fn flow_id_parity_follows_the_connection_role_unless_it_is_inherited() {
        assert!(Parity::Even.matches(0));
        assert!(!Parity::Even.matches(1));
        assert!(Parity::Odd.matches(1));

        assert_eq!(parity_for(Role::Initiator), Parity::Even);
        assert_eq!(parity_for(Role::Acceptor), Parity::Odd);
        assert_ne!(
            parity_for(Role::Initiator).matches(2),
            parity_for(Role::Acceptor).matches(2)
        );
    }

    // REAUTH_DEADLINE

    #[test]
    fn the_reauth_schedule_leaves_room_to_retry_before_the_deadline() {
        assert!(REAUTH_INTERVAL < REAUTH_DEADLINE);
        assert!(REAUTH_DEADLINE - REAUTH_INTERVAL > REAUTH_RETRY * 2);
        assert!(REAUTH_CHECK < REAUTH_DEADLINE);
        assert!(REAUTH_RECOVERY_GRACE + REAUTH_RETRY < REAUTH_DEADLINE);
    }
}
