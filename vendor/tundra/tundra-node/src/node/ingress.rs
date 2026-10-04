use crate::node::{
    Node,
    quic::conn::{DrainMsg, PeerConn, read_frame},
    relay::{
        flows::{Side, TcpFlowGuard},
        tcp::{ByteCounters, Outcome, Prelude, relay_stream},
        udp::{
            Hold, IngressFlow, LOCAL_SEND_QUEUE, UDP_RECV_BUF, UdpTables, container_writer,
            next_group, send_payload,
        },
    },
    restart::MAX_CARRIED_FLOWS,
};
use quinn::VarInt;
use std::{
    net::{IpAddr, SocketAddr},
    sync::{Arc, atomic::Ordering::Relaxed},
    time::{Duration, Instant},
};
use tokio::net::{TcpStream, UdpSocket};
use tundra_common::{
    admit::{Transport, admit},
    codes::{CloseCode, StreamCode},
    datagram::parse,
    flow::Parity,
    frag::FragReassembler,
    wire::{ControlMsg, FlowOpen, StreamHeader},
};

pub const DIAL_TIMEOUT: Duration = Duration::from_secs(5);

enum Ingress {
    Deliver(tokio::sync::mpsc::Sender<Vec<u8>>, Vec<u8>),
    Pending,
    Unknown,
}

#[inline]
pub fn dial_target(node: &Node, server: &uuid::Uuid, port: u16) -> Option<SocketAddr> {
    let index = node.index();
    let entry = index.server(server)?;

    if let Some(dial) = &entry.dial_addr {
        if let Ok(addr) = dial.parse::<SocketAddr>() {
            return Some(addr);
        }
        if let Ok(ip) = dial.parse::<IpAddr>() {
            return Some(SocketAddr::new(ip, port));
        }

        tracing::warn!(
            server = %server,
            dial_addr = %dial,
            "unparseable dial_addr"
        );
        return None;
    }

    let container = node.container_of(server)?;
    container.ip.map(|ip| SocketAddr::new(IpAddr::V4(ip), port))
}

pub async fn control_loop(node: Arc<Node>, conn: Arc<PeerConn>, mut recv: quinn::RecvStream) {
    loop {
        let msg: ControlMsg = match read_frame(&mut recv).await {
            Ok(m) => m,
            Err(err) => {
                tracing::debug!(
                    peer = %conn.peer,
                    "control stream ended: {:?}",
                    err
                );
                conn.close(CloseCode::Protocol);
                return;
            }
        };

        match msg {
            ControlMsg::ReAuth { jwt } => {
                let cert = crate::node::quic::conn::peer_cert_hash(&conn.conn);
                let ok = cert.is_some_and(|c| node.validate_token(&jwt, c, conn.peer).is_ok());
                if ok {
                    conn.touch_auth();
                    conn.metrics.reauth_total.fetch_add(1, Relaxed);
                    conn.try_control(ControlMsg::ReAuthAck);
                    tracing::debug!(
                        peer = %conn.peer,
                        "re-authenticated"
                    );
                } else {
                    tracing::warn!(
                        peer = %conn.peer,
                        "re-authentication rejected, closing"
                    );
                    conn.close(CloseCode::AuthFailed);
                    return;
                }
            }
            ControlMsg::ReAuthAck => {
                if !conn.ack_reauth() {
                    tracing::warn!(
                        peer = %conn.peer,
                        "unsolicited re-auth ack, closing"
                    );
                    conn.close(CloseCode::Protocol);
                    return;
                }
            }
            ControlMsg::FlowOpen(open) => flow_open(&node, &conn, open).await,
            ControlMsg::FlowUnknown { flow_id } => flow_unknown(&conn, flow_id),
            ControlMsg::DrainStart { flows, last } => {
                if conn.begin_drain() {
                    tracing::info!(
                        peer = %conn.peer,
                        "the peer is restarting, draining"
                    );
                    tokio::spawn(crate::node::restart::drain::serve_drain(
                        Arc::clone(&node),
                        Arc::clone(&conn),
                    ));
                }
                conn.post_drain(DrainMsg::Start { flows, last });
            }
            ControlMsg::DrainReady { flows, last } => {
                conn.post_drain(DrainMsg::Ready { flows, last })
            }
            ControlMsg::DrainComplete => conn.post_drain(DrainMsg::Complete),
            ControlMsg::ResumeFlows { flows, last } => {
                if !resume_flows(&node, &conn, flows, last) {
                    conn.close(CloseCode::Protocol);
                    return;
                }
            }
            ControlMsg::Hello { .. } | ControlMsg::HelloAck { .. } => {
                tracing::warn!(
                    peer = %conn.peer,
                    "unexpected handshake message on an established connection"
                );
                conn.close(CloseCode::Protocol);
                return;
            }
        }
    }
}

#[derive(Debug)]
enum ClaimStep {
    Partial,
    Complete(Vec<u64>),
    OverBudget,
}

/// The sender's own freeze path never carries more than `MAX_CARRIED_FLOWS`, so a claim set
/// that outgrows it is a peer trying to grow this buffer, not a resume.
fn accumulate_claims(claimed: &mut Vec<u64>, flows: Vec<u64>, last: bool, cap: usize) -> ClaimStep {
    if claimed.len() + flows.len() > cap {
        return ClaimStep::OverBudget;
    }

    claimed.extend(flows);
    if last {
        ClaimStep::Complete(std::mem::take(claimed))
    } else {
        ClaimStep::Partial
    }
}

/// `claim` kills every frozen flow the list does not name, so it waits for the last chunk.
/// Returns false when the peer's claims exceed the carry budget and the connection must go.
fn resume_flows(node: &Arc<Node>, conn: &Arc<PeerConn>, flows: Vec<u64>, last: bool) -> bool {
    let step = {
        let mut claimed = conn.claimed.lock();
        accumulate_claims(&mut claimed, flows, last, MAX_CARRIED_FLOWS)
    };

    match step {
        ClaimStep::Partial => true,
        ClaimStep::Complete(all) => {
            crate::node::restart::resume::claim(node, &conn.peer, &all);
            true
        }
        ClaimStep::OverBudget => {
            tracing::warn!(
                peer = %conn.peer,
                cap = MAX_CARRIED_FLOWS,
                "the peer claimed more resumed flows than a carry can hold, closing"
            );
            false
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnknownAction {
    /// Our id: dropping the flow would discard the loopback client's address and never converge.
    Reannounce,
    /// The peer's id: release the container socket rather than wait out the idle timer.
    ReleaseIngress,
}

#[inline]
pub fn classify_unknown(parity: Parity, flow_id: u64) -> UnknownAction {
    if parity.matches(flow_id) {
        UnknownAction::Reannounce
    } else {
        UnknownAction::ReleaseIngress
    }
}

#[inline]
fn flow_unknown(conn: &PeerConn, flow_id: u64) {
    let now = Instant::now();

    let reopen = {
        let mut udp = conn.udp.lock();
        if classify_unknown(conn.parity, flow_id) == UnknownAction::ReleaseIngress {
            if udp.ingress.remove(flow_id).is_some() {
                tracing::debug!(
                    peer = %conn.peer,
                    flow = flow_id,
                    "peer abandoned an inbound flow, releasing it"
                );
            }

            return;
        }

        udp.egress.by_id(flow_id, now).map(|flow| FlowOpen {
            flow_id,
            src_server: flow.src_server,
            dst_server: flow.dst_server,
            dst_port: flow.dst_port,
        })
    };

    if let Some(open) = reopen {
        tracing::debug!(
            peer = %conn.peer,
            flow = flow_id,
            "re-announcing a flow the peer does not know"
        );
        conn.try_control(ControlMsg::FlowOpen(open));
    }
}

async fn flow_open(node: &Arc<Node>, conn: &Arc<PeerConn>, open: FlowOpen) {
    let index = node.index();
    if let Err(code) = admit(
        &index,
        &conn.peer,
        &node.uuid,
        &open.src_server,
        &open.dst_server,
        open.dst_port,
        Transport::Udp,
    ) {
        tracing::debug!(
            peer = %conn.peer,
            src = %open.src_server,
            dst = %open.dst_server,
            port = open.dst_port,
            reason = %code.to_str(),
            "refusing a flow"
        );
        return;
    }

    {
        let udp = conn.udp.lock();
        if let Some(existing) = udp.ingress.peek(open.flow_id)
            && existing.src_server == open.src_server
            && existing.dst_server == open.dst_server
            && existing.dst_port == open.dst_port
        {
            return;
        }
    }

    let (_relay_guard, cancel) = node.relays.register(
        open.src_server,
        open.dst_server,
        open.dst_port,
        Transport::Udp,
    );

    let Some(target) = dial_target(node, &open.dst_server, open.dst_port) else {
        tracing::debug!(
            dst = %open.dst_server,
            "no dial target for an incoming flow"
        );
        return;
    };

    let socket = match bind_connected(target).await {
        Ok(s) => Arc::new(s),
        Err(err) => {
            tracing::warn!(
                target = %target,
                "failed to open a socket toward the container: {:?}",
                err
            );
            return;
        }
    };

    if let Err(code) = admit(
        &node.index(),
        &conn.peer,
        &node.uuid,
        &open.src_server,
        &open.dst_server,
        open.dst_port,
        Transport::Udp,
    ) {
        tracing::debug!(
            peer = %conn.peer,
            reason = %code.to_str(),
            "access withdrawn while dialling"
        );
        return;
    }

    let reader = tokio::spawn(ingress_reader(
        Arc::clone(conn),
        open.flow_id,
        Arc::clone(&socket),
    ));
    let (to_container, rx) = tokio::sync::mpsc::channel(LOCAL_SEND_QUEUE);
    let writer = tokio::spawn(container_writer(Arc::clone(&socket), rx));

    let mut udp = conn.udp.lock();

    if *cancel.borrow() {
        tracing::debug!(
            peer = %conn.peer,
            flow = open.flow_id,
            "access withdrawn while dialling"
        );
        reader.abort();
        writer.abort();
        return;
    }
    let flow = IngressFlow {
        to_container,
        socket,
        src_server: open.src_server,
        dst_server: open.dst_server,
        dst_port: open.dst_port,
        reasm: FragReassembler::new(),
        group: 0,
        reader: reader.abort_handle(),
        writer: writer.abort_handle(),
    };
    if let Err(err) = udp
        .ingress
        .adopt(open.flow_id, open.flow_id, flow, Instant::now())
    {
        tracing::warn!(
            peer = %conn.peer,
            flow = open.flow_id,
            "refusing an incoming flow: {:?}",
            err
        );
        reader.abort();
        writer.abort();
        return;
    }

    let parked = udp.pending.take(open.flow_id);
    drop(udp);

    if !parked.is_empty() {
        tracing::debug!(
            peer = %conn.peer,
            flow = open.flow_id,
            datagrams = parked.len(),
            "replaying datagrams that arrived before their announcement"
        );
        for datagram in parked {
            deliver(conn, &datagram, Instant::now());
        }
    }
}

/// One lock acquisition: split apart, a `FlowOpen` lands in between and parks a datagram for
/// an already-open flow that nothing replays. The idle timer is deliberately not refreshed
/// here - only what the container accepts counts as liveness.
fn ingress_step(
    udp: &mut UdpTables,
    metrics: &crate::metrics::PeerMetrics,
    header: tundra_common::datagram::DatagramHeader,
    payload: &[u8],
    now: Instant,
) -> Ingress {
    let Some(flow) = udp.ingress.get_mut(header.flow_id) else {
        return Ingress::Unknown;
    };

    let complete = match header.frag {
        None => Some(payload.to_vec()),
        Some(f) => flow.reasm.push(f, payload, now),
    };
    let drops = flow.reasm.take_drops();
    let sink = flow.to_container.clone();
    account_drops(metrics, drops);

    match complete {
        Some(data) => Ingress::Deliver(sink, data),
        None => Ingress::Pending,
    }
}

fn deliver(conn: &Arc<PeerConn>, raw: &[u8], now: Instant) {
    let Ok((header, payload)) = parse(raw) else {
        conn.metrics.drops.malformed.fetch_add(1, Relaxed);
        return;
    };

    let ready = {
        let mut udp = conn.udp.lock();
        ingress_step(&mut udp, &conn.metrics, header, payload, now)
    };

    match ready {
        Ingress::Unknown | Ingress::Pending => {}
        Ingress::Deliver(sink, data) => {
            if sink.try_send(data).is_err() {
                conn.metrics.drops.send_buffer_full.fetch_add(1, Relaxed);
            } else {
                conn.udp.lock().ingress.touch(header.flow_id, now);
            }
        }
    }
}

async fn bind_connected(target: SocketAddr) -> Result<UdpSocket, std::io::Error> {
    let bind: SocketAddr = if target.is_ipv4() {
        "0.0.0.0:0"
            .parse()
            .expect("failed to parse the ipv4 wildcard bind address")
    } else {
        "[::]:0"
            .parse()
            .expect("failed to parse the ipv6 wildcard bind address")
    };

    let socket = UdpSocket::bind(bind).await?;
    socket.connect(target).await?;

    Ok(socket)
}

pub async fn ingress_reader(conn: Arc<PeerConn>, flow_id: u64, socket: Arc<UdpSocket>) {
    let mut buf = vec![0; UDP_RECV_BUF];
    loop {
        let n = match socket.recv(&mut buf).await {
            Ok(n) => n,
            Err(err) => {
                tracing::debug!(
                    peer = %conn.peer,
                    flow = flow_id,
                    "container reply socket error: {:?}",
                    err
                );
                continue;
            }
        };

        let group = {
            let mut udp = conn.udp.lock();
            match udp.ingress.by_id(flow_id, Instant::now()) {
                Some(flow) => next_group(&mut flow.group),
                None => return,
            }
        };

        let Some(payload) = buf.get(..n) else {
            continue;
        };

        send_payload(
            &conn.conn,
            flow_id,
            group,
            payload,
            &conn.metrics.drops,
            &conn.metrics.datagrams_out,
            &conn.metrics.datagram_bytes_out,
        );
    }
}

pub async fn datagram_loop(conn: Arc<PeerConn>) {
    let parity = conn.parity;

    while let Ok(bytes) = conn.conn.read_datagram().await {
        conn.metrics.datagrams_in.fetch_add(1, Relaxed);
        conn.metrics
            .datagram_bytes_in
            .fetch_add(bytes.len() as u64, Relaxed);

        let Ok((header, payload)) = parse(&bytes) else {
            conn.metrics.drops.malformed.fetch_add(1, Relaxed);
            continue;
        };

        let now = Instant::now();
        let delivery = if parity.matches(header.flow_id) {
            let mut udp = conn.udp.lock();
            match udp.egress.by_id(header.flow_id, now) {
                Some(flow) => {
                    let complete = match header.frag {
                        None => Some(payload.to_vec()),
                        Some(f) => flow.reasm.push(f, payload, now),
                    };
                    let drops = flow.reasm.take_drops();
                    let target = (flow.replies.clone(), flow.client);
                    account_drops(&conn.metrics, drops);
                    complete.map(|data| Delivery::ToClient(target.0, target.1, data))
                }
                None => {
                    conn.metrics.drops.unknown_flow.fetch_add(1, Relaxed);
                    notify_unknown(&conn, &mut udp.unknown, header.flow_id, now);
                    None
                }
            }
        } else {
            let mut udp = conn.udp.lock();
            match ingress_step(&mut udp, &conn.metrics, header, payload, now) {
                Ingress::Pending => None,
                Ingress::Deliver(sink, data) => {
                    if sink.try_send(data).is_err() {
                        conn.metrics.drops.send_buffer_full.fetch_add(1, Relaxed);
                    } else {
                        udp.ingress.touch(header.flow_id, now);
                    }
                    None
                }
                Ingress::Unknown => {
                    let (verdict, abandoned) = udp.pending.hold(header.flow_id, bytes.clone(), now);
                    let lost = abandoned + u64::from(verdict == Hold::Dropped);
                    if lost > 0 {
                        conn.metrics.drops.unknown_flow.fetch_add(lost, Relaxed);
                    }
                    notify_unknown(&conn, &mut udp.unknown, header.flow_id, now);
                    None
                }
            }
        };

        enum Delivery {
            ToClient(
                tokio::sync::mpsc::Sender<(Vec<u8>, SocketAddr)>,
                SocketAddr,
                Vec<u8>,
            ),
        }

        // outside the lock and never awaiting: a stalled local socket must not stall the reader
        let Some(Delivery::ToClient(replies, client, data)) = delivery else {
            continue;
        };

        if replies.try_send((data, client)).is_err() {
            conn.metrics.drops.send_buffer_full.fetch_add(1, Relaxed);
        }
    }
}

fn account_drops(metrics: &crate::metrics::PeerMetrics, drops: tundra_common::frag::FragDrops) {
    if drops.total() == 0 {
        return;
    }

    let counters = &metrics.drops;
    counters.frag_timeout.fetch_add(drops.timeout, Relaxed);
    counters.frag_limit.fetch_add(drops.limit, Relaxed);
    counters.oversize.fetch_add(drops.oversize, Relaxed);
    counters.malformed.fetch_add(drops.malformed, Relaxed);
}

fn notify_unknown(
    conn: &PeerConn,
    limiter: &mut tundra_common::flow::UnknownFlowLimiter,
    flow_id: u64,
    now: Instant,
) {
    if limiter.allow(flow_id, now) {
        conn.try_control(ControlMsg::FlowUnknown { flow_id });
    }
}

pub async fn stream_loop(node: Arc<Node>, conn: Arc<PeerConn>) {
    while let Ok((send, recv)) = conn.conn.accept_bi().await {
        tokio::spawn({
            let node = Arc::clone(&node);
            let conn = Arc::clone(&conn);

            async move {
                if let Err(err) = inbound_stream(node, conn, send, recv).await {
                    tracing::debug!("inbound relay ended: {:?}", err);
                }
            }
        });
    }
}

async fn inbound_stream(
    node: Arc<Node>,
    conn: Arc<PeerConn>,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
) -> Result<(), anyhow::Error> {
    let header: StreamHeader = read_frame(&mut recv).await?;

    let reject = |code: StreamCode, send: &mut quinn::SendStream, recv: &mut quinn::RecvStream| {
        let v = VarInt::from_u32(code.as_u32());
        let _ = send.reset(v);
        let _ = recv.stop(v);
    };

    let open = match header {
        StreamHeader::Open(open) => open,
        StreamHeader::Resume { flow_id, half } => {
            crate::node::restart::resume::accept_resumed(node, conn, flow_id, half, send, recv)
                .await;
            return Ok(());
        }
    };

    if conn.is_draining() {
        tracing::debug!(
            peer = %conn.peer,
            "refusing a relay on a draining connection"
        );
        reject(StreamCode::Unavailable, &mut send, &mut recv);
        return Ok(());
    }

    let index = node.index();
    if let Err(code) = admit(
        &index,
        &conn.peer,
        &node.uuid,
        &open.src_server,
        &open.dst_server,
        open.dst_port,
        Transport::Tcp,
    ) {
        tracing::debug!(
            peer = %conn.peer,
            src = %open.src_server,
            dst = %open.dst_server,
            port = open.dst_port,
            reason = %code.to_str(),
            "refusing a stream"
        );
        reject(code, &mut send, &mut recv);
        return Ok(());
    }

    let Some(target) = dial_target(&node, &open.dst_server, open.dst_port) else {
        reject(StreamCode::Unavailable, &mut send, &mut recv);
        return Ok(());
    };

    let registered = conn.tcp.lock().adopt(
        open.flow_id,
        Side::Ingress,
        open.src_server,
        open.dst_server,
        open.dst_port,
    );
    let (flow, ctl) = match registered {
        Ok(pair) => pair,
        Err(err) => {
            tracing::debug!(
                peer = %conn.peer,
                flow = open.flow_id,
                "refusing an inbound relay: {:?}",
                err
            );
            reject(StreamCode::Unavailable, &mut send, &mut recv);
            return Ok(());
        }
    };

    let _flow_guard = TcpFlowGuard::new(Arc::clone(&conn.tcp), flow);

    // registered before the dial, so a snapshot that withdraws access mid-connect still
    // reaches this relay; the re-check below covers one that lands just before this
    let (_guard, cancel) = node.relays.register(
        open.src_server,
        open.dst_server,
        open.dst_port,
        Transport::Tcp,
    );

    let tcp = match tokio::time::timeout(DIAL_TIMEOUT, TcpStream::connect(target)).await {
        Ok(Ok(s)) => s,
        Ok(Err(err)) => {
            tracing::debug!(
                target = %target,
                "failed to dial the container: {:?}",
                err
            );
            reject(StreamCode::DialFailed, &mut send, &mut recv);
            return Ok(());
        }
        Err(_) => {
            tracing::debug!(
                target = %target,
                "dial timed out"
            );
            reject(StreamCode::DialFailed, &mut send, &mut recv);
            return Ok(());
        }
    };
    let _ = tcp.set_nodelay(true);

    if let Err(code) = admit(
        &node.index(),
        &conn.peer,
        &node.uuid,
        &open.src_server,
        &open.dst_server,
        open.dst_port,
        Transport::Tcp,
    ) {
        tracing::debug!(
            peer = %conn.peer,
            reason = %code.to_str(),
            "access withdrawn while dialling"
        );
        reject(code, &mut send, &mut recv);
        return Ok(());
    }

    conn.metrics.streams_open.fetch_add(1, Relaxed);
    conn.metrics.streams_total.fetch_add(1, Relaxed);

    let outcome = relay_stream(
        tcp,
        send,
        recv,
        cancel,
        ByteCounters {
            from_peer: &conn.metrics.bytes_in,
            to_peer: &conn.metrics.bytes_out,
        },
        ctl,
        Prelude::default(),
    )
    .await;

    conn.metrics.streams_open.fetch_sub(1, Relaxed);
    if !matches!(outcome, Outcome::Closed | Outcome::Frozen) {
        tracing::debug!(
            peer = %conn.peer,
            dst = %open.dst_server,
            outcome = %outcome,
            "inbound relay ended"
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tundra_common::flow::{FlowTable, MAX_EGRESS_FLOWS_PER_CONN, Parity};

    // accumulate_claims

    #[test]
    fn accumulate_claims_holds_chunks_until_the_last_one() {
        let mut claimed = Vec::new();
        assert!(matches!(
            accumulate_claims(&mut claimed, vec![1, 2], false, 8),
            ClaimStep::Partial
        ));
        assert_eq!(claimed, vec![1, 2]);

        let ClaimStep::Complete(all) = accumulate_claims(&mut claimed, vec![3], true, 8) else {
            panic!("the last chunk must complete the claim");
        };
        assert_eq!(all, vec![1, 2, 3]);
        assert!(claimed.is_empty());
    }

    #[test]
    fn accumulate_claims_refuses_a_set_larger_than_any_carry() {
        let mut claimed = Vec::new();
        assert!(matches!(
            accumulate_claims(&mut claimed, vec![0; 4], false, 4),
            ClaimStep::Partial
        ));
        assert!(matches!(
            accumulate_claims(&mut claimed, vec![0], false, 4),
            ClaimStep::OverBudget
        ));
        assert!(matches!(
            accumulate_claims(&mut claimed, vec![0], true, 4),
            ClaimStep::OverBudget
        ));
    }

    // classify_unknown

    #[test]
    fn classify_unknown_reannounces_our_own_ids() {
        assert_eq!(classify_unknown(Parity::Even, 0), UnknownAction::Reannounce);
        assert_eq!(
            classify_unknown(Parity::Even, 4242),
            UnknownAction::Reannounce
        );
        assert_eq!(classify_unknown(Parity::Odd, 1), UnknownAction::Reannounce);
        assert_eq!(
            classify_unknown(Parity::Odd, 4243),
            UnknownAction::Reannounce
        );
    }

    #[test]
    fn classify_unknown_releases_the_ingress_socket_for_peer_ids() {
        assert_eq!(
            classify_unknown(Parity::Even, 1),
            UnknownAction::ReleaseIngress
        );
        assert_eq!(
            classify_unknown(Parity::Odd, 0),
            UnknownAction::ReleaseIngress
        );
    }

    #[test]
    fn classify_unknown_disagrees_between_the_two_parities() {
        // holds on an inherited parity too, which keeps a resumed connection consistent
        for flow_id in 0..16 {
            assert_ne!(
                classify_unknown(Parity::Even, flow_id),
                classify_unknown(Parity::Odd, flow_id)
            );
        }
    }

    #[test]
    fn collected_flow_reopens_under_a_fresh_id() {
        let t0 = Instant::now();
        let mut egress = FlowTable::new(
            Parity::Even,
            Duration::from_secs(60),
            MAX_EGRESS_FLOWS_PER_CONN,
        );
        let client: SocketAddr = "127.0.1.1:5000".parse().unwrap();

        let first = egress.open((0, client), (), t0).unwrap();
        assert_eq!(
            classify_unknown(Parity::Even, first),
            UnknownAction::Reannounce
        );

        // our side collects the flow while the peer still has it, or vice versa
        egress.gc(t0 + Duration::from_secs(60));
        assert!(egress.by_id(first, t0).is_none());

        let second = egress
            .open((0, client), (), t0 + Duration::from_secs(61))
            .unwrap();
        assert_ne!(first, second);
        assert!(Parity::Even.matches(second));
        assert_eq!(egress.opened_total(), 2);
        assert_eq!(egress.gc_total(), 1);
    }
}
