use crate::node::{
    Node,
    frontend::binder::Kind,
    plan::FrontendKey,
    quic::conn::{HANDSHAKE_TIMEOUT, PeerConn, read_frame, write_frame},
    relay::{
        flows::{Side, TcpFlowGuard},
        tcp::{ByteCounters, Outcome, Prelude, relay_stream},
    },
    restart::{
        Killed, RESUME_BUDGET,
        blob::{Blob, Decoded, FrontendRec, UdpEgressRec, UdpIngressRec},
        exec::{close_raw, discard, read_staged, reset_raw, set_cloexec},
        frozen::FrozenFlow,
    },
};
use anyhow::Context;
use compact_str::ToCompactString;
use quinn::VarInt;
use std::{
    collections::HashMap,
    os::fd::{FromRawFd, RawFd},
    sync::{Arc, atomic::Ordering::Relaxed},
};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tundra_common::{
    admit::{Transport, admit},
    codes::StreamCode,
    flow::Parity,
    state::Snapshot,
    wire::{ControlMsg, DRAIN_CHUNK, ResumeAck, StreamHeader},
};

#[derive(Debug)]
pub enum Bound {
    Tcp(TcpListener),
    Udp(Arc<UdpSocket>),
}

#[derive(Debug)]
pub struct AdoptedFrontend {
    pub key: FrontendKey,
    pub id: u64,
    pub pid: i32,
    pub bound: Bound,
}

#[derive(Debug, Default)]
pub struct CarriedUdp {
    pub egress: Vec<UdpEgressRec>,
    pub ingress: Vec<(UdpIngressRec, Arc<UdpSocket>)>,
}

#[derive(Debug)]
pub struct PeerResume {
    pub parity: Parity,
    pub flows: Vec<FrozenFlow>,
    pub udp: CarriedUdp,
}

#[derive(Debug)]
pub struct Inherited {
    pub node_uuid: uuid::Uuid,
    pub old_instance: u64,
    pub generation: u64,
    pub triggered_unix_ms: u64,

    pub snapshot: Snapshot,
    pub next_frontend_id: u64,
    pub frontends: Vec<AdoptedFrontend>,
    pub peers: HashMap<uuid::Uuid, PeerResume>,
}

pub fn inherit(fd: RawFd) -> Option<Inherited> {
    let body = match read_staged(fd) {
        Ok(body) => body,
        Err(err) => {
            tracing::warn!("failed to read the handover blob, cold starting: {:?}", err);
            close_raw(fd);
            return None;
        }
    };

    match crate::node::restart::blob::decode(&body) {
        Decoded::Ok(blob) => Some(rebuild(*blob)),
        Decoded::Unusable { fds, why } => {
            tracing::warn!(
                why = %why,
                descriptors = fds.len(),
                "unusable handover blob, cold starting"
            );
            for carried in fds {
                discard(carried);
            }
            None
        }
    }
}

fn rebuild(blob: Blob) -> Inherited {
    let mut peers: HashMap<uuid::Uuid, PeerResume> = blob
        .peers
        .iter()
        .map(|p| {
            let parity = if p.parity_even {
                Parity::Even
            } else {
                Parity::Odd
            };
            (
                p.peer,
                PeerResume {
                    parity,
                    flows: Vec::new(),
                    udp: CarriedUdp::default(),
                },
            )
        })
        .collect();

    let frontends = blob.frontends.iter().filter_map(adopt_frontend).collect();

    for rec in blob.tcp_flows {
        let Some(slot) = peers.get_mut(&rec.peer) else {
            tracing::warn!(
                flow = rec.flow_id,
                "a carried relay names no peer, resetting it"
            );
            reset_raw(rec.fd);
            continue;
        };

        let tcp = match adopt_stream(rec.fd) {
            Ok(tcp) => tcp,
            Err(err) => {
                tracing::error!(
                    flow = rec.flow_id,
                    "failed to adopt a carried relay socket: {:?}",
                    err
                );
                reset_raw(rec.fd);
                continue;
            }
        };

        slot.flows.push(FrozenFlow {
            id: rec.flow_id,
            side: rec.side,
            src_server: rec.src_server,
            dst_server: rec.dst_server,
            dst_port: rec.dst_port,
            written: rec.written,
            consumed: rec.consumed,
            pending_send: rec.pending_send,
            pending_write: rec.pending_write,
            half: rec.half,
            tcp,
        });
    }

    for rec in blob.udp_egress {
        if let Some(slot) = peers.get_mut(&rec.peer) {
            slot.udp.egress.push(rec);
        }
    }

    for rec in blob.udp_ingress {
        let Some(slot) = peers.get_mut(&rec.peer) else {
            close_raw(rec.fd);
            continue;
        };

        match adopt_udp(rec.fd) {
            Ok(socket) => slot.udp.ingress.push((rec, Arc::new(socket))),
            Err(err) => tracing::error!(
                flow = rec.flow_id,
                "failed to adopt a carried udp socket: {:?}",
                err
            ),
        }
    }

    Inherited {
        node_uuid: blob.node_uuid,
        old_instance: blob.old_instance,
        generation: blob.generation,
        triggered_unix_ms: blob.triggered_unix_ms,
        snapshot: blob.snapshot,
        next_frontend_id: blob.next_frontend_id,
        frontends,
        peers,
    }
}

fn adopt_frontend(rec: &FrontendRec) -> Option<AdoptedFrontend> {
    let key = FrontendKey {
        src_server: rec.src_server,
        dst_server: rec.dst_server,
        port: rec.port,
        kind: rec.kind,
    };

    let bound = match rec.kind {
        Kind::Tcp => adopt_listener(rec.fd).map(Bound::Tcp),
        Kind::Udp => adopt_udp(rec.fd).map(|s| Bound::Udp(Arc::new(s))),
    };

    match bound {
        Ok(bound) => Some(AdoptedFrontend {
            key,
            id: rec.frontend_id,
            pid: rec.pid,
            bound,
        }),
        Err(err) => {
            // the adopters take ownership before anything that can fail, so it is closed here
            tracing::error!(
                src = %rec.src_server,
                dst = %rec.dst_server,
                port = rec.port,
                "failed to adopt a carried frontend: {:?}",
                err
            );
            None
        }
    }
}

/// CLOEXEC is clear because that is what let these cross the exec, and must not stay that way.
#[inline]
fn reclaim(fd: RawFd) -> Result<(), anyhow::Error> {
    set_cloexec(fd, true).context(format!("failed to restore CLOEXEC on descriptor {fd}"))
}

fn adopt_listener(fd: RawFd) -> Result<TcpListener, anyhow::Error> {
    // SAFETY: the blob hands each descriptor over once, so this is its only owner.
    let std = unsafe { std::net::TcpListener::from_raw_fd(fd) };
    reclaim(fd)?;
    std.set_nonblocking(true)?;
    Ok(TcpListener::from_std(std)?)
}

fn adopt_stream(fd: RawFd) -> Result<TcpStream, anyhow::Error> {
    // SAFETY: the blob hands each descriptor over once, so this is its only owner.
    let std = unsafe { std::net::TcpStream::from_raw_fd(fd) };
    reclaim(fd)?;
    std.set_nonblocking(true)?;
    let tcp = TcpStream::from_std(std)?;
    Ok(tcp)
}

fn adopt_udp(fd: RawFd) -> Result<UdpSocket, anyhow::Error> {
    // SAFETY: the blob hands each descriptor over once, so this is its only owner.
    let std = unsafe { std::net::UdpSocket::from_raw_fd(fd) };
    reclaim(fd)?;
    std.set_nonblocking(true)?;
    Ok(UdpSocket::from_std(std)?)
}

/// Dialling is unconditional: `needed_peers` would never name a peer this node cannot reach,
/// and that peer is holding off its own dial while it waits for exactly this connection.
pub async fn run(node: Arc<Node>, peers: Vec<uuid::Uuid>) {
    // frontend accepts are held until this returns, and a dial to a host that has gone away
    // is otherwise only bounded by the QUIC idle timeout
    let settled = tokio::time::timeout(RESUME_BUDGET, reconnect(Arc::clone(&node), peers)).await;
    if settled.is_err() {
        tracing::warn!(
            budget_secs = RESUME_BUDGET.as_secs(),
            "the resume did not settle in time, releasing the frontends anyway"
        );
    }

    node.finish_resume();
}

async fn reconnect(node: Arc<Node>, peers: Vec<uuid::Uuid>) {
    const RESUME_DIAL_RETRY: std::time::Duration = std::time::Duration::from_millis(250);
    /// Rounds a live connection may coexist with untaken carried flows before they are judged
    /// stranded: a connection whose Hello carried no accepted intent will never take them.
    const STRANDED_ROUNDS: u32 = 2;

    // headroom under RESUME_BUDGET so the give-up accounting (and its warn) happens here in
    // the per-peer task; past the outer timeout it would fall to finish_resume's sweep
    let deadline = RESUME_BUDGET - std::time::Duration::from_secs(2);

    let mut tasks = Vec::new();
    for peer in peers {
        tasks.push(tokio::spawn({
            let node = Arc::clone(&node);

            async move {
                // Any dial made while the carried map holds this peer negotiates the resume
                // in its Hello - including the one the seeded snapshot spawns concurrently,
                // in which case ensure_peer reports None purely because that dial is already
                // in flight. So the carried map emptying is the success signal, not our own
                // dial landing, and losing the begin_dial race must not discard anything.
                let start = tokio::time::Instant::now();
                let mut stranded_rounds = 0u32;
                while node.carried_parity(&peer).is_some() {
                    if node.peers.get(&peer).is_none() {
                        stranded_rounds = 0;
                        node.ensure_peer(peer).await;
                    } else {
                        // a glare loser or an accepted connection never negotiated the resume
                        stranded_rounds += 1;
                    }
                    if node.carried_parity(&peer).is_none() {
                        break;
                    }
                    if start.elapsed() >= deadline || stranded_rounds > STRANDED_ROUNDS {
                        tracing::warn!(peer = %peer, "failed to reconnect to resume flows");
                        let killed = node.discard_carried(&peer, Killed::NoResume);
                        if killed > 0 {
                            tracing::warn!(
                                peer = %peer,
                                flows = killed,
                                "gave up on carried relays"
                            );
                        }
                        return;
                    }
                    tokio::time::sleep(RESUME_DIAL_RETRY).await;
                }
            }
        }));
    }

    for task in tasks {
        let _ = task.await;
    }

    // the dial hands each peer's flows to a task of its own, so the handover is not over yet
    node.await_resumes().await;
}

pub async fn attach_all(node: Arc<Node>, conn: Arc<PeerConn>, carried: PeerResume) {
    let ids: Vec<_> = carried.flows.iter().map(|f| f.id).collect();
    if !announce(&conn, &ids).await {
        tracing::warn!(peer = %conn.peer, "failed to announce the resumed flows");
        for flow in carried.flows {
            flow.kill();
        }
        node.restart
            .counters
            .killed(Killed::NoResume, ids.len() as u64);
        return;
    }

    restore_udp(&node, &conn, carried.udp);

    let mut tasks = Vec::new();
    for flow in carried.flows {
        let node = Arc::clone(&node);
        let conn = Arc::clone(&conn);

        tasks.push(tokio::spawn(attach(node, conn, flow)));
    }

    for task in tasks {
        let _ = task.await;
    }

    let attached = conn.tcp.lock().len();
    tracing::info!(
        peer = %conn.peer,
        claimed = ids.len(),
        attached,
        "resumed"
    );
    node.end_resume();
}

async fn announce(conn: &Arc<PeerConn>, ids: &[u64]) -> bool {
    let mut chunks: Vec<&[u64]> = ids.chunks(DRAIN_CHUNK).collect();
    if chunks.is_empty() {
        chunks.push(&[]);
    }

    let count = chunks.len();

    for (i, chunk) in chunks.into_iter().enumerate() {
        let msg = ControlMsg::ResumeFlows {
            flows: chunk.to_vec(),
            last: i + 1 == count,
        };
        if !conn.send_control(msg).await {
            return false;
        }
    }

    true
}

async fn attach(node: Arc<Node>, conn: Arc<PeerConn>, flow: FrozenFlow) {
    let permit = Arc::clone(&conn.stream_slots).try_acquire_owned().ok();
    if permit.is_none() {
        tracing::warn!(
            peer = %conn.peer,
            flow = flow.id,
            "no stream budget for a resumed relay"
        );
        flow.kill();
        node.restart.counters.killed(Killed::NoResume, 1);
        return;
    }

    let opened = tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        let (mut send, mut recv) = conn
            .conn
            .open_bi()
            .await
            .map_err(|err| err.to_compact_string())?;
        let header = StreamHeader::Resume {
            flow_id: flow.id,
            half: flow.half,
        };
        write_frame(&mut send, &header)
            .await
            .map_err(|err| err.to_compact_string())?;
        let ack: ResumeAck = read_frame(&mut recv)
            .await
            .map_err(|err| err.to_compact_string())?;
        Ok::<_, compact_str::CompactString>((send, recv, ack))
    })
    .await
    .unwrap_or_else(|_| Err("the peer never answered the resume".into()));

    let (send, recv, ack) = match opened {
        Ok(parts) => parts,
        Err(err) => {
            tracing::warn!(
                peer = %conn.peer,
                flow = flow.id,
                "the peer refused a resumed relay: {}",
                err
            );
            flow.kill();
            node.restart.counters.killed(Killed::Unmatched, 1);
            return;
        }
    };

    tracing::debug!(
        peer = %conn.peer,
        flow = flow.id,
        side = %flow.side.to_str(),
        "re-attached"
    );
    node.restart.counters.flows_resumed.fetch_add(1, Relaxed);
    // spawned rather than awaited: the handover is over the moment the relay is attached
    tokio::spawn(run_resumed(node, conn, flow, send, recv, ack.half, permit));
}

pub async fn accept_resumed(
    node: Arc<Node>,
    conn: Arc<PeerConn>,
    flow_id: u64,
    peer_half: tundra_common::wire::HalfClose,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
) {
    let refuse = |send: &mut quinn::SendStream, recv: &mut quinn::RecvStream| {
        let v = VarInt::from_u32(StreamCode::DrainFailed.as_u32());
        let _ = send.reset(v);
        let _ = recv.stop(v);
    };

    let Some(flow) = node.frozen.take_flow(&conn.peer, flow_id) else {
        tracing::debug!(
            peer = %conn.peer,
            flow = flow_id,
            "no frozen relay for this resume"
        );
        refuse(&mut send, &mut recv);
        node.restart.counters.killed(Killed::Unmatched, 1);
        return;
    };

    // the flow's admission has to still hold, and its direction comes from the flow rather
    // than from who opens the stream: a restart re-opens from its own side
    let (src_owner, dst_owner) = match flow.side {
        Side::Ingress => (conn.peer, node.uuid),
        Side::Frontend => (node.uuid, conn.peer),
    };
    if let Err(code) = admit(
        &node.index(),
        &src_owner,
        &dst_owner,
        &flow.src_server,
        &flow.dst_server,
        flow.dst_port,
        Transport::Tcp,
    ) {
        tracing::debug!(
            peer = %conn.peer,
            flow = flow_id,
            reason = %code.to_str(),
            "refusing to resume"
        );
        let v = VarInt::from_u32(code.as_u32());
        let _ = send.reset(v);
        let _ = recv.stop(v);
        flow.kill();
        node.restart.counters.killed(Killed::Unmatched, 1);
        return;
    }

    if write_frame(&mut send, &ResumeAck { half: flow.half })
        .await
        .is_err()
    {
        flow.kill();
        node.restart.counters.killed(Killed::Unmatched, 1);
        return;
    }

    node.restart.counters.flows_resumed.fetch_add(1, Relaxed);
    run_resumed(node, conn, flow, send, recv, peer_half, None).await;
}

async fn run_resumed(
    node: Arc<Node>,
    conn: Arc<PeerConn>,
    flow: FrozenFlow,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    peer_half: tundra_common::wire::HalfClose,
    permit: Option<tokio::sync::OwnedSemaphorePermit>,
) {
    let restored = conn.tcp.lock().restore(
        flow.id,
        flow.side,
        flow.src_server,
        flow.dst_server,
        flow.dst_port,
        flow.written,
        flow.consumed,
    );
    let (handle, ctl) = match restored {
        Ok(pair) => pair,
        Err(err) => {
            tracing::warn!(
                peer = %conn.peer,
                flow = flow.id,
                "failed to re-register a resumed relay: {:?}",
                err
            );
            flow.kill();
            node.restart.counters.killed(Killed::Anomaly, 1);
            return;
        }
    };

    let _flow_guard = TcpFlowGuard::new(Arc::clone(&conn.tcp), handle);
    let (_relay_guard, cancel) = node.relays.register(
        flow.src_server,
        flow.dst_server,
        flow.dst_port,
        Transport::Tcp,
    );

    let (src_owner, dst_owner) = match flow.side {
        Side::Ingress => (conn.peer, node.uuid),
        Side::Frontend => (node.uuid, conn.peer),
    };
    if let Err(code) = admit(
        &node.index(),
        &src_owner,
        &dst_owner,
        &flow.src_server,
        &flow.dst_server,
        flow.dst_port,
        Transport::Tcp,
    ) {
        tracing::debug!(
            peer = %conn.peer,
            flow = flow.id,
            reason = %code.to_str(),
            "access withdrawn while resuming"
        );
        let v = VarInt::from_u32(code.as_u32());
        let _ = send.reset(v);
        let _ = recv.stop(v);
        flow.kill();
        node.restart.counters.killed(Killed::Unmatched, 1);
        return;
    }

    conn.metrics.streams_open.fetch_add(1, Relaxed);
    conn.metrics.streams_total.fetch_add(1, Relaxed);

    let outcome = relay_stream(
        flow.tcp,
        send,
        recv,
        cancel,
        ByteCounters {
            from_peer: &conn.metrics.bytes_in,
            to_peer: &conn.metrics.bytes_out,
        },
        ctl,
        Prelude {
            pending_send: flow.pending_send,
            pending_write: flow.pending_write,
            half: flow.half,
            peer_half,
        },
    )
    .await;

    conn.metrics.streams_open.fetch_sub(1, Relaxed);
    drop(permit);
    if !matches!(outcome, Outcome::Closed | Outcome::Frozen) {
        tracing::debug!(
            peer = %conn.peer,
            flow = flow.id,
            outcome = %outcome,
            "resumed relay ended"
        );
    }
}

/// Carried UDP flows are soft state on both ends: anything that fails here re-announces itself.
fn restore_udp(node: &Arc<Node>, conn: &Arc<PeerConn>, udp: CarriedUdp) {
    let now = std::time::Instant::now();
    let mut restored = 0;

    let index = node.index();
    for (rec, socket) in udp.ingress {
        if admit(
            &index,
            &conn.peer,
            &node.uuid,
            &rec.src_server,
            &rec.dst_server,
            rec.dst_port,
            Transport::Udp,
        )
        .is_err()
        {
            continue;
        }

        let reader = tokio::spawn(crate::node::ingress::ingress_reader(
            Arc::clone(conn),
            rec.flow_id,
            Arc::clone(&socket),
        ));
        let (to_container, rx) =
            tokio::sync::mpsc::channel(crate::node::relay::udp::LOCAL_SEND_QUEUE);
        let writer = tokio::spawn(crate::node::relay::udp::container_writer(
            Arc::clone(&socket),
            rx,
        ));

        let flow = crate::node::relay::udp::IngressFlow {
            to_container,
            socket,
            src_server: rec.src_server,
            dst_server: rec.dst_server,
            dst_port: rec.dst_port,
            reasm: tundra_common::frag::FragReassembler::new(),
            group: 0,
            reader: reader.abort_handle(),
            writer: writer.abort_handle(),
        };
        let mut tables = conn.udp.lock();
        if tables
            .ingress
            .restore(rec.flow_id, rec.flow_id, flow, now)
            .is_err()
        {
            reader.abort();
            writer.abort();
            continue;
        }

        restored += 1;
    }

    for rec in udp.egress {
        if admit(
            &index,
            &node.uuid,
            &conn.peer,
            &rec.src_server,
            &rec.dst_server,
            rec.dst_port,
            Transport::Udp,
        )
        .is_err()
        {
            continue;
        }

        let Some(replies) = node.frontend_replies(rec.frontend_id) else {
            continue;
        };

        let flow = crate::node::relay::udp::EgressFlow {
            replies,
            client: rec.client,
            src_server: rec.src_server,
            dst_server: rec.dst_server,
            dst_port: rec.dst_port,
            reasm: tundra_common::frag::FragReassembler::new(),
            group: 1,
        };

        let mut tables = conn.udp.lock();
        if tables
            .egress
            .restore(rec.flow_id, (rec.frontend_id, rec.client), flow, now)
            .is_ok()
        {
            restored += 1;
        }
    }

    if restored > 0 {
        tracing::debug!(peer = %conn.peer, flows = restored, "restored udp flows");
    }

    conn.refresh_flow_metrics();
}

pub fn claim(node: &Arc<Node>, peer: &uuid::Uuid, claimed: &[u64]) {
    let dropped = node.frozen.retain(peer, claimed);
    if !dropped.is_empty() {
        tracing::warn!(
            peer = %peer,
            flows = dropped.len(),
            "killing relays the resume did not claim"
        );
    }

    let n = dropped.len() as u64;
    for flow in dropped {
        flow.kill();
    }

    node.restart.counters.killed(Killed::Unmatched, n);

    node.gate.resume_peer(peer);
    node.peers.unsuppress_dial(peer);
}
