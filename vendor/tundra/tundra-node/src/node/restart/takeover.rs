use crate::node::{
    Node,
    restart::{
        KILL_GRACE, Killed, MAX_CARRIED_FLOWS, MAX_CARRY_BYTES, PeerOutcome,
        blob::{
            Blob, Carried, FrontendRec, PeerRec, TcpFlowRec, UdpEgressRec, UdpIngressRec, encode,
        },
        drain::{PeerDrain, PeerOutcomeKind, drain_peer},
        exec::{Carrier, close_raw, exec, restore_cloexec, stage},
        frozen::FrozenFlow,
        unix_millis,
    },
};
use std::{
    os::fd::{AsRawFd, RawFd},
    sync::{Arc, atomic::Ordering::Relaxed},
};
use tundra_common::codes::CloseCode;

pub async fn run(node: Arc<Node>) {
    if !node.restart.begin() {
        return;
    }

    node.restart.mark_triggered(unix_millis());
    tracing::info!(
        instance = node.restart.instance_id,
        generation = node.restart.generation,
        "handover requested"
    );

    node.gate.pause_all();

    let drained = drain_all(&node).await;
    node.restart.with_pending(|report| {
        report.peers = drained
            .iter()
            .map(|d| PeerOutcome {
                peer: d.peer,
                name: node.peer_name(&d.peer),
                outcome: d.outcome.to_str(),
                flows: d.flows.len(),
            })
            .collect();
    });

    // relays held for a peer that is restarting too are never drained, so they have to be
    // reset here rather than closed gracefully by the exec
    let orphaned: usize = node
        .frozen
        .peers()
        .iter()
        .map(|peer| node.frozen.discard(peer, "this node is restarting too"))
        .sum();
    if orphaned > 0 {
        tracing::warn!(
            flows = orphaned,
            "reset relays held for a peer that is restarting at the same time"
        );
        node.restart
            .counters
            .killed(Killed::Unmatched, orphaned as u64);
    }

    match build(&node, drained) {
        Some(staged) => launch(&node, staged).await,
        None => abandon(&node, "the handover state could not be assembled"),
    }
}

// the originals stay owned until the exec closes them, so a failed exec can reset them
struct Staged {
    body: Vec<u8>,
    fds: Vec<Carried>,
    carrier: Carrier,
    flows: Vec<FrozenFlow>,
}

async fn drain_all(node: &Arc<Node>) -> Vec<PeerDrain> {
    let budget = node.restart.drain_timeout;
    let mut tasks = Vec::new();
    for peer in node.peers.connected() {
        let Some(conn) = node.peers.get(&peer) else {
            continue;
        };

        tasks.push(tokio::spawn(drain_peer(Arc::clone(node), conn, budget)));
    }

    // aborts rather than detaches: a detached drain would still hold sockets at the exec
    let mut drained = Vec::new();
    let deadline = tokio::time::Instant::now() + budget * 2;
    for mut task in tasks {
        match tokio::time::timeout_at(deadline, &mut task).await {
            Ok(Ok(result)) => drained.push(result),
            Ok(Err(err)) => tracing::error!("a peer drain panicked: {:?}", err),
            Err(_) => {
                task.abort();
                tracing::error!("a peer drain outlived the global budget and was abandoned");
            }
        }
    }

    for result in &drained {
        match result.outcome {
            PeerOutcomeKind::Drained => node.restart.counters.peers_drained.fetch_add(1, Relaxed),
            PeerOutcomeKind::Timeout | PeerOutcomeKind::Concurrent => {
                node.restart.counters.peers_failed.fetch_add(1, Relaxed)
            }
        };
    }

    drained
}

fn build(node: &Arc<Node>, drained: Vec<PeerDrain>) -> Option<Staged> {
    let mut carrier = Carrier::default();
    let mut peers = Vec::new();
    let mut tcp_flows = Vec::new();
    let mut held = Vec::new();
    let mut carried_bytes = 0usize;

    // a peer with nothing to resume would otherwise be dialled with the frontends held shut
    let mut all: Vec<(uuid::Uuid, FrozenFlow)> = drained
        .into_iter()
        .filter(|d| !d.flows.is_empty())
        .inspect(|d| {
            peers.push(PeerRec {
                peer: d.peer,
                parity_even: d.parity_even,
            })
        })
        .flat_map(|d| d.flows.into_iter().map(move |f| (d.peer, f)))
        .collect();
    // sorted so the budget cut below is deterministic rather than a hash order
    all.sort_by_key(|(peer, flow)| (*peer, flow.id));

    for (peer, flow) in all {
        let over_budget = tcp_flows.len() >= MAX_CARRIED_FLOWS
            || carried_bytes + flow.carried_bytes() > MAX_CARRY_BYTES;
        if over_budget {
            tracing::warn!(
                peer = %peer,
                flow = flow.id,
                "over the handover budget, killing this relay"
            );
            flow.kill();
            node.restart.counters.killed(Killed::Budget, 1);
            continue;
        }

        let Ok(fd) = carrier.carry(flow.tcp.as_raw_fd()) else {
            flow.kill();
            node.restart.counters.killed(Killed::Anomaly, 1);
            continue;
        };

        carried_bytes += flow.carried_bytes();
        tcp_flows.push(TcpFlowRec {
            fd,
            flow_id: flow.id,
            peer,
            side: flow.side,
            src_server: flow.src_server,
            dst_server: flow.dst_server,
            dst_port: flow.dst_port,
            written: flow.written,
            consumed: flow.consumed,
            pending_send: flow.pending_send.clone(),
            pending_write: flow.pending_write.clone(),
            half: flow.half,
        });
        held.push(flow);
    }

    let frontends = carry_frontends(node, &mut carrier);
    let (udp_egress, udp_ingress) = carry_udp(node, &peers, &mut carrier);

    let blob = Blob {
        old_instance: node.restart.instance_id,
        triggered_unix_ms: unix_millis(),
        generation: node.restart.generation + 1,
        node_uuid: node.uuid,
        snapshot: node.index().snapshot().clone(),
        next_frontend_id: crate::node::frontend::next_frontend_id(),
        peers,
        frontends,
        tcp_flows,
        udp_egress,
        udp_ingress,
    };

    node.restart
        .counters
        .flows_carried
        .fetch_add(blob.tcp_flows.len() as u64, Relaxed);
    node.restart
        .counters
        .bytes_carried
        .fetch_add(blob.carried_bytes() as u64, Relaxed);

    let fds = blob.fds();

    match encode(&blob) {
        Ok(body) => Some(Staged {
            body,
            fds,
            carrier,
            flows: held,
        }),
        Err(err) => {
            tracing::error!("failed to encode the handover blob: {:?}", err);
            carrier.abandon();
            for flow in held {
                flow.kill();
            }
            None
        }
    }
}

fn carry_frontends(node: &Arc<Node>, carrier: &mut Carrier) -> Vec<FrontendRec> {
    let frontends = node.frontends.lock();

    frontends
        .iter()
        .filter_map(|(key, handle)| {
            let fd = carrier.carry(handle.fd).ok()?;
            Some(FrontendRec {
                fd,
                kind: key.kind,
                frontend_id: handle.id,
                pid: handle.pid,
                src_server: key.src_server,
                dst_server: key.dst_server,
                port: key.port,
            })
        })
        .collect()
}

// only peers with a `PeerRec` are dialled back and resumed; anyone else's records would be
// carried across the exec just for `rebuild` to close them, so their soft state stays put
fn carry_udp(
    node: &Arc<Node>,
    peers: &[PeerRec],
    carrier: &mut Carrier,
) -> (Vec<UdpEgressRec>, Vec<UdpIngressRec>) {
    let mut egress = Vec::new();
    let mut ingress = Vec::new();

    for peer in node.peers.connected() {
        if !peers.iter().any(|p| p.peer == peer) {
            continue;
        }
        let Some(conn) = node.peers.get(&peer) else {
            continue;
        };

        let mut tables = conn.udp.lock();

        for flow in tables.egress.drain_where(|_, _| true) {
            let (frontend_id, client) = flow.key;
            egress.push(UdpEgressRec {
                flow_id: flow.id,
                peer,
                frontend_id,
                client,
                src_server: flow.value.src_server,
                dst_server: flow.value.dst_server,
                dst_port: flow.value.dst_port,
            });
        }

        for flow in tables.ingress.drain_where(|_, _| true) {
            let Ok(fd) = carrier.carry(flow.value.socket.as_raw_fd()) else {
                continue;
            };
            ingress.push(UdpIngressRec {
                fd,
                flow_id: flow.id,
                peer,
                src_server: flow.value.src_server,
                dst_server: flow.value.dst_server,
                dst_port: flow.value.dst_port,
            });
        }
    }

    (egress, ingress)
}

async fn launch(node: &Arc<Node>, staged: Staged) {
    // same-node short circuits carry no flow id and no peer, and a relay that fails to
    // drain is still running; both must be reset rather than closed gracefully by the exec
    let reset = node.relays.cancel_where(|_, _, _, _| true);
    if reset > 0 {
        tracing::warn!(flows = reset, "resetting relays the handover cannot carry");
        tokio::time::sleep(KILL_GRACE).await;
    }

    let Staged {
        body,
        fds,
        carrier,
        flows,
    } = staged;

    let blob_fd = match stage(&body) {
        Ok(fd) => fd,
        Err(err) => {
            tracing::error!("failed to stage the handover blob: {:?}", err);
            return give_up(
                node,
                carrier,
                flows,
                None,
                &fds,
                "the blob could not be staged",
            );
        }
    };

    let Some(binary) = node.restart.binary.clone() else {
        return give_up(
            node,
            carrier,
            flows,
            Some(blob_fd),
            &fds,
            "no binary path to exec; set restart.binary_path",
        );
    };

    let raw: Vec<RawFd> = fds.iter().map(|(fd, _)| *fd).collect();
    let err = exec(&binary, &node.restart.args, blob_fd, &raw);
    tracing::error!(
        binary = %binary.display(),
        "failed to exec, staying on the old image: {:?}",
        err
    );
    node.restart.counters.exec_failed.fetch_add(1, Relaxed);
    give_up(node, carrier, flows, Some(blob_fd), &fds, "execve failed");
}

// the duplicates go first: a socket only resets once its last descriptor is closed, so
// killing the originals while a copy is still open would deliver nothing
fn give_up(
    node: &Arc<Node>,
    carrier: Carrier,
    flows: Vec<FrozenFlow>,
    blob_fd: Option<RawFd>,
    fds: &[Carried],
    why: &str,
) {
    if let Some(blob_fd) = blob_fd {
        let raw: Vec<RawFd> = fds.iter().map(|(fd, _)| *fd).collect();
        restore_cloexec(&raw, blob_fd);
        close_raw(blob_fd);
    }

    carrier.abandon();

    let killed = flows.len() as u64;
    for flow in flows {
        flow.kill();
    }

    node.restart.counters.killed(Killed::ExecFailed, killed);
    abandon(node, why);
}

fn abandon(node: &Arc<Node>, why: &str) {
    tracing::error!(why = %why, "handover abandoned, continuing on this image");

    // closing a drained connection is what makes both nodes start over instead of staying idle
    for peer in node.peers.connected() {
        if let Some(conn) = node.peers.get(&peer)
            && conn.is_draining()
        {
            conn.close(CloseCode::Shutdown);
        }
    }

    node.gate.resume_all();
    node.restart.with_pending(|report| {
        let mut report = std::mem::take(report);
        report.unix = crate::metrics::unix_now();
        report.pause_ms = node.restart.pause_ms();
        report.flows_killed = node.restart.counters.killed_total();
        node.restart.record(report);
    });

    node.restart.finish();
}

pub async fn signal_loop(node: Arc<Node>) {
    let mut signals =
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined2()) {
            Ok(s) => s,
            Err(err) => {
                tracing::error!(
                    "failed to listen for SIGUSR2, in-place restart is unavailable: {:?}",
                    err
                );
                return;
            }
        };

    while signals.recv().await.is_some() {
        tracing::info!("received SIGUSR2");
        tokio::spawn(run(Arc::clone(&node)));
    }
}
