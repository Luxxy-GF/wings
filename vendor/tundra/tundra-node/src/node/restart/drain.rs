use crate::node::{
    Node,
    quic::conn::{DrainMsg, PeerConn},
    relay::{
        flows::TcpFlow,
        tcp::{Frozen, kill_frozen},
    },
    restart::{
        DRAIN_PER_CONNECTION, Killed, MAX_CARRIED_FLOWS, WORST_CASE_PER_FLOW, frozen::FrozenFlow,
    },
};
use std::{
    collections::HashMap,
    io::ErrorKind,
    sync::{Arc, atomic::Ordering::Relaxed},
    time::{Duration, Instant},
};
use tokio::{net::TcpStream, sync::mpsc};
use tundra_common::{
    codes::{CloseCode, StreamCode},
    wire::{ControlMsg, DRAIN_CHUNK, FlowTotal},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerOutcomeKind {
    Drained,
    Timeout,
    Concurrent,
}

impl PeerOutcomeKind {
    #[inline]
    pub fn to_str(self) -> &'static str {
        match self {
            Self::Drained => "drained",
            Self::Timeout => "timeout",
            Self::Concurrent => "concurrent",
        }
    }
}

#[derive(Debug)]
pub struct PeerDrain {
    pub peer: uuid::Uuid,
    pub outcome: PeerOutcomeKind,
    pub parity_even: bool,
    pub flows: Vec<FrozenFlow>,
}

pub async fn drain_peer(node: Arc<Node>, conn: Arc<PeerConn>, budget: Duration) -> PeerDrain {
    let peer = conn.peer;
    let parity_even = conn.parity == tundra_common::flow::Parity::Even;
    let give_up = |outcome| PeerDrain {
        peer,
        outcome,
        parity_even,
        flows: Vec::new(),
    };

    if !conn.begin_drain() {
        tracing::warn!(peer = %peer, "this connection is already draining");
        return give_up(PeerOutcomeKind::Concurrent);
    }

    let mut mailbox = conn.drain_mailbox().await;
    let deadline = Instant::now() + budget.min(DRAIN_PER_CONNECTION);

    // frozen first, then announced: a relay that closes on its own during the freeze must not
    // appear in the totals, or the peer holds a phantom flow open until its resume deadline
    let mut frozen = freeze_all(&node, &conn, deadline).await;
    node.restart
        .counters
        .flows_frozen
        .fetch_add(frozen.len() as u64, Relaxed);
    tracing::info!(
        peer = %peer,
        flows = frozen.len(),
        "relays frozen, announcing the drain"
    );

    let ours: Vec<_> = frozen.values().map(|(flow, _)| flow.total()).collect();
    if !send_totals(&conn, &ours, true, deadline).await {
        kill_all(&node, frozen, StreamCode::DrainFailed, Killed::Deadline);
        return give_up(PeerOutcomeKind::Timeout);
    }

    let theirs = match collect(&mut mailbox, deadline, Want::Ready).await {
        Collected::Totals(totals) => totals,
        Collected::PeerRestarting => {
            tracing::warn!(
                peer = %peer,
                "the peer is restarting at the same time, neither side can carry"
            );
            kill_all(&node, frozen, StreamCode::DrainFailed, Killed::Unmatched);
            return give_up(PeerOutcomeKind::Concurrent);
        }
        Collected::Nothing => {
            kill_all(&node, frozen, StreamCode::DrainFailed, Killed::Deadline);
            return give_up(PeerOutcomeKind::Timeout);
        }
    };

    reconcile(&node, &mut frozen, &theirs, deadline).await;

    if !matches!(
        collect(&mut mailbox, deadline, Want::Complete).await,
        Collected::Totals(_)
    ) {
        tracing::warn!(peer = %peer, "the peer never confirmed it consumed our bytes");
        kill_all(&node, frozen, StreamCode::DrainFailed, Killed::Deadline);
        return give_up(PeerOutcomeKind::Timeout);
    }

    // `finish` rather than `reset`: a reset discards data the peer has received but not read
    let flows = frozen
        .into_iter()
        .map(|(id, (flow, mut f))| {
            let _ = f.send.finish();
            FrozenFlow::from_drained(
                id,
                flow.side,
                flow.src_server,
                flow.dst_server,
                flow.dst_port,
                f,
            )
        })
        .collect::<Vec<_>>();

    conn.close(CloseCode::Restarting);
    tracing::info!(peer = %peer, flows = flows.len(), "drained");

    PeerDrain {
        peer,
        outcome: PeerOutcomeKind::Drained,
        parity_even,
        flows,
    }
}

pub async fn serve_drain(node: Arc<Node>, conn: Arc<PeerConn>) {
    let peer = conn.peer;
    let mut mailbox = conn.drain_mailbox().await;
    let deadline = Instant::now() + DRAIN_PER_CONNECTION;

    let Collected::Totals(theirs) = collect(&mut mailbox, deadline, Want::Start).await else {
        tracing::warn!(
            peer = %peer,
            "a peer began a drain and never finished announcing it"
        );
        conn.close(CloseCode::Shutdown);
        return;
    };

    node.gate.pause_peer(peer);
    node.peers.suppress_dial(peer);

    let mut frozen = freeze_all(&node, &conn, deadline).await;
    node.restart
        .counters
        .flows_frozen
        .fetch_add(frozen.len() as u64, Relaxed);

    // anything the restarting node did not name would be held for a resume that never claims it
    let named: std::collections::HashSet<_> = theirs.keys().copied().collect();
    let dropped: Vec<_> = frozen
        .keys()
        .filter(|id| !named.contains(id))
        .copied()
        .collect();
    for id in dropped {
        if let Some((_, f)) = frozen.remove(&id) {
            kill_frozen(f, StreamCode::DrainFailed);
            node.restart.counters.killed(Killed::Unmatched, 1);
        }
    }

    let ours: Vec<_> = frozen.values().map(|(flow, _)| flow.total()).collect();
    if !send_totals(&conn, &ours, false, deadline).await {
        return give_up_serving(&node, &conn, frozen);
    }

    reconcile(&node, &mut frozen, &theirs, deadline).await;

    if !post(&conn, ControlMsg::DrainComplete, deadline).await {
        return give_up_serving(&node, &conn, frozen);
    }

    let flows: Vec<_> = frozen
        .into_iter()
        .map(|(id, (flow, mut f))| {
            let _ = f.send.finish();
            FrozenFlow::from_drained(
                id,
                flow.side,
                flow.src_server,
                flow.dst_server,
                flow.dst_port,
                f,
            )
        })
        .collect();

    // the hold stays on: resume's claim, or release_expired, is what lifts it
    tracing::info!(
        peer = %peer,
        flows = flows.len(),
        "holding relays while the peer restarts"
    );
    node.frozen.park(
        peer,
        conn.parity,
        Instant::now() + node.restart.peer_resume_timeout,
        flows,
    );
}

fn give_up_serving(
    node: &Arc<Node>,
    conn: &Arc<PeerConn>,
    frozen: HashMap<u64, (Arc<TcpFlow>, Frozen)>,
) {
    kill_all(node, frozen, StreamCode::DrainFailed, Killed::Deadline);
    node.gate.resume_peer(&conn.peer);
    node.peers.unsuppress_dial(&conn.peer);
    conn.close(CloseCode::Shutdown);
}

async fn freeze_all(
    node: &Arc<Node>,
    conn: &Arc<PeerConn>,
    deadline: Instant,
) -> HashMap<u64, (Arc<TcpFlow>, Frozen)> {
    let mut live: Vec<Arc<TcpFlow>> = {
        let tcp = conn.tcp.lock();
        tcp.ids().into_iter().filter_map(|id| tcp.get(id)).collect()
    };

    // the cap is applied here rather than at assembly: a frozen relay can hold an interrupted
    // write in each direction, so by then the memory is already spent
    live.sort_by_key(|f| f.id);
    if live.len() > MAX_CARRIED_FLOWS {
        let dropped = live.split_off(MAX_CARRIED_FLOWS);
        tracing::warn!(
            peer = %conn.peer,
            flows = dropped.len(),
            cap = MAX_CARRIED_FLOWS,
            "over the handover budget, these relays will reset with the connection"
        );
        node.restart
            .counters
            .killed(Killed::Budget, dropped.len() as u64);
    }

    let mut waiting = Vec::new();
    for flow in live {
        flow.freeze();
        if let Some(rx) = flow.claim() {
            waiting.push((flow, rx));
        }
    }

    let mut out = HashMap::new();
    for (flow, rx) in waiting {
        match tokio::time::timeout_at(deadline.into(), rx).await {
            Ok(Ok(frozen)) => {
                out.insert(flow.id, (flow, frozen));
            }
            Ok(Err(_)) => tracing::debug!(
                peer = %conn.peer,
                flow = flow.id,
                "relay ended before it froze"
            ),
            Err(_) => tracing::warn!(
                peer = %conn.peer,
                flow = flow.id,
                "relay did not freeze in time"
            ),
        }
    }

    out
}

async fn reconcile(
    node: &Arc<Node>,
    frozen: &mut HashMap<u64, (Arc<TcpFlow>, Frozen)>,
    theirs: &HashMap<u64, u64>,
    deadline: Instant,
) {
    let ids: Vec<_> = frozen.keys().copied().collect();
    let mut results = Vec::new();
    for id in ids {
        let Some((_, f)) = frozen.get_mut(&id) else {
            continue;
        };

        let target = theirs.get(&id).copied();
        results.push((id, consume_to(f, target, deadline).await));
    }

    for (id, verdict) in results {
        let Err(reason) = verdict else {
            continue;
        };

        if let Some((_, f)) = frozen.remove(&id) {
            tracing::warn!(
                flow = id,
                reason = %reason.to_str(),
                "killing a flow the drain failed to reconcile"
            );
            kill_frozen(f, StreamCode::DrainFailed);
            node.restart.counters.killed(reason.killed(), 1);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DrainFailure {
    TimedOut,
    Anomaly(&'static str),
    OverBudget,
}

impl DrainFailure {
    #[inline]
    fn to_str(self) -> &'static str {
        match self {
            Self::TimedOut => "the peer's bytes did not arrive in time",
            Self::Anomaly(reason) => reason,
            Self::OverBudget => "the flow buffered more than the carry budget",
        }
    }

    #[inline]
    fn killed(self) -> Killed {
        match self {
            Self::TimedOut => Killed::Deadline,
            Self::Anomaly(_) => Killed::Anomaly,
            Self::OverBudget => Killed::Budget,
        }
    }
}

fn check_totals(consumed: u64, target: Option<u64>, rx_done: bool) -> Result<u64, DrainFailure> {
    let target = target.ok_or(DrainFailure::Anomaly("the peer did not report this flow"))?;
    if consumed > target {
        return Err(DrainFailure::Anomaly(
            "we consumed more than the peer submitted",
        ));
    }
    // flow control admits at most one stream window past what is already consumed, so a
    // larger total is a lie that would otherwise set an unreachable drain target; bounded
    // by the largest window per-path sizing can advertise, since the drain cannot know
    // the closing connection's negotiated window
    if target - consumed > u64::from(crate::node::quic::MAX_STREAM_WINDOW) {
        return Err(DrainFailure::Anomaly(
            "the peer claims more in-flight bytes than flow control admits",
        ));
    }
    if consumed < target && rx_done {
        return Err(DrainFailure::Anomaly(
            "the peer submitted bytes after finishing the stream",
        ));
    }

    Ok(target)
}

async fn consume_to(
    frozen: &mut Frozen,
    target: Option<u64>,
    deadline: Instant,
) -> Result<(), DrainFailure> {
    let target = check_totals(frozen.consumed, target, frozen.half.rx_done)?;

    let mut buf = vec![0; crate::node::relay::tcp::RELAY_BUF];
    while frozen.consumed < target {
        let want = (target - frozen.consumed).min(buf.len() as u64) as usize;
        let window = buf
            .get_mut(..want)
            .ok_or(DrainFailure::Anomaly("the drain window exceeds the buffer"))?;
        let read = tokio::time::timeout_at(deadline.into(), frozen.recv.read(window))
            .await
            .map_err(|_| DrainFailure::TimedOut)?;

        match read {
            Ok(Some(n)) => {
                frozen.consumed += n as u64;
                let payload = buf
                    .get(..n)
                    .ok_or(DrainFailure::Anomaly("the stream read past the buffer"))?;
                if !push_now(&frozen.tcp, payload, &mut frozen.pending_write) {
                    return Err(DrainFailure::OverBudget);
                }
            }
            Ok(None) => {
                return Err(DrainFailure::Anomaly(
                    "the stream ended before the peer's total was reached",
                ));
            }
            Err(_) => {
                return Err(DrainFailure::Anomaly(
                    "the stream was reset during the drain",
                ));
            }
        }
    }

    Ok(())
}

/// A container that has stopped reading must not be able to hold the whole handover up, nor
/// buffer past the per-flow share of the carry budget; false means the flow is over budget
/// and nothing is queued.
fn push_now(tcp: &TcpStream, data: &[u8], pending: &mut Vec<u8>) -> bool {
    // order first: the residue is flushed before anything new, so one transient full
    // buffer does not condemn the rest of the drain to accumulate behind it
    let mut flushed = 0;
    while flushed < pending.len() {
        let Some(window) = pending.get(flushed..) else {
            break;
        };
        match tcp.try_write(window) {
            Ok(0) => break,
            Ok(n) => flushed += n,
            Err(err) if err.kind() == ErrorKind::WouldBlock => break,
            Err(_) => break,
        }
    }
    pending.drain(..flushed);

    let mut rest = data;
    if pending.is_empty() {
        while !rest.is_empty() {
            let n = match tcp.try_write(rest) {
                Ok(0) => break,
                Ok(n) => n,
                Err(err) if err.kind() == ErrorKind::WouldBlock => break,
                Err(_) => break,
            };
            let Some(tail) = rest.get(n..) else { break };
            rest = tail;
        }
    }

    if pending.len() + rest.len() > WORST_CASE_PER_FLOW {
        return false;
    }

    pending.extend_from_slice(rest);
    true
}

fn kill_all(
    node: &Arc<Node>,
    frozen: HashMap<u64, (Arc<TcpFlow>, Frozen)>,
    code: StreamCode,
    reason: Killed,
) {
    let n = frozen.len() as u64;
    for (_, (_, f)) in frozen {
        kill_frozen(f, code);
    }

    node.restart.counters.killed(reason, n);
}

/// An empty list is still one frame, because `last` is what ends the sequence.
async fn send_totals(
    conn: &Arc<PeerConn>,
    totals: &[FlowTotal],
    start: bool,
    deadline: Instant,
) -> bool {
    let mut chunks: Vec<&[FlowTotal]> = totals.chunks(DRAIN_CHUNK).collect();
    if chunks.is_empty() {
        chunks.push(&[]);
    }

    let count = chunks.len();

    for (i, chunk) in chunks.into_iter().enumerate() {
        let last = i + 1 == count;
        let msg = if start {
            ControlMsg::DrainStart {
                flows: chunk.to_vec(),
                last,
            }
        } else {
            ControlMsg::DrainReady {
                flows: chunk.to_vec(),
                last,
            }
        };
        if !post(conn, msg, deadline).await {
            return false;
        }
    }

    true
}

/// A stalled peer can stall the control stream too: it shares the relays' flow control.
async fn post(conn: &Arc<PeerConn>, msg: ControlMsg, deadline: Instant) -> bool {
    matches!(
        tokio::time::timeout_at(deadline.into(), conn.send_control(msg)).await,
        Ok(true)
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Want {
    Start,
    Ready,
    Complete,
}

#[derive(Debug, PartialEq, Eq)]
enum Collected {
    Totals(HashMap<u64, u64>),
    PeerRestarting,
    Nothing,
}

async fn collect(
    mailbox: &mut mpsc::Receiver<DrainMsg>,
    deadline: Instant,
    want: Want,
) -> Collected {
    let mut totals = HashMap::new();
    loop {
        let msg = match tokio::time::timeout_at(deadline.into(), mailbox.recv()).await {
            Ok(Some(msg)) => msg,
            Ok(None) | Err(_) => return Collected::Nothing,
        };

        match (want, msg) {
            (Want::Complete, DrainMsg::Complete) => return Collected::Totals(totals),
            (Want::Start, DrainMsg::Start { flows, last })
            | (Want::Ready, DrainMsg::Ready { flows, last }) => {
                for total in flows {
                    // an unreachable target makes `check_totals` kill a twice-reported flow
                    if totals.insert(total.flow_id, total.written).is_some() {
                        totals.insert(total.flow_id, u64::MAX);
                    }
                }
                if totals.len() > MAX_CARRIED_FLOWS {
                    tracing::warn!(
                        flows = totals.len(),
                        cap = MAX_CARRIED_FLOWS,
                        "the peer announced more flows than a carry can hold"
                    );
                    return Collected::Nothing;
                }
                if last {
                    return Collected::Totals(totals);
                }
            }
            (Want::Ready | Want::Complete, DrainMsg::Start { .. }) => {
                return Collected::PeerRestarting;
            }
            (_, other) => tracing::debug!(
                other = ?other,
                want = ?want,
                "ignoring an out-of-phase drain message"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{io::AsyncReadExt, net::TcpListener};

    async fn pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::spawn(async move { TcpStream::connect(addr).await.unwrap() });
        let (server, _) = listener.accept().await.unwrap();
        (client.await.unwrap(), server)
    }

    // push_now

    #[test]
    fn push_now_sends_what_the_socket_takes_and_carries_the_rest() {
        tokio_test::block_on(async {
            let (sender, mut receiver) = pair().await;
            let mut pending = Vec::new();

            assert!(push_now(&sender, b"hello", &mut pending));
            assert!(pending.is_empty());

            let mut buf = [0; 5];
            receiver.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"hello");
        });
    }

    #[test]
    fn push_now_on_a_stalled_socket_never_blocks_and_never_exceeds_the_budget() {
        tokio_test::block_on(async {
            let (sender, receiver) = pair().await;
            let mut pending = Vec::new();

            let chunk = vec![0xab; 256 * 1024];
            let mut refused = false;
            for _ in 0..64 {
                if !push_now(&sender, &chunk, &mut pending) {
                    refused = true;
                    break;
                }
            }
            assert!(refused);
            assert!(pending.len() <= WORST_CASE_PER_FLOW);
            drop(receiver);
        });
    }

    #[test]
    fn push_now_flushes_the_residue_before_new_bytes() {
        tokio_test::block_on(async {
            let (sender, mut receiver) = pair().await;
            let mut pending = b"first".to_vec();

            assert!(push_now(&sender, b"second", &mut pending));
            assert!(pending.is_empty());

            let mut buf = [0; 11];
            receiver.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"firstsecond");
        });
    }

    #[test]
    fn push_now_refuses_to_grow_a_full_pending_buffer() {
        tokio_test::block_on(async {
            let (sender, receiver) = pair().await;
            // stall the socket first, or the residue would simply flush
            let chunk = vec![0xab; 64 * 1024];
            while sender.try_write(&chunk).is_ok() {}

            let mut pending = vec![0xab; WORST_CASE_PER_FLOW];
            assert!(!push_now(&sender, b"one more", &mut pending));
            assert_eq!(pending.len(), WORST_CASE_PER_FLOW);
            drop(receiver);
        });
    }

    // collect

    #[test]
    fn collect_reassembles_chunked_totals_into_one_map() {
        tokio_test::block_on(async {
            let (tx, mut rx) = mpsc::channel(8);
            tx.send(DrainMsg::Ready {
                flows: vec![FlowTotal {
                    flow_id: 0,
                    written: 10,
                }],
                last: false,
            })
            .await
            .unwrap();
            tx.send(DrainMsg::Ready {
                flows: vec![FlowTotal {
                    flow_id: 2,
                    written: 20,
                }],
                last: true,
            })
            .await
            .unwrap();

            let got = collect(
                &mut rx,
                Instant::now() + Duration::from_secs(5),
                Want::Ready,
            )
            .await;
            assert_eq!(got, Collected::Totals(HashMap::from([(0, 10), (2, 20)])));
        });
    }

    #[test]
    fn collect_poisons_a_duplicate_flow_id_rather_than_believing_it() {
        tokio_test::block_on(async {
            let (tx, mut rx) = mpsc::channel(8);
            tx.send(DrainMsg::Ready {
                flows: vec![
                    FlowTotal {
                        flow_id: 4,
                        written: 10,
                    },
                    FlowTotal {
                        flow_id: 4,
                        written: 99,
                    },
                ],
                last: true,
            })
            .await
            .unwrap();

            let got = collect(
                &mut rx,
                Instant::now() + Duration::from_secs(5),
                Want::Ready,
            )
            .await;
            assert_eq!(got, Collected::Totals(HashMap::from([(4, u64::MAX)])));
        });
    }

    #[test]
    fn collect_times_out_on_a_silent_peer() {
        tokio_test::block_on(async {
            let (_tx, mut rx) = mpsc::channel::<DrainMsg>(8);
            let got = collect(
                &mut rx,
                Instant::now() + Duration::from_millis(50),
                Want::Ready,
            )
            .await;
            assert_eq!(got, Collected::Nothing);
        });
    }

    #[test]
    fn collect_ignores_out_of_phase_messages() {
        tokio_test::block_on(async {
            let (tx, mut rx) = mpsc::channel(8);
            tx.send(DrainMsg::Complete).await.unwrap();
            tx.send(DrainMsg::Ready {
                flows: Vec::new(),
                last: true,
            })
            .await
            .unwrap();

            let got = collect(
                &mut rx,
                Instant::now() + Duration::from_secs(5),
                Want::Ready,
            )
            .await;
            assert_eq!(got, Collected::Totals(HashMap::new()));
        });
    }

    #[test]
    fn collect_ends_the_wait_when_the_peer_starts_its_own_drain() {
        tokio_test::block_on(async {
            let (tx, mut rx) = mpsc::channel(8);
            tx.send(DrainMsg::Start {
                flows: Vec::new(),
                last: true,
            })
            .await
            .unwrap();

            let got = collect(
                &mut rx,
                Instant::now() + Duration::from_secs(30),
                Want::Ready,
            )
            .await;
            assert_eq!(got, Collected::PeerRestarting);
        });
    }

    fn ready_chunks(ids: std::ops::Range<u64>, last: bool) -> Vec<DrainMsg> {
        let ids: Vec<u64> = ids.collect();
        let n = ids.chunks(256).len();
        ids.chunks(256)
            .enumerate()
            .map(|(i, chunk)| DrainMsg::Ready {
                flows: chunk
                    .iter()
                    .map(|&flow_id| FlowTotal {
                        flow_id,
                        written: flow_id,
                    })
                    .collect(),
                last: last && i + 1 == n,
            })
            .collect()
    }

    #[test]
    fn collect_accepts_exactly_the_carried_flow_cap_across_chunks() {
        tokio_test::block_on(async {
            let cap = MAX_CARRIED_FLOWS as u64;
            let msgs = ready_chunks(0..cap, true);
            let (tx, mut rx) = mpsc::channel(msgs.len());
            for msg in msgs {
                tx.send(msg).await.unwrap();
            }

            let got = collect(
                &mut rx,
                Instant::now() + Duration::from_secs(5),
                Want::Ready,
            )
            .await;
            assert_eq!(
                got,
                Collected::Totals((0..cap).map(|id| (id, id)).collect())
            );
        });
    }

    #[test]
    fn collect_does_not_count_repeated_flow_ids_toward_the_cap() {
        tokio_test::block_on(async {
            let cap = MAX_CARRIED_FLOWS as u64;
            let mut msgs = ready_chunks(0..cap, false);
            msgs.push(DrainMsg::Ready {
                flows: vec![
                    FlowTotal {
                        flow_id: 0,
                        written: 1,
                    },
                    FlowTotal {
                        flow_id: cap - 1,
                        written: 1,
                    },
                ],
                last: true,
            });
            let (tx, mut rx) = mpsc::channel(msgs.len());
            for msg in msgs {
                tx.send(msg).await.unwrap();
            }

            let got = collect(
                &mut rx,
                Instant::now() + Duration::from_secs(5),
                Want::Ready,
            )
            .await;
            let mut want: HashMap<u64, u64> = (0..cap).map(|id| (id, id)).collect();
            want.insert(0, u64::MAX);
            want.insert(cap - 1, u64::MAX);
            assert_eq!(got, Collected::Totals(want));
        });
    }

    #[test]
    fn collect_gives_up_on_a_peer_announcing_more_than_the_cap_without_waiting() {
        tokio_test::block_on(async {
            let msgs = ready_chunks(0..MAX_CARRIED_FLOWS as u64 + 1, false);
            let (tx, mut rx) = mpsc::channel(msgs.len());
            for msg in msgs {
                tx.send(msg).await.unwrap();
            }

            let got = tokio::time::timeout(
                Duration::from_secs(5),
                collect(
                    &mut rx,
                    Instant::now() + Duration::from_secs(60),
                    Want::Ready,
                ),
            )
            .await
            .expect("collect waited on the deadline instead of enforcing the cap");
            assert_eq!(got, Collected::Nothing);
            drop(tx);
        });
    }

    // check_totals

    #[test]
    fn check_totals_rejects_every_way_the_two_ends_can_disagree() {
        assert!(check_totals(5, None, false).is_err());
        assert!(check_totals(9, Some(5), false).is_err());
        assert!(check_totals(1, Some(5), true).is_err());
        // a poisoned duplicate total shows up as an impossible target
        assert!(check_totals(0, Some(u64::MAX), true).is_err());

        assert_eq!(check_totals(5, Some(5), true), Ok(5));
        assert_eq!(check_totals(5, Some(5), false), Ok(5));
        assert_eq!(check_totals(1, Some(5), false), Ok(5));
        assert_eq!(check_totals(0, Some(0), false), Ok(0));
    }

    #[test]
    fn check_totals_rejects_a_target_flow_control_could_never_admit() {
        let window = u64::from(crate::node::quic::MAX_STREAM_WINDOW);

        assert!(check_totals(0, Some(u64::MAX), false).is_err());
        assert!(check_totals(0, Some(window + 1), false).is_err());
        assert!(check_totals(10, Some(window + 11), false).is_err());

        assert_eq!(check_totals(0, Some(window), false), Ok(window));
        assert_eq!(check_totals(10, Some(window + 10), false), Ok(window + 10));
    }
}
