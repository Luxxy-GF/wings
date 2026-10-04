use crate::node::{
    FrontendHandle, Node,
    frontend::binder::Kind,
    ingress::{DIAL_TIMEOUT, dial_target},
    plan::{FrontendKey, desired_frontends},
    quic::conn::write_frame,
    relay::{
        flows::{Side, TcpFlowGuard},
        tcp::{ByteCounters, Outcome, Prelude, relay_local, relay_stream},
        udp::{
            EgressFlow, LOCAL_SEND_QUEUE, UDP_RECV_BUF, container_writer, frontend_writer,
            next_group, send_payload,
        },
    },
    restart::resume::{AdoptedFrontend, Bound},
};
use std::{
    collections::HashMap,
    net::{SocketAddr, SocketAddrV4},
    os::fd::AsRawFd,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering::Relaxed},
    },
    time::{Duration, Instant},
};
use tokio::{
    net::{TcpListener, TcpStream, UdpSocket},
    sync::watch,
};
use tundra_common::{
    admit::{Transport, admit},
    frag::FragReassembler,
    state::{SnapshotIndex, frontend_ip},
    wire::{ControlMsg, FlowOpen, StreamHeader},
};

pub mod binder;

const LOCAL_UDP_IDLE: Duration = Duration::from_secs(60);
const LOCAL_UDP_GC: Duration = Duration::from_secs(10);
const MAX_LOCAL_FLOWS: usize = 512;
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

static FRONTEND_IDS: AtomicU64 = AtomicU64::new(0);

#[inline]
pub fn next_frontend_id() -> u64 {
    FRONTEND_IDS.load(Relaxed)
}

pub async fn reconcile(node: &Arc<Node>, index: &SnapshotIndex) {
    let desired = desired_frontends(index, &node.uuid);

    let current: Vec<(FrontendKey, i32)> = node
        .frontends
        .lock()
        .iter()
        .map(|(key, handle)| (*key, handle.pid))
        .collect();

    let mut stale = Vec::new();
    for (key, pid) in current {
        let moved = node
            .container_of(&key.src_server)
            .is_some_and(|c| c.pid != pid);
        if desired.contains(&key) && !moved {
            continue;
        }

        stale.push(key);
    }

    for key in stale {
        unbind(node, &key);
    }

    for key in desired {
        if node.frontends.lock().contains_key(&key) {
            continue;
        }

        if node.container_of(&key.src_server).is_none() {
            continue;
        }

        match bind(node, key).await {
            Ok(handle) => {
                let current = node.container_of(&key.src_server).map(|c| c.pid);
                if current == Some(handle.pid) {
                    node.frontends.lock().insert(key, handle);
                } else {
                    tracing::debug!(
                        src = %key.src_server,
                        "container changed while binding, discarding the frontend"
                    );
                }
            }
            Err(err) => tracing::warn!(
                src = %key.src_server,
                dst = %key.dst_server,
                port = key.port,
                kind = %key.kind.to_str(),
                "failed to bind a frontend: {:?}",
                err
            ),
        }
    }

    node.metrics
        .frontends
        .store(node.frontends.lock().len() as u64, Relaxed);
}

pub fn unbind_server(node: &Arc<Node>, server: &uuid::Uuid) {
    let keys = {
        let current = node.frontends.lock();
        let mut keys = Vec::new();
        for key in current.keys() {
            if key.src_server != *server {
                continue;
            }

            keys.push(*key);
        }

        keys
    };

    for key in &keys {
        unbind(node, key);
    }

    if !keys.is_empty() {
        tracing::info!(
            server = %server,
            frontends = keys.len(),
            "released frontends"
        );
    }
}

fn unbind(node: &Arc<Node>, key: &FrontendKey) {
    let handle = node.frontends.lock().remove(key);
    let Some(handle) = handle else {
        return;
    };

    for peer in node.peers.connected() {
        let Some(conn) = node.peers.get(&peer) else {
            continue;
        };

        let dropped = conn
            .udp
            .lock()
            .egress
            .drain_where(|(frontend, _), _| *frontend == handle.id)
            .len();
        if dropped > 0 {
            tracing::debug!(
                peer = %peer,
                flows = dropped,
                "released egress flows with their frontend"
            );
        }
    }

    tracing::debug!(
        src = %key.src_server,
        dst = %key.dst_server,
        port = key.port,
        kind = %key.kind.to_str(),
        "frontend released"
    );
}

async fn bind(node: &Arc<Node>, key: FrontendKey) -> Result<FrontendHandle, anyhow::Error> {
    let index = node.index();
    let Some(dst) = index.server(&key.dst_server) else {
        return Err(anyhow::anyhow!("the destination server vanished"));
    };
    let Some(ip) = frontend_ip(dst.idx) else {
        return Err(anyhow::anyhow!("the server index has no loopback address"));
    };
    let Some(target) = node.target_of(&key.src_server) else {
        return Err(anyhow::anyhow!("the container is not running"));
    };

    let addr = SocketAddrV4::new(ip, key.port);
    let id = FRONTEND_IDS.fetch_add(1, Relaxed);
    let pid = target.pid;

    let bound = match key.kind {
        Kind::Tcp => Bound::Tcp(binder::bind_tcp(Arc::clone(&node.binder), target, addr).await?),
        Kind::Udp => Bound::Udp(Arc::new(
            binder::bind_udp(Arc::clone(&node.binder), target, addr).await?,
        )),
    };

    tracing::info!(
        src = %key.src_server,
        dst = %key.dst_server,
        addr = %addr,
        kind = %key.kind.to_str(),
        "frontend bound"
    );

    Ok(spawn(node, key, id, pid, bound))
}

pub fn adopt(node: &Arc<Node>, adopted: Vec<AdoptedFrontend>, next_id: u64) {
    FRONTEND_IDS.fetch_max(next_id, Relaxed);

    let mut installed = 0;
    for frontend in adopted {
        let AdoptedFrontend {
            key,
            id,
            pid,
            bound,
        } = frontend;

        let handle = spawn(node, key, id, pid, bound);
        node.frontends.lock().insert(key, handle);
        installed += 1;
    }

    node.metrics
        .frontends
        .store(node.frontends.lock().len() as u64, Relaxed);

    if installed > 0 {
        tracing::info!(
            frontends = installed,
            "adopted frontends from the previous image"
        );
    }
}

fn spawn(node: &Arc<Node>, key: FrontendKey, id: u64, pid: i32, bound: Bound) -> FrontendHandle {
    let (cancel, rx) = watch::channel(false);

    let (fd, replies, tasks) = match bound {
        Bound::Tcp(listener) => {
            let fd = listener.as_raw_fd();

            (
                fd,
                None,
                vec![tokio::spawn(tcp_loop(Arc::clone(node), key, listener, rx))],
            )
        }
        Bound::Udp(socket) => {
            let fd = socket.as_raw_fd();
            let (replies, reply_rx) = tokio::sync::mpsc::channel(LOCAL_SEND_QUEUE);
            let tasks = vec![
                tokio::spawn(frontend_writer(Arc::clone(&socket), reply_rx)),
                tokio::spawn(udp_loop(
                    Arc::clone(node),
                    key,
                    id,
                    socket,
                    replies.clone(),
                    rx,
                )),
            ];

            (fd, Some(replies), tasks)
        }
    };

    FrontendHandle::new(id, pid, fd, replies, cancel, tasks)
}

async fn tcp_loop(
    node: Arc<Node>,
    key: FrontendKey,
    listener: TcpListener,
    mut cancel: watch::Receiver<bool>,
) {
    let mut gate = node.gate.subscribe();
    loop {
        if let Some(peer) = node.index().server(&key.dst_server).map(|s| s.node_uuid)
            && node.gate.paused(&peer)
        {
            tokio::select! {
                _ = node.gate.wait_open(&peer, &mut gate) => {}
                _ = crate::node::relay::cancelled(&mut cancel) => return,
            }
            continue;
        }

        tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok((tcp, from)) => {
                    tokio::spawn({
                        let node = Arc::clone(&node);

                        async move { egress_tcp(node, key, tcp, from).await }
                    });
                }
                Err(err) => {
                    tracing::warn!("failed to accept on a frontend: {}", err);
                    tokio::time::sleep(ACCEPT_BACKOFF).await;
                }
            },
            _ = crate::node::relay::cancelled(&mut cancel) => return,
        }
    }
}

async fn egress_tcp(node: Arc<Node>, key: FrontendKey, tcp: TcpStream, from: SocketAddr) {
    let _ = tcp.set_nodelay(true);

    let index = node.index();
    let Some(dst) = index.server(&key.dst_server) else {
        return;
    };

    if let Err(code) = admit(
        &index,
        &node.uuid,
        &dst.node_uuid,
        &key.src_server,
        &key.dst_server,
        key.port,
        Transport::Tcp,
    ) {
        tracing::debug!(
            src = %key.src_server,
            dst = %key.dst_server,
            reason = %code.to_str(),
            "refusing a connection"
        );
        return;
    }

    if dst.node_uuid == node.uuid {
        let Some(target) = dial_target(&node, &key.dst_server, key.port) else {
            return;
        };

        let Ok(_permit) = Arc::clone(&node.local_slots).try_acquire_owned() else {
            tracing::warn!(
                src = %key.src_server,
                dst = %key.dst_server,
                "local stream budget exhausted, refusing a connection"
            );
            return;
        };
        let (_guard, cancel) =
            node.relays
                .register(key.src_server, key.dst_server, key.port, Transport::Tcp);

        let backend = match tokio::time::timeout(DIAL_TIMEOUT, TcpStream::connect(target)).await {
            Ok(Ok(s)) => s,
            Ok(Err(err)) => {
                tracing::debug!(
                    target = %target,
                    "failed to dial the local backend: {:?}",
                    err
                );
                return;
            }
            Err(_) => {
                tracing::debug!(
                    target = %target,
                    "local backend dial timed out"
                );
                return;
            }
        };
        let _ = backend.set_nodelay(true);

        if let Err(code) = admit(
            &node.index(),
            &node.uuid,
            &node.uuid,
            &key.src_server,
            &key.dst_server,
            key.port,
            Transport::Tcp,
        ) {
            tracing::debug!(
                src = %key.src_server,
                dst = %key.dst_server,
                reason = %code.to_str(),
                "access withdrawn while dialling"
            );
            return;
        }
        node.metrics.local_streams_total.fetch_add(1, Relaxed);

        let outcome = relay_local(tcp, backend, cancel).await;
        if !matches!(outcome, Outcome::Closed) {
            tracing::debug!(
                outcome = %outcome,
                "local relay ended"
            );
        }

        return;
    }

    let Some(conn) = node.ensure_peer(dst.node_uuid).await else {
        tracing::debug!(
            peer = %dst.node_uuid,
            from = %from,
            "no connection to the destination node"
        );
        return;
    };

    if conn.is_draining() {
        tracing::debug!(
            peer = %conn.peer,
            "not opening a relay into a draining connection"
        );
        return;
    }

    let Ok(_permit) = Arc::clone(&conn.stream_slots).try_acquire_owned() else {
        tracing::warn!(
            peer = %conn.peer,
            "stream budget exhausted, refusing a connection"
        );
        return;
    };

    let registered = conn
        .tcp
        .lock()
        .open(Side::Frontend, key.src_server, key.dst_server, key.port);
    let (flow, ctl) = match registered {
        Ok(pair) => pair,
        Err(err) => {
            tracing::warn!(
                peer = %conn.peer,
                "failed to register an outbound relay flow: {}",
                err
            );
            return;
        }
    };

    let _flow_guard = TcpFlowGuard::new(Arc::clone(&conn.tcp), Arc::clone(&flow));

    let (_guard, cancel) =
        node.relays
            .register(key.src_server, key.dst_server, key.port, Transport::Tcp);

    let Ok((mut send, recv)) = conn.conn.open_bi().await else {
        return;
    };

    let header = StreamHeader::Open(FlowOpen {
        flow_id: flow.id,
        src_server: key.src_server,
        dst_server: key.dst_server,
        dst_port: key.port,
    });
    if write_frame(&mut send, &header).await.is_err() {
        return;
    }
    if let Err(code) = admit(
        &node.index(),
        &node.uuid,
        &dst.node_uuid,
        &key.src_server,
        &key.dst_server,
        key.port,
        Transport::Tcp,
    ) {
        tracing::debug!(
            src = %key.src_server,
            dst = %key.dst_server,
            reason = %code.to_str(),
            "access withdrawn while opening the stream"
        );
        return;
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
            outcome = %outcome,
            "outbound relay ended"
        );
    }
}

struct LocalFlow {
    to_backend: tokio::sync::mpsc::Sender<Vec<u8>>,
    reader: tokio::task::AbortHandle,
    writer: tokio::task::AbortHandle,
    last: Instant,
    target: SocketAddr,
}

impl Drop for LocalFlow {
    fn drop(&mut self) {
        self.reader.abort();
        self.writer.abort();
    }
}

async fn udp_loop(
    node: Arc<Node>,
    key: FrontendKey,
    id: u64,
    socket: Arc<UdpSocket>,
    replies: tokio::sync::mpsc::Sender<(Vec<u8>, SocketAddr)>,
    mut cancel: watch::Receiver<bool>,
) {
    let mut buf = vec![0; UDP_RECV_BUF];
    let mut local: HashMap<SocketAddr, LocalFlow> = HashMap::new();
    let mut gc = tokio::time::interval(LOCAL_UDP_GC);

    loop {
        tokio::select! {
            received = socket.recv_from(&mut buf) => match received {
                Ok((n, from)) => {
                    let Some(payload) = buf.get(..n) else { continue };
                    egress_udp(&node, key, id, &replies, from, payload, &mut local).await;
                }
                Err(err) => {
                    tracing::debug!("failed to receive on a frontend: {}", err);
                    tokio::time::sleep(ACCEPT_BACKOFF).await;
                }
            },
            _ = gc.tick() => {
                let now = Instant::now();
                let before = local.len();

                let current = crate::node::ingress::dial_target(&node, &key.dst_server, key.port);
                local.retain(|_, f| {
                    now.duration_since(f.last) < LOCAL_UDP_IDLE && current == Some(f.target)
                });
                node.metrics
                    .local_flows_open
                    .fetch_sub((before - local.len()) as u64, Relaxed);
            },
            _ = crate::node::relay::cancelled(&mut cancel) => {
                node.metrics
                    .local_flows_open
                    .fetch_sub(local.len() as u64, Relaxed);
                return;
            }
        }
    }
}

async fn egress_udp(
    node: &Arc<Node>,
    key: FrontendKey,
    id: u64,
    replies: &tokio::sync::mpsc::Sender<(Vec<u8>, SocketAddr)>,
    from: SocketAddr,
    payload: &[u8],
    local: &mut HashMap<SocketAddr, LocalFlow>,
) {
    let index = node.index();
    if !index.allows(&key.src_server, &key.dst_server) {
        return;
    }

    let Some(dst) = index.server(&key.dst_server) else {
        return;
    };

    if dst.node_uuid == node.uuid {
        local_udp(node, key, replies, from, payload, local).await;
        return;
    }

    let Some(conn) = node.peers.get(&dst.node_uuid) else {
        let peer = dst.node_uuid;
        tokio::spawn({
            let node = Arc::clone(node);

            async move { node.ensure_peer(peer).await }
        });

        return;
    };

    let opened;
    let (flow_id, group) = {
        let mut udp = conn.udp.lock();
        let now = Instant::now();
        match udp.egress.by_key(&(id, from), now) {
            Some((flow_id, flow)) => {
                opened = false;
                (flow_id, next_group(&mut flow.group))
            }
            None => {
                let flow = EgressFlow {
                    replies: replies.clone(),
                    client: from,
                    src_server: key.src_server,
                    dst_server: key.dst_server,
                    dst_port: key.port,
                    reasm: FragReassembler::new(),
                    group: 1,
                };
                match udp.egress.open((id, from), flow, now) {
                    Ok(flow_id) => {
                        opened = true;
                        (flow_id, 0)
                    }
                    Err(err) => {
                        tracing::debug!(
                            peer = %conn.peer,
                            "failed to open a new egress flow: {}",
                            err
                        );
                        return;
                    }
                }
            }
        }
    };

    if opened {
        conn.try_control(ControlMsg::FlowOpen(FlowOpen {
            flow_id,
            src_server: key.src_server,
            dst_server: key.dst_server,
            dst_port: key.port,
        }));
    }

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

async fn local_udp(
    node: &Arc<Node>,
    key: FrontendKey,
    replies: &tokio::sync::mpsc::Sender<(Vec<u8>, SocketAddr)>,
    from: SocketAddr,
    payload: &[u8],
    local: &mut HashMap<SocketAddr, LocalFlow>,
) {
    let target = dial_target(node, &key.dst_server, key.port);

    if let Some(flow) = local.get_mut(&from) {
        if target == Some(flow.target) {
            if flow.to_backend.try_send(payload.to_vec()).is_ok() {
                flow.last = Instant::now();
            } else {
                node.metrics.local_drops.fetch_add(1, Relaxed);
            }

            return;
        }

        local.remove(&from);
        node.metrics.local_flows_open.fetch_sub(1, Relaxed);
    }

    if local.len() >= MAX_LOCAL_FLOWS {
        node.metrics.local_drops.fetch_add(1, Relaxed);
        return;
    }

    let Some(target) = target else {
        return;
    };

    let bind: SocketAddr = if target.is_ipv4() {
        "0.0.0.0:0"
            .parse()
            .expect("failed to parse the ipv4 wildcard bind address")
    } else {
        "[::]:0"
            .parse()
            .expect("failed to parse the ipv6 wildcard bind address")
    };

    let Ok(socket) = UdpSocket::bind(bind).await else {
        return;
    };

    if socket.connect(target).await.is_err() {
        return;
    }

    let socket = Arc::new(socket);
    let reply = tokio::spawn(local_udp_reader(
        Arc::clone(&socket),
        replies.clone(),
        from,
        Arc::clone(&node.metrics),
    ));

    let (to_backend, rx) = tokio::sync::mpsc::channel(LOCAL_SEND_QUEUE);
    let writer = tokio::spawn(container_writer(socket, rx));

    if to_backend.try_send(payload.to_vec()).is_err() {
        node.metrics.local_drops.fetch_add(1, Relaxed);
    }

    local.insert(
        from,
        LocalFlow {
            to_backend,
            reader: reply.abort_handle(),
            writer: writer.abort_handle(),
            last: Instant::now(),
            target,
        },
    );

    node.metrics.local_flows_open.fetch_add(1, Relaxed);
}

async fn local_udp_reader(
    socket: Arc<UdpSocket>,
    replies: tokio::sync::mpsc::Sender<(Vec<u8>, SocketAddr)>,
    client: SocketAddr,
    metrics: Arc<crate::metrics::Metrics>,
) {
    let mut buf = vec![0; UDP_RECV_BUF];
    while let Ok(n) = socket.recv(&mut buf).await {
        let Some(payload) = buf.get(..n) else {
            continue;
        };

        if replies.try_send((payload.to_vec(), client)).is_err() {
            tracing::debug!(
                client = %client,
                "dropping a local reply, the frontend queue is full"
            );
            metrics.local_drops.fetch_add(1, Relaxed);
        }
    }
}

pub async fn on_container_event(node: &Arc<Node>, id: &str, name: Option<&str>, started: bool) {
    let index = node.index();
    let mut affected = Vec::new();
    for server in index.servers_on(&node.uuid) {
        if !adopts(node, &index, server, id, name) {
            continue;
        }

        affected.push(*server);
    }

    if affected.is_empty() {
        return;
    }

    for server in &affected {
        unbind_server(node, server);
    }

    if !started {
        tracing::info!(
            container = %id,
            servers = affected.len(),
            "container died, frontends released"
        );
        {
            let mut containers = node.containers.lock();
            for server in &affected {
                containers.remove(server);
            }
        }

        drain_container_flows(node, &affected);
        return;
    }

    tracing::info!(
        container = %id,
        servers = affected.len(),
        "container started, rebinding"
    );
    node.reconcile_local().await;
}

/// Docker's IPAM can hand a dead container's address to the next container it starts, so a
/// flow that keeps its connected socket would deliver another server's traffic to whoever
/// inherits the address.
fn drain_container_flows(node: &Arc<Node>, affected: &[uuid::Uuid]) {
    let cancelled = node
        .relays
        .cancel_where(|src, dst, _, _| affected.contains(src) || affected.contains(dst));
    if cancelled > 0 {
        tracing::info!(flows = cancelled, "reset relays of a dead container");
    }

    for peer in node.peers.connected() {
        let Some(conn) = node.peers.get(&peer) else {
            continue;
        };

        let dropped = {
            let mut udp = conn.udp.lock();
            let ingress = udp
                .ingress
                .drain_where(|_, f| affected.contains(&f.dst_server))
                .len();
            let egress = udp
                .egress
                .drain_where(|_, f| affected.contains(&f.src_server))
                .len();
            ingress + egress
        };
        if dropped > 0 {
            tracing::info!(
                peer = %peer,
                flows = dropped,
                "dropped flows of a dead container"
            );
        }

        conn.refresh_flow_metrics();
    }
}

fn adopts(
    node: &Arc<Node>,
    index: &SnapshotIndex,
    server: &uuid::Uuid,
    id: &str,
    name: Option<&str>,
) -> bool {
    let Some(entry) = index.server(server) else {
        return false;
    };

    let reference = entry.container_ref.as_str();

    reference == id
        || Some(reference) == name
        || (reference.len() >= 12 && id.starts_with(reference))
        || node.container_of(server).is_some_and(|c| c.id == id)
}
