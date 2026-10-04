use crate::node::relay::{
    flows::Side,
    tcp::{Frozen, kill_socket},
};
use std::{
    collections::{HashMap, HashSet},
    time::Instant,
};
use tokio::net::TcpStream;
use tundra_common::{flow::Parity, wire::HalfClose};

/// The two ends must agree on the surviving set exactly, or a flow id could later be reused.
pub fn split_unclaimed(held: &mut FrozenPeer, claimed: &HashSet<u64>) -> Vec<FrozenFlow> {
    let unclaimed: Vec<_> = held
        .flows
        .keys()
        .filter(|id| !claimed.contains(id))
        .copied()
        .collect();

    unclaimed
        .into_iter()
        .filter_map(|id| held.flows.remove(&id))
        .collect()
}

fn kill_all(peer: uuid::Uuid, held: FrozenPeer, why: &str) {
    if held.flows.is_empty() {
        return;
    }

    tracing::warn!(
        peer = %peer,
        flows = held.flows.len(),
        why = %why,
        "killing frozen relays"
    );
    for (_, flow) in held.flows {
        flow.kill();
    }
}

#[derive(Debug)]
pub struct FrozenFlow {
    pub id: u64,
    pub side: Side,

    pub src_server: uuid::Uuid,
    pub dst_server: uuid::Uuid,
    pub dst_port: u16,

    pub written: u64,
    pub consumed: u64,
    pub pending_send: Vec<u8>,
    pub pending_write: Vec<u8>,
    pub half: HalfClose,

    pub tcp: TcpStream,
}

impl FrozenFlow {
    #[inline]
    pub fn from_drained(
        id: u64,
        side: Side,
        src_server: uuid::Uuid,
        dst_server: uuid::Uuid,
        dst_port: u16,
        frozen: Frozen,
    ) -> Self {
        Self {
            id,
            side,
            src_server,
            dst_server,
            dst_port,
            written: frozen.written,
            consumed: frozen.consumed,
            pending_send: frozen.pending_send,
            pending_write: frozen.pending_write,
            half: frozen.half,
            tcp: frozen.tcp,
        }
    }

    #[inline]
    pub fn carried_bytes(&self) -> usize {
        self.pending_send.len() + self.pending_write.len()
    }

    #[inline]
    pub fn kill(self) {
        kill_socket(&self.tcp);
    }
}

#[derive(Debug)]
pub struct FrozenPeer {
    pub parity: Parity,
    pub deadline: Instant,
    pub flows: HashMap<u64, FrozenFlow>,
}

#[derive(Debug, Default)]
pub struct FrozenStore {
    peers: parking_lot::Mutex<HashMap<uuid::Uuid, FrozenPeer>>,
}

impl FrozenStore {
    pub fn park(
        &self,
        peer: uuid::Uuid,
        parity: Parity,
        deadline: Instant,
        flows: Vec<FrozenFlow>,
    ) {
        let flows = flows.into_iter().map(|f| (f.id, f)).collect();
        let displaced = self.peers.lock().insert(
            peer,
            FrozenPeer {
                parity,
                deadline,
                flows,
            },
        );
        if let Some(old) = displaced {
            kill_all(peer, old, "superseded by a second handover");
        }
    }

    #[inline]
    pub fn take(&self, peer: &uuid::Uuid) -> Option<FrozenPeer> {
        self.peers.lock().remove(peer)
    }

    /// The resume announcement and the streams it covers race on separate QUIC streams.
    #[inline]
    pub fn take_flow(&self, peer: &uuid::Uuid, id: u64) -> Option<FrozenFlow> {
        self.peers.lock().get_mut(peer)?.flows.remove(&id)
    }

    pub fn retain(&self, peer: &uuid::Uuid, claimed: &[u64]) -> Vec<FrozenFlow> {
        let claimed: HashSet<u64> = claimed.iter().copied().collect();
        let mut peers = self.peers.lock();
        match peers.get_mut(peer) {
            Some(held) => split_unclaimed(held, &claimed),
            None => Vec::new(),
        }
    }

    #[inline]
    pub fn parity_of(&self, peer: &uuid::Uuid) -> Option<Parity> {
        self.peers.lock().get(peer).map(|p| p.parity)
    }

    #[inline]
    pub fn peers(&self) -> Vec<uuid::Uuid> {
        self.peers.lock().keys().copied().collect()
    }

    #[inline]
    pub fn flows_held(&self) -> usize {
        self.peers.lock().values().map(|p| p.flows.len()).sum()
    }

    pub fn discard(&self, peer: &uuid::Uuid, why: &str) -> usize {
        match self.take(peer) {
            Some(held) => {
                let n = held.flows.len();
                kill_all(*peer, held, why);
                n
            }
            None => 0,
        }
    }

    /// The caller must lift the dial block for the returned peers, or the pair never reconnects.
    pub fn reap(&self, now: Instant) -> (Vec<uuid::Uuid>, usize) {
        let expired: Vec<_> = {
            let mut peers = self.peers.lock();
            let due: Vec<_> = peers
                .iter()
                .filter(|(_, p)| now >= p.deadline)
                .map(|(&peer, _)| peer)
                .collect();
            due.into_iter()
                .filter_map(|peer| peers.remove(&peer).map(|held| (peer, held)))
                .collect()
        };

        let mut killed = 0;
        let mut peers = Vec::with_capacity(expired.len());
        for (peer, held) in expired {
            killed += held.flows.len();
            peers.push(peer);
            kill_all(peer, held, "the peer did not come back in time");
        }

        (peers, killed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::net::TcpListener;

    const PEER: uuid::Uuid = uuid::Uuid::from_u128(9);

    async fn socket() -> TcpStream {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::spawn(async move { TcpStream::connect(addr).await.unwrap() });
        let accepted = listener.accept().await.unwrap();
        // leaked on purpose: dropping the accepted end would close the peer of the socket under test
        std::mem::forget(accepted);
        client.await.unwrap()
    }

    async fn flow(id: u64) -> FrozenFlow {
        FrozenFlow {
            id,
            side: Side::Frontend,
            src_server: uuid::Uuid::from_u128(1),
            dst_server: uuid::Uuid::from_u128(2),
            dst_port: 80,
            written: 0,
            consumed: 0,
            pending_send: Vec::new(),
            pending_write: Vec::new(),
            half: HalfClose::default(),
            tcp: socket().await,
        }
    }

    // FrozenStore

    #[test]
    fn park_hands_a_peer_back_once_and_only_once() {
        tokio_test::block_on(async {
            let store = FrozenStore::default();
            let deadline = Instant::now() + Duration::from_secs(30);
            store.park(
                PEER,
                Parity::Even,
                deadline,
                vec![flow(0).await, flow(2).await],
            );

            assert_eq!(store.parity_of(&PEER), Some(Parity::Even));
            assert_eq!(store.flows_held(), 2);

            let held = store.take(&PEER).unwrap();
            assert_eq!(held.flows.len(), 2);
            assert!(store.parity_of(&PEER).is_none());
            assert!(store.take(&PEER).is_none());
        });
    }

    #[test]
    fn reap_only_takes_what_is_past_its_deadline() {
        tokio_test::block_on(async {
            let store = FrozenStore::default();
            let now = Instant::now();
            store.park(
                PEER,
                Parity::Even,
                now + Duration::from_secs(30),
                vec![flow(0).await],
            );
            store.park(
                uuid::Uuid::from_u128(10),
                Parity::Odd,
                now + Duration::from_secs(1),
                vec![flow(1).await, flow(3).await],
            );

            assert_eq!(store.reap(now), (Vec::new(), 0));
            assert_eq!(
                store.reap(now + Duration::from_secs(2)),
                (vec![uuid::Uuid::from_u128(10)], 2)
            );
            assert!(store.parity_of(&PEER).is_some());
            assert!(store.parity_of(&uuid::Uuid::from_u128(10)).is_none());

            assert_eq!(store.reap(now + Duration::from_secs(31)), (vec![PEER], 1));
            assert_eq!(store.flows_held(), 0);
        });
    }

    #[test]
    fn discard_drops_the_flows_of_a_peer_that_never_resumed() {
        tokio_test::block_on(async {
            let store = FrozenStore::default();
            store.park(
                PEER,
                Parity::Even,
                Instant::now() + Duration::from_secs(30),
                vec![flow(0).await],
            );
            assert_eq!(store.discard(&PEER, "cold start"), 1);
            assert_eq!(store.discard(&PEER, "cold start"), 0);
        });
    }

    // split_unclaimed

    #[test]
    fn split_unclaimed_separates_the_flows_the_resume_never_names() {
        tokio_test::block_on(async {
            let mut held = FrozenPeer {
                parity: Parity::Even,
                deadline: Instant::now(),
                flows: [flow(0).await, flow(2).await, flow(4).await]
                    .into_iter()
                    .map(|f| (f.id, f))
                    .collect(),
            };

            let dropped = split_unclaimed(&mut held, &HashSet::from([0, 4]));
            let mut ids: Vec<_> = dropped.iter().map(|f| f.id).collect();
            ids.sort_unstable();

            assert_eq!(ids, [2]);
            assert_eq!(held.flows.len(), 2);
            assert!(held.flows.contains_key(&0) && held.flows.contains_key(&4));
        });
    }
}
