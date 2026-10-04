use crate::node::relay::tcp::{FlowCtl, Frozen};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering::Relaxed},
    },
};
use tokio::sync::{oneshot, watch};
use tundra_common::{
    flow::{FlowError, Parity},
    wire::FlowTotal,
};

pub const MAX_TCP_FLOWS_PER_CONN: usize = 4096;

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
pub enum Side {
    Frontend,
    Ingress,
}

impl Side {
    #[inline]
    pub fn to_str(self) -> &'static str {
        match self {
            Self::Frontend => "frontend",
            Self::Ingress => "ingress",
        }
    }
}

#[derive(Debug)]
pub struct TcpFlow {
    pub id: u64,
    pub side: Side,

    pub src_server: uuid::Uuid,
    pub dst_server: uuid::Uuid,
    pub dst_port: u16,

    pub written: Arc<AtomicU64>,
    pub consumed: Arc<AtomicU64>,

    freeze: watch::Sender<bool>,
    handback: parking_lot::Mutex<Option<oneshot::Receiver<Frozen>>>,
}

impl TcpFlow {
    #[inline]
    pub fn freeze(&self) {
        let _ = self.freeze.send(true);
    }

    #[inline]
    pub fn claim(&self) -> Option<oneshot::Receiver<Frozen>> {
        self.handback.lock().take()
    }

    #[inline]
    pub fn total(&self) -> FlowTotal {
        FlowTotal {
            flow_id: self.id,
            written: self.written.load(Relaxed),
        }
    }
}

#[derive(Debug)]
pub struct TcpFlows {
    map: HashMap<u64, Arc<TcpFlow>>,
    parity: Parity,
    next: u64,
    capacity: usize,

    rejected_total: u64,
}

impl TcpFlows {
    #[inline]
    pub fn new(parity: Parity, capacity: usize) -> Self {
        Self {
            map: HashMap::new(),
            parity,
            next: u64::from(parity == Parity::Odd),
            capacity,
            rejected_total: 0,
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    #[inline]
    pub fn rejected_total(&self) -> u64 {
        self.rejected_total
    }

    #[inline]
    pub fn ids(&self) -> Vec<u64> {
        self.map.keys().copied().collect()
    }

    #[inline]
    pub fn get(&self, id: u64) -> Option<Arc<TcpFlow>> {
        self.map.get(&id).cloned()
    }

    #[inline]
    pub fn remove_same(&mut self, flow: &Arc<TcpFlow>) {
        if self.map.get(&flow.id).is_some_and(|f| Arc::ptr_eq(f, flow)) {
            self.map.remove(&flow.id);
        }
    }

    pub fn open(
        &mut self,
        side: Side,
        src_server: uuid::Uuid,
        dst_server: uuid::Uuid,
        dst_port: u16,
    ) -> Result<(Arc<TcpFlow>, FlowCtl), FlowError> {
        if self.map.len() >= self.capacity {
            self.rejected_total += 1;
            return Err(FlowError::Full(self.capacity));
        }

        let id = loop {
            let id = self.next;
            self.next = self.next.wrapping_add(2);
            if !self.map.contains_key(&id) {
                break id;
            }
        };

        Ok(self.install(id, side, src_server, dst_server, dst_port))
    }

    /// The id must fall in the peer's half of the id space, or the peer could collide with
    /// a relay this node opened and steer its bytes.
    pub fn adopt(
        &mut self,
        id: u64,
        side: Side,
        src_server: uuid::Uuid,
        dst_server: uuid::Uuid,
        dst_port: u16,
    ) -> Result<(Arc<TcpFlow>, FlowCtl), FlowError> {
        if self.parity.matches(id) {
            self.rejected_total += 1;
            return Err(FlowError::WrongParity(id));
        }
        if !self.map.contains_key(&id) && self.map.len() >= self.capacity {
            self.rejected_total += 1;
            return Err(FlowError::Full(self.capacity));
        }

        Ok(self.install(id, side, src_server, dst_server, dst_port))
    }

    /// The parity rule is deliberately not applied: a resume re-opens streams for flows
    /// from both ends, and each id is validated when it is first created.
    #[allow(clippy::too_many_arguments)]
    pub fn restore(
        &mut self,
        id: u64,
        side: Side,
        src_server: uuid::Uuid,
        dst_server: uuid::Uuid,
        dst_port: u16,
        written: u64,
        consumed: u64,
    ) -> Result<(Arc<TcpFlow>, FlowCtl), FlowError> {
        if !self.map.contains_key(&id) && self.map.len() >= self.capacity {
            self.rejected_total += 1;
            return Err(FlowError::Full(self.capacity));
        }

        let (flow, ctl) = self.install(id, side, src_server, dst_server, dst_port);
        flow.written.store(written, Relaxed);
        flow.consumed.store(consumed, Relaxed);

        Ok((flow, ctl))
    }

    fn install(
        &mut self,
        id: u64,
        side: Side,
        src_server: uuid::Uuid,
        dst_server: uuid::Uuid,
        dst_port: u16,
    ) -> (Arc<TcpFlow>, FlowCtl) {
        let (freeze_tx, freeze_rx) = watch::channel(false);
        let (handback_tx, handback_rx) = oneshot::channel();

        let flow = Arc::new(TcpFlow {
            id,
            side,
            src_server,
            dst_server,
            dst_port,
            written: Arc::new(AtomicU64::new(0)),
            consumed: Arc::new(AtomicU64::new(0)),
            freeze: freeze_tx,
            handback: parking_lot::Mutex::new(Some(handback_rx)),
        });

        let ctl = FlowCtl {
            written: Arc::clone(&flow.written),
            consumed: Arc::clone(&flow.consumed),
            freeze: freeze_rx,
            handback: handback_tx,
        };

        self.map.insert(id, Arc::clone(&flow));

        (flow, ctl)
    }
}

#[derive(Debug)]
pub struct TcpFlowGuard {
    flows: Arc<parking_lot::Mutex<TcpFlows>>,
    flow: Arc<TcpFlow>,
}

impl TcpFlowGuard {
    #[inline]
    pub fn new(flows: Arc<parking_lot::Mutex<TcpFlows>>, flow: Arc<TcpFlow>) -> Self {
        Self { flows, flow }
    }
}

impl Drop for TcpFlowGuard {
    fn drop(&mut self) {
        self.flows.lock().remove_same(&self.flow);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(n: u128) -> uuid::Uuid {
        uuid::Uuid::from_u128(n)
    }

    fn table(parity: Parity) -> TcpFlows {
        TcpFlows::new(parity, 4)
    }

    fn open(t: &mut TcpFlows) -> Result<u64, FlowError> {
        t.open(Side::Frontend, u(1), u(2), 80).map(|(f, _)| f.id)
    }

    // TcpFlows

    #[test]
    fn allocated_ids_respect_parity_and_the_two_ends_never_collide() {
        let mut even = table(Parity::Even);
        let mut odd = table(Parity::Odd);

        let ours: Vec<_> = (0..4).map(|_| open(&mut even).unwrap()).collect();
        let theirs: Vec<_> = (0..4).map(|_| open(&mut odd).unwrap()).collect();

        assert!(ours.iter().all(|id| id.is_multiple_of(2)));
        assert!(theirs.iter().all(|id| !id.is_multiple_of(2)));
        assert!(ours.iter().all(|a| !theirs.contains(a)));
    }

    #[test]
    fn a_full_table_refuses_rather_than_growing() {
        let mut t = table(Parity::Even);
        for _ in 0..4 {
            open(&mut t).unwrap();
        }
        assert_eq!(open(&mut t), Err(FlowError::Full(4)));
        assert_eq!(t.rejected_total(), 1);
        assert_eq!(t.len(), 4);
    }

    #[test]
    fn adopting_an_id_from_our_own_half_is_refused() {
        let mut t = table(Parity::Even);
        assert_eq!(
            t.adopt(2, Side::Ingress, u(1), u(2), 80).err(),
            Some(FlowError::WrongParity(2))
        );
        assert!(t.adopt(3, Side::Ingress, u(1), u(2), 80).is_ok());
    }

    #[test]
    fn a_restore_accepts_either_half_and_carries_the_counters_forward() {
        let mut t = table(Parity::Even);
        let (flow, _ctl) = t
            .restore(3, Side::Frontend, u(1), u(2), 80, 900, 500)
            .unwrap();

        assert_eq!(flow.written.load(Relaxed), 900);
        assert_eq!(flow.consumed.load(Relaxed), 500);
        assert_eq!(flow.total().written, 900);

        let (mine, _) = t.restore(0, Side::Frontend, u(1), u(2), 80, 0, 0).unwrap();
        assert_eq!(mine.id, 0);
        assert_ne!(open(&mut t).unwrap(), 0);
    }

    // TcpFlowGuard

    #[test]
    fn a_guard_only_removes_the_entry_it_registered() {
        let flows = Arc::new(parking_lot::Mutex::new(table(Parity::Even)));
        let (first, _ctl) = flows.lock().open(Side::Frontend, u(1), u(2), 80).unwrap();
        let guard = TcpFlowGuard::new(Arc::clone(&flows), Arc::clone(&first));

        let (replacement, _ctl) = flows
            .lock()
            .restore(first.id, Side::Frontend, u(1), u(2), 80, 0, 0)
            .unwrap();
        drop(guard);

        let live = flows.lock().get(first.id).unwrap();
        assert!(Arc::ptr_eq(&live, &replacement));
    }

    // TcpFlow

    #[test]
    fn a_freeze_is_observable_and_the_handback_is_claimed_once() {
        let mut t = table(Parity::Even);
        let (flow, ctl) = t.open(Side::Frontend, u(1), u(2), 80).unwrap();

        let mut rx = ctl.freeze.clone();
        assert!(!*rx.borrow_and_update());
        flow.freeze();
        assert!(*rx.borrow_and_update());

        assert!(flow.claim().is_some());
        assert!(flow.claim().is_none());
    }
}
