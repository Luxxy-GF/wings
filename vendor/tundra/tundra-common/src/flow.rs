use std::{
    collections::HashMap,
    hash::Hash,
    time::{Duration, Instant},
};

pub const FLOW_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
pub const MAX_EGRESS_FLOWS_PER_CONN: usize = 16 * 1024;
pub const MAX_INGRESS_FLOWS_PER_CONN: usize = 512;
pub const FLOW_UNKNOWN_NOTIFY_INTERVAL: Duration = Duration::from_secs(1);
pub const FLOW_UNKNOWN_TRACKED: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Parity {
    Even,
    Odd,
}

impl Parity {
    #[inline]
    fn first(self) -> u64 {
        match self {
            Self::Even => 0,
            Self::Odd => 1,
        }
    }

    #[inline]
    pub fn matches(self, flow_id: u64) -> bool {
        flow_id.is_multiple_of(2) == matches!(self, Self::Even)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum FlowError {
    Full(usize),
    WrongParity(u64),
}

impl std::fmt::Display for FlowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FlowError::Full(flows) => write!(f, "flow table is full ({flows} flows)"),
            FlowError::WrongParity(id) => {
                write!(f, "flow id {id} is not in the peer's half of the id space")
            }
        }
    }
}

impl std::error::Error for FlowError {}

#[derive(Debug)]
pub struct Flow<K, V> {
    pub id: u64,
    pub key: K,
    pub value: V,
    last: Instant,
}

#[derive(Debug)]
pub struct FlowTable<K, V> {
    by_key: HashMap<K, u64>,
    by_id: HashMap<u64, Flow<K, V>>,

    parity: Parity,
    next: u64,
    idle: Duration,
    capacity: usize,

    opened_total: u64,
    gc_total: u64,
    rejected_total: u64,
}

impl<K: Eq + Hash + Clone, V> FlowTable<K, V> {
    #[inline]
    pub fn new(parity: Parity, idle: Duration, capacity: usize) -> Self {
        Self {
            by_key: HashMap::new(),
            by_id: HashMap::new(),
            parity,
            next: parity.first(),
            idle,
            capacity,
            opened_total: 0,
            gc_total: 0,
            rejected_total: 0,
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }

    #[inline]
    pub fn opened_total(&self) -> u64 {
        self.opened_total
    }

    #[inline]
    pub fn gc_total(&self) -> u64 {
        self.gc_total
    }

    #[inline]
    pub fn rejected_total(&self) -> u64 {
        self.rejected_total
    }

    pub fn open(&mut self, key: K, value: V, now: Instant) -> Result<u64, FlowError> {
        let id = self.alloc()?;
        self.install(id, key, value, now);
        Ok(id)
    }

    /// The id must fall in the peer's half of the id space: accepting one of ours would let
    /// the peer collide with a live egress flow and steer replies meant for a local client.
    pub fn adopt(&mut self, id: u64, key: K, value: V, now: Instant) -> Result<(), FlowError> {
        if self.parity.matches(id) {
            self.rejected_total += 1;
            return Err(FlowError::WrongParity(id));
        }
        if !self.by_id.contains_key(&id) && self.by_id.len() >= self.capacity {
            self.rejected_total += 1;
            return Err(FlowError::Full(self.capacity));
        }

        self.install(id, key, value, now);
        Ok(())
    }

    /// The parity rule is deliberately not applied: a restart carries flows from both halves
    /// of the id space, and each id is validated when it is first created.
    pub fn restore(&mut self, id: u64, key: K, value: V, now: Instant) -> Result<(), FlowError> {
        if !self.by_id.contains_key(&id) && self.by_id.len() >= self.capacity {
            self.rejected_total += 1;
            return Err(FlowError::Full(self.capacity));
        }

        self.install(id, key, value, now);
        Ok(())
    }

    fn alloc(&mut self) -> Result<u64, FlowError> {
        if self.by_id.len() >= self.capacity {
            self.rejected_total += 1;
            return Err(FlowError::Full(self.capacity));
        }

        loop {
            let id = self.next;
            self.next = self.next.wrapping_add(2);
            if !self.by_id.contains_key(&id) {
                return Ok(id);
            }
        }
    }

    fn install(&mut self, id: u64, key: K, value: V, now: Instant) {
        if let Some(old) = self.by_id.remove(&id) {
            self.by_key.remove(&old.key);
        }
        if let Some(old_id) = self.by_key.insert(key.clone(), id) {
            self.by_id.remove(&old_id);
        }

        self.by_id.insert(
            id,
            Flow {
                id,
                key,
                value,
                last: now,
            },
        );
        self.opened_total += 1;
    }

    pub fn by_key(&mut self, key: &K, now: Instant) -> Option<(u64, &mut V)> {
        let id = *self.by_key.get(key)?;
        let flow = self.by_id.get_mut(&id)?;
        flow.last = now;
        Some((id, &mut flow.value))
    }

    pub fn by_id(&mut self, id: u64, now: Instant) -> Option<&mut V> {
        let flow = self.by_id.get_mut(&id)?;
        flow.last = now;
        Some(&mut flow.value)
    }

    #[inline]
    pub fn peek(&self, id: u64) -> Option<&V> {
        self.by_id.get(&id).map(|f| &f.value)
    }

    /// Does not refresh the idle timer, unlike `by_id`: only a delivery counts as liveness.
    #[inline]
    pub fn get_mut(&mut self, id: u64) -> Option<&mut V> {
        self.by_id.get_mut(&id).map(|f| &mut f.value)
    }

    #[inline]
    pub fn touch(&mut self, id: u64, now: Instant) -> bool {
        match self.by_id.get_mut(&id) {
            Some(flow) => {
                flow.last = now;
                true
            }
            None => false,
        }
    }

    #[inline]
    pub fn remove(&mut self, id: u64) -> Option<Flow<K, V>> {
        let flow = self.by_id.remove(&id)?;
        self.by_key.remove(&flow.key);
        Some(flow)
    }

    pub fn gc(&mut self, now: Instant) -> Vec<Flow<K, V>> {
        let mut expired = Vec::new();
        for (&id, flow) in &self.by_id {
            if now.duration_since(flow.last) < self.idle {
                continue;
            }

            expired.push(id);
        }

        self.gc_total += expired.len() as u64;

        let mut collected = Vec::with_capacity(expired.len());
        for id in expired {
            let Some(flow) = self.remove(id) else {
                continue;
            };

            collected.push(flow);
        }

        collected
    }

    pub fn drain_where(&mut self, mut pred: impl FnMut(&K, &V) -> bool) -> Vec<Flow<K, V>> {
        let mut doomed = Vec::new();
        for (&id, flow) in &self.by_id {
            if !pred(&flow.key, &flow.value) {
                continue;
            }

            doomed.push(id);
        }

        let mut drained = Vec::with_capacity(doomed.len());
        for id in doomed {
            let Some(flow) = self.remove(id) else {
                continue;
            };

            drained.push(flow);
        }

        drained
    }
}

#[derive(Debug)]
pub struct UnknownFlowLimiter {
    seen: HashMap<u64, Instant>,
    interval: Duration,
    capacity: usize,
    last_sweep: Option<Instant>,
}

impl Default for UnknownFlowLimiter {
    fn default() -> Self {
        Self::new(FLOW_UNKNOWN_NOTIFY_INTERVAL, FLOW_UNKNOWN_TRACKED)
    }
}

impl UnknownFlowLimiter {
    #[inline]
    pub fn new(interval: Duration, capacity: usize) -> Self {
        Self {
            seen: HashMap::new(),
            interval,
            capacity,
            last_sweep: None,
        }
    }

    pub fn allow(&mut self, flow_id: u64, now: Instant) -> bool {
        if let Some(last) = self.seen.get(&flow_id) {
            if now.duration_since(*last) < self.interval {
                return false;
            }
        } else if self.seen.len() >= self.capacity {
            let due = self
                .last_sweep
                .is_none_or(|t| now.duration_since(t) >= self.interval);
            if !due {
                return false;
            }

            self.last_sweep = Some(now);
            self.seen
                .retain(|_, t| now.duration_since(*t) < self.interval);

            if self.seen.len() >= self.capacity {
                return false;
            }
        }

        self.seen.insert(flow_id, now);

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn addr(port: u16) -> SocketAddr {
        format!("127.0.1.1:{port}").parse().unwrap()
    }

    fn table(parity: Parity) -> FlowTable<SocketAddr, u32> {
        FlowTable::new(parity, FLOW_IDLE_TIMEOUT, 4)
    }

    // FlowTable

    #[test]
    fn allocated_ids_respect_parity_and_never_collide() {
        let now = Instant::now();
        let mut even = table(Parity::Even);
        let mut odd = table(Parity::Odd);

        let a: Vec<_> = (0..4)
            .map(|i| even.open(addr(i), i as u32, now).unwrap())
            .collect();
        let b: Vec<_> = (0..4)
            .map(|i| odd.open(addr(i), i as u32, now).unwrap())
            .collect();

        assert!(a.iter().all(|&id| Parity::Even.matches(id)));
        assert!(b.iter().all(|&id| Parity::Odd.matches(id)));
        assert!(a.iter().all(|id| !b.contains(id)));
    }

    #[test]
    fn lookup_by_key_and_id_agree() {
        let now = Instant::now();
        let mut t = table(Parity::Even);
        let id = t.open(addr(1), 42, now).unwrap();

        assert_eq!(t.by_key(&addr(1), now), Some((id, &mut 42)));
        assert_eq!(t.by_id(id, now), Some(&mut 42));
        assert!(t.by_key(&addr(2), now).is_none());
        assert!(t.by_id(id + 2, now).is_none());
    }

    #[test]
    fn reopening_a_key_replaces_the_old_flow() {
        let now = Instant::now();
        let mut t = table(Parity::Even);
        let first = t.open(addr(1), 1, now).unwrap();
        let second = t.open(addr(1), 2, now).unwrap();

        assert_ne!(first, second);
        assert_eq!(t.len(), 1);
        assert!(t.by_id(first, now).is_none());
        assert_eq!(t.by_key(&addr(1), now), Some((second, &mut 2)));
    }

    #[test]
    fn adopt_refuses_an_id_from_our_own_half() {
        let now = Instant::now();
        let mut t = table(Parity::Even);

        assert_eq!(t.adopt(4, addr(1), 1, now), Err(FlowError::WrongParity(4)));
        assert!(t.is_empty());
        assert_eq!(t.rejected_total(), 1);

        assert!(t.adopt(5, addr(1), 1, now).is_ok());
        assert_eq!(t.len(), 1);

        let mut t = table(Parity::Odd);
        assert_eq!(t.adopt(5, addr(1), 1, now), Err(FlowError::WrongParity(5)));
        assert!(t.adopt(4, addr(1), 1, now).is_ok());
    }

    #[test]
    fn adopt_refuses_an_id_held_by_a_live_egress_flow() {
        let now = Instant::now();
        let mut t = table(Parity::Even);
        let mine = t.open(addr(1), 111, now).unwrap();

        assert_eq!(
            t.adopt(mine, addr(2), 222, now),
            Err(FlowError::WrongParity(mine))
        );
        assert_eq!(t.by_id(mine, now), Some(&mut 111));
    }

    #[test]
    fn capacity_is_enforced_and_counted() {
        let now = Instant::now();
        let mut t = table(Parity::Even);
        for i in 0..4 {
            t.open(addr(i), i as u32, now).unwrap();
        }
        assert!(t.open(addr(9), 9, now).is_err());
        assert_eq!(t.rejected_total(), 1);
        assert_eq!(t.len(), 4);

        assert!(t.adopt(101, addr(10), 10, now).is_err());
        assert_eq!(t.rejected_total(), 2);
    }

    #[test]
    fn idle_flows_are_collected_and_counted() {
        let t0 = Instant::now();
        let mut t = table(Parity::Even);
        let stale = t.open(addr(1), 1, t0).unwrap();
        let fresh = t.open(addr(2), 2, t0).unwrap();

        t.by_id(fresh, t0 + Duration::from_secs(59));

        let collected = t.gc(t0 + FLOW_IDLE_TIMEOUT);
        assert_eq!(collected.len(), 1);
        assert_eq!(collected[0].id, stale);
        assert_eq!(t.gc_total(), 1);
        assert_eq!(t.len(), 1);

        assert!(t.gc(t0 + FLOW_IDLE_TIMEOUT).is_empty());
        assert_eq!(t.gc_total(), 1);
    }

    #[test]
    fn get_mut_does_not_refresh_the_idle_timer_but_touch_does() {
        let t0 = Instant::now();
        let mut t = table(Parity::Even);
        let id = t.open(addr(1), 1, t0).unwrap();

        for _ in 1..60 {
            assert!(t.get_mut(id).is_some());
        }
        assert_eq!(t.gc(t0 + FLOW_IDLE_TIMEOUT).len(), 1);

        let id = t.open(addr(2), 2, t0).unwrap();
        assert!(t.touch(id, t0 + Duration::from_secs(59)));
        assert!(t.gc(t0 + FLOW_IDLE_TIMEOUT).is_empty());
        assert!(!t.touch(9999, t0));
    }

    #[test]
    fn restore_accepts_either_half_and_does_not_reallocate() {
        let now = Instant::now();
        let mut t = table(Parity::Even);

        assert!(t.restore(7, addr(7), 7, now).is_ok());
        assert!(t.restore(8, addr(8), 8, now).is_ok());
        assert_eq!(t.peek(7), Some(&7));

        let fresh = t.open(addr(9), 9, now).unwrap();
        assert_ne!(fresh, 8);
        assert!(Parity::Even.matches(fresh));
    }

    #[test]
    fn touching_by_key_defers_collection() {
        let t0 = Instant::now();
        let mut t = table(Parity::Even);
        t.open(addr(1), 1, t0).unwrap();

        t.by_key(&addr(1), t0 + Duration::from_secs(50));
        assert!(t.gc(t0 + Duration::from_secs(100)).is_empty());
        assert!(!t.gc(t0 + Duration::from_secs(111)).is_empty());
    }

    #[test]
    fn collected_key_reopens_with_a_fresh_id() {
        let t0 = Instant::now();
        let mut t = table(Parity::Even);
        let first = t.open(addr(1), 1, t0).unwrap();
        t.gc(t0 + FLOW_IDLE_TIMEOUT);

        let second = t.open(addr(1), 1, t0 + FLOW_IDLE_TIMEOUT).unwrap();
        assert_ne!(first, second);
        assert_eq!(t.opened_total(), 2);
    }

    #[test]
    fn adopt_replaces_in_place_and_stays_addressable() {
        let now = Instant::now();
        let mut t = table(Parity::Even);
        t.adopt(7, addr(1), 1, now).unwrap();
        assert_eq!(t.by_id(7, now), Some(&mut 1));

        t.adopt(7, addr(2), 2, now).unwrap();
        assert_eq!(t.len(), 1);
        assert!(t.by_key(&addr(1), now).is_none());
        assert_eq!(t.by_key(&addr(2), now), Some((7, &mut 2)));
    }

    #[test]
    fn drain_where_removes_matching_flows_only() {
        let now = Instant::now();
        let mut t = table(Parity::Even);
        for i in 0..4 {
            t.open(addr(i), i as u32, now).unwrap();
        }
        let gone = t.drain_where(|_, v| *v % 2 == 0);
        assert_eq!(gone.len(), 2);
        assert_eq!(t.len(), 2);
        assert!(t.by_key(&addr(0), now).is_none());
        assert!(t.by_key(&addr(1), now).is_some());
    }

    // UnknownFlowLimiter

    #[test]
    fn notifications_are_rate_limited_per_flow() {
        let t0 = Instant::now();
        let mut l = UnknownFlowLimiter::new(Duration::from_secs(1), 8);

        assert!(l.allow(1, t0));
        assert!(!l.allow(1, t0 + Duration::from_millis(999)));
        assert!(l.allow(2, t0));
        assert!(l.allow(1, t0 + Duration::from_secs(1)));
    }

    #[test]
    fn limiter_memory_is_bounded() {
        let t0 = Instant::now();
        let mut l = UnknownFlowLimiter::new(Duration::from_secs(1), 8);

        for i in 0..8 {
            assert!(l.allow(i, t0));
        }
        assert!(!l.allow(99, t0));
        assert_eq!(l.seen.len(), 8);

        assert!(l.allow(99, t0 + Duration::from_secs(2)));
        assert!(l.seen.len() <= 8);
    }

    #[test]
    fn limiter_sweeps_once_under_a_flood_of_fresh_ids() {
        let t0 = Instant::now();
        let mut l = UnknownFlowLimiter::new(Duration::from_secs(1), 8);
        for i in 0..8 {
            l.allow(i, t0);
        }

        let flood = t0 + Duration::from_millis(10);
        for i in 100..1000 {
            assert!(!l.allow(i, flood));
        }
        assert_eq!(l.last_sweep, Some(flood));
        assert_eq!(l.seen.len(), 8);

        assert!(l.allow(1000, t0 + Duration::from_secs(2)));
        assert!(l.last_sweep.is_some());
    }
}
