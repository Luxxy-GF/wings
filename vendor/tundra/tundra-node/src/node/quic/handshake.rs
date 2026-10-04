use std::{collections::HashMap, net::IpAddr, sync::Arc};

pub const MAX_HANDSHAKES: usize = 128;
pub const MAX_HANDSHAKES_PER_IP: usize = 8;

#[derive(Debug, Default)]
pub struct HandshakeBudget {
    inner: parking_lot::Mutex<Counts>,
}

#[derive(Debug, Default)]
struct Counts {
    total: usize,
    per_ip: HashMap<IpAddr, usize>,
}

impl HandshakeBudget {
    pub fn try_acquire(self: &Arc<Self>, ip: IpAddr) -> Option<HandshakeSlot> {
        let mut counts = self.inner.lock();
        let from_ip = counts.per_ip.get(&ip).copied().unwrap_or(0);
        if counts.total >= MAX_HANDSHAKES || from_ip >= MAX_HANDSHAKES_PER_IP {
            return None;
        }

        counts.total += 1;
        counts.per_ip.insert(ip, from_ip + 1);

        Some(HandshakeSlot {
            budget: Arc::clone(self),
            ip,
        })
    }

    fn release(&self, ip: IpAddr) {
        let mut counts = self.inner.lock();
        counts.total = counts.total.saturating_sub(1);
        if let Some(n) = counts.per_ip.get_mut(&ip) {
            *n -= 1;
            if *n == 0 {
                counts.per_ip.remove(&ip);
            }
        }
    }
}

pub struct HandshakeSlot {
    budget: Arc<HandshakeBudget>,
    ip: IpAddr,
}

impl Drop for HandshakeSlot {
    fn drop(&mut self) {
        self.budget.release(self.ip);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn ip(n: u32) -> IpAddr {
        IpAddr::from((0x0a00_0000 | n).to_be_bytes())
    }

    fn fill(budget: &Arc<HandshakeBudget>, ip: IpAddr, n: usize) -> Vec<HandshakeSlot> {
        (0..n)
            .map(|_| budget.try_acquire(ip).expect("under cap"))
            .collect()
    }

    // HandshakeBudget

    #[test]
    fn one_ip_is_capped_without_affecting_others() {
        let budget = Arc::new(HandshakeBudget::default());
        let _held = fill(&budget, ip(1), MAX_HANDSHAKES_PER_IP);

        assert!(budget.try_acquire(ip(1)).is_none());
        assert!(budget.try_acquire(ip(2)).is_some());
    }

    #[test]
    fn total_is_capped_across_ips() {
        let budget = Arc::new(HandshakeBudget::default());
        let _held: Vec<_> = (0..MAX_HANDSHAKES as u32)
            .map(|n| budget.try_acquire(ip(n)).expect("under cap"))
            .collect();

        assert!(budget.try_acquire(ip(MAX_HANDSHAKES as u32)).is_none());
    }

    #[test]
    fn dropping_a_slot_frees_exactly_one_per_ip_after_refusals() {
        let budget = Arc::new(HandshakeBudget::default());
        let mut held = fill(&budget, ip(1), MAX_HANDSHAKES_PER_IP);
        for _ in 0..5 {
            assert!(budget.try_acquire(ip(1)).is_none());
        }

        held.pop();
        held.push(budget.try_acquire(ip(1)).expect("freed slot"));
        assert!(budget.try_acquire(ip(1)).is_none());
    }

    #[test]
    fn dropping_a_slot_frees_exactly_one_global_after_refusals() {
        let budget = Arc::new(HandshakeBudget::default());
        let mut held: Vec<_> = (0..MAX_HANDSHAKES as u32)
            .map(|n| budget.try_acquire(ip(n)).expect("under cap"))
            .collect();
        let fresh = MAX_HANDSHAKES as u32;
        for _ in 0..5 {
            assert!(budget.try_acquire(ip(fresh)).is_none());
        }

        held.pop();
        held.push(budget.try_acquire(ip(fresh)).expect("freed slot"));
        assert!(budget.try_acquire(ip(fresh + 1)).is_none());
    }

    #[test]
    fn releasing_all_slots_of_an_ip_restores_its_full_allowance() {
        let budget = Arc::new(HandshakeBudget::default());
        for _ in 0..3 {
            let held = fill(&budget, ip(1), MAX_HANDSHAKES_PER_IP);
            assert!(budget.try_acquire(ip(1)).is_none());
            drop(held);
        }
    }
}
