use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering::Relaxed},
    },
};
use tokio::sync::watch;
use tundra_common::admit::Transport;

pub mod flows;
pub mod tcp;
pub mod udp;

#[inline]
pub async fn cancelled(rx: &mut watch::Receiver<bool>) {
    loop {
        let done = *rx.borrow_and_update();
        if done {
            return;
        }
        if rx.changed().await.is_err() {
            return;
        }
    }
}

#[derive(Debug)]
struct Entry {
    src: uuid::Uuid,
    dst: uuid::Uuid,
    port: u16,
    transport: Transport,
    cancel: watch::Sender<bool>,
}

#[derive(Debug, Default)]
pub struct RelayRegistry {
    next: AtomicU64,
    entries: parking_lot::Mutex<HashMap<u64, Entry>>,
}

impl RelayRegistry {
    pub fn register(
        self: &Arc<Self>,
        src: uuid::Uuid,
        dst: uuid::Uuid,
        port: u16,
        transport: Transport,
    ) -> (RelayGuard, watch::Receiver<bool>) {
        let id = self.next.fetch_add(1, Relaxed);
        let (cancel, rx) = watch::channel(false);

        self.entries.lock().insert(
            id,
            Entry {
                src,
                dst,
                port,
                transport,
                cancel,
            },
        );

        (
            RelayGuard {
                registry: Arc::clone(self),
                id,
            },
            rx,
        )
    }

    #[cfg(test)]
    #[inline]
    pub fn len(&self) -> usize {
        self.entries.lock().len()
    }

    pub fn cancel_where(
        &self,
        mut pred: impl FnMut(&uuid::Uuid, &uuid::Uuid, u16, Transport) -> bool,
    ) -> usize {
        let doomed = {
            let entries = self.entries.lock();
            let mut doomed = Vec::new();
            for entry in entries.values() {
                if !pred(&entry.src, &entry.dst, entry.port, entry.transport) {
                    continue;
                }

                doomed.push(entry.cancel.clone());
            }

            doomed
        };

        for cancel in &doomed {
            let _ = cancel.send(true);
        }

        doomed.len()
    }

    #[cfg(test)]
    #[inline]
    pub fn cancel_all(&self) -> usize {
        self.cancel_where(|_, _, _, _| true)
    }

    #[inline]
    fn release(&self, id: u64) {
        self.entries.lock().remove(&id);
    }
}

#[derive(Debug)]
pub struct RelayGuard {
    registry: Arc<RelayRegistry>,
    id: u64,
}

impl Drop for RelayGuard {
    fn drop(&mut self) {
        self.registry.release(self.id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(n: u128) -> uuid::Uuid {
        uuid::Uuid::from_u128(n)
    }

    // RelayRegistry

    #[test]
    fn a_relay_deregisters_itself_when_dropped() {
        let reg = Arc::new(RelayRegistry::default());
        {
            let (_guard, _rx) = reg.register(u(1), u(2), 80, Transport::Tcp);
            assert_eq!(reg.len(), 1);
        }
        assert_eq!(reg.len(), 0);
    }

    #[test]
    fn ids_are_unique_across_connections() {
        let reg = Arc::new(RelayRegistry::default());
        let held: Vec<_> = (0..100)
            .map(|_| reg.register(u(1), u(2), 80, Transport::Tcp))
            .collect();
        assert_eq!(reg.len(), 100);
        drop(held);
        assert_eq!(reg.len(), 0);
    }

    #[test]
    fn cancelling_signals_only_the_matching_pairs() {
        let reg = Arc::new(RelayRegistry::default());
        let (_a, mut ra) = reg.register(u(1), u(2), 80, Transport::Tcp);
        let (_b, mut rb) = reg.register(u(1), u(3), 80, Transport::Tcp);
        let (_c, mut rc) = reg.register(u(9), u(2), 80, Transport::Tcp);

        assert_eq!(
            reg.cancel_where(|src, dst, _, _| *src == u(1) && *dst == u(2)),
            1
        );

        assert!(*ra.borrow_and_update());
        assert!(!*rb.borrow_and_update());
        assert!(!*rc.borrow_and_update());
    }

    #[test]
    fn cancelling_is_observable_by_an_awaiting_relay() {
        let reg = Arc::new(RelayRegistry::default());
        let (_guard, mut rx) = reg.register(u(1), u(2), 80, Transport::Tcp);

        assert!(!*rx.borrow_and_update());
        reg.cancel_all();
        assert!(*rx.borrow_and_update());
    }

    #[test]
    fn cancelling_an_already_finished_relay_is_harmless() {
        let reg = Arc::new(RelayRegistry::default());
        {
            let (_guard, _rx) = reg.register(u(1), u(2), 80, Transport::Tcp);
        }
        assert_eq!(reg.cancel_all(), 0);
    }

    #[test]
    fn de_registering_a_port_can_be_selected_without_touching_the_others() {
        let reg = Arc::new(RelayRegistry::default());
        let (_a, mut ra) = reg.register(u(1), u(2), 25565, Transport::Tcp);
        let (_b, mut rb) = reg.register(u(1), u(2), 8080, Transport::Tcp);
        let (_c, mut rc) = reg.register(u(1), u(2), 25565, Transport::Udp);

        assert_eq!(
            reg.cancel_where(|_, _, port, t| port == 25565 && t == Transport::Tcp),
            1
        );
        assert!(*ra.borrow_and_update());
        assert!(!*rb.borrow_and_update());
        assert!(!*rc.borrow_and_update());
    }

    #[test]
    fn a_dropped_receiver_does_not_break_cancellation_of_the_rest() {
        let reg = Arc::new(RelayRegistry::default());
        let (_a, ra) = reg.register(u(1), u(2), 80, Transport::Tcp);
        let (_b, mut rb) = reg.register(u(1), u(2), 80, Transport::Tcp);
        drop(ra);

        assert_eq!(reg.cancel_all(), 2);
        assert!(*rb.borrow_and_update());
    }
}
