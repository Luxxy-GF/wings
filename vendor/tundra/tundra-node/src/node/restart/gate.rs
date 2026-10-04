use std::collections::HashSet;
use tokio::sync::watch;

#[derive(Debug, Default)]
struct GateState {
    all: bool,
    peers: HashSet<uuid::Uuid>,
    epoch: u64,
}

/// Pausing `accept()` rather than unbinding is the whole point: connections queue in the
/// kernel backlog instead of being refused, so the handover is invisible to applications.
#[derive(Debug)]
pub struct AcceptGate {
    state: parking_lot::Mutex<GateState>,
    tx: watch::Sender<u64>,
}

impl Default for AcceptGate {
    fn default() -> Self {
        Self {
            state: parking_lot::Mutex::new(GateState::default()),
            tx: watch::channel(0).0,
        }
    }
}

impl AcceptGate {
    #[inline]
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.tx.subscribe()
    }

    #[inline]
    fn update(&self, f: impl FnOnce(&mut GateState)) {
        let epoch = {
            let mut state = self.state.lock();
            f(&mut state);
            state.epoch += 1;
            state.epoch
        };

        let _ = self.tx.send(epoch);
    }

    #[inline]
    pub fn pause_all(&self) {
        self.update(|s| s.all = true);
    }

    /// A node finishing its own restart must not unpause a peer that is still restarting.
    #[inline]
    pub fn resume_all(&self) {
        self.update(|s| s.all = false);
    }

    #[inline]
    pub fn pause_peer(&self, peer: uuid::Uuid) {
        self.update(|s| {
            s.peers.insert(peer);
        });
    }

    #[inline]
    pub fn resume_peer(&self, peer: &uuid::Uuid) {
        self.update(|s| {
            s.peers.remove(peer);
        });
    }

    #[inline]
    pub fn paused(&self, peer: &uuid::Uuid) -> bool {
        let state = self.state.lock();
        state.all || state.peers.contains(peer)
    }

    pub async fn wait_open(&self, peer: &uuid::Uuid, rx: &mut watch::Receiver<u64>) {
        loop {
            // mark seen before the check, or a resume landing in between is a lost wakeup
            rx.mark_unchanged();
            if !self.paused(peer) {
                return;
            }
            if rx.changed().await.is_err() {
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: uuid::Uuid = uuid::Uuid::from_u128(1);
    const B: uuid::Uuid = uuid::Uuid::from_u128(2);

    // AcceptGate

    #[test]
    fn pause_peer_leaves_the_others_accepting() {
        let gate = AcceptGate::default();
        gate.pause_peer(A);

        assert!(gate.paused(&A));
        assert!(!gate.paused(&B));

        gate.resume_peer(&A);
        assert!(!gate.paused(&A));
    }

    #[test]
    fn pause_all_covers_peers_that_were_never_named() {
        let gate = AcceptGate::default();
        gate.pause_all();
        assert!(gate.paused(&A));
        assert!(gate.paused(&B));

        gate.resume_all();
        assert!(!gate.paused(&A));
    }

    #[test]
    fn resume_all_leaves_another_peers_hold_alone() {
        let gate = AcceptGate::default();
        gate.pause_peer(A);
        gate.pause_all();

        gate.resume_all();
        assert!(!gate.paused(&B));
        assert!(gate.paused(&A));

        gate.resume_peer(&A);
        assert!(!gate.paused(&A));
    }

    #[test]
    fn wait_open_wakes_when_its_peer_is_resumed() {
        tokio_test::block_on(async {
            let gate = std::sync::Arc::new(AcceptGate::default());
            gate.pause_peer(A);

            let mut rx = gate.subscribe();
            let waiter = {
                let gate = std::sync::Arc::clone(&gate);
                tokio::spawn(async move { gate.wait_open(&A, &mut rx).await })
            };

            tokio::task::yield_now().await;
            assert!(!waiter.is_finished());

            gate.resume_peer(&A);
            tokio::time::timeout(std::time::Duration::from_secs(2), waiter)
                .await
                .unwrap()
                .unwrap();
        });
    }

    #[test]
    fn wait_open_returns_at_once_on_an_open_gate() {
        tokio_test::block_on(async {
            let gate = AcceptGate::default();
            let mut rx = gate.subscribe();
            tokio::time::timeout(
                std::time::Duration::from_secs(2),
                gate.wait_open(&A, &mut rx),
            )
            .await
            .unwrap();
        });
    }
}
