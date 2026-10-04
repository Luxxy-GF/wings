use crate::node::quic::conn::PeerConn;
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Duration,
};
use tundra_common::codes::{CloseCode, keep_outbound};

pub const GLARE_WINDOW: Duration = Duration::from_secs(10);

pub fn resolve(
    local: &uuid::Uuid,
    peer: &uuid::Uuid,
    existing: Option<Existing>,
    incoming: Role,
    incoming_instance: u64,
) -> Decision {
    let Some(existing) = existing else {
        return Decision::Install;
    };

    if existing.closed
        || existing.instance != incoming_instance
        || existing.role == incoming
        || existing.age > GLARE_WINDOW
    {
        return Decision::Install;
    }

    let preferred = if keep_outbound(local, peer) {
        Role::Initiator
    } else {
        Role::Acceptor
    };

    if incoming == preferred {
        Decision::Install
    } else {
        Decision::RejectIncoming
    }
}

#[inline]
fn candidate_role(live: &HashMap<uuid::Uuid, Arc<PeerConn>>, peer: &uuid::Uuid) -> &'static str {
    live.get(peer).map_or("none", |c| c.role.to_str())
}

pub fn close_loser(conn: &PeerConn) {
    conn.conn.close(
        CloseCode::DuplicateConnection.as_u32().into(),
        CloseCode::DuplicateConnection.reason(),
    );
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Initiator,
    Acceptor,
}

impl Role {
    #[inline]
    pub fn to_str(self) -> &'static str {
        match self {
            Self::Initiator => "initiator",
            Self::Acceptor => "acceptor",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Install,
    RejectIncoming,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Existing {
    role: Role,
    closed: bool,
    age: Duration,
    instance: u64,
}

pub struct PeerRegistry {
    local: uuid::Uuid,
    live: parking_lot::Mutex<HashMap<uuid::Uuid, Arc<PeerConn>>>,
    dialing: parking_lot::Mutex<HashSet<uuid::Uuid>>,
    suppressed: parking_lot::Mutex<HashSet<uuid::Uuid>>,
}

impl PeerRegistry {
    #[inline]
    pub fn new(local: uuid::Uuid) -> Self {
        Self {
            local,
            live: parking_lot::Mutex::new(HashMap::new()),
            dialing: parking_lot::Mutex::new(HashSet::new()),
            suppressed: parking_lot::Mutex::new(HashSet::new()),
        }
    }

    // only the restarted node may dial, because only a dialer can claim the flow-id space
    // it inherited
    #[inline]
    pub fn suppress_dial(&self, peer: uuid::Uuid) {
        self.suppressed.lock().insert(peer);
    }

    #[inline]
    pub fn unsuppress_dial(&self, peer: &uuid::Uuid) {
        self.suppressed.lock().remove(peer);
    }

    #[inline]
    pub fn dial_suppressed(&self, peer: &uuid::Uuid) -> bool {
        self.suppressed.lock().contains(peer)
    }

    #[inline]
    pub fn get(&self, peer: &uuid::Uuid) -> Option<Arc<PeerConn>> {
        self.live.lock().get(peer).cloned()
    }

    #[inline]
    pub fn connected(&self) -> Vec<uuid::Uuid> {
        self.live.lock().keys().copied().collect()
    }

    #[inline]
    pub fn begin_dial(&self, peer: uuid::Uuid) -> bool {
        if self.dial_suppressed(&peer) {
            return false;
        }

        self.dialing.lock().insert(peer)
    }

    #[inline]
    pub fn end_dial(&self, peer: &uuid::Uuid) {
        self.dialing.lock().remove(peer);
    }

    pub fn install(&self, candidate: Arc<PeerConn>) -> Install {
        let peer = candidate.peer;
        let mut live = self.live.lock();

        let existing = live.get(&peer).map(|c| Existing {
            role: c.role,
            closed: c.conn.close_reason().is_some(),
            age: c.metrics.age(),
            instance: c.peer_instance,
        });
        let decision = resolve(
            &self.local,
            &peer,
            existing,
            candidate.role,
            candidate.peer_instance,
        );

        match decision {
            Decision::Install => {
                let displaced = live.insert(peer, candidate);
                if let Some(old) = &displaced {
                    tracing::info!(
                        peer = %peer,
                        kept = %candidate_role(&live, &peer),
                        closed = %old.role.to_str(),
                        "glare resolved, replacing the existing connection"
                    );
                }
                Install::Installed { displaced }
            }
            Decision::RejectIncoming => {
                tracing::info!(
                    peer = %peer,
                    rejected = %candidate.role.to_str(),
                    "glare resolved, keeping the existing connection"
                );
                Install::Rejected(candidate)
            }
        }
    }

    // identity-checked so a glare loser tearing down cannot evict the winner
    pub fn remove(&self, conn: &Arc<PeerConn>) {
        let mut live = self.live.lock();
        if live.get(&conn.peer).is_some_and(|c| Arc::ptr_eq(c, conn)) {
            live.remove(&conn.peer);
        }
    }
}

pub enum Install {
    Installed { displaced: Option<Arc<PeerConn>> },
    Rejected(Arc<PeerConn>),
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOW: uuid::Uuid = uuid::Uuid::from_u128(1);
    const HIGH: uuid::Uuid = uuid::Uuid::from_u128(2);
    const YOUNG: Duration = Duration::ZERO;
    const SAME: u64 = 77;

    fn held(role: Role, closed: bool, age: Duration) -> Option<Existing> {
        Some(Existing {
            role,
            closed,
            age,
            instance: SAME,
        })
    }

    // resolve

    #[test]
    fn an_empty_slot_always_accepts() {
        for role in [Role::Initiator, Role::Acceptor] {
            assert_eq!(resolve(&LOW, &HIGH, None, role, SAME), Decision::Install);
            assert_eq!(resolve(&HIGH, &LOW, None, role, SAME), Decision::Install);
        }
    }

    #[test]
    fn simultaneous_dials_converge_on_the_lower_uuids_outbound() {
        assert_eq!(
            resolve(
                &LOW,
                &HIGH,
                held(Role::Initiator, false, YOUNG),
                Role::Acceptor,
                SAME
            ),
            Decision::RejectIncoming
        );
        assert_eq!(
            resolve(
                &HIGH,
                &LOW,
                held(Role::Initiator, false, YOUNG),
                Role::Acceptor,
                SAME
            ),
            Decision::Install
        );
    }

    #[test]
    fn the_reverse_arrival_order_reaches_the_same_connection() {
        assert_eq!(
            resolve(
                &LOW,
                &HIGH,
                held(Role::Acceptor, false, YOUNG),
                Role::Initiator,
                SAME
            ),
            Decision::Install
        );
        assert_eq!(
            resolve(
                &HIGH,
                &LOW,
                held(Role::Acceptor, false, YOUNG),
                Role::Initiator,
                SAME
            ),
            Decision::RejectIncoming
        );
    }

    #[test]
    fn both_ends_of_every_pairing_agree_on_the_survivor() {
        for (local, remote) in [(LOW, HIGH), (HIGH, LOW)] {
            let prefers_own_dial = local < remote;

            for first in [Role::Initiator, Role::Acceptor] {
                let second = if first == Role::Initiator {
                    Role::Acceptor
                } else {
                    Role::Initiator
                };
                let held = match resolve(&local, &remote, held(first, false, YOUNG), second, SAME) {
                    Decision::Install => second,
                    Decision::RejectIncoming => first,
                };
                assert_eq!(held == Role::Initiator, prefers_own_dial);
            }
        }
    }

    #[test]
    fn a_peer_that_reconnects_replaces_its_own_stale_connection() {
        // same direction twice is a reconnect: a peer does not dial again while it still
        // holds a connection
        for (local, remote) in [(LOW, HIGH), (HIGH, LOW)] {
            for role in [Role::Initiator, Role::Acceptor] {
                assert_eq!(
                    resolve(&local, &remote, held(role, false, YOUNG), role, SAME),
                    Decision::Install
                );
            }
        }
    }

    #[test]
    fn a_peer_that_restarted_displaces_its_old_connection_immediately() {
        for (local, remote) in [(LOW, HIGH), (HIGH, LOW)] {
            for existing in [Role::Initiator, Role::Acceptor] {
                for incoming in [Role::Initiator, Role::Acceptor] {
                    assert_eq!(
                        resolve(
                            &local,
                            &remote,
                            held(existing, false, YOUNG),
                            incoming,
                            SAME + 1
                        ),
                        Decision::Install
                    );
                }
            }
        }
    }

    #[test]
    fn genuine_glare_shares_a_peer_instance_id_and_still_tie_breaks() {
        assert_eq!(
            resolve(
                &LOW,
                &HIGH,
                held(Role::Initiator, false, YOUNG),
                Role::Acceptor,
                SAME
            ),
            Decision::RejectIncoming
        );
    }

    #[test]
    fn a_stale_connection_yields_to_a_fresh_one_from_the_same_peer() {
        let stale = GLARE_WINDOW + Duration::from_secs(1);
        assert_eq!(
            resolve(
                &LOW,
                &HIGH,
                held(Role::Initiator, false, stale),
                Role::Acceptor,
                SAME
            ),
            Decision::Install
        );
        assert_eq!(
            resolve(
                &HIGH,
                &LOW,
                held(Role::Acceptor, false, stale),
                Role::Initiator,
                SAME
            ),
            Decision::Install
        );

        // exactly at the window is still genuine glare, resolved by the tie-break rather
        // than by age
        assert_eq!(
            resolve(
                &LOW,
                &HIGH,
                held(Role::Initiator, false, GLARE_WINDOW),
                Role::Acceptor,
                SAME
            ),
            Decision::RejectIncoming
        );
    }

    #[test]
    fn a_dead_connection_never_blocks_a_replacement() {
        for existing in [Role::Initiator, Role::Acceptor] {
            for incoming in [Role::Initiator, Role::Acceptor] {
                assert_eq!(
                    resolve(&LOW, &HIGH, held(existing, true, YOUNG), incoming, SAME),
                    Decision::Install
                );
            }
        }
    }

    // PeerRegistry

    #[test]
    fn only_one_dial_per_peer_is_in_flight() {
        let reg = PeerRegistry::new(LOW);
        assert!(reg.begin_dial(HIGH));
        assert!(!reg.begin_dial(HIGH));

        reg.end_dial(&HIGH);
        assert!(reg.begin_dial(HIGH));
    }

    #[test]
    fn a_peer_that_is_restarting_is_not_dialled_from_here() {
        let reg = PeerRegistry::new(LOW);
        reg.suppress_dial(HIGH);

        assert!(!reg.begin_dial(HIGH));
        assert!(reg.dial_suppressed(&HIGH));
        assert!(reg.begin_dial(uuid::Uuid::from_u128(3)));

        reg.unsuppress_dial(&HIGH);
        assert!(reg.begin_dial(HIGH));
    }
}
