use crate::{codes::StreamCode, state::SnapshotIndex};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Tcp,
    Udp,
}

/// `src_owner` and `dst_owner` are stated by the caller rather than inferred as "peer" and
/// "local": a relay resumed after a restart is re-opened by whichever node restarted.
#[inline]
pub fn admit(
    index: &SnapshotIndex,
    src_owner: &uuid::Uuid,
    dst_owner: &uuid::Uuid,
    src_server: &uuid::Uuid,
    dst_server: &uuid::Uuid,
    dst_port: u16,
    transport: Transport,
) -> Result<(), StreamCode> {
    if !index.owns_server(src_owner, src_server) {
        return Err(StreamCode::NoSuchServer);
    }
    if !index.owns_server(dst_owner, dst_server) {
        return Err(StreamCode::NoSuchServer);
    }
    if !index.allows(src_server, dst_server) {
        return Err(StreamCode::AclDenied);
    }

    if !port_registered(index, dst_server, dst_port, transport) {
        return Err(StreamCode::PortNotRegistered);
    }

    Ok(())
}

#[inline]
pub fn port_registered(
    index: &SnapshotIndex,
    dst_server: &uuid::Uuid,
    dst_port: u16,
    transport: Transport,
) -> bool {
    index.server(dst_server).is_some_and(|dst| {
        dst.ports.iter().any(|p| {
            p.port == dst_port
                && match transport {
                    Transport::Tcp => p.proto.tcp(),
                    Transport::Udp => p.proto.udp(),
                }
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        hash::Hash32,
        state::{AclEntry, NodeEntry, PortSpec, Proto, ServerEntry, Snapshot},
    };

    fn u(n: u128) -> uuid::Uuid {
        uuid::Uuid::from_u128(n)
    }

    const LOCAL: u128 = 1;
    const PEER: u128 = 2;
    const THIRD: u128 = 3;
    const THEIRS: u128 = 20;
    const MINE: u128 = 10;

    fn snap() -> SnapshotIndex {
        let node = |n: u128| NodeEntry {
            uuid: u(n),
            name: format!("node-{n}"),
            host: "10.0.0.1".into(),
            tunnel_port: 7100,
            cert_sha256: Some(Hash32([n as u8; 32])),
        };
        let server = |s: u128, idx: u16, n: u128, ports: Vec<PortSpec>| ServerEntry {
            uuid: u(s),
            idx,
            node_uuid: u(n),
            name: format!("s{s}"),
            aliases: Vec::new(),
            container_ref: format!("c{s}"),
            dial_addr: None,
            ports,
        };

        SnapshotIndex::new(Snapshot {
            epoch: 1,
            jwt_pubkey: Hash32([0; 32]),
            nodes: vec![node(LOCAL), node(PEER), node(THIRD)],
            servers: vec![
                server(
                    MINE,
                    0,
                    LOCAL,
                    vec![
                        PortSpec {
                            port: 25565,
                            proto: Proto::Both,
                        },
                        PortSpec {
                            port: 8080,
                            proto: Proto::Tcp,
                        },
                        PortSpec {
                            port: 19132,
                            proto: Proto::Udp,
                        },
                    ],
                ),
                server(
                    THEIRS,
                    1,
                    PEER,
                    vec![PortSpec {
                        port: 1,
                        proto: Proto::Both,
                    }],
                ),
                server(
                    30,
                    2,
                    THIRD,
                    vec![PortSpec {
                        port: 1,
                        proto: Proto::Both,
                    }],
                ),
            ],
            acls: vec![AclEntry {
                src_server: u(THEIRS),
                dst_server: u(MINE),
            }],
        })
    }

    fn check(src: u128, dst: u128, port: u16, t: Transport) -> Result<(), StreamCode> {
        admit(&snap(), &u(PEER), &u(LOCAL), &u(src), &u(dst), port, t)
    }

    // admit

    #[test]
    fn admit_allows_a_permitted_pair_on_a_registered_port() {
        assert_eq!(check(THEIRS, MINE, 25565, Transport::Tcp), Ok(()));
        assert_eq!(check(THEIRS, MINE, 25565, Transport::Udp), Ok(()));
        assert_eq!(check(THEIRS, MINE, 8080, Transport::Tcp), Ok(()));
        assert_eq!(check(THEIRS, MINE, 19132, Transport::Udp), Ok(()));
    }

    #[test]
    fn admit_refuses_a_source_server_the_peer_does_not_host() {
        // server 30 lives on a third node; the peer must not be able to speak for it
        assert_eq!(
            check(30, MINE, 25565, Transport::Tcp),
            Err(StreamCode::NoSuchServer)
        );
        assert_eq!(
            check(MINE, MINE, 25565, Transport::Tcp),
            Err(StreamCode::NoSuchServer)
        );
        assert_eq!(
            check(999, MINE, 25565, Transport::Tcp),
            Err(StreamCode::NoSuchServer)
        );
    }

    #[test]
    fn admit_refuses_a_destination_hosted_elsewhere() {
        assert_eq!(
            check(THEIRS, THEIRS, 1, Transport::Tcp),
            Err(StreamCode::NoSuchServer)
        );
        assert_eq!(
            check(THEIRS, 999, 1, Transport::Tcp),
            Err(StreamCode::NoSuchServer)
        );
    }

    #[test]
    fn admit_refuses_a_missing_acl_despite_valid_servers() {
        let index = SnapshotIndex::new(Snapshot {
            acls: vec![],
            ..snap().snapshot().clone()
        });
        assert_eq!(
            admit(
                &index,
                &u(PEER),
                &u(LOCAL),
                &u(THEIRS),
                &u(MINE),
                25565,
                Transport::Tcp
            ),
            Err(StreamCode::AclDenied)
        );
    }

    #[test]
    fn admit_treats_the_acl_direction_as_asymmetric() {
        let index = snap();
        assert_eq!(
            admit(
                &index,
                &u(LOCAL),
                &u(PEER),
                &u(MINE),
                &u(THEIRS),
                1,
                Transport::Tcp
            ),
            Err(StreamCode::AclDenied)
        );
    }

    #[test]
    fn admit_refuses_an_unregistered_port_despite_the_acl() {
        assert_eq!(
            check(THEIRS, MINE, 22, Transport::Tcp),
            Err(StreamCode::PortNotRegistered)
        );
        assert_eq!(
            check(THEIRS, MINE, 0, Transport::Udp),
            Err(StreamCode::PortNotRegistered)
        );
    }

    #[test]
    fn admit_refuses_a_port_registered_for_the_other_protocol() {
        // 8080 is tcp-only, 19132 is udp-only
        assert_eq!(
            check(THEIRS, MINE, 8080, Transport::Udp),
            Err(StreamCode::PortNotRegistered)
        );
        assert_eq!(
            check(THEIRS, MINE, 19132, Transport::Tcp),
            Err(StreamCode::PortNotRegistered)
        );
    }

    #[test]
    fn admit_reports_unknown_servers_before_checking_the_acl() {
        assert_eq!(
            check(999, 998, 1, Transport::Tcp),
            Err(StreamCode::NoSuchServer)
        );
    }

    // port_registered

    #[test]
    fn port_registration_is_reported_per_transport() {
        let index = snap();
        assert!(port_registered(&index, &u(MINE), 25565, Transport::Tcp));
        assert!(port_registered(&index, &u(MINE), 25565, Transport::Udp));
        assert!(port_registered(&index, &u(MINE), 8080, Transport::Tcp));
        assert!(!port_registered(&index, &u(MINE), 8080, Transport::Udp));
        assert!(!port_registered(&index, &u(MINE), 22, Transport::Tcp));
        assert!(!port_registered(&index, &u(999), 25565, Transport::Tcp));
    }
}
