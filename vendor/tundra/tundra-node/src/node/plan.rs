use crate::node::{frontend::binder::Kind, naming};
use std::collections::BTreeSet;
use tundra_common::state::{SnapshotIndex, frontend_ip};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FrontendKey {
    pub src_server: uuid::Uuid,
    pub dst_server: uuid::Uuid,
    pub port: u16,
    pub kind: Kind,
}

pub fn desired_frontends(index: &SnapshotIndex, node: &uuid::Uuid) -> BTreeSet<FrontendKey> {
    let mut out = BTreeSet::new();

    for src in index.servers_on(node) {
        for dst in index.reachable_from(src) {
            let Some(peer) = index.server(dst) else {
                continue;
            };
            if frontend_ip(peer.idx).is_none() {
                continue;
            }

            for port in &peer.ports {
                if port.proto.tcp() {
                    out.insert(FrontendKey {
                        src_server: *src,
                        dst_server: *dst,
                        port: port.port,
                        kind: Kind::Tcp,
                    });
                }
                if port.proto.udp() {
                    out.insert(FrontendKey {
                        src_server: *src,
                        dst_server: *dst,
                        port: port.port,
                        kind: Kind::Udp,
                    });
                }
            }
        }
    }

    out
}

pub fn desired_hosts(index: &SnapshotIndex, src_server: &uuid::Uuid) -> Vec<naming::Entry> {
    let mut entries = Vec::new();
    for dst in index.reachable_from(src_server) {
        let Some(peer) = index.server(dst) else {
            continue;
        };
        let Some(ip) = frontend_ip(peer.idx) else {
            continue;
        };

        for name in std::iter::once(&peer.name).chain(peer.aliases.iter()) {
            if !naming::is_valid_label(name) {
                tracing::warn!(server = %peer.uuid, name, "refusing a malformed tunnel hostname");

                continue;
            }

            entries.push(naming::Entry {
                ip,
                name: name.clone(),
            });
        }
    }

    entries.sort_by(|a, b| a.name.cmp(&b.name).then(a.ip.cmp(&b.ip)));
    entries.dedup_by(|a, b| a.name == b.name);

    entries
}

pub fn needed_peers(index: &SnapshotIndex, node: &uuid::Uuid) -> BTreeSet<uuid::Uuid> {
    let mut out = BTreeSet::new();

    for src in index.servers_on(node) {
        for dst in index.reachable_from(src) {
            let Some(peer) = index.server(dst) else {
                continue;
            };
            if peer.node_uuid == *node {
                continue;
            }
            if !index
                .node(&peer.node_uuid)
                .is_some_and(|e| e.cert_sha256.is_some())
            {
                continue;
            }

            out.insert(peer.node_uuid);
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tundra_common::{
        hash::Hash32,
        state::{AclEntry, NodeEntry, PortSpec, Proto, ServerEntry, Snapshot},
    };

    fn u(n: u128) -> uuid::Uuid {
        uuid::Uuid::from_u128(n)
    }

    fn node(n: u128, cert: bool) -> NodeEntry {
        NodeEntry {
            uuid: u(n),
            name: format!("node-{n}"),
            host: "10.0.0.1".into(),
            tunnel_port: 7100,
            cert_sha256: cert.then_some(Hash32([n as u8; 32])),
        }
    }

    fn server(s: u128, idx: u16, n: u128, name: &str, ports: &[(u16, Proto)]) -> ServerEntry {
        ServerEntry {
            uuid: u(s),
            idx,
            node_uuid: u(n),
            name: name.into(),
            aliases: Vec::new(),
            container_ref: name.into(),
            dial_addr: None,
            ports: ports
                .iter()
                .map(|&(port, proto)| PortSpec { port, proto })
                .collect(),
        }
    }

    fn acl(a: u128, b: u128) -> AclEntry {
        AclEntry {
            src_server: u(a),
            dst_server: u(b),
        }
    }

    fn snap(
        nodes: Vec<NodeEntry>,
        servers: Vec<ServerEntry>,
        acls: Vec<AclEntry>,
    ) -> SnapshotIndex {
        SnapshotIndex::new(Snapshot {
            epoch: 1,
            jwt_pubkey: Hash32([0; 32]),
            nodes,
            servers,
            acls,
        })
    }

    fn two_nodes() -> SnapshotIndex {
        snap(
            vec![node(1, true), node(2, true)],
            vec![
                server(10, 0, 1, "alpha", &[(25565, Proto::Both)]),
                server(
                    20,
                    1,
                    2,
                    "beta",
                    &[(25565, Proto::Tcp), (19132, Proto::Udp)],
                ),
            ],
            vec![acl(10, 20), acl(20, 10)],
        )
    }

    // desired_frontends

    #[test]
    fn desired_frontends_binds_one_socket_per_protocol_offered() {
        let index = two_nodes();
        let got = desired_frontends(&index, &u(1));

        assert_eq!(
            got,
            BTreeSet::from([
                FrontendKey {
                    src_server: u(10),
                    dst_server: u(20),
                    port: 25565,
                    kind: Kind::Tcp
                },
                FrontendKey {
                    src_server: u(10),
                    dst_server: u(20),
                    port: 19132,
                    kind: Kind::Udp
                },
            ])
        );
    }

    #[test]
    fn desired_frontends_splits_a_both_port_into_tcp_and_udp() {
        let index = two_nodes();
        let got = desired_frontends(&index, &u(2));

        assert_eq!(
            got,
            BTreeSet::from([
                FrontendKey {
                    src_server: u(20),
                    dst_server: u(10),
                    port: 25565,
                    kind: Kind::Tcp
                },
                FrontendKey {
                    src_server: u(20),
                    dst_server: u(10),
                    port: 25565,
                    kind: Kind::Udp
                },
            ])
        );
    }

    #[test]
    fn desired_frontends_is_empty_without_an_acl() {
        let index = snap(
            vec![node(1, true), node(2, true)],
            vec![
                server(10, 0, 1, "alpha", &[(25565, Proto::Both)]),
                server(20, 1, 2, "beta", &[(25565, Proto::Tcp)]),
            ],
            vec![],
        );
        assert!(desired_frontends(&index, &u(1)).is_empty());
    }

    #[test]
    fn desired_frontends_covers_a_same_node_peer() {
        let index = snap(
            vec![node(1, true)],
            vec![
                server(10, 0, 1, "alpha", &[(1, Proto::Tcp)]),
                server(11, 1, 1, "gamma", &[(2, Proto::Tcp)]),
            ],
            vec![acl(10, 11)],
        );
        assert_eq!(
            desired_frontends(&index, &u(1)),
            BTreeSet::from([FrontendKey {
                src_server: u(10),
                dst_server: u(11),
                port: 2,
                kind: Kind::Tcp
            }])
        );
    }

    #[test]
    fn desired_frontends_skips_servers_on_other_nodes() {
        let index = two_nodes();
        assert!(
            desired_frontends(&index, &u(1))
                .iter()
                .all(|f| f.src_server == u(10))
        );
    }

    // desired_hosts

    #[test]
    fn desired_hosts_maps_peer_names_to_frontend_addresses() {
        let index = two_nodes();
        assert_eq!(
            desired_hosts(&index, &u(10)),
            vec![naming::Entry {
                ip: "127.0.1.1".parse().unwrap(),
                name: "beta".into()
            }]
        );
    }

    #[test]
    fn desired_hosts_are_sorted_so_the_file_is_stable() {
        let index = snap(
            vec![node(1, true)],
            vec![
                server(10, 0, 1, "alpha", &[(1, Proto::Tcp)]),
                server(11, 1, 1, "zulu", &[(1, Proto::Tcp)]),
                server(12, 2, 1, "mike", &[(1, Proto::Tcp)]),
            ],
            vec![acl(10, 11), acl(10, 12)],
        );
        let names: Vec<_> = desired_hosts(&index, &u(10))
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert_eq!(names, ["mike", "zulu"]);
    }

    #[test]
    fn desired_hosts_gives_every_alias_the_peers_address() {
        let mut beta = server(11, 1, 1, "beta", &[(1, Proto::Tcp)]);
        beta.aliases = vec!["deadbeef".into(), "also-beta".into()];

        let index = snap(
            vec![node(1, true)],
            vec![server(10, 0, 1, "alpha", &[(1, Proto::Tcp)]), beta],
            vec![acl(10, 11)],
        );

        assert_eq!(
            desired_hosts(&index, &u(10)),
            vec![
                naming::Entry {
                    ip: "127.0.1.1".parse().unwrap(),
                    name: "also-beta".into()
                },
                naming::Entry {
                    ip: "127.0.1.1".parse().unwrap(),
                    name: "beta".into()
                },
                naming::Entry {
                    ip: "127.0.1.1".parse().unwrap(),
                    name: "deadbeef".into()
                },
            ]
        );
    }

    #[test]
    fn desired_hosts_refuses_a_malformed_hostname() {
        let mut beta = server(11, 1, 1, "beta", &[(1, Proto::Tcp)]);
        beta.aliases = vec!["evil\n127.0.0.1 target".into()];

        let index = snap(
            vec![node(1, true)],
            vec![server(10, 0, 1, "alpha", &[(1, Proto::Tcp)]), beta],
            vec![acl(10, 11)],
        );

        let names: Vec<_> = desired_hosts(&index, &u(10))
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert_eq!(names, ["beta"]);
    }

    #[test]
    fn a_name_collision_resolves_the_same_way_whatever_the_snapshot_order() {
        let mut first = server(11, 1, 1, "beta", &[(1, Proto::Tcp)]);
        first.aliases = vec!["shared".into()];
        let mut second = server(12, 2, 1, "gamma", &[(1, Proto::Tcp)]);
        second.aliases = vec!["shared".into()];

        let forwards = snap(
            vec![node(1, true)],
            vec![
                server(10, 0, 1, "alpha", &[(1, Proto::Tcp)]),
                first.clone(),
                second.clone(),
            ],
            vec![acl(10, 11), acl(10, 12)],
        );
        let backwards = snap(
            vec![node(1, true)],
            vec![server(10, 0, 1, "alpha", &[(1, Proto::Tcp)]), second, first],
            vec![acl(10, 12), acl(10, 11)],
        );

        assert_eq!(
            desired_hosts(&forwards, &u(10)),
            desired_hosts(&backwards, &u(10))
        );
    }

    #[test]
    fn desired_hosts_is_empty_for_a_server_with_no_peers() {
        let index = two_nodes();
        assert!(desired_hosts(&index, &u(999)).is_empty());
    }

    // needed_peers

    #[test]
    fn needed_peers_only_names_nodes_hosting_reachable_servers() {
        let index = snap(
            vec![node(1, true), node(2, true), node(3, true)],
            vec![
                server(10, 0, 1, "alpha", &[(1, Proto::Tcp)]),
                server(20, 1, 2, "beta", &[(1, Proto::Tcp)]),
                server(30, 2, 3, "gamma", &[(1, Proto::Tcp)]),
            ],
            vec![acl(10, 20)],
        );
        assert_eq!(needed_peers(&index, &u(1)), BTreeSet::from([u(2)]));
    }

    #[test]
    fn needed_peers_excludes_self() {
        let index = snap(
            vec![node(1, true)],
            vec![
                server(10, 0, 1, "alpha", &[(1, Proto::Tcp)]),
                server(11, 1, 1, "gamma", &[(1, Proto::Tcp)]),
            ],
            vec![acl(10, 11)],
        );
        assert!(needed_peers(&index, &u(1)).is_empty());
    }

    #[test]
    fn needed_peers_skips_a_node_without_a_certificate() {
        let index = snap(
            vec![node(1, true), node(2, false)],
            vec![
                server(10, 0, 1, "alpha", &[(1, Proto::Tcp)]),
                server(20, 1, 2, "beta", &[(1, Proto::Tcp)]),
            ],
            vec![acl(10, 20)],
        );
        assert!(needed_peers(&index, &u(1)).is_empty());
    }

    #[test]
    fn needed_peers_ignores_inbound_only_acls() {
        let index = snap(
            vec![node(1, true), node(2, true)],
            vec![
                server(10, 0, 1, "alpha", &[(1, Proto::Tcp)]),
                server(20, 1, 2, "beta", &[(1, Proto::Tcp)]),
            ],
            vec![acl(20, 10)],
        );
        assert!(needed_peers(&index, &u(1)).is_empty());
        assert_eq!(needed_peers(&index, &u(2)), BTreeSet::from([u(1)]));
    }
}
