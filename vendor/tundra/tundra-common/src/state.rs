use crate::hash::Hash32;
use compact_str::ToCompactString;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    net::Ipv4Addr,
};

pub const MAX_SERVER_IDX: u16 = 255 * 256 - 1;

#[inline]
pub fn frontend_ip(idx: u16) -> Option<Ipv4Addr> {
    (idx <= MAX_SERVER_IDX).then(|| Ipv4Addr::new(127, 0, 1 + (idx / 256) as u8, (idx % 256) as u8))
}

pub fn revoked_nodes(old: &SnapshotIndex, new: &SnapshotIndex) -> Vec<uuid::Uuid> {
    let mut revoked = Vec::new();
    for prev in old.nodes() {
        let Some(cur) = new.node(&prev.uuid) else {
            revoked.push(prev.uuid);
            continue;
        };

        if prev.cert_sha256.is_some() && cur.cert_sha256 != prev.cert_sha256 {
            revoked.push(prev.uuid);
        }
    }

    revoked
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    Tcp,
    Udp,
    Both,
}

impl Proto {
    #[inline]
    pub fn tcp(self) -> bool {
        matches!(self, Self::Tcp | Self::Both)
    }

    #[inline]
    pub fn udp(self) -> bool {
        matches!(self, Self::Udp | Self::Both)
    }

    #[inline]
    pub fn to_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Both => "both",
        }
    }
}

impl std::str::FromStr for Proto {
    type Err = UnknownProto;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "tcp" => Ok(Proto::Tcp),
            "udp" => Ok(Proto::Udp),
            "both" => Ok(Proto::Both),
            other => Err(UnknownProto(other.to_compact_string())),
        }
    }
}

#[derive(Debug)]
#[repr(transparent)]
pub struct UnknownProto(compact_str::CompactString);

impl std::fmt::Display for UnknownProto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "unknown protocol {:?}, expected tcp|udp|both", self.0)
    }
}

impl std::error::Error for UnknownProto {}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Hash)]
pub struct PortSpec {
    pub port: u16,
    pub proto: Proto,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct NodeEntry {
    pub uuid: uuid::Uuid,
    pub name: String,
    pub host: String,
    pub tunnel_port: u16,
    pub cert_sha256: Option<Hash32>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct ServerEntry {
    pub uuid: uuid::Uuid,
    pub idx: u16,
    pub node_uuid: uuid::Uuid,

    pub name: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    pub container_ref: String,
    pub dial_addr: Option<String>,
    pub ports: Vec<PortSpec>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AclEntry {
    pub src_server: uuid::Uuid,
    pub dst_server: uuid::Uuid,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct Snapshot {
    pub epoch: u64,
    pub jwt_pubkey: Hash32,
    pub nodes: Vec<NodeEntry>,
    pub servers: Vec<ServerEntry>,
    pub acls: Vec<AclEntry>,
}

impl Snapshot {
    pub fn empty() -> Self {
        Self {
            epoch: 0,
            jwt_pubkey: Hash32([0; 32]),
            nodes: Vec::new(),
            servers: Vec::new(),
            acls: Vec::new(),
        }
    }
}

#[derive(Debug)]
pub struct SnapshotIndex {
    snapshot: Snapshot,
    nodes: HashMap<uuid::Uuid, usize>,
    servers: HashMap<uuid::Uuid, usize>,

    node_by_cert: HashMap<Hash32, uuid::Uuid>,
    servers_by_node: HashMap<uuid::Uuid, Vec<uuid::Uuid>>,

    acls: HashSet<(uuid::Uuid, uuid::Uuid)>,
    reach: HashMap<uuid::Uuid, Vec<uuid::Uuid>>,
}

impl SnapshotIndex {
    pub fn new(snapshot: Snapshot) -> Self {
        let nodes = snapshot
            .nodes
            .iter()
            .enumerate()
            .map(|(i, n)| (n.uuid, i))
            .collect();
        let servers: HashMap<_, _> = snapshot
            .servers
            .iter()
            .enumerate()
            .map(|(i, s)| (s.uuid, i))
            .collect();
        let node_by_cert = snapshot
            .nodes
            .iter()
            .filter_map(|n| n.cert_sha256.map(|h| (h, n.uuid)))
            .collect();

        let mut servers_by_node: HashMap<_, Vec<_>> = HashMap::new();
        for s in &snapshot.servers {
            servers_by_node.entry(s.node_uuid).or_default().push(s.uuid);
        }

        let mut acls = HashSet::new();
        let mut reach: HashMap<_, Vec<_>> = HashMap::new();
        for a in &snapshot.acls {
            if !servers.contains_key(&a.src_server) || !servers.contains_key(&a.dst_server) {
                continue;
            }

            if acls.insert((a.src_server, a.dst_server)) {
                reach.entry(a.src_server).or_default().push(a.dst_server);
            }
        }

        Self {
            snapshot,
            nodes,
            servers,
            node_by_cert,
            servers_by_node,
            acls,
            reach,
        }
    }

    #[inline]
    pub fn snapshot(&self) -> &Snapshot {
        &self.snapshot
    }

    #[inline]
    pub fn epoch(&self) -> u64 {
        self.snapshot.epoch
    }

    #[inline]
    pub fn node(&self, uuid: &uuid::Uuid) -> Option<&NodeEntry> {
        self.nodes
            .get(uuid)
            .and_then(|&i| self.snapshot.nodes.get(i))
    }

    #[inline]
    pub fn server(&self, uuid: &uuid::Uuid) -> Option<&ServerEntry> {
        self.servers
            .get(uuid)
            .and_then(|&i| self.snapshot.servers.get(i))
    }

    #[inline]
    pub fn nodes(&self) -> &[NodeEntry] {
        &self.snapshot.nodes
    }

    #[inline]
    pub fn servers(&self) -> &[ServerEntry] {
        &self.snapshot.servers
    }

    #[inline]
    pub fn node_by_cert(&self, hash: &Hash32) -> Option<uuid::Uuid> {
        self.node_by_cert.get(hash).copied()
    }

    #[inline]
    pub fn servers_on(&self, node: &uuid::Uuid) -> &[uuid::Uuid] {
        self.servers_by_node.get(node).map_or(&[], Vec::as_slice)
    }

    #[inline]
    pub fn allows(&self, src: &uuid::Uuid, dst: &uuid::Uuid) -> bool {
        self.acls.contains(&(*src, *dst))
    }

    /// ACL entries with dangling endpoints are already filtered out.
    #[inline]
    pub fn reachable_from(&self, src: &uuid::Uuid) -> &[uuid::Uuid] {
        self.reach.get(src).map_or(&[], Vec::as_slice)
    }

    #[inline]
    pub fn owns_server(&self, node: &uuid::Uuid, server: &uuid::Uuid) -> bool {
        self.server(server).is_some_and(|s| s.node_uuid == *node)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(n: u128) -> uuid::Uuid {
        uuid::Uuid::from_u128(n)
    }

    fn server(uuid: uuid::Uuid, idx: u16, node: uuid::Uuid) -> ServerEntry {
        ServerEntry {
            uuid,
            idx,
            node_uuid: node,
            name: format!("s{idx}"),
            aliases: Vec::new(),
            container_ref: format!("c{idx}"),
            dial_addr: None,
            ports: vec![PortSpec {
                port: 25565,
                proto: Proto::Both,
            }],
        }
    }

    fn node(uuid: uuid::Uuid, cert: Option<u8>) -> NodeEntry {
        NodeEntry {
            uuid,
            name: format!("n{uuid}"),
            host: "10.0.0.1".into(),
            tunnel_port: 7100,
            cert_sha256: cert.map(|b| Hash32([b; 32])),
        }
    }

    fn snap(
        nodes: Vec<NodeEntry>,
        servers: Vec<ServerEntry>,
        acls: Vec<AclEntry>,
    ) -> SnapshotIndex {
        SnapshotIndex::new(Snapshot {
            epoch: 1,
            jwt_pubkey: Hash32([9; 32]),
            nodes,
            servers,
            acls,
        })
    }

    // frontend_ip

    #[test]
    fn frontend_ip_layout() {
        assert_eq!(frontend_ip(0).unwrap(), Ipv4Addr::new(127, 0, 1, 0));
        assert_eq!(frontend_ip(1).unwrap(), Ipv4Addr::new(127, 0, 1, 1));
        assert_eq!(frontend_ip(255).unwrap(), Ipv4Addr::new(127, 0, 1, 255));
        assert_eq!(frontend_ip(256).unwrap(), Ipv4Addr::new(127, 0, 2, 0));
        assert_eq!(
            frontend_ip(MAX_SERVER_IDX).unwrap(),
            Ipv4Addr::new(127, 0, 255, 255)
        );
    }

    #[test]
    fn frontend_ip_rejects_unrepresentable_index() {
        assert!(frontend_ip(MAX_SERVER_IDX + 1).is_none());
        assert!(frontend_ip(u16::MAX).is_none());
    }

    #[test]
    fn frontend_ips_are_unique_across_the_index_space() {
        let mut seen = HashSet::new();
        for idx in 0..=MAX_SERVER_IDX {
            assert!(seen.insert(frontend_ip(idx).unwrap()));
        }
    }

    // SnapshotIndex

    #[test]
    fn acl_is_directional() {
        let index = snap(
            vec![node(u(1), Some(1))],
            vec![server(u(10), 0, u(1)), server(u(11), 1, u(1))],
            vec![AclEntry {
                src_server: u(10),
                dst_server: u(11),
            }],
        );
        assert!(index.allows(&u(10), &u(11)));
        assert!(!index.allows(&u(11), &u(10)));
        assert_eq!(index.reachable_from(&u(10)), [u(11)]);
        assert!(index.reachable_from(&u(11)).is_empty());
    }

    #[test]
    fn dangling_acl_endpoints_are_dropped() {
        let index = snap(
            vec![node(u(1), Some(1))],
            vec![server(u(10), 0, u(1))],
            vec![
                AclEntry {
                    src_server: u(10),
                    dst_server: u(99),
                },
                AclEntry {
                    src_server: u(98),
                    dst_server: u(10),
                },
            ],
        );
        assert!(!index.allows(&u(10), &u(99)));
        assert!(index.reachable_from(&u(10)).is_empty());
    }

    #[test]
    fn duplicate_acl_rows_do_not_duplicate_reachability() {
        let a = AclEntry {
            src_server: u(10),
            dst_server: u(11),
        };
        let index = snap(
            vec![node(u(1), Some(1))],
            vec![server(u(10), 0, u(1)), server(u(11), 1, u(1))],
            vec![a, a],
        );
        assert_eq!(index.reachable_from(&u(10)).len(), 1);
    }

    #[test]
    fn cert_hash_maps_to_owning_node() {
        let index = snap(vec![node(u(1), Some(1)), node(u(2), None)], vec![], vec![]);
        assert_eq!(index.node_by_cert(&Hash32([1; 32])), Some(u(1)));
        assert_eq!(index.node_by_cert(&Hash32([2; 32])), None);
    }

    #[test]
    fn ownership_check_rejects_foreign_servers() {
        let index = snap(
            vec![node(u(1), Some(1)), node(u(2), Some(2))],
            vec![server(u(10), 0, u(1))],
            vec![],
        );
        assert!(index.owns_server(&u(1), &u(10)));
        assert!(!index.owns_server(&u(2), &u(10)));
        assert!(!index.owns_server(&u(1), &u(999)));
    }

    // revoked_nodes

    #[test]
    fn revocation_detects_changed_cleared_and_removed_certs() {
        let old = snap(
            vec![
                node(u(1), Some(1)),
                node(u(2), Some(2)),
                node(u(3), Some(3)),
                node(u(4), Some(4)),
            ],
            vec![],
            vec![],
        );
        let new = snap(
            vec![node(u(1), Some(1)), node(u(2), Some(9)), node(u(3), None)],
            vec![],
            vec![],
        );

        let mut revoked = revoked_nodes(&old, &new);
        revoked.sort();
        assert_eq!(revoked, [u(2), u(3), u(4)]);
    }

    #[test]
    fn revocation_ignores_a_node_gaining_its_first_cert() {
        let old = snap(vec![node(u(1), None)], vec![], vec![]);
        let new = snap(vec![node(u(1), Some(7))], vec![], vec![]);
        assert!(revoked_nodes(&old, &new).is_empty());
    }
}
