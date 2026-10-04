use crate::node::{frontend::binder::Kind, relay::flows::Side};
use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, os::fd::RawFd};
use tundra_common::{state::Snapshot, wire::HalfClose};

pub const MAGIC: [u8; 4] = *b"CTRB";
// a mismatch is a cold start, never a best-effort parse: a guessed descriptor is worse than none
pub const SCHEMA: u32 = 1;
pub const RESUME_FD_ENV: &str = "TUNDRA_RESUME_FD";

pub type Carried = (RawFd, FdKind);

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FrontendRec {
    pub fd: RawFd,
    pub kind: Kind,
    pub frontend_id: u64,
    pub pid: i32,
    pub src_server: uuid::Uuid,
    pub dst_server: uuid::Uuid,
    pub port: u16,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TcpFlowRec {
    pub fd: RawFd,
    pub flow_id: u64,
    pub peer: uuid::Uuid,
    pub side: Side,

    pub src_server: uuid::Uuid,
    pub dst_server: uuid::Uuid,
    pub dst_port: u16,

    pub written: u64,
    pub consumed: u64,
    pub pending_send: Vec<u8>,
    pub pending_write: Vec<u8>,
    pub half: HalfClose,
}

// no fd: the socket this flow replies through is the frontend, carried separately
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UdpEgressRec {
    pub flow_id: u64,
    pub peer: uuid::Uuid,
    pub frontend_id: u64,
    pub client: SocketAddr,
    pub src_server: uuid::Uuid,
    pub dst_server: uuid::Uuid,
    pub dst_port: u16,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UdpIngressRec {
    pub fd: RawFd,
    pub flow_id: u64,
    pub peer: uuid::Uuid,
    pub src_server: uuid::Uuid,
    pub dst_server: uuid::Uuid,
    pub dst_port: u16,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PeerRec {
    pub peer: uuid::Uuid,
    pub parity_even: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Blob {
    pub old_instance: u64,
    pub triggered_unix_ms: u64,
    pub generation: u64,

    pub node_uuid: uuid::Uuid,
    pub snapshot: Snapshot,
    pub next_frontend_id: u64,

    pub peers: Vec<PeerRec>,
    pub frontends: Vec<FrontendRec>,
    pub tcp_flows: Vec<TcpFlowRec>,
    pub udp_egress: Vec<UdpEgressRec>,
    pub udp_ingress: Vec<UdpIngressRec>,
}

impl Blob {
    pub fn fds(&self) -> Vec<Carried> {
        self.frontends
            .iter()
            .map(|f| (f.fd, FdKind::Plain))
            .chain(self.tcp_flows.iter().map(|f| (f.fd, FdKind::Relay)))
            .chain(self.udp_ingress.iter().map(|f| (f.fd, FdKind::Plain)))
            .collect()
    }

    #[inline]
    pub fn carried_bytes(&self) -> usize {
        self.tcp_flows
            .iter()
            .map(|f| f.pending_send.len() + f.pending_write.len())
            .sum()
    }
}

// a relay socket must be reset, not closed: a FIN reads to the application as a clean transfer
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum FdKind {
    Plain = 0,
    Relay = 1,
}

impl FdKind {
    #[inline]
    fn from_u32(v: u32) -> Self {
        match v {
            1 => FdKind::Relay,
            // guessing "relay" on a descriptor of unknown provenance is the riskier default
            _ => FdKind::Plain,
        }
    }
}

pub fn encode(blob: &Blob) -> Result<Vec<u8>, anyhow::Error> {
    let body = postcard::to_stdvec(blob).context("failed to encode the handover blob")?;
    let fds = blob.fds();

    let mut out = Vec::with_capacity(20 + fds.len() * 8 + body.len());
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&SCHEMA.to_le_bytes());
    out.extend_from_slice(&(fds.len() as u32).to_le_bytes());
    for (fd, kind) in &fds {
        out.extend_from_slice(&(*fd as u32).to_le_bytes());
        out.extend_from_slice(&(*kind as u32).to_le_bytes());
    }

    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(&body);

    Ok(out)
}

#[derive(Debug)]
pub enum Decoded {
    Ok(Box<Blob>),
    Unusable { fds: Vec<Carried>, why: String },
}

pub fn decode(bytes: &[u8]) -> Decoded {
    let (schema, fds, rest) = match header(bytes) {
        Ok(parts) => parts,
        Err(err) => {
            return Decoded::Unusable {
                fds: Vec::new(),
                why: err.to_string(),
            };
        }
    };

    // a listening socket left open with no owner pins a container's network namespace, so
    // every failure from here still names the fds, a schema this image cannot read included
    if schema != SCHEMA {
        return Decoded::Unusable {
            fds,
            why: format!("blob schema {schema}, this image speaks {SCHEMA}"),
        };
    }

    let body = match body(rest) {
        Ok(body) => body,
        Err(err) => {
            return Decoded::Unusable {
                fds,
                why: err.to_string(),
            };
        }
    };

    match postcard::from_bytes::<Blob>(body) {
        Ok(blob) => Decoded::Ok(Box::new(blob)),
        Err(err) => Decoded::Unusable {
            fds,
            why: format!("blob body: {err}"),
        },
    }
}

fn take<'a>(bytes: &'a [u8], at: &mut usize, n: usize) -> Result<&'a [u8], anyhow::Error> {
    let end = at
        .checked_add(n)
        .context("failed to read the blob, its header overflows")?;
    let slice = bytes
        .get(*at..end)
        .context("failed to read the blob, it is truncated")?;
    *at = end;
    Ok(slice)
}

fn word(bytes: &[u8], at: &mut usize) -> Result<u32, anyhow::Error> {
    let word = take(bytes, at, 4)?
        .try_into()
        .context("failed to read a four-byte word from the blob")?;

    Ok(u32::from_le_bytes(word))
}

fn header(bytes: &[u8]) -> Result<(u32, Vec<Carried>, &[u8]), anyhow::Error> {
    let mut at = 0;
    if take(bytes, &mut at, 4)? != MAGIC {
        return Err(anyhow::anyhow!("not a handover blob"));
    }

    let schema = word(bytes, &mut at)?;

    let count = word(bytes, &mut at)? as usize;
    // bounded so a corrupt header cannot ask for the allocation before the fds are read
    let mut fds = Vec::with_capacity(count.min(1024));
    for _ in 0..count {
        let fd = word(bytes, &mut at)? as RawFd;
        fds.push((fd, FdKind::from_u32(word(bytes, &mut at)?)));
    }

    let rest = bytes
        .get(at..)
        .context("failed to read the blob, it is truncated")?;

    Ok((schema, fds, rest))
}

fn body(rest: &[u8]) -> Result<&[u8], anyhow::Error> {
    let mut at = 0;
    let len = word(rest, &mut at)? as usize;
    take(rest, &mut at, len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::restart::exec::{Carrier, close_raw};
    use std::os::fd::{AsRawFd, FromRawFd};
    use tundra_common::hash::Hash32;

    fn ok(decoded: Decoded) -> Option<Box<Blob>> {
        match decoded {
            Decoded::Ok(blob) => Some(blob),
            Decoded::Unusable { .. } => None,
        }
    }

    fn unusable(decoded: Decoded) -> Option<(Vec<Carried>, String)> {
        match decoded {
            Decoded::Unusable { fds, why } => Some((fds, why)),
            Decoded::Ok(_) => None,
        }
    }

    fn blob() -> Blob {
        Blob {
            old_instance: 7,
            triggered_unix_ms: 1_700_000_000_000,
            generation: 3,
            node_uuid: uuid::Uuid::from_u128(1),
            snapshot: Snapshot {
                epoch: 42,
                jwt_pubkey: Hash32([9; 32]),
                nodes: Vec::new(),
                servers: Vec::new(),
                acls: Vec::new(),
            },
            next_frontend_id: 11,
            peers: vec![PeerRec {
                peer: uuid::Uuid::from_u128(2),
                parity_even: false,
            }],
            frontends: vec![FrontendRec {
                fd: 20,
                kind: Kind::Tcp,
                frontend_id: 4,
                pid: 1234,
                src_server: uuid::Uuid::from_u128(10),
                dst_server: uuid::Uuid::from_u128(20),
                port: 25565,
            }],
            tcp_flows: vec![TcpFlowRec {
                fd: 21,
                flow_id: 6,
                peer: uuid::Uuid::from_u128(2),
                side: Side::Frontend,
                src_server: uuid::Uuid::from_u128(10),
                dst_server: uuid::Uuid::from_u128(20),
                dst_port: 25565,
                written: 900,
                consumed: 512,
                pending_send: vec![1, 2, 3],
                pending_write: vec![4],
                half: HalfClose {
                    tx_done: true,
                    rx_done: false,
                },
            }],
            udp_egress: vec![UdpEgressRec {
                flow_id: 8,
                peer: uuid::Uuid::from_u128(2),
                frontend_id: 4,
                client: "127.0.1.1:5000".parse().unwrap(),
                src_server: uuid::Uuid::from_u128(10),
                dst_server: uuid::Uuid::from_u128(20),
                dst_port: 19132,
            }],
            udp_ingress: vec![UdpIngressRec {
                fd: 22,
                flow_id: 9,
                peer: uuid::Uuid::from_u128(2),
                src_server: uuid::Uuid::from_u128(20),
                dst_server: uuid::Uuid::from_u128(10),
                dst_port: 19132,
            }],
        }
    }

    // encode / decode

    #[test]
    fn encode_round_trips_every_record_kind() {
        let original = blob();
        let back = ok(decode(&encode(&original).unwrap())).unwrap();

        assert_eq!(back.node_uuid, original.node_uuid);
        assert_eq!(back.snapshot.epoch, 42);
        assert_eq!(back.next_frontend_id, 11);
        assert_eq!(back.tcp_flows[0].pending_send, [1, 2, 3]);
        assert!(back.tcp_flows[0].half.tx_done);
        assert!(!back.tcp_flows[0].half.rx_done);
        assert_eq!(back.udp_egress[0].client.port(), 5000);
        assert_eq!(
            back.fds(),
            [
                (20, FdKind::Plain),
                (21, FdKind::Relay),
                (22, FdKind::Plain)
            ]
        );
        assert_eq!(back.carried_bytes(), 4);
    }

    #[test]
    fn decode_refuses_a_schema_mismatch_but_still_names_every_descriptor() {
        let mut bytes = encode(&blob()).unwrap();
        bytes[4..8].copy_from_slice(&(SCHEMA + 1).to_le_bytes());

        let (fds, why) = unusable(decode(&bytes)).unwrap();
        assert!(why.contains("schema"), "{why}");
        assert_eq!(
            fds,
            [
                (20, FdKind::Plain),
                (21, FdKind::Relay),
                (22, FdKind::Plain)
            ]
        );
    }

    #[test]
    fn decode_names_every_descriptor_when_the_body_is_unparseable() {
        let mut corrupt = encode(&blob()).unwrap();
        let last = corrupt.len() - 1;
        corrupt[last] ^= 0xff;

        let (fds, why) = unusable(decode(&corrupt)).unwrap();
        assert!(why.contains("body"), "{why}");
        assert_eq!(fds.len(), 3);
        assert_eq!(fds[1].1, FdKind::Relay);

        let mut truncated = encode(&blob()).unwrap();
        truncated.truncate(truncated.len() - 8);
        let (fds, _) = unusable(decode(&truncated)).unwrap();
        assert_eq!(fds.len(), 3);
    }

    #[test]
    fn decode_refuses_a_non_blob_without_claiming_descriptors() {
        for bytes in [&b""[..], b"CTR", b"XXXX\x01\x00\x00\x00", &[0; 64]] {
            let (fds, _) = unusable(decode(bytes)).unwrap();
            assert!(fds.is_empty());
        }
    }

    #[test]
    fn descriptors_survive_the_round_trip_and_still_name_the_same_sockets() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let mut carrier = Carrier::default();
        let carried = carrier.carry(listener.as_raw_fd()).unwrap();

        let mut original = blob();
        original.frontends[0].fd = carried;
        original.tcp_flows.clear();
        original.udp_ingress.clear();

        let back = ok(decode(&encode(&original).unwrap())).unwrap();
        assert_eq!(back.fds(), [(carried, FdKind::Plain)]);

        // SAFETY: the carried fd is a live duplicate owned by this test, and the forget below
        // leaves the single close to close_raw
        let adopted = unsafe { std::net::TcpListener::from_raw_fd(back.frontends[0].fd) };
        assert_eq!(adopted.local_addr().unwrap(), addr);
        std::mem::forget(adopted);
        close_raw(carried);
    }

    #[test]
    fn decode_does_not_allocate_a_descriptor_count_larger_than_the_blob() {
        let mut bytes = encode(&blob()).unwrap();
        bytes[8..12].copy_from_slice(&u32::MAX.to_le_bytes());

        let (fds, _) = unusable(decode(&bytes)).unwrap();
        assert!(fds.is_empty());
    }
}
