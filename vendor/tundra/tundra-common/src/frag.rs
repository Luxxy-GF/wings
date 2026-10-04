use crate::datagram::{DatagramHeader, FragHeader, header_len, put_header};
use bytes::Bytes;
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

pub const FRAG_TIMEOUT: Duration = Duration::from_secs(2);
pub const FRAG_MAX_GROUP_BYTES: usize = 64 * 1024;
pub const FRAG_MAX_GROUPS: usize = 8;

#[derive(Debug)]
pub enum FragError {
    TooLarge { len: usize, mtu: usize },
    NoRoom { mtu: usize },
}

impl std::fmt::Display for FragError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FragError::TooLarge { len, mtu } => write!(
                f,
                "payload of {len} bytes needs more than 255 fragments at {mtu} byte datagrams"
            ),
            FragError::NoRoom { mtu } => write!(
                f,
                "datagram limit of {mtu} bytes leaves no room for a fragment payload"
            ),
        }
    }
}

impl std::error::Error for FragError {}

pub fn build_datagrams(
    flow_id: u64,
    group: u16,
    payload: &[u8],
    max_datagram: usize,
) -> Result<Vec<Bytes>, FragError> {
    let plain = header_len(flow_id, false);
    if plain + payload.len() <= max_datagram {
        let mut buf = Vec::with_capacity(plain + payload.len());
        put_header(
            DatagramHeader {
                flow_id,
                frag: None,
            },
            &mut buf,
        );
        buf.extend_from_slice(payload);
        return Ok(vec![buf.into()]);
    }

    let fragged = header_len(flow_id, true);
    let room = max_datagram
        .checked_sub(fragged)
        .filter(|&r| r > 0)
        .ok_or(FragError::NoRoom { mtu: max_datagram })?;

    let count = payload.len().div_ceil(room);
    if count > u8::MAX as usize {
        return Err(FragError::TooLarge {
            len: payload.len(),
            mtu: max_datagram,
        });
    }

    let mut out = Vec::with_capacity(count);
    for (i, chunk) in payload.chunks(room).enumerate() {
        let mut buf = Vec::with_capacity(fragged + chunk.len());
        put_header(
            DatagramHeader {
                flow_id,
                frag: Some(FragHeader {
                    group,
                    index: i as u8,
                    count: count as u8,
                }),
            },
            &mut buf,
        );
        buf.extend_from_slice(chunk);
        out.push(buf.into());
    }

    Ok(out)
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FragDrops {
    pub timeout: u64,
    pub limit: u64,
    pub oversize: u64,
    pub malformed: u64,
}

impl FragDrops {
    #[inline]
    pub fn total(&self) -> u64 {
        self.timeout + self.limit + self.oversize + self.malformed
    }
}

#[derive(Debug)]
struct Group {
    parts: Vec<Option<Vec<u8>>>,
    have: usize,
    bytes: usize,
    started: Instant,
}

/// One per flow and direction: groups are keyed by group id alone, so a shared reassembler
/// mixes flows.
#[derive(Debug, Default)]
pub struct FragReassembler {
    groups: HashMap<u16, Group>,
    drops: FragDrops,
}

impl FragReassembler {
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    #[inline]
    pub fn take_drops(&mut self) -> FragDrops {
        std::mem::take(&mut self.drops)
    }

    #[inline]
    pub fn groups(&self) -> usize {
        self.groups.len()
    }

    pub fn gc(&mut self, now: Instant) {
        let before = self.groups.len();
        self.groups
            .retain(|_, g| now.duration_since(g.started) < FRAG_TIMEOUT);
        self.drops.timeout += (before - self.groups.len()) as u64;
    }

    pub fn push(&mut self, hdr: FragHeader, payload: &[u8], now: Instant) -> Option<Vec<u8>> {
        self.gc(now);

        if hdr.count == 0 || hdr.index >= hdr.count {
            self.drops.malformed += 1;
            return None;
        }
        if payload.len() > FRAG_MAX_GROUP_BYTES {
            self.drops.oversize += 1;
            return None;
        }

        if !self.groups.contains_key(&hdr.group)
            && self.groups.len() >= FRAG_MAX_GROUPS
            && let Some(oldest) = self
                .groups
                .iter()
                .min_by_key(|(_, g)| g.started)
                .map(|(&k, _)| k)
        {
            self.groups.remove(&oldest);
            self.drops.limit += 1;
        }

        let group = self.groups.entry(hdr.group).or_insert_with(|| Group {
            parts: vec![None; hdr.count as usize],
            have: 0,
            bytes: 0,
            started: now,
        });

        if group.parts.len() != hdr.count as usize {
            self.groups.remove(&hdr.group);
            self.drops.malformed += 1;
            return None;
        }

        let Some(slot) = group.parts.get_mut(hdr.index as usize) else {
            self.drops.malformed += 1;
            return None;
        };

        if slot.is_some() {
            return None;
        }

        if group.bytes + payload.len() > FRAG_MAX_GROUP_BYTES {
            self.groups.remove(&hdr.group);
            self.drops.oversize += 1;
            return None;
        }

        *slot = Some(payload.to_vec());
        group.have += 1;
        group.bytes += payload.len();

        if group.have < group.parts.len() {
            return None;
        }

        let done = self.groups.remove(&hdr.group)?;
        let mut out = Vec::with_capacity(done.bytes);
        for part in done.parts {
            out.extend_from_slice(&part?);
        }

        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::datagram::parse;

    fn frags(datagrams: &[Bytes]) -> Vec<(FragHeader, Vec<u8>)> {
        datagrams
            .iter()
            .map(|d| {
                let (h, p) = parse(d).unwrap();
                (h.frag.unwrap(), p.to_vec())
            })
            .collect()
    }

    // build_datagrams

    #[test]
    fn small_payloads_stay_unfragmented() {
        let dg = build_datagrams(1, 0, b"hello", 1200).unwrap();
        assert_eq!(dg.len(), 1);
        let (h, p) = parse(&dg[0]).unwrap();
        assert_eq!(h.flow_id, 1);
        assert!(h.frag.is_none());
        assert_eq!(p, b"hello");
    }

    #[test]
    fn payload_exactly_filling_a_datagram_stays_unfragmented() {
        let mtu = 1200;
        let payload = vec![7; mtu - header_len(5, false)];
        let dg = build_datagrams(5, 0, &payload, mtu).unwrap();
        assert_eq!(dg.len(), 1);
        assert_eq!(dg[0].len(), mtu);

        let payload = vec![7; payload.len() + 1];
        assert!(build_datagrams(5, 0, &payload, mtu).unwrap().len() > 1);
    }

    #[test]
    fn fragments_respect_the_datagram_limit_and_are_indexed() {
        let payload: Vec<_> = (0..8192).map(|i| i as u8).collect();
        let dg = build_datagrams(1234, 42, &payload, 1200).unwrap();
        assert!(dg.len() > 1);
        assert!(dg.iter().all(|d| d.len() <= 1200));

        for (i, (h, _)) in frags(&dg).iter().enumerate() {
            assert_eq!(h.group, 42);
            assert_eq!(h.index as usize, i);
            assert_eq!(h.count as usize, dg.len());
        }
    }

    #[test]
    fn build_datagrams_refuses_payloads_needing_more_than_255_fragments() {
        let payload = vec![0; 64 * 1024];

        let too_large = build_datagrams(1, 0, &payload, 100)
            .unwrap_err()
            .to_string();
        assert!(too_large.contains("more than 255 fragments"));

        let no_room = build_datagrams(1, 0, &payload, 4).unwrap_err().to_string();
        assert!(no_room.contains("no room for a fragment payload"));
    }

    // FragReassembler

    fn feed(
        r: &mut FragReassembler,
        parts: &[(FragHeader, Vec<u8>)],
        now: Instant,
    ) -> Option<Vec<u8>> {
        let mut out = None;
        for (h, p) in parts {
            if let Some(done) = r.push(*h, p, now) {
                assert!(out.is_none());
                out = Some(done);
            }
        }

        out
    }

    #[test]
    fn reassembles_in_order() {
        let payload: Vec<_> = (0..8192).map(|i| (i % 251) as u8).collect();
        let parts = frags(&build_datagrams(1, 0, &payload, 1200).unwrap());
        let mut r = FragReassembler::new();

        assert_eq!(feed(&mut r, &parts, Instant::now()), Some(payload));
        assert_eq!(r.take_drops(), FragDrops::default());
        assert_eq!(r.groups(), 0);
    }

    #[test]
    fn reassembles_out_of_order() {
        let payload: Vec<_> = (0..8192).map(|i| (i % 251) as u8).collect();
        let mut parts = frags(&build_datagrams(1, 0, &payload, 1200).unwrap());
        parts.reverse();
        let mut r = FragReassembler::new();

        assert_eq!(feed(&mut r, &parts, Instant::now()), Some(payload));
        assert_eq!(r.take_drops(), FragDrops::default());
    }

    #[test]
    fn duplicate_fragments_are_ignored_not_counted() {
        let payload = vec![3; 4096];
        let parts = frags(&build_datagrams(1, 0, &payload, 1200).unwrap());
        let now = Instant::now();
        let mut r = FragReassembler::new();

        for (h, p) in &parts[..parts.len() - 1] {
            assert!(r.push(*h, p, now).is_none());
            assert!(r.push(*h, p, now).is_none());
        }

        assert_eq!(r.groups(), 1);
        assert_eq!(r.take_drops(), FragDrops::default());
    }

    #[test]
    fn duplicates_do_not_short_circuit_completion() {
        let payload = vec![3; 4096];
        let parts = frags(&build_datagrams(1, 0, &payload, 1200).unwrap());
        let now = Instant::now();
        let mut r = FragReassembler::new();

        for (h, p) in parts.iter().take(parts.len() - 1) {
            r.push(*h, p, now);
            r.push(*h, p, now);
        }

        let (h, p) = parts.last().unwrap();
        assert_eq!(r.push(*h, p, now), Some(payload));
    }

    #[test]
    fn interleaved_groups_reassemble_independently() {
        let a = vec![0xaa; 4096];
        let b = vec![0xbb; 5000];
        let pa = frags(&build_datagrams(1, 1, &a, 1200).unwrap());
        let pb = frags(&build_datagrams(1, 2, &b, 1200).unwrap());
        let now = Instant::now();
        let mut r = FragReassembler::new();

        let mut got = Vec::new();
        for i in 0..pa.len().max(pb.len()) {
            if let Some((h, p)) = pa.get(i) {
                got.extend(r.push(*h, p, now));
            }
            if let Some((h, p)) = pb.get(i) {
                got.extend(r.push(*h, p, now));
            }
        }

        assert_eq!(got, vec![a, b]);
    }

    #[test]
    fn stale_groups_time_out_and_are_counted() {
        let payload = vec![1; 4096];
        let parts = frags(&build_datagrams(1, 0, &payload, 1200).unwrap());
        let t0 = Instant::now();
        let mut r = FragReassembler::new();

        r.push(parts[0].0, &parts[0].1, t0);
        assert_eq!(r.groups(), 1);

        r.gc(t0 + FRAG_TIMEOUT - Duration::from_millis(1));
        assert_eq!(r.groups(), 1);

        r.gc(t0 + FRAG_TIMEOUT);
        assert_eq!(r.groups(), 0);
        assert_eq!(r.take_drops().timeout, 1);

        let late = t0 + FRAG_TIMEOUT;
        assert!(feed(&mut r, &parts[1..], late).is_none());
    }

    #[test]
    fn exceeding_the_group_limit_evicts_the_oldest() {
        let t0 = Instant::now();
        let mut r = FragReassembler::new();

        for g in 0..FRAG_MAX_GROUPS as u16 {
            let h = FragHeader {
                group: g,
                index: 0,
                count: 2,
            };
            r.push(h, b"x", t0 + Duration::from_millis(g.into()));
        }

        assert_eq!(r.groups(), FRAG_MAX_GROUPS);

        let h = FragHeader {
            group: 99,
            index: 0,
            count: 2,
        };
        r.push(h, b"x", t0 + Duration::from_millis(100));
        assert_eq!(r.groups(), FRAG_MAX_GROUPS);
        assert_eq!(r.take_drops().limit, 1);

        let finish = |g| FragHeader {
            group: g,
            index: 1,
            count: 2,
        };
        let t = t0 + Duration::from_millis(100);
        assert!(r.push(finish(1), b"y", t).is_some());
        assert!(r.push(finish(0), b"y", t).is_none());
        assert_eq!(r.take_drops(), FragDrops::default());
    }

    #[test]
    fn oversized_groups_are_dropped_whole() {
        let now = Instant::now();
        let mut r = FragReassembler::new();
        let chunk = vec![0; 16 * 1024];

        for i in 0..4 {
            let h = FragHeader {
                group: 1,
                index: i,
                count: 8,
            };
            assert!(r.push(h, &chunk, now).is_none());
        }

        assert_eq!(r.groups(), 1);

        let h = FragHeader {
            group: 1,
            index: 4,
            count: 8,
        };
        assert!(r.push(h, &chunk, now).is_none());
        assert_eq!(r.groups(), 0);
        assert_eq!(r.take_drops().oversize, 1);
    }

    #[test]
    fn malformed_fragment_headers_are_rejected() {
        let now = Instant::now();
        let mut r = FragReassembler::new();

        r.push(
            FragHeader {
                group: 1,
                index: 0,
                count: 0,
            },
            b"x",
            now,
        );
        r.push(
            FragHeader {
                group: 1,
                index: 5,
                count: 3,
            },
            b"x",
            now,
        );

        assert_eq!(r.take_drops().malformed, 2);
        assert_eq!(r.groups(), 0);
    }

    #[test]
    fn conflicting_fragment_counts_drop_the_group() {
        let now = Instant::now();
        let mut r = FragReassembler::new();

        r.push(
            FragHeader {
                group: 1,
                index: 0,
                count: 4,
            },
            b"x",
            now,
        );
        r.push(
            FragHeader {
                group: 1,
                index: 1,
                count: 7,
            },
            b"x",
            now,
        );

        assert_eq!(r.groups(), 0);
        assert_eq!(r.take_drops().malformed, 1);
    }

    #[test]
    fn eight_kib_payload_survives_a_realistic_quic_datagram_size() {
        for mtu in [1200, 1252, 1350, 1452] {
            let payload: Vec<_> = (0..8192).map(|i| (i % 256) as u8).collect();
            let parts = frags(&build_datagrams(u64::MAX, 3, &payload, mtu).unwrap());
            let mut r = FragReassembler::new();
            assert_eq!(feed(&mut r, &parts, Instant::now()), Some(payload));
        }
    }
}
