use crate::metrics::Drops;
use bytes::Bytes;
use quinn::Connection;
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, atomic::Ordering::Relaxed},
    time::{Duration, Instant},
};
use tokio::net::UdpSocket;
use tundra_common::{
    flow::{FlowTable, UnknownFlowLimiter},
    frag::{FragError, FragReassembler, build_datagrams},
};

pub type EgressKey = (u64, SocketAddr);

pub const PENDING_TTL: Duration = Duration::from_millis(250);
pub const MAX_PENDING_FLOWS: usize = 64;
pub const MAX_PENDING_PER_FLOW: usize = 8;
pub const UDP_RECV_BUF: usize = 65535;
pub const LOCAL_SEND_QUEUE: usize = 16;

#[derive(Debug)]
struct Pending {
    datagrams: Vec<Bytes>,
    since: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hold {
    Parked,
    Dropped,
}

#[derive(Debug, Default)]
pub struct PendingFlows {
    map: HashMap<u64, Pending>,
}

impl PendingFlows {
    pub fn hold(&mut self, flow_id: u64, datagram: Bytes, now: Instant) -> (Hold, u64) {
        let expired = self.expire(now);

        if let Some(pending) = self.map.get_mut(&flow_id) {
            if pending.datagrams.len() >= MAX_PENDING_PER_FLOW {
                return (Hold::Dropped, expired);
            }

            pending.datagrams.push(datagram);
            return (Hold::Parked, expired);
        }

        if self.map.len() >= MAX_PENDING_FLOWS {
            return (Hold::Dropped, expired);
        }

        self.map.insert(
            flow_id,
            Pending {
                datagrams: vec![datagram],
                since: now,
            },
        );

        (Hold::Parked, expired)
    }

    #[inline]
    pub fn take(&mut self, flow_id: u64) -> Vec<Bytes> {
        self.map
            .remove(&flow_id)
            .map(|p| p.datagrams)
            .unwrap_or_default()
    }

    pub fn expire(&mut self, now: Instant) -> u64 {
        let mut dropped = 0;
        self.map.retain(|_, p| {
            let live = now.duration_since(p.since) < PENDING_TTL;
            if !live {
                dropped += p.datagrams.len() as u64;
            }
            live
        });

        dropped
    }

    #[cfg(test)]
    #[inline]
    pub fn len(&self) -> usize {
        self.map.len()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
    SendBufferFull,
    Oversize,
    DatagramsUnavailable,
}

impl DropReason {
    #[inline]
    pub fn count(self, drops: &Drops) {
        match self {
            DropReason::SendBufferFull => &drops.send_buffer_full,
            DropReason::Oversize | DropReason::DatagramsUnavailable => &drops.oversize,
        }
        .fetch_add(1, Relaxed);
    }
}

#[derive(Debug)]
pub enum SendPlan {
    Send(Vec<Bytes>),
    Drop(DropReason),
}

pub fn plan_send(
    max_datagram: Option<usize>,
    buffer_space: usize,
    flow_id: u64,
    group: u16,
    payload: &[u8],
) -> SendPlan {
    let Some(max) = max_datagram else {
        return SendPlan::Drop(DropReason::DatagramsUnavailable);
    };

    let datagrams = match build_datagrams(flow_id, group, payload, max) {
        Ok(d) => d,
        Err(FragError::TooLarge { .. } | FragError::NoRoom { .. }) => {
            return SendPlan::Drop(DropReason::Oversize);
        }
    };

    let total: usize = datagrams.iter().map(Bytes::len).sum();
    if total > buffer_space {
        return SendPlan::Drop(DropReason::SendBufferFull);
    }

    SendPlan::Send(datagrams)
}

pub fn send_payload(
    conn: &Connection,
    flow_id: u64,
    group: u16,
    payload: &[u8],
    drops: &Drops,
    sent: &std::sync::atomic::AtomicU64,
    sent_bytes: &std::sync::atomic::AtomicU64,
) -> bool {
    match plan_send(
        conn.max_datagram_size(),
        conn.datagram_send_buffer_space(),
        flow_id,
        group,
        payload,
    ) {
        SendPlan::Drop(reason) => {
            tracing::debug!(
                reason = ?reason,
                len = payload.len(),
                "dropping an outbound payload"
            );
            reason.count(drops);
            false
        }
        SendPlan::Send(datagrams) => {
            for datagram in datagrams {
                let len = datagram.len() as u64;
                if let Err(err) = conn.send_datagram(datagram) {
                    tracing::debug!(
                        len,
                        max = ?conn.max_datagram_size(),
                        "failed to send a datagram fragment: {}",
                        err
                    );
                    drops.send_buffer_full.fetch_add(1, Relaxed);
                    return false;
                }

                sent.fetch_add(1, Relaxed);
                sent_bytes.fetch_add(len, Relaxed);
            }

            true
        }
    }
}

#[derive(Debug)]
pub struct EgressFlow {
    pub replies: tokio::sync::mpsc::Sender<(Vec<u8>, SocketAddr)>,
    pub client: SocketAddr,

    pub src_server: uuid::Uuid,
    pub dst_server: uuid::Uuid,
    pub dst_port: u16,

    pub reasm: FragReassembler,
    pub group: u16,
}

#[derive(Debug)]
pub struct IngressFlow {
    pub to_container: tokio::sync::mpsc::Sender<Vec<u8>>,
    pub socket: Arc<UdpSocket>,

    pub src_server: uuid::Uuid,
    pub dst_server: uuid::Uuid,
    pub dst_port: u16,

    pub reasm: FragReassembler,
    pub group: u16,

    pub reader: tokio::task::AbortHandle,
    pub writer: tokio::task::AbortHandle,
}

impl Drop for IngressFlow {
    fn drop(&mut self) {
        self.reader.abort();
        self.writer.abort();
    }
}

#[derive(Debug)]
pub struct UdpTables {
    pub egress: FlowTable<EgressKey, EgressFlow>,
    pub ingress: FlowTable<u64, IngressFlow>,
    pub unknown: UnknownFlowLimiter,
    pub pending: PendingFlows,
}

pub async fn container_writer(
    socket: Arc<UdpSocket>,
    mut rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
) {
    while let Some(payload) = rx.recv().await {
        if let Err(err) = socket.send(&payload).await {
            tracing::debug!("failed to send a datagram bound for the container: {}", err);
        }
    }
}

pub async fn frontend_writer(
    socket: Arc<UdpSocket>,
    mut rx: tokio::sync::mpsc::Receiver<(Vec<u8>, SocketAddr)>,
) {
    while let Some((payload, client)) = rx.recv().await {
        let _ = socket.send_to(&payload, client).await;
    }
}

#[inline]
pub fn next_group(group: &mut u16) -> u16 {
    let current = *group;
    *group = group.wrapping_add(1);
    current
}

#[cfg(test)]
mod tests {
    use super::*;
    use tundra_common::datagram::parse;

    const MTU: usize = 1200;
    const ROOM: usize = 1024 * 1024;

    fn sent(plan: SendPlan) -> Option<Vec<Bytes>> {
        match plan {
            SendPlan::Send(datagrams) => Some(datagrams),
            SendPlan::Drop(_) => None,
        }
    }

    fn dropped(plan: SendPlan) -> Option<DropReason> {
        match plan {
            SendPlan::Send(_) => None,
            SendPlan::Drop(reason) => Some(reason),
        }
    }

    // plan_send

    #[test]
    fn a_small_payload_becomes_one_datagram() {
        let dg = sent(plan_send(Some(MTU), ROOM, 4, 0, b"hello")).unwrap();
        assert_eq!(dg.len(), 1);

        let (hdr, payload) = parse(&dg[0]).unwrap();
        assert_eq!(hdr.flow_id, 4);
        assert!(hdr.frag.is_none());
        assert_eq!(payload, b"hello");
    }

    #[test]
    fn an_eight_kib_payload_fragments_and_still_fits_the_buffer() {
        let payload = vec![0xab; 8192];
        let dg = sent(plan_send(Some(MTU), ROOM, 2, 7, &payload)).unwrap();
        assert!(dg.len() > 1);
        assert!(dg.iter().all(|d| d.len() <= MTU));
        assert!(parse(&dg[0]).unwrap().0.frag.is_some());
    }

    #[test]
    fn a_full_send_buffer_drops_the_whole_payload_rather_than_half_of_it() {
        let payload = vec![0; 8192];
        assert_eq!(
            dropped(plan_send(Some(MTU), MTU * 2, 2, 0, &payload)),
            Some(DropReason::SendBufferFull)
        );

        let dg = sent(plan_send(Some(MTU), ROOM, 2, 0, &payload)).unwrap();
        let total: usize = dg.iter().map(Bytes::len).sum();
        assert!(sent(plan_send(Some(MTU), total, 2, 0, &payload)).is_some());
        assert_eq!(
            dropped(plan_send(Some(MTU), total - 1, 2, 0, &payload)),
            Some(DropReason::SendBufferFull)
        );
    }

    #[test]
    fn a_payload_that_cannot_be_fragmented_is_counted_as_oversize() {
        let huge = vec![0; 64 * 1024];
        assert_eq!(
            dropped(plan_send(Some(100), ROOM, 1, 0, &huge)),
            Some(DropReason::Oversize)
        );
        assert_eq!(
            dropped(plan_send(Some(4), ROOM, 1, 0, &huge)),
            Some(DropReason::Oversize)
        );
    }

    #[test]
    fn a_connection_without_datagram_support_drops_rather_than_blocking() {
        assert_eq!(
            dropped(plan_send(None, ROOM, 1, 0, b"x")),
            Some(DropReason::DatagramsUnavailable)
        );
    }

    #[test]
    fn every_drop_reason_lands_in_a_named_counter() {
        let drops = Drops::default();
        DropReason::SendBufferFull.count(&drops);
        DropReason::Oversize.count(&drops);
        DropReason::DatagramsUnavailable.count(&drops);

        assert_eq!(drops.send_buffer_full.load(Relaxed), 1);
        assert_eq!(drops.oversize.load(Relaxed), 2);
        assert_eq!(drops.unknown_flow.load(Relaxed), 0);
    }

    // PendingFlows

    #[test]
    fn a_datagram_that_beats_its_announcement_is_replayed() {
        let now = Instant::now();
        let mut pending = PendingFlows::default();

        assert_eq!(
            pending.hold(4, Bytes::from_static(b"first"), now),
            (Hold::Parked, 0)
        );
        assert_eq!(
            pending.hold(4, Bytes::from_static(b"second"), now),
            (Hold::Parked, 0)
        );

        let held = pending.take(4);
        assert_eq!(
            held,
            [Bytes::from_static(b"first"), Bytes::from_static(b"second")]
        );
        assert_eq!(pending.len(), 0);
        assert!(pending.take(4).is_empty());
    }

    #[test]
    fn parked_datagrams_expire_and_are_counted() {
        let t0 = Instant::now();
        let mut pending = PendingFlows::default();
        pending.hold(4, Bytes::from_static(b"x"), t0);
        pending.hold(4, Bytes::from_static(b"y"), t0);

        assert_eq!(pending.expire(t0 + PENDING_TTL / 2), 0);
        assert_eq!(pending.len(), 1);

        assert_eq!(pending.expire(t0 + PENDING_TTL), 2);
        assert_eq!(pending.len(), 0);
        assert!(pending.take(4).is_empty());
    }

    #[test]
    fn a_flood_of_unknown_flows_cannot_grow_the_buffer() {
        let now = Instant::now();
        let mut pending = PendingFlows::default();

        for id in 0..MAX_PENDING_FLOWS as u64 {
            assert_eq!(
                pending.hold(id, Bytes::from_static(b"x"), now),
                (Hold::Parked, 0)
            );
        }
        assert_eq!(
            pending.hold(9999, Bytes::from_static(b"x"), now),
            (Hold::Dropped, 0)
        );
        assert_eq!(pending.len(), MAX_PENDING_FLOWS);
    }

    #[test]
    fn one_flow_cannot_park_unlimited_datagrams() {
        let now = Instant::now();
        let mut pending = PendingFlows::default();

        for _ in 0..MAX_PENDING_PER_FLOW {
            assert_eq!(
                pending.hold(2, Bytes::from_static(b"x"), now),
                (Hold::Parked, 0)
            );
        }
        assert_eq!(
            pending.hold(2, Bytes::from_static(b"x"), now),
            (Hold::Dropped, 0)
        );
        assert_eq!(pending.take(2).len(), MAX_PENDING_PER_FLOW);
    }

    #[test]
    fn expiry_frees_room_for_new_flows() {
        let t0 = Instant::now();
        let mut pending = PendingFlows::default();
        for id in 0..MAX_PENDING_FLOWS as u64 {
            pending.hold(id, Bytes::from_static(b"x"), t0);
        }
        assert_eq!(
            pending.hold(9999, Bytes::from_static(b"x"), t0),
            (Hold::Dropped, 0)
        );

        let later = t0 + PENDING_TTL;
        let (verdict, abandoned) = pending.hold(9999, Bytes::from_static(b"x"), later);
        assert_eq!(verdict, Hold::Parked);
        assert_eq!(abandoned, MAX_PENDING_FLOWS as u64);
        assert_eq!(pending.len(), 1);
    }

    // next_group

    #[test]
    fn fragment_groups_advance_and_wrap() {
        let mut g = 65534;
        assert_eq!(next_group(&mut g), 65534);
        assert_eq!(next_group(&mut g), 65535);
        assert_eq!(next_group(&mut g), 0);
        assert_eq!(g, 1);
    }
}
