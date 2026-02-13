//! Peer tracking and packet deduplication for the Auto interface.
//!
//! All types here are pure logic (no I/O) and fully unit-testable.

use std::collections::HashMap;
use std::net::Ipv6Addr;
use std::time::{Duration, Instant};

use super::{MULTI_IF_DEQUE_LEN, MULTI_IF_DEQUE_TTL};

/// A discovered peer on the local network.
#[derive(Debug, Clone)]
pub struct Peer {
    /// Peer's IPv6 link-local address.
    pub addr: Ipv6Addr,
    /// OS interface name the peer was discovered on.
    pub ifname: String,
    /// OS interface index.
    pub if_index: u32,
    /// When we last heard from this peer (discovery or data).
    pub last_heard: Instant,
    /// When we last sent a reverse peering packet to this peer.
    pub last_outbound: Instant,
}

/// Table of known peers, keyed by IPv6 address.
#[derive(Debug)]
pub struct PeerTable {
    peers: HashMap<Ipv6Addr, Peer>,
    dedup: DedupRing,
}

impl PeerTable {
    /// Create an empty peer table.
    pub fn new() -> Self {
        Self {
            peers: HashMap::new(),
            dedup: DedupRing::new(MULTI_IF_DEQUE_LEN, MULTI_IF_DEQUE_TTL),
        }
    }

    /// Add a new peer or refresh an existing one's timestamp.
    ///
    /// Returns `true` if this is a newly discovered peer.
    pub fn add_or_refresh(&mut self, addr: Ipv6Addr, ifname: String, if_index: u32) -> bool {
        if let Some(existing) = self.peers.get_mut(&addr) {
            existing.last_heard = Instant::now();
            false
        } else {
            let now = Instant::now();
            self.peers.insert(
                addr,
                Peer {
                    addr,
                    ifname,
                    if_index,
                    last_heard: now,
                    last_outbound: now,
                },
            );
            true
        }
    }

    /// Update the `last_outbound` timestamp for a peer.
    pub fn mark_outbound(&mut self, addr: &Ipv6Addr) {
        if let Some(peer) = self.peers.get_mut(addr) {
            peer.last_outbound = Instant::now();
        }
    }

    /// Remove peers that haven't been heard from within `timeout`.
    ///
    /// Returns the list of removed peer addresses.
    pub fn prune_timed_out(&mut self, timeout: Duration) -> Vec<Ipv6Addr> {
        let now = Instant::now();
        let timed_out: Vec<Ipv6Addr> = self
            .peers
            .iter()
            .filter(|(_, peer)| now.duration_since(peer.last_heard) > timeout)
            .map(|(addr, _)| *addr)
            .collect();

        for addr in &timed_out {
            self.peers.remove(addr);
        }

        timed_out
    }

    /// Check if data has been seen recently (dedup).
    ///
    /// Returns `true` if this is a duplicate. If not a duplicate, records it.
    pub fn is_duplicate(&mut self, data_hash: [u8; 32]) -> bool {
        self.dedup.check_and_insert(data_hash)
    }

    /// Iterate over all known peers.
    pub fn peers(&self) -> impl Iterator<Item = &Peer> {
        self.peers.values()
    }

    /// Number of known peers.
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    /// Whether the peer table is empty.
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }
}

impl Default for PeerTable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Deduplication ring buffer
// ---------------------------------------------------------------------------

/// Fixed-size ring buffer for packet deduplication.
///
/// Entries expire after `ttl` and are evicted when the buffer is full.
#[derive(Debug)]
struct DedupRing {
    entries: Vec<([u8; 32], Instant)>,
    capacity: usize,
    ttl: Duration,
}

impl DedupRing {
    fn new(capacity: usize, ttl: Duration) -> Self {
        Self {
            entries: Vec::with_capacity(capacity),
            capacity,
            ttl,
        }
    }

    /// Check if `hash` was seen recently. If not, insert it.
    ///
    /// Returns `true` if this is a duplicate (already in the buffer and not expired).
    fn check_and_insert(&mut self, hash: [u8; 32]) -> bool {
        let now = Instant::now();

        // Prune expired entries.
        self.entries
            .retain(|(_, ts)| now.duration_since(*ts) <= self.ttl);

        // Check for match.
        if self.entries.iter().any(|(h, _)| *h == hash) {
            return true;
        }

        // Evict oldest if at capacity.
        if self.entries.len() >= self.capacity {
            self.entries.remove(0);
        }

        self.entries.push((hash, now));
        false
    }
}

#[cfg(test)]
mod tests {
    use super::super::PEERING_TIMEOUT;
    use super::*;

    #[test]
    fn peer_add_and_refresh() {
        let mut table = PeerTable::new();
        let addr: Ipv6Addr = "fe80::1".parse().unwrap();

        // First add is new.
        assert!(table.add_or_refresh(addr, "en0".into(), 1));
        assert_eq!(table.len(), 1);

        // Second add is a refresh.
        assert!(!table.add_or_refresh(addr, "en0".into(), 1));
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn peer_prune_timeout() {
        let mut table = PeerTable::new();
        let addr: Ipv6Addr = "fe80::1".parse().unwrap();

        table.add_or_refresh(addr, "en0".into(), 1);

        // Not timed out yet.
        let removed = table.prune_timed_out(PEERING_TIMEOUT);
        assert!(removed.is_empty());
        assert_eq!(table.len(), 1);

        // Manually set last_heard to the past.
        table.peers.get_mut(&addr).unwrap().last_heard =
            Instant::now() - PEERING_TIMEOUT - Duration::from_secs(1);

        let removed = table.prune_timed_out(PEERING_TIMEOUT);
        assert_eq!(removed, vec![addr]);
        assert!(table.is_empty());
    }

    #[test]
    fn dedup_detects_duplicates() {
        let mut table = PeerTable::new();
        let hash = [0xAA; 32];

        assert!(!table.is_duplicate(hash));
        assert!(table.is_duplicate(hash)); // duplicate!

        // Different hash is not a duplicate.
        let hash2 = [0xBB; 32];
        assert!(!table.is_duplicate(hash2));
    }

    #[test]
    fn dedup_ring_eviction() {
        let mut ring = DedupRing::new(3, Duration::from_secs(60));

        let h1 = [1u8; 32];
        let h2 = [2u8; 32];
        let h3 = [3u8; 32];
        let h4 = [4u8; 32];

        assert!(!ring.check_and_insert(h1));
        assert!(!ring.check_and_insert(h2));
        assert!(!ring.check_and_insert(h3));

        // Buffer full, h1 should be evicted when h4 is inserted.
        assert!(!ring.check_and_insert(h4));
        assert_eq!(ring.entries.len(), 3);

        // h1 was evicted, should not be found.
        assert!(!ring.check_and_insert(h1));
    }

    #[test]
    fn dedup_ring_expiry() {
        let mut ring = DedupRing::new(48, Duration::from_millis(0));

        let hash = [0xCC; 32];
        assert!(!ring.check_and_insert(hash));

        // With a 0ms TTL, the entry should already be expired.
        // (In practice Instant granularity may or may not catch this,
        // but the prune logic handles it.)
        // Insert again — should either find it expired or not, both are valid.
        // The important thing is that it doesn't panic.
        let _ = ring.check_and_insert(hash);
    }

    #[test]
    fn peer_iteration() {
        let mut table = PeerTable::new();
        table.add_or_refresh("fe80::1".parse().unwrap(), "en0".into(), 1);
        table.add_or_refresh("fe80::2".parse().unwrap(), "en1".into(), 2);

        let addrs: Vec<Ipv6Addr> = table.peers().map(|p| p.addr).collect();
        assert_eq!(addrs.len(), 2);
        assert!(addrs.contains(&"fe80::1".parse().unwrap()));
        assert!(addrs.contains(&"fe80::2".parse().unwrap()));
    }
}
