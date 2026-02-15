//! Reverse table and link table for packet routing.

use std::collections::HashMap;

use reticulum_core::types::{LinkId, TruncatedHash};

use super::types::{LinkTableEntry, ReverseEntry};
use crate::path::InterfaceId;

/// Reverse table for routing proofs back to the originator.
///
/// Key: truncated hash of the packet's hashable part (= packet hash truncated to 16 bytes).
pub struct ReverseTable {
    entries: HashMap<TruncatedHash, ReverseEntry>,
}

impl ReverseTable {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Insert a reverse entry.
    pub fn insert(&mut self, key: TruncatedHash, entry: ReverseEntry) {
        self.entries.insert(key, entry);
    }

    /// Look up and remove a reverse entry (consumed on use).
    pub fn take(&mut self, key: &TruncatedHash) -> Option<ReverseEntry> {
        self.entries.remove(key)
    }

    /// Look up a reverse entry without removing it.
    #[must_use]
    pub fn get(&self, key: &TruncatedHash) -> Option<&ReverseEntry> {
        self.entries.get(key)
    }

    /// Check if a key exists.
    #[must_use]
    pub fn contains(&self, key: &TruncatedHash) -> bool {
        self.entries.contains_key(key)
    }

    /// Remove expired entries and entries with disappeared interfaces.
    pub fn cull(&mut self, now: u64, active_interfaces: &[InterfaceId]) -> usize {
        let before = self.entries.len();
        self.entries.retain(|_, entry| {
            !entry.is_expired(now)
                && active_interfaces.contains(&entry.receiving_interface)
                && active_interfaces.contains(&entry.outbound_interface)
        });
        before - self.entries.len()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for ReverseTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Link table for routing link-related packets.
///
/// Key: link ID (16-byte truncated hash).
pub struct LinkTable {
    entries: HashMap<LinkId, LinkTableEntry>,
}

impl LinkTable {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Insert a link table entry.
    pub fn insert(&mut self, link_id: LinkId, entry: LinkTableEntry) {
        self.entries.insert(link_id, entry);
    }

    /// Look up a link table entry.
    #[must_use]
    pub fn get(&self, link_id: &LinkId) -> Option<&LinkTableEntry> {
        self.entries.get(link_id)
    }

    /// Look up a mutable link table entry.
    pub fn get_mut(&mut self, link_id: &LinkId) -> Option<&mut LinkTableEntry> {
        self.entries.get_mut(link_id)
    }

    /// Remove a link table entry.
    pub fn remove(&mut self, link_id: &LinkId) -> Option<LinkTableEntry> {
        self.entries.remove(link_id)
    }

    /// Check if a link ID exists.
    #[must_use]
    pub fn contains(&self, link_id: &LinkId) -> bool {
        self.entries.contains_key(link_id)
    }

    /// Remove expired entries (proof timeout passed).
    pub fn cull(&mut self, now: u64) -> usize {
        let before = self.entries.len();
        self.entries.retain(|_, entry| now <= entry.proof_timeout);
        before - self.entries.len()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for LinkTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::router::constants::REVERSE_TIMEOUT;
    use reticulum_core::types::DestinationHash;

    fn make_trunc(seed: u8) -> TruncatedHash {
        TruncatedHash::new([seed; 16])
    }

    fn make_link_id(seed: u8) -> LinkId {
        LinkId::new([seed; 16])
    }

    fn make_dest(seed: u8) -> DestinationHash {
        DestinationHash::new([seed; 16])
    }

    // === Reverse table tests from multi_hop_routing.json ===

    #[test]
    fn test_reverse_table_entry_creation() {
        let vectors = reticulum_test_vectors::multi_hop_routing::load();

        for tv in &vectors.reverse_table_entry_vectors {
            if let Some(ref key_hex) = tv.truncated_hash_key {
                let key_bytes = hex::decode(key_hex).unwrap();
                let key = TruncatedHash::try_from(key_bytes.as_slice()).unwrap();

                let timestamp = tv.timestamp.unwrap_or(0);
                let entry = ReverseEntry {
                    receiving_interface: InterfaceId(1),
                    outbound_interface: InterfaceId(2),
                    timestamp,
                };

                let mut table = ReverseTable::new();
                table.insert(key, entry);
                assert!(table.contains(&key));
            }
        }
    }

    #[test]
    fn test_reverse_table_expiration() {
        let vectors = reticulum_test_vectors::multi_hop_routing::load();

        for tv in &vectors.reverse_table_entry_vectors {
            if let Some(is_expired) = tv.is_expired {
                let timestamp = tv.timestamp.unwrap_or(0);
                let check_time = tv.check_time.unwrap_or(0);

                let entry = ReverseEntry {
                    receiving_interface: InterfaceId(1),
                    outbound_interface: InterfaceId(2),
                    timestamp,
                };

                assert_eq!(
                    entry.is_expired(check_time),
                    is_expired,
                    "expiration mismatch for: {} (timestamp={}, check={}, timeout={})",
                    tv.description,
                    timestamp,
                    check_time,
                    REVERSE_TIMEOUT,
                );
            }
        }
    }

    #[test]
    fn test_reverse_table_cull() {
        let mut table = ReverseTable::new();
        let ifaces = vec![InterfaceId(1), InterfaceId(2)];

        // Active entry
        table.insert(
            make_trunc(1),
            ReverseEntry {
                receiving_interface: InterfaceId(1),
                outbound_interface: InterfaceId(2),
                timestamp: 1000,
            },
        );

        // Expired entry (timestamp=100, now=1000 > 100+480=580)
        table.insert(
            make_trunc(2),
            ReverseEntry {
                receiving_interface: InterfaceId(1),
                outbound_interface: InterfaceId(2),
                timestamp: 100,
            },
        );

        // Entry with disappeared interface
        table.insert(
            make_trunc(3),
            ReverseEntry {
                receiving_interface: InterfaceId(99), // not in active list
                outbound_interface: InterfaceId(2),
                timestamp: 1000,
            },
        );

        assert_eq!(table.len(), 3);
        let removed = table.cull(1000, &ifaces);
        assert_eq!(removed, 2);
        assert!(table.contains(&make_trunc(1)));
    }

    #[test]
    fn test_reverse_table_take() {
        let mut table = ReverseTable::new();
        let key = make_trunc(1);

        table.insert(
            key,
            ReverseEntry {
                receiving_interface: InterfaceId(1),
                outbound_interface: InterfaceId(2),
                timestamp: 1000,
            },
        );

        assert!(table.contains(&key));
        let entry = table.take(&key).unwrap();
        assert_eq!(entry.timestamp, 1000);
        assert!(!table.contains(&key));
    }

    // === Link table tests ===

    #[test]
    fn test_link_table_entry_from_vectors() {
        let vectors = reticulum_test_vectors::multi_hop_routing::load();

        for tv in &vectors.link_table_entry_vectors {
            let link_id_bytes = hex::decode(&tv.link_id).unwrap();
            let link_id = LinkId::try_from(link_id_bytes.as_slice()).unwrap();

            let dest_bytes = hex::decode(&tv.destination_hash).unwrap();
            let dest = DestinationHash::try_from(dest_bytes.as_slice()).unwrap();

            if let Some(ref fields) = tv.entry_fields {
                // next_hop_transport_id can be descriptive text instead of hex — skip those
                let next_hop_hex = match fields.next_hop_transport_id.as_str() {
                    Some(s) => s,
                    None => continue,
                };
                let Ok(next_hop_bytes) = hex::decode(next_hop_hex) else {
                    continue;
                };
                let next_hop = TruncatedHash::try_from(next_hop_bytes.as_slice()).unwrap();

                let remaining = fields.remaining_hops as u8;
                let taken = fields.taken_hops as u8;
                let validated = fields.validated;

                let entry = LinkTableEntry {
                    timestamp: fields.timestamp,
                    next_hop_transport_id: next_hop,
                    next_hop_interface: InterfaceId(1),
                    remaining_hops: remaining,
                    received_interface: InterfaceId(0),
                    taken_hops: taken,
                    dest_hash: dest,
                    validated,
                    proof_timeout: fields.proof_timeout as u64,
                };

                let mut table = LinkTable::new();
                table.insert(link_id, entry.clone());
                assert!(table.contains(&link_id));

                let retrieved = table.get(&link_id).unwrap();
                assert_eq!(retrieved.remaining_hops, remaining);
                assert_eq!(retrieved.taken_hops, taken);
            }
        }
    }

    #[test]
    fn test_link_table_cull() {
        let mut table = LinkTable::new();

        // Active entry (proof_timeout in future)
        table.insert(
            make_link_id(1),
            LinkTableEntry {
                timestamp: 1000,
                next_hop_transport_id: make_trunc(1),
                next_hop_interface: InterfaceId(1),
                remaining_hops: 2,
                received_interface: InterfaceId(0),
                taken_hops: 1,
                dest_hash: make_dest(1),
                validated: false,
                proof_timeout: 2000,
            },
        );

        // Expired entry (proof_timeout in past)
        table.insert(
            make_link_id(2),
            LinkTableEntry {
                timestamp: 500,
                next_hop_transport_id: make_trunc(2),
                next_hop_interface: InterfaceId(1),
                remaining_hops: 1,
                received_interface: InterfaceId(0),
                taken_hops: 2,
                dest_hash: make_dest(2),
                validated: false,
                proof_timeout: 900,
            },
        );

        assert_eq!(table.len(), 2);
        let removed = table.cull(1000);
        assert_eq!(removed, 1);
        assert!(table.contains(&make_link_id(1)));
        assert!(!table.contains(&make_link_id(2)));
    }

    // ================================================================== //
    // Boundary: reverse entry expiration strict > semantics
    // ================================================================== //

    #[test]
    fn reverse_entry_at_exact_timeout() {
        let entry = ReverseEntry {
            receiving_interface: InterfaceId(1),
            outbound_interface: InterfaceId(2),
            timestamp: 1000,
        };
        // now == timestamp + REVERSE_TIMEOUT → NOT expired (strict >)
        assert!(!entry.is_expired(1000 + REVERSE_TIMEOUT));
    }

    #[test]
    fn reverse_entry_past_timeout() {
        let entry = ReverseEntry {
            receiving_interface: InterfaceId(1),
            outbound_interface: InterfaceId(2),
            timestamp: 1000,
        };
        // now == timestamp + REVERSE_TIMEOUT + 1 → expired
        assert!(entry.is_expired(1000 + REVERSE_TIMEOUT + 1));
    }

    #[test]
    fn reverse_cull_boundary() {
        let mut table = ReverseTable::new();
        let ifaces = vec![InterfaceId(1), InterfaceId(2)];

        table.insert(
            make_trunc(1),
            ReverseEntry {
                receiving_interface: InterfaceId(1),
                outbound_interface: InterfaceId(2),
                timestamp: 1000,
            },
        );

        // At exact timeout: NOT culled
        let removed = table.cull(1000 + REVERSE_TIMEOUT, &ifaces);
        assert_eq!(removed, 0);
        assert!(table.contains(&make_trunc(1)));

        // One past: culled
        let removed = table.cull(1000 + REVERSE_TIMEOUT + 1, &ifaces);
        assert_eq!(removed, 1);
        assert!(!table.contains(&make_trunc(1)));
    }

    #[test]
    fn link_table_cull_boundary() {
        let mut table = LinkTable::new();

        table.insert(
            make_link_id(1),
            LinkTableEntry {
                timestamp: 1000,
                next_hop_transport_id: make_trunc(1),
                next_hop_interface: InterfaceId(1),
                remaining_hops: 2,
                received_interface: InterfaceId(0),
                taken_hops: 1,
                dest_hash: make_dest(1),
                validated: false,
                proof_timeout: 2000,
            },
        );

        // now <= proof_timeout → retained (condition: now <= proof_timeout)
        let removed = table.cull(2000);
        assert_eq!(removed, 0);
        assert!(table.contains(&make_link_id(1)));

        // now > proof_timeout → culled
        let removed = table.cull(2001);
        assert_eq!(removed, 1);
        assert!(!table.contains(&make_link_id(1)));
    }
}
