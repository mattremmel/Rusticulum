//! Packet deduplication using two-set rotation.
//!
//! Maintains a current and previous hash set. When the current set exceeds
//! the rotation threshold, it becomes the previous set and a new empty set
//! is created. Both sets are checked for duplicates.

use std::collections::HashSet;

use reticulum_core::types::PacketHash;

/// Maximum combined hashlist size before rotation.
pub const HASHLIST_MAX_SIZE: usize = 1_000_000;

/// Rotation threshold: when current set exceeds this, rotate.
pub const HASHLIST_ROTATION_THRESHOLD: usize = HASHLIST_MAX_SIZE / 2;

/// Two-set packet deduplication filter.
///
/// Matches the Python reference implementation's rotation strategy:
/// when `current.len() > HASHLIST_ROTATION_THRESHOLD`, the current set
/// becomes the previous set and a new empty current set is created.
pub struct PacketHashlist {
    current: HashSet<PacketHash>,
    prev: HashSet<PacketHash>,
}

impl PacketHashlist {
    pub fn new() -> Self {
        Self {
            current: HashSet::new(),
            prev: HashSet::new(),
        }
    }

    /// Check if a packet hash has been seen before.
    pub fn contains(&self, hash: &PacketHash) -> bool {
        self.current.contains(hash) || self.prev.contains(hash)
    }

    /// Insert a packet hash and return `true` if it was new (not a duplicate).
    ///
    /// Automatically rotates the sets if the current set exceeds the threshold.
    pub fn insert(&mut self, hash: PacketHash) -> bool {
        if self.contains(&hash) {
            return false;
        }
        self.current.insert(hash);
        self.maybe_rotate();
        true
    }

    /// Rotate sets if the current set exceeds the threshold.
    fn maybe_rotate(&mut self) {
        if self.current.len() > HASHLIST_ROTATION_THRESHOLD {
            self.prev = std::mem::take(&mut self.current);
        }
    }

    /// Total number of tracked hashes across both sets.
    pub fn len(&self) -> usize {
        self.current.len() + self.prev.len()
    }

    /// Returns true if both sets are empty.
    pub fn is_empty(&self) -> bool {
        self.current.is_empty() && self.prev.is_empty()
    }

    /// Number of hashes in the current set.
    pub fn current_len(&self) -> usize {
        self.current.len()
    }

    /// Number of hashes in the previous set.
    pub fn prev_len(&self) -> usize {
        self.prev.len()
    }
}

impl Default for PacketHashlist {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_hash(seed: u8) -> PacketHash {
        let mut bytes = [0u8; 32];
        bytes[0] = seed;
        PacketHash::new(bytes)
    }

    #[test]
    fn test_new_hashlist_is_empty() {
        let hl = PacketHashlist::new();
        assert!(hl.is_empty());
        assert_eq!(hl.len(), 0);
    }

    #[test]
    fn test_insert_new_returns_true() {
        let mut hl = PacketHashlist::new();
        assert!(hl.insert(make_hash(1)));
        assert_eq!(hl.len(), 1);
    }

    #[test]
    fn test_insert_duplicate_returns_false() {
        let mut hl = PacketHashlist::new();
        assert!(hl.insert(make_hash(1)));
        assert!(!hl.insert(make_hash(1)));
        assert_eq!(hl.current_len(), 1);
    }

    #[test]
    fn test_contains_checks_both_sets() {
        let mut hl = PacketHashlist::new();
        let h1 = make_hash(1);
        hl.insert(h1);

        // Force rotation by filling current set
        for i in 2..=255 {
            hl.current.insert(make_hash(i));
        }
        // Add enough with different high bytes to exceed threshold
        for i in 0u32..HASHLIST_ROTATION_THRESHOLD as u32 {
            let mut bytes = [0u8; 32];
            bytes[0..4].copy_from_slice(&i.to_le_bytes());
            bytes[31] = 0xFF; // differentiate from make_hash
            hl.current.insert(PacketHash::new(bytes));
        }

        // Trigger rotation
        hl.maybe_rotate();

        // h1 should now be in prev
        assert_eq!(hl.current_len(), 0);
        assert!(hl.prev_len() > 0);
        assert!(hl.contains(&h1));
    }

    #[test]
    fn test_rotation_threshold() {
        let mut hl = PacketHashlist::new();

        // Insert exactly at threshold — should NOT rotate yet
        for i in 0u32..HASHLIST_ROTATION_THRESHOLD as u32 {
            let mut bytes = [0u8; 32];
            bytes[0..4].copy_from_slice(&i.to_le_bytes());
            hl.current.insert(PacketHash::new(bytes));
        }
        assert_eq!(hl.current_len(), HASHLIST_ROTATION_THRESHOLD);
        hl.maybe_rotate();
        // At exactly threshold, should NOT rotate (> not >=)
        assert_eq!(hl.current_len(), HASHLIST_ROTATION_THRESHOLD);

        // One more triggers rotation
        let extra = {
            let mut bytes = [0xFFu8; 32];
            bytes[0] = 0xAA;
            PacketHash::new(bytes)
        };
        hl.insert(extra);
        // After insert of (threshold+1)th element, rotation happens
        assert_eq!(hl.current_len(), 0);
        assert_eq!(hl.prev_len(), HASHLIST_ROTATION_THRESHOLD + 1);
    }

    #[test]
    fn test_duplicate_across_rotation() {
        let mut hl = PacketHashlist::new();
        let h1 = make_hash(42);
        hl.insert(h1);

        // Force rotation
        for i in 0u32..(HASHLIST_ROTATION_THRESHOLD as u32 + 1) {
            let mut bytes = [0u8; 32];
            bytes[0..4].copy_from_slice(&i.to_le_bytes());
            bytes[31] = 0xEE;
            hl.current.insert(PacketHash::new(bytes));
        }
        hl.maybe_rotate();

        // h1 is in prev, inserting again should detect duplicate
        assert!(!hl.insert(h1));
    }

    #[test]
    fn test_double_rotation_evicts() {
        let mut hl = PacketHashlist::new();
        let h1 = make_hash(99);
        hl.insert(h1);

        // First rotation: h1 moves to prev
        for i in 0u32..(HASHLIST_ROTATION_THRESHOLD as u32 + 1) {
            let mut bytes = [0u8; 32];
            bytes[0..4].copy_from_slice(&i.to_le_bytes());
            bytes[31] = 0xAA;
            hl.current.insert(PacketHash::new(bytes));
        }
        hl.maybe_rotate();
        assert!(hl.contains(&h1));

        // Second rotation: h1 is evicted (prev replaced)
        for i in 0u32..(HASHLIST_ROTATION_THRESHOLD as u32 + 1) {
            let mut bytes = [0u8; 32];
            bytes[0..4].copy_from_slice(&i.to_le_bytes());
            bytes[31] = 0xBB;
            hl.current.insert(PacketHash::new(bytes));
        }
        hl.maybe_rotate();
        assert!(!hl.contains(&h1));
    }

    #[test]
    fn test_insert_after_rotation_goes_to_current() {
        let mut hl = PacketHashlist::new();

        // Fill and rotate
        for i in 0u32..(HASHLIST_ROTATION_THRESHOLD as u32 + 1) {
            let mut bytes = [0u8; 32];
            bytes[0..4].copy_from_slice(&i.to_le_bytes());
            hl.current.insert(PacketHash::new(bytes));
        }
        hl.maybe_rotate();
        assert_eq!(hl.current_len(), 0);

        // New insert goes to current (use a hash that can't collide with the loop entries)
        let h = PacketHash::new([0xFFu8; 32]);
        hl.insert(h);
        assert_eq!(hl.current_len(), 1);
        assert!(hl.contains(&h));
    }
}
