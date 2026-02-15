//! Path table for destination routing.

use std::collections::HashMap;

use reticulum_core::types::{DestinationHash, TruncatedHash};

use super::constants::PATHFINDER_M;
use super::types::{InterfaceId, PathEntry};

/// Path table mapping destination hashes to path entries.
#[must_use]
pub struct PathTable {
    entries: HashMap<DestinationHash, PathEntry>,
}

impl PathTable {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Get a path entry for a destination.
    #[must_use]
    pub fn get(&self, dest: &DestinationHash) -> Option<&PathEntry> {
        self.entries.get(dest)
    }

    /// Get a mutable path entry for a destination.
    pub fn get_mut(&mut self, dest: &DestinationHash) -> Option<&mut PathEntry> {
        self.entries.get_mut(dest)
    }

    /// Check if a valid (non-expired) path exists to the destination.
    #[must_use]
    pub fn has_path(&self, dest: &DestinationHash, now: u64) -> bool {
        self.entries.get(dest).is_some_and(|e| !e.is_expired(now))
    }

    /// Get the hop count to a destination, or `PATHFINDER_M` if unknown.
    #[must_use]
    pub fn hops_to(&self, dest: &DestinationHash, now: u64) -> u8 {
        self.entries
            .get(dest)
            .filter(|e| !e.is_expired(now))
            .map(|e| e.hops)
            .unwrap_or(PATHFINDER_M)
    }

    /// Get the next hop for a destination.
    #[must_use]
    pub fn next_hop(&self, dest: &DestinationHash, now: u64) -> Option<TruncatedHash> {
        self.entries
            .get(dest)
            .filter(|e| !e.is_expired(now))
            .map(|e| e.next_hop)
    }

    /// Get the interface that the path was learned on.
    #[must_use]
    pub fn next_hop_interface(&self, dest: &DestinationHash, now: u64) -> Option<InterfaceId> {
        self.entries
            .get(dest)
            .filter(|e| !e.is_expired(now))
            .map(|e| e.receiving_interface)
    }

    /// Insert or update a path entry.
    pub fn insert(&mut self, dest: DestinationHash, entry: PathEntry) {
        self.entries.insert(dest, entry);
    }

    /// Force-expire a path. Returns true if the path existed.
    pub fn expire_path(&mut self, dest: &DestinationHash) -> bool {
        if let Some(entry) = self.entries.get_mut(dest) {
            entry.expire();
            true
        } else {
            false
        }
    }

    /// Remove a path entry entirely.
    pub fn remove(&mut self, dest: &DestinationHash) -> Option<PathEntry> {
        self.entries.remove(dest)
    }

    /// Check if a destination hash exists in the table (regardless of expiry).
    #[must_use]
    pub fn contains(&self, dest: &DestinationHash) -> bool {
        self.entries.contains_key(dest)
    }

    /// Number of entries in the table.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the table is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Cull expired entries and entries for disappeared interfaces.
    ///
    /// Returns the number of entries removed.
    pub fn cull(&mut self, now: u64, active_interfaces: &[InterfaceId]) -> usize {
        let before = self.entries.len();
        self.entries.retain(|_, entry| {
            !entry.is_expired(now) && active_interfaces.contains(&entry.receiving_interface)
        });
        before - self.entries.len()
    }

    /// Iterate over all entries.
    pub fn iter(&self) -> impl Iterator<Item = (&DestinationHash, &PathEntry)> {
        self.entries.iter()
    }

    /// Consume the table and return all entries as `(DestinationHash, PathEntry)` pairs.
    #[must_use]
    pub fn into_entries(self) -> Vec<(DestinationHash, PathEntry)> {
        self.entries.into_iter().collect()
    }

    /// Build a path table from an iterator of `(DestinationHash, PathEntry)` pairs.
    pub fn from_entries(iter: impl IntoIterator<Item = (DestinationHash, PathEntry)>) -> Self {
        Self {
            entries: iter.into_iter().collect(),
        }
    }
}

impl Default for PathTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::path::types::InterfaceMode;
    use reticulum_core::types::{DestinationHash, PacketHash};

    /// Parse a hex-encoded packet hash from test vectors.
    ///
    /// Test vectors use 16-byte (truncated) packet hashes, but `PacketHash`
    /// is a 32-byte `FullHash`. Zero-pads to 32 bytes when needed.
    fn packet_hash_from_hex(hex_str: &str) -> PacketHash {
        let bytes = hex::decode(hex_str).unwrap();
        if bytes.len() == 32 {
            PacketHash::try_from(bytes.as_slice()).unwrap()
        } else {
            let mut padded = [0u8; 32];
            padded[..bytes.len()].copy_from_slice(&bytes);
            PacketHash::new(padded)
        }
    }

    fn make_dest(seed: u8) -> DestinationHash {
        DestinationHash::new([seed; 16])
    }

    fn make_next_hop(seed: u8) -> TruncatedHash {
        TruncatedHash::new([seed; 16])
    }

    fn make_packet_hash(seed: u8) -> PacketHash {
        PacketHash::new([seed; 32])
    }

    fn make_blob(seed: u8) -> [u8; 10] {
        [seed; 10]
    }

    fn make_entry(timestamp: u64, hops: u8, mode: InterfaceMode, iface: InterfaceId) -> PathEntry {
        PathEntry::new(
            timestamp,
            make_next_hop(0xAA),
            hops,
            mode,
            vec![make_blob(1)],
            iface,
            make_packet_hash(0xBB),
        )
    }

    // === Test vectors from path_requests.json ===

    #[test]
    fn test_path_table_entry_ttl_by_mode() {
        let vectors = reticulum_test_vectors::path_requests::load();

        for tv in &vectors.path_table_entry_vectors {
            let mode = InterfaceMode::from_vector_str(
                tv.interface_mode
                    .as_deref()
                    .unwrap_or(crate::path::types::mode_str::MODE_FULL),
            )
            .unwrap();

            let dest_bytes = hex::decode(&tv.destination_hash).unwrap();
            let _dest = DestinationHash::try_from(dest_bytes.as_slice()).unwrap();

            let next_hop_bytes = hex::decode(&tv.next_hop).unwrap();
            let next_hop = TruncatedHash::try_from(next_hop_bytes.as_slice()).unwrap();

            let packet_hash = packet_hash_from_hex(&tv.packet_hash);

            let random_blobs: Vec<[u8; 10]> = tv
                .random_blobs
                .iter()
                .map(|b| {
                    let bytes = hex::decode(b).unwrap();
                    bytes.try_into().expect("blob should be 10 bytes")
                })
                .collect();

            let entry = PathEntry::new(
                tv.timestamp,
                next_hop,
                tv.hops as u8,
                mode,
                random_blobs,
                InterfaceId(0),
                packet_hash,
            );

            assert_eq!(
                entry.expires, tv.expires,
                "expires mismatch for: {}",
                tv.description
            );
            assert_eq!(
                entry.expires - entry.timestamp,
                tv.expires_in_seconds,
                "TTL mismatch for: {}",
                tv.description
            );
        }
    }

    // === Test vectors from path_expiration.json ===

    #[test]
    fn test_ttl_enforcement() {
        let vectors = reticulum_test_vectors::path_expiration::load();

        for tv in &vectors.ttl_enforcement_vectors {
            let mode = InterfaceMode::from_vector_str(&tv.interface_mode).unwrap();

            assert_eq!(
                mode.path_ttl(),
                tv.ttl_seconds,
                "TTL constant mismatch for: {}",
                tv.description
            );

            let pe = &tv.path_entry;
            let next_hop_bytes = hex::decode(&pe.next_hop).unwrap();

            let entry = PathEntry::from_raw(
                pe.timestamp,
                TruncatedHash::try_from(next_hop_bytes.as_slice()).unwrap(),
                pe.hops as u8,
                pe.expires,
                pe.random_blobs
                    .iter()
                    .map(|b| hex::decode(b).unwrap().try_into().unwrap())
                    .collect(),
                InterfaceId(0),
                packet_hash_from_hex(&pe.packet_hash),
                false,
            );

            let valid = !entry.is_expired(tv.check_time);
            assert_eq!(
                valid, tv.expected_valid,
                "validity mismatch for: {} (check_time={}, expires={}, comparison={})",
                tv.description, tv.check_time, entry.expires, tv.comparison
            );
        }
    }

    #[test]
    fn test_expire_path() {
        let vectors = reticulum_test_vectors::path_expiration::load();

        for tv in &vectors.expire_path_vectors {
            let mut table = PathTable::new();
            let dest_bytes = hex::decode(&tv.destination_hash).unwrap();
            let dest = DestinationHash::try_from(dest_bytes.as_slice()).unwrap();

            if tv.path_exists {
                let mode = match tv.interface_mode.as_deref() {
                    Some("MODE_ACCESS_POINT") => InterfaceMode::AccessPoint,
                    Some("MODE_ROAMING") => InterfaceMode::Roaming,
                    _ => InterfaceMode::Full,
                };
                let entry = make_entry(1000, 2, mode, InterfaceId(0));
                table.insert(dest, entry);
            }

            let result = table.expire_path(&dest);
            assert_eq!(
                result, tv.expected_return,
                "expire_path return mismatch for: {}",
                tv.description
            );

            if tv.path_exists {
                let entry = table.get(&dest).unwrap();
                assert_eq!(entry.expires, 0, "expires should be 0 after expire_path");
                // Should be immediately expired (now > 0 for any positive time)
                assert!(entry.is_expired(1));
            }
        }
    }

    #[test]
    fn test_timestamp_refresh() {
        let vectors = reticulum_test_vectors::path_expiration::load();

        for tv in &vectors.timestamp_refresh_vectors {
            let mode = InterfaceMode::from_vector_str(&tv.interface_mode).unwrap();

            // Create initial entry
            let initial = &tv.path_entry_initial;
            let next_hop_bytes = hex::decode(&initial.next_hop).unwrap();

            let mut entry = PathEntry::from_raw(
                initial.timestamp,
                TruncatedHash::try_from(next_hop_bytes.as_slice()).unwrap(),
                initial.hops as u8,
                initial.expires,
                vec![],
                InterfaceId(0),
                packet_hash_from_hex(&initial.packet_hash),
                false,
            );

            assert_eq!(entry.expires, tv.original_expiry);

            // Refresh
            entry.refresh_timestamp(tv.packet_forward_time, mode);
            assert_eq!(
                entry.expires, tv.new_effective_expiry,
                "new expiry mismatch for: {}",
                tv.description
            );

            // Check validity at test time
            let without_refresh = !PathEntry::from_raw(
                initial.timestamp,
                entry.next_hop,
                entry.hops,
                tv.original_expiry,
                vec![],
                InterfaceId(0),
                entry.packet_hash,
                false,
            )
            .is_expired(tv.check_time);
            assert_eq!(
                without_refresh, tv.without_refresh_valid,
                "without_refresh mismatch for: {}",
                tv.description
            );

            let with_refresh = !entry.is_expired(tv.check_time);
            assert_eq!(
                with_refresh, tv.with_refresh_valid,
                "with_refresh mismatch for: {}",
                tv.description
            );
        }
    }

    /// Map a string interface name to a stable u64 ID for testing.
    fn iface_name_to_id(name: &str) -> InterfaceId {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        name.hash(&mut hasher);
        InterfaceId(hasher.finish())
    }

    #[test]
    fn test_interface_disappearance() {
        let vectors = reticulum_test_vectors::path_expiration::load();

        for tv in &vectors.interface_disappearance_vectors {
            let mut table = PathTable::new();
            let dest_bytes = hex::decode(&tv.destination_hash).unwrap();
            let dest = DestinationHash::try_from(dest_bytes.as_slice()).unwrap();

            let pe = &tv.path_entry;
            let iface_name = pe.attached_interface.as_deref().unwrap();
            let iface_id = iface_name_to_id(iface_name);

            let next_hop_bytes = hex::decode(&pe.next_hop).unwrap();

            let entry = PathEntry::from_raw(
                pe.timestamp,
                TruncatedHash::try_from(next_hop_bytes.as_slice()).unwrap(),
                pe.hops as u8,
                pe.expires,
                vec![],
                iface_id,
                packet_hash_from_hex(&pe.packet_hash),
                false,
            );

            table.insert(dest, entry);

            let active: Vec<InterfaceId> = tv
                .active_interfaces
                .iter()
                .map(|s| iface_name_to_id(s))
                .collect();

            let removed = table.cull(tv.now, &active);

            if tv.expected_removed {
                assert_eq!(removed, 1, "should have removed for: {}", tv.description);
                assert!(!table.contains(&dest));
            } else {
                assert_eq!(
                    removed, 0,
                    "should not have removed for: {}",
                    tv.description
                );
                assert!(table.contains(&dest));
            }
        }
    }

    // === Test vectors from multi_hop_routing.json ===

    #[test]
    fn test_path_table_queries() {
        let vectors = reticulum_test_vectors::multi_hop_routing::load();
        let now = 1000u64;

        for tv in &vectors.path_table_query_vectors {
            let mut table = PathTable::new();
            let dest_bytes = hex::decode(&tv.destination_hash).unwrap();
            let dest = DestinationHash::try_from(dest_bytes.as_slice()).unwrap();

            if tv.path_table_entry_exists {
                let next_hop_bytes = hex::decode(tv.path_table_next_hop.as_ref().unwrap()).unwrap();
                let next_hop = TruncatedHash::try_from(next_hop_bytes.as_slice()).unwrap();
                let hops = tv.path_table_hops.unwrap() as u8;

                let entry = PathEntry::new(
                    now,
                    next_hop,
                    hops,
                    InterfaceMode::Full,
                    vec![],
                    InterfaceId(0),
                    make_packet_hash(0),
                );
                table.insert(dest, entry);
            }

            assert_eq!(
                table.has_path(&dest, now),
                tv.has_path_result,
                "has_path mismatch for: {}",
                tv.description
            );

            let expected_hops = tv.hops_to_result.map(|h| h as u8);
            let actual_hops = table.hops_to(&dest, now);
            if let Some(eh) = expected_hops {
                assert_eq!(actual_hops, eh, "hops_to mismatch for: {}", tv.description);
            } else {
                assert_eq!(
                    actual_hops, PATHFINDER_M,
                    "should return PATHFINDER_M for: {}",
                    tv.description
                );
            }

            let expected_next_hop = tv.next_hop_result.as_ref().map(|h| hex::decode(h).unwrap());
            let actual_next_hop = table.next_hop(&dest, now);
            match (expected_next_hop, actual_next_hop) {
                (Some(expected), Some(actual)) => {
                    assert_eq!(
                        actual.as_ref(),
                        expected.as_slice(),
                        "next_hop mismatch for: {}",
                        tv.description
                    );
                }
                (None, None) => {}
                _ => panic!("next_hop presence mismatch for: {}", tv.description),
            }
        }
    }

    // === Unit tests ===

    #[test]
    fn test_random_blob_tracking() {
        let mut entry = make_entry(1000, 2, InterfaceMode::Full, InterfaceId(0));
        assert!(entry.has_random_blob(&make_blob(1)));
        assert!(!entry.has_random_blob(&make_blob(2)));

        entry.add_random_blob(make_blob(2));
        assert!(entry.has_random_blob(&make_blob(2)));
        assert_eq!(entry.random_blobs().len(), 2);

        // Adding duplicate should not increase count
        entry.add_random_blob(make_blob(2));
        assert_eq!(entry.random_blobs().len(), 2);
    }

    #[test]
    fn test_random_blob_max_size() {
        let mut entry = PathEntry::new(
            1000,
            make_next_hop(1),
            1,
            InterfaceMode::Full,
            vec![],
            InterfaceId(0),
            make_packet_hash(0),
        );

        for i in 0..crate::path::constants::MAX_RANDOM_BLOBS {
            entry.add_random_blob(make_blob(i as u8));
        }
        assert_eq!(
            entry.random_blobs().len(),
            crate::path::constants::MAX_RANDOM_BLOBS
        );

        // Adding one more should evict the oldest
        entry.add_random_blob(make_blob(0xFF));
        assert_eq!(
            entry.random_blobs().len(),
            crate::path::constants::MAX_RANDOM_BLOBS
        );
        assert!(!entry.has_random_blob(&make_blob(0)));
        assert!(entry.has_random_blob(&make_blob(0xFF)));
    }

    #[test]
    fn test_timebase_from_random_blobs() {
        let mut entry = PathEntry::new(
            1000,
            make_next_hop(1),
            1,
            InterfaceMode::Full,
            vec![],
            InterfaceId(0),
            make_packet_hash(0),
        );

        // Empty blobs = 0
        assert_eq!(entry.timebase_from_random_blobs(), 0);

        // Add blob with known timebase (bytes 5..10 = big-endian value)
        let mut blob = [0u8; 10];
        blob[5] = 0x00;
        blob[6] = 0x00;
        blob[7] = 0x01;
        blob[8] = 0x00;
        blob[9] = 0x00;
        entry.add_random_blob(blob);
        assert_eq!(entry.timebase_from_random_blobs(), 0x10000);

        // Add blob with higher timebase
        let mut blob2 = [0u8; 10];
        blob2[5] = 0x00;
        blob2[6] = 0x00;
        blob2[7] = 0x02;
        blob2[8] = 0x00;
        blob2[9] = 0x00;
        entry.add_random_blob(blob2);
        assert_eq!(entry.timebase_from_random_blobs(), 0x20000);
    }

    #[test]
    fn test_cull_expired() {
        let mut table = PathTable::new();
        let iface = InterfaceId(1);
        let active = vec![iface];

        // Non-expired entry
        table.insert(
            make_dest(1),
            make_entry(1000, 2, InterfaceMode::Full, iface),
        );

        // Expired entry (timestamp=0, TTL=604800 → expires=604800, now=604801)
        let mut expired = make_entry(0, 2, InterfaceMode::Full, iface);
        expired.expires = 100;
        table.insert(make_dest(2), expired);

        assert_eq!(table.len(), 2);
        let removed = table.cull(604801, &active);
        assert_eq!(removed, 1);
        assert!(table.contains(&make_dest(1)));
        assert!(!table.contains(&make_dest(2)));
    }

    // ================================================================== //
    // Boundary: path expiration strict > semantics
    // ================================================================== //

    #[test]
    fn has_path_at_exact_expiration() {
        let mut table = PathTable::new();
        let iface = InterfaceId(1);
        let mut entry = make_entry(1000, 2, InterfaceMode::Full, iface);
        entry.expires = 2000;
        table.insert(make_dest(1), entry);

        // now == expires → NOT expired (strict >)
        assert!(table.has_path(&make_dest(1), 2000));
    }

    #[test]
    fn has_path_one_past_expiration() {
        let mut table = PathTable::new();
        let iface = InterfaceId(1);
        let mut entry = make_entry(1000, 2, InterfaceMode::Full, iface);
        entry.expires = 2000;
        table.insert(make_dest(1), entry);

        // now == expires + 1 → expired
        assert!(!table.has_path(&make_dest(1), 2001));
    }

    #[test]
    fn has_path_one_before_expiration() {
        let mut table = PathTable::new();
        let iface = InterfaceId(1);
        let mut entry = make_entry(1000, 2, InterfaceMode::Full, iface);
        entry.expires = 2000;
        table.insert(make_dest(1), entry);

        // now == expires - 1 → NOT expired
        assert!(table.has_path(&make_dest(1), 1999));
    }

    #[test]
    fn hops_to_expired_returns_pathfinder_m() {
        let mut table = PathTable::new();
        let iface = InterfaceId(1);
        let mut entry = make_entry(1000, 3, InterfaceMode::Full, iface);
        entry.expires = 2000;
        table.insert(make_dest(1), entry);

        // Before expiry: returns actual hops
        assert_eq!(table.hops_to(&make_dest(1), 2000), 3);
        // After expiry: returns PATHFINDER_M
        assert_eq!(table.hops_to(&make_dest(1), 2001), PATHFINDER_M);
    }

    #[test]
    fn cull_at_exact_boundary() {
        let mut table = PathTable::new();
        let iface = InterfaceId(1);
        let active = vec![iface];

        let mut entry = make_entry(1000, 2, InterfaceMode::Full, iface);
        entry.expires = 2000;
        table.insert(make_dest(1), entry);

        // At exact expiration: NOT culled
        let removed = table.cull(2000, &active);
        assert_eq!(removed, 0);
        assert!(table.contains(&make_dest(1)));

        // One past: culled
        let removed = table.cull(2001, &active);
        assert_eq!(removed, 1);
        assert!(!table.contains(&make_dest(1)));
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use crate::path::types::InterfaceMode;
    use proptest::prelude::*;
    use reticulum_core::types::{PacketHash, TruncatedHash};

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn insert_then_has_path(
            dest_bytes in any::<[u8; 16]>(),
            timestamp in 1000..1_000_000u64,
            hops in 0..128u8,
        ) {
            let mut table = PathTable::new();
            let dest = DestinationHash::new(dest_bytes);
            let iface = InterfaceId(1);
            let entry = PathEntry::new(
                timestamp,
                TruncatedHash::new([0xAA; 16]),
                hops,
                InterfaceMode::Full,
                vec![],
                iface,
                PacketHash::new([0xBB; 32]),
            );
            table.insert(dest, entry);
            // Full mode TTL = 604800, so query at timestamp is always before expiry
            prop_assert!(table.has_path(&dest, timestamp));
            prop_assert_eq!(table.hops_to(&dest, timestamp), hops);
        }
    }
}
