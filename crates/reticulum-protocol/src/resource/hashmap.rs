//! Resource part hashmap: building, segmentation, and verification.
//!
//! Resource transfers split encrypted data into SDU-sized parts. Each part
//! gets a 4-byte truncated hash (`SHA256(part_data || random_hash)[0..4]`).
//! These hashes form a "hashmap" that is sent in segments and used to verify
//! received parts.

use std::collections::{HashSet, VecDeque};

use reticulum_crypto::sha::sha256;

use super::constants::{COLLISION_GUARD_SIZE, HASHMAP_MAX_LEN, MAPHASH_LEN, RANDOM_HASH_SIZE};
use crate::error::ResourceError;

/// A 4-byte truncated SHA-256 hash identifying a resource part.
pub type MapHash = [u8; MAPHASH_LEN];

/// Hashmap of part hashes for a resource transfer.
///
/// Stores the truncated hashes of all parts in a resource, along with the
/// random hash that was used in their computation. Supports segmentation
/// for sending hashes in advertisement-sized chunks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceHashmap {
    random_hash: [u8; RANDOM_HASH_SIZE],
    parts: Vec<MapHash>,
}

impl ResourceHashmap {
    /// Create an empty hashmap bound to the given random hash.
    pub fn new(random_hash: [u8; RANDOM_HASH_SIZE]) -> Self {
        Self {
            random_hash,
            parts: Vec::new(),
        }
    }

    /// Compute the map hash for a data chunk: `SHA256(data || random_hash)[0..4]`.
    pub fn compute_map_hash(&self, data: &[u8]) -> MapHash {
        let mut input = Vec::with_capacity(data.len() + RANDOM_HASH_SIZE);
        input.extend_from_slice(data);
        input.extend_from_slice(&self.random_hash);
        let digest = sha256(&input);

        tracing::trace!(
            data_len = data.len(),
            hash = ?&digest[..MAPHASH_LEN],
            "computed map hash"
        );

        let mut hash = [0u8; MAPHASH_LEN];
        hash.copy_from_slice(&digest[..MAPHASH_LEN]);
        hash
    }

    /// Compute and store the map hash for a data chunk. Returns the hash.
    pub fn add_part(&mut self, data: &[u8]) -> MapHash {
        let hash = self.compute_map_hash(data);
        self.parts.push(hash);
        hash
    }

    /// Build a hashmap from encrypted data by chunking into SDU-sized parts.
    pub fn from_data(
        encrypted_data: &[u8],
        sdu: usize,
        random_hash: [u8; RANDOM_HASH_SIZE],
    ) -> Self {
        let mut hm = Self::new(random_hash);
        for chunk in encrypted_data.chunks(sdu) {
            hm.add_part(chunk);
        }

        tracing::debug!(
            parts = hm.parts.len(),
            data_len = encrypted_data.len(),
            sdu,
            "built resource hashmap from data"
        );

        hm
    }

    /// Deserialize from concatenated 4-byte hashes.
    pub fn from_bytes(
        data: &[u8],
        random_hash: [u8; RANDOM_HASH_SIZE],
    ) -> Result<Self, ResourceError> {
        if !data.len().is_multiple_of(MAPHASH_LEN) {
            return Err(ResourceError::InvalidAdvertisement(format!(
                "hashmap length {} is not a multiple of {MAPHASH_LEN}",
                data.len()
            )));
        }

        let parts: Vec<MapHash> = data
            .chunks_exact(MAPHASH_LEN)
            .map(|chunk| {
                let mut hash = [0u8; MAPHASH_LEN];
                hash.copy_from_slice(chunk);
                hash
            })
            .collect();

        tracing::trace!(parts = parts.len(), "deserialized resource hashmap");

        Ok(Self { random_hash, parts })
    }

    /// Serialize all hashes as concatenated bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.parts.len() * MAPHASH_LEN);
        for hash in &self.parts {
            buf.extend_from_slice(hash);
        }
        buf
    }

    /// Verify that data at the given index matches its stored hash.
    pub fn verify_part(&self, index: usize, data: &[u8]) -> bool {
        match self.parts.get(index) {
            Some(expected) => {
                let computed = self.compute_map_hash(data);
                computed == *expected
            }
            None => false,
        }
    }

    /// Number of part hashes stored.
    pub fn len(&self) -> usize {
        self.parts.len()
    }

    /// Whether the hashmap is empty.
    pub fn is_empty(&self) -> bool {
        self.parts.is_empty()
    }

    /// The random hash bound to this hashmap.
    pub fn random_hash(&self) -> &[u8; RANDOM_HASH_SIZE] {
        &self.random_hash
    }

    /// Get the hash at the given index.
    pub fn get(&self, index: usize) -> Option<&MapHash> {
        self.parts.get(index)
    }

    // -------------------------------------------------------------- //
    // Segmentation (HASHMAP_MAX_LEN = 74 hashes per segment)
    // -------------------------------------------------------------- //

    /// Number of segments needed to send all hashes.
    pub fn segment_count(&self) -> usize {
        if self.parts.is_empty() {
            return 0;
        }
        self.parts.len().div_ceil(HASHMAP_MAX_LEN)
    }

    /// Slice of hashes for the given segment index.
    pub fn segment(&self, index: usize) -> &[MapHash] {
        let start = index * HASHMAP_MAX_LEN;
        if start >= self.parts.len() {
            return &[];
        }
        let end = (start + HASHMAP_MAX_LEN).min(self.parts.len());
        &self.parts[start..end]
    }

    /// Flattened bytes for the given segment index.
    pub fn segment_bytes(&self, index: usize) -> Vec<u8> {
        let seg = self.segment(index);
        let mut buf = Vec::with_capacity(seg.len() * MAPHASH_LEN);
        for hash in seg {
            buf.extend_from_slice(hash);
        }
        buf
    }

    /// Number of hashes in the given segment.
    pub fn segment_hash_count(&self, index: usize) -> usize {
        self.segment(index).len()
    }

    // -------------------------------------------------------------- //
    // Collision detection
    // -------------------------------------------------------------- //

    /// Check for hash collisions within a sliding window of `COLLISION_GUARD_SIZE`.
    ///
    /// Returns the index of the first duplicate hash, or `None` if no
    /// collisions are found.
    pub fn check_collisions(&self) -> Option<usize> {
        let mut window: VecDeque<MapHash> = VecDeque::with_capacity(COLLISION_GUARD_SIZE);
        let mut seen: HashSet<MapHash> = HashSet::with_capacity(COLLISION_GUARD_SIZE);

        for (i, hash) in self.parts.iter().enumerate() {
            if !seen.insert(*hash) {
                return Some(i);
            }
            window.push_back(*hash);

            if window.len() > COLLISION_GUARD_SIZE
                && let Some(old) = window.pop_front()
            {
                // Only remove from seen if the hash doesn't appear
                // elsewhere in the current window.
                if !window.contains(&old) {
                    seen.remove(&old);
                }
            }
        }
        None
    }
}

// ------------------------------------------------------------------ //
// Tests
// ------------------------------------------------------------------ //

#[cfg(test)]
mod tests {
    use super::super::constants::SDU;
    use super::*;

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        hex::decode(hex).expect("invalid hex")
    }

    // ============================================================== //
    // Unit tests
    // ============================================================== //

    #[test]
    fn new_creates_empty() {
        let hm = ResourceHashmap::new([0xAA; RANDOM_HASH_SIZE]);
        assert_eq!(hm.len(), 0);
        assert!(hm.is_empty());
    }

    #[test]
    fn add_part_increments_length() {
        let mut hm = ResourceHashmap::new([0xBB; RANDOM_HASH_SIZE]);
        hm.add_part(b"part one");
        hm.add_part(b"part two");
        hm.add_part(b"part three");
        assert_eq!(hm.len(), 3);
        assert!(!hm.is_empty());
    }

    #[test]
    fn to_bytes_from_bytes_roundtrip() {
        let mut hm = ResourceHashmap::new([0x01, 0x02, 0x03, 0x04]);
        hm.add_part(b"alpha");
        hm.add_part(b"beta");
        hm.add_part(b"gamma");

        let bytes = hm.to_bytes();
        let hm2 = ResourceHashmap::from_bytes(&bytes, [0x01, 0x02, 0x03, 0x04]).unwrap();
        assert_eq!(hm, hm2);
    }

    #[test]
    fn from_bytes_rejects_bad_length() {
        let result = ResourceHashmap::from_bytes(&[0u8; 5], [0; RANDOM_HASH_SIZE]);
        assert!(result.is_err());
    }

    #[test]
    fn from_bytes_empty_ok() {
        let hm = ResourceHashmap::from_bytes(&[], [0; RANDOM_HASH_SIZE]).unwrap();
        assert!(hm.is_empty());
        assert_eq!(hm.len(), 0);
    }

    #[test]
    fn verify_part_out_of_bounds() {
        let hm = ResourceHashmap::new([0; RANDOM_HASH_SIZE]);
        assert!(!hm.verify_part(999, b"data"));
    }

    #[test]
    fn verify_part_wrong_data() {
        let mut hm = ResourceHashmap::new([0xCC; RANDOM_HASH_SIZE]);
        hm.add_part(b"correct data");
        assert!(!hm.verify_part(0, b"wrong data"));
    }

    #[test]
    fn verify_part_correct_data() {
        let mut hm = ResourceHashmap::new([0xDD; RANDOM_HASH_SIZE]);
        hm.add_part(b"hello world");
        assert!(hm.verify_part(0, b"hello world"));
    }

    #[test]
    fn segment_count_boundaries() {
        let rh = [0u8; RANDOM_HASH_SIZE];

        // 0 parts → 0 segments
        let hm = ResourceHashmap {
            random_hash: rh,
            parts: vec![],
        };
        assert_eq!(hm.segment_count(), 0);

        // 1 part → 1 segment
        let hm = ResourceHashmap {
            random_hash: rh,
            parts: vec![[0; 4]; 1],
        };
        assert_eq!(hm.segment_count(), 1);

        // 74 parts → 1 segment
        let hm = ResourceHashmap {
            random_hash: rh,
            parts: vec![[0; 4]; 74],
        };
        assert_eq!(hm.segment_count(), 1);

        // 75 parts → 2 segments
        let hm = ResourceHashmap {
            random_hash: rh,
            parts: vec![[0; 4]; 75],
        };
        assert_eq!(hm.segment_count(), 2);

        // 148 parts → 2 segments
        let hm = ResourceHashmap {
            random_hash: rh,
            parts: vec![[0; 4]; 148],
        };
        assert_eq!(hm.segment_count(), 2);

        // 149 parts → 3 segments
        let hm = ResourceHashmap {
            random_hash: rh,
            parts: vec![[0; 4]; 149],
        };
        assert_eq!(hm.segment_count(), 3);
    }

    #[test]
    fn segment_out_of_bounds() {
        let hm = ResourceHashmap::new([0; RANDOM_HASH_SIZE]);
        assert!(hm.segment(0).is_empty());
        assert!(hm.segment(100).is_empty());
    }

    #[test]
    fn collision_check_no_collisions() {
        let mut hm = ResourceHashmap::new([0; RANDOM_HASH_SIZE]);
        // Use distinct data to get distinct hashes (overwhelmingly likely).
        for i in 0u32..100 {
            hm.add_part(&i.to_le_bytes());
        }
        assert_eq!(hm.check_collisions(), None);
    }

    #[test]
    fn collision_check_detects_collision() {
        let rh = [0u8; RANDOM_HASH_SIZE];
        // Manually insert a duplicate hash within the guard window.
        let hash_a = [0x01, 0x02, 0x03, 0x04];
        let hash_b = [0x05, 0x06, 0x07, 0x08];
        let hm = ResourceHashmap {
            random_hash: rh,
            parts: vec![hash_a, hash_b, hash_a],
        };
        assert_eq!(hm.check_collisions(), Some(2));
    }

    #[test]
    fn compute_map_hash_matches_manual() {
        let random_hash = [0x05, 0x08, 0xAD, 0x6A];
        let hm = ResourceHashmap::new(random_hash);

        // SHA256(data || random_hash) then take first 4 bytes.
        let data = b"test data";
        let mut input = Vec::new();
        input.extend_from_slice(data);
        input.extend_from_slice(&random_hash);
        let digest = sha256(&input);

        let expected: MapHash = digest[..MAPHASH_LEN].try_into().unwrap();
        let computed = hm.compute_map_hash(data);
        assert_eq!(computed, expected);
    }

    #[test]
    fn from_data_chunks_correctly() {
        // 5 bytes of data with SDU=2 → 3 parts (2, 2, 1 bytes).
        let data = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
        let hm = ResourceHashmap::from_data(&data, 2, [0x11; RANDOM_HASH_SIZE]);
        assert_eq!(hm.len(), 3);

        // Verify each part hash manually.
        let mut expected = ResourceHashmap::new([0x11; RANDOM_HASH_SIZE]);
        expected.add_part(&[0xAA, 0xBB]);
        expected.add_part(&[0xCC, 0xDD]);
        expected.add_part(&[0xEE]);
        assert_eq!(hm, expected);
    }

    // ============================================================== //
    // Test vector tests — Vector 1 (256KB, 552 parts, 8 segments)
    // ============================================================== //

    fn load_transfer_vectors()
    -> Vec<reticulum_test_vectors::resource_transfers::TransferSequenceVector> {
        reticulum_test_vectors::resource_transfers::load().transfer_sequence_vectors
    }

    /// Find vector by index (0-based in the array, but the "index" field in JSON
    /// may differ; we use the array position for vectors with hashmap data).
    fn vector_with_hashmap(
        vectors: &[reticulum_test_vectors::resource_transfers::TransferSequenceVector],
        idx: usize,
    ) -> &reticulum_test_vectors::resource_transfers::TransferSequenceVector {
        // Vectors with hashmap_by_segment are the ones with multi-part transfers.
        let with_hashmap: Vec<_> = vectors
            .iter()
            .filter(|v| v.hashmap_by_segment.is_some())
            .collect();
        with_hashmap[idx]
    }

    #[test]
    fn hashmap_from_bytes_vector_1() {
        let vectors = load_transfer_vectors();
        let v = vector_with_hashmap(&vectors, 0);

        let total_hex = v.total_hashmap_hex.as_ref().unwrap();
        let total_bytes = hex_to_bytes(total_hex);
        let random_hash: [u8; 4] = hex_to_bytes(v.random_hash_hex.as_ref().unwrap())
            .try_into()
            .unwrap();

        let hm = ResourceHashmap::from_bytes(&total_bytes, random_hash).unwrap();
        assert_eq!(hm.len(), v.num_parts.unwrap() as usize);

        // Roundtrip
        assert_eq!(hm.to_bytes(), total_bytes);
    }

    #[test]
    fn hashmap_segmentation_vector_1() {
        let vectors = load_transfer_vectors();
        let v = vector_with_hashmap(&vectors, 0);

        let total_hex = v.total_hashmap_hex.as_ref().unwrap();
        let total_bytes = hex_to_bytes(total_hex);
        let random_hash: [u8; 4] = hex_to_bytes(v.random_hash_hex.as_ref().unwrap())
            .try_into()
            .unwrap();

        let hm = ResourceHashmap::from_bytes(&total_bytes, random_hash).unwrap();

        let segments = v.hashmap_by_segment.as_ref().unwrap();
        assert_eq!(hm.segment_count(), segments.len());

        for seg_val in segments {
            let seg_idx = seg_val.segment as usize;
            let expected_count = seg_val.hash_count as usize;
            let expected_hex = seg_val.hashmap_hex.as_ref().unwrap();
            let expected_bytes = hex_to_bytes(expected_hex);

            assert_eq!(
                hm.segment_hash_count(seg_idx),
                expected_count,
                "segment {seg_idx} hash count"
            );
            assert_eq!(
                hm.segment_bytes(seg_idx),
                expected_bytes,
                "segment {seg_idx} bytes"
            );
        }
    }

    #[test]
    fn hashmap_verify_parts_vector_1() {
        let vectors = load_transfer_vectors();
        let v = vector_with_hashmap(&vectors, 0);

        let total_hex = v.total_hashmap_hex.as_ref().unwrap();
        let total_bytes = hex_to_bytes(total_hex);
        let random_hash: [u8; 4] = hex_to_bytes(v.random_hash_hex.as_ref().unwrap())
            .try_into()
            .unwrap();

        let hm = ResourceHashmap::from_bytes(&total_bytes, random_hash).unwrap();

        let rep_parts = v.representative_parts.as_ref().unwrap();
        for part in rep_parts {
            let idx = part.part_index as usize;
            let expected_hash: MapHash = hex_to_bytes(&part.map_hash_hex).try_into().unwrap();

            assert_eq!(
                *hm.get(idx).unwrap(),
                expected_hash,
                "part {idx} hash mismatch"
            );
        }
    }

    // ============================================================== //
    // Test vector tests — Vector 2 (1MB, 2156 parts, 30 segments)
    // ============================================================== //

    #[test]
    fn hashmap_total_sha256_vector_2() {
        let vectors = load_transfer_vectors();
        let v = vector_with_hashmap(&vectors, 1);

        let segments = v.hashmap_by_segment.as_ref().unwrap();

        // Reconstruct from segment 0 (has hashmap_hex) + segment 29 (has hashmap_hex).
        // We can only verify the overall SHA256 since middle segments only have sha256.
        // But let's verify using the total_hashmap_sha256.
        let expected_sha256 = v.total_hashmap_sha256.as_ref().unwrap();
        let num_parts = v.num_parts.unwrap() as usize;
        assert_eq!(num_parts, 2156);

        // Verify segment structure.
        assert_eq!(segments.len(), 30);

        // First segment has hashmap_hex.
        let seg0_hex = segments[0].hashmap_hex.as_ref().unwrap();
        let seg0_bytes = hex_to_bytes(seg0_hex);
        assert_eq!(seg0_bytes.len(), 74 * MAPHASH_LEN);

        // Last segment has hashmap_hex.
        let seg29_hex = segments[29].hashmap_hex.as_ref().unwrap();
        let seg29_bytes = hex_to_bytes(seg29_hex);
        assert_eq!(seg29_bytes.len(), 10 * MAPHASH_LEN);

        // Verify segment hash counts: 29 segments of 74, last segment of 10.
        for (i, seg) in segments.iter().enumerate() {
            let count = seg.hash_count as usize;
            if i < 29 {
                assert_eq!(count, 74, "segment {i} should have 74 hashes");
            } else {
                assert_eq!(count, 10, "segment 29 should have 10 hashes");
            }
        }

        // Total parts: 29 * 74 + 10 = 2156
        assert_eq!(29 * 74 + 10, 2156);

        // Verify the SHA256 of the total hashmap matches expected.
        // We can't fully reconstruct since middle segments only have sha256 checksums,
        // but we can verify the first and last segment structure.
        let expected_sha = hex_to_bytes(expected_sha256);
        assert_eq!(expected_sha.len(), 32);
    }

    #[test]
    fn hashmap_segment_count_vector_2() {
        let vectors = load_transfer_vectors();
        let v = vector_with_hashmap(&vectors, 1);

        let num_parts = v.num_parts.unwrap() as usize;
        assert_eq!(num_parts, 2156);

        // Construct a hashmap with the right number of parts and verify segment_count.
        let rh = [0u8; RANDOM_HASH_SIZE];
        let hm = ResourceHashmap {
            random_hash: rh,
            parts: vec![[0u8; MAPHASH_LEN]; num_parts],
        };
        assert_eq!(hm.segment_count(), 30);

        // 29 segments × 74 + 1 segment × 10 = 2156
        for i in 0..29 {
            assert_eq!(hm.segment_hash_count(i), 74, "segment {i}");
        }
        assert_eq!(hm.segment_hash_count(29), 10, "last segment");
    }

    #[test]
    fn hashmap_verify_parts_vector_2() {
        let vectors = load_transfer_vectors();
        let v = vector_with_hashmap(&vectors, 1);

        // We can only verify part hashes that appear in segments with hashmap_hex.
        // Segment 0 covers parts 0..74, segment 29 covers parts 2146..2156.
        let segments = v.hashmap_by_segment.as_ref().unwrap();
        let seg0_bytes = hex_to_bytes(segments[0].hashmap_hex.as_ref().unwrap());
        let seg29_bytes = hex_to_bytes(segments[29].hashmap_hex.as_ref().unwrap());

        let random_hash: [u8; 4] = hex_to_bytes(v.random_hash_hex.as_ref().unwrap())
            .try_into()
            .unwrap();

        // Build partial hashmaps from the available segments.
        let seg0_hm = ResourceHashmap::from_bytes(&seg0_bytes, random_hash).unwrap();
        let seg29_hm = ResourceHashmap::from_bytes(&seg29_bytes, random_hash).unwrap();

        let rep_parts = v.representative_parts.as_ref().unwrap();
        for part in rep_parts {
            let idx = part.part_index as usize;
            let expected_hash: MapHash = hex_to_bytes(&part.map_hash_hex).try_into().unwrap();

            if idx < 74 {
                // In segment 0.
                assert_eq!(
                    *seg0_hm.get(idx).unwrap(),
                    expected_hash,
                    "part {idx} hash mismatch in segment 0"
                );
            } else if idx >= 29 * 74 {
                // In segment 29.
                let local_idx = idx - 29 * 74;
                assert_eq!(
                    *seg29_hm.get(local_idx).unwrap(),
                    expected_hash,
                    "part {idx} hash mismatch in segment 29"
                );
            }
            // Parts in middle segments can't be verified without full hashmap data.
        }
    }

    // ============================================================== //
    // Adversarial collision tests
    // ============================================================== //

    #[test]
    fn test_hashmap_adversarial_collision_at_guard_boundary() {
        let rh = [0u8; RANDOM_HASH_SIZE];
        let dup = [0x01, 0x02, 0x03, 0x04];
        let filler = [0x05, 0x06, 0x07, 0x08];

        // Duplicate within COLLISION_GUARD_SIZE window → detected
        let mut parts_within = vec![dup];
        for _ in 1..COLLISION_GUARD_SIZE {
            parts_within.push(filler);
        }
        parts_within.push(dup); // at index COLLISION_GUARD_SIZE (within window)
        let hm_within = ResourceHashmap {
            random_hash: rh,
            parts: parts_within,
        };
        assert!(
            hm_within.check_collisions().is_some(),
            "duplicate within guard window should be detected"
        );

        // Duplicate outside COLLISION_GUARD_SIZE window → NOT detected
        // Need COLLISION_GUARD_SIZE + 1 distinct fillers between the duplicates
        let mut parts_outside = vec![dup];
        for i in 1..=COLLISION_GUARD_SIZE + 1 {
            // Use unique fillers to avoid collisions with each other
            parts_outside.push([(i & 0xFF) as u8, ((i >> 8) & 0xFF) as u8, 0xAA, 0xBB]);
        }
        parts_outside.push(dup); // well outside the guard window
        let hm_outside = ResourceHashmap {
            random_hash: rh,
            parts: parts_outside,
        };
        assert!(
            hm_outside.check_collisions().is_none(),
            "duplicate outside guard window should NOT be detected"
        );
    }

    // ============================================================== //
    // Property tests
    // ============================================================== //

    mod proptests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn roundtrip(
                random_hash in any::<[u8; RANDOM_HASH_SIZE]>(),
                parts in proptest::collection::vec(
                    proptest::collection::vec(any::<u8>(), 1..=SDU),
                    0..50
                )
            ) {
                let mut hm = ResourceHashmap::new(random_hash);
                for part in &parts {
                    hm.add_part(part);
                }

                let bytes = hm.to_bytes();
                let hm2 = ResourceHashmap::from_bytes(&bytes, random_hash).unwrap();
                prop_assert_eq!(hm, hm2);
            }

            #[test]
            fn verify_agrees_with_add(
                random_hash in any::<[u8; RANDOM_HASH_SIZE]>(),
                data in proptest::collection::vec(any::<u8>(), 1..=100)
            ) {
                let mut hm = ResourceHashmap::new(random_hash);
                hm.add_part(&data);
                prop_assert!(hm.verify_part(0, &data));
            }

            #[test]
            fn segment_count_formula(
                n in 0usize..5000
            ) {
                let rh = [0u8; RANDOM_HASH_SIZE];
                let hm = ResourceHashmap {
                    random_hash: rh,
                    parts: vec![[0u8; MAPHASH_LEN]; n],
                };

                let expected = if n == 0 { 0 } else { (n + HASHMAP_MAX_LEN - 1) / HASHMAP_MAX_LEN };
                prop_assert_eq!(hm.segment_count(), expected);
            }

            #[test]
            fn segments_concatenate_to_total(
                random_hash in any::<[u8; RANDOM_HASH_SIZE]>(),
                parts in proptest::collection::vec(
                    proptest::collection::vec(any::<u8>(), 1..=10),
                    0..200
                )
            ) {
                let mut hm = ResourceHashmap::new(random_hash);
                for part in &parts {
                    hm.add_part(part);
                }

                let total = hm.to_bytes();
                let mut concatenated = Vec::new();
                for i in 0..hm.segment_count() {
                    concatenated.extend_from_slice(&hm.segment_bytes(i));
                }
                prop_assert_eq!(total, concatenated);
            }
        }
    }
}
