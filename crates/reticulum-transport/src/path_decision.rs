//! Pure functions for path table update decisions.
//!
//! Extracts the 4-branch decision logic from `process_inbound_announce()`
//! into testable, stateless functions.

use reticulum_core::types::{DestinationHash, TruncatedHash};

use crate::path::types::PathEntry;

/// The outcome of evaluating whether to update a path table entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathUpdateDecision {
    /// No existing entry — insert a fresh path entry.
    InsertNew,
    /// Existing entry should be replaced (better hops or expired).
    Replace,
    /// Existing entry kept, but track the new random blob for dedup.
    TrackBlob,
    /// Exact duplicate announce (same random_hash) — skip entirely.
    Skip,
}

/// Decide whether an inbound announce should update the path table.
///
/// Evaluates the 4-branch decision:
/// 1. No existing entry → `InsertNew`
/// 2. Duplicate random_hash → `Skip`
/// 3. Fewer hops or expired entry → `Replace`
/// 4. Same or worse hops → `TrackBlob`
#[must_use]
pub fn decide_path_update(
    existing: Option<&PathEntry>,
    hops: u8,
    now: u64,
    random_hash: &[u8; 10],
) -> PathUpdateDecision {
    match existing {
        None => PathUpdateDecision::InsertNew,
        Some(entry) => {
            if entry.has_random_blob(random_hash) {
                PathUpdateDecision::Skip
            } else if hops < entry.hops || entry.is_expired(now) {
                PathUpdateDecision::Replace
            } else {
                PathUpdateDecision::TrackBlob
            }
        }
    }
}

/// Compute the next_hop field for a path entry from an optional transport_id.
///
/// - If the announce arrived via HEADER_2 relay with a `transport_id`, use it.
/// - If direct (HEADER_1, no transport_id), return all-zeros.
pub fn compute_announce_next_hop(transport_id: Option<&DestinationHash>) -> TruncatedHash {
    let zeros = TruncatedHash::new([0u8; 16]);
    transport_id
        .map(|tid| {
            TruncatedHash::try_from(tid.as_ref()).unwrap_or_else(|_| {
                tracing::warn!(
                    tid_len = tid.as_ref().len(),
                    "transport_id to TruncatedHash conversion failed, using zeros"
                );
                zeros
            })
        })
        .unwrap_or(zeros)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::path::types::{InterfaceId, InterfaceMode};
    use reticulum_core::types::PacketHash;

    fn make_entry(hops: u8, timestamp: u64, blobs: Vec<[u8; 10]>) -> PathEntry {
        PathEntry::new(
            timestamp,
            TruncatedHash::new([0u8; 16]),
            hops,
            InterfaceMode::Full,
            blobs,
            InterfaceId(1),
            PacketHash::new([0u8; 32]),
        )
    }

    // --- decide_path_update tests ---

    #[test]
    fn new_destination_inserts() {
        let decision = decide_path_update(None, 3, 1000, &[0xAA; 10]);
        assert_eq!(decision, PathUpdateDecision::InsertNew);
    }

    #[test]
    fn duplicate_blob_skips() {
        let entry = make_entry(3, 1000, vec![[0xAA; 10]]);
        let decision = decide_path_update(Some(&entry), 3, 1001, &[0xAA; 10]);
        assert_eq!(decision, PathUpdateDecision::Skip);
    }

    #[test]
    fn fewer_hops_replaces() {
        let entry = make_entry(5, 1000, vec![[0x11; 10]]);
        let decision = decide_path_update(Some(&entry), 2, 1001, &[0x22; 10]);
        assert_eq!(decision, PathUpdateDecision::Replace);
    }

    #[test]
    fn equal_hops_tracks_blob() {
        let entry = make_entry(3, 1000, vec![[0x11; 10]]);
        let decision = decide_path_update(Some(&entry), 3, 1001, &[0x22; 10]);
        assert_eq!(decision, PathUpdateDecision::TrackBlob);
    }

    #[test]
    fn more_hops_tracks_blob() {
        let entry = make_entry(2, 1000, vec![[0x11; 10]]);
        let decision = decide_path_update(Some(&entry), 5, 1001, &[0x22; 10]);
        assert_eq!(decision, PathUpdateDecision::TrackBlob);
    }

    #[test]
    fn expired_entry_worse_hops_replaces() {
        // Full mode TTL is 604800 (7 days), so entry at t=1000 expires at t=605800
        let entry = make_entry(2, 1000, vec![[0x11; 10]]);
        // now=605801 > 605800, entry is expired
        let decision = decide_path_update(Some(&entry), 5, 605801, &[0x22; 10]);
        assert_eq!(decision, PathUpdateDecision::Replace);
    }

    #[test]
    fn expired_entry_same_hops_replaces() {
        let entry = make_entry(3, 1000, vec![[0x11; 10]]);
        let decision = decide_path_update(Some(&entry), 3, 605801, &[0x22; 10]);
        assert_eq!(decision, PathUpdateDecision::Replace);
    }

    #[test]
    fn boundary_expiration_strict_greater() {
        // Expires = 1000 + 604800 = 605800
        let entry = make_entry(3, 1000, vec![[0x11; 10]]);
        // now == expires: NOT expired (strict >)
        let decision = decide_path_update(Some(&entry), 5, 605800, &[0x22; 10]);
        assert_eq!(decision, PathUpdateDecision::TrackBlob);
        // now == expires + 1: expired
        let decision = decide_path_update(Some(&entry), 5, 605801, &[0x22; 10]);
        assert_eq!(decision, PathUpdateDecision::Replace);
    }

    #[test]
    fn zero_hops_fewer_than_existing() {
        let entry = make_entry(1, 1000, vec![[0x11; 10]]);
        let decision = decide_path_update(Some(&entry), 0, 1001, &[0x22; 10]);
        assert_eq!(decision, PathUpdateDecision::Replace);
    }

    #[test]
    fn blob_priority_over_better_hops() {
        // If the blob is already tracked, skip even if hops are better
        let entry = make_entry(5, 1000, vec![[0xAA; 10]]);
        let decision = decide_path_update(Some(&entry), 1, 1001, &[0xAA; 10]);
        assert_eq!(decision, PathUpdateDecision::Skip);
    }

    // --- compute_announce_next_hop tests ---

    #[test]
    fn next_hop_with_transport_id() {
        let tid = DestinationHash::new([0xBB; 16]);
        let next_hop = compute_announce_next_hop(Some(&tid));
        assert_eq!(next_hop.as_ref(), &[0xBB; 16]);
    }

    #[test]
    fn next_hop_without_transport_id() {
        let next_hop = compute_announce_next_hop(None);
        assert_eq!(next_hop.as_ref(), &[0u8; 16]);
    }

    #[test]
    fn next_hop_distinct_transport_ids() {
        let tid1 = DestinationHash::new([0x11; 16]);
        let tid2 = DestinationHash::new([0x22; 16]);
        let nh1 = compute_announce_next_hop(Some(&tid1));
        let nh2 = compute_announce_next_hop(Some(&tid2));
        assert_ne!(nh1.as_ref(), nh2.as_ref());
    }

    #[test]
    fn next_hop_preserves_exact_bytes() {
        let mut tid_bytes = [0u8; 16];
        for (i, b) in tid_bytes.iter_mut().enumerate() {
            *b = i as u8;
        }
        let tid = DestinationHash::new(tid_bytes);
        let next_hop = compute_announce_next_hop(Some(&tid));
        assert_eq!(next_hop.as_ref(), &tid_bytes);
    }
}
