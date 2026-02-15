//! Announce propagation and rate limiting.

use std::collections::HashMap;

use reticulum_core::types::DestinationHash;

use super::constants::*;
use crate::path::InterfaceId;

/// Action to take for a pending announce.
#[derive(Debug, Clone)]
pub enum AnnounceAction {
    /// Retransmit the announce on the specified interface.
    Retransmit {
        destination: DestinationHash,
        raw_packet: Vec<u8>,
        exclude_interface: Option<InterfaceId>,
    },
    /// Announce has completed all retransmissions, remove it.
    Completed { destination: DestinationHash },
}

/// An entry in the announce retransmission table.
#[derive(Debug, Clone)]
pub struct AnnounceTableEntry {
    /// When the announce was first received.
    pub timestamp: f64,
    /// Next retransmission timeout (absolute time).
    pub retransmit_timeout: f64,
    /// Number of retransmit attempts so far.
    pub retries: u32,
    /// Interface the announce was received from.
    pub received_from: InterfaceId,
    /// Hop count of the announce.
    pub hops: u8,
    /// The raw packet to retransmit.
    pub raw_packet: Vec<u8>,
    /// Local rebroadcast count.
    pub local_rebroadcast_count: u32,
    /// Whether to block further rebroadcasts.
    pub block_rebroadcasts: bool,
    /// Interface the announce is attached to.
    pub attached_interface: Option<InterfaceId>,
}

/// Parameters for inserting an announce entry into the retransmission table.
#[derive(Debug, Clone)]
pub struct AnnounceInsertParams {
    /// Destination hash for this announce.
    pub destination: DestinationHash,
    /// Current time (seconds).
    pub now: f64,
    /// Random delay factor for retransmission scheduling.
    pub random_delay: f64,
    /// Number of retransmit attempts so far.
    pub retries: u32,
    /// Interface the announce was received from.
    pub received_from: InterfaceId,
    /// Hop count of the announce.
    pub hops: u8,
    /// The raw packet to retransmit.
    pub raw_packet: Vec<u8>,
    /// Local rebroadcast count.
    pub local_rebroadcasts: u32,
    /// Whether to block further rebroadcasts.
    pub block_rebroadcasts: bool,
    /// Interface the announce is attached to.
    pub attached_interface: Option<InterfaceId>,
}

/// Decision from evaluating a single announce table entry for retransmission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetransmitDecision {
    /// Entry has exhausted retries and should be removed.
    Completed,
    /// Timeout reached and entry should be retransmitted.
    Retransmit,
    /// Timeout reached but rebroadcasts are blocked for this entry.
    BlockedRetransmit,
    /// Timeout not yet reached; wait.
    Wait,
}

/// Decide whether a single announce entry should be retransmitted.
///
/// This is the pure decision extracted from `process_retransmissions`.
#[must_use]
pub fn decide_retransmission(
    retries: u32,
    retransmit_timeout: f64,
    block_rebroadcasts: bool,
    now: f64,
) -> RetransmitDecision {
    if retries >= LOCAL_REBROADCASTS_MAX || retries > PATHFINDER_R {
        return RetransmitDecision::Completed;
    }
    if now > retransmit_timeout {
        if block_rebroadcasts {
            RetransmitDecision::BlockedRetransmit
        } else {
            RetransmitDecision::Retransmit
        }
    } else {
        RetransmitDecision::Wait
    }
}

/// Announce retransmission table.
#[must_use]
pub struct AnnounceTable {
    entries: HashMap<DestinationHash, AnnounceTableEntry>,
}

impl AnnounceTable {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Insert a new announce entry for retransmission.
    pub fn insert(&mut self, params: AnnounceInsertParams) {
        let retransmit_timeout = params.now + params.random_delay * PATHFINDER_RW;
        let entry = AnnounceTableEntry {
            timestamp: params.now,
            retransmit_timeout,
            retries: params.retries,
            received_from: params.received_from,
            hops: params.hops,
            raw_packet: params.raw_packet,
            local_rebroadcast_count: params.local_rebroadcasts,
            block_rebroadcasts: params.block_rebroadcasts,
            attached_interface: params.attached_interface,
        };
        self.entries.insert(params.destination, entry);
    }

    /// Get an announce entry.
    #[must_use]
    pub fn get(&self, destination: &DestinationHash) -> Option<&AnnounceTableEntry> {
        self.entries.get(destination)
    }

    /// Remove an announce entry.
    pub fn remove(&mut self, destination: &DestinationHash) -> Option<AnnounceTableEntry> {
        self.entries.remove(destination)
    }

    /// Check if an entry exists for this destination.
    #[must_use]
    pub fn contains(&self, destination: &DestinationHash) -> bool {
        self.entries.contains_key(destination)
    }

    /// Process retransmissions: check all entries, return actions.
    ///
    /// Call this periodically (e.g., every second).
    pub fn process_retransmissions(&mut self, now: f64) -> Vec<AnnounceAction> {
        let mut actions = Vec::with_capacity(self.entries.len());
        let mut completed = Vec::with_capacity(self.entries.len());

        for (dest, entry) in &mut self.entries {
            match decide_retransmission(
                entry.retries,
                entry.retransmit_timeout,
                entry.block_rebroadcasts,
                now,
            ) {
                RetransmitDecision::Completed => {
                    completed.push(*dest);
                }
                RetransmitDecision::Retransmit => {
                    entry.retransmit_timeout = now + PATHFINDER_G + PATHFINDER_RW;
                    entry.retries += 1;
                    actions.push(AnnounceAction::Retransmit {
                        destination: *dest,
                        raw_packet: entry.raw_packet.clone(),
                        exclude_interface: Some(entry.received_from),
                    });
                }
                RetransmitDecision::BlockedRetransmit => {
                    entry.retransmit_timeout = now + PATHFINDER_G + PATHFINDER_RW;
                    entry.retries += 1;
                }
                RetransmitDecision::Wait => {}
            }
        }

        for dest in &completed {
            self.entries.remove(dest);
            actions.push(AnnounceAction::Completed { destination: *dest });
        }

        actions
    }

    /// Number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the table is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for AnnounceTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute the minimum wait time before retransmitting an announce.
///
/// Formula: `(size_bits / bitrate) / cap`
#[must_use]
pub fn compute_announce_wait_time(size_bytes: usize, bitrate: f64, cap: f64) -> f64 {
    let size_bits = (size_bytes * 8) as f64;
    (size_bits / bitrate) / cap
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::path::InterfaceId;
    use reticulum_core::types::DestinationHash;

    fn make_dest(seed: u8) -> DestinationHash {
        DestinationHash::new([seed; 16])
    }

    #[test]
    fn test_announce_table_insert_and_get() {
        let mut table = AnnounceTable::new();
        let dest = make_dest(1);

        table.insert(AnnounceInsertParams {
            destination: dest,
            now: 1000.0,
            random_delay: 0.5,
            retries: 0,
            received_from: InterfaceId(1),
            hops: 1,
            raw_packet: vec![0x01, 0x02],
            local_rebroadcasts: 0,
            block_rebroadcasts: false,
            attached_interface: None,
        });

        assert!(table.contains(&dest));
        let entry = table.get(&dest).unwrap();
        assert_eq!(entry.hops, 1);
        assert_eq!(entry.retries, 0);
    }

    #[test]
    fn test_process_retransmissions_timeout() {
        let mut table = AnnounceTable::new();
        let dest = make_dest(1);

        // Insert with timeout at 1000.25 (1000.0 + 0.5 * 0.5)
        table.insert(AnnounceInsertParams {
            destination: dest,
            now: 1000.0,
            random_delay: 0.5,
            retries: 0,
            received_from: InterfaceId(1),
            hops: 1,
            raw_packet: vec![0x01],
            local_rebroadcasts: 0,
            block_rebroadcasts: false,
            attached_interface: None,
        });

        // Before timeout: no actions
        let actions = table.process_retransmissions(1000.1);
        assert!(
            actions
                .iter()
                .all(|a| !matches!(a, AnnounceAction::Retransmit { .. })),
            "should not retransmit before timeout"
        );

        // After timeout: retransmit
        let actions = table.process_retransmissions(1000.3);
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, AnnounceAction::Retransmit { .. })),
            "should retransmit after timeout"
        );
    }

    #[test]
    fn test_process_retransmissions_max_retries() {
        let mut table = AnnounceTable::new();
        let dest = make_dest(1);

        // Insert with retries already at PATHFINDER_R + 1 = 2
        table.insert(AnnounceInsertParams {
            destination: dest,
            now: 1000.0,
            random_delay: 0.0,
            retries: PATHFINDER_R + 1,
            received_from: InterfaceId(1),
            hops: 1,
            raw_packet: vec![0x01],
            local_rebroadcasts: 0,
            block_rebroadcasts: false,
            attached_interface: None,
        });

        let actions = table.process_retransmissions(2000.0);
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, AnnounceAction::Completed { .. })),
            "should complete after max retries"
        );
        assert!(!table.contains(&dest));
    }

    #[test]
    fn test_process_retransmissions_local_rebroadcast_max() {
        let mut table = AnnounceTable::new();
        let dest = make_dest(1);

        // Insert with retries at LOCAL_REBROADCASTS_MAX
        table.insert(AnnounceInsertParams {
            destination: dest,
            now: 1000.0,
            random_delay: 0.0,
            retries: LOCAL_REBROADCASTS_MAX,
            received_from: InterfaceId(1),
            hops: 1,
            raw_packet: vec![0x01],
            local_rebroadcasts: 0,
            block_rebroadcasts: false,
            attached_interface: None,
        });

        let actions = table.process_retransmissions(2000.0);
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, AnnounceAction::Completed { .. })),
            "should complete at local rebroadcast max"
        );
    }

    #[test]
    fn test_block_rebroadcasts() {
        let mut table = AnnounceTable::new();
        let dest = make_dest(1);

        table.insert(AnnounceInsertParams {
            destination: dest,
            now: 1000.0,
            random_delay: 0.0, // immediate timeout
            retries: 0,
            received_from: InterfaceId(1),
            hops: 1,
            raw_packet: vec![0x01],
            local_rebroadcasts: 0,
            block_rebroadcasts: true, // block rebroadcasts
            attached_interface: None,
        });

        let actions = table.process_retransmissions(1001.0);
        // Should not emit Retransmit actions when blocked
        assert!(
            !actions
                .iter()
                .any(|a| matches!(a, AnnounceAction::Retransmit { .. })),
            "should not retransmit when blocked"
        );
    }

    #[test]
    fn test_compute_announce_wait_time() {
        // 100 bytes at 1000 bps with 2% cap
        let wait = compute_announce_wait_time(100, 1000.0, ANNOUNCE_CAP);
        // (100*8 / 1000) / 0.02 = 0.8 / 0.02 = 40.0
        assert!((wait - 40.0).abs() < 0.001);
    }

    #[test]
    fn test_compute_announce_wait_time_high_bitrate() {
        // 500 bytes at 1_000_000 bps with 2% cap
        let wait = compute_announce_wait_time(500, 1_000_000.0, ANNOUNCE_CAP);
        // (500*8 / 1_000_000) / 0.02 = 0.004 / 0.02 = 0.2
        assert!((wait - 0.2).abs() < 0.001);
    }

    #[test]
    fn test_announce_table_remove() {
        let mut table = AnnounceTable::new();
        let dest = make_dest(1);

        table.insert(AnnounceInsertParams {
            destination: dest,
            now: 1000.0,
            random_delay: 0.5,
            retries: 0,
            received_from: InterfaceId(1),
            hops: 1,
            raw_packet: vec![0x01],
            local_rebroadcasts: 0,
            block_rebroadcasts: false,
            attached_interface: None,
        });
        assert!(table.contains(&dest));

        table.remove(&dest);
        assert!(!table.contains(&dest));
    }

    // -----------------------------------------------------------------------
    // decide_retransmission pure function tests
    // -----------------------------------------------------------------------

    #[test]
    fn decide_completed_at_local_rebroadcasts_max() {
        assert_eq!(
            decide_retransmission(LOCAL_REBROADCASTS_MAX, 100.0, false, 200.0),
            RetransmitDecision::Completed
        );
    }

    #[test]
    fn decide_completed_above_pathfinder_r() {
        assert_eq!(
            decide_retransmission(PATHFINDER_R + 1, 100.0, false, 200.0),
            RetransmitDecision::Completed
        );
    }

    #[test]
    fn decide_wait_before_timeout() {
        assert_eq!(
            decide_retransmission(0, 100.0, false, 99.9),
            RetransmitDecision::Wait
        );
    }

    #[test]
    fn decide_wait_exact_boundary() {
        // Exact equality is NOT past timeout (uses strict >)
        assert_eq!(
            decide_retransmission(0, 100.0, false, 100.0),
            RetransmitDecision::Wait
        );
    }

    #[test]
    fn decide_retransmit_after_timeout() {
        assert_eq!(
            decide_retransmission(0, 100.0, false, 100.1),
            RetransmitDecision::Retransmit
        );
    }

    #[test]
    fn decide_blocked_retransmit() {
        assert_eq!(
            decide_retransmission(0, 100.0, true, 100.1),
            RetransmitDecision::BlockedRetransmit
        );
    }

    #[test]
    fn decide_at_pathfinder_r_fires_if_timeout_reached() {
        // retries == PATHFINDER_R (1) is NOT > PATHFINDER_R, so it should still fire
        assert_eq!(
            decide_retransmission(PATHFINDER_R, 50.0, false, 51.0),
            RetransmitDecision::Retransmit
        );
    }

    #[test]
    fn decide_zero_retries_not_completed() {
        assert_ne!(
            decide_retransmission(0, 100.0, false, 50.0),
            RetransmitDecision::Completed
        );
    }

    #[test]
    fn decide_zero_timeout_edge() {
        // timeout=0.0, now=0.0 → exact boundary → Wait
        assert_eq!(
            decide_retransmission(0, 0.0, false, 0.0),
            RetransmitDecision::Wait
        );
        // now just past → Retransmit
        assert_eq!(
            decide_retransmission(0, 0.0, false, 0.001),
            RetransmitDecision::Retransmit
        );
    }
}
