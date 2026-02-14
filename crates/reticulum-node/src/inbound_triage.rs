//! Pure inbound packet triage — early-drop decisions and packet classification.
//!
//! Extracted from [`crate::node`] so that deduplication, hop-limit, and
//! packet-type routing decisions can be tested without a running Node.

use reticulum_core::constants::PacketType;
use reticulum_transport::path::constants::PATHFINDER_M;

/// Reason a packet should be dropped before full processing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EarlyDropReason {
    /// The packet hash was already seen (deduplication).
    Duplicate,
    /// The hop count has reached or exceeded [`PATHFINDER_M`].
    HopLimitReached,
}

/// Check whether a packet should be dropped early.
///
/// `is_new` should be the result of inserting the packet hash into the
/// deduplication hashlist (`true` = not seen before).
///
/// Returns `Some(reason)` if the packet should be dropped, `None` if it
/// should proceed to full processing.
pub fn should_drop_early(is_new: bool, hops: u8) -> Option<EarlyDropReason> {
    if !is_new {
        return Some(EarlyDropReason::Duplicate);
    }
    if hops >= PATHFINDER_M {
        return Some(EarlyDropReason::HopLimitReached);
    }
    None
}

/// High-level classification of an inbound packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboundAction {
    /// Route through announce processing pipeline.
    ProcessAnnounce,
    /// Route through link/data/proof handling.
    HandleLinkPacket,
}

/// Classify a parsed packet by its [`PacketType`].
pub fn classify_inbound(packet_type: PacketType) -> InboundAction {
    match packet_type {
        PacketType::Announce => InboundAction::ProcessAnnounce,
        PacketType::Data | PacketType::LinkRequest | PacketType::Proof => {
            InboundAction::HandleLinkPacket
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- should_drop_early ---

    #[test]
    fn new_packet_below_limit_passes() {
        assert_eq!(should_drop_early(true, 0), None);
    }

    #[test]
    fn new_packet_at_limit_drops() {
        assert_eq!(
            should_drop_early(true, PATHFINDER_M),
            Some(EarlyDropReason::HopLimitReached)
        );
    }

    #[test]
    fn new_packet_above_limit_drops() {
        assert_eq!(
            should_drop_early(true, 255),
            Some(EarlyDropReason::HopLimitReached)
        );
    }

    #[test]
    fn duplicate_packet_drops() {
        assert_eq!(
            should_drop_early(false, 0),
            Some(EarlyDropReason::Duplicate)
        );
    }

    #[test]
    fn duplicate_at_limit_prefers_duplicate() {
        // Dedup is checked first, so even at hop limit we get Duplicate
        assert_eq!(
            should_drop_early(false, PATHFINDER_M),
            Some(EarlyDropReason::Duplicate)
        );
    }

    #[test]
    fn one_below_limit_passes() {
        assert_eq!(should_drop_early(true, PATHFINDER_M - 1), None);
    }

    #[test]
    fn mid_range_passes() {
        assert_eq!(should_drop_early(true, 64), None);
    }

    // --- classify_inbound ---

    #[test]
    fn classify_announce() {
        assert_eq!(
            classify_inbound(PacketType::Announce),
            InboundAction::ProcessAnnounce
        );
    }

    #[test]
    fn classify_data() {
        assert_eq!(
            classify_inbound(PacketType::Data),
            InboundAction::HandleLinkPacket
        );
    }

    #[test]
    fn classify_link_request() {
        assert_eq!(
            classify_inbound(PacketType::LinkRequest),
            InboundAction::HandleLinkPacket
        );
    }

    #[test]
    fn classify_proof() {
        assert_eq!(
            classify_inbound(PacketType::Proof),
            InboundAction::HandleLinkPacket
        );
    }
}
