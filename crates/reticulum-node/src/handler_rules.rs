//! Pure packet context handling rules.
//!
//! Encodes the critical interop invariants about which packet contexts
//! require link-layer encryption, delivery proofs, or raw data handling.
//! The `Resource` context bypassing link encryption was a major bug source
//! during interop development — this module makes those rules explicit
//! and exhaustively tested.

use crate::link_dispatch::LinkPacketKind;

/// Whether a link-layer packet context requires link-layer encryption.
///
/// The critical rule: `Resource` (context 0x01 = raw resource parts)
/// bypasses link encryption because the resource layer handles its own
/// Token encryption. All other data contexts (ResourceAdv, ResourceReq,
/// ResourcePrf, Channel, Request, Response) ARE link-encrypted.
pub fn needs_link_encryption(kind: LinkPacketKind) -> bool {
    match kind {
        // Resource parts bypass link encryption — resource layer encrypts
        LinkPacketKind::ResourcePart => false,
        // Handshake packets have their own crypto, not link-layer encryption
        LinkPacketKind::LinkRequest
        | LinkPacketKind::LinkProof
        | LinkPacketKind::LinkRtt => false,
        // Plain link data and all other contexts use link encryption
        LinkPacketKind::LinkData
        | LinkPacketKind::ResourceAdvertisement
        | LinkPacketKind::ResourceRequest
        | LinkPacketKind::ResourceProof
        | LinkPacketKind::ChannelData
        | LinkPacketKind::Request
        | LinkPacketKind::Response => true,
        // Keepalive packets are NOT encrypted (raw passthrough, like Resource)
        LinkPacketKind::Keepalive => false,
        // Delivery proofs are not encrypted data
        LinkPacketKind::DeliveryProof => false,
        LinkPacketKind::Unknown => false,
    }
}

/// Whether a link-layer packet context requires automatic delivery proof.
///
/// Only `Channel` messages require delivery proofs — the Python Channel
/// implementation expects them and will retransmit without them.
pub fn needs_delivery_proof(kind: LinkPacketKind) -> bool {
    matches!(kind, LinkPacketKind::ChannelData)
}

/// Whether a link-layer packet uses raw (unencrypted) data extraction.
///
/// Only `ResourcePart` uses raw extraction — the resource layer handles
/// its own encryption, so we must NOT decrypt at the link layer.
pub fn uses_raw_data(kind: LinkPacketKind) -> bool {
    matches!(kind, LinkPacketKind::ResourcePart)
}

/// Describe the handler for a packet kind (useful for logging/debugging).
pub fn describe_handler(kind: LinkPacketKind) -> &'static str {
    match kind {
        LinkPacketKind::LinkRequest => "link_request",
        LinkPacketKind::LinkProof => "link_proof",
        LinkPacketKind::LinkRtt => "link_rtt",
        LinkPacketKind::LinkData => "link_data",
        LinkPacketKind::ResourceAdvertisement => "resource_advertisement (encrypted)",
        LinkPacketKind::ResourceRequest => "resource_request (encrypted)",
        LinkPacketKind::ResourcePart => "resource_part (raw/unencrypted)",
        LinkPacketKind::ResourceProof => "resource_proof (encrypted)",
        LinkPacketKind::ChannelData => "channel (encrypted+proof)",
        LinkPacketKind::Request => "request (encrypted)",
        LinkPacketKind::Response => "response (encrypted)",
        LinkPacketKind::Keepalive => "keepalive (raw/unencrypted)",
        LinkPacketKind::DeliveryProof => "delivery_proof",
        LinkPacketKind::Unknown => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reticulum_core::constants::{DestinationType, PacketType};
    use reticulum_core::packet::context::ContextType;
    use crate::link_dispatch::classify_link_packet;

    // === needs_link_encryption ===

    #[test]
    fn resource_part_bypasses_encryption() {
        let kind = classify_link_packet(
            PacketType::Data,
            ContextType::Resource,
            DestinationType::Link,
        );
        assert_eq!(kind, LinkPacketKind::ResourcePart);
        assert!(!needs_link_encryption(kind));
    }

    #[test]
    fn resource_adv_requires_encryption() {
        let kind = classify_link_packet(
            PacketType::Data,
            ContextType::ResourceAdv,
            DestinationType::Link,
        );
        assert!(needs_link_encryption(kind));
    }

    #[test]
    fn resource_req_requires_encryption() {
        let kind = classify_link_packet(
            PacketType::Data,
            ContextType::ResourceReq,
            DestinationType::Link,
        );
        assert!(needs_link_encryption(kind));
    }

    #[test]
    fn resource_prf_requires_encryption() {
        let kind = classify_link_packet(
            PacketType::Data,
            ContextType::ResourcePrf,
            DestinationType::Link,
        );
        assert!(needs_link_encryption(kind));
    }

    #[test]
    fn channel_requires_encryption() {
        let kind = classify_link_packet(
            PacketType::Data,
            ContextType::Channel,
            DestinationType::Link,
        );
        assert!(needs_link_encryption(kind));
    }

    #[test]
    fn request_requires_encryption() {
        let kind = classify_link_packet(
            PacketType::Data,
            ContextType::Request,
            DestinationType::Link,
        );
        assert!(needs_link_encryption(kind));
    }

    #[test]
    fn response_requires_encryption() {
        let kind = classify_link_packet(
            PacketType::Data,
            ContextType::Response,
            DestinationType::Link,
        );
        assert!(needs_link_encryption(kind));
    }

    #[test]
    fn link_data_requires_encryption() {
        let kind = classify_link_packet(
            PacketType::Data,
            ContextType::None,
            DestinationType::Link,
        );
        assert!(needs_link_encryption(kind));
    }

    #[test]
    fn handshake_packets_not_encrypted() {
        assert!(!needs_link_encryption(LinkPacketKind::LinkRequest));
        assert!(!needs_link_encryption(LinkPacketKind::LinkProof));
        assert!(!needs_link_encryption(LinkPacketKind::LinkRtt));
    }

    #[test]
    fn delivery_proof_not_encrypted() {
        assert!(!needs_link_encryption(LinkPacketKind::DeliveryProof));
    }

    #[test]
    fn unknown_not_encrypted() {
        assert!(!needs_link_encryption(LinkPacketKind::Unknown));
    }

    // === needs_delivery_proof ===

    #[test]
    fn channel_needs_proof() {
        assert!(needs_delivery_proof(LinkPacketKind::ChannelData));
    }

    #[test]
    fn request_no_proof() {
        assert!(!needs_delivery_proof(LinkPacketKind::Request));
    }

    #[test]
    fn response_no_proof() {
        assert!(!needs_delivery_proof(LinkPacketKind::Response));
    }

    #[test]
    fn resource_adv_no_proof() {
        assert!(!needs_delivery_proof(LinkPacketKind::ResourceAdvertisement));
    }

    #[test]
    fn link_data_no_proof() {
        assert!(!needs_delivery_proof(LinkPacketKind::LinkData));
    }

    // === uses_raw_data ===

    #[test]
    fn resource_part_uses_raw() {
        assert!(uses_raw_data(LinkPacketKind::ResourcePart));
    }

    #[test]
    fn resource_adv_not_raw() {
        assert!(!uses_raw_data(LinkPacketKind::ResourceAdvertisement));
    }

    #[test]
    fn channel_not_raw() {
        assert!(!uses_raw_data(LinkPacketKind::ChannelData));
    }

    #[test]
    fn link_data_not_raw() {
        assert!(!uses_raw_data(LinkPacketKind::LinkData));
    }

    // === Exhaustive coverage ===

    #[test]
    fn all_kinds_have_consistent_rules() {
        let all_kinds = [
            LinkPacketKind::LinkRequest,
            LinkPacketKind::LinkProof,
            LinkPacketKind::LinkRtt,
            LinkPacketKind::LinkData,
            LinkPacketKind::ResourceAdvertisement,
            LinkPacketKind::ResourceRequest,
            LinkPacketKind::ResourcePart,
            LinkPacketKind::ResourceProof,
            LinkPacketKind::ChannelData,
            LinkPacketKind::Request,
            LinkPacketKind::Response,
            LinkPacketKind::Keepalive,
            LinkPacketKind::DeliveryProof,
            LinkPacketKind::Unknown,
        ];

        for kind in all_kinds {
            // Every kind should have a description
            let desc = describe_handler(kind);
            assert!(!desc.is_empty());

            // If it uses raw data, it must NOT need encryption
            if uses_raw_data(kind) {
                assert!(
                    !needs_link_encryption(kind),
                    "{desc}: raw data and encryption are mutually exclusive"
                );
            }

            // If it needs a proof, it must need encryption
            if needs_delivery_proof(kind) {
                assert!(
                    needs_link_encryption(kind),
                    "{desc}: proof requires encryption"
                );
            }
        }
    }

    // === describe_handler ===

    #[test]
    fn resource_part_description_indicates_raw() {
        let desc = describe_handler(LinkPacketKind::ResourcePart);
        assert!(desc.contains("raw") || desc.contains("unencrypted"));
    }

    #[test]
    fn channel_description_indicates_proof() {
        let desc = describe_handler(LinkPacketKind::ChannelData);
        assert!(desc.contains("proof"));
    }

    // === Keepalive rules ===

    #[test]
    fn keepalive_not_encrypted() {
        assert!(!needs_link_encryption(LinkPacketKind::Keepalive));
    }

    #[test]
    fn keepalive_no_proof() {
        assert!(!needs_delivery_proof(LinkPacketKind::Keepalive));
    }

    #[test]
    fn keepalive_not_raw_data() {
        // Keepalive uses raw passthrough but is not the "raw data" context (Resource)
        assert!(!uses_raw_data(LinkPacketKind::Keepalive));
    }
}
