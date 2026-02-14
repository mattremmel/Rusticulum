//! Pure link packet kind classification.
//!
//! Extracts the 11-arm match on `(packet_type, context, dest_type)` from
//! `handle_link_packet` into a pure function. This documents all 13 link
//! packet kinds in a single enum and ensures exhaustive matching.

use reticulum_core::constants::{DestinationType, PacketType};
use reticulum_core::packet::context::ContextType;

/// The kind of link-layer packet, classified from header fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkPacketKind {
    /// Incoming link establishment request (we are responder).
    LinkRequest,
    /// Link proof from responder (we are initiator).
    LinkProof,
    /// RTT measurement (we are responder, link now active).
    LinkRtt,
    /// Encrypted data on an active link.
    LinkData,
    /// Resource advertisement from sender.
    ResourceAdvertisement,
    /// Part request from resource receiver.
    ResourceRequest,
    /// Raw resource part data (bypasses link encryption).
    ResourcePart,
    /// Proof from resource receiver confirming assembly.
    ResourceProof,
    /// Channel message (link-encrypted, auto-proved).
    ChannelData,
    /// Request message (link-encrypted, not auto-proved).
    Request,
    /// Response message (link-encrypted, not auto-proved).
    Response,
    /// Packet delivery proof.
    DeliveryProof,
    /// Unrecognized combination of packet type / context / dest type.
    Unknown,
}

/// Classify a packet into a [`LinkPacketKind`] based on its header fields.
///
/// This is the pure classification extracted from `handle_link_packet`.
/// The caller dispatches to the appropriate handler based on the result.
pub fn classify_link_packet(
    packet_type: PacketType,
    context: ContextType,
    destination_type: DestinationType,
) -> LinkPacketKind {
    match (packet_type, context, destination_type) {
        (PacketType::LinkRequest, ContextType::None, DestinationType::Single) => {
            LinkPacketKind::LinkRequest
        }
        (PacketType::Proof, ContextType::Lrproof, DestinationType::Link) => {
            LinkPacketKind::LinkProof
        }
        (PacketType::Data, ContextType::Lrrtt, DestinationType::Link) => LinkPacketKind::LinkRtt,
        (PacketType::Data, ContextType::None, DestinationType::Link) => LinkPacketKind::LinkData,
        (PacketType::Data, ContextType::ResourceAdv, DestinationType::Link) => {
            LinkPacketKind::ResourceAdvertisement
        }
        (PacketType::Data, ContextType::ResourceReq, DestinationType::Link) => {
            LinkPacketKind::ResourceRequest
        }
        (PacketType::Data, ContextType::Resource, DestinationType::Link) => {
            LinkPacketKind::ResourcePart
        }
        (PacketType::Data, ContextType::ResourcePrf, DestinationType::Link) => {
            LinkPacketKind::ResourceProof
        }
        (PacketType::Data, ContextType::Channel, DestinationType::Link) => {
            LinkPacketKind::ChannelData
        }
        (PacketType::Data, ContextType::Request, DestinationType::Link) => {
            LinkPacketKind::Request
        }
        (PacketType::Data, ContextType::Response, DestinationType::Link) => {
            LinkPacketKind::Response
        }
        (PacketType::Proof, ContextType::None, DestinationType::Link) => {
            LinkPacketKind::DeliveryProof
        }
        _ => LinkPacketKind::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_request() {
        assert_eq!(
            classify_link_packet(PacketType::LinkRequest, ContextType::None, DestinationType::Single),
            LinkPacketKind::LinkRequest,
        );
    }

    #[test]
    fn link_proof() {
        assert_eq!(
            classify_link_packet(PacketType::Proof, ContextType::Lrproof, DestinationType::Link),
            LinkPacketKind::LinkProof,
        );
    }

    #[test]
    fn link_rtt() {
        assert_eq!(
            classify_link_packet(PacketType::Data, ContextType::Lrrtt, DestinationType::Link),
            LinkPacketKind::LinkRtt,
        );
    }

    #[test]
    fn link_data() {
        assert_eq!(
            classify_link_packet(PacketType::Data, ContextType::None, DestinationType::Link),
            LinkPacketKind::LinkData,
        );
    }

    #[test]
    fn resource_advertisement() {
        assert_eq!(
            classify_link_packet(PacketType::Data, ContextType::ResourceAdv, DestinationType::Link),
            LinkPacketKind::ResourceAdvertisement,
        );
    }

    #[test]
    fn resource_request() {
        assert_eq!(
            classify_link_packet(PacketType::Data, ContextType::ResourceReq, DestinationType::Link),
            LinkPacketKind::ResourceRequest,
        );
    }

    #[test]
    fn resource_part() {
        assert_eq!(
            classify_link_packet(PacketType::Data, ContextType::Resource, DestinationType::Link),
            LinkPacketKind::ResourcePart,
        );
    }

    #[test]
    fn resource_proof() {
        assert_eq!(
            classify_link_packet(PacketType::Data, ContextType::ResourcePrf, DestinationType::Link),
            LinkPacketKind::ResourceProof,
        );
    }

    #[test]
    fn channel_data() {
        assert_eq!(
            classify_link_packet(PacketType::Data, ContextType::Channel, DestinationType::Link),
            LinkPacketKind::ChannelData,
        );
    }

    #[test]
    fn request() {
        assert_eq!(
            classify_link_packet(PacketType::Data, ContextType::Request, DestinationType::Link),
            LinkPacketKind::Request,
        );
    }

    #[test]
    fn response() {
        assert_eq!(
            classify_link_packet(PacketType::Data, ContextType::Response, DestinationType::Link),
            LinkPacketKind::Response,
        );
    }

    #[test]
    fn delivery_proof() {
        assert_eq!(
            classify_link_packet(PacketType::Proof, ContextType::None, DestinationType::Link),
            LinkPacketKind::DeliveryProof,
        );
    }

    #[test]
    fn unknown_combination() {
        // Data with Channel context but Single destination type
        assert_eq!(
            classify_link_packet(PacketType::Data, ContextType::Channel, DestinationType::Single),
            LinkPacketKind::Unknown,
        );
    }

    #[test]
    fn non_link_destination_returns_unknown() {
        // Proof with Lrproof context but on Single destination
        assert_eq!(
            classify_link_packet(PacketType::Proof, ContextType::Lrproof, DestinationType::Single),
            LinkPacketKind::Unknown,
        );
        // Data with ResourceAdv context but on Plain destination
        assert_eq!(
            classify_link_packet(PacketType::Data, ContextType::ResourceAdv, DestinationType::Plain),
            LinkPacketKind::Unknown,
        );
    }
}
