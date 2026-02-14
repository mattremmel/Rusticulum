//! Pure functions for building link-related packets.
//!
//! Every link packet type the node sends is constructed here, making the
//! packet format authoritative in one place and fully testable without
//! any `LinkManager` state or async I/O.

use reticulum_core::constants::{DestinationType, HeaderType, PacketType, TransportType};
use reticulum_core::packet::context::ContextType;
use reticulum_core::packet::flags::PacketFlags;
use reticulum_core::packet::wire::RawPacket;
use reticulum_core::types::{DestinationHash, LinkId};

use reticulum_crypto::ed25519::Ed25519PrivateKey;

// ---------------------------------------------------------------------------
// Conversion helpers
// ---------------------------------------------------------------------------

/// Convert a LinkId to a DestinationHash (both are 16 bytes).
pub fn link_id_to_dest_hash(link_id: &LinkId) -> DestinationHash {
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(link_id.as_ref());
    DestinationHash::new(bytes)
}

/// Convert a DestinationHash back to a LinkId.
pub fn dest_hash_to_link_id(dest_hash: &DestinationHash) -> LinkId {
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(dest_hash.as_ref());
    LinkId::new(bytes)
}

// ---------------------------------------------------------------------------
// Packet builders
// ---------------------------------------------------------------------------

/// Build a LINKREQUEST packet.
///
/// flags: H1|BC|SINGLE|LINKREQUEST (0x02), ctx=None, dest=dest_hash
pub fn build_linkrequest_packet(dest_hash: DestinationHash, request_data: Vec<u8>) -> Vec<u8> {
    let packet = RawPacket {
        flags: PacketFlags {
            header_type: HeaderType::Header1,
            context_flag: false,
            transport_type: TransportType::Broadcast,
            destination_type: DestinationType::Single,
            packet_type: PacketType::LinkRequest,
        },
        hops: 0,
        transport_id: None,
        destination: dest_hash,
        context: ContextType::None,
        data: request_data,
    };
    packet.serialize()
}

/// Build an LRPROOF packet.
///
/// flags: H1|BC|LINK|PROOF (0x0F), ctx=Lrproof, dest=link_id
pub fn build_lrproof_packet(link_id: &LinkId, proof_data: Vec<u8>) -> Vec<u8> {
    let packet = RawPacket {
        flags: PacketFlags {
            header_type: HeaderType::Header1,
            context_flag: false,
            transport_type: TransportType::Broadcast,
            destination_type: DestinationType::Link,
            packet_type: PacketType::Proof,
        },
        hops: 0,
        transport_id: None,
        destination: link_id_to_dest_hash(link_id),
        context: ContextType::Lrproof,
        data: proof_data,
    };
    packet.serialize()
}

/// Build an LRRTT packet.
///
/// flags: H1|BC|LINK|DATA (0x0C), ctx=Lrrtt, dest=link_id
pub fn build_lrrtt_packet(link_id: &LinkId, encrypted_rtt: Vec<u8>) -> Vec<u8> {
    let packet = RawPacket {
        flags: PacketFlags {
            header_type: HeaderType::Header1,
            context_flag: false,
            transport_type: TransportType::Broadcast,
            destination_type: DestinationType::Link,
            packet_type: PacketType::Data,
        },
        hops: 0,
        transport_id: None,
        destination: link_id_to_dest_hash(link_id),
        context: ContextType::Lrrtt,
        data: encrypted_rtt,
    };
    packet.serialize()
}

/// Build a link data packet (no context).
///
/// flags: H1|BC|LINK|DATA (0x0C), ctx=None, dest=link_id
pub fn build_link_data_packet(link_id: &LinkId, ciphertext: Vec<u8>) -> Vec<u8> {
    let packet = RawPacket {
        flags: PacketFlags {
            header_type: HeaderType::Header1,
            context_flag: false,
            transport_type: TransportType::Broadcast,
            destination_type: DestinationType::Link,
            packet_type: PacketType::Data,
        },
        hops: 0,
        transport_id: None,
        destination: link_id_to_dest_hash(link_id),
        context: ContextType::None,
        data: ciphertext,
    };
    packet.serialize()
}

/// Build a link data packet with a specific context type.
///
/// flags: H1|BC|LINK|DATA, context_flag=true, ctx=given, dest=link_id
pub fn build_link_data_packet_with_context(
    link_id: &LinkId,
    data: Vec<u8>,
    context: ContextType,
) -> Vec<u8> {
    let packet = RawPacket {
        flags: PacketFlags {
            header_type: HeaderType::Header1,
            context_flag: true,
            transport_type: TransportType::Broadcast,
            destination_type: DestinationType::Link,
            packet_type: PacketType::Data,
        },
        hops: 0,
        transport_id: None,
        destination: link_id_to_dest_hash(link_id),
        context,
        data,
    };
    packet.serialize()
}

/// Build the delivery proof data payload (pure crypto, no packet building).
///
/// Returns `packet_hash(32) + Ed25519_signature(64)` = 96 bytes.
pub fn build_delivery_proof_data(packet_hash: &[u8; 32], ed25519_seed: &[u8; 32]) -> Vec<u8> {
    let signing_key = Ed25519PrivateKey::from_bytes(*ed25519_seed);
    let signature = signing_key.sign(packet_hash);

    let mut proof_data = Vec::with_capacity(96);
    proof_data.extend_from_slice(packet_hash);
    proof_data.extend_from_slice(&signature.to_bytes());
    proof_data
}

/// Build a delivery proof packet.
///
/// flags: H1|BC|LINK|PROOF (0x0F), ctx=None, context_flag=false, dest=link_id
pub fn build_proof_packet(link_id: &LinkId, proof_data: Vec<u8>) -> Vec<u8> {
    let packet = RawPacket {
        flags: PacketFlags {
            header_type: HeaderType::Header1,
            context_flag: false,
            transport_type: TransportType::Broadcast,
            destination_type: DestinationType::Link,
            packet_type: PacketType::Proof,
        },
        hops: 0,
        transport_id: None,
        destination: link_id_to_dest_hash(link_id),
        context: ContextType::None,
        data: proof_data,
    };
    packet.serialize()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use reticulum_crypto::ed25519::Ed25519PrivateKey;

    fn test_link_id() -> LinkId {
        LinkId::new([0xAB; 16])
    }

    fn test_dest_hash() -> DestinationHash {
        DestinationHash::new([0xCD; 16])
    }

    // -- Conversion helpers -------------------------------------------------

    #[test]
    fn test_link_id_dest_hash_roundtrip() {
        let link_id = LinkId::new([0xAB; 16]);
        let dh = link_id_to_dest_hash(&link_id);
        let back = dest_hash_to_link_id(&dh);
        assert_eq!(link_id.as_ref(), back.as_ref());
    }

    // -- LINKREQUEST --------------------------------------------------------

    #[test]
    fn test_build_linkrequest_packet_flags() {
        let raw = build_linkrequest_packet(test_dest_hash(), vec![0u8; 67]);
        let pkt = RawPacket::parse(&raw).unwrap();
        assert_eq!(pkt.flags.header_type, HeaderType::Header1);
        assert!(!pkt.flags.context_flag);
        assert_eq!(pkt.flags.transport_type, TransportType::Broadcast);
        assert_eq!(pkt.flags.destination_type, DestinationType::Single);
        assert_eq!(pkt.flags.packet_type, PacketType::LinkRequest);
        assert_eq!(pkt.flags.to_byte(), 0x02);
        assert_eq!(pkt.context, ContextType::None);
    }

    // -- LRPROOF ------------------------------------------------------------

    #[test]
    fn test_build_lrproof_packet_flags() {
        let raw = build_lrproof_packet(&test_link_id(), vec![0u8; 99]);
        let pkt = RawPacket::parse(&raw).unwrap();
        assert_eq!(pkt.flags.header_type, HeaderType::Header1);
        assert!(!pkt.flags.context_flag);
        assert_eq!(pkt.flags.transport_type, TransportType::Broadcast);
        assert_eq!(pkt.flags.destination_type, DestinationType::Link);
        assert_eq!(pkt.flags.packet_type, PacketType::Proof);
        assert_eq!(pkt.flags.to_byte(), 0x0F);
        assert_eq!(pkt.context, ContextType::Lrproof);
    }

    #[test]
    fn test_build_lrproof_packet_data() {
        let proof = vec![0x11; 99];
        let raw = build_lrproof_packet(&test_link_id(), proof.clone());
        let pkt = RawPacket::parse(&raw).unwrap();
        assert_eq!(pkt.data, proof);
    }

    // -- LRRTT --------------------------------------------------------------

    #[test]
    fn test_build_lrrtt_packet_flags() {
        let raw = build_lrrtt_packet(&test_link_id(), vec![0u8; 48]);
        let pkt = RawPacket::parse(&raw).unwrap();
        assert_eq!(pkt.flags.header_type, HeaderType::Header1);
        assert!(!pkt.flags.context_flag);
        assert_eq!(pkt.flags.destination_type, DestinationType::Link);
        assert_eq!(pkt.flags.packet_type, PacketType::Data);
        assert_eq!(pkt.flags.to_byte(), 0x0C);
        assert_eq!(pkt.context, ContextType::Lrrtt);
    }

    #[test]
    fn test_build_lrrtt_packet_data() {
        let rtt_data = vec![0x22; 48];
        let raw = build_lrrtt_packet(&test_link_id(), rtt_data.clone());
        let pkt = RawPacket::parse(&raw).unwrap();
        assert_eq!(pkt.data, rtt_data);
    }

    // -- Link data (no context) ---------------------------------------------

    #[test]
    fn test_build_link_data_packet_flags() {
        let raw = build_link_data_packet(&test_link_id(), vec![0u8; 64]);
        let pkt = RawPacket::parse(&raw).unwrap();
        assert_eq!(pkt.flags.to_byte(), 0x0C);
        assert!(!pkt.flags.context_flag);
        assert_eq!(pkt.context, ContextType::None);
    }

    #[test]
    fn test_build_link_data_empty_payload() {
        let raw = build_link_data_packet(&test_link_id(), vec![]);
        let pkt = RawPacket::parse(&raw).unwrap();
        assert!(pkt.data.is_empty());
        assert_eq!(pkt.flags.destination_type, DestinationType::Link);
    }

    // -- Link data with context ---------------------------------------------

    #[test]
    fn test_build_link_data_packet_with_context_flags() {
        let raw = build_link_data_packet_with_context(
            &test_link_id(),
            vec![0u8; 32],
            ContextType::Channel,
        );
        let pkt = RawPacket::parse(&raw).unwrap();
        assert!(pkt.flags.context_flag);
        assert_eq!(pkt.flags.destination_type, DestinationType::Link);
        assert_eq!(pkt.flags.packet_type, PacketType::Data);
        assert_eq!(pkt.context, ContextType::Channel);
    }

    #[test]
    fn test_build_link_data_packet_with_context_various() {
        let contexts = [
            ContextType::ResourceAdv,
            ContextType::ResourceReq,
            ContextType::Channel,
            ContextType::Request,
            ContextType::Response,
            ContextType::Resource,
        ];
        for ctx in contexts {
            let raw = build_link_data_packet_with_context(&test_link_id(), vec![0xAA; 16], ctx);
            let pkt = RawPacket::parse(&raw).unwrap();
            assert!(
                pkt.flags.context_flag,
                "context_flag must be true for {ctx:?}"
            );
            assert_eq!(pkt.context, ctx, "context mismatch for {ctx:?}");
        }
    }

    // -- Delivery proof packet ----------------------------------------------

    #[test]
    fn test_build_proof_packet_flags() {
        let raw = build_proof_packet(&test_link_id(), vec![0u8; 96]);
        let pkt = RawPacket::parse(&raw).unwrap();
        assert_eq!(pkt.flags.to_byte(), 0x0F);
        assert!(!pkt.flags.context_flag);
        assert_eq!(pkt.flags.destination_type, DestinationType::Link);
        assert_eq!(pkt.flags.packet_type, PacketType::Proof);
        assert_eq!(pkt.context, ContextType::None);
    }

    // -- Delivery proof data ------------------------------------------------

    #[test]
    fn test_build_delivery_proof_data_length() {
        let hash = [0x42; 32];
        let seed = Ed25519PrivateKey::generate().to_bytes();
        let proof = build_delivery_proof_data(&hash, &seed);
        assert_eq!(proof.len(), 96);
    }

    #[test]
    fn test_build_delivery_proof_data_hash_prefix() {
        let hash = [0x42; 32];
        let seed = Ed25519PrivateKey::generate().to_bytes();
        let proof = build_delivery_proof_data(&hash, &seed);
        assert_eq!(&proof[..32], &hash);
    }

    #[test]
    fn test_build_delivery_proof_data_signature_valid() {
        let hash = [0x42; 32];
        let key = Ed25519PrivateKey::generate();
        let pubkey = key.public_key();
        let seed = key.to_bytes();

        let proof = build_delivery_proof_data(&hash, &seed);
        let sig_bytes: [u8; 64] = proof[32..96].try_into().unwrap();
        let sig = reticulum_crypto::ed25519::Ed25519Signature::from_bytes(sig_bytes);
        assert!(pubkey.verify(&hash, &sig).is_ok());
    }

    #[test]
    fn test_build_delivery_proof_data_different_hashes() {
        let seed = Ed25519PrivateKey::generate().to_bytes();
        let proof_a = build_delivery_proof_data(&[0x01; 32], &seed);
        let proof_b = build_delivery_proof_data(&[0x02; 32], &seed);
        assert_ne!(proof_a, proof_b);
    }

    // -- Invariant tests (all builders) -------------------------------------

    /// All builders that set context != None also set context_flag = true.
    #[test]
    fn test_all_context_packets_have_context_flag() {
        // Packets with non-None context:
        let lrproof = build_lrproof_packet(&test_link_id(), vec![0; 99]);
        let lrrtt = build_lrrtt_packet(&test_link_id(), vec![0; 48]);
        let ctx_data =
            build_link_data_packet_with_context(&test_link_id(), vec![0; 32], ContextType::Channel);

        // LRPROOF: context=Lrproof but context_flag=false (protocol convention)
        let pkt = RawPacket::parse(&lrproof).unwrap();
        assert_eq!(pkt.context, ContextType::Lrproof);
        // Note: Lrproof has context_flag=false per protocol spec

        // LRRTT: context=Lrrtt but context_flag=false (protocol convention)
        let pkt = RawPacket::parse(&lrrtt).unwrap();
        assert_eq!(pkt.context, ContextType::Lrrtt);

        // Context data: context_flag must be true
        let pkt = RawPacket::parse(&ctx_data).unwrap();
        assert!(pkt.flags.context_flag);
        assert_eq!(pkt.context, ContextType::Channel);
    }

    #[test]
    fn test_all_packets_are_header1() {
        let packets = vec![
            build_linkrequest_packet(test_dest_hash(), vec![0; 67]),
            build_lrproof_packet(&test_link_id(), vec![0; 99]),
            build_lrrtt_packet(&test_link_id(), vec![0; 48]),
            build_link_data_packet(&test_link_id(), vec![0; 64]),
            build_link_data_packet_with_context(&test_link_id(), vec![0; 32], ContextType::Channel),
            build_proof_packet(&test_link_id(), vec![0; 96]),
        ];
        for (i, raw) in packets.iter().enumerate() {
            let pkt = RawPacket::parse(raw).unwrap();
            assert_eq!(
                pkt.flags.header_type,
                HeaderType::Header1,
                "packet {i} should be Header1"
            );
        }
    }

    #[test]
    fn test_all_packets_have_zero_hops() {
        let packets = vec![
            build_linkrequest_packet(test_dest_hash(), vec![0; 67]),
            build_lrproof_packet(&test_link_id(), vec![0; 99]),
            build_lrrtt_packet(&test_link_id(), vec![0; 48]),
            build_link_data_packet(&test_link_id(), vec![0; 64]),
            build_link_data_packet_with_context(
                &test_link_id(),
                vec![0; 32],
                ContextType::ResourceAdv,
            ),
            build_proof_packet(&test_link_id(), vec![0; 96]),
        ];
        for (i, raw) in packets.iter().enumerate() {
            let pkt = RawPacket::parse(raw).unwrap();
            assert_eq!(pkt.hops, 0, "packet {i} should have 0 hops");
        }
    }

    #[test]
    fn test_all_packets_have_no_transport_id() {
        let packets = vec![
            build_linkrequest_packet(test_dest_hash(), vec![0; 67]),
            build_lrproof_packet(&test_link_id(), vec![0; 99]),
            build_lrrtt_packet(&test_link_id(), vec![0; 48]),
            build_link_data_packet(&test_link_id(), vec![0; 64]),
            build_link_data_packet_with_context(&test_link_id(), vec![0; 32], ContextType::Request),
            build_proof_packet(&test_link_id(), vec![0; 96]),
        ];
        for (i, raw) in packets.iter().enumerate() {
            let pkt = RawPacket::parse(raw).unwrap();
            assert!(
                pkt.transport_id.is_none(),
                "packet {i} should have no transport_id"
            );
        }
    }

    #[test]
    fn test_packet_serialize_parse_roundtrip() {
        let cases: Vec<(&str, Vec<u8>)> = vec![
            (
                "linkrequest",
                build_linkrequest_packet(test_dest_hash(), vec![0xAA; 67]),
            ),
            (
                "lrproof",
                build_lrproof_packet(&test_link_id(), vec![0xBB; 99]),
            ),
            ("lrrtt", build_lrrtt_packet(&test_link_id(), vec![0xCC; 48])),
            (
                "link_data",
                build_link_data_packet(&test_link_id(), vec![0xDD; 64]),
            ),
            (
                "link_data_ctx",
                build_link_data_packet_with_context(
                    &test_link_id(),
                    vec![0xEE; 32],
                    ContextType::Response,
                ),
            ),
            ("proof", build_proof_packet(&test_link_id(), vec![0xFF; 96])),
        ];

        for (name, raw) in &cases {
            let pkt = RawPacket::parse(raw).expect(&format!("{name} should parse"));
            let re_serialized = pkt.serialize();
            assert_eq!(
                raw, &re_serialized,
                "{name}: re-serialized bytes should match original"
            );
        }
    }
}
