//! Pure helper functions for common packet operations.
//!
//! These functions extract repeated patterns from the node event loop
//! into testable, stateless utilities.

use reticulum_core::packet::wire::RawPacket;
use reticulum_core::types::LinkId;
use reticulum_transport::error::IfacError;
use reticulum_transport::ifac::{IfacConfig, has_ifac_flag, ifac_apply, ifac_verify};

/// Extract a [`LinkId`] from a packet's destination field.
///
/// This replaces the repeated 3-line pattern found in 6+ locations:
/// ```ignore
/// let link_id_bytes: [u8; 16] = packet.destination.as_ref().try_into().unwrap_or([0u8; 16]);
/// let link_id = LinkId::new(link_id_bytes);
/// ```
pub fn extract_link_id(packet: &RawPacket) -> LinkId {
    let link_id_bytes: [u8; 16] = packet.destination.as_ref().try_into().unwrap_or([0u8; 16]);
    LinkId::new(link_id_bytes)
}

/// Apply IFAC masking to outbound packet bytes if configured.
///
/// When `ifac_config` is `Some`, applies cryptographic masking via [`ifac_apply`].
/// When `None`, returns an unmodified copy of the input bytes.
pub fn apply_ifac(ifac_config: Option<&IfacConfig>, raw: &[u8]) -> Result<Vec<u8>, IfacError> {
    match ifac_config {
        Some(ifac) => ifac_apply(ifac, raw),
        None => Ok(raw.to_vec()),
    }
}

/// Verify IFAC on an inbound packet, handling all 4 cases:
///
/// 1. No IFAC config, no IFAC flag → passthrough (copy raw bytes)
/// 2. No IFAC config, IFAC flag set → reject (unexpected IFAC flag)
/// 3. IFAC config present, no IFAC flag → reject (missing IFAC flag)
/// 4. IFAC config present, IFAC flag set → verify signature
pub fn verify_ifac(config: Option<&IfacConfig>, raw: &[u8]) -> Result<Vec<u8>, IfacError> {
    match config {
        Some(ifac) => {
            if has_ifac_flag(raw) {
                ifac_verify(ifac, raw)
            } else {
                Err(IfacError::MissingFlag)
            }
        }
        None => {
            if has_ifac_flag(raw) {
                Err(IfacError::UnexpectedFlag)
            } else {
                Ok(raw.to_vec())
            }
        }
    }
}

/// Extract a request ID from a raw packet's hashable part.
///
/// Parses the packet, computes the hashable part, and derives the 16-byte
/// request ID. Returns `None` if the packet cannot be parsed.
pub fn extract_request_id(raw: &[u8]) -> Option<[u8; 16]> {
    let pkt = RawPacket::parse(raw).ok()?;
    let hashable = pkt.hashable_part();
    let request_id = reticulum_protocol::request::types::RequestId::from_hashable_part(&hashable);
    let mut id_bytes = [0u8; 16];
    id_bytes.copy_from_slice(request_id.as_ref());
    Some(id_bytes)
}

/// Format a byte slice as a UTF-8 preview string, truncated to `max_len` chars.
///
/// Invalid UTF-8 sequences are replaced with the Unicode replacement character.
pub fn format_data_preview(data: &[u8], max_len: usize) -> String {
    let text = String::from_utf8_lossy(data);
    text[..text.len().min(max_len)].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use reticulum_core::constants::{DestinationType, HeaderType, PacketType, TransportType};
    use reticulum_core::packet::context::ContextType;
    use reticulum_core::packet::flags::PacketFlags;
    use reticulum_core::types::DestinationHash;
    use reticulum_transport::ifac::{IfacCredentials, ifac_verify};

    use crate::link_packets::dest_hash_to_link_id;

    fn make_test_packet(dest_bytes: [u8; 16]) -> RawPacket {
        RawPacket {
            flags: PacketFlags {
                header_type: HeaderType::Header1,
                context_flag: false,
                transport_type: TransportType::Broadcast,
                destination_type: DestinationType::Link,
                packet_type: PacketType::Data,
            },
            hops: 0,
            transport_id: None,
            destination: DestinationHash::new(dest_bytes),
            context: ContextType::None,
            data: b"test".to_vec(),
        }
    }

    // -- extract_link_id tests -----------------------------------------------

    #[test]
    fn extract_link_id_valid_destination() {
        let packet = make_test_packet([0xAB; 16]);
        let link_id = extract_link_id(&packet);
        assert_eq!(link_id.as_ref(), &[0xAB; 16]);
    }

    #[test]
    fn extract_link_id_zero_destination() {
        let packet = make_test_packet([0x00; 16]);
        let link_id = extract_link_id(&packet);
        assert_eq!(link_id.as_ref(), &[0x00; 16]);
    }

    #[test]
    fn extract_link_id_roundtrip_with_dest_hash_to_link_id() {
        let dest_hash = DestinationHash::new([0xCD; 16]);
        let expected = dest_hash_to_link_id(&dest_hash);

        let packet = make_test_packet([0xCD; 16]);
        let extracted = extract_link_id(&packet);
        assert_eq!(extracted.as_ref(), expected.as_ref());
    }

    #[test]
    fn extract_link_id_distinct_values() {
        let pkt_a = make_test_packet([0x11; 16]);
        let pkt_b = make_test_packet([0x22; 16]);
        let a = extract_link_id(&pkt_a);
        let b = extract_link_id(&pkt_b);
        assert_ne!(a.as_ref(), b.as_ref());
    }

    // -- apply_ifac tests ----------------------------------------------------

    #[test]
    fn apply_ifac_no_config_passthrough() {
        let raw = b"hello world packet bytes";
        let result = apply_ifac(None, raw).unwrap();
        assert_eq!(result, raw);
    }

    #[test]
    fn apply_ifac_no_config_empty_input() {
        let result = apply_ifac(None, &[]).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn apply_ifac_with_config_modifies_output() {
        let ifac = IfacConfig::new(IfacCredentials::NameAndKey { name: "testnet", key: "secret" }, 8);

        // Build a minimal valid packet (at least 3 bytes: header + hops + data)
        let packet = make_test_packet([0xAA; 16]);
        let raw = packet.serialize();

        let result = apply_ifac(Some(&ifac), &raw).unwrap();
        // IFAC-masked output should differ from the input
        assert_ne!(result, raw);
        // IFAC adds ifac_size bytes, so output is longer
        assert_eq!(result.len(), raw.len() + 8);
    }

    #[test]
    fn apply_ifac_roundtrip_with_verify() {
        let ifac = IfacConfig::new(IfacCredentials::NameAndKey { name: "testnet", key: "key123" }, 8);

        let packet = make_test_packet([0xBB; 16]);
        let raw = packet.serialize();

        let masked = apply_ifac(Some(&ifac), &raw).unwrap();
        let verified = ifac_verify(&ifac, &masked).unwrap();
        assert_eq!(verified, raw);
    }

    // -- verify_ifac tests ---------------------------------------------------

    #[test]
    fn verify_ifac_no_config() {
        let raw = b"some packet bytes";
        let result = verify_ifac(None, raw).unwrap();
        assert_eq!(result, raw);
    }

    #[test]
    fn verify_ifac_config_no_flag_rejected() {
        let ifac = IfacConfig::new(IfacCredentials::NameAndKey { name: "testnet", key: "key" }, 8);
        // Packet without IFAC flag (bit 7 clear) should be rejected when IFAC is configured
        let packet = make_test_packet([0xAA; 16]);
        let raw = packet.serialize();
        assert!(raw[0] & 0x80 == 0, "test packet should not have IFAC flag");

        let result = verify_ifac(Some(&ifac), &raw);
        assert!(
            result.is_err(),
            "non-IFAC packet should be rejected when IFAC is configured"
        );
    }

    #[test]
    fn verify_ifac_no_config_with_flag_rejected() {
        // Packet with IFAC flag should be rejected when no IFAC is configured
        let packet = make_test_packet([0xAA; 16]);
        let mut raw = packet.serialize();
        raw[0] |= 0x80; // Set IFAC flag

        let result = verify_ifac(None, &raw);
        assert!(
            result.is_err(),
            "IFAC-flagged packet should be rejected when no IFAC is configured"
        );
    }

    #[test]
    fn verify_ifac_config_flag_ok() {
        let ifac = IfacConfig::new(IfacCredentials::NameAndKey { name: "testnet", key: "key" }, 8);
        let packet = make_test_packet([0xBB; 16]);
        let raw = packet.serialize();

        // Apply IFAC to set the flag + mask
        let masked = apply_ifac(Some(&ifac), &raw).unwrap();
        assert!(masked[0] & 0x80 != 0, "masked packet should have IFAC flag");

        // Verify should recover the original
        let result = verify_ifac(Some(&ifac), &masked).unwrap();
        assert_eq!(result, raw);
    }

    #[test]
    fn verify_ifac_config_flag_fail() {
        let ifac = IfacConfig::new(IfacCredentials::NameAndKey { name: "testnet", key: "key" }, 8);
        let packet = make_test_packet([0xCC; 16]);
        let raw = packet.serialize();

        // Apply IFAC then corrupt the masked bytes
        let mut masked = apply_ifac(Some(&ifac), &raw).unwrap();
        // Corrupt a byte in the IFAC region (bytes 2..10 are the IFAC signature)
        if masked.len() > 5 {
            masked[5] ^= 0xFF;
        }

        let result = verify_ifac(Some(&ifac), &masked);
        assert!(result.is_err());
    }

    #[test]
    fn verify_ifac_empty_input() {
        // No config, empty input → empty output
        let result = verify_ifac(None, &[]).unwrap();
        assert!(result.is_empty());
    }

    // -- extract_request_id tests --------------------------------------------

    #[test]
    fn extract_request_id_valid_packet() {
        let packet = make_test_packet([0xDD; 16]);
        let raw = packet.serialize();
        let id = extract_request_id(&raw);
        assert!(id.is_some());
        assert_eq!(id.unwrap().len(), 16);
    }

    #[test]
    fn extract_request_id_malformed_input() {
        let result = extract_request_id(&[0x01, 0x02]);
        assert!(result.is_none());
    }

    #[test]
    fn extract_request_id_empty_input() {
        let result = extract_request_id(&[]);
        assert!(result.is_none());
    }

    #[test]
    fn extract_request_id_deterministic() {
        let packet = make_test_packet([0xEE; 16]);
        let raw = packet.serialize();
        let id1 = extract_request_id(&raw).unwrap();
        let id2 = extract_request_id(&raw).unwrap();
        assert_eq!(id1, id2);
    }

    // -- format_data_preview tests -------------------------------------------

    #[test]
    fn format_data_preview_under_limit() {
        let data = b"hello";
        let result = format_data_preview(data, 200);
        assert_eq!(result, "hello");
    }

    #[test]
    fn format_data_preview_over_limit() {
        let data = b"hello world, this is a long message";
        let result = format_data_preview(data, 10);
        assert_eq!(result, "hello worl");
    }

    #[test]
    fn format_data_preview_empty() {
        let result = format_data_preview(&[], 200);
        assert_eq!(result, "");
    }

    #[test]
    fn format_data_preview_invalid_utf8() {
        let data = &[0xFF, 0xFE, 0x41, 0x42]; // invalid UTF-8 + "AB"
        let result = format_data_preview(data, 200);
        assert!(result.contains("AB"));
        assert!(result.contains('\u{FFFD}')); // replacement character
    }

    #[test]
    fn format_data_preview_exact_boundary() {
        let data = b"12345";
        let result = format_data_preview(data, 5);
        assert_eq!(result, "12345");
    }
}
