//! Pure helper functions for common packet operations.
//!
//! These functions extract repeated patterns from the node event loop
//! into testable, stateless utilities.

use reticulum_core::packet::wire::RawPacket;
use reticulum_core::types::LinkId;
use reticulum_transport::error::IfacError;
use reticulum_transport::ifac::{IfacConfig, ifac_apply};

/// Extract a [`LinkId`] from a packet's destination field.
///
/// This replaces the repeated 3-line pattern found in 6+ locations:
/// ```ignore
/// let link_id_bytes: [u8; 16] = packet.destination.as_ref().try_into().unwrap_or([0u8; 16]);
/// let link_id = LinkId::new(link_id_bytes);
/// ```
pub fn extract_link_id(packet: &RawPacket) -> LinkId {
    let link_id_bytes: [u8; 16] = packet
        .destination
        .as_ref()
        .try_into()
        .unwrap_or([0u8; 16]);
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

#[cfg(test)]
mod tests {
    use super::*;
    use reticulum_core::constants::{DestinationType, HeaderType, PacketType, TransportType};
    use reticulum_core::packet::context::ContextType;
    use reticulum_core::packet::flags::PacketFlags;
    use reticulum_core::types::DestinationHash;
    use reticulum_transport::ifac::ifac_verify;

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
        let ifac = IfacConfig::new(Some("testnet"), Some("secret"), 8);

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
        let ifac = IfacConfig::new(Some("testnet"), Some("key123"), 8);

        let packet = make_test_packet([0xBB; 16]);
        let raw = packet.serialize();

        let masked = apply_ifac(Some(&ifac), &raw).unwrap();
        let verified = ifac_verify(&ifac, &masked).unwrap();
        assert_eq!(verified, raw);
    }
}
