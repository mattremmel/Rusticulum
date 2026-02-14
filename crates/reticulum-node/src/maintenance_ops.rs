//! Pure maintenance tick logic.
//!
//! Extracts decision-making from the node's periodic maintenance ticks
//! into testable pure functions. Separates the "what to do" from the
//! "when to do it" (timer intervals remain in the async event loop).

use reticulum_core::types::TruncatedHash;
use reticulum_transport::path::types::InterfaceId;

use crate::routing;

/// Whether pending announces should be broadcast.
///
/// Announces are deferred from startup until at least one interface is
/// connected, to avoid sending into the void.
pub fn should_broadcast_pending_announces(
    has_pending: bool,
    has_connected_interface: bool,
) -> bool {
    has_pending && has_connected_interface
}

/// Plan announce retransmission with optional transport header injection.
///
/// Wraps [`routing::prepare_announce_retransmission`] with the
/// "use original if no transform" fallback logic from the event loop.
pub fn plan_announce_retransmission(
    raw: &[u8],
    enable_transport: bool,
    our_hash: Option<&TruncatedHash>,
) -> Vec<u8> {
    match routing::prepare_announce_retransmission(raw, enable_transport, our_hash) {
        Some(out) if out != raw => out,
        _ => raw.to_vec(),
    }
}

/// Collect IDs of connected interfaces for table culling.
pub fn collect_active_interface_ids(interfaces: &[(InterfaceId, bool)]) -> Vec<InterfaceId> {
    interfaces
        .iter()
        .filter(|(_, connected)| *connected)
        .map(|(id, _)| *id)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use reticulum_core::constants::{DestinationType, HeaderType, PacketType, TransportType};
    use reticulum_core::packet::context::ContextType;
    use reticulum_core::packet::flags::PacketFlags;
    use reticulum_core::packet::wire::RawPacket;
    use reticulum_core::types::DestinationHash;

    fn make_announce_raw() -> Vec<u8> {
        let packet = RawPacket {
            flags: PacketFlags {
                header_type: HeaderType::Header1,
                context_flag: false,
                transport_type: TransportType::Broadcast,
                destination_type: DestinationType::Single,
                packet_type: PacketType::Announce,
            },
            hops: 0,
            transport_id: None,
            destination: DestinationHash::new([0x11; 16]),
            context: ContextType::None,
            data: vec![0xAA; 20],
        };
        packet.serialize()
    }

    // === should_broadcast_pending_announces ===

    #[test]
    fn broadcast_when_pending_and_connected() {
        assert!(should_broadcast_pending_announces(true, true));
    }

    #[test]
    fn no_broadcast_without_pending() {
        assert!(!should_broadcast_pending_announces(false, true));
    }

    #[test]
    fn no_broadcast_without_connected_interface() {
        assert!(!should_broadcast_pending_announces(true, false));
    }

    #[test]
    fn no_broadcast_with_neither() {
        assert!(!should_broadcast_pending_announces(false, false));
    }

    // === plan_announce_retransmission ===

    #[test]
    fn retx_non_transport_returns_original() {
        let raw = make_announce_raw();
        let result = plan_announce_retransmission(&raw, false, None);
        assert_eq!(result, raw);
    }

    #[test]
    fn retx_transport_injects_header2() {
        let raw = make_announce_raw();
        let our_hash = TruncatedHash::new([0xBB; 16]);
        let result = plan_announce_retransmission(&raw, true, Some(&our_hash));

        // Should produce HEADER_2 with our hash as transport_id
        let output = RawPacket::parse(&result).unwrap();
        assert_eq!(output.flags.header_type, HeaderType::Header2);
        assert_eq!(output.transport_id.unwrap().as_ref(), &[0xBB; 16]);
    }

    #[test]
    fn retx_transport_without_hash_returns_original() {
        let raw = make_announce_raw();
        let result = plan_announce_retransmission(&raw, true, None);
        assert_eq!(result, raw);
    }

    // === collect_active_interface_ids ===

    #[test]
    fn collect_connected_only() {
        let interfaces = vec![
            (InterfaceId(1), true),
            (InterfaceId(2), false),
            (InterfaceId(3), true),
            (InterfaceId(4), false),
        ];
        let active = collect_active_interface_ids(&interfaces);
        assert_eq!(active, vec![InterfaceId(1), InterfaceId(3)]);
    }

    #[test]
    fn collect_empty() {
        let interfaces: Vec<(InterfaceId, bool)> = vec![];
        let active = collect_active_interface_ids(&interfaces);
        assert!(active.is_empty());
    }

    #[test]
    fn collect_all_disconnected() {
        let interfaces = vec![(InterfaceId(1), false), (InterfaceId(2), false)];
        let active = collect_active_interface_ids(&interfaces);
        assert!(active.is_empty());
    }

    #[test]
    fn collect_all_connected() {
        let interfaces = vec![(InterfaceId(1), true), (InterfaceId(2), true)];
        let active = collect_active_interface_ids(&interfaces);
        assert_eq!(active.len(), 2);
    }
}
