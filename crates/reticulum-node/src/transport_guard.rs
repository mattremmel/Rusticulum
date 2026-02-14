//! Pure transport relay classification logic.
//!
//! Extracts the HEADER_2 relay guard from the node event loop into a
//! testable pure function. The guard decides whether an inbound packet
//! should be relayed as transport, dropped, or forwarded normally.

use reticulum_core::constants::{HeaderType, PacketType};
use reticulum_core::types::DestinationHash;

/// Decision from the transport guard classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportGuardDecision {
    /// HEADER_2 packet addressed to us — relay it.
    RelayAsTransport,
    /// HEADER_2 packet not addressed to us — drop silently.
    DropForeignTransport,
    /// HEADER_1 or announce — proceed with normal forwarding.
    ProceedWithForwarding,
}

/// Classify an inbound packet for the transport relay guard.
///
/// This is the pure decision extracted from `handle_inbound_packet` lines 769-789.
/// The caller executes the I/O action (relay, drop, or continue forwarding).
pub fn classify_transport_guard(
    enable_transport: bool,
    header_type: HeaderType,
    packet_type: PacketType,
    transport_id: Option<&DestinationHash>,
    our_identity_hash: Option<&[u8]>,
) -> TransportGuardDecision {
    // Only transport nodes inspect HEADER_2 packets
    if !enable_transport {
        return TransportGuardDecision::ProceedWithForwarding;
    }

    // Only HEADER_2 non-announce packets are transport relayed
    if header_type != HeaderType::Header2 {
        return TransportGuardDecision::ProceedWithForwarding;
    }

    // Announces have their own processing path
    if packet_type == PacketType::Announce {
        return TransportGuardDecision::ProceedWithForwarding;
    }

    // HEADER_2 non-announce: check if addressed to us
    match (transport_id, our_identity_hash) {
        (Some(tid), Some(our_hash)) if tid.as_ref() == our_hash => {
            TransportGuardDecision::RelayAsTransport
        }
        _ => TransportGuardDecision::DropForeignTransport,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reticulum_core::constants::HeaderType;

    fn dest_hash(b: u8) -> DestinationHash {
        DestinationHash::new([b; 16])
    }

    #[test]
    fn transport_disabled_proceeds() {
        let result = classify_transport_guard(
            false,
            HeaderType::Header2,
            PacketType::Data,
            Some(&dest_hash(0xAA)),
            Some(&[0xAA; 16]),
        );
        assert_eq!(result, TransportGuardDecision::ProceedWithForwarding);
    }

    #[test]
    fn header1_proceeds() {
        let result = classify_transport_guard(
            true,
            HeaderType::Header1,
            PacketType::Data,
            None,
            Some(&[0xAA; 16]),
        );
        assert_eq!(result, TransportGuardDecision::ProceedWithForwarding);
    }

    #[test]
    fn announce_bypasses_guard() {
        let result = classify_transport_guard(
            true,
            HeaderType::Header2,
            PacketType::Announce,
            Some(&dest_hash(0xAA)),
            Some(&[0xAA; 16]),
        );
        assert_eq!(result, TransportGuardDecision::ProceedWithForwarding);
    }

    #[test]
    fn matching_hash_relays() {
        let tid = dest_hash(0xBB);
        let result = classify_transport_guard(
            true,
            HeaderType::Header2,
            PacketType::Data,
            Some(&tid),
            Some(&[0xBB; 16]),
        );
        assert_eq!(result, TransportGuardDecision::RelayAsTransport);
    }

    #[test]
    fn non_matching_hash_drops() {
        let tid = dest_hash(0xBB);
        let result = classify_transport_guard(
            true,
            HeaderType::Header2,
            PacketType::Data,
            Some(&tid),
            Some(&[0xCC; 16]),
        );
        assert_eq!(result, TransportGuardDecision::DropForeignTransport);
    }

    #[test]
    fn missing_transport_id_drops() {
        let result = classify_transport_guard(
            true,
            HeaderType::Header2,
            PacketType::Data,
            None,
            Some(&[0xAA; 16]),
        );
        assert_eq!(result, TransportGuardDecision::DropForeignTransport);
    }

    #[test]
    fn missing_our_hash_drops() {
        let tid = dest_hash(0xAA);
        let result = classify_transport_guard(
            true,
            HeaderType::Header2,
            PacketType::Data,
            Some(&tid),
            None,
        );
        assert_eq!(result, TransportGuardDecision::DropForeignTransport);
    }

    #[test]
    fn exact_byte_comparison() {
        // Differ by one byte
        let tid = dest_hash(0xAA);
        let mut our = [0xAA; 16];
        our[15] = 0xAB;
        let result = classify_transport_guard(
            true,
            HeaderType::Header2,
            PacketType::Data,
            Some(&tid),
            Some(&our),
        );
        assert_eq!(result, TransportGuardDecision::DropForeignTransport);
    }
}
