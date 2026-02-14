//! Pure announce identity extraction logic.
//!
//! Wraps the decision "given a successful announce validation result,
//! should we parse the announce and register the identity?" into a
//! pure function, separating the parsing from the I/O of registration.

use reticulum_core::announce::Announce;
use reticulum_core::constants::PacketType;
use reticulum_core::packet::wire::RawPacket;
use reticulum_core::types::DestinationHash;
use reticulum_transport::error::RouterError;
use reticulum_transport::router::dispatch::AnnounceResult;

/// Decision from announce processing.
#[derive(Debug)]
pub enum AnnounceDecision {
    /// Announce validated — register the identity with the provided data.
    RegisterIdentity {
        destination_hash: DestinationHash,
        announce: Box<Announce>,
    },
    /// Announce validated but payload parsing failed.
    ParseFailed,
    /// Announce validation itself failed.
    ValidationFailed,
    /// The packet is not an announce.
    NotAnAnnounce,
}

/// Decide what action to take after announce validation.
///
/// This is the pure decision extracted from `handle_inbound_packet` lines 720-763.
/// On success, returns the parsed announce and destination hash for identity
/// registration. The caller performs the actual registration I/O.
pub fn decide_announce_action(
    packet: &RawPacket,
    announce_result: &Result<AnnounceResult, RouterError>,
) -> AnnounceDecision {
    if packet.flags.packet_type != PacketType::Announce {
        return AnnounceDecision::NotAnAnnounce;
    }

    match announce_result {
        Ok(result) => {
            match Announce::from_payload(
                packet.destination,
                packet.flags.context_flag,
                packet.context,
                &packet.data,
            ) {
                Ok(announce) => AnnounceDecision::RegisterIdentity {
                    destination_hash: result.destination_hash,
                    announce: Box::new(announce),
                },
                Err(_) => AnnounceDecision::ParseFailed,
            }
        }
        Err(_) => AnnounceDecision::ValidationFailed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reticulum_core::announce::make_random_hash;
    use reticulum_core::constants::{DestinationType, HeaderType, PacketType, TransportType};
    use reticulum_core::destination;
    use reticulum_core::identity::Identity;
    use reticulum_core::packet::context::ContextType;
    use reticulum_core::packet::flags::PacketFlags;
    use reticulum_core::types::DestinationHash;

    /// Build a valid announce packet for testing.
    fn make_announce_packet() -> (RawPacket, AnnounceResult) {
        let identity = Identity::generate();
        let aspects: Vec<&str> = vec!["test"];
        let nh = destination::name_hash("testapp", &aspects);
        let dh = destination::destination_hash(&nh, identity.hash());
        let random_hash = make_random_hash();

        let announce = Announce::create(&identity, nh, dh, random_hash, None, Some(b"hello"))
            .expect("create announce");
        let raw_pkt = announce.to_raw_packet(0);

        let result = AnnounceResult {
            destination_hash: dh,
            hops: 0,
            app_data: Some(b"hello".to_vec()),
            path_updated: true,
            queued: false,
        };

        (raw_pkt, result)
    }

    fn make_non_announce_packet() -> RawPacket {
        RawPacket {
            flags: PacketFlags {
                header_type: HeaderType::Header1,
                context_flag: false,
                transport_type: TransportType::Broadcast,
                destination_type: DestinationType::Single,
                packet_type: PacketType::Data,
            },
            hops: 0,
            transport_id: None,
            destination: DestinationHash::new([0xAA; 16]),
            context: ContextType::None,
            data: b"not an announce".to_vec(),
        }
    }

    #[test]
    fn validated_announce_registers_identity() {
        let (packet, result) = make_announce_packet();
        match decide_announce_action(&packet, &Ok(result)) {
            AnnounceDecision::RegisterIdentity {
                destination_hash,
                announce,
            } => {
                assert_eq!(destination_hash.as_ref().len(), 16);
                assert!(!announce.public_key.is_empty());
            }
            other => panic!("expected RegisterIdentity, got {other:?}"),
        }
    }

    #[test]
    fn validation_failed_returns_failure() {
        let (packet, _) = make_announce_packet();
        let err = Err(RouterError::DuplicatePacket);
        match decide_announce_action(&packet, &err) {
            AnnounceDecision::ValidationFailed => {}
            other => panic!("expected ValidationFailed, got {other:?}"),
        }
    }

    #[test]
    fn non_announce_packet_returns_not_announce() {
        let packet = make_non_announce_packet();
        let result = Ok(AnnounceResult {
            destination_hash: DestinationHash::new([0xAA; 16]),
            hops: 0,
            app_data: None,
            path_updated: false,
            queued: false,
        });
        match decide_announce_action(&packet, &result) {
            AnnounceDecision::NotAnAnnounce => {}
            other => panic!("expected NotAnAnnounce, got {other:?}"),
        }
    }

    #[test]
    fn preserves_destination_hash() {
        let (packet, result) = make_announce_packet();
        let expected_dh = result.destination_hash;
        match decide_announce_action(&packet, &Ok(result)) {
            AnnounceDecision::RegisterIdentity {
                destination_hash, ..
            } => {
                assert_eq!(destination_hash, expected_dh);
            }
            other => panic!("expected RegisterIdentity, got {other:?}"),
        }
    }

    #[test]
    fn announce_with_app_data_preserves_it() {
        let (packet, result) = make_announce_packet();
        match decide_announce_action(&packet, &Ok(result)) {
            AnnounceDecision::RegisterIdentity { announce, .. } => {
                assert!(announce.app_data.is_some());
                assert_eq!(announce.app_data.unwrap(), b"hello");
            }
            other => panic!("expected RegisterIdentity, got {other:?}"),
        }
    }

    #[test]
    fn malformed_payload_returns_parse_failed() {
        // Create an announce-type packet but with garbage data
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
            destination: DestinationHash::new([0xBB; 16]),
            context: ContextType::None,
            data: vec![0xFF; 10], // too short to be a valid announce
        };
        let result = Ok(AnnounceResult {
            destination_hash: DestinationHash::new([0xBB; 16]),
            hops: 0,
            app_data: None,
            path_updated: true,
            queued: false,
        });
        match decide_announce_action(&packet, &result) {
            AnnounceDecision::ParseFailed => {}
            other => panic!("expected ParseFailed, got {other:?}"),
        }
    }

    #[test]
    fn announce_without_app_data() {
        let identity = Identity::generate();
        let aspects: Vec<&str> = vec!["nodata"];
        let nh = destination::name_hash("testapp", &aspects);
        let dh = destination::destination_hash(&nh, identity.hash());
        let random_hash = make_random_hash();

        let announce =
            Announce::create(&identity, nh, dh, random_hash, None, None).expect("create announce");
        let packet = announce.to_raw_packet(0);
        let result = AnnounceResult {
            destination_hash: dh,
            hops: 3,
            app_data: None,
            path_updated: false,
            queued: false,
        };
        match decide_announce_action(&packet, &Ok(result)) {
            AnnounceDecision::RegisterIdentity { announce, .. } => {
                assert!(announce.app_data.is_none());
            }
            other => panic!("expected RegisterIdentity, got {other:?}"),
        }
    }
}
