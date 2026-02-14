//! Pure functions for building announces from configuration.
//!
//! Extracts the announce construction logic from `Node::start()` into
//! testable pure functions. Randomness (random hashes) is injected by
//! the caller, making all functions deterministic.

use reticulum_core::announce::Announce;
use reticulum_core::destination;
use reticulum_core::identity::Identity;
use reticulum_core::types::{DestinationHash, NameHash};

use crate::config::DestinationEntry;

/// A destination registration to be applied after announce building.
#[derive(Debug, Clone)]
pub struct DestinationRegistration {
    pub dest_hash: DestinationHash,
    pub app_name: String,
    pub aspects: Vec<String>,
}

/// Compute the name hash and destination hash for a destination.
pub fn compute_destination_hashes(
    identity: &Identity,
    app_name: &str,
    aspects: &[String],
) -> (NameHash, DestinationHash) {
    let aspect_refs: Vec<&str> = aspects.iter().map(|s| s.as_str()).collect();
    let nh = destination::name_hash(app_name, &aspect_refs);
    let dh = destination::destination_hash(&nh, identity.hash());
    (nh, dh)
}

/// Build a single announce packet from identity and destination config.
///
/// Returns `(destination_hash, serialized_packet)` on success.
/// The `random_hash` must be provided by the caller (for deterministic testing).
pub fn build_single_announce(
    identity: &Identity,
    app_name: &str,
    aspects: &[String],
    random_hash: [u8; 10],
    app_data: Option<&[u8]>,
) -> Result<(DestinationHash, Vec<u8>), String> {
    let (nh, dh) = compute_destination_hashes(identity, app_name, aspects);

    let announce = Announce::create(identity, nh, dh, random_hash, None, app_data)
        .map_err(|e| format!("{e}"))?;

    let raw = announce.to_raw_packet(0).serialize();
    Ok((dh, raw))
}

/// Result of building all announces from configuration.
pub struct AnnouncesBuild {
    /// Successfully built announce packets: (destination_hash, serialized_bytes).
    pub announces: Vec<(DestinationHash, Vec<u8>)>,
    /// Destinations that should be registered for link acceptance.
    pub registrations: Vec<DestinationRegistration>,
    /// Errors encountered (app_name, error message).
    pub errors: Vec<(String, String)>,
}

/// Build all announces from a list of destination configs.
///
/// `random_hashes` must have one entry per destination. Caller pre-generates
/// randomness so this function remains deterministic.
pub fn build_all_announces(
    identity: &Identity,
    destinations: &[DestinationEntry],
    random_hashes: &[[u8; 10]],
) -> AnnouncesBuild {
    let mut announces = Vec::new();
    let mut registrations = Vec::new();
    let mut errors = Vec::new();

    for (dest_cfg, random_hash) in destinations.iter().zip(random_hashes.iter()) {
        // Collect registration if destination accepts links
        if dest_cfg.accept_links {
            let (_, dh) =
                compute_destination_hashes(identity, &dest_cfg.app_name, &dest_cfg.aspects);
            registrations.push(DestinationRegistration {
                dest_hash: dh,
                app_name: dest_cfg.app_name.clone(),
                aspects: dest_cfg.aspects.clone(),
            });
        }

        let app_data = dest_cfg.app_data.as_deref().map(|s| s.as_bytes());

        match build_single_announce(
            identity,
            &dest_cfg.app_name,
            &dest_cfg.aspects,
            *random_hash,
            app_data,
        ) {
            Ok((dh, raw)) => announces.push((dh, raw)),
            Err(e) => errors.push((dest_cfg.app_name.clone(), e)),
        }
    }

    AnnouncesBuild {
        announces,
        registrations,
        errors,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reticulum_core::packet::wire::RawPacket;

    fn test_identity() -> Identity {
        Identity::generate()
    }

    // ---- compute_destination_hashes ----

    #[test]
    fn compute_destination_hashes_deterministic() {
        let id = test_identity();
        let aspects = vec!["echo".to_string()];
        let (nh1, dh1) = compute_destination_hashes(&id, "testapp", &aspects);
        let (nh2, dh2) = compute_destination_hashes(&id, "testapp", &aspects);
        assert_eq!(nh1, nh2);
        assert_eq!(dh1, dh2);
    }

    #[test]
    fn compute_destination_hashes_different_apps() {
        let id = test_identity();
        let aspects = vec!["echo".to_string()];
        let (_, dh1) = compute_destination_hashes(&id, "app_a", &aspects);
        let (_, dh2) = compute_destination_hashes(&id, "app_b", &aspects);
        assert_ne!(dh1, dh2);
    }

    #[test]
    fn compute_destination_hashes_aspects_affect_hash() {
        let id = test_identity();
        let (_, dh1) = compute_destination_hashes(&id, "myapp", &["one".to_string()].to_vec());
        let (_, dh2) = compute_destination_hashes(&id, "myapp", &["two".to_string()].to_vec());
        assert_ne!(dh1, dh2);
    }

    // ---- build_single_announce ----

    #[test]
    fn build_single_announce_produces_parseable_packet() {
        let id = test_identity();
        let aspects = vec!["echo".to_string()];
        let random_hash = [0xAA; 10];
        let (_, raw) = build_single_announce(&id, "testapp", &aspects, random_hash, None).unwrap();

        let packet = RawPacket::parse(&raw).unwrap();
        assert_eq!(
            packet.flags.packet_type,
            reticulum_core::constants::PacketType::Announce
        );
    }

    #[test]
    fn build_single_announce_with_app_data() {
        let id = test_identity();
        let aspects = vec!["echo".to_string()];
        let random_hash = [0xBB; 10];
        let (_, raw) =
            build_single_announce(&id, "testapp", &aspects, random_hash, Some(b"hello")).unwrap();

        RawPacket::parse(&raw).unwrap(); // verify parseable
        // App data is embedded in the announce payload — packet should be larger
        // than one without app_data
        let (_, raw_no_data) =
            build_single_announce(&id, "testapp", &aspects, random_hash, None).unwrap();
        assert!(raw.len() > raw_no_data.len());
    }

    #[test]
    fn build_single_announce_app_data_absent_when_none() {
        let id = test_identity();
        let aspects = vec!["echo".to_string()];
        let random_hash = [0xCC; 10];
        let (_, raw) = build_single_announce(&id, "testapp", &aspects, random_hash, None).unwrap();

        let packet = RawPacket::parse(&raw).unwrap();
        let announce = Announce::from_payload(
            packet.destination,
            packet.flags.context_flag,
            packet.context,
            &packet.data,
        )
        .unwrap();
        assert!(announce.app_data.is_none());
    }

    #[test]
    fn build_single_announce_is_header1() {
        let id = test_identity();
        let aspects = vec!["echo".to_string()];
        let random_hash = [0xDD; 10];
        let (_, raw) = build_single_announce(&id, "testapp", &aspects, random_hash, None).unwrap();

        let packet = RawPacket::parse(&raw).unwrap();
        assert_eq!(
            packet.flags.header_type,
            reticulum_core::constants::HeaderType::Header1
        );
    }

    // ---- build_all_announces ----

    #[test]
    fn build_all_announces_empty_destinations() {
        let id = test_identity();
        let result = build_all_announces(&id, &[], &[]);
        assert!(result.announces.is_empty());
        assert!(result.registrations.is_empty());
        assert!(result.errors.is_empty());
    }

    #[test]
    fn build_all_announces_collects_registrations() {
        let id = test_identity();
        let destinations = vec![
            DestinationEntry {
                app_name: "app_a".to_string(),
                aspects: vec!["echo".to_string()],
                app_data: None,
                accept_links: true,
            },
            DestinationEntry {
                app_name: "app_b".to_string(),
                aspects: vec!["echo".to_string()],
                app_data: None,
                accept_links: false,
            },
        ];
        let random_hashes = [[0x11; 10], [0x22; 10]];
        let result = build_all_announces(&id, &destinations, &random_hashes);

        assert_eq!(result.announces.len(), 2);
        // Only app_a has accept_links=true
        assert_eq!(result.registrations.len(), 1);
        assert_eq!(result.registrations[0].app_name, "app_a");
        assert!(result.errors.is_empty());
    }

    #[test]
    fn build_all_announces_multiple_valid() {
        let id = test_identity();
        let destinations = vec![
            DestinationEntry {
                app_name: "svc1".to_string(),
                aspects: vec!["a".to_string()],
                app_data: Some("data1".to_string()),
                accept_links: true,
            },
            DestinationEntry {
                app_name: "svc2".to_string(),
                aspects: vec!["b".to_string()],
                app_data: None,
                accept_links: true,
            },
        ];
        let random_hashes = [[0xAA; 10], [0xBB; 10]];
        let result = build_all_announces(&id, &destinations, &random_hashes);

        assert_eq!(result.announces.len(), 2);
        assert_eq!(result.registrations.len(), 2);
        assert!(result.errors.is_empty());

        // Both should produce parseable packets
        for (_, raw) in &result.announces {
            assert!(RawPacket::parse(raw).is_ok());
        }
    }
}
