//! Test vector loading infrastructure for Rusticulum.
//!
//! This crate provides serde-deserializable structs for all test vector JSON files
//! used to validate the Reticulum protocol implementation.
//!
//! Each module corresponds to a single JSON test vector file and provides:
//! - Typed structs matching the JSON schema
//! - A `load()` function that deserializes the embedded JSON via `include_str!`
//!
//! # Usage
//!
//! ```rust
//! let vectors = reticulum_test_vectors::hashes::load();
//! for v in &vectors.sha256 {
//!     let input_bytes = hex::decode(&v.input).unwrap();
//!     // ... test SHA-256 against v.digest
//! }
//! ```

pub mod announces;
pub mod buffer_transfers;
pub mod channels;
pub mod destination_hashes;
pub mod hashes;
pub mod hkdf;
pub mod interface_framing;
pub mod keypairs;
pub mod links;
pub mod multi_hop_routing;
pub mod packet_headers;
pub mod packets_data;
pub mod path_expiration;
pub mod path_requests;
pub mod requests;
pub mod resource_transfers;
pub mod resources;
pub mod retry_timers;
pub mod token;
pub mod window_adaptation;

// Re-export top-level vector types for convenience
pub use announces::AnnouncesVectors;
pub use buffer_transfers::BufferTransfersVectors;
pub use channels::ChannelsVectors;
pub use destination_hashes::DestinationHashesVectors;
pub use hashes::HashesVectors;
pub use hkdf::HkdfVectors;
pub use interface_framing::InterfaceFramingVectors;
pub use keypairs::KeypairsVectors;
pub use links::LinksVectors;
pub use multi_hop_routing::MultiHopRoutingVectors;
pub use packet_headers::PacketHeadersVectors;
pub use packets_data::PacketsDataVectors;
pub use path_expiration::PathExpirationVectors;
pub use path_requests::PathRequestsVectors;
pub use requests::RequestsVectors;
pub use resource_transfers::ResourceTransfersVectors;
pub use resources::ResourcesVectors;
pub use retry_timers::RetryTimersVectors;
pub use token::TokenVectors;
pub use window_adaptation::WindowAdaptationVectors;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_test_vectors_deserialize_successfully() {
        // Each load() call will panic with a descriptive message if deserialization fails.

        let h = hashes::load();
        assert!(
            !h.sha256.is_empty(),
            "hashes: sha256 vectors should not be empty"
        );
        assert!(
            !h.sha512.is_empty(),
            "hashes: sha512 vectors should not be empty"
        );
        assert!(
            !h.truncated_hash.is_empty(),
            "hashes: truncated_hash vectors should not be empty"
        );

        let hk = hkdf::load();
        assert!(
            !hk.rfc5869_vectors.is_empty(),
            "hkdf: rfc5869_vectors should not be empty"
        );

        let t = token::load();
        assert!(
            !t.pkcs7_padding.is_empty(),
            "token: pkcs7_padding should not be empty"
        );
        assert!(
            !t.hmac_sha256.is_empty(),
            "token: hmac_sha256 should not be empty"
        );
        assert!(
            !t.deterministic_fernet_vectors.is_empty(),
            "token: deterministic_fernet_vectors should not be empty"
        );

        let kp = keypairs::load();
        assert!(
            !kp.keypairs.is_empty(),
            "keypairs: keypairs should not be empty"
        );
        assert!(
            !kp.signature_vectors.is_empty(),
            "keypairs: signature_vectors should not be empty"
        );
        assert!(
            !kp.ecdh_vectors.is_empty(),
            "keypairs: ecdh_vectors should not be empty"
        );

        let dh = destination_hashes::load();
        assert!(
            !dh.single_destinations.is_empty(),
            "destination_hashes: single_destinations should not be empty"
        );
        assert!(
            !dh.plain_destinations.is_empty(),
            "destination_hashes: plain_destinations should not be empty"
        );

        let ph = packet_headers::load();
        assert!(
            !ph.flag_packing_vectors.is_empty(),
            "packet_headers: flag_packing_vectors should not be empty"
        );
        assert!(
            !ph.flag_unpacking_vectors.is_empty(),
            "packet_headers: flag_unpacking_vectors should not be empty"
        );
        assert!(
            !ph.exhaustive_flag_vectors.is_empty(),
            "packet_headers: exhaustive_flag_vectors should not be empty"
        );
        assert!(
            !ph.header_vectors.is_empty(),
            "packet_headers: header_vectors should not be empty"
        );

        let pd = packets_data::load();
        assert!(
            !pd.data_packet_vectors.is_empty(),
            "packets_data: data_packet_vectors should not be empty"
        );
        assert!(
            !pd.proof_generation_vectors.is_empty(),
            "packets_data: proof_generation_vectors should not be empty"
        );
        assert!(
            !pd.proof_validation_vectors.is_empty(),
            "packets_data: proof_validation_vectors should not be empty"
        );

        let ann = announces::load();
        assert!(
            !ann.valid_announces.is_empty(),
            "announces: valid_announces should not be empty"
        );
        assert!(
            !ann.invalid_announces.is_empty(),
            "announces: invalid_announces should not be empty"
        );
        assert!(
            !ann.app_data_announces.is_empty(),
            "announces: app_data_announces should not be empty"
        );
        assert!(
            !ann.ratchet_announces.is_empty(),
            "announces: ratchet_announces should not be empty"
        );

        let ifr = interface_framing::load();
        assert!(
            !ifr.hdlc.vectors.is_empty(),
            "interface_framing: hdlc vectors should not be empty"
        );
        assert!(
            !ifr.kiss.vectors.is_empty(),
            "interface_framing: kiss vectors should not be empty"
        );
        assert!(
            !ifr.ifac.vectors.is_empty(),
            "interface_framing: ifac vectors should not be empty"
        );
        assert!(
            !ifr.full_pipeline.vectors.is_empty(),
            "interface_framing: full_pipeline vectors should not be empty"
        );

        let lnk = links::load();
        assert!(
            !lnk.ephemeral_keys.is_empty(),
            "links: ephemeral_keys should not be empty"
        );
        assert!(
            !lnk.signalling_bytes_vectors.is_empty(),
            "links: signalling_bytes_vectors should not be empty"
        );
        assert!(
            !lnk.link_id_vectors.is_empty(),
            "links: link_id_vectors should not be empty"
        );
        assert!(
            !lnk.handshake_vectors.is_empty(),
            "links: handshake_vectors should not be empty"
        );

        let ch = channels::load();
        assert!(
            !ch.envelope_vectors.is_empty(),
            "channels: envelope_vectors should not be empty"
        );
        assert!(
            !ch.stream_data_vectors.is_empty(),
            "channels: stream_data_vectors should not be empty"
        );

        let res = resources::load();
        assert!(
            !res.metadata_vectors.is_empty(),
            "resources: metadata_vectors should not be empty"
        );
        assert!(
            !res.resource_advertisement_vectors.is_empty(),
            "resources: resource_advertisement_vectors should not be empty"
        );
        assert!(
            !res.assembly_vectors.is_empty(),
            "resources: assembly_vectors should not be empty"
        );
        assert!(
            !res.resource_proof_vectors.is_empty(),
            "resources: resource_proof_vectors should not be empty"
        );

        let rt = resource_transfers::load();
        assert!(
            !rt.transfer_sequence_vectors.is_empty(),
            "resource_transfers: transfer_sequence_vectors should not be empty"
        );
        assert!(
            !rt.cancellation_vectors.is_empty(),
            "resource_transfers: cancellation_vectors should not be empty"
        );

        let bt = buffer_transfers::load();
        assert!(
            !bt.small_transfer_vectors.is_empty(),
            "buffer_transfers: small_transfer_vectors should not be empty"
        );
        assert!(
            !bt.large_transfer_vectors.is_empty(),
            "buffer_transfers: large_transfer_vectors should not be empty"
        );
        assert!(
            !bt.compression_vectors.is_empty(),
            "buffer_transfers: compression_vectors should not be empty"
        );
        assert!(
            !bt.eof_vectors.is_empty(),
            "buffer_transfers: eof_vectors should not be empty"
        );

        let req = requests::load();
        assert!(
            !req.path_hash_vectors.is_empty(),
            "requests: path_hash_vectors should not be empty"
        );
        assert!(
            !req.request_serialization_vectors.is_empty(),
            "requests: request_serialization_vectors should not be empty"
        );
        assert!(
            !req.response_serialization_vectors.is_empty(),
            "requests: response_serialization_vectors should not be empty"
        );

        let rtm = retry_timers::load();
        assert!(
            !rtm.link_keepalive.vectors.is_empty(),
            "retry_timers: link_keepalive vectors should not be empty"
        );
        assert!(
            !rtm.link_establishment.vectors.is_empty(),
            "retry_timers: link_establishment vectors should not be empty"
        );
        assert!(
            !rtm.resource_retry.vectors.is_empty(),
            "retry_timers: resource_retry vectors should not be empty"
        );

        let wa = window_adaptation::load();
        assert!(
            !wa.resource_window.growth_vectors.is_empty(),
            "window_adaptation: resource growth_vectors should not be empty"
        );
        assert!(
            !wa.resource_window.shrink_vectors.is_empty(),
            "window_adaptation: resource shrink_vectors should not be empty"
        );
        assert!(
            !wa.channel_window.key_differences.is_empty(),
            "window_adaptation: channel key_differences should not be empty"
        );

        let pr = path_requests::load();
        assert!(
            !pr.path_request_destination_vectors.is_empty(),
            "path_requests: path_request_destination_vectors should not be empty"
        );
        assert!(
            !pr.path_request_packet_vectors.is_empty(),
            "path_requests: path_request_packet_vectors should not be empty"
        );
        assert!(
            !pr.path_request_parsing_vectors.is_empty(),
            "path_requests: path_request_parsing_vectors should not be empty"
        );

        let pe = path_expiration::load();
        assert!(
            !pe.ttl_enforcement_vectors.is_empty(),
            "path_expiration: ttl_enforcement_vectors should not be empty"
        );
        assert!(
            !pe.expire_path_vectors.is_empty(),
            "path_expiration: expire_path_vectors should not be empty"
        );

        let mhr = multi_hop_routing::load();
        assert!(
            !mhr.header_transformation_vectors.is_empty(),
            "multi_hop_routing: header_transformation_vectors should not be empty"
        );
        assert!(
            !mhr.announce_propagation_vectors.is_empty(),
            "multi_hop_routing: announce_propagation_vectors should not be empty"
        );
        assert!(
            !mhr.link_request_forwarding_vectors.is_empty(),
            "multi_hop_routing: link_request_forwarding_vectors should not be empty"
        );
    }
}
