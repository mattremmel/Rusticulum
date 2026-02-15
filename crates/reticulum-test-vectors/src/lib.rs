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

#[cfg(feature = "helpers")]
pub mod helpers;

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
    fn deserialize_hashes() {
        let v = hashes::load();
        assert!(!v.sha256.is_empty());
        assert!(!v.sha512.is_empty());
        assert!(!v.truncated_hash.is_empty());
    }

    #[test]
    fn deserialize_hkdf() {
        let v = hkdf::load();
        assert!(!v.rfc5869_vectors.is_empty());
    }

    #[test]
    fn deserialize_token() {
        let v = token::load();
        assert!(!v.pkcs7_padding.is_empty());
        assert!(!v.hmac_sha256.is_empty());
        assert!(!v.deterministic_fernet_vectors.is_empty());
    }

    #[test]
    fn deserialize_keypairs() {
        let v = keypairs::load();
        assert!(!v.keypairs.is_empty());
        assert!(!v.signature_vectors.is_empty());
        assert!(!v.ecdh_vectors.is_empty());
    }

    #[test]
    fn deserialize_destination_hashes() {
        let v = destination_hashes::load();
        assert!(!v.single_destinations.is_empty());
        assert!(!v.plain_destinations.is_empty());
    }

    #[test]
    fn deserialize_packet_headers() {
        let v = packet_headers::load();
        assert!(!v.flag_packing_vectors.is_empty());
        assert!(!v.flag_unpacking_vectors.is_empty());
        assert!(!v.exhaustive_flag_vectors.is_empty());
        assert!(!v.header_vectors.is_empty());
    }

    #[test]
    fn deserialize_packets_data() {
        let v = packets_data::load();
        assert!(!v.data_packet_vectors.is_empty());
        assert!(!v.proof_generation_vectors.is_empty());
        assert!(!v.proof_validation_vectors.is_empty());
    }

    #[test]
    fn deserialize_announces() {
        let v = announces::load();
        assert!(!v.valid_announces.is_empty());
        assert!(!v.invalid_announces.is_empty());
        assert!(!v.app_data_announces.is_empty());
        assert!(!v.ratchet_announces.is_empty());
    }

    #[test]
    fn deserialize_interface_framing() {
        let v = interface_framing::load();
        assert!(!v.hdlc.vectors.is_empty());
        assert!(!v.kiss.vectors.is_empty());
        assert!(!v.ifac.vectors.is_empty());
        assert!(!v.full_pipeline.vectors.is_empty());
    }

    #[test]
    fn deserialize_links() {
        let v = links::load();
        assert!(!v.ephemeral_keys.is_empty());
        assert!(!v.signalling_bytes_vectors.is_empty());
        assert!(!v.link_id_vectors.is_empty());
        assert!(!v.handshake_vectors.is_empty());
    }

    #[test]
    fn deserialize_channels() {
        let v = channels::load();
        assert!(!v.envelope_vectors.is_empty());
        assert!(!v.stream_data_vectors.is_empty());
    }

    #[test]
    fn deserialize_resources() {
        let v = resources::load();
        assert!(!v.metadata_vectors.is_empty());
        assert!(!v.resource_advertisement_vectors.is_empty());
        assert!(!v.assembly_vectors.is_empty());
        assert!(!v.resource_proof_vectors.is_empty());
    }

    #[test]
    fn deserialize_resource_transfers() {
        let v = resource_transfers::load();
        assert!(!v.transfer_sequence_vectors.is_empty());
        assert!(!v.cancellation_vectors.is_empty());
    }

    #[test]
    fn deserialize_buffer_transfers() {
        let v = buffer_transfers::load();
        assert!(!v.small_transfer_vectors.is_empty());
        assert!(!v.large_transfer_vectors.is_empty());
        assert!(!v.compression_vectors.is_empty());
        assert!(!v.eof_vectors.is_empty());
    }

    #[test]
    fn deserialize_requests() {
        let v = requests::load();
        assert!(!v.path_hash_vectors.is_empty());
        assert!(!v.request_serialization_vectors.is_empty());
        assert!(!v.response_serialization_vectors.is_empty());
    }

    #[test]
    fn deserialize_retry_timers() {
        let v = retry_timers::load();
        assert!(!v.link_keepalive.vectors.is_empty());
        assert!(!v.link_establishment.vectors.is_empty());
        assert!(!v.resource_retry.vectors.is_empty());
    }

    #[test]
    fn deserialize_window_adaptation() {
        let v = window_adaptation::load();
        assert!(!v.resource_window.growth_vectors.is_empty());
        assert!(!v.resource_window.shrink_vectors.is_empty());
        assert!(!v.channel_window.key_differences.is_empty());
    }

    #[test]
    fn deserialize_path_requests() {
        let v = path_requests::load();
        assert!(!v.path_request_destination_vectors.is_empty());
        assert!(!v.path_request_packet_vectors.is_empty());
        assert!(!v.path_request_parsing_vectors.is_empty());
    }

    #[test]
    fn deserialize_path_expiration() {
        let v = path_expiration::load();
        assert!(!v.ttl_enforcement_vectors.is_empty());
        assert!(!v.expire_path_vectors.is_empty());
    }

    #[test]
    fn deserialize_multi_hop_routing() {
        let v = multi_hop_routing::load();
        assert!(!v.header_transformation_vectors.is_empty());
        assert!(!v.announce_propagation_vectors.is_empty());
        assert!(!v.link_request_forwarding_vectors.is_empty());
    }
}
