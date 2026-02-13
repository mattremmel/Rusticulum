//! Test vector types for announces.json
//!
//! Announce protocol test vectors including valid, invalid, app data, and ratchet announces.

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct AnnounceConstants {
    pub mtu_bytes: u64,
    #[serde(default)]
    pub header_minsize_bytes: Option<u64>,
    #[serde(default)]
    pub keysize_bytes: Option<u64>,
    #[serde(default)]
    pub name_hash_length_bytes: Option<u64>,
    #[serde(default)]
    pub signature_length_bytes: Option<u64>,
    pub ratchetsize_bytes: u64,
    pub random_hash_length_bytes: u64,
    pub truncated_hash_length_bytes: u64,
    pub announce_min_payload_bytes: u64,
    #[serde(default)]
    pub max_app_data_no_ratchet_bytes: Option<u64>,
    #[serde(default)]
    pub max_app_data_with_ratchet_bytes: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct ValidAnnounce {
    pub description: String,
    pub keypair_index: u64,
    pub app_name: String,
    pub aspects: Vec<String>,
    pub name_hash: String,
    pub identity_hash: String,
    pub destination_hash: String,
    pub random_hash: String,
    #[serde(default)]
    pub timestamp_embedded: Option<u64>,
    pub public_key: String,
    pub signed_data: String,
    pub signature: String,
    pub announce_payload: String,
    pub announce_payload_length: u64,
    pub context_flag: u64,
    pub flags_byte: String,
    pub hops: u64,
    pub context: String,
    pub raw_packet: String,
    pub raw_packet_length: u64,
    pub packet_hash: String,
}

#[derive(Debug, Deserialize)]
pub struct InvalidAnnounce {
    pub description: String,
    #[serde(default)]
    pub keypair_index: Option<u64>,
    #[serde(default)]
    pub signing_keypair_index: Option<u64>,
    #[serde(default)]
    pub embedded_keypair_index: Option<u64>,
    #[serde(default)]
    pub destination_hash: Option<String>,
    #[serde(default)]
    pub destination_hash_in_header: Option<String>,
    #[serde(default)]
    pub correct_destination_hash: Option<String>,
    #[serde(default)]
    pub tampered_field: Option<String>,
    #[serde(default)]
    pub tampered_byte_offset_in_payload: Option<u64>,
    #[serde(default)]
    pub original_byte: Option<String>,
    #[serde(default)]
    pub tampered_byte: Option<String>,
    #[serde(default)]
    pub correct_name_hash: Option<String>,
    #[serde(default)]
    pub wrong_name_hash: Option<String>,
    #[serde(default)]
    pub context_flag: Option<u64>,
    #[serde(default)]
    pub flags_byte: Option<String>,
    #[serde(default)]
    pub announce_payload_length: Option<u64>,
    #[serde(default)]
    pub minimum_payload_length: Option<u64>,
    #[serde(default)]
    pub payload_parsing_note: Option<serde_json::Value>,
    pub announce_payload: String,
    pub raw_packet: String,
    pub expected_failure: String,
    pub failure_reason: String,
}

#[derive(Debug, Deserialize)]
pub struct AppDataAnnounce {
    pub description: String,
    pub keypair_index: u64,
    pub destination_hash: String,
    pub app_data: String,
    pub app_data_length: u64,
    #[serde(default)]
    pub app_data_utf8: Option<String>,
    #[serde(default)]
    pub app_data_decoded: Option<serde_json::Value>,
    #[serde(default)]
    pub app_data_encoding: Option<String>,
    #[serde(default)]
    pub max_app_data_derivation: Option<String>,
    pub signed_data: String,
    pub signature: String,
    pub announce_payload: String,
    pub announce_payload_length: u64,
    pub raw_packet: String,
    #[serde(default)]
    pub raw_packet_length: Option<u64>,
    pub packet_hash: String,
}

#[derive(Debug, Deserialize)]
pub struct RatchetAnnounce {
    pub description: String,
    pub keypair_index: u64,
    pub destination_hash: String,
    #[serde(default)]
    pub ratchet_private_key: Option<String>,
    pub ratchet_public_key: String,
    #[serde(default)]
    pub app_data: Option<String>,
    #[serde(default)]
    pub app_data_utf8: Option<String>,
    #[serde(default)]
    pub app_data_length: Option<u64>,
    #[serde(default)]
    pub max_app_data_derivation: Option<String>,
    pub context_flag: u64,
    pub flags_byte: String,
    pub signed_data: String,
    pub signature: String,
    pub announce_payload: String,
    pub announce_payload_length: u64,
    #[serde(default)]
    pub payload_layout: Option<serde_json::Value>,
    pub raw_packet: String,
    pub raw_packet_length: u64,
    pub packet_hash: String,
}

#[derive(Debug, Deserialize)]
pub struct AnnouncesVectors {
    pub description: String,
    pub source: String,
    pub constants: AnnounceConstants,
    pub algorithm: serde_json::Value,
    pub valid_announces: Vec<ValidAnnounce>,
    pub invalid_announces: Vec<InvalidAnnounce>,
    pub app_data_announces: Vec<AppDataAnnounce>,
    pub ratchet_announces: Vec<RatchetAnnounce>,
    pub propagation_metadata: serde_json::Value,
    pub rate_limiting: serde_json::Value,
}

pub fn load() -> AnnouncesVectors {
    let json = include_str!("../../../.test-vectors/announces.json");
    serde_json::from_str(json).expect("Failed to deserialize announces.json")
}
