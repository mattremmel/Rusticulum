//! Test vector types for path_requests.json
//!
//! Path request/response protocol test vectors including packet construction,
//! parsing, path table entries, duplicate detection, and grace periods.

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct PathRequestDestinationVector {
    pub description: String,
    pub full_name: String,
    pub app_name: String,
    pub aspects: Vec<String>,
    pub destination_type: String,
    pub name_hash: String,
    pub destination_hash: String,
    pub derivation: serde_json::Value,
}

#[derive(Debug, Deserialize)]
pub struct PathRequestPacketVector {
    pub description: String,
    pub transport_enabled: bool,
    pub target_destination_hash: String,
    pub request_tag: String,
    pub transport_id: Option<String>,
    pub path_request_data: String,
    pub path_request_data_length: u64,
    pub flags_byte: String,
    pub hops: u64,
    pub context: String,
    pub path_request_dest_hash: String,
    pub header: String,
    pub raw_packet: String,
    pub raw_packet_length: u64,
    pub packet_hash: String,
    #[serde(default)]
    pub payload_layout: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct PathRequestParsingVector {
    pub description: String,
    pub input_data: String,
    pub input_data_length: u64,
    pub expected_destination_hash: Option<String>,
    pub expected_requesting_transport_instance: Option<String>,
    pub expected_tag_bytes: Option<String>,
    pub expected_tag_length: Option<u64>,
    pub expected_unique_tag: Option<String>,
    pub expected_result: String,
    #[serde(default)]
    pub ignore_reason: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct PathResponsePacketVector {
    pub description: String,
    pub source_keypair_index: u64,
    pub transport_keypair_index: u64,
    #[serde(default)]
    pub app_name: Option<String>,
    #[serde(default)]
    pub aspects: Option<Vec<String>>,
    pub destination_hash: String,
    pub transport_id: String,
    #[serde(default)]
    pub random_hash: Option<String>,
    #[serde(default)]
    pub ratchet_public_key: Option<String>,
    #[serde(default)]
    pub app_data: Option<String>,
    #[serde(default)]
    pub app_data_utf8: Option<String>,
    pub flags_byte: String,
    pub context_flag: u64,
    pub hops: u64,
    pub context: String,
    pub signed_data: String,
    pub signature: String,
    pub announce_payload: String,
    pub announce_payload_length: u64,
    pub header: String,
    #[serde(default)]
    pub header_length: Option<u64>,
    pub raw_packet: String,
    pub raw_packet_length: u64,
    pub packet_hash: String,
    #[serde(default)]
    pub header_type: Option<String>,
    #[serde(default)]
    pub transport_type: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct PathTableEntryVector {
    pub description: String,
    pub destination_hash: String,
    pub interface_mode: Option<String>,
    pub interface_mode_value: Option<u64>,
    pub timestamp: u64,
    pub next_hop: String,
    pub hops: u64,
    pub expires: u64,
    pub expires_in_seconds: u64,
    pub random_blobs: Vec<String>,
    pub packet_hash: String,
    #[serde(default)]
    pub entry_indices: Option<serde_json::Value>,
    #[serde(default)]
    pub random_blobs_count: Option<u64>,
    #[serde(default)]
    pub max_random_blobs_memory: Option<u64>,
    #[serde(default)]
    pub max_random_blobs_persist: Option<u64>,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DuplicateDetectionVector {
    pub description: String,
    pub destination_hash: String,
    pub tag_bytes: String,
    pub unique_tag: String,
    pub unique_tag_length: u64,
    pub expected_result: String,
    pub tags_state_before: Vec<String>,
    pub tags_state_after: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct GracePeriodVector {
    pub description: String,
    pub is_from_local_client: bool,
    pub interface_mode: Option<String>,
    pub next_hop_is_local_client: Option<bool>,
    pub retransmit_delay_seconds: f64,
    pub retransmit_timeout: f64,
    pub base_timestamp: f64,
    pub retries: u64,
    pub block_rebroadcasts: bool,
    pub algorithm: String,
}

#[derive(Debug, Deserialize)]
pub struct PathRequestsVectors {
    pub description: String,
    pub source: String,
    pub constants: serde_json::Value,
    pub algorithm: serde_json::Value,
    pub path_request_destination_vectors: Vec<PathRequestDestinationVector>,
    pub path_request_packet_vectors: Vec<PathRequestPacketVector>,
    pub path_request_parsing_vectors: Vec<PathRequestParsingVector>,
    pub path_response_packet_vectors: Vec<PathResponsePacketVector>,
    pub path_table_entry_vectors: Vec<PathTableEntryVector>,
    pub duplicate_detection_vectors: Vec<DuplicateDetectionVector>,
    pub grace_period_vectors: Vec<GracePeriodVector>,
}

pub fn load() -> PathRequestsVectors {
    let json = include_str!("../../../.test-vectors/path_requests.json");
    serde_json::from_str(json).expect("Failed to deserialize path_requests.json")
}
