//! Test vector types for resource_transfers.json
//!
//! Resource transfer protocol sequence and cancellation test vectors.

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct HashmapSegment {
    pub segment: u64,
    pub hash_count: u64,
    #[serde(default)]
    pub hashmap_hex: Option<String>,
    #[serde(default)]
    pub hashmap_sha256: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RepresentativePart {
    pub part_index: u64,
    #[serde(default)]
    pub part_data_hex: Option<String>,
    #[serde(default)]
    pub part_data_length: Option<u64>,
    pub map_hash_hex: String,
}

#[derive(Debug, Deserialize)]
pub struct TransferStep {
    #[serde(default)]
    pub step: Option<u64>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub advertisement_packed_hex: Option<String>,
    #[serde(default)]
    pub advertisement_packed_length: Option<u64>,
    #[serde(default)]
    pub advertisement_dict: Option<serde_json::Value>,
    #[serde(default)]
    pub request_payload_hex: Option<String>,
    #[serde(default)]
    pub request_payload_length: Option<u64>,
    #[serde(default)]
    pub request_breakdown: Option<serde_json::Value>,
    #[serde(default)]
    pub request_layout: Option<serde_json::Value>,
    #[serde(default)]
    pub proof_payload_hex: Option<String>,
    #[serde(default)]
    pub proof_payload_length: Option<u64>,
    #[serde(default)]
    pub proof_breakdown: Option<serde_json::Value>,
    #[serde(default)]
    pub proof_layout: Option<serde_json::Value>,
    #[serde(default)]
    pub proof_valid: Option<bool>,
    #[serde(default)]
    pub resource_hash_hex: Option<String>,
    #[serde(default)]
    pub random_hash_hex: Option<String>,
    #[serde(default)]
    pub part_index: Option<u64>,
    #[serde(default)]
    pub part_data_hex: Option<String>,
    #[serde(default)]
    pub part_data_length: Option<u64>,
    #[serde(default)]
    pub map_hash_hex: Option<String>,
    #[serde(default)]
    pub num_parts: Option<u64>,
    #[serde(default)]
    pub hashmap_hex: Option<String>,
    #[serde(default)]
    pub flags: Option<serde_json::Value>,
    #[serde(default)]
    pub flags_hex: Option<String>,
    #[serde(default)]
    pub metadata_dict: Option<serde_json::Value>,
    #[serde(default)]
    pub metadata_bytes_hex: Option<String>,
    #[serde(default)]
    pub packed_metadata_hex: Option<String>,
    #[serde(default)]
    pub encrypted_data_length: Option<u64>,
    #[serde(default)]
    pub expected_proof_hex: Option<String>,
    #[serde(default)]
    pub assembly: Option<serde_json::Value>,
    #[serde(default)]
    pub compression_info: Option<serde_json::Value>,
    #[serde(default)]
    pub validation: Option<serde_json::Value>,
    #[serde(default)]
    pub sender_state: Option<serde_json::Value>,
    #[serde(default)]
    pub sender_state_before: Option<serde_json::Value>,
    #[serde(default)]
    pub sender_state_after: Option<serde_json::Value>,
    #[serde(default)]
    pub receiver_state: Option<serde_json::Value>,
    #[serde(default)]
    pub receiver_state_sequence: Option<serde_json::Value>,
    #[serde(default)]
    pub callbacks_fired: Option<serde_json::Value>,
    #[serde(default)]
    pub packet_context: Option<serde_json::Value>,
    #[serde(default)]
    pub packet_context_data: Option<serde_json::Value>,
    #[serde(default)]
    pub packet_context_req: Option<serde_json::Value>,
    #[serde(default)]
    pub initial_window: Option<serde_json::Value>,
    #[serde(default)]
    pub final_window: Option<serde_json::Value>,
    #[serde(default)]
    pub window_max: Option<u64>,
    #[serde(default)]
    pub total_rounds: Option<u64>,
    #[serde(default)]
    pub parts: Option<serde_json::Value>,
    #[serde(default)]
    pub progress_at_callback: Option<serde_json::Value>,
    #[serde(default)]
    pub metadata_extraction: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct TransferSequenceVector {
    pub index: u64,
    pub description: String,
    #[serde(default)]
    pub input_data_hex: Option<String>,
    pub input_data_length: u64,
    pub input_sha256: String,
    #[serde(default)]
    pub derived_key_hex: Option<String>,
    #[serde(default)]
    pub deterministic_iv_hex: Option<String>,
    #[serde(default)]
    pub random_hash_hex: Option<String>,
    #[serde(default)]
    pub steps: Option<Vec<TransferStep>>,
    #[serde(default)]
    pub data_integrity: Option<serde_json::Value>,
    pub state_machine_sequence: Vec<serde_json::Value>,
    // Large transfer fields
    #[serde(default)]
    pub encrypted_data_length: Option<u64>,
    #[serde(default)]
    pub encrypted_data_sha256: Option<String>,
    #[serde(default)]
    pub num_parts: Option<u64>,
    #[serde(default)]
    pub sdu: Option<u64>,
    #[serde(default)]
    pub last_part_size: Option<u64>,
    #[serde(default)]
    pub compression_attempted: Option<bool>,
    #[serde(default)]
    pub compression_used: Option<bool>,
    #[serde(default)]
    pub hashmap_by_segment: Option<Vec<HashmapSegment>>,
    #[serde(default)]
    pub total_hashmap_hex: Option<String>,
    #[serde(default)]
    pub total_hashmap_sha256: Option<String>,
    #[serde(default)]
    pub representative_parts: Option<Vec<RepresentativePart>>,
    #[serde(default)]
    pub resource_hash_hex: Option<String>,
    #[serde(default)]
    pub expected_proof_hex: Option<String>,
    #[serde(default)]
    pub transfer_protocol: Option<serde_json::Value>,
    // Split/segmented resource fields
    #[serde(default)]
    pub total_segments: Option<u64>,
    #[serde(default)]
    pub split: Option<bool>,
    #[serde(default)]
    pub flags: Option<u64>,
    #[serde(default)]
    pub flags_hex: Option<String>,
    #[serde(default)]
    pub original_hash_hex: Option<String>,
    #[serde(default)]
    pub segment_sizes: Option<serde_json::Value>,
    #[serde(default)]
    pub aggregate_stats: Option<serde_json::Value>,
    #[serde(default)]
    pub segments: Option<serde_json::Value>,
    #[serde(default)]
    pub cross_segment_verification: Option<serde_json::Value>,
    // Metadata/compression fields
    #[serde(default)]
    pub metadata_dict: Option<serde_json::Value>,
    #[serde(default)]
    pub has_metadata: Option<bool>,
    #[serde(default)]
    pub compressed: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct CancellationVector {
    #[serde(rename = "type")]
    pub cancellation_type: String,
    pub description: String,
    pub payload_hex: String,
    pub payload_length: u64,
    pub payload_content: serde_json::Value,
    pub packet_context: String,
    pub source: String,
}

#[derive(Debug, Deserialize)]
pub struct ResourceTransfersVectors {
    pub description: String,
    pub source: String,
    pub constants: serde_json::Value,
    pub transfer_sequence_vectors: Vec<TransferSequenceVector>,
    pub cancellation_vectors: Vec<CancellationVector>,
}

pub fn load() -> ResourceTransfersVectors {
    let json = include_str!("../../../.test-vectors/resource_transfers.json");
    serde_json::from_str(json).expect("Failed to deserialize resource_transfers.json")
}
