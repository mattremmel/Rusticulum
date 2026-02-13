//! Test vector types for resources.json
//!
//! Resource transfer test vectors including metadata, advertisement, assembly, and proof vectors.

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct FlagsBreakdown {
    pub encrypted: bool,
    pub compressed: bool,
    pub split: bool,
    pub is_request: bool,
    pub is_response: bool,
    pub has_metadata: bool,
}

#[derive(Debug, Deserialize)]
pub struct AdvertisementDict {
    pub t: u64,
    pub d: u64,
    pub n: u64,
    pub h: String,
    pub r: String,
    pub o: String,
    pub i: u64,
    pub l: u64,
    #[serde(default)]
    pub q: Option<String>,
    pub f: u64,
    pub m: String,
}

#[derive(Debug, Deserialize)]
pub struct ResourcePart {
    #[serde(default)]
    pub index: Option<u64>,
    pub offset: u64,
    pub length: u64,
    pub data_hex: String,
    pub map_hash_hex: String,
}

#[derive(Debug, Deserialize)]
pub struct MetadataVector {
    pub index: u64,
    pub description: String,
    pub metadata_dict: serde_json::Value,
    #[serde(default)]
    pub metadata_dict_note: Option<String>,
    pub packed_metadata_hex: String,
    pub packed_metadata_length: u64,
    pub size_prefix_hex: String,
    #[serde(default)]
    pub size_prefix_note: Option<String>,
    pub full_metadata_bytes_hex: String,
    pub full_metadata_length: u64,
}

#[derive(Debug, Deserialize)]
pub struct ResourceAdvertisementVector {
    pub index: u64,
    pub description: String,
    pub input_data_hex: String,
    pub input_data_length: u64,
    pub metadata_dict: Option<serde_json::Value>,
    pub has_metadata: bool,
    pub data_with_metadata_hex: String,
    pub data_with_metadata_length: u64,
    pub total_size: u64,
    pub random_hash_hex: String,
    pub random_hash_seed: String,
    pub auto_compress: bool,
    pub compressed: bool,
    pub compressible: bool,
    pub pre_encryption_data_hex: String,
    pub pre_encryption_data_length: u64,
    pub pre_encryption_layout: String,
    pub deterministic_iv_hex: String,
    pub deterministic_iv_seed: String,
    pub encrypted_data_hex: String,
    pub encrypted_data_length: u64,
    pub encryption_layout: String,
    pub sdu: u64,
    pub num_parts: u64,
    pub parts: Vec<ResourcePart>,
    pub hashmap_hex: String,
    pub hashmap_length: u64,
    pub resource_hash_hex: String,
    pub resource_hash_note: String,
    pub original_hash_hex: String,
    pub expected_proof_hex: String,
    pub expected_proof_note: String,
    pub flags: u64,
    pub flags_hex: String,
    pub flags_breakdown: FlagsBreakdown,
    pub advertisement_dict: AdvertisementDict,
    pub advertisement_packed_hex: String,
    pub advertisement_packed_length: u64,
}

#[derive(Debug, Deserialize)]
pub struct AssemblyVector {
    pub index: u64,
    pub description: String,
    pub resource_hash_hex: String,
    pub random_hash_hex: String,
    pub flags: u64,
    pub steps: serde_json::Value,
    pub decrypted_stream_hex: String,
    pub decrypted_stream_length: u64,
    pub stripped_data_hex: String,
    pub stripped_data_length: u64,
    pub calculated_hash_hex: String,
    pub verified: bool,
    pub extracted_payload_hex: String,
    pub extracted_payload_length: u64,
}

#[derive(Debug, Deserialize)]
pub struct ResourceProofVector {
    pub index: u64,
    pub description: String,
    pub resource_hash_hex: String,
    pub expected_proof_hex: String,
    pub proof_computation: String,
    pub proof_computation_note: String,
    pub proof_packet_payload_hex: String,
    pub proof_packet_payload_length: u64,
    pub proof_packet_layout: String,
    pub validation_note: String,
}

#[derive(Debug, Deserialize)]
pub struct ResourcesVectors {
    pub description: String,
    pub source: String,
    pub constants: serde_json::Value,
    pub metadata_vectors: Vec<MetadataVector>,
    pub resource_advertisement_vectors: Vec<ResourceAdvertisementVector>,
    pub assembly_vectors: Vec<AssemblyVector>,
    pub resource_proof_vectors: Vec<ResourceProofVector>,
    pub integrity_failure_vector: serde_json::Value,
    pub invalid_metadata_vector: serde_json::Value,
}

pub fn load() -> ResourcesVectors {
    let json = include_str!("../../../.test-vectors/resources.json");
    serde_json::from_str(json).expect("Failed to deserialize resources.json")
}
