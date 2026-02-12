//! Test vector types for packet_headers.json
//!
//! Packet header flag packing/unpacking, header serialization, and hash test vectors.

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct FlagPackingVector {
    pub description: String,
    pub header_type: u64,
    pub context_flag: u64,
    pub transport_type: u64,
    pub destination_type: u64,
    pub packet_type: u64,
    pub flags_byte: String,
    pub flags_binary: String,
}

#[derive(Debug, Deserialize)]
pub struct FlagUnpackingVector {
    pub flags_byte: String,
    pub flags_binary: String,
    pub header_type: u64,
    pub context_flag: u64,
    pub transport_type: u64,
    pub destination_type: u64,
    pub packet_type: u64,
}

#[derive(Debug, Deserialize)]
pub struct ExhaustiveFlagVector {
    pub description: String,
    pub header_type: u64,
    pub context_flag: u64,
    pub transport_type: u64,
    pub destination_type: u64,
    pub packet_type: u64,
    pub flags_byte: String,
    pub flags_binary: String,
}

#[derive(Debug, Deserialize)]
pub struct HeaderVector {
    pub description: String,
    pub header_type: String,
    pub flags_byte: String,
    pub hops: u64,
    pub destination_hash: String,
    pub context: String,
    pub header: String,
    pub header_length: u64,
    pub payload: String,
    pub raw_packet: String,
    pub hashable_part: String,
    pub hashable_part_note: String,
    pub packet_hash_full: String,
    pub packet_hash: String,
    pub expected_header_length: u64,
    #[serde(default)]
    pub transport_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct PacketHeadersVectors {
    pub description: String,
    pub source: String,
    pub constants: serde_json::Value,
    pub flag_byte_layout: serde_json::Value,
    pub packet_type_values: serde_json::Value,
    pub destination_type_values: serde_json::Value,
    pub header_type_values: serde_json::Value,
    pub transport_type_values: serde_json::Value,
    pub context_type_values: serde_json::Value,
    pub header_1_layout: serde_json::Value,
    pub header_2_layout: serde_json::Value,
    pub packet_hash_algorithm: serde_json::Value,
    pub flag_packing_vectors: Vec<FlagPackingVector>,
    pub flag_unpacking_vectors: Vec<FlagUnpackingVector>,
    pub exhaustive_flag_vectors: Vec<ExhaustiveFlagVector>,
    pub header_vectors: Vec<HeaderVector>,
    pub packet_hash_vectors: serde_json::Value,
    pub size_limits: serde_json::Value,
}

pub fn load() -> PacketHeadersVectors {
    let json = include_str!("../../../.test-vectors/packet_headers.json");
    serde_json::from_str(json).expect("Failed to deserialize packet_headers.json")
}
