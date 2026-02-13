//! Test vector types for buffer_transfers.json
//!
//! Buffer protocol transfer test vectors including small/large transfers,
//! compression, EOF handling, bidirectional transfers, and reassembly.

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct WriteResult {
    pub processed_length: u64,
    pub compressed: bool,
    pub chunk_hex: String,
    #[serde(default)]
    pub chunk_length: Option<u64>,
    pub stream_packed_hex: String,
    #[serde(default)]
    pub stream_packed_length: Option<u64>,
    #[serde(default)]
    pub envelope_packed_hex: Option<String>,
    #[serde(default)]
    pub envelope_packed_length: Option<u64>,
    #[serde(default)]
    pub compression_attempts: Option<Vec<serde_json::Value>>,
    #[serde(default)]
    pub compression_skipped: Option<bool>,
    #[serde(default)]
    pub offset: Option<u64>,
    #[serde(default)]
    pub sequence: Option<u64>,
    #[serde(default)]
    pub is_eof: Option<bool>,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct EofMessage {
    pub stream_packed_hex: String,
    #[serde(default)]
    pub stream_packed_length: Option<u64>,
    #[serde(default)]
    pub envelope_packed_hex: Option<String>,
    #[serde(default)]
    pub envelope_packed_length: Option<u64>,
    #[serde(default)]
    pub is_eof: Option<bool>,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SmallTransferMessage {
    pub processed_length: u64,
    pub compressed: bool,
    pub chunk_hex: String,
    pub chunk_length: u64,
    pub stream_packed_hex: String,
    pub stream_packed_length: u64,
    pub envelope_packed_hex: String,
    pub envelope_packed_length: u64,
    pub compression_attempts: Vec<serde_json::Value>,
    pub compression_skipped: bool,
    pub offset: u64,
    pub sequence: u64,
    #[serde(default)]
    pub is_eof: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct SmallTransferVector {
    pub index: u64,
    pub description: String,
    pub input_data_hex: String,
    pub input_data_length: u64,
    pub input_sha256: String,
    pub stream_id: u64,
    #[serde(default)]
    pub data_seed: Option<String>,
    pub message_count: u64,
    pub messages: Vec<SmallTransferMessage>,
}

#[derive(Debug, Deserialize)]
pub struct LargeTransferVector {
    pub index: u64,
    pub description: String,
    pub input_data_length: u64,
    pub input_sha256: String,
    pub stream_id: u64,
    pub message_count: u64,
    pub data_message_count: u64,
    pub total_wire_bytes: u64,
    pub compact_messages: Vec<serde_json::Value>,
    pub spot_checks: serde_json::Value,
}

#[derive(Debug, Deserialize)]
pub struct CompressionVector {
    pub index: u64,
    pub description: String,
    #[serde(default)]
    pub input_data_hex: Option<String>,
    pub input_data_length: u64,
    #[serde(default)]
    pub input_sha256: Option<String>,
    pub stream_id: u64,
    #[serde(default)]
    pub data_seed: Option<String>,
    pub write_result: WriteResult,
}

#[derive(Debug, Deserialize)]
pub struct EofVector {
    pub index: u64,
    pub description: String,
    #[serde(default)]
    pub input_data_hex: Option<String>,
    #[serde(default)]
    pub input_data_length: Option<u64>,
    pub stream_id: u64,
    #[serde(default)]
    pub total_messages: Option<u64>,
    pub eof_message: EofMessage,
    #[serde(default)]
    pub envelope_packed_hex: Option<String>,
    #[serde(default)]
    pub envelope_packed_length: Option<u64>,
    pub eof_header_value: u64,
    pub eof_header_hex: String,
    pub eof_header_breakdown: serde_json::Value,
    #[serde(default)]
    pub expected_stream_id: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct BidirectionalTransferVector {
    pub index: u64,
    pub description: String,
    #[serde(default)]
    pub note: Option<String>,
    pub side_a: serde_json::Value,
    #[serde(default)]
    pub side_b: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct ReassemblyVector {
    pub index: u64,
    pub description: String,
    pub input_data_length: u64,
    pub input_sha256: String,
    #[serde(default)]
    pub data_seed: Option<String>,
    #[serde(default)]
    pub input_data_description: Option<String>,
    pub stream_id: u64,
    pub message_count: u64,
    pub reassembly_steps: Vec<serde_json::Value>,
    pub assembled_sha256: String,
    pub reassembly_verified: bool,
}

#[derive(Debug, Deserialize)]
pub struct BufferTransfersVectors {
    pub description: String,
    pub source: String,
    pub constants: serde_json::Value,
    pub small_transfer_vectors: Vec<SmallTransferVector>,
    pub large_transfer_vectors: Vec<LargeTransferVector>,
    pub compression_vectors: Vec<CompressionVector>,
    pub eof_vectors: Vec<EofVector>,
    pub bidirectional_vectors: Vec<BidirectionalTransferVector>,
    pub reassembly_vectors: Vec<ReassemblyVector>,
}

pub fn load() -> BufferTransfersVectors {
    let json = include_str!("../../../.test-vectors/buffer_transfers.json");
    serde_json::from_str(json).expect("Failed to deserialize buffer_transfers.json")
}
