//! Test vector types for channels.json
//!
//! Channel/buffer protocol test vectors including envelope, stream data, window adaptation,
//! sequence numbering, and message handler test vectors.

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct EnvelopeVector {
    pub index: u64,
    pub description: String,
    pub msgtype: u64,
    pub sequence: u64,
    pub data_hex: String,
    pub data_length: u64,
    pub packed_hex: String,
    pub packed_length: u64,
    pub header_hex: String,
    pub decoded_msgtype: u64,
    pub decoded_sequence: u64,
    pub decoded_length: u64,
    pub decoded_data_hex: String,
}

#[derive(Debug, Deserialize)]
pub struct MessageSerializationVector {
    pub index: u64,
    pub description: String,
    pub input_tuple: serde_json::Value,
    #[serde(default)]
    pub input_note: Option<String>,
    pub packed_hex: String,
    pub packed_length: u64,
    #[serde(default)]
    pub unpacked: Option<serde_json::Value>,
    #[serde(default)]
    pub unpacked_id: Option<String>,
    #[serde(default)]
    pub unpacked_data_hex: Option<String>,
    #[serde(default)]
    pub unpacked_data_length: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct SequenceNumberVector {
    pub index: u64,
    pub description: String,
    #[serde(default)]
    pub current_seq: Option<u64>,
    #[serde(default)]
    pub next_seq: Option<u64>,
    #[serde(default)]
    pub formula: Option<String>,
    #[serde(rename = "type", default)]
    pub vector_type: Option<String>,
    #[serde(default)]
    pub next_rx_sequence: Option<u64>,
    #[serde(default)]
    pub incoming_sequence: Option<u64>,
    #[serde(default)]
    pub accepted: Option<bool>,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub window_max: Option<u64>,
    #[serde(default)]
    pub window_overflow: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct StreamDataVector {
    pub index: u64,
    pub description: String,
    pub stream_id: u64,
    pub eof: bool,
    pub compressed: bool,
    #[serde(default)]
    pub data_hex: Option<String>,
    #[serde(default)]
    pub data_length: Option<u64>,
    #[serde(default)]
    pub original_data_hex: Option<String>,
    #[serde(default)]
    pub original_data_length: Option<u64>,
    #[serde(default)]
    pub compressed_data_hex: Option<String>,
    #[serde(default)]
    pub compressed_data_length: Option<u64>,
    pub packed_hex: String,
    pub packed_length: u64,
    pub header_hex: String,
    pub header_value: u64,
    #[serde(default)]
    pub header_value_hex: Option<String>,
    #[serde(default)]
    pub header_breakdown: Option<serde_json::Value>,
    pub decoded_stream_id: u64,
    pub decoded_eof: bool,
    pub decoded_compressed: bool,
    pub decoded_data_hex: String,
    #[serde(default)]
    pub decoded_data_length: Option<u64>,
    #[serde(default)]
    pub decompression_verified: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct WindowInitVector {
    pub index: u64,
    pub description: String,
    pub rtt: f64,
    pub window: u64,
    pub window_max: u64,
    pub window_min: u64,
    pub window_flexibility: u64,
    pub condition: String,
}

#[derive(Debug, Deserialize)]
pub struct WindowAdaptationVector {
    pub index: u64,
    pub description: String,
    pub event: String,
    pub before: serde_json::Value,
    pub rtt: Option<f64>,
    pub after: serde_json::Value,
    pub note: String,
}

#[derive(Debug, Deserialize)]
pub struct TimeoutVector {
    pub index: u64,
    pub description: String,
    pub tries: u64,
    pub rtt: f64,
    pub tx_ring_length: u64,
    pub timeout: f64,
    pub formula: String,
    pub breakdown: serde_json::Value,
    pub computation: serde_json::Value,
}

#[derive(Debug, Deserialize)]
pub struct ChannelMduVector {
    pub index: u64,
    pub description: String,
    pub outlet_mdu: u64,
    pub channel_mdu: u64,
    pub formula: String,
    pub computation: serde_json::Value,
}

#[derive(Debug, Deserialize)]
pub struct SystemMessageVector {
    pub msgtype: u64,
    pub msgtype_hex: String,
    pub description: String,
    pub is_system: bool,
    pub is_valid_user_type: bool,
}

#[derive(Debug, Deserialize)]
pub struct RoundTripVector {
    pub index: u64,
    pub description: String,
    #[serde(default)]
    pub message: Option<serde_json::Value>,
    #[serde(default)]
    pub message_packed_hex: Option<String>,
    #[serde(default)]
    pub sequence: Option<u64>,
    #[serde(default)]
    pub next_sequence: Option<u64>,
    pub envelope_raw_hex: String,
    pub envelope_length: u64,
    #[serde(default)]
    pub decoded_msgtype: Option<u64>,
    #[serde(default)]
    pub decoded_sequence: Option<u64>,
    #[serde(default)]
    pub decoded_data_length: Option<u64>,
    #[serde(default)]
    pub decoded_message_id: Option<String>,
    #[serde(default)]
    pub decoded_message_data: Option<String>,
    pub verified: bool,
    // StreamData round-trip fields
    #[serde(default)]
    pub stream_id: Option<u64>,
    #[serde(default)]
    pub stream_data_hex: Option<String>,
    #[serde(default)]
    pub stream_msg_packed_hex: Option<String>,
    #[serde(default)]
    pub envelope_msgtype: Option<u64>,
    #[serde(default)]
    pub envelope_sequence: Option<u64>,
    #[serde(default)]
    pub decoded_envelope_msgtype: Option<u64>,
    #[serde(default)]
    pub decoded_envelope_sequence: Option<u64>,
    #[serde(default)]
    pub decoded_stream_id: Option<u64>,
    #[serde(default)]
    pub decoded_stream_eof: Option<bool>,
    #[serde(default)]
    pub decoded_stream_compressed: Option<bool>,
    #[serde(default)]
    pub decoded_stream_data_hex: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SendReceiveVector {
    pub index: u64,
    #[serde(rename = "type")]
    pub vector_type: String,
    pub description: String,
    #[serde(default)]
    pub steps: Option<Vec<serde_json::Value>>,
    #[serde(default)]
    pub final_next_sequence: Option<u64>,
    #[serde(default)]
    pub final_next_rx_sequence: Option<u64>,
    // Serialization round-trip variant fields
    #[serde(flatten)]
    pub extra: serde_json::Value,
}

#[derive(Debug, Deserialize)]
pub struct HandlerChainingVector {
    pub index: u64,
    pub description: String,
    pub handlers: Vec<serde_json::Value>,
    pub message_envelope_hex: String,
    pub message_msgtype: u64,
    pub message_msgtype_hex: String,
    pub expected_calls: Vec<String>,
    pub expected_call_count: u64,
    pub short_circuited: bool,
    #[serde(default)]
    pub short_circuit_handler: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RegistrationValidationVector {
    pub index: u64,
    pub description: String,
    pub msgtype: Option<u64>,
    pub msgtype_hex: Option<String>,
    pub is_subclass_of_message_base: bool,
    pub msgtype_is_none: bool,
    pub constructor_succeeds: bool,
    #[serde(default)]
    pub use_internal_api: Option<bool>,
    #[serde(default)]
    pub is_system_type_flag: Option<bool>,
    pub expected_result: String,
    pub validation_gate: Option<String>,
    #[serde(default)]
    pub ce_type: Option<serde_json::Value>,
    pub factory_registered: bool,
}

#[derive(Debug, Deserialize)]
pub struct SequenceDedupVector {
    pub index: u64,
    pub description: String,
    #[serde(default)]
    pub initial_state: Option<serde_json::Value>,
    pub steps: Vec<serde_json::Value>,
    // Variant fields for TX sequence tracking
    #[serde(rename = "type", default)]
    pub vector_type: Option<String>,
    #[serde(default)]
    pub initial_tx_sequence: Option<u64>,
    #[serde(default)]
    pub final_tx_sequence: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct RetrySequenceVector {
    pub index: u64,
    pub description: String,
    pub initial_state: serde_json::Value,
    pub steps: Vec<serde_json::Value>,
    pub final_state: serde_json::Value,
}

#[derive(Debug, Deserialize)]
pub struct WindowAdaptationSequenceVector {
    pub index: u64,
    pub description: String,
    pub initial_state: serde_json::Value,
    #[serde(default)]
    pub rtt: Option<f64>,
    #[serde(default)]
    pub rtt_sequence: Option<Vec<f64>>,
    pub steps: Vec<serde_json::Value>,
    pub final_state: serde_json::Value,
}

#[derive(Debug, Deserialize)]
pub struct PacketLossScenarioVector {
    pub index: u64,
    pub description: String,
    pub initial_state: serde_json::Value,
    pub events: Vec<serde_json::Value>,
    pub final_state: serde_json::Value,
}

#[derive(Debug, Deserialize)]
pub struct ChannelsVectors {
    pub description: String,
    pub source: String,
    pub constants: serde_json::Value,
    pub envelope_vectors: Vec<EnvelopeVector>,
    pub message_serialization_vectors: Vec<MessageSerializationVector>,
    pub sequence_number_vectors: Vec<SequenceNumberVector>,
    pub stream_data_vectors: Vec<StreamDataVector>,
    pub window_init_vectors: Vec<WindowInitVector>,
    pub window_adaptation_vectors: Vec<WindowAdaptationVector>,
    pub timeout_vectors: Vec<TimeoutVector>,
    pub mdu_vectors: Vec<ChannelMduVector>,
    pub system_message_vectors: Vec<SystemMessageVector>,
    pub round_trip_vectors: Vec<RoundTripVector>,
    pub send_receive_vectors: Vec<SendReceiveVector>,
    pub handler_chaining_vectors: Vec<HandlerChainingVector>,
    pub registration_validation_vectors: Vec<RegistrationValidationVector>,
    pub sequence_dedup_vectors: Vec<SequenceDedupVector>,
    pub retry_sequence_vectors: Vec<RetrySequenceVector>,
    pub window_adaptation_sequence_vectors: Vec<WindowAdaptationSequenceVector>,
    pub packet_loss_scenario_vectors: Vec<PacketLossScenarioVector>,
}

pub fn load() -> ChannelsVectors {
    let json = include_str!("../../../.test-vectors/channels.json");
    serde_json::from_str(json).expect("Failed to deserialize channels.json")
}
