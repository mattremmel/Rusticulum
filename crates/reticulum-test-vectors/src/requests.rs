//! Test vector types for requests.json
//!
//! Request/response protocol test vectors including serialization, wire format,
//! policy enforcement, timeouts, and handler management.

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct PathHashVector {
    pub index: u64,
    pub description: String,
    pub path: String,
    pub path_bytes_hex: String,
    pub path_hash: String,
    pub algorithm: String,
}

#[derive(Debug, Deserialize)]
pub struct RequestSerializationVector {
    pub index: u64,
    pub description: String,
    pub path: String,
    pub timestamp: f64,
    pub path_hash: String,
    #[serde(default)]
    pub data_description: Option<String>,
    #[serde(default)]
    pub packed_request_hex: Option<String>,
    pub packed_request_length: u64,
    pub fits_in_mdu: bool,
    pub mdu: u64,
    #[serde(default)]
    pub data_hex: Option<String>,
    #[serde(default)]
    pub data_json: Option<serde_json::Value>,
    #[serde(default)]
    pub data_length: Option<u64>,
    #[serde(default)]
    pub data_hex_prefix: Option<String>,
    #[serde(default)]
    pub packed_request_hex_prefix: Option<String>,
    #[serde(default)]
    pub request_id: Option<String>,
    #[serde(default)]
    pub request_id_algorithm: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ResponseSerializationVector {
    pub index: u64,
    pub description: String,
    pub request_id: String,
    #[serde(default)]
    pub packed_response_hex: Option<String>,
    pub packed_response_length: u64,
    pub fits_in_mdu: bool,
    pub mdu: u64,
    #[serde(default)]
    pub response_data: Option<serde_json::Value>,
    #[serde(default)]
    pub response_data_hex: Option<String>,
    #[serde(default)]
    pub response_data_json: Option<serde_json::Value>,
    #[serde(default)]
    pub response_data_length: Option<u64>,
    #[serde(default)]
    pub response_data_hex_prefix: Option<String>,
    #[serde(default)]
    pub packed_response_hex_prefix: Option<String>,
    #[serde(default)]
    pub request_id_for_resource: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SmallRequestWireVector {
    pub index: u64,
    pub description: String,
    pub path: String,
    pub timestamp: f64,
    pub path_hash: String,
    pub data_description: String,
    pub packed_request_hex: String,
    pub packed_request_length: u64,
    pub iv: String,
    pub token_data_hex: String,
    pub token_data_length: u64,
    pub flags_byte: String,
    pub context_byte: String,
    pub link_id: String,
    pub raw_packet_hex: String,
    pub raw_packet_length: u64,
    pub hashable_part_hex: String,
    pub hashable_part_length: u64,
    pub request_id: String,
    pub request_id_algorithm: String,
}

#[derive(Debug, Deserialize)]
pub struct SmallResponseWireVector {
    pub index: u64,
    pub description: String,
    pub request_id: String,
    pub packed_response_hex: String,
    pub packed_response_length: u64,
    pub iv: String,
    pub token_data_hex: String,
    pub token_data_length: u64,
    pub flags_byte: String,
    pub context_byte: String,
    pub link_id: String,
    pub raw_packet_hex: String,
    pub raw_packet_length: u64,
    pub hashable_part_hex: String,
    pub hashable_part_length: u64,
    pub packet_hash: String,
    #[serde(default)]
    pub response_data: Option<serde_json::Value>,
    #[serde(default)]
    pub response_data_hex: Option<String>,
    #[serde(default)]
    pub response_data_json: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct ResourceParams {
    pub is_response: bool,
    pub request_id: String,
}

#[derive(Debug, Deserialize)]
pub struct LargeRequestResourceVector {
    pub index: u64,
    pub description: String,
    #[serde(rename = "type")]
    pub vector_type: String,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub timestamp: Option<f64>,
    #[serde(default)]
    pub path_hash: Option<String>,
    #[serde(default)]
    pub data_length: Option<u64>,
    #[serde(default)]
    pub packed_request_length: Option<u64>,
    #[serde(default)]
    pub packed_response_length: Option<u64>,
    #[serde(default)]
    pub response_data_length: Option<u64>,
    pub exceeds_mdu: bool,
    pub request_id: String,
    #[serde(default)]
    pub request_id_algorithm: Option<String>,
    pub resource_params: ResourceParams,
    pub receiver_side: serde_json::Value,
}

#[derive(Debug, Deserialize)]
pub struct PolicyVector {
    pub index: u64,
    pub description: String,
    pub policy: u64,
    pub policy_name: String,
    pub remote_identity_hash: Option<String>,
    pub allowed_list: Option<Vec<String>>,
    pub expected_allowed: bool,
    pub computed_allowed: bool,
}

#[derive(Debug, Deserialize)]
pub struct RequestTimeoutVector {
    pub index: u64,
    pub description: String,
    pub rtt: f64,
    pub traffic_timeout_factor: u64,
    pub response_max_grace_time: u64,
    pub grace_multiplier: f64,
    pub timeout: f64,
    pub formula: String,
    pub computation: serde_json::Value,
}

#[derive(Debug, Deserialize)]
pub struct RequestRoundTripVector {
    pub index: u64,
    pub description: String,
    pub path: String,
    pub timestamp: f64,
    #[serde(default)]
    pub request_data_hex: Option<String>,
    #[serde(default)]
    pub response_data_hex: Option<String>,
    #[serde(default)]
    pub request_data_json: Option<serde_json::Value>,
    #[serde(default)]
    pub response_data_json: Option<serde_json::Value>,
    #[serde(default)]
    pub request_data: Option<serde_json::Value>,
    #[serde(default)]
    pub response_data: Option<serde_json::Value>,
    #[serde(default)]
    pub request_data_description: Option<String>,
    #[serde(default)]
    pub response_data_description: Option<String>,
    #[serde(default)]
    pub request_data_length: Option<u64>,
    #[serde(default)]
    pub response_data_length: Option<u64>,
    #[serde(default)]
    pub transport_mode: Option<serde_json::Value>,
    pub step_1_registration: serde_json::Value,
    pub step_2_request_packing: serde_json::Value,
    #[serde(default)]
    pub step_3_request_encryption: Option<serde_json::Value>,
    #[serde(default)]
    pub step_4_receiver_decrypt: Option<serde_json::Value>,
    #[serde(default)]
    pub step_5_response_encryption: Option<serde_json::Value>,
    #[serde(default)]
    pub step_5_response_packing: Option<serde_json::Value>,
    #[serde(default)]
    pub step_6_initiator_decrypt: Option<serde_json::Value>,
    pub verified: bool,
}

#[derive(Debug, Deserialize)]
pub struct ReceiptLifecycleVector {
    pub index: u64,
    pub description: String,
    pub request_transport: String,
    pub response_transport: String,
    #[serde(default)]
    pub round_trip_vector_index: Option<u64>,
    pub state_transitions: Vec<serde_json::Value>,
    pub callbacks_invoked: Vec<serde_json::Value>,
    pub receipt_response: serde_json::Value,
    #[serde(default)]
    pub progress_at_completion: Option<serde_json::Value>,
    #[serde(default)]
    pub timeout_note: Option<String>,
    #[serde(default)]
    pub timeout_formula: Option<String>,
    #[serde(default)]
    pub timeout_constants: Option<serde_json::Value>,
    #[serde(default)]
    pub failure_note: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct HandlerInvocationVector {
    pub index: u64,
    pub description: String,
    pub path: String,
    pub path_hash: String,
    #[serde(default)]
    pub timestamp: Option<f64>,
    #[serde(default)]
    pub request_id: Option<String>,
    #[serde(default)]
    pub param_count: Option<u64>,
    #[serde(default)]
    pub dispatch_args: Option<serde_json::Value>,
    #[serde(default)]
    pub dispatch_algorithm: Option<String>,
    #[serde(default)]
    pub unpacked_request_indices: Option<serde_json::Value>,
    #[serde(default)]
    pub handler_found: Option<bool>,
    #[serde(default)]
    pub behavior: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct PolicyEnforcementWireVector {
    pub index: u64,
    pub description: String,
    pub path: String,
    pub path_hash: String,
    #[serde(default)]
    pub timestamp: Option<f64>,
    #[serde(default)]
    pub request_data_hex: Option<String>,
    pub policy: u64,
    pub policy_name: String,
    pub remote_identity_hash: Option<String>,
    pub allowed_list: Option<Vec<String>>,
    pub expected_allowed: bool,
    #[serde(default)]
    pub request_wire: Option<serde_json::Value>,
    #[serde(default)]
    pub policy_trace: Option<serde_json::Value>,
    #[serde(default)]
    pub response_wire: Option<serde_json::Value>,
    #[serde(default)]
    pub server_behavior: Option<serde_json::Value>,
    #[serde(default)]
    pub server_log: Option<serde_json::Value>,
    #[serde(default)]
    pub client_consequence: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct FailureCallbackVector {
    pub index: u64,
    pub description: String,
    pub transport: String,
    pub request_id: String,
    #[serde(default)]
    pub packed_request_length: Option<u64>,
    #[serde(default)]
    pub request_wire: Option<serde_json::Value>,
    pub state_transitions: Vec<serde_json::Value>,
    pub callback_invoked: bool,
    pub callback: Option<String>,
    #[serde(default)]
    pub receipt_state_at_callback: Option<serde_json::Value>,
    #[serde(default)]
    pub timeout_mechanism: Option<serde_json::Value>,
    #[serde(default)]
    pub server_behavior: Option<serde_json::Value>,
    #[serde(default)]
    pub stuck_state: Option<serde_json::Value>,
    #[serde(default)]
    pub behavioral_gap: Option<serde_json::Value>,
    #[serde(default)]
    pub note: Option<String>,
    pub source_reference: serde_json::Value,
}

#[derive(Debug, Deserialize)]
pub struct HandlerErrorVector {
    pub index: u64,
    pub description: String,
    pub path: String,
    pub path_hash: String,
    pub timestamp: f64,
    pub request_id: String,
    #[serde(default)]
    pub request_wire: Option<serde_json::Value>,
    pub handler_param_count: u64,
    pub expected_exception: Option<String>,
    #[serde(default)]
    pub expected_message: Option<String>,
    pub response_sent: bool,
    pub server_behavior: serde_json::Value,
    #[serde(default)]
    pub note: Option<String>,
    pub source_reference: serde_json::Value,
}

#[derive(Debug, Deserialize)]
pub struct RequestsVectors {
    pub description: String,
    pub source: String,
    pub handshake_reference: String,
    pub constants: serde_json::Value,
    pub path_hash_vectors: Vec<PathHashVector>,
    pub request_serialization_vectors: Vec<RequestSerializationVector>,
    pub response_serialization_vectors: Vec<ResponseSerializationVector>,
    pub small_request_wire_vectors: Vec<SmallRequestWireVector>,
    pub small_response_wire_vectors: Vec<SmallResponseWireVector>,
    pub large_request_resource_vectors: Vec<LargeRequestResourceVector>,
    pub policy_vectors: Vec<PolicyVector>,
    pub timeout_vectors: Vec<RequestTimeoutVector>,
    pub round_trip_vectors: Vec<RequestRoundTripVector>,
    pub receipt_lifecycle_vectors: Vec<ReceiptLifecycleVector>,
    pub handler_registration_vectors: serde_json::Value,
    pub handler_deregistration_vectors: serde_json::Value,
    pub handler_invocation_vectors: Vec<HandlerInvocationVector>,
    pub handler_validation_vectors: serde_json::Value,
    pub policy_enforcement_wire_vectors: Vec<PolicyEnforcementWireVector>,
    pub failure_callback_vectors: Vec<FailureCallbackVector>,
    pub handler_error_vectors: Vec<HandlerErrorVector>,
}

pub fn load() -> RequestsVectors {
    let json = include_str!("../../../.test-vectors/requests.json");
    serde_json::from_str(json).expect("Failed to deserialize requests.json")
}
