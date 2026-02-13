//! Test vector types for links.json
//!
//! Link establishment handshake, RTT, keepalive, MDU, teardown, and identify test vectors.

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct EphemeralKey {
    pub index: u64,
    pub x25519_seed: String,
    pub x25519_private: String,
    pub x25519_public: String,
    pub ed25519_seed: String,
    pub ed25519_private: String,
    pub ed25519_public: String,
}

#[derive(Debug, Deserialize)]
pub struct SignallingBytesVector {
    pub description: String,
    pub input_mtu: u64,
    pub input_mode: u64,
    pub input_mode_name: String,
    pub signalling_bytes: String,
    pub decoded_mtu: u64,
    pub decoded_mode: u64,
    pub round_trip_match: bool,
    pub formula: String,
}

#[derive(Debug, Deserialize)]
pub struct LinkIdVector {
    pub description: String,
    #[serde(default)]
    pub keypair_index: Option<u64>,
    #[serde(default)]
    pub ephemeral_index: Option<u64>,
    #[serde(default)]
    pub destination_hash: Option<String>,
    #[serde(default)]
    pub request_data: Option<String>,
    #[serde(default)]
    pub request_data_length: Option<u64>,
    #[serde(default)]
    pub signalling_bytes: Option<String>,
    #[serde(default)]
    pub flags_byte: Option<String>,
    #[serde(default)]
    pub raw_packet: Option<String>,
    #[serde(default)]
    pub hashable_part: Option<String>,
    #[serde(default)]
    pub hashable_part_length: Option<u64>,
    #[serde(default)]
    pub signalling_diff: Option<u64>,
    #[serde(default)]
    pub hashable_stripped: Option<String>,
    #[serde(default)]
    pub hashable_stripped_length: Option<u64>,
    #[serde(default)]
    pub link_id: Option<String>,
    #[serde(default)]
    pub algorithm: Option<String>,
    // For MTU comparison vectors
    #[serde(default)]
    pub link_id_mtu_500: Option<String>,
    #[serde(default)]
    pub link_id_mtu_1000: Option<String>,
    #[serde(default)]
    pub link_id_legacy: Option<String>,
    #[serde(default)]
    pub all_match: Option<bool>,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct Step1LinkRequest {
    pub initiator_eph_x25519_public: String,
    pub initiator_eph_ed25519_public: String,
    pub signalling_bytes: Option<String>,
    pub request_data: String,
    pub request_data_length: u64,
    pub responder_destination_hash: String,
    pub flags_byte: String,
    pub context_byte: String,
    pub raw_packet: String,
    pub raw_packet_length: u64,
    pub hashable_part: String,
    pub signalling_diff: u64,
    pub hashable_stripped: String,
    pub link_id: String,
}

#[derive(Debug, Deserialize)]
pub struct Step2LrProof {
    pub responder_eph_x25519_public: String,
    pub responder_identity_ed25519_public: String,
    pub shared_key: String,
    pub shared_key_length: u64,
    pub hkdf_salt: String,
    pub hkdf_context: Option<String>,
    pub hkdf_length: u64,
    pub derived_key: String,
    pub signing_key: String,
    pub encryption_key: String,
    pub signalling_bytes: Option<String>,
    pub signed_data: String,
    pub signed_data_layout: String,
    pub signature: String,
    pub proof_data: String,
    pub proof_data_layout: String,
    pub proof_data_length: u64,
    pub flags_byte: String,
    pub context_byte: String,
    pub header_destination: String,
    pub header_destination_note: String,
    pub raw_packet: String,
    pub raw_packet_length: u64,
}

#[derive(Debug, Deserialize)]
pub struct Step3Verify {
    pub initiator_shared_key: String,
    pub ecdh_symmetric: bool,
    pub initiator_derived_key: String,
    pub derived_keys_match: bool,
    pub signature_valid: bool,
}

#[derive(Debug, Deserialize)]
pub struct Step4LrRtt {
    pub rtt_value: f64,
    pub rtt_msgpack: String,
    pub fixed_iv: String,
    pub padded_plaintext: String,
    pub ciphertext: String,
    pub hmac: String,
    pub encrypted_rtt_token: String,
    pub encrypted_rtt_token_length: u64,
    pub context_byte: String,
    pub note: String,
}

#[derive(Debug, Deserialize)]
pub struct HandshakeVector {
    pub description: String,
    pub initiator_keypair_index: u64,
    pub responder_keypair_index: u64,
    pub initiator_ephemeral_index: u64,
    pub responder_ephemeral_index: u64,
    pub mtu: u64,
    pub mode: u64,
    pub mode_name: String,
    pub use_signalling: bool,
    pub step_1_linkrequest: Step1LinkRequest,
    pub step_2_lrproof: Step2LrProof,
    pub step_3_verify: Step3Verify,
    pub step_4_lrrtt: Step4LrRtt,
}

#[derive(Debug, Deserialize)]
pub struct RttVector {
    pub description: String,
    pub rtt_float: f64,
    pub msgpack_bytes: String,
    pub msgpack_length: u64,
    pub round_trip_value: f64,
    pub round_trip_match: bool,
}

#[derive(Debug, Deserialize)]
pub struct KeepaliveCalculationVector {
    pub description: String,
    pub rtt: f64,
    pub keepalive: f64,
    pub stale_time: f64,
    pub formula: String,
    pub formula_simplified: String,
    pub stale_formula: String,
}

#[derive(Debug, Deserialize)]
pub struct MduVector {
    pub description: String,
    pub mtu: u64,
    pub ifac_min_size: u64,
    pub header_minsize: u64,
    pub token_overhead: u64,
    pub aes128_blocksize: u64,
    pub mdu: u64,
    pub formula: String,
    pub intermediate: serde_json::Value,
}

#[derive(Debug, Deserialize)]
pub struct ModeRejectionVector {
    pub description: String,
    #[serde(default)]
    pub mode_encodings: Option<serde_json::Value>,
    #[serde(default)]
    pub encoding_formula: Option<String>,
    #[serde(default)]
    pub extraction_formula: Option<String>,
    #[serde(default)]
    pub mode_value: Option<u64>,
    #[serde(default)]
    pub mode_name: Option<String>,
    #[serde(default)]
    pub is_enabled: Option<bool>,
    #[serde(default, rename = "signalling_bytes_raises_TypeError")]
    pub signalling_bytes_raises_type_error: Option<bool>,
    #[serde(default)]
    pub note: Option<String>,
    #[serde(default)]
    pub mtu: Option<u64>,
    #[serde(default)]
    pub hypothetical_signalling_bytes: Option<String>,
    #[serde(default)]
    pub decoded_mtu: Option<u64>,
    #[serde(default)]
    pub decoded_mode: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct TeardownVector {
    pub description: String,
    pub handshake_reference: String,
    pub link_id: String,
    pub plaintext: String,
    pub plaintext_note: String,
    pub fixed_iv: String,
    pub encrypted_token: String,
    pub encrypted_token_length: u64,
    pub context_byte: String,
    pub context_name: String,
}

#[derive(Debug, Deserialize)]
pub struct IdentifyVector {
    pub description: String,
    pub handshake_reference: String,
    pub link_id: String,
    pub initiator_keypair_index: u64,
    pub initiator_public_key: String,
    pub signed_data: String,
    pub signed_data_layout: String,
    pub signature: String,
    pub proof_data: String,
    pub proof_data_layout: String,
    pub proof_data_length: u64,
    pub fixed_iv: String,
    pub encrypted_token: String,
    pub encrypted_token_length: u64,
    pub context_byte: String,
    pub context_name: String,
}

#[derive(Debug, Deserialize)]
pub struct LinksVectors {
    pub description: String,
    pub source: String,
    pub constants: serde_json::Value,
    pub ephemeral_keys: Vec<EphemeralKey>,
    pub signalling_bytes_vectors: Vec<SignallingBytesVector>,
    pub link_id_vectors: Vec<LinkIdVector>,
    pub handshake_vectors: Vec<HandshakeVector>,
    pub rtt_vectors: Vec<RttVector>,
    pub keepalive_calculation_vectors: Vec<KeepaliveCalculationVector>,
    pub mdu_vectors: Vec<MduVector>,
    pub mode_rejection_vectors: Vec<ModeRejectionVector>,
    pub teardown_vectors: Vec<TeardownVector>,
    pub identify_vectors: Vec<IdentifyVector>,
    pub state_machine_spec: serde_json::Value,
}

pub fn load() -> LinksVectors {
    let json = include_str!("../../../.test-vectors/links.json");
    serde_json::from_str(json).expect("Failed to deserialize links.json")
}
