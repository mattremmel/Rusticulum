//! Test vector types for packets_data.json
//!
//! Data packet encryption, proof generation/validation, and receipt test vectors.

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct DataPacketVector {
    pub index: u64,
    pub description: String,
    pub handshake_reference: String,
    pub link_id: String,
    pub plaintext: String,
    pub plaintext_length: u64,
    pub deterministic_iv: String,
    pub deterministic_iv_seed: String,
    pub padded_plaintext: String,
    pub padded_plaintext_length: u64,
    pub aes_ciphertext: String,
    pub aes_ciphertext_length: u64,
    pub hmac: String,
    pub token_ciphertext: String,
    pub token_ciphertext_length: u64,
    pub token_layout: String,
    pub flags_byte: String,
    pub context_byte: String,
    pub raw_packet: String,
    pub raw_packet_length: u64,
    pub hashable_part: String,
    pub packet_hash: String,
    pub packet_hash_note: String,
}

#[derive(Debug, Deserialize)]
pub struct ProofGenerationVector {
    pub data_packet_index: u64,
    pub description: String,
    pub link_id: String,
    pub original_packet_hash: String,
    pub signer: String,
    pub signer_private_key: String,
    pub signer_note: String,
    pub signature: String,
    pub signature_length: u64,
    pub proof_data: String,
    pub proof_data_length: u64,
    pub proof_data_layout: String,
    pub not_encrypted: bool,
    pub not_encrypted_note: String,
    pub flags_byte: String,
    pub context_byte: String,
    pub context_note: String,
    pub raw_proof_packet: String,
    pub raw_proof_packet_length: u64,
    pub proof_packet_hash: String,
}

#[derive(Debug, Deserialize)]
pub struct ProofValidationVector {
    pub data_packet_index: u64,
    pub description: String,
    pub proof_data: String,
    pub proof_hash_extracted: String,
    pub signature_extracted: String,
    pub validator_public_key: String,
    pub validator_note: String,
    pub step_1_hash_match: bool,
    pub step_2_signature_valid: bool,
    pub expected_receipt_status: String,
    pub expected_receipt_status_value: u64,
}

#[derive(Debug, Deserialize)]
pub struct InvalidProofVector {
    pub description: String,
    pub data_packet_index: u64,
    pub original_packet_hash: String,
    #[serde(default)]
    pub tampered_proof_data: Option<String>,
    #[serde(default)]
    pub tampered_proof_hash: Option<String>,
    #[serde(default)]
    pub signature: Option<String>,
    #[serde(default)]
    pub tampered_signature: Option<String>,
    #[serde(default)]
    pub proof_hash: Option<String>,
    #[serde(default)]
    pub wrong_key_proof_data: Option<String>,
    #[serde(default)]
    pub wrong_signature: Option<String>,
    #[serde(default)]
    pub wrong_signer_keypair_index: Option<u64>,
    #[serde(default)]
    pub wrong_signer_ed25519_public: Option<String>,
    pub failure_reason: String,
    pub hash_match: bool,
    pub signature_check_reached: bool,
    #[serde(default)]
    pub signature_valid: Option<bool>,
    #[serde(default)]
    pub signature_valid_with_correct_key: Option<bool>,
    #[serde(default)]
    pub signature_valid_with_wrong_key: Option<bool>,
    pub expected_result: bool,
}

#[derive(Debug, Deserialize)]
pub struct BidirectionalVector {
    pub direction: String,
    pub description: String,
    pub plaintext: String,
    pub deterministic_iv: String,
    pub token_ciphertext: String,
    pub raw_data_packet: String,
    pub packet_hash: String,
    pub proof_signer: String,
    pub proof_signer_private: String,
    pub proof_signer_note: String,
    pub proof_signature: String,
    pub proof_data: String,
    pub raw_proof_packet: String,
    pub proof_validator_public: String,
    pub proof_validator_note: String,
}

#[derive(Debug, Deserialize)]
pub struct BidirectionalVectors {
    pub description: String,
    pub encryption_note: String,
    pub signing_note: String,
    pub link_id: String,
    pub derived_key: String,
    pub vectors: Vec<BidirectionalVector>,
}

#[derive(Debug, Deserialize)]
pub struct BurstVectorEntry {
    pub burst_index: u64,
    pub plaintext: String,
    pub deterministic_iv: String,
    pub token_ciphertext: String,
    pub raw_packet: String,
    pub packet_hash: String,
    pub proof_signature: String,
    pub proof_data: String,
    pub raw_proof_packet: String,
    pub proof_packet_hash: String,
}

#[derive(Debug, Deserialize)]
pub struct BurstVectors {
    pub description: String,
    pub link_id: String,
    pub burst_count: u64,
    pub packet_size: u64,
    pub ordering_note: String,
    pub receipt_independence_note: String,
    pub vectors: Vec<BurstVectorEntry>,
    pub uniqueness_verification: serde_json::Value,
}

#[derive(Debug, Deserialize)]
pub struct LinkTimeoutScenario {
    pub description: String,
    pub rtt_ms: f64,
    pub rtt_seconds: f64,
    pub formula: String,
    pub timeout_seconds: f64,
}

#[derive(Debug, Deserialize)]
pub struct NonLinkTimeoutScenario {
    pub description: String,
    pub hops: u64,
    pub first_hop_timeout: f64,
    pub first_hop_timeout_note: String,
    pub formula: String,
    pub timeout_seconds: f64,
}

#[derive(Debug, Deserialize)]
pub struct ReceiptTimeoutScenarios {
    pub description: String,
    pub link_formula: String,
    pub link_formula_source: String,
    pub non_link_formula: String,
    pub non_link_formula_source: String,
    pub link_scenarios: Vec<LinkTimeoutScenario>,
    pub non_link_scenarios: Vec<NonLinkTimeoutScenario>,
}

#[derive(Debug, Deserialize)]
pub struct ReceiptProofMatchingEntry {
    pub data_packet_index: u64,
    pub description: String,
    pub full_packet_hash: String,
    pub full_packet_hash_length: u64,
    pub truncated_hash: String,
    pub truncated_hash_length: u64,
    pub truncated_is_prefix: bool,
    pub matching_note: String,
    pub source: String,
}

#[derive(Debug, Deserialize)]
pub struct ReceiptProofMatchingVectors {
    pub description: String,
    pub link_id: String,
    pub full_hash_length: u64,
    pub truncated_hash_length: u64,
    pub vectors: Vec<ReceiptProofMatchingEntry>,
}

#[derive(Debug, Deserialize)]
pub struct PacketsDataVectors {
    pub description: String,
    pub source: String,
    pub constants: serde_json::Value,
    pub proof_strategies: serde_json::Value,
    pub receipt_states: serde_json::Value,
    pub data_packet_vectors: Vec<DataPacketVector>,
    pub proof_generation_vectors: Vec<ProofGenerationVector>,
    pub proof_validation_vectors: Vec<ProofValidationVector>,
    pub invalid_proof_vectors: Vec<InvalidProofVector>,
    pub bidirectional_vectors: BidirectionalVectors,
    pub burst_vectors: BurstVectors,
    pub receipt_timeout_constants: serde_json::Value,
    pub receipt_timeout_scenarios: ReceiptTimeoutScenarios,
    pub receipt_state_machine: serde_json::Value,
    pub receipt_proof_matching_vectors: ReceiptProofMatchingVectors,
}

pub fn load() -> PacketsDataVectors {
    let json = include_str!("../../../.test-vectors/packets_data.json");
    serde_json::from_str(json).expect("Failed to deserialize packets_data.json")
}
