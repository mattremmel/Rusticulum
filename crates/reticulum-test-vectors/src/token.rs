//! Test vector types for token.json
//!
//! Token (modified Fernet), PKCS7, HMAC-SHA256 test vectors.

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Pkcs7PaddingVector {
    pub description: String,
    pub input: String,
    pub input_length: u64,
    pub padded: String,
    pub padded_length: u64,
    pub pad_byte: String,
    pub pad_length: u64,
}

#[derive(Debug, Deserialize)]
pub struct HmacSha256Vector {
    pub description: String,
    pub key: String,
    pub message: String,
    pub digest: String,
    pub digest_length: u64,
}

#[derive(Debug, Deserialize)]
pub struct KeySplit {
    pub signing_key: String,
    pub encryption_key: String,
    pub note: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DeterministicFernetVector {
    pub description: String,
    pub key: String,
    pub key_split: KeySplit,
    pub iv: String,
    pub plaintext: String,
    pub padded_plaintext: String,
    pub ciphertext: String,
    pub signed_parts: String,
    pub signed_parts_note: String,
    pub hmac: String,
    pub token: String,
    pub token_layout: serde_json::Value,
    #[serde(default)]
    pub plaintext_utf8: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct FixedTokenDecomposition {
    pub description: String,
    pub fixed_token: String,
    pub total_length: u64,
    pub layout: serde_json::Value,
    pub plaintext: String,
    pub decryption_note: String,
}

#[derive(Debug, Deserialize)]
pub struct TokenVectors {
    pub description: String,
    pub source: String,
    pub constants: serde_json::Value,
    pub token_format: serde_json::Value,
    pub pkcs7_padding: Vec<Pkcs7PaddingVector>,
    pub hmac_sha256: Vec<HmacSha256Vector>,
    pub deterministic_fernet_vectors: Vec<DeterministicFernetVector>,
    pub fixed_token_decomposition: FixedTokenDecomposition,
}

pub fn load() -> TokenVectors {
    let json = include_str!("../../../.test-vectors/token.json");
    serde_json::from_str(json).expect("Failed to deserialize token.json")
}
