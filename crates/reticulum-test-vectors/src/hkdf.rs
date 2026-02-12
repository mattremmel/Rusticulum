//! Test vector types for hkdf.json
//!
//! HKDF-SHA256 test vectors including RFC 5869 and Reticulum-specific vectors.

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Rfc5869Vector {
    pub description: String,
    pub ikm: String,
    pub salt: String,
    #[serde(default)]
    pub salt_note: Option<String>,
    pub info: String,
    pub length: u64,
    pub prk: String,
    pub okm: String,
}

#[derive(Debug, Deserialize)]
pub struct ReticulumVector {
    pub description: String,
    pub keypair_0_x25519_private: String,
    pub keypair_0_x25519_public: String,
    pub keypair_1_x25519_private: String,
    pub keypair_1_x25519_public: String,
    pub shared_key: String,
    pub salt: String,
    pub salt_note: String,
    pub info: String,
    pub info_note: String,
    pub length: u64,
    pub prk: String,
    pub derived_key: String,
}

#[derive(Debug, Deserialize)]
pub struct HkdfVectors {
    pub description: String,
    pub source: String,
    pub constants: serde_json::Value,
    pub algorithm_notes: serde_json::Value,
    pub rfc5869_vectors: Vec<Rfc5869Vector>,
    pub reticulum_vector: ReticulumVector,
}

pub fn load() -> HkdfVectors {
    let json = include_str!("../../../.test-vectors/hkdf.json");
    serde_json::from_str(json).expect("Failed to deserialize hkdf.json")
}
