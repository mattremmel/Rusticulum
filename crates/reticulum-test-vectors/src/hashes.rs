//! Test vector types for hashes.json
//!
//! SHA-256, SHA-512, and truncated hash test vectors.

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Sha256Vector {
    pub description: String,
    pub input: String,
    pub input_length: u64,
    pub digest: String,
}

#[derive(Debug, Deserialize)]
pub struct Sha512Vector {
    pub description: String,
    pub input: String,
    pub input_length: u64,
    pub digest: String,
}

#[derive(Debug, Deserialize)]
pub struct TruncatedHashVector {
    pub description: String,
    pub input: String,
    pub input_length: u64,
    pub full_sha256: String,
    pub truncated_hash: String,
    pub truncated_length_bytes: u64,
}

#[derive(Debug, Deserialize)]
pub struct HashesVectors {
    pub description: String,
    pub source: String,
    pub constants: serde_json::Value,
    pub sha256: Vec<Sha256Vector>,
    pub sha512: Vec<Sha512Vector>,
    pub truncated_hash: Vec<TruncatedHashVector>,
}

pub fn load() -> HashesVectors {
    let json = include_str!("../../../.test-vectors/hashes.json");
    serde_json::from_str(json).expect("Failed to deserialize hashes.json")
}
