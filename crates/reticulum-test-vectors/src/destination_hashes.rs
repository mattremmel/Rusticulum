//! Test vector types for destination_hashes.json
//!
//! Destination hash derivation test vectors for SINGLE and PLAIN types.

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct SingleDestination {
    pub app_name: String,
    pub aspects: Vec<String>,
    pub base_name: String,
    #[serde(default)]
    pub base_name_note: Option<String>,
    pub full_name: String,
    #[serde(default)]
    pub full_name_note: Option<String>,
    pub name_hash: String,
    pub name_hash_length_bytes: u64,
    pub identity_hash: String,
    pub addr_hash_material: String,
    pub addr_hash_material_length_bytes: u64,
    pub destination_hash: String,
    pub keypair_index: u64,
}

#[derive(Debug, Deserialize)]
pub struct PlainDestination {
    pub app_name: String,
    pub aspects: Vec<String>,
    pub base_name: String,
    pub name_hash: String,
    pub name_hash_length_bytes: u64,
    pub identity_hash: Option<String>,
    pub addr_hash_material: String,
    pub addr_hash_material_length_bytes: u64,
    pub destination_hash: String,
    pub note: String,
}

#[derive(Debug, Deserialize)]
pub struct DestinationHashesVectors {
    pub description: String,
    pub source: String,
    pub constants: serde_json::Value,
    pub algorithm: serde_json::Value,
    pub single_destinations: Vec<SingleDestination>,
    pub plain_destinations: Vec<PlainDestination>,
}

pub fn load() -> DestinationHashesVectors {
    let json = include_str!("../../../.test-vectors/destination_hashes.json");
    serde_json::from_str(json).expect("Failed to deserialize destination_hashes.json")
}
