//! Test vector types for keypairs.json
//!
//! Fixed keypair, signature, ECDH, and encryption test vectors.

use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Deserialize)]
pub struct Keypair {
    pub index: u64,
    pub private_key: String,
    pub x25519_private: String,
    pub ed25519_private: String,
    pub public_key: String,
    pub x25519_public: String,
    pub ed25519_public: String,
    pub identity_hash: String,
    pub destination_hashes: HashMap<String, String>,
}

#[derive(Debug, Deserialize)]
pub struct SignatureTest {
    pub keypair_index: u64,
    pub message: String,
    pub message_note: String,
    pub signature: String,
}

#[derive(Debug, Deserialize)]
pub struct SignatureVector {
    pub keypair_index: u64,
    pub common_message: String,
    pub common_signature: String,
    pub unique_message: String,
    pub unique_message_utf8: String,
    pub unique_signature: String,
}

#[derive(Debug, Deserialize)]
pub struct EcdhVector {
    pub keypair_a: u64,
    pub keypair_b: u64,
    pub shared_secret: String,
    pub shared_secret_length: u64,
}

#[derive(Debug, Deserialize)]
pub struct EncryptionTest {
    pub keypair_index: u64,
    pub plaintext: String,
    pub ciphertext_token: String,
    pub ephemeral_public_key: String,
    pub fernet_token: String,
    pub note: String,
}

#[derive(Debug, Deserialize)]
pub struct KeypairsVectors {
    pub description: String,
    pub source: String,
    pub constants: serde_json::Value,
    pub keypairs: Vec<Keypair>,
    pub signature_test: SignatureTest,
    pub signature_vectors: Vec<SignatureVector>,
    pub ecdh_vectors: Vec<EcdhVector>,
    pub encryption_test: EncryptionTest,
}

pub fn load() -> KeypairsVectors {
    let json = include_str!("../../../.test-vectors/keypairs.json");
    serde_json::from_str(json).expect("Failed to deserialize keypairs.json")
}
