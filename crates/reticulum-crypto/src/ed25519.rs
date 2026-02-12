//! Ed25519 digital signature operations.
//!
//! Provides key generation, signing, and verification using the Ed25519
//! signature scheme as required by the Reticulum protocol.

use crate::CryptoError;
use ed25519_dalek::{Signer, Verifier};

/// An Ed25519 private (signing) key wrapping the 32-byte seed.
#[derive(Debug)]
pub struct Ed25519PrivateKey(ed25519_dalek::SigningKey);

impl Ed25519PrivateKey {
    /// Generate a new random Ed25519 private key using the OS random number generator.
    pub fn generate() -> Self {
        let mut csprng = rand::rngs::OsRng;
        Self(ed25519_dalek::SigningKey::generate(&mut csprng))
    }

    /// Create a private key from the raw 32-byte seed.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(ed25519_dalek::SigningKey::from_bytes(&bytes))
    }

    /// Derive the corresponding Ed25519 public key.
    pub fn public_key(&self) -> Ed25519PublicKey {
        Ed25519PublicKey(self.0.verifying_key())
    }

    /// Sign a message and return the 64-byte Ed25519 signature.
    pub fn sign(&self, message: &[u8]) -> Ed25519Signature {
        let sig = self.0.sign(message);
        Ed25519Signature(sig)
    }

    /// Extract the 32-byte seed bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

/// An Ed25519 public (verifying) key, the 32-byte compressed Edwards point.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ed25519PublicKey(ed25519_dalek::VerifyingKey);

impl Ed25519PublicKey {
    /// Create a public key from its 32-byte compressed Edwards point representation.
    ///
    /// Returns `CryptoError::InvalidKeyLength` if the bytes do not represent a
    /// valid point on the Ed25519 curve.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, CryptoError> {
        ed25519_dalek::VerifyingKey::from_bytes(&bytes)
            .map(Self)
            .map_err(|_| CryptoError::InvalidKeyLength {
                expected: 32,
                actual: 32,
            })
    }

    /// Verify an Ed25519 signature over a message.
    ///
    /// Returns `Ok(())` if the signature is valid, or `CryptoError::InvalidSignature`
    /// if verification fails.
    pub fn verify(&self, message: &[u8], signature: &Ed25519Signature) -> Result<(), CryptoError> {
        self.0
            .verify(message, &signature.0)
            .map_err(|_| CryptoError::InvalidSignature)
    }

    /// Extract the 32-byte compressed Edwards point representation.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

/// A 64-byte Ed25519 signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ed25519Signature(ed25519_dalek::Signature);

impl Ed25519Signature {
    /// Create a signature from raw 64-byte representation.
    pub fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(ed25519_dalek::Signature::from_bytes(&bytes))
    }

    /// Extract the raw 64-byte signature.
    pub fn to_bytes(&self) -> [u8; 64] {
        self.0.to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_to_32(hex_str: &str) -> [u8; 32] {
        let bytes = hex::decode(hex_str).expect("invalid hex");
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        arr
    }

    fn hex_to_64(hex_str: &str) -> [u8; 64] {
        let bytes = hex::decode(hex_str).expect("invalid hex");
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&bytes);
        arr
    }

    #[test]
    fn test_ed25519_public_key_derivation() {
        let vectors = reticulum_test_vectors::keypairs::load();
        for kp in &vectors.keypairs {
            let private_key = Ed25519PrivateKey::from_bytes(hex_to_32(&kp.ed25519_private));
            let public_key = private_key.public_key();
            let expected = hex_to_32(&kp.ed25519_public);
            assert_eq!(
                public_key.to_bytes(),
                expected,
                "public key mismatch for keypair index {}",
                kp.index
            );
        }
    }

    #[test]
    fn test_ed25519_signature_test() {
        let vectors = reticulum_test_vectors::keypairs::load();
        let st = &vectors.signature_test;

        // Find the keypair at the specified index
        let kp = vectors
            .keypairs
            .iter()
            .find(|k| k.index == st.keypair_index)
            .expect("keypair not found for signature_test");

        let private_key = Ed25519PrivateKey::from_bytes(hex_to_32(&kp.ed25519_private));

        // The message field is hex-encoded. The message_note clarifies that the decoded
        // content is a "UTF-8 encoding of hex string literal, NOT decoded hex bytes",
        // meaning: hex-decode the field to get ASCII hex chars, sign those chars as-is
        // (do NOT hex-decode them a second time).
        let message = hex::decode(&st.message).expect("invalid hex in signature_test message");
        let signature = private_key.sign(&message);

        let expected_sig = hex_to_64(&st.signature);
        assert_eq!(
            signature.to_bytes(),
            expected_sig,
            "signature mismatch for signature_test"
        );

        // Also verify the signature
        let public_key = private_key.public_key();
        public_key
            .verify(&message, &signature)
            .expect("signature verification failed for signature_test");
    }

    #[test]
    fn test_ed25519_signature_vectors() {
        let vectors = reticulum_test_vectors::keypairs::load();

        for sv in &vectors.signature_vectors {
            let kp = vectors
                .keypairs
                .iter()
                .find(|k| k.index == sv.keypair_index)
                .expect("keypair not found for signature_vector");

            let private_key = Ed25519PrivateKey::from_bytes(hex_to_32(&kp.ed25519_private));
            let public_key = private_key.public_key();

            // common_message is hex-encoded bytes
            let common_msg =
                hex::decode(&sv.common_message).expect("invalid hex in common_message");
            let common_sig = private_key.sign(&common_msg);
            let expected_common_sig = hex_to_64(&sv.common_signature);
            assert_eq!(
                common_sig.to_bytes(),
                expected_common_sig,
                "common_signature mismatch for keypair index {}",
                sv.keypair_index
            );
            public_key
                .verify(&common_msg, &common_sig)
                .expect("common_signature verification failed");

            // unique_message is hex-encoded bytes
            let unique_msg =
                hex::decode(&sv.unique_message).expect("invalid hex in unique_message");
            let unique_sig = private_key.sign(&unique_msg);
            let expected_unique_sig = hex_to_64(&sv.unique_signature);
            assert_eq!(
                unique_sig.to_bytes(),
                expected_unique_sig,
                "unique_signature mismatch for keypair index {}",
                sv.keypair_index
            );
            public_key
                .verify(&unique_msg, &unique_sig)
                .expect("unique_signature verification failed");
        }
    }

    #[test]
    fn test_ed25519_verify_invalid() {
        let private_key = Ed25519PrivateKey::generate();
        let public_key = private_key.public_key();

        let message = b"test message for verification";
        let signature = private_key.sign(message);

        // Verification of the original message should succeed
        public_key
            .verify(message, &signature)
            .expect("valid signature should verify");

        // Modify the message; verification must fail with InvalidSignature
        let modified_message = b"modified message for verification";
        let result = public_key.verify(modified_message, &signature);
        assert_eq!(result, Err(CryptoError::InvalidSignature));
    }

    #[test]
    fn test_ed25519_roundtrip() {
        let original = Ed25519PrivateKey::generate();
        let original_pub = original.public_key();
        let seed_bytes = original.to_bytes();

        // Reconstruct from seed bytes
        let restored = Ed25519PrivateKey::from_bytes(seed_bytes);
        let restored_pub = restored.public_key();

        assert_eq!(
            original_pub.to_bytes(),
            restored_pub.to_bytes(),
            "public key should be identical after from_bytes roundtrip"
        );

        // Roundtrip the public key through bytes
        let pub_bytes = original_pub.to_bytes();
        let restored_pub2 =
            Ed25519PublicKey::from_bytes(pub_bytes).expect("valid public key bytes");
        assert_eq!(original_pub, restored_pub2);

        // Verify that signing still works after roundtrip
        let message = b"roundtrip signing test";
        let sig = restored.sign(message);
        restored_pub
            .verify(message, &sig)
            .expect("signature from restored key should verify");
    }
}
