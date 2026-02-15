//! Identity key management and cryptographic operations.
//!
//! An [`Identity`] represents a Reticulum network identity, consisting of an
//! X25519 key pair (for encryption/key exchange) and an Ed25519 key pair (for
//! signing). The identity hash is `SHA-256(x25519_pub || ed25519_pub)[:16]`.

extern crate alloc;
use alloc::vec::Vec;

use reticulum_crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature};
use reticulum_crypto::hkdf::hkdf;
use reticulum_crypto::sha::sha256;
use reticulum_crypto::token::Token;
use reticulum_crypto::x25519::{X25519PrivateKey, X25519PublicKey};

use crate::error::IdentityError;
use crate::types::IdentityHash;

/// A Reticulum network identity with optional private keys.
///
/// A full identity (with private keys) can sign, decrypt, and create announces.
/// A public-only identity can verify signatures and encrypt messages to the holder.
#[must_use]
pub struct Identity {
    x25519_private: Option<X25519PrivateKey>,
    ed25519_private: Option<Ed25519PrivateKey>,
    x25519_public: X25519PublicKey,
    ed25519_public: Ed25519PublicKey,
    hash: IdentityHash,
}

impl Identity {
    /// Generate a new random identity with both key pairs.
    pub fn generate() -> Self {
        let x25519_private = X25519PrivateKey::generate();
        let ed25519_private = Ed25519PrivateKey::generate();
        let x25519_public = x25519_private.public_key();
        let ed25519_public = ed25519_private.public_key();
        let hash = compute_hash(&x25519_public, &ed25519_public);

        Identity {
            x25519_private: Some(x25519_private),
            ed25519_private: Some(ed25519_private),
            x25519_public,
            ed25519_public,
            hash,
        }
    }

    /// Create an identity from 64 raw private key bytes.
    ///
    /// Layout: `x25519_private(32) || ed25519_private(32)`
    pub fn from_private_bytes(bytes: &[u8; 64]) -> Self {
        let mut x25519_bytes = [0u8; 32];
        let mut ed25519_bytes = [0u8; 32];
        x25519_bytes.copy_from_slice(&bytes[..32]);
        ed25519_bytes.copy_from_slice(&bytes[32..]);

        let x25519_private = X25519PrivateKey::from_bytes(x25519_bytes);
        let ed25519_private = Ed25519PrivateKey::from_bytes(ed25519_bytes);
        let x25519_public = x25519_private.public_key();
        let ed25519_public = ed25519_private.public_key();
        let hash = compute_hash(&x25519_public, &ed25519_public);

        Identity {
            x25519_private: Some(x25519_private),
            ed25519_private: Some(ed25519_private),
            x25519_public,
            ed25519_public,
            hash,
        }
    }

    /// Create a public-only identity from 64 raw public key bytes.
    ///
    /// Layout: `x25519_public(32) || ed25519_public(32)`
    pub fn from_public_bytes(bytes: &[u8; 64]) -> Result<Self, IdentityError> {
        let mut x25519_bytes = [0u8; 32];
        let mut ed25519_bytes = [0u8; 32];
        x25519_bytes.copy_from_slice(&bytes[..32]);
        ed25519_bytes.copy_from_slice(&bytes[32..]);

        let x25519_public = X25519PublicKey::from_bytes(x25519_bytes);
        let ed25519_public =
            Ed25519PublicKey::from_bytes(ed25519_bytes).map_err(IdentityError::CryptoError)?;
        let hash = compute_hash(&x25519_public, &ed25519_public);

        Ok(Identity {
            x25519_private: None,
            ed25519_private: None,
            x25519_public,
            ed25519_public,
            hash,
        })
    }

    /// Whether this identity has private keys (i.e., can sign and decrypt).
    #[must_use = "returns a bool without side effects"]
    pub fn has_private_key(&self) -> bool {
        self.x25519_private.is_some() && self.ed25519_private.is_some()
    }

    /// Get the 64 raw private key bytes: `x25519_private(32) || ed25519_private(32)`.
    ///
    /// Returns `None` for public-only identities.
    #[must_use = "returns the private key bytes without side effects"]
    pub fn private_key_bytes(&self) -> Option<[u8; 64]> {
        let x25519_prv = self.x25519_private.as_ref()?;
        let ed25519_prv = self.ed25519_private.as_ref()?;
        let mut result = [0u8; 64];
        result[..32].copy_from_slice(&x25519_prv.to_bytes());
        result[32..].copy_from_slice(&ed25519_prv.to_bytes());
        Some(result)
    }

    /// Get the 64-byte combined public key: `x25519_public(32) || ed25519_public(32)`.
    #[must_use = "returns the public key bytes without side effects"]
    pub fn public_key_bytes(&self) -> [u8; 64] {
        let mut result = [0u8; 64];
        result[..32].copy_from_slice(&self.x25519_public.to_bytes());
        result[32..].copy_from_slice(&self.ed25519_public.to_bytes());
        result
    }

    /// Get the 16-byte identity hash.
    #[must_use = "returns the identity hash without side effects"]
    pub fn hash(&self) -> &IdentityHash {
        &self.hash
    }

    /// Get the Ed25519 public key.
    #[must_use = "returns the public key without side effects"]
    pub fn ed25519_public(&self) -> &Ed25519PublicKey {
        &self.ed25519_public
    }

    /// Get the Ed25519 private key, if available.
    pub fn ed25519_private(&self) -> Option<&Ed25519PrivateKey> {
        self.ed25519_private.as_ref()
    }

    /// Get the X25519 public key.
    #[must_use = "returns the public key without side effects"]
    pub fn x25519_public(&self) -> &X25519PublicKey {
        &self.x25519_public
    }

    /// Get the X25519 private key, if available.
    pub fn x25519_private(&self) -> Option<&X25519PrivateKey> {
        self.x25519_private.as_ref()
    }

    /// Sign data with the Ed25519 private key.
    #[must_use = "signing may fail; check the Result"]
    pub fn sign(&self, data: &[u8]) -> Result<Ed25519Signature, IdentityError> {
        let key = self
            .ed25519_private
            .as_ref()
            .ok_or(IdentityError::NoPrivateKey)?;
        Ok(key.sign(data))
    }

    /// Verify an Ed25519 signature.
    #[must_use = "verification may fail; check the Result"]
    pub fn verify(&self, data: &[u8], signature: &Ed25519Signature) -> Result<(), IdentityError> {
        self.ed25519_public
            .verify(data, signature)
            .map_err(|_| IdentityError::SignatureVerificationFailed)
    }

    /// Encrypt data to this identity using envelope encryption.
    ///
    /// Uses a random ephemeral X25519 keypair. Output format:
    /// `ephemeral_public(32) || Token(IV(16) || ciphertext || HMAC(32))`
    #[must_use = "returns the ciphertext without modifying the identity"]
    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let ephemeral = X25519PrivateKey::generate();
        self.encrypt_with_ephemeral(plaintext, &ephemeral)
    }

    /// Encrypt with a specific ephemeral key (for deterministic testing).
    pub fn encrypt_with_ephemeral(
        &self,
        plaintext: &[u8],
        ephemeral: &X25519PrivateKey,
    ) -> Vec<u8> {
        let ephemeral_public = ephemeral.public_key();
        let shared_secret = ephemeral.diffie_hellman(&self.x25519_public);
        let derived = hkdf(64, &shared_secret, Some(self.hash.as_ref()), None);
        // SAFETY: hkdf(64, ...) always returns exactly 64 bytes.
        let key: [u8; 64] = derived.try_into().expect("HKDF always returns 64 bytes");
        let token = Token::new(&key);
        let fernet_token = token.encrypt(plaintext);

        let mut result = Vec::with_capacity(32 + fernet_token.len());
        result.extend_from_slice(&ephemeral_public.to_bytes());
        result.extend_from_slice(&fernet_token);
        result
    }

    /// Decrypt data that was encrypted to this identity.
    ///
    /// Requires the X25519 private key. Input format:
    /// `ephemeral_public(32) || Token(IV(16) || ciphertext || HMAC(32))`
    #[must_use = "decryption may fail; check the Result"]
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, IdentityError> {
        let x25519_prv = self
            .x25519_private
            .as_ref()
            .ok_or(IdentityError::NoPrivateKey)?;

        if ciphertext.len() < 32 + 48 {
            // 32 (ephemeral pub) + 16 (IV) + 0 (min ciphertext) + 32 (HMAC)
            return Err(IdentityError::PayloadTooShort {
                min: 80,
                actual: ciphertext.len(),
            });
        }

        let ephemeral_pub_bytes: [u8; 32] = ciphertext[..32]
            .try_into()
            .map_err(|_| IdentityError::DecryptionFailed)?;
        let ephemeral_public = X25519PublicKey::from_bytes(ephemeral_pub_bytes);
        let fernet_data = &ciphertext[32..];

        let shared_secret = x25519_prv.diffie_hellman(&ephemeral_public);
        let derived = hkdf(64, &shared_secret, Some(self.hash.as_ref()), None);
        let key: [u8; 64] = derived
            .try_into()
            .map_err(|_| IdentityError::DecryptionFailed)?;
        let token = Token::new(&key);

        token
            .decrypt(fernet_data)
            .map_err(|_| IdentityError::DecryptionFailed)
    }
}

fn compute_hash(x25519_pub: &X25519PublicKey, ed25519_pub: &Ed25519PublicKey) -> IdentityHash {
    let mut key_data = [0u8; 64];
    key_data[..32].copy_from_slice(&x25519_pub.to_bytes());
    key_data[32..].copy_from_slice(&ed25519_pub.to_bytes());
    let full_hash = sha256(&key_data);
    let mut truncated = [0u8; 16];
    truncated.copy_from_slice(&full_hash[..16]);
    IdentityHash::new(truncated)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_to_32(hex_str: &str) -> [u8; 32] {
        hex::decode(hex_str)
            .expect("invalid hex")
            .try_into()
            .expect("must be 32 bytes")
    }

    fn hex_to_64(hex_str: &str) -> [u8; 64] {
        hex::decode(hex_str)
            .expect("invalid hex")
            .try_into()
            .expect("must be 64 bytes")
    }

    #[test]
    fn test_private_key_bytes_roundtrip() {
        let identity = Identity::generate();
        assert!(identity.has_private_key());

        let prv_bytes = identity.private_key_bytes().unwrap();
        let restored = Identity::from_private_bytes(&prv_bytes);

        assert_eq!(identity.hash().as_ref(), restored.hash().as_ref());
        assert_eq!(identity.public_key_bytes(), restored.public_key_bytes());
    }

    #[test]
    fn test_private_key_bytes_public_only_returns_none() {
        let identity = Identity::generate();
        let public_only = Identity::from_public_bytes(&identity.public_key_bytes()).unwrap();

        assert!(!public_only.has_private_key());
        assert!(public_only.private_key_bytes().is_none());
    }

    #[test]
    fn test_identity_from_private_bytes() {
        let v = reticulum_test_vectors::keypairs::load();

        for kp in &v.keypairs {
            let private_key = hex_to_64(&kp.private_key);
            let identity = Identity::from_private_bytes(&private_key);

            // Verify public key
            let expected_public = hex_to_64(&kp.public_key);
            assert_eq!(
                identity.public_key_bytes(),
                expected_public,
                "public key mismatch for keypair {}",
                kp.index
            );

            // Verify identity hash
            let expected_hash = hex::decode(&kp.identity_hash).expect("invalid hex identity_hash");
            assert_eq!(
                identity.hash().as_ref(),
                expected_hash.as_slice(),
                "identity hash mismatch for keypair {}",
                kp.index
            );
        }
    }

    #[test]
    fn test_identity_from_public_bytes() {
        let v = reticulum_test_vectors::keypairs::load();

        for kp in &v.keypairs {
            let public_key = hex_to_64(&kp.public_key);
            let identity = Identity::from_public_bytes(&public_key).unwrap();

            // Verify hash matches
            let expected_hash = hex::decode(&kp.identity_hash).expect("invalid hex identity_hash");
            assert_eq!(
                identity.hash().as_ref(),
                expected_hash.as_slice(),
                "identity hash mismatch for keypair {}",
                kp.index
            );

            // No private keys
            assert!(identity.sign(b"test").is_err());
        }
    }

    #[test]
    fn test_identity_sign_verify() {
        let v = reticulum_test_vectors::keypairs::load();

        for sv in &v.signature_vectors {
            let kp = v
                .keypairs
                .iter()
                .find(|k| k.index == sv.keypair_index)
                .unwrap();

            let identity = Identity::from_private_bytes(&hex_to_64(&kp.private_key));

            // Sign common message
            let common_msg = hex::decode(&sv.common_message).unwrap();
            let sig = identity.sign(&common_msg).unwrap();
            let expected_sig = hex_to_64(&sv.common_signature);
            assert_eq!(
                sig.to_bytes(),
                expected_sig,
                "common signature mismatch for keypair {}",
                sv.keypair_index
            );

            // Verify
            identity.verify(&common_msg, &sig).unwrap();

            // Sign unique message
            let unique_msg = hex::decode(&sv.unique_message).unwrap();
            let sig2 = identity.sign(&unique_msg).unwrap();
            let expected_sig2 = hex_to_64(&sv.unique_signature);
            assert_eq!(sig2.to_bytes(), expected_sig2);
            identity.verify(&unique_msg, &sig2).unwrap();
        }
    }

    #[test]
    fn test_identity_decrypt() {
        let v = reticulum_test_vectors::keypairs::load();
        let et = &v.encryption_test;

        let kp = v
            .keypairs
            .iter()
            .find(|k| k.index == et.keypair_index)
            .unwrap();

        let identity = Identity::from_private_bytes(&hex_to_64(&kp.private_key));

        let ciphertext = hex::decode(&et.ciphertext_token).unwrap();
        let expected_plaintext = hex::decode(&et.plaintext).unwrap();

        let decrypted = identity.decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted, expected_plaintext, "decryption mismatch");
    }

    #[test]
    fn test_identity_encrypt_decrypt_roundtrip() {
        let identity = Identity::generate();

        let plaintext = b"Hello, Reticulum! This is a test message for roundtrip encryption.";
        let ciphertext = identity.encrypt(plaintext);

        let decrypted = identity.decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_identity_encrypt_decrypt_empty() {
        let identity = Identity::generate();
        let ciphertext = identity.encrypt(b"");
        let decrypted = identity.decrypt(&ciphertext).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_identity_decrypt_no_private_key() {
        let identity = Identity::generate();
        let public_only = Identity::from_public_bytes(&identity.public_key_bytes()).unwrap();

        let ciphertext = identity.encrypt(b"test");
        assert!(public_only.decrypt(&ciphertext).is_err());
    }

    #[test]
    fn test_identity_verify_with_public_only() {
        let v = reticulum_test_vectors::keypairs::load();
        let kp = &v.keypairs[0];

        let full_identity = Identity::from_private_bytes(&hex_to_64(&kp.private_key));
        let public_identity = Identity::from_public_bytes(&hex_to_64(&kp.public_key)).unwrap();

        let message = b"verification test";
        let sig = full_identity.sign(message).unwrap();

        // Public-only identity can verify
        public_identity.verify(message, &sig).unwrap();
    }

    #[test]
    fn test_ephemeral_key_structure() {
        let v = reticulum_test_vectors::keypairs::load();
        let et = &v.encryption_test;

        let ciphertext = hex::decode(&et.ciphertext_token).unwrap();
        let expected_eph_pub = hex_to_32(&et.ephemeral_public_key);
        let expected_fernet = hex::decode(&et.fernet_token).unwrap();

        // First 32 bytes are the ephemeral public key
        assert_eq!(&ciphertext[..32], &expected_eph_pub);
        // Rest is the fernet token
        assert_eq!(&ciphertext[32..], expected_fernet.as_slice());
    }

    #[test]
    fn test_identity_malformed_decrypt_truncated() {
        let identity = Identity::generate();
        // Various lengths below the minimum (80 bytes)
        for &len in &[0usize, 1, 31, 32, 48, 79] {
            let data = vec![0xAA; len];
            let result = identity.decrypt(&data);
            assert!(
                matches!(result, Err(IdentityError::PayloadTooShort { .. })),
                "len={len} should return PayloadTooShort, got: {result:?}"
            );
        }
    }

    #[test]
    fn test_identity_malformed_decrypt_exactly_minimum() {
        let identity = Identity::generate();
        // Exactly 80 random bytes: ephemeral_pub(32) + IV(16) + HMAC(32)
        let data = vec![0xBB; 80];
        let result = identity.decrypt(&data);
        // HMAC won't match → DecryptionFailed (not panic)
        assert!(result.is_err());
    }

    #[test]
    fn test_identity_malformed_decrypt_corrupted_ephemeral() {
        let identity = Identity::generate();
        let plaintext = b"ephemeral corruption test";
        let mut ciphertext = identity.encrypt(plaintext);
        // Corrupt the first 32 bytes (ephemeral public key)
        for byte in ciphertext[..32].iter_mut() {
            *byte ^= 0xFF;
        }
        let result = identity.decrypt(&ciphertext);
        assert!(
            result.is_err(),
            "corrupted ephemeral key should fail decrypt"
        );
    }

    #[test]
    fn test_identity_adversarial_cross_identity_decrypt() {
        let identity_a = Identity::generate();
        let identity_b = Identity::generate();
        let plaintext = b"cross identity decrypt test";
        let ciphertext = identity_a.encrypt(plaintext);
        let result = identity_b.decrypt(&ciphertext);
        assert!(result.is_err(), "decrypt with wrong identity should fail");
    }

    #[test]
    fn test_identity_adversarial_decrypt_garbage() {
        let identity = Identity::generate();
        let garbage = vec![0xDE; 128];
        let result = identity.decrypt(&garbage);
        assert!(result.is_err(), "garbage data should fail decrypt");
    }

    #[test]
    fn test_identity_malformed_invalid_ed25519_in_public_bytes() {
        // ed25519 portion (bytes 32..64) all-zero
        let mut pubkey_bytes = [0u8; 64];
        // x25519 portion can be anything valid
        pubkey_bytes[..32].copy_from_slice(&[0x01; 32]);
        // ed25519 portion all-zero
        pubkey_bytes[32..64].fill(0);
        let result = Identity::from_public_bytes(&pubkey_bytes);
        // All-zero may or may not be valid for ed25519-dalek. Either error or success is OK.
        // The key thing is no panic.
        match result {
            Err(IdentityError::CryptoError(_)) => {} // expected
            Ok(_) => {} // also acceptable — dalek may accept identity point
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    #[test]
    fn test_identity_malformed_non_curve_ed25519_in_public_bytes() {
        let mut pubkey_bytes = [0u8; 64];
        pubkey_bytes[..32].copy_from_slice(&[0x01; 32]);
        // ed25519 portion all-0xFF — likely not a valid curve point
        pubkey_bytes[32..64].fill(0xFF);
        let result = Identity::from_public_bytes(&pubkey_bytes);
        // Either error (likely) or success, no panic is the requirement
        match result {
            Err(IdentityError::CryptoError(_)) => {} // expected
            Ok(_) => {}                              // also acceptable
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    #[test]
    fn test_identity_malformed_sign_public_only_explicit() {
        let identity = Identity::generate();
        let public_only = Identity::from_public_bytes(&identity.public_key_bytes()).unwrap();
        let result = public_only.sign(b"should fail");
        assert!(
            matches!(result, Err(IdentityError::NoPrivateKey)),
            "public-only identity should return NoPrivateKey"
        );
    }
}
