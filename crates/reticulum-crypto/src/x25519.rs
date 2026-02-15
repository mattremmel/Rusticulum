//! X25519 Diffie-Hellman key exchange.
//!
//! Provides [`X25519PrivateKey`] and [`X25519PublicKey`] newtypes wrapping the
//! `x25519-dalek` primitives. These are used throughout Reticulum for link
//! establishment, identity key exchange, and ephemeral DH during encryption.

use x25519_dalek::{PublicKey, StaticSecret};

/// An X25519 private key (Curve25519 scalar).
///
/// Wraps [`x25519_dalek::StaticSecret`]. The underlying library applies
/// clamping internally when the key is used, so raw bytes are stored as-is.
pub struct X25519PrivateKey(StaticSecret);

impl X25519PrivateKey {
    /// Generate a random X25519 private key using the OS CSPRNG.
    #[must_use]
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        Self(secret)
    }

    /// Create an X25519 private key from raw bytes.
    ///
    /// The `x25519-dalek` library applies Curve25519 clamping internally when
    /// the key is used for scalar multiplication, so the bytes are accepted
    /// as-is without pre-processing.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(StaticSecret::from(bytes))
    }

    /// Derive the corresponding X25519 public key.
    #[must_use]
    pub fn public_key(&self) -> X25519PublicKey {
        X25519PublicKey(PublicKey::from(&self.0))
    }

    /// Perform X25519 Diffie-Hellman key exchange with another party's public key.
    ///
    /// Returns the 32-byte shared secret. Both sides computing
    /// `a.diffie_hellman(&B)` and `b.diffie_hellman(&A)` will arrive at the
    /// same shared secret.
    #[must_use]
    pub fn diffie_hellman(&self, their_public: &X25519PublicKey) -> [u8; 32] {
        *self.0.diffie_hellman(&their_public.0).as_bytes()
    }

    /// Extract the raw 32-byte private key material.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

/// An X25519 public key (Curve25519 group element).
///
/// Wraps [`x25519_dalek::PublicKey`]. Implements `Clone`, `Debug`,
/// `PartialEq`, and `Eq` for convenient use in protocol structures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X25519PublicKey(PublicKey);

impl X25519PublicKey {
    /// Create an X25519 public key from raw bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(PublicKey::from(bytes))
    }

    /// Extract the raw 32-byte public key.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        *self.0.as_bytes()
    }
}

impl From<[u8; 32]> for X25519PublicKey {
    fn from(bytes: [u8; 32]) -> Self {
        Self::from_bytes(bytes)
    }
}

impl AsRef<[u8]> for X25519PublicKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_x25519_public_key_derivation() {
        let vectors = reticulum_test_vectors::keypairs::load();

        for kp in &vectors.keypairs {
            let private_bytes: [u8; 32] = hex::decode(&kp.x25519_private)
                .expect("invalid hex in x25519_private")
                .try_into()
                .expect("x25519_private must be 32 bytes");

            let expected_public: [u8; 32] = hex::decode(&kp.x25519_public)
                .expect("invalid hex in x25519_public")
                .try_into()
                .expect("x25519_public must be 32 bytes");

            let private_key = X25519PrivateKey::from_bytes(private_bytes);
            let derived_public = private_key.public_key();

            assert_eq!(
                derived_public.to_bytes(),
                expected_public,
                "public key derivation mismatch for keypair index {}",
                kp.index
            );
        }
    }

    #[test]
    fn test_x25519_ecdh() {
        let vectors = reticulum_test_vectors::keypairs::load();

        for ecdh in &vectors.ecdh_vectors {
            // Find keypairs by index
            let kp_a = vectors
                .keypairs
                .iter()
                .find(|kp| kp.index == ecdh.keypair_a)
                .unwrap_or_else(|| panic!("keypair_a index {} not found", ecdh.keypair_a));
            let kp_b = vectors
                .keypairs
                .iter()
                .find(|kp| kp.index == ecdh.keypair_b)
                .unwrap_or_else(|| panic!("keypair_b index {} not found", ecdh.keypair_b));

            let private_a = X25519PrivateKey::from_bytes(
                hex::decode(&kp_a.x25519_private)
                    .expect("invalid hex")
                    .try_into()
                    .expect("must be 32 bytes"),
            );
            let private_b = X25519PrivateKey::from_bytes(
                hex::decode(&kp_b.x25519_private)
                    .expect("invalid hex")
                    .try_into()
                    .expect("must be 32 bytes"),
            );

            let public_a = private_a.public_key();
            let public_b = private_b.public_key();

            let expected_secret: [u8; 32] = hex::decode(&ecdh.shared_secret)
                .expect("invalid hex in shared_secret")
                .try_into()
                .expect("shared_secret must be 32 bytes");

            // a.dh(B) should match expected
            let secret_ab = private_a.diffie_hellman(&public_b);
            assert_eq!(
                secret_ab, expected_secret,
                "ECDH mismatch for a.dh(B): keypair_a={}, keypair_b={}",
                ecdh.keypair_a, ecdh.keypair_b
            );

            // b.dh(A) should match expected
            let secret_ba = private_b.diffie_hellman(&public_a);
            assert_eq!(
                secret_ba, expected_secret,
                "ECDH mismatch for b.dh(A): keypair_a={}, keypair_b={}",
                ecdh.keypair_a, ecdh.keypair_b
            );

            // Both directions must agree
            assert_eq!(
                secret_ab, secret_ba,
                "ECDH commutativity failure: keypair_a={}, keypair_b={}",
                ecdh.keypair_a, ecdh.keypair_b
            );
        }
    }

    #[test]
    fn test_ecdh_mismatched_keys_differ() {
        let key_a = X25519PrivateKey::from_bytes([0x01; 32]);
        let key_b = X25519PrivateKey::from_bytes([0x02; 32]);
        let key_c = X25519PrivateKey::from_bytes([0x03; 32]);
        let pub_c = key_c.public_key();

        let shared_ac = key_a.diffie_hellman(&pub_c);
        let shared_bc = key_b.diffie_hellman(&pub_c);
        assert_ne!(
            shared_ac, shared_bc,
            "DH with different private keys should yield different shared secrets"
        );
    }

    #[test]
    fn test_x25519_roundtrip() {
        let key = X25519PrivateKey::generate();
        let original_public = key.public_key();

        // Round-trip through bytes
        let bytes = key.to_bytes();
        let restored = X25519PrivateKey::from_bytes(bytes);
        let restored_public = restored.public_key();

        assert_eq!(
            original_public.to_bytes(),
            restored_public.to_bytes(),
            "public key mismatch after private key round-trip"
        );

        // Public key round-trip
        let pub_bytes = original_public.to_bytes();
        let restored_pub = X25519PublicKey::from_bytes(pub_bytes);
        assert_eq!(
            original_public, restored_pub,
            "public key mismatch after public key round-trip"
        );
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn dh_symmetry(seed_a in any::<[u8; 32]>(), seed_b in any::<[u8; 32]>()) {
            let key_a = X25519PrivateKey::from_bytes(seed_a);
            let key_b = X25519PrivateKey::from_bytes(seed_b);
            let pub_a = key_a.public_key();
            let pub_b = key_b.public_key();
            prop_assert_eq!(key_a.diffie_hellman(&pub_b), key_b.diffie_hellman(&pub_a));
        }
    }
}
