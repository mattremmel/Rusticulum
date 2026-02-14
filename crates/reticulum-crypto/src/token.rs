//! Modified Fernet token encryption.
//!
//! Implements the Reticulum protocol's modified Fernet token format, which
//! differs from standard Fernet by omitting the VERSION and TIMESTAMP fields.
//!
//! # Token layout
//!
//! ```text
//! [IV: 16 bytes] || [Ciphertext: variable] || [HMAC-SHA256: 32 bytes]
//! ```
//!
//! # Key split
//!
//! A 64-byte key is split as:
//! - `signing_key = key[0..32]` (first 32 bytes) -- used for HMAC
//! - `encryption_key = key[32..64]` (last 32 bytes) -- used for AES-256-CBC

extern crate alloc;
use alloc::vec::Vec;

use crate::CryptoError;

/// Modified Fernet token for authenticated symmetric encryption.
///
/// Holds a 64-byte key split into a signing key (HMAC-SHA256) and an
/// encryption key (AES-256-CBC).
pub struct Token {
    signing_key: [u8; 32],
    encryption_key: [u8; 32],
}

impl Token {
    /// Create a new `Token` from a 64-byte key.
    ///
    /// The key is split as:
    /// - `key[0..32]` = signing key (HMAC-SHA256)
    /// - `key[32..64]` = encryption key (AES-256-CBC)
    pub fn new(key: &[u8; 64]) -> Self {
        let mut signing_key = [0u8; 32];
        let mut encryption_key = [0u8; 32];
        signing_key.copy_from_slice(&key[..32]);
        encryption_key.copy_from_slice(&key[32..]);
        Self {
            signing_key,
            encryption_key,
        }
    }

    /// Encrypt `plaintext` with a randomly generated IV.
    ///
    /// Returns the complete token: `IV || ciphertext || HMAC`.
    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        use rand::Rng;
        let mut iv = [0u8; 16];
        rand::rngs::OsRng.fill(&mut iv);
        self.encrypt_with_iv(plaintext, &iv)
    }

    /// Encrypt `plaintext` with a specific IV (for deterministic testing).
    ///
    /// Returns the complete token: `IV || ciphertext || HMAC`.
    pub fn encrypt_with_iv(&self, plaintext: &[u8], iv: &[u8; 16]) -> Vec<u8> {
        let ciphertext = crate::aes_cbc::aes256_cbc_encrypt(&self.encryption_key, iv, plaintext);

        // signed_parts = IV || ciphertext
        let mut signed_parts = Vec::with_capacity(16 + ciphertext.len());
        signed_parts.extend_from_slice(iv);
        signed_parts.extend_from_slice(&ciphertext);

        let hmac = crate::hmac::hmac_sha256(&self.signing_key, &signed_parts);

        // token = signed_parts || hmac = IV || ciphertext || hmac
        let mut token = signed_parts;
        token.extend_from_slice(&hmac);
        token
    }

    /// Decrypt a token, verifying the HMAC and returning the original plaintext.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidLength`] if the token is too short,
    /// [`CryptoError::InvalidHmac`] if the HMAC does not match, or a
    /// decryption/padding error from the underlying AES-CBC layer.
    pub fn decrypt(&self, token_data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // Minimum: 16 (IV) + 16 (at least 1 AES block) + 32 (HMAC) = 64
        // But we first check we can at least split into signed_parts + HMAC (48 bytes).
        if token_data.len() < 48 {
            return Err(CryptoError::InvalidLength {
                reason: "token too short: need at least 48 bytes (16 IV + 0 ciphertext + 32 HMAC)",
            });
        }

        let len = token_data.len();
        let signed_parts = &token_data[..len - 32];
        let received_hmac = &token_data[len - 32..];

        // Verify HMAC
        let computed_hmac = crate::hmac::hmac_sha256(&self.signing_key, signed_parts);
        if computed_hmac.as_slice() != received_hmac {
            return Err(CryptoError::InvalidHmac);
        }

        // Split signed_parts into IV and ciphertext
        let iv: [u8; 16] = signed_parts[..16]
            .try_into()
            .expect("signed_parts is at least 16 bytes");
        let ciphertext = &signed_parts[16..];

        // Decrypt (aes256_cbc_decrypt handles the empty/non-aligned ciphertext check)
        crate::aes_cbc::aes256_cbc_decrypt(&self.encryption_key, &iv, ciphertext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_key_split() {
        let vectors = reticulum_test_vectors::token::load();

        for v in &vectors.deterministic_fernet_vectors {
            let full_key: [u8; 64] = hex::decode(&v.key)
                .expect("invalid hex key")
                .try_into()
                .expect("key must be 64 bytes");

            let token = Token::new(&full_key);

            let expected_signing_key =
                hex::decode(&v.key_split.signing_key).expect("invalid hex signing_key");
            let expected_encryption_key =
                hex::decode(&v.key_split.encryption_key).expect("invalid hex encryption_key");

            assert_eq!(
                token.signing_key.as_slice(),
                expected_signing_key.as_slice(),
                "signing_key mismatch for: {}",
                v.description
            );
            assert_eq!(
                token.encryption_key.as_slice(),
                expected_encryption_key.as_slice(),
                "encryption_key mismatch for: {}",
                v.description
            );
        }
    }

    #[test]
    fn test_token_encrypt_deterministic() {
        let vectors = reticulum_test_vectors::token::load();

        for v in &vectors.deterministic_fernet_vectors {
            let full_key: [u8; 64] = hex::decode(&v.key)
                .expect("invalid hex key")
                .try_into()
                .expect("key must be 64 bytes");
            let iv: [u8; 16] = hex::decode(&v.iv)
                .expect("invalid hex iv")
                .try_into()
                .expect("iv must be 16 bytes");
            let plaintext = hex::decode(&v.plaintext).expect("invalid hex plaintext");
            let expected_token = hex::decode(&v.token).expect("invalid hex token");

            let token = Token::new(&full_key);
            let result = token.encrypt_with_iv(&plaintext, &iv);

            assert_eq!(
                result, expected_token,
                "token encrypt mismatch for: {}",
                v.description
            );
        }
    }

    #[test]
    fn test_token_decrypt_deterministic() {
        let vectors = reticulum_test_vectors::token::load();

        for v in &vectors.deterministic_fernet_vectors {
            let full_key: [u8; 64] = hex::decode(&v.key)
                .expect("invalid hex key")
                .try_into()
                .expect("key must be 64 bytes");
            let token_bytes = hex::decode(&v.token).expect("invalid hex token");
            let expected_plaintext = hex::decode(&v.plaintext).expect("invalid hex plaintext");

            let token = Token::new(&full_key);
            let result = token
                .decrypt(&token_bytes)
                .expect("decryption should succeed");

            assert_eq!(
                result, expected_plaintext,
                "token decrypt mismatch for: {}",
                v.description
            );
        }
    }

    #[test]
    fn test_token_fixed_decomposition() {
        let vectors = reticulum_test_vectors::token::load();
        let decomp = &vectors.fixed_token_decomposition;

        let fixed_token_full = hex::decode(&decomp.fixed_token).expect("invalid hex fixed_token");

        // Verify the total length matches the expected value.
        assert_eq!(
            fixed_token_full.len() as u64,
            decomp.total_length,
            "total length mismatch"
        );

        // The fixed_token layout is: ephemeral_public_key (32 bytes) || fernet_token (176 bytes)
        // Verify we can extract the structural components from the layout.
        let layout = &decomp.layout;
        let eph_key_info = &layout.ephemeral_public_key;
        let fernet_info = &layout.fernet_token;

        let eph_offset = eph_key_info.offset as usize;
        let eph_len = eph_key_info.length as usize;
        let fernet_offset = fernet_info.offset as usize;
        let fernet_len = fernet_info.length as usize;

        // Check structural consistency
        assert_eq!(eph_offset, 0);
        assert_eq!(eph_len, 32);
        assert_eq!(fernet_offset, 32);
        assert_eq!(eph_len + fernet_len, fixed_token_full.len());

        // Verify the ephemeral public key hex matches
        let actual_eph = &fixed_token_full[eph_offset..eph_offset + eph_len];
        assert_eq!(
            hex::encode(actual_eph),
            eph_key_info.value,
            "ephemeral public key mismatch"
        );

        // Verify the fernet_token hex matches
        let actual_fernet = &fixed_token_full[fernet_offset..fernet_offset + fernet_len];
        assert_eq!(
            hex::encode(actual_fernet),
            fernet_info.value,
            "fernet token value mismatch"
        );

        // Verify the fernet token sub-components (iv, ciphertext, hmac)
        let components = fernet_info.components.as_ref().unwrap();
        let iv_info = &components.iv;
        let ct_info = &components.ciphertext;
        let hmac_info = &components.hmac;

        let iv_offset = iv_info.offset as usize;
        let iv_len = iv_info.length as usize;
        let ct_offset = ct_info.offset as usize;
        let ct_len = ct_info.length as usize;
        let hmac_offset = hmac_info.offset as usize;
        let hmac_len = hmac_info.length as usize;

        // IV + ciphertext + HMAC should equal fernet_len
        assert_eq!(iv_len + ct_len + hmac_len, fernet_len);
        assert_eq!(iv_offset, 0);
        assert_eq!(ct_offset, iv_len);
        assert_eq!(hmac_offset, iv_len + ct_len);
        assert_eq!(iv_len, 16);
        assert_eq!(hmac_len, 32);
        // Ciphertext must be a multiple of 16 (AES block size)
        assert_eq!(ct_len % 16, 0);

        // Verify sub-component hex values match the fernet token bytes
        assert_eq!(
            hex::encode(&actual_fernet[iv_offset..iv_offset + iv_len]),
            iv_info.value,
        );
        assert_eq!(
            hex::encode(&actual_fernet[ct_offset..ct_offset + ct_len]),
            ct_info.value,
        );
        assert_eq!(
            hex::encode(&actual_fernet[hmac_offset..hmac_offset + hmac_len]),
            hmac_info.value,
        );
    }

    #[test]
    fn test_token_roundtrip() {
        let key: [u8; 64] = [0x55; 64];
        let token = Token::new(&key);

        for size in [0, 1, 7, 15, 16, 17, 31, 32, 33, 100, 255, 256] {
            let data: Vec<u8> = (0..size).map(|i| (i & 0xFF) as u8).collect();
            let encrypted = token.encrypt(&data);

            // Token must be: 16 (IV) + padded_ciphertext + 32 (HMAC)
            assert!(
                encrypted.len() >= 64,
                "token too short for size {size}: got {} bytes",
                encrypted.len()
            );

            let decrypted = token
                .decrypt(&encrypted)
                .expect("roundtrip decryption should succeed");
            assert_eq!(decrypted, data, "roundtrip mismatch for size {size}");
        }
    }

    #[test]
    fn test_token_decrypt_invalid_hmac() {
        let key: [u8; 64] = [0x55; 64];
        let token = Token::new(&key);

        let plaintext = b"test data for HMAC verification";
        let mut encrypted = token.encrypt(plaintext);

        // Flip a byte in the ciphertext portion (between IV and HMAC) to
        // invalidate the HMAC without changing the HMAC bytes themselves.
        let mid = encrypted.len() / 2;
        encrypted[mid] ^= 0xFF;

        let result = token.decrypt(&encrypted);
        assert_eq!(
            result,
            Err(CryptoError::InvalidHmac),
            "should fail with InvalidHmac when token data is corrupted"
        );
    }

    #[test]
    fn test_token_malformed_undersized_47_bytes() {
        let key: [u8; 64] = [0xAA; 64];
        let token = Token::new(&key);
        let result = token.decrypt(&[0u8; 47]);
        assert_eq!(result, Err(CryptoError::InvalidLength {
            reason: "token too short: need at least 48 bytes (16 IV + 0 ciphertext + 32 HMAC)",
        }));
    }

    #[test]
    fn test_token_malformed_minimum_size_48_bytes() {
        // Craft 48-byte token: 16 IV + 0 ciphertext + 32 HMAC (with valid HMAC)
        let key: [u8; 64] = [0xBB; 64];
        let token = Token::new(&key);
        let iv = [0x11u8; 16];
        // Compute valid HMAC over just the IV (no ciphertext)
        let hmac = crate::hmac::hmac_sha256(&key[..32], &iv);
        let mut data = Vec::with_capacity(48);
        data.extend_from_slice(&iv);
        data.extend_from_slice(&hmac);
        assert_eq!(data.len(), 48);
        // HMAC is valid but AES-CBC gets empty ciphertext → DecryptionFailed
        let result = token.decrypt(&data);
        assert_eq!(result, Err(CryptoError::DecryptionFailed));
    }

    #[test]
    fn test_token_adversarial_hmac_position_corruption() {
        let key: [u8; 64] = [0xCC; 64];
        let token = Token::new(&key);
        let encrypted = token.encrypt(b"hmac corruption test");
        let len = encrypted.len();

        // Flip bytes at various HMAC positions (last 32 bytes)
        for &offset in &[0, 15, 31] {
            let mut corrupted = encrypted.clone();
            corrupted[len - 32 + offset] ^= 0x01;
            assert_eq!(
                token.decrypt(&corrupted),
                Err(CryptoError::InvalidHmac),
                "corrupting HMAC byte at offset {offset} should fail"
            );
        }
    }

    // ================================================================== //
    // Boundary: token decrypt edge cases
    // ================================================================== //

    #[test]
    fn token_decrypt_non_block_aligned_ciphertext() {
        // Build a token with valid HMAC but non-block-aligned ciphertext
        // IV(16) + 5 bytes ciphertext + HMAC(32) = 53 bytes
        let key: [u8; 64] = [0xEE; 64];
        let token = Token::new(&key);
        let iv = [0x11u8; 16];
        let fake_ct = [0x22u8; 5]; // not a multiple of 16

        let mut signed_parts = Vec::with_capacity(21);
        signed_parts.extend_from_slice(&iv);
        signed_parts.extend_from_slice(&fake_ct);
        let hmac = crate::hmac::hmac_sha256(&key[..32], &signed_parts);

        let mut data = signed_parts;
        data.extend_from_slice(&hmac);
        assert_eq!(data.len(), 53);

        let result = token.decrypt(&data);
        assert!(result.is_err(), "non-block-aligned ciphertext should fail");
    }

    #[test]
    fn token_decrypt_exactly_one_block() {
        // Encrypt data that fits in exactly one AES block after padding
        let key: [u8; 64] = [0xFF; 64];
        let token = Token::new(&key);

        // Empty plaintext → 16 bytes of padding → 1 AES block ciphertext
        let encrypted = token.encrypt(b"");
        // Should be: 16 (IV) + 16 (ciphertext) + 32 (HMAC) = 64
        assert_eq!(encrypted.len(), 64);

        let decrypted = token.decrypt(&encrypted).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_token_decrypt_wrong_key() {
        let key_a: [u8; 64] = [0xAA; 64];
        let key_b: [u8; 64] = [0xBB; 64];
        let token_a = Token::new(&key_a);
        let token_b = Token::new(&key_b);

        let encrypted = token_a.encrypt(b"secret message");
        assert_eq!(
            token_b.decrypt(&encrypted),
            Err(CryptoError::InvalidHmac),
            "decrypting with wrong key should fail with InvalidHmac"
        );
    }

    #[test]
    fn test_token_adversarial_iv_corruption() {
        let key: [u8; 64] = [0xDD; 64];
        let token = Token::new(&key);
        let encrypted = token.encrypt(b"iv corruption test");

        // Corrupt IV bytes — HMAC covers IV, so HMAC check should fail
        for &offset in &[0, 7, 15] {
            let mut corrupted = encrypted.clone();
            corrupted[offset] ^= 0x01;
            assert_eq!(
                token.decrypt(&corrupted),
                Err(CryptoError::InvalidHmac),
                "corrupting IV byte at offset {offset} should fail with InvalidHmac"
            );
        }
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn token_encrypt_decrypt_roundtrip(
            key in any::<[u8; 64]>(),
            plaintext in proptest::collection::vec(any::<u8>(), 0..512),
        ) {
            let token = Token::new(&key);
            let encrypted = token.encrypt(&plaintext);
            let decrypted = token.decrypt(&encrypted).unwrap();
            prop_assert_eq!(&decrypted, &plaintext);
        }
    }
}
