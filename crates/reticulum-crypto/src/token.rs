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
        let eph_key_info = &layout["ephemeral_public_key"];
        let fernet_info = &layout["fernet_token"];

        let eph_offset = eph_key_info["offset"].as_u64().unwrap() as usize;
        let eph_len = eph_key_info["length"].as_u64().unwrap() as usize;
        let fernet_offset = fernet_info["offset"].as_u64().unwrap() as usize;
        let fernet_len = fernet_info["length"].as_u64().unwrap() as usize;

        // Check structural consistency
        assert_eq!(eph_offset, 0);
        assert_eq!(eph_len, 32);
        assert_eq!(fernet_offset, 32);
        assert_eq!(eph_len + fernet_len, fixed_token_full.len());

        // Verify the ephemeral public key hex matches
        let expected_eph_hex = eph_key_info["value"].as_str().unwrap();
        let actual_eph = &fixed_token_full[eph_offset..eph_offset + eph_len];
        assert_eq!(
            hex::encode(actual_eph),
            expected_eph_hex,
            "ephemeral public key mismatch"
        );

        // Verify the fernet_token hex matches
        let expected_fernet_hex = fernet_info["value"].as_str().unwrap();
        let actual_fernet = &fixed_token_full[fernet_offset..fernet_offset + fernet_len];
        assert_eq!(
            hex::encode(actual_fernet),
            expected_fernet_hex,
            "fernet token value mismatch"
        );

        // Verify the fernet token sub-components (iv, ciphertext, hmac)
        let components = &fernet_info["components"];
        let iv_info = &components["iv"];
        let ct_info = &components["ciphertext"];
        let hmac_info = &components["hmac"];

        let iv_offset = iv_info["offset"].as_u64().unwrap() as usize;
        let iv_len = iv_info["length"].as_u64().unwrap() as usize;
        let ct_offset = ct_info["offset"].as_u64().unwrap() as usize;
        let ct_len = ct_info["length"].as_u64().unwrap() as usize;
        let hmac_offset = hmac_info["offset"].as_u64().unwrap() as usize;
        let hmac_len = hmac_info["length"].as_u64().unwrap() as usize;

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
            iv_info["value"].as_str().unwrap(),
        );
        assert_eq!(
            hex::encode(&actual_fernet[ct_offset..ct_offset + ct_len]),
            ct_info["value"].as_str().unwrap(),
        );
        assert_eq!(
            hex::encode(&actual_fernet[hmac_offset..hmac_offset + hmac_len]),
            hmac_info["value"].as_str().unwrap(),
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
}
