//! AES-256-CBC encryption and decryption.
//!
//! Provides AES-256-CBC encryption with PKCS7 padding (handled externally via
//! [`crate::pkcs7`]) and decryption with PKCS7 unpadding. The IV is passed
//! explicitly and is **not** prepended to the ciphertext output.

extern crate alloc;
use alloc::vec::Vec;

use aes::Aes256;
use cbc::cipher::block_padding::NoPadding;
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};

use crate::CryptoError;

type Aes256CbcEnc = cbc::Encryptor<Aes256>;
type Aes256CbcDec = cbc::Decryptor<Aes256>;

/// Encrypt `plaintext` with AES-256-CBC using the given `key` and `iv`.
///
/// The plaintext is PKCS7-padded before encryption. The returned ciphertext
/// does **not** include the IV — callers must transmit or store the IV
/// separately.
#[must_use]
pub fn aes256_cbc_encrypt(key: &[u8; 32], iv: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
    let padded = crate::pkcs7::pkcs7_pad(plaintext, 16);
    let encryptor = Aes256CbcEnc::new(key.into(), iv.into());

    // Allocate output buffer of the same size as the padded plaintext.
    let mut out = alloc::vec![0u8; padded.len()];
    // SAFETY: output buffer is block-aligned and same size as padded input; this never fails.
    encryptor
        .encrypt_padded_b2b_mut::<NoPadding>(&padded, &mut out)
        .expect("output buffer is block-aligned and same size as padded input");
    out
}

/// Decrypt `ciphertext` with AES-256-CBC using the given `key` and `iv`.
///
/// After decryption, PKCS7 padding is removed. Returns the original plaintext.
///
/// # Errors
///
/// Returns [`CryptoError::DecryptionFailed`] if the ciphertext length is not a
/// multiple of 16 bytes or is empty, and [`CryptoError::InvalidPadding`] if the
/// PKCS7 padding is malformed.
pub fn aes256_cbc_decrypt(
    key: &[u8; 32],
    iv: &[u8; 16],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if ciphertext.is_empty() || !ciphertext.len().is_multiple_of(16) {
        return Err(CryptoError::DecryptionFailed);
    }

    let decryptor = Aes256CbcDec::new(key.into(), iv.into());

    let mut buf = ciphertext.to_vec();
    let decrypted = decryptor
        .decrypt_padded_mut::<NoPadding>(&mut buf)
        .map_err(|_| CryptoError::DecryptionFailed)?;

    // Remove PKCS7 padding from the decrypted plaintext.
    let unpadded = crate::pkcs7::pkcs7_unpad(decrypted)?;
    Ok(unpadded.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes256_cbc_encrypt_vectors() {
        let vectors = reticulum_test_vectors::token::load();

        for v in &vectors.deterministic_fernet_vectors {
            let full_key = hex::decode(&v.key).expect("invalid hex key");
            let encryption_key: [u8; 32] = full_key[32..64]
                .try_into()
                .expect("encryption key must be 32 bytes");
            let iv: [u8; 16] = hex::decode(&v.iv)
                .expect("invalid hex iv")
                .try_into()
                .expect("iv must be 16 bytes");
            let plaintext = hex::decode(&v.plaintext).expect("invalid hex plaintext");
            let expected_ciphertext = hex::decode(&v.ciphertext).expect("invalid hex ciphertext");

            let ciphertext = aes256_cbc_encrypt(&encryption_key, &iv, &plaintext);
            assert_eq!(
                ciphertext, expected_ciphertext,
                "encrypt mismatch for: {}",
                v.description
            );
        }
    }

    #[test]
    fn test_aes256_cbc_decrypt_vectors() {
        let vectors = reticulum_test_vectors::token::load();

        for v in &vectors.deterministic_fernet_vectors {
            let full_key = hex::decode(&v.key).expect("invalid hex key");
            let encryption_key: [u8; 32] = full_key[32..64]
                .try_into()
                .expect("encryption key must be 32 bytes");
            let iv: [u8; 16] = hex::decode(&v.iv)
                .expect("invalid hex iv")
                .try_into()
                .expect("iv must be 16 bytes");
            let ciphertext = hex::decode(&v.ciphertext).expect("invalid hex ciphertext");
            let expected_plaintext = hex::decode(&v.plaintext).expect("invalid hex plaintext");

            let plaintext = aes256_cbc_decrypt(&encryption_key, &iv, &ciphertext)
                .expect("decryption should succeed");
            assert_eq!(
                plaintext, expected_plaintext,
                "decrypt mismatch for: {}",
                v.description
            );
        }
    }

    #[test]
    fn test_aes256_cbc_roundtrip() {
        let key: [u8; 32] = [0x42; 32];
        let iv: [u8; 16] = [0x24; 16];

        for size in [0, 1, 7, 15, 16, 17, 31, 32, 33, 100, 255, 256] {
            let data: Vec<u8> = (0..size).map(|i| (i & 0xFF) as u8).collect();
            let ciphertext = aes256_cbc_encrypt(&key, &iv, &data);

            // Ciphertext must be a non-zero multiple of 16
            assert_eq!(
                ciphertext.len() % 16,
                0,
                "ciphertext not block-aligned for size {size}"
            );
            assert!(
                !ciphertext.is_empty(),
                "ciphertext should never be empty for size {size}"
            );

            let recovered = aes256_cbc_decrypt(&key, &iv, &ciphertext)
                .expect("roundtrip decryption should succeed");
            assert_eq!(recovered, data, "roundtrip mismatch for size {size}");
        }
    }

    #[test]
    fn test_aes256_cbc_invalid_ciphertext() {
        let key: [u8; 32] = [0x42; 32];
        let iv: [u8; 16] = [0x24; 16];

        // Empty ciphertext
        assert_eq!(
            aes256_cbc_decrypt(&key, &iv, &[]),
            Err(CryptoError::DecryptionFailed)
        );

        // Not a multiple of 16 bytes
        assert_eq!(
            aes256_cbc_decrypt(&key, &iv, &[0u8; 15]),
            Err(CryptoError::DecryptionFailed)
        );

        // 17 bytes -- not aligned
        assert_eq!(
            aes256_cbc_decrypt(&key, &iv, &[0u8; 17]),
            Err(CryptoError::DecryptionFailed)
        );

        // 1 byte -- not aligned
        assert_eq!(
            aes256_cbc_decrypt(&key, &iv, &[0u8; 1]),
            Err(CryptoError::DecryptionFailed)
        );
    }

    #[test]
    fn test_aes256_cbc_malformed_all_zero_key_iv() {
        let key = [0u8; 32];
        let iv = [0u8; 16];
        // Roundtrip with all-zero key/IV works
        let data = b"test data for zero key";
        let ct = aes256_cbc_encrypt(&key, &iv, data);
        let recovered = aes256_cbc_decrypt(&key, &iv, &ct).unwrap();
        assert_eq!(recovered, data);
        // Decrypt garbage with valid alignment → InvalidPadding
        let garbage = [0xAB; 16];
        let result = aes256_cbc_decrypt(&key, &iv, &garbage);
        assert_eq!(result, Err(CryptoError::InvalidPadding));
    }

    #[test]
    fn test_aes256_cbc_malformed_corrupted_ciphertext() {
        let key = [0x42u8; 32];
        let iv = [0x24u8; 16];
        let data = b"bitflip test data";
        let mut ct = aes256_cbc_encrypt(&key, &iv, data);
        // Flip a bit in the last block (affects padding validation)
        let last_block_start = ct.len() - 16;
        ct[last_block_start] ^= 0x01;
        let result = aes256_cbc_decrypt(&key, &iv, &ct);
        assert_eq!(result, Err(CryptoError::InvalidPadding));
    }

    #[test]
    fn test_aes256_cbc_malformed_single_zero_block() {
        let key = [0x42u8; 32];
        let iv = [0x24u8; 16];
        let result = aes256_cbc_decrypt(&key, &iv, &[0u8; 16]);
        assert_eq!(result, Err(CryptoError::InvalidPadding));
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn aes_cbc_roundtrip(
            key in any::<[u8; 32]>(),
            iv in any::<[u8; 16]>(),
            plaintext in proptest::collection::vec(any::<u8>(), 0..512),
        ) {
            let ciphertext = aes256_cbc_encrypt(&key, &iv, &plaintext);
            let recovered = aes256_cbc_decrypt(&key, &iv, &ciphertext).unwrap();
            prop_assert_eq!(&recovered, &plaintext);
        }

        #[test]
        fn aes_cbc_ciphertext_block_aligned(
            key in any::<[u8; 32]>(),
            iv in any::<[u8; 16]>(),
            plaintext in proptest::collection::vec(any::<u8>(), 0..512),
        ) {
            let ciphertext = aes256_cbc_encrypt(&key, &iv, &plaintext);
            prop_assert_eq!(ciphertext.len() % 16, 0);
            prop_assert!(ciphertext.len() >= plaintext.len() + 1);
        }
    }
}
