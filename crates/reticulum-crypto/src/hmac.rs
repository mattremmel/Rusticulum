//! HMAC-SHA256 message authentication.
//!
//! Provides HMAC-SHA256 computation and constant-time verification using the
//! `hmac` crate with `sha2::Sha256`.

use crate::CryptoError;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Compute the HMAC-SHA256 of `data` using the given `key`.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts keys of any length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// Verify that the HMAC-SHA256 of `data` under `key` matches `expected`.
///
/// Returns `Ok(())` if the MAC is valid, or `Err(CryptoError::InvalidHmac)` if
/// it does not match. The comparison is performed in constant time by the
/// underlying `hmac` crate.
pub fn hmac_sha256_verify(key: &[u8], data: &[u8], expected: &[u8; 32]) -> Result<(), CryptoError> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts keys of any length");
    mac.update(data);
    mac.verify_slice(expected)
        .map_err(|_| CryptoError::InvalidHmac)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_sha256_vectors() {
        let vectors = reticulum_test_vectors::token::load();
        for v in &vectors.hmac_sha256 {
            let key = hex::decode(&v.key).expect("invalid hex key");
            let message = hex::decode(&v.message).expect("invalid hex message");
            let expected_digest = hex::decode(&v.digest).expect("invalid hex digest");

            let digest = hmac_sha256(&key, &message);
            assert_eq!(
                digest.as_slice(),
                expected_digest.as_slice(),
                "HMAC-SHA256 mismatch for: {}",
                v.description
            );
            assert_eq!(
                digest.len() as u64,
                v.digest_length,
                "digest length mismatch for: {}",
                v.description
            );
        }
    }

    #[test]
    fn test_hmac_sha256_verify() {
        let vectors = reticulum_test_vectors::token::load();
        for v in &vectors.hmac_sha256 {
            let key = hex::decode(&v.key).expect("invalid hex key");
            let message = hex::decode(&v.message).expect("invalid hex message");
            let expected_digest: [u8; 32] = hex::decode(&v.digest)
                .expect("invalid hex digest")
                .try_into()
                .expect("digest must be 32 bytes");

            let result = hmac_sha256_verify(&key, &message, &expected_digest);
            assert!(
                result.is_ok(),
                "HMAC-SHA256 verify should succeed for: {}",
                v.description
            );
        }
    }

    #[test]
    fn test_hmac_sha256_verify_invalid() {
        let vectors = reticulum_test_vectors::token::load();
        let v = &vectors.hmac_sha256[0];
        let key = hex::decode(&v.key).expect("invalid hex key");
        let message = hex::decode(&v.message).expect("invalid hex message");

        let mut digest = hmac_sha256(&key, &message);
        // Flip a byte to make it invalid.
        digest[0] ^= 0xff;

        let result = hmac_sha256_verify(&key, &message, &digest);
        assert_eq!(
            result,
            Err(CryptoError::InvalidHmac),
            "HMAC-SHA256 verify should fail with InvalidHmac for corrupted digest"
        );
    }

    #[test]
    fn test_hmac_verify_wrong_key() {
        let key_a = [0xAA; 32];
        let key_b = [0xBB; 32];
        let data = b"test data";
        let mac = hmac_sha256(&key_a, data);
        assert_eq!(
            hmac_sha256_verify(&key_b, data, &mac),
            Err(CryptoError::InvalidHmac),
            "HMAC verify with wrong key should fail"
        );
    }

    #[test]
    fn test_hmac_verify_wrong_data() {
        let key = [0xCC; 32];
        let mac = hmac_sha256(&key, b"data A");
        assert_eq!(
            hmac_sha256_verify(&key, b"data B", &mac),
            Err(CryptoError::InvalidHmac),
            "HMAC verify with wrong data should fail"
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
        fn hmac_verify_roundtrip(
            key in proptest::collection::vec(any::<u8>(), 1..128),
            data in proptest::collection::vec(any::<u8>(), 0..512),
        ) {
            let mac = hmac_sha256(&key, &data);
            prop_assert!(hmac_sha256_verify(&key, &data, &mac).is_ok());
        }
    }
}
