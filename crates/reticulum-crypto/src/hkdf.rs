//! HKDF key derivation (hand-rolled to match Python reference semantics).
//!
//! This module implements HKDF-SHA256 using [`crate::hmac::hmac_sha256`] directly,
//! rather than the `hkdf` crate, to exactly match the Python reference implementation's
//! behavior -- particularly around empty-salt handling and counter wrapping.
//!
//! # Critical subtleties
//!
//! - **Empty salt**: If salt is `None` or an empty slice, 32 zero bytes are used
//!   (explicit, not the HMAC default).
//! - **Counter byte**: `(i + 1) % 256`, matching the Python `bytes([(i + 1) % (0xFF + 1)])`.
//! - **Extract argument order**: `HMAC(salt, ikm)` -- salt is the HMAC key, ikm is the data.

use alloc::vec::Vec;

use crate::hmac::hmac_sha256;

/// The SHA-256 hash output length in bytes.
const HASH_LEN: usize = 32;

/// HKDF-SHA256 extract step.
///
/// Computes `PRK = HMAC-SHA256(salt, ikm)`. If `salt` is `None` or empty, 32
/// zero bytes are used as the salt, matching the Python reference implementation.
pub fn hkdf_extract(salt: Option<&[u8]>, ikm: &[u8]) -> [u8; 32] {
    let effective_salt: &[u8] = match salt {
        Some(s) if !s.is_empty() => s,
        _ => &[0u8; HASH_LEN],
    };
    hmac_sha256(effective_salt, ikm)
}

/// HKDF-SHA256 expand step.
///
/// Expands a pseudorandom key (`prk`) with optional `info` context to produce
/// `length` bytes of output keying material. The counter byte is computed as
/// `(i + 1) % 256` to match the Python reference.
pub fn hkdf_expand(prk: &[u8; 32], info: &[u8], length: usize) -> Vec<u8> {
    let num_blocks = length.div_ceil(HASH_LEN);
    let mut derived = Vec::with_capacity(num_blocks * HASH_LEN);
    let mut block = Vec::new();

    for i in 0..num_blocks {
        // T(i+1) = HMAC(PRK, T(i) || info || counter_byte)
        let counter = ((i + 1) % 256) as u8;
        let mut input = Vec::with_capacity(block.len() + info.len() + 1);
        input.extend_from_slice(&block);
        input.extend_from_slice(info);
        input.push(counter);

        let output = hmac_sha256(prk, &input);
        block = output.to_vec();
        derived.extend_from_slice(&output);
    }

    derived.truncate(length);
    derived
}

/// All-in-one HKDF-SHA256: extract then expand.
///
/// Derives `length` bytes from `derive_from` (the input keying material) using
/// an optional `salt` and optional `context` (info).
///
/// If `salt` is `None` or `Some(&[])`, 32 zero bytes are used. If `context` is
/// `None`, an empty byte slice is used.
pub fn hkdf(
    length: usize,
    derive_from: &[u8],
    salt: Option<&[u8]>,
    context: Option<&[u8]>,
) -> Vec<u8> {
    let prk = hkdf_extract(salt, derive_from);
    let info = context.unwrap_or(b"");
    hkdf_expand(&prk, info, length)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hkdf_rfc5869_vectors() {
        let vectors = reticulum_test_vectors::hkdf::load();
        for v in &vectors.rfc5869_vectors {
            let ikm = hex::decode(&v.ikm).expect("invalid hex ikm");
            let salt_bytes = hex::decode(&v.salt).expect("invalid hex salt");
            let info = hex::decode(&v.info).expect("invalid hex info");
            let expected_prk = hex::decode(&v.prk).expect("invalid hex prk");
            let expected_okm = hex::decode(&v.okm).expect("invalid hex okm");
            let length = v.length as usize;

            // Determine salt parameter: empty hex string means empty salt.
            let salt_param: Option<&[u8]> = if v.salt.is_empty() {
                Some(&[])
            } else {
                Some(&salt_bytes)
            };

            // Test extract step.
            let prk = hkdf_extract(salt_param, &ikm);
            assert_eq!(
                prk.as_slice(),
                expected_prk.as_slice(),
                "HKDF extract PRK mismatch for: {}",
                v.description
            );

            // Test expand step.
            let prk_array: [u8; 32] = expected_prk
                .as_slice()
                .try_into()
                .expect("PRK must be 32 bytes");
            let okm = hkdf_expand(&prk_array, &info, length);
            assert_eq!(
                okm.as_slice(),
                expected_okm.as_slice(),
                "HKDF expand OKM mismatch for: {}",
                v.description
            );

            // Test all-in-one.
            let info_param: Option<&[u8]> = if info.is_empty() { None } else { Some(&info) };
            let result = hkdf(length, &ikm, salt_param, info_param);
            assert_eq!(
                result.as_slice(),
                expected_okm.as_slice(),
                "HKDF all-in-one OKM mismatch for: {}",
                v.description
            );
        }
    }

    #[test]
    fn test_hkdf_reticulum_vector() {
        let vectors = reticulum_test_vectors::hkdf::load();
        let v = &vectors.reticulum_vector;

        let derive_from = hex::decode(&v.shared_key).expect("invalid hex shared_key");
        let salt_bytes = hex::decode(&v.salt).expect("invalid hex salt");
        let info_bytes = hex::decode(&v.info).expect("invalid hex info");
        let expected_prk = hex::decode(&v.prk).expect("invalid hex prk");
        let expected_derived = hex::decode(&v.derived_key).expect("invalid hex derived_key");
        let length = v.length as usize;

        // Salt is non-empty for this vector.
        let salt_param: Option<&[u8]> = if v.salt.is_empty() {
            Some(&[])
        } else {
            Some(&salt_bytes)
        };

        // Info is empty for this vector.
        let info_param: Option<&[u8]> = if v.info.is_empty() {
            None
        } else {
            Some(&info_bytes)
        };

        // Verify PRK.
        let prk = hkdf_extract(salt_param, &derive_from);
        assert_eq!(
            prk.as_slice(),
            expected_prk.as_slice(),
            "Reticulum HKDF extract PRK mismatch"
        );

        // Verify derived key via all-in-one.
        let result = hkdf(length, &derive_from, salt_param, info_param);
        assert_eq!(
            result.as_slice(),
            expected_derived.as_slice(),
            "Reticulum HKDF derived key mismatch"
        );
    }

    #[test]
    fn test_hkdf_empty_salt() {
        // Verify that None and Some(&[]) produce identical results.
        let ikm = b"test input keying material";
        let info = b"test context";
        let length = 64;

        let result_none = hkdf(length, ikm, None, Some(info));
        let result_empty = hkdf(length, ikm, Some(&[]), Some(info));

        assert_eq!(
            result_none, result_empty,
            "HKDF with None salt and empty salt should produce identical output"
        );
    }

    #[test]
    fn test_hkdf_counter_wraparound_256_blocks() {
        // 256 blocks = 8192 bytes, counter wraps at (i+1)%256
        let result = hkdf(8192, b"wraparound test", None, None);
        assert_eq!(result.len(), 8192);
        // Verify deterministic: same inputs produce same output
        let result2 = hkdf(8192, b"wraparound test", None, None);
        assert_eq!(result, result2);
    }

    #[test]
    fn test_hkdf_zero_length_output() {
        let result = hkdf(0, b"zero length", None, None);
        assert!(result.is_empty());
    }
}
