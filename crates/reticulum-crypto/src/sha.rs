//! SHA-256 and SHA-512 hashing primitives.
//!
//! Provides one-shot hashing functions and a streaming hasher for SHA-256.
//! Also provides Reticulum's truncated hash (first 128 bits of SHA-256),
//! used for name hashing and addressing.

use sha2::{Digest, Sha256, Sha512};

/// Compute the SHA-256 hash of the given data.
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Compute the SHA-512 hash of the given data.
#[must_use]
pub fn sha512(data: &[u8]) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Compute the truncated hash of the given data: SHA-256, then take the first
/// 16 bytes (128 bits). This is Reticulum's "name hash" used for addressing.
#[must_use]
pub fn truncated_hash(data: &[u8]) -> [u8; 16] {
    let full = sha256(data);
    let mut result = [0u8; 16];
    result.copy_from_slice(&full[..16]);
    result
}

/// A streaming SHA-256 hasher that allows incremental feeding of data.
pub struct Sha256Hasher {
    inner: Sha256,
}

impl Sha256Hasher {
    /// Create a new streaming SHA-256 hasher.
    pub fn new() -> Self {
        Self {
            inner: Sha256::new(),
        }
    }

    /// Feed more data into the hasher.
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Consume the hasher and return the final SHA-256 digest.
    #[must_use]
    pub fn finalize(self) -> [u8; 32] {
        self.inner.finalize().into()
    }
}

impl Default for Sha256Hasher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_vectors() {
        let vectors = reticulum_test_vectors::hashes::load();
        for v in &vectors.sha256 {
            let input = hex::decode(&v.input).expect("invalid hex input");
            assert_eq!(
                input.len() as u64,
                v.input_length,
                "input length mismatch for: {}",
                v.description
            );
            let digest = sha256(&input);
            let expected = hex::decode(&v.digest).expect("invalid hex digest");
            assert_eq!(
                digest.as_slice(),
                expected.as_slice(),
                "SHA-256 mismatch for: {}",
                v.description
            );
        }
    }

    #[test]
    fn test_sha512_vectors() {
        let vectors = reticulum_test_vectors::hashes::load();
        for v in &vectors.sha512 {
            let input = hex::decode(&v.input).expect("invalid hex input");
            assert_eq!(
                input.len() as u64,
                v.input_length,
                "input length mismatch for: {}",
                v.description
            );
            let digest = sha512(&input);
            let expected = hex::decode(&v.digest).expect("invalid hex digest");
            assert_eq!(
                digest.as_slice(),
                expected.as_slice(),
                "SHA-512 mismatch for: {}",
                v.description
            );
        }
    }

    #[test]
    fn test_truncated_hash_vectors() {
        let vectors = reticulum_test_vectors::hashes::load();
        for v in &vectors.truncated_hash {
            let input = hex::decode(&v.input).expect("invalid hex input");
            assert_eq!(
                input.len() as u64,
                v.input_length,
                "input length mismatch for: {}",
                v.description
            );

            // Verify the full SHA-256 matches too.
            let full = sha256(&input);
            let expected_full = hex::decode(&v.full_sha256).expect("invalid hex full_sha256");
            assert_eq!(
                full.as_slice(),
                expected_full.as_slice(),
                "full SHA-256 mismatch for: {}",
                v.description
            );

            // Verify the truncated hash.
            let truncated = truncated_hash(&input);
            assert_eq!(
                truncated.len() as u64,
                v.truncated_length_bytes,
                "truncated length mismatch for: {}",
                v.description
            );
            let expected_truncated =
                hex::decode(&v.truncated_hash).expect("invalid hex truncated_hash");
            assert_eq!(
                truncated.as_slice(),
                expected_truncated.as_slice(),
                "truncated hash mismatch for: {}",
                v.description
            );
        }
    }

    #[test]
    fn test_sha256_streaming() {
        let vectors = reticulum_test_vectors::hashes::load();
        for v in &vectors.sha256 {
            let input = hex::decode(&v.input).expect("invalid hex input");

            // One-shot result for comparison.
            let expected = sha256(&input);

            // Streaming: feed data in two halves.
            let mid = input.len() / 2;
            let mut hasher = Sha256Hasher::new();
            hasher.update(&input[..mid]);
            hasher.update(&input[mid..]);
            let streaming_result = hasher.finalize();

            assert_eq!(
                streaming_result, expected,
                "streaming SHA-256 mismatch for: {}",
                v.description
            );
        }
    }
}
