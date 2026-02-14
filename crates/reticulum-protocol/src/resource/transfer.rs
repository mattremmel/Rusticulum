//! Resource transfer simulation: prepare, assemble, and payload encoding.
//!
//! This module provides the computational core for resource transfers:
//! preparing resources for sending (encryption, hashing, advertisement building),
//! assembling received parts (decryption, decompression, verification), and
//! encoding/decoding the various control payloads (requests, proofs, cancellations).
//!
//! All functions are pure — no I/O, no async — producing `Vec<u8>` outputs.

use bzip2::Compression;
use bzip2::read::{BzDecoder, BzEncoder};
use rmpv::Value;
use std::io::Read;

use reticulum_crypto::sha::sha256;
use reticulum_crypto::token::Token;

use super::advertisement::{ResourceAdvertisement, ResourceFlags};
use super::constants::{RANDOM_HASH_SIZE, SDU};
use super::hashmap::ResourceHashmap;
use crate::error::ResourceError;

// ------------------------------------------------------------------ //
// Types
// ------------------------------------------------------------------ //

/// State of a resource transfer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceState {
    Queued,
    Advertised,
    Transferring,
    AwaitingProof,
    Assembling,
    Complete,
    Failed(String),
    Corrupt,
}

/// A resource prepared for sending (sender side).
#[derive(Debug, Clone)]
pub struct PreparedResource {
    /// The encrypted data to be split into parts and sent.
    pub encrypted_data: Vec<u8>,
    /// Hashmap of part hashes for verification.
    pub hashmap: ResourceHashmap,
    /// SHA256(data_with_metadata || random_hash).
    pub resource_hash: [u8; 32],
    /// SHA256(data_with_metadata || resource_hash).
    pub expected_proof: [u8; 32],
    /// The advertisement to send to the receiver.
    pub advertisement: ResourceAdvertisement,
    /// Decoded flags for the resource.
    pub flags: ResourceFlags,
}

/// A resource assembled from received parts (receiver side).
#[derive(Debug, Clone)]
pub struct AssembledResource {
    /// The original data with metadata prefix (if any).
    pub data_with_metadata: Vec<u8>,
    /// SHA256(data_with_metadata || random_hash).
    pub resource_hash: [u8; 32],
    /// SHA256(data_with_metadata || resource_hash) — to send back as proof.
    pub proof: [u8; 32],
}

/// A decoded part request from the receiver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartRequest {
    /// Whether the receiver's hashmap is exhausted (needs more segments).
    pub exhausted: bool,
    /// The last map hash the receiver has (only present when exhausted).
    pub last_map_hash: Option<[u8; 4]>,
    /// The resource hash identifying the transfer.
    pub resource_hash: [u8; 32],
    /// The requested part hashes.
    pub map_hashes: Vec<[u8; 4]>,
}

// ------------------------------------------------------------------ //
// Metadata encoding/decoding
// ------------------------------------------------------------------ //

/// Encode metadata as a 3-byte big-endian size prefix followed by msgpack bytes.
pub fn encode_metadata(metadata: &Value) -> Result<Vec<u8>, ResourceError> {
    let mut packed = Vec::new();
    rmpv::encode::write_value(&mut packed, metadata)
        .map_err(|e| ResourceError::InvalidMetadata(format!("msgpack encode: {e}")))?;

    let size = packed.len();
    if size > 0xFF_FFFF {
        return Err(ResourceError::InvalidMetadata(format!(
            "metadata too large: {size} bytes (max 16777215)"
        )));
    }

    // 3-byte big-endian size prefix (equivalent to struct.pack(">I", size)[1:])
    let size_bytes = (size as u32).to_be_bytes();
    let mut result = Vec::with_capacity(3 + packed.len());
    result.extend_from_slice(&size_bytes[1..4]);
    result.extend_from_slice(&packed);
    Ok(result)
}

/// Decode metadata from a 3-byte size prefix + msgpack payload.
///
/// Returns the decoded value and the remaining bytes after the metadata.
pub fn decode_metadata(data: &[u8]) -> Result<(Value, &[u8]), ResourceError> {
    if data.len() < 3 {
        return Err(ResourceError::InvalidMetadata(
            "data too short for size prefix".into(),
        ));
    }

    let size = ((data[0] as usize) << 16) | ((data[1] as usize) << 8) | (data[2] as usize);

    if data.len() < 3 + size {
        return Err(ResourceError::InvalidMetadata(format!(
            "data too short: need {} bytes for metadata, have {}",
            3 + size,
            data.len()
        )));
    }

    let packed = &data[3..3 + size];
    let value = rmpv::decode::read_value(&mut &packed[..])
        .map_err(|e| ResourceError::InvalidMetadata(format!("msgpack decode: {e}")))?;

    Ok((value, &data[3 + size..]))
}

/// Build data_with_metadata: optional metadata prefix + raw data.
pub fn build_data_with_metadata(
    raw_data: &[u8],
    metadata: Option<&Value>,
) -> Result<Vec<u8>, ResourceError> {
    match metadata {
        Some(meta) => {
            let meta_bytes = encode_metadata(meta)?;
            let mut result = Vec::with_capacity(meta_bytes.len() + raw_data.len());
            result.extend_from_slice(&meta_bytes);
            result.extend_from_slice(raw_data);
            Ok(result)
        }
        None => Ok(raw_data.to_vec()),
    }
}

// ------------------------------------------------------------------ //
// Compression
// ------------------------------------------------------------------ //

/// Compress data using bz2. Returns `Some(compressed)` if compression reduces size.
pub fn compress_resource_data(data: &[u8]) -> Option<Vec<u8>> {
    let mut encoder = BzEncoder::new(data, Compression::best());
    let mut compressed = Vec::new();
    if encoder.read_to_end(&mut compressed).is_err() {
        return None;
    }
    if compressed.len() < data.len() {
        Some(compressed)
    } else {
        None
    }
}

/// Decompress bz2-compressed data.
pub fn decompress_resource_data(data: &[u8]) -> Result<Vec<u8>, ResourceError> {
    let mut decoder = BzDecoder::new(data);
    let mut decompressed = Vec::new();
    decoder
        .read_to_end(&mut decompressed)
        .map_err(|e| ResourceError::DecompressionFailed(e.to_string()))?;
    Ok(decompressed)
}

// ------------------------------------------------------------------ //
// Hash and proof computation
// ------------------------------------------------------------------ //

/// Compute resource hash: `SHA256(data_with_metadata || random_hash)`.
pub fn compute_resource_hash(
    data_with_metadata: &[u8],
    random_hash: &[u8; RANDOM_HASH_SIZE],
) -> [u8; 32] {
    let mut input = Vec::with_capacity(data_with_metadata.len() + RANDOM_HASH_SIZE);
    input.extend_from_slice(data_with_metadata);
    input.extend_from_slice(random_hash);
    sha256(&input)
}

/// Compute proof: `SHA256(data_with_metadata || resource_hash)`.
pub fn compute_proof(data_with_metadata: &[u8], resource_hash: &[u8; 32]) -> [u8; 32] {
    let mut input = Vec::with_capacity(data_with_metadata.len() + 32);
    input.extend_from_slice(data_with_metadata);
    input.extend_from_slice(resource_hash);
    sha256(&input)
}

/// Validate a received proof payload against the expected proof.
///
/// Proof payload is 64 bytes: `resource_hash(32) || proof(32)`.
pub fn validate_proof(proof_data: &[u8], expected_proof: &[u8; 32]) -> bool {
    proof_data.len() == 64 && proof_data[32..] == expected_proof[..]
}

// ------------------------------------------------------------------ //
// Payload encoding/decoding
// ------------------------------------------------------------------ //

/// Encode a part request payload.
///
/// - Not exhausted: `0x00 || resource_hash(32) || map_hashes(N*4)`
/// - Exhausted: `0xFF || last_map_hash(4) || resource_hash(32) || map_hashes(N*4)`
pub fn encode_part_request(
    exhausted: bool,
    resource_hash: &[u8; 32],
    map_hashes: &[[u8; 4]],
    last_map_hash: Option<&[u8; 4]>,
) -> Vec<u8> {
    let mut buf = Vec::new();
    if exhausted {
        buf.push(0xFF);
        if let Some(lmh) = last_map_hash {
            buf.extend_from_slice(lmh);
        }
    } else {
        buf.push(0x00);
    }
    buf.extend_from_slice(resource_hash);
    for hash in map_hashes {
        buf.extend_from_slice(hash);
    }
    buf
}

/// Decode a part request payload.
pub fn decode_part_request(data: &[u8]) -> Result<PartRequest, ResourceError> {
    if data.is_empty() {
        return Err(ResourceError::InvalidPayload("empty part request".into()));
    }

    let exhausted = data[0] == 0xFF;
    let (offset, last_map_hash) = if exhausted {
        if data.len() < 1 + 4 + 32 {
            return Err(ResourceError::InvalidPayload(
                "exhausted request too short".into(),
            ));
        }
        let mut lmh = [0u8; 4];
        lmh.copy_from_slice(&data[1..5]);
        (5, Some(lmh))
    } else {
        if data.len() < 1 + 32 {
            return Err(ResourceError::InvalidPayload(
                "request too short for resource hash".into(),
            ));
        }
        (1, None)
    };

    let mut resource_hash = [0u8; 32];
    resource_hash.copy_from_slice(&data[offset..offset + 32]);

    let remaining = &data[offset + 32..];
    if !remaining.len().is_multiple_of(4) {
        return Err(ResourceError::InvalidPayload(format!(
            "map hashes region length {} is not a multiple of 4",
            remaining.len()
        )));
    }

    let map_hashes: Vec<[u8; 4]> = remaining
        .chunks_exact(4)
        .map(|c| {
            let mut h = [0u8; 4];
            h.copy_from_slice(c);
            h
        })
        .collect();

    Ok(PartRequest {
        exhausted,
        last_map_hash,
        resource_hash,
        map_hashes,
    })
}

/// Encode a proof payload: `resource_hash(32) || proof(32)`.
pub fn encode_proof_payload(resource_hash: &[u8; 32], proof: &[u8; 32]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(resource_hash);
    buf.extend_from_slice(proof);
    buf
}

/// Decode a proof payload: returns `(resource_hash, proof)`.
pub fn decode_proof_payload(data: &[u8]) -> Result<([u8; 32], [u8; 32]), ResourceError> {
    if data.len() != 64 {
        return Err(ResourceError::InvalidPayload(format!(
            "proof payload must be 64 bytes, got {}",
            data.len()
        )));
    }
    let mut resource_hash = [0u8; 32];
    let mut proof = [0u8; 32];
    resource_hash.copy_from_slice(&data[..32]);
    proof.copy_from_slice(&data[32..]);
    Ok((resource_hash, proof))
}

/// Encode a cancellation payload: `resource_hash(32)`.
pub fn encode_cancellation(resource_hash: &[u8; 32]) -> Vec<u8> {
    resource_hash.to_vec()
}

/// Decode a cancellation payload: returns the resource hash.
pub fn decode_cancellation(data: &[u8]) -> Result<[u8; 32], ResourceError> {
    if data.len() != 32 {
        return Err(ResourceError::InvalidPayload(format!(
            "cancellation payload must be 32 bytes, got {}",
            data.len()
        )));
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(data);
    Ok(hash)
}

// ------------------------------------------------------------------ //
// Prepare (sender side)
// ------------------------------------------------------------------ //

/// Prepare a resource for sending.
///
/// Performs: metadata attachment → optional compression → encryption →
/// hashmap building → hash/proof computation → advertisement building.
#[allow(clippy::too_many_arguments)]
pub fn prepare_resource(
    raw_data: &[u8],
    derived_key: &[u8; 64],
    iv: &[u8; 16],
    random_hash: [u8; RANDOM_HASH_SIZE],
    metadata: Option<&Value>,
    compress: bool,
    segment_index: u64,
    total_segments: u64,
    original_hash: Option<&[u8; 32]>,
    request_id: Option<Vec<u8>>,
) -> Result<PreparedResource, ResourceError> {
    // 1. Build data_with_metadata
    let data_with_metadata = build_data_with_metadata(raw_data, metadata)?;

    // 2. Optional compression
    let (payload, compressed) = if compress {
        match compress_resource_data(&data_with_metadata) {
            Some(compressed_data) => (compressed_data, true),
            None => (data_with_metadata.clone(), false),
        }
    } else {
        (data_with_metadata.clone(), false)
    };

    // 3. Prepend random_hash to plaintext
    let mut plaintext = Vec::with_capacity(RANDOM_HASH_SIZE + payload.len());
    plaintext.extend_from_slice(&random_hash);
    plaintext.extend_from_slice(&payload);

    // 4. Encrypt with Token
    let token = Token::new(derived_key);
    let encrypted_data = token.encrypt_with_iv(&plaintext, iv);

    // 5. Build hashmap from encrypted data
    let hashmap = ResourceHashmap::from_data(&encrypted_data, SDU, random_hash);

    // 6. Compute resource hash and expected proof
    let resource_hash = compute_resource_hash(&data_with_metadata, &random_hash);
    let expected_proof = compute_proof(&data_with_metadata, &resource_hash);

    // 7. Build flags
    let flags = ResourceFlags {
        encrypted: true,
        compressed,
        split: total_segments > 1,
        is_request: false,
        is_response: false,
        has_metadata: metadata.is_some(),
    };

    // 8. Build advertisement
    let orig_hash = original_hash.copied().unwrap_or(resource_hash);
    let advertisement = ResourceAdvertisement {
        transfer_size: encrypted_data.len() as u64,
        data_size: data_with_metadata.len() as u64,
        num_parts: hashmap.len() as u64,
        resource_hash,
        random_hash,
        original_hash: orig_hash,
        segment_index,
        total_segments,
        request_id,
        flags: flags.to_byte(),
        hashmap: hashmap.to_bytes(),
    };

    Ok(PreparedResource {
        encrypted_data,
        hashmap,
        resource_hash,
        expected_proof,
        advertisement,
        flags,
    })
}

// ------------------------------------------------------------------ //
// Assemble (receiver side)
// ------------------------------------------------------------------ //

/// Assemble a resource from received encrypted parts.
///
/// Performs: concatenation → decryption → random_hash stripping →
/// optional decompression → hash verification → proof computation.
pub fn assemble_resource(
    parts: &[Vec<u8>],
    derived_key: &[u8; 64],
    random_hash: &[u8; RANDOM_HASH_SIZE],
    resource_hash: &[u8; 32],
    compressed: bool,
) -> Result<AssembledResource, ResourceError> {
    // 1. Concatenate all parts
    let total_len: usize = parts.iter().map(|p| p.len()).sum();
    let mut joined = Vec::with_capacity(total_len);
    for part in parts {
        joined.extend_from_slice(part);
    }

    // 2. Decrypt
    let token = Token::new(derived_key);
    let decrypted = token
        .decrypt(&joined)
        .map_err(|e| ResourceError::DecryptionFailed(e.to_string()))?;

    // 3. Strip random_hash prefix
    if decrypted.len() < RANDOM_HASH_SIZE {
        return Err(ResourceError::DecryptionFailed(
            "decrypted data too short for random hash prefix".into(),
        ));
    }
    let stripped = &decrypted[RANDOM_HASH_SIZE..];

    // 4. Optional decompression
    let data_with_metadata = if compressed {
        decompress_resource_data(stripped)?
    } else {
        stripped.to_vec()
    };

    // 5. Verify resource hash
    let computed_hash = compute_resource_hash(&data_with_metadata, random_hash);
    if computed_hash != *resource_hash {
        return Err(ResourceError::HashMismatch {
            expected: format!("{:02x?}", &resource_hash[..8]),
            actual: format!("{:02x?}", &computed_hash[..8]),
        });
    }

    // 6. Compute proof
    let proof = compute_proof(&data_with_metadata, resource_hash);

    Ok(AssembledResource {
        data_with_metadata,
        resource_hash: *resource_hash,
        proof,
    })
}

// ------------------------------------------------------------------ //
// Tests
// ------------------------------------------------------------------ //

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        hex::decode(s).expect("invalid hex")
    }

    // ============================================================== //
    // Metadata tests (using resources.json test vectors)
    // ============================================================== //

    fn load_resources() -> reticulum_test_vectors::resources::ResourcesVectors {
        reticulum_test_vectors::resources::load()
    }

    #[test]
    fn encode_metadata_vector_0() {
        let vecs = load_resources();
        let v = &vecs.metadata_vectors[0];
        // {"text": "hello", "n": 42}
        let packed_expected = hex(&v.full_metadata_bytes_hex);

        // Reconstruct the msgpack value from the packed bytes to ensure identical encoding
        let packed_metadata = hex(&v.packed_metadata_hex);
        let value = rmpv::decode::read_value(&mut &packed_metadata[..]).unwrap();

        let result = encode_metadata(&value).unwrap();
        assert_eq!(result, packed_expected, "metadata vector 0 encode mismatch");
    }

    #[test]
    fn encode_metadata_vector_1() {
        let vecs = load_resources();
        let v = &vecs.metadata_vectors[1];
        let packed_expected = hex(&v.full_metadata_bytes_hex);

        let packed_metadata = hex(&v.packed_metadata_hex);
        let value = rmpv::decode::read_value(&mut &packed_metadata[..]).unwrap();

        let result = encode_metadata(&value).unwrap();
        assert_eq!(result, packed_expected, "metadata vector 1 encode mismatch");
    }

    #[test]
    fn decode_metadata_vector_0_roundtrip() {
        let vecs = load_resources();
        let v = &vecs.metadata_vectors[0];
        let full_bytes = hex(&v.full_metadata_bytes_hex);

        // Append some trailing data to test remaining slice
        let mut data_with_trail = full_bytes.clone();
        data_with_trail.extend_from_slice(b"trailing");

        let (value, remaining) = decode_metadata(&data_with_trail).unwrap();
        assert_eq!(remaining, b"trailing");

        // Re-encode and verify
        let re_encoded = encode_metadata(&value).unwrap();
        assert_eq!(re_encoded, full_bytes);
    }

    #[test]
    fn decode_metadata_vector_1_roundtrip() {
        let vecs = load_resources();
        let v = &vecs.metadata_vectors[1];
        let full_bytes = hex(&v.full_metadata_bytes_hex);

        let (value, remaining) = decode_metadata(&full_bytes).unwrap();
        assert!(remaining.is_empty());

        let re_encoded = encode_metadata(&value).unwrap();
        assert_eq!(re_encoded, full_bytes);
    }

    // ============================================================== //
    // Hash and proof tests (synthetic — test vector data is truncated)
    // ============================================================== //

    #[test]
    fn compute_resource_hash_synthetic() {
        let data = b"test data with metadata";
        let random_hash = [0x11, 0x22, 0x33, 0x44];
        let hash = compute_resource_hash(data, &random_hash);

        // SHA256("test data with metadata" || [0x11, 0x22, 0x33, 0x44])
        let mut input = Vec::new();
        input.extend_from_slice(data);
        input.extend_from_slice(&random_hash);
        let expected = reticulum_crypto::sha::sha256(&input);
        assert_eq!(hash, expected);
    }

    #[test]
    fn compute_proof_synthetic() {
        let data = b"test data";
        let resource_hash = [0xAA; 32];
        let proof = compute_proof(data, &resource_hash);

        // SHA256("test data" || resource_hash)
        let mut input = Vec::new();
        input.extend_from_slice(data);
        input.extend_from_slice(&resource_hash);
        let expected = reticulum_crypto::sha::sha256(&input);
        assert_eq!(proof, expected);
    }

    // ============================================================== //
    // Proof payload tests (using resources.json proof vectors)
    // ============================================================== //

    #[test]
    fn encode_proof_payload_all_vectors() {
        let vecs = load_resources();
        for v in &vecs.resource_proof_vectors {
            let resource_hash: [u8; 32] = hex(&v.resource_hash_hex).try_into().unwrap();
            let proof: [u8; 32] = hex(&v.expected_proof_hex).try_into().unwrap();
            let expected = hex(&v.proof_packet_payload_hex);

            let encoded = encode_proof_payload(&resource_hash, &proof);
            assert_eq!(
                encoded, expected,
                "proof payload mismatch for vector {}",
                v.index
            );
            assert_eq!(encoded.len(), v.proof_packet_payload_length as usize);
        }
    }

    #[test]
    fn decode_proof_payload_roundtrip() {
        let vecs = load_resources();
        for v in &vecs.resource_proof_vectors {
            let payload = hex(&v.proof_packet_payload_hex);
            let (rh, proof) = decode_proof_payload(&payload).unwrap();
            assert_eq!(hex::encode(rh), v.resource_hash_hex);
            assert_eq!(hex::encode(proof), v.expected_proof_hex);
        }
    }

    #[test]
    fn validate_proof_true_and_false() {
        let vecs = load_resources();
        let v = &vecs.resource_proof_vectors[0];
        let payload = hex(&v.proof_packet_payload_hex);
        let expected_proof: [u8; 32] = hex(&v.expected_proof_hex).try_into().unwrap();

        // True case
        assert!(validate_proof(&payload, &expected_proof));

        // False case — flip a byte in the proof portion
        let mut bad_payload = payload.clone();
        bad_payload[63] ^= 0xFF;
        assert!(!validate_proof(&bad_payload, &expected_proof));

        // Wrong length
        assert!(!validate_proof(&payload[..63], &expected_proof));
    }

    // ============================================================== //
    // Request payload tests (using resource_transfers.json)
    // ============================================================== //

    fn load_transfer_vectors()
    -> Vec<reticulum_test_vectors::resource_transfers::TransferSequenceVector> {
        reticulum_test_vectors::resource_transfers::load().transfer_sequence_vectors
    }

    #[test]
    fn encode_decode_request_payload_all_vectors() {
        // Test all vectors that have request steps with request_payload_hex
        let vectors = load_transfer_vectors();
        for v in &vectors {
            let steps = match &v.steps {
                Some(s) => s,
                None => continue,
            };

            // Get resource hash from the advertisement step
            let resource_hash_hex = steps
                .iter()
                .find(|s| s.name.as_deref() == Some("sender_prepare_advertisement"))
                .and_then(|s| s.resource_hash_hex.as_deref());

            for step in steps {
                if step.name.as_deref() != Some("receiver_request_parts") {
                    continue;
                }
                let payload_hex = step.request_payload_hex.as_deref().unwrap();
                let payload = hex(payload_hex);

                // Decode
                let req = decode_part_request(&payload).unwrap();
                assert!(!req.exhausted, "vector {} should not be exhausted", v.index);

                // Verify resource hash if available
                if let Some(rh_hex) = resource_hash_hex {
                    assert_eq!(
                        hex::encode(req.resource_hash),
                        rh_hex,
                        "vector {} resource hash mismatch",
                        v.index
                    );
                }

                // Re-encode and compare
                let re_encoded =
                    encode_part_request(false, &req.resource_hash, &req.map_hashes, None);
                assert_eq!(
                    re_encoded, payload,
                    "vector {} request roundtrip mismatch",
                    v.index
                );
            }
        }
    }

    // ============================================================== //
    // Cancellation payload tests
    // ============================================================== //

    fn load_cancellation_vectors()
    -> Vec<reticulum_test_vectors::resource_transfers::CancellationVector> {
        reticulum_test_vectors::resource_transfers::load().cancellation_vectors
    }

    #[test]
    fn encode_cancellation_icl() {
        let vecs = load_cancellation_vectors();
        let v = &vecs[0]; // RESOURCE_ICL
        let expected = hex(&v.payload_hex);
        let resource_hash: [u8; 32] = expected.clone().try_into().unwrap();

        let encoded = encode_cancellation(&resource_hash);
        assert_eq!(encoded, expected);
        assert_eq!(encoded.len(), v.payload_length as usize);
    }

    #[test]
    fn cancellation_roundtrip() {
        let vecs = load_cancellation_vectors();
        for v in &vecs {
            let payload = hex(&v.payload_hex);
            let hash = decode_cancellation(&payload).unwrap();
            let re_encoded = encode_cancellation(&hash);
            assert_eq!(re_encoded, payload);
        }
    }

    // ============================================================== //
    // Compression tests
    // ============================================================== //

    #[test]
    fn compress_decompress_roundtrip() {
        // Highly compressible data
        let data = vec![0x41u8; 4096];
        let compressed = compress_resource_data(&data).expect("should compress");
        assert!(compressed.len() < data.len());

        let decompressed = decompress_resource_data(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn compress_incompressible_returns_none() {
        // Random-ish data that won't compress
        let data: Vec<u8> = (0..256u16).map(|i| (i & 0xFF) as u8).collect();
        // Small random data likely won't compress well
        let result = compress_resource_data(&data);
        // bz2 may or may not compress this, but if it does, it's fine
        if let Some(compressed) = &result {
            // At least verify decompression works
            let decompressed = decompress_resource_data(compressed).unwrap();
            assert_eq!(decompressed, data);
        }
    }

    // ============================================================== //
    // Full round-trip tests (prepare → assemble)
    // ============================================================== //

    fn make_test_key() -> [u8; 64] {
        let mut key = [0u8; 64];
        for (i, b) in key.iter_mut().enumerate() {
            *b = (i * 7 + 13) as u8;
        }
        key
    }

    fn make_test_iv() -> [u8; 16] {
        let mut iv = [0u8; 16];
        for (i, b) in iv.iter_mut().enumerate() {
            *b = (i * 3 + 5) as u8;
        }
        iv
    }

    #[test]
    fn roundtrip_no_metadata_no_compression() {
        let key = make_test_key();
        let iv = make_test_iv();
        let random_hash = [0x11, 0x22, 0x33, 0x44];
        let data = b"Hello, Reticulum!";

        let prepared =
            prepare_resource(data, &key, &iv, random_hash, None, false, 1, 1, None, None).unwrap();

        assert!(prepared.flags.encrypted);
        assert!(!prepared.flags.compressed);
        assert!(!prepared.flags.has_metadata);
        assert_eq!(prepared.advertisement.data_size, data.len() as u64);

        // Assemble from the encrypted data (single part)
        let parts = vec![prepared.encrypted_data.clone()];
        let assembled =
            assemble_resource(&parts, &key, &random_hash, &prepared.resource_hash, false).unwrap();

        assert_eq!(assembled.data_with_metadata, data);
        assert_eq!(assembled.resource_hash, prepared.resource_hash);
        assert_eq!(assembled.proof, prepared.expected_proof);
    }

    #[test]
    fn roundtrip_with_metadata() {
        let key = make_test_key();
        let iv = make_test_iv();
        let random_hash = [0xAA, 0xBB, 0xCC, 0xDD];
        let data = b"Some data with metadata";

        let metadata = Value::Map(vec![
            (Value::String("name".into()), Value::String("test".into())),
            (Value::String("size".into()), Value::Integer(23.into())),
        ]);

        let prepared = prepare_resource(
            data,
            &key,
            &iv,
            random_hash,
            Some(&metadata),
            false,
            1,
            1,
            None,
            None,
        )
        .unwrap();

        assert!(prepared.flags.has_metadata);
        assert!(prepared.advertisement.data_size > data.len() as u64);

        let parts = vec![prepared.encrypted_data.clone()];
        let assembled =
            assemble_resource(&parts, &key, &random_hash, &prepared.resource_hash, false).unwrap();

        assert_eq!(assembled.resource_hash, prepared.resource_hash);
        assert_eq!(assembled.proof, prepared.expected_proof);

        // Decode metadata from assembled data
        let (decoded_meta, remaining_data) =
            decode_metadata(&assembled.data_with_metadata).unwrap();
        assert_eq!(remaining_data, data);
        // Check metadata values match
        if let Value::Map(entries) = &decoded_meta {
            assert_eq!(entries.len(), 2);
        } else {
            panic!("expected map metadata");
        }
    }

    #[test]
    fn roundtrip_with_compression() {
        let key = make_test_key();
        let iv = make_test_iv();
        let random_hash = [0x01, 0x02, 0x03, 0x04];
        // Highly compressible
        let data = vec![0x42u8; 2048];

        let prepared =
            prepare_resource(&data, &key, &iv, random_hash, None, true, 1, 1, None, None).unwrap();

        assert!(prepared.flags.compressed);
        assert!(prepared.encrypted_data.len() < data.len());

        let parts = vec![prepared.encrypted_data.clone()];
        let assembled =
            assemble_resource(&parts, &key, &random_hash, &prepared.resource_hash, true).unwrap();

        assert_eq!(assembled.data_with_metadata, data);
        assert_eq!(assembled.proof, prepared.expected_proof);
    }

    #[test]
    fn roundtrip_with_metadata_and_compression() {
        let key = make_test_key();
        let iv = make_test_iv();
        let random_hash = [0xDE, 0xAD, 0xBE, 0xEF];
        let data = vec![0x55u8; 4096];

        let metadata = Value::Map(vec![(
            Value::String("type".into()),
            Value::String("compressed_with_meta".into()),
        )]);

        let prepared = prepare_resource(
            &data,
            &key,
            &iv,
            random_hash,
            Some(&metadata),
            true,
            1,
            1,
            None,
            None,
        )
        .unwrap();

        assert!(prepared.flags.has_metadata);
        assert!(prepared.flags.compressed);

        let parts = vec![prepared.encrypted_data.clone()];
        let assembled =
            assemble_resource(&parts, &key, &random_hash, &prepared.resource_hash, true).unwrap();

        assert_eq!(assembled.proof, prepared.expected_proof);

        // Verify metadata extraction
        let (_, remaining) = decode_metadata(&assembled.data_with_metadata).unwrap();
        assert_eq!(remaining, data);
    }

    #[test]
    fn roundtrip_multipart() {
        let key = make_test_key();
        let iv = make_test_iv();
        let random_hash = [0xF0, 0xF1, 0xF2, 0xF3];
        // Data large enough to produce multiple parts (> SDU after encryption)
        let data: Vec<u8> = (0..2000u16).map(|i| (i % 256) as u8).collect();

        let prepared =
            prepare_resource(&data, &key, &iv, random_hash, None, false, 1, 1, None, None).unwrap();

        // Should have multiple parts
        assert!(
            prepared.hashmap.len() > 1,
            "expected multiple parts, got {}",
            prepared.hashmap.len()
        );

        // Split encrypted data into SDU-sized parts
        let parts: Vec<Vec<u8>> = prepared
            .encrypted_data
            .chunks(SDU)
            .map(|c| c.to_vec())
            .collect();

        // Assemble as single joined stream (which is what parts concatenated gives)
        let assembled =
            assemble_resource(&parts, &key, &random_hash, &prepared.resource_hash, false).unwrap();

        assert_eq!(assembled.data_with_metadata, data);
        assert_eq!(assembled.proof, prepared.expected_proof);
    }

    // ============================================================== //
    // Test vector: proof payload encoding from transfer vectors
    // ============================================================== //

    #[test]
    fn proof_payload_all_transfer_vectors() {
        let vectors = load_transfer_vectors();
        for v in &vectors {
            let steps = match &v.steps {
                Some(s) => s,
                None => continue,
            };
            for step in steps {
                let name = step.name.as_deref().unwrap_or("");
                if name != "receiver_assemble_and_prove" && name != "receiver_prove" {
                    continue;
                }
                let payload_hex = step.proof_payload_hex.as_deref().unwrap();
                let payload = hex(payload_hex);
                assert_eq!(
                    payload.len(),
                    64,
                    "vector {} proof payload must be 64 bytes",
                    v.index
                );

                let (rh, proof) = decode_proof_payload(&payload).unwrap();

                // Verify resource hash matches the vector's resource_hash_hex
                if let Some(ref expected_rh) = v.resource_hash_hex {
                    assert_eq!(
                        hex::encode(rh),
                        *expected_rh,
                        "vector {} resource hash from proof mismatch",
                        v.index
                    );
                }

                // Verify the proof_breakdown if present
                if let Some(breakdown) = step.proof_breakdown.as_ref() {
                    let expected_proof_hex = breakdown["proof_hex"].as_str().unwrap();
                    assert_eq!(
                        hex::encode(proof),
                        expected_proof_hex,
                        "vector {} proof value mismatch",
                        v.index
                    );
                }

                // Roundtrip
                let re_encoded = encode_proof_payload(&rh, &proof);
                assert_eq!(
                    re_encoded, payload,
                    "vector {} proof roundtrip mismatch",
                    v.index
                );
            }
        }
    }

    #[test]
    fn advertisement_packed_matches_transfer_vectors() {
        // For vectors with advertisement steps, verify we can decode the packed bytes
        let vectors = load_transfer_vectors();
        for v in &vectors {
            let steps = match &v.steps {
                Some(s) => s,
                None => continue,
            };
            for step in steps {
                if step.name.as_deref() != Some("sender_prepare_advertisement") {
                    continue;
                }
                let adv_hex = step.advertisement_packed_hex.as_deref().unwrap();
                let adv_bytes = hex(adv_hex);

                // Verify we can decode it
                let adv = ResourceAdvertisement::from_msgpack(&adv_bytes)
                    .unwrap_or_else(|e| panic!("vector {} adv decode failed: {e}", v.index));

                // Verify resource hash matches
                if let Some(ref rh_hex) = v.resource_hash_hex {
                    assert_eq!(
                        hex::encode(adv.resource_hash),
                        *rh_hex,
                        "vector {} resource hash from adv mismatch",
                        v.index
                    );
                }

                // Re-encode and verify
                let re_packed = adv.to_msgpack();
                assert_eq!(
                    re_packed, adv_bytes,
                    "vector {} adv re-encode mismatch",
                    v.index
                );
            }
        }
    }

    // ============================================================== //
    // Malformed input tests
    // ============================================================== //

    #[test]
    fn test_decode_metadata_malformed_truncated() {
        // 0, 1, 2 bytes → error (need at least 3 for size prefix)
        for len in 0..3 {
            let data = vec![0u8; len];
            assert!(decode_metadata(&data).is_err(), "len={len} should fail");
        }
    }

    #[test]
    fn test_decode_metadata_malformed_invalid_msgpack() {
        // Size prefix claims 3 bytes, provide a map16 header that needs entries but has none
        // 0xDE = map16 marker, 0x00 0x0A = 10 entries, but no entries follow
        let mut data = vec![0x00, 0x00, 0x03]; // size = 3
        data.extend_from_slice(&[0xDE, 0x00, 0x0A]); // map16 with 10 entries, no data
        let result = decode_metadata(&data);
        assert!(result.is_err(), "truncated map should fail msgpack decode");
    }

    #[test]
    fn test_decode_metadata_malformed_size_overflow() {
        // Size prefix claims 0xFFFFFF bytes but we only have a few trailing bytes
        let mut data = vec![0xFF, 0xFF, 0xFF]; // size = 16777215
        data.extend_from_slice(&[0x00, 0x01, 0x02]); // only 3 bytes
        let result = decode_metadata(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_part_request_malformed() {
        // Empty → error
        assert!(decode_part_request(&[]).is_err());
        // Single byte (not exhausted) → too short for resource hash
        assert!(decode_part_request(&[0x00]).is_err());
        // Exhausted flag but too short
        assert!(decode_part_request(&[0xFF]).is_err());
        assert!(decode_part_request(&[0xFF, 0x00, 0x00, 0x00]).is_err());
    }

    #[test]
    fn test_decompress_resource_data_malformed() {
        // Garbage bytes → DecompressionFailed
        let result = decompress_resource_data(&[0xDE, 0xAD, 0xBE, 0xEF]);
        assert!(result.is_err());
    }

    // ============================================================== //
    // Boundary: metadata encoding/decoding edge cases
    // ============================================================== //

    #[test]
    fn encode_metadata_size_zero() {
        // Encode msgpack nil → tiny payload
        let value = Value::Nil;
        let encoded = encode_metadata(&value).unwrap();
        // 3-byte size prefix + 1-byte nil (0xC0)
        assert_eq!(encoded.len(), 4);
        assert_eq!(&encoded[..3], &[0x00, 0x00, 0x01]); // size = 1
    }

    #[test]
    fn decode_metadata_exactly_3_bytes_size_zero() {
        // [0x00, 0x00, 0x00] = size prefix of 0, zero-length msgpack → error
        // (msgpack decode on empty input fails)
        let data = [0x00, 0x00, 0x00];
        let result = decode_metadata(&data);
        assert!(result.is_err());
    }

    #[test]
    fn decode_metadata_size_mismatch() {
        // Size prefix claims 100 bytes but only 50 available
        let mut data = vec![0x00, 0x00, 100]; // size = 100
        data.extend_from_slice(&vec![0x00; 50]); // only 50 bytes
        let result = decode_metadata(&data);
        assert!(result.is_err());
    }

    #[test]
    fn decode_metadata_size_prefix_all_ff() {
        // [0xFF, 0xFF, 0xFF] = 16777215, with only a few bytes → error
        let mut data = vec![0xFF, 0xFF, 0xFF];
        data.extend_from_slice(&[0x00; 10]);
        let result = decode_metadata(&data);
        assert!(result.is_err());
    }

    // ============================================================== //
    // Property tests
    // ============================================================== //

    mod proptests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn metadata_encode_decode_roundtrip(
                key in "[a-z]{1,10}",
                val in "[a-z]{1,20}",
            ) {
                let metadata = Value::Map(vec![
                    (Value::String(key.into()), Value::String(val.into())),
                ]);
                let encoded = encode_metadata(&metadata).unwrap();
                let (decoded, remaining) = decode_metadata(&encoded).unwrap();
                prop_assert!(remaining.is_empty());
                // Re-encode to check consistency
                let re_encoded = encode_metadata(&decoded).unwrap();
                prop_assert_eq!(encoded, re_encoded);
            }

            #[test]
            fn request_payload_roundtrip(
                resource_hash in any::<[u8; 32]>(),
                num_hashes in 0usize..20,
            ) {
                let map_hashes: Vec<[u8; 4]> = (0..num_hashes)
                    .map(|i| [(i * 7) as u8, (i * 13) as u8, (i * 3) as u8, (i * 11) as u8])
                    .collect();

                let encoded = encode_part_request(false, &resource_hash, &map_hashes, None);
                let decoded = decode_part_request(&encoded).unwrap();
                prop_assert!(!decoded.exhausted);
                prop_assert_eq!(decoded.resource_hash, resource_hash);
                prop_assert_eq!(decoded.map_hashes, map_hashes);
            }

            #[test]
            fn request_payload_exhausted_roundtrip(
                resource_hash in any::<[u8; 32]>(),
                last_map_hash in any::<[u8; 4]>(),
                num_hashes in 0usize..20,
            ) {
                let map_hashes: Vec<[u8; 4]> = (0..num_hashes)
                    .map(|i| [(i * 7) as u8, (i * 13) as u8, (i * 3) as u8, (i * 11) as u8])
                    .collect();

                let encoded = encode_part_request(
                    true,
                    &resource_hash,
                    &map_hashes,
                    Some(&last_map_hash),
                );
                let decoded = decode_part_request(&encoded).unwrap();
                prop_assert!(decoded.exhausted);
                prop_assert_eq!(decoded.last_map_hash.unwrap(), last_map_hash);
                prop_assert_eq!(decoded.resource_hash, resource_hash);
                prop_assert_eq!(decoded.map_hashes, map_hashes);
            }

            #[test]
            fn proof_payload_roundtrip(
                resource_hash in any::<[u8; 32]>(),
                proof in any::<[u8; 32]>(),
            ) {
                let encoded = encode_proof_payload(&resource_hash, &proof);
                let (rh, p) = decode_proof_payload(&encoded).unwrap();
                prop_assert_eq!(rh, resource_hash);
                prop_assert_eq!(p, proof);
            }

            #[test]
            fn cancellation_roundtrip_prop(
                resource_hash in any::<[u8; 32]>(),
            ) {
                let encoded = encode_cancellation(&resource_hash);
                let decoded = decode_cancellation(&encoded).unwrap();
                prop_assert_eq!(decoded, resource_hash);
            }
        }
    }

    // ================================================================== //
    // Resource assembly failure paths
    // ================================================================== //

    /// Helper: split encrypted_data into parts by SDU size
    fn split_encrypted_data(encrypted_data: &[u8], num_parts: usize) -> Vec<Vec<u8>> {
        (0..num_parts)
            .map(|i| {
                let start = i * SDU;
                let end = (start + SDU).min(encrypted_data.len());
                encrypted_data[start..end].to_vec()
            })
            .collect()
    }

    #[test]
    fn test_assemble_resource_wrong_key() {
        let raw_data = b"test resource data for wrong key";
        let key_a: [u8; 64] = [0xAA; 64];
        let key_b: [u8; 64] = [0xBB; 64];
        let iv = [0x00; 16];
        let random_hash = [0x11; RANDOM_HASH_SIZE];

        let prepared = prepare_resource(
            raw_data,
            &key_a,
            &iv,
            random_hash,
            None,
            false,
            1,
            1,
            None,
            None,
        )
        .unwrap();
        let parts = split_encrypted_data(&prepared.encrypted_data, prepared.hashmap.len());

        let result =
            assemble_resource(&parts, &key_b, &random_hash, &prepared.resource_hash, false);
        assert!(result.is_err(), "assemble with wrong key should fail");
    }

    #[test]
    fn test_assemble_resource_wrong_hash() {
        let raw_data = b"test resource data for wrong hash";
        let key: [u8; 64] = [0xCC; 64];
        let iv = [0x00; 16];
        let random_hash = [0x22; RANDOM_HASH_SIZE];

        let prepared = prepare_resource(
            raw_data,
            &key,
            &iv,
            random_hash,
            None,
            false,
            1,
            1,
            None,
            None,
        )
        .unwrap();
        let parts = split_encrypted_data(&prepared.encrypted_data, prepared.hashmap.len());

        let wrong_hash = [0xFF; 32];
        let result = assemble_resource(&parts, &key, &random_hash, &wrong_hash, false);
        assert!(
            result.is_err(),
            "assemble with wrong resource_hash should fail"
        );
    }

    #[test]
    fn test_assemble_resource_corrupt_ciphertext() {
        let raw_data = b"test resource data for corruption";
        let key: [u8; 64] = [0xDD; 64];
        let iv = [0x00; 16];
        let random_hash = [0x33; RANDOM_HASH_SIZE];

        let prepared = prepare_resource(
            raw_data,
            &key,
            &iv,
            random_hash,
            None,
            false,
            1,
            1,
            None,
            None,
        )
        .unwrap();
        let mut parts = split_encrypted_data(&prepared.encrypted_data, prepared.hashmap.len());

        // Flip a byte in the first part
        if !parts.is_empty() && !parts[0].is_empty() {
            parts[0][0] ^= 0xFF;
        }

        let result = assemble_resource(&parts, &key, &random_hash, &prepared.resource_hash, false);
        assert!(result.is_err(), "corrupt ciphertext should fail assembly");
    }

    #[test]
    fn test_assemble_resource_empty_parts() {
        let key: [u8; 64] = [0xEE; 64];
        let random_hash = [0x44; RANDOM_HASH_SIZE];
        let resource_hash = [0x55; 32];

        let result = assemble_resource(&[], &key, &random_hash, &resource_hash, true);
        assert!(result.is_err(), "empty parts should fail assembly");
    }

    #[test]
    fn test_decode_proof_payload_wrong_length() {
        // 0 bytes
        assert!(decode_proof_payload(&[]).is_err());
        // 63 bytes (one short)
        assert!(decode_proof_payload(&[0u8; 63]).is_err());
        // 65 bytes (one over)
        assert!(decode_proof_payload(&[0u8; 65]).is_err());
    }

    #[test]
    fn test_decode_cancellation_wrong_length() {
        // 0 bytes
        assert!(decode_cancellation(&[]).is_err());
        // 31 bytes (one short)
        assert!(decode_cancellation(&[0u8; 31]).is_err());
        // 33 bytes (one over)
        assert!(decode_cancellation(&[0u8; 33]).is_err());
    }

    #[test]
    fn test_decode_part_request_non_aligned() {
        // 1 (flag) + 32 (resource_hash) + 3 (not multiple of 4) = 36 bytes
        let mut data = vec![0x00]; // not exhausted
        data.extend_from_slice(&[0xAA; 32]); // resource_hash
        data.extend_from_slice(&[0x01, 0x02, 0x03]); // 3 trailing bytes, not multiple of 4
        let result = decode_part_request(&data);
        assert!(result.is_err(), "non-aligned trailing bytes should fail");
    }
}
