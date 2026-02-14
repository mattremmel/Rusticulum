//! Pure functions for resource transfer operations.
//!
//! These functions extract the advertisement parsing, part matching, and
//! assembly logic from [`ResourceManager`] into stateless functions that
//! are easy to unit-test without needing the full transfer lifecycle.

use reticulum_protocol::link::types::DerivedKey;
use reticulum_protocol::resource::advertisement::{ResourceAdvertisement, ResourceFlags};
use reticulum_protocol::resource::hashmap::ResourceHashmap;
use reticulum_protocol::resource::transfer::{
    assemble_resource, decode_part_request, decode_proof_payload, encode_part_request,
    encode_proof_payload, validate_proof,
};

/// Parsed and validated resource advertisement, ready for transfer setup.
pub struct ParsedAdvertisement {
    pub advertisement: ResourceAdvertisement,
    pub flags: ResourceFlags,
    pub hashmap: ResourceHashmap,
    pub resource_hash: [u8; 32],
    pub random_hash: [u8; 4],
    pub initial_request: Vec<u8>,
    pub num_parts: usize,
}

/// Parse a resource advertisement and prepare the initial part request.
///
/// Decodes the advertisement msgpack bytes, extracts the hashmap, and builds
/// a part request for all parts. Returns everything needed to set up an
/// incoming transfer.
pub fn parse_advertisement(adv_bytes: &[u8]) -> Result<ParsedAdvertisement, String> {
    let adv = ResourceAdvertisement::from_msgpack(adv_bytes)
        .map_err(|e| format!("decode advertisement: {e}"))?;

    let flags = adv.decoded_flags();
    let resource_hash = adv.resource_hash;
    let random_hash = adv.random_hash;

    let hashmap = ResourceHashmap::from_bytes(&adv.hashmap, random_hash)
        .map_err(|e| format!("decode hashmap: {e}"))?;

    let num_parts = hashmap.len();

    let all_map_hashes: Vec<[u8; 4]> = (0..num_parts).map(|i| *hashmap.get(i).unwrap()).collect();

    let initial_request = encode_part_request(false, &resource_hash, &all_map_hashes, None);

    Ok(ParsedAdvertisement {
        advertisement: adv,
        flags,
        hashmap,
        resource_hash,
        random_hash,
        initial_request,
        num_parts,
    })
}

/// Find which part slot incoming data belongs to by matching its map hash.
///
/// Iterates through `parts` looking for an unfilled slot whose expected
/// map hash (from the `hashmap`) matches the computed hash of `part_data`.
/// Returns the slot index, or `None` if no match is found.
pub fn match_resource_part(
    parts: &[Option<Vec<u8>>],
    hashmap: &ResourceHashmap,
    part_data: &[u8],
) -> Option<usize> {
    let computed_hash = hashmap.compute_map_hash(part_data);

    for (i, stored) in parts.iter().enumerate() {
        if stored.is_none()
            && let Some(expected) = hashmap.get(i)
            && *expected == computed_hash
        {
            return Some(i);
        }
    }

    None
}

/// Collect all received parts and assemble the resource.
///
/// Verifies all parts are present, calls [`assemble_resource`] to decrypt
/// and decompress, then encodes the proof payload.
///
/// Returns `(original_data, proof_payload_bytes)`.
pub fn collect_and_assemble(
    parts: &[Option<Vec<u8>>],
    derived_key: &DerivedKey,
    random_hash: &[u8; 4],
    resource_hash: &[u8; 32],
    compressed: bool,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let collected: Vec<Vec<u8>> = parts
        .iter()
        .enumerate()
        .map(|(i, p)| p.clone().ok_or_else(|| format!("missing part {i}")))
        .collect::<Result<Vec<_>, _>>()?;

    let assembled = assemble_resource(
        &collected,
        derived_key.as_bytes(),
        random_hash,
        resource_hash,
        compressed,
    )
    .map_err(|e| format!("assemble_resource failed: {e}"))?;

    let proof_bytes = encode_proof_payload(&assembled.resource_hash, &assembled.proof);

    Ok((assembled.data_with_metadata, proof_bytes))
}

// ======================================================================== //
// Extraction: select_parts_for_request
// ======================================================================== //

/// Parts selected for a part request.
pub struct PartSelection {
    /// The resource hash from the request.
    pub resource_hash: [u8; 32],
    /// The selected parts to send (MVP: all available parts).
    pub selected_parts: Vec<Vec<u8>>,
}

/// Decode a part request and select matching parts from the available set.
///
/// MVP behaviour: returns all available parts regardless of which map hashes
/// were requested. The resource_hash is extracted for the caller to validate
/// against its outgoing transfer table.
pub fn select_parts_for_request(
    request_data: &[u8],
    available_parts: &[Vec<u8>],
) -> Result<PartSelection, String> {
    let req = decode_part_request(request_data).map_err(|e| format!("decode part request: {e}"))?;

    Ok(PartSelection {
        resource_hash: req.resource_hash,
        selected_parts: available_parts.to_vec(),
    })
}

// ======================================================================== //
// Extraction: validate_resource_proof
// ======================================================================== //

/// Result of validating a resource proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofValidation {
    /// The proof matched the expected value.
    Valid { resource_hash: [u8; 32] },
    /// The proof did not match the expected value.
    Invalid { resource_hash: [u8; 32] },
}

/// Decode a proof payload and validate it against the expected proof.
///
/// Returns `Valid` or `Invalid` with the resource_hash, or an error
/// if the proof data cannot be decoded.
pub fn validate_resource_proof(
    proof_data: &[u8],
    expected_proof: &[u8; 32],
) -> Result<ProofValidation, String> {
    let (resource_hash, _proof) =
        decode_proof_payload(proof_data).map_err(|e| format!("decode proof: {e}"))?;

    if validate_proof(proof_data, expected_proof) {
        Ok(ProofValidation::Valid { resource_hash })
    } else {
        Ok(ProofValidation::Invalid { resource_hash })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reticulum_protocol::link::types::DerivedKey;
    use reticulum_protocol::resource::constants::SDU;
    use reticulum_protocol::resource::transfer::prepare_resource;

    fn make_test_derived_key() -> DerivedKey {
        let mut key = [0u8; 64];
        for (i, b) in key.iter_mut().enumerate() {
            *b = (i * 7 + 13) as u8;
        }
        DerivedKey::new(key)
    }

    /// Helper: prepare a resource and return (adv_bytes, encrypted_parts, resource_hash, random_hash)
    fn prepare_test_resource(data: &[u8]) -> (Vec<u8>, Vec<Vec<u8>>, [u8; 32], [u8; 4]) {
        let key = make_test_derived_key();
        let iv = [0x42u8; 16];
        let random_hash = [0xAA, 0xBB, 0xCC, 0xDD];

        let prepared = prepare_resource(
            data,
            key.as_bytes(),
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

        let adv_bytes = prepared.advertisement.to_msgpack();
        let parts: Vec<Vec<u8>> = prepared
            .encrypted_data
            .chunks(SDU)
            .map(|c| c.to_vec())
            .collect();

        (adv_bytes, parts, prepared.resource_hash, random_hash)
    }

    // -- parse_advertisement tests -------------------------------------------

    #[test]
    fn parse_advertisement_roundtrip() {
        let (adv_bytes, _, _, _) = prepare_test_resource(b"hello world");
        let parsed = parse_advertisement(&adv_bytes).unwrap();
        assert!(!parsed.initial_request.is_empty());
        assert!(parsed.num_parts > 0);
    }

    #[test]
    fn parse_advertisement_correct_num_parts() {
        let data = b"test data for resource";
        let (adv_bytes, parts, _, _) = prepare_test_resource(data);
        let parsed = parse_advertisement(&adv_bytes).unwrap();
        assert_eq!(parsed.num_parts, parts.len());
    }

    #[test]
    fn parse_advertisement_initial_request_contains_all_hashes() {
        let (adv_bytes, _, _, _) = prepare_test_resource(b"test resource");
        let parsed = parse_advertisement(&adv_bytes).unwrap();

        // The initial request should be non-trivial (has resource_hash + all map hashes)
        // Minimum size: 1 (flag) + 32 (resource_hash) + 4*num_parts (map hashes)
        let expected_min = 1 + 32 + 4 * parsed.num_parts;
        assert!(
            parsed.initial_request.len() >= expected_min,
            "request len {} < expected min {}",
            parsed.initial_request.len(),
            expected_min
        );
    }

    #[test]
    fn parse_advertisement_invalid_bytes() {
        let result = parse_advertisement(&[0xFF, 0x00, 0x01]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_advertisement_preserves_resource_hash() {
        let (adv_bytes, _, resource_hash, _) = prepare_test_resource(b"check hash");
        let parsed = parse_advertisement(&adv_bytes).unwrap();
        assert_eq!(parsed.resource_hash, resource_hash);
    }

    // -- match_resource_part tests -------------------------------------------

    #[test]
    fn match_resource_part_finds_correct_slot() {
        let (adv_bytes, parts, _, _) = prepare_test_resource(b"single part test data");
        let parsed = parse_advertisement(&adv_bytes).unwrap();

        let mut slots: Vec<Option<Vec<u8>>> = vec![None; parsed.num_parts];

        // First part should match slot 0
        let idx = match_resource_part(&slots, &parsed.hashmap, &parts[0]);
        assert_eq!(idx, Some(0));

        // Fill slot 0 and check remaining parts
        slots[0] = Some(parts[0].clone());

        if parts.len() > 1 {
            let idx = match_resource_part(&slots, &parsed.hashmap, &parts[1]);
            assert_eq!(idx, Some(1));
        }
    }

    #[test]
    fn match_resource_part_returns_none_for_unknown_data() {
        let (adv_bytes, _, _, _) = prepare_test_resource(b"test data");
        let parsed = parse_advertisement(&adv_bytes).unwrap();
        let slots: Vec<Option<Vec<u8>>> = vec![None; parsed.num_parts];

        let idx = match_resource_part(&slots, &parsed.hashmap, b"garbage data that doesn't match");
        assert!(idx.is_none());
    }

    #[test]
    fn match_resource_part_skips_filled_slots() {
        let data: Vec<u8> = (0..2000u16).map(|i| (i % 256) as u8).collect();
        let (adv_bytes, parts, _, _) = prepare_test_resource(&data);
        let parsed = parse_advertisement(&adv_bytes).unwrap();

        assert!(parts.len() > 1, "need multi-part resource for this test");

        let mut slots: Vec<Option<Vec<u8>>> = vec![None; parsed.num_parts];

        // Fill slot 0
        slots[0] = Some(parts[0].clone());

        // Part 0 should no longer match (slot is filled)
        let idx = match_resource_part(&slots, &parsed.hashmap, &parts[0]);
        assert!(idx.is_none());
    }

    #[test]
    fn match_resource_part_single_part_resource() {
        // Small data should produce a single part
        let (adv_bytes, parts, _, _) = prepare_test_resource(b"tiny");
        let parsed = parse_advertisement(&adv_bytes).unwrap();
        let slots: Vec<Option<Vec<u8>>> = vec![None; parsed.num_parts];

        let idx = match_resource_part(&slots, &parsed.hashmap, &parts[0]);
        assert_eq!(idx, Some(0));
    }

    // -- collect_and_assemble tests ------------------------------------------

    #[test]
    fn collect_and_assemble_succeeds_with_all_parts() {
        let data = b"resource assembly test!";
        let key = make_test_derived_key();
        let (adv_bytes, parts, resource_hash, _) = prepare_test_resource(data);
        let parsed = parse_advertisement(&adv_bytes).unwrap();

        let filled: Vec<Option<Vec<u8>>> = parts.into_iter().map(Some).collect();

        let (result_data, proof_bytes) = collect_and_assemble(
            &filled,
            &key,
            &parsed.random_hash,
            &resource_hash,
            parsed.flags.compressed,
        )
        .unwrap();

        assert_eq!(result_data, data);
        assert!(!proof_bytes.is_empty());
    }

    #[test]
    fn collect_and_assemble_fails_when_part_missing() {
        let data = b"resource assembly test!";
        let key = make_test_derived_key();
        let (adv_bytes, _, resource_hash, _) = prepare_test_resource(data);
        let parsed = parse_advertisement(&adv_bytes).unwrap();

        // All slots None
        let empty: Vec<Option<Vec<u8>>> = vec![None; parsed.num_parts];

        let result = collect_and_assemble(
            &empty,
            &key,
            &parsed.random_hash,
            &resource_hash,
            parsed.flags.compressed,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing part"));
    }

    #[test]
    fn collect_and_assemble_proof_matches_prepare() {
        use reticulum_protocol::resource::transfer::validate_proof as proto_validate_proof;

        let data = b"proof validation roundtrip";
        let key = make_test_derived_key();
        let iv = [0x42u8; 16];
        let random_hash = [0xAA, 0xBB, 0xCC, 0xDD];

        let prepared = prepare_resource(
            data,
            key.as_bytes(),
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

        let adv_bytes = prepared.advertisement.to_msgpack();
        let parts: Vec<Vec<u8>> = prepared
            .encrypted_data
            .chunks(SDU)
            .map(|c| c.to_vec())
            .collect();

        let parsed = parse_advertisement(&adv_bytes).unwrap();
        let filled: Vec<Option<Vec<u8>>> = parts.into_iter().map(Some).collect();

        let (_result_data, proof_bytes) = collect_and_assemble(
            &filled,
            &key,
            &parsed.random_hash,
            &parsed.resource_hash,
            parsed.flags.compressed,
        )
        .unwrap();

        // The proof should validate against the expected proof from prepare_resource
        assert!(proto_validate_proof(&proof_bytes, &prepared.expected_proof));
    }

    // -- select_parts_for_request tests -----------------------------------------

    #[test]
    fn select_parts_valid_request() {
        let (adv_bytes, parts, _, _) = prepare_test_resource(b"test data");
        let parsed = parse_advertisement(&adv_bytes).unwrap();

        let selection = select_parts_for_request(&parsed.initial_request, &parts).unwrap();
        assert_eq!(selection.resource_hash, parsed.resource_hash);
        assert_eq!(selection.selected_parts.len(), parts.len());
    }

    #[test]
    fn select_parts_single_part() {
        let (adv_bytes, parts, _, _) = prepare_test_resource(b"tiny");
        let parsed = parse_advertisement(&adv_bytes).unwrap();
        assert_eq!(parts.len(), 1);

        let selection = select_parts_for_request(&parsed.initial_request, &parts).unwrap();
        assert_eq!(selection.selected_parts.len(), 1);
        assert_eq!(selection.selected_parts[0], parts[0]);
    }

    #[test]
    fn select_parts_multiple() {
        let data: Vec<u8> = (0..2000u16).map(|i| (i % 256) as u8).collect();
        let (adv_bytes, parts, _, _) = prepare_test_resource(&data);
        let parsed = parse_advertisement(&adv_bytes).unwrap();
        assert!(parts.len() > 1);

        let selection = select_parts_for_request(&parsed.initial_request, &parts).unwrap();
        assert_eq!(selection.selected_parts.len(), parts.len());
        for (i, part) in selection.selected_parts.iter().enumerate() {
            assert_eq!(part, &parts[i]);
        }
    }

    #[test]
    fn select_parts_empty_request_error() {
        let result = select_parts_for_request(&[], &[vec![1, 2, 3]]);
        assert!(result.is_err());
    }

    #[test]
    fn select_parts_corrupt_request_error() {
        let result = select_parts_for_request(&[0xAB, 0xCD], &[vec![1, 2, 3]]);
        assert!(result.is_err());
    }

    #[test]
    fn select_parts_resource_hash_extracted() {
        let (adv_bytes, parts, resource_hash, _) = prepare_test_resource(b"hash check");
        let parsed = parse_advertisement(&adv_bytes).unwrap();

        let selection = select_parts_for_request(&parsed.initial_request, &parts).unwrap();
        assert_eq!(selection.resource_hash, resource_hash);
    }

    // -- validate_resource_proof tests ------------------------------------------

    #[test]
    fn validate_proof_valid() {
        let data = b"proof test data";
        let key = make_test_derived_key();
        let (adv_bytes, parts, _, _) = prepare_test_resource(data);
        let parsed = parse_advertisement(&adv_bytes).unwrap();
        let filled: Vec<Option<Vec<u8>>> = parts.into_iter().map(Some).collect();

        let (_result_data, proof_bytes) = collect_and_assemble(
            &filled,
            &key,
            &parsed.random_hash,
            &parsed.resource_hash,
            parsed.flags.compressed,
        )
        .unwrap();

        // Get expected proof from prepare_resource
        let iv = [0x42u8; 16];
        let random_hash = [0xAA, 0xBB, 0xCC, 0xDD];
        let prepared = prepare_resource(
            data,
            key.as_bytes(),
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

        let result = validate_resource_proof(&proof_bytes, &prepared.expected_proof).unwrap();
        assert_eq!(
            result,
            ProofValidation::Valid {
                resource_hash: parsed.resource_hash
            }
        );
    }

    #[test]
    fn validate_proof_invalid() {
        let data = b"proof test data";
        let key = make_test_derived_key();
        let (adv_bytes, parts, _, _) = prepare_test_resource(data);
        let parsed = parse_advertisement(&adv_bytes).unwrap();
        let filled: Vec<Option<Vec<u8>>> = parts.into_iter().map(Some).collect();

        let (_result_data, proof_bytes) = collect_and_assemble(
            &filled,
            &key,
            &parsed.random_hash,
            &parsed.resource_hash,
            parsed.flags.compressed,
        )
        .unwrap();

        // Use wrong expected proof
        let wrong_proof = [0xFFu8; 32];
        let result = validate_resource_proof(&proof_bytes, &wrong_proof).unwrap();
        assert_eq!(
            result,
            ProofValidation::Invalid {
                resource_hash: parsed.resource_hash
            }
        );
    }

    #[test]
    fn validate_proof_too_short_error() {
        let result = validate_resource_proof(&[0x00; 10], &[0x00; 32]);
        assert!(result.is_err());
    }

    #[test]
    fn validate_proof_empty_error() {
        let result = validate_resource_proof(&[], &[0x00; 32]);
        assert!(result.is_err());
    }

    #[test]
    fn validate_proof_wrong_length_error() {
        // 63 bytes instead of 64
        let result = validate_resource_proof(&[0x00; 63], &[0x00; 32]);
        assert!(result.is_err());
    }

    #[test]
    fn validate_proof_extracts_resource_hash() {
        // Construct a valid 64-byte proof payload manually
        let resource_hash = [0xAA; 32];
        let proof = [0xBB; 32];
        let mut proof_data = Vec::new();
        proof_data.extend_from_slice(&resource_hash);
        proof_data.extend_from_slice(&proof);

        // Expected proof matches
        let result = validate_resource_proof(&proof_data, &proof).unwrap();
        match result {
            ProofValidation::Valid { resource_hash: rh } => {
                assert_eq!(rh, resource_hash);
            }
            _ => panic!("expected Valid"),
        }
    }
}
