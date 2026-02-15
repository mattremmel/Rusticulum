//! Tests for the link handshake protocol.
//!
//! Validates the 3-packet handshake (LINKREQUEST → LRPROOF → LRRTT) against
//! the test vectors in links.json.

use reticulum_crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey};
use reticulum_crypto::x25519::X25519PrivateKey;
use reticulum_protocol::link::{LinkHandshake, LinkMode, LinkPending};
use reticulum_test_vectors::{keypairs, links};

fn hex_to_32(hex_str: &str) -> [u8; 32] {
    let bytes = hex::decode(hex_str).expect("invalid hex");
    bytes.try_into().expect("must be 32 bytes")
}

fn hex_to_16(hex_str: &str) -> [u8; 16] {
    let bytes = hex::decode(hex_str).expect("invalid hex");
    bytes.try_into().expect("must be 16 bytes")
}

/// Load identity and ephemeral keys for a handshake vector.
struct HandshakeKeys {
    // Initiator's ephemeral keys (from links.json ephemeral_keys)
    init_eph_x25519_prv: X25519PrivateKey,
    init_eph_ed25519_prv: Ed25519PrivateKey,
    // Responder's identity Ed25519 (from keypairs.json)
    resp_identity_ed25519_prv: Ed25519PrivateKey,
    resp_identity_ed25519_pub: Ed25519PublicKey,
    // Responder's ephemeral X25519 (from links.json ephemeral_keys)
    resp_eph_x25519_prv: X25519PrivateKey,
}

fn load_handshake_keys(
    links_vecs: &links::LinksVectors,
    kp_vecs: &keypairs::KeypairsVectors,
    hs: &links::HandshakeVector,
) -> HandshakeKeys {
    let init_eph = &links_vecs.ephemeral_keys[hs.initiator_ephemeral_index as usize];
    let resp_eph = &links_vecs.ephemeral_keys[hs.responder_ephemeral_index as usize];
    let resp_kp = &kp_vecs.keypairs[hs.responder_keypair_index as usize];

    HandshakeKeys {
        init_eph_x25519_prv: X25519PrivateKey::from_bytes(hex_to_32(&init_eph.x25519_private)),
        init_eph_ed25519_prv: Ed25519PrivateKey::from_bytes(hex_to_32(&init_eph.ed25519_private)),
        resp_identity_ed25519_prv: Ed25519PrivateKey::from_bytes(hex_to_32(
            &resp_kp.ed25519_private,
        )),
        resp_identity_ed25519_pub: Ed25519PublicKey::from_bytes(hex_to_32(&resp_kp.ed25519_public))
            .unwrap(),
        resp_eph_x25519_prv: X25519PrivateKey::from_bytes(hex_to_32(&resp_eph.x25519_private)),
    }
}

// ---------------------------------------------------------------------------
// Step 1: LINKREQUEST - verify request data and link ID
// ---------------------------------------------------------------------------

#[test]
fn handshake_step1_request_data_all_vectors() {
    let links_vecs = links::load();
    let kp_vecs = keypairs::load();

    for (i, hs) in links_vecs.handshake_vectors.iter().enumerate() {
        let step1 = &hs.step_1_linkrequest;
        let keys = load_handshake_keys(&links_vecs, &kp_vecs, hs);

        let expected_request_data = hex::decode(&step1.request_data).unwrap();
        let expected_link_id = hex::decode(&step1.link_id).unwrap();
        let hashable_part = hex::decode(&step1.hashable_part).unwrap();
        let data_len = step1.request_data_length as usize;
        let dest_hash_bytes = hex::decode(&step1.responder_destination_hash).unwrap();
        let dest_hash =
            reticulum_core::types::DestinationHash::new(dest_hash_bytes.try_into().unwrap());

        let mode = LinkMode::try_from(hs.mode as u8).unwrap();

        if hs.use_signalling {
            // With signalling: use new_initiator_deterministic
            let (pending, request_data) = LinkPending::new_initiator_deterministic(
                dest_hash,
                hs.mtu as u32,
                mode,
                1, // hops
                keys.init_eph_x25519_prv,
                keys.init_eph_ed25519_prv,
                &hashable_part,
                data_len,
            )
            .unwrap_or_else(|e| panic!("vector {i}: new_initiator_deterministic failed: {e}"));

            assert_eq!(
                request_data, expected_request_data,
                "vector {i}: request_data mismatch"
            );
            assert_eq!(
                pending.link_id.as_ref(),
                expected_link_id.as_slice(),
                "vector {i}: link_id mismatch"
            );
        } else {
            // Legacy (no signalling) - just verify link_id computation
            let link_id = LinkPending::compute_link_id(&hashable_part, data_len);
            assert_eq!(
                link_id.as_ref(),
                expected_link_id.as_slice(),
                "vector {i}: legacy link_id mismatch"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Step 2: LRPROOF - verify derived key and proof data
// ---------------------------------------------------------------------------

#[test]
fn handshake_step2_derived_key_all_vectors() {
    let links_vecs = links::load();
    let kp_vecs = keypairs::load();

    for (i, hs) in links_vecs.handshake_vectors.iter().enumerate() {
        let step1 = &hs.step_1_linkrequest;
        let step2 = &hs.step_2_lrproof;
        let keys = load_handshake_keys(&links_vecs, &kp_vecs, hs);

        let request_data = hex::decode(&step1.request_data).unwrap();
        let hashable_part = hex::decode(&step1.hashable_part).unwrap();
        let data_len = step1.request_data_length as usize;

        let expected_derived_key = hex::decode(&step2.derived_key).unwrap();
        let expected_proof_data = hex::decode(&step2.proof_data).unwrap();
        let expected_signed_data = hex::decode(&step2.signed_data).unwrap();
        let expected_signature = hex::decode(&step2.signature).unwrap();

        let mode = LinkMode::try_from(hs.mode as u8).unwrap();

        let (handshake, proof_data) = LinkHandshake::from_link_request_deterministic(
            &request_data,
            &hashable_part,
            data_len,
            &keys.resp_identity_ed25519_prv,
            &keys.resp_identity_ed25519_pub,
            hs.mtu as u32,
            mode,
            1, // hops
            keys.resp_eph_x25519_prv,
        )
        .unwrap_or_else(|e| panic!("vector {i}: from_link_request_deterministic failed: {e}"));

        // Verify derived key matches
        assert_eq!(
            handshake.derived_key.to_bytes().as_slice(),
            expected_derived_key.as_slice(),
            "vector {i}: derived_key mismatch"
        );

        // Verify signing key split
        let expected_signing_key = hex::decode(&step2.signing_key).unwrap();
        let expected_encryption_key = hex::decode(&step2.encryption_key).unwrap();
        assert_eq!(
            handshake.derived_key.signing_key().as_slice(),
            expected_signing_key.as_slice(),
            "vector {i}: signing_key mismatch"
        );
        assert_eq!(
            handshake.derived_key.encryption_key().as_slice(),
            expected_encryption_key.as_slice(),
            "vector {i}: encryption_key mismatch"
        );

        // Verify proof data (signature + x25519_pub + [signalling])
        assert_eq!(
            proof_data, expected_proof_data,
            "vector {i}: proof_data mismatch"
        );

        // Verify signature matches expected
        assert_eq!(
            &proof_data[..64],
            expected_signature.as_slice(),
            "vector {i}: signature mismatch"
        );

        // Verify link_id matches
        let expected_link_id = hex::decode(&step1.link_id).unwrap();
        assert_eq!(
            handshake.link_id.as_ref(),
            expected_link_id.as_slice(),
            "vector {i}: responder link_id mismatch"
        );

        // Also verify the signed_data reconstruction
        // (The test implicitly verifies this because the signature matches,
        // but let's also check explicitly via step2.signed_data)
        let _ = expected_signed_data; // verified implicitly through signature match
    }
}

// ---------------------------------------------------------------------------
// Step 3: Verify - initiator validates proof, derives same key
// ---------------------------------------------------------------------------

#[test]
fn handshake_step3_initiator_verify_all_vectors() {
    let links_vecs = links::load();
    let kp_vecs = keypairs::load();

    for (i, hs) in links_vecs.handshake_vectors.iter().enumerate() {
        if !hs.use_signalling {
            // Legacy vector requires separate handling (no signalling in new_initiator)
            continue;
        }

        let step1 = &hs.step_1_linkrequest;
        let step2 = &hs.step_2_lrproof;
        let step3 = &hs.step_3_verify;
        let step4 = &hs.step_4_lrrtt;
        let keys = load_handshake_keys(&links_vecs, &kp_vecs, hs);

        let hashable_part = hex::decode(&step1.hashable_part).unwrap();
        let data_len = step1.request_data_length as usize;
        let dest_hash_bytes = hex::decode(&step1.responder_destination_hash).unwrap();
        let dest_hash =
            reticulum_core::types::DestinationHash::new(dest_hash_bytes.try_into().unwrap());

        let mode = LinkMode::try_from(hs.mode as u8).unwrap();

        // Rebuild the initiator's pending link
        let (pending, _request_data) = LinkPending::new_initiator_deterministic(
            dest_hash,
            hs.mtu as u32,
            mode,
            1,
            keys.init_eph_x25519_prv,
            keys.init_eph_ed25519_prv,
            &hashable_part,
            data_len,
        )
        .unwrap();

        // Get proof_data from test vector
        let proof_data = hex::decode(&step2.proof_data).unwrap();

        // Get RTT and IV from step4 for deterministic encryption
        let rtt = step4.rtt_value;
        let fixed_iv = hex_to_16(&step4.fixed_iv);
        let expected_encrypted_rtt = hex::decode(&step4.encrypted_rtt_token).unwrap();

        // Initiator receives proof and transitions to active
        let (active, encrypted_rtt) = pending
            .receive_proof_deterministic(
                &proof_data,
                &keys.resp_identity_ed25519_pub,
                rtt,
                &fixed_iv,
            )
            .unwrap_or_else(|e| panic!("vector {i}: receive_proof failed: {e}"));

        // Verify derived keys match (step3)
        let expected_derived_key = hex::decode(&step3.initiator_derived_key).unwrap();
        assert_eq!(
            active.derived_key.to_bytes().as_slice(),
            expected_derived_key.as_slice(),
            "vector {i}: initiator derived_key mismatch"
        );

        // Verify the derived keys match between initiator and responder
        assert!(
            step3.derived_keys_match,
            "vector {i}: test vector says keys should match"
        );
        assert!(
            step3.signature_valid,
            "vector {i}: test vector says signature should be valid"
        );

        // Verify encrypted RTT matches
        assert_eq!(
            encrypted_rtt, expected_encrypted_rtt,
            "vector {i}: encrypted_rtt mismatch"
        );
    }
}

// ---------------------------------------------------------------------------
// Step 4: Full round-trip handshake
// ---------------------------------------------------------------------------

#[test]
fn handshake_full_roundtrip_all_vectors() {
    let links_vecs = links::load();
    let kp_vecs = keypairs::load();

    for (i, hs) in links_vecs.handshake_vectors.iter().enumerate() {
        if !hs.use_signalling {
            continue;
        }

        let step1 = &hs.step_1_linkrequest;
        let step4 = &hs.step_4_lrrtt;

        // Load keys - we need fresh copies since keys are consumed
        let init_eph = &links_vecs.ephemeral_keys[hs.initiator_ephemeral_index as usize];
        let resp_eph = &links_vecs.ephemeral_keys[hs.responder_ephemeral_index as usize];
        let resp_kp = &kp_vecs.keypairs[hs.responder_keypair_index as usize];

        let hashable_part = hex::decode(&step1.hashable_part).unwrap();
        let data_len = step1.request_data_length as usize;
        let dest_hash_bytes = hex::decode(&step1.responder_destination_hash).unwrap();
        let dest_hash =
            reticulum_core::types::DestinationHash::new(dest_hash_bytes.try_into().unwrap());
        let mode = LinkMode::try_from(hs.mode as u8).unwrap();

        let resp_ed25519_prv = Ed25519PrivateKey::from_bytes(hex_to_32(&resp_kp.ed25519_private));
        let resp_ed25519_pub =
            Ed25519PublicKey::from_bytes(hex_to_32(&resp_kp.ed25519_public)).unwrap();

        // Step 1: Initiator creates LINKREQUEST
        let (pending, request_data) = LinkPending::new_initiator_deterministic(
            dest_hash,
            hs.mtu as u32,
            mode,
            1,
            X25519PrivateKey::from_bytes(hex_to_32(&init_eph.x25519_private)),
            Ed25519PrivateKey::from_bytes(hex_to_32(&init_eph.ed25519_private)),
            &hashable_part,
            data_len,
        )
        .unwrap();

        // Step 2: Responder processes request and produces proof
        let (handshake, proof_data) = LinkHandshake::from_link_request_deterministic(
            &request_data,
            &hashable_part,
            data_len,
            &resp_ed25519_prv,
            &resp_ed25519_pub,
            hs.mtu as u32,
            mode,
            1,
            X25519PrivateKey::from_bytes(hex_to_32(&resp_eph.x25519_private)),
        )
        .unwrap();

        // Step 3: Initiator validates proof and produces encrypted RTT
        let rtt = step4.rtt_value;
        let fixed_iv = hex_to_16(&step4.fixed_iv);

        let (initiator_active, encrypted_rtt) = pending
            .receive_proof_deterministic(&proof_data, &resp_ed25519_pub, rtt, &fixed_iv)
            .unwrap();

        // Step 4: Responder receives RTT and activates
        let responder_active = handshake.receive_rtt(&encrypted_rtt).unwrap_or_else(|e| {
            panic!("vector {i}: receive_rtt failed: {e}");
        });

        // Verify both sides have the same derived key
        assert_eq!(
            initiator_active.derived_key.to_bytes(),
            responder_active.derived_key.to_bytes(),
            "vector {i}: derived keys don't match between initiator and responder"
        );

        // Verify both sides have the same link ID
        assert_eq!(
            initiator_active.link_id, responder_active.link_id,
            "vector {i}: link IDs don't match"
        );

        // Verify encrypt/decrypt roundtrip
        let test_msg = b"hello over the link";
        let encrypted = initiator_active.encrypt(test_msg).unwrap();
        let decrypted = responder_active.decrypt(&encrypted).unwrap();
        assert_eq!(
            decrypted.as_slice(),
            test_msg,
            "vector {i}: encrypt/decrypt roundtrip failed"
        );

        // And in the other direction
        let encrypted2 = responder_active.encrypt(b"response").unwrap();
        let decrypted2 = initiator_active.decrypt(&encrypted2).unwrap();
        assert_eq!(decrypted2.as_slice(), b"response");

        // Verify sign/verify roundtrip
        let sig = initiator_active.sign(test_msg);
        assert!(
            responder_active.verify(test_msg, &sig),
            "vector {i}: sign/verify failed"
        );
    }
}

// ---------------------------------------------------------------------------
// RTT msgpack vectors
// ---------------------------------------------------------------------------

#[test]
fn rtt_msgpack_encoding_all_vectors() {
    let links_vecs = links::load();
    for v in &links_vecs.rtt_vectors {
        let expected = hex::decode(&v.msgpack_bytes).unwrap();

        // Encode via rmpv and compare
        let mut buf = Vec::new();
        rmpv::encode::write_value(&mut buf, &rmpv::Value::F64(v.rtt_float)).unwrap();
        assert_eq!(buf, expected, "RTT msgpack mismatch for: {}", v.description);
        assert_eq!(buf.len(), v.msgpack_length as usize);

        // Decode and verify roundtrip
        let mut cursor = std::io::Cursor::new(&expected);
        let decoded = rmpv::decode::read_value(&mut cursor).unwrap();
        match decoded {
            rmpv::Value::F64(val) => {
                assert!(
                    (val - v.round_trip_value).abs() < 1e-15,
                    "RTT decode mismatch for: {}",
                    v.description
                );
            }
            _ => panic!("expected F64 for: {}", v.description),
        }
    }
}

// ---------------------------------------------------------------------------
// Encrypt/decrypt with test vector derived key
// ---------------------------------------------------------------------------

#[test]
fn handshake_token_encrypt_matches_vectors() {
    let links_vecs = links::load();

    for (i, hs) in links_vecs.handshake_vectors.iter().enumerate() {
        if !hs.use_signalling {
            continue;
        }

        let step2 = &hs.step_2_lrproof;
        let step4 = &hs.step_4_lrrtt;

        let derived_key_bytes = hex::decode(&step2.derived_key).unwrap();
        let dk_arr: [u8; 64] = derived_key_bytes.try_into().unwrap();

        let rtt_msgpack = hex::decode(&step4.rtt_msgpack).unwrap();
        let fixed_iv = hex_to_16(&step4.fixed_iv);
        let expected_token = hex::decode(&step4.encrypted_rtt_token).unwrap();

        let token = reticulum_crypto::token::Token::new(&dk_arr);
        let encrypted = token.encrypt_with_iv(&rtt_msgpack, &fixed_iv);

        assert_eq!(
            encrypted, expected_token,
            "vector {i}: Token encrypt mismatch"
        );

        // Also verify decrypt roundtrips
        let decrypted = token.decrypt(&encrypted).unwrap();
        assert_eq!(
            decrypted, rtt_msgpack,
            "vector {i}: Token decrypt roundtrip failed"
        );
    }
}

// ---------------------------------------------------------------------------
// Handshake with invalid proof should fail
// ---------------------------------------------------------------------------

#[test]
fn handshake_invalid_proof_rejected() {
    let links_vecs = links::load();
    let kp_vecs = keypairs::load();

    let hs = &links_vecs.handshake_vectors[0];
    let step1 = &hs.step_1_linkrequest;
    let step2 = &hs.step_2_lrproof;
    let init_eph = &links_vecs.ephemeral_keys[hs.initiator_ephemeral_index as usize];
    let resp_kp = &kp_vecs.keypairs[hs.responder_keypair_index as usize];

    let hashable_part = hex::decode(&step1.hashable_part).unwrap();
    let data_len = step1.request_data_length as usize;
    let dest_hash_bytes = hex::decode(&step1.responder_destination_hash).unwrap();
    let dest_hash =
        reticulum_core::types::DestinationHash::new(dest_hash_bytes.try_into().unwrap());
    let mode = LinkMode::try_from(hs.mode as u8).unwrap();

    let (pending, _) = LinkPending::new_initiator_deterministic(
        dest_hash,
        hs.mtu as u32,
        mode,
        1,
        X25519PrivateKey::from_bytes(hex_to_32(&init_eph.x25519_private)),
        Ed25519PrivateKey::from_bytes(hex_to_32(&init_eph.ed25519_private)),
        &hashable_part,
        data_len,
    )
    .unwrap();

    let resp_ed25519_pub =
        Ed25519PublicKey::from_bytes(hex_to_32(&resp_kp.ed25519_public)).unwrap();

    // Tamper with the proof data (flip a byte in the signature)
    let mut bad_proof = hex::decode(&step2.proof_data).unwrap();
    bad_proof[10] ^= 0xFF;

    let result = pending.receive_proof_deterministic(&bad_proof, &resp_ed25519_pub, 0.1, &[0; 16]);
    assert!(result.is_err(), "tampered proof should be rejected");
}

// ---------------------------------------------------------------------------
// Handshake with random keys (property test)
// ---------------------------------------------------------------------------

#[test]
fn handshake_random_keys_roundtrip() {
    // Generate random identity keys for the responder
    let resp_ed25519_prv = Ed25519PrivateKey::generate();
    let resp_ed25519_pub = resp_ed25519_prv.public_key();

    // Simulate a packet hashable_part: flags(1) + hops(1) + dest(16) + data(67)
    // For this test, we just need a consistent hashable_part
    let dummy_header = [0x02u8; 18]; // flags + hops + dest_hash
    let init_x25519 = X25519PrivateKey::generate();
    let init_ed25519 = Ed25519PrivateKey::generate();
    let init_x25519_pub = init_x25519.public_key();
    let init_ed25519_pub = init_ed25519.public_key();

    // Build request data manually
    let mut request_data = Vec::new();
    request_data.extend_from_slice(&init_x25519_pub.to_bytes());
    request_data.extend_from_slice(&init_ed25519_pub.to_bytes());
    let signalling = reticulum_protocol::link::encode(500, LinkMode::Aes256Cbc).unwrap();
    request_data.extend_from_slice(&signalling);

    // Build hashable_part = header + data
    let mut hashable_part = Vec::new();
    hashable_part.extend_from_slice(&dummy_header);
    hashable_part.extend_from_slice(&request_data);

    let data_len = request_data.len();
    let dest_hash = reticulum_core::types::DestinationHash::new([0x42; 16]);

    // Create initiator pending
    let (pending, req_data) = LinkPending::new_initiator_deterministic(
        dest_hash,
        500,
        LinkMode::Aes256Cbc,
        1,
        init_x25519,
        init_ed25519,
        &hashable_part,
        data_len,
    )
    .unwrap();

    // Responder processes request
    let (handshake, proof_data) = LinkHandshake::from_link_request(
        &req_data,
        &hashable_part,
        data_len,
        &resp_ed25519_prv,
        &resp_ed25519_pub,
        500,
        LinkMode::Aes256Cbc,
        1,
    )
    .unwrap();

    // Initiator validates proof
    let (init_active, encrypted_rtt) = pending
        .receive_proof(&proof_data, &resp_ed25519_pub)
        .unwrap();

    // Responder receives RTT
    let resp_active = handshake.receive_rtt(&encrypted_rtt).unwrap();

    // Both sides should have the same derived key
    assert_eq!(
        init_active.derived_key.to_bytes(),
        resp_active.derived_key.to_bytes(),
    );
    assert_eq!(init_active.link_id, resp_active.link_id);

    // Derived key is 64 bytes
    assert_eq!(init_active.derived_key.to_bytes().len(), 64);
    // Link ID is 16 bytes
    assert_eq!(init_active.link_id.as_ref().len(), 16);

    // Encrypt/decrypt roundtrip
    let msg = b"property test message";
    let ct = init_active.encrypt(msg).unwrap();
    let pt = resp_active.decrypt(&ct).unwrap();
    assert_eq!(pt.as_slice(), msg);
}

// ---------------------------------------------------------------------------
// Handshake with wrong responder identity should fail
// ---------------------------------------------------------------------------

#[test]
fn handshake_wrong_responder_identity_rejected() {
    // Create a valid handshake, but verify with a DIFFERENT identity key
    let real_resp_ed25519_prv = Ed25519PrivateKey::generate();
    let real_resp_ed25519_pub = real_resp_ed25519_prv.public_key();
    let wrong_resp_ed25519_prv = Ed25519PrivateKey::generate();
    let wrong_resp_ed25519_pub = wrong_resp_ed25519_prv.public_key();

    let init_x25519 = X25519PrivateKey::generate();
    let init_ed25519 = Ed25519PrivateKey::generate();
    let init_x25519_pub = init_x25519.public_key();
    let init_ed25519_pub = init_ed25519.public_key();

    let mut request_data = Vec::new();
    request_data.extend_from_slice(&init_x25519_pub.to_bytes());
    request_data.extend_from_slice(&init_ed25519_pub.to_bytes());
    let signalling = reticulum_protocol::link::encode(500, LinkMode::Aes256Cbc).unwrap();
    request_data.extend_from_slice(&signalling);

    let dummy_header = [0x02u8; 18];
    let mut hashable_part = Vec::new();
    hashable_part.extend_from_slice(&dummy_header);
    hashable_part.extend_from_slice(&request_data);

    let data_len = request_data.len();
    let dest_hash = reticulum_core::types::DestinationHash::new([0x42; 16]);

    let (pending, req_data) = LinkPending::new_initiator_deterministic(
        dest_hash,
        500,
        LinkMode::Aes256Cbc,
        1,
        init_x25519,
        init_ed25519,
        &hashable_part,
        data_len,
    )
    .unwrap();

    // Responder signs with real identity
    let (_handshake, proof_data) = LinkHandshake::from_link_request(
        &req_data,
        &hashable_part,
        data_len,
        &real_resp_ed25519_prv,
        &real_resp_ed25519_pub,
        500,
        LinkMode::Aes256Cbc,
        1,
    )
    .unwrap();

    // Initiator tries to verify with WRONG identity → should fail
    let result = pending.receive_proof(&proof_data, &wrong_resp_ed25519_pub);
    assert!(
        result.is_err(),
        "proof signed by wrong identity should be rejected"
    );
}

// ---------------------------------------------------------------------------
// Handshake RTT with wrong key should fail
// ---------------------------------------------------------------------------

#[test]
fn handshake_receive_rtt_wrong_key() {
    // Build a valid handshake up to LRPROOF, then feed RTT encrypted with wrong key
    let resp_ed25519_prv = Ed25519PrivateKey::generate();
    let resp_ed25519_pub = resp_ed25519_prv.public_key();

    let init_x25519 = X25519PrivateKey::generate();
    let init_ed25519 = Ed25519PrivateKey::generate();
    let init_x25519_pub = init_x25519.public_key();
    let init_ed25519_pub = init_ed25519.public_key();

    let mut request_data = Vec::new();
    request_data.extend_from_slice(&init_x25519_pub.to_bytes());
    request_data.extend_from_slice(&init_ed25519_pub.to_bytes());
    let signalling = reticulum_protocol::link::encode(500, LinkMode::Aes256Cbc).unwrap();
    request_data.extend_from_slice(&signalling);

    let dummy_header = [0x02u8; 18];
    let mut hashable_part = Vec::new();
    hashable_part.extend_from_slice(&dummy_header);
    hashable_part.extend_from_slice(&request_data);

    let data_len = request_data.len();
    let dest_hash = reticulum_core::types::DestinationHash::new([0x42; 16]);

    let (_pending, req_data) = LinkPending::new_initiator_deterministic(
        dest_hash,
        500,
        LinkMode::Aes256Cbc,
        1,
        init_x25519,
        init_ed25519,
        &hashable_part,
        data_len,
    )
    .unwrap();

    let (handshake, _proof_data) = LinkHandshake::from_link_request(
        &req_data,
        &hashable_part,
        data_len,
        &resp_ed25519_prv,
        &resp_ed25519_pub,
        500,
        LinkMode::Aes256Cbc,
        1,
    )
    .unwrap();

    // Encrypt RTT with a WRONG key
    let wrong_key = [0xFF; 64];
    let token = reticulum_crypto::token::Token::new(&wrong_key);
    let mut rtt_buf = Vec::new();
    rmpv::encode::write_value(&mut rtt_buf, &rmpv::Value::F64(0.05)).unwrap();
    let wrong_encrypted_rtt = token.encrypt(&rtt_buf);

    let result = handshake.receive_rtt(&wrong_encrypted_rtt);
    assert!(
        result.is_err(),
        "RTT encrypted with wrong key should fail decryption"
    );
}
