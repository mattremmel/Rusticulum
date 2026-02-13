//! Link encryption/decryption tests.
//!
//! Validates `LinkActive::encrypt`, `decrypt`, `sign`, and `verify` using:
//! - Teardown test vectors (keepalive request, keepalive response, linkclose)
//! - Identify test vectors (link identify packet)
//! - Property-based tests (roundtrip, overhead, wrong key, corruption)

use std::time::Instant;

use proptest::prelude::*;
use reticulum_protocol::link::{DerivedKey, LinkActive, LinkMode, LinkRole, LinkStats};
use reticulum_test_vectors::{keypairs, links};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn hex_to_bytes(hex_str: &str) -> Vec<u8> {
    hex::decode(hex_str).expect("invalid hex")
}

fn hex_to_16(hex_str: &str) -> [u8; 16] {
    let bytes = hex::decode(hex_str).expect("invalid hex");
    bytes.try_into().expect("must be 16 bytes")
}

fn hex_to_32(hex_str: &str) -> [u8; 32] {
    let bytes = hex::decode(hex_str).expect("invalid hex");
    bytes.try_into().expect("must be 32 bytes")
}

/// Build a `LinkActive` from a derived key for testing.
fn link_active_from_derived_key(derived_key: DerivedKey, link_id: [u8; 16]) -> LinkActive {
    let now = Instant::now();
    LinkActive {
        link_id: reticulum_core::types::LinkId::new(link_id),
        derived_key,
        role: LinkRole::Initiator,
        mode: LinkMode::Aes256Cbc,
        rtt: 0.1,
        mtu: 500,
        mdu: LinkActive::compute_mdu(500),
        keepalive: LinkActive::compute_keepalive(0.1),
        stale_time: LinkActive::compute_stale_time(LinkActive::compute_keepalive(0.1)),
        activated_at: now,
        last_inbound: now,
        last_outbound: now,
        stats: LinkStats::default(),
        is_stale: false,
        stale_since: None,
    }
}

/// Extract the handshake vector index from a reference string like "handshake_vectors[0]".
fn parse_handshake_ref(reference: &str) -> usize {
    let start = reference.find('[').expect("missing '['") + 1;
    let end = reference.find(']').expect("missing ']'");
    reference[start..end].parse().expect("invalid index")
}

/// Reconstruct the derived key from a handshake vector by replaying the responder side.
fn derived_key_from_handshake(links_vecs: &links::LinksVectors, hs_index: usize) -> DerivedKey {
    let hs = &links_vecs.handshake_vectors[hs_index];
    let step2 = &hs.step_2_lrproof;
    let dk_bytes: [u8; 64] = hex_to_bytes(&step2.derived_key).try_into().unwrap();
    DerivedKey::new(dk_bytes)
}

// ---------------------------------------------------------------------------
// Teardown vector tests
// ---------------------------------------------------------------------------

#[test]
fn teardown_vectors_encrypt_with_fixed_iv() {
    let links_vecs = links::load();

    for (i, tv) in links_vecs.teardown_vectors.iter().enumerate() {
        let hs_index = parse_handshake_ref(&tv.handshake_reference);
        let derived_key = derived_key_from_handshake(&links_vecs, hs_index);
        let link_id = hex_to_16(&tv.link_id);
        let active = link_active_from_derived_key(derived_key, link_id);

        let plaintext = hex_to_bytes(&tv.plaintext);
        let fixed_iv = hex_to_16(&tv.fixed_iv);
        let expected_token = hex_to_bytes(&tv.encrypted_token);

        // Encrypt with fixed IV and compare
        let encrypted = active.encrypt_with_iv(&plaintext, &fixed_iv).unwrap();
        assert_eq!(
            encrypted, expected_token,
            "teardown vector {i} ({}) encrypt mismatch",
            tv.description
        );
        assert_eq!(
            encrypted.len(),
            tv.encrypted_token_length as usize,
            "teardown vector {i} ({}) length mismatch",
            tv.description
        );

        // Decrypt and verify roundtrip
        let decrypted = active.decrypt(&encrypted).unwrap();
        assert_eq!(
            decrypted, plaintext,
            "teardown vector {i} ({}) decrypt roundtrip failed",
            tv.description
        );
    }
}

// ---------------------------------------------------------------------------
// Identify vector tests
// ---------------------------------------------------------------------------

#[test]
fn identify_vectors_encrypt_with_fixed_iv() {
    let links_vecs = links::load();
    let kp_vecs = keypairs::load();

    for (i, iv) in links_vecs.identify_vectors.iter().enumerate() {
        let hs_index = parse_handshake_ref(&iv.handshake_reference);
        let derived_key = derived_key_from_handshake(&links_vecs, hs_index);
        let link_id = hex_to_16(&iv.link_id);
        let active = link_active_from_derived_key(derived_key, link_id);

        // Verify proof_data = public_key(64) + signature(64)
        let proof_data = hex_to_bytes(&iv.proof_data);
        assert_eq!(
            proof_data.len(),
            iv.proof_data_length as usize,
            "identify vector {i}: proof_data length mismatch"
        );

        let fixed_iv = hex_to_16(&iv.fixed_iv);
        let expected_token = hex_to_bytes(&iv.encrypted_token);

        // Encrypt proof_data with fixed IV
        let encrypted = active.encrypt_with_iv(&proof_data, &fixed_iv).unwrap();
        assert_eq!(
            encrypted, expected_token,
            "identify vector {i} ({}) encrypt mismatch",
            iv.description
        );
        assert_eq!(
            encrypted.len(),
            iv.encrypted_token_length as usize,
            "identify vector {i} ({}) length mismatch",
            iv.description
        );

        // Decrypt and verify roundtrip
        let decrypted = active.decrypt(&encrypted).unwrap();
        assert_eq!(
            decrypted, proof_data,
            "identify vector {i} ({}) decrypt roundtrip failed",
            iv.description
        );

        // Verify the signed_data and signature are consistent
        let signed_data = hex_to_bytes(&iv.signed_data);
        let signature = hex_to_bytes(&iv.signature);
        let initiator_kp = &kp_vecs.keypairs[iv.initiator_keypair_index as usize];
        let ed25519_pub = reticulum_crypto::ed25519::Ed25519PublicKey::from_bytes(hex_to_32(
            &initiator_kp.ed25519_public,
        ))
        .unwrap();
        ed25519_pub
            .verify(
                &signed_data,
                &reticulum_crypto::ed25519::Ed25519Signature::from_bytes(
                    signature.as_slice().try_into().unwrap(),
                ),
            )
            .expect("identify vector {i}: signature verification failed");
    }
}

// ---------------------------------------------------------------------------
// Property-based tests
// ---------------------------------------------------------------------------

/// Generate a random 64-byte derived key for property tests.
fn arb_derived_key() -> impl Strategy<Value = DerivedKey> {
    prop::collection::vec(any::<u8>(), 64).prop_map(|bytes| {
        let arr: [u8; 64] = bytes.try_into().unwrap();
        DerivedKey::new(arr)
    })
}

proptest! {
    /// encrypt then decrypt always roundtrips.
    #[test]
    fn prop_encrypt_decrypt_roundtrip(
        key in arb_derived_key(),
        plaintext in prop::collection::vec(any::<u8>(), 0..512),
    ) {
        let active = link_active_from_derived_key(key, [0x42; 16]);
        let encrypted = active.encrypt(&plaintext).unwrap();
        let decrypted = active.decrypt(&encrypted).unwrap();
        prop_assert_eq!(decrypted, plaintext);
    }

    /// Encrypted output length follows the Token format:
    /// IV(16) + PKCS7-padded ciphertext + HMAC(32)
    /// PKCS7 padding always adds at least 1 byte, so ciphertext_blocks = (len / 16) + 1.
    #[test]
    fn prop_encrypt_overhead(
        key in arb_derived_key(),
        plaintext in prop::collection::vec(any::<u8>(), 0..512),
    ) {
        let active = link_active_from_derived_key(key, [0x42; 16]);
        let encrypted = active.encrypt(&plaintext).unwrap();
        let expected_len = 16 + ((plaintext.len() / 16) + 1) * 16 + 32;
        prop_assert_eq!(encrypted.len(), expected_len);
    }

    /// Decrypting with a different key always fails.
    #[test]
    fn prop_wrong_key_fails(
        key1 in arb_derived_key(),
        key2 in arb_derived_key(),
        plaintext in prop::collection::vec(any::<u8>(), 1..128),
    ) {
        let active1 = link_active_from_derived_key(key1, [0x42; 16]);
        let active2 = link_active_from_derived_key(key2, [0x42; 16]);

        // Only test when keys are actually different
        if active1.derived_key.as_bytes() != active2.derived_key.as_bytes() {
            let encrypted = active1.encrypt(&plaintext).unwrap();
            prop_assert!(active2.decrypt(&encrypted).is_err());
        }
    }

    /// Flipping any byte in the ciphertext causes decryption to fail.
    #[test]
    fn prop_corrupted_ciphertext_fails(
        key in arb_derived_key(),
        plaintext in prop::collection::vec(any::<u8>(), 1..128),
        flip_pos_pct in 0..100u32,
    ) {
        let active = link_active_from_derived_key(key, [0x42; 16]);
        let encrypted = active.encrypt(&plaintext).unwrap();

        // Pick a position to corrupt based on percentage
        let flip_pos = (flip_pos_pct as usize * encrypted.len()) / 100;
        let flip_pos = flip_pos.min(encrypted.len() - 1);

        let mut corrupted = encrypted.clone();
        corrupted[flip_pos] ^= 0xFF;

        prop_assert!(active.decrypt(&corrupted).is_err());
    }
}
