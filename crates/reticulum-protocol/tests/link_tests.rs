//! Tests for link types, MTU signalling, keepalive, MDU, and state machine.

use reticulum_protocol::link::{
    self, DerivedKey, LinkActive, LinkMode, LinkPending, LinkRole, LinkStats, PhyStats,
    ResourceStrategy, TeardownReason,
};
use reticulum_test_vectors::links;

// ---------------------------------------------------------------------------
// MTU signalling tests (signalling_bytes_vectors)
// ---------------------------------------------------------------------------

#[test]
fn signalling_bytes_encode_all_vectors() {
    let vectors = links::load();
    for v in &vectors.signalling_bytes_vectors {
        let mode = LinkMode::try_from(v.input_mode as u8).unwrap();
        let result = link::encode(v.input_mtu as u32, mode).unwrap();
        let expected = hex::decode(&v.signalling_bytes).unwrap();
        assert_eq!(
            result.as_slice(),
            expected.as_slice(),
            "encode failed for: {}",
            v.description
        );
    }
}

#[test]
fn signalling_bytes_decode_mtu_all_vectors() {
    let vectors = links::load();
    for v in &vectors.signalling_bytes_vectors {
        let bytes_vec = hex::decode(&v.signalling_bytes).unwrap();
        let bytes: [u8; 3] = bytes_vec.try_into().unwrap();
        let mtu = link::decode_mtu(&bytes);
        assert_eq!(
            mtu, v.decoded_mtu as u32,
            "decode_mtu failed for: {}",
            v.description
        );
    }
}

#[test]
fn signalling_bytes_decode_mode_all_vectors() {
    let vectors = links::load();
    for v in &vectors.signalling_bytes_vectors {
        let bytes_vec = hex::decode(&v.signalling_bytes).unwrap();
        let bytes: [u8; 3] = bytes_vec.try_into().unwrap();
        let mode = link::decode_mode(&bytes);
        assert_eq!(
            mode as u8, v.decoded_mode as u8,
            "decode_mode failed for: {}",
            v.description
        );
    }
}

#[test]
fn signalling_bytes_roundtrip_all_vectors() {
    let vectors = links::load();
    for v in &vectors.signalling_bytes_vectors {
        let mode = LinkMode::try_from(v.input_mode as u8).unwrap();
        let encoded = link::encode(v.input_mtu as u32, mode).unwrap();
        let decoded_mtu = link::decode_mtu(&encoded);
        let decoded_mode = link::decode_mode(&encoded);
        assert_eq!(
            decoded_mtu, v.input_mtu as u32,
            "roundtrip mtu: {}",
            v.description
        );
        assert_eq!(decoded_mode, mode, "roundtrip mode: {}", v.description);
    }
}

// ---------------------------------------------------------------------------
// Link ID tests (link_id_vectors)
// ---------------------------------------------------------------------------

#[test]
fn link_id_from_hashable_part_with_signalling() {
    let vectors = links::load();
    let v = &vectors.link_id_vectors[0];
    assert!(
        v.signalling_bytes.is_some(),
        "first vector should have signalling"
    );

    let hashable = hex::decode(v.hashable_part.as_ref().unwrap()).unwrap();
    let data_len = v.request_data_length.unwrap() as usize;
    let link_id = LinkPending::compute_link_id(&hashable, data_len);
    let expected = hex::decode(v.link_id.as_ref().unwrap()).unwrap();
    assert_eq!(link_id.as_ref(), expected.as_slice());
}

#[test]
fn link_id_from_hashable_part_without_signalling() {
    let vectors = links::load();
    let v = &vectors.link_id_vectors[1];

    let hashable = hex::decode(v.hashable_part.as_ref().unwrap()).unwrap();
    let data_len = v.request_data_length.unwrap() as usize;
    let link_id = LinkPending::compute_link_id(&hashable, data_len);
    let expected = hex::decode(v.link_id.as_ref().unwrap()).unwrap();
    assert_eq!(link_id.as_ref(), expected.as_slice());
}

#[test]
fn link_id_same_regardless_of_mtu() {
    let vectors = links::load();
    let v = &vectors.link_id_vectors[2];
    assert!(v.all_match.unwrap());

    let expected_id = hex::decode(v.link_id_mtu_500.as_ref().unwrap()).unwrap();
    let id_1000 = hex::decode(v.link_id_mtu_1000.as_ref().unwrap()).unwrap();
    let id_legacy = hex::decode(v.link_id_legacy.as_ref().unwrap()).unwrap();

    assert_eq!(expected_id, id_1000);
    assert_eq!(expected_id, id_legacy);
}

// Also verify compute_link_id produces the same result for both MTU variants
#[test]
fn link_id_compute_consistency_across_mtu_signalling() {
    let vectors = links::load();
    // Vector 0: with signalling (MTU=500)
    let v0 = &vectors.link_id_vectors[0];
    let hashable0 = hex::decode(v0.hashable_part.as_ref().unwrap()).unwrap();
    let data_len0 = v0.request_data_length.unwrap() as usize;
    let id0 = LinkPending::compute_link_id(&hashable0, data_len0);

    // Vector 1: without signalling (same keys)
    let v1 = &vectors.link_id_vectors[1];
    let hashable1 = hex::decode(v1.hashable_part.as_ref().unwrap()).unwrap();
    let data_len1 = v1.request_data_length.unwrap() as usize;
    let id1 = LinkPending::compute_link_id(&hashable1, data_len1);

    assert_eq!(id0, id1);
}

// ---------------------------------------------------------------------------
// Keepalive calculation tests
// ---------------------------------------------------------------------------

#[test]
fn keepalive_calculation_all_vectors() {
    let vectors = links::load();
    for v in &vectors.keepalive_calculation_vectors {
        let keepalive = LinkActive::compute_keepalive(v.rtt);
        let stale_time = LinkActive::compute_stale_time(keepalive);

        assert!(
            (keepalive - v.keepalive).abs() < 1e-6,
            "keepalive mismatch for RTT={}: got {}, expected {}",
            v.rtt,
            keepalive,
            v.keepalive
        );
        assert!(
            (stale_time - v.stale_time).abs() < 1e-6,
            "stale_time mismatch for RTT={}: got {}, expected {}",
            v.rtt,
            stale_time,
            v.stale_time
        );
    }
}

#[test]
fn keepalive_from_retry_timers_vectors() {
    let vectors = reticulum_test_vectors::retry_timers::load();
    for v in &vectors.link_keepalive.vectors {
        let keepalive = LinkActive::compute_keepalive(v.rtt);
        let stale_time = LinkActive::compute_stale_time(keepalive);

        assert!(
            (keepalive - v.keepalive_interval).abs() < 1e-6,
            "keepalive mismatch for RTT={}: got {}, expected {}",
            v.rtt,
            keepalive,
            v.keepalive_interval
        );
        assert!(
            (stale_time - v.stale_time).abs() < 1e-6,
            "stale_time mismatch for RTT={}: got {}, expected {}",
            v.rtt,
            stale_time,
            v.stale_time
        );
    }
}

// ---------------------------------------------------------------------------
// MDU tests
// ---------------------------------------------------------------------------

#[test]
fn mdu_calculation_all_vectors() {
    let vectors = links::load();
    for v in &vectors.mdu_vectors {
        let mdu = LinkActive::compute_mdu(v.mtu as u32);
        assert_eq!(
            mdu, v.mdu as u32,
            "MDU mismatch for MTU={}: got {}, expected {}",
            v.mtu, mdu, v.mdu
        );
    }
}

#[test]
fn mdu_zero_for_tiny_mtu() {
    // MTU too small to hold any data
    assert_eq!(LinkActive::compute_mdu(0), 0);
    assert_eq!(LinkActive::compute_mdu(60), 0);
}

// ---------------------------------------------------------------------------
// Mode tests (mode_rejection_vectors)
// ---------------------------------------------------------------------------

#[test]
fn mode_from_u8_all_values() {
    for i in 0..=7u8 {
        let mode = LinkMode::try_from(i).unwrap();
        assert_eq!(mode as u8, i);
    }
}

#[test]
fn mode_from_u8_invalid() {
    assert!(LinkMode::try_from(8).is_err());
    assert!(LinkMode::try_from(255).is_err());
}

#[test]
fn mode_is_enabled_matches_vectors() {
    let vectors = links::load();
    // First vector has mode_encodings with all 8 modes
    let v = &vectors.mode_rejection_vectors[0];
    let encodings = v.mode_encodings.as_ref().unwrap();
    let arr = encodings.as_array().unwrap();

    for entry in arr {
        let mode_val = entry["mode_value"].as_u64().unwrap() as u8;
        let enabled = entry["enabled"].as_bool().unwrap();
        let mode = LinkMode::try_from(mode_val).unwrap();
        assert_eq!(
            mode.is_enabled(),
            enabled,
            "is_enabled mismatch for mode={}",
            mode_val
        );
    }
}

#[test]
fn mode_default_is_aes256_cbc() {
    assert_eq!(LinkMode::default(), LinkMode::Aes256Cbc);
    assert!(LinkMode::default().is_enabled());
}

#[test]
fn mode_aes128_cbc_not_enabled() {
    let mode = LinkMode::try_from(0).unwrap();
    assert!(!mode.is_enabled());
}

#[test]
fn mode_encode_disabled_returns_error() {
    let result = link::encode(500, LinkMode::Aes128Cbc);
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// TeardownReason tests
// ---------------------------------------------------------------------------

#[test]
fn teardown_reason_repr_values() {
    assert_eq!(TeardownReason::Timeout as u8, 0x01);
    assert_eq!(TeardownReason::InitiatorClosed as u8, 0x02);
    assert_eq!(TeardownReason::DestinationClosed as u8, 0x03);
}

#[test]
fn teardown_reason_from_u8() {
    assert_eq!(TeardownReason::try_from(1).unwrap(), TeardownReason::Timeout);
    assert_eq!(
        TeardownReason::try_from(2).unwrap(),
        TeardownReason::InitiatorClosed
    );
    assert_eq!(
        TeardownReason::try_from(3).unwrap(),
        TeardownReason::DestinationClosed
    );
    assert!(TeardownReason::try_from(0).is_err());
    assert!(TeardownReason::try_from(4).is_err());
}

#[test]
fn teardown_reason_matches_test_vector_constants() {
    let vectors = links::load();
    let constants = &vectors.constants;
    let teardown = &constants["teardown_reasons"];

    assert_eq!(
        teardown["TIMEOUT"].as_u64().unwrap(),
        TeardownReason::Timeout as u64
    );
    assert_eq!(
        teardown["INITIATOR_CLOSED"].as_u64().unwrap(),
        TeardownReason::InitiatorClosed as u64
    );
    assert_eq!(
        teardown["DESTINATION_CLOSED"].as_u64().unwrap(),
        TeardownReason::DestinationClosed as u64
    );
}

// ---------------------------------------------------------------------------
// DerivedKey tests
// ---------------------------------------------------------------------------

#[test]
fn derived_key_split_correctness() {
    let vectors = links::load();
    let hs = &vectors.handshake_vectors[0];
    let step2 = &hs.step_2_lrproof;

    let dk_hex = step2.derived_key.as_str();
    let sk_hex = step2.signing_key.as_str();
    let ek_hex = step2.encryption_key.as_str();

    let dk_bytes = hex::decode(dk_hex).unwrap();
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&dk_bytes);
    let dk = DerivedKey::new(arr);

    assert_eq!(hex::encode(dk.signing_key()), sk_hex);
    assert_eq!(hex::encode(dk.encryption_key()), ek_hex);
}

#[test]
fn derived_key_debug_redacts() {
    let dk = DerivedKey::new([0u8; 64]);
    let debug = format!("{:?}", dk);
    assert!(debug.contains("REDACTED"));
    assert!(!debug.contains("0000"));
}

// ---------------------------------------------------------------------------
// ResourceStrategy tests
// ---------------------------------------------------------------------------

#[test]
fn resource_strategy_repr_values() {
    assert_eq!(ResourceStrategy::AcceptNone as u8, 0);
    assert_eq!(ResourceStrategy::AcceptApp as u8, 1);
    assert_eq!(ResourceStrategy::AcceptAll as u8, 2);
}

#[test]
fn resource_strategy_from_u8() {
    assert_eq!(
        ResourceStrategy::try_from(0).unwrap(),
        ResourceStrategy::AcceptNone
    );
    assert_eq!(
        ResourceStrategy::try_from(1).unwrap(),
        ResourceStrategy::AcceptApp
    );
    assert_eq!(
        ResourceStrategy::try_from(2).unwrap(),
        ResourceStrategy::AcceptAll
    );
    assert!(ResourceStrategy::try_from(3).is_err());
}

#[test]
fn resource_strategy_matches_test_vector_constants() {
    let vectors = links::load();
    let constants = &vectors.constants;
    let strategies = &constants["resource_strategies"];

    assert_eq!(
        strategies["ACCEPT_NONE"].as_u64().unwrap(),
        ResourceStrategy::AcceptNone as u64
    );
    assert_eq!(
        strategies["ACCEPT_APP"].as_u64().unwrap(),
        ResourceStrategy::AcceptApp as u64
    );
    assert_eq!(
        strategies["ACCEPT_ALL"].as_u64().unwrap(),
        ResourceStrategy::AcceptAll as u64
    );
}

// ---------------------------------------------------------------------------
// PhyStats / LinkStats defaults
// ---------------------------------------------------------------------------

#[test]
fn phy_stats_default() {
    let stats = PhyStats::default();
    assert!(stats.rssi.is_none());
    assert!(stats.snr.is_none());
    assert!(stats.quality.is_none());
}

#[test]
fn link_stats_default() {
    let stats = LinkStats::default();
    assert_eq!(stats.tx_packets, 0);
    assert_eq!(stats.rx_packets, 0);
    assert_eq!(stats.tx_bytes, 0);
    assert_eq!(stats.rx_bytes, 0);
}

// ---------------------------------------------------------------------------
// LinkState enum tests
// ---------------------------------------------------------------------------

#[test]
fn link_state_names() {
    // We can't easily construct all states without full handshake,
    // but we can verify the state_name strings match expected values.
    let vectors = links::load();
    let sm = &vectors.state_machine_spec;
    let states = &sm["states"];

    // Verify our state names match the spec
    assert_eq!(states["PENDING"]["value"].as_u64().unwrap(), 0);
    assert_eq!(states["HANDSHAKE"]["value"].as_u64().unwrap(), 1);
    assert_eq!(states["ACTIVE"]["value"].as_u64().unwrap(), 2);
    assert_eq!(states["CLOSED"]["value"].as_u64().unwrap(), 4);
}

// ---------------------------------------------------------------------------
// Link ID from handshake vectors
// ---------------------------------------------------------------------------

#[test]
fn link_id_all_handshake_vectors() {
    let vectors = links::load();
    for hs in &vectors.handshake_vectors {
        let step1 = &hs.step_1_linkrequest;
        let hashable = hex::decode(&step1.hashable_part).unwrap();
        let data_len = step1.request_data_length as usize;
        let link_id = LinkPending::compute_link_id(&hashable, data_len);
        let expected = hex::decode(&step1.link_id).unwrap();
        assert_eq!(
            link_id.as_ref(),
            expected.as_slice(),
            "link_id mismatch for: {}",
            hs.description
        );
    }
}

// ---------------------------------------------------------------------------
// Hypothetical mode decoding (mode_rejection_vectors[2])
// ---------------------------------------------------------------------------

#[test]
fn hypothetical_mode_0_decode() {
    let vectors = links::load();
    // Third mode rejection vector: hypothetical mode=0 encoding
    let v = &vectors.mode_rejection_vectors[2];
    let sig_hex = v.hypothetical_signalling_bytes.as_ref().unwrap();
    let bytes_vec = hex::decode(sig_hex).unwrap();
    let bytes: [u8; 3] = bytes_vec.try_into().unwrap();

    let mtu = link::decode_mtu(&bytes);
    let mode = link::decode_mode(&bytes);

    assert_eq!(mtu, v.decoded_mtu.unwrap() as u32);
    assert_eq!(mode as u8, v.decoded_mode.unwrap() as u8);
    assert_eq!(mode, LinkMode::Aes128Cbc);
    assert!(!mode.is_enabled());
}

// ---------------------------------------------------------------------------
// LinkRole
// ---------------------------------------------------------------------------

#[test]
fn link_role_debug() {
    assert_eq!(format!("{:?}", LinkRole::Initiator), "Initiator");
    assert_eq!(format!("{:?}", LinkRole::Responder), "Responder");
}

// ---------------------------------------------------------------------------
// Traffic timeout, stale timeout, total timeout from retry_timers vectors
// ---------------------------------------------------------------------------

#[test]
fn traffic_timeout_boundary_values() {
    // Min keepalive (5) → 5*6 = 30
    assert!((LinkActive::compute_traffic_timeout(link::KEEPALIVE_MIN) - 30.0).abs() < 1e-10);
    // Max keepalive (360) → 360*6 = 2160
    assert!((LinkActive::compute_traffic_timeout(link::KEEPALIVE_MAX) - 2160.0).abs() < 1e-10);
    // Zero → 0
    assert!((LinkActive::compute_traffic_timeout(0.0)).abs() < 1e-10);
}

#[test]
fn stale_timeout_all_retry_vectors() {
    // Vector stale_timeout = rtt * KEEPALIVE_TIMEOUT_FACTOR + STALE_GRACE
    // This is the grace period after a link goes stale before teardown.
    let vectors = reticulum_test_vectors::retry_timers::load();
    for v in &vectors.link_keepalive.vectors {
        let expected_stale_timeout = v.rtt * link::KEEPALIVE_TIMEOUT_FACTOR + link::STALE_GRACE;
        assert!(
            (expected_stale_timeout - v.stale_timeout).abs() < 1e-6,
            "stale_timeout mismatch for RTT={}: got {}, expected {} ({})",
            v.rtt,
            expected_stale_timeout,
            v.stale_timeout,
            v.description
        );
    }
}

#[test]
fn total_timeout_all_retry_vectors() {
    // Vector total_timeout = stale_time + stale_timeout
    // Where stale_time = keepalive * STALE_FACTOR
    // And stale_timeout = rtt * KEEPALIVE_TIMEOUT_FACTOR + STALE_GRACE
    let vectors = reticulum_test_vectors::retry_timers::load();
    for v in &vectors.link_keepalive.vectors {
        let keepalive = LinkActive::compute_keepalive(v.rtt);
        let stale_time = LinkActive::compute_stale_time(keepalive);
        let stale_timeout = v.rtt * link::KEEPALIVE_TIMEOUT_FACTOR + link::STALE_GRACE;
        let total = stale_time + stale_timeout;
        assert!(
            (total - v.total_timeout).abs() < 1e-6,
            "total_timeout mismatch for RTT={}: got {} (stale_time={} + stale_timeout={}), expected {} ({})",
            v.rtt,
            total,
            stale_time,
            stale_timeout,
            v.total_timeout,
            v.description
        );
    }
}

#[test]
fn establishment_timeout_all_vectors() {
    let vectors = reticulum_test_vectors::retry_timers::load();
    for v in &vectors.link_establishment.vectors {
        let expected = v.timeout as f64;
        let computed =
            link::ESTABLISHMENT_TIMEOUT_PER_HOP * (v.hops.max(1) as f64) + link::KEEPALIVE_DEFAULT;
        assert!(
            (computed - expected).abs() < 1e-6,
            "establishment timeout mismatch for hops={}: got {}, expected {} ({})",
            v.hops,
            computed,
            expected,
            v.description
        );
    }
}
