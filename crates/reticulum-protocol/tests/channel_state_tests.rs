//! Tests for channel sequencing and window control.

use reticulum_protocol::channel::{ChannelState, MAX_TRIES, TimeoutOutcome};
use reticulum_test_vectors::channels::{self, ChannelWindowState};

/// Build a ChannelState from a ChannelWindowState snapshot.
fn state_from_snapshot(s: &ChannelWindowState) -> ChannelState {
    ChannelState::from_parts(
        s.window as u16,
        s.window_max as u16,
        s.window_min.unwrap_or(2) as u16,
        s.window_flexibility.unwrap_or(4) as u16,
        s.fast_rate_rounds.unwrap_or(0) as u16,
        s.medium_rate_rounds.unwrap_or(0) as u16,
    )
}

// ---------------------------------------------------------------------------
// Sequence number vectors (indices 0–2)
// ---------------------------------------------------------------------------

#[test]
fn sequence_increment_all_vectors() {
    let vectors = channels::load();
    for v in &vectors.sequence_number_vectors {
        if v.vector_type.is_some() {
            continue; // Skip rx_validation vectors here
        }
        let current = v.current_seq.unwrap() as u16;
        let expected_next = v.next_seq.unwrap() as u16;
        let mut state = ChannelState::new(0.5);
        // Advance to `current`
        for _ in 0..current as u32 {
            state.next_sequence();
        }
        assert_eq!(
            state.peek_tx_sequence(),
            current,
            "vector {}: setup failed",
            v.index
        );
        let got = state.next_sequence();
        assert_eq!(
            got, current,
            "vector {}: next_sequence should return current",
            v.index
        );
        assert_eq!(
            state.peek_tx_sequence(),
            expected_next,
            "vector {}: {} — expected next={}, got={}",
            v.index,
            v.description,
            expected_next,
            state.peek_tx_sequence()
        );
    }
}

// ---------------------------------------------------------------------------
// RX validation vectors (indices 3–7)
// ---------------------------------------------------------------------------

#[test]
fn rx_validation_all_vectors() {
    let vectors = channels::load();
    for v in &vectors.sequence_number_vectors {
        if v.vector_type.as_deref() != Some("rx_validation") {
            continue;
        }
        let next_rx = v.next_rx_sequence.unwrap() as u16;
        let incoming = v.incoming_sequence.unwrap() as u16;
        let accepted = v.accepted.unwrap();

        // Build state with the given next_rx_sequence
        let mut state = ChannelState::new(0.5);
        // Set next_rx_sequence by advancing it
        for _ in 0..next_rx as u32 {
            state.advance_rx_sequence();
        }
        assert_eq!(state.next_rx_sequence(), next_rx);

        // Use the window_max from the vector if present, otherwise WINDOW_MAX
        let wmax = v.window_max.unwrap_or(48) as u16;

        let result = state.is_rx_valid(incoming, wmax);
        assert_eq!(
            result, accepted,
            "vector {}: {} — next_rx={}, incoming={}, window_max={}, expected accepted={}, got={}",
            v.index, v.description, next_rx, incoming, wmax, accepted, result
        );
    }
}

// ---------------------------------------------------------------------------
// Window init vectors
// ---------------------------------------------------------------------------

#[test]
fn window_init_all_vectors() {
    let vectors = channels::load();
    for v in &vectors.window_init_vectors {
        let state = ChannelState::new(v.rtt);
        assert_eq!(
            state.window, v.window as u16,
            "vector {}: {} — window mismatch",
            v.index, v.description
        );
        assert_eq!(
            state.window_max, v.window_max as u16,
            "vector {}: {} — window_max mismatch",
            v.index, v.description
        );
        assert_eq!(
            state.window_min, v.window_min as u16,
            "vector {}: {} — window_min mismatch",
            v.index, v.description
        );
        assert_eq!(
            state.window_flexibility, v.window_flexibility as u16,
            "vector {}: {} — window_flexibility mismatch",
            v.index, v.description
        );
    }
}

// ---------------------------------------------------------------------------
// Window adaptation vectors (single events)
// ---------------------------------------------------------------------------

#[test]
fn window_adaptation_all_vectors() {
    let vectors = channels::load();
    for v in &vectors.window_adaptation_vectors {
        match v.event.as_str() {
            "delivery" => {
                let before = &v.before;
                let after = &v.after;
                let rtt = v.rtt.unwrap_or(0.0);

                let mut state = state_from_snapshot(before);

                state.on_delivery(rtt);

                assert_eq!(
                    state.window, after.window as u16,
                    "vector {}: {} — window mismatch",
                    v.index, v.description
                );
                assert_eq!(
                    state.window_max, after.window_max as u16,
                    "vector {}: {} — window_max mismatch",
                    v.index, v.description
                );
                if let Some(wmin) = after.window_min {
                    assert_eq!(
                        state.window_min, wmin as u16,
                        "vector {}: {} — window_min mismatch",
                        v.index, v.description
                    );
                }
                if let Some(frr) = after.fast_rate_rounds {
                    assert_eq!(
                        state.fast_rate_rounds, frr as u16,
                        "vector {}: {} — fast_rate_rounds mismatch",
                        v.index, v.description
                    );
                }
                if let Some(mrr) = after.medium_rate_rounds {
                    assert_eq!(
                        state.medium_rate_rounds, mrr as u16,
                        "vector {}: {} — medium_rate_rounds mismatch",
                        v.index, v.description
                    );
                }
            }
            "timeout" => {
                let before = &v.before;
                let after = &v.after;

                let mut state = ChannelState::from_parts(
                    before.window as u16,
                    before.window_max as u16,
                    before.window_min.unwrap() as u16,
                    before.window_flexibility.unwrap() as u16,
                    0,
                    0,
                );

                // Timeout with tries=0 (first timeout)
                state.on_timeout(0);

                assert_eq!(
                    state.window, after.window as u16,
                    "vector {}: {} — window mismatch after timeout",
                    v.index, v.description
                );
                assert_eq!(
                    state.window_max, after.window_max as u16,
                    "vector {}: {} — window_max mismatch after timeout",
                    v.index, v.description
                );
            }
            other => panic!("unexpected event type: {other}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Timeout calculation vectors
// ---------------------------------------------------------------------------

#[test]
fn timeout_calculation_all_vectors() {
    let vectors = channels::load();
    for v in &vectors.timeout_vectors {
        let timeout =
            ChannelState::packet_timeout(v.tries as u32, v.rtt, v.tx_ring_length as usize);
        let diff = (timeout - v.timeout).abs();
        assert!(
            diff < 1e-10,
            "vector {}: {} — expected timeout={}, got={}, diff={}",
            v.index,
            v.description,
            v.timeout,
            timeout,
            diff
        );
    }
}

// ---------------------------------------------------------------------------
// MDU vectors
// ---------------------------------------------------------------------------

#[test]
fn mdu_calculation_all_vectors() {
    let vectors = channels::load();
    for v in &vectors.mdu_vectors {
        let mdu = ChannelState::channel_mdu(v.outlet_mdu as usize);
        assert_eq!(
            mdu, v.channel_mdu as usize,
            "vector {}: {} — expected channel_mdu={}, got={}",
            v.index, v.description, v.channel_mdu, mdu
        );
    }
}

// ---------------------------------------------------------------------------
// Window adaptation sequence vectors (multi-step)
// ---------------------------------------------------------------------------

#[test]
fn window_adaptation_sequence_all_vectors() {
    let vectors = channels::load();
    for v in &vectors.window_adaptation_sequence_vectors {
        let mut state = state_from_snapshot(&v.initial_state);

        // Track tries for timeout steps
        let mut tries: u32 = 0;

        for step in &v.steps {
            match step.event.as_str() {
                "delivery" => {
                    let rtt = step.rtt.unwrap();
                    state.on_delivery(rtt);
                }
                "timeout" => {
                    let (new_tries, _) = state.on_timeout(tries);
                    tries = new_tries;
                }
                other => panic!("vector {}: unexpected event: {other}", v.index),
            }

            let step_num = step.step.unwrap();

            // Validate after-state
            if let Some(w) = step.window_after {
                assert_eq!(
                    state.window, w as u16,
                    "vector {} step {}: window mismatch",
                    v.index, step_num
                );
            }

            if let Some(wm) = step.window_max_after {
                assert_eq!(
                    state.window_max, wm as u16,
                    "vector {} step {}: window_max mismatch",
                    v.index, step_num
                );
            }

            if let Some(wmin) = step.window_min_after {
                assert_eq!(
                    state.window_min, wmin as u16,
                    "vector {} step {}: window_min mismatch",
                    v.index, step_num
                );
            }

            if let Some(frr) = step.fast_rate_rounds_after {
                assert_eq!(
                    state.fast_rate_rounds, frr as u16,
                    "vector {} step {}: fast_rate_rounds mismatch",
                    v.index, step_num
                );
            }

            if let Some(mrr) = step.medium_rate_rounds_after {
                assert_eq!(
                    state.medium_rate_rounds, mrr as u16,
                    "vector {} step {}: medium_rate_rounds mismatch",
                    v.index, step_num
                );
            }
        }

        // Validate final state
        let final_state = &v.final_state;
        assert_eq!(
            state.window, final_state.window as u16,
            "vector {}: final window mismatch",
            v.index
        );
        assert_eq!(
            state.window_max, final_state.window_max as u16,
            "vector {}: final window_max mismatch",
            v.index
        );
        if let Some(wmin) = final_state.window_min {
            assert_eq!(
                state.window_min, wmin as u16,
                "vector {}: final window_min mismatch",
                v.index
            );
        }
        if let Some(frr) = final_state.fast_rate_rounds {
            assert_eq!(
                state.fast_rate_rounds, frr as u16,
                "vector {}: final fast_rate_rounds mismatch",
                v.index
            );
        }
        if let Some(mrr) = final_state.medium_rate_rounds {
            assert_eq!(
                state.medium_rate_rounds, mrr as u16,
                "vector {}: final medium_rate_rounds mismatch",
                v.index
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Retry sequence vectors
// ---------------------------------------------------------------------------

#[test]
fn retry_sequence_all_vectors() {
    let vectors = channels::load();
    for v in &vectors.retry_sequence_vectors {
        let init = &v.initial_state;
        let mut state = state_from_snapshot(init);
        let rtt = init.rtt.unwrap();
        let tx_ring_length = init.tx_ring_length.unwrap() as usize;

        let mut tries: u32 = init.tries.unwrap_or(0) as u32;

        for step in &v.steps {
            let expected_outcome = step.outcome.as_deref().unwrap();
            let step_num = step.step.unwrap();

            match step.event.as_str() {
                "timeout" => {
                    let expected_tries_before = step.tries_before.unwrap() as u32;
                    assert_eq!(
                        tries, expected_tries_before,
                        "vector {} step {}: tries_before mismatch",
                        v.index, step_num
                    );

                    if tries >= MAX_TRIES {
                        // Exhausted
                        assert_eq!(
                            expected_outcome, "fail",
                            "vector {} step {}: expected fail for exhausted tries",
                            v.index, step_num
                        );
                        continue;
                    }

                    let (new_tries, outcome) = state.on_timeout(tries);
                    tries = new_tries;

                    let expected_tries_after = step.tries_after.unwrap() as u32;
                    assert_eq!(
                        tries, expected_tries_after,
                        "vector {} step {}: tries_after mismatch",
                        v.index, step_num
                    );

                    match expected_outcome {
                        "retry" => {
                            assert_eq!(outcome, TimeoutOutcome::Retry);

                            // Validate timeout value
                            if let Some(expected_timeout) = step.timeout {
                                let computed =
                                    ChannelState::packet_timeout(tries, rtt, tx_ring_length);
                                let diff = (computed - expected_timeout).abs();
                                assert!(
                                    diff < 1e-10,
                                    "vector {} step {}: timeout mismatch — expected={}, got={}",
                                    v.index,
                                    step_num,
                                    expected_timeout,
                                    computed
                                );
                            }
                        }
                        "fail" => {
                            // This case is handled above (tries >= MAX_TRIES)
                        }
                        other => panic!("unexpected outcome: {other}"),
                    }

                    // Validate window state
                    assert_eq!(
                        state.window,
                        step.window_after.unwrap() as u16,
                        "vector {} step {}: window mismatch",
                        v.index,
                        step_num
                    );
                    assert_eq!(
                        state.window_max,
                        step.window_max_after.unwrap() as u16,
                        "vector {} step {}: window_max mismatch",
                        v.index,
                        step_num
                    );
                }
                "delivery" => {
                    state.on_delivery(rtt);

                    assert_eq!(
                        state.window,
                        step.window_after.unwrap() as u16,
                        "vector {} step {}: window mismatch after delivery",
                        v.index,
                        step_num
                    );

                    if let Some(frr) = step.fast_rate_rounds_after {
                        assert_eq!(
                            state.fast_rate_rounds, frr as u16,
                            "vector {} step {}: fast_rate_rounds mismatch",
                            v.index, step_num
                        );
                    }
                    if let Some(mrr) = step.medium_rate_rounds_after {
                        assert_eq!(
                            state.medium_rate_rounds, mrr as u16,
                            "vector {} step {}: medium_rate_rounds mismatch",
                            v.index, step_num
                        );
                    }
                }
                other => panic!("unexpected event: {other}"),
            }
        }

        // Validate final state
        let final_state = &v.final_state;
        assert_eq!(
            state.window, final_state.window as u16,
            "vector {}: final window mismatch",
            v.index
        );
        assert_eq!(
            state.window_max, final_state.window_max as u16,
            "vector {}: final window_max mismatch",
            v.index
        );
        if let Some(expected_tries) = final_state.tries {
            assert_eq!(
                tries, expected_tries as u32,
                "vector {}: final tries mismatch",
                v.index
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Packet loss scenario vectors
// ---------------------------------------------------------------------------

#[test]
fn packet_loss_scenario_all_vectors() {
    let vectors = channels::load();
    for v in &vectors.packet_loss_scenario_vectors {
        let init = &v.initial_state;
        let rtt = init.rtt.unwrap();
        let mut state = state_from_snapshot(init);

        // Track per-sequence tries
        let mut envelope_tries: std::collections::HashMap<u16, u32> =
            std::collections::HashMap::new();
        let mut tx_ring: Vec<u16> = Vec::new();

        for event in &v.events {
            match event.event.as_str() {
                "send" => {
                    let seq = event.sequence.unwrap() as u16;
                    tx_ring.push(seq);
                    envelope_tries.insert(seq, 0);

                    // Validate TX ring
                    let expected_ring: Vec<u16> = event
                        .tx_ring
                        .as_ref()
                        .unwrap()
                        .iter()
                        .map(|&v| v as u16)
                        .collect();
                    assert_eq!(
                        tx_ring, expected_ring,
                        "vector {}: tx_ring mismatch after send seq={}",
                        v.index, seq
                    );

                    // Validate window (sends don't change window)
                    assert_eq!(
                        state.window,
                        event.window.unwrap() as u16,
                        "vector {}: window mismatch on send seq={}",
                        v.index,
                        seq
                    );
                }
                "delivery" => {
                    let seq = event.sequence.unwrap() as u16;

                    // Validate before state
                    assert_eq!(
                        state.window,
                        event.window_before.unwrap() as u16,
                        "vector {}: window_before mismatch on delivery seq={}",
                        v.index,
                        seq
                    );

                    state.on_delivery(rtt);

                    // Remove from tx_ring
                    tx_ring.retain(|&s| s != seq);

                    // Validate after state
                    assert_eq!(
                        state.window,
                        event.window_after.unwrap() as u16,
                        "vector {}: window_after mismatch on delivery seq={}",
                        v.index,
                        seq
                    );

                    let expected_ring: Vec<u16> = event
                        .tx_ring
                        .as_ref()
                        .unwrap()
                        .iter()
                        .map(|&v| v as u16)
                        .collect();
                    assert_eq!(
                        tx_ring, expected_ring,
                        "vector {}: tx_ring mismatch after delivery seq={}",
                        v.index, seq
                    );
                }
                "timeout" => {
                    let seq = event.sequence.unwrap() as u16;
                    let expected_tries_before = event.tries_before.unwrap() as u32;
                    let tries = *envelope_tries.get(&seq).unwrap_or(&0);
                    assert_eq!(
                        tries, expected_tries_before,
                        "vector {}: tries_before mismatch for seq={}",
                        v.index, seq
                    );

                    let expected_outcome = event.outcome.as_deref().unwrap();

                    if tries >= MAX_TRIES {
                        assert_eq!(expected_outcome, "fail");
                        continue;
                    }

                    let (new_tries, outcome) = state.on_timeout(tries);
                    envelope_tries.insert(seq, new_tries);

                    match expected_outcome {
                        "retry" => assert_eq!(outcome, TimeoutOutcome::Retry),
                        "fail" => {} // handled above
                        other => panic!("unexpected outcome: {other}"),
                    }

                    assert_eq!(
                        state.window,
                        event.window_after.unwrap() as u16,
                        "vector {}: window mismatch after timeout seq={}",
                        v.index,
                        seq
                    );

                    // Validate timeout value
                    if let Some(expected_timeout) = event.timeout {
                        let computed = ChannelState::packet_timeout(new_tries, rtt, tx_ring.len());
                        let diff = (computed - expected_timeout).abs();
                        assert!(
                            diff < 1e-10,
                            "vector {}: timeout mismatch for seq={} — expected={}, got={}",
                            v.index,
                            seq,
                            expected_timeout,
                            computed
                        );
                    }
                }
                other => panic!("unexpected event type: {other}"),
            }
        }

        // Validate final state
        let final_state = &v.final_state;
        assert_eq!(
            state.window, final_state.window as u16,
            "vector {}: final window mismatch",
            v.index
        );
        assert_eq!(
            state.window_max, final_state.window_max as u16,
            "vector {}: final window_max mismatch",
            v.index
        );
        let expected_final_ring: Vec<u16> = final_state
            .tx_ring
            .as_ref()
            .unwrap()
            .iter()
            .map(|&v| v as u16)
            .collect();
        assert_eq!(
            tx_ring, expected_final_ring,
            "vector {}: final tx_ring mismatch",
            v.index
        );
    }
}

// ---------------------------------------------------------------------------
// Property tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod proptest_tests {
    use proptest::prelude::*;
    use reticulum_protocol::channel::ChannelState;

    proptest! {
        #[test]
        fn sequence_wraps_correctly(count in 0u32..200_000) {
            let mut state = ChannelState::new(0.5);
            for _ in 0..count {
                state.next_sequence();
            }
            let seq = state.peek_tx_sequence();
            prop_assert_eq!(seq, (count % 65536) as u16);
        }

        #[test]
        fn window_stays_within_bounds(
            deliveries in 0usize..100,
            timeouts in 0usize..100,
            rtt in 0.0f64..3.0
        ) {
            let mut state = ChannelState::new(rtt);
            let initial_min = state.window_min;

            for _ in 0..deliveries {
                state.on_delivery(rtt);
            }
            for _ in 0..timeouts {
                state.on_timeout(0);
            }

            prop_assert!(state.window >= initial_min.min(state.window_min));
            prop_assert!(state.window <= state.window_max.max(state.window));
        }

        #[test]
        fn successive_next_sequence_increments(count in 1u32..1000) {
            let mut state = ChannelState::new(0.5);
            let mut prev = state.next_sequence();
            for _ in 1..count {
                let current = state.next_sequence();
                let expected = ((prev as u32 + 1) % 65536) as u16;
                prop_assert_eq!(current, expected, "non-sequential: prev={}, got={}", prev, current);
                prev = current;
            }
        }

        #[test]
        fn timeout_always_positive(
            tries in 1u32..6,
            rtt in 0.0f64..10.0,
            ring_len in 0usize..20
        ) {
            let timeout = ChannelState::packet_timeout(tries, rtt, ring_len);
            prop_assert!(timeout > 0.0, "timeout should be positive, got {timeout}");
        }

        #[test]
        fn mdu_never_exceeds_outlet(outlet_mdu in 0usize..100_000) {
            let mdu = ChannelState::channel_mdu(outlet_mdu);
            prop_assert!(mdu <= outlet_mdu);
            prop_assert!(mdu <= 0xFFFF);
        }

        #[test]
        fn rx_validation_accepts_exact_match(next_rx in 0u16..65535) {
            let mut state = ChannelState::new(0.5);
            for _ in 0..next_rx as u32 {
                state.advance_rx_sequence();
            }
            prop_assert!(state.is_rx_valid(next_rx, 48));
        }
    }
}
