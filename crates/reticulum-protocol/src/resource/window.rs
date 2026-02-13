//! Resource window adaptation (rate-based).
//!
//! [`WindowState`] tracks the adaptive window that controls how many
//! unacknowledged resource parts may be in flight. Unlike channel windowing
//! (RTT-based), resource windowing adapts based on throughput in bytes/sec.

use super::constants::*;

/// Resource transfer window state.
///
/// The window grows on each successful completion of an outstanding-parts
/// window and shrinks on part-request timeouts. Rate-based thresholds
/// trigger transitions between slow, medium, and fast `window_max` limits.
#[derive(Debug, Clone)]
pub struct WindowState {
    /// Current window size (max unacknowledged parts in flight).
    pub window: u16,
    /// Maximum window size (adapts based on throughput class).
    pub window_max: u16,
    /// Minimum window size (grows alongside window to prevent regressing too far).
    pub window_min: u16,
    /// Minimum gap between `window_max` and `window_min`.
    pub window_flexibility: u16,
    /// Consecutive window completions at fast rate (> RATE_FAST B/s).
    pub fast_rate_rounds: u16,
    /// Consecutive window completions at very slow rate (< RATE_VERY_SLOW B/s).
    pub very_slow_rate_rounds: u16,
}

impl WindowState {
    /// Create a new resource window state with default initial values.
    pub fn new() -> Self {
        Self {
            window: WINDOW,
            window_max: WINDOW_MAX_SLOW,
            window_min: WINDOW_MIN,
            window_flexibility: WINDOW_FLEXIBILITY,
            fast_rate_rounds: 0,
            very_slow_rate_rounds: 0,
        }
    }

    /// Construct a `WindowState` from explicit field values (for test setup).
    pub fn from_parts(
        window: u16,
        window_max: u16,
        window_min: u16,
        window_flexibility: u16,
        fast_rate_rounds: u16,
        very_slow_rate_rounds: u16,
    ) -> Self {
        Self {
            window,
            window_max,
            window_min,
            window_flexibility,
            fast_rate_rounds,
            very_slow_rate_rounds,
        }
    }

    /// Adapt the window after a successful window completion.
    ///
    /// `rate` is the measured throughput in bytes per second for this window.
    ///
    /// Steps:
    /// 1. Grow `window` toward `window_max`.
    /// 2. Grow `window_min` if the gap exceeds `window_flexibility - 1`.
    /// 3. Track consecutive fast/very-slow rounds and upgrade/downgrade limits.
    pub fn on_window_complete(&mut self, rate: f64) {
        // Step 1: grow window.
        if self.window < self.window_max {
            self.window += 1;
            tracing::debug!(
                window = self.window,
                window_max = self.window_max,
                "resource: window grew"
            );
        }

        // Step 2: grow window_min if gap is large enough.
        if (self.window - self.window_min) > (self.window_flexibility - 1) {
            self.window_min += 1;
            tracing::trace!(window_min = self.window_min, "resource: window_min grew");
        }

        // Step 3: rate classification.
        if rate > RATE_FAST {
            if self.fast_rate_rounds < FAST_RATE_THRESHOLD {
                self.fast_rate_rounds += 1;
                tracing::trace!(
                    fast_rate_rounds = self.fast_rate_rounds,
                    "resource: fast rate round"
                );
            }
            if self.fast_rate_rounds == FAST_RATE_THRESHOLD {
                self.window_max = WINDOW_MAX_FAST;
                tracing::debug!(window_max = self.window_max, "resource: upgraded to FAST");
            }
        } else if self.fast_rate_rounds == 0 && rate < RATE_VERY_SLOW {
            if self.very_slow_rate_rounds < VERY_SLOW_RATE_THRESHOLD {
                self.very_slow_rate_rounds += 1;
                tracing::trace!(
                    very_slow_rate_rounds = self.very_slow_rate_rounds,
                    "resource: very slow rate round"
                );
            }
            if self.very_slow_rate_rounds == VERY_SLOW_RATE_THRESHOLD {
                self.window_max = WINDOW_MAX_VERY_SLOW;
                tracing::debug!(
                    window_max = self.window_max,
                    "resource: downgraded to VERY SLOW"
                );
            }
        }
    }

    /// Adapt the window after a part-request timeout.
    ///
    /// All three shrink steps are gated by `window > window_min`. When the
    /// window is already at minimum, nothing changes.
    pub fn on_timeout(&mut self) {
        if self.window > self.window_min {
            // Step 1: shrink window.
            self.window -= 1;
            tracing::debug!(window = self.window, "resource: window shrank on timeout");

            // Step 2: shrink window_max (if above window_min).
            if self.window_max > self.window_min {
                self.window_max -= 1;
                tracing::trace!(window_max = self.window_max, "resource: window_max shrank");
            }

            // Step 3: double-decrement if gap exceeds flexibility.
            if (self.window_max - self.window) > (self.window_flexibility - 1) {
                self.window_max -= 1;
                tracing::trace!(
                    window_max = self.window_max,
                    "resource: window_max double-decremented"
                );
            }
        }
    }

    /// Check if more parts can be sent given the current outstanding count.
    pub fn is_ready_to_send(&self, outstanding: usize) -> bool {
        outstanding < self.window as usize
    }
}

impl Default for WindowState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use reticulum_test_vectors::window_adaptation::ResourceWindowStep;

    // ------------------------------------------------------------------ //
    // Helper to assert window state matches a typed step
    // ------------------------------------------------------------------ //

    fn assert_state(ws: &WindowState, step: &ResourceWindowStep) {
        let state = &step.state;
        let step_num = step.step;
        assert_eq!(
            ws.window, state.window as u16,
            "step {step_num}: window mismatch"
        );
        assert_eq!(
            ws.window_max, state.window_max as u16,
            "step {step_num}: window_max mismatch"
        );
        assert_eq!(
            ws.window_min, state.window_min as u16,
            "step {step_num}: window_min mismatch"
        );
        assert_eq!(
            ws.fast_rate_rounds, state.fast_rate_rounds as u16,
            "step {step_num}: fast_rate_rounds mismatch"
        );
        assert_eq!(
            ws.very_slow_rate_rounds, state.very_slow_rate_rounds as u16,
            "step {step_num}: very_slow_rate_rounds mismatch"
        );
    }

    fn run_steps(steps: &[ResourceWindowStep]) {
        let mut ws = WindowState::new();

        for step in steps {
            let event = step.event.as_str();

            if event == "initial" || event.starts_with("initial ") {
                assert_state(&ws, step);
                continue;
            }

            match event {
                "window_complete" => {
                    let rate = step.rate.unwrap();
                    ws.on_window_complete(rate);
                }
                "timeout" => {
                    ws.on_timeout();
                }
                other => panic!("unknown event: {other}"),
            }
            assert_state(&ws, step);
        }
    }

    // ================================================================== //
    // Growth vectors
    // ================================================================== //

    #[test]
    fn growth_fast_rate() {
        let vectors = reticulum_test_vectors::window_adaptation::load();
        let v = &vectors.resource_window.growth_vectors[0];
        assert!(v.description.contains("Fast rate"));
        run_steps(&v.steps);
    }

    #[test]
    fn growth_medium_rate() {
        let vectors = reticulum_test_vectors::window_adaptation::load();
        let v = &vectors.resource_window.growth_vectors[1];
        assert!(v.description.contains("Medium rate"));
        run_steps(&v.steps);
    }

    #[test]
    fn growth_very_slow_rate() {
        let vectors = reticulum_test_vectors::window_adaptation::load();
        let v = &vectors.resource_window.growth_vectors[2];
        assert!(v.description.contains("Very slow rate"));
        run_steps(&v.steps);
    }

    #[test]
    fn growth_borderline_fast() {
        let vectors = reticulum_test_vectors::window_adaptation::load();
        let v = &vectors.resource_window.growth_vectors[3];
        assert!(v.description.contains("Borderline fast"));
        run_steps(&v.steps);
    }

    #[test]
    fn growth_just_above_fast() {
        let vectors = reticulum_test_vectors::window_adaptation::load();
        let v = &vectors.resource_window.growth_vectors[4];
        assert!(v.description.contains("Just above fast"));
        run_steps(&v.steps);
    }

    // ================================================================== //
    // Shrink vectors
    // ================================================================== //

    #[test]
    fn shrink_from_initial() {
        let vectors = reticulum_test_vectors::window_adaptation::load();
        let v = &vectors.resource_window.shrink_vectors[0];
        assert!(v.description.contains("Timeout shrink"));
        run_steps(&v.steps);
    }

    #[test]
    fn shrink_grow_then_timeout() {
        let vectors = reticulum_test_vectors::window_adaptation::load();
        let v = &vectors.resource_window.shrink_vectors[1];
        assert!(v.description.contains("Grow at fast rate"));
        run_steps(&v.steps);
    }

    #[test]
    fn shrink_alternating() {
        let vectors = reticulum_test_vectors::window_adaptation::load();
        let v = &vectors.resource_window.shrink_vectors[2];
        assert!(v.description.contains("Alternating"));
        run_steps(&v.steps);
    }

    #[test]
    fn shrink_double_decrement() {
        let vectors = reticulum_test_vectors::window_adaptation::load();
        let v = &vectors.resource_window.shrink_vectors[3];
        assert!(v.description.contains("double-decrement"));
        run_steps(&v.steps);
    }

    // ================================================================== //
    // Rate transition vectors
    // ================================================================== //

    #[test]
    fn rate_transition_slow_to_fast() {
        let vectors = reticulum_test_vectors::window_adaptation::load();
        let v = &vectors.resource_window.rate_transition_vectors[0];
        assert!(v.description.contains("Slow-to-fast"));
        run_steps(&v.steps);
    }

    #[test]
    fn rate_transition_very_slow_cap() {
        let vectors = reticulum_test_vectors::window_adaptation::load();
        let v = &vectors.resource_window.rate_transition_vectors[1];
        assert!(v.description.contains("Very slow rate cap"));
        run_steps(&v.steps);
    }

    #[test]
    fn rate_transition_very_slow_blocked() {
        let vectors = reticulum_test_vectors::window_adaptation::load();
        let v = &vectors.resource_window.rate_transition_vectors[2];
        assert!(v.description.contains("blocked"));
        run_steps(&v.steps);
    }

    // ================================================================== //
    // Unit tests
    // ================================================================== //

    #[test]
    fn default_initial_state() {
        let ws = WindowState::new();
        assert_eq!(ws.window, 4);
        assert_eq!(ws.window_max, 10);
        assert_eq!(ws.window_min, 2);
        assert_eq!(ws.window_flexibility, 4);
        assert_eq!(ws.fast_rate_rounds, 0);
        assert_eq!(ws.very_slow_rate_rounds, 0);
    }

    #[test]
    fn from_parts_roundtrip() {
        let ws = WindowState::from_parts(8, 75, 5, 4, 4, 0);
        assert_eq!(ws.window, 8);
        assert_eq!(ws.window_max, 75);
        assert_eq!(ws.window_min, 5);
        assert_eq!(ws.fast_rate_rounds, 4);
    }

    #[test]
    fn is_ready_to_send_basic() {
        let ws = WindowState::new();
        assert!(ws.is_ready_to_send(0));
        assert!(ws.is_ready_to_send(3));
        assert!(!ws.is_ready_to_send(4));
        assert!(!ws.is_ready_to_send(5));
    }

    #[test]
    fn default_trait() {
        let ws = WindowState::default();
        assert_eq!(ws.window, 4);
    }

    // ================================================================== //
    // Property tests
    // ================================================================== //

    mod proptests {
        use super::*;
        use proptest::prelude::*;

        fn window_state_strategy() -> impl Strategy<Value = WindowState> {
            (2u16..=75, 2u16..=75, 2u16..=75, 1u16..=10).prop_map(
                |(window, window_max, window_min_raw, flex)| {
                    let window_min = window_min_raw.min(window).min(window_max);
                    let window_max = window_max.max(window_min);
                    let window = window.clamp(window_min, window_max);
                    WindowState::from_parts(window, window_max, window_min, flex, 0, 0)
                },
            )
        }

        proptest! {
            #[test]
            fn on_complete_never_exceeds_window_max(
                mut ws in window_state_strategy(),
                rate in 0.0f64..20000.0,
            ) {
                ws.on_window_complete(rate);
                // After on_window_complete, window should not exceed the (possibly updated) window_max
                prop_assert!(ws.window <= ws.window_max,
                    "window {} > window_max {}", ws.window, ws.window_max);
            }

            #[test]
            fn on_timeout_never_below_window_min(
                mut ws in window_state_strategy(),
            ) {
                ws.on_timeout();
                prop_assert!(ws.window >= ws.window_min,
                    "window {} < window_min {}", ws.window, ws.window_min);
            }

            #[test]
            fn fast_rate_rounds_bounded(
                mut ws in window_state_strategy(),
                rate in 6251.0f64..20000.0,
                rounds in 0u16..20,
            ) {
                for _ in 0..rounds {
                    ws.on_window_complete(rate);
                }
                prop_assert!(ws.fast_rate_rounds <= FAST_RATE_THRESHOLD,
                    "fast_rate_rounds {} > threshold {}", ws.fast_rate_rounds, FAST_RATE_THRESHOLD);
            }

            #[test]
            fn very_slow_rate_rounds_bounded(
                mut ws in window_state_strategy(),
                rate in 0.0f64..249.0,
                rounds in 0u16..20,
            ) {
                for _ in 0..rounds {
                    ws.on_window_complete(rate);
                }
                prop_assert!(ws.very_slow_rate_rounds <= VERY_SLOW_RATE_THRESHOLD,
                    "very_slow_rate_rounds {} > threshold {}", ws.very_slow_rate_rounds, VERY_SLOW_RATE_THRESHOLD);
            }

            #[test]
            fn window_min_never_exceeds_window(
                mut ws in window_state_strategy(),
                events in proptest::collection::vec(prop_oneof![
                    (6000.0f64..20000.0).prop_map(|r| Some(r)),
                    Just(None),
                ], 0..30),
            ) {
                for event in events {
                    match event {
                        Some(rate) => ws.on_window_complete(rate),
                        None => ws.on_timeout(),
                    }
                }
                prop_assert!(ws.window_min <= ws.window,
                    "window_min {} > window {}", ws.window_min, ws.window);
            }
        }
    }
}
