//! Channel sequencing and window-based flow control.
//!
//! [`ChannelState`] tracks sequence numbers and manages the adaptive window
//! that controls how many unacknowledged messages may be in flight. The window
//! grows on successful delivery and shrinks on timeout, with rate-based
//! upgrades after sustained fast or medium RTT performance.

use super::constants::*;

/// The maximum number of send attempts before the link is torn down.
pub const MAX_TRIES: u32 = 5;

/// Outcome of a timeout event on a tracked envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeoutOutcome {
    /// The envelope should be retried (tries < MAX_TRIES).
    Retry,
    /// The envelope has exhausted all retries — tear down the link.
    Fail,
}

/// Result of calling [`ChannelState::on_timeout`]: the updated try count and outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeoutResult {
    /// The try count after this timeout.
    pub new_tries: u32,
    /// Whether to retry or fail the envelope.
    pub outcome: TimeoutOutcome,
}

// ======================================================================== //
// Pure functions — channel window adaptation
// ======================================================================== //

/// Initial window parameters computed from link RTT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InitialWindow {
    pub window: u16,
    pub window_max: u16,
    pub window_min: u16,
    pub window_flexibility: u16,
}

/// Compute initial window parameters from a link's RTT.
///
/// Very slow links (RTT > RTT_SLOW) get a minimal all-ones window.
/// All other links start at the default slow-link parameters.
pub fn compute_initial_window(rtt: f64) -> InitialWindow {
    if rtt > RTT_SLOW {
        InitialWindow {
            window: 1,
            window_max: 1,
            window_min: 1,
            window_flexibility: 1,
        }
    } else {
        InitialWindow {
            window: WINDOW,
            window_max: WINDOW_MAX_SLOW,
            window_min: WINDOW_MIN,
            window_flexibility: WINDOW_FLEXIBILITY,
        }
    }
}

/// Input state for delivery adaptation.
#[derive(Debug, Clone, Copy)]
pub struct DeliveryInput {
    pub rtt: f64,
    pub window: u16,
    pub window_max: u16,
    pub window_min: u16,
    pub fast_rate_rounds: u16,
    pub medium_rate_rounds: u16,
}

/// Output of delivery adaptation — new window and rate-tracking state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeliveryAdaptation {
    pub new_window: u16,
    pub new_window_max: u16,
    pub new_window_min: u16,
    pub new_fast_rate_rounds: u16,
    pub new_medium_rate_rounds: u16,
}

/// Classify and adapt channel window parameters after a successful delivery.
///
/// Grows the window by 1 (up to `window_max`), then classifies the RTT to
/// track consecutive fast/medium rounds and potentially upgrade limits.
pub fn classify_delivery_adaptation(input: DeliveryInput) -> DeliveryAdaptation {
    let mut window = input.window;
    let mut window_max = input.window_max;
    let mut window_min = input.window_min;
    let mut fast_rate_rounds = input.fast_rate_rounds;
    let mut medium_rate_rounds = input.medium_rate_rounds;

    // Grow window toward max.
    if window < window_max {
        window += 1;
    }

    // RTT == 0 means no measurement yet — skip rate adaptation.
    if input.rtt == 0.0 {
        return DeliveryAdaptation {
            new_window: window,
            new_window_max: window_max,
            new_window_min: window_min,
            new_fast_rate_rounds: fast_rate_rounds,
            new_medium_rate_rounds: medium_rate_rounds,
        };
    }

    if input.rtt > RTT_FAST {
        // Not fast — reset fast counter.
        fast_rate_rounds = 0;

        if input.rtt > RTT_MEDIUM {
            // Slow — reset medium counter too.
            medium_rate_rounds = 0;
        } else {
            // Medium — accumulate medium rounds.
            medium_rate_rounds += 1;

            if window_max < WINDOW_MAX_MEDIUM && medium_rate_rounds == FAST_RATE_THRESHOLD {
                window_max = WINDOW_MAX_MEDIUM;
                window_min = WINDOW_MIN_LIMIT_MEDIUM;
            }
        }
    } else {
        // Fast — accumulate fast rounds.
        fast_rate_rounds += 1;

        if window_max < WINDOW_MAX_FAST && fast_rate_rounds == FAST_RATE_THRESHOLD {
            window_max = WINDOW_MAX_FAST;
            window_min = WINDOW_MIN_LIMIT_FAST;
        }
    }

    DeliveryAdaptation {
        new_window: window,
        new_window_max: window_max,
        new_window_min: window_min,
        new_fast_rate_rounds: fast_rate_rounds,
        new_medium_rate_rounds: medium_rate_rounds,
    }
}

/// Input state for timeout adaptation.
#[derive(Debug, Clone, Copy)]
pub struct TimeoutInput {
    pub tries: u32,
    pub window: u16,
    pub window_min: u16,
    pub window_max: u16,
    pub window_flexibility: u16,
}

/// Output of timeout adaptation — new try count, outcome, and window params.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeoutAdaptation {
    pub new_tries: u32,
    pub outcome: TimeoutOutcome,
    pub new_window: u16,
    pub new_window_max: u16,
}

/// Compute channel window adaptation after a packet timeout.
///
/// If tries+1 exceeds MAX_TRIES, returns Fail without changing the window.
/// Otherwise shrinks window and window_max within their constraints.
pub fn compute_timeout_adaptation(input: TimeoutInput) -> TimeoutAdaptation {
    let new_tries = input.tries + 1;
    if new_tries > MAX_TRIES {
        return TimeoutAdaptation {
            new_tries: input.tries,
            outcome: TimeoutOutcome::Fail,
            new_window: input.window,
            new_window_max: input.window_max,
        };
    }

    let mut window = input.window;
    let mut window_max = input.window_max;

    // Shrink window (but not below minimum).
    if window > input.window_min {
        window -= 1;
    }

    // Shrink window_max (but maintain flexibility gap).
    if window_max > input.window_min + input.window_flexibility {
        window_max -= 1;
    }

    TimeoutAdaptation {
        new_tries,
        outcome: TimeoutOutcome::Retry,
        new_window: window,
        new_window_max: window_max,
    }
}

/// Check whether an incoming sequence number should be accepted.
///
/// Returns `true` if `sequence` is within the valid receive window starting
/// at `next_rx_sequence` with width `window_max`, accounting for 16-bit
/// wraparound at SEQ_MODULUS (65536).
pub fn check_rx_sequence_valid(sequence: u16, next_rx_sequence: u16, window_max: u16) -> bool {
    if sequence >= next_rx_sequence {
        return true;
    }

    // sequence < next_rx_sequence — could be genuinely old, or could be
    // a wraparound case where the window spans the 0 boundary.
    let window_overflow = ((next_rx_sequence as u32 + window_max as u32) % SEQ_MODULUS) as u16;

    if window_overflow < next_rx_sequence {
        // Window wraps around 0. Sequences in [0..=window_overflow] are valid.
        sequence <= window_overflow
    } else {
        // No wraparound — sequence is simply old.
        false
    }
}

// ======================================================================== //
// ChannelState
// ======================================================================== //

/// Channel sequencing and window state.
///
/// This struct is deliberately decoupled from I/O: it tracks pure protocol
/// state and produces decisions that the caller acts on.
#[derive(Debug, Clone)]
pub struct ChannelState {
    // ---- Sequence tracking ----
    /// Next TX sequence number to assign.
    next_tx_sequence: u16,
    /// Next RX sequence number expected for in-order delivery.
    next_rx_sequence: u16,

    // ---- Window parameters ----
    /// Current window size (max unacknowledged messages in flight).
    pub window: u16,
    /// Maximum window size (adapts upward on sustained fast RTT).
    pub window_max: u16,
    /// Minimum window size (adapts upward on sustained fast RTT).
    pub window_min: u16,
    /// Minimum gap between window_max and window_min.
    pub window_flexibility: u16,

    // ---- Rate tracking ----
    /// Consecutive deliveries at fast RTT (≤ RTT_FAST).
    pub fast_rate_rounds: u16,
    /// Consecutive deliveries at medium RTT (≤ RTT_MEDIUM, > RTT_FAST).
    pub medium_rate_rounds: u16,
}

impl ChannelState {
    /// Create a new channel state, initialising the window from the link RTT.
    ///
    /// Very slow links (RTT > RTT_SLOW) get a minimal window of 1.
    /// All other links start at the default slow-link window and grow via
    /// adaptation during delivery callbacks.
    pub fn new(rtt: f64) -> Self {
        let iw = compute_initial_window(rtt);
        tracing::debug!(
            rtt,
            window = iw.window,
            window_max = iw.window_max,
            "channel: init"
        );
        Self {
            next_tx_sequence: 0,
            next_rx_sequence: 0,
            window: iw.window,
            window_max: iw.window_max,
            window_min: iw.window_min,
            window_flexibility: iw.window_flexibility,
            fast_rate_rounds: 0,
            medium_rate_rounds: 0,
        }
    }

    /// Construct a `ChannelState` from explicit field values.
    pub fn from_parts(
        window: u16,
        window_max: u16,
        window_min: u16,
        window_flexibility: u16,
        fast_rate_rounds: u16,
        medium_rate_rounds: u16,
    ) -> Self {
        Self {
            next_tx_sequence: 0,
            next_rx_sequence: 0,
            window,
            window_max,
            window_min,
            window_flexibility,
            fast_rate_rounds,
            medium_rate_rounds,
        }
    }

    // ------------------------------------------------------------------ //
    // Sequence numbers
    // ------------------------------------------------------------------ //

    /// Return the current TX sequence number and advance it (wrapping at SEQ_MODULUS).
    pub fn next_sequence(&mut self) -> u16 {
        let seq = self.next_tx_sequence;
        self.next_tx_sequence = ((seq as u32 + 1) % SEQ_MODULUS) as u16;
        tracing::trace!(
            seq,
            next = self.next_tx_sequence,
            "channel: assigned TX sequence"
        );
        seq
    }

    /// Return the current TX sequence without advancing it.
    pub fn peek_tx_sequence(&self) -> u16 {
        self.next_tx_sequence
    }

    /// Return the next expected RX sequence.
    pub fn next_rx_sequence(&self) -> u16 {
        self.next_rx_sequence
    }

    /// Advance the RX sequence counter by one (wrapping at SEQ_MODULUS).
    pub fn advance_rx_sequence(&mut self) {
        self.next_rx_sequence = ((self.next_rx_sequence as u32 + 1) % SEQ_MODULUS) as u16;
    }

    /// Check whether an incoming sequence number should be accepted.
    ///
    /// Returns `true` if the sequence is within the valid receive window,
    /// accounting for 16-bit wraparound.
    pub fn is_rx_valid(&self, sequence: u16, window_max: u16) -> bool {
        let valid = check_rx_sequence_valid(sequence, self.next_rx_sequence, window_max);
        if !valid {
            tracing::trace!(
                sequence,
                next_rx = self.next_rx_sequence,
                window_max,
                "channel: RX rejected"
            );
        }
        valid
    }

    // ------------------------------------------------------------------ //
    // Window adaptation — delivery
    // ------------------------------------------------------------------ //

    /// Adapt the window after a successful delivery.
    ///
    /// Grows the window by 1 (up to `window_max`), then classifies the
    /// current RTT to track consecutive fast/medium rounds and potentially
    /// upgrade the window limits.
    pub fn on_delivery(&mut self, rtt: f64) {
        let input = DeliveryInput {
            rtt,
            window: self.window,
            window_max: self.window_max,
            window_min: self.window_min,
            fast_rate_rounds: self.fast_rate_rounds,
            medium_rate_rounds: self.medium_rate_rounds,
        };
        let adaptation = classify_delivery_adaptation(input);

        if adaptation.new_window != self.window {
            tracing::debug!(
                window = adaptation.new_window,
                window_max = self.window_max,
                "channel: window grew on delivery"
            );
        }
        if adaptation.new_window_max != self.window_max {
            tracing::debug!(
                window_max = adaptation.new_window_max,
                window_min = adaptation.new_window_min,
                "channel: rate upgrade"
            );
        }

        self.window = adaptation.new_window;
        self.window_max = adaptation.new_window_max;
        self.window_min = adaptation.new_window_min;
        self.fast_rate_rounds = adaptation.new_fast_rate_rounds;
        self.medium_rate_rounds = adaptation.new_medium_rate_rounds;
    }

    // ------------------------------------------------------------------ //
    // Window adaptation — timeout
    // ------------------------------------------------------------------ //

    /// Adapt the window after a packet timeout and return the outcome.
    ///
    /// `tries` is the current try count for the timed-out envelope **before**
    /// this timeout. The method increments it internally and returns the new
    /// value together with the outcome.
    pub fn on_timeout(&mut self, tries: u32) -> TimeoutResult {
        let input = TimeoutInput {
            tries,
            window: self.window,
            window_min: self.window_min,
            window_max: self.window_max,
            window_flexibility: self.window_flexibility,
        };
        let adaptation = compute_timeout_adaptation(input);

        if adaptation.new_window != self.window {
            tracing::debug!(
                window = adaptation.new_window,
                "channel: window shrank on timeout"
            );
        }
        if adaptation.new_window_max != self.window_max {
            tracing::debug!(
                window_max = adaptation.new_window_max,
                "channel: window_max shrank on timeout"
            );
        }

        self.window = adaptation.new_window;
        self.window_max = adaptation.new_window_max;

        TimeoutResult {
            new_tries: adaptation.new_tries,
            outcome: adaptation.outcome,
        }
    }

    /// Check whether the given try count means the envelope has failed.
    pub fn is_exhausted(tries: u32) -> bool {
        tries >= MAX_TRIES
    }

    // ------------------------------------------------------------------ //
    // Timeout calculation
    // ------------------------------------------------------------------ //

    /// Compute the timeout duration (seconds) for a packet.
    ///
    /// Formula: `1.5^(tries-1) * max(rtt*2.5, 0.025) * (tx_ring_length + 1.5)`
    pub fn packet_timeout(tries: u32, rtt: f64, tx_ring_length: usize) -> f64 {
        let exponential_factor = 1.5_f64.powi(tries as i32 - 1);
        let rtt_factor = (rtt * 2.5).max(0.025);
        let ring_factor = tx_ring_length as f64 + 1.5;
        exponential_factor * rtt_factor * ring_factor
    }

    // ------------------------------------------------------------------ //
    // MDU calculation
    // ------------------------------------------------------------------ //

    /// Compute the channel MDU (Maximum Data Unit) from the outlet MDU.
    ///
    /// This is the maximum payload size that can fit in a single envelope:
    /// `min(outlet_mdu - ENVELOPE_OVERHEAD, 0xFFFF)`.
    pub fn channel_mdu(outlet_mdu: usize) -> usize {
        let raw = outlet_mdu.saturating_sub(ENVELOPE_OVERHEAD);
        raw.min(MAX_CHANNEL_MDU)
    }

    // ------------------------------------------------------------------ //
    // Ready-to-send check
    // ------------------------------------------------------------------ //

    /// Check if the channel can accept another outgoing message.
    ///
    /// `outstanding` is the number of unacknowledged messages currently in the TX ring.
    pub fn is_ready_to_send(&self, outstanding: usize) -> bool {
        outstanding < self.window as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ================================================================== //
    // compute_initial_window tests
    // ================================================================== //

    #[test]
    fn init_very_slow_rtt_all_ones() {
        let iw = compute_initial_window(2.0);
        assert_eq!(
            iw,
            InitialWindow {
                window: 1,
                window_max: 1,
                window_min: 1,
                window_flexibility: 1
            }
        );
    }

    #[test]
    fn init_normal_rtt_defaults() {
        let iw = compute_initial_window(0.5);
        assert_eq!(
            iw,
            InitialWindow {
                window: 2,
                window_max: 5,
                window_min: 2,
                window_flexibility: 4
            }
        );
    }

    #[test]
    fn init_fast_rtt_same_as_normal() {
        let iw = compute_initial_window(0.01);
        assert_eq!(
            iw,
            InitialWindow {
                window: 2,
                window_max: 5,
                window_min: 2,
                window_flexibility: 4
            }
        );
    }

    #[test]
    fn init_exact_boundary() {
        // RTT == RTT_SLOW exactly → normal (condition is >, not >=)
        let iw = compute_initial_window(RTT_SLOW);
        assert_eq!(
            iw,
            InitialWindow {
                window: 2,
                window_max: 5,
                window_min: 2,
                window_flexibility: 4
            }
        );
    }

    // ================================================================== //
    // classify_delivery_adaptation tests
    // ================================================================== //

    fn default_delivery_input(rtt: f64) -> DeliveryInput {
        DeliveryInput {
            rtt,
            window: 2,
            window_max: 5,
            window_min: 2,
            fast_rate_rounds: 0,
            medium_rate_rounds: 0,
        }
    }

    #[test]
    fn delivery_rtt_zero_skips_rate_tracking() {
        let input = default_delivery_input(0.0);
        let result = classify_delivery_adaptation(input);
        assert_eq!(result.new_window, 3);
        assert_eq!(result.new_fast_rate_rounds, 0);
        assert_eq!(result.new_medium_rate_rounds, 0);
    }

    #[test]
    fn delivery_fast_increments_fast_rounds() {
        let input = DeliveryInput {
            rtt: 0.10,
            ..default_delivery_input(0.10)
        };
        let result = classify_delivery_adaptation(input);
        assert_eq!(result.new_fast_rate_rounds, 1);
        assert_eq!(result.new_medium_rate_rounds, 0);
    }

    #[test]
    fn delivery_fast_threshold_upgrades_to_fast() {
        let input = DeliveryInput {
            rtt: 0.10,
            fast_rate_rounds: 9,
            ..default_delivery_input(0.10)
        };
        let result = classify_delivery_adaptation(input);
        assert_eq!(result.new_fast_rate_rounds, FAST_RATE_THRESHOLD);
        assert_eq!(result.new_window_max, WINDOW_MAX_FAST); // 48
        assert_eq!(result.new_window_min, WINDOW_MIN_LIMIT_FAST); // 16
    }

    #[test]
    fn delivery_medium_increments_medium_rounds() {
        let input = DeliveryInput {
            rtt: 0.50,
            ..default_delivery_input(0.50)
        };
        let result = classify_delivery_adaptation(input);
        assert_eq!(result.new_fast_rate_rounds, 0);
        assert_eq!(result.new_medium_rate_rounds, 1);
    }

    #[test]
    fn delivery_medium_threshold_upgrades_to_medium() {
        let input = DeliveryInput {
            rtt: 0.50,
            medium_rate_rounds: 9,
            ..default_delivery_input(0.50)
        };
        let result = classify_delivery_adaptation(input);
        assert_eq!(result.new_medium_rate_rounds, FAST_RATE_THRESHOLD);
        assert_eq!(result.new_window_max, WINDOW_MAX_MEDIUM); // 12
        assert_eq!(result.new_window_min, WINDOW_MIN_LIMIT_MEDIUM); // 5
    }

    #[test]
    fn delivery_slow_resets_both_counters() {
        let input = DeliveryInput {
            rtt: 1.0,
            fast_rate_rounds: 5,
            medium_rate_rounds: 3,
            ..default_delivery_input(1.0)
        };
        let result = classify_delivery_adaptation(input);
        assert_eq!(result.new_fast_rate_rounds, 0);
        assert_eq!(result.new_medium_rate_rounds, 0);
    }

    #[test]
    fn delivery_window_at_max_no_growth() {
        let input = DeliveryInput {
            rtt: 0.10,
            window: 5,
            window_max: 5,
            window_min: 2,
            fast_rate_rounds: 0,
            medium_rate_rounds: 0,
        };
        let result = classify_delivery_adaptation(input);
        assert_eq!(result.new_window, 5);
    }

    #[test]
    fn delivery_already_at_fast_no_double_upgrade() {
        let input = DeliveryInput {
            rtt: 0.10,
            window: 20,
            window_max: WINDOW_MAX_FAST,
            window_min: WINDOW_MIN_LIMIT_FAST,
            fast_rate_rounds: 9,
            medium_rate_rounds: 0,
        };
        let result = classify_delivery_adaptation(input);
        // fast_rate_rounds increments but no upgrade (already at max)
        assert_eq!(result.new_fast_rate_rounds, 10);
        assert_eq!(result.new_window_max, WINDOW_MAX_FAST);
    }

    #[test]
    fn delivery_fast_resets_medium_counter() {
        // When medium RTT hits, fast_rate_rounds is reset; check the reverse doesn't happen
        let input = DeliveryInput {
            rtt: 0.50, // medium
            fast_rate_rounds: 3,
            medium_rate_rounds: 0,
            ..default_delivery_input(0.50)
        };
        let result = classify_delivery_adaptation(input);
        assert_eq!(result.new_fast_rate_rounds, 0); // reset by medium
        assert_eq!(result.new_medium_rate_rounds, 1);
    }

    // ================================================================== //
    // compute_timeout_adaptation tests
    // ================================================================== //

    fn default_timeout_input(tries: u32) -> TimeoutInput {
        TimeoutInput {
            tries,
            window: 4,
            window_min: 2,
            window_max: 10,
            window_flexibility: 4,
        }
    }

    #[test]
    fn timeout_exhausted_returns_fail() {
        let result = compute_timeout_adaptation(default_timeout_input(MAX_TRIES));
        assert_eq!(result.outcome, TimeoutOutcome::Fail);
        assert_eq!(result.new_tries, MAX_TRIES); // unchanged
        assert_eq!(result.new_window, 4); // unchanged
    }

    #[test]
    fn timeout_increments_tries() {
        let result = compute_timeout_adaptation(default_timeout_input(2));
        assert_eq!(result.new_tries, 3);
        assert_eq!(result.outcome, TimeoutOutcome::Retry);
    }

    #[test]
    fn timeout_shrinks_window() {
        let result = compute_timeout_adaptation(default_timeout_input(0));
        assert_eq!(result.new_window, 3); // 4 → 3
    }

    #[test]
    fn timeout_window_at_min_no_shrink() {
        let input = TimeoutInput {
            tries: 0,
            window: 2,
            window_min: 2,
            window_max: 10,
            window_flexibility: 4,
        };
        let result = compute_timeout_adaptation(input);
        assert_eq!(result.new_window, 2); // at min, no shrink
    }

    #[test]
    fn timeout_shrinks_window_max() {
        // window_max(10) > window_min(2) + flexibility(4) = 6 → shrinks
        let result = compute_timeout_adaptation(default_timeout_input(0));
        assert_eq!(result.new_window_max, 9);
    }

    #[test]
    fn timeout_window_max_at_boundary_no_shrink() {
        let input = TimeoutInput {
            tries: 0,
            window: 4,
            window_min: 2,
            window_max: 6, // == min(2) + flex(4), not >
            window_flexibility: 4,
        };
        let result = compute_timeout_adaptation(input);
        assert_eq!(result.new_window_max, 6); // at boundary, no shrink
    }

    #[test]
    fn timeout_first_try() {
        let result = compute_timeout_adaptation(default_timeout_input(0));
        assert_eq!(result.new_tries, 1);
        assert_eq!(result.outcome, TimeoutOutcome::Retry);
        assert_eq!(result.new_window, 3);
    }

    // ================================================================== //
    // check_rx_sequence_valid tests
    // ================================================================== //

    #[test]
    fn rx_sequence_ahead_valid() {
        assert!(check_rx_sequence_valid(10, 5, 5));
    }

    #[test]
    fn rx_sequence_equal_valid() {
        assert!(check_rx_sequence_valid(5, 5, 5));
    }

    #[test]
    fn rx_old_no_wrap_rejected() {
        assert!(!check_rx_sequence_valid(3, 5, 5));
    }

    #[test]
    fn rx_wraparound_in_window_valid() {
        // next_rx=65534, window_max=5 → overflow=(65534+5)%65536=3
        // sequence=1 ≤ 3 → valid
        assert!(check_rx_sequence_valid(1, 65534, 5));
    }

    #[test]
    fn rx_wraparound_beyond_window_rejected() {
        // next_rx=65534, window_max=2 → overflow=(65534+2)%65536=0
        // sequence=5 > 0 → rejected
        assert!(!check_rx_sequence_valid(5, 65534, 2));
    }

    #[test]
    fn rx_no_wraparound_exact_boundary() {
        // next_rx=65534, window_max=5 → overflow=3
        // sequence=3 ≤ 3 → valid (exact boundary)
        assert!(check_rx_sequence_valid(3, 65534, 5));
    }

    #[test]
    fn rx_window_max_zero() {
        // window_max=0 → overflow = next_rx itself → no wrap detected
        // sequence=4 < next_rx=5 → old, no wrap → rejected
        assert!(!check_rx_sequence_valid(4, 5, 0));
    }

    // ================================================================== //
    // Boundary: channel sequence wraparound
    // ================================================================== //

    #[test]
    fn rx_wraparound_next_rx_zero() {
        // next_rx=0, window_max=5, sequence=3 → 3 >= 0 → valid
        assert!(check_rx_sequence_valid(3, 0, 5));
    }

    #[test]
    fn rx_wraparound_sequence_zero_at_boundary() {
        // next_rx=65534, window_max=5, sequence=0
        // overflow = (65534+5) % 65536 = 3, overflow(3) < next_rx(65534) → wrap
        // sequence(0) <= overflow(3) → valid
        assert!(check_rx_sequence_valid(0, 65534, 5));
    }

    #[test]
    fn rx_wraparound_full_width_window() {
        // window_max=65535: overflow = (next_rx + 65535) % 65536 = next_rx - 1
        // For next_rx=100: overflow = 99, overflow(99) < next_rx(100) → wrap
        // Any sequence in [0..=99] is valid (plus >= 100)
        assert!(check_rx_sequence_valid(0, 100, 65535));
        assert!(check_rx_sequence_valid(99, 100, 65535));
        assert!(check_rx_sequence_valid(100, 100, 65535)); // >= next_rx
        assert!(check_rx_sequence_valid(65535, 100, 65535)); // >= next_rx
    }

    #[test]
    fn tx_sequence_wraps_at_modulus() {
        let mut cs = ChannelState::new(0.5);
        // Manually set next_tx to SEQ_MAX
        cs.next_tx_sequence = SEQ_MAX;
        let seq = cs.next_sequence();
        assert_eq!(seq, SEQ_MAX);
        assert_eq!(cs.peek_tx_sequence(), 0); // wrapped to 0
    }

    #[test]
    fn rx_advance_wraps_at_modulus() {
        let mut cs = ChannelState::new(0.5);
        cs.next_rx_sequence = SEQ_MAX;
        cs.advance_rx_sequence();
        assert_eq!(cs.next_rx_sequence(), 0); // wrapped to 0
    }

    // ================================================================== //
    // Boundary: channel MDU underflow
    // ================================================================== //

    #[test]
    fn channel_mdu_zero_outlet() {
        assert_eq!(ChannelState::channel_mdu(0), 0);
    }

    #[test]
    fn channel_mdu_below_overhead() {
        assert_eq!(ChannelState::channel_mdu(5), 0);
    }

    #[test]
    fn channel_mdu_at_overhead() {
        assert_eq!(ChannelState::channel_mdu(ENVELOPE_OVERHEAD), 0);
    }

    #[test]
    fn channel_mdu_just_above_overhead() {
        assert_eq!(ChannelState::channel_mdu(ENVELOPE_OVERHEAD + 1), 1);
    }

    #[test]
    fn channel_mdu_capped_at_u16_max() {
        // outlet_mdu = 0x1_0005 → raw = 0x1_0005 - 6 = 0xFFFF → min(0xFFFF, 0xFFFF) = 0xFFFF
        assert_eq!(ChannelState::channel_mdu(0x1_0005), 0xFFFF);
    }

    #[test]
    fn channel_mdu_exactly_u16_max_plus_overhead() {
        assert_eq!(
            ChannelState::channel_mdu(0xFFFF + ENVELOPE_OVERHEAD),
            0xFFFF
        );
    }

    // ================================================================== //
    // check_rx_sequence_valid: out-of-window rejection
    // ================================================================== //

    #[test]
    fn test_check_rx_rejects_behind_no_wrap() {
        // next_rx=100, sequence=50, window_max=5 → 50 < 100, no wrap → rejected
        assert!(!check_rx_sequence_valid(50, 100, 5));
    }

    #[test]
    fn test_check_rx_rejects_wrap_beyond_window() {
        // next_rx=65534, window_max=2 → overflow=(65534+2)%65536=0
        // overflow(0) < next_rx(65534) → wrap zone is [0..=0]
        // sequence=5 → 5 > 0 → rejected (beyond wrap window)
        assert!(!check_rx_sequence_valid(5, 65534, 2));
    }

    #[test]
    fn test_check_rx_accepts_wraparound() {
        // next_rx=65530, sequence=2, window_max=10
        // overflow = (65530 + 10) % 65536 = 4, overflow(4) < next_rx(65530) → wrap
        // sequence(2) <= overflow(4) → valid
        assert!(check_rx_sequence_valid(2, 65530, 10));
    }
}
