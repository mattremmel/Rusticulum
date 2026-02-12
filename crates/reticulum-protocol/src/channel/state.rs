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
        if rtt > RTT_SLOW {
            tracing::debug!(rtt, "channel: very slow link — window=1");
            Self {
                next_tx_sequence: 0,
                next_rx_sequence: 0,
                window: 1,
                window_max: 1,
                window_min: 1,
                window_flexibility: 1,
                fast_rate_rounds: 0,
                medium_rate_rounds: 0,
            }
        } else {
            tracing::debug!(rtt, window = WINDOW, window_max = WINDOW_MAX_SLOW, "channel: normal init");
            Self {
                next_tx_sequence: 0,
                next_rx_sequence: 0,
                window: WINDOW,
                window_max: WINDOW_MAX_SLOW,
                window_min: WINDOW_MIN,
                window_flexibility: WINDOW_FLEXIBILITY,
                fast_rate_rounds: 0,
                medium_rate_rounds: 0,
            }
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
        tracing::trace!(seq, next = self.next_tx_sequence, "channel: assigned TX sequence");
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
        if sequence >= self.next_rx_sequence {
            // Not old — always accept (further filtering may happen upstream).
            return true;
        }

        // sequence < next_rx_sequence — could be genuinely old, or could be
        // a wraparound case where the window spans the 0 boundary.
        let window_overflow =
            ((self.next_rx_sequence as u32 + window_max as u32) % SEQ_MODULUS) as u16;

        if window_overflow < self.next_rx_sequence {
            // Window wraps around 0. Sequences in [0..=window_overflow] are valid.
            if sequence > window_overflow {
                tracing::trace!(
                    sequence,
                    next_rx = self.next_rx_sequence,
                    window_overflow,
                    "channel: RX rejected (beyond wrapped window)"
                );
                return false;
            }
            // sequence <= window_overflow — valid wrapped sequence
            true
        } else {
            // No wraparound — sequence is simply old.
            tracing::trace!(
                sequence,
                next_rx = self.next_rx_sequence,
                "channel: RX rejected (old sequence)"
            );
            false
        }
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
        // Grow window toward max.
        if self.window < self.window_max {
            self.window += 1;
            tracing::debug!(window = self.window, window_max = self.window_max, "channel: window grew on delivery");
        }

        // RTT == 0 means no measurement yet — skip rate adaptation.
        if rtt == 0.0 {
            return;
        }

        if rtt > RTT_FAST {
            // Not fast — reset fast counter.
            self.fast_rate_rounds = 0;

            if rtt > RTT_MEDIUM {
                // Slow — reset medium counter too.
                self.medium_rate_rounds = 0;
            } else {
                // Medium — accumulate medium rounds.
                self.medium_rate_rounds += 1;

                if self.window_max < WINDOW_MAX_MEDIUM
                    && self.medium_rate_rounds == FAST_RATE_THRESHOLD
                {
                    self.window_max = WINDOW_MAX_MEDIUM;
                    self.window_min = WINDOW_MIN_LIMIT_MEDIUM;
                    tracing::debug!(
                        window_max = self.window_max,
                        window_min = self.window_min,
                        "channel: upgraded to MEDIUM"
                    );
                }
            }
        } else {
            // Fast — accumulate fast rounds.
            self.fast_rate_rounds += 1;

            if self.window_max < WINDOW_MAX_FAST
                && self.fast_rate_rounds == FAST_RATE_THRESHOLD
            {
                self.window_max = WINDOW_MAX_FAST;
                self.window_min = WINDOW_MIN_LIMIT_FAST;
                tracing::debug!(
                    window_max = self.window_max,
                    window_min = self.window_min,
                    "channel: upgraded to FAST"
                );
            }
        }
    }

    // ------------------------------------------------------------------ //
    // Window adaptation — timeout
    // ------------------------------------------------------------------ //

    /// Adapt the window after a packet timeout and return the outcome.
    ///
    /// `tries` is the current try count for the timed-out envelope **before**
    /// this timeout. The method increments it internally and returns the new
    /// value together with the outcome.
    pub fn on_timeout(&mut self, tries: u32) -> (u32, TimeoutOutcome) {
        let new_tries = tries + 1;
        if new_tries > MAX_TRIES {
            // Already exhausted — signal failure without touching the window.
            return (tries, TimeoutOutcome::Fail);
        }

        if new_tries == MAX_TRIES + 1 {
            unreachable!(); // guarded above
        }

        // Shrink window (but not below minimum).
        if self.window > self.window_min {
            self.window -= 1;
            tracing::debug!(window = self.window, "channel: window shrank on timeout");
        }

        // Shrink window_max (but maintain flexibility gap).
        if self.window_max > self.window_min + self.window_flexibility {
            self.window_max -= 1;
            tracing::debug!(window_max = self.window_max, "channel: window_max shrank on timeout");
        }

        (new_tries, TimeoutOutcome::Retry)
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
        raw.min(0xFFFF)
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
