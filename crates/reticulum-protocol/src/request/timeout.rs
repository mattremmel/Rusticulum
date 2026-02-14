//! Request timeout computation.

use super::constants::{GRACE_MULTIPLIER, RESPONSE_MAX_GRACE_TIME, TRAFFIC_TIMEOUT_FACTOR};

/// Compute the request timeout from the measured round-trip time.
///
/// Formula: `rtt * TRAFFIC_TIMEOUT_FACTOR + RESPONSE_MAX_GRACE_TIME * GRACE_MULTIPLIER`
pub fn compute_request_timeout(rtt: f64) -> f64 {
    rtt * TRAFFIC_TIMEOUT_FACTOR + RESPONSE_MAX_GRACE_TIME * GRACE_MULTIPLIER
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timeout_vectors() {
        let vectors = reticulum_test_vectors::requests::load();
        for tv in &vectors.timeout_vectors {
            let computed = compute_request_timeout(tv.rtt);
            assert!(
                (computed - tv.timeout).abs() < 1e-9,
                "index={}: expected {} but got {} for rtt={}",
                tv.index,
                tv.timeout,
                computed,
                tv.rtt,
            );
        }
    }

    #[test]
    fn test_timeout_zero_rtt() {
        // RTT=0.0 → 0*6 + 10*1.125 = 11.25
        let t = compute_request_timeout(0.0);
        assert!((t - 11.25).abs() < 1e-9);
    }

    #[test]
    fn test_timeout_negative_rtt() {
        // RTT=-1.0 → -6 + 11.25 = 5.25 (no panic)
        let t = compute_request_timeout(-1.0);
        assert!((t - 5.25).abs() < 1e-9);
    }

    #[test]
    fn test_timeout_very_large_rtt() {
        // RTT=1e6 → 6e6 + 11.25, verify no overflow and proportional
        let t = compute_request_timeout(1e6);
        assert!(t > 5_999_000.0);
        assert!(t < 6_100_000.0);
    }

    #[test]
    fn test_timeout_monotonically_increasing() {
        let rtts = [0.01, 0.1, 1.0, 10.0, 100.0];
        let timeouts: Vec<f64> = rtts.iter().map(|&r| compute_request_timeout(r)).collect();
        for i in 1..timeouts.len() {
            assert!(
                timeouts[i] > timeouts[i - 1],
                "timeout at rtt={} ({}) should exceed timeout at rtt={} ({})",
                rtts[i],
                timeouts[i],
                rtts[i - 1],
                timeouts[i - 1],
            );
        }
    }

    #[test]
    fn test_timeout_exact_formula() {
        // RTT=1.0 → 1.0*6.0 + 10.0*1.125 = 6.0 + 11.25 = 17.25
        let t = compute_request_timeout(1.0);
        assert!((t - 17.25).abs() < 1e-9);
    }
}
