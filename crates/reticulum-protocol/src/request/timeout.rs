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
}
