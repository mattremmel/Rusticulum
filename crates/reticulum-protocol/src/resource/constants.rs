//! Resource transfer window constants.
//!
//! These values are derived from the Python reference implementation (RNS/Resource.py)
//! and validated against the window_adaptation.json test vectors.

/// Initial window size for resource transfers.
pub const WINDOW: u16 = 4;

/// Minimum window size.
pub const WINDOW_MIN: u16 = 2;

/// Default maximum window size (medium-rate links).
pub const WINDOW_MAX_SLOW: u16 = 10;

/// Maximum window size for very slow links (<250 B/s).
pub const WINDOW_MAX_VERY_SLOW: u16 = 4;

/// Maximum window size for fast links (>6250 B/s).
pub const WINDOW_MAX_FAST: u16 = 75;

/// Minimum gap between `window_max` and `window_min`.
pub const WINDOW_FLEXIBILITY: u16 = 4;

/// Throughput threshold for fast links (bytes per second).
pub const RATE_FAST: f64 = 6250.0;

/// Throughput threshold for very slow links (bytes per second).
pub const RATE_VERY_SLOW: f64 = 250.0;

/// Consecutive fast-rate rounds needed to upgrade to `WINDOW_MAX_FAST`.
pub const FAST_RATE_THRESHOLD: u16 = 4;

/// Consecutive very-slow-rate rounds needed to cap at `WINDOW_MAX_VERY_SLOW`.
pub const VERY_SLOW_RATE_THRESHOLD: u16 = 2;
