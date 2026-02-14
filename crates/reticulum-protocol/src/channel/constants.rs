//! Channel protocol constants.
//!
//! These values are derived from the Python reference implementation (RNS/Channel.py)
//! and validated against the channels.json test vectors.

/// Envelope header overhead in bytes (msg_type + sequence + data_length, each u16 big-endian).
pub const ENVELOPE_OVERHEAD: usize = 6;

/// Maximum sequence number value.
pub const SEQ_MAX: u16 = 0xFFFF;

/// Sequence number modulus (wraps at 65536).
pub const SEQ_MODULUS: u32 = 65536;

/// Message types at or above this boundary are system-reserved.
pub const SYSTEM_MESSAGE_BOUNDARY: u16 = 0xF000;

// ---- Window constants (for sequencing/windowing in c7u.7) ----

/// Default initial window size.
pub const WINDOW: u16 = 2;

/// Minimum window size.
pub const WINDOW_MIN: u16 = 2;

/// Minimum window limit for slow links.
pub const WINDOW_MIN_LIMIT_SLOW: u16 = 2;

/// Minimum window limit for medium links.
pub const WINDOW_MIN_LIMIT_MEDIUM: u16 = 5;

/// Minimum window limit for fast links.
pub const WINDOW_MIN_LIMIT_FAST: u16 = 16;

/// Maximum window size for slow links.
pub const WINDOW_MAX_SLOW: u16 = 5;

/// Maximum window size for medium links.
pub const WINDOW_MAX_MEDIUM: u16 = 12;

/// Maximum window size for fast links.
pub const WINDOW_MAX_FAST: u16 = 48;

/// Absolute maximum window size.
pub const WINDOW_MAX: u16 = 48;

/// RTT threshold for fast links (seconds).
pub const RTT_FAST: f64 = 0.18;

/// RTT threshold for medium links (seconds).
pub const RTT_MEDIUM: f64 = 0.75;

/// RTT threshold for slow links (seconds).
pub const RTT_SLOW: f64 = 1.45;

/// Fast rate threshold.
pub const FAST_RATE_THRESHOLD: u16 = 10;

/// Window flexibility parameter.
pub const WINDOW_FLEXIBILITY: u16 = 4;

/// Maximum channel MDU (payload capped at u16 max due to 2-byte length field).
pub const MAX_CHANNEL_MDU: usize = 0xFFFF;
