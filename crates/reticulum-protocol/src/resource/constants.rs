//! Resource transfer constants.
//!
//! These values are derived from the Python reference implementation (RNS/Resource.py)
//! and validated against the resources.json and window_adaptation.json test vectors.

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

// ------------------------------------------------------------------ //
// Resource sizing constants
// ------------------------------------------------------------------ //

/// Bytes per part-map hash entry (truncated SHA-256).
pub const MAPHASH_LEN: usize = 4;

/// Bytes of random hash prepended to resource data before encryption.
pub const RANDOM_HASH_SIZE: usize = 4;

/// Service Data Unit — maximum resource part size (MTU - headers).
///
/// `MTU(500) - HEADER_MAXSIZE(35) - IFAC_MIN_SIZE(1) = 464`
pub const SDU: usize = 464;

/// Maximum resource size that fits in a single segment.
pub const MAX_EFFICIENT_SIZE: usize = 1_048_575;

/// Maximum metadata size (limited by 3-byte big-endian size prefix).
pub const METADATA_MAX_SIZE: usize = 16_777_215;

/// Resources up to this size are automatically bz2-compressed if beneficial.
pub const AUTO_COMPRESS_MAX_SIZE: usize = 67_108_864;

/// Fixed msgpack overhead per resource advertisement.
pub const ADVERTISEMENT_OVERHEAD: usize = 134;

/// Maximum number of 4-byte part hashes per advertisement.
///
/// `floor((LINK_MDU(431) - OVERHEAD(134)) / MAPHASH_LEN(4)) = 74`
pub const HASHMAP_MAX_LEN: usize = 74;

/// Collision guard size for part tracking.
///
/// `2 * WINDOW_MAX(75) + HASHMAP_MAX_LEN(74) = 224`
pub const COLLISION_GUARD_SIZE: usize = 224;

// ------------------------------------------------------------------ //
// Timeout and retry constants
// ------------------------------------------------------------------ //

/// Part timeout multiplier before RTT is known.
pub const PART_TIMEOUT_FACTOR: u32 = 4;

/// Part timeout multiplier after RTT is established.
pub const PART_TIMEOUT_FACTOR_AFTER_RTT: u32 = 2;

/// Proof timeout multiplier (relative to part timeout).
pub const PROOF_TIMEOUT_FACTOR: u32 = 3;

/// Maximum retries for individual resource parts.
pub const MAX_RETRIES: u32 = 16;

/// Maximum retries for advertisement delivery.
pub const MAX_ADV_RETRIES: u32 = 4;

/// Grace time (seconds) added to sender's overall timeout.
pub const SENDER_GRACE_TIME: f64 = 10.0;

/// Grace time (seconds) for processing after all parts received.
pub const PROCESSING_GRACE: f64 = 1.0;

/// Grace time (seconds) between retry attempts.
pub const RETRY_GRACE_TIME: f64 = 0.25;

/// Delay (seconds) per retry attempt.
pub const PER_RETRY_DELAY: f64 = 0.5;

/// Maximum watchdog sleep interval (seconds).
pub const WATCHDOG_MAX_SLEEP: u32 = 1;

/// Maximum grace time (seconds) for response resources.
pub const RESPONSE_MAX_GRACE_TIME: u32 = 10;

// ------------------------------------------------------------------ //
// Part request flags
// ------------------------------------------------------------------ //

/// Flag byte for a normal (non-exhausted) part request.
pub const PART_REQUEST_NORMAL: u8 = 0x00;

/// Flag byte for an exhausted part request (receiver gave up retrying).
pub const PART_REQUEST_EXHAUSTED: u8 = 0xFF;
