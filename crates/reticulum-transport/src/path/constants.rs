//! Path table constants.

/// Default path expiration time (7 days in seconds).
pub const PATHFINDER_E: u64 = 60 * 60 * 24 * 7; // 604800

/// Access Point path time (24 hours in seconds).
pub const AP_PATH_TIME: u64 = 60 * 60 * 24; // 86400

/// Roaming path time (6 hours in seconds).
pub const ROAMING_PATH_TIME: u64 = 60 * 60 * 6; // 21600

/// Maximum hop count.
pub const PATHFINDER_M: u8 = 128;

/// Maximum random blobs stored per path entry.
pub const MAX_RANDOM_BLOBS: usize = 64;

/// Minimum interval between path requests for the same destination (seconds).
pub const PATH_REQUEST_MI: f64 = 20.0;

/// Default timeout for awaiting a path response (seconds).
pub const PATH_REQUEST_TIMEOUT: f64 = 15.0;

/// Grace period before serving a known path (seconds).
pub const PATH_REQUEST_GRACE: f64 = 0.4;

/// Extra grace for roaming interfaces (seconds).
pub const PATH_REQUEST_RG: f64 = 1.5;

/// Maximum number of discovery tags tracked for deduplication.
pub const MAX_PR_TAGS: usize = 32_000;
