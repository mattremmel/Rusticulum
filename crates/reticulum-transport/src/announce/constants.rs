//! Announce propagation constants.

/// Number of retransmit retries for announces.
pub const PATHFINDER_R: u32 = 1;

/// Retry grace period in seconds.
pub const PATHFINDER_G: f64 = 5.0;

/// Random window for announce rebroadcast (seconds).
pub const PATHFINDER_RW: f64 = 0.5;

/// Maximum local rebroadcasts allowed.
pub const LOCAL_REBROADCASTS_MAX: u32 = 2;

/// Announce bandwidth cap (2% of interface bandwidth).
pub const ANNOUNCE_CAP: f64 = 0.02;
