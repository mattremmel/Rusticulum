//! Link protocol constants.
//!
//! Values sourced from `links.json` test vectors and the Python reference implementation.

/// Size of combined ephemeral public keys (X25519 + Ed25519).
pub const ECPUBSIZE: usize = 64;

/// Size of a single key (X25519 or Ed25519).
pub const LINK_KEYSIZE: usize = 32;

/// Size of the MTU signalling field in bytes.
pub const LINK_MTU_SIZE: usize = 3;

/// 21-bit mask for MTU value in signalling bytes.
pub const MTU_BYTEMASK: u32 = 0x1F_FFFF;

/// 3-bit mask (shifted) for mode value in signalling bytes.
pub const MODE_BYTEMASK: u32 = 0xE0;

/// Maximum keepalive interval in seconds.
pub const KEEPALIVE_MAX: f64 = 360.0;

/// Minimum keepalive interval in seconds.
pub const KEEPALIVE_MIN: f64 = 5.0;

/// RTT value that produces the maximum keepalive interval.
pub const KEEPALIVE_MAX_RTT: f64 = 1.75;

/// Multiplier for stale detection: `stale_time = keepalive * STALE_FACTOR`.
pub const STALE_FACTOR: f64 = 2.0;

/// Grace period (seconds) added before tearing down a stale link.
pub const STALE_GRACE: f64 = 5.0;

/// Factor for keepalive timeout: `timeout = keepalive * KEEPALIVE_TIMEOUT_FACTOR`.
pub const KEEPALIVE_TIMEOUT_FACTOR: f64 = 4.0;

/// Factor for traffic timeout: `timeout = keepalive * TRAFFIC_TIMEOUT_FACTOR`.
pub const TRAFFIC_TIMEOUT_FACTOR: f64 = 6.0;

/// Per-hop timeout for link establishment (seconds).
pub const ESTABLISHMENT_TIMEOUT_PER_HOP: f64 = 6.0;

/// AES block size in bytes.
pub const AES_BLOCKSIZE: usize = 16;

/// Minimum IFAC (interface authentication code) size in bytes.
pub const IFAC_MIN_SIZE: usize = 1;

/// Ed25519 signature size in bytes.
pub const SIGNATURE_SIZE: usize = 64;

/// Minimum packet header size in bytes.
pub const HEADER_MINSIZE: usize = 19;

/// Default keepalive interval (same as KEEPALIVE_MAX).
pub const KEEPALIVE_DEFAULT: f64 = 360.0;

/// Data byte sent by the initiator in a keepalive packet.
pub const KEEPALIVE_MARKER: u8 = 0xFF;

/// Data byte sent by the responder echoing a keepalive.
pub const KEEPALIVE_ECHO_MARKER: u8 = 0xFE;
