//! Shared link types.
//!
//! Enums, configuration types, and statistics structs used across the link module.

use crate::error::LinkError;

/// Role of a peer in a link handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkRole {
    Initiator,
    Responder,
}

/// Reason a link was torn down.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TeardownReason {
    Timeout = 0x01,
    InitiatorClosed = 0x02,
    DestinationClosed = 0x03,
}

impl TeardownReason {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(Self::Timeout),
            0x02 => Some(Self::InitiatorClosed),
            0x03 => Some(Self::DestinationClosed),
            _ => None,
        }
    }
}

/// Link encryption mode (3-bit field).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LinkMode {
    Aes128Cbc = 0,
    #[default]
    Aes256Cbc = 1,
    Aes256Gcm = 2,
    OtpReserved = 3,
    PqReserved1 = 4,
    PqReserved2 = 5,
    PqReserved3 = 6,
    PqReserved4 = 7,
}

impl LinkMode {
    /// Parse a mode value from a `u8`. Returns `Err(LinkError::UnsupportedMode)` for values >= 8.
    pub fn from_u8(value: u8) -> Result<Self, LinkError> {
        match value {
            0 => Ok(Self::Aes128Cbc),
            1 => Ok(Self::Aes256Cbc),
            2 => Ok(Self::Aes256Gcm),
            3 => Ok(Self::OtpReserved),
            4 => Ok(Self::PqReserved1),
            5 => Ok(Self::PqReserved2),
            6 => Ok(Self::PqReserved3),
            7 => Ok(Self::PqReserved4),
            other => Err(LinkError::UnsupportedMode(other)),
        }
    }

    /// Whether this mode is currently enabled (supported) by the implementation.
    pub fn is_enabled(&self) -> bool {
        matches!(self, Self::Aes256Cbc)
    }
}

/// Resource acceptance strategy for a link.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ResourceStrategy {
    #[default]
    AcceptNone = 0,
    AcceptApp = 1,
    AcceptAll = 2,
}

impl ResourceStrategy {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::AcceptNone),
            1 => Some(Self::AcceptApp),
            2 => Some(Self::AcceptAll),
            _ => None,
        }
    }
}

/// Physical layer statistics reported by the interface.
#[derive(Debug, Clone, Default)]
pub struct PhyStats {
    pub rssi: Option<f64>,
    pub snr: Option<f64>,
    pub quality: Option<f64>,
}

/// Traffic counters for a link.
#[derive(Debug, Clone, Default)]
pub struct LinkStats {
    pub tx_packets: u64,
    pub rx_packets: u64,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
}

/// A 64-byte derived key split into signing (first 32) and encryption (last 32).
pub struct DerivedKey([u8; 64]);

impl DerivedKey {
    pub fn new(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }

    /// First 32 bytes: used for HMAC signing in Token encrypt/decrypt.
    pub fn signing_key(&self) -> &[u8; 32] {
        self.0[..32].try_into().unwrap()
    }

    /// Last 32 bytes: used for AES-256-CBC encryption in Token encrypt/decrypt.
    pub fn encryption_key(&self) -> &[u8; 32] {
        self.0[32..].try_into().unwrap()
    }
}

impl std::fmt::Debug for DerivedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("DerivedKey").field(&"[REDACTED]").finish()
    }
}

impl Clone for DerivedKey {
    fn clone(&self) -> Self {
        Self(self.0)
    }
}

impl Drop for DerivedKey {
    fn drop(&mut self) {
        // Zero out key material on drop.
        // This is best-effort; the compiler may optimize it away.
        // For production use, consider `zeroize` crate.
        self.0.fill(0);
    }
}
