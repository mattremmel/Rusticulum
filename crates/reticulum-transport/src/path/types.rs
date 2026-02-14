//! Path table types.

use std::collections::VecDeque;

use reticulum_core::types::{PacketHash, TruncatedHash};

use super::constants::*;
use crate::error::PathError;

/// Lightweight interface identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct InterfaceId(pub u64);

/// Interface operating mode, determines path TTL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum InterfaceMode {
    Full = 0,
    PointToPoint = 1,
    AccessPoint = 2,
    Roaming = 3,
    Boundary = 4,
    Gateway = 5,
}

/// Test-vector mode string constants.
pub mod mode_str {
    pub const MODE_FULL: &str = "MODE_FULL";
    pub const MODE_ACCESS_POINT: &str = "MODE_ACCESS_POINT";
    pub const MODE_ROAMING: &str = "MODE_ROAMING";
    pub const MODE_POINT_TO_POINT: &str = "MODE_POINT_TO_POINT";
    pub const MODE_BOUNDARY: &str = "MODE_BOUNDARY";
    pub const MODE_GATEWAY: &str = "MODE_GATEWAY";
    pub const DEFAULT: &str = "default";
}

impl InterfaceMode {
    /// Convert from raw byte value.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(InterfaceMode::Full),
            1 => Some(InterfaceMode::PointToPoint),
            2 => Some(InterfaceMode::AccessPoint),
            3 => Some(InterfaceMode::Roaming),
            4 => Some(InterfaceMode::Boundary),
            5 => Some(InterfaceMode::Gateway),
            _ => None,
        }
    }

    /// Parse from test-vector string representation (e.g. "MODE_FULL", "default").
    pub fn from_vector_str(s: &str) -> Result<Self, PathError> {
        match s {
            mode_str::MODE_ACCESS_POINT => Ok(InterfaceMode::AccessPoint),
            mode_str::MODE_ROAMING => Ok(InterfaceMode::Roaming),
            mode_str::MODE_POINT_TO_POINT => Ok(InterfaceMode::PointToPoint),
            mode_str::MODE_BOUNDARY => Ok(InterfaceMode::Boundary),
            mode_str::MODE_GATEWAY => Ok(InterfaceMode::Gateway),
            mode_str::MODE_FULL | mode_str::DEFAULT => Ok(InterfaceMode::Full),
            other => Err(PathError::InvalidInterfaceMode(other.to_string())),
        }
    }

    /// Get the path TTL for this interface mode.
    pub fn path_ttl(&self) -> u64 {
        match self {
            InterfaceMode::AccessPoint => AP_PATH_TIME,
            InterfaceMode::Roaming => ROAMING_PATH_TIME,
            InterfaceMode::Full
            | InterfaceMode::PointToPoint
            | InterfaceMode::Boundary
            | InterfaceMode::Gateway => PATHFINDER_E,
        }
    }
}

/// A single entry in the path table.
#[derive(Debug, Clone)]
pub struct PathEntry {
    /// Timestamp when the path was last updated.
    pub timestamp: u64,
    /// Next hop address (16-byte truncated hash).
    pub next_hop: TruncatedHash,
    /// Number of hops to destination.
    pub hops: u8,
    /// Absolute timestamp when this path expires.
    pub expires: u64,
    /// Random blobs from announces (for deduplication and timebase).
    random_blobs: VecDeque<[u8; 10]>,
    /// Interface on which this path was learned.
    pub receiving_interface: InterfaceId,
    /// Cached packet hash of the announce that created/updated this entry.
    pub packet_hash: PacketHash,
    /// Whether the path is marked as unresponsive.
    pub unresponsive: bool,
}

impl PathEntry {
    /// Create a new path entry with TTL computed from interface mode.
    pub fn new(
        timestamp: u64,
        next_hop: TruncatedHash,
        hops: u8,
        mode: InterfaceMode,
        random_blobs: Vec<[u8; 10]>,
        receiving_interface: InterfaceId,
        packet_hash: PacketHash,
    ) -> Self {
        let expires = timestamp + mode.path_ttl();
        Self {
            timestamp,
            next_hop,
            hops,
            expires,
            random_blobs: VecDeque::from(random_blobs),
            receiving_interface,
            packet_hash,
            unresponsive: false,
        }
    }

    /// Create a path entry from raw fields (for deserialization).
    #[allow(clippy::too_many_arguments)]
    pub fn from_raw(
        timestamp: u64,
        next_hop: TruncatedHash,
        hops: u8,
        expires: u64,
        random_blobs: Vec<[u8; 10]>,
        receiving_interface: InterfaceId,
        packet_hash: PacketHash,
        unresponsive: bool,
    ) -> Self {
        Self {
            timestamp,
            next_hop,
            hops,
            expires,
            random_blobs: VecDeque::from(random_blobs),
            receiving_interface,
            packet_hash,
            unresponsive,
        }
    }

    /// Access the random blobs.
    pub fn random_blobs(&self) -> &VecDeque<[u8; 10]> {
        &self.random_blobs
    }

    /// Convert random blobs to a Vec for serialization.
    pub fn random_blobs_to_vec(&self) -> Vec<[u8; 10]> {
        self.random_blobs.iter().copied().collect()
    }

    /// Check if this path is expired at the given time.
    ///
    /// Uses strict `>` comparison: `now > expires` means expired.
    pub fn is_expired(&self, now: u64) -> bool {
        now > self.expires
    }

    /// Force-expire this path by setting expires to 0.
    pub fn expire(&mut self) {
        self.expires = 0;
    }

    /// Refresh the timestamp and extend TTL (called on packet forward).
    pub fn refresh_timestamp(&mut self, now: u64, mode: InterfaceMode) {
        self.timestamp = now;
        self.expires = now + mode.path_ttl();
    }

    /// Check if a random blob is already tracked.
    pub fn has_random_blob(&self, blob: &[u8; 10]) -> bool {
        self.random_blobs.iter().any(|b| b == blob)
    }

    /// Add a random blob, maintaining the max size limit.
    pub fn add_random_blob(&mut self, blob: [u8; 10]) {
        if !self.has_random_blob(&blob) {
            if self.random_blobs.len() >= MAX_RANDOM_BLOBS {
                self.random_blobs.pop_front();
            }
            self.random_blobs.push_back(blob);
        }
    }

    /// Compute the emission timebase from random blobs.
    ///
    /// Takes the maximum of bytes [5..10] (big-endian u64) across all blobs.
    pub fn timebase_from_random_blobs(&self) -> u64 {
        self.random_blobs
            .iter()
            .map(|blob| {
                let mut bytes = [0u8; 8];
                // Bytes 5..10 of the blob are the 5-byte big-endian timestamp
                bytes[3..8].copy_from_slice(&blob[5..10]);
                u64::from_be_bytes(bytes)
            })
            .max()
            .unwrap_or(0)
    }
}
