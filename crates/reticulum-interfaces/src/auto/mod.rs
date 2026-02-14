//! Auto interface — automatic peer discovery via IPv6 multicast.
//!
//! Implements a two-phase protocol:
//! 1. **Discovery** — periodic multicast announcements to find peers on the LAN
//! 2. **Data transport** — unicast UDP directly to discovered peers

pub mod discovery;
pub mod interface;
pub mod netif;
pub mod peer;

pub use interface::AutoInterface;

use std::time::Duration;

use reticulum_transport::path::InterfaceMode;

// ---------------------------------------------------------------------------
// Constants matching Python reference (AutoInterface.py)
// ---------------------------------------------------------------------------

/// Default multicast discovery port.
pub const DEFAULT_DISCOVERY_PORT: u16 = 29716;

/// Default unicast data port.
pub const DEFAULT_DATA_PORT: u16 = 42671;

/// Default group identifier.
pub const DEFAULT_GROUP_ID: &[u8] = b"reticulum";

/// Peer timeout — remove peers not heard within this window.
pub const PEERING_TIMEOUT: Duration = Duration::from_millis(22_000);

/// Interval between multicast discovery announcements.
pub const ANNOUNCE_INTERVAL: Duration = Duration::from_millis(1_600);

/// Interval between peer maintenance jobs (prune + reverse peering).
pub const PEER_JOB_INTERVAL: Duration = Duration::from_millis(4_000);

/// Multicast echo timeout (carrier detection).
pub const MCAST_ECHO_TIMEOUT: Duration = Duration::from_millis(6_500);

/// Hardware MTU for the Auto interface.
pub const HW_MTU: usize = 1196;

/// Assumed link-layer bitrate in bits per second (10 Mbps).
pub const BITRATE_GUESS: u64 = 10_000_000;

/// Dedup ring buffer length.
pub const MULTI_IF_DEQUE_LEN: usize = 48;

/// Dedup entry time-to-live.
pub const MULTI_IF_DEQUE_TTL: Duration = Duration::from_millis(750);

/// Size of the UDP receive buffer.
pub const RECV_BUFFER: usize = 2048;

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

/// IPv6 multicast discovery scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveryScope {
    /// Link-local (scope 2) — same physical LAN segment.
    Link,
    /// Admin-local (scope 4).
    Admin,
    /// Site-local (scope 5).
    Site,
    /// Organisation-local (scope 8).
    Organisation,
    /// Global (scope e).
    Global,
}

impl DiscoveryScope {
    /// Return the single hex character used in the IPv6 multicast address.
    pub fn as_hex_char(self) -> char {
        match self {
            DiscoveryScope::Link => '2',
            DiscoveryScope::Admin => '4',
            DiscoveryScope::Site => '5',
            DiscoveryScope::Organisation => '8',
            DiscoveryScope::Global => 'e',
        }
    }
}

/// Multicast address type (flags nibble in the IPv6 multicast prefix).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MulticastAddressType {
    /// Well-known / permanent (flag 0).
    Permanent,
    /// Transient / temporary (flag 1).
    Temporary,
}

impl MulticastAddressType {
    /// Return the single hex character used in the IPv6 multicast address.
    pub fn as_hex_char(self) -> char {
        match self {
            MulticastAddressType::Permanent => '0',
            MulticastAddressType::Temporary => '1',
        }
    }
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for an [`AutoInterface`].
#[derive(Debug, Clone)]
pub struct AutoConfig {
    /// Human-readable name for this interface.
    pub name: String,
    /// Group identifier — peers must share the same group to discover each other.
    pub group_id: Vec<u8>,
    /// Multicast discovery port.
    pub discovery_port: u16,
    /// Unicast data port.
    pub data_port: u16,
    /// IPv6 multicast scope.
    pub discovery_scope: DiscoveryScope,
    /// Multicast address type flag.
    pub multicast_address_type: MulticastAddressType,
    /// Interface operating mode.
    pub mode: InterfaceMode,
    /// Only use these network interfaces (empty = all eligible).
    pub allowed_interfaces: Vec<String>,
    /// Ignore these network interfaces.
    pub ignored_interfaces: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_scope_hex_chars() {
        assert_eq!(DiscoveryScope::Link.as_hex_char(), '2');
        assert_eq!(DiscoveryScope::Admin.as_hex_char(), '4');
        assert_eq!(DiscoveryScope::Site.as_hex_char(), '5');
        assert_eq!(DiscoveryScope::Organisation.as_hex_char(), '8');
        assert_eq!(DiscoveryScope::Global.as_hex_char(), 'e');
    }

    #[test]
    fn multicast_address_type_hex_chars() {
        assert_eq!(MulticastAddressType::Permanent.as_hex_char(), '0');
        assert_eq!(MulticastAddressType::Temporary.as_hex_char(), '1');
    }
}

impl AutoConfig {
    /// Create a default configuration with the given name.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            group_id: DEFAULT_GROUP_ID.to_vec(),
            discovery_port: DEFAULT_DISCOVERY_PORT,
            data_port: DEFAULT_DATA_PORT,
            discovery_scope: DiscoveryScope::Link,
            multicast_address_type: MulticastAddressType::Temporary,
            mode: InterfaceMode::Full,
            allowed_interfaces: Vec::new(),
            ignored_interfaces: Vec::new(),
        }
    }
}
