//! Instance mode classification for shared Reticulum nodes.
//!
//! Determines whether this node is the master (owning hardware interfaces),
//! a client (relaying through a master), or standalone (no sharing).

/// The operating mode of a Reticulum node instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstanceMode {
    /// Master node: owns all hardware interfaces, runs transport,
    /// manages routing tables, and serves local clients via a Unix socket.
    SharedMaster,
    /// Client node: connects to a master via a local socket,
    /// relays all packets through the master. No hardware interfaces,
    /// no persistent state, no transport relay.
    SharedClient,
    /// Standalone node: no sharing. Owns hardware interfaces and runs
    /// the full protocol stack independently.
    Standalone,
}

impl InstanceMode {
    /// Whether this mode creates and manages hardware interfaces (TCP, UDP, etc.).
    pub const fn creates_hardware_interfaces(&self) -> bool {
        matches!(self, Self::SharedMaster | Self::Standalone)
    }

    /// Whether this mode runs the transport relay (HEADER_2 forwarding).
    pub const fn runs_transport(&self) -> bool {
        matches!(self, Self::SharedMaster | Self::Standalone)
    }

    /// Whether this mode manages persistent state (identity, path table, hashlist).
    pub const fn manages_state(&self) -> bool {
        matches!(self, Self::SharedMaster | Self::Standalone)
    }

    /// Whether this mode is a shared client.
    pub const fn is_client(&self) -> bool {
        matches!(self, Self::SharedClient)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standalone_creates_hardware_and_manages_state() {
        let mode = InstanceMode::Standalone;
        assert!(mode.creates_hardware_interfaces());
        assert!(mode.runs_transport());
        assert!(mode.manages_state());
        assert!(!mode.is_client());
    }

    #[test]
    fn shared_master_creates_hardware_and_manages_state() {
        let mode = InstanceMode::SharedMaster;
        assert!(mode.creates_hardware_interfaces());
        assert!(mode.runs_transport());
        assert!(mode.manages_state());
        assert!(!mode.is_client());
    }

    #[test]
    fn shared_client_is_minimal() {
        let mode = InstanceMode::SharedClient;
        assert!(!mode.creates_hardware_interfaces());
        assert!(!mode.runs_transport());
        assert!(!mode.manages_state());
        assert!(mode.is_client());
    }
}
