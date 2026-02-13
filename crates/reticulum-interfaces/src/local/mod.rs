//! Local (Unix domain socket) interface implementation with HDLC framing.
//!
//! Provides [`LocalClientInterface`] (initiator and responder modes) and
//! [`LocalServerInterface`] (listener that spawns responder clients) for
//! inter-process communication between Reticulum instances on the same machine.

pub mod client;
pub mod server;

pub use client::{LocalClientInterface, LocalClientRole};
pub use server::LocalServerInterface;

use std::path::PathBuf;
use std::time::Duration;

use reticulum_transport::path::InterfaceMode;

// ---------------------------------------------------------------------------
// Constants matching Python reference (LocalInterface.py)
// ---------------------------------------------------------------------------

/// Assumed link-layer bitrate in bits per second (1 Gbps — local IPC).
pub const BITRATE_GUESS: u64 = 1_000_000_000;

/// MTU for local interfaces (262 144 bytes — much larger than network MTU).
pub const LOCAL_MTU: usize = 262_144;

/// Delay between reconnection attempts for initiator clients.
pub const RECONNECT_WAIT: Duration = Duration::from_secs(8);

/// Timeout for the initial Unix socket connection attempt.
pub const INITIAL_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Size of the read buffer for `UnixStream::read`.
pub const LOCAL_RECV_BUFFER: usize = 4096;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Return the default socket path for a given Reticulum instance name.
///
/// Uses `std::env::temp_dir()` as the base directory, producing paths like
/// `/tmp/rns_<instance_name>.sock`.
pub fn default_socket_path(instance_name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("rns_{instance_name}.sock"))
}

// ---------------------------------------------------------------------------
// Configuration types
// ---------------------------------------------------------------------------

/// Configuration for a [`LocalClientInterface`].
#[derive(Debug, Clone)]
pub struct LocalClientConfig {
    /// Human-readable name for this interface.
    pub name: String,
    /// Socket path (required for initiator mode, ignored for responder).
    pub socket_path: Option<PathBuf>,
    /// Interface operating mode.
    pub mode: InterfaceMode,
    /// Maximum reconnection attempts (`None` = unlimited).
    pub max_reconnect_tries: Option<u32>,
    /// Timeout for connection attempts.
    pub connect_timeout: Duration,
    /// Whether this interface can transmit packets.
    pub can_transmit: bool,
    /// Whether this interface can receive packets.
    pub can_receive: bool,
}

impl LocalClientConfig {
    /// Create a config for a client that initiates connections.
    pub fn initiator(name: impl Into<String>, socket_path: PathBuf) -> Self {
        Self {
            name: name.into(),
            socket_path: Some(socket_path),
            mode: InterfaceMode::Full,
            max_reconnect_tries: None,
            connect_timeout: INITIAL_CONNECT_TIMEOUT,
            can_transmit: true,
            can_receive: true,
        }
    }

    /// Create a config for a server-spawned responder client.
    pub fn responder(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            socket_path: None,
            mode: InterfaceMode::Full,
            max_reconnect_tries: None,
            connect_timeout: INITIAL_CONNECT_TIMEOUT,
            can_transmit: true,
            can_receive: true,
        }
    }
}

/// Configuration for a [`LocalServerInterface`].
#[derive(Debug, Clone)]
pub struct LocalServerConfig {
    /// Human-readable name for this server interface.
    pub name: String,
    /// Path for the Unix domain socket to bind.
    pub socket_path: PathBuf,
    /// Interface mode applied to spawned client interfaces.
    pub mode: InterfaceMode,
    /// Whether spawned clients can transmit.
    pub client_can_transmit: bool,
    /// Whether spawned clients can receive.
    pub client_can_receive: bool,
}

impl LocalServerConfig {
    pub fn new(name: impl Into<String>, socket_path: PathBuf) -> Self {
        Self {
            name: name.into(),
            socket_path,
            mode: InterfaceMode::Full,
            client_can_transmit: true,
            client_can_receive: true,
        }
    }
}
