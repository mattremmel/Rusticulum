//! TCP interface implementation with HDLC framing.
//!
//! Provides [`TcpClientInterface`] (initiator and responder modes) and
//! [`TcpServerInterface`] (listener that spawns responder clients).

pub mod client;
pub mod framing;
pub mod server;

pub use client::{TcpClientInterface, TcpClientRole};
pub use framing::HdlcFrameAccumulator;
pub use server::TcpServerInterface;

use std::net::SocketAddr;
use std::time::Duration;

use reticulum_transport::path::InterfaceMode;

// ---------------------------------------------------------------------------
// Constants matching Python reference (TCPInterface.py)
// ---------------------------------------------------------------------------

/// Assumed link-layer bitrate in bits per second (10 Mbps).
pub const BITRATE_GUESS: u64 = 10_000_000;

/// Delay between reconnection attempts for initiator clients.
pub const RECONNECT_WAIT: Duration = Duration::from_secs(5);

/// Timeout for the initial TCP connection attempt.
pub const INITIAL_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Size of the read buffer for `TcpStream::read`.
pub const TCP_RECV_BUFFER: usize = 4096;

// ---------------------------------------------------------------------------
// Configuration types
// ---------------------------------------------------------------------------

/// Configuration for a [`TcpClientInterface`].
#[derive(Debug, Clone)]
pub struct TcpClientConfig {
    /// Human-readable name for this interface.
    pub name: String,
    /// Target address (required for initiator mode, ignored for responder).
    pub target_addr: Option<SocketAddr>,
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

impl TcpClientConfig {
    /// Create a config for a client that initiates connections.
    pub fn initiator(name: impl Into<String>, target: SocketAddr) -> Self {
        Self {
            name: name.into(),
            target_addr: Some(target),
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
            target_addr: None,
            mode: InterfaceMode::Full,
            max_reconnect_tries: None,
            connect_timeout: INITIAL_CONNECT_TIMEOUT,
            can_transmit: true,
            can_receive: true,
        }
    }
}

/// Configuration for a [`TcpServerInterface`].
#[derive(Debug, Clone)]
pub struct TcpServerConfig {
    /// Human-readable name for this server interface.
    pub name: String,
    /// Address to bind the TCP listener to.
    pub bind_addr: SocketAddr,
    /// Interface mode applied to spawned client interfaces.
    pub mode: InterfaceMode,
    /// Whether spawned clients can transmit.
    pub client_can_transmit: bool,
    /// Whether spawned clients can receive.
    pub client_can_receive: bool,
}

impl TcpServerConfig {
    pub fn new(name: impl Into<String>, bind_addr: SocketAddr) -> Self {
        Self {
            name: name.into(),
            bind_addr,
            mode: InterfaceMode::Full,
            client_can_transmit: true,
            client_can_receive: true,
        }
    }
}
