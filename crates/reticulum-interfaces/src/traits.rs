//! Core interface trait and event types.

use reticulum_transport::path::{InterfaceId, InterfaceMode};

use crate::error::InterfaceError;

/// Reticulum default MTU in bytes.
pub const DEFAULT_MTU: usize = 500;

/// Async trait implemented by all network interfaces (TCP, UDP, Local, etc.).
///
/// Protocol state machines produce `Vec<u8>` actions rather than performing I/O
/// directly — concrete interface implementations bridge that to actual network I/O.
pub trait Interface: Send + Sync {
    // -- Identity --

    /// Human-readable name for this interface (e.g. "TCPInterface[localhost:4242]").
    fn name(&self) -> &str;

    /// Unique identifier for this interface instance.
    fn id(&self) -> InterfaceId;

    /// Operating mode (Full, AccessPoint, Roaming, etc.).
    fn mode(&self) -> InterfaceMode;

    // -- Capabilities --

    /// Link-layer bitrate in bits per second (used for announce rate limiting).
    fn bitrate(&self) -> u64;

    /// Maximum transmission unit. Defaults to `DEFAULT_MTU` (500 bytes).
    fn mtu(&self) -> usize {
        DEFAULT_MTU
    }

    /// Whether this interface can receive packets (Python `IN` flag).
    fn can_receive(&self) -> bool;

    /// Whether this interface can transmit packets (Python `OUT` flag).
    fn can_transmit(&self) -> bool;

    /// Whether the interface is currently connected and operational.
    fn is_connected(&self) -> bool;

    // -- Async I/O --

    /// Start the interface (bind sockets, open ports, spawn read loops, etc.).
    fn start(&mut self) -> impl Future<Output = Result<(), InterfaceError>> + Send;

    /// Stop the interface and release resources.
    fn stop(&mut self) -> impl Future<Output = Result<(), InterfaceError>> + Send;

    /// Transmit raw packet bytes over this interface.
    fn transmit(&self, data: &[u8]) -> impl Future<Output = Result<(), InterfaceError>> + Send;

    /// Receive the next raw packet from this interface.
    fn receive(&self) -> impl Future<Output = Result<Vec<u8>, InterfaceError>> + Send;
}

/// Events emitted by an interface for consumption by the transport layer.
#[derive(Debug)]
pub enum InterfaceEvent {
    /// A complete packet was received from the wire.
    PacketReceived {
        data: Vec<u8>,
        interface_id: InterfaceId,
    },
    /// Interface has connected / come online.
    Connected,
    /// Interface has disconnected / gone offline.
    Disconnected,
    /// An error occurred on the interface.
    Error(InterfaceError),
}
