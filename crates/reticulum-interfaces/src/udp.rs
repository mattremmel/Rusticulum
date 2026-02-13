//! UDP interface implementation.
//!
//! Provides [`UdpInterface`] for datagram-based communication. Unlike TCP,
//! UDP datagrams are atomic so no HDLC framing is needed, there is no
//! connection state, and no reconnection logic.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::net::UdpSocket;
use tokio::sync::{Mutex, mpsc, watch};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use reticulum_transport::path::{InterfaceId, InterfaceMode};

use crate::error::InterfaceError;
use crate::traits::Interface;

// ---------------------------------------------------------------------------
// Constants matching Python reference (UDPInterface.py)
// ---------------------------------------------------------------------------

/// Assumed link-layer bitrate in bits per second (10 Mbps).
pub const BITRATE_GUESS: u64 = 10_000_000;

/// Hardware MTU for UDP interface (matching Python `HW_MTU`).
pub const UDP_HW_MTU: usize = 1064;

/// Size of the receive buffer for `UdpSocket::recv_from`.
pub const UDP_RECV_BUFFER: usize = 2048;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for a [`UdpInterface`].
#[derive(Debug, Clone)]
pub struct UdpConfig {
    /// Human-readable name for this interface.
    pub name: String,
    /// Local address to bind the UDP socket to.
    pub bind_addr: SocketAddr,
    /// Target address for outgoing datagrams (`None` for receive-only).
    pub target_addr: Option<SocketAddr>,
    /// Whether to enable `SO_BROADCAST` on the socket.
    pub broadcast: bool,
    /// Interface operating mode.
    pub mode: InterfaceMode,
    /// Whether this interface can transmit packets.
    pub can_transmit: bool,
    /// Whether this interface can receive packets.
    pub can_receive: bool,
}

impl UdpConfig {
    /// Create a unicast UDP config (send and receive to a specific peer).
    pub fn unicast(
        name: impl Into<String>,
        bind_addr: SocketAddr,
        target_addr: SocketAddr,
    ) -> Self {
        Self {
            name: name.into(),
            bind_addr,
            target_addr: Some(target_addr),
            broadcast: false,
            mode: InterfaceMode::Full,
            can_transmit: true,
            can_receive: true,
        }
    }

    /// Create a broadcast UDP config.
    pub fn broadcast(
        name: impl Into<String>,
        bind_addr: SocketAddr,
        target_addr: SocketAddr,
    ) -> Self {
        Self {
            name: name.into(),
            bind_addr,
            target_addr: Some(target_addr),
            broadcast: true,
            mode: InterfaceMode::Full,
            can_transmit: true,
            can_receive: true,
        }
    }

    /// Create a receive-only UDP config (no target, no transmit).
    pub fn receive_only(name: impl Into<String>, bind_addr: SocketAddr) -> Self {
        Self {
            name: name.into(),
            bind_addr,
            target_addr: None,
            broadcast: false,
            mode: InterfaceMode::Full,
            can_transmit: false,
            can_receive: true,
        }
    }
}

// ---------------------------------------------------------------------------
// UdpInterface
// ---------------------------------------------------------------------------

/// A UDP network interface that sends and receives raw datagrams.
///
/// Each datagram is one complete packet — no framing or reassembly needed.
pub struct UdpInterface {
    config: UdpConfig,
    id: InterfaceId,
    socket: Mutex<Option<Arc<UdpSocket>>>,
    rx_receiver: Mutex<mpsc::Receiver<Vec<u8>>>,
    rx_sender: mpsc::Sender<Vec<u8>>,
    online: AtomicBool,
    stop_tx: watch::Sender<bool>,
    stop_rx: watch::Receiver<bool>,
    task_handle: Mutex<Option<JoinHandle<()>>>,
}

impl UdpInterface {
    /// Create a new UDP interface with the given configuration.
    pub fn new(config: UdpConfig, id: InterfaceId) -> Self {
        let (rx_sender, rx_receiver) = mpsc::channel(256);
        let (stop_tx, stop_rx) = watch::channel(false);

        Self {
            config,
            id,
            socket: Mutex::new(None),
            rx_receiver: Mutex::new(rx_receiver),
            rx_sender,
            online: AtomicBool::new(false),
            stop_tx,
            stop_rx,
            task_handle: Mutex::new(None),
        }
    }

    /// Run the receive loop: read datagrams and send them through the channel.
    async fn read_loop(
        socket: Arc<UdpSocket>,
        tx: mpsc::Sender<Vec<u8>>,
        mut stop_rx: watch::Receiver<bool>,
        name: String,
    ) {
        let mut buf = vec![0u8; UDP_RECV_BUFFER];

        loop {
            tokio::select! {
                result = socket.recv_from(&mut buf) => {
                    match result {
                        Ok((n, src)) => {
                            debug!("{}: received {} bytes from {}", name, n, src);
                            if tx.send(buf[..n].to_vec()).await.is_err() {
                                // Receiver dropped — stop
                                return;
                            }
                        }
                        Err(e) => {
                            warn!("{}: recv error: {}", name, e);
                            // UDP errors are typically transient; keep going
                            // unless we're stopping.
                            if *stop_rx.borrow() {
                                break;
                            }
                        }
                    }
                }
                _ = stop_rx.changed() => {
                    break;
                }
            }
        }
    }
}

impl Interface for UdpInterface {
    fn name(&self) -> &str {
        &self.config.name
    }

    fn id(&self) -> InterfaceId {
        self.id
    }

    fn mode(&self) -> InterfaceMode {
        self.config.mode
    }

    fn bitrate(&self) -> u64 {
        BITRATE_GUESS
    }

    fn mtu(&self) -> usize {
        UDP_HW_MTU
    }

    fn can_receive(&self) -> bool {
        self.config.can_receive
    }

    fn can_transmit(&self) -> bool {
        self.config.can_transmit
    }

    fn is_connected(&self) -> bool {
        self.online.load(Ordering::SeqCst)
    }

    async fn start(&mut self) -> Result<(), InterfaceError> {
        let socket = UdpSocket::bind(self.config.bind_addr).await?;

        if self.config.broadcast {
            socket.set_broadcast(true)?;
        }

        info!(
            "{}: bound to {}",
            self.config.name,
            socket.local_addr().unwrap_or(self.config.bind_addr)
        );

        let socket = Arc::new(socket);
        *self.socket.lock().await = Some(Arc::clone(&socket));
        self.online.store(true, Ordering::SeqCst);

        if self.config.can_receive {
            let sock = Arc::clone(&socket);
            let tx = self.rx_sender.clone();
            let stop_rx = self.stop_rx.clone();
            let name = self.config.name.clone();

            let handle = tokio::spawn(async move {
                Self::read_loop(sock, tx, stop_rx, name).await;
            });
            *self.task_handle.lock().await = Some(handle);
        }

        Ok(())
    }

    async fn stop(&mut self) -> Result<(), InterfaceError> {
        let _ = self.stop_tx.send(true);
        self.online.store(false, Ordering::SeqCst);

        // Clear the socket to unblock any pending recv
        *self.socket.lock().await = None;

        // Wait for the read loop to finish
        let handle = self.task_handle.lock().await.take();
        if let Some(h) = handle {
            let _ = h.await;
        }

        Ok(())
    }

    async fn transmit(&self, data: &[u8]) -> Result<(), InterfaceError> {
        if !self.online.load(Ordering::SeqCst) {
            return Err(InterfaceError::NotConnected);
        }

        if !self.config.can_transmit {
            return Err(InterfaceError::Configuration(
                "interface is receive-only".into(),
            ));
        }

        let target = self
            .config
            .target_addr
            .ok_or_else(|| InterfaceError::Configuration("no target address configured".into()))?;

        // Brief lock to clone the Arc — no I/O under the lock.
        let socket = {
            let guard = self.socket.lock().await;
            guard.as_ref().ok_or(InterfaceError::NotConnected)?.clone()
        };

        let sent = socket.send_to(data, target).await?;
        if sent != data.len() {
            return Err(InterfaceError::TransmitFailed(format!(
                "sent {} of {} bytes",
                sent,
                data.len()
            )));
        }

        Ok(())
    }

    async fn receive(&self) -> Result<Vec<u8>, InterfaceError> {
        let mut rx = self.rx_receiver.lock().await;
        rx.recv().await.ok_or(InterfaceError::Stopped)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unicast_roundtrip() {
        // Bind two interfaces on loopback with ephemeral ports.
        // We need to bind first to discover the assigned ports, then create
        // the configs pointing at each other.
        let sock_a = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let sock_b = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr_a = sock_a.local_addr().unwrap();
        let addr_b = sock_b.local_addr().unwrap();
        // Drop std sockets so tokio can rebind the same ports.
        drop(sock_a);
        drop(sock_b);

        let config_a = UdpConfig::unicast("udp-a", addr_a, addr_b);
        let config_b = UdpConfig::unicast("udp-b", addr_b, addr_a);

        let mut iface_a = UdpInterface::new(config_a, InterfaceId(10));
        let mut iface_b = UdpInterface::new(config_b, InterfaceId(11));

        iface_a.start().await.unwrap();
        iface_b.start().await.unwrap();

        // A sends to B
        let payload = vec![0xAB; 50];
        iface_a.transmit(&payload).await.unwrap();

        let received = tokio::time::timeout(std::time::Duration::from_secs(2), iface_b.receive())
            .await
            .expect("timed out waiting for packet")
            .unwrap();
        assert_eq!(received, payload);

        // B sends to A
        let reply = vec![0xCD; 30];
        iface_b.transmit(&reply).await.unwrap();

        let received = tokio::time::timeout(std::time::Duration::from_secs(2), iface_a.receive())
            .await
            .expect("timed out waiting for reply")
            .unwrap();
        assert_eq!(received, reply);

        iface_a.stop().await.unwrap();
        iface_b.stop().await.unwrap();
    }

    #[tokio::test]
    async fn transmit_when_not_started() {
        let config = UdpConfig::unicast(
            "udp-not-started",
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:9999".parse().unwrap(),
        );
        let iface = UdpInterface::new(config, InterfaceId(20));

        let result = iface.transmit(&[0x01; 20]).await;
        assert!(matches!(result, Err(InterfaceError::NotConnected)));
    }

    #[tokio::test]
    async fn receive_only_cannot_transmit() {
        let config = UdpConfig::receive_only("udp-rx-only", "127.0.0.1:0".parse().unwrap());
        let mut iface = UdpInterface::new(config, InterfaceId(30));
        iface.start().await.unwrap();

        let result = iface.transmit(&[0x01; 20]).await;
        assert!(matches!(result, Err(InterfaceError::Configuration(_))));

        iface.stop().await.unwrap();
    }

    #[tokio::test]
    async fn mtu_matches_python_reference() {
        let config = UdpConfig::receive_only("udp-mtu", "127.0.0.1:0".parse().unwrap());
        let iface = UdpInterface::new(config, InterfaceId(40));
        assert_eq!(iface.mtu(), 1064);
    }

    #[tokio::test]
    async fn start_stop_lifecycle() {
        let config = UdpConfig::receive_only("udp-lifecycle", "127.0.0.1:0".parse().unwrap());
        let mut iface = UdpInterface::new(config, InterfaceId(50));

        assert!(!iface.is_connected());

        iface.start().await.unwrap();
        assert!(iface.is_connected());

        iface.stop().await.unwrap();
        assert!(!iface.is_connected());
    }
}
