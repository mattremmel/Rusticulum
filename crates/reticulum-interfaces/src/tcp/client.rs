//! TCP client interface with HDLC framing and automatic reconnection.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::net::tcp::OwnedWriteHalf;
use tokio::sync::{Mutex, mpsc, watch};
use tracing::{debug, info, warn};

use reticulum_core::framing::hdlc::hdlc_frame;
use reticulum_transport::path::{InterfaceId, InterfaceMode};

use super::framing::HdlcFrameAccumulator;
use super::{BITRATE_GUESS, RECONNECT_WAIT, TCP_RECV_BUFFER, TcpClientConfig};
use crate::error::InterfaceError;
use crate::shutdown::ShutdownToken;
use crate::traits::Interface;

/// Whether this client initiates connections or was spawned by a server.
#[derive(Debug, Clone)]
pub enum TcpClientRole {
    /// Client that connects to a remote address/hostname and auto-reconnects.
    Initiator { target: String },
    /// Client spawned by a server from an accepted connection (no reconnect).
    Responder,
}

/// Shared interior state for the TCP client.
struct TcpClientInner {
    /// Write half of the TCP stream (None when disconnected).
    writer: Mutex<Option<OwnedWriteHalf>>,
    /// Background read task sends complete frames through this channel.
    rx_sender: mpsc::Sender<Vec<u8>>,
    /// Whether the TCP connection is currently active.
    connected: AtomicBool,
    /// Shared shutdown token for cancellation signaling.
    shutdown: ShutdownToken,
}

/// A TCP client interface that frames packets with HDLC over a TCP stream.
///
/// Operates in two roles:
/// - **Initiator**: connects to a target address, auto-reconnects on disconnect.
/// - **Responder**: spawned by [`TcpServerInterface`] with a pre-connected socket.
pub struct TcpClientInterface {
    config: TcpClientConfig,
    id: InterfaceId,
    role: TcpClientRole,
    inner: Arc<TcpClientInner>,
    rx_receiver: Mutex<mpsc::Receiver<Vec<u8>>>,
    task_handle: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl TcpClientInterface {
    /// Create an initiator client that will connect to `config.target_addr`.
    pub fn new(config: TcpClientConfig, id: InterfaceId) -> Result<Self, InterfaceError> {
        let target = config.target_addr.clone().ok_or_else(|| {
            InterfaceError::Configuration("initiator config must have target_addr".into())
        })?;
        let role = TcpClientRole::Initiator { target };
        Ok(Self::build(config, id, role))
    }

    /// Create a responder client from an already-connected TCP stream.
    ///
    /// Immediately spawns the read loop — no need to call `start()`.
    pub fn from_connected(
        config: TcpClientConfig,
        id: InterfaceId,
        stream: TcpStream,
    ) -> Result<Self, InterfaceError> {
        let role = TcpClientRole::Responder;
        let iface = Self::build(config, id, role);

        // Set up the connected stream
        let _ = stream.set_nodelay(true);
        let (reader, writer) = stream.into_split();

        {
            // We can't await here but we need to set the writer synchronously.
            // Since the Mutex is uncontested, try_lock will succeed.
            let mut guard = iface.inner.writer.try_lock().map_err(|_| {
                InterfaceError::Configuration("writer lock contended during init".into())
            })?;
            *guard = Some(writer);
        }
        iface.inner.connected.store(true, Ordering::SeqCst);

        // Spawn the read loop immediately
        let inner = Arc::clone(&iface.inner);
        let stop_rx = iface.inner.shutdown.subscribe();
        let name = iface.config.name.clone();
        let handle = tokio::spawn(async move {
            Self::read_loop(inner, reader, stop_rx, &name).await;
        });
        {
            let mut guard = iface.task_handle.try_lock().map_err(|_| {
                InterfaceError::Configuration("task_handle lock contended during init".into())
            })?;
            *guard = Some(handle);
        }

        Ok(iface)
    }

    fn build(config: TcpClientConfig, id: InterfaceId, role: TcpClientRole) -> Self {
        let (tx, rx) = mpsc::channel(256);

        let inner = Arc::new(TcpClientInner {
            writer: Mutex::new(None),
            rx_sender: tx,
            connected: AtomicBool::new(false),
            shutdown: ShutdownToken::new(),
        });

        Self {
            config,
            id,
            role,
            inner,
            rx_receiver: Mutex::new(rx),
            task_handle: Mutex::new(None),
        }
    }

    /// Run the initiator's connect-and-reconnect loop.
    async fn connect_and_run(
        inner: Arc<TcpClientInner>,
        target: String,
        connect_timeout: std::time::Duration,
        max_reconnect_tries: Option<u32>,
        mut stop_rx: watch::Receiver<bool>,
        name: String,
    ) {
        let mut attempts: u32 = 0;

        loop {
            if *stop_rx.borrow() {
                break;
            }

            // Try to connect
            let stream =
                match tokio::time::timeout(connect_timeout, TcpStream::connect(&*target)).await {
                    Ok(Ok(stream)) => {
                        let _ = stream.set_nodelay(true);
                        info!("{}: connected to {}", name, target);
                        attempts = 0;
                        stream
                    }
                    Ok(Err(e)) => {
                        debug!("{}: connection failed: {}", name, e);
                        attempts += 1;
                        if let Some(max) = max_reconnect_tries
                            && attempts > max
                        {
                            warn!("{}: max reconnect attempts ({}) reached", name, max);
                            break;
                        }
                        // Wait before retrying, but break early on stop
                        tokio::select! {
                            _ = tokio::time::sleep(RECONNECT_WAIT) => {}
                            _ = stop_rx.changed() => { break; }
                        }
                        continue;
                    }
                    Err(_) => {
                        debug!("{}: connection timed out", name);
                        attempts += 1;
                        if let Some(max) = max_reconnect_tries
                            && attempts > max
                        {
                            warn!("{}: max reconnect attempts ({}) reached", name, max);
                            break;
                        }
                        tokio::select! {
                            _ = tokio::time::sleep(RECONNECT_WAIT) => {}
                            _ = stop_rx.changed() => { break; }
                        }
                        continue;
                    }
                };

            let (reader, writer) = stream.into_split();
            {
                let mut guard = inner.writer.lock().await;
                *guard = Some(writer);
            }
            inner.connected.store(true, Ordering::SeqCst);

            // Run read loop until disconnect
            Self::read_loop(Arc::clone(&inner), reader, stop_rx.clone(), &name).await;

            // Disconnected — clean up writer
            {
                let mut guard = inner.writer.lock().await;
                *guard = None;
            }
            inner.connected.store(false, Ordering::SeqCst);

            if *stop_rx.borrow() {
                break;
            }

            info!(
                "{}: disconnected, will reconnect in {:?}",
                name, RECONNECT_WAIT
            );
            tokio::select! {
                _ = tokio::time::sleep(RECONNECT_WAIT) => {}
                _ = stop_rx.changed() => { break; }
            }
        }
    }

    /// Read bytes from the TCP stream, extract HDLC frames, send through channel.
    async fn read_loop(
        inner: Arc<TcpClientInner>,
        mut reader: tokio::net::tcp::OwnedReadHalf,
        mut stop_rx: watch::Receiver<bool>,
        name: &str,
    ) {
        let mut acc = HdlcFrameAccumulator::new();
        let mut buf = vec![0u8; TCP_RECV_BUFFER];

        loop {
            let n = tokio::select! {
                result = reader.read(&mut buf) => {
                    match result {
                        Ok(0) => {
                            debug!("{}: socket closed (EOF)", name);
                            break;
                        }
                        Ok(n) => n,
                        Err(e) => {
                            debug!("{}: read error: {}", name, e);
                            break;
                        }
                    }
                }
                _ = stop_rx.changed() => {
                    break;
                }
            };

            for frame in acc.feed(&buf[..n]) {
                if inner.rx_sender.send(frame).await.is_err() {
                    // Receiver dropped — stop
                    return;
                }
            }
        }

        inner.connected.store(false, Ordering::SeqCst);
    }
}

impl Interface for TcpClientInterface {
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

    fn can_receive(&self) -> bool {
        self.config.can_receive
    }

    fn can_transmit(&self) -> bool {
        self.config.can_transmit
    }

    fn is_connected(&self) -> bool {
        self.inner.connected.load(Ordering::SeqCst)
    }

    async fn start(&self) -> Result<(), InterfaceError> {
        match &self.role {
            TcpClientRole::Initiator { target } => {
                let inner = Arc::clone(&self.inner);
                let target = target.clone();
                let timeout = self.config.connect_timeout;
                let max_tries = self.config.max_reconnect_tries;
                let stop_rx = self.inner.shutdown.subscribe();
                let name = self.config.name.clone();

                let handle = tokio::spawn(async move {
                    Self::connect_and_run(inner, target, timeout, max_tries, stop_rx, name).await;
                });
                *self.task_handle.lock().await = Some(handle);
                Ok(())
            }
            TcpClientRole::Responder => {
                // Responder is already running from `from_connected`
                Ok(())
            }
        }
    }

    async fn stop(&self) -> Result<(), InterfaceError> {
        // Signal background tasks to stop
        self.inner.shutdown.signal_stop();

        // Shut down the writer to force read side to see EOF
        {
            let mut guard = self.inner.writer.lock().await;
            if let Some(mut writer) = guard.take() {
                let _ = writer.shutdown().await;
            }
        }
        self.inner.connected.store(false, Ordering::SeqCst);

        // Wait for background task to finish
        let handle = self.task_handle.lock().await.take();
        if let Some(h) = handle {
            let _ = h.await;
        }

        Ok(())
    }

    async fn transmit(&self, data: &[u8]) -> Result<(), InterfaceError> {
        if !self.inner.connected.load(Ordering::SeqCst) {
            return Err(InterfaceError::NotConnected);
        }

        let framed = hdlc_frame(data);
        let mut guard = self.inner.writer.lock().await;
        match guard.as_mut() {
            Some(writer) => writer.write_all(&framed).await.map_err(InterfaceError::Io),
            None => Err(InterfaceError::NotConnected),
        }
    }

    async fn receive(&self) -> Result<Vec<u8>, InterfaceError> {
        let mut rx = self.rx_receiver.lock().await;
        rx.recv().await.ok_or(InterfaceError::Stopped)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn client_server_roundtrip() {
        // Bind a raw TCP listener to simulate a peer
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Create an initiator client
        let config = TcpClientConfig::initiator("test-client", addr.to_string());
        let client = TcpClientInterface::new(config, InterfaceId(1)).unwrap();
        client.start().await.unwrap();

        // Accept the connection on the listener side
        let (mut peer_stream, _) = listener.accept().await.unwrap();

        // Wait for client to be connected
        for _ in 0..50 {
            if client.is_connected() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert!(client.is_connected());

        // Client transmits → peer reads an HDLC frame
        let payload = vec![0x42; 20];
        client.transmit(&payload).await.unwrap();

        let mut buf = vec![0u8; 256];
        let n = peer_stream.read(&mut buf).await.unwrap();
        let expected_frame = hdlc_frame(&payload);
        assert_eq!(&buf[..n], &expected_frame[..]);

        // Peer sends an HDLC frame → client receives unframed payload
        let return_payload = vec![0x55; 25];
        let return_frame = hdlc_frame(&return_payload);
        peer_stream.write_all(&return_frame).await.unwrap();

        let received = client.receive().await.unwrap();
        assert_eq!(received, return_payload);

        client.stop().await.unwrap();
    }

    #[tokio::test]
    async fn transmit_when_disconnected() {
        let config = TcpClientConfig::initiator(
            "test-disconnected",
            "127.0.0.1:1", // will not connect
        );
        let client = TcpClientInterface::new(config, InterfaceId(99)).unwrap();
        // Don't start — not connected
        let result = client.transmit(&[0x01; 20]).await;
        assert!(matches!(result, Err(InterfaceError::NotConnected)));
    }

    #[tokio::test]
    async fn client_connects_via_hostname() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        // Use "localhost" hostname instead of raw IP
        let target = format!("localhost:{port}");
        let config = TcpClientConfig::initiator("test-hostname", target);
        let client = TcpClientInterface::new(config, InterfaceId(10)).unwrap();
        client.start().await.unwrap();

        // Accept the connection
        let (mut peer_stream, _) = listener.accept().await.unwrap();

        // Wait for connected
        for _ in 0..50 {
            if client.is_connected() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert!(client.is_connected());

        // Client → peer
        let payload = vec![0x42; 20];
        client.transmit(&payload).await.unwrap();

        let mut buf = vec![0u8; 256];
        let n = peer_stream.read(&mut buf).await.unwrap();
        let expected_frame = hdlc_frame(&payload);
        assert_eq!(&buf[..n], &expected_frame[..]);

        // Peer → client
        let return_payload = vec![0x55; 25];
        let return_frame = hdlc_frame(&return_payload);
        peer_stream.write_all(&return_frame).await.unwrap();

        let received = client.receive().await.unwrap();
        assert_eq!(received, return_payload);

        client.stop().await.unwrap();
    }

    #[tokio::test]
    async fn reconnection_after_disconnect() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let config = TcpClientConfig::initiator("test-reconnect", addr.to_string());
        let client = TcpClientInterface::new(config, InterfaceId(2)).unwrap();
        client.start().await.unwrap();

        // Accept first connection
        let (peer1, _) = listener.accept().await.unwrap();
        for _ in 0..50 {
            if client.is_connected() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert!(client.is_connected());

        // Drop peer → triggers disconnect + reconnect
        drop(peer1);

        // Wait for disconnect
        for _ in 0..50 {
            if !client.is_connected() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }

        // Accept the reconnection
        let (_peer2, _) =
            tokio::time::timeout(std::time::Duration::from_secs(10), listener.accept())
                .await
                .expect("timed out waiting for reconnect")
                .unwrap();

        // Wait for connected again
        for _ in 0..100 {
            if client.is_connected() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        assert!(client.is_connected());

        client.stop().await.unwrap();
    }
}
