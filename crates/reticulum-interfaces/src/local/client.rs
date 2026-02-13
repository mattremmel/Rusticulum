//! Local (Unix domain socket) client interface with HDLC framing and automatic reconnection.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::net::unix::OwnedWriteHalf;
use tokio::sync::{Mutex, mpsc, watch};
use tracing::{debug, info, warn};

use reticulum_core::framing::hdlc::hdlc_frame;
use reticulum_transport::path::{InterfaceId, InterfaceMode};

use super::{BITRATE_GUESS, LOCAL_MTU, LOCAL_RECV_BUFFER, LocalClientConfig, RECONNECT_WAIT};
use crate::error::InterfaceError;
use crate::framing::HdlcFrameAccumulator;
use crate::traits::Interface;

/// Whether this client initiates connections or was spawned by a server.
#[derive(Debug, Clone)]
pub enum LocalClientRole {
    /// Client that connects to a socket path and auto-reconnects.
    Initiator { socket_path: PathBuf },
    /// Client spawned by a server from an accepted connection (no reconnect).
    Responder,
}

/// Shared interior state for the local client.
struct LocalClientInner {
    /// Write half of the Unix stream (None when disconnected).
    writer: Mutex<Option<OwnedWriteHalf>>,
    /// Background read task sends complete frames through this channel.
    rx_sender: mpsc::Sender<Vec<u8>>,
    /// Whether the Unix connection is currently active.
    connected: AtomicBool,
    /// Cancellation signal for background tasks.
    stop_tx: watch::Sender<bool>,
}

/// A Unix domain socket client interface that frames packets with HDLC.
///
/// Operates in two roles:
/// - **Initiator**: connects to a socket path, auto-reconnects on disconnect.
/// - **Responder**: spawned by [`LocalServerInterface`] with a pre-connected socket.
pub struct LocalClientInterface {
    config: LocalClientConfig,
    id: InterfaceId,
    role: LocalClientRole,
    inner: Arc<LocalClientInner>,
    rx_receiver: Mutex<mpsc::Receiver<Vec<u8>>>,
    stop_rx: watch::Receiver<bool>,
    task_handle: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl LocalClientInterface {
    /// Create an initiator client that will connect to `config.socket_path`.
    pub fn new(config: LocalClientConfig, id: InterfaceId) -> Self {
        let socket_path = config
            .socket_path
            .clone()
            .expect("initiator config must have socket_path");
        let role = LocalClientRole::Initiator { socket_path };
        Self::build(config, id, role)
    }

    /// Create a responder client from an already-connected Unix stream.
    ///
    /// Immediately spawns the read loop — no need to call `start()`.
    pub fn from_connected(config: LocalClientConfig, id: InterfaceId, stream: UnixStream) -> Self {
        let role = LocalClientRole::Responder;
        let iface = Self::build(config, id, role);

        let (reader, writer) = stream.into_split();

        {
            let mut guard = iface.inner.writer.try_lock().unwrap();
            *guard = Some(writer);
        }
        iface.inner.connected.store(true, Ordering::SeqCst);

        // Spawn the read loop immediately
        let inner = Arc::clone(&iface.inner);
        let stop_rx = iface.stop_rx.clone();
        let name = iface.config.name.clone();
        let handle = tokio::spawn(async move {
            Self::read_loop(inner, reader, stop_rx, &name).await;
        });
        *iface.task_handle.try_lock().unwrap() = Some(handle);

        iface
    }

    fn build(config: LocalClientConfig, id: InterfaceId, role: LocalClientRole) -> Self {
        let (tx, rx) = mpsc::channel(256);
        let (stop_tx, stop_rx) = watch::channel(false);

        let inner = Arc::new(LocalClientInner {
            writer: Mutex::new(None),
            rx_sender: tx,
            connected: AtomicBool::new(false),
            stop_tx,
        });

        Self {
            config,
            id,
            role,
            inner,
            rx_receiver: Mutex::new(rx),
            stop_rx,
            task_handle: Mutex::new(None),
        }
    }

    /// Run the initiator's connect-and-reconnect loop.
    async fn connect_and_run(
        inner: Arc<LocalClientInner>,
        socket_path: PathBuf,
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
            let stream = match tokio::time::timeout(
                connect_timeout,
                UnixStream::connect(&socket_path),
            )
            .await
            {
                Ok(Ok(stream)) => {
                    info!("{}: connected to {:?}", name, socket_path);
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

    /// Read bytes from the Unix stream, extract HDLC frames, send through channel.
    async fn read_loop(
        inner: Arc<LocalClientInner>,
        mut reader: tokio::net::unix::OwnedReadHalf,
        mut stop_rx: watch::Receiver<bool>,
        name: &str,
    ) {
        let mut acc = HdlcFrameAccumulator::new();
        let mut buf = vec![0u8; LOCAL_RECV_BUFFER];

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

impl Interface for LocalClientInterface {
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
        LOCAL_MTU
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

    async fn start(&mut self) -> Result<(), InterfaceError> {
        match &self.role {
            LocalClientRole::Initiator { socket_path } => {
                let inner = Arc::clone(&self.inner);
                let path = socket_path.clone();
                let timeout = self.config.connect_timeout;
                let max_tries = self.config.max_reconnect_tries;
                let stop_rx = self.stop_rx.clone();
                let name = self.config.name.clone();

                let handle = tokio::spawn(async move {
                    Self::connect_and_run(inner, path, timeout, max_tries, stop_rx, name).await;
                });
                *self.task_handle.lock().await = Some(handle);
                Ok(())
            }
            LocalClientRole::Responder => {
                // Responder is already running from `from_connected`
                Ok(())
            }
        }
    }

    async fn stop(&mut self) -> Result<(), InterfaceError> {
        // Signal background tasks to stop
        let _ = self.inner.stop_tx.send(true);

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
    use tokio::net::UnixListener;

    /// Generate a unique socket path for testing.
    fn test_socket_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("rns_test_{}_{}.sock", name, std::process::id()))
    }

    /// Guard that removes the socket file on drop.
    struct SocketCleanup(PathBuf);
    impl Drop for SocketCleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    #[tokio::test]
    async fn client_server_roundtrip() {
        let path = test_socket_path("client_roundtrip");
        let _cleanup = SocketCleanup(path.clone());
        let _ = std::fs::remove_file(&path);

        // Bind a raw Unix listener to simulate a peer
        let listener = UnixListener::bind(&path).unwrap();

        // Create an initiator client
        let config = LocalClientConfig::initiator("test-local-client", path.clone());
        let mut client = LocalClientInterface::new(config, InterfaceId(1));
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
        let path = test_socket_path("disconnected");
        let config = LocalClientConfig::initiator("test-disconnected", path);
        let client = LocalClientInterface::new(config, InterfaceId(99));
        // Don't start — not connected
        let result = client.transmit(&[0x01; 20]).await;
        assert!(matches!(result, Err(InterfaceError::NotConnected)));
    }

    #[tokio::test]
    async fn reconnection_after_disconnect() {
        let path = test_socket_path("reconnect");
        let _cleanup = SocketCleanup(path.clone());
        let _ = std::fs::remove_file(&path);

        let listener = UnixListener::bind(&path).unwrap();

        let config = LocalClientConfig::initiator("test-reconnect", path.clone());
        let mut client = LocalClientInterface::new(config, InterfaceId(2));
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
            tokio::time::timeout(std::time::Duration::from_secs(15), listener.accept())
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
