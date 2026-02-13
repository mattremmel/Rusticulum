//! Local (Unix domain socket) server interface that listens for connections
//! and spawns client interfaces.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use tokio::net::UnixListener;
use tokio::sync::{Mutex, watch};
use tracing::{debug, info, warn};

use reticulum_transport::path::{InterfaceId, InterfaceMode};

use super::client::LocalClientInterface;
use super::{BITRATE_GUESS, INITIAL_CONNECT_TIMEOUT, LocalClientConfig, LocalServerConfig};
use crate::error::InterfaceError;
use crate::traits::Interface;

/// A Unix domain socket server interface that accepts incoming connections and
/// spawns [`LocalClientInterface`] instances in responder mode for each one.
///
/// The server itself does not transmit or receive packets — spawned clients
/// handle all I/O. Use [`clients()`](Self::clients) to access them.
pub struct LocalServerInterface {
    config: LocalServerConfig,
    id: InterfaceId,
    /// Spawned responder clients.
    spawned_clients: Arc<Mutex<Vec<LocalClientInterface>>>,
    /// Counter for generating unique IDs for spawned clients.
    next_client_id: AtomicU64,
    /// Whether the accept loop is running.
    online: AtomicBool,
    /// Cancellation signal.
    stop_tx: watch::Sender<bool>,
    stop_rx: watch::Receiver<bool>,
    /// Accept loop task handle.
    task_handle: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl LocalServerInterface {
    pub fn new(config: LocalServerConfig, id: InterfaceId) -> Self {
        let (stop_tx, stop_rx) = watch::channel(false);

        Self {
            config,
            id,
            spawned_clients: Arc::new(Mutex::new(Vec::new())),
            next_client_id: AtomicU64::new(id.0.wrapping_mul(1000) + 1),
            online: AtomicBool::new(false),
            stop_tx,
            stop_rx,
            task_handle: Mutex::new(None),
        }
    }

    /// The socket path this server is listening on.
    pub fn socket_path(&self) -> &PathBuf {
        &self.config.socket_path
    }

    /// Number of currently tracked spawned clients.
    pub async fn client_count(&self) -> usize {
        let clients = self.spawned_clients.lock().await;
        clients.len()
    }

    /// Access the list of spawned client interfaces.
    pub async fn clients(&self) -> tokio::sync::MutexGuard<'_, Vec<LocalClientInterface>> {
        self.spawned_clients.lock().await
    }

    /// Handle stale socket file before binding.
    ///
    /// If a socket file already exists at the path:
    /// - Try to connect to it. If connection is refused (no process listening),
    ///   the file is stale and can be removed.
    /// - If connection succeeds, another server is already running — return an error.
    async fn handle_stale_socket(path: &PathBuf) -> Result<(), InterfaceError> {
        if !path.exists() {
            return Ok(());
        }

        // Try connecting via tokio to check if someone is listening
        match tokio::net::UnixStream::connect(path).await {
            Ok(_) => {
                // Another process is actively listening — cannot bind
                Err(InterfaceError::Configuration(format!(
                    "socket path {:?} is already in use by another process",
                    path
                )))
            }
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                // Stale socket file — safe to remove
                info!("removing stale socket file: {:?}", path);
                tokio::fs::remove_file(path)
                    .await
                    .map_err(InterfaceError::Io)?;
                Ok(())
            }
            Err(_) => {
                // Other error (e.g. permission denied, not a socket) — try removing
                info!("removing orphan socket file: {:?}", path);
                tokio::fs::remove_file(path)
                    .await
                    .map_err(InterfaceError::Io)?;
                Ok(())
            }
        }
    }

    /// Accept loop: listens for new connections and spawns responder clients.
    async fn accept_loop(
        listener: UnixListener,
        spawned: Arc<Mutex<Vec<LocalClientInterface>>>,
        next_id: Arc<AtomicU64>,
        mut stop_rx: watch::Receiver<bool>,
        server_config: LocalServerConfig,
    ) {
        loop {
            let stream = tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, _addr)) => {
                            let client_num = next_id.load(Ordering::SeqCst);
                            info!("{}: accepted local connection (client #{})",
                                  server_config.name, client_num);
                            stream
                        }
                        Err(e) => {
                            warn!("{}: accept error: {}", server_config.name, e);
                            continue;
                        }
                    }
                }
                _ = stop_rx.changed() => {
                    debug!("{}: accept loop stopping", server_config.name);
                    break;
                }
            };

            // Prune disconnected clients before adding new one
            {
                let mut clients = spawned.lock().await;
                clients.retain(|c| c.is_connected());
            }

            let client_id = next_id.fetch_add(1, Ordering::SeqCst);
            let client_config = LocalClientConfig {
                name: format!("Client on {}", server_config.name),
                socket_path: None,
                mode: server_config.mode,
                max_reconnect_tries: None,
                connect_timeout: INITIAL_CONNECT_TIMEOUT,
                can_transmit: server_config.client_can_transmit,
                can_receive: server_config.client_can_receive,
            };

            let client = match LocalClientInterface::from_connected(client_config, InterfaceId(client_id), stream) {
                Ok(c) => c,
                Err(e) => {
                    warn!("{}: failed to initialize client: {}", server_config.name, e);
                    continue;
                }
            };

            spawned.lock().await.push(client);
        }
    }
}

impl Interface for LocalServerInterface {
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
        false
    }

    fn can_transmit(&self) -> bool {
        false
    }

    fn is_connected(&self) -> bool {
        self.online.load(Ordering::SeqCst)
    }

    async fn start(&mut self) -> Result<(), InterfaceError> {
        // Handle stale socket file before binding
        Self::handle_stale_socket(&self.config.socket_path).await?;

        let listener = UnixListener::bind(&self.config.socket_path).map_err(InterfaceError::Io)?;

        info!(
            "{}: listening on {:?}",
            self.config.name, self.config.socket_path
        );
        self.online.store(true, Ordering::SeqCst);

        let spawned = Arc::clone(&self.spawned_clients);
        let next_id = Arc::new(AtomicU64::new(self.next_client_id.load(Ordering::SeqCst)));
        let stop_rx = self.stop_rx.clone();
        let server_config = self.config.clone();

        let handle = tokio::spawn(async move {
            Self::accept_loop(listener, spawned, next_id, stop_rx, server_config).await;
        });
        *self.task_handle.lock().await = Some(handle);

        Ok(())
    }

    async fn stop(&mut self) -> Result<(), InterfaceError> {
        let _ = self.stop_tx.send(true);
        self.online.store(false, Ordering::SeqCst);

        // Stop all spawned clients
        {
            let mut clients = self.spawned_clients.lock().await;
            for client in clients.iter_mut() {
                let _ = client.stop().await;
            }
            clients.clear();
        }

        // Wait for accept loop to finish
        let handle = self.task_handle.lock().await.take();
        if let Some(h) = handle {
            let _ = h.await;
        }

        // Clean up the socket file
        if let Err(e) = tokio::fs::remove_file(&self.config.socket_path).await {
            debug!(
                "{}: could not remove socket file {:?}: {}",
                self.config.name, self.config.socket_path, e
            );
        }

        Ok(())
    }

    async fn transmit(&self, _data: &[u8]) -> Result<(), InterfaceError> {
        Err(InterfaceError::Configuration(
            "server interface does not transmit directly; use spawned clients".into(),
        ))
    }

    async fn receive(&self) -> Result<Vec<u8>, InterfaceError> {
        Err(InterfaceError::Configuration(
            "server interface does not receive directly; use spawned clients".into(),
        ))
    }
}

impl Drop for LocalServerInterface {
    fn drop(&mut self) {
        // Best-effort cleanup of socket file
        let _ = std::fs::remove_file(&self.config.socket_path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UnixStream;

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
    async fn server_spawns_clients() {
        let path = test_socket_path("srv_spawn");
        let _cleanup = SocketCleanup(path.clone());
        let _ = std::fs::remove_file(&path);

        let config = LocalServerConfig::new("test-local-server", path.clone());
        let mut server = LocalServerInterface::new(config, InterfaceId(100));
        server.start().await.unwrap();

        // Connect two raw Unix streams
        let _c1 = UnixStream::connect(&path).await.unwrap();
        let _c2 = UnixStream::connect(&path).await.unwrap();

        // Wait for the server to accept both
        for _ in 0..50 {
            if server.client_count().await >= 2 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert_eq!(server.client_count().await, 2);

        server.stop().await.unwrap();
    }

    #[tokio::test]
    async fn server_client_roundtrip() {
        let path = test_socket_path("srv_roundtrip");
        let _cleanup = SocketCleanup(path.clone());
        let _ = std::fs::remove_file(&path);

        let config = LocalServerConfig::new("test-local-server-rt", path.clone());
        let mut server = LocalServerInterface::new(config, InterfaceId(200));
        server.start().await.unwrap();

        // Create an initiator client pointing at the server
        let client_config = LocalClientConfig::initiator("test-local-client-rt", path.clone());
        let mut client = LocalClientInterface::new(client_config, InterfaceId(201)).unwrap();
        client.start().await.unwrap();

        // Wait for connection
        for _ in 0..50 {
            if client.is_connected() && server.client_count().await >= 1 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert!(client.is_connected());
        assert!(server.client_count().await >= 1);

        // Client transmits → server's spawned client receives
        let payload = vec![0xBE; 20];
        client.transmit(&payload).await.unwrap();

        let clients = server.clients().await;
        let received =
            tokio::time::timeout(std::time::Duration::from_secs(2), clients[0].receive())
                .await
                .expect("timeout")
                .unwrap();
        drop(clients);

        assert_eq!(received, payload);

        // Server's spawned client transmits → initiator client receives
        let return_payload = vec![0xEF; 25];
        {
            let clients = server.clients().await;
            clients[0].transmit(&return_payload).await.unwrap();
        }

        let received = tokio::time::timeout(std::time::Duration::from_secs(2), client.receive())
            .await
            .expect("timeout")
            .unwrap();
        assert_eq!(received, return_payload);

        client.stop().await.unwrap();
        server.stop().await.unwrap();
    }

    #[tokio::test]
    async fn server_cleans_up_socket() {
        let path = test_socket_path("srv_cleanup");
        let _cleanup = SocketCleanup(path.clone());
        let _ = std::fs::remove_file(&path);

        let config = LocalServerConfig::new("test-cleanup", path.clone());
        let mut server = LocalServerInterface::new(config, InterfaceId(300));
        server.start().await.unwrap();

        // Socket file should exist while server is running
        assert!(path.exists());

        server.stop().await.unwrap();

        // Socket file should be cleaned up after stop
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn server_removes_stale_socket() {
        let path = test_socket_path("srv_stale");
        let _cleanup = SocketCleanup(path.clone());

        // Create an orphan socket file (not backed by a listener)
        let _ = std::fs::remove_file(&path);
        // Bind and immediately drop to create a stale socket file
        {
            let _listener = UnixListener::bind(&path).unwrap();
        }
        // Listener is dropped but file remains
        assert!(path.exists());

        // Server should detect the stale socket file and remove it before binding
        let config = LocalServerConfig::new("test-stale", path.clone());
        let mut server = LocalServerInterface::new(config, InterfaceId(400));
        server.start().await.unwrap();

        assert!(server.is_connected());

        server.stop().await.unwrap();
    }
}
