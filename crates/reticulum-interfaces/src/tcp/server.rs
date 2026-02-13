//! TCP server interface that listens for connections and spawns client interfaces.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::net::TcpListener;
use tokio::sync::{Mutex, watch};
use tracing::{debug, info, warn};

use reticulum_transport::path::{InterfaceId, InterfaceMode};

use super::client::TcpClientInterface;
use super::{BITRATE_GUESS, TcpClientConfig, TcpServerConfig};
use crate::error::InterfaceError;
use crate::shutdown::ShutdownToken;
use crate::traits::Interface;

/// A TCP server interface that accepts incoming connections and spawns
/// [`TcpClientInterface`] instances in responder mode for each one.
///
/// The server itself does not transmit or receive packets — spawned clients
/// handle all I/O. Use [`clients()`](Self::clients) to access them.
pub struct TcpServerInterface {
    config: TcpServerConfig,
    id: InterfaceId,
    /// Bound local address (available after `start()`).
    local_addr: Mutex<Option<SocketAddr>>,
    /// Spawned responder clients.
    spawned_clients: Arc<Mutex<Vec<TcpClientInterface>>>,
    /// Counter for generating unique IDs for spawned clients.
    next_client_id: AtomicU64,
    /// Shared shutdown token for online state, stop signaling, and task tracking.
    shutdown: ShutdownToken,
}

impl TcpServerInterface {
    pub fn new(config: TcpServerConfig, id: InterfaceId) -> Self {
        Self {
            config,
            id,
            local_addr: Mutex::new(None),
            spawned_clients: Arc::new(Mutex::new(Vec::new())),
            next_client_id: AtomicU64::new(id.0.wrapping_mul(1000) + 1),
            shutdown: ShutdownToken::new(),
        }
    }

    /// The local address the server is listening on. Available after `start()`.
    pub async fn local_addr(&self) -> Option<SocketAddr> {
        *self.local_addr.lock().await
    }

    /// Number of currently tracked spawned clients.
    pub async fn client_count(&self) -> usize {
        let clients = self.spawned_clients.lock().await;
        clients.len()
    }

    /// Access the list of spawned client interfaces.
    pub async fn clients(&self) -> tokio::sync::MutexGuard<'_, Vec<TcpClientInterface>> {
        self.spawned_clients.lock().await
    }

    /// Accept loop: listens for new connections and spawns responder clients.
    async fn accept_loop(
        listener: TcpListener,
        spawned: Arc<Mutex<Vec<TcpClientInterface>>>,
        next_id: Arc<AtomicU64>,
        mut stop_rx: watch::Receiver<bool>,
        server_config: TcpServerConfig,
    ) {
        loop {
            let stream = tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, peer_addr)) => {
                            info!("{}: accepted connection from {}", server_config.name, peer_addr);
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
            let client_config = TcpClientConfig {
                name: format!("Client on {}", server_config.name),
                target_addr: None,
                mode: server_config.mode,
                max_reconnect_tries: None,
                connect_timeout: super::INITIAL_CONNECT_TIMEOUT,
                can_transmit: server_config.client_can_transmit,
                can_receive: server_config.client_can_receive,
            };

            let client = match TcpClientInterface::from_connected(
                client_config,
                InterfaceId(client_id),
                stream,
            ) {
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

impl Interface for TcpServerInterface {
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
        self.shutdown.is_online()
    }

    async fn start(&self) -> Result<(), InterfaceError> {
        let listener = TcpListener::bind(self.config.bind_addr)
            .await
            .map_err(InterfaceError::Io)?;

        let addr = listener.local_addr().map_err(InterfaceError::Io)?;
        info!("{}: listening on {}", self.config.name, addr);
        *self.local_addr.lock().await = Some(addr);
        self.shutdown.set_online();

        let spawned = Arc::clone(&self.spawned_clients);
        let next_id = Arc::new(AtomicU64::new(self.next_client_id.load(Ordering::SeqCst)));
        let stop_rx = self.shutdown.subscribe();
        let server_config = self.config.clone();

        let handle = tokio::spawn(async move {
            Self::accept_loop(listener, spawned, next_id, stop_rx, server_config).await;
        });
        self.shutdown.set_task(handle).await;

        Ok(())
    }

    async fn stop(&self) -> Result<(), InterfaceError> {
        self.shutdown.signal_stop_and_go_offline();

        // Stop all spawned clients
        {
            let mut clients = self.spawned_clients.lock().await;
            for client in clients.iter() {
                let _ = client.stop().await;
            }
            clients.clear();
        }

        // Wait for accept loop to finish
        self.shutdown.join_all().await;

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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpStream;

    #[tokio::test]
    async fn server_spawns_clients() {
        let config = TcpServerConfig::new("test-server", "127.0.0.1:0".parse().unwrap());
        let server = TcpServerInterface::new(config, InterfaceId(100));
        server.start().await.unwrap();

        let addr = server.local_addr().await.unwrap();

        // Connect two raw TCP streams
        let _c1 = TcpStream::connect(addr).await.unwrap();
        let _c2 = TcpStream::connect(addr).await.unwrap();

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
        let config = TcpServerConfig::new("test-server-rt", "127.0.0.1:0".parse().unwrap());
        let server = TcpServerInterface::new(config, InterfaceId(200));
        server.start().await.unwrap();

        let addr = server.local_addr().await.unwrap();

        // Create an initiator client pointing at the server
        let client_config = TcpClientConfig::initiator("test-client-rt", addr);
        let client = TcpClientInterface::new(client_config, InterfaceId(201)).unwrap();
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
}
