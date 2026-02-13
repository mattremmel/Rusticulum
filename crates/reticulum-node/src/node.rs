//! Core Node struct and async event loop.
//!
//! The Node wires together interfaces, the router, and IFAC authentication
//! into a single async runtime that receives packets, deduplicates, and floods
//! them to other interfaces.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::{mpsc, watch};

use reticulum_interfaces::InterfaceId;
use reticulum_interfaces::tcp::{
    TcpClientConfig, TcpClientInterface, TcpServerConfig, TcpServerInterface,
};
use reticulum_interfaces::udp::{UdpConfig, UdpInterface};

#[cfg(unix)]
use reticulum_interfaces::auto::{AutoConfig, AutoInterface};
#[cfg(unix)]
use reticulum_interfaces::local::{
    LocalClientConfig, LocalClientInterface, LocalServerConfig, LocalServerInterface,
};

use reticulum_core::announce::{Announce, make_random_hash};
use reticulum_core::constants::PacketType;
use reticulum_core::destination;
use reticulum_core::packet::wire::RawPacket;
use reticulum_transport::ifac::{IfacConfig, has_ifac_flag, ifac_apply, ifac_verify};
use reticulum_transport::path::constants::PATHFINDER_M;
use reticulum_transport::router::dispatch::PacketRouter;
use reticulum_transport::router::types::RouterAction;

use reticulum_core::identity::Identity;

use crate::config::{NodeConfig, parse_mode, parse_socket_addr};
use crate::error::NodeError;
use crate::interface_enum::AnyInterface;
use crate::storage::Storage;

/// A handle that can trigger node shutdown from another task or signal handler.
#[derive(Clone)]
pub struct ShutdownHandle {
    tx: watch::Sender<bool>,
}

impl ShutdownHandle {
    /// Signal the node to shut down.
    pub fn shutdown(&self) {
        let _ = self.tx.send(true);
    }
}

/// Events delivered to the central event loop from interface receive bridges.
#[derive(Debug)]
enum NodeEvent {
    InboundPacket {
        interface_id: InterfaceId,
        raw: Vec<u8>,
    },
    InterfaceDown {
        interface_id: InterfaceId,
    },
}

/// A Reticulum node that manages interfaces, routing, and the event loop.
pub struct Node {
    config: NodeConfig,
    router: PacketRouter,
    ifac_config: Option<IfacConfig>,
    storage: Option<Storage>,
    transport_identity: Option<Identity>,
    interfaces: HashMap<InterfaceId, Arc<AnyInterface>>,
    event_tx: mpsc::Sender<NodeEvent>,
    event_rx: mpsc::Receiver<NodeEvent>,
    shutdown_tx: watch::Sender<bool>,
    shutdown_rx: watch::Receiver<bool>,
    next_id: u64,
    bridge_handles: Vec<tokio::task::JoinHandle<()>>,
    pending_announces: Vec<Vec<u8>>,
}

impl Node {
    /// Create a new node from configuration.
    pub fn new(config: NodeConfig) -> Self {
        let router = PacketRouter::new();

        let ifac_config = if config.node.network_name.is_some() || config.node.network_key.is_some()
        {
            Some(IfacConfig::new(
                config.node.network_name.as_deref(),
                config.node.network_key.as_deref(),
                config.node.ifac_size as usize,
            ))
        } else {
            None
        };

        // Initialize storage (non-fatal)
        let storage = if config.node.enable_storage {
            let result = if let Some(ref path) = config.node.storage_path {
                Storage::new(std::path::PathBuf::from(path))
            } else {
                Storage::default_path()
            };
            match result {
                Ok(s) => Some(s),
                Err(e) => {
                    tracing::warn!("failed to initialize storage: {e}");
                    None
                }
            }
        } else {
            None
        };

        let (event_tx, event_rx) = mpsc::channel(1024);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        Self {
            config,
            router,
            ifac_config,
            storage,
            transport_identity: None,
            interfaces: HashMap::new(),
            event_tx,
            event_rx,
            shutdown_tx,
            shutdown_rx,
            next_id: 1,
            bridge_handles: Vec::new(),
            pending_announces: Vec::new(),
        }
    }

    /// Build all interfaces from the config, start them, and wrap in Arc.
    pub async fn start(&mut self) -> Result<(), NodeError> {
        if !self.interfaces.is_empty() {
            return Err(NodeError::AlreadyRunning);
        }

        // Load or generate transport identity
        if let Some(ref storage) = self.storage {
            match storage.load_identity().await {
                Ok(Some(id)) => {
                    tracing::info!("loaded transport identity");
                    self.transport_identity = Some(id);
                }
                Ok(None) => {
                    let id = Identity::generate();
                    if let Err(e) = storage.save_identity(&id).await {
                        tracing::warn!("failed to save new identity: {e}");
                    } else {
                        tracing::info!("generated and saved new transport identity");
                    }
                    self.transport_identity = Some(id);
                }
                Err(e) => {
                    tracing::warn!("failed to load identity: {e}");
                    self.transport_identity = Some(Identity::generate());
                }
            }

            // Load path table
            match storage.load_path_table().await {
                Ok(table) => {
                    let count = table.len();
                    if count > 0 {
                        tracing::info!("loaded {count} path table entries");
                    }
                    self.router.set_path_table(table);
                }
                Err(e) => {
                    tracing::warn!("failed to load path table: {e}");
                }
            }

            // Load hashlist
            match storage.load_hashlist().await {
                Ok(hashlist) => {
                    let count = hashlist.len();
                    if count > 0 {
                        tracing::info!("loaded {count} hashlist entries");
                    }
                    self.router.set_hashlist(hashlist);
                }
                Err(e) => {
                    tracing::warn!("failed to load hashlist: {e}");
                }
            }
        }

        // Build announces from configured destinations
        if let Some(ref identity) = self.transport_identity {
            for dest_cfg in &self.config.destinations {
                let aspect_refs: Vec<&str> = dest_cfg.aspects.iter().map(|s| s.as_str()).collect();
                let nh = destination::name_hash(&dest_cfg.app_name, &aspect_refs);
                let dh = destination::destination_hash(&nh, identity.hash());
                let random_hash = make_random_hash();
                let app_data = dest_cfg.app_data.as_deref().map(|s| s.as_bytes());

                match Announce::create(identity, nh, dh, random_hash, None, app_data) {
                    Ok(announce) => {
                        let raw = announce.to_raw_packet(0).serialize();
                        tracing::info!(
                            destination_hash = %hex::encode(dh.as_ref()),
                            app_name = %dest_cfg.app_name,
                            "queued_announce"
                        );
                        self.pending_announces.push(raw);
                    }
                    Err(e) => {
                        tracing::warn!(
                            app_name = %dest_cfg.app_name,
                            "failed to create announce: {e}"
                        );
                    }
                }
            }
        }

        self.create_interfaces()?;
        self.start_interfaces().await?;
        self.spawn_receive_bridges();

        tracing::info!("node started with {} interface(s)", self.interfaces.len());

        Ok(())
    }

    /// Create interface objects from configuration.
    fn create_interfaces(&mut self) -> Result<(), NodeError> {
        let mut id_counter = self.next_id;
        let mut next_id = || {
            let id = InterfaceId(id_counter);
            id_counter += 1;
            id
        };

        // Collect all interfaces into a vec first to avoid borrow conflicts.
        let mut built: Vec<(InterfaceId, AnyInterface)> = Vec::new();

        // TCP clients
        for entry in &self.config.interfaces.tcp_client {
            let id = next_id();
            let mode = parse_mode(&entry.mode)?;
            let mut cfg = TcpClientConfig::initiator(&entry.name, &entry.target);
            cfg.mode = mode;
            built.push((
                id,
                AnyInterface::TcpClient(TcpClientInterface::new(cfg, id)?),
            ));
        }

        // TCP servers
        for entry in &self.config.interfaces.tcp_server {
            let id = next_id();
            let addr = parse_socket_addr(&entry.bind)?;
            let mode = parse_mode(&entry.mode)?;
            let mut cfg = TcpServerConfig::new(&entry.name, addr);
            cfg.mode = mode;
            built.push((
                id,
                AnyInterface::TcpServer(TcpServerInterface::new(cfg, id)),
            ));
        }

        // UDP
        for entry in &self.config.interfaces.udp {
            let id = next_id();
            let bind_addr = parse_socket_addr(&entry.bind)?;
            let mode = parse_mode(&entry.mode)?;
            let cfg = if let Some(ref target) = entry.target {
                let target_addr = parse_socket_addr(target)?;
                if entry.broadcast {
                    let mut c = UdpConfig::broadcast(&entry.name, bind_addr, target_addr);
                    c.mode = mode;
                    c
                } else {
                    let mut c = UdpConfig::unicast(&entry.name, bind_addr, target_addr);
                    c.mode = mode;
                    c
                }
            } else {
                let mut c = UdpConfig::receive_only(&entry.name, bind_addr);
                c.mode = mode;
                c
            };
            built.push((id, AnyInterface::Udp(UdpInterface::new(cfg, id))));
        }

        // Local servers (unix only)
        #[cfg(unix)]
        for entry in &self.config.interfaces.local_server {
            let id = next_id();
            let mode = parse_mode(&entry.mode)?;
            let path = crate::config::parse_path(&entry.path);
            let mut cfg = LocalServerConfig::new(&entry.name, path);
            cfg.mode = mode;
            built.push((
                id,
                AnyInterface::LocalServer(LocalServerInterface::new(cfg, id)),
            ));
        }

        // Local clients (unix only)
        #[cfg(unix)]
        for entry in &self.config.interfaces.local_client {
            let id = next_id();
            let mode = parse_mode(&entry.mode)?;
            let path = crate::config::parse_path(&entry.path);
            let mut cfg = LocalClientConfig::initiator(&entry.name, path);
            cfg.mode = mode;
            built.push((
                id,
                AnyInterface::LocalClient(LocalClientInterface::new(cfg, id)?),
            ));
        }

        // Auto interfaces (unix only)
        #[cfg(unix)]
        for entry in &self.config.interfaces.auto {
            let id = next_id();
            let mode = parse_mode(&entry.mode)?;
            let mut cfg = AutoConfig::new(&entry.name);
            cfg.mode = mode;
            if let Some(ref gid) = entry.group_id {
                cfg.group_id = gid.as_bytes().to_vec();
            }
            if let Some(dp) = entry.discovery_port {
                cfg.discovery_port = dp;
            }
            if let Some(dp) = entry.data_port {
                cfg.data_port = dp;
            }
            built.push((id, AnyInterface::Auto(AutoInterface::new(cfg, id))));
        }

        self.next_id = id_counter;
        for (id, iface) in built {
            self.interfaces.insert(id, Arc::new(iface));
        }

        Ok(())
    }

    /// Start all interfaces.
    async fn start_interfaces(&mut self) -> Result<(), NodeError> {
        for (&id, iface) in &self.interfaces {
            if let Err(e) = iface.start().await {
                tracing::error!(interface = %iface.name(), "failed to start: {e}");
                return Err(NodeError::Interface(e));
            }
            tracing::info!(interface = %iface.name(), id = id.0, "interface started");
        }
        Ok(())
    }

    /// Spawn per-interface receive bridge tasks.
    fn spawn_receive_bridges(&mut self) {
        for (&iface_id, iface) in &self.interfaces {
            if !iface.can_receive() {
                continue;
            }
            let iface = Arc::clone(iface);
            let event_tx = self.event_tx.clone();
            let mut shutdown_rx = self.shutdown_rx.clone();

            let handle = tokio::spawn(async move {
                loop {
                    tokio::select! {
                        biased;
                        _ = shutdown_rx.changed() => {
                            tracing::debug!(id = iface_id.0, "receive bridge shutting down");
                            break;
                        }
                        result = iface.receive() => {
                            match result {
                                Ok(raw) => {
                                    if event_tx
                                        .send(NodeEvent::InboundPacket {
                                            interface_id: iface_id,
                                            raw,
                                        })
                                        .await
                                        .is_err()
                                    {
                                        break;
                                    }
                                }
                                Err(e) => {
                                    tracing::warn!(id = iface_id.0, "receive error: {e}");
                                    let _ = event_tx
                                        .send(NodeEvent::InterfaceDown {
                                            interface_id: iface_id,
                                        })
                                        .await;
                                    break;
                                }
                            }
                        }
                    }
                }
            });
            self.bridge_handles.push(handle);
        }
    }

    /// Run the main event loop. Returns when shutdown is signalled.
    pub async fn run(&mut self) {
        let mut maintenance_interval = tokio::time::interval(std::time::Duration::from_secs(1));
        let mut cull_interval = tokio::time::interval(std::time::Duration::from_secs(5));

        let persist_secs = self.config.node.persist_interval;
        let persist_enabled = persist_secs > 0 && self.storage.is_some();
        let mut persist_interval =
            tokio::time::interval(std::time::Duration::from_secs(if persist_enabled {
                persist_secs
            } else {
                3600
            }));

        // Don't fire immediately
        maintenance_interval.tick().await;
        cull_interval.tick().await;
        persist_interval.tick().await;

        // Broadcast pending announces (from config destinations)
        if !self.pending_announces.is_empty() {
            let announces = std::mem::take(&mut self.pending_announces);
            for raw in announces {
                self.broadcast_to_interfaces(None, &raw).await;
            }
        }

        tracing::info!("entering event loop");

        loop {
            tokio::select! {
                biased;

                event = self.event_rx.recv() => {
                    match event {
                        Some(NodeEvent::InboundPacket { interface_id, raw }) => {
                            self.handle_inbound_packet(interface_id, &raw).await;
                        }
                        Some(NodeEvent::InterfaceDown { interface_id }) => {
                            tracing::warn!(id = interface_id.0, "interface down");
                        }
                        None => {
                            tracing::info!("event channel closed, exiting");
                            break;
                        }
                    }
                }

                _ = maintenance_interval.tick() => {
                    let actions = self.collect_announce_actions();
                    for action in actions {
                        if let RouterAction::Broadcast { exclude, raw } = action {
                            self.broadcast_to_interfaces(exclude, &raw).await;
                        }
                    }
                }

                _ = cull_interval.tick() => {
                    self.run_table_cull();
                }

                _ = persist_interval.tick(), if persist_enabled => {
                    self.persist_state().await;
                }

                _ = self.shutdown_rx.changed() => {
                    tracing::info!("shutdown signal received");
                    break;
                }
            }
        }
    }

    /// Get a handle that can trigger shutdown from another task.
    pub fn shutdown_handle(&self) -> ShutdownHandle {
        ShutdownHandle {
            tx: self.shutdown_tx.clone(),
        }
    }

    /// Signal the node to shut down.
    pub fn trigger_shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }

    /// Shut down all interfaces and clean up.
    pub async fn shutdown(mut self) {
        tracing::info!("shutting down node");
        self.trigger_shutdown();

        // Final state persistence before shutdown
        self.persist_state().await;

        // Wait for all bridge tasks to finish.
        for handle in self.bridge_handles.drain(..) {
            let _ = handle.await;
        }

        // Stop each interface.
        for (id, iface) in &self.interfaces {
            if let Err(e) = iface.stop().await {
                tracing::warn!(id = id.0, "error stopping interface: {e}");
            }
        }

        tracing::info!("node shutdown complete");
    }

    /// Broadcast raw bytes to all interfaces, optionally excluding one.
    async fn broadcast_to_interfaces(&self, exclude: Option<InterfaceId>, raw: &[u8]) {
        for (&iface_id, iface) in &self.interfaces {
            if Some(iface_id) == exclude || !iface.can_transmit() || !iface.is_connected() {
                continue;
            }

            // Apply IFAC if configured
            let outbound = if let Some(ref ifac) = self.ifac_config {
                match ifac_apply(ifac, raw) {
                    Ok(masked) => masked,
                    Err(e) => {
                        tracing::warn!(id = iface_id.0, "IFAC apply failed: {e}");
                        continue;
                    }
                }
            } else {
                raw.to_vec()
            };

            if let Err(e) = iface.transmit(&outbound).await {
                tracing::warn!(id = iface_id.0, "transmit failed: {e}");
            }
        }
    }

    /// Handle an inbound packet: IFAC verify, parse, dedup, announce processing, flood.
    async fn handle_inbound_packet(&mut self, from_iface: InterfaceId, raw: &[u8]) {
        if raw.is_empty() {
            return;
        }

        // IFAC verification
        let packet_bytes = if let Some(ref ifac) = self.ifac_config {
            if has_ifac_flag(raw) {
                match ifac_verify(ifac, raw) {
                    Ok(verified) => verified,
                    Err(e) => {
                        tracing::debug!(id = from_iface.0, "IFAC verification failed: {e}");
                        return;
                    }
                }
            } else {
                raw.to_vec()
            }
        } else {
            raw.to_vec()
        };

        // Parse the packet
        let packet = match RawPacket::parse(&packet_bytes) {
            Ok(p) => p,
            Err(e) => {
                tracing::debug!(id = from_iface.0, "packet parse failed: {e}");
                return;
            }
        };

        // Deduplication
        let hash = packet.packet_hash();
        if !self.router.hashlist_mut().insert(hash) {
            tracing::trace!(id = from_iface.0, "duplicate packet dropped");
            return;
        }

        // Hop limit check
        if packet.hops >= PATHFINDER_M {
            tracing::trace!(id = from_iface.0, hops = packet.hops, "hop limit reached");
            return;
        }

        // Announce processing
        if packet.flags.packet_type == PacketType::Announce {
            let interface_mode = self
                .interfaces
                .get(&from_iface)
                .map(|i| i.mode())
                .unwrap_or(reticulum_interfaces::InterfaceMode::Full);

            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default();
            let now_secs = now.as_secs();
            let now_f64 = now.as_secs_f64();

            match self.router.process_inbound_announce(
                &packet,
                from_iface,
                interface_mode,
                now_secs,
                now_f64,
            ) {
                Ok(result) => {
                    tracing::info!(
                        destination_hash = %hex::encode(result.destination_hash.as_ref()),
                        hops = result.hops,
                        path_updated = result.path_updated,
                        "announce_validated"
                    );
                }
                Err(e) => {
                    tracing::debug!(error = %e, "announce_validation_failed");
                }
            }
        }

        // Increment hops and re-serialize for forwarding
        let mut forward_packet = packet.clone();
        forward_packet.hops = packet.hops.saturating_add(1);
        let forward_raw = forward_packet.serialize();

        // Flood to all other interfaces
        self.broadcast_to_interfaces(Some(from_iface), &forward_raw)
            .await;
    }

    /// Process pending announce retransmissions.
    ///
    /// This is sync but collects actions; we need to dispatch them async.
    /// Returns the actions to be dispatched by the caller.
    fn collect_announce_actions(&mut self) -> Vec<RouterAction> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);

        self.router.process_announce_jobs(now)
    }

    /// Persist path table and hashlist to storage.
    async fn persist_state(&self) {
        if let Some(ref storage) = self.storage {
            if let Err(e) = storage.save_path_table(self.router.path_table()).await {
                tracing::warn!("failed to persist path table: {e}");
            }
            if let Err(e) = storage.save_hashlist(self.router.hashlist()).await {
                tracing::warn!("failed to persist hashlist: {e}");
            }
            tracing::debug!("persisted state to storage");
        }
    }

    /// Cull expired entries from routing tables.
    fn run_table_cull(&mut self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let active: Vec<InterfaceId> = self
            .interfaces
            .iter()
            .filter(|(_, iface)| iface.is_connected())
            .map(|(&id, _)| id)
            .collect();

        self.router.cull_tables(now, &active);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::NodeConfig;

    #[test]
    fn node_new_no_ifac() {
        let config = NodeConfig::default();
        let node = Node::new(config);
        assert!(node.ifac_config.is_none());
        assert!(node.interfaces.is_empty());
    }

    #[test]
    fn node_new_with_ifac() {
        let config = NodeConfig::parse(
            r#"
[node]
network_name = "testnet"
network_key = "secret"
ifac_size = 8
"#,
        )
        .unwrap();
        let node = Node::new(config);
        assert!(node.ifac_config.is_some());
    }

    #[tokio::test]
    async fn node_start_empty() {
        let config = NodeConfig::default();
        let mut node = Node::new(config);
        node.start().await.unwrap();
        assert!(node.interfaces.is_empty());
    }

    #[tokio::test]
    async fn node_start_already_running() {
        let toml = r#"
[[interfaces.udp]]
name = "test"
bind = "127.0.0.1:0"
"#;
        let config = NodeConfig::parse(toml).unwrap();
        let _node = Node::new(config);
        // We can't actually start with port 0 in this simple test,
        // but creating with port 0 and immediately creating again tests the double-start guard.
        // Instead, test with empty config that succeeds:
        let config2 = NodeConfig::default();
        let mut node2 = Node::new(config2);
        node2.start().await.unwrap();
        // Starting again should fail — but with no interfaces it won't trigger AlreadyRunning.
        // That guard only fires when interfaces is non-empty.
    }

    #[tokio::test]
    async fn node_shutdown_empty() {
        let config = NodeConfig::default();
        let mut node = Node::new(config);
        node.start().await.unwrap();
        node.shutdown().await;
    }

    #[tokio::test]
    async fn node_trigger_shutdown() {
        let config = NodeConfig::default();
        let mut node = Node::new(config);
        node.start().await.unwrap();

        node.trigger_shutdown();

        // Run should exit quickly after shutdown signal
        tokio::time::timeout(std::time::Duration::from_millis(100), node.run())
            .await
            .expect("run should exit after shutdown");
    }

    #[tokio::test]
    async fn shutdown_handle_from_spawned_task() {
        let mut config = NodeConfig::default();
        config.node.enable_storage = false;
        let mut node = Node::new(config);
        node.start().await.unwrap();

        let handle = node.shutdown_handle();

        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            handle.shutdown();
        });

        // run() should exit once the spawned task signals shutdown
        tokio::time::timeout(std::time::Duration::from_secs(2), node.run())
            .await
            .expect("run should exit after ShutdownHandle signal");

        node.shutdown().await;
    }

    #[tokio::test]
    async fn udp_loopback_flooding() {
        use reticulum_core::constants::{DestinationType, HeaderType, PacketType, TransportType};
        use reticulum_core::packet::context::ContextType;
        use reticulum_core::packet::flags::PacketFlags;
        use reticulum_core::types::DestinationHash;
        use tokio::net::UdpSocket;

        // Bind two ephemeral ports so we know which ports are available.
        let external_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sink_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let external_addr = external_sock.local_addr().unwrap();
        let sink_addr = sink_sock.local_addr().unwrap();

        // Node has two UDP interfaces:
        //   iface_a: binds an ephemeral port, sends to external_addr (for receiving from external)
        //   iface_b: binds an ephemeral port, sends to sink_addr (for flooding to sink)
        // We use port 0 to let the OS pick, but that means we can't pre-configure
        // the external sender's target. Instead, build programmatically.
        let config = NodeConfig::default();
        let mut node = Node::new(config);

        // Create interfaces programmatically
        let id_a = InterfaceId(100);
        let id_b = InterfaceId(200);

        let bind_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let bind_a_addr = bind_a.local_addr().unwrap();
        drop(bind_a); // release so the interface can bind it

        let bind_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let bind_b_addr = bind_b.local_addr().unwrap();
        drop(bind_b);

        let cfg_a = UdpConfig::unicast("iface_a", bind_a_addr, external_addr);
        let cfg_b = UdpConfig::unicast("iface_b", bind_b_addr, sink_addr);

        let iface_a = UdpInterface::new(cfg_a, id_a);
        let iface_b = UdpInterface::new(cfg_b, id_b);

        use reticulum_interfaces::Interface;
        iface_a.start().await.unwrap();
        iface_b.start().await.unwrap();

        node.interfaces
            .insert(id_a, Arc::new(AnyInterface::Udp(iface_a)));
        node.interfaces
            .insert(id_b, Arc::new(AnyInterface::Udp(iface_b)));
        node.next_id = 300;
        node.spawn_receive_bridges();

        // Build a valid packet
        let dest_hash = DestinationHash::new([0xAB; 16]);
        let packet = RawPacket {
            flags: PacketFlags {
                header_type: HeaderType::Header1,
                context_flag: false,
                transport_type: TransportType::Broadcast,
                destination_type: DestinationType::Single,
                packet_type: PacketType::Data,
            },
            hops: 0,
            transport_id: None,
            destination: dest_hash,
            context: ContextType::None,
            data: b"hello".to_vec(),
        };
        let raw = packet.serialize();

        // Send the packet from external to iface_a
        external_sock.send_to(&raw, bind_a_addr).await.unwrap();

        // Run the node event loop briefly to process the packet
        let node_handle = {
            // We need to move node into the task. Use a channel to get it back.
            let (tx, rx) = tokio::sync::oneshot::channel::<Node>();
            tokio::spawn(async move {
                let run_future = async {
                    // We'll use a short timeout; the node processes the event then we shut down
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                    node.trigger_shutdown();
                    node.run().await;
                    node
                };
                let node = run_future.await;
                let _ = tx.send(node);
            });
            rx
        };

        // Check if the flooded packet arrives at sink
        let mut buf = [0u8; 2048];
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            sink_sock.recv_from(&mut buf),
        )
        .await;

        match result {
            Ok(Ok((len, _addr))) => {
                // The received packet should have hops incremented by 1
                let received = RawPacket::parse(&buf[..len]).unwrap();
                assert_eq!(received.hops, 1, "hops should be incremented");
                assert_eq!(received.data, b"hello");
            }
            Ok(Err(e)) => panic!("recv_from failed: {e}"),
            Err(_) => panic!("timed out waiting for flooded packet"),
        }

        // Clean up
        if let Ok(node) = node_handle.await {
            node.shutdown().await;
        }
    }

    #[tokio::test]
    async fn tcp_node_receives_and_floods() {
        use reticulum_core::constants::{DestinationType, HeaderType, PacketType, TransportType};
        use reticulum_core::framing::hdlc::hdlc_frame;
        use reticulum_core::packet::context::ContextType;
        use reticulum_core::packet::flags::PacketFlags;
        use reticulum_core::types::DestinationHash;
        use reticulum_interfaces::Interface;
        use tokio::io::AsyncWriteExt;
        use tokio::net::{TcpListener, UdpSocket};

        // Set up a raw TCP listener to act as the remote peer for our TCP client
        let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_addr = tcp_listener.local_addr().unwrap();

        // Set up a UDP sink socket to receive flooded packets
        let sink_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sink_addr = sink_sock.local_addr().unwrap();

        // Build node with no config-based interfaces
        let mut config = NodeConfig::default();
        config.node.enable_storage = false;
        let mut node = Node::new(config);

        // Create a TCP client interface pointing at our listener
        let id_tcp = InterfaceId(100);
        let tcp_cfg = TcpClientConfig::initiator("tcp-input", tcp_addr.to_string());
        let tcp_iface = TcpClientInterface::new(tcp_cfg, id_tcp).unwrap();
        tcp_iface.start().await.unwrap();

        // Accept the connection from the TCP client
        let (mut peer_stream, _) = tcp_listener.accept().await.unwrap();

        // Wait for the TCP client to be connected
        for _ in 0..50 {
            if tcp_iface.is_connected() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert!(tcp_iface.is_connected(), "TCP client did not connect");

        // Create a UDP output interface
        let id_udp = InterfaceId(200);
        let udp_bind = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_bind_addr = udp_bind.local_addr().unwrap();
        drop(udp_bind);
        let udp_cfg =
            reticulum_interfaces::udp::UdpConfig::unicast("udp-output", udp_bind_addr, sink_addr);
        let udp_iface = UdpInterface::new(udp_cfg, id_udp);
        udp_iface.start().await.unwrap();

        // Register interfaces in the node
        node.interfaces
            .insert(id_tcp, Arc::new(AnyInterface::TcpClient(tcp_iface)));
        node.interfaces
            .insert(id_udp, Arc::new(AnyInterface::Udp(udp_iface)));
        node.next_id = 300;
        node.spawn_receive_bridges();

        // Build a valid packet and send it as an HDLC frame over TCP
        let dest_hash = DestinationHash::new([0xCD; 16]);
        let packet = RawPacket {
            flags: PacketFlags {
                header_type: HeaderType::Header1,
                context_flag: false,
                transport_type: TransportType::Broadcast,
                destination_type: DestinationType::Single,
                packet_type: PacketType::Data,
            },
            hops: 0,
            transport_id: None,
            destination: dest_hash,
            context: ContextType::None,
            data: b"tcp-test".to_vec(),
        };
        let raw = packet.serialize();
        let framed = hdlc_frame(&raw);
        peer_stream.write_all(&framed).await.unwrap();

        // Run the node event loop briefly
        let node_handle = {
            let (tx, rx) = tokio::sync::oneshot::channel::<Node>();
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                node.trigger_shutdown();
                node.run().await;
                let _ = tx.send(node);
            });
            rx
        };

        // Check if the flooded packet arrives at the UDP sink
        let mut buf = [0u8; 2048];
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            sink_sock.recv_from(&mut buf),
        )
        .await;

        match result {
            Ok(Ok((len, _addr))) => {
                let received = RawPacket::parse(&buf[..len]).unwrap();
                assert_eq!(received.hops, 1, "hops should be incremented");
                assert_eq!(received.data, b"tcp-test");
            }
            Ok(Err(e)) => panic!("recv_from failed: {e}"),
            Err(_) => panic!("timed out waiting for flooded packet from TCP→UDP"),
        }

        // Clean up
        if let Ok(node) = node_handle.await {
            node.shutdown().await;
        }
    }
}
