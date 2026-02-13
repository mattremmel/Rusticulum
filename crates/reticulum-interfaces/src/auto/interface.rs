//! `AutoInterface` — automatic peer discovery and data transport via IPv6 multicast.
//!
//! Spawns per-interface background tasks for multicast discovery and unicast data
//! transport, presenting a single unified [`Interface`] to the rest of the stack.

use std::net::{Ipv6Addr, SocketAddrV6};
use std::sync::Arc;

use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, RwLock, mpsc, watch};
use tracing::{debug, info, warn};

use reticulum_transport::path::{InterfaceId, InterfaceMode};

use crate::error::InterfaceError;
use crate::shutdown::ShutdownToken;
use crate::traits::Interface;

use super::discovery::{
    derive_multicast_address, generate_discovery_token, verify_discovery_token,
};
use super::netif::{self, Ipv6Interface, descope_link_local};
use super::peer::PeerTable;
use super::{
    ANNOUNCE_INTERVAL, AutoConfig, BITRATE_GUESS, HW_MTU, PEER_JOB_INTERVAL, PEERING_TIMEOUT,
    RECV_BUFFER,
};

/// Auto interface with multicast discovery and unicast UDP data transport.
pub struct AutoInterface {
    config: AutoConfig,
    id: InterfaceId,
    multicast_addr: Ipv6Addr,
    peer_table: Arc<RwLock<PeerTable>>,
    rx_receiver: Mutex<mpsc::Receiver<Vec<u8>>>,
    rx_sender: mpsc::Sender<Vec<u8>>,
    /// One outbound data socket per adopted interface, keyed by ifname.
    #[allow(clippy::type_complexity)]
    outbound_sockets: Arc<RwLock<Vec<(String, Arc<UdpSocket>)>>>,
    shutdown: ShutdownToken,
    /// Link-local addresses that belong to us (for echo detection).
    own_addresses: Arc<RwLock<Vec<String>>>,
}

impl AutoInterface {
    /// Create a new Auto interface with the given configuration.
    pub fn new(config: AutoConfig, id: InterfaceId) -> Self {
        let multicast_addr = derive_multicast_address(
            &config.group_id,
            config.discovery_scope,
            config.multicast_address_type,
        );

        let (rx_sender, rx_receiver) = mpsc::channel(256);

        Self {
            config,
            id,
            multicast_addr,
            peer_table: Arc::new(RwLock::new(PeerTable::new())),
            rx_receiver: Mutex::new(rx_receiver),
            rx_sender,
            outbound_sockets: Arc::new(RwLock::new(Vec::new())),
            shutdown: ShutdownToken::new(),
            own_addresses: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Create a multicast discovery socket bound to the given interface.
    fn create_multicast_socket(
        mcast_addr: Ipv6Addr,
        discovery_port: u16,
        iface: &Ipv6Interface,
        scope: super::DiscoveryScope,
    ) -> std::io::Result<std::net::UdpSocket> {
        let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_reuse_address(true)?;
        #[cfg(unix)]
        socket.set_reuse_port(true)?;
        socket.set_nonblocking(true)?;

        // Set multicast interface.
        socket.set_multicast_if_v6(iface.if_index)?;

        // Join multicast group on this interface.
        socket.join_multicast_v6(&mcast_addr, iface.if_index)?;

        // Bind to the multicast address with scope for link-local,
        // or without scope for wider scopes.
        let bind_addr = if scope == super::DiscoveryScope::Link {
            SocketAddrV6::new(mcast_addr, discovery_port, 0, iface.if_index)
        } else {
            SocketAddrV6::new(mcast_addr, discovery_port, 0, 0)
        };
        socket.bind(&SockAddr::from(bind_addr))?;

        Ok(socket.into())
    }

    /// Create a unicast discovery socket bound to the link-local address.
    fn create_unicast_discovery_socket(
        iface: &Ipv6Interface,
        unicast_discovery_port: u16,
    ) -> std::io::Result<std::net::UdpSocket> {
        let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_reuse_address(true)?;
        #[cfg(unix)]
        socket.set_reuse_port(true)?;
        socket.set_nonblocking(true)?;

        let bind_addr = SocketAddrV6::new(iface.addr, unicast_discovery_port, 0, iface.if_index);
        socket.bind(&SockAddr::from(bind_addr))?;

        Ok(socket.into())
    }

    /// Create a data socket for receiving unicast data on the given interface.
    fn create_data_socket(
        iface: &Ipv6Interface,
        data_port: u16,
    ) -> std::io::Result<std::net::UdpSocket> {
        let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_reuse_address(true)?;
        #[cfg(unix)]
        socket.set_reuse_port(true)?;
        socket.set_nonblocking(true)?;

        let bind_addr = SocketAddrV6::new(iface.addr, data_port, 0, iface.if_index);
        socket.bind(&SockAddr::from(bind_addr))?;

        Ok(socket.into())
    }

    /// Create an outbound data socket for sending to peers on the given interface.
    fn create_outbound_socket(iface: &Ipv6Interface) -> std::io::Result<std::net::UdpSocket> {
        let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_nonblocking(true)?;

        // Bind to an ephemeral port on the link-local address.
        let bind_addr = SocketAddrV6::new(iface.addr, 0, 0, iface.if_index);
        socket.bind(&SockAddr::from(bind_addr))?;

        Ok(socket.into())
    }

    // -----------------------------------------------------------------------
    // Background tasks
    // -----------------------------------------------------------------------

    /// Receive multicast or unicast discovery packets and update the peer table.
    #[allow(clippy::too_many_arguments)]
    async fn discovery_recv_loop(
        socket: Arc<UdpSocket>,
        group_id: Vec<u8>,
        ifname: String,
        if_index: u32,
        peer_table: Arc<RwLock<PeerTable>>,
        own_addresses: Arc<RwLock<Vec<String>>>,
        mut stop_rx: watch::Receiver<bool>,
        name: String,
    ) {
        let mut buf = vec![0u8; RECV_BUFFER];

        loop {
            tokio::select! {
                result = socket.recv_from(&mut buf) => {
                    match result {
                        Ok((n, src)) => {
                            if n < 32 {
                                continue;
                            }

                            let sender_ip = match src.ip() {
                                std::net::IpAddr::V6(ip) => ip,
                                _ => continue,
                            };
                            let sender_addr_str = descope_link_local(&sender_ip.to_string());
                            let token = &buf[..n.min(32)];

                            // Check if this is our own echo.
                            {
                                let own = own_addresses.read().await;
                                if own.contains(&sender_addr_str) {
                                    // Our own multicast echo — skip silently.
                                    continue;
                                }
                            }

                            if verify_discovery_token(token, &group_id, &sender_addr_str) {
                                let mut table = peer_table.write().await;
                                let is_new = table.add_or_refresh(sender_ip, ifname.clone(), if_index);
                                if is_new {
                                    info!("{}: discovered peer {} on {}", name, sender_addr_str, ifname);
                                } else {
                                    debug!("{}: refreshed peer {} on {}", name, sender_addr_str, ifname);
                                }
                            } else {
                                debug!(
                                    "{}: invalid discovery token from {} on {}",
                                    name, sender_addr_str, ifname
                                );
                            }
                        }
                        Err(e) => {
                            warn!("{}: discovery recv error on {}: {}", name, ifname, e);
                            if *stop_rx.borrow() {
                                break;
                            }
                        }
                    }
                }
                _ = stop_rx.changed() => break,
            }
        }
    }

    /// Periodically send multicast discovery announcements.
    async fn announce_loop(
        mcast_addr: Ipv6Addr,
        discovery_port: u16,
        group_id: Vec<u8>,
        link_local_addr: String,
        if_index: u32,
        mut stop_rx: watch::Receiver<bool>,
        name: String,
    ) {
        loop {
            // Generate and send discovery token.
            let token = generate_discovery_token(&group_id, &link_local_addr);
            let dest = SocketAddrV6::new(mcast_addr, discovery_port, 0, if_index);

            // Create a temporary socket for each announcement (matching Python behavior).
            match create_announce_socket(if_index) {
                Ok(sock) => {
                    if let Err(e) = sock.send_to(&token, dest).await {
                        debug!("{}: announce send error: {}", name, e);
                    }
                }
                Err(e) => {
                    debug!("{}: could not create announce socket: {}", name, e);
                }
            }

            tokio::select! {
                _ = tokio::time::sleep(ANNOUNCE_INTERVAL) => {}
                _ = stop_rx.changed() => break,
            }
        }
    }

    /// Receive unicast data packets and forward them to the channel.
    async fn data_recv_loop(
        socket: Arc<UdpSocket>,
        tx: mpsc::Sender<Vec<u8>>,
        peer_table: Arc<RwLock<PeerTable>>,
        mut stop_rx: watch::Receiver<bool>,
        name: String,
    ) {
        let mut buf = vec![0u8; RECV_BUFFER];

        loop {
            tokio::select! {
                result = socket.recv_from(&mut buf) => {
                    match result {
                        Ok((n, src)) => {
                            debug!("{}: data received {} bytes from {}", name, n, src);

                            let data = buf[..n].to_vec();
                            let data_hash = reticulum_crypto::sha::sha256(&data);

                            let mut table = peer_table.write().await;
                            if table.is_duplicate(data_hash) {
                                debug!("{}: dedup dropped packet from {}", name, src);
                                continue;
                            }
                            drop(table);

                            if tx.send(data).await.is_err() {
                                return; // Receiver dropped.
                            }
                        }
                        Err(e) => {
                            warn!("{}: data recv error: {}", name, e);
                            if *stop_rx.borrow() {
                                break;
                            }
                        }
                    }
                }
                _ = stop_rx.changed() => break,
            }
        }
    }

    /// Periodically prune timed-out peers and send reverse peering announcements.
    async fn peer_maintenance_loop(
        group_id: Vec<u8>,
        own_link_locals: Vec<(String, String, u32)>, // (link_local_addr, ifname, if_index)
        unicast_discovery_port: u16,
        peer_table: Arc<RwLock<PeerTable>>,
        mut stop_rx: watch::Receiver<bool>,
        name: String,
    ) {
        let reverse_peering_interval = ANNOUNCE_INTERVAL.mul_f64(3.25);

        loop {
            tokio::select! {
                _ = tokio::time::sleep(PEER_JOB_INTERVAL) => {}
                _ = stop_rx.changed() => break,
            }

            // Prune timed-out peers.
            let removed = {
                let mut table = peer_table.write().await;
                table.prune_timed_out(PEERING_TIMEOUT)
            };
            for addr in &removed {
                info!("{}: peer {} timed out", name, addr);
            }

            // Send reverse peering announcements to peers that need them.
            let peers_snapshot: Vec<(Ipv6Addr, String, u32, std::time::Instant)> = {
                let table = peer_table.read().await;
                table
                    .peers()
                    .map(|p| (p.addr, p.ifname.clone(), p.if_index, p.last_outbound))
                    .collect()
            };

            let now = std::time::Instant::now();
            for (peer_addr, peer_ifname, _peer_if_index, last_outbound) in &peers_snapshot {
                if now.duration_since(*last_outbound) < reverse_peering_interval {
                    continue;
                }

                // Find our link-local for this interface.
                let our_ll = own_link_locals
                    .iter()
                    .find(|(_, ifn, _)| ifn == peer_ifname);
                let Some((link_local_addr, _ifname, if_index)) = our_ll else {
                    continue;
                };

                let token = generate_discovery_token(&group_id, link_local_addr);
                let dest = SocketAddrV6::new(*peer_addr, unicast_discovery_port, 0, *if_index);

                match create_announce_socket(*if_index) {
                    Ok(sock) => {
                        if let Err(e) = sock.send_to(&token, dest).await {
                            debug!(
                                "{}: reverse peering send error to {}: {}",
                                name, peer_addr, e
                            );
                        } else {
                            let mut table = peer_table.write().await;
                            table.mark_outbound(peer_addr);
                        }
                    }
                    Err(e) => {
                        debug!("{}: could not create reverse peering socket: {}", name, e);
                    }
                }
            }
        }
    }
}

/// Create a temporary UDP socket for sending announcements on a specific interface.
fn create_announce_socket(if_index: u32) -> std::io::Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_nonblocking(true)?;
    socket.set_multicast_if_v6(if_index)?;

    // Bind to any address, ephemeral port, on this interface.
    let bind_addr = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, if_index);
    socket.bind(&SockAddr::from(bind_addr))?;

    let std_sock: std::net::UdpSocket = socket.into();
    UdpSocket::from_std(std_sock)
}

impl Interface for AutoInterface {
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
        HW_MTU
    }

    fn can_receive(&self) -> bool {
        true
    }

    fn can_transmit(&self) -> bool {
        true
    }

    fn is_connected(&self) -> bool {
        self.shutdown.is_online()
    }

    async fn start(&self) -> Result<(), InterfaceError> {
        let interfaces = netif::enumerate_ipv6_interfaces(
            &self.config.allowed_interfaces,
            &self.config.ignored_interfaces,
        )?;

        if interfaces.is_empty() {
            warn!(
                "{}: no suitable network interfaces found — no connectivity",
                self.config.name
            );
            return Ok(());
        }

        let unicast_discovery_port = self.config.discovery_port + 1;
        let mut handles = Vec::new();

        // Collect own link-local addresses for echo detection.
        let mut own_ll = Vec::new();
        {
            let mut own = self.own_addresses.write().await;
            for iface in &interfaces {
                let addr_str = descope_link_local(&iface.addr.to_string());
                own.push(addr_str.clone());
                own_ll.push((addr_str, iface.name.clone(), iface.if_index));
            }
        }

        // Set up per-interface sockets and tasks.
        let mut outbound = Vec::new();
        for iface in &interfaces {
            let link_local_str = descope_link_local(&iface.addr.to_string());

            // --- Multicast discovery socket ---
            match Self::create_multicast_socket(
                self.multicast_addr,
                self.config.discovery_port,
                iface,
                self.config.discovery_scope,
            ) {
                Ok(std_sock) => {
                    let tok_sock = Arc::new(UdpSocket::from_std(std_sock)?);

                    // Discovery receive loop.
                    let handle = tokio::spawn(Self::discovery_recv_loop(
                        Arc::clone(&tok_sock),
                        self.config.group_id.clone(),
                        iface.name.clone(),
                        iface.if_index,
                        Arc::clone(&self.peer_table),
                        Arc::clone(&self.own_addresses),
                        self.shutdown.subscribe(),
                        self.config.name.clone(),
                    ));
                    handles.push(handle);

                    // Announce loop for this interface.
                    let handle = tokio::spawn(Self::announce_loop(
                        self.multicast_addr,
                        self.config.discovery_port,
                        self.config.group_id.clone(),
                        link_local_str.clone(),
                        iface.if_index,
                        self.shutdown.subscribe(),
                        self.config.name.clone(),
                    ));
                    handles.push(handle);

                    info!(
                        "{}: multicast discovery on {} ({})",
                        self.config.name, iface.name, link_local_str
                    );
                }
                Err(e) => {
                    warn!(
                        "{}: could not set up multicast on {}: {}",
                        self.config.name, iface.name, e
                    );
                }
            }

            // --- Unicast discovery socket ---
            match Self::create_unicast_discovery_socket(iface, unicast_discovery_port) {
                Ok(std_sock) => {
                    let tok_sock = Arc::new(UdpSocket::from_std(std_sock)?);

                    let handle = tokio::spawn(Self::discovery_recv_loop(
                        tok_sock,
                        self.config.group_id.clone(),
                        iface.name.clone(),
                        iface.if_index,
                        Arc::clone(&self.peer_table),
                        Arc::clone(&self.own_addresses),
                        self.shutdown.subscribe(),
                        self.config.name.clone(),
                    ));
                    handles.push(handle);
                }
                Err(e) => {
                    warn!(
                        "{}: could not set up unicast discovery on {}: {}",
                        self.config.name, iface.name, e
                    );
                }
            }

            // --- Data socket ---
            match Self::create_data_socket(iface, self.config.data_port) {
                Ok(std_sock) => {
                    let tok_sock = Arc::new(UdpSocket::from_std(std_sock)?);

                    let handle = tokio::spawn(Self::data_recv_loop(
                        tok_sock,
                        self.rx_sender.clone(),
                        Arc::clone(&self.peer_table),
                        self.shutdown.subscribe(),
                        self.config.name.clone(),
                    ));
                    handles.push(handle);
                }
                Err(e) => {
                    warn!(
                        "{}: could not set up data socket on {}: {}",
                        self.config.name, iface.name, e
                    );
                }
            }

            // --- Outbound data socket ---
            match Self::create_outbound_socket(iface) {
                Ok(std_sock) => {
                    let tok_sock = Arc::new(UdpSocket::from_std(std_sock)?);
                    outbound.push((iface.name.clone(), tok_sock));
                }
                Err(e) => {
                    warn!(
                        "{}: could not set up outbound socket on {}: {}",
                        self.config.name, iface.name, e
                    );
                }
            }
        }

        *self.outbound_sockets.write().await = outbound;

        // Peer maintenance loop (global, not per-interface).
        let handle = tokio::spawn(Self::peer_maintenance_loop(
            self.config.group_id.clone(),
            own_ll,
            unicast_discovery_port,
            Arc::clone(&self.peer_table),
            self.shutdown.subscribe(),
            self.config.name.clone(),
        ));
        handles.push(handle);

        self.shutdown.set_tasks(handles).await;

        // Wait for initial peering window.
        let peering_wait = ANNOUNCE_INTERVAL.mul_f64(1.2);
        info!(
            "{}: discovering peers for {:.1}s...",
            self.config.name,
            peering_wait.as_secs_f64()
        );
        tokio::time::sleep(peering_wait).await;

        self.shutdown.set_online();
        let peer_count = self.peer_table.read().await.len();
        info!("{}: online with {} peer(s)", self.config.name, peer_count);

        Ok(())
    }

    async fn stop(&self) -> Result<(), InterfaceError> {
        self.shutdown.signal_stop_and_go_offline();

        // Clear outbound sockets.
        self.outbound_sockets.write().await.clear();

        // Await all background tasks.
        self.shutdown.join_all().await;

        info!("{}: stopped", self.config.name);
        Ok(())
    }

    async fn transmit(&self, data: &[u8]) -> Result<(), InterfaceError> {
        if !self.shutdown.is_online() {
            return Err(InterfaceError::NotConnected);
        }

        let peers: Vec<(Ipv6Addr, String, u32)> = {
            let table = self.peer_table.read().await;
            table
                .peers()
                .map(|p| (p.addr, p.ifname.clone(), p.if_index))
                .collect()
        };

        if peers.is_empty() {
            return Err(InterfaceError::TransmitFailed("no peers discovered".into()));
        }

        let sockets = self.outbound_sockets.read().await;

        for (peer_addr, peer_ifname, peer_if_index) in &peers {
            // Find the outbound socket for this peer's interface.
            let sock = sockets.iter().find(|(name, _)| name == peer_ifname);
            let Some((_, socket)) = sock else {
                debug!(
                    "{}: no outbound socket for interface {}",
                    self.config.name, peer_ifname
                );
                continue;
            };

            let dest = SocketAddrV6::new(*peer_addr, self.config.data_port, 0, *peer_if_index);
            if let Err(e) = socket.send_to(data, dest).await {
                debug!(
                    "{}: transmit to {} failed: {}",
                    self.config.name, peer_addr, e
                );
            }
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

    #[test]
    fn auto_interface_creation() {
        let config = AutoConfig::new("AutoInterface[test]");
        let iface = AutoInterface::new(config, InterfaceId(100));

        assert_eq!(iface.name(), "AutoInterface[test]");
        assert_eq!(iface.id(), InterfaceId(100));
        assert_eq!(iface.mtu(), 1196);
        assert_eq!(iface.bitrate(), 10_000_000);
        assert!(iface.can_receive());
        assert!(iface.can_transmit());
        assert!(!iface.is_connected());
    }

    #[test]
    fn multicast_addr_matches_config() {
        let mut config = AutoConfig::new("test");
        config.group_id = b"reticulum".to_vec();
        config.discovery_scope = super::super::DiscoveryScope::Link;
        config.multicast_address_type = super::super::MulticastAddressType::Temporary;

        let iface = AutoInterface::new(config, InterfaceId(101));

        // Should match the independently computed address.
        let expected = derive_multicast_address(
            b"reticulum",
            super::super::DiscoveryScope::Link,
            super::super::MulticastAddressType::Temporary,
        );
        assert_eq!(iface.multicast_addr, expected);
    }

    #[tokio::test]
    async fn transmit_when_not_started() {
        let config = AutoConfig::new("test-not-started");
        let iface = AutoInterface::new(config, InterfaceId(102));

        let result = iface.transmit(&[0x01; 20]).await;
        assert!(matches!(result, Err(InterfaceError::NotConnected)));
    }
}
