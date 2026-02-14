//! Pure interface creation planning.
//!
//! Extracts the interface config → spec conversion logic from `node.rs`
//! into pure functions, making every configuration combination testable
//! without I/O or network resources.

use std::net::SocketAddr;
use std::path::PathBuf;

use reticulum_interfaces::InterfaceMode;
use reticulum_transport::path::types::InterfaceId;

use crate::config::{InterfacesSection, parse_mode, parse_path, parse_socket_addr};

/// A fully-validated specification for creating an interface.
///
/// This is a pure data type with no I/O — it captures the validated
/// configuration needed to instantiate the actual interface object.
#[derive(Debug, Clone, PartialEq)]
pub enum InterfaceSpec {
    TcpClient {
        name: String,
        target: String,
        mode: InterfaceMode,
        id: InterfaceId,
    },
    TcpServer {
        name: String,
        bind: SocketAddr,
        mode: InterfaceMode,
        id: InterfaceId,
    },
    Udp {
        name: String,
        bind: SocketAddr,
        target: Option<SocketAddr>,
        broadcast: bool,
        mode: InterfaceMode,
        id: InterfaceId,
    },
    LocalServer {
        name: String,
        path: PathBuf,
        mode: InterfaceMode,
        id: InterfaceId,
    },
    LocalClient {
        name: String,
        path: PathBuf,
        mode: InterfaceMode,
        id: InterfaceId,
    },
    Auto {
        name: String,
        mode: InterfaceMode,
        group_id: Option<Vec<u8>>,
        discovery_port: Option<u16>,
        data_port: Option<u16>,
        id: InterfaceId,
    },
}

impl InterfaceSpec {
    /// Returns the interface ID.
    pub fn id(&self) -> InterfaceId {
        match self {
            InterfaceSpec::TcpClient { id, .. }
            | InterfaceSpec::TcpServer { id, .. }
            | InterfaceSpec::Udp { id, .. }
            | InterfaceSpec::LocalServer { id, .. }
            | InterfaceSpec::LocalClient { id, .. }
            | InterfaceSpec::Auto { id, .. } => *id,
        }
    }
}

/// Plan TCP client interface specs from config entries.
pub fn plan_tcp_clients(
    entries: &[crate::config::TcpClientEntry],
    id_start: u64,
) -> Result<Vec<InterfaceSpec>, String> {
    let mut specs = Vec::with_capacity(entries.len());
    for (i, entry) in entries.iter().enumerate() {
        let id = InterfaceId(id_start + i as u64);
        let mode = parse_mode(&entry.mode).map_err(|e| format!("{e}"))?;
        specs.push(InterfaceSpec::TcpClient {
            name: entry.name.clone(),
            target: entry.target.clone(),
            mode,
            id,
        });
    }
    Ok(specs)
}

/// Plan TCP server interface specs from config entries.
pub fn plan_tcp_servers(
    entries: &[crate::config::TcpServerEntry],
    id_start: u64,
) -> Result<Vec<InterfaceSpec>, String> {
    let mut specs = Vec::with_capacity(entries.len());
    for (i, entry) in entries.iter().enumerate() {
        let id = InterfaceId(id_start + i as u64);
        let addr = parse_socket_addr(&entry.bind).map_err(|e| format!("{e}"))?;
        let mode = parse_mode(&entry.mode).map_err(|e| format!("{e}"))?;
        specs.push(InterfaceSpec::TcpServer {
            name: entry.name.clone(),
            bind: addr,
            mode,
            id,
        });
    }
    Ok(specs)
}

/// Plan UDP interface specs from config entries.
///
/// Handles broadcast, unicast, and receive-only variants based on
/// whether a target address is specified and the broadcast flag.
pub fn plan_udp(
    entries: &[crate::config::UdpEntry],
    id_start: u64,
) -> Result<Vec<InterfaceSpec>, String> {
    let mut specs = Vec::with_capacity(entries.len());
    for (i, entry) in entries.iter().enumerate() {
        let id = InterfaceId(id_start + i as u64);
        let bind = parse_socket_addr(&entry.bind).map_err(|e| format!("{e}"))?;
        let mode = parse_mode(&entry.mode).map_err(|e| format!("{e}"))?;
        let target = match &entry.target {
            Some(t) => Some(parse_socket_addr(t).map_err(|e| format!("{e}"))?),
            None => None,
        };
        specs.push(InterfaceSpec::Udp {
            name: entry.name.clone(),
            bind,
            target,
            broadcast: entry.broadcast,
            mode,
            id,
        });
    }
    Ok(specs)
}

/// Plan local server interface specs from config entries.
pub fn plan_local_servers(
    entries: &[crate::config::LocalServerEntry],
    id_start: u64,
) -> Result<Vec<InterfaceSpec>, String> {
    let mut specs = Vec::with_capacity(entries.len());
    for (i, entry) in entries.iter().enumerate() {
        let id = InterfaceId(id_start + i as u64);
        let mode = parse_mode(&entry.mode).map_err(|e| format!("{e}"))?;
        let path = parse_path(&entry.path);
        specs.push(InterfaceSpec::LocalServer {
            name: entry.name.clone(),
            path,
            mode,
            id,
        });
    }
    Ok(specs)
}

/// Plan local client interface specs from config entries.
pub fn plan_local_clients(
    entries: &[crate::config::LocalClientEntry],
    id_start: u64,
) -> Result<Vec<InterfaceSpec>, String> {
    let mut specs = Vec::with_capacity(entries.len());
    for (i, entry) in entries.iter().enumerate() {
        let id = InterfaceId(id_start + i as u64);
        let mode = parse_mode(&entry.mode).map_err(|e| format!("{e}"))?;
        let path = parse_path(&entry.path);
        specs.push(InterfaceSpec::LocalClient {
            name: entry.name.clone(),
            path,
            mode,
            id,
        });
    }
    Ok(specs)
}

/// Plan auto-discovery interface specs from config entries.
pub fn plan_auto(
    entries: &[crate::config::AutoEntry],
    id_start: u64,
) -> Result<Vec<InterfaceSpec>, String> {
    let mut specs = Vec::with_capacity(entries.len());
    for (i, entry) in entries.iter().enumerate() {
        let id = InterfaceId(id_start + i as u64);
        let mode = parse_mode(&entry.mode).map_err(|e| format!("{e}"))?;
        specs.push(InterfaceSpec::Auto {
            name: entry.name.clone(),
            mode,
            group_id: entry.group_id.as_ref().map(|g| g.as_bytes().to_vec()),
            discovery_port: entry.discovery_port,
            data_port: entry.data_port,
            id,
        });
    }
    Ok(specs)
}

/// Plan all interfaces from the full config.
///
/// Returns the list of specs and the next available interface ID.
pub fn plan_all_interfaces(
    interfaces: &InterfacesSection,
    id_start: u64,
) -> Result<(Vec<InterfaceSpec>, u64), String> {
    let mut all = Vec::new();
    let mut next_id = id_start;

    let tcp_clients = plan_tcp_clients(&interfaces.tcp_client, next_id)?;
    next_id += tcp_clients.len() as u64;
    all.extend(tcp_clients);

    let tcp_servers = plan_tcp_servers(&interfaces.tcp_server, next_id)?;
    next_id += tcp_servers.len() as u64;
    all.extend(tcp_servers);

    let udp = plan_udp(&interfaces.udp, next_id)?;
    next_id += udp.len() as u64;
    all.extend(udp);

    let local_servers = plan_local_servers(&interfaces.local_server, next_id)?;
    next_id += local_servers.len() as u64;
    all.extend(local_servers);

    let local_clients = plan_local_clients(&interfaces.local_client, next_id)?;
    next_id += local_clients.len() as u64;
    all.extend(local_clients);

    let autos = plan_auto(&interfaces.auto, next_id)?;
    next_id += autos.len() as u64;
    all.extend(autos);

    Ok((all, next_id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::NodeConfig;

    #[test]
    fn empty_config_produces_no_specs() {
        let config = NodeConfig::default();
        let (specs, next_id) = plan_all_interfaces(&config.interfaces, 1).unwrap();
        assert!(specs.is_empty());
        assert_eq!(next_id, 1);
    }

    #[test]
    fn tcp_client_valid() {
        let toml = r#"
[[interfaces.tcp_client]]
name = "peer1"
target = "192.168.1.10:4242"

[[interfaces.tcp_client]]
name = "peer2"
target = "localhost:4243"
mode = "roaming"
"#;
        let config = NodeConfig::parse(toml).unwrap();
        let specs = plan_tcp_clients(&config.interfaces.tcp_client, 10).unwrap();

        assert_eq!(specs.len(), 2);
        match &specs[0] {
            InterfaceSpec::TcpClient { name, target, mode, id } => {
                assert_eq!(name, "peer1");
                assert_eq!(target, "192.168.1.10:4242");
                assert_eq!(*mode, InterfaceMode::Full);
                assert_eq!(*id, InterfaceId(10));
            }
            other => panic!("expected TcpClient, got: {other:?}"),
        }
        match &specs[1] {
            InterfaceSpec::TcpClient { name, mode, id, .. } => {
                assert_eq!(name, "peer2");
                assert_eq!(*mode, InterfaceMode::Roaming);
                assert_eq!(*id, InterfaceId(11));
            }
            other => panic!("expected TcpClient, got: {other:?}"),
        }
    }

    #[test]
    fn tcp_client_invalid_mode() {
        let toml = r#"
[[interfaces.tcp_client]]
name = "bad"
target = "localhost:4242"
mode = "invalid_mode"
"#;
        let config = NodeConfig::parse(toml).unwrap();
        let result = plan_tcp_clients(&config.interfaces.tcp_client, 1);
        assert!(result.is_err());
    }

    #[test]
    fn tcp_server_valid() {
        let toml = r#"
[[interfaces.tcp_server]]
name = "server1"
bind = "0.0.0.0:4242"
mode = "accesspoint"
"#;
        let config = NodeConfig::parse(toml).unwrap();
        let specs = plan_tcp_servers(&config.interfaces.tcp_server, 5).unwrap();

        assert_eq!(specs.len(), 1);
        match &specs[0] {
            InterfaceSpec::TcpServer { name, bind, mode, id } => {
                assert_eq!(name, "server1");
                assert_eq!(bind.port(), 4242);
                assert_eq!(*mode, InterfaceMode::AccessPoint);
                assert_eq!(*id, InterfaceId(5));
            }
            other => panic!("expected TcpServer, got: {other:?}"),
        }
    }

    #[test]
    fn tcp_server_invalid_bind() {
        let toml = r#"
[[interfaces.tcp_server]]
name = "bad"
bind = "not_an_address"
"#;
        let config = NodeConfig::parse(toml).unwrap();
        let result = plan_tcp_servers(&config.interfaces.tcp_server, 1);
        assert!(result.is_err());
    }

    #[test]
    fn udp_broadcast() {
        let toml = r#"
[[interfaces.udp]]
name = "broadcast"
bind = "0.0.0.0:4243"
target = "255.255.255.255:4243"
broadcast = true
"#;
        let config = NodeConfig::parse(toml).unwrap();
        let specs = plan_udp(&config.interfaces.udp, 1).unwrap();

        assert_eq!(specs.len(), 1);
        match &specs[0] {
            InterfaceSpec::Udp { name, target, broadcast, .. } => {
                assert_eq!(name, "broadcast");
                assert!(target.is_some());
                assert!(*broadcast);
            }
            other => panic!("expected Udp, got: {other:?}"),
        }
    }

    #[test]
    fn udp_unicast() {
        let toml = r#"
[[interfaces.udp]]
name = "unicast"
bind = "0.0.0.0:4244"
target = "192.168.1.20:4244"
"#;
        let config = NodeConfig::parse(toml).unwrap();
        let specs = plan_udp(&config.interfaces.udp, 1).unwrap();

        match &specs[0] {
            InterfaceSpec::Udp { target, broadcast, .. } => {
                assert!(target.is_some());
                assert!(!*broadcast);
            }
            other => panic!("expected Udp, got: {other:?}"),
        }
    }

    #[test]
    fn udp_receive_only() {
        let toml = r#"
[[interfaces.udp]]
name = "rx"
bind = "0.0.0.0:4245"
"#;
        let config = NodeConfig::parse(toml).unwrap();
        let specs = plan_udp(&config.interfaces.udp, 1).unwrap();

        match &specs[0] {
            InterfaceSpec::Udp { target, broadcast, .. } => {
                assert!(target.is_none());
                assert!(!*broadcast);
            }
            other => panic!("expected Udp, got: {other:?}"),
        }
    }

    #[test]
    fn udp_invalid_target() {
        let toml = r#"
[[interfaces.udp]]
name = "bad"
bind = "0.0.0.0:4243"
target = "not_valid"
"#;
        let config = NodeConfig::parse(toml).unwrap();
        let result = plan_udp(&config.interfaces.udp, 1);
        assert!(result.is_err());
    }

    #[test]
    fn local_server_valid() {
        let toml = r#"
[[interfaces.local_server]]
name = "local_srv"
path = "/tmp/rns.sock"
mode = "gateway"
"#;
        let config = NodeConfig::parse(toml).unwrap();
        let specs = plan_local_servers(&config.interfaces.local_server, 1).unwrap();

        assert_eq!(specs.len(), 1);
        match &specs[0] {
            InterfaceSpec::LocalServer { name, path, mode, id } => {
                assert_eq!(name, "local_srv");
                assert_eq!(path, &PathBuf::from("/tmp/rns.sock"));
                assert_eq!(*mode, InterfaceMode::Gateway);
                assert_eq!(*id, InterfaceId(1));
            }
            other => panic!("expected LocalServer, got: {other:?}"),
        }
    }

    #[test]
    fn local_client_valid() {
        let toml = r#"
[[interfaces.local_client]]
name = "local_cl"
path = "/tmp/rns.sock"
"#;
        let config = NodeConfig::parse(toml).unwrap();
        let specs = plan_local_clients(&config.interfaces.local_client, 1).unwrap();

        assert_eq!(specs.len(), 1);
        match &specs[0] {
            InterfaceSpec::LocalClient { name, path, mode, .. } => {
                assert_eq!(name, "local_cl");
                assert_eq!(path, &PathBuf::from("/tmp/rns.sock"));
                assert_eq!(*mode, InterfaceMode::Full);
            }
            other => panic!("expected LocalClient, got: {other:?}"),
        }
    }

    #[test]
    fn auto_full_config() {
        let toml = r#"
[[interfaces.auto]]
name = "auto1"
group_id = "mygroup"
discovery_port = 29716
data_port = 42671
mode = "boundary"
"#;
        let config = NodeConfig::parse(toml).unwrap();
        let specs = plan_auto(&config.interfaces.auto, 1).unwrap();

        assert_eq!(specs.len(), 1);
        match &specs[0] {
            InterfaceSpec::Auto { name, mode, group_id, discovery_port, data_port, id } => {
                assert_eq!(name, "auto1");
                assert_eq!(*mode, InterfaceMode::Boundary);
                assert_eq!(group_id.as_deref(), Some(b"mygroup".as_slice()));
                assert_eq!(*discovery_port, Some(29716));
                assert_eq!(*data_port, Some(42671));
                assert_eq!(*id, InterfaceId(1));
            }
            other => panic!("expected Auto, got: {other:?}"),
        }
    }

    #[test]
    fn auto_minimal_config() {
        let toml = r#"
[[interfaces.auto]]
name = "auto_minimal"
"#;
        let config = NodeConfig::parse(toml).unwrap();
        let specs = plan_auto(&config.interfaces.auto, 1).unwrap();

        match &specs[0] {
            InterfaceSpec::Auto { group_id, discovery_port, data_port, .. } => {
                assert!(group_id.is_none());
                assert!(discovery_port.is_none());
                assert!(data_port.is_none());
            }
            other => panic!("expected Auto, got: {other:?}"),
        }
    }

    #[test]
    fn sequential_ids_across_types() {
        let toml = r#"
[[interfaces.tcp_client]]
name = "tc1"
target = "localhost:4242"

[[interfaces.tcp_client]]
name = "tc2"
target = "localhost:4243"

[[interfaces.tcp_server]]
name = "ts1"
bind = "0.0.0.0:4242"

[[interfaces.udp]]
name = "udp1"
bind = "0.0.0.0:4243"
"#;
        let config = NodeConfig::parse(toml).unwrap();
        let (specs, next_id) = plan_all_interfaces(&config.interfaces, 1).unwrap();

        assert_eq!(specs.len(), 4);
        assert_eq!(specs[0].id(), InterfaceId(1));
        assert_eq!(specs[1].id(), InterfaceId(2));
        assert_eq!(specs[2].id(), InterfaceId(3));
        assert_eq!(specs[3].id(), InterfaceId(4));
        assert_eq!(next_id, 5);
    }

    #[test]
    fn id_start_offset() {
        let toml = r#"
[[interfaces.tcp_client]]
name = "tc1"
target = "localhost:4242"
"#;
        let config = NodeConfig::parse(toml).unwrap();
        let (specs, next_id) = plan_all_interfaces(&config.interfaces, 100).unwrap();

        assert_eq!(specs[0].id(), InterfaceId(100));
        assert_eq!(next_id, 101);
    }

    #[test]
    fn all_mode_variants() {
        let modes = ["full", "roaming", "accesspoint", "pointtopoint", "boundary", "gateway"];
        for mode_str in modes {
            let toml = format!(
                r#"
[[interfaces.tcp_client]]
name = "test"
target = "localhost:4242"
mode = "{mode_str}"
"#
            );
            let config = NodeConfig::parse(&toml).unwrap();
            let specs = plan_tcp_clients(&config.interfaces.tcp_client, 1).unwrap();
            assert_eq!(specs.len(), 1);
        }
    }

    #[test]
    fn full_mixed_config() {
        let toml = r#"
[[interfaces.tcp_client]]
name = "tc"
target = "localhost:4242"

[[interfaces.tcp_server]]
name = "ts"
bind = "0.0.0.0:4242"

[[interfaces.udp]]
name = "udp"
bind = "0.0.0.0:4243"

[[interfaces.local_server]]
name = "ls"
path = "/tmp/ls.sock"

[[interfaces.local_client]]
name = "lc"
path = "/tmp/lc.sock"

[[interfaces.auto]]
name = "auto"
"#;
        let config = NodeConfig::parse(toml).unwrap();
        let (specs, next_id) = plan_all_interfaces(&config.interfaces, 1).unwrap();

        assert_eq!(specs.len(), 6);
        assert!(matches!(specs[0], InterfaceSpec::TcpClient { .. }));
        assert!(matches!(specs[1], InterfaceSpec::TcpServer { .. }));
        assert!(matches!(specs[2], InterfaceSpec::Udp { .. }));
        assert!(matches!(specs[3], InterfaceSpec::LocalServer { .. }));
        assert!(matches!(specs[4], InterfaceSpec::LocalClient { .. }));
        assert!(matches!(specs[5], InterfaceSpec::Auto { .. }));
        assert_eq!(next_id, 7);
    }

    #[test]
    fn error_propagates_from_nested_call() {
        let toml = r#"
[[interfaces.tcp_client]]
name = "ok"
target = "localhost:4242"

[[interfaces.tcp_server]]
name = "bad_bind"
bind = "not_valid"
"#;
        let config = NodeConfig::parse(toml).unwrap();
        let result = plan_all_interfaces(&config.interfaces, 1);
        assert!(result.is_err());
    }

    #[test]
    fn interface_spec_id_accessor() {
        let spec = InterfaceSpec::TcpClient {
            name: "t".into(),
            target: "localhost:1".into(),
            mode: InterfaceMode::Full,
            id: InterfaceId(42),
        };
        assert_eq!(spec.id(), InterfaceId(42));
    }
}
