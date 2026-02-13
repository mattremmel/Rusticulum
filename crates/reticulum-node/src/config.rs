//! TOML-based configuration for Reticulum nodes.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use reticulum_interfaces::InterfaceMode;

use crate::error::NodeError;

/// Top-level node configuration loaded from a TOML file.
#[derive(Debug, Default, Deserialize)]
pub struct NodeConfig {
    #[serde(default)]
    pub node: NodeSection,
    #[serde(default)]
    pub logging: LoggingSection,
    #[serde(default)]
    pub interfaces: InterfacesSection,
}

impl NodeConfig {
    /// Load configuration from a TOML file.
    pub fn load(path: &Path) -> Result<Self, NodeError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| NodeError::Config(format!("failed to read config file: {e}")))?;
        toml::from_str(&content)
            .map_err(|e| NodeError::Config(format!("failed to parse config: {e}")))
    }

    /// Parse configuration from a TOML string.
    pub fn parse(s: &str) -> Result<Self, NodeError> {
        toml::from_str(s).map_err(|e| NodeError::Config(format!("failed to parse config: {e}")))
    }
}

/// The `[node]` section.
#[derive(Debug, Deserialize)]
pub struct NodeSection {
    #[serde(default)]
    pub enable_transport: bool,
    pub network_name: Option<String>,
    pub network_key: Option<String>,
    #[serde(default = "default_ifac_size")]
    pub ifac_size: u8,
}

fn default_ifac_size() -> u8 {
    8
}

impl Default for NodeSection {
    fn default() -> Self {
        Self {
            enable_transport: false,
            network_name: None,
            network_key: None,
            ifac_size: default_ifac_size(),
        }
    }
}

/// The `[logging]` section.
#[derive(Debug, Deserialize)]
pub struct LoggingSection {
    #[serde(default = "default_log_level")]
    pub level: String,
}

fn default_log_level() -> String {
    "info".to_string()
}

impl Default for LoggingSection {
    fn default() -> Self {
        Self {
            level: default_log_level(),
        }
    }
}

/// The `[interfaces]` section containing arrays of interface configs.
#[derive(Debug, Default, Deserialize)]
pub struct InterfacesSection {
    #[serde(default)]
    pub tcp_client: Vec<TcpClientEntry>,
    #[serde(default)]
    pub tcp_server: Vec<TcpServerEntry>,
    #[serde(default)]
    pub udp: Vec<UdpEntry>,
    #[serde(default)]
    pub local_server: Vec<LocalServerEntry>,
    #[serde(default)]
    pub local_client: Vec<LocalClientEntry>,
    #[serde(default)]
    pub auto: Vec<AutoEntry>,
}

/// A `[[interfaces.tcp_client]]` entry.
#[derive(Debug, Deserialize)]
pub struct TcpClientEntry {
    pub name: String,
    pub target: String,
    #[serde(default = "default_mode_str")]
    pub mode: String,
}

/// A `[[interfaces.tcp_server]]` entry.
#[derive(Debug, Deserialize)]
pub struct TcpServerEntry {
    pub name: String,
    pub bind: String,
    #[serde(default = "default_mode_str")]
    pub mode: String,
}

/// A `[[interfaces.udp]]` entry.
#[derive(Debug, Deserialize)]
pub struct UdpEntry {
    pub name: String,
    pub bind: String,
    pub target: Option<String>,
    #[serde(default)]
    pub broadcast: bool,
    #[serde(default = "default_mode_str")]
    pub mode: String,
}

/// A `[[interfaces.local_server]]` entry.
#[derive(Debug, Deserialize)]
pub struct LocalServerEntry {
    pub name: String,
    pub path: String,
    #[serde(default = "default_mode_str")]
    pub mode: String,
}

/// A `[[interfaces.local_client]]` entry.
#[derive(Debug, Deserialize)]
pub struct LocalClientEntry {
    pub name: String,
    pub path: String,
    #[serde(default = "default_mode_str")]
    pub mode: String,
}

/// A `[[interfaces.auto]]` entry.
#[derive(Debug, Deserialize)]
pub struct AutoEntry {
    pub name: String,
    pub group_id: Option<String>,
    pub discovery_port: Option<u16>,
    pub data_port: Option<u16>,
    #[serde(default = "default_mode_str")]
    pub mode: String,
}

fn default_mode_str() -> String {
    "full".to_string()
}

/// Parse a mode string to an `InterfaceMode`.
pub fn parse_mode(s: &str) -> Result<InterfaceMode, NodeError> {
    match s.to_lowercase().as_str() {
        "full" => Ok(InterfaceMode::Full),
        "pointtopoint" | "point_to_point" => Ok(InterfaceMode::PointToPoint),
        "accesspoint" | "access_point" | "ap" => Ok(InterfaceMode::AccessPoint),
        "roaming" => Ok(InterfaceMode::Roaming),
        "boundary" => Ok(InterfaceMode::Boundary),
        "gateway" => Ok(InterfaceMode::Gateway),
        other => Err(NodeError::Config(format!(
            "unknown interface mode: {other}"
        ))),
    }
}

/// Parse a socket address string like "0.0.0.0:4242".
pub fn parse_socket_addr(s: &str) -> Result<SocketAddr, NodeError> {
    s.parse()
        .map_err(|e| NodeError::Config(format!("invalid socket address '{s}': {e}")))
}

/// Parse a file path string.
pub fn parse_path(s: &str) -> PathBuf {
    PathBuf::from(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_config() {
        let config = NodeConfig::parse("").unwrap();
        assert!(!config.node.enable_transport);
        assert_eq!(config.logging.level, "info");
        assert!(config.interfaces.tcp_client.is_empty());
        assert!(config.interfaces.udp.is_empty());
        assert!(config.interfaces.auto.is_empty());
    }

    #[test]
    fn parse_full_config() {
        let toml = r#"
[node]
enable_transport = true
network_name = "testnet"
network_key = "secret"
ifac_size = 16

[logging]
level = "debug"

[[interfaces.tcp_client]]
name = "TCP Peer"
target = "192.168.1.10:4242"

[[interfaces.tcp_server]]
name = "TCP Server"
bind = "0.0.0.0:4242"

[[interfaces.udp]]
name = "UDP Broadcast"
bind = "0.0.0.0:4243"
target = "255.255.255.255:4243"
broadcast = true

[[interfaces.udp]]
name = "UDP Unicast"
bind = "0.0.0.0:4244"
target = "192.168.1.20:4244"

[[interfaces.local_server]]
name = "Local Server"
path = "/tmp/rns_default.sock"

[[interfaces.local_client]]
name = "Local Client"
path = "/tmp/rns_default.sock"

[[interfaces.auto]]
name = "Auto"
group_id = "mygroup"
discovery_port = 29716
data_port = 42671
"#;
        let config = NodeConfig::parse(toml).unwrap();
        assert!(config.node.enable_transport);
        assert_eq!(config.node.network_name.as_deref(), Some("testnet"));
        assert_eq!(config.node.network_key.as_deref(), Some("secret"));
        assert_eq!(config.node.ifac_size, 16);
        assert_eq!(config.logging.level, "debug");
        assert_eq!(config.interfaces.tcp_client.len(), 1);
        assert_eq!(config.interfaces.tcp_client[0].name, "TCP Peer");
        assert_eq!(config.interfaces.tcp_server.len(), 1);
        assert_eq!(config.interfaces.udp.len(), 2);
        assert!(config.interfaces.udp[1].target.is_some());
        assert!(!config.interfaces.udp[1].broadcast);
        assert_eq!(config.interfaces.local_server.len(), 1);
        assert_eq!(config.interfaces.local_client.len(), 1);
        assert_eq!(config.interfaces.auto.len(), 1);
        assert_eq!(
            config.interfaces.auto[0].group_id.as_deref(),
            Some("mygroup")
        );
    }

    #[test]
    fn parse_mode_variants() {
        assert_eq!(parse_mode("full").unwrap(), InterfaceMode::Full);
        assert_eq!(parse_mode("Full").unwrap(), InterfaceMode::Full);
        assert_eq!(
            parse_mode("accesspoint").unwrap(),
            InterfaceMode::AccessPoint
        );
        assert_eq!(parse_mode("ap").unwrap(), InterfaceMode::AccessPoint);
        assert_eq!(parse_mode("roaming").unwrap(), InterfaceMode::Roaming);
        assert_eq!(
            parse_mode("pointtopoint").unwrap(),
            InterfaceMode::PointToPoint
        );
        assert_eq!(parse_mode("boundary").unwrap(), InterfaceMode::Boundary);
        assert_eq!(parse_mode("gateway").unwrap(), InterfaceMode::Gateway);
        assert!(parse_mode("invalid").is_err());
    }
}
