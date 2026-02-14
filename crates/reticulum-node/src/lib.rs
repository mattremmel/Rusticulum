//! Node orchestration for the Reticulum network stack.
//!
//! This crate ties together all protocol layers, providing configuration,
//! storage, and runtime management for a Reticulum node.

pub mod announce_builder;
pub mod announce_processing;
pub mod auto_data_plan;
pub mod channel_manager;
pub mod channel_ops;
pub mod config;
pub mod error;
pub mod handler_rules;
pub mod interface_enum;
pub mod interface_planning;
pub mod link_dispatch;
pub mod link_initiation;
pub mod link_manager;
pub mod link_packets;
pub mod logging;
pub mod maintenance_ops;
pub mod node;
pub mod packet_helpers;
pub mod resource_manager;
pub mod resource_ops;
pub mod routing;
pub mod storage;
pub mod transport_guard;

pub use config::NodeConfig;
pub use error::NodeError;
pub use interface_enum::AnyInterface;
pub use node::{Node, ShutdownHandle};
pub use storage::Storage;
