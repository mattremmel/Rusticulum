//! Node orchestration for the Reticulum network stack.
//!
//! This crate ties together all protocol layers, providing configuration,
//! storage, and runtime management for a Reticulum node.

pub(crate) mod announce_builder;
pub(crate) mod announce_processing;
pub(crate) mod auto_data_plan;
pub mod channel_manager;
pub(crate) mod channel_ops;
pub mod config;
pub mod error;
pub(crate) mod handler_rules;
pub(crate) mod identity_loading;
pub(crate) mod inbound_triage;
pub mod interface_enum;
pub(crate) mod interface_planning;
pub(crate) mod link_dispatch;
pub(crate) mod link_initiation;
pub(crate) mod link_lifecycle;
pub mod link_manager;
pub(crate) mod link_packets;
pub(crate) mod link_response;
pub mod logging;
pub(crate) mod maintenance_ops;
pub mod node;
pub(crate) mod node_init;
pub(crate) mod packet_helpers;
pub(crate) mod packet_outcome;
pub(crate) mod post_transfer_drain;
pub(crate) mod resource_assembly;
pub mod resource_manager;
pub(crate) mod resource_ops;
pub(crate) mod routing;
pub mod storage;
pub(crate) mod storage_codec;
pub(crate) mod transmit_filter;
pub(crate) mod transport_guard;

pub use config::NodeConfig;
pub use error::NodeError;
pub use interface_enum::AnyInterface;
pub use node::{Node, ShutdownHandle};
pub use storage::Storage;
