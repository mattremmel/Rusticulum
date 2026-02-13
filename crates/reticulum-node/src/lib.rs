//! Node orchestration for the Reticulum network stack.
//!
//! This crate ties together all protocol layers, providing configuration,
//! storage, and runtime management for a Reticulum node.

pub mod config;
pub mod error;
pub mod interface_enum;
pub mod channel_manager;
pub mod link_manager;
pub mod logging;
pub mod node;
pub mod resource_manager;
pub mod routing;
pub mod storage;

pub use config::NodeConfig;
pub use error::NodeError;
pub use interface_enum::AnyInterface;
pub use node::{Node, ShutdownHandle};
pub use storage::Storage;
