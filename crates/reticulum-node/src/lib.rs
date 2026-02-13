//! Node orchestration for the Reticulum network stack.
//!
//! This crate ties together all protocol layers, providing configuration,
//! storage, and runtime management for a Reticulum node.

pub mod config;
pub mod error;
pub mod interface_enum;
pub mod logging;
pub mod node;

pub use config::NodeConfig;
pub use error::NodeError;
pub use interface_enum::AnyInterface;
pub use node::Node;
