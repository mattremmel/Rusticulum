//! Error types for the node orchestrator.

use reticulum_interfaces::InterfaceError;

/// Errors that can occur during node operation.
#[derive(Debug, thiserror::Error)]
pub enum NodeError {
    #[error("configuration error: {0}")]
    Config(String),
    #[error("interface error: {0}")]
    Interface(#[from] InterfaceError),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("router error: {0}")]
    Router(&'static str),
    #[error("identity error: {0}")]
    Identity(&'static str),
    #[error("IFAC error: {0}")]
    Ifac(&'static str),
    #[error("storage error: {0}")]
    Storage(#[from] crate::storage::StorageError),
    #[error("node not started")]
    NotStarted,
    #[error("node already running")]
    AlreadyRunning,
}
