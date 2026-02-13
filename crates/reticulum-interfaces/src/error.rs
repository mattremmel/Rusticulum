//! Error types for the interfaces layer.

use reticulum_core::error::FramingError;

/// Errors that can occur during interface operations.
#[derive(Debug, thiserror::Error)]
pub enum InterfaceError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("framing error: {0}")]
    Framing(#[from] FramingError),
    #[error("interface not connected")]
    NotConnected,
    #[error("interface stopped")]
    Stopped,
    #[error("transmit failed: {0}")]
    TransmitFailed(String),
    #[error("receive failed: {0}")]
    ReceiveFailed(String),
    #[error("configuration error: {0}")]
    Configuration(String),
}
