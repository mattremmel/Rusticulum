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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display_variants() {
        let io_err = InterfaceError::Io(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "broken pipe",
        ));
        assert!(io_err.to_string().contains("I/O error"));

        let nc = InterfaceError::NotConnected;
        assert_eq!(nc.to_string(), "interface not connected");

        let stopped = InterfaceError::Stopped;
        assert_eq!(stopped.to_string(), "interface stopped");

        let tx = InterfaceError::TransmitFailed("buffer full".into());
        assert!(tx.to_string().contains("transmit failed"));
        assert!(tx.to_string().contains("buffer full"));

        let rx = InterfaceError::ReceiveFailed("timeout".into());
        assert!(rx.to_string().contains("receive failed"));

        let cfg = InterfaceError::Configuration("bad config".into());
        assert!(cfg.to_string().contains("configuration error"));
    }

    #[test]
    fn test_error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "not found");
        let iface_err: InterfaceError = io_err.into();
        assert!(matches!(iface_err, InterfaceError::Io(_)));
        assert!(iface_err.to_string().contains("not found"));
    }
}
