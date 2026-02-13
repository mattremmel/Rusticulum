//! Transport layer error types.

use reticulum_core::error::{AnnounceError, IdentityError, PacketError};
use reticulum_crypto::CryptoError;
use reticulum_protocol::error::LinkError;

#[derive(Debug, thiserror::Error)]
pub enum RouterError {
    #[error("packet error: {0}")]
    PacketError(#[from] PacketError),

    #[error("link error: {0}")]
    LinkError(#[from] LinkError),

    #[error("announce error: {0}")]
    AnnounceError(#[from] AnnounceError),

    #[error("duplicate packet")]
    DuplicatePacket,

    #[error("max hops exceeded: {0}")]
    MaxHopsExceeded(u8),

    #[error("no path to destination: {0}")]
    NoPath(String),

    #[error("invalid header transformation: {0}")]
    InvalidTransformation(String),
}

#[derive(Debug, thiserror::Error)]
pub enum PathError {
    #[error("path not found: {0}")]
    NotFound(String),

    #[error("path expired")]
    Expired,

    #[error("invalid interface mode: {0}")]
    InvalidInterfaceMode(String),

    #[error("packet error: {0}")]
    PacketError(#[from] PacketError),
}

#[derive(Debug, thiserror::Error)]
pub enum IfacError {
    #[error("authentication failed")]
    AuthenticationFailed,

    #[error("missing ifac flag")]
    MissingFlag,

    #[error("unexpected ifac flag")]
    UnexpectedFlag,

    #[error("packet too short for ifac: need {min} bytes, got {actual}")]
    PacketTooShort { min: usize, actual: usize },

    #[error("identity error: {0}")]
    IdentityError(#[from] IdentityError),

    #[error("crypto error: {0}")]
    CryptoError(#[from] CryptoError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_router_error_display() {
        let err = RouterError::DuplicatePacket;
        assert_eq!(err.to_string(), "duplicate packet");

        let err = RouterError::MaxHopsExceeded(129);
        assert_eq!(err.to_string(), "max hops exceeded: 129");
    }

    #[test]
    fn test_path_error_display() {
        let err = PathError::Expired;
        assert_eq!(err.to_string(), "path expired");

        let err = PathError::NotFound("abcd1234".to_string());
        assert_eq!(err.to_string(), "path not found: abcd1234");
    }

    #[test]
    fn test_ifac_error_display() {
        let err = IfacError::AuthenticationFailed;
        assert_eq!(err.to_string(), "authentication failed");

        let err = IfacError::PacketTooShort {
            min: 20,
            actual: 10,
        };
        assert_eq!(
            err.to_string(),
            "packet too short for ifac: need 20 bytes, got 10"
        );
    }

    #[test]
    fn test_router_error_from_packet_error() {
        let pe = PacketError::TooShort { min: 19, actual: 5 };
        let re: RouterError = pe.into();
        assert!(matches!(re, RouterError::PacketError(_)));
    }

    #[test]
    fn test_ifac_error_from_crypto_error() {
        let ce = CryptoError::InvalidKeyLength {
            expected: 32,
            actual: 16,
        };
        let ie: IfacError = ce.into();
        assert!(matches!(ie, IfacError::CryptoError(_)));
    }
}
