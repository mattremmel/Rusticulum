//! Protocol error types.
//!
//! These errors cover all protocol-layer failures: link handshake,
//! channel messaging, resource transfers, buffer streams, and requests.

use reticulum_core::error::{IdentityError, PacketError};
use reticulum_crypto::CryptoError;

#[derive(Debug, thiserror::Error)]
pub enum LinkError {
    #[error("handshake failed: {0}")]
    HandshakeFailed(String),

    #[error("invalid link proof")]
    InvalidProof,

    #[error("signature verification failed")]
    SignatureVerificationFailed,

    #[error("invalid state: expected {expected}, got {actual}")]
    InvalidState {
        expected: &'static str,
        actual: &'static str,
    },

    #[error("unsupported link mode: {0}")]
    UnsupportedMode(u8),

    #[error("encryption failed: {0}")]
    EncryptionFailed(#[from] CryptoError),

    #[error("identity error: {0}")]
    IdentityError(#[from] IdentityError),

    #[error("packet error: {0}")]
    PacketError(#[from] PacketError),

    #[error("no private key available")]
    NoPrivateKey,
}

#[derive(Debug, thiserror::Error)]
pub enum ChannelError {
    #[error("channel not ready")]
    NotReady,

    #[error("message too large: {size} bytes (max {max})")]
    MessageTooLarge { size: usize, max: usize },

    #[error("invalid envelope: {0}")]
    InvalidEnvelope(String),

    #[error("sequence error: expected {expected}, got {actual}")]
    SequenceError { expected: u16, actual: u16 },

    #[error("link error: {0}")]
    LinkError(#[from] LinkError),
}

#[derive(Debug, thiserror::Error)]
pub enum ResourceError {
    #[error("resource too large: {0} bytes")]
    TooLarge(usize),

    #[error("invalid advertisement: {0}")]
    InvalidAdvertisement(String),

    #[error("invalid part hash at index {0}")]
    InvalidPartHash(usize),

    #[error("transfer failed: {0}")]
    TransferFailed(String),

    #[error("proof verification failed")]
    ProofFailed,

    #[error("resource transfer timed out")]
    Timeout,

    #[error("link error: {0}")]
    LinkError(#[from] LinkError),

    #[error("channel error: {0}")]
    ChannelError(#[from] ChannelError),
}

#[derive(Debug, thiserror::Error)]
pub enum BufferError {
    #[error("buffer closed")]
    Closed,

    #[error("compression failed: {0}")]
    CompressionFailed(String),

    #[error("invalid stream header")]
    InvalidStreamHeader,

    #[error("channel error: {0}")]
    ChannelError(#[from] ChannelError),
}

#[derive(Debug, thiserror::Error)]
pub enum RequestError {
    #[error("request timed out")]
    Timeout,

    #[error("request failed: {0}")]
    Failed(String),

    #[error("request payload too large")]
    TooLarge,

    #[error("link error: {0}")]
    LinkError(#[from] LinkError),

    #[error("resource error: {0}")]
    ResourceError(#[from] ResourceError),
}
