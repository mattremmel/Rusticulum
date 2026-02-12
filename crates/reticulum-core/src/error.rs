//! Error types for the reticulum-core crate.

extern crate alloc;
use alloc::string::String;
use core::fmt;

use reticulum_crypto::CryptoError;

#[derive(Debug)]
pub enum PacketError {
    TooShort { min: usize, actual: usize },
    InvalidHeaderType(u8),
    InvalidTransportType(u8),
    InvalidDestinationType(u8),
    InvalidPacketType(u8),
    InvalidContextType(u8),
    InvalidDestinationHash,
}

impl fmt::Display for PacketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PacketError::TooShort { min, actual } => {
                write!(
                    f,
                    "packet too short: need at least {min} bytes, got {actual}"
                )
            }
            PacketError::InvalidHeaderType(v) => write!(f, "invalid header type: {v}"),
            PacketError::InvalidTransportType(v) => write!(f, "invalid transport type: {v}"),
            PacketError::InvalidDestinationType(v) => {
                write!(f, "invalid destination type: {v}")
            }
            PacketError::InvalidPacketType(v) => write!(f, "invalid packet type: {v}"),
            PacketError::InvalidContextType(v) => write!(f, "invalid context type: {v}"),
            PacketError::InvalidDestinationHash => write!(f, "invalid destination hash"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PacketError {}

#[derive(Debug)]
pub enum IdentityError {
    NoPrivateKey,
    InvalidKeyLength { expected: usize, actual: usize },
    DecryptionFailed,
    SignatureVerificationFailed,
    CryptoError(CryptoError),
    PayloadTooShort { min: usize, actual: usize },
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IdentityError::NoPrivateKey => write!(f, "no private key available"),
            IdentityError::InvalidKeyLength { expected, actual } => {
                write!(f, "invalid key length: expected {expected}, got {actual}")
            }
            IdentityError::DecryptionFailed => write!(f, "decryption failed"),
            IdentityError::SignatureVerificationFailed => {
                write!(f, "signature verification failed")
            }
            IdentityError::CryptoError(e) => write!(f, "crypto error: {e}"),
            IdentityError::PayloadTooShort { min, actual } => {
                write!(
                    f,
                    "payload too short: need at least {min} bytes, got {actual}"
                )
            }
        }
    }
}

impl From<CryptoError> for IdentityError {
    fn from(e: CryptoError) -> Self {
        IdentityError::CryptoError(e)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for IdentityError {}

#[derive(Debug)]
pub enum FramingError {
    MissingDelimiter,
    IncompleteEscape,
    InvalidEscapeSequence(u8),
}

impl fmt::Display for FramingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FramingError::MissingDelimiter => write!(f, "missing frame delimiter"),
            FramingError::IncompleteEscape => write!(f, "incomplete escape sequence"),
            FramingError::InvalidEscapeSequence(v) => {
                write!(f, "invalid escape sequence: 0x{v:02x}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for FramingError {}

#[derive(Debug)]
pub enum AnnounceError {
    PayloadTooShort { min: usize, actual: usize },
    InvalidSignature(String),
    InvalidDestinationHash,
    IdentityError(IdentityError),
    PacketError(PacketError),
}

impl fmt::Display for AnnounceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AnnounceError::PayloadTooShort { min, actual } => {
                write!(
                    f,
                    "announce payload too short: need at least {min} bytes, got {actual}"
                )
            }
            AnnounceError::InvalidSignature(reason) => {
                write!(f, "invalid announce signature: {reason}")
            }
            AnnounceError::InvalidDestinationHash => {
                write!(f, "destination hash does not match identity")
            }
            AnnounceError::IdentityError(e) => write!(f, "identity error: {e}"),
            AnnounceError::PacketError(e) => write!(f, "packet error: {e}"),
        }
    }
}

impl From<IdentityError> for AnnounceError {
    fn from(e: IdentityError) -> Self {
        AnnounceError::IdentityError(e)
    }
}

impl From<PacketError> for AnnounceError {
    fn from(e: PacketError) -> Self {
        AnnounceError::PacketError(e)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for AnnounceError {}
