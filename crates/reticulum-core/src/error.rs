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

#[cfg(test)]
mod tests {
    extern crate alloc;
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn test_packet_error_display_all_variants() {
        let variants: &[PacketError] = &[
            PacketError::TooShort { min: 19, actual: 5 },
            PacketError::InvalidHeaderType(0xFF),
            PacketError::InvalidTransportType(0x03),
            PacketError::InvalidDestinationType(0x04),
            PacketError::InvalidPacketType(0x05),
            PacketError::InvalidContextType(0x10),
            PacketError::InvalidDestinationHash,
        ];
        for v in variants {
            let msg = v.to_string();
            assert!(!msg.is_empty(), "{v:?} should have non-empty Display");
        }
    }

    #[test]
    fn test_identity_error_display_all_variants() {
        let variants: Vec<IdentityError> = vec![
            IdentityError::NoPrivateKey,
            IdentityError::InvalidKeyLength {
                expected: 32,
                actual: 16,
            },
            IdentityError::DecryptionFailed,
            IdentityError::SignatureVerificationFailed,
            IdentityError::CryptoError(CryptoError::InvalidHmac),
            IdentityError::PayloadTooShort {
                min: 64,
                actual: 10,
            },
        ];
        for v in &variants {
            let msg = v.to_string();
            assert!(!msg.is_empty(), "{v:?} should have non-empty Display");
        }
    }

    #[test]
    fn test_framing_error_display_all_variants() {
        let variants: &[FramingError] = &[
            FramingError::MissingDelimiter,
            FramingError::IncompleteEscape,
            FramingError::InvalidEscapeSequence(0xAB),
        ];
        for v in variants {
            let msg = v.to_string();
            assert!(!msg.is_empty(), "{v:?} should have non-empty Display");
        }
    }

    #[test]
    fn test_announce_error_display_and_from() {
        let variants: Vec<AnnounceError> = vec![
            AnnounceError::PayloadTooShort {
                min: 100,
                actual: 10,
            },
            AnnounceError::InvalidSignature("bad sig".into()),
            AnnounceError::InvalidDestinationHash,
            AnnounceError::IdentityError(IdentityError::NoPrivateKey),
            AnnounceError::PacketError(PacketError::InvalidDestinationHash),
        ];
        for v in &variants {
            let msg = v.to_string();
            assert!(!msg.is_empty(), "{v:?} should have non-empty Display");
        }

        // Test From<IdentityError>
        let ie = IdentityError::DecryptionFailed;
        let ae: AnnounceError = ie.into();
        assert!(matches!(ae, AnnounceError::IdentityError(_)));

        // Test From<PacketError>
        let pe = PacketError::InvalidHeaderType(0x03);
        let ae: AnnounceError = pe.into();
        assert!(matches!(ae, AnnounceError::PacketError(_)));
    }
}
