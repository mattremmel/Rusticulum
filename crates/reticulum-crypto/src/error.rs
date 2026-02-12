use core::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    InvalidKeyLength { expected: usize, actual: usize },
    InvalidSignature,
    InvalidPadding,
    DecryptionFailed,
    InvalidHmac,
    InvalidLength { reason: &'static str },
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::InvalidKeyLength { expected, actual } => {
                write!(f, "invalid key length: expected {expected}, got {actual}")
            }
            CryptoError::InvalidSignature => write!(f, "invalid signature"),
            CryptoError::InvalidPadding => write!(f, "invalid PKCS7 padding"),
            CryptoError::DecryptionFailed => write!(f, "decryption failed"),
            CryptoError::InvalidHmac => write!(f, "HMAC verification failed"),
            CryptoError::InvalidLength { reason } => write!(f, "invalid length: {reason}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CryptoError {}
