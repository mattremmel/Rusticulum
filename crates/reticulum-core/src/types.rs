//! Newtype wrappers for protocol byte-array fields.
//!
//! These types provide type safety, preventing accidental mixing of
//! different hash types that share the same underlying byte representation.

extern crate alloc;

use core::fmt;
use core::ops::Deref;

/// Helper to write lowercase hex without the `hex` crate.
fn fmt_hex(bytes: &[u8], f: &mut fmt::Formatter<'_>) -> fmt::Result {
    for byte in bytes {
        write!(f, "{:02x}", byte)?;
    }
    Ok(())
}

/// A 16-byte truncated hash (first 128 bits of SHA-256).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[must_use]
pub struct TruncatedHash(pub(crate) [u8; 16]);

impl TruncatedHash {
    pub const fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for TruncatedHash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<&[u8]> for TruncatedHash {
    type Error = InvalidLength;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let arr: [u8; 16] = bytes.try_into().map_err(|_| InvalidLength {
            expected: 16,
            actual: bytes.len(),
        })?;
        Ok(Self(arr))
    }
}

impl fmt::Display for TruncatedHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_hex(&self.0, f)
    }
}

impl fmt::Debug for TruncatedHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TruncatedHash(")?;
        fmt_hex(&self.0[..4], f)?;
        write!(f, "..)")
    }
}

/// A 32-byte full SHA-256 hash.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[must_use]
pub struct FullHash(pub(crate) [u8; 32]);

impl FullHash {
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for FullHash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<&[u8]> for FullHash {
    type Error = InvalidLength;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let arr: [u8; 32] = bytes.try_into().map_err(|_| InvalidLength {
            expected: 32,
            actual: bytes.len(),
        })?;
        Ok(Self(arr))
    }
}

impl fmt::Display for FullHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_hex(&self.0, f)
    }
}

impl fmt::Debug for FullHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FullHash(")?;
        fmt_hex(&self.0[..4], f)?;
        write!(f, "..)")
    }
}

/// A 10-byte name hash (first 80 bits of SHA-256).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[must_use]
pub struct NameHash(pub(crate) [u8; 10]);

impl NameHash {
    pub const fn new(bytes: [u8; 10]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for NameHash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<&[u8]> for NameHash {
    type Error = InvalidLength;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let arr: [u8; 10] = bytes.try_into().map_err(|_| InvalidLength {
            expected: 10,
            actual: bytes.len(),
        })?;
        Ok(Self(arr))
    }
}

impl fmt::Display for NameHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_hex(&self.0, f)
    }
}

impl fmt::Debug for NameHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NameHash(")?;
        fmt_hex(&self.0[..4], f)?;
        write!(f, "..)")
    }
}

/// A destination hash (16-byte truncated hash).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[must_use]
pub struct DestinationHash(pub(crate) TruncatedHash);

impl DestinationHash {
    pub const fn new(bytes: [u8; 16]) -> Self {
        Self(TruncatedHash(bytes))
    }
}

impl Deref for DestinationHash {
    type Target = TruncatedHash;
    fn deref(&self) -> &TruncatedHash {
        &self.0
    }
}

impl AsRef<[u8]> for DestinationHash {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl TryFrom<&[u8]> for DestinationHash {
    type Error = InvalidLength;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self(TruncatedHash::try_from(bytes)?))
    }
}

impl fmt::Display for DestinationHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::Debug for DestinationHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DestinationHash(")?;
        fmt_hex(&self.0.0[..4], f)?;
        write!(f, "..)")
    }
}

/// An identity hash (16-byte truncated hash of public keys).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[must_use]
pub struct IdentityHash(pub(crate) TruncatedHash);

impl IdentityHash {
    pub const fn new(bytes: [u8; 16]) -> Self {
        Self(TruncatedHash(bytes))
    }
}

impl Deref for IdentityHash {
    type Target = TruncatedHash;
    fn deref(&self) -> &TruncatedHash {
        &self.0
    }
}

impl AsRef<[u8]> for IdentityHash {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl TryFrom<&[u8]> for IdentityHash {
    type Error = InvalidLength;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self(TruncatedHash::try_from(bytes)?))
    }
}

impl fmt::Display for IdentityHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::Debug for IdentityHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IdentityHash(")?;
        fmt_hex(&self.0.0[..4], f)?;
        write!(f, "..)")
    }
}

/// A link ID (16-byte truncated hash).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[must_use]
pub struct LinkId(pub(crate) TruncatedHash);

impl LinkId {
    pub const fn new(bytes: [u8; 16]) -> Self {
        Self(TruncatedHash(bytes))
    }
}

impl Deref for LinkId {
    type Target = TruncatedHash;
    fn deref(&self) -> &TruncatedHash {
        &self.0
    }
}

impl AsRef<[u8]> for LinkId {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl TryFrom<&[u8]> for LinkId {
    type Error = InvalidLength;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self(TruncatedHash::try_from(bytes)?))
    }
}

impl fmt::Display for LinkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::Debug for LinkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LinkId(")?;
        fmt_hex(&self.0.0[..4], f)?;
        write!(f, "..)")
    }
}

/// A full 32-byte packet hash.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[must_use]
pub struct PacketHash(pub(crate) FullHash);

impl PacketHash {
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(FullHash(bytes))
    }

    /// Get the truncated (16-byte) packet hash used for addressing.
    #[must_use = "returns the truncated hash without modifying the original"]
    pub fn truncated(&self) -> TruncatedHash {
        let mut arr = [0u8; 16];
        arr.copy_from_slice(&self.0.0[..16]);
        TruncatedHash(arr)
    }
}

impl Deref for PacketHash {
    type Target = FullHash;
    fn deref(&self) -> &FullHash {
        &self.0
    }
}

impl AsRef<[u8]> for PacketHash {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl TryFrom<&[u8]> for PacketHash {
    type Error = InvalidLength;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self(FullHash::try_from(bytes)?))
    }
}

impl fmt::Display for PacketHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::Debug for PacketHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PacketHash(")?;
        fmt_hex(&self.0.0[..4], f)?;
        write!(f, "..)")
    }
}

/// Error returned when a byte slice has the wrong length for a newtype.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidLength {
    pub expected: usize,
    pub actual: usize,
}

impl fmt::Display for InvalidLength {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid length: expected {} bytes, got {}",
            self.expected, self.actual
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_truncated_hash_construction() {
        let bytes = [1u8; 16];
        let hash = TruncatedHash::new(bytes);
        assert_eq!(hash.as_ref(), &bytes);
    }

    #[test]
    fn test_truncated_hash_try_from_valid() {
        let bytes = [2u8; 16];
        let hash = TruncatedHash::try_from(bytes.as_ref()).unwrap();
        assert_eq!(hash.as_ref(), &bytes);
    }

    #[test]
    fn test_truncated_hash_try_from_invalid() {
        let bytes = [3u8; 15];
        let err = TruncatedHash::try_from(bytes.as_ref()).unwrap_err();
        assert_eq!(err.expected, 16);
        assert_eq!(err.actual, 15);
    }

    #[test]
    fn test_full_hash_try_from_invalid() {
        let bytes = [4u8; 31];
        let err = FullHash::try_from(bytes.as_ref()).unwrap_err();
        assert_eq!(err.expected, 32);
        assert_eq!(err.actual, 31);
    }

    #[test]
    fn test_name_hash_try_from_invalid() {
        let bytes = [5u8; 9];
        let err = NameHash::try_from(bytes.as_ref()).unwrap_err();
        assert_eq!(err.expected, 10);
        assert_eq!(err.actual, 9);
    }

    #[test]
    fn test_display_hex() {
        let hash = TruncatedHash::new([
            0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45,
            0x67, 0x89,
        ]);
        assert_eq!(format!("{hash}"), "abcdef0123456789abcdef0123456789");
    }

    #[test]
    fn test_debug_format() {
        let hash = TruncatedHash::new([
            0xab, 0xcd, 0xef, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ]);
        assert_eq!(format!("{hash:?}"), "TruncatedHash(abcdef01..)");
    }

    #[test]
    fn test_destination_hash_deref() {
        let dest = DestinationHash::new([0xaa; 16]);
        // Deref to TruncatedHash
        let inner: &TruncatedHash = &dest;
        assert_eq!(inner.as_ref(), &[0xaa; 16]);
    }

    #[test]
    fn test_packet_hash_truncated() {
        let full = [0u8; 32];
        let mut full_modified = full;
        full_modified[0] = 0xab;
        full_modified[15] = 0xcd;
        let ph = PacketHash::new(full_modified);
        let trunc = ph.truncated();
        assert_eq!(trunc.0[0], 0xab);
        assert_eq!(trunc.0[15], 0xcd);
    }

    #[test]
    fn test_identity_hash_display() {
        let ih = IdentityHash::new([
            0x65, 0x0b, 0x5d, 0x76, 0xb6, 0xbe, 0xc0, 0x39, 0x0d, 0x1f, 0x8c, 0xfc, 0xa5, 0xbd,
            0x33, 0xf9,
        ]);
        assert_eq!(format!("{ih}"), "650b5d76b6bec0390d1f8cfca5bd33f9");
    }
}
