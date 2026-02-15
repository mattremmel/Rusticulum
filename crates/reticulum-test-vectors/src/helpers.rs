//! Shared hex-decoding test helpers.
//!
//! These functions consolidate the `hex_to_*` helpers that were duplicated
//! across six test modules. Enable the `helpers` feature to use them.

/// Decode a hex string into a `Vec<u8>`.
pub fn hex_to_bytes(hex: &str) -> Vec<u8> {
    hex::decode(hex).expect("invalid hex")
}

/// Decode a hex string into a `[u8; 16]`.
pub fn hex_to_16(hex: &str) -> [u8; 16] {
    let bytes = hex::decode(hex).expect("invalid hex");
    bytes.try_into().expect("must be 16 bytes")
}

/// Decode a hex string into a `[u8; 32]`.
pub fn hex_to_32(hex: &str) -> [u8; 32] {
    let bytes = hex::decode(hex).expect("invalid hex");
    bytes.try_into().expect("must be 32 bytes")
}

/// Decode a hex string into a `[u8; 64]`.
pub fn hex_to_64(hex: &str) -> [u8; 64] {
    let bytes = hex::decode(hex).expect("invalid hex");
    bytes.try_into().expect("must be 64 bytes")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_to_bytes_works() {
        assert_eq!(hex_to_bytes("deadbeef"), vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(hex_to_bytes(""), Vec::<u8>::new());
    }

    #[test]
    fn hex_to_16_works() {
        let hex = "00112233445566778899aabbccddeeff";
        let arr = hex_to_16(hex);
        assert_eq!(arr[0], 0x00);
        assert_eq!(arr[15], 0xFF);
    }

    #[test]
    fn hex_to_32_works() {
        let hex = "0000000000000000000000000000000000000000000000000000000000000001";
        let arr = hex_to_32(hex);
        assert_eq!(arr[31], 0x01);
    }

    #[test]
    fn hex_to_64_works() {
        let hex = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
        let arr = hex_to_64(hex);
        assert_eq!(arr[63], 0x01);
    }
}
