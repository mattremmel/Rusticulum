//! PKCS7 padding and unpadding for block ciphers.
//!
//! Implements standard PKCS7 padding as used by AES-CBC in the Reticulum protocol.
//! Supports block sizes from 1 to 255 bytes.

extern crate alloc;
use alloc::vec::Vec;

use crate::CryptoError;

/// Pad `data` to a multiple of `block_size` using PKCS7.
///
/// If the data length is already a multiple of `block_size`, a full block of
/// padding is appended (so there is always at least 1 byte of padding).
///
/// # Panics
///
/// Panics if `block_size` is 0 or greater than 255.
#[must_use]
pub fn pkcs7_pad(data: &[u8], block_size: usize) -> Vec<u8> {
    assert!(
        (1..=255).contains(&block_size),
        "PKCS7 block_size must be in 1..=255, got {block_size}"
    );

    let pad_len = block_size - (data.len() % block_size);
    let pad_byte = pad_len as u8;

    let mut out = Vec::with_capacity(data.len() + pad_len);
    out.extend_from_slice(data);
    out.resize(data.len() + pad_len, pad_byte);
    out
}

/// Remove PKCS7 padding from `data`, returning a slice of the original unpadded content.
///
/// Validates that the padding bytes are well-formed. Returns
/// `CryptoError::InvalidPadding` if the data is empty, the last byte is zero,
/// the indicated padding length exceeds the data length, or any padding byte
/// does not match the expected value.
pub fn pkcs7_unpad(data: &[u8]) -> Result<&[u8], CryptoError> {
    if data.is_empty() {
        return Err(CryptoError::InvalidPadding);
    }

    let pad_byte = data[data.len() - 1];
    let pad_len = pad_byte as usize;

    if pad_len == 0 || pad_len > data.len() {
        return Err(CryptoError::InvalidPadding);
    }

    let content_len = data.len() - pad_len;
    for &b in &data[content_len..] {
        if b != pad_byte {
            return Err(CryptoError::InvalidPadding);
        }
    }

    Ok(&data[..content_len])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pkcs7_pad_vectors() {
        let vectors = reticulum_test_vectors::token::load();

        for v in &vectors.pkcs7_padding {
            let input = hex::decode(&v.input).expect("invalid hex in input");
            assert_eq!(
                input.len() as u64,
                v.input_length,
                "input length mismatch for: {}",
                v.description
            );

            let padded = pkcs7_pad(&input, 16);
            let expected = hex::decode(&v.padded).expect("invalid hex in padded");

            assert_eq!(padded, expected, "padding mismatch for: {}", v.description);
            assert_eq!(
                padded.len() as u64,
                v.padded_length,
                "padded length mismatch for: {}",
                v.description
            );
        }
    }

    #[test]
    fn test_pkcs7_unpad_vectors() {
        let vectors = reticulum_test_vectors::token::load();

        for v in &vectors.pkcs7_padding {
            let padded = hex::decode(&v.padded).expect("invalid hex in padded");
            let unpadded = pkcs7_unpad(&padded).expect("unpadding failed");
            let expected_input = hex::decode(&v.input).expect("invalid hex in input");

            assert_eq!(
                unpadded,
                &expected_input[..],
                "unpadding mismatch for: {}",
                v.description
            );
        }
    }

    #[test]
    fn test_pkcs7_unpad_invalid() {
        // Empty data
        assert_eq!(pkcs7_unpad(&[]), Err(CryptoError::InvalidPadding));

        // Last byte is zero (invalid pad length)
        assert_eq!(pkcs7_unpad(&[0xAA, 0x00]), Err(CryptoError::InvalidPadding));

        // pad_len exceeds data length: single byte claiming 2 bytes of padding
        assert_eq!(pkcs7_unpad(&[0x02]), Err(CryptoError::InvalidPadding));

        // Inconsistent padding bytes: claims 3 bytes of padding but they don't all match
        assert_eq!(
            pkcs7_unpad(&[0xAA, 0xBB, 0x01, 0x03, 0x03]),
            Err(CryptoError::InvalidPadding)
        );

        // All padding bytes should be 0x04, but one is wrong
        assert_eq!(
            pkcs7_unpad(&[0xAA, 0x04, 0x04, 0x03, 0x04]),
            Err(CryptoError::InvalidPadding)
        );
    }

    // ================================================================== //
    // Boundary: PKCS7 edge cases
    // ================================================================== //

    #[test]
    fn pkcs7_full_block_padding() {
        // data len == block_size → adds a full block of padding (16 bytes of 0x10)
        let data = [0xAAu8; 16];
        let padded = pkcs7_pad(&data, 16);
        assert_eq!(padded.len(), 32);
        assert_eq!(&padded[16..], &[0x10u8; 16]);
        let unpadded = pkcs7_unpad(&padded).unwrap();
        assert_eq!(unpadded, &data);
    }

    #[test]
    fn pkcs7_block_size_one() {
        // block_size=1: every byte needs 1 pad byte (0x01)
        let data = b"hello";
        let padded = pkcs7_pad(data, 1);
        // 5 bytes + 1 byte of padding = 6 bytes
        assert_eq!(padded.len(), 6);
        assert_eq!(padded[5], 0x01);
        let unpadded = pkcs7_unpad(&padded).unwrap();
        assert_eq!(unpadded, data);
    }

    #[test]
    fn pkcs7_block_size_255() {
        let data = b"small";
        let padded = pkcs7_pad(data, 255);
        // 5 bytes → pad_len = 255 - 5 = 250
        assert_eq!(padded.len(), 255);
        assert_eq!(padded[254], 250u8);
        let unpadded = pkcs7_unpad(&padded).unwrap();
        assert_eq!(unpadded, data);
    }

    #[test]
    fn pkcs7_unpad_all_zeros() {
        // [0x00; 16] → pad byte = 0 → invalid (pad_len == 0)
        let data = [0x00u8; 16];
        assert_eq!(pkcs7_unpad(&data), Err(CryptoError::InvalidPadding));
    }

    #[test]
    fn test_pkcs7_roundtrip() {
        // Test a range of input sizes including 0, sub-block, exact block, and multi-block
        let block_size = 16;
        for size in [0, 1, 7, 15, 16, 17, 31, 32, 33, 100, 255, 256] {
            let data: Vec<u8> = (0..size).map(|i| (i & 0xFF) as u8).collect();
            let padded = pkcs7_pad(&data, block_size);

            // Padded length must be a non-zero multiple of block_size
            assert_eq!(
                padded.len() % block_size,
                0,
                "padded length not aligned for size {size}"
            );
            assert!(
                padded.len() > data.len(),
                "padded must be strictly longer than input for size {size}"
            );
            assert!(
                padded.len() <= data.len() + block_size,
                "padding added more than one block for size {size}"
            );

            let unpadded = pkcs7_unpad(&padded).expect("roundtrip unpad failed");
            assert_eq!(unpadded, &data[..], "roundtrip mismatch for size {size}");
        }

        // Also test non-16 block sizes
        for block_size in [1, 2, 5, 8, 13, 32, 128, 255] {
            let data = b"hello world";
            let padded = pkcs7_pad(data, block_size);
            assert_eq!(padded.len() % block_size, 0);
            let unpadded = pkcs7_unpad(&padded).expect("roundtrip unpad failed");
            assert_eq!(unpadded, data);
        }
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn pkcs7_roundtrip(
            data in proptest::collection::vec(any::<u8>(), 0..256),
            block_size in 1..=255usize,
        ) {
            let padded = pkcs7_pad(&data, block_size);
            let unpadded = pkcs7_unpad(&padded).unwrap();
            prop_assert_eq!(unpadded, &data[..]);
        }
    }
}
