//! HDLC byte-stuffing framing.
//!
//! Implements the HDLC-like framing used by Reticulum's serial and pipe interfaces.
//! Escape order is critical: ESC bytes must be escaped before FLAG bytes.

extern crate alloc;
use alloc::vec::Vec;

use crate::error::FramingError;

pub const FLAG: u8 = 0x7E;
pub const ESC: u8 = 0x7D;
pub const ESC_MASK: u8 = 0x20;

/// Escape special bytes in data using HDLC byte-stuffing.
///
/// Replaces ESC (0x7D) with ESC + 0x5D, and FLAG (0x7E) with ESC + 0x5E.
/// The escape order (ESC first, then FLAG) is critical for correctness.
pub fn hdlc_escape(data: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(data.len());
    for &byte in data {
        match byte {
            ESC => {
                result.push(ESC);
                result.push(ESC ^ ESC_MASK);
            }
            FLAG => {
                result.push(ESC);
                result.push(FLAG ^ ESC_MASK);
            }
            _ => result.push(byte),
        }
    }
    result
}

/// Frame data with HDLC delimiters: FLAG + escape(data) + FLAG.
pub fn hdlc_frame(data: &[u8]) -> Vec<u8> {
    let escaped = hdlc_escape(data);
    let mut framed = Vec::with_capacity(escaped.len() + 2);
    framed.push(FLAG);
    framed.extend_from_slice(&escaped);
    framed.push(FLAG);
    framed
}

/// Remove HDLC framing: strip delimiters and unescape data.
pub fn hdlc_unframe(framed: &[u8]) -> Result<Vec<u8>, FramingError> {
    if framed.len() < 2 || framed[0] != FLAG || framed[framed.len() - 1] != FLAG {
        return Err(FramingError::MissingDelimiter);
    }

    let inner = &framed[1..framed.len() - 1];
    let mut result = Vec::with_capacity(inner.len());
    let mut i = 0;
    while i < inner.len() {
        if inner[i] == ESC {
            if i + 1 >= inner.len() {
                return Err(FramingError::IncompleteEscape);
            }
            result.push(inner[i + 1] ^ ESC_MASK);
            i += 2;
        } else {
            result.push(inner[i]);
            i += 1;
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hdlc_vectors() {
        let vectors = reticulum_test_vectors::interface_framing::load();

        for v in &vectors.hdlc.vectors {
            let input = hex::decode(&v.input).expect("invalid hex input");
            let expected_escaped = hex::decode(&v.escaped).expect("invalid hex escaped");
            let expected_framed = hex::decode(&v.framed).expect("invalid hex framed");

            // Test escape
            let escaped = hdlc_escape(&input);
            assert_eq!(
                escaped, expected_escaped,
                "HDLC escape mismatch for: {}",
                v.description
            );
            assert_eq!(
                escaped.len() as u64,
                v.escaped_length,
                "HDLC escaped length mismatch for: {}",
                v.description
            );

            // Test frame
            let framed = hdlc_frame(&input);
            assert_eq!(
                framed, expected_framed,
                "HDLC frame mismatch for: {}",
                v.description
            );
            assert_eq!(
                framed.len() as u64,
                v.framed_length,
                "HDLC framed length mismatch for: {}",
                v.description
            );

            // Test unframe (bidirectional)
            let unframed = hdlc_unframe(&expected_framed).expect("unframe should succeed");
            assert_eq!(
                unframed, input,
                "HDLC unframe mismatch for: {}",
                v.description
            );
        }
    }

    #[test]
    fn test_hdlc_roundtrip() {
        let data = vec![0x00, 0x7D, 0x7E, 0xFF, 0x7D, 0x7E, 0x01];
        let framed = hdlc_frame(&data);
        let recovered = hdlc_unframe(&framed).unwrap();
        assert_eq!(recovered, data);
    }

    #[test]
    fn test_hdlc_missing_delimiter() {
        assert!(hdlc_unframe(&[]).is_err());
        assert!(hdlc_unframe(&[FLAG]).is_err());
        assert!(hdlc_unframe(&[0x00, FLAG]).is_err());
    }

    #[test]
    fn test_hdlc_incomplete_escape() {
        // FLAG + ESC (no following byte) + FLAG
        let bad = vec![FLAG, ESC, FLAG];
        // The ESC at position 1 would need a following byte, but position 2 is the trailing FLAG
        // which has been stripped. Actually let me reconsider - inner is [ESC] with length 1.
        let result = hdlc_unframe(&bad);
        assert!(result.is_err());
    }
}
