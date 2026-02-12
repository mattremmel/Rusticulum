//! KISS byte-stuffing framing.
//!
//! Implements the KISS TNC framing used by Reticulum's serial interfaces.
//! Frame format: FEND + CMD_DATA(0x00) + escaped(data) + FEND.

extern crate alloc;
use alloc::vec::Vec;

use crate::error::FramingError;

pub const FEND: u8 = 0xC0;
pub const FESC: u8 = 0xDB;
pub const TFEND: u8 = 0xDC;
pub const TFESC: u8 = 0xDD;
pub const CMD_DATA: u8 = 0x00;

/// Escape special bytes in data using KISS byte-stuffing.
///
/// Replaces FEND (0xC0) with FESC + TFEND, and FESC (0xDB) with FESC + TFESC.
pub fn kiss_escape(data: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(data.len());
    for &byte in data {
        match byte {
            FEND => {
                result.push(FESC);
                result.push(TFEND);
            }
            FESC => {
                result.push(FESC);
                result.push(TFESC);
            }
            _ => result.push(byte),
        }
    }
    result
}

/// Frame data with KISS delimiters: FEND + CMD_DATA + escape(data) + FEND.
pub fn kiss_frame(data: &[u8]) -> Vec<u8> {
    let escaped = kiss_escape(data);
    let mut framed = Vec::with_capacity(escaped.len() + 3);
    framed.push(FEND);
    framed.push(CMD_DATA);
    framed.extend_from_slice(&escaped);
    framed.push(FEND);
    framed
}

/// Remove KISS framing: strip delimiters, command byte, and unescape data.
pub fn kiss_unframe(framed: &[u8]) -> Result<Vec<u8>, FramingError> {
    if framed.len() < 3 || framed[0] != FEND || framed[framed.len() - 1] != FEND {
        return Err(FramingError::MissingDelimiter);
    }

    // Skip FEND + CMD byte
    let inner = &framed[2..framed.len() - 1];
    let mut result = Vec::with_capacity(inner.len());
    let mut i = 0;
    while i < inner.len() {
        if inner[i] == FESC {
            if i + 1 >= inner.len() {
                return Err(FramingError::IncompleteEscape);
            }
            match inner[i + 1] {
                TFEND => result.push(FEND),
                TFESC => result.push(FESC),
                other => return Err(FramingError::InvalidEscapeSequence(other)),
            }
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
    fn test_kiss_vectors() {
        let vectors = reticulum_test_vectors::interface_framing::load();

        for v in &vectors.kiss.vectors {
            let input = hex::decode(&v.input).expect("invalid hex input");
            let expected_escaped = hex::decode(&v.escaped).expect("invalid hex escaped");
            let expected_framed = hex::decode(&v.framed).expect("invalid hex framed");

            // Test escape
            let escaped = kiss_escape(&input);
            assert_eq!(
                escaped, expected_escaped,
                "KISS escape mismatch for: {}",
                v.description
            );
            assert_eq!(
                escaped.len() as u64,
                v.escaped_length,
                "KISS escaped length mismatch for: {}",
                v.description
            );

            // Test frame
            let framed = kiss_frame(&input);
            assert_eq!(
                framed, expected_framed,
                "KISS frame mismatch for: {}",
                v.description
            );
            assert_eq!(
                framed.len() as u64,
                v.framed_length,
                "KISS framed length mismatch for: {}",
                v.description
            );

            // Test unframe (bidirectional)
            let unframed = kiss_unframe(&expected_framed).expect("unframe should succeed");
            assert_eq!(
                unframed, input,
                "KISS unframe mismatch for: {}",
                v.description
            );
        }
    }

    #[test]
    fn test_kiss_roundtrip() {
        let data = vec![0x00, 0xC0, 0xDB, 0xFF, 0xC0, 0xDB, 0x01];
        let framed = kiss_frame(&data);
        let recovered = kiss_unframe(&framed).unwrap();
        assert_eq!(recovered, data);
    }

    #[test]
    fn test_kiss_missing_delimiter() {
        assert!(kiss_unframe(&[]).is_err());
        assert!(kiss_unframe(&[FEND]).is_err());
        assert!(kiss_unframe(&[FEND, CMD_DATA]).is_err());
    }

    #[test]
    fn test_kiss_invalid_escape() {
        // FEND + CMD + FESC + invalid_byte + FEND
        let bad = vec![FEND, CMD_DATA, FESC, 0x00, FEND];
        let result = kiss_unframe(&bad);
        assert!(result.is_err());
    }
}
