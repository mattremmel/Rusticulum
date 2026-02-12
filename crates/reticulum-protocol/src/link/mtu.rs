//! MTU signalling byte encoding and decoding.
//!
//! The signalling field is 3 bytes encoding a 21-bit MTU value and a 3-bit mode value.
//! Formula: `signalling_value = (mtu & 0x1FFFFF) | ((mode << 5) & 0xE0) << 16)`
//! The 3 bytes are the big-endian representation of this 24-bit value.

use super::constants::{MODE_BYTEMASK, MTU_BYTEMASK};
use super::types::LinkMode;
use crate::error::LinkError;

/// Encode an MTU value and link mode into 3 signalling bytes.
///
/// The mode must be an enabled mode; the MTU must fit in 21 bits.
pub fn encode(mtu: u32, mode: LinkMode) -> Result<[u8; 3], LinkError> {
    if !mode.is_enabled() {
        return Err(LinkError::UnsupportedMode(mode as u8));
    }

    let mode_val = mode as u32;
    let value = (mtu & MTU_BYTEMASK) | (((mode_val << 5) & MODE_BYTEMASK) << 16);
    let be_bytes = value.to_be_bytes();
    // Take the last 3 bytes of the 4-byte BE representation (skip leading zero)
    Ok([be_bytes[1], be_bytes[2], be_bytes[3]])
}

/// Decode the MTU value from 3 signalling bytes.
pub fn decode_mtu(bytes: &[u8; 3]) -> u32 {
    let value = u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]]);
    value & MTU_BYTEMASK
}

/// Decode the link mode from 3 signalling bytes.
pub fn decode_mode(bytes: &[u8; 3]) -> LinkMode {
    let value = u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]]);
    let mode_val = ((value >> 16) & (MODE_BYTEMASK)) >> 5;
    // Safe: mode_val is masked to 3 bits (0-7), all valid LinkMode variants
    LinkMode::from_u8(mode_val as u8).unwrap()
}
