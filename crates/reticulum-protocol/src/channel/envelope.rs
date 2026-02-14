//! Channel envelope packing and unpacking.
//!
//! The envelope is the foundational wire format for all channel-layer messaging.
//! It wraps a payload with a 6-byte header: `msg_type(u16) || sequence(u16) || length(u16)`,
//! all big-endian, followed by the payload bytes.

use crate::error::ChannelError;

/// A channel envelope containing a typed, sequenced message payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    /// Message type identifier.
    pub msg_type: u16,
    /// Sequence number.
    pub sequence: u16,
    /// Message payload.
    pub payload: Vec<u8>,
}

impl Envelope {
    /// Header overhead in bytes.
    pub const OVERHEAD: usize = 6;

    /// Pack the envelope into its wire format.
    ///
    /// Layout: `msg_type(2) || sequence(2) || data_length(2) || payload`
    pub fn pack(&self) -> Vec<u8> {
        let len = self.payload.len() as u16;
        let mut buf = Vec::with_capacity(Self::OVERHEAD + self.payload.len());
        buf.extend_from_slice(&self.msg_type.to_be_bytes());
        buf.extend_from_slice(&self.sequence.to_be_bytes());
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(&self.payload);

        tracing::trace!(
            msg_type = self.msg_type,
            sequence = self.sequence,
            payload_len = self.payload.len(),
            "packed envelope"
        );

        buf
    }

    /// Unpack an envelope from its wire format.
    pub fn unpack(data: &[u8]) -> Result<Self, ChannelError> {
        if data.len() < Self::OVERHEAD {
            return Err(ChannelError::InvalidEnvelope(format!(
                "data too short: {} bytes (minimum {})",
                data.len(),
                Self::OVERHEAD
            )));
        }

        let msg_type = u16::from_be_bytes([data[0], data[1]]);
        let sequence = u16::from_be_bytes([data[2], data[3]]);
        let length = u16::from_be_bytes([data[4], data[5]]) as usize;

        if data.len() != Self::OVERHEAD + length {
            return Err(ChannelError::InvalidEnvelope(format!(
                "length mismatch: header says {} payload bytes but got {}",
                length,
                data.len() - Self::OVERHEAD
            )));
        }

        let payload = data[Self::OVERHEAD..].to_vec();

        tracing::trace!(
            msg_type,
            sequence,
            payload_len = payload.len(),
            "unpacked envelope"
        );

        Ok(Self {
            msg_type,
            sequence,
            payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_envelope_pack_unpack_roundtrip() {
        let env = Envelope {
            msg_type: 0x1234,
            sequence: 0x5678,
            payload: vec![0xAA, 0xBB, 0xCC],
        };
        let packed = env.pack();
        let unpacked = Envelope::unpack(&packed).unwrap();
        assert_eq!(unpacked, env);
    }

    #[test]
    fn test_envelope_malformed_too_short() {
        for len in 0..6 {
            let data = vec![0u8; len];
            let result = Envelope::unpack(&data);
            assert!(result.is_err(), "len={len} should fail");
        }
    }

    #[test]
    fn test_envelope_malformed_empty() {
        let result = Envelope::unpack(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_envelope_zero_payload() {
        // 6-byte header with length field = 0 → Ok with empty payload
        let mut data = vec![0u8; 6];
        data[0] = 0x00; data[1] = 0x01; // msg_type = 1
        data[2] = 0x00; data[3] = 0x02; // sequence = 2
        data[4] = 0x00; data[5] = 0x00; // length = 0
        let env = Envelope::unpack(&data).unwrap();
        assert_eq!(env.msg_type, 1);
        assert_eq!(env.sequence, 2);
        assert!(env.payload.is_empty());
    }

    #[test]
    fn test_envelope_malformed_length_too_long() {
        // Header claims 100 payload bytes, but only 1 byte after header
        let mut data = vec![0u8; 7];
        data[4] = 0x00; data[5] = 100; // length = 100
        data[6] = 0xFF; // only 1 byte of payload
        let result = Envelope::unpack(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_envelope_malformed_length_too_short() {
        // Pack a valid envelope, then append an extra byte → length mismatch
        let env = Envelope {
            msg_type: 1,
            sequence: 1,
            payload: vec![0xAA],
        };
        let mut packed = env.pack();
        packed.push(0xFF); // extra byte
        let result = Envelope::unpack(&packed);
        assert!(result.is_err());
    }
}
