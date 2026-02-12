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
