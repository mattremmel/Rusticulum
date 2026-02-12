//! Raw packet wire format parsing and serialization.
//!
//! Handles parsing raw bytes into structured packet headers and computing
//! the hashable part and packet hash according to the Reticulum protocol.

extern crate alloc;
use alloc::vec::Vec;

use crate::constants::{HEADER_1_SIZE, HEADER_2_SIZE, HeaderType, TRUNCATED_HASHLENGTH};
use crate::error::PacketError;
use crate::packet::context::ContextType;
use crate::packet::flags::PacketFlags;
use crate::types::{DestinationHash, PacketHash};

/// A parsed packet with references to the original data.
#[derive(Debug, Clone)]
pub struct RawPacket {
    pub flags: PacketFlags,
    pub hops: u8,
    pub transport_id: Option<DestinationHash>,
    pub destination: DestinationHash,
    pub context: ContextType,
    pub data: Vec<u8>,
}

impl RawPacket {
    /// Parse a raw packet from wire bytes.
    pub fn parse(raw: &[u8]) -> Result<Self, PacketError> {
        if raw.len() < HEADER_1_SIZE {
            return Err(PacketError::TooShort {
                min: HEADER_1_SIZE,
                actual: raw.len(),
            });
        }

        let flags = PacketFlags::from_byte(raw[0])?;
        let hops = raw[1];

        match flags.header_type {
            HeaderType::Header1 => {
                // HEADER_1: flags(1) + hops(1) + destination(16) + context(1) = 19
                let dest_bytes: [u8; 16] =
                    raw[2..18].try_into().expect("slice is exactly 16 bytes");
                let destination = DestinationHash::new(dest_bytes);
                let context = ContextType::from_byte(raw[18])?;
                let data = raw[19..].to_vec();

                Ok(RawPacket {
                    flags,
                    hops,
                    transport_id: None,
                    destination,
                    context,
                    data,
                })
            }
            HeaderType::Header2 => {
                // HEADER_2: flags(1) + hops(1) + transport_id(16) + destination(16) + context(1) = 35
                if raw.len() < HEADER_2_SIZE {
                    return Err(PacketError::TooShort {
                        min: HEADER_2_SIZE,
                        actual: raw.len(),
                    });
                }

                let transport_bytes: [u8; 16] =
                    raw[2..18].try_into().expect("slice is exactly 16 bytes");
                let transport_id = DestinationHash::new(transport_bytes);

                let dest_bytes: [u8; 16] =
                    raw[18..34].try_into().expect("slice is exactly 16 bytes");
                let destination = DestinationHash::new(dest_bytes);
                let context = ContextType::from_byte(raw[34])?;
                let data = raw[35..].to_vec();

                Ok(RawPacket {
                    flags,
                    hops,
                    transport_id: Some(transport_id),
                    destination,
                    context,
                    data,
                })
            }
        }
    }

    /// Serialize the packet back to wire format.
    pub fn serialize(&self) -> Vec<u8> {
        let header_size = match self.flags.header_type {
            HeaderType::Header1 => HEADER_1_SIZE,
            HeaderType::Header2 => HEADER_2_SIZE,
        };
        let mut result = Vec::with_capacity(header_size + self.data.len());

        result.push(self.flags.to_byte());
        result.push(self.hops);

        if let Some(ref tid) = self.transport_id {
            result.extend_from_slice(tid.as_ref());
        }

        result.extend_from_slice(self.destination.as_ref());
        result.push(self.context.to_byte());
        result.extend_from_slice(&self.data);
        result
    }

    /// Compute the hashable part of the packet.
    ///
    /// Per protocol: flags masked to lower 4 bits (& 0x0F), hops stripped,
    /// transport_id stripped for HEADER_2.
    /// Result: masked_flags(1) + destination(16) + context(1) + data
    pub fn hashable_part(&self) -> Vec<u8> {
        let masked_flags = self.flags.to_byte() & 0x0F;

        let mut result = Vec::with_capacity(1 + TRUNCATED_HASHLENGTH + 1 + self.data.len());
        result.push(masked_flags);
        // Skip hops and transport_id — go straight to destination
        result.extend_from_slice(self.destination.as_ref());
        result.push(self.context.to_byte());
        result.extend_from_slice(&self.data);
        result
    }

    /// Compute the full 32-byte SHA-256 packet hash.
    pub fn packet_hash(&self) -> PacketHash {
        let hashable = self.hashable_part();
        let hash = reticulum_crypto::sha::sha256(&hashable);
        PacketHash::new(hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_vectors() {
        let v = reticulum_test_vectors::packet_headers::load();

        for hv in &v.header_vectors {
            let raw_bytes = hex::decode(&hv.raw_packet).expect("invalid hex raw_packet");

            // Test parse
            let packet = RawPacket::parse(&raw_bytes)
                .unwrap_or_else(|e| panic!("parse failed for '{}': {e}", hv.description));

            // Verify flags byte
            let expected_flags =
                u8::from_str_radix(&hv.flags_byte, 16).expect("invalid hex flags_byte");
            assert_eq!(
                packet.flags.to_byte(),
                expected_flags,
                "flags mismatch for: {}",
                hv.description
            );

            // Verify hops
            assert_eq!(
                packet.hops, hv.hops as u8,
                "hops mismatch for: {}",
                hv.description
            );

            // Verify destination hash
            let expected_dest =
                hex::decode(&hv.destination_hash).expect("invalid hex destination_hash");
            assert_eq!(
                packet.destination.as_ref(),
                expected_dest.as_slice(),
                "destination_hash mismatch for: {}",
                hv.description
            );

            // Verify transport_id
            if let Some(ref tid_hex) = hv.transport_id {
                let expected_tid = hex::decode(tid_hex).expect("invalid hex transport_id");
                assert_eq!(
                    packet.transport_id.as_ref().unwrap().as_ref(),
                    expected_tid.as_slice(),
                    "transport_id mismatch for: {}",
                    hv.description
                );
            } else {
                assert!(
                    packet.transport_id.is_none(),
                    "expected no transport_id for: {}",
                    hv.description
                );
            }

            // Verify context
            let expected_context =
                u8::from_str_radix(&hv.context, 16).expect("invalid hex context");
            assert_eq!(
                packet.context.to_byte(),
                expected_context,
                "context mismatch for: {}",
                hv.description
            );

            // Verify payload
            let expected_payload = hex::decode(&hv.payload).expect("invalid hex payload");
            assert_eq!(
                packet.data, expected_payload,
                "payload mismatch for: {}",
                hv.description
            );

            // Verify header length
            let header_len = match packet.flags.header_type {
                HeaderType::Header1 => HEADER_1_SIZE,
                HeaderType::Header2 => HEADER_2_SIZE,
            };
            assert_eq!(
                header_len as u64, hv.expected_header_length,
                "header length mismatch for: {}",
                hv.description
            );

            // Test serialize (bidirectional)
            let serialized = packet.serialize();
            assert_eq!(
                serialized, raw_bytes,
                "serialize mismatch for: {}",
                hv.description
            );

            // Test hashable_part
            let expected_hashable =
                hex::decode(&hv.hashable_part).expect("invalid hex hashable_part");
            let hashable = packet.hashable_part();
            assert_eq!(
                hashable, expected_hashable,
                "hashable_part mismatch for: {}",
                hv.description
            );

            // Test packet_hash (full)
            let expected_hash_full =
                hex::decode(&hv.packet_hash_full).expect("invalid hex packet_hash_full");
            let ph = packet.packet_hash();
            assert_eq!(
                ph.as_ref(),
                expected_hash_full.as_slice(),
                "packet_hash_full mismatch for: {}",
                hv.description
            );

            // Test packet_hash (truncated)
            let expected_hash = hex::decode(&hv.packet_hash).expect("invalid hex packet_hash");
            let trunc = ph.truncated();
            assert_eq!(
                trunc.as_ref(),
                expected_hash.as_slice(),
                "packet_hash truncated mismatch for: {}",
                hv.description
            );
        }
    }

    #[test]
    fn test_packet_too_short() {
        let result = RawPacket::parse(&[0x00; 5]);
        assert!(result.is_err());
    }

    #[test]
    fn test_header2_too_short() {
        // Valid HEADER_2 flags byte (bit 6 set = 0x40) but only 19 bytes
        let mut data = vec![0x40; 19];
        data[18] = 0x00; // valid context
        let result = RawPacket::parse(&data);
        assert!(result.is_err());
    }
}
