//! Raw packet wire format parsing and serialization.
//!
//! Handles parsing raw bytes into structured packet headers and computing
//! the hashable part and packet hash according to the Reticulum protocol.

extern crate alloc;
use alloc::vec::Vec;

use crate::constants::{
    FLAGS_LOWER_NIBBLE_MASK, HEADER_1_SIZE, HEADER_2_SIZE, HeaderType, TRUNCATED_HASHLENGTH,
};
use crate::error::PacketError;
use crate::packet::context::ContextType;
use crate::packet::flags::PacketFlags;
use crate::types::{DestinationHash, PacketHash};

/// A parsed packet with references to the original data.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
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
    #[must_use = "parsing may fail; check the Result"]
    pub fn parse(raw: &[u8]) -> Result<Self, PacketError> {
        if raw.len() < HEADER_1_SIZE {
            return Err(PacketError::TooShort {
                min: HEADER_1_SIZE,
                actual: raw.len(),
            });
        }

        let flags = PacketFlags::try_from(raw[0])?;
        let hops = raw[1];

        match flags.header_type {
            HeaderType::Header1 => {
                // HEADER_1: flags(1) + hops(1) + destination(16) + context(1) = 19
                let dest_bytes: [u8; 16] =
                    raw[2..18].try_into().expect("slice is exactly 16 bytes");
                let destination = DestinationHash::new(dest_bytes);
                let context = ContextType::try_from(raw[18])?;
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
                let context = ContextType::try_from(raw[34])?;
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
    #[must_use = "serialization produces a new Vec without modifying the packet"]
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
    #[must_use = "returns the hashable bytes without modifying the packet"]
    pub fn hashable_part(&self) -> Vec<u8> {
        let masked_flags = self.flags.to_byte() & FLAGS_LOWER_NIBBLE_MASK;

        let mut result = Vec::with_capacity(1 + TRUNCATED_HASHLENGTH + 1 + self.data.len());
        result.push(masked_flags);
        // Skip hops and transport_id — go straight to destination
        result.extend_from_slice(self.destination.as_ref());
        result.push(self.context.to_byte());
        result.extend_from_slice(&self.data);
        result
    }

    /// Compute the full 32-byte SHA-256 packet hash.
    #[must_use = "returns the computed hash without modifying the packet"]
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

    #[test]
    fn test_parse_malformed_truncated_systematic() {
        // H1 packets: anything < 19 bytes should fail with TooShort
        for len in 1..HEADER_1_SIZE {
            let mut data = vec![0x00; len];
            if len > 0 {
                data[0] = 0x00; // H1 flags
            }
            let result = RawPacket::parse(&data);
            assert!(result.is_err(), "H1 packet of {len} bytes should fail");
        }
        // H2 packets: anything < 35 bytes (with H2 flag) should fail
        for len in HEADER_1_SIZE..HEADER_2_SIZE {
            let mut data = vec![0x00; len];
            data[0] = 0x40; // H2 flag
            data[18] = 0x00; // valid context for H1 check (won't be reached)
            let result = RawPacket::parse(&data);
            assert!(result.is_err(), "H2 packet of {len} bytes should fail");
        }
    }

    #[test]
    fn test_parse_malformed_zero_length_payload() {
        // Exactly 19 bytes H1 packet → Ok with empty data
        let mut data = vec![0x00; HEADER_1_SIZE];
        data[0] = 0x00; // valid H1 flags
        data[18] = 0x00; // valid context (None)
        let packet = RawPacket::parse(&data).unwrap();
        assert!(packet.data.is_empty());
    }

    #[test]
    fn test_parse_malformed_oversized_payload() {
        // 600-byte packet → Ok (RawPacket doesn't enforce MTU)
        let mut data = vec![0x00; 600];
        data[0] = 0x00; // valid H1 flags
        data[18] = 0x00; // valid context
        let packet = RawPacket::parse(&data).unwrap();
        assert_eq!(packet.data.len(), 600 - HEADER_1_SIZE);
    }

    // ================================================================== //
    // Boundary: packet size edge cases
    // ================================================================== //

    #[test]
    fn parse_header2_exact_minimum() {
        // Exactly HEADER_2_SIZE (35) bytes, zero payload
        let mut data = vec![0x00; HEADER_2_SIZE];
        data[0] = 0x40; // HEADER_2 flags
        data[34] = 0x00; // valid context (None)
        let packet = RawPacket::parse(&data).unwrap();
        assert_eq!(packet.flags.header_type, HeaderType::Header2);
        assert!(packet.data.is_empty());
    }

    #[test]
    fn parse_at_mtu_boundary() {
        let mut data = vec![0x00; 500];
        data[0] = 0x00; // H1 flags
        data[18] = 0x00; // valid context
        let packet = RawPacket::parse(&data).unwrap();
        assert_eq!(packet.data.len(), 500 - HEADER_1_SIZE);
    }

    #[test]
    fn serialize_roundtrip_zero_payload_h1() {
        let mut data = vec![0x00; HEADER_1_SIZE];
        data[0] = 0x00; // valid H1 flags
        data[18] = 0x00; // valid context
        let packet = RawPacket::parse(&data).unwrap();
        let serialized = packet.serialize();
        assert_eq!(serialized.len(), HEADER_1_SIZE);
        assert_eq!(serialized, data);
    }

    #[test]
    fn serialize_roundtrip_zero_payload_h2() {
        let mut data = vec![0x00; HEADER_2_SIZE];
        data[0] = 0x40; // HEADER_2 flags
        data[34] = 0x00; // valid context
        let packet = RawPacket::parse(&data).unwrap();
        let serialized = packet.serialize();
        assert_eq!(serialized.len(), HEADER_2_SIZE);
        assert_eq!(serialized, data);
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    /// Valid context byte values (21 valid values from the ContextType enum).
    fn valid_context_byte() -> impl Strategy<Value = u8> {
        prop_oneof![
            Just(0u8),
            Just(1),
            Just(2),
            Just(3),
            Just(4),
            Just(5),
            Just(6),
            Just(7),
            Just(8),
            Just(9),
            Just(10),
            Just(11),
            Just(12),
            Just(13),
            Just(14),
            Just(250),
            Just(251),
            Just(252),
            Just(253),
            Just(254),
            Just(255),
        ]
    }

    /// Valid H1 flags byte (header_type=0, lower 6 bits vary).
    fn h1_flags_byte() -> impl Strategy<Value = u8> {
        (0..=1u8, 0..=1u8, 0..=3u8, 0..=3u8)
            .prop_map(|(cf, tt, dt, pt)| (cf << 5) | (tt << 4) | (dt << 2) | pt)
    }

    /// Valid H2 flags byte (header_type=1, lower 6 bits vary).
    fn h2_flags_byte() -> impl Strategy<Value = u8> {
        (0..=1u8, 0..=1u8, 0..=3u8, 0..=3u8)
            .prop_map(|(cf, tt, dt, pt)| 0x40 | (cf << 5) | (tt << 4) | (dt << 2) | pt)
    }

    /// Generate a valid H1 raw packet: flags(1) + hops(1) + dest(16) + ctx(1) + data(0..128).
    fn valid_h1_packet() -> impl Strategy<Value = Vec<u8>> {
        (
            h1_flags_byte(),
            any::<u8>(),
            any::<[u8; 16]>(),
            valid_context_byte(),
            proptest::collection::vec(any::<u8>(), 0..128),
        )
            .prop_map(|(flags, hops, dest, ctx, data)| {
                let mut raw = Vec::with_capacity(19 + data.len());
                raw.push(flags);
                raw.push(hops);
                raw.extend_from_slice(&dest);
                raw.push(ctx);
                raw.extend_from_slice(&data);
                raw
            })
    }

    /// Generate a valid H2 raw packet: flags(1) + hops(1) + tid(16) + dest(16) + ctx(1) + data(0..128).
    fn valid_h2_packet() -> impl Strategy<Value = Vec<u8>> {
        (
            h2_flags_byte(),
            any::<u8>(),
            any::<[u8; 16]>(),
            any::<[u8; 16]>(),
            valid_context_byte(),
            proptest::collection::vec(any::<u8>(), 0..128),
        )
            .prop_map(|(flags, hops, tid, dest, ctx, data)| {
                let mut raw = Vec::with_capacity(35 + data.len());
                raw.push(flags);
                raw.push(hops);
                raw.extend_from_slice(&tid);
                raw.extend_from_slice(&dest);
                raw.push(ctx);
                raw.extend_from_slice(&data);
                raw
            })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn h1_parse_serialize_roundtrip(raw in valid_h1_packet()) {
            let packet = RawPacket::parse(&raw).unwrap();
            let serialized = packet.serialize();
            prop_assert_eq!(&serialized, &raw);
        }

        #[test]
        fn h2_parse_serialize_roundtrip(raw in valid_h2_packet()) {
            let packet = RawPacket::parse(&raw).unwrap();
            let serialized = packet.serialize();
            prop_assert_eq!(&serialized, &raw);
        }

        #[test]
        fn arbitrary_bytes_never_panic(raw in proptest::collection::vec(any::<u8>(), 0..600)) {
            let _ = RawPacket::parse(&raw);
        }

        #[test]
        fn hashable_part_deterministic(raw in valid_h1_packet()) {
            let packet = RawPacket::parse(&raw).unwrap();
            let a = packet.hashable_part();
            let b = packet.hashable_part();
            prop_assert_eq!(&a, &b);
        }

        #[test]
        fn packet_hash_deterministic(raw in valid_h1_packet()) {
            let packet = RawPacket::parse(&raw).unwrap();
            let a = packet.packet_hash();
            let b = packet.packet_hash();
            prop_assert_eq!(a, b);
        }
    }
}
