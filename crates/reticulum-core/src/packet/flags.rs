//! Packet flag byte encoding and decoding.
//!
//! The flag byte layout (from test vectors):
//! ```text
//! Bit 7: unused (reserved)
//! Bit 6: header_type (0=HEADER_1, 1=HEADER_2)
//! Bit 5: context_flag
//! Bit 4: transport_type (0=BROADCAST, 1=TRANSPORT)
//! Bits 3-2: destination_type (0=SINGLE, 1=GROUP, 2=PLAIN, 3=LINK)
//! Bits 1-0: packet_type (0=DATA, 1=ANNOUNCE, 2=LINKREQUEST, 3=PROOF)
//! ```
//!
//! Packing formula: `(header_type << 6) | (context_flag << 5) | (transport_type << 4) | (dest_type << 2) | packet_type`

use crate::constants::{DestinationType, HeaderType, PacketType, TransportType};
use crate::error::PacketError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketFlags {
    pub header_type: HeaderType,
    pub context_flag: bool,
    pub transport_type: TransportType,
    pub destination_type: DestinationType,
    pub packet_type: PacketType,
}

impl PacketFlags {
    pub fn from_byte(byte: u8) -> Result<Self, PacketError> {
        let header_type = HeaderType::from_u8((byte >> 6) & 0x01)?;
        let context_flag = (byte >> 5) & 0x01 != 0;
        let transport_type = TransportType::from_u8((byte >> 4) & 0x01)?;
        let destination_type = DestinationType::from_u8((byte >> 2) & 0x03)?;
        let packet_type = PacketType::from_u8(byte & 0x03)?;

        Ok(PacketFlags {
            header_type,
            context_flag,
            transport_type,
            destination_type,
            packet_type,
        })
    }

    pub fn to_byte(&self) -> u8 {
        ((self.header_type as u8) << 6)
            | ((self.context_flag as u8) << 5)
            | ((self.transport_type as u8) << 4)
            | ((self.destination_type as u8) << 2)
            | (self.packet_type as u8)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flag_packing_vectors() {
        let v = reticulum_test_vectors::packet_headers::load();

        for fv in &v.flag_packing_vectors {
            let flags = PacketFlags {
                header_type: HeaderType::from_u8(fv.header_type as u8).unwrap(),
                context_flag: fv.context_flag != 0,
                transport_type: TransportType::from_u8(fv.transport_type as u8).unwrap(),
                destination_type: DestinationType::from_u8(fv.destination_type as u8).unwrap(),
                packet_type: PacketType::from_u8(fv.packet_type as u8).unwrap(),
            };

            let expected_byte =
                u8::from_str_radix(&fv.flags_byte, 16).expect("invalid hex flags_byte");
            assert_eq!(
                flags.to_byte(),
                expected_byte,
                "flag packing mismatch for: {}",
                fv.description
            );
        }
    }

    #[test]
    fn test_flag_unpacking_vectors() {
        let v = reticulum_test_vectors::packet_headers::load();

        for fv in &v.flag_unpacking_vectors {
            let byte = u8::from_str_radix(&fv.flags_byte, 16).expect("invalid hex flags_byte");
            let flags = PacketFlags::from_byte(byte).expect("should parse valid flags byte");

            assert_eq!(
                flags.header_type as u64, fv.header_type,
                "header_type mismatch for flags_byte {}",
                fv.flags_byte
            );
            assert_eq!(
                flags.context_flag as u64, fv.context_flag,
                "context_flag mismatch for flags_byte {}",
                fv.flags_byte
            );
            assert_eq!(
                flags.transport_type as u64, fv.transport_type,
                "transport_type mismatch for flags_byte {}",
                fv.flags_byte
            );
            assert_eq!(
                flags.destination_type as u64, fv.destination_type,
                "destination_type mismatch for flags_byte {}",
                fv.flags_byte
            );
            assert_eq!(
                flags.packet_type as u64, fv.packet_type,
                "packet_type mismatch for flags_byte {}",
                fv.flags_byte
            );
        }
    }

    #[test]
    fn test_exhaustive_flag_vectors() {
        let v = reticulum_test_vectors::packet_headers::load();

        for fv in &v.exhaustive_flag_vectors {
            let expected_byte =
                u8::from_str_radix(&fv.flags_byte, 16).expect("invalid hex flags_byte");

            // Test packing
            let flags = PacketFlags {
                header_type: HeaderType::from_u8(fv.header_type as u8).unwrap(),
                context_flag: fv.context_flag != 0,
                transport_type: TransportType::from_u8(fv.transport_type as u8).unwrap(),
                destination_type: DestinationType::from_u8(fv.destination_type as u8).unwrap(),
                packet_type: PacketType::from_u8(fv.packet_type as u8).unwrap(),
            };
            assert_eq!(
                flags.to_byte(),
                expected_byte,
                "exhaustive packing mismatch for: {}",
                fv.description
            );

            // Test unpacking
            let unpacked = PacketFlags::from_byte(expected_byte).expect("should parse");
            assert_eq!(
                unpacked, flags,
                "exhaustive unpacking mismatch for: {}",
                fv.description
            );
        }
    }

    #[test]
    fn test_flag_roundtrip() {
        // Test all valid combinations
        for ht in 0..=1u8 {
            for cf in 0..=1u8 {
                for tt in 0..=1u8 {
                    for dt in 0..=3u8 {
                        for pt in 0..=3u8 {
                            let byte = (ht << 6) | (cf << 5) | (tt << 4) | (dt << 2) | pt;
                            let flags = PacketFlags::from_byte(byte).unwrap();
                            assert_eq!(flags.to_byte(), byte);
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn test_flags_malformed_reserved_bit_set() {
        // Bit 7 (0x80) is reserved/unused. The parser shifts byte>>6 & 0x01,
        // so bit 7 is effectively shifted out. Verify that bytes 0x80..0xFF
        // parse identically to their lower 7-bit equivalents.
        for byte in 0x80..=0xFFu8 {
            let with_bit7 = PacketFlags::from_byte(byte);
            let without_bit7 = PacketFlags::from_byte(byte & 0x7F);
            assert_eq!(
                with_bit7.is_ok(),
                without_bit7.is_ok(),
                "bit 7 should not affect parse success for byte 0x{byte:02x}"
            );
            if let (Ok(a), Ok(b)) = (with_bit7, without_bit7) {
                assert_eq!(
                    a, b,
                    "bit 7 should not affect parsed flags for 0x{byte:02x}"
                );
            }
        }
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    fn valid_flags_byte() -> impl Strategy<Value = u8> {
        (0..=1u8, 0..=1u8, 0..=1u8, 0..=3u8, 0..=3u8)
            .prop_map(|(ht, cf, tt, dt, pt)| (ht << 6) | (cf << 5) | (tt << 4) | (dt << 2) | pt)
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn flags_roundtrip(byte in valid_flags_byte()) {
            let flags = PacketFlags::from_byte(byte).unwrap();
            prop_assert_eq!(flags.to_byte(), byte);
        }
    }
}
