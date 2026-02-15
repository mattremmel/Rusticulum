//! Packet context type enumeration.
//!
//! Context types identify the purpose of a packet's data payload,
//! enabling multiplexing of different protocol functions over the same link.

use crate::error::PacketError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[repr(u8)]
pub enum ContextType {
    None = 0,
    Resource = 1,
    ResourceAdv = 2,
    ResourceReq = 3,
    ResourceHmu = 4,
    ResourcePrf = 5,
    ResourceIcl = 6,
    ResourceRcl = 7,
    CacheRequest = 8,
    Request = 9,
    Response = 10,
    PathResponse = 11,
    Command = 12,
    CommandStatus = 13,
    Channel = 14,
    Keepalive = 250,
    LinkIdentify = 251,
    LinkClose = 252,
    LinkProof = 253,
    Lrrtt = 254,
    Lrproof = 255,
}

impl TryFrom<u8> for ContextType {
    type Error = PacketError;

    fn try_from(byte: u8) -> Result<Self, Self::Error> {
        match byte {
            0 => Ok(ContextType::None),
            1 => Ok(ContextType::Resource),
            2 => Ok(ContextType::ResourceAdv),
            3 => Ok(ContextType::ResourceReq),
            4 => Ok(ContextType::ResourceHmu),
            5 => Ok(ContextType::ResourcePrf),
            6 => Ok(ContextType::ResourceIcl),
            7 => Ok(ContextType::ResourceRcl),
            8 => Ok(ContextType::CacheRequest),
            9 => Ok(ContextType::Request),
            10 => Ok(ContextType::Response),
            11 => Ok(ContextType::PathResponse),
            12 => Ok(ContextType::Command),
            13 => Ok(ContextType::CommandStatus),
            14 => Ok(ContextType::Channel),
            250 => Ok(ContextType::Keepalive),
            251 => Ok(ContextType::LinkIdentify),
            252 => Ok(ContextType::LinkClose),
            253 => Ok(ContextType::LinkProof),
            254 => Ok(ContextType::Lrrtt),
            255 => Ok(ContextType::Lrproof),
            _ => Err(PacketError::InvalidContextType(byte)),
        }
    }
}

impl ContextType {

    #[must_use = "returns the encoded byte without side effects"]
    pub const fn to_byte(&self) -> u8 {
        *self as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_context_type_values_match_test_vectors() {
        let v = reticulum_test_vectors::packet_headers::load();
        let ctv = &v.context_type_values;

        let expected: &[(&str, u8)] = &[
            ("NONE", 0),
            ("RESOURCE", 1),
            ("RESOURCE_ADV", 2),
            ("RESOURCE_REQ", 3),
            ("RESOURCE_HMU", 4),
            ("RESOURCE_PRF", 5),
            ("RESOURCE_ICL", 6),
            ("RESOURCE_RCL", 7),
            ("CACHE_REQUEST", 8),
            ("REQUEST", 9),
            ("RESPONSE", 10),
            ("PATH_RESPONSE", 11),
            ("COMMAND", 12),
            ("COMMAND_STATUS", 13),
            ("CHANNEL", 14),
            ("KEEPALIVE", 250),
            ("LINKIDENTIFY", 251),
            ("LINKCLOSE", 252),
            ("LINKPROOF", 253),
            ("LRRTT", 254),
            ("LRPROOF", 255),
        ];

        for &(name, value) in expected {
            assert_eq!(
                ctv[name].as_u64().unwrap(),
                value as u64,
                "context type value mismatch for {name}"
            );
            // Verify our enum roundtrips
            let ct = ContextType::try_from(value).unwrap();
            assert_eq!(ct.to_byte(), value, "roundtrip failed for {name}");
        }
    }

    #[test]
    fn test_context_type_invalid() {
        // Values between 15 and 249 are invalid
        for v in [15, 16, 100, 200, 249] {
            assert!(ContextType::try_from(v).is_err());
        }
    }

    #[test]
    fn test_context_type_malformed_exhaustive() {
        // Exhaustively test all 256 byte values: exactly 21 succeed, 235 fail
        let mut success_count = 0u32;
        let mut fail_count = 0u32;
        for byte in 0..=255u8 {
            match ContextType::try_from(byte) {
                Ok(ct) => {
                    assert_eq!(ct.to_byte(), byte, "roundtrip failed for byte {byte}");
                    success_count += 1;
                }
                Err(PacketError::InvalidContextType(v)) => {
                    assert_eq!(v, byte);
                    fail_count += 1;
                }
                Err(other) => {
                    panic!("unexpected error variant for byte {byte}: {other}");
                }
            }
        }
        assert_eq!(
            success_count, 21,
            "exactly 21 context types should be valid"
        );
        assert_eq!(
            fail_count, 235,
            "exactly 235 context types should be invalid"
        );
    }
}
