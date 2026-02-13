//! Protocol constants and enumerations for the Reticulum protocol.

use crate::error::PacketError;

// Wire format sizes (from test vectors)
pub const MTU: usize = 500;
pub const HEADER_1_SIZE: usize = 19;
pub const HEADER_2_SIZE: usize = 35;
pub const HEADER_MINSIZE: usize = HEADER_1_SIZE;
pub const HEADER_MAXSIZE: usize = HEADER_2_SIZE;
pub const PLAIN_MDU: usize = 464;
pub const ENCRYPTED_MDU: usize = 383;

// Hash and key sizes
pub const TRUNCATED_HASHLENGTH: usize = 16;
pub const HASHLENGTH: usize = 32;
pub const KEYSIZE: usize = 64;
pub const SIGLENGTH: usize = 64;
pub const NAME_HASH_LENGTH: usize = 10;
pub const RANDOM_HASH_LENGTH: usize = 10;
pub const TOKEN_OVERHEAD: usize = 48;
pub const RATCHETSIZE: usize = 32;

// Announce sizes
pub const ANNOUNCE_MIN_PAYLOAD: usize = KEYSIZE + NAME_HASH_LENGTH + RANDOM_HASH_LENGTH + SIGLENGTH; // 148

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HeaderType {
    Header1 = 0,
    Header2 = 1,
}

impl HeaderType {
    pub fn from_u8(v: u8) -> Result<Self, PacketError> {
        match v {
            0 => Ok(HeaderType::Header1),
            1 => Ok(HeaderType::Header2),
            _ => Err(PacketError::InvalidHeaderType(v)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TransportType {
    Broadcast = 0,
    Transport = 1,
}

impl TransportType {
    pub fn from_u8(v: u8) -> Result<Self, PacketError> {
        match v {
            0 => Ok(TransportType::Broadcast),
            1 => Ok(TransportType::Transport),
            _ => Err(PacketError::InvalidTransportType(v)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DestinationType {
    Single = 0,
    Group = 1,
    Plain = 2,
    Link = 3,
}

impl DestinationType {
    pub fn from_u8(v: u8) -> Result<Self, PacketError> {
        match v {
            0 => Ok(DestinationType::Single),
            1 => Ok(DestinationType::Group),
            2 => Ok(DestinationType::Plain),
            3 => Ok(DestinationType::Link),
            _ => Err(PacketError::InvalidDestinationType(v)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketType {
    Data = 0,
    Announce = 1,
    LinkRequest = 2,
    Proof = 3,
}

impl PacketType {
    pub fn from_u8(v: u8) -> Result<Self, PacketError> {
        match v {
            0 => Ok(PacketType::Data),
            1 => Ok(PacketType::Announce),
            2 => Ok(PacketType::LinkRequest),
            3 => Ok(PacketType::Proof),
            _ => Err(PacketError::InvalidPacketType(v)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants_match_test_vectors() {
        let v = reticulum_test_vectors::packet_headers::load();
        let constants = &v.constants;

        assert_eq!(MTU, constants.mtu_bytes as usize);
        assert_eq!(HEADER_1_SIZE, constants.header_1_size_bytes as usize);
        assert_eq!(HEADER_2_SIZE, constants.header_2_size_bytes as usize);
        assert_eq!(
            TRUNCATED_HASHLENGTH,
            constants.truncated_hash_length_bytes as usize
        );
        assert_eq!(PLAIN_MDU, constants.plain_mdu_bytes as usize);
        assert_eq!(ENCRYPTED_MDU, constants.encrypted_mdu_bytes as usize);
        assert_eq!(HEADER_MAXSIZE, constants.header_maxsize_bytes as usize);
    }

    #[test]
    fn test_keypair_constants_match_test_vectors() {
        let v = reticulum_test_vectors::keypairs::load();
        let constants = &v.constants;

        assert_eq!(
            TRUNCATED_HASHLENGTH,
            constants.truncated_hash_length_bytes as usize
        );
        assert_eq!(NAME_HASH_LENGTH, constants.name_hash_length_bytes as usize);
        assert_eq!(KEYSIZE, constants.key_size_bytes as usize);
        assert_eq!(SIGLENGTH, constants.signature_length_bytes as usize);
        assert_eq!(TOKEN_OVERHEAD, constants.token_overhead_bytes as usize);
    }

    #[test]
    fn test_announce_constants_match_test_vectors() {
        let v = reticulum_test_vectors::announces::load();
        let constants = &v.constants;

        assert_eq!(
            ANNOUNCE_MIN_PAYLOAD,
            constants.announce_min_payload_bytes as usize
        );
        assert_eq!(RATCHETSIZE, constants.ratchetsize_bytes as usize);
        assert_eq!(
            RANDOM_HASH_LENGTH,
            constants.random_hash_length_bytes as usize
        );
    }

    #[test]
    fn test_enum_values() {
        assert_eq!(HeaderType::Header1 as u8, 0);
        assert_eq!(HeaderType::Header2 as u8, 1);
        assert_eq!(TransportType::Broadcast as u8, 0);
        assert_eq!(TransportType::Transport as u8, 1);
        assert_eq!(DestinationType::Single as u8, 0);
        assert_eq!(DestinationType::Group as u8, 1);
        assert_eq!(DestinationType::Plain as u8, 2);
        assert_eq!(DestinationType::Link as u8, 3);
        assert_eq!(PacketType::Data as u8, 0);
        assert_eq!(PacketType::Announce as u8, 1);
        assert_eq!(PacketType::LinkRequest as u8, 2);
        assert_eq!(PacketType::Proof as u8, 3);
    }
}
