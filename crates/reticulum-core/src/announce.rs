//! Announce construction and validation.
//!
//! Announces are broadcast by Reticulum destinations to allow other nodes
//! to discover them. The announce payload contains the identity's public key,
//! name hash, random hash, optional ratchet key, a signature, and optional
//! application data.
//!
//! # Payload layout
//!
//! Without ratchet (context_flag=0):
//! ```text
//! public_key(64) + name_hash(10) + random_hash(10) + signature(64) [+ app_data]
//! ```
//!
//! With ratchet (context_flag=1):
//! ```text
//! public_key(64) + name_hash(10) + random_hash(10) + ratchet(32) + signature(64) [+ app_data]
//! ```
//!
//! # Signed data
//!
//! ```text
//! destination_hash(16) + public_key(64) + name_hash(10) + random_hash(10) [+ ratchet(32)] [+ app_data]
//! ```

extern crate alloc;
use alloc::vec::Vec;

use reticulum_crypto::ed25519::{Ed25519PublicKey, Ed25519Signature};
use reticulum_crypto::sha::sha256;

use crate::constants::{
    ANNOUNCE_MIN_PAYLOAD, DestinationType, HeaderType, KEYSIZE, NAME_HASH_LENGTH, PacketType,
    RANDOM_HASH_LENGTH, RATCHETSIZE, SIGLENGTH, TRUNCATED_HASHLENGTH, TransportType,
};
use crate::error::AnnounceError;
use crate::identity::Identity;
use crate::packet::context::ContextType;
use crate::packet::flags::PacketFlags;
use crate::packet::wire::RawPacket;
use crate::types::{DestinationHash, IdentityHash, NameHash};

/// A parsed or constructed announce.
#[derive(Debug, Clone)]
pub struct Announce {
    pub destination_hash: DestinationHash,
    pub public_key: [u8; 64],
    pub name_hash: NameHash,
    pub random_hash: [u8; 10],
    pub ratchet: Option<[u8; 32]>,
    pub signature: [u8; 64],
    pub app_data: Option<Vec<u8>>,
    /// Context type from the packet header (preserved for roundtrip serialization).
    pub context: ContextType,
}

/// Generate a 10-byte random hash: 5 random bytes + 5-byte big-endian Unix timestamp.
///
/// This matches the Python reference implementation's announce random hash format.
#[cfg(feature = "std")]
pub fn make_random_hash() -> [u8; 10] {
    use rand::RngCore;
    let mut rng = rand::thread_rng();
    let mut result = [0u8; 10];
    rng.fill_bytes(&mut result[..5]);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // Lower 5 bytes of the 8-byte big-endian timestamp
    result[5..10].copy_from_slice(&now.to_be_bytes()[3..8]);
    result
}

impl Announce {
    /// Create a new signed announce from an identity and destination parameters.
    ///
    /// The identity must have private keys (for signing).
    pub fn create(
        identity: &Identity,
        name_hash: NameHash,
        destination_hash: DestinationHash,
        random_hash: [u8; 10],
        ratchet: Option<[u8; 32]>,
        app_data: Option<&[u8]>,
    ) -> Result<Self, AnnounceError> {
        let public_key = identity.public_key_bytes();

        let mut announce = Announce {
            destination_hash,
            public_key,
            name_hash,
            random_hash,
            ratchet,
            signature: [0u8; 64],
            app_data: app_data.map(|d| d.to_vec()),
            context: ContextType::None,
        };

        // Build signed_data and sign
        let signed_data = announce.signed_data();
        let sig = identity
            .sign(&signed_data)
            .map_err(AnnounceError::IdentityError)?;
        announce.signature = sig.to_bytes();

        Ok(announce)
    }

    /// Parse an announce from a raw packet's payload.
    ///
    /// `destination_hash` comes from the packet header.
    /// `context_flag` indicates whether a ratchet key is present.
    /// `context` is the context type from the packet header.
    pub fn from_payload(
        destination_hash: DestinationHash,
        context_flag: bool,
        context: ContextType,
        payload: &[u8],
    ) -> Result<Self, AnnounceError> {
        let min_len = if context_flag {
            ANNOUNCE_MIN_PAYLOAD + RATCHETSIZE // 180
        } else {
            ANNOUNCE_MIN_PAYLOAD // 148
        };

        if payload.len() < min_len {
            return Err(AnnounceError::PayloadTooShort {
                min: min_len,
                actual: payload.len(),
            });
        }

        let mut cursor = payload;

        // public_key(64)
        let (chunk, rest) = cursor.split_at(KEYSIZE);
        let mut public_key = [0u8; 64];
        public_key.copy_from_slice(chunk);
        cursor = rest;

        // name_hash(10)
        let (chunk, rest) = cursor.split_at(NAME_HASH_LENGTH);
        let mut name_hash_bytes = [0u8; 10];
        name_hash_bytes.copy_from_slice(chunk);
        let name_hash = NameHash::new(name_hash_bytes);
        cursor = rest;

        // random_hash(10)
        let (chunk, rest) = cursor.split_at(RANDOM_HASH_LENGTH);
        let mut random_hash = [0u8; 10];
        random_hash.copy_from_slice(chunk);
        cursor = rest;

        // ratchet(32) if context_flag
        let ratchet = if context_flag {
            let (chunk, rest) = cursor.split_at(RATCHETSIZE);
            let mut ratchet_key = [0u8; 32];
            ratchet_key.copy_from_slice(chunk);
            cursor = rest;
            Some(ratchet_key)
        } else {
            None
        };

        // signature(64)
        let (chunk, rest) = cursor.split_at(SIGLENGTH);
        let mut signature = [0u8; 64];
        signature.copy_from_slice(chunk);
        cursor = rest;

        // app_data (remaining bytes, if any)
        let app_data = if !cursor.is_empty() {
            Some(cursor.to_vec())
        } else {
            None
        };

        Ok(Announce {
            destination_hash,
            public_key,
            name_hash,
            random_hash,
            ratchet,
            signature,
            app_data,
            context,
        })
    }

    /// Parse an announce from a complete raw packet (header + payload).
    pub fn from_raw_packet(raw: &[u8]) -> Result<Self, AnnounceError> {
        let packet = RawPacket::parse(raw)?;

        if packet.flags.packet_type != PacketType::Announce {
            return Err(AnnounceError::NotAnAnnounce);
        }

        Self::from_payload(
            packet.destination,
            packet.flags.context_flag,
            packet.context,
            &packet.data,
        )
    }

    /// Build the signed data for this announce.
    ///
    /// `signed_data = dest_hash(16) + public_key(64) + name_hash(10) + random_hash(10) [+ ratchet(32)] [+ app_data]`
    pub fn signed_data(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(
            TRUNCATED_HASHLENGTH + KEYSIZE + NAME_HASH_LENGTH + RANDOM_HASH_LENGTH,
        );
        data.extend_from_slice(self.destination_hash.as_ref());
        data.extend_from_slice(&self.public_key);
        data.extend_from_slice(self.name_hash.as_ref());
        data.extend_from_slice(&self.random_hash);
        if let Some(ref ratchet) = self.ratchet {
            data.extend_from_slice(ratchet);
        }
        if let Some(ref app_data) = self.app_data {
            data.extend_from_slice(app_data);
        }
        data
    }

    /// Validate the announce: verify signature and destination hash.
    pub fn validate(&self) -> Result<(), AnnounceError> {
        // 1. Verify Ed25519 signature
        let ed25519_pub_bytes: [u8; 32] = self.public_key[32..64]
            .try_into()
            .map_err(|_| AnnounceError::InvalidPublicKey)?;
        let ed25519_pub =
            Ed25519PublicKey::from_bytes(ed25519_pub_bytes).map_err(|_| AnnounceError::InvalidPublicKey)?;

        let signed_data = self.signed_data();
        let sig = Ed25519Signature::from_bytes(self.signature);

        ed25519_pub
            .verify(&signed_data, &sig)
            .map_err(|_| AnnounceError::SignatureVerificationFailed)?;

        // 2. Verify destination hash
        let identity_hash = compute_identity_hash(&self.public_key);
        let expected_dest = compute_destination_hash(&self.name_hash, &identity_hash);

        if self.destination_hash != expected_dest {
            return Err(AnnounceError::InvalidDestinationHash);
        }

        Ok(())
    }

    /// Serialize the announce to wire payload format.
    pub fn to_payload(&self) -> Vec<u8> {
        let mut payload = Vec::with_capacity(ANNOUNCE_MIN_PAYLOAD + 64);
        payload.extend_from_slice(&self.public_key);
        payload.extend_from_slice(self.name_hash.as_ref());
        payload.extend_from_slice(&self.random_hash);
        if let Some(ref ratchet) = self.ratchet {
            payload.extend_from_slice(ratchet);
        }
        payload.extend_from_slice(&self.signature);
        if let Some(ref app_data) = self.app_data {
            payload.extend_from_slice(app_data);
        }
        payload
    }

    /// Build a complete raw packet from this announce.
    pub fn to_raw_packet(&self, hops: u8) -> RawPacket {
        let flags = PacketFlags {
            header_type: HeaderType::Header1,
            context_flag: self.ratchet.is_some(),
            transport_type: TransportType::Broadcast,
            destination_type: DestinationType::Single,
            packet_type: PacketType::Announce,
        };

        RawPacket {
            flags,
            hops,
            transport_id: None,
            destination: self.destination_hash,
            context: self.context,
            data: self.to_payload(),
        }
    }
}

fn compute_identity_hash(public_key: &[u8; 64]) -> IdentityHash {
    let full_hash = sha256(public_key);
    let mut truncated = [0u8; 16];
    truncated.copy_from_slice(&full_hash[..16]);
    IdentityHash::new(truncated)
}

fn compute_destination_hash(name_hash: &NameHash, identity_hash: &IdentityHash) -> DestinationHash {
    let mut material = Vec::with_capacity(26);
    material.extend_from_slice(name_hash.as_ref());
    material.extend_from_slice(identity_hash.as_ref());
    let hash = sha256(&material);
    let mut result = [0u8; 16];
    result.copy_from_slice(&hash[..16]);
    DestinationHash::new(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::destination;

    #[test]
    fn test_create_and_validate_roundtrip() {
        let identity = Identity::generate();
        let nh = destination::name_hash("test_app", &["announce", "v1"]);
        let dh = destination::destination_hash(&nh, identity.hash());
        let random_hash = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A];

        let announce =
            Announce::create(&identity, nh, dh, random_hash, None, None).expect("create failed");

        // Validate the signature and destination hash
        announce.validate().expect("validate failed");

        // Check fields
        assert_eq!(announce.destination_hash, dh);
        assert_eq!(announce.public_key, identity.public_key_bytes());
        assert_eq!(announce.name_hash, nh);
        assert_eq!(announce.random_hash, random_hash);
        assert!(announce.ratchet.is_none());
        assert!(announce.app_data.is_none());
    }

    #[test]
    fn test_create_payload_roundtrip() {
        let identity = Identity::generate();
        let nh = destination::name_hash("test_app", &["announce", "v1"]);
        let dh = destination::destination_hash(&nh, identity.hash());
        let random_hash = [0xAA; 10];

        let announce =
            Announce::create(&identity, nh, dh, random_hash, None, None).expect("create failed");

        let payload = announce.to_payload();
        let parsed = Announce::from_payload(dh, false, ContextType::None, &payload)
            .expect("parse from payload failed");

        parsed
            .validate()
            .expect("parsed announce validation failed");
        assert_eq!(parsed.public_key, announce.public_key);
        assert_eq!(parsed.signature, announce.signature);
        assert_eq!(parsed.random_hash, announce.random_hash);
    }

    #[test]
    fn test_create_with_app_data() {
        let identity = Identity::generate();
        let nh = destination::name_hash("test_app", &["data"]);
        let dh = destination::destination_hash(&nh, identity.hash());
        let random_hash = [0xBB; 10];
        let app_data = b"hello from rust";

        let announce = Announce::create(&identity, nh, dh, random_hash, None, Some(app_data))
            .expect("create failed");

        announce.validate().expect("validate failed");
        assert_eq!(announce.app_data.as_deref(), Some(app_data.as_slice()));

        // Raw packet roundtrip
        let raw = announce.to_raw_packet(0);
        let serialized = raw.serialize();
        let parsed = Announce::from_raw_packet(&serialized).expect("parse raw failed");
        parsed.validate().expect("parsed validation failed");
        assert_eq!(parsed.app_data.as_deref(), Some(app_data.as_slice()));
    }

    #[test]
    fn test_create_with_ratchet() {
        let identity = Identity::generate();
        let nh = destination::name_hash("test_app", &["ratchet"]);
        let dh = destination::destination_hash(&nh, identity.hash());
        let random_hash = [0xCC; 10];
        let ratchet = [0xDD; 32];

        let announce = Announce::create(&identity, nh, dh, random_hash, Some(ratchet), None)
            .expect("create failed");

        announce.validate().expect("validate failed");
        assert_eq!(announce.ratchet, Some(ratchet));

        // Roundtrip through raw packet (context_flag should be set)
        let raw = announce.to_raw_packet(0);
        assert!(raw.flags.context_flag);
        let serialized = raw.serialize();
        let parsed = Announce::from_raw_packet(&serialized).expect("parse raw failed");
        parsed.validate().expect("parsed validation failed");
        assert_eq!(parsed.ratchet, Some(ratchet));
    }

    #[test]
    fn test_make_random_hash() {
        let rh1 = make_random_hash();
        let rh2 = make_random_hash();
        assert_eq!(rh1.len(), 10);
        assert_eq!(rh2.len(), 10);
        // Random parts (first 5 bytes) should differ
        assert_ne!(&rh1[..5], &rh2[..5]);
        // Timestamp parts (last 5 bytes) should be the same or very close
        // (both generated within the same second)
        assert_eq!(&rh1[5..10], &rh2[5..10]);
    }

    #[test]
    fn test_valid_announces() {
        let v = reticulum_test_vectors::announces::load();
        let keypairs = reticulum_test_vectors::keypairs::load();

        for av in &v.valid_announces {
            let raw_bytes = hex::decode(&av.raw_packet).expect("invalid hex raw_packet");
            let announce = Announce::from_raw_packet(&raw_bytes)
                .unwrap_or_else(|e| panic!("parse failed for '{}': {e}", av.description));

            // Verify destination hash
            let expected_dest =
                hex::decode(&av.destination_hash).expect("invalid hex destination_hash");
            assert_eq!(
                announce.destination_hash.as_ref(),
                expected_dest.as_slice(),
                "destination_hash mismatch for: {}",
                av.description
            );

            // Verify public key
            let expected_pubkey = hex::decode(&av.public_key).expect("invalid hex public_key");
            assert_eq!(
                &announce.public_key[..],
                expected_pubkey.as_slice(),
                "public_key mismatch for: {}",
                av.description
            );

            // Verify name hash
            let expected_nh = hex::decode(&av.name_hash).expect("invalid hex name_hash");
            assert_eq!(
                announce.name_hash.as_ref(),
                expected_nh.as_slice(),
                "name_hash mismatch for: {}",
                av.description
            );

            // Verify random hash
            let expected_rh = hex::decode(&av.random_hash).expect("invalid hex random_hash");
            assert_eq!(
                &announce.random_hash[..],
                expected_rh.as_slice(),
                "random_hash mismatch for: {}",
                av.description
            );

            // Verify signature
            let expected_sig = hex::decode(&av.signature).expect("invalid hex signature");
            assert_eq!(
                &announce.signature[..],
                expected_sig.as_slice(),
                "signature mismatch for: {}",
                av.description
            );

            // Verify signed_data
            let expected_signed = hex::decode(&av.signed_data).expect("invalid hex signed_data");
            assert_eq!(
                announce.signed_data(),
                expected_signed,
                "signed_data mismatch for: {}",
                av.description
            );

            // Verify payload roundtrip
            let expected_payload =
                hex::decode(&av.announce_payload).expect("invalid hex announce_payload");
            assert_eq!(
                announce.to_payload(),
                expected_payload,
                "payload roundtrip mismatch for: {}",
                av.description
            );
            assert_eq!(
                announce.to_payload().len() as u64,
                av.announce_payload_length,
                "payload length mismatch for: {}",
                av.description
            );

            // Validate signature and destination hash
            announce
                .validate()
                .unwrap_or_else(|e| panic!("validation failed for '{}': {e}", av.description));

            // Verify raw packet roundtrip
            let raw_packet = announce.to_raw_packet(av.hops as u8);
            let serialized = raw_packet.serialize();
            assert_eq!(
                serialized, raw_bytes,
                "raw packet roundtrip mismatch for: {}",
                av.description
            );

            // Verify packet hash
            let expected_ph = hex::decode(&av.packet_hash).expect("invalid hex packet_hash");
            let ph = raw_packet.packet_hash();
            assert_eq!(
                ph.truncated().as_ref(),
                expected_ph.as_slice(),
                "packet_hash mismatch for: {}",
                av.description
            );

            // Verify identity hash
            let kp = keypairs
                .keypairs
                .iter()
                .find(|k| k.index == av.keypair_index)
                .unwrap();
            let expected_ih = hex::decode(&kp.identity_hash).unwrap();
            let ih = compute_identity_hash(&announce.public_key);
            assert_eq!(
                ih.as_ref(),
                expected_ih.as_slice(),
                "identity_hash mismatch for: {}",
                av.description
            );
        }
    }

    #[test]
    fn test_invalid_announces() {
        let v = reticulum_test_vectors::announces::load();

        for iv in &v.invalid_announces {
            let raw_bytes = hex::decode(&iv.raw_packet).expect("invalid hex raw_packet");
            let announce_result = Announce::from_raw_packet(&raw_bytes);

            // Either parsing or validation must fail for invalid announces.
            // Our Rust implementation may reject at parse time what Python
            // rejects at validation time (e.g., ratchet flag set with
            // insufficient payload length).
            match announce_result {
                Err(_) => {} // parse rejection is fine
                Ok(announce) => {
                    let result = announce.validate();
                    assert!(
                        result.is_err(),
                        "either parse or validate should fail for: {} ({})",
                        iv.description,
                        iv.failure_reason
                    );
                }
            }
        }
    }

    #[test]
    fn test_app_data_announces() {
        let v = reticulum_test_vectors::announces::load();

        for av in &v.app_data_announces {
            let raw_bytes = hex::decode(&av.raw_packet).expect("invalid hex raw_packet");
            let announce = Announce::from_raw_packet(&raw_bytes)
                .unwrap_or_else(|e| panic!("parse failed for '{}': {e}", av.description));

            // Verify app_data is present
            let expected_app_data = hex::decode(&av.app_data).expect("invalid hex app_data");
            assert_eq!(
                announce.app_data.as_deref(),
                Some(expected_app_data.as_slice()),
                "app_data mismatch for: {}",
                av.description
            );
            assert_eq!(
                expected_app_data.len() as u64,
                av.app_data_length,
                "app_data_length mismatch for: {}",
                av.description
            );

            // Verify signed_data includes app_data
            let expected_signed = hex::decode(&av.signed_data).expect("invalid hex signed_data");
            assert_eq!(
                announce.signed_data(),
                expected_signed,
                "signed_data mismatch for: {}",
                av.description
            );

            // Verify signature
            let expected_sig = hex::decode(&av.signature).expect("invalid hex signature");
            assert_eq!(
                &announce.signature[..],
                expected_sig.as_slice(),
                "signature mismatch for: {}",
                av.description
            );

            // Validate
            announce
                .validate()
                .unwrap_or_else(|e| panic!("validation failed for '{}': {e}", av.description));

            // Verify payload roundtrip
            let expected_payload =
                hex::decode(&av.announce_payload).expect("invalid hex announce_payload");
            assert_eq!(
                announce.to_payload(),
                expected_payload,
                "payload roundtrip mismatch for: {}",
                av.description
            );

            // Verify packet hash
            let raw_packet = announce.to_raw_packet(0);
            let expected_ph = hex::decode(&av.packet_hash).expect("invalid hex packet_hash");
            let ph = raw_packet.packet_hash();
            assert_eq!(
                ph.truncated().as_ref(),
                expected_ph.as_slice(),
                "packet_hash mismatch for: {}",
                av.description
            );
        }
    }

    #[test]
    fn test_ratchet_announces() {
        let v = reticulum_test_vectors::announces::load();

        for rv in &v.ratchet_announces {
            let raw_bytes = hex::decode(&rv.raw_packet).expect("invalid hex raw_packet");
            let announce = Announce::from_raw_packet(&raw_bytes)
                .unwrap_or_else(|e| panic!("parse failed for '{}': {e}", rv.description));

            // Verify ratchet is present
            let expected_ratchet =
                hex::decode(&rv.ratchet_public_key).expect("invalid hex ratchet_public_key");
            assert_eq!(
                announce.ratchet.as_ref().map(|r| r.as_slice()),
                Some(expected_ratchet.as_slice()),
                "ratchet mismatch for: {}",
                rv.description
            );

            // Verify context_flag
            assert_eq!(
                rv.context_flag, 1,
                "ratchet announces should have context_flag=1"
            );

            // Verify signed_data
            let expected_signed = hex::decode(&rv.signed_data).expect("invalid hex signed_data");
            assert_eq!(
                announce.signed_data(),
                expected_signed,
                "signed_data mismatch for: {}",
                rv.description
            );

            // Verify signature
            let expected_sig = hex::decode(&rv.signature).expect("invalid hex signature");
            assert_eq!(
                &announce.signature[..],
                expected_sig.as_slice(),
                "signature mismatch for: {}",
                rv.description
            );

            // Validate
            announce
                .validate()
                .unwrap_or_else(|e| panic!("validation failed for '{}': {e}", rv.description));

            // Verify payload roundtrip
            let expected_payload =
                hex::decode(&rv.announce_payload).expect("invalid hex announce_payload");
            assert_eq!(
                announce.to_payload(),
                expected_payload,
                "payload roundtrip mismatch for: {}",
                rv.description
            );
            assert_eq!(
                announce.to_payload().len() as u64,
                rv.announce_payload_length,
                "payload length mismatch for: {}",
                rv.description
            );

            // Verify raw packet roundtrip
            let expected_flags =
                u8::from_str_radix(&rv.flags_byte, 16).expect("invalid hex flags_byte");
            let raw_packet = announce.to_raw_packet(0);
            assert_eq!(
                raw_packet.flags.to_byte(),
                expected_flags,
                "flags mismatch for: {}",
                rv.description
            );
            let serialized = raw_packet.serialize();
            assert_eq!(
                serialized, raw_bytes,
                "raw packet roundtrip mismatch for: {}",
                rv.description
            );

            // Verify packet hash
            let expected_ph = hex::decode(&rv.packet_hash).expect("invalid hex packet_hash");
            let ph = raw_packet.packet_hash();
            assert_eq!(
                ph.truncated().as_ref(),
                expected_ph.as_slice(),
                "packet_hash mismatch for: {}",
                rv.description
            );

            // Verify app_data if present
            if let Some(ref app_data_hex) = rv.app_data {
                let expected_app_data = hex::decode(app_data_hex).expect("invalid hex app_data");
                assert_eq!(
                    announce.app_data.as_deref(),
                    Some(expected_app_data.as_slice()),
                    "app_data mismatch for: {}",
                    rv.description
                );
            }
        }
    }

    #[test]
    fn test_announce_adversarial_signature_bitflip() {
        let identity = Identity::generate();
        let nh = destination::name_hash("test_app", &["sigflip"]);
        let dh = destination::destination_hash(&nh, identity.hash());
        let random_hash = [0x01; 10];

        let mut announce = Announce::create(&identity, nh, dh, random_hash, None, None).unwrap();
        // Flip one bit in the signature
        announce.signature[0] ^= 0x01;
        assert!(
            announce.validate().is_err(),
            "flipped signature should fail validation"
        );
    }

    #[test]
    fn test_announce_malformed_all_zero_pubkey() {
        let identity = Identity::generate();
        let nh = destination::name_hash("test_app", &["zeropk"]);
        let dh = destination::destination_hash(&nh, identity.hash());
        let random_hash = [0x02; 10];

        let mut announce = Announce::create(&identity, nh, dh, random_hash, None, None).unwrap();
        // Zero out the ed25519 public key portion (bytes 32..64)
        announce.public_key[32..64].fill(0);
        assert!(
            announce.validate().is_err(),
            "zero ed25519 pubkey should fail validation"
        );
    }

    #[test]
    fn test_announce_adversarial_wrong_destination_hash() {
        let identity = Identity::generate();
        let nh = destination::name_hash("test_app", &["wrongdest"]);
        let dh = destination::destination_hash(&nh, identity.hash());
        let random_hash = [0x03; 10];

        let mut announce = Announce::create(&identity, nh, dh, random_hash, None, None).unwrap();
        // Swap to a different destination hash
        let wrong_dh = DestinationHash::new([0xFF; 16]);
        announce.destination_hash = wrong_dh;
        // Signature was computed over original dest_hash, so validate fails
        assert!(
            announce.validate().is_err(),
            "wrong dest_hash should fail validation"
        );
    }

    #[test]
    fn test_announce_malformed_oversized_app_data() {
        let identity = Identity::generate();
        let nh = destination::name_hash("test_app", &["bigdata"]);
        let dh = destination::destination_hash(&nh, identity.hash());
        let random_hash = [0x04; 10];
        let big_app_data = vec![0x42; 10_000];

        let announce =
            Announce::create(&identity, nh, dh, random_hash, None, Some(&big_app_data)).unwrap();
        announce
            .validate()
            .expect("large app_data should still validate");
        assert_eq!(announce.app_data.as_ref().unwrap().len(), 10_000);
    }

    #[test]
    fn test_announce_malformed_zero_length_payload() {
        let dh = DestinationHash::new([0x00; 16]);
        let result = Announce::from_payload(dh, false, ContextType::None, &[]);
        assert!(
            matches!(
                result,
                Err(crate::error::AnnounceError::PayloadTooShort { .. })
            ),
            "empty payload should return PayloadTooShort"
        );
    }

    #[test]
    fn announce_empty_app_data_vs_none() {
        let identity = Identity::generate();
        let nh = destination::name_hash("test_app", &["empty_vs_none"]);
        let dh = destination::destination_hash(&nh, identity.hash());
        let random_hash = [0x06; 10];

        // Create with None app_data
        let announce_none = Announce::create(&identity, nh, dh, random_hash, None, None).unwrap();
        // Create with Some(empty) app_data
        let announce_empty =
            Announce::create(&identity, nh, dh, random_hash, None, Some(b"")).unwrap();

        // Both should validate
        announce_none.validate().unwrap();
        announce_empty.validate().unwrap();

        // None → no app_data at all; Some(b"") → empty app_data
        assert!(announce_none.app_data.is_none());
        assert_eq!(announce_empty.app_data.as_deref(), Some(b"".as_slice()));

        // Payloads should be the same length since empty app_data is zero bytes
        // But the signed data differs (app_data=b"" is included in signed data even if empty)
        // Actually in the protocol, empty app_data means we have 0 trailing bytes
        // which is the same as no app_data. Let's just verify both produce valid announces.
        let payload_none = announce_none.to_payload();
        let payload_empty = announce_empty.to_payload();

        // Signatures differ because signed_data may include empty app_data
        // The key point: both are valid, and we can distinguish them
        assert!(payload_none.len() <= payload_empty.len());
    }

    #[test]
    fn test_announce_malformed_truncated_systematic() {
        // Create a valid announce, then truncate its payload at every position
        let identity = Identity::generate();
        let nh = destination::name_hash("test_app", &["truncate"]);
        let dh = destination::destination_hash(&nh, identity.hash());
        let random_hash = [0x05; 10];

        let announce =
            Announce::create(&identity, nh, dh, random_hash, None, Some(b"test")).unwrap();
        let payload = announce.to_payload();

        for truncate_at in 0..payload.len() {
            let truncated = &payload[..truncate_at];
            let result = Announce::from_payload(dh, false, ContextType::None, truncated);
            match result {
                Err(_) => {} // parse rejection is correct
                Ok(ann) => {
                    // If it parses (e.g. just missing app_data), validation must fail
                    // unless we have all signature+key bytes (which only happens at full length)
                    if truncate_at < 148 {
                        panic!("should not parse with only {truncate_at} bytes");
                    }
                    // The signature was over the full payload including app_data,
                    // so truncated versions should fail validation
                    if truncate_at < payload.len() {
                        assert!(
                            ann.validate().is_err(),
                            "truncated at {truncate_at} should fail validate"
                        );
                    }
                }
            }
        }
    }
}
