//! Interface Access Code (IFAC) authentication.
//!
//! IFAC provides per-interface cryptographic authentication of packets.
//! It derives a signing identity from a network name and/or key, then
//! signs packets on transmit and verifies signatures on receive.

use reticulum_core::identity::Identity;
use reticulum_crypto::hkdf::hkdf;
use reticulum_crypto::sha::sha256;

use crate::error::IfacError;

/// Fixed salt for IFAC key derivation (from Reticulum.py line 152).
pub const IFAC_SALT: [u8; 32] = [
    0xad, 0xf5, 0x4d, 0x88, 0x2c, 0x9a, 0x9b, 0x80, 0x77, 0x1e, 0xb4, 0x99, 0x5d, 0x70, 0x2d, 0x4a,
    0x3e, 0x73, 0x33, 0x91, 0xb2, 0xa0, 0xf5, 0x3f, 0x41, 0x6d, 0x9f, 0x90, 0x7e, 0x55, 0xcf, 0xf8,
];

/// The IFAC flag bit in the first header byte.
pub const IFAC_FLAG: u8 = 0x80;

/// Minimum IFAC size in bytes.
pub const IFAC_MIN_SIZE: usize = 1;

/// IFAC configuration and identity for an interface.
pub struct IfacConfig {
    /// The 64-byte IFAC key.
    pub ifac_key: [u8; 64],
    /// The IFAC identity derived from the key.
    pub ifac_identity: Identity,
    /// Number of IFAC bytes to use (typically 8 or 16).
    pub ifac_size: usize,
}

impl IfacConfig {
    /// Derive an IFAC configuration from network name and/or key.
    ///
    /// At least one of `netname` or `netkey` must be `Some`.
    pub fn new(netname: Option<&str>, netkey: Option<&str>, ifac_size: usize) -> Self {
        let mut ifac_origin = Vec::new();
        if let Some(name) = netname {
            ifac_origin.extend_from_slice(&sha256(name.as_bytes()));
        }
        if let Some(key) = netkey {
            ifac_origin.extend_from_slice(&sha256(key.as_bytes()));
        }

        let ifac_origin_hash = sha256(&ifac_origin);
        let ifac_key_vec = hkdf(64, &ifac_origin_hash, Some(&IFAC_SALT), None);
        let ifac_key: [u8; 64] = ifac_key_vec.try_into().expect("HKDF returns 64 bytes");
        let ifac_identity = Identity::from_private_bytes(&ifac_key);

        Self {
            ifac_key,
            ifac_identity,
            ifac_size,
        }
    }
}

/// Apply IFAC authentication to a raw packet for transmission.
///
/// Algorithm:
/// 1. Sign the raw packet, take last `ifac_size` bytes as IFAC value
/// 2. Generate mask using HKDF(len=raw_len+ifac_size, derive_from=ifac, salt=ifac_key)
/// 3. Set IFAC flag in header, insert IFAC bytes after 2-byte header
/// 4. Mask: byte 0 XOR mask[0] | 0x80, byte 1 XOR mask[1],
///    bytes 2..2+ifac_size NOT masked, remaining bytes XOR mask[i]
pub fn ifac_apply(config: &IfacConfig, raw: &[u8]) -> Result<Vec<u8>, IfacError> {
    // Minimum: 2-byte header + at least 1 byte payload
    if raw.len() < 3 {
        return Err(IfacError::PacketTooShort {
            min: 3,
            actual: raw.len(),
        });
    }

    // Step 1: Sign and extract IFAC value
    let signature = config.ifac_identity.sign(raw)?;
    let sig_bytes = signature.to_bytes();
    let ifac = &sig_bytes[64 - config.ifac_size..];

    // Step 2: Generate mask
    let mask = hkdf(
        raw.len() + config.ifac_size,
        ifac,
        Some(&config.ifac_key),
        None,
    );

    // Step 3: Build new_raw = header_with_flag + ifac + payload
    let mut new_raw = Vec::with_capacity(2 + config.ifac_size + raw.len() - 2);
    new_raw.push(raw[0] | IFAC_FLAG);
    new_raw.push(raw[1]);
    new_raw.extend_from_slice(ifac);
    new_raw.extend_from_slice(&raw[2..]);

    // Step 4: Mask byte-by-byte
    let mut masked = Vec::with_capacity(new_raw.len());
    for (i, &byte) in new_raw.iter().enumerate() {
        if i == 0 {
            // XOR with mask, then force IFAC flag
            masked.push((byte ^ mask[i]) | IFAC_FLAG);
        } else if i == 1 || i > config.ifac_size + 1 {
            // Mask header byte 1 and payload
            masked.push(byte ^ mask[i]);
        } else {
            // IFAC bytes (2..2+ifac_size) are NOT masked
            masked.push(byte);
        }
    }

    Ok(masked)
}

/// Verify and strip IFAC authentication from a received packet.
///
/// Returns the original raw packet (without IFAC) on success.
///
/// Algorithm:
/// 1. Check IFAC flag is set
/// 2. Extract IFAC bytes (positions 2..2+ifac_size)
/// 3. Generate mask using HKDF(len=masked_len, derive_from=ifac, salt=ifac_key)
/// 4. Unmask: bytes 0..1 XOR mask[i], bytes 2..2+ifac_size NOT unmasked,
///    remaining bytes XOR mask[i]
/// 5. Clear IFAC flag, reassemble without IFAC bytes
/// 6. Verify signature matches
pub fn ifac_verify(config: &IfacConfig, masked_raw: &[u8]) -> Result<Vec<u8>, IfacError> {
    // Check minimum length before any indexing
    if masked_raw.len() < 2 + config.ifac_size + 1 {
        return Err(IfacError::PacketTooShort {
            min: 2 + config.ifac_size + 1,
            actual: masked_raw.len(),
        });
    }

    // Step 1: Check IFAC flag
    if masked_raw[0] & IFAC_FLAG != IFAC_FLAG {
        return Err(IfacError::MissingFlag);
    }

    // Step 2: Extract IFAC
    let ifac = &masked_raw[2..2 + config.ifac_size];

    // Step 3: Generate mask (length = full masked packet length)
    let mask = hkdf(masked_raw.len(), ifac, Some(&config.ifac_key), None);

    // Step 4: Unmask
    let mut unmasked = Vec::with_capacity(masked_raw.len());
    for (i, &byte) in masked_raw.iter().enumerate() {
        if i <= 1 || i > config.ifac_size + 1 {
            // Unmask header bytes and payload
            unmasked.push(byte ^ mask[i]);
        } else {
            // IFAC bytes stay clear
            unmasked.push(byte);
        }
    }

    // Step 5: Clear IFAC flag and reassemble
    let mut new_raw = Vec::with_capacity(unmasked.len() - config.ifac_size);
    new_raw.push(unmasked[0] & !IFAC_FLAG);
    new_raw.push(unmasked[1]);
    new_raw.extend_from_slice(&unmasked[2 + config.ifac_size..]);

    // Step 6: Verify IFAC
    let expected_sig = config.ifac_identity.sign(&new_raw)?;
    let expected_ifac = &expected_sig.to_bytes()[64 - config.ifac_size..];
    if ifac != expected_ifac {
        return Err(IfacError::AuthenticationFailed);
    }

    Ok(new_raw)
}

/// Check if a raw packet has the IFAC flag set.
pub fn has_ifac_flag(raw: &[u8]) -> bool {
    !raw.is_empty() && raw[0] & IFAC_FLAG == IFAC_FLAG
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_from_test(
        netname: Option<&str>,
        netkey: Option<&str>,
        ifac_size: usize,
    ) -> IfacConfig {
        IfacConfig::new(netname, netkey, ifac_size)
    }

    #[test]
    fn test_key_derivation_netname_only() {
        let vectors = reticulum_test_vectors::interface_framing::load();
        let kd = &vectors.ifac.key_derivation;
        let kd_vectors: Vec<serde_json::Value> = serde_json::from_value(kd["vectors"].clone())
            .expect("key_derivation.vectors should be array");

        let v = &kd_vectors[0]; // netname only
        let netname = v["ifac_netname"].as_str().unwrap();
        let expected_origin = v["ifac_origin"].as_str().unwrap();
        let expected_origin_hash = v["ifac_origin_hash"].as_str().unwrap();
        let expected_key = v["ifac_key"].as_str().unwrap();
        let expected_pubkey = v["identity_public_key"].as_str().unwrap();

        // Verify origin
        let origin = sha256(netname.as_bytes());
        assert_eq!(hex::encode(origin), expected_origin);

        // Verify origin_hash
        let origin_hash = sha256(&origin);
        assert_eq!(hex::encode(origin_hash), expected_origin_hash);

        // Verify key
        let key_vec = hkdf(64, &origin_hash, Some(&IFAC_SALT), None);
        assert_eq!(hex::encode(&key_vec), expected_key);

        // Verify identity public key
        let key: [u8; 64] = key_vec.try_into().unwrap();
        let identity = Identity::from_private_bytes(&key);
        assert_eq!(hex::encode(identity.public_key_bytes()), expected_pubkey);
    }

    #[test]
    fn test_key_derivation_netkey_only() {
        let vectors = reticulum_test_vectors::interface_framing::load();
        let kd = &vectors.ifac.key_derivation;
        let kd_vectors: Vec<serde_json::Value> = serde_json::from_value(kd["vectors"].clone())
            .expect("key_derivation.vectors should be array");

        let v = &kd_vectors[1]; // netkey only
        let netkey = v["ifac_netkey"].as_str().unwrap();
        let expected_origin = v["ifac_origin"].as_str().unwrap();
        let expected_origin_hash = v["ifac_origin_hash"].as_str().unwrap();
        let expected_key = v["ifac_key"].as_str().unwrap();
        let expected_pubkey = v["identity_public_key"].as_str().unwrap();

        let origin = sha256(netkey.as_bytes());
        assert_eq!(hex::encode(origin), expected_origin);

        let origin_hash = sha256(&origin);
        assert_eq!(hex::encode(origin_hash), expected_origin_hash);

        let key_vec = hkdf(64, &origin_hash, Some(&IFAC_SALT), None);
        assert_eq!(hex::encode(&key_vec), expected_key);

        let key: [u8; 64] = key_vec.try_into().unwrap();
        let identity = Identity::from_private_bytes(&key);
        assert_eq!(hex::encode(identity.public_key_bytes()), expected_pubkey);
    }

    #[test]
    fn test_key_derivation_both() {
        let vectors = reticulum_test_vectors::interface_framing::load();
        let kd = &vectors.ifac.key_derivation;
        let kd_vectors: Vec<serde_json::Value> = serde_json::from_value(kd["vectors"].clone())
            .expect("key_derivation.vectors should be array");

        let v = &kd_vectors[2]; // both netname and netkey
        let netname = v["ifac_netname"].as_str().unwrap();
        let netkey = v["ifac_netkey"].as_str().unwrap();
        let expected_origin = v["ifac_origin"].as_str().unwrap();
        let expected_origin_hash = v["ifac_origin_hash"].as_str().unwrap();
        let expected_key = v["ifac_key"].as_str().unwrap();
        let expected_pubkey = v["identity_public_key"].as_str().unwrap();

        let mut origin = Vec::new();
        origin.extend_from_slice(&sha256(netname.as_bytes()));
        origin.extend_from_slice(&sha256(netkey.as_bytes()));
        assert_eq!(hex::encode(&origin), expected_origin);

        let origin_hash = sha256(&origin);
        assert_eq!(hex::encode(origin_hash), expected_origin_hash);

        let key_vec = hkdf(64, &origin_hash, Some(&IFAC_SALT), None);
        assert_eq!(hex::encode(&key_vec), expected_key);

        let key: [u8; 64] = key_vec.try_into().unwrap();
        let identity = Identity::from_private_bytes(&key);
        assert_eq!(hex::encode(identity.public_key_bytes()), expected_pubkey);
    }

    #[test]
    fn test_ifac_config_new() {
        let vectors = reticulum_test_vectors::interface_framing::load();
        let kd = &vectors.ifac.key_derivation;
        let kd_vectors: Vec<serde_json::Value> = serde_json::from_value(kd["vectors"].clone())
            .expect("key_derivation.vectors should be array");

        // Test with netname only
        let v = &kd_vectors[0];
        let config = IfacConfig::new(Some(v["ifac_netname"].as_str().unwrap()), None, 16);
        assert_eq!(
            hex::encode(config.ifac_key),
            v["ifac_key"].as_str().unwrap()
        );

        // Test with netkey only
        let v = &kd_vectors[1];
        let config = IfacConfig::new(None, Some(v["ifac_netkey"].as_str().unwrap()), 16);
        assert_eq!(
            hex::encode(config.ifac_key),
            v["ifac_key"].as_str().unwrap()
        );

        // Test with both
        let v = &kd_vectors[2];
        let config = IfacConfig::new(
            Some(v["ifac_netname"].as_str().unwrap()),
            Some(v["ifac_netkey"].as_str().unwrap()),
            16,
        );
        assert_eq!(
            hex::encode(config.ifac_key),
            v["ifac_key"].as_str().unwrap()
        );
    }

    #[test]
    fn test_ifac_apply_roundtrip_size_8() {
        let vectors = reticulum_test_vectors::interface_framing::load();
        let v = &vectors.ifac.vectors[0]; // ifac_size=8

        let config = config_from_test(
            v.ifac_netname.as_deref(),
            v.ifac_netkey.as_deref(),
            v.ifac_size as usize,
        );
        let raw = hex::decode(&v.raw_packet).unwrap();

        // Apply
        let masked = ifac_apply(&config, &raw).unwrap();
        let expected_masked = hex::decode(v.masked_packet.as_ref().unwrap()).unwrap();
        assert_eq!(
            hex::encode(&masked),
            hex::encode(&expected_masked),
            "masked mismatch"
        );

        // Check IFAC value
        let expected_ifac = hex::decode(v.ifac_value.as_ref().unwrap()).unwrap();
        assert_eq!(&masked[2..2 + config.ifac_size], expected_ifac.as_slice());

        // Verify
        let recovered = ifac_verify(&config, &masked).unwrap();
        assert_eq!(recovered, raw);
    }

    #[test]
    fn test_ifac_apply_roundtrip_size_16() {
        let vectors = reticulum_test_vectors::interface_framing::load();
        let v = &vectors.ifac.vectors[1]; // ifac_size=16

        let config = config_from_test(
            v.ifac_netname.as_deref(),
            v.ifac_netkey.as_deref(),
            v.ifac_size as usize,
        );
        let raw = hex::decode(&v.raw_packet).unwrap();

        // Apply
        let masked = ifac_apply(&config, &raw).unwrap();
        let expected_masked = hex::decode(v.masked_packet.as_ref().unwrap()).unwrap();
        assert_eq!(
            hex::encode(&masked),
            hex::encode(&expected_masked),
            "masked mismatch"
        );

        // Check IFAC value
        let expected_ifac = hex::decode(v.ifac_value.as_ref().unwrap()).unwrap();
        assert_eq!(&masked[2..2 + config.ifac_size], expected_ifac.as_slice());

        // Verify
        let recovered = ifac_verify(&config, &masked).unwrap();
        assert_eq!(recovered, raw);
    }

    #[test]
    fn test_ifac_reject_tampered() {
        let vectors = reticulum_test_vectors::interface_framing::load();
        let v = &vectors.ifac.vectors[2]; // tampered packet

        let config = config_from_test(
            v.ifac_netname.as_deref(),
            v.ifac_netkey.as_deref(),
            v.ifac_size as usize,
        );
        let tampered = hex::decode(v.tampered_packet.as_ref().unwrap()).unwrap();

        let result = ifac_verify(&config, &tampered);
        assert!(result.is_err());
    }

    #[test]
    fn test_ifac_reject_wrong_key() {
        let vectors = reticulum_test_vectors::interface_framing::load();
        let v = &vectors.ifac.vectors[3]; // wrong key

        // Receiver uses different netname
        let receiver_config = config_from_test(
            v.receiver_netname.as_deref(),
            v.receiver_netkey.as_deref(),
            v.ifac_size as usize,
        );
        let masked = hex::decode(v.masked_packet.as_ref().unwrap()).unwrap();

        let result = ifac_verify(&receiver_config, &masked);
        assert!(result.is_err());
    }

    #[test]
    fn test_ifac_reject_missing_flag() {
        let vectors = reticulum_test_vectors::interface_framing::load();
        let v = &vectors.ifac.vectors[4]; // no IFAC flag

        let raw = hex::decode(&v.raw_packet).unwrap();
        assert!(!has_ifac_flag(&raw), "should not have IFAC flag set");

        // Any IFAC config should reject this
        let config = config_from_test(Some("testnet"), Some("testkey"), v.ifac_size as usize);
        let result = ifac_verify(&config, &raw);
        assert!(matches!(result, Err(IfacError::MissingFlag)));
    }

    #[test]
    fn test_has_ifac_flag() {
        assert!(!has_ifac_flag(&[0x00]));
        assert!(!has_ifac_flag(&[0x7F]));
        assert!(has_ifac_flag(&[0x80]));
        assert!(has_ifac_flag(&[0xFF]));
        assert!(!has_ifac_flag(&[]));
    }

    #[test]
    fn test_ifac_verify_empty_packet() {
        let config = config_from_test(Some("testnet"), Some("testkey"), 8);
        let result = ifac_verify(&config, &[]);
        assert!(matches!(result, Err(IfacError::PacketTooShort { .. })));
    }

    #[test]
    fn test_ifac_verify_one_byte_packet() {
        let config = config_from_test(Some("testnet"), Some("testkey"), 8);
        let result = ifac_verify(&config, &[0x80]);
        assert!(matches!(result, Err(IfacError::PacketTooShort { .. })));
    }

    #[test]
    fn test_ifac_verify_two_byte_packet() {
        let config = config_from_test(Some("testnet"), Some("testkey"), 8);
        let result = ifac_verify(&config, &[0x80, 0x00]);
        assert!(matches!(result, Err(IfacError::PacketTooShort { .. })));
    }

    #[test]
    fn test_ifac_apply_empty_packet() {
        let config = config_from_test(Some("testnet"), Some("testkey"), 8);
        let result = ifac_apply(&config, &[]);
        assert!(matches!(result, Err(IfacError::PacketTooShort { .. })));
    }

    #[test]
    fn test_ifac_apply_short_packet() {
        let config = config_from_test(Some("testnet"), Some("testkey"), 8);
        let result = ifac_apply(&config, &[0x00]);
        assert!(matches!(result, Err(IfacError::PacketTooShort { .. })));
    }

    #[test]
    fn test_ifac_full_pipeline_hdlc() {
        let vectors = reticulum_test_vectors::interface_framing::load();

        for pv in &vectors.full_pipeline.vectors {
            if pv.ifac_netname.is_none() && pv.ifac_netkey.is_none() {
                continue; // Skip non-IFAC pipelines
            }

            let config = config_from_test(
                pv.ifac_netname.as_deref(),
                pv.ifac_netkey.as_deref(),
                pv.ifac_size as usize,
            );
            let raw = hex::decode(&pv.step_0_raw).unwrap();
            let expected_applied = hex::decode(&pv.step_1_ifac_applied).unwrap();
            let expected_verified = hex::decode(&pv.step_4_ifac_verified).unwrap();

            // Apply IFAC
            let applied = ifac_apply(&config, &raw).unwrap();
            assert_eq!(
                hex::encode(&applied),
                hex::encode(&expected_applied),
                "apply mismatch for: {}",
                pv.description
            );

            // Verify IFAC
            let verified = ifac_verify(&config, &applied).unwrap();
            assert_eq!(
                hex::encode(&verified),
                hex::encode(&expected_verified),
                "verify mismatch for: {}",
                pv.description
            );
        }
    }
}
