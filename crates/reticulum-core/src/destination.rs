//! Destination types and hash derivation.
//!
//! A Reticulum destination identifies a specific endpoint on the network.
//! The destination hash is derived from the application name, aspects, and
//! (for non-PLAIN types) the identity hash.

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

use reticulum_crypto::sha::sha256;

use crate::constants::DestinationType;
use crate::types::{DestinationHash, IdentityHash, NameHash};

/// Compute the name hash for a destination.
///
/// `name_hash = SHA-256("app_name.aspect1.aspect2")[:10]`
#[must_use = "returns the computed name hash"]
pub fn name_hash(app_name: &str, aspects: &[&str]) -> NameHash {
    let base_name = build_base_name(app_name, aspects);
    let hash = sha256(base_name.as_bytes());
    let mut result = [0u8; 10];
    result.copy_from_slice(&hash[..10]);
    NameHash::new(result)
}

/// Compute the destination hash for a SINGLE destination.
///
/// `destination_hash = SHA-256(name_hash || identity_hash)[:16]`
#[must_use = "returns the computed destination hash"]
pub fn destination_hash(name_hash: &NameHash, identity_hash: &IdentityHash) -> DestinationHash {
    let mut material = Vec::with_capacity(26);
    material.extend_from_slice(name_hash.as_ref());
    material.extend_from_slice(identity_hash.as_ref());
    let hash = sha256(&material);
    let mut result = [0u8; 16];
    result.copy_from_slice(&hash[..16]);
    DestinationHash::new(result)
}

/// Compute the destination hash for a PLAIN destination (no identity).
///
/// `destination_hash = SHA-256(name_hash)[:16]`
#[must_use = "returns the computed destination hash"]
pub fn plain_destination_hash(name_hash: &NameHash) -> DestinationHash {
    let hash = sha256(name_hash.as_ref());
    let mut result = [0u8; 16];
    result.copy_from_slice(&hash[..16]);
    DestinationHash::new(result)
}

/// A Reticulum destination.
#[must_use]
pub struct Destination {
    pub identity_hash: Option<IdentityHash>,
    pub app_name: String,
    pub aspects: Vec<String>,
    pub dtype: DestinationType,
    name_hash: NameHash,
    dest_hash: DestinationHash,
}

impl Destination {
    /// Create a new SINGLE destination bound to an identity.
    pub fn single(identity_hash: IdentityHash, app_name: &str, aspects: &[&str]) -> Self {
        let nh = name_hash(app_name, aspects);
        let dh = destination_hash(&nh, &identity_hash);
        Destination {
            identity_hash: Some(identity_hash),
            app_name: String::from(app_name),
            aspects: aspects.iter().map(|s| String::from(*s)).collect(),
            dtype: DestinationType::Single,
            name_hash: nh,
            dest_hash: dh,
        }
    }

    /// Create a new PLAIN destination (no identity binding).
    pub fn plain(app_name: &str, aspects: &[&str]) -> Self {
        let nh = name_hash(app_name, aspects);
        let dh = plain_destination_hash(&nh);
        Destination {
            identity_hash: None,
            app_name: String::from(app_name),
            aspects: aspects.iter().map(|s| String::from(*s)).collect(),
            dtype: DestinationType::Plain,
            name_hash: nh,
            dest_hash: dh,
        }
    }

    #[must_use = "returns the name hash without side effects"]
    pub fn name_hash(&self) -> &NameHash {
        &self.name_hash
    }

    #[must_use = "returns the destination hash without side effects"]
    pub fn hash(&self) -> &DestinationHash {
        &self.dest_hash
    }
}

fn build_base_name(app_name: &str, aspects: &[&str]) -> String {
    let mut name = String::from(app_name);
    for aspect in aspects {
        name.push('.');
        name.push_str(aspect);
    }
    name
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_destination_hashes() {
        let v = reticulum_test_vectors::destination_hashes::load();
        let keypairs = reticulum_test_vectors::keypairs::load();

        for sd in &v.single_destinations {
            // Get identity hash from keypair
            let kp = keypairs
                .keypairs
                .iter()
                .find(|k| k.index == sd.keypair_index)
                .unwrap();

            let expected_identity_hash =
                hex::decode(&kp.identity_hash).expect("invalid hex identity_hash");

            // Verify name_hash
            let aspect_refs: Vec<&str> = sd.aspects.iter().map(|s| s.as_str()).collect();
            let nh = name_hash(&sd.app_name, &aspect_refs);
            let expected_nh = hex::decode(&sd.name_hash).expect("invalid hex name_hash");
            assert_eq!(
                nh.as_ref(),
                expected_nh.as_slice(),
                "name_hash mismatch for {}",
                sd.base_name
            );

            // Verify identity_hash matches
            assert_eq!(
                expected_identity_hash,
                hex::decode(&sd.identity_hash).unwrap(),
                "identity_hash mismatch"
            );

            // Verify addr_hash_material
            let expected_material =
                hex::decode(&sd.addr_hash_material).expect("invalid hex addr_hash_material");
            let mut material = Vec::new();
            material.extend_from_slice(nh.as_ref());
            material.extend_from_slice(&expected_identity_hash);
            assert_eq!(
                material, expected_material,
                "addr_hash_material mismatch for {}",
                sd.base_name
            );
            assert_eq!(
                material.len() as u64,
                sd.addr_hash_material_length_bytes,
                "addr_hash_material length mismatch"
            );

            // Verify destination_hash
            let ih = IdentityHash::new(
                expected_identity_hash
                    .as_slice()
                    .try_into()
                    .expect("must be 16 bytes"),
            );
            let dh = destination_hash(&nh, &ih);
            let expected_dh =
                hex::decode(&sd.destination_hash).expect("invalid hex destination_hash");
            assert_eq!(
                dh.as_ref(),
                expected_dh.as_slice(),
                "destination_hash mismatch for {}",
                sd.base_name
            );

            // Verify via Destination struct
            let dest = Destination::single(ih, &sd.app_name, &aspect_refs);
            assert_eq!(dest.hash().as_ref(), expected_dh.as_slice());
            assert_eq!(dest.name_hash().as_ref(), expected_nh.as_slice());
        }
    }

    #[test]
    fn test_plain_destination_hashes() {
        let v = reticulum_test_vectors::destination_hashes::load();

        for pd in &v.plain_destinations {
            // Verify name_hash
            let aspect_refs: Vec<&str> = pd.aspects.iter().map(|s| s.as_str()).collect();
            let nh = name_hash(&pd.app_name, &aspect_refs);
            let expected_nh = hex::decode(&pd.name_hash).expect("invalid hex name_hash");
            assert_eq!(
                nh.as_ref(),
                expected_nh.as_slice(),
                "name_hash mismatch for {}",
                pd.base_name
            );

            // Verify addr_hash_material (for PLAIN, it's just name_hash)
            let expected_material =
                hex::decode(&pd.addr_hash_material).expect("invalid hex addr_hash_material");
            assert_eq!(
                nh.as_ref(),
                expected_material.as_slice(),
                "addr_hash_material mismatch for {}",
                pd.base_name
            );
            assert_eq!(nh.as_ref().len() as u64, pd.addr_hash_material_length_bytes,);

            // Verify destination_hash
            let dh = plain_destination_hash(&nh);
            let expected_dh =
                hex::decode(&pd.destination_hash).expect("invalid hex destination_hash");
            assert_eq!(
                dh.as_ref(),
                expected_dh.as_slice(),
                "destination_hash mismatch for {}",
                pd.base_name
            );

            // Verify via Destination struct
            let dest = Destination::plain(&pd.app_name, &aspect_refs);
            assert_eq!(dest.hash().as_ref(), expected_dh.as_slice());
        }
    }
}
