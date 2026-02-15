//! Resource advertisement serialization (msgpack).
//!
//! A [`ResourceAdvertisement`] is the first message sent to initiate a resource
//! transfer. It describes the resource (size, hashes, flags, part map) as a
//! msgpack dictionary with single-character keys.

use std::collections::HashMap;

use rmpv::Value;

use crate::error::ResourceError;

// ------------------------------------------------------------------ //
// ResourceFlags
// ------------------------------------------------------------------ //

/// Decoded resource advertisement flags.
///
/// Bit layout (matching Python reference `Resource.py` line 1288):
/// ```text
/// bit 5: has_metadata (x)
/// bit 4: is_response (p)
/// bit 3: is_request  (u)
/// bit 2: split       (s)
/// bit 1: compressed  (c)
/// bit 0: encrypted   (e)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub struct ResourceFlags {
    pub encrypted: bool,
    pub compressed: bool,
    pub split: bool,
    pub is_request: bool,
    pub is_response: bool,
    pub has_metadata: bool,
}

impl ResourceFlags {
    /// Decode a flags byte into individual fields.
    pub fn from_byte(b: u8) -> Self {
        Self {
            encrypted: (b & 0x01) != 0,
            compressed: (b >> 1 & 0x01) != 0,
            split: (b >> 2 & 0x01) != 0,
            is_request: (b >> 3 & 0x01) != 0,
            is_response: (b >> 4 & 0x01) != 0,
            has_metadata: (b >> 5 & 0x01) != 0,
        }
    }

    /// Encode individual fields back into a flags byte.
    #[must_use]
    pub fn to_byte(&self) -> u8 {
        (self.has_metadata as u8) << 5
            | (self.is_response as u8) << 4
            | (self.is_request as u8) << 3
            | (self.split as u8) << 2
            | (self.compressed as u8) << 1
            | (self.encrypted as u8)
    }
}

// ------------------------------------------------------------------ //
// ResourceAdvertisement
// ------------------------------------------------------------------ //

/// A resource advertisement — the first message of a resource transfer.
///
/// Serialized as an 11-entry msgpack map with single-character keys:
/// `t, d, n, h, r, o, i, l, q, f, m`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub struct ResourceAdvertisement {
    /// `"t"` — Encrypted transfer size (bytes).
    pub transfer_size: u64,
    /// `"d"` — Original uncompressed data size (bytes).
    pub data_size: u64,
    /// `"n"` — Number of parts in this segment.
    pub num_parts: u64,
    /// `"h"` — SHA-256 of (data_with_metadata + random_hash).
    pub resource_hash: [u8; 32],
    /// `"r"` — 4-byte random hash prepended to data before encryption.
    pub random_hash: [u8; 4],
    /// `"o"` — Original hash (first-segment hash for multi-segment resources).
    pub original_hash: [u8; 32],
    /// `"i"` — 1-based segment index.
    pub segment_index: u64,
    /// `"l"` — Total number of segments.
    pub total_segments: u64,
    /// `"q"` — Request ID (`None` → msgpack nil).
    pub request_id: Option<Vec<u8>>,
    /// `"f"` — Flags byte (see [`ResourceFlags`]).
    pub flags: u8,
    /// `"m"` — Concatenated 4-byte part hashes.
    pub hashmap: Vec<u8>,
}

impl ResourceAdvertisement {
    /// Encode this advertisement as msgpack bytes.
    ///
    /// Produces an 11-entry fixmap (`0x8b`) with keys in the canonical order:
    /// `t, d, n, h, r, o, i, l, q, f, m`.
    #[must_use]
    pub fn to_msgpack(&self) -> Vec<u8> {
        let q_val = match &self.request_id {
            Some(id) => Value::Binary(id.clone()),
            None => Value::Nil,
        };

        let map = Value::Map(vec![
            (
                Value::String("t".into()),
                Value::Integer(self.transfer_size.into()),
            ),
            (
                Value::String("d".into()),
                Value::Integer(self.data_size.into()),
            ),
            (
                Value::String("n".into()),
                Value::Integer(self.num_parts.into()),
            ),
            (
                Value::String("h".into()),
                Value::Binary(self.resource_hash.to_vec()),
            ),
            (
                Value::String("r".into()),
                Value::Binary(self.random_hash.to_vec()),
            ),
            (
                Value::String("o".into()),
                Value::Binary(self.original_hash.to_vec()),
            ),
            (
                Value::String("i".into()),
                Value::Integer(self.segment_index.into()),
            ),
            (
                Value::String("l".into()),
                Value::Integer(self.total_segments.into()),
            ),
            (Value::String("q".into()), q_val),
            (Value::String("f".into()), Value::Integer(self.flags.into())),
            (
                Value::String("m".into()),
                Value::Binary(self.hashmap.clone()),
            ),
        ]);

        let mut buf = Vec::new();
        // SAFETY: encoding to a Vec<u8> never fails (infallible Write impl).
        rmpv::encode::write_value(&mut buf, &map).expect("msgpack encoding to Vec never fails");

        tracing::trace!(
            len = buf.len(),
            transfer_size = self.transfer_size,
            num_parts = self.num_parts,
            "resource advertisement packed"
        );

        buf
    }

    /// Decode a resource advertisement from msgpack bytes.
    pub fn from_msgpack(data: &[u8]) -> Result<Self, ResourceError> {
        let value = rmpv::decode::read_value(&mut &data[..])
            .map_err(|_| ResourceError::InvalidAdvertisement("msgpack decode failed"))?;

        let entries = match value {
            Value::Map(entries) => entries,
            _ => {
                return Err(ResourceError::InvalidAdvertisement("expected map"));
            }
        };

        // Build lookup by key for order-tolerant parsing.
        let mut lookup: HashMap<String, &Value> = HashMap::new();
        for (k, v) in &entries {
            if let Value::String(s) = k
                && let Some(s) = s.as_str()
            {
                lookup.insert(s.to_owned(), v);
            }
        }

        let transfer_size = get_u64(&lookup, "t")?;
        let data_size = get_u64(&lookup, "d")?;
        let num_parts = get_u64(&lookup, "n")?;
        let resource_hash = get_bytes_fixed::<32>(&lookup, "h")?;
        let random_hash = get_bytes_fixed::<4>(&lookup, "r")?;
        let original_hash = get_bytes_fixed::<32>(&lookup, "o")?;
        let segment_index = get_u64(&lookup, "i")?;
        let total_segments = get_u64(&lookup, "l")?;
        let flags = get_u64(&lookup, "f")? as u8;
        let hashmap = get_bytes(&lookup, "m")?;

        let request_id = match lookup.get("q") {
            Some(Value::Nil) | None => None,
            Some(Value::Binary(b)) => Some(b.clone()),
            Some(_) => {
                return Err(ResourceError::InvalidAdvertisement(
                    "key 'q': expected binary or nil",
                ));
            }
        };

        let adv = Self {
            transfer_size,
            data_size,
            num_parts,
            resource_hash,
            random_hash,
            original_hash,
            segment_index,
            total_segments,
            request_id,
            flags,
            hashmap,
        };

        tracing::trace!(
            transfer_size = adv.transfer_size,
            num_parts = adv.num_parts,
            flags = adv.flags,
            "resource advertisement unpacked"
        );

        Ok(adv)
    }

    /// Decode the flags byte into a [`ResourceFlags`] struct.
    pub fn decoded_flags(&self) -> ResourceFlags {
        ResourceFlags::from_byte(self.flags)
    }
}

// ------------------------------------------------------------------ //
// Helpers
// ------------------------------------------------------------------ //

fn get_u64(lookup: &HashMap<String, &Value>, key: &str) -> Result<u64, ResourceError> {
    match lookup.get(key) {
        Some(Value::Integer(i)) => i
            .as_u64()
            .ok_or(ResourceError::InvalidAdvertisement("invalid integer value")),
        Some(_) => Err(ResourceError::InvalidAdvertisement("expected integer")),
        None => Err(ResourceError::InvalidAdvertisement("missing required key")),
    }
}

fn get_bytes(lookup: &HashMap<String, &Value>, key: &str) -> Result<Vec<u8>, ResourceError> {
    match lookup.get(key) {
        Some(Value::Binary(b)) => Ok(b.clone()),
        Some(_) => Err(ResourceError::InvalidAdvertisement("expected binary")),
        None => Err(ResourceError::InvalidAdvertisement("missing required key")),
    }
}

fn get_bytes_fixed<const N: usize>(
    lookup: &HashMap<String, &Value>,
    key: &str,
) -> Result<[u8; N], ResourceError> {
    let bytes = get_bytes(lookup, key)?;
    bytes
        .try_into()
        .map_err(|_| ResourceError::InvalidAdvertisement("unexpected byte length"))
}

// ------------------------------------------------------------------ //
// Tests
// ------------------------------------------------------------------ //

#[cfg(test)]
mod tests {
    use super::*;

    // ============================================================== //
    // Test-vector helpers
    // ============================================================== //

    fn load_vectors() -> Vec<reticulum_test_vectors::resources::ResourceAdvertisementVector> {
        let vecs = reticulum_test_vectors::resources::load();
        vecs.resource_advertisement_vectors
    }

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        hex::decode(hex).expect("invalid hex")
    }

    fn build_adv_from_dict(
        v: &reticulum_test_vectors::resources::ResourceAdvertisementVector,
    ) -> ResourceAdvertisement {
        let dict = &v.advertisement_dict;
        ResourceAdvertisement {
            transfer_size: dict.t,
            data_size: dict.d,
            num_parts: dict.n,
            resource_hash: hex_to_bytes(&dict.h).try_into().unwrap(),
            random_hash: hex_to_bytes(&dict.r).try_into().unwrap(),
            original_hash: hex_to_bytes(&dict.o).try_into().unwrap(),
            segment_index: dict.i,
            total_segments: dict.l,
            request_id: dict.q.as_ref().map(|q| hex_to_bytes(q)),
            flags: dict.f as u8,
            hashmap: hex_to_bytes(&dict.m),
        }
    }

    // ============================================================== //
    // Serialization test vectors
    // ============================================================== //

    #[test]
    fn serialize_all_advertisement_vectors() {
        let vectors = load_vectors();
        assert_eq!(vectors.len(), 5);

        for v in &vectors {
            let adv = build_adv_from_dict(v);
            let packed = adv.to_msgpack();
            let expected = hex_to_bytes(&v.advertisement_packed_hex);

            assert_eq!(
                packed, expected,
                "serialize mismatch for vector {}: {}",
                v.index, v.description
            );
            assert_eq!(
                packed.len(),
                v.advertisement_packed_length as usize,
                "length mismatch for vector {}",
                v.index
            );
        }
    }

    // ============================================================== //
    // Deserialization test vectors
    // ============================================================== //

    #[test]
    fn deserialize_all_advertisement_vectors() {
        let vectors = load_vectors();

        for v in &vectors {
            let packed = hex_to_bytes(&v.advertisement_packed_hex);
            let adv = ResourceAdvertisement::from_msgpack(&packed)
                .unwrap_or_else(|e| panic!("deserialize failed for vector {}: {e}", v.index));

            let expected = build_adv_from_dict(v);
            assert_eq!(
                adv, expected,
                "deserialize mismatch for vector {}: {}",
                v.index, v.description
            );
        }
    }

    // ============================================================== //
    // Flags test vectors
    // ============================================================== //

    #[test]
    fn flags_all_vectors() {
        let vectors = load_vectors();

        for v in &vectors {
            let flags = ResourceFlags::from_byte(v.flags as u8);
            let breakdown = &v.flags_breakdown;

            assert_eq!(
                flags.encrypted, breakdown.encrypted,
                "vector {}: encrypted mismatch",
                v.index
            );
            assert_eq!(
                flags.compressed, breakdown.compressed,
                "vector {}: compressed mismatch",
                v.index
            );
            assert_eq!(
                flags.split, breakdown.split,
                "vector {}: split mismatch",
                v.index
            );
            assert_eq!(
                flags.is_request, breakdown.is_request,
                "vector {}: is_request mismatch",
                v.index
            );
            assert_eq!(
                flags.is_response, breakdown.is_response,
                "vector {}: is_response mismatch",
                v.index
            );
            assert_eq!(
                flags.has_metadata, breakdown.has_metadata,
                "vector {}: has_metadata mismatch",
                v.index
            );

            // Roundtrip
            assert_eq!(
                flags.to_byte(),
                v.flags as u8,
                "vector {}: flags roundtrip mismatch",
                v.index
            );
        }
    }

    // ============================================================== //
    // Error tests
    // ============================================================== //

    #[test]
    fn from_msgpack_empty_input() {
        assert!(ResourceAdvertisement::from_msgpack(&[]).is_err());
    }

    #[test]
    fn from_msgpack_non_map() {
        // Encode a simple integer
        let mut buf = Vec::new();
        rmpv::encode::write_value(&mut buf, &Value::Integer(42.into())).unwrap();
        assert!(ResourceAdvertisement::from_msgpack(&buf).is_err());
    }

    #[test]
    fn from_msgpack_missing_keys() {
        // Encode a map with only one key
        let map = Value::Map(vec![(
            Value::String("t".into()),
            Value::Integer(100.into()),
        )]);
        let mut buf = Vec::new();
        rmpv::encode::write_value(&mut buf, &map).unwrap();
        assert!(ResourceAdvertisement::from_msgpack(&buf).is_err());
    }

    // ============================================================== //
    // Malformed input tests
    // ============================================================== //

    #[test]
    fn test_advertisement_malformed_truncated_msgpack() {
        // Take a valid advertisement, pack it, then truncate at half
        let vectors = load_vectors();
        let v = &vectors[0];
        let packed = hex_to_bytes(&v.advertisement_packed_hex);
        let truncated = &packed[..packed.len() / 2];
        assert!(ResourceAdvertisement::from_msgpack(truncated).is_err());
    }

    #[test]
    fn test_advertisement_malformed_wrong_value_types() {
        // Build msgpack map where integer fields are strings instead
        let map = Value::Map(vec![
            (
                Value::String("t".into()),
                Value::String("not_a_number".into()),
            ),
            (Value::String("d".into()), Value::Integer(0.into())),
            (Value::String("n".into()), Value::Integer(1.into())),
            (Value::String("h".into()), Value::Binary(vec![0; 32])),
            (Value::String("r".into()), Value::Binary(vec![0; 4])),
            (Value::String("o".into()), Value::Binary(vec![0; 32])),
            (Value::String("i".into()), Value::Integer(0.into())),
            (Value::String("l".into()), Value::Integer(1.into())),
            (Value::String("q".into()), Value::Nil),
            (Value::String("f".into()), Value::Integer(1.into())),
            (Value::String("m".into()), Value::Binary(vec![0; 4])),
        ]);
        let mut buf = Vec::new();
        rmpv::encode::write_value(&mut buf, &map).unwrap();
        assert!(ResourceAdvertisement::from_msgpack(&buf).is_err());
    }

    // ============================================================== //
    // Property tests
    // ============================================================== //

    mod proptests {
        use super::*;
        use proptest::prelude::*;

        fn adv_strategy() -> impl Strategy<Value = ResourceAdvertisement> {
            (
                any::<u64>(),
                any::<u64>(),
                1u64..=1000,
                any::<[u8; 32]>(),
                any::<[u8; 4]>(),
                any::<[u8; 32]>(),
                1u64..=100,
                1u64..=100,
                proptest::option::of(proptest::collection::vec(any::<u8>(), 0..64)),
                0u8..64, // 6 bits used
                proptest::collection::vec(any::<u8>(), 0..300),
            )
                .prop_map(|(t, d, n, h, r, o, i, l, q, f, m)| ResourceAdvertisement {
                    transfer_size: t,
                    data_size: d,
                    num_parts: n,
                    resource_hash: h,
                    random_hash: r,
                    original_hash: o,
                    segment_index: i,
                    total_segments: l,
                    request_id: q,
                    flags: f,
                    hashmap: m,
                })
        }

        proptest! {
            #[test]
            fn roundtrip(adv in adv_strategy()) {
                let packed = adv.to_msgpack();
                let decoded = ResourceAdvertisement::from_msgpack(&packed).unwrap();
                prop_assert_eq!(adv, decoded);
            }

            #[test]
            fn fixmap_header(adv in adv_strategy()) {
                let packed = adv.to_msgpack();
                // 0x8b = fixmap with 11 entries
                prop_assert_eq!(packed[0], 0x8b, "expected 11-entry fixmap header");
            }

            #[test]
            fn flags_roundtrip(b in 0u8..64) {
                let flags = ResourceFlags::from_byte(b);
                prop_assert_eq!(flags.to_byte(), b);
            }
        }
    }
}
