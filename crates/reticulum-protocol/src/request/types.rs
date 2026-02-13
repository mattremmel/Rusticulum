//! Request and response message types with msgpack serialization.

use reticulum_core::types::TruncatedHash;
use reticulum_crypto::sha::truncated_hash;
use rmpv::Value;

use crate::error::RequestError;

/// A path hash identifying a request handler endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathHash(TruncatedHash);

impl PathHash {
    /// Compute the path hash from a UTF-8 path string.
    pub fn from_path(path: &str) -> Self {
        Self(TruncatedHash::new(truncated_hash(path.as_bytes())))
    }

    /// Create from a raw 16-byte truncated hash.
    pub fn new(hash: TruncatedHash) -> Self {
        Self(hash)
    }

    /// Get the inner truncated hash.
    pub fn as_truncated_hash(&self) -> &TruncatedHash {
        &self.0
    }
}

impl AsRef<[u8]> for PathHash {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

/// A request ID derived from the packet's hashable part or packed request data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestId(TruncatedHash);

impl RequestId {
    /// Compute request ID from a packet's hashable part (small requests on a link).
    pub fn from_hashable_part(hashable_part: &[u8]) -> Self {
        Self(TruncatedHash::new(truncated_hash(hashable_part)))
    }

    /// Compute request ID from the packed request data (large requests sent as Resource).
    pub fn from_packed_request(packed: &[u8]) -> Self {
        Self(TruncatedHash::new(truncated_hash(packed)))
    }

    /// Create from a raw 16-byte truncated hash.
    pub fn new(hash: TruncatedHash) -> Self {
        Self(hash)
    }

    /// Get the inner truncated hash.
    pub fn as_truncated_hash(&self) -> &TruncatedHash {
        &self.0
    }
}

impl AsRef<[u8]> for RequestId {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

/// A request message: `[timestamp, path_hash, data]` in msgpack.
#[derive(Debug, Clone)]
pub struct Request {
    pub timestamp: f64,
    pub path_hash: PathHash,
    pub data: Value,
}

impl Request {
    /// Serialize to msgpack bytes as a 3-element array.
    pub fn to_msgpack(&self) -> Vec<u8> {
        let arr = Value::Array(vec![
            Value::F64(self.timestamp),
            Value::Binary(self.path_hash.as_ref().to_vec()),
            self.data.clone(),
        ]);
        let mut buf = Vec::new();
        rmpv::encode::write_value(&mut buf, &arr).expect("msgpack encode should not fail");
        buf
    }

    /// Deserialize from msgpack bytes.
    pub fn from_msgpack(data: &[u8]) -> Result<Self, RequestError> {
        let value = rmpv::decode::read_value(&mut &data[..])
            .map_err(|e| RequestError::Failed(format!("msgpack decode error: {e}")))?;

        let arr = match value {
            Value::Array(a) if a.len() == 3 => a,
            _ => return Err(RequestError::Failed("expected 3-element array".into())),
        };

        let timestamp = match &arr[0] {
            Value::F64(f) => *f,
            Value::F32(f) => *f as f64,
            _ => return Err(RequestError::Failed("expected float timestamp".into())),
        };

        let path_hash_bytes = match &arr[1] {
            Value::Binary(b) if b.len() == 16 => b.as_slice(),
            _ => {
                return Err(RequestError::Failed(
                    "expected 16-byte binary path_hash".into(),
                ));
            }
        };

        let mut hash_arr = [0u8; 16];
        hash_arr.copy_from_slice(path_hash_bytes);
        let path_hash = PathHash::new(TruncatedHash::new(hash_arr));

        Ok(Self {
            timestamp,
            path_hash,
            data: arr.into_iter().nth(2).unwrap(),
        })
    }

    /// Check whether the packed request fits within the given MDU.
    pub fn fits_in_mdu(&self, mdu: usize) -> bool {
        self.to_msgpack().len() <= mdu
    }
}

/// A response message: `[request_id, data]` in msgpack.
#[derive(Debug, Clone)]
pub struct Response {
    pub request_id: RequestId,
    pub data: Value,
}

impl Response {
    /// Serialize to msgpack bytes as a 2-element array.
    pub fn to_msgpack(&self) -> Vec<u8> {
        let arr = Value::Array(vec![
            Value::Binary(self.request_id.as_ref().to_vec()),
            self.data.clone(),
        ]);
        let mut buf = Vec::new();
        rmpv::encode::write_value(&mut buf, &arr).expect("msgpack encode should not fail");
        buf
    }

    /// Deserialize from msgpack bytes.
    pub fn from_msgpack(data: &[u8]) -> Result<Self, RequestError> {
        let value = rmpv::decode::read_value(&mut &data[..])
            .map_err(|e| RequestError::Failed(format!("msgpack decode error: {e}")))?;

        let arr = match value {
            Value::Array(a) if a.len() == 2 => a,
            _ => return Err(RequestError::Failed("expected 2-element array".into())),
        };

        let request_id_bytes = match &arr[0] {
            Value::Binary(b) if b.len() == 16 => b.as_slice(),
            _ => {
                return Err(RequestError::Failed(
                    "expected 16-byte binary request_id".into(),
                ));
            }
        };

        let mut id_arr = [0u8; 16];
        id_arr.copy_from_slice(request_id_bytes);
        let request_id = RequestId::new(TruncatedHash::new(id_arr));

        Ok(Self {
            request_id,
            data: arr.into_iter().nth(1).unwrap(),
        })
    }

    /// Check whether the packed response fits within the given MDU.
    pub fn fits_in_mdu(&self, mdu: usize) -> bool {
        self.to_msgpack().len() <= mdu
    }
}

/// Convert a serde_json::Value to an rmpv::Value for test comparisons.
#[cfg(test)]
fn json_to_msgpack(v: &serde_json::Value) -> Value {
    match v {
        serde_json::Value::Null => Value::Nil,
        serde_json::Value::Bool(b) => Value::Boolean(*b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                if i >= 0 {
                    Value::from(i as u64)
                } else {
                    Value::from(i)
                }
            } else if let Some(f) = n.as_f64() {
                Value::F64(f)
            } else {
                Value::Nil
            }
        }
        serde_json::Value::String(s) => Value::String(s.clone().into()),
        serde_json::Value::Array(arr) => Value::Array(arr.iter().map(json_to_msgpack).collect()),
        serde_json::Value::Object(map) => {
            let pairs = map
                .iter()
                .map(|(k, v)| (Value::String(k.clone().into()), json_to_msgpack(v)))
                .collect();
            Value::Map(pairs)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reticulum_crypto::sha::sha256;

    fn load_vectors() -> reticulum_test_vectors::requests::RequestsVectors {
        reticulum_test_vectors::requests::load()
    }

    #[test]
    fn test_path_hash_vectors() {
        let vectors = load_vectors();
        for tv in &vectors.path_hash_vectors {
            let computed = PathHash::from_path(&tv.path);
            let expected = hex::decode(&tv.path_hash).unwrap();
            assert_eq!(
                computed.as_ref(),
                expected.as_slice(),
                "index={}: path={:?}",
                tv.index,
                tv.path,
            );
        }
    }

    #[test]
    fn test_request_serialization() {
        let vectors = load_vectors();
        for tv in &vectors.request_serialization_vectors {
            let path_hash_bytes = hex::decode(&tv.path_hash).unwrap();
            let mut hash_arr = [0u8; 16];
            hash_arr.copy_from_slice(&path_hash_bytes);

            // Build the data value — skip vectors with only prefix (no full data)
            let data = if let Some(ref data_hex) = tv.data_hex {
                Value::Binary(hex::decode(data_hex).unwrap())
            } else if let Some(ref data_json) = tv.data_json {
                json_to_msgpack(data_json)
            } else if tv.data_hex_prefix.is_some() {
                // Large vector with only prefix — verify fits_in_mdu=false and skip
                assert!(
                    !tv.fits_in_mdu,
                    "index={}: prefix-only vector should exceed MDU",
                    tv.index,
                );
                continue;
            } else {
                Value::Nil
            };

            let request = Request {
                timestamp: tv.timestamp,
                path_hash: PathHash::new(TruncatedHash::new(hash_arr)),
                data,
            };

            let packed = request.to_msgpack();

            // Check length
            assert_eq!(
                packed.len(),
                tv.packed_request_length as usize,
                "index={}: packed length mismatch",
                tv.index,
            );

            // Check exact bytes if available
            if let Some(ref expected_hex) = tv.packed_request_hex {
                let expected = hex::decode(expected_hex).unwrap();
                assert_eq!(
                    packed, expected,
                    "index={}: packed bytes mismatch",
                    tv.index,
                );
            }

            // Check fits_in_mdu
            assert_eq!(
                request.fits_in_mdu(tv.mdu as usize),
                tv.fits_in_mdu,
                "index={}: fits_in_mdu mismatch",
                tv.index,
            );

            // Round-trip: parse back and verify fields
            if tv.packed_request_hex.is_some() {
                let parsed = Request::from_msgpack(&packed).unwrap();
                assert_eq!(
                    parsed.timestamp, tv.timestamp,
                    "index={}: timestamp",
                    tv.index
                );
                assert_eq!(
                    parsed.path_hash.as_ref(),
                    path_hash_bytes.as_slice(),
                    "index={}: path_hash",
                    tv.index,
                );
            }
        }
    }

    #[test]
    fn test_response_serialization() {
        let vectors = load_vectors();
        for tv in &vectors.response_serialization_vectors {
            let request_id_bytes = hex::decode(&tv.request_id).unwrap();
            let mut id_arr = [0u8; 16];
            id_arr.copy_from_slice(&request_id_bytes);

            // Build response data — skip vectors with only prefix (no full data)
            let data = if let Some(ref data_hex) = tv.response_data_hex {
                Value::Binary(hex::decode(data_hex).unwrap())
            } else if let Some(ref data_json) = tv.response_data_json {
                json_to_msgpack(data_json)
            } else if let Some(ref data) = tv.response_data {
                json_to_msgpack(data)
            } else if tv.response_data_hex_prefix.is_some() {
                // Large vector with only prefix — verify fits_in_mdu=false and skip
                assert!(
                    !tv.fits_in_mdu,
                    "index={}: prefix-only vector should exceed MDU",
                    tv.index,
                );
                continue;
            } else {
                Value::Nil
            };

            let response = Response {
                request_id: RequestId::new(TruncatedHash::new(id_arr)),
                data,
            };

            let packed = response.to_msgpack();

            // Check length
            assert_eq!(
                packed.len(),
                tv.packed_response_length as usize,
                "index={}: packed length mismatch",
                tv.index,
            );

            // Check exact bytes if available
            if let Some(ref expected_hex) = tv.packed_response_hex {
                let expected = hex::decode(expected_hex).unwrap();
                assert_eq!(
                    packed, expected,
                    "index={}: packed bytes mismatch",
                    tv.index,
                );
            }

            // Check fits_in_mdu
            assert_eq!(
                response.fits_in_mdu(tv.mdu as usize),
                tv.fits_in_mdu,
                "index={}: fits_in_mdu mismatch",
                tv.index,
            );

            // Round-trip
            if tv.packed_response_hex.is_some() {
                let parsed = Response::from_msgpack(&packed).unwrap();
                assert_eq!(
                    parsed.request_id.as_ref(),
                    request_id_bytes.as_slice(),
                    "index={}: request_id",
                    tv.index,
                );
            }
        }
    }

    #[test]
    fn test_small_request_wire() {
        let vectors = load_vectors();
        for tv in &vectors.small_request_wire_vectors {
            let hashable_part = hex::decode(&tv.hashable_part_hex).unwrap();
            let expected_id = hex::decode(&tv.request_id).unwrap();

            let computed = RequestId::from_hashable_part(&hashable_part);
            assert_eq!(
                computed.as_ref(),
                expected_id.as_slice(),
                "index={}: request_id from hashable_part",
                tv.index,
            );
        }
    }

    #[test]
    fn test_small_response_wire() {
        let vectors = load_vectors();
        for tv in &vectors.small_response_wire_vectors {
            let hashable_part = hex::decode(&tv.hashable_part_hex).unwrap();
            let expected_hash = hex::decode(&tv.packet_hash).unwrap();

            let computed_hash = sha256(&hashable_part);
            assert_eq!(
                computed_hash.as_slice(),
                expected_hash.as_slice(),
                "index={}: packet_hash",
                tv.index,
            );
        }
    }

    #[test]
    fn test_large_request_resource() {
        let vectors = load_vectors();
        for tv in &vectors.large_request_resource_vectors {
            // Verify resource_params structure
            let params = &tv.resource_params;
            let is_response = params.is_response;
            let param_request_id = params.request_id.as_str();

            assert_eq!(
                param_request_id, tv.request_id,
                "index={}: resource_params.request_id",
                tv.index,
            );

            if tv.vector_type == "request" {
                assert!(!is_response, "index={}: should be request", tv.index);
            } else {
                assert!(is_response, "index={}: should be response", tv.index);
            }
        }
    }

    #[test]
    fn test_request_from_msgpack_errors() {
        // Empty input
        assert!(Request::from_msgpack(&[]).is_err());

        // Wrong array length (1-element)
        let one = Value::Array(vec![Value::Nil]);
        let mut buf = Vec::new();
        rmpv::encode::write_value(&mut buf, &one).unwrap();
        assert!(Request::from_msgpack(&buf).is_err());

        // Wrong type for timestamp (string instead of float)
        let bad_ts = Value::Array(vec![
            Value::String("not_a_number".into()),
            Value::Binary(vec![0u8; 16]),
            Value::Nil,
        ]);
        buf.clear();
        rmpv::encode::write_value(&mut buf, &bad_ts).unwrap();
        assert!(Request::from_msgpack(&buf).is_err());

        // Wrong length for path_hash (8 bytes instead of 16)
        let bad_ph = Value::Array(vec![
            Value::F64(1.0),
            Value::Binary(vec![0u8; 8]),
            Value::Nil,
        ]);
        buf.clear();
        rmpv::encode::write_value(&mut buf, &bad_ph).unwrap();
        assert!(Request::from_msgpack(&buf).is_err());

        // Not an array
        let not_arr = Value::String("hello".into());
        buf.clear();
        rmpv::encode::write_value(&mut buf, &not_arr).unwrap();
        assert!(Request::from_msgpack(&buf).is_err());
    }

    #[test]
    fn test_response_from_msgpack_errors() {
        // Empty input
        assert!(Response::from_msgpack(&[]).is_err());

        // Wrong array length
        let one = Value::Array(vec![Value::Nil]);
        let mut buf = Vec::new();
        rmpv::encode::write_value(&mut buf, &one).unwrap();
        assert!(Response::from_msgpack(&buf).is_err());

        // Wrong length for request_id
        let bad_id = Value::Array(vec![Value::Binary(vec![0u8; 8]), Value::Nil]);
        buf.clear();
        rmpv::encode::write_value(&mut buf, &bad_id).unwrap();
        assert!(Response::from_msgpack(&buf).is_err());
    }
}
