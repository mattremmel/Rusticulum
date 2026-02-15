//! Path request construction, parsing, and rate limiting.
//!
//! Path requests are broadcast DATA packets sent to the well-known PLAIN
//! destination `rnstransport.path.request`. Transport nodes that know a path
//! respond with cached announce packets.

use std::collections::HashMap;

use reticulum_core::constants::{
    DestinationType, HeaderType, PacketType, TransportType, TRUNCATED_HASHLENGTH,
};
use reticulum_core::destination::{name_hash, plain_destination_hash};
use reticulum_core::packet::context::ContextType;
use reticulum_core::packet::flags::PacketFlags;
use reticulum_core::types::{DestinationHash, TruncatedHash};

use super::constants::PATH_REQUEST_MI;

/// Compute the well-known path request destination hash at runtime.
///
/// This is `plain_destination_hash(name_hash("rnstransport", ["path", "request"]))`.
pub fn path_request_destination_hash() -> DestinationHash {
    let nh = name_hash("rnstransport", &["path", "request"]);
    plain_destination_hash(&nh)
}

/// Precomputed path request destination hash bytes.
pub const PATH_REQUEST_DEST_HASH_BYTES: [u8; 16] = [
    0x6b, 0x9f, 0x66, 0x01, 0x4d, 0x98, 0x53, 0xfa, 0xab, 0x22, 0x0f, 0xba, 0x47, 0xd0, 0x27,
    0x61,
];

/// Result of parsing path request data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseResult {
    /// Successfully parsed a path request.
    Processed(ParsedPathRequest),
    /// Data is too short to contain a destination hash.
    TooShort,
    /// Data has a destination hash but no tag — ignored.
    Tagless,
}

/// A successfully parsed path request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedPathRequest {
    /// The destination being requested.
    pub destination_hash: DestinationHash,
    /// The requesting transport instance ID (if transport-enabled).
    pub requesting_transport_id: Option<TruncatedHash>,
    /// The tag bytes from the request (1-16 bytes).
    pub tag_bytes: Vec<u8>,
    /// The unique tag for deduplication: destination_hash || tag_bytes.
    pub unique_tag: Vec<u8>,
}

/// Parse path request data payload.
///
/// Data layout:
/// - Transport-disabled: `target_dest(16) + tag(1-16)` = 17-32 bytes
/// - Transport-enabled: `target_dest(16) + transport_id(16) + tag(1-16)` = 33-48 bytes
///
/// If total length is exactly 16, the request is tagless and ignored.
/// If total length is < 16, it's too short.
/// Tags longer than 16 bytes are truncated to 16.
#[must_use]
pub fn parse_path_request_data(data: &[u8]) -> ParseResult {
    if data.len() < TRUNCATED_HASHLENGTH {
        return ParseResult::TooShort;
    }

    let dest_bytes: [u8; 16] = data[..16].try_into().expect("slice is exactly 16 bytes");
    let destination_hash = DestinationHash::new(dest_bytes);

    let remaining = &data[16..];

    if remaining.is_empty() {
        return ParseResult::Tagless;
    }

    // Determine if transport-enabled: if remaining >= 32 bytes, first 16 is transport_id
    // If remaining >= 17 and remaining's length suggests transport (>= 17 means at least
    // transport_id(16) + tag(1)), treat as transport-enabled.
    // Otherwise, all remaining is the tag.
    let (requesting_transport_id, tag_start) = if remaining.len() >= 17 {
        // Transport-enabled: transport_id(16) + tag(1+)
        let tid_bytes: [u8; 16] = remaining[..16].try_into().expect("slice is exactly 16 bytes");
        (Some(TruncatedHash::new(tid_bytes)), 16)
    } else {
        // Transport-disabled: all remaining is tag
        (None, 0)
    };

    let raw_tag = &remaining[tag_start..];
    if raw_tag.is_empty() {
        return ParseResult::Tagless;
    }

    // Truncate tag to 16 bytes max
    let tag_len = raw_tag.len().min(TRUNCATED_HASHLENGTH);
    let tag_bytes = raw_tag[..tag_len].to_vec();

    // Unique tag = destination_hash || tag_bytes
    let mut unique_tag = Vec::with_capacity(16 + tag_len);
    unique_tag.extend_from_slice(destination_hash.as_ref());
    unique_tag.extend_from_slice(&tag_bytes);

    ParseResult::Processed(ParsedPathRequest {
        destination_hash,
        requesting_transport_id,
        tag_bytes,
        unique_tag,
    })
}

/// Build the data payload for a path request.
///
/// Returns `target_dest(16) [+ transport_id(16)] + tag(16)`.
#[must_use]
pub fn build_path_request_data(
    target: &DestinationHash,
    transport_id: Option<&TruncatedHash>,
    tag: &[u8; 16],
) -> Vec<u8> {
    let capacity = 16 + if transport_id.is_some() { 16 } else { 0 } + 16;
    let mut data = Vec::with_capacity(capacity);
    data.extend_from_slice(target.as_ref());
    if let Some(tid) = transport_id {
        data.extend_from_slice(tid.as_ref());
    }
    data.extend_from_slice(tag);
    data
}

/// Build a complete path request packet (header + data).
///
/// Flags: HEADER_1 | DATA | BROADCAST | PLAIN, context=None.
#[must_use]
pub fn build_path_request_packet(
    target: &DestinationHash,
    transport_id: Option<&TruncatedHash>,
    tag: &[u8; 16],
) -> Vec<u8> {
    let flags = PacketFlags {
        header_type: HeaderType::Header1,
        context_flag: false,
        transport_type: TransportType::Broadcast,
        destination_type: DestinationType::Plain,
        packet_type: PacketType::Data,
    };

    let dest = path_request_destination_hash();
    let data = build_path_request_data(target, transport_id, tag);

    // Header: flags(1) + hops(1) + dest(16) + context(1) = 19 bytes
    let mut packet = Vec::with_capacity(19 + data.len());
    packet.push(flags.to_byte());
    packet.push(0); // hops = 0
    packet.extend_from_slice(dest.as_ref());
    packet.push(ContextType::None.to_byte());
    packet.extend_from_slice(&data);
    packet
}

/// Rate limiter for path requests per destination.
pub struct PathRequestTracker {
    requests: HashMap<DestinationHash, f64>,
}

impl PathRequestTracker {
    #[must_use]
    pub fn new() -> Self {
        Self {
            requests: HashMap::new(),
        }
    }

    /// Check if a path request for this destination is allowed (respects min interval).
    ///
    /// Returns `true` if the request is allowed and records the timestamp.
    pub fn try_request(&mut self, dest: &DestinationHash, now: f64) -> bool {
        if let Some(&last) = self.requests.get(dest) && now - last < PATH_REQUEST_MI {
            return false;
        }
        self.requests.insert(*dest, now);
        true
    }
}

impl Default for PathRequestTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_request_destination_hash_matches_precomputed() {
        let computed = path_request_destination_hash();
        assert_eq!(computed.as_ref(), &PATH_REQUEST_DEST_HASH_BYTES);
    }

    #[test]
    fn path_request_destination_vectors() {
        let vectors = reticulum_test_vectors::path_requests::load();

        for tv in &vectors.path_request_destination_vectors {
            let aspect_refs: Vec<&str> = tv.aspects.iter().map(|s| s.as_str()).collect();
            let nh = name_hash(&tv.app_name, &aspect_refs);
            let expected_nh = hex::decode(&tv.name_hash).unwrap();
            assert_eq!(
                nh.as_ref(),
                expected_nh.as_slice(),
                "name_hash mismatch for: {}",
                tv.description
            );

            let dh = plain_destination_hash(&nh);
            let expected_dh = hex::decode(&tv.destination_hash).unwrap();
            assert_eq!(
                dh.as_ref(),
                expected_dh.as_slice(),
                "destination_hash mismatch for: {}",
                tv.description
            );
        }
    }

    #[test]
    fn path_request_packet_vectors() {
        let vectors = reticulum_test_vectors::path_requests::load();

        for tv in &vectors.path_request_packet_vectors {
            let target_bytes = hex::decode(&tv.target_destination_hash).unwrap();
            let target = DestinationHash::try_from(target_bytes.as_slice()).unwrap();

            let tag_bytes = hex::decode(&tv.request_tag).unwrap();
            let tag: [u8; 16] = tag_bytes.try_into().unwrap();

            let transport_id = tv.transport_id.as_ref().map(|tid_hex| {
                let tid_bytes = hex::decode(tid_hex).unwrap();
                TruncatedHash::try_from(tid_bytes.as_slice()).unwrap()
            });

            // Verify data construction
            let data = build_path_request_data(&target, transport_id.as_ref(), &tag);
            let expected_data = hex::decode(&tv.path_request_data).unwrap();
            assert_eq!(
                data, expected_data,
                "data mismatch for: {}",
                tv.description
            );
            assert_eq!(
                data.len() as u64, tv.path_request_data_length,
                "data length mismatch for: {}",
                tv.description
            );

            // Verify full packet construction
            let packet = build_path_request_packet(&target, transport_id.as_ref(), &tag);
            let expected_packet = hex::decode(&tv.raw_packet).unwrap();
            assert_eq!(
                packet, expected_packet,
                "packet mismatch for: {}",
                tv.description
            );
            assert_eq!(
                packet.len() as u64, tv.raw_packet_length,
                "packet length mismatch for: {}",
                tv.description
            );

            // Verify flags byte
            let expected_flags = u8::from_str_radix(&tv.flags_byte, 16).unwrap();
            assert_eq!(
                packet[0], expected_flags,
                "flags mismatch for: {}",
                tv.description
            );

            // Verify dest hash in header
            let expected_dest = hex::decode(&tv.path_request_dest_hash).unwrap();
            assert_eq!(
                &packet[2..18],
                expected_dest.as_slice(),
                "dest hash mismatch for: {}",
                tv.description
            );

            // Verify context
            let expected_ctx = u8::from_str_radix(&tv.context, 16).unwrap();
            assert_eq!(
                packet[18], expected_ctx,
                "context mismatch for: {}",
                tv.description
            );
        }
    }

    #[test]
    fn path_request_parsing_vectors() {
        let vectors = reticulum_test_vectors::path_requests::load();

        for tv in &vectors.path_request_parsing_vectors {
            let input = hex::decode(&tv.input_data).unwrap();
            assert_eq!(input.len() as u64, tv.input_data_length);

            let result = parse_path_request_data(&input);

            match tv.expected_result.as_str() {
                "processed" => {
                    let parsed = match result {
                        ParseResult::Processed(p) => p,
                        other => panic!(
                            "expected Processed for '{}', got: {other:?}",
                            tv.description
                        ),
                    };

                    let expected_dest =
                        hex::decode(tv.expected_destination_hash.as_ref().unwrap()).unwrap();
                    assert_eq!(
                        parsed.destination_hash.as_ref(),
                        expected_dest.as_slice(),
                        "dest hash mismatch for: {}",
                        tv.description
                    );

                    // Check transport_id
                    match (&tv.expected_requesting_transport_instance, &parsed.requesting_transport_id) {
                        (Some(expected_hex), Some(actual)) => {
                            let expected = hex::decode(expected_hex).unwrap();
                            assert_eq!(
                                actual.as_ref(),
                                expected.as_slice(),
                                "transport_id mismatch for: {}",
                                tv.description
                            );
                        }
                        (None, None) => {}
                        _ => panic!(
                            "transport_id presence mismatch for: {}",
                            tv.description
                        ),
                    }

                    // Check tag bytes
                    let expected_tag =
                        hex::decode(tv.expected_tag_bytes.as_ref().unwrap()).unwrap();
                    assert_eq!(
                        parsed.tag_bytes, expected_tag,
                        "tag mismatch for: {}",
                        tv.description
                    );
                    assert_eq!(
                        parsed.tag_bytes.len() as u64,
                        tv.expected_tag_length.unwrap(),
                        "tag length mismatch for: {}",
                        tv.description
                    );

                    // Check unique_tag
                    let expected_unique =
                        hex::decode(tv.expected_unique_tag.as_ref().unwrap()).unwrap();
                    assert_eq!(
                        parsed.unique_tag, expected_unique,
                        "unique_tag mismatch for: {}",
                        tv.description
                    );
                }
                "ignored" => {
                    let reason = tv.ignore_reason.as_deref().unwrap_or("");
                    match reason {
                        "too_short" => {
                            assert_eq!(
                                result,
                                ParseResult::TooShort,
                                "expected TooShort for: {}",
                                tv.description
                            );
                        }
                        "tagless" => {
                            assert_eq!(
                                result,
                                ParseResult::Tagless,
                                "expected Tagless for: {}",
                                tv.description
                            );
                        }
                        _ => panic!("unknown ignore_reason: {reason}"),
                    }
                }
                other => panic!("unknown expected_result: {other}"),
            }
        }
    }

    #[test]
    fn rate_limiting_respects_min_interval() {
        let mut tracker = PathRequestTracker::new();
        let dest = DestinationHash::new([0x01; 16]);

        // First request should succeed
        assert!(tracker.try_request(&dest, 100.0));

        // Request within interval should fail
        assert!(!tracker.try_request(&dest, 110.0));

        // Request after interval should succeed
        assert!(tracker.try_request(&dest, 121.0));
    }

    #[test]
    fn rate_limiting_different_destinations_independent() {
        let mut tracker = PathRequestTracker::new();
        let dest1 = DestinationHash::new([0x01; 16]);
        let dest2 = DestinationHash::new([0x02; 16]);

        assert!(tracker.try_request(&dest1, 100.0));
        // Different destination should succeed even within interval
        assert!(tracker.try_request(&dest2, 105.0));
        // Original should still be rate-limited
        assert!(!tracker.try_request(&dest1, 105.0));
    }
}
