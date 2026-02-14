//! Pure functions for channel, buffer, and request/response operations.
//!
//! These functions extract computation from `ChannelManager` methods,
//! making the logic independently testable without channel state.

use std::collections::HashMap;

use reticulum_core::types::LinkId;
use reticulum_protocol::buffer::constants::SMT_STREAM_DATA;
use reticulum_protocol::buffer::stream_data::{StreamDataMessage, StreamHeader};
use reticulum_protocol::channel::envelope::Envelope;
use reticulum_protocol::channel::state::check_rx_sequence_valid;
use reticulum_protocol::request::types::{PathHash, Request, RequestId, Response};
use rmpv::Value;

/// Extract request data bytes from a msgpack Value.
///
/// Handles three cases:
/// - Binary: return bytes directly
/// - String: return UTF-8 bytes
/// - Other: msgpack-encode the value
///
/// Returns `None` only if msgpack encoding fails for the "other" case.
pub fn extract_request_data(data: &Value) -> Option<Vec<u8>> {
    match data {
        Value::Binary(b) => Some(b.clone()),
        Value::String(s) => Some(s.as_str().unwrap_or("").as_bytes().to_vec()),
        other => {
            let mut buf = Vec::new();
            rmpv::encode::write_value(&mut buf, other).ok()?;
            Some(buf)
        }
    }
}

/// Build serialized response bytes from a request ID and response data.
///
/// Constructs a `Response` with Binary-wrapped data and serializes to msgpack.
pub fn build_response_bytes(request_id: RequestId, response_data: Vec<u8>) -> Vec<u8> {
    let response = Response {
        request_id,
        data: Value::Binary(response_data),
    };
    response.to_msgpack()
}

/// Build a serialized request message from path, data, and an explicit timestamp.
///
/// By taking the timestamp as a parameter (instead of calling `SystemTime::now()`),
/// this function is deterministic and testable.
pub fn build_request_msgpack(path: &str, data: &[u8], timestamp: f64) -> Vec<u8> {
    let request = Request {
        timestamp,
        path_hash: PathHash::from_path(path),
        data: Value::Binary(data.to_vec()),
    };
    request.to_msgpack()
}

/// Build a packed stream data message from stream ID, data, and EOF flag.
///
/// Constructs a `StreamDataMessage` and packs it into bytes suitable for
/// wrapping in a channel envelope with `SMT_STREAM_DATA` msg_type.
pub fn build_stream_data_packed(stream_id: u16, data: &[u8], eof: bool) -> Vec<u8> {
    let stream_msg = StreamDataMessage {
        header: StreamHeader {
            stream_id,
            is_eof: eof,
            is_compressed: false,
        },
        data: data.to_vec(),
    };
    stream_msg.pack()
}

/// Format a response data value as a human-readable preview string.
///
/// Binary data is converted via lossy UTF-8; other values use Debug formatting.
pub fn format_response_preview(data: &Value) -> String {
    match data {
        Value::Binary(b) => String::from_utf8_lossy(b).to_string(),
        other => format!("{other:?}"),
    }
}

// ======================================================================== //
// Extraction: classify_channel_envelope
// ======================================================================== //

/// Classification of an unpacked channel envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelEnvelopeAction {
    /// An application-level message (non-stream).
    ApplicationMessage { msg_type: u16, payload: Vec<u8> },
    /// A buffer stream data chunk.
    StreamData { payload: Vec<u8> },
    /// The envelope's sequence was outside the valid receive window.
    SequenceRejected { sequence: u16 },
}

/// Unpack an envelope from plaintext, validate its sequence, and classify it.
///
/// Returns the classification together with the envelope's sequence number,
/// or an error string if the plaintext cannot be unpacked.
pub fn classify_channel_envelope(
    plaintext: &[u8],
    next_rx_sequence: u16,
    window_max: u16,
) -> Result<(ChannelEnvelopeAction, u16), String> {
    let envelope =
        Envelope::unpack(plaintext).map_err(|e| format!("failed to unpack envelope: {e}"))?;

    let seq = envelope.sequence;

    if !check_rx_sequence_valid(seq, next_rx_sequence, window_max) {
        return Ok((
            ChannelEnvelopeAction::SequenceRejected { sequence: seq },
            seq,
        ));
    }

    if envelope.msg_type == SMT_STREAM_DATA {
        Ok((
            ChannelEnvelopeAction::StreamData {
                payload: envelope.payload,
            },
            seq,
        ))
    } else {
        Ok((
            ChannelEnvelopeAction::ApplicationMessage {
                msg_type: envelope.msg_type,
                payload: envelope.payload,
            },
            seq,
        ))
    }
}

// ======================================================================== //
// Extraction: decide_stream_accumulation
// ======================================================================== //

/// Result of accumulating a stream data chunk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamAccumulationResult {
    /// More chunks are expected for this stream.
    Accumulating {
        stream_id: u16,
        updated_buffer: Vec<u8>,
    },
    /// The stream is complete (EOF received).
    Complete { stream_id: u16, data: Vec<u8> },
}

/// Unpack a stream data message and accumulate it with the existing buffer.
///
/// If EOF is set, returns `Complete` with the full accumulated data.
/// Otherwise returns `Accumulating` with the updated buffer.
pub fn decide_stream_accumulation(
    stream_packed: &[u8],
    existing_buffer: &[u8],
) -> Result<StreamAccumulationResult, String> {
    let msg = StreamDataMessage::unpack(stream_packed)
        .map_err(|e| format!("failed to unpack stream data: {e}"))?;

    let mut buffer = Vec::with_capacity(existing_buffer.len() + msg.data.len());
    buffer.extend_from_slice(existing_buffer);
    buffer.extend_from_slice(&msg.data);

    if msg.header.is_eof {
        Ok(StreamAccumulationResult::Complete {
            stream_id: msg.header.stream_id,
            data: buffer,
        })
    } else {
        Ok(StreamAccumulationResult::Accumulating {
            stream_id: msg.header.stream_id,
            updated_buffer: buffer,
        })
    }
}

// ======================================================================== //
// Extraction: match_pending_response
// ======================================================================== //

/// Result of matching a response against pending requests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponseMatch {
    /// The response matched a pending request.
    Matched {
        request_id: [u8; 16],
        path: String,
        data_preview: String,
    },
    /// The response did not match any pending request.
    Unmatched { request_id: [u8; 16] },
    /// The response plaintext could not be parsed.
    ParseError(String),
}

/// Parse a response and check if it matches a pending request.
///
/// Returns `Matched` with context if found, `Unmatched` if not, or
/// `ParseError` if the plaintext cannot be decoded.
pub fn match_pending_response(
    plaintext: &[u8],
    pending_requests: &HashMap<[u8; 16], (LinkId, String)>,
) -> ResponseMatch {
    let response = match Response::from_msgpack(plaintext) {
        Ok(r) => r,
        Err(e) => return ResponseMatch::ParseError(format!("failed to parse response: {e}")),
    };

    let mut key = [0u8; 16];
    key.copy_from_slice(response.request_id.as_ref());

    if let Some((_, path)) = pending_requests.get(&key) {
        let data_preview = format_response_preview(&response.data);
        ResponseMatch::Matched {
            request_id: key,
            path: path.clone(),
            data_preview,
        }
    } else {
        ResponseMatch::Unmatched { request_id: key }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reticulum_core::types::TruncatedHash;

    // ---- extract_request_data ----

    #[test]
    fn extract_request_data_binary() {
        let val = Value::Binary(vec![1, 2, 3, 4]);
        let result = extract_request_data(&val).unwrap();
        assert_eq!(result, vec![1, 2, 3, 4]);
    }

    #[test]
    fn extract_request_data_string() {
        let val = Value::String("hello".into());
        let result = extract_request_data(&val).unwrap();
        assert_eq!(result, b"hello");
    }

    #[test]
    fn extract_request_data_other_value() {
        let val = Value::Integer(42.into());
        let result = extract_request_data(&val).unwrap();
        // Should be msgpack-encoded integer
        let decoded: Value = rmpv::decode::read_value(&mut &result[..]).unwrap();
        assert_eq!(decoded, Value::Integer(42.into()));
    }

    #[test]
    fn extract_request_data_empty_binary() {
        let val = Value::Binary(vec![]);
        let result = extract_request_data(&val).unwrap();
        assert!(result.is_empty());
    }

    // ---- build_response_bytes ----

    #[test]
    fn build_response_bytes_roundtrip() {
        let request_id = RequestId::new(TruncatedHash::new([0xAA; 16]));
        let bytes = build_response_bytes(request_id, b"pong".to_vec());
        let response = Response::from_msgpack(&bytes).unwrap();
        match response.data {
            Value::Binary(b) => assert_eq!(b, b"pong"),
            _ => panic!("expected Binary"),
        }
    }

    #[test]
    fn build_response_bytes_preserves_request_id() {
        let request_id = RequestId::new(TruncatedHash::new([0x42; 16]));
        let bytes = build_response_bytes(request_id, vec![]);
        let response = Response::from_msgpack(&bytes).unwrap();
        assert_eq!(response.request_id.as_ref(), &[0x42; 16]);
    }

    // ---- build_request_msgpack ----

    #[test]
    fn build_request_msgpack_roundtrip() {
        let bytes = build_request_msgpack("/test/echo", b"payload", 1700000000.0);
        let request = Request::from_msgpack(&bytes).unwrap();
        match request.data {
            Value::Binary(b) => assert_eq!(b, b"payload"),
            _ => panic!("expected Binary"),
        }
    }

    #[test]
    fn build_request_msgpack_timestamp_preserved() {
        let ts = 1700000000.5;
        let bytes = build_request_msgpack("/test/echo", b"data", ts);
        let request = Request::from_msgpack(&bytes).unwrap();
        assert!((request.timestamp - ts).abs() < 1e-6);
    }

    #[test]
    fn build_request_msgpack_path_hash_correct() {
        let bytes = build_request_msgpack("/test/echo", b"data", 1.0);
        let request = Request::from_msgpack(&bytes).unwrap();
        let expected = PathHash::from_path("/test/echo");
        assert_eq!(request.path_hash.as_ref(), expected.as_ref());
    }

    // ---- build_stream_data_packed ----

    #[test]
    fn build_stream_data_packed_roundtrip() {
        let packed = build_stream_data_packed(0, b"stream data", false);
        let msg = StreamDataMessage::unpack(&packed).unwrap();
        assert_eq!(msg.data, b"stream data");
        assert_eq!(msg.header.stream_id, 0);
        assert!(!msg.header.is_eof);
    }

    #[test]
    fn build_stream_data_packed_eof_flag() {
        let packed = build_stream_data_packed(0, b"last chunk", true);
        let msg = StreamDataMessage::unpack(&packed).unwrap();
        assert!(msg.header.is_eof);
    }

    #[test]
    fn build_stream_data_packed_stream_id_preserved() {
        let packed = build_stream_data_packed(42, b"data", false);
        let msg = StreamDataMessage::unpack(&packed).unwrap();
        assert_eq!(msg.header.stream_id, 42);
    }

    // ---- format_response_preview ----

    #[test]
    fn format_response_preview_binary() {
        let val = Value::Binary(b"hello world".to_vec());
        let preview = format_response_preview(&val);
        assert_eq!(preview, "hello world");
    }

    #[test]
    fn format_response_preview_other() {
        let val = Value::Integer(99.into());
        let preview = format_response_preview(&val);
        assert!(preview.contains("99"));
    }

    // ---- classify_channel_envelope ----

    #[test]
    fn classify_application_message() {
        let envelope = Envelope {
            msg_type: 0x0101,
            sequence: 0,
            payload: b"hello".to_vec(),
        };
        let packed = envelope.pack();

        let (action, seq) = classify_channel_envelope(&packed, 0, 5).unwrap();
        assert_eq!(seq, 0);
        assert_eq!(
            action,
            ChannelEnvelopeAction::ApplicationMessage {
                msg_type: 0x0101,
                payload: b"hello".to_vec(),
            }
        );
    }

    #[test]
    fn classify_stream_data() {
        let stream_packed = build_stream_data_packed(0, b"chunk", false);
        let envelope = Envelope {
            msg_type: SMT_STREAM_DATA,
            sequence: 0,
            payload: stream_packed.clone(),
        };
        let packed = envelope.pack();

        let (action, seq) = classify_channel_envelope(&packed, 0, 5).unwrap();
        assert_eq!(seq, 0);
        assert_eq!(
            action,
            ChannelEnvelopeAction::StreamData {
                payload: stream_packed,
            }
        );
    }

    #[test]
    fn classify_sequence_in_window_accepted() {
        let envelope = Envelope {
            msg_type: 0x0001,
            sequence: 3,
            payload: b"data".to_vec(),
        };
        let packed = envelope.pack();

        // next_rx=0, window=5 → sequence 3 is valid
        let (action, _) = classify_channel_envelope(&packed, 0, 5).unwrap();
        assert!(matches!(
            action,
            ChannelEnvelopeAction::ApplicationMessage { .. }
        ));
    }

    #[test]
    fn classify_sequence_outside_window_rejected() {
        let envelope = Envelope {
            msg_type: 0x0001,
            sequence: 0,
            payload: b"data".to_vec(),
        };
        let packed = envelope.pack();

        // next_rx=5, window=2, sequence=0 → outside window, no wraparound
        let (action, seq) = classify_channel_envelope(&packed, 5, 2).unwrap();
        assert_eq!(seq, 0);
        assert_eq!(
            action,
            ChannelEnvelopeAction::SequenceRejected { sequence: 0 }
        );
    }

    #[test]
    fn classify_corrupt_plaintext_error() {
        let result = classify_channel_envelope(b"xx", 0, 5);
        assert!(result.is_err());
    }

    #[test]
    fn classify_empty_plaintext_error() {
        let result = classify_channel_envelope(&[], 0, 5);
        assert!(result.is_err());
    }

    #[test]
    fn classify_sequence_at_wrap_boundary() {
        let envelope = Envelope {
            msg_type: 0x0001,
            sequence: 0,
            payload: b"wrapped".to_vec(),
        };
        let packed = envelope.pack();

        // next_rx=65534, window=5 → window wraps around 0, sequence 0 is valid
        let (action, seq) = classify_channel_envelope(&packed, 65534, 5).unwrap();
        assert_eq!(seq, 0);
        assert!(matches!(
            action,
            ChannelEnvelopeAction::ApplicationMessage { .. }
        ));
    }

    #[test]
    fn classify_various_msg_types() {
        for msg_type in [0x0000, 0x0001, 0x0100, 0xFEFF] {
            let envelope = Envelope {
                msg_type,
                sequence: 0,
                payload: vec![],
            };
            let packed = envelope.pack();
            let (action, _) = classify_channel_envelope(&packed, 0, 5).unwrap();
            match action {
                ChannelEnvelopeAction::ApplicationMessage { msg_type: mt, .. } => {
                    assert_eq!(mt, msg_type);
                }
                _ => panic!("expected ApplicationMessage for msg_type 0x{msg_type:04X}"),
            }
        }
    }

    // ---- decide_stream_accumulation ----

    #[test]
    fn accumulation_single_chunk_eof() {
        let packed = build_stream_data_packed(0, b"complete", true);
        let result = decide_stream_accumulation(&packed, &[]).unwrap();
        assert_eq!(
            result,
            StreamAccumulationResult::Complete {
                stream_id: 0,
                data: b"complete".to_vec(),
            }
        );
    }

    #[test]
    fn accumulation_single_chunk_no_eof() {
        let packed = build_stream_data_packed(0, b"partial", false);
        let result = decide_stream_accumulation(&packed, &[]).unwrap();
        assert_eq!(
            result,
            StreamAccumulationResult::Accumulating {
                stream_id: 0,
                updated_buffer: b"partial".to_vec(),
            }
        );
    }

    #[test]
    fn accumulation_multi_chunk() {
        // First chunk
        let packed1 = build_stream_data_packed(0, b"hello ", false);
        let result1 = decide_stream_accumulation(&packed1, &[]).unwrap();
        let buf = match result1 {
            StreamAccumulationResult::Accumulating { updated_buffer, .. } => updated_buffer,
            _ => panic!("expected Accumulating"),
        };

        // Second chunk with EOF
        let packed2 = build_stream_data_packed(0, b"world", true);
        let result2 = decide_stream_accumulation(&packed2, &buf).unwrap();
        assert_eq!(
            result2,
            StreamAccumulationResult::Complete {
                stream_id: 0,
                data: b"hello world".to_vec(),
            }
        );
    }

    #[test]
    fn accumulation_empty_chunk_eof() {
        let packed = build_stream_data_packed(0, b"", true);
        let result = decide_stream_accumulation(&packed, b"existing").unwrap();
        assert_eq!(
            result,
            StreamAccumulationResult::Complete {
                stream_id: 0,
                data: b"existing".to_vec(),
            }
        );
    }

    #[test]
    fn accumulation_empty_existing_buffer() {
        let packed = build_stream_data_packed(0, b"data", false);
        let result = decide_stream_accumulation(&packed, &[]).unwrap();
        assert_eq!(
            result,
            StreamAccumulationResult::Accumulating {
                stream_id: 0,
                updated_buffer: b"data".to_vec(),
            }
        );
    }

    #[test]
    fn accumulation_corrupt_packed_error() {
        let result = decide_stream_accumulation(&[0xFF], &[]);
        assert!(result.is_err());
    }

    #[test]
    fn accumulation_stream_id_preserved() {
        let packed = build_stream_data_packed(42, b"data", false);
        let result = decide_stream_accumulation(&packed, &[]).unwrap();
        match result {
            StreamAccumulationResult::Accumulating { stream_id, .. } => {
                assert_eq!(stream_id, 42);
            }
            _ => panic!("expected Accumulating"),
        }
    }

    #[test]
    fn accumulation_stream_id_preserved_eof() {
        let packed = build_stream_data_packed(7, b"done", true);
        let result = decide_stream_accumulation(&packed, &[]).unwrap();
        match result {
            StreamAccumulationResult::Complete { stream_id, .. } => {
                assert_eq!(stream_id, 7);
            }
            _ => panic!("expected Complete"),
        }
    }

    // ---- match_pending_response ----

    #[test]
    fn response_matches_pending() {
        let request_id = [0x42u8; 16];
        let link_id = LinkId::new([0xAA; 16]);
        let mut pending = HashMap::new();
        pending.insert(request_id, (link_id, "/test/echo".to_string()));

        let response = Response {
            request_id: RequestId::new(TruncatedHash::new(request_id)),
            data: Value::Binary(b"pong".to_vec()),
        };
        let bytes = response.to_msgpack();

        let result = match_pending_response(&bytes, &pending);
        match result {
            ResponseMatch::Matched {
                request_id: rid,
                path,
                data_preview,
            } => {
                assert_eq!(rid, request_id);
                assert_eq!(path, "/test/echo");
                assert_eq!(data_preview, "pong");
            }
            _ => panic!("expected Matched"),
        }
    }

    #[test]
    fn response_unmatched() {
        let request_id = [0x42u8; 16];
        let response = Response {
            request_id: RequestId::new(TruncatedHash::new(request_id)),
            data: Value::Binary(b"data".to_vec()),
        };
        let bytes = response.to_msgpack();

        let pending = HashMap::new();
        let result = match_pending_response(&bytes, &pending);
        match result {
            ResponseMatch::Unmatched { request_id: rid } => {
                assert_eq!(rid, request_id);
            }
            _ => panic!("expected Unmatched"),
        }
    }

    #[test]
    fn response_parse_error() {
        let result = match_pending_response(b"not valid msgpack", &HashMap::new());
        assert!(matches!(result, ResponseMatch::ParseError(_)));
    }

    #[test]
    fn response_multiple_pending_correct_match() {
        let id1 = [0x11u8; 16];
        let id2 = [0x22u8; 16];
        let id3 = [0x33u8; 16];
        let link_id = LinkId::new([0xBB; 16]);
        let mut pending = HashMap::new();
        pending.insert(id1, (link_id, "/path/one".to_string()));
        pending.insert(id2, (link_id, "/path/two".to_string()));
        pending.insert(id3, (link_id, "/path/three".to_string()));

        // Response for id2
        let response = Response {
            request_id: RequestId::new(TruncatedHash::new(id2)),
            data: Value::Binary(b"result".to_vec()),
        };
        let bytes = response.to_msgpack();

        let result = match_pending_response(&bytes, &pending);
        match result {
            ResponseMatch::Matched { path, .. } => {
                assert_eq!(path, "/path/two");
            }
            _ => panic!("expected Matched"),
        }
    }

    #[test]
    fn response_binary_data_preview() {
        let request_id = [0x01u8; 16];
        let link_id = LinkId::new([0xCC; 16]);
        let mut pending = HashMap::new();
        pending.insert(request_id, (link_id, "/test".to_string()));

        // Non-UTF8 binary data
        let response = Response {
            request_id: RequestId::new(TruncatedHash::new(request_id)),
            data: Value::Binary(vec![0xFF, 0xFE, 0xFD]),
        };
        let bytes = response.to_msgpack();

        let result = match_pending_response(&bytes, &pending);
        match result {
            ResponseMatch::Matched { data_preview, .. } => {
                // Lossy UTF-8 should contain replacement characters
                assert!(!data_preview.is_empty());
            }
            _ => panic!("expected Matched"),
        }
    }

    #[test]
    fn response_non_binary_data_preview() {
        let request_id = [0x02u8; 16];
        let link_id = LinkId::new([0xDD; 16]);
        let mut pending = HashMap::new();
        pending.insert(request_id, (link_id, "/test".to_string()));

        let response = Response {
            request_id: RequestId::new(TruncatedHash::new(request_id)),
            data: Value::Integer(42.into()),
        };
        let bytes = response.to_msgpack();

        let result = match_pending_response(&bytes, &pending);
        match result {
            ResponseMatch::Matched { data_preview, .. } => {
                assert!(data_preview.contains("42"));
            }
            _ => panic!("expected Matched"),
        }
    }
}
