//! Pure functions for channel, buffer, and request/response operations.
//!
//! These functions extract computation from `ChannelManager` methods,
//! making the logic independently testable without channel state.

use reticulum_protocol::buffer::stream_data::{StreamDataMessage, StreamHeader};
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
}
