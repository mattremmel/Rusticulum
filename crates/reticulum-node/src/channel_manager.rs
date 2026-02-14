//! Channel, buffer, and request/response management for the node.
//!
//! Manages per-link channel state (envelope sequencing), buffer stream
//! accumulation, and request/response dispatching. This module is a pure
//! state tracker — it does NOT send packets or hold crypto keys.

use std::collections::HashMap;

use reticulum_core::types::LinkId;
use reticulum_protocol::buffer::constants::SMT_STREAM_DATA;
use reticulum_protocol::buffer::stream_data::StreamHeader;
use reticulum_protocol::channel::envelope::Envelope;
use reticulum_protocol::channel::state::ChannelState;
use reticulum_protocol::request::types::{PathHash, Request, RequestId};

use crate::channel_ops::{self, ChannelEnvelopeAction, ClassifiedEnvelope, ResponseMatch, StreamAccumulationResult};

/// Actions the node should take after processing a channel event.
#[derive(Debug)]
pub enum ChannelAction {
    /// A channel message was received (msg_type, payload).
    MessageReceived { msg_type: u16, payload: Vec<u8> },
    /// A buffer stream completed (stream_id, accumulated data).
    BufferComplete { stream_id: u16, data: Vec<u8> },
    /// A response should be sent (serialized response bytes).
    SendResponse(Vec<u8>),
}

/// Per-link channel context.
struct ChannelContext {
    state: ChannelState,
    /// Buffer accumulation: stream_id -> accumulated data chunks.
    rx_buffers: HashMap<u16, Vec<u8>>,
}

/// Request handler callback type.
type RequestHandler = Box<dyn Fn(&[u8]) -> Vec<u8> + Send + Sync>;

/// Manages channel, buffer, and request/response state for all links.
pub struct ChannelManager {
    /// Per-link channel state.
    channels: HashMap<LinkId, ChannelContext>,
    /// Request handlers keyed by path hash (first 16 bytes).
    request_handlers: HashMap<[u8; 16], RequestHandler>,
    /// Pending outbound requests: request_id -> (link_id, path).
    pending_requests: HashMap<[u8; 16], (LinkId, String)>,
    /// Auto-send queues from config.
    auto_channel_queue: HashMap<LinkId, String>,
    auto_buffer_queue: HashMap<LinkId, String>,
    auto_request_queue: HashMap<LinkId, (String, String)>,
}

impl Default for ChannelManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ChannelManager {
    /// Create a new empty ChannelManager.
    pub fn new() -> Self {
        Self {
            channels: HashMap::new(),
            request_handlers: HashMap::new(),
            pending_requests: HashMap::new(),
            auto_channel_queue: HashMap::new(),
            auto_buffer_queue: HashMap::new(),
            auto_request_queue: HashMap::new(),
        }
    }

    /// Remove all state for a torn-down link.
    pub fn remove_link(&mut self, link_id: &LinkId) {
        self.channels.remove(link_id);
        self.auto_channel_queue.remove(link_id);
        self.auto_buffer_queue.remove(link_id);
        self.auto_request_queue.remove(link_id);
        // Remove any pending requests associated with this link
        self.pending_requests.retain(|_, (lid, _)| lid != link_id);
    }

    /// Register a link for channel communication.
    pub fn register_link(&mut self, link_id: LinkId, rtt: f64) {
        tracing::debug!(
            link_id = %hex::encode(link_id.as_ref()),
            rtt,
            "registered link for channel communication"
        );
        self.channels.insert(
            link_id,
            ChannelContext {
                state: ChannelState::new(rtt),
                rx_buffers: HashMap::new(),
            },
        );
    }

    /// Register a request handler for a given path.
    pub fn register_request_handler<F>(&mut self, path: &str, handler: F)
    where
        F: Fn(&[u8]) -> Vec<u8> + Send + Sync + 'static,
    {
        let path_hash = PathHash::from_path(path);
        let mut key = [0u8; 16];
        key.copy_from_slice(path_hash.as_ref());
        tracing::debug!(path, path_hash = %hex::encode(key), "registered request handler");
        self.request_handlers.insert(key, Box::new(handler));
    }

    // ---- Channel message handling ----

    /// Handle decrypted channel data (from a CHANNEL context packet).
    ///
    /// Parses the Envelope, dispatches by msg_type.
    /// Returns an action if the message was processed.
    pub fn handle_channel_data(
        &mut self,
        link_id: &LinkId,
        plaintext: &[u8],
    ) -> Option<ChannelAction> {
        let ctx = self.channels.get_mut(link_id)?;

        let ClassifiedEnvelope { action, sequence } = match channel_ops::classify_channel_envelope(
            plaintext,
            ctx.state.next_rx_sequence(),
            ctx.state.window_max,
        ) {
            Ok(result) => result,
            Err(e) => {
                tracing::warn!(
                    link_id = %hex::encode(link_id.as_ref()),
                    "failed to classify channel envelope: {e}"
                );
                return None;
            }
        };

        match action {
            ChannelEnvelopeAction::SequenceRejected { sequence } => {
                tracing::warn!(
                    link_id = %hex::encode(link_id.as_ref()),
                    sequence,
                    "channel sequence rejected"
                );
                None
            }
            ChannelEnvelopeAction::StreamData { payload } => {
                ctx.state.advance_rx_sequence();
                tracing::info!(
                    link_id = %hex::encode(link_id.as_ref()),
                    msg_type = SMT_STREAM_DATA,
                    sequence,
                    payload_len = payload.len(),
                    "channel_message_received"
                );
                self.handle_stream_data_inner(link_id, &payload)
            }
            ChannelEnvelopeAction::ApplicationMessage { msg_type, payload } => {
                ctx.state.advance_rx_sequence();
                tracing::info!(
                    link_id = %hex::encode(link_id.as_ref()),
                    msg_type,
                    sequence,
                    payload_len = payload.len(),
                    "channel_message_received"
                );
                Some(ChannelAction::MessageReceived { msg_type, payload })
            }
        }
    }

    /// Handle a stream data message (inside an envelope with msg_type=SMT_STREAM_DATA).
    fn handle_stream_data_inner(
        &mut self,
        link_id: &LinkId,
        stream_packed: &[u8],
    ) -> Option<ChannelAction> {
        let ctx = self.channels.get_mut(link_id)?;

        // Peek at the stream header to get stream_id for buffer lookup
        let header = match StreamHeader::decode(stream_packed) {
            Ok(h) => h,
            Err(e) => {
                tracing::warn!(
                    link_id = %hex::encode(link_id.as_ref()),
                    "failed to decode stream header: {e}"
                );
                return None;
            }
        };

        let existing = ctx.rx_buffers.entry(header.stream_id).or_default();
        let result = match channel_ops::decide_stream_accumulation(stream_packed, existing) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(
                    link_id = %hex::encode(link_id.as_ref()),
                    "failed to unpack stream data: {e}"
                );
                return None;
            }
        };

        match result {
            StreamAccumulationResult::Accumulating {
                stream_id,
                updated_buffer,
            } => {
                tracing::debug!(
                    link_id = %hex::encode(link_id.as_ref()),
                    stream_id,
                    total_len = updated_buffer.len(),
                    "buffer_chunk_received"
                );
                *ctx.rx_buffers.entry(stream_id).or_default() = updated_buffer;
                None
            }
            StreamAccumulationResult::Complete { stream_id, data } => {
                ctx.rx_buffers.remove(&stream_id);
                tracing::info!(
                    link_id = %hex::encode(link_id.as_ref()),
                    stream_id,
                    total_len = data.len(),
                    "buffer_complete"
                );
                Some(ChannelAction::BufferComplete { stream_id, data })
            }
        }
    }

    // ---- Request/Response handling ----

    /// Handle a decrypted request (from a REQUEST context packet).
    ///
    /// Looks up the request handler by path hash and invokes it.
    /// Returns the serialized Response bytes to send back, if a handler matched.
    pub fn handle_request(
        &mut self,
        link_id: &LinkId,
        plaintext: &[u8],
        hashable_part: &[u8],
    ) -> Option<Vec<u8>> {
        let request = match Request::from_msgpack(plaintext) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(
                    link_id = %hex::encode(link_id.as_ref()),
                    "failed to parse request: {e}"
                );
                return None;
            }
        };

        let mut key = [0u8; 16];
        key.copy_from_slice(request.path_hash.as_ref());

        tracing::info!(
            link_id = %hex::encode(link_id.as_ref()),
            path_hash = %hex::encode(key),
            "request_received"
        );

        let handler = self.request_handlers.get(&key)?;

        // Extract request data as bytes
        let request_data = channel_ops::extract_request_data(&request.data)?;

        let response_data = handler(&request_data);

        // Compute request_id from the hashable_part of the incoming packet
        let request_id = RequestId::from_hashable_part(hashable_part);

        let response_bytes = channel_ops::build_response_bytes(request_id, response_data);

        tracing::info!(
            link_id = %hex::encode(link_id.as_ref()),
            request_id = %hex::encode(request_id.as_ref()),
            response_len = response_bytes.len(),
            "request_handled"
        );

        Some(response_bytes)
    }

    /// Handle a decrypted response (from a RESPONSE context packet).
    pub fn handle_response(&mut self, link_id: &LinkId, plaintext: &[u8]) {
        match channel_ops::match_pending_response(plaintext, &self.pending_requests) {
            ResponseMatch::Matched {
                request_id,
                path,
                data_preview,
            } => {
                self.pending_requests.remove(&request_id);
                tracing::info!(
                    link_id = %hex::encode(link_id.as_ref()),
                    request_id = %hex::encode(request_id),
                    path,
                    data_preview = %&data_preview[..data_preview.len().min(200)],
                    "response_received"
                );
            }
            ResponseMatch::Unmatched { request_id } => {
                tracing::debug!(
                    link_id = %hex::encode(link_id.as_ref()),
                    request_id = %hex::encode(request_id),
                    "received response for unknown request"
                );
            }
            ResponseMatch::ParseError(e) => {
                tracing::warn!(
                    link_id = %hex::encode(link_id.as_ref()),
                    "{e}"
                );
            }
        }
    }

    // ---- Building outbound messages ----

    /// Build a channel envelope for sending (returns plaintext to be link-encrypted).
    pub fn build_channel_message(
        &mut self,
        link_id: &LinkId,
        msg_type: u16,
        payload: &[u8],
    ) -> Option<Vec<u8>> {
        let ctx = self.channels.get_mut(link_id)?;
        let sequence = ctx.state.next_sequence();

        let envelope = Envelope {
            msg_type,
            sequence,
            payload: payload.to_vec(),
        };

        Some(envelope.pack())
    }

    /// Build a buffer stream chunk wrapped in an envelope (returns plaintext).
    ///
    /// Uses stream_id=0, wraps data in StreamDataMessage inside Envelope(SMT_STREAM_DATA).
    pub fn build_stream_message(
        &mut self,
        link_id: &LinkId,
        stream_id: u16,
        data: &[u8],
        eof: bool,
    ) -> Option<Vec<u8>> {
        let stream_packed = channel_ops::build_stream_data_packed(stream_id, data, eof);
        self.build_channel_message(link_id, SMT_STREAM_DATA, &stream_packed)
    }

    /// Build a request message (returns plaintext for REQUEST context).
    pub fn build_request(&mut self, link_id: &LinkId, path: &str, data: &[u8]) -> Option<Vec<u8>> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();

        let packed = channel_ops::build_request_msgpack(path, data, timestamp);

        tracing::debug!(
            link_id = %hex::encode(link_id.as_ref()),
            path,
            packed_len = packed.len(),
            "built request"
        );

        Some(packed)
    }

    /// Record a pending outbound request so we can match the response later.
    pub fn record_pending_request(&mut self, link_id: &LinkId, path: &str, request_id: [u8; 16]) {
        self.pending_requests
            .insert(request_id, (*link_id, path.to_string()));
    }

    // ---- Auto-send queue management ----

    /// Queue an auto-channel message for a link.
    pub fn queue_auto_channel(&mut self, link_id: LinkId, msg: String) {
        self.auto_channel_queue.insert(link_id, msg);
    }

    /// Queue auto-buffer data for a link.
    pub fn queue_auto_buffer(&mut self, link_id: LinkId, data: String) {
        self.auto_buffer_queue.insert(link_id, data);
    }

    /// Queue an auto-request for a link.
    pub fn queue_auto_request(&mut self, link_id: LinkId, path: String, data: String) {
        self.auto_request_queue.insert(link_id, (path, data));
    }

    /// Drain auto-channel message.
    pub fn drain_auto_channel(&mut self, link_id: &LinkId) -> Option<String> {
        self.auto_channel_queue.remove(link_id)
    }

    /// Drain auto-buffer data.
    pub fn drain_auto_buffer(&mut self, link_id: &LinkId) -> Option<String> {
        self.auto_buffer_queue.remove(link_id)
    }

    /// Drain auto-request.
    pub fn drain_auto_request(&mut self, link_id: &LinkId) -> Option<(String, String)> {
        self.auto_request_queue.remove(link_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reticulum_core::types::TruncatedHash;
    use reticulum_protocol::channel::envelope::Envelope;
    use reticulum_protocol::request::types::Response;
    use rmpv::Value;

    #[test]
    fn test_register_link() {
        let mut mgr = ChannelManager::new();
        let link_id = LinkId::new([0xAA; 16]);
        mgr.register_link(link_id, 0.05);
        assert!(mgr.channels.contains_key(&link_id));
    }

    #[test]
    fn test_envelope_roundtrip() {
        let mut mgr = ChannelManager::new();
        let link_id = LinkId::new([0xBB; 16]);
        mgr.register_link(link_id, 0.05);

        let plaintext = mgr
            .build_channel_message(&link_id, 0x0101, b"hello channel")
            .unwrap();

        let action = mgr.handle_channel_data(&link_id, &plaintext).unwrap();

        match action {
            ChannelAction::MessageReceived { msg_type, payload } => {
                assert_eq!(msg_type, 0x0101);
                assert_eq!(payload, b"hello channel");
            }
            _ => panic!("expected MessageReceived"),
        }
    }

    #[test]
    fn test_stream_buffer_accumulation() {
        let mut mgr = ChannelManager::new();
        let link_id = LinkId::new([0xCC; 16]);
        mgr.register_link(link_id, 0.05);

        // Send first chunk (not EOF)
        let chunk1 = mgr
            .build_stream_message(&link_id, 0, b"hello ", false)
            .unwrap();
        let action1 = mgr.handle_channel_data(&link_id, &chunk1);
        assert!(action1.is_none()); // Not complete yet

        // Send second chunk (EOF)
        let chunk2 = mgr
            .build_stream_message(&link_id, 0, b"world", true)
            .unwrap();
        let action2 = mgr.handle_channel_data(&link_id, &chunk2).unwrap();

        match action2 {
            ChannelAction::BufferComplete { stream_id, data } => {
                assert_eq!(stream_id, 0);
                assert_eq!(data, b"hello world");
            }
            _ => panic!("expected BufferComplete"),
        }
    }

    #[test]
    fn test_request_handler_echo() {
        let mut mgr = ChannelManager::new();
        let link_id = LinkId::new([0xDD; 16]);
        mgr.register_link(link_id, 0.05);

        // Register echo handler
        mgr.register_request_handler("/test/echo", |data| data.to_vec());

        // Build a request
        let request_bytes = mgr.build_request(&link_id, "/test/echo", b"ping").unwrap();

        // Simulate hashable_part (just use the request bytes for test)
        let fake_hashable = b"fake_hashable_part_for_test_1234567890abcdef";

        // Handle request
        let response_bytes = mgr
            .handle_request(&link_id, &request_bytes, fake_hashable)
            .unwrap();

        // Parse response
        let response = Response::from_msgpack(&response_bytes).unwrap();
        match response.data {
            Value::Binary(b) => assert_eq!(b, b"ping"),
            _ => panic!("expected binary response data"),
        }
    }

    #[test]
    fn test_response_matching() {
        let mut mgr = ChannelManager::new();
        let link_id = LinkId::new([0xEE; 16]);
        mgr.register_link(link_id, 0.05);

        // Record a pending request
        let request_id = [0x42u8; 16];
        mgr.record_pending_request(&link_id, "/test/echo", request_id);

        // Build a matching response
        let response = Response {
            request_id: RequestId::new(TruncatedHash::new(request_id)),
            data: Value::Binary(b"pong".to_vec()),
        };
        let response_bytes = response.to_msgpack();

        // Handle response -- should log response_received (not panic)
        mgr.handle_response(&link_id, &response_bytes);

        // Pending request should be removed
        assert!(!mgr.pending_requests.contains_key(&request_id));
    }

    #[test]
    fn test_sequence_wrapping() {
        let mut mgr = ChannelManager::new();
        let link_id = LinkId::new([0xFF; 16]);
        mgr.register_link(link_id, 0.05);

        // Manually set TX sequence near wrap point
        {
            let ctx = mgr.channels.get_mut(&link_id).unwrap();
            // Advance to 65534 (two before wrap)
            for _ in 0..65534u32 {
                ctx.state.next_sequence();
            }
            assert_eq!(ctx.state.peek_tx_sequence(), 65534);
        }

        // Build messages across the wrap boundary
        let msg1 = mgr
            .build_channel_message(&link_id, 0x0101, b"before wrap")
            .unwrap();
        let msg2 = mgr
            .build_channel_message(&link_id, 0x0101, b"at wrap")
            .unwrap();
        let msg3 = mgr
            .build_channel_message(&link_id, 0x0101, b"after wrap")
            .unwrap();

        // Verify sequences in the envelopes
        let env1 = Envelope::unpack(&msg1).unwrap();
        let env2 = Envelope::unpack(&msg2).unwrap();
        let env3 = Envelope::unpack(&msg3).unwrap();

        assert_eq!(env1.sequence, 65534);
        assert_eq!(env2.sequence, 65535);
        assert_eq!(env3.sequence, 0); // wrapped!
    }

    #[test]
    fn test_auto_queues() {
        let mut mgr = ChannelManager::new();
        let link_id = LinkId::new([0x11; 16]);

        mgr.queue_auto_channel(link_id, "hello".to_string());
        mgr.queue_auto_buffer(link_id, "stream data".to_string());
        mgr.queue_auto_request(link_id, "/test/echo".to_string(), "payload".to_string());

        assert_eq!(mgr.drain_auto_channel(&link_id).as_deref(), Some("hello"));
        assert_eq!(
            mgr.drain_auto_buffer(&link_id).as_deref(),
            Some("stream data")
        );
        assert_eq!(
            mgr.drain_auto_request(&link_id),
            Some(("/test/echo".to_string(), "payload".to_string()))
        );

        // Second drain should return None
        assert!(mgr.drain_auto_channel(&link_id).is_none());
    }

    #[test]
    fn test_unknown_link_returns_none() {
        let mut mgr = ChannelManager::new();
        let link_id = LinkId::new([0x99; 16]);

        assert!(
            mgr.build_channel_message(&link_id, 0x0101, b"test")
                .is_none()
        );
        assert!(mgr.handle_channel_data(&link_id, b"test").is_none());
    }

    #[test]
    fn test_handle_channel_data_unknown_msg_type() {
        let mut mgr = ChannelManager::new();
        let link_id = LinkId::new([0xA1; 16]);
        mgr.register_link(link_id, 0.05);

        // Build envelope with an unusual msg_type
        let plaintext = mgr
            .build_channel_message(&link_id, 0xBEEF, b"unusual")
            .unwrap();

        let action = mgr.handle_channel_data(&link_id, &plaintext).unwrap();
        match action {
            ChannelAction::MessageReceived { msg_type, payload } => {
                assert_eq!(msg_type, 0xBEEF);
                assert_eq!(payload, b"unusual");
            }
            _ => panic!("expected MessageReceived for unknown msg_type"),
        }
    }

    #[test]
    fn test_request_handler_no_matching_path() {
        let mut mgr = ChannelManager::new();
        let link_id = LinkId::new([0xA2; 16]);
        mgr.register_link(link_id, 0.05);

        // Register handler for /test/echo but send request to /test/other
        mgr.register_request_handler("/test/echo", |data| data.to_vec());

        let request_bytes = mgr.build_request(&link_id, "/test/other", b"data").unwrap();
        let fake_hashable = b"fake_hashable_part_for_test_1234567890abcdef";

        let response = mgr.handle_request(&link_id, &request_bytes, fake_hashable);
        assert!(response.is_none());
    }

    #[test]
    fn test_response_for_unknown_request_id() {
        let mut mgr = ChannelManager::new();
        let link_id = LinkId::new([0xA3; 16]);
        mgr.register_link(link_id, 0.05);

        // Build a response with a request_id we never registered
        let response = Response {
            request_id: RequestId::new(TruncatedHash::new([0xDEu8; 16])),
            data: Value::Binary(b"orphan response".to_vec()),
        };
        let response_bytes = response.to_msgpack();

        // Should not panic, just log a debug message
        mgr.handle_response(&link_id, &response_bytes);

        // No pending requests should exist
        assert!(mgr.pending_requests.is_empty());
    }

    #[test]
    fn test_multiple_stream_ids() {
        let mut mgr = ChannelManager::new();
        let link_id = LinkId::new([0xA4; 16]);
        mgr.register_link(link_id, 0.05);

        // Stream 0: partial data
        let chunk0 = mgr
            .build_stream_message(&link_id, 0, b"stream-0-part1", false)
            .unwrap();
        let action0 = mgr.handle_channel_data(&link_id, &chunk0);
        assert!(action0.is_none()); // accumulating

        // Stream 1: complete in one chunk
        let chunk1 = mgr
            .build_stream_message(&link_id, 1, b"stream-1-complete", true)
            .unwrap();
        let action1 = mgr.handle_channel_data(&link_id, &chunk1).unwrap();
        match action1 {
            ChannelAction::BufferComplete { stream_id, data } => {
                assert_eq!(stream_id, 1);
                assert_eq!(data, b"stream-1-complete");
            }
            _ => panic!("expected BufferComplete for stream 1"),
        }

        // Stream 0: finish
        let chunk0_final = mgr
            .build_stream_message(&link_id, 0, b"-part2", true)
            .unwrap();
        let action0_final = mgr.handle_channel_data(&link_id, &chunk0_final).unwrap();
        match action0_final {
            ChannelAction::BufferComplete { stream_id, data } => {
                assert_eq!(stream_id, 0);
                assert_eq!(data, b"stream-0-part1-part2");
            }
            _ => panic!("expected BufferComplete for stream 0"),
        }
    }

    #[test]
    fn test_many_simultaneous_streams() {
        let mut mgr = ChannelManager::new();
        let link_id = LinkId::new([0xB1; 16]);
        mgr.register_link(link_id, 0.05);

        // Create 100 streams, each with data+EOF chunks
        for sid in 0u16..100 {
            let data_part = format!("stream-{sid}-data");
            let chunk = mgr
                .build_stream_message(&link_id, sid, data_part.as_bytes(), false)
                .unwrap();
            let action = mgr.handle_channel_data(&link_id, &chunk);
            assert!(
                action.is_none(),
                "should still be accumulating for stream {sid}"
            );
        }

        // Now send EOF for each stream
        let mut completed = 0u16;
        for sid in 0u16..100 {
            let eof_chunk = mgr
                .build_stream_message(&link_id, sid, b"-eof", true)
                .unwrap();
            let action = mgr.handle_channel_data(&link_id, &eof_chunk).unwrap();
            match action {
                ChannelAction::BufferComplete { stream_id, data } => {
                    assert_eq!(stream_id, sid);
                    let expected = format!("stream-{sid}-data-eof");
                    assert_eq!(data, expected.as_bytes());
                    completed += 1;
                }
                _ => panic!("expected BufferComplete for stream {sid}"),
            }
        }
        assert_eq!(completed, 100);
    }

    #[test]
    fn test_rapid_delivery_timeout_cycles() {
        let mut mgr = ChannelManager::new();
        let link_id = LinkId::new([0xB2; 16]);
        mgr.register_link(link_id, 0.05);

        let ctx = mgr.channels.get_mut(&link_id).unwrap();

        // 50 deliveries (rtt = 0.05)
        for _ in 0..50 {
            ctx.state.on_delivery(0.05);
        }
        let window_after_delivery = ctx.state.window;
        assert!(window_after_delivery >= 1);

        // 20 timeouts (tries = 1)
        for _ in 0..20 {
            ctx.state.on_timeout(1);
        }
        let window_after_timeout = ctx.state.window;
        // Window should have shrunk (or stayed at minimum)
        assert!(window_after_timeout >= 1);
        assert!(window_after_timeout <= window_after_delivery);

        // 30 more deliveries
        for _ in 0..30 {
            ctx.state.on_delivery(0.05);
        }
        let window_final = ctx.state.window;
        assert!(window_final >= 1);

        // Window invariants should hold throughout
        assert!(ctx.state.window <= ctx.state.window_max);
        assert!(ctx.state.window >= ctx.state.window_min);
    }

    #[test]
    fn test_channel_data_unregistered_link() {
        let mut mgr = ChannelManager::new();
        let unknown = LinkId::new([0xB3; 16]);

        // handle_channel_data for unknown link → None
        assert!(mgr.handle_channel_data(&unknown, b"test").is_none());
    }

    #[test]
    fn test_build_channel_message_unregistered_link() {
        let mut mgr = ChannelManager::new();
        let unknown = LinkId::new([0xB4; 16]);

        // build_channel_message for unknown link → None
        assert!(
            mgr.build_channel_message(&unknown, 0x0101, b"test")
                .is_none()
        );
    }

    #[test]
    fn test_many_pending_requests() {
        let mut mgr = ChannelManager::new();
        let link_id = LinkId::new([0xB5; 16]);
        mgr.register_link(link_id, 0.05);

        // Record 1000 pending requests
        for i in 0u32..1000 {
            let mut request_id = [0u8; 16];
            request_id[..4].copy_from_slice(&i.to_be_bytes());
            mgr.record_pending_request(&link_id, "/test/stress", request_id);
        }
        assert_eq!(mgr.pending_requests.len(), 1000);

        // Handle 500 responses — remove half
        for i in 0u32..500 {
            let mut request_id = [0u8; 16];
            request_id[..4].copy_from_slice(&i.to_be_bytes());
            let response = Response {
                request_id: RequestId::new(TruncatedHash::new(request_id)),
                data: Value::Binary(format!("resp-{i}").into_bytes()),
            };
            let response_bytes = response.to_msgpack();
            mgr.handle_response(&link_id, &response_bytes);
        }

        // 500 should remain
        assert_eq!(mgr.pending_requests.len(), 500);

        // Verify the remaining are the correct ones (500-999)
        for i in 500u32..1000 {
            let mut request_id = [0u8; 16];
            request_id[..4].copy_from_slice(&i.to_be_bytes());
            assert!(mgr.pending_requests.contains_key(&request_id));
        }
    }
}
