//! Path request handler: decision tree, tag dedup, and grace period computation.
//!
//! Pure functions for processing inbound path requests. Transport nodes that know
//! a path to the requested destination serve cached announce packets as path responses.

use std::collections::{HashSet, VecDeque};

use reticulum_core::types::{DestinationHash, PacketHash, TruncatedHash};
use reticulum_transport::path::constants::{PATH_REQUEST_GRACE, PATH_REQUEST_RG, MAX_PR_TAGS};
use reticulum_transport::path::path_request::{ParseResult, parse_path_request_data};
use reticulum_transport::path::types::InterfaceMode;

/// Discovery tag deduplication table.
///
/// Tracks unique tags (destination_hash || tag_bytes) to prevent duplicate
/// path request processing. Uses FIFO eviction at `MAX_PR_TAGS`.
pub struct DiscoveryTagTable {
    tags: HashSet<Vec<u8>>,
    order: VecDeque<Vec<u8>>,
}

impl DiscoveryTagTable {
    #[must_use]
    pub fn new() -> Self {
        Self {
            tags: HashSet::new(),
            order: VecDeque::new(),
        }
    }

    /// Check if a unique tag has been seen before.
    ///
    /// Returns `true` if the tag is new (first time seen).
    /// Returns `false` if it's a duplicate.
    pub fn check_and_insert(&mut self, unique_tag: &[u8]) -> bool {
        if self.tags.contains(unique_tag) {
            return false;
        }

        // Evict oldest if at capacity
        while self.tags.len() >= MAX_PR_TAGS {
            if let Some(old) = self.order.pop_front() {
                self.tags.remove(&old);
            }
        }

        let tag_vec = unique_tag.to_vec();
        self.tags.insert(tag_vec.clone());
        self.order.push_back(tag_vec);
        true
    }

    /// Number of tracked tags.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.tags.len()
    }
}

impl Default for DiscoveryTagTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Decision from evaluating a path request.
#[derive(Debug, Clone)]
pub enum PathRequestDecision {
    /// Serve a cached announce via the announce table.
    AnswerWithCachedAnnounce {
        destination: DestinationHash,
        cached_raw: Vec<u8>,
        hops: u8,
        retransmit_timeout: f64,
        from_interface: u64,
        block_rebroadcasts: bool,
    },
    /// Forward the path request to other interfaces (we don't have the path).
    ForwardPathRequest {
        raw_packet: Vec<u8>,
        exclude_interface: u64,
    },
    /// Tag was already seen, skip.
    DuplicateTag,
    /// Data too short.
    TooShort,
    /// No tag in request.
    Tagless,
    /// Loop detected: requestor is our next_hop for this dest.
    SkipLoop,
    /// No action needed.
    #[allow(dead_code)]
    Ignore,
}

/// Input data for path request decision making.
pub struct PathRequestContext<'a> {
    /// The raw path request data (payload after header).
    pub data: &'a [u8],
    /// The full raw packet (for forwarding).
    pub raw_packet: &'a [u8],
    /// Interface the request arrived on.
    pub from_interface: u64,
    /// Whether the requesting interface is a local client.
    pub is_from_local_client: bool,
    /// Current time as f64 seconds.
    pub now: f64,
    /// Current time as u64 seconds (used for path table queries).
    #[allow(dead_code)]
    pub now_secs: u64,
    /// Whether the next hop for the target is on a local client interface.
    pub next_hop_is_local_client: bool,
    /// Interface mode of the receiving interface.
    pub interface_mode: InterfaceMode,
}

/// Info about a known path for decision making.
pub struct KnownPathInfo {
    #[allow(dead_code)]
    pub packet_hash: PacketHash,
    pub cached_raw: Vec<u8>,
    pub hops: u8,
    pub next_hop: TruncatedHash,
}

/// Compute the retransmit delay for a path response.
///
/// - From local client → immediate (0)
/// - Next hop is local client → immediate (0)
/// - Normal interface → PATH_REQUEST_GRACE (0.4s)
/// - Roaming interface → GRACE + RG (1.9s)
#[must_use]
pub fn compute_retransmit_delay(
    is_from_local_client: bool,
    next_hop_is_local_client: bool,
    mode: InterfaceMode,
) -> f64 {
    if is_from_local_client || next_hop_is_local_client {
        return 0.0;
    }

    let mut delay = PATH_REQUEST_GRACE;
    if mode == InterfaceMode::Roaming {
        delay += PATH_REQUEST_RG;
    }
    delay
}

/// Make the path request decision.
///
/// This is the core pure function: given a parsed request and path table state,
/// decides what action to take.
pub fn decide_path_request(
    ctx: &PathRequestContext<'_>,
    tag_table: &mut DiscoveryTagTable,
    known_path: Option<KnownPathInfo>,
) -> PathRequestDecision {
    // Parse the request data
    let parsed = match parse_path_request_data(ctx.data) {
        ParseResult::Processed(p) => p,
        ParseResult::TooShort => return PathRequestDecision::TooShort,
        ParseResult::Tagless => return PathRequestDecision::Tagless,
    };

    // Dedup check
    if !tag_table.check_and_insert(&parsed.unique_tag) {
        return PathRequestDecision::DuplicateTag;
    }

    // Do we have a path?
    match known_path {
        Some(path_info) => {
            // Loop detection: if the requestor's transport_id matches our next_hop,
            // they already know the path — skip.
            if let Some(ref requesting_tid) = parsed.requesting_transport_id
                && requesting_tid.as_ref() == path_info.next_hop.as_ref()
            {
                return PathRequestDecision::SkipLoop;
            }

            let delay = compute_retransmit_delay(
                ctx.is_from_local_client,
                ctx.next_hop_is_local_client,
                ctx.interface_mode,
            );
            let retransmit_timeout = ctx.now + delay;

            PathRequestDecision::AnswerWithCachedAnnounce {
                destination: parsed.destination_hash,
                cached_raw: path_info.cached_raw,
                hops: path_info.hops,
                retransmit_timeout,
                from_interface: ctx.from_interface,
                block_rebroadcasts: true,
            }
        }
        None => {
            // Forward the request to other interfaces
            PathRequestDecision::ForwardPathRequest {
                raw_packet: ctx.raw_packet.to_vec(),
                exclude_interface: ctx.from_interface,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // === Duplicate detection tests (against test vectors) ===

    #[test]
    fn duplicate_detection_vectors() {
        let vectors = reticulum_test_vectors::path_requests::load();
        let mut tag_table = DiscoveryTagTable::new();

        for tv in &vectors.duplicate_detection_vectors {
            let unique_tag = hex::decode(&tv.unique_tag).unwrap();
            assert_eq!(unique_tag.len() as u64, tv.unique_tag_length);

            let is_new = tag_table.check_and_insert(&unique_tag);

            match tv.expected_result.as_str() {
                "processed" => {
                    assert!(
                        is_new,
                        "expected new tag for: {}",
                        tv.description
                    );
                }
                "duplicate" => {
                    assert!(
                        !is_new,
                        "expected duplicate for: {}",
                        tv.description
                    );
                }
                other => panic!("unknown expected_result: {other}"),
            }

            // Verify tag count matches expected state_after
            assert_eq!(
                tag_table.len(),
                tv.tags_state_after.len(),
                "tag count mismatch for: {}",
                tv.description
            );
        }
    }

    // === Grace period tests (against test vectors) ===

    #[test]
    fn grace_period_vectors() {
        let vectors = reticulum_test_vectors::path_requests::load();

        for tv in &vectors.grace_period_vectors {
            let mode = match tv.interface_mode.as_deref() {
                Some("MODE_ROAMING") => InterfaceMode::Roaming,
                Some("MODE_ACCESS_POINT") => InterfaceMode::AccessPoint,
                _ => InterfaceMode::Full,
            };

            let delay = compute_retransmit_delay(
                tv.is_from_local_client,
                tv.next_hop_is_local_client.unwrap_or(false),
                mode,
            );

            assert!(
                (delay - tv.retransmit_delay_seconds).abs() < 0.001,
                "delay mismatch for '{}': got {delay}, expected {}",
                tv.description,
                tv.retransmit_delay_seconds,
            );

            let retransmit_timeout = tv.base_timestamp + delay;
            assert!(
                (retransmit_timeout - tv.retransmit_timeout).abs() < 0.001,
                "timeout mismatch for '{}': got {retransmit_timeout}, expected {}",
                tv.description,
                tv.retransmit_timeout,
            );
        }
    }

    // === Tag table unit tests ===

    #[test]
    fn tag_table_eviction_at_max() {
        let mut table = DiscoveryTagTable::new();

        // Insert MAX_PR_TAGS entries
        for i in 0..MAX_PR_TAGS {
            let tag = format!("tag_{i}").into_bytes();
            assert!(table.check_and_insert(&tag));
        }
        assert_eq!(table.len(), MAX_PR_TAGS);

        // Next insert should evict the oldest
        let new_tag = b"new_tag";
        assert!(table.check_and_insert(new_tag));
        assert_eq!(table.len(), MAX_PR_TAGS);

        // The oldest should be evicted
        let oldest = b"tag_0".to_vec();
        assert!(table.check_and_insert(&oldest)); // should be new again
    }

    // === Decision tree unit tests ===

    #[test]
    fn decide_too_short() {
        let mut tags = DiscoveryTagTable::new();
        let data = &[0u8; 10]; // too short
        let ctx = PathRequestContext {
            data,
            raw_packet: &[],
            from_interface: 1,
            is_from_local_client: false,
            now: 1000.0,
            now_secs: 1000,
            next_hop_is_local_client: false,
            interface_mode: InterfaceMode::Full,
        };

        match decide_path_request(&ctx, &mut tags, None) {
            PathRequestDecision::TooShort => {}
            other => panic!("expected TooShort, got: {other:?}"),
        }
    }

    #[test]
    fn decide_forward_when_no_path() {
        let mut tags = DiscoveryTagTable::new();
        let mut data = vec![0u8; 32]; // dest(16) + tag(16)
        data[..16].copy_from_slice(&[0x01; 16]);
        data[16..32].copy_from_slice(&[0xAA; 16]);

        let ctx = PathRequestContext {
            data: &data,
            raw_packet: &[0xFF; 51],
            from_interface: 1,
            is_from_local_client: false,
            now: 1000.0,
            now_secs: 1000,
            next_hop_is_local_client: false,
            interface_mode: InterfaceMode::Full,
        };

        match decide_path_request(&ctx, &mut tags, None) {
            PathRequestDecision::ForwardPathRequest { exclude_interface, .. } => {
                assert_eq!(exclude_interface, 1);
            }
            other => panic!("expected ForwardPathRequest, got: {other:?}"),
        }
    }

    #[test]
    fn decide_answer_with_cached() {
        let mut tags = DiscoveryTagTable::new();
        let mut data = vec![0u8; 32];
        data[..16].copy_from_slice(&[0x01; 16]);
        data[16..32].copy_from_slice(&[0xBB; 16]);

        let ctx = PathRequestContext {
            data: &data,
            raw_packet: &[],
            from_interface: 1,
            is_from_local_client: false,
            now: 1000.0,
            now_secs: 1000,
            next_hop_is_local_client: false,
            interface_mode: InterfaceMode::Full,
        };

        let path_info = KnownPathInfo {
            packet_hash: PacketHash::new([0xCC; 32]),
            cached_raw: vec![0x51, 0x00],
            hops: 2,
            next_hop: TruncatedHash::new([0xDD; 16]),
        };

        match decide_path_request(&ctx, &mut tags, Some(path_info)) {
            PathRequestDecision::AnswerWithCachedAnnounce {
                retransmit_timeout,
                block_rebroadcasts,
                hops,
                ..
            } => {
                assert!((retransmit_timeout - 1000.4).abs() < 0.001);
                assert!(block_rebroadcasts);
                assert_eq!(hops, 2);
            }
            other => panic!("expected AnswerWithCachedAnnounce, got: {other:?}"),
        }
    }

    #[test]
    fn decide_loop_detection() {
        let mut tags = DiscoveryTagTable::new();
        let next_hop = TruncatedHash::new([0xEE; 16]);

        // Build transport-enabled request where transport_id == next_hop
        let mut data = vec![0u8; 48]; // dest(16) + transport_id(16) + tag(16)
        data[..16].copy_from_slice(&[0x01; 16]); // dest
        data[16..32].copy_from_slice(next_hop.as_ref()); // transport_id = next_hop
        data[32..48].copy_from_slice(&[0xCC; 16]); // tag

        let ctx = PathRequestContext {
            data: &data,
            raw_packet: &[],
            from_interface: 1,
            is_from_local_client: false,
            now: 1000.0,
            now_secs: 1000,
            next_hop_is_local_client: false,
            interface_mode: InterfaceMode::Full,
        };

        let path_info = KnownPathInfo {
            packet_hash: PacketHash::new([0xDD; 32]),
            cached_raw: vec![],
            hops: 1,
            next_hop,
        };

        match decide_path_request(&ctx, &mut tags, Some(path_info)) {
            PathRequestDecision::SkipLoop => {}
            other => panic!("expected SkipLoop, got: {other:?}"),
        }
    }

    #[test]
    fn decide_duplicate_tag() {
        let mut tags = DiscoveryTagTable::new();
        let mut data = vec![0u8; 32];
        data[..16].copy_from_slice(&[0x01; 16]);
        data[16..32].copy_from_slice(&[0xAA; 16]);

        let ctx = PathRequestContext {
            data: &data,
            raw_packet: &[],
            from_interface: 1,
            is_from_local_client: false,
            now: 1000.0,
            now_secs: 1000,
            next_hop_is_local_client: false,
            interface_mode: InterfaceMode::Full,
        };

        // First request should succeed
        match decide_path_request(&ctx, &mut tags, None) {
            PathRequestDecision::ForwardPathRequest { .. } => {}
            other => panic!("expected ForwardPathRequest, got: {other:?}"),
        }

        // Second request with same tag should be duplicate
        match decide_path_request(&ctx, &mut tags, None) {
            PathRequestDecision::DuplicateTag => {}
            other => panic!("expected DuplicateTag, got: {other:?}"),
        }
    }
}
