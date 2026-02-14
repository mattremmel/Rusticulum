//! Pure functions for link initiation decisions and construction.
//!
//! These functions extract the auto-link decision logic and the two-pass
//! LINKREQUEST construction algorithm from [`LinkManager`] into stateless,
//! deterministic functions that are easy to unit-test.

use reticulum_core::constants::MTU;
use reticulum_core::destination;
use reticulum_core::packet::wire::RawPacket;
use reticulum_core::types::{DestinationHash, LinkId};

use reticulum_protocol::error::LinkError;
use reticulum_protocol::link::state::LinkPending;
use reticulum_protocol::link::types::LinkMode;

use crate::config::LinkTargetEntry;
use crate::link_manager::LinkAutoActions;
use crate::link_packets::build_linkrequest_packet;

/// Output from [`build_link_request`].
pub struct LinkRequestOutput {
    /// Serialized LINKREQUEST packet bytes, ready to broadcast.
    pub packet_bytes: Vec<u8>,
    /// Computed link ID for this request.
    pub link_id: LinkId,
    /// The pending link state (holds ephemeral keys for handshake continuation).
    pub pending: LinkPending,
}

/// Queues of auto-actions to populate after a link is established.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AutoActionQueues {
    pub auto_data: Option<String>,
    pub auto_resource: Option<String>,
    pub auto_channel: Option<String>,
    pub auto_buffer: Option<String>,
    pub auto_request: Option<(String, String)>,
}

/// Decide whether to auto-link to a destination based on its announce name_hash.
///
/// Returns `Some(LinkAutoActions)` if a matching link target is found and
/// we should initiate a link. Returns `None` if:
/// - `is_local_dest` is true (don't self-link)
/// - `has_existing_link` is true (already linked)
/// - No link target matches the announce's name_hash
pub fn should_auto_link(
    announce_name_hash: &[u8],
    link_targets: &[LinkTargetEntry],
    is_local_dest: bool,
    has_existing_link: bool,
) -> Option<LinkAutoActions> {
    if is_local_dest || has_existing_link {
        return None;
    }

    for target in link_targets {
        let aspect_refs: Vec<&str> = target.aspects.iter().map(|s| s.as_str()).collect();
        let target_nh = destination::name_hash(&target.app_name, &aspect_refs);
        if target_nh.as_ref() == announce_name_hash {
            return Some(LinkAutoActions::from_target(target));
        }
    }

    None
}

/// Construct a LINKREQUEST packet using the two-pass algorithm.
///
/// Pass 1: Build a placeholder packet to get the hashable_part layout.
/// Pass 2: Create real ephemeral keys with the correct hashable_part, then
/// rebuild the packet with real request data.
///
/// Returns a [`LinkRequestOutput`] containing the packet bytes, the computed
/// link_id, and the [`LinkPending`] state needed for handshake continuation.
pub fn build_link_request(dest_hash: DestinationHash) -> Result<LinkRequestOutput, LinkError> {
    // Pass 1: temporary packet with placeholder data to get initial hashable_part
    let (pending, request_data) = {
        let temp_raw = build_linkrequest_packet(dest_hash, vec![0u8; 67]);
        let temp_packet = RawPacket::parse(&temp_raw).expect("just built a valid packet");
        let hashable = temp_packet.hashable_part();

        LinkPending::new_initiator(
            dest_hash,
            MTU as u32,
            LinkMode::default(),
            0,
            &hashable,
            67,
        )?
    };

    // Pass 2: real packet with actual request data
    let raw = build_linkrequest_packet(dest_hash, request_data);
    let real_packet = RawPacket::parse(&raw).expect("just built a valid packet");
    let hashable = real_packet.hashable_part();
    let link_id = LinkPending::compute_link_id(&hashable, real_packet.data.len());

    // Rebuild LinkPending with the real hashable_part
    let real_pending = {
        let eph_x25519 = pending.eph_x25519_private;
        let eph_ed25519 = pending.eph_ed25519_private;
        let (p, _) = LinkPending::new_initiator_deterministic(
            dest_hash,
            MTU as u32,
            LinkMode::default(),
            0,
            eph_x25519,
            eph_ed25519,
            &hashable,
            real_packet.data.len(),
        )?;
        p
    };

    Ok(LinkRequestOutput {
        packet_bytes: raw,
        link_id,
        pending: real_pending,
    })
}

/// Map [`LinkAutoActions`] into queue-ready structures.
///
/// Converts the action configuration into the concrete queue entries to
/// insert into the link manager's auto-action queues.
pub fn queue_auto_actions(actions: &LinkAutoActions) -> AutoActionQueues {
    AutoActionQueues {
        auto_data: actions.auto_data.clone(),
        auto_resource: actions.auto_resource.clone(),
        auto_channel: actions.auto_channel.clone(),
        auto_buffer: actions.auto_buffer.clone(),
        auto_request: actions.auto_request_path.as_ref().map(|path| {
            (
                path.clone(),
                actions.auto_request_data.clone().unwrap_or_default(),
            )
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reticulum_core::constants::{DestinationType, HeaderType, PacketType, TransportType};
    use reticulum_core::destination;

    fn make_link_target(app_name: &str, aspects: &[&str]) -> LinkTargetEntry {
        LinkTargetEntry {
            app_name: app_name.to_string(),
            aspects: aspects.iter().map(|s| s.to_string()).collect(),
            auto_data: None,
            auto_resource: None,
            auto_channel: None,
            auto_buffer: None,
            auto_request_path: None,
            auto_request_data: None,
        }
    }

    fn make_link_target_with_actions(
        app_name: &str,
        aspects: &[&str],
        auto_data: Option<&str>,
        auto_resource: Option<&str>,
        auto_request_path: Option<&str>,
    ) -> LinkTargetEntry {
        LinkTargetEntry {
            app_name: app_name.to_string(),
            aspects: aspects.iter().map(|s| s.to_string()).collect(),
            auto_data: auto_data.map(|s| s.to_string()),
            auto_resource: auto_resource.map(|s| s.to_string()),
            auto_channel: None,
            auto_buffer: None,
            auto_request_path: auto_request_path.map(|s| s.to_string()),
            auto_request_data: Some("request body".to_string()),
        }
    }

    fn name_hash_for(app_name: &str, aspects: &[&str]) -> Vec<u8> {
        destination::name_hash(app_name, aspects).as_ref().to_vec()
    }

    // -- should_auto_link tests -----------------------------------------------

    #[test]
    fn should_auto_link_matches_by_name_hash() {
        let targets = vec![make_link_target("my_app", &["link", "v1"])];
        let nh = name_hash_for("my_app", &["link", "v1"]);
        let result = should_auto_link(&nh, &targets, false, false);
        assert!(result.is_some());
    }

    #[test]
    fn should_auto_link_returns_none_no_match() {
        let targets = vec![make_link_target("my_app", &["link", "v1"])];
        let nh = name_hash_for("other_app", &["link", "v1"]);
        let result = should_auto_link(&nh, &targets, false, false);
        assert!(result.is_none());
    }

    #[test]
    fn should_auto_link_returns_none_for_local_dest() {
        let targets = vec![make_link_target("my_app", &["link", "v1"])];
        let nh = name_hash_for("my_app", &["link", "v1"]);
        let result = should_auto_link(&nh, &targets, true, false);
        assert!(result.is_none());
    }

    #[test]
    fn should_auto_link_returns_none_when_already_linked() {
        let targets = vec![make_link_target("my_app", &["link", "v1"])];
        let nh = name_hash_for("my_app", &["link", "v1"]);
        let result = should_auto_link(&nh, &targets, false, true);
        assert!(result.is_none());
    }

    #[test]
    fn should_auto_link_multiple_targets_only_one_matches() {
        let targets = vec![
            make_link_target("app_a", &["link"]),
            make_link_target("app_b", &["link"]),
            make_link_target("app_c", &["link"]),
        ];
        let nh = name_hash_for("app_b", &["link"]);
        let result = should_auto_link(&nh, &targets, false, false);
        assert!(result.is_some());
    }

    #[test]
    fn should_auto_link_extracts_actions_from_target() {
        let targets = vec![make_link_target_with_actions(
            "my_app",
            &["link"],
            Some("hello"),
            Some("resource data"),
            Some("/test/echo"),
        )];
        let nh = name_hash_for("my_app", &["link"]);
        let result = should_auto_link(&nh, &targets, false, false).unwrap();
        assert_eq!(result.auto_data.as_deref(), Some("hello"));
        assert_eq!(result.auto_resource.as_deref(), Some("resource data"));
        assert_eq!(result.auto_request_path.as_deref(), Some("/test/echo"));
    }

    #[test]
    fn should_auto_link_empty_targets() {
        let nh = name_hash_for("my_app", &["link"]);
        let result = should_auto_link(&nh, &[], false, false);
        assert!(result.is_none());
    }

    // -- build_link_request tests --------------------------------------------

    #[test]
    fn build_link_request_produces_valid_packet() {
        let dest = DestinationHash::new([0xAA; 16]);
        let output = build_link_request(dest).unwrap();

        let pkt = RawPacket::parse(&output.packet_bytes).unwrap();
        assert_eq!(pkt.flags.packet_type, PacketType::LinkRequest);
        assert_eq!(pkt.flags.destination_type, DestinationType::Single);
        assert_eq!(pkt.flags.header_type, HeaderType::Header1);
        assert_eq!(pkt.flags.transport_type, TransportType::Broadcast);
    }

    #[test]
    fn build_link_request_correct_flags_byte() {
        let dest = DestinationHash::new([0xBB; 16]);
        let output = build_link_request(dest).unwrap();
        let pkt = RawPacket::parse(&output.packet_bytes).unwrap();
        // H1|BC|SINGLE|LR = 0x02
        assert_eq!(pkt.flags.to_byte(), 0x02);
    }

    #[test]
    fn build_link_request_link_id_consistent() {
        // The returned link_id should match what we compute from the packet
        let dest = DestinationHash::new([0xCC; 16]);
        let output = build_link_request(dest).unwrap();
        let pkt = RawPacket::parse(&output.packet_bytes).unwrap();
        let hashable = pkt.hashable_part();
        let computed = LinkPending::compute_link_id(&hashable, pkt.data.len());
        assert_eq!(output.link_id.as_ref(), computed.as_ref());
    }

    #[test]
    fn build_link_request_different_dests_different_link_ids() {
        let out_a = build_link_request(DestinationHash::new([0x11; 16])).unwrap();
        let out_b = build_link_request(DestinationHash::new([0x22; 16])).unwrap();
        assert_ne!(out_a.link_id.as_ref(), out_b.link_id.as_ref());
    }

    #[test]
    fn build_link_request_pending_has_correct_dest() {
        let dest = DestinationHash::new([0xDD; 16]);
        let output = build_link_request(dest).unwrap();
        assert_eq!(output.pending.destination_hash.as_ref(), dest.as_ref());
    }

    // -- queue_auto_actions tests --------------------------------------------

    #[test]
    fn queue_auto_actions_all_fields_set() {
        let actions = LinkAutoActions {
            auto_data: Some("data".to_string()),
            auto_resource: Some("resource".to_string()),
            auto_channel: Some("channel".to_string()),
            auto_buffer: Some("buffer".to_string()),
            auto_request_path: Some("/test".to_string()),
            auto_request_data: Some("body".to_string()),
        };
        let queues = queue_auto_actions(&actions);
        assert_eq!(queues.auto_data.as_deref(), Some("data"));
        assert_eq!(queues.auto_resource.as_deref(), Some("resource"));
        assert_eq!(queues.auto_channel.as_deref(), Some("channel"));
        assert_eq!(queues.auto_buffer.as_deref(), Some("buffer"));
        assert_eq!(queues.auto_request, Some(("/test".to_string(), "body".to_string())));
    }

    #[test]
    fn queue_auto_actions_no_fields_set() {
        let actions = LinkAutoActions::default();
        let queues = queue_auto_actions(&actions);
        assert_eq!(queues, AutoActionQueues::default());
    }

    #[test]
    fn queue_auto_actions_only_auto_data() {
        let actions = LinkAutoActions {
            auto_data: Some("hello".to_string()),
            ..Default::default()
        };
        let queues = queue_auto_actions(&actions);
        assert_eq!(queues.auto_data.as_deref(), Some("hello"));
        assert!(queues.auto_resource.is_none());
        assert!(queues.auto_request.is_none());
    }

    #[test]
    fn queue_auto_actions_request_path_defaults_data_to_empty() {
        let actions = LinkAutoActions {
            auto_request_path: Some("/echo".to_string()),
            auto_request_data: None,
            ..Default::default()
        };
        let queues = queue_auto_actions(&actions);
        assert_eq!(
            queues.auto_request,
            Some(("/echo".to_string(), String::new()))
        );
    }
}
