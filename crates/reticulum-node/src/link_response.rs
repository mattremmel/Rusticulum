//! Pure link handshake outcome decisions.
//!
//! Extracted from [`crate::node::Node::handle_link_packet`] so that the
//! three link-establishment arms (LinkRequest, LinkProof, LinkRtt) can be
//! tested without a running Node or async I/O.

use reticulum_core::packet::wire::RawPacket;
use reticulum_core::types::LinkId;

use crate::packet_helpers::extract_link_id;

/// Outcome of processing an incoming link proof (LRPROOF).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkProofOutcome {
    /// Proof accepted — we have an RTT packet to broadcast and a link_id to
    /// initiate auto-data on.
    Accepted { rtt_raw: Vec<u8>, link_id: LinkId },
    /// Proof accepted but RTT packet could not be parsed for link_id extraction.
    AcceptedNoLinkId { rtt_raw: Vec<u8> },
    /// No proof was generated (link_manager returned None).
    NotHandled,
}

/// Decide the outcome of a link proof response.
///
/// `rtt_raw` is the optional RTT packet bytes returned by
/// `link_manager.handle_lrproof()`.
pub fn plan_link_proof_response(rtt_raw: Option<Vec<u8>>) -> LinkProofOutcome {
    match rtt_raw {
        Some(rtt_raw) => match RawPacket::parse(&rtt_raw) {
            Ok(rtt_pkt) => {
                let link_id = extract_link_id(&rtt_pkt);
                LinkProofOutcome::Accepted { rtt_raw, link_id }
            }
            Err(_) => LinkProofOutcome::AcceptedNoLinkId { rtt_raw },
        },
        None => LinkProofOutcome::NotHandled,
    }
}

/// Outcome of processing an incoming link RTT (LRRTT).
#[derive(Debug, Clone, PartialEq)]
pub enum LinkRttOutcome {
    /// Link fully established with a known RTT.
    Established { link_id: LinkId, rtt: f64 },
    /// The LRRTT was not handled (link_manager returned None).
    NotHandled,
}

/// Decide the outcome of a link RTT response.
///
/// `link_id` is the optional LinkId returned by `link_manager.handle_lrrtt()`.
/// `rtt` is the optional RTT value from `link_manager.get_rtt()`.
pub fn plan_link_rtt_response(link_id: Option<LinkId>, rtt: Option<f64>) -> LinkRttOutcome {
    match link_id {
        Some(link_id) => {
            let rtt = rtt.unwrap_or(0.05);
            LinkRttOutcome::Established { link_id, rtt }
        }
        None => LinkRttOutcome::NotHandled,
    }
}

/// Outcome of processing an incoming link request (LINKREQUEST).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkRequestOutcome {
    /// Request accepted — we have a proof packet to broadcast.
    Accepted { proof_raw: Vec<u8> },
    /// Request was not handled (no identity or link_manager returned None).
    NotHandled,
}

/// Decide the outcome of a link request response.
///
/// `has_identity` indicates whether the node has a transport identity.
/// `proof_raw` is the optional proof packet bytes returned by
/// `link_manager.handle_link_request()`.
pub fn plan_link_request_response(
    has_identity: bool,
    proof_raw: Option<Vec<u8>>,
) -> LinkRequestOutcome {
    if !has_identity {
        return LinkRequestOutcome::NotHandled;
    }
    match proof_raw {
        Some(proof_raw) => LinkRequestOutcome::Accepted { proof_raw },
        None => LinkRequestOutcome::NotHandled,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reticulum_core::constants::{DestinationType, HeaderType, PacketType, TransportType};
    use reticulum_core::packet::context::ContextType;
    use reticulum_core::packet::flags::PacketFlags;
    use reticulum_core::types::DestinationHash;

    fn make_valid_packet(dest: [u8; 16]) -> Vec<u8> {
        let packet = RawPacket {
            flags: PacketFlags {
                header_type: HeaderType::Header1,
                context_flag: false,
                transport_type: TransportType::Broadcast,
                destination_type: DestinationType::Link,
                packet_type: PacketType::Data,
            },
            hops: 0,
            transport_id: None,
            destination: DestinationHash::new(dest),
            context: ContextType::None,
            data: b"test".to_vec(),
        };
        packet.serialize()
    }

    // --- plan_link_proof_response ---

    #[test]
    fn proof_response_none_returns_not_handled() {
        assert_eq!(plan_link_proof_response(None), LinkProofOutcome::NotHandled);
    }

    #[test]
    fn proof_response_valid_rtt_extracts_link_id() {
        let rtt_raw = make_valid_packet([0xAB; 16]);
        let outcome = plan_link_proof_response(Some(rtt_raw.clone()));
        match outcome {
            LinkProofOutcome::Accepted {
                rtt_raw: r,
                link_id,
            } => {
                assert_eq!(r, rtt_raw);
                assert_eq!(link_id.as_ref(), &[0xAB; 16]);
            }
            other => panic!("expected Accepted, got {other:?}"),
        }
    }

    #[test]
    fn proof_response_invalid_rtt_returns_no_link_id() {
        let garbage = vec![0x01, 0x02, 0x03];
        let outcome = plan_link_proof_response(Some(garbage.clone()));
        match outcome {
            LinkProofOutcome::AcceptedNoLinkId { rtt_raw } => {
                assert_eq!(rtt_raw, garbage);
            }
            other => panic!("expected AcceptedNoLinkId, got {other:?}"),
        }
    }

    #[test]
    fn proof_response_empty_rtt_returns_no_link_id() {
        let outcome = plan_link_proof_response(Some(vec![]));
        assert!(matches!(outcome, LinkProofOutcome::AcceptedNoLinkId { .. }));
    }

    #[test]
    fn proof_response_preserves_rtt_bytes() {
        let rtt_raw = make_valid_packet([0xCD; 16]);
        let expected = rtt_raw.clone();
        let outcome = plan_link_proof_response(Some(rtt_raw));
        match outcome {
            LinkProofOutcome::Accepted { rtt_raw, .. } => {
                assert_eq!(rtt_raw, expected);
            }
            other => panic!("expected Accepted, got {other:?}"),
        }
    }

    // --- plan_link_rtt_response ---

    #[test]
    fn rtt_response_none_returns_not_handled() {
        assert_eq!(
            plan_link_rtt_response(None, None),
            LinkRttOutcome::NotHandled
        );
    }

    #[test]
    fn rtt_response_with_link_id_and_rtt() {
        let link_id = LinkId::new([0x11; 16]);
        let outcome = plan_link_rtt_response(Some(link_id), Some(0.123));
        match outcome {
            LinkRttOutcome::Established { link_id: lid, rtt } => {
                assert_eq!(lid.as_ref(), &[0x11; 16]);
                assert!((rtt - 0.123).abs() < f64::EPSILON);
            }
            other => panic!("expected Established, got {other:?}"),
        }
    }

    #[test]
    fn rtt_response_defaults_rtt_to_005() {
        let link_id = LinkId::new([0x22; 16]);
        let outcome = plan_link_rtt_response(Some(link_id), None);
        match outcome {
            LinkRttOutcome::Established { rtt, .. } => {
                assert!((rtt - 0.05).abs() < f64::EPSILON);
            }
            other => panic!("expected Established, got {other:?}"),
        }
    }

    #[test]
    fn rtt_response_zero_rtt() {
        let link_id = LinkId::new([0x33; 16]);
        let outcome = plan_link_rtt_response(Some(link_id), Some(0.0));
        match outcome {
            LinkRttOutcome::Established { rtt, .. } => {
                assert!((rtt - 0.0).abs() < f64::EPSILON);
            }
            other => panic!("expected Established, got {other:?}"),
        }
    }

    #[test]
    fn rtt_response_ignores_rtt_when_no_link_id() {
        let outcome = plan_link_rtt_response(None, Some(0.5));
        assert_eq!(outcome, LinkRttOutcome::NotHandled);
    }

    // --- plan_link_request_response ---

    #[test]
    fn request_response_no_identity() {
        assert_eq!(
            plan_link_request_response(false, Some(vec![1, 2, 3])),
            LinkRequestOutcome::NotHandled
        );
    }

    #[test]
    fn request_response_identity_no_proof() {
        assert_eq!(
            plan_link_request_response(true, None),
            LinkRequestOutcome::NotHandled
        );
    }

    #[test]
    fn request_response_accepted() {
        let proof = vec![0xAA, 0xBB, 0xCC];
        let outcome = plan_link_request_response(true, Some(proof.clone()));
        match outcome {
            LinkRequestOutcome::Accepted { proof_raw } => {
                assert_eq!(proof_raw, proof);
            }
            other => panic!("expected Accepted, got {other:?}"),
        }
    }

    #[test]
    fn request_response_no_identity_no_proof() {
        assert_eq!(
            plan_link_request_response(false, None),
            LinkRequestOutcome::NotHandled
        );
    }
}
