//! Pure packet outcome decisions for link-encrypted context packets.
//!
//! Extracted from [`crate::node::Node`] methods: `handle_channel_packet`,
//! `handle_request_packet`, `handle_response_packet`, `handle_resource_proof`,
//! `handle_resource_adv`, and `handle_resource_req`. All follow the same
//! pattern: check link → decrypt → dispatch. This module captures the
//! dispatch decision so it can be tested without async I/O.

use reticulum_core::types::LinkId;

/// Result type for resource advertisement acceptance.
pub type AdvAcceptResult = Result<([u8; 32], Vec<u8>), String>;

/// Result type for resource part request handling.
pub type PartRequestResult = Result<(LinkId, Vec<Vec<u8>>), String>;

// ---------------------------------------------------------------------------
// Resource advertisement outcome
// ---------------------------------------------------------------------------

/// Outcome of processing a resource advertisement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceAdvOutcome {
    /// The link was not found (packet not for us).
    NotForUs,
    /// Link-layer decryption failed.
    DecryptFailed,
    /// Advertisement accepted — send back a part request.
    Accepted {
        resource_hash: [u8; 32],
        request_bytes: Vec<u8>,
    },
    /// Advertisement rejected (e.g. bad format).
    Rejected { error: String },
}

/// Plan the outcome of a resource advertisement.
///
/// * `has_link` — whether the destination matches a known link.
/// * `plaintext` — result of link-layer decrypt (`None` = decrypt failed).
/// * `accept_result` — result of `resource_manager.accept_advertisement()`,
///   only present when decrypt succeeded.
pub fn plan_resource_adv(
    has_link: bool,
    plaintext: Option<&[u8]>,
    accept_result: Option<AdvAcceptResult>,
) -> ResourceAdvOutcome {
    if !has_link {
        return ResourceAdvOutcome::NotForUs;
    }
    if plaintext.is_none() {
        return ResourceAdvOutcome::DecryptFailed;
    }
    match accept_result {
        Some(Ok((resource_hash, request_bytes))) => ResourceAdvOutcome::Accepted {
            resource_hash,
            request_bytes,
        },
        Some(Err(e)) => ResourceAdvOutcome::Rejected { error: e },
        None => ResourceAdvOutcome::Rejected {
            error: "accept not attempted".to_string(),
        },
    }
}

// ---------------------------------------------------------------------------
// Resource request outcome
// ---------------------------------------------------------------------------

/// Outcome of processing a resource part request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceReqOutcome {
    /// The link was not found.
    NotForUs,
    /// Link-layer decryption failed.
    DecryptFailed,
    /// Parts should be sent back.
    SendParts {
        link_id: LinkId,
        parts: Vec<Vec<u8>>,
    },
    /// Part request handling failed.
    Error { error: String },
}

/// Plan the outcome of a resource part request.
///
/// * `has_link` — whether the destination matches a known link.
/// * `plaintext` — result of link-layer decrypt (`None` = decrypt failed).
/// * `part_result` — result of `resource_manager.handle_part_request()`,
///   only present when decrypt succeeded.
pub fn plan_resource_req(
    has_link: bool,
    plaintext: Option<&[u8]>,
    part_result: Option<PartRequestResult>,
) -> ResourceReqOutcome {
    if !has_link {
        return ResourceReqOutcome::NotForUs;
    }
    if plaintext.is_none() {
        return ResourceReqOutcome::DecryptFailed;
    }
    match part_result {
        Some(Ok((link_id, parts))) => ResourceReqOutcome::SendParts { link_id, parts },
        Some(Err(e)) => ResourceReqOutcome::Error { error: e },
        None => ResourceReqOutcome::Error {
            error: "part request not attempted".to_string(),
        },
    }
}

// ---------------------------------------------------------------------------
// Resource proof outcome
// ---------------------------------------------------------------------------

/// Outcome of processing a resource proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceProofOutcome {
    /// The link was not found.
    NotForUs,
    /// Link-layer decryption failed.
    DecryptFailed,
    /// Proof verified successfully.
    Verified,
    /// Proof was invalid.
    Invalid,
    /// Proof handling encountered an error.
    Error { error: String },
}

/// Plan the outcome of a resource proof.
///
/// * `has_link` — whether the destination matches a known link.
/// * `plaintext` — result of link-layer decrypt (`None` = decrypt failed).
/// * `proof_result` — result of `resource_manager.handle_proof()`,
///   only present when decrypt succeeded.
pub fn plan_resource_proof(
    has_link: bool,
    plaintext: Option<&[u8]>,
    proof_result: Option<Result<bool, String>>,
) -> ResourceProofOutcome {
    if !has_link {
        return ResourceProofOutcome::NotForUs;
    }
    if plaintext.is_none() {
        return ResourceProofOutcome::DecryptFailed;
    }
    match proof_result {
        Some(Ok(true)) => ResourceProofOutcome::Verified,
        Some(Ok(false)) => ResourceProofOutcome::Invalid,
        Some(Err(e)) => ResourceProofOutcome::Error { error: e },
        None => ResourceProofOutcome::Error {
            error: "proof handling not attempted".to_string(),
        },
    }
}

// ---------------------------------------------------------------------------
// Channel dispatch outcome
// ---------------------------------------------------------------------------

/// Outcome of processing a channel packet (after decrypt).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelDispatchOutcome {
    /// The link was not found.
    NotForUs,
    /// Link-layer decryption failed.
    DecryptFailed,
    /// A channel message was received.
    MessageReceived {
        link_id: LinkId,
        msg_type: u16,
        payload: Vec<u8>,
    },
    /// A buffer stream completed.
    BufferComplete {
        link_id: LinkId,
        stream_id: u16,
        data: Vec<u8>,
    },
    /// A response should be sent back.
    SendResponse {
        link_id: LinkId,
        response_bytes: Vec<u8>,
    },
    /// Channel envelope was processed but no action needed (e.g. accumulating).
    NoAction { link_id: LinkId },
}

/// Map a `ChannelAction` (from `ChannelManager`) into a `ChannelDispatchOutcome`.
///
/// * `has_link` — whether the destination matches a known link.
/// * `decrypt_ok` — whether link-layer decryption succeeded.
/// * `link_id` — the link ID extracted from the packet destination.
/// * `channel_action` — the action returned by `ChannelManager::handle_channel_data()`.
pub fn plan_channel_dispatch(
    has_link: bool,
    decrypt_ok: bool,
    link_id: LinkId,
    channel_action: Option<ChannelDispatchAction>,
) -> ChannelDispatchOutcome {
    if !has_link {
        return ChannelDispatchOutcome::NotForUs;
    }
    if !decrypt_ok {
        return ChannelDispatchOutcome::DecryptFailed;
    }
    match channel_action {
        Some(ChannelDispatchAction::MessageReceived { msg_type, payload }) => {
            ChannelDispatchOutcome::MessageReceived {
                link_id,
                msg_type,
                payload,
            }
        }
        Some(ChannelDispatchAction::BufferComplete { stream_id, data }) => {
            ChannelDispatchOutcome::BufferComplete {
                link_id,
                stream_id,
                data,
            }
        }
        Some(ChannelDispatchAction::SendResponse(response_bytes)) => {
            ChannelDispatchOutcome::SendResponse {
                link_id,
                response_bytes,
            }
        }
        None => ChannelDispatchOutcome::NoAction { link_id },
    }
}

/// Simplified channel action for use in the pure function.
///
/// Mirrors `crate::channel_manager::ChannelAction` without requiring
/// the full ChannelManager dependency.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelDispatchAction {
    /// A channel message was received.
    MessageReceived { msg_type: u16, payload: Vec<u8> },
    /// A buffer stream completed.
    BufferComplete { stream_id: u16, data: Vec<u8> },
    /// A response should be sent.
    SendResponse(Vec<u8>),
}

// ---------------------------------------------------------------------------
// Request outcome
// ---------------------------------------------------------------------------

/// Outcome of processing a request packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestOutcome {
    /// The link was not found.
    NotForUs,
    /// Link-layer decryption failed.
    DecryptFailed,
    /// A response should be sent back.
    SendResponse {
        link_id: LinkId,
        response_bytes: Vec<u8>,
    },
    /// Request was received but no handler matched.
    NoHandler { link_id: LinkId },
}

/// Plan the outcome of a request packet.
///
/// * `has_link` — whether the destination matches a known link.
/// * `decrypt_ok` — whether link-layer decryption succeeded.
/// * `link_id` — the link ID extracted from the packet.
/// * `response_bytes` — result of `ChannelManager::handle_request()`.
pub fn plan_request_dispatch(
    has_link: bool,
    decrypt_ok: bool,
    link_id: LinkId,
    response_bytes: Option<Vec<u8>>,
) -> RequestOutcome {
    if !has_link {
        return RequestOutcome::NotForUs;
    }
    if !decrypt_ok {
        return RequestOutcome::DecryptFailed;
    }
    match response_bytes {
        Some(bytes) => RequestOutcome::SendResponse {
            link_id,
            response_bytes: bytes,
        },
        None => RequestOutcome::NoHandler { link_id },
    }
}

// ---------------------------------------------------------------------------
// Response outcome
// ---------------------------------------------------------------------------

/// Outcome of processing a response packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseOutcome {
    /// The link was not found.
    NotForUs,
    /// Link-layer decryption failed.
    DecryptFailed,
    /// Response was processed.
    Processed,
}

/// Plan the outcome of a response packet.
///
/// * `has_link` — whether the destination matches a known link.
/// * `decrypt_ok` — whether link-layer decryption succeeded.
pub fn plan_response_dispatch(has_link: bool, decrypt_ok: bool) -> ResponseOutcome {
    if !has_link {
        return ResponseOutcome::NotForUs;
    }
    if !decrypt_ok {
        return ResponseOutcome::DecryptFailed;
    }
    ResponseOutcome::Processed
}

#[cfg(test)]
mod tests {
    use super::*;
    use reticulum_core::types::TruncatedHash;

    fn test_link_id() -> LinkId {
        LinkId::new([0xAA; 16])
    }

    // === Resource advertisement ===

    #[test]
    fn resource_adv_not_for_us() {
        assert_eq!(
            plan_resource_adv(false, None, None),
            ResourceAdvOutcome::NotForUs
        );
    }

    #[test]
    fn resource_adv_decrypt_failed() {
        assert_eq!(
            plan_resource_adv(true, None, None),
            ResourceAdvOutcome::DecryptFailed
        );
    }

    #[test]
    fn resource_adv_accepted() {
        let hash = [0x42; 32];
        let req = vec![1, 2, 3];
        assert_eq!(
            plan_resource_adv(true, Some(&[0xFF]), Some(Ok((hash, req.clone())))),
            ResourceAdvOutcome::Accepted {
                resource_hash: hash,
                request_bytes: req,
            }
        );
    }

    #[test]
    fn resource_adv_rejected() {
        assert_eq!(
            plan_resource_adv(true, Some(&[0xFF]), Some(Err("bad format".to_string()))),
            ResourceAdvOutcome::Rejected {
                error: "bad format".to_string()
            }
        );
    }

    #[test]
    fn resource_adv_accept_not_attempted() {
        assert_eq!(
            plan_resource_adv(true, Some(&[0xFF]), None),
            ResourceAdvOutcome::Rejected {
                error: "accept not attempted".to_string()
            }
        );
    }

    // === Resource request ===

    #[test]
    fn resource_req_not_for_us() {
        assert_eq!(
            plan_resource_req(false, None, None),
            ResourceReqOutcome::NotForUs
        );
    }

    #[test]
    fn resource_req_decrypt_failed() {
        assert_eq!(
            plan_resource_req(true, None, None),
            ResourceReqOutcome::DecryptFailed
        );
    }

    #[test]
    fn resource_req_send_parts() {
        let lid = test_link_id();
        let parts = vec![vec![1, 2], vec![3, 4]];
        assert_eq!(
            plan_resource_req(true, Some(&[0xFF]), Some(Ok((lid, parts.clone())))),
            ResourceReqOutcome::SendParts {
                link_id: lid,
                parts,
            }
        );
    }

    #[test]
    fn resource_req_error() {
        assert_eq!(
            plan_resource_req(
                true,
                Some(&[0xFF]),
                Some(Err("no such resource".to_string()))
            ),
            ResourceReqOutcome::Error {
                error: "no such resource".to_string()
            }
        );
    }

    #[test]
    fn resource_req_not_attempted() {
        assert_eq!(
            plan_resource_req(true, Some(&[0xFF]), None),
            ResourceReqOutcome::Error {
                error: "part request not attempted".to_string()
            }
        );
    }

    // === Resource proof ===

    #[test]
    fn resource_proof_not_for_us() {
        assert_eq!(
            plan_resource_proof(false, None, None),
            ResourceProofOutcome::NotForUs
        );
    }

    #[test]
    fn resource_proof_decrypt_failed() {
        assert_eq!(
            plan_resource_proof(true, None, None),
            ResourceProofOutcome::DecryptFailed
        );
    }

    #[test]
    fn resource_proof_verified() {
        assert_eq!(
            plan_resource_proof(true, Some(&[0xFF]), Some(Ok(true))),
            ResourceProofOutcome::Verified
        );
    }

    #[test]
    fn resource_proof_invalid() {
        assert_eq!(
            plan_resource_proof(true, Some(&[0xFF]), Some(Ok(false))),
            ResourceProofOutcome::Invalid
        );
    }

    #[test]
    fn resource_proof_error() {
        assert_eq!(
            plan_resource_proof(true, Some(&[0xFF]), Some(Err("decode error".to_string()))),
            ResourceProofOutcome::Error {
                error: "decode error".to_string()
            }
        );
    }

    #[test]
    fn resource_proof_not_attempted() {
        assert_eq!(
            plan_resource_proof(true, Some(&[0xFF]), None),
            ResourceProofOutcome::Error {
                error: "proof handling not attempted".to_string()
            }
        );
    }

    // === Channel dispatch ===

    #[test]
    fn channel_not_for_us() {
        let lid = test_link_id();
        assert_eq!(
            plan_channel_dispatch(false, true, lid, None),
            ChannelDispatchOutcome::NotForUs
        );
    }

    #[test]
    fn channel_decrypt_failed() {
        let lid = test_link_id();
        assert_eq!(
            plan_channel_dispatch(true, false, lid, None),
            ChannelDispatchOutcome::DecryptFailed
        );
    }

    #[test]
    fn channel_message_received() {
        let lid = test_link_id();
        let payload = b"hello channel".to_vec();
        assert_eq!(
            plan_channel_dispatch(
                true,
                true,
                lid,
                Some(ChannelDispatchAction::MessageReceived {
                    msg_type: 0x0101,
                    payload: payload.clone(),
                })
            ),
            ChannelDispatchOutcome::MessageReceived {
                link_id: lid,
                msg_type: 0x0101,
                payload,
            }
        );
    }

    #[test]
    fn channel_buffer_complete() {
        let lid = test_link_id();
        let data = b"streamed data".to_vec();
        assert_eq!(
            plan_channel_dispatch(
                true,
                true,
                lid,
                Some(ChannelDispatchAction::BufferComplete {
                    stream_id: 42,
                    data: data.clone(),
                })
            ),
            ChannelDispatchOutcome::BufferComplete {
                link_id: lid,
                stream_id: 42,
                data,
            }
        );
    }

    #[test]
    fn channel_send_response() {
        let lid = test_link_id();
        let resp = vec![0xDE, 0xAD];
        assert_eq!(
            plan_channel_dispatch(
                true,
                true,
                lid,
                Some(ChannelDispatchAction::SendResponse(resp.clone()))
            ),
            ChannelDispatchOutcome::SendResponse {
                link_id: lid,
                response_bytes: resp,
            }
        );
    }

    #[test]
    fn channel_no_action() {
        let lid = test_link_id();
        assert_eq!(
            plan_channel_dispatch(true, true, lid, None),
            ChannelDispatchOutcome::NoAction { link_id: lid }
        );
    }

    #[test]
    fn channel_not_for_us_overrides_action() {
        let lid = test_link_id();
        assert_eq!(
            plan_channel_dispatch(
                false,
                true,
                lid,
                Some(ChannelDispatchAction::MessageReceived {
                    msg_type: 1,
                    payload: vec![],
                })
            ),
            ChannelDispatchOutcome::NotForUs
        );
    }

    #[test]
    fn channel_decrypt_failed_overrides_action() {
        let lid = test_link_id();
        assert_eq!(
            plan_channel_dispatch(
                true,
                false,
                lid,
                Some(ChannelDispatchAction::MessageReceived {
                    msg_type: 1,
                    payload: vec![],
                })
            ),
            ChannelDispatchOutcome::DecryptFailed
        );
    }

    // === Request dispatch ===

    #[test]
    fn request_not_for_us() {
        let lid = test_link_id();
        assert_eq!(
            plan_request_dispatch(false, true, lid, None),
            RequestOutcome::NotForUs
        );
    }

    #[test]
    fn request_decrypt_failed() {
        let lid = test_link_id();
        assert_eq!(
            plan_request_dispatch(true, false, lid, None),
            RequestOutcome::DecryptFailed
        );
    }

    #[test]
    fn request_send_response() {
        let lid = test_link_id();
        let resp = vec![1, 2, 3];
        assert_eq!(
            plan_request_dispatch(true, true, lid, Some(resp.clone())),
            RequestOutcome::SendResponse {
                link_id: lid,
                response_bytes: resp,
            }
        );
    }

    #[test]
    fn request_no_handler() {
        let lid = test_link_id();
        assert_eq!(
            plan_request_dispatch(true, true, lid, None),
            RequestOutcome::NoHandler { link_id: lid }
        );
    }

    // === Response dispatch ===

    #[test]
    fn response_not_for_us() {
        assert_eq!(
            plan_response_dispatch(false, true),
            ResponseOutcome::NotForUs
        );
    }

    #[test]
    fn response_decrypt_failed() {
        assert_eq!(
            plan_response_dispatch(true, false),
            ResponseOutcome::DecryptFailed
        );
    }

    #[test]
    fn response_processed() {
        assert_eq!(
            plan_response_dispatch(true, true),
            ResponseOutcome::Processed
        );
    }

    #[test]
    fn response_not_for_us_overrides_decrypt() {
        assert_eq!(
            plan_response_dispatch(false, false),
            ResponseOutcome::NotForUs
        );
    }

    // === Precedence tests ===

    #[test]
    fn adv_not_for_us_overrides_decrypt() {
        // has_link=false, plaintext=None → NotForUs (not DecryptFailed)
        assert_eq!(
            plan_resource_adv(false, None, None),
            ResourceAdvOutcome::NotForUs
        );
    }

    #[test]
    fn req_not_for_us_overrides_decrypt() {
        assert_eq!(
            plan_resource_req(false, None, None),
            ResourceReqOutcome::NotForUs
        );
    }

    #[test]
    fn proof_not_for_us_overrides_decrypt() {
        assert_eq!(
            plan_resource_proof(false, None, None),
            ResourceProofOutcome::NotForUs
        );
    }

    #[test]
    fn adv_decrypt_overrides_result() {
        // has_link=true, plaintext=None, accept=Ok → DecryptFailed
        let hash = [0x42; 32];
        assert_eq!(
            plan_resource_adv(true, None, Some(Ok((hash, vec![])))),
            ResourceAdvOutcome::DecryptFailed
        );
    }

    #[test]
    fn req_decrypt_overrides_result() {
        let lid = test_link_id();
        assert_eq!(
            plan_resource_req(true, None, Some(Ok((lid, vec![])))),
            ResourceReqOutcome::DecryptFailed
        );
    }

    #[test]
    fn proof_decrypt_overrides_result() {
        assert_eq!(
            plan_resource_proof(true, None, Some(Ok(true))),
            ResourceProofOutcome::DecryptFailed
        );
    }
}
