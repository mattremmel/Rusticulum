//! Pure decision functions for link lifecycle management.
//!
//! These functions extract the decision chains from [`LinkManager`] methods
//! into stateless classifiers. The actual state mutations remain in
//! `link_manager.rs`; these functions only decide *what* to do.

use crate::link_manager::LinkAutoActions;

/// Outcome of classifying an identity registration from an announce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityRegistrationOutcome {
    /// The announce is for our own destination — skip.
    SkipSelfAnnounce,
    /// The public key bytes couldn't be parsed into an identity.
    IdentityParseFailed,
    /// Identity stored, no auto-link needed.
    Registered,
    /// Identity stored and we should auto-link.
    RegisteredAndAutoLink { actions: LinkAutoActions },
}

/// Classify whether an announce should result in identity registration
/// and/or auto-linking.
///
/// Arguments:
/// - `is_self`: true if the announce destination is one of our local destinations
/// - `identity_parse_ok`: true if the public key bytes from the announce were valid
/// - `auto_link_decision`: result of checking link targets (None = no match)
pub fn classify_identity_registration(
    is_self: bool,
    identity_parse_ok: bool,
    auto_link_decision: Option<LinkAutoActions>,
) -> IdentityRegistrationOutcome {
    if is_self {
        return IdentityRegistrationOutcome::SkipSelfAnnounce;
    }
    if !identity_parse_ok {
        return IdentityRegistrationOutcome::IdentityParseFailed;
    }
    match auto_link_decision {
        Some(actions) => IdentityRegistrationOutcome::RegisteredAndAutoLink { actions },
        None => IdentityRegistrationOutcome::Registered,
    }
}

/// Outcome of classifying a link request acceptance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkAcceptanceOutcome {
    /// Link request accepted successfully.
    Accept,
    /// The destination is not one we manage.
    UnknownDestination,
    /// The handshake computation failed.
    HandshakeFailed,
}

/// Classify whether an incoming link request should be accepted.
pub fn classify_link_acceptance(
    is_known_destination: bool,
    handshake_ok: bool,
) -> LinkAcceptanceOutcome {
    if !is_known_destination {
        return LinkAcceptanceOutcome::UnknownDestination;
    }
    if !handshake_ok {
        return LinkAcceptanceOutcome::HandshakeFailed;
    }
    LinkAcceptanceOutcome::Accept
}

/// Outcome of classifying a proof receipt (initiator side).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofReceiptOutcome {
    /// Proof verified, link activated.
    Activated,
    /// No pending link for this link_id.
    NoPending,
    /// No known identity for the destination.
    NoIdentity,
    /// Proof verification failed.
    ProofFailed,
}

/// Classify the outcome of receiving a link proof.
pub fn classify_proof_receipt(
    has_pending: bool,
    has_identity: bool,
    proof_ok: bool,
) -> ProofReceiptOutcome {
    if !has_pending {
        return ProofReceiptOutcome::NoPending;
    }
    if !has_identity {
        return ProofReceiptOutcome::NoIdentity;
    }
    if !proof_ok {
        return ProofReceiptOutcome::ProofFailed;
    }
    ProofReceiptOutcome::Activated
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- classify_identity_registration tests ---------------------------------

    #[test]
    fn identity_registration_skip_self() {
        let result = classify_identity_registration(true, true, None);
        assert_eq!(result, IdentityRegistrationOutcome::SkipSelfAnnounce);
    }

    #[test]
    fn identity_registration_skip_self_even_with_auto_link() {
        let actions = LinkAutoActions {
            auto_data: Some("hello".to_string()),
            ..Default::default()
        };
        let result = classify_identity_registration(true, true, Some(actions));
        assert_eq!(result, IdentityRegistrationOutcome::SkipSelfAnnounce);
    }

    #[test]
    fn identity_registration_parse_failed() {
        let result = classify_identity_registration(false, false, None);
        assert_eq!(result, IdentityRegistrationOutcome::IdentityParseFailed);
    }

    #[test]
    fn identity_registration_registered_no_auto_link() {
        let result = classify_identity_registration(false, true, None);
        assert_eq!(result, IdentityRegistrationOutcome::Registered);
    }

    #[test]
    fn identity_registration_registered_with_auto_link() {
        let actions = LinkAutoActions {
            auto_data: Some("hello".to_string()),
            ..Default::default()
        };
        let result = classify_identity_registration(false, true, Some(actions.clone()));
        assert_eq!(
            result,
            IdentityRegistrationOutcome::RegisteredAndAutoLink { actions }
        );
    }

    #[test]
    fn identity_registration_parse_failed_ignores_auto_link() {
        let actions = LinkAutoActions {
            auto_data: Some("hello".to_string()),
            ..Default::default()
        };
        let result = classify_identity_registration(false, false, Some(actions));
        assert_eq!(result, IdentityRegistrationOutcome::IdentityParseFailed);
    }

    // -- classify_link_acceptance tests ----------------------------------------

    #[test]
    fn link_acceptance_unknown_destination() {
        assert_eq!(
            classify_link_acceptance(false, true),
            LinkAcceptanceOutcome::UnknownDestination,
        );
    }

    #[test]
    fn link_acceptance_handshake_failed() {
        assert_eq!(
            classify_link_acceptance(true, false),
            LinkAcceptanceOutcome::HandshakeFailed,
        );
    }

    #[test]
    fn link_acceptance_success() {
        assert_eq!(
            classify_link_acceptance(true, true),
            LinkAcceptanceOutcome::Accept,
        );
    }

    #[test]
    fn link_acceptance_unknown_dest_overrides_handshake() {
        assert_eq!(
            classify_link_acceptance(false, false),
            LinkAcceptanceOutcome::UnknownDestination,
        );
    }

    // -- classify_proof_receipt tests ------------------------------------------

    #[test]
    fn proof_receipt_no_pending() {
        assert_eq!(
            classify_proof_receipt(false, true, true),
            ProofReceiptOutcome::NoPending,
        );
    }

    #[test]
    fn proof_receipt_no_identity() {
        assert_eq!(
            classify_proof_receipt(true, false, true),
            ProofReceiptOutcome::NoIdentity,
        );
    }

    #[test]
    fn proof_receipt_proof_failed() {
        assert_eq!(
            classify_proof_receipt(true, true, false),
            ProofReceiptOutcome::ProofFailed,
        );
    }

    #[test]
    fn proof_receipt_activated() {
        assert_eq!(
            classify_proof_receipt(true, true, true),
            ProofReceiptOutcome::Activated,
        );
    }

    #[test]
    fn proof_receipt_no_pending_overrides_all() {
        assert_eq!(
            classify_proof_receipt(false, false, false),
            ProofReceiptOutcome::NoPending,
        );
    }
}
