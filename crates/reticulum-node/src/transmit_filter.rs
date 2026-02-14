//! Pure interface transmission filtering decisions.
//!
//! Extracted from [`crate::node::Node::broadcast_to_interfaces`] and
//! [`crate::node::Node::transmit_to_interface`] so that the skip/transmit
//! decision can be tested without async I/O or real interfaces.

use reticulum_interfaces::InterfaceId;

/// Decision for whether to transmit on a given interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransmitDecision {
    /// The interface should be skipped.
    Skip { reason: SkipReason },
    /// The interface is eligible for transmission.
    Transmit,
}

/// Reason an interface was skipped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    /// The interface was explicitly excluded (e.g. the source interface).
    Excluded,
    /// The interface cannot transmit (e.g. receive-only).
    CannotTransmit,
    /// The interface is not currently connected.
    NotConnected,
    /// The interface was not found.
    NotFound,
}

/// Decide whether to transmit on a specific interface during broadcast.
///
/// `exclude` is the optional interface to skip (typically the source).
/// `can_transmit` and `is_connected` come from the interface's runtime state.
pub fn should_transmit_broadcast(
    iface_id: InterfaceId,
    exclude: Option<InterfaceId>,
    can_transmit: bool,
    is_connected: bool,
) -> TransmitDecision {
    if Some(iface_id) == exclude {
        return TransmitDecision::Skip {
            reason: SkipReason::Excluded,
        };
    }
    if !can_transmit {
        return TransmitDecision::Skip {
            reason: SkipReason::CannotTransmit,
        };
    }
    if !is_connected {
        return TransmitDecision::Skip {
            reason: SkipReason::NotConnected,
        };
    }
    TransmitDecision::Transmit
}

/// Decide whether to transmit on a targeted interface.
///
/// `found` indicates whether the interface exists in the interface map.
/// `can_transmit` and `is_connected` come from the interface's runtime state
/// (only meaningful when `found` is true).
pub fn should_transmit_targeted(
    found: bool,
    can_transmit: bool,
    is_connected: bool,
) -> TransmitDecision {
    if !found {
        return TransmitDecision::Skip {
            reason: SkipReason::NotFound,
        };
    }
    if !can_transmit {
        return TransmitDecision::Skip {
            reason: SkipReason::CannotTransmit,
        };
    }
    if !is_connected {
        return TransmitDecision::Skip {
            reason: SkipReason::NotConnected,
        };
    }
    TransmitDecision::Transmit
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u64) -> InterfaceId {
        InterfaceId(n)
    }

    // --- should_transmit_broadcast ---

    #[test]
    fn broadcast_all_clear() {
        assert_eq!(
            should_transmit_broadcast(id(1), None, true, true),
            TransmitDecision::Transmit,
        );
    }

    #[test]
    fn broadcast_excluded() {
        assert_eq!(
            should_transmit_broadcast(id(1), Some(id(1)), true, true),
            TransmitDecision::Skip {
                reason: SkipReason::Excluded
            },
        );
    }

    #[test]
    fn broadcast_different_exclude() {
        assert_eq!(
            should_transmit_broadcast(id(1), Some(id(2)), true, true),
            TransmitDecision::Transmit,
        );
    }

    #[test]
    fn broadcast_cannot_transmit() {
        assert_eq!(
            should_transmit_broadcast(id(1), None, false, true),
            TransmitDecision::Skip {
                reason: SkipReason::CannotTransmit
            },
        );
    }

    #[test]
    fn broadcast_not_connected() {
        assert_eq!(
            should_transmit_broadcast(id(1), None, true, false),
            TransmitDecision::Skip {
                reason: SkipReason::NotConnected
            },
        );
    }

    #[test]
    fn broadcast_excluded_takes_precedence_over_cannot_transmit() {
        assert_eq!(
            should_transmit_broadcast(id(1), Some(id(1)), false, true),
            TransmitDecision::Skip {
                reason: SkipReason::Excluded
            },
        );
    }

    #[test]
    fn broadcast_excluded_takes_precedence_over_not_connected() {
        assert_eq!(
            should_transmit_broadcast(id(1), Some(id(1)), true, false),
            TransmitDecision::Skip {
                reason: SkipReason::Excluded
            },
        );
    }

    #[test]
    fn broadcast_cannot_transmit_takes_precedence_over_not_connected() {
        assert_eq!(
            should_transmit_broadcast(id(1), None, false, false),
            TransmitDecision::Skip {
                reason: SkipReason::CannotTransmit
            },
        );
    }

    #[test]
    fn broadcast_all_bad() {
        // excluded + can't transmit + not connected → excluded wins
        assert_eq!(
            should_transmit_broadcast(id(5), Some(id(5)), false, false),
            TransmitDecision::Skip {
                reason: SkipReason::Excluded
            },
        );
    }

    // --- should_transmit_targeted ---

    #[test]
    fn targeted_all_clear() {
        assert_eq!(
            should_transmit_targeted(true, true, true),
            TransmitDecision::Transmit,
        );
    }

    #[test]
    fn targeted_not_found() {
        assert_eq!(
            should_transmit_targeted(false, true, true),
            TransmitDecision::Skip {
                reason: SkipReason::NotFound
            },
        );
    }

    #[test]
    fn targeted_cannot_transmit() {
        assert_eq!(
            should_transmit_targeted(true, false, true),
            TransmitDecision::Skip {
                reason: SkipReason::CannotTransmit
            },
        );
    }

    #[test]
    fn targeted_not_connected() {
        assert_eq!(
            should_transmit_targeted(true, true, false),
            TransmitDecision::Skip {
                reason: SkipReason::NotConnected
            },
        );
    }

    #[test]
    fn targeted_not_found_takes_precedence_over_cannot_transmit() {
        assert_eq!(
            should_transmit_targeted(false, false, true),
            TransmitDecision::Skip {
                reason: SkipReason::NotFound
            },
        );
    }

    #[test]
    fn targeted_not_found_takes_precedence_over_not_connected() {
        assert_eq!(
            should_transmit_targeted(false, true, false),
            TransmitDecision::Skip {
                reason: SkipReason::NotFound
            },
        );
    }
}
