//! Router types.

use reticulum_core::types::{DestinationHash, TruncatedHash};

use crate::path::InterfaceId;

/// An entry in the reverse table (for proof routing).
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct ReverseEntry {
    /// Interface the original packet was received on.
    pub receiving_interface: InterfaceId,
    /// Interface the packet was forwarded to.
    pub outbound_interface: InterfaceId,
    /// Timestamp when the entry was created.
    pub timestamp: u64,
}

impl ReverseEntry {
    /// Check if this entry is expired at the given time.
    ///
    /// Uses strict `>` comparison.
    #[must_use]
    pub fn is_expired(&self, now: u64) -> bool {
        now > self.timestamp + super::constants::REVERSE_TIMEOUT
    }
}

/// An entry in the link table (for link request forwarding).
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct LinkTableEntry {
    /// Timestamp when the entry was created.
    pub timestamp: u64,
    /// Transport ID of the next hop.
    pub next_hop_transport_id: TruncatedHash,
    /// Interface for the next hop.
    pub next_hop_interface: InterfaceId,
    /// Remaining hops to destination.
    pub remaining_hops: u8,
    /// Interface the link request was received on.
    pub received_interface: InterfaceId,
    /// Hops taken so far.
    pub taken_hops: u8,
    /// Destination hash of the link target.
    pub dest_hash: DestinationHash,
    /// Whether the link has been validated.
    pub validated: bool,
    /// Proof timeout timestamp.
    pub proof_timeout: u64,
}

/// Action returned by the packet router.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouterAction {
    /// Transmit a packet on a specific interface.
    Transmit {
        interface: InterfaceId,
        raw: Vec<u8>,
    },
    /// Broadcast a packet on all interfaces except the excluded one.
    Broadcast {
        exclude: Option<InterfaceId>,
        raw: Vec<u8>,
    },
    /// Deliver a packet to the local node.
    DeliverLocal { raw: Vec<u8> },
    /// Queue an announce for retransmission.
    QueueAnnounce {
        destination: DestinationHash,
        raw: Vec<u8>,
        hops: u8,
        received_from: InterfaceId,
    },
    /// No action needed.
    None,
}
