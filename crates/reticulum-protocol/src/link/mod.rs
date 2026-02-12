//! Link state machine and supporting types.
//!
//! Links are encrypted point-to-point tunnels established via an ECDH handshake
//! between an initiator and a responder (destination).

pub mod constants;
pub mod mtu;
pub mod state;
pub mod types;

pub use constants::*;
pub use mtu::{decode_mode, decode_mtu, encode};
pub use state::{LinkActive, LinkClosed, LinkHandshake, LinkPending, LinkState};
pub use types::{
    DerivedKey, LinkMode, LinkRole, LinkStats, PhyStats, ResourceStrategy, TeardownReason,
};
