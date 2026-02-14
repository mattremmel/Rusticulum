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
pub use state::{
    build_proof_data, build_signed_data, is_establishment_timed_out_at, parse_proof_data,
    parse_request_data, should_go_stale_at, should_send_keepalive_at, should_teardown_at,
    LinkActive, LinkClosed, LinkHandshake, LinkPending, LinkState, ParsedProofData,
    ParsedRequestData,
};
pub use types::{
    DerivedKey, LinkMode, LinkRole, LinkStats, PhyStats, ResourceStrategy, TeardownReason,
};
