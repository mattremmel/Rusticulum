//! Announce propagation and rate limiting.
//!
//! Handles retransmission of announces with configurable delays,
//! bandwidth caps, and hop-count-based acceptance logic.

pub mod constants;
pub mod propagation;

pub use constants::*;
pub use propagation::{
    AnnounceAction, AnnounceTable, AnnounceTableEntry, compute_announce_wait_time,
};
