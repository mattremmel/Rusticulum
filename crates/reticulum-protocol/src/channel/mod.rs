//! Channel protocol: envelope format, sequencing, and windowing.
//!
//! The channel layer provides reliable, ordered delivery of typed messages
//! over an encrypted link.

pub mod constants;
pub mod envelope;
pub mod state;

pub use constants::*;
pub use envelope::Envelope;
pub use state::{ChannelState, TimeoutOutcome, MAX_TRIES};
