//! Buffer stream protocol.
//!
//! Enables streaming binary data over Reticulum channels with optional
//! bz2 compression and EOF signalling.

pub mod constants;
pub mod stream_data;

pub use constants::*;
pub use stream_data::{StreamDataMessage, StreamHeader, compress_chunk, write_chunk};
