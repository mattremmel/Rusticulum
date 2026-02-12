//! Protocol state machines for the Reticulum network stack.
//!
//! This crate implements the stateful protocol logic including link handshakes,
//! resource transfers, channel management, buffer streams, and request/response.

pub mod channel;
pub mod error;
pub mod link;
