//! Network interfaces for the Reticulum network stack.
//!
//! This crate provides async I/O implementations for TCP, UDP, serial, and local
//! interfaces with HDLC and KISS framing support.

pub mod error;
pub mod traits;

pub use error::InterfaceError;
pub use traits::{Interface, InterfaceEvent};

// Re-export transport types used in the public trait API.
pub use reticulum_transport::path::{InterfaceId, InterfaceMode};
