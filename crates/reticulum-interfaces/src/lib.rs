//! Network interfaces for the Reticulum network stack.
//!
//! This crate provides async I/O implementations for TCP, UDP, serial, and local
//! interfaces with HDLC and KISS framing support.

#[cfg(unix)]
pub mod auto;
pub mod error;
pub mod framing;
#[cfg(unix)]
pub mod local;
pub mod shutdown;
pub mod tcp;
pub mod traits;
pub mod testing;
pub mod udp;

pub use error::InterfaceError;
pub use traits::{Interface, InterfaceEvent};

// Re-export transport types used in the public trait API.
pub use reticulum_transport::path::{InterfaceId, InterfaceMode};
