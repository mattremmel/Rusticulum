//! Re-export of the shared HDLC frame accumulator.
//!
//! The implementation lives in [`crate::framing`] so it can be shared
//! across TCP, Local, and other stream-oriented interfaces.

pub use crate::framing::*;
