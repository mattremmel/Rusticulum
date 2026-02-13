//! Path table management for destination routing.
//!
//! Tracks known paths to destinations, their hop counts, TTLs,
//! and the interfaces through which they were learned.

pub mod constants;
pub mod table;
pub mod types;

pub use constants::*;
pub use table::PathTable;
pub use types::{InterfaceId, InterfaceMode, PathEntry};
