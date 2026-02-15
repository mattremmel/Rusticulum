//! Routing and transport layer for the Reticulum network stack.
//!
//! This crate handles packet routing, announce propagation, path table management,
//! deduplication, and interface access code (IFAC) processing.

pub mod announce;
pub mod dedup;
pub mod error;
pub mod ifac;
pub mod path;
pub mod path_decision;
pub mod router;

pub use dedup::PacketHashlist;
pub use error::{IfacError, PathError, RouterError};
pub use ifac::IfacConfig;
pub use path::table::PathTable;
pub use path::types::{InterfaceId, InterfaceMode, PathEntry};
pub use router::dispatch::PacketRouter;
pub use router::types::RouterAction;
