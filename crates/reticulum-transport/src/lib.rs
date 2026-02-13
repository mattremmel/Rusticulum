//! Routing and transport layer for the Reticulum network stack.
//!
//! This crate handles packet routing, announce propagation, path table management,
//! deduplication, and interface access code (IFAC) processing.

pub mod announce;
pub mod dedup;
pub mod error;
pub mod ifac;
pub mod path;
pub mod router;
