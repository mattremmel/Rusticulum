//! Packet routing, header transformation, and table management.
//!
//! The packet router is the central dispatcher that processes inbound packets,
//! manages reverse and link tables, and produces routing actions.

pub mod constants;
pub mod dispatch;
pub mod tables;
pub mod types;

pub use constants::*;
pub use dispatch::{
    PacketRouter, compute_link_id_from_raw, inject_transport_header, strip_transport_header,
};
pub use tables::{LinkTable, ReverseTable};
pub use types::{LinkTableEntry, ReverseEntry, RouterAction};
