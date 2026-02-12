//! Core types, constants, and wire formats for the Reticulum network stack.
//!
//! This crate defines the protocol types, newtype wrappers, packet wire formats,
//! identity and addressing, and interface framing used by the Reticulum protocol.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod announce;
pub mod constants;
pub mod destination;
pub mod error;
pub mod framing;
pub mod identity;
pub mod packet;
pub mod types;
