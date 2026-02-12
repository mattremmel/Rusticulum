//! Cryptographic primitives for the Reticulum network stack.
//!
//! This crate provides the foundational cryptographic operations used throughout
//! the Reticulum protocol, including hashing, key derivation, symmetric encryption,
//! and asymmetric key operations.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;
