//! Cryptographic primitives for the Reticulum network stack.
//!
//! This crate provides the foundational cryptographic operations used throughout
//! the Reticulum protocol, including hashing, key derivation, symmetric encryption,
//! and asymmetric key operations.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod aes_cbc;
pub mod ed25519;
pub mod error;
pub mod hkdf;
pub mod hmac;
pub mod pkcs7;
pub mod sha;
pub mod token;
pub mod x25519;

pub use error::CryptoError;
