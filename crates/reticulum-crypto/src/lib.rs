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

pub use ed25519::{Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature};
pub use error::CryptoError;
pub use hmac::{hmac_sha256, hmac_sha256_verify};
pub use sha::{sha256, sha512, truncated_hash};
pub use token::Token;
pub use x25519::{X25519PrivateKey, X25519PublicKey};
