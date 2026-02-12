//! Resource transfer protocol: window adaptation and transfer state machines.
//!
//! The resource layer manages reliable transfer of arbitrarily large data
//! over an encrypted link, using rate-based window adaptation.

pub mod advertisement;
pub mod constants;
pub mod window;

pub use advertisement::{ResourceAdvertisement, ResourceFlags};
pub use constants::*;
pub use window::WindowState;
