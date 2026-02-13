//! Resource transfer protocol: window adaptation and transfer state machines.
//!
//! The resource layer manages reliable transfer of arbitrarily large data
//! over an encrypted link, using rate-based window adaptation.

pub mod advertisement;
pub mod constants;
pub mod hashmap;
pub mod transfer;
pub mod window;

pub use advertisement::{ResourceAdvertisement, ResourceFlags};
pub use constants::*;
pub use hashmap::{MapHash, ResourceHashmap};
pub use transfer::{
    AssembledResource, PartRequest, PreparedResource, ResourceState, assemble_resource,
    prepare_resource,
};
pub use window::WindowState;
