//! Protocol state machines for the Reticulum network stack.
//!
//! This crate implements the stateful protocol logic including link handshakes,
//! resource transfers, channel management, buffer streams, and request/response.

pub mod buffer;
pub mod channel;
pub mod error;
pub mod link;
pub mod request;
pub mod resource;

pub use channel::envelope::Envelope;
pub use channel::state::ChannelState;
pub use error::{BufferError, ChannelError, LinkError, RequestError, ResourceError};
pub use link::state::{LinkActive, LinkClosed, LinkHandshake, LinkPending, LinkState};
pub use link::types::{DerivedKey, LinkMode, LinkRole, ResourceStrategy, TeardownReason};
pub use resource::advertisement::ResourceAdvertisement;
pub use resource::transfer::{AssembledResource, PreparedResource};
