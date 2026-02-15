//! Request/response protocol constants.

use crate::error::RequestError;

/// Multiplier applied to RTT for the traffic timeout component.
pub const TRAFFIC_TIMEOUT_FACTOR: f64 = 6.0;

/// Maximum grace time added for response processing.
pub const RESPONSE_MAX_GRACE_TIME: f64 = 10.0;

/// Multiplier applied to the grace time.
pub const GRACE_MULTIPLIER: f64 = 1.125;

/// Access control policy for request handlers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AccessPolicy {
    AllowNone = 0,
    AllowAll = 1,
    AllowList = 2,
}

impl TryFrom<u8> for AccessPolicy {
    type Error = RequestError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::AllowNone),
            1 => Ok(Self::AllowAll),
            2 => Ok(Self::AllowList),
            _ => Err(RequestError::InvalidAccessPolicy(value)),
        }
    }
}

/// Status of a request receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ReceiptStatus {
    Failed = 0,
    Sent = 1,
    Delivered = 2,
    Receiving = 3,
    Ready = 4,
}

impl TryFrom<u8> for ReceiptStatus {
    type Error = RequestError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Failed),
            1 => Ok(Self::Sent),
            2 => Ok(Self::Delivered),
            3 => Ok(Self::Receiving),
            4 => Ok(Self::Ready),
            _ => Err(RequestError::InvalidReceiptStatus(value)),
        }
    }
}
