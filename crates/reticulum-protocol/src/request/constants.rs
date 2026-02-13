//! Request/response protocol constants.

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

impl AccessPolicy {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::AllowNone),
            1 => Some(Self::AllowAll),
            2 => Some(Self::AllowList),
            _ => None,
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

impl ReceiptStatus {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Failed),
            1 => Some(Self::Sent),
            2 => Some(Self::Delivered),
            3 => Some(Self::Receiving),
            4 => Some(Self::Ready),
            _ => None,
        }
    }
}
