//! Router constants.

/// Reverse table entry timeout (8 minutes).
pub const REVERSE_TIMEOUT: u64 = 8 * 60; // 480 seconds

/// Link table entry field names (matches Python reference IDX_LT_* indices).
pub mod lt_field {
    pub const TIMESTAMP: &str = "IDX_LT_TIMESTAMP";
    pub const NEXT_HOP_TRANSPORT_ID: &str = "IDX_LT_NH_TRID";
    pub const NEXT_HOP_INTERFACE: &str = "IDX_LT_NH_IF";
    pub const REMAINING_HOPS: &str = "IDX_LT_REM_HOPS";
    pub const RECEIVED_INTERFACE: &str = "IDX_LT_RCVD_IF";
    pub const TAKEN_HOPS: &str = "IDX_LT_HOPS";
    pub const DEST_HASH: &str = "IDX_LT_DSTHASH";
    pub const VALIDATED: &str = "IDX_LT_VALIDATED";
    pub const PROOF_TIMEOUT: &str = "IDX_LT_PROOF_TMO";
    pub const INTERFACES_SAME: &str = "interfaces_same";
}
