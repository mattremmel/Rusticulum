//! Test vector types for retry_timers.json
//!
//! Retry timer and timeout test vectors for links, resources, and channels.

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct LinkKeepaliveVector {
    pub rtt: f64,
    pub keepalive_interval: f64,
    pub stale_time: f64,
    pub stale_timeout: f64,
    pub total_timeout: f64,
    pub description: String,
}

#[derive(Debug, Deserialize)]
pub struct LinkKeepalive {
    pub description: String,
    pub constants: serde_json::Value,
    pub formulas: serde_json::Value,
    pub timeout_sequence: Vec<String>,
    pub vectors: Vec<LinkKeepaliveVector>,
}

#[derive(Debug, Deserialize)]
pub struct LinkEstablishmentVector {
    pub hops: u64,
    pub timeout: u64,
    pub description: String,
}

#[derive(Debug, Deserialize)]
pub struct LinkEstablishment {
    pub description: String,
    pub constants: serde_json::Value,
    pub formula: String,
    pub note: String,
    pub vectors: Vec<LinkEstablishmentVector>,
}

#[derive(Debug, Deserialize)]
pub struct ResourceRetryVector {
    pub description: String,
    pub rtt: f64,
    pub eifr_bps: f64,
    pub sdu: u64,
    pub retry_progression: Vec<serde_json::Value>,
    pub proof_timeout: serde_json::Value,
    pub sender_max_wait: serde_json::Value,
}

#[derive(Debug, Deserialize)]
pub struct ResourceRetry {
    pub description: String,
    pub constants: serde_json::Value,
    pub formulas: serde_json::Value,
    pub timeout_sequence: Vec<String>,
    pub vectors: Vec<ResourceRetryVector>,
}

#[derive(Debug, Deserialize)]
pub struct ResourceAdvertisementRetryVector {
    pub description: String,
    pub rtt: f64,
    pub timeout_per_attempt: f64,
    pub max_retries: u64,
    pub attempts: Vec<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct ResourceAdvertisementRetry {
    pub description: String,
    pub constants: serde_json::Value,
    pub formula: String,
    pub note: String,
    pub vectors: Vec<ResourceAdvertisementRetryVector>,
}

#[derive(Debug, Deserialize)]
pub struct ChannelTimeoutWorkedExample {
    pub description: String,
    pub tries: u64,
    pub rtt: f64,
    pub tx_ring_length: u64,
    pub pow_1_5_tries_minus_1: f64,
    pub max_rtt_times_2_5_or_0_025: f64,
    pub tx_ring_plus_1_5: f64,
    pub timeout: f64,
    pub formula: String,
}

#[derive(Debug, Deserialize)]
pub struct ChannelTimeoutMatrixEntry {
    pub tries: u64,
    pub rtt: f64,
    pub tx_ring_length: u64,
    pub timeout: f64,
}

#[derive(Debug, Deserialize)]
pub struct ChannelTimeout {
    pub description: String,
    pub constants: serde_json::Value,
    pub formula: String,
    pub notes: Vec<String>,
    pub worked_examples: Vec<ChannelTimeoutWorkedExample>,
    pub full_matrix: Vec<ChannelTimeoutMatrixEntry>,
}

#[derive(Debug, Deserialize)]
pub struct RetryTimersVectors {
    pub description: String,
    pub sources: Vec<String>,
    pub link_keepalive: LinkKeepalive,
    pub link_establishment: LinkEstablishment,
    pub resource_retry: ResourceRetry,
    pub resource_advertisement_retry: ResourceAdvertisementRetry,
    pub channel_timeout: ChannelTimeout,
}

pub fn load() -> RetryTimersVectors {
    let json = include_str!("../../../.test-vectors/retry_timers.json");
    serde_json::from_str(json).expect("Failed to deserialize retry_timers.json")
}
