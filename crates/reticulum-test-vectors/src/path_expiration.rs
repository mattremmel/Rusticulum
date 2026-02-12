//! Test vector types for path_expiration.json
//!
//! Path expiration, TTL enforcement, timestamp refresh, announce refresh,
//! and rediscovery trigger test vectors.

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct PathEntry {
    pub timestamp: u64,
    pub next_hop: String,
    pub hops: u64,
    pub expires: u64,
    pub random_blobs: Vec<String>,
    pub packet_hash: String,
}

#[derive(Debug, Deserialize)]
pub struct TtlEnforcementVector {
    pub description: String,
    pub interface_mode: String,
    pub interface_mode_value: Option<u64>,
    pub ttl_constant: String,
    pub ttl_seconds: u64,
    pub path_entry: PathEntry,
    pub check_time: u64,
    pub destination_expiry: u64,
    pub expected_valid: bool,
    pub comparison: String,
    pub reason: String,
}

#[derive(Debug, Deserialize)]
pub struct ExpirePathVector {
    pub description: String,
    pub destination_hash: String,
    pub path_exists: bool,
    pub expected_return: bool,
    #[serde(default)]
    pub interface_mode: Option<String>,
    #[serde(default)]
    pub interface_mode_value: Option<u64>,
    #[serde(default)]
    pub before: Option<serde_json::Value>,
    #[serde(default)]
    pub after: Option<serde_json::Value>,
    #[serde(default)]
    pub effective_expiry_after_expire: Option<u64>,
    #[serde(default)]
    pub effective_expiry_formula: Option<String>,
    #[serde(default)]
    pub now_at_check: Option<u64>,
    #[serde(default)]
    pub would_be_culled: Option<bool>,
    #[serde(default)]
    pub culling_check: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TimestampRefreshVector {
    pub description: String,
    pub interface_mode: String,
    pub interface_mode_value: Option<u64>,
    pub ttl_seconds: u64,
    pub ttl_constant: String,
    pub path_entry_initial: serde_json::Value,
    pub original_expiry: u64,
    pub packet_forward_time: u64,
    pub path_entry_after_forward: serde_json::Value,
    pub new_effective_expiry: u64,
    pub effective_expiry_formula: String,
    pub check_time: u64,
    pub without_refresh_valid: bool,
    pub with_refresh_valid: bool,
    pub note: String,
}

#[derive(Debug, Deserialize)]
pub struct AnnounceRefreshVector {
    pub description: String,
    pub existing_entry: serde_json::Value,
    pub existing_path_timebase: f64,
    pub new_announce: serde_json::Value,
    pub conditions: serde_json::Value,
    pub should_add: bool,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ExpiredPathReplacementVector {
    pub description: String,
    pub existing_entry: serde_json::Value,
    pub now: u64,
    pub path_expired: bool,
    pub new_announce: serde_json::Value,
    pub conditions: serde_json::Value,
    pub should_add: bool,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct EmissionOverrideVector {
    pub description: String,
    pub existing_entry: serde_json::Value,
    pub path_announce_emitted: f64,
    pub now: u64,
    pub path_expired: bool,
    pub new_announce: serde_json::Value,
    pub conditions: serde_json::Value,
    pub should_add: bool,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UnresponsiveReplacementVector {
    pub description: String,
    pub existing_entry: serde_json::Value,
    pub path_announce_emitted: f64,
    pub now: u64,
    pub path_expired: bool,
    pub new_announce: serde_json::Value,
    pub conditions: serde_json::Value,
    pub should_add: bool,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RediscoveryTriggerVector {
    pub description: String,
    pub trigger: String,
    #[serde(default)]
    pub transport_enabled: Option<bool>,
    #[serde(default)]
    pub is_connected_to_shared_instance: Option<bool>,
    #[serde(default)]
    pub destination_hash: Option<String>,
    #[serde(default)]
    pub last_path_request_time: Option<f64>,
    #[serde(default)]
    pub now: Option<f64>,
    #[serde(default)]
    pub time_since_last_request: Option<f64>,
    #[serde(default)]
    pub path_request_mi_seconds: Option<u64>,
    #[serde(default)]
    pub throttle_check: Option<String>,
    #[serde(default)]
    pub expected_actions: Option<Vec<String>>,
    pub source_lines: serde_json::Value,
    #[serde(default)]
    pub note: Option<String>,
    #[serde(default)]
    pub path_exists: Option<bool>,
    #[serde(default)]
    pub lr_taken_hops: Option<u64>,
    #[serde(default)]
    pub path_request_throttle: Option<serde_json::Value>,
    #[serde(default)]
    pub hops_to_destination: Option<u64>,
    #[serde(default)]
    pub discovery_entry: Option<serde_json::Value>,
    #[serde(default)]
    pub check_time_before_timeout: Option<f64>,
    #[serde(default)]
    pub check_before_expired: Option<bool>,
    #[serde(default)]
    pub check_time_after_timeout: Option<f64>,
    #[serde(default)]
    pub check_after_expired: Option<bool>,
    #[serde(default)]
    pub path_request_timeout_seconds: Option<u64>,
    #[serde(default)]
    pub expected_action: Option<String>,
    #[serde(default)]
    pub expiry_check: Option<serde_json::Value>,
    #[serde(default)]
    pub examples: Option<serde_json::Value>,
    #[serde(default)]
    pub throttle_comparison: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct InterfaceDisappearanceVector {
    pub description: String,
    pub destination_hash: String,
    pub path_entry: serde_json::Value,
    #[serde(default)]
    pub interface_mode: Option<String>,
    #[serde(default)]
    pub interface_mode_value: Option<u64>,
    pub active_interfaces: Vec<String>,
    pub now: u64,
    pub ttl_expired: bool,
    pub interface_present: bool,
    pub expected_removed: bool,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
    #[serde(default)]
    pub source_lines: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct PathExpirationVectors {
    pub description: String,
    pub source: String,
    pub constants: serde_json::Value,
    pub algorithm: serde_json::Value,
    pub ttl_enforcement_vectors: Vec<TtlEnforcementVector>,
    pub expire_path_vectors: Vec<ExpirePathVector>,
    pub timestamp_refresh_vectors: Vec<TimestampRefreshVector>,
    pub announce_refresh_vectors: Vec<AnnounceRefreshVector>,
    pub expired_path_replacement_vectors: Vec<ExpiredPathReplacementVector>,
    pub emission_override_vectors: Vec<EmissionOverrideVector>,
    pub unresponsive_replacement_vectors: Vec<UnresponsiveReplacementVector>,
    pub rediscovery_trigger_vectors: Vec<RediscoveryTriggerVector>,
    pub interface_disappearance_vectors: Vec<InterfaceDisappearanceVector>,
}

pub fn load() -> PathExpirationVectors {
    let json = include_str!("../../../.test-vectors/path_expiration.json");
    serde_json::from_str(json).expect("Failed to deserialize path_expiration.json")
}
