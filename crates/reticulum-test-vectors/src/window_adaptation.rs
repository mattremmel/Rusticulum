//! Test vector types for window_adaptation.json
//!
//! Window adaptation test vectors for resource and channel protocols.

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct ResourceWindowState {
    pub window: u64,
    pub window_max: u64,
    pub window_min: u64,
    pub fast_rate_rounds: u64,
    pub very_slow_rate_rounds: u64,
}

#[derive(Debug, Deserialize)]
pub struct ResourceWindowStep {
    pub step: u64,
    pub event: String,
    #[serde(default)]
    pub rate: Option<f64>,
    pub state: ResourceWindowState,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ResourceGrowthVector {
    pub description: String,
    pub rate_bytes_per_sec: f64,
    pub rate_is_above_fast: bool,
    pub rate_is_below_very_slow: bool,
    pub steps: Vec<ResourceWindowStep>,
}

#[derive(Debug, Deserialize)]
pub struct ResourceShrinkVector {
    pub description: String,
    pub steps: Vec<ResourceWindowStep>,
}

#[derive(Debug, Deserialize)]
pub struct ResourceRateTransitionVector {
    pub description: String,
    #[serde(default)]
    pub fast_rate_threshold: Option<u64>,
    #[serde(default)]
    pub very_slow_rate_threshold: Option<u64>,
    pub steps: Vec<ResourceWindowStep>,
}

#[derive(Debug, Deserialize)]
pub struct ResourceWindow {
    pub description: String,
    pub constants: serde_json::Value,
    pub initial_state: serde_json::Value,
    pub growth_algorithm: Vec<String>,
    pub shrink_algorithm: Vec<String>,
    pub growth_vectors: Vec<ResourceGrowthVector>,
    pub shrink_vectors: Vec<ResourceShrinkVector>,
    pub rate_transition_vectors: Vec<ResourceRateTransitionVector>,
}

#[derive(Debug, Deserialize)]
pub struct ChannelWindow {
    pub description: String,
    pub constants: serde_json::Value,
    pub initialization_note: String,
    pub key_differences: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct ComparisonVector {
    pub description: String,
    pub resource_rate: f64,
    pub channel_rtt: f64,
    pub steps: Vec<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct WindowAdaptationVectors {
    pub description: String,
    pub sources: Vec<String>,
    pub resource_window: ResourceWindow,
    pub channel_window: ChannelWindow,
    pub comparison_vectors: Vec<ComparisonVector>,
}

pub fn load() -> WindowAdaptationVectors {
    let json = include_str!("../../../.test-vectors/window_adaptation.json");
    serde_json::from_str(json).expect("Failed to deserialize window_adaptation.json")
}
