//! Test vector types for interface_framing.json
//!
//! HDLC, KISS framing, IFAC authentication, and full pipeline test vectors.

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct HdlcVector {
    pub description: String,
    pub input: String,
    pub escaped: String,
    pub framed: String,
    pub escaped_length: u64,
    pub framed_length: u64,
}

#[derive(Debug, Deserialize)]
pub struct Hdlc {
    pub description: String,
    pub constants: serde_json::Value,
    pub escape_rules: serde_json::Value,
    pub frame_format: String,
    pub escape_order_note: String,
    pub vectors: Vec<HdlcVector>,
}

#[derive(Debug, Deserialize)]
pub struct KissVector {
    pub description: String,
    pub input: String,
    pub escaped: String,
    pub framed: String,
    pub escaped_length: u64,
    pub framed_length: u64,
}

#[derive(Debug, Deserialize)]
pub struct Kiss {
    pub description: String,
    pub constants: serde_json::Value,
    pub escape_rules: serde_json::Value,
    pub frame_format: String,
    pub escape_order_note: String,
    pub vectors: Vec<KissVector>,
}

#[derive(Debug, Deserialize)]
pub struct ConsecutiveFrames {
    pub description: String,
    pub packets: Vec<String>,
    pub hdlc_concatenated: String,
    pub kiss_concatenated: String,
    pub hdlc_separator: String,
    pub kiss_separator: String,
    pub note: String,
}

#[derive(Debug, Deserialize)]
pub struct IfacVector {
    pub description: String,
    #[serde(default)]
    pub ifac_netname: Option<String>,
    #[serde(default)]
    pub ifac_netkey: Option<String>,
    #[serde(default)]
    pub sender_netname: Option<String>,
    #[serde(default)]
    pub sender_netkey: Option<String>,
    #[serde(default)]
    pub receiver_netname: Option<String>,
    #[serde(default)]
    pub receiver_netkey: Option<String>,
    pub ifac_size: u64,
    pub raw_packet: String,
    #[serde(default)]
    pub ifac_value: Option<String>,
    #[serde(default)]
    pub mask: Option<String>,
    pub masked_packet: Option<String>,
    #[serde(default)]
    pub recovered_packet: Option<String>,
    #[serde(default)]
    pub ifac_flag_set: Option<bool>,
    #[serde(default)]
    pub tampered_packet: Option<String>,
    #[serde(default)]
    pub verification_result: Option<String>,
    #[serde(default)]
    pub notes: Option<serde_json::Value>,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct Ifac {
    pub description: String,
    pub constants: serde_json::Value,
    pub key_derivation: serde_json::Value,
    pub transmit_apply: serde_json::Value,
    pub receive_verify: serde_json::Value,
    pub vectors: Vec<IfacVector>,
}

#[derive(Debug, Deserialize)]
pub struct FullPipelineVector {
    pub description: String,
    pub framing: String,
    pub ifac_netname: Option<String>,
    pub ifac_netkey: Option<String>,
    pub ifac_size: u64,
    pub step_0_raw: String,
    pub step_1_ifac_applied: String,
    pub step_2_framed: String,
    pub step_3_deframed: String,
    pub step_4_ifac_verified: String,
}

#[derive(Debug, Deserialize)]
pub struct FullPipeline {
    pub description: String,
    pub pipeline_order_transmit: serde_json::Value,
    pub pipeline_order_receive: serde_json::Value,
    pub vectors: Vec<FullPipelineVector>,
}

#[derive(Debug, Deserialize)]
pub struct InterfaceFramingVectors {
    pub description: String,
    pub sources: Vec<String>,
    pub hdlc: Hdlc,
    pub kiss: Kiss,
    pub consecutive_frames: ConsecutiveFrames,
    pub ifac: Ifac,
    pub full_pipeline: FullPipeline,
}

pub fn load() -> InterfaceFramingVectors {
    let json = include_str!("../../../.test-vectors/interface_framing.json");
    serde_json::from_str(json).expect("Failed to deserialize interface_framing.json")
}
