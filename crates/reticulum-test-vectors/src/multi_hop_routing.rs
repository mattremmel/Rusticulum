//! Test vector types for multi_hop_routing.json
//!
//! Multi-hop routing test vectors including header transformations, announce propagation,
//! link request forwarding, link/reverse table entries, and path table queries.

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct LinkTableEntryFields {
    #[serde(rename = "IDX_LT_NH_TRID")]
    pub next_hop_transport_id: serde_json::Value,
    #[serde(rename = "IDX_LT_REM_HOPS")]
    pub remaining_hops: u64,
    #[serde(rename = "IDX_LT_HOPS")]
    pub taken_hops: u64,
    #[serde(rename = "IDX_LT_VALIDATED")]
    pub validated: bool,
    #[serde(rename = "IDX_LT_TIMESTAMP")]
    pub timestamp: u64,
    #[serde(rename = "IDX_LT_PROOF_TMO")]
    pub proof_timeout: f64,
    #[serde(rename = "IDX_LT_NH_IF")]
    pub next_hop_interface: serde_json::Value,
    #[serde(rename = "IDX_LT_RCVD_IF")]
    pub received_interface: serde_json::Value,
    #[serde(rename = "IDX_LT_DSTHASH")]
    pub destination_hash: serde_json::Value,
}

#[derive(Debug, Deserialize)]
pub struct LinkRoutingEntry {
    #[serde(rename = "IDX_LT_REM_HOPS")]
    pub remaining_hops: u64,
    #[serde(rename = "IDX_LT_HOPS")]
    pub hops: u64,
    pub interfaces_same: bool,
}

#[derive(Debug, Deserialize)]
pub struct HeaderTransformationVector {
    pub description: String,
    pub scenario: String,
    pub source_node: String,
    pub destination_node: String,
    pub next_hop_node: String,
    pub path_hops: u64,
    #[serde(default)]
    pub is_shared_instance: Option<bool>,
    pub packet_type: String,
    pub destination_hash: String,
    pub next_hop: String,
    #[serde(default)]
    pub payload: Option<String>,
    pub original_flags: String,
    #[serde(default)]
    pub original_header_type: Option<String>,
    #[serde(default)]
    pub original_transport_type: Option<String>,
    pub original_raw: String,
    pub original_raw_length: u64,
    pub original_packet_hash: String,
    pub transformed_flags: String,
    #[serde(default)]
    pub transformed_header_type: Option<String>,
    #[serde(default)]
    pub transformed_transport_type: Option<String>,
    pub transformed_raw: String,
    pub transformed_raw_length: u64,
    pub transformed_packet_hash: String,
    pub size_increase: u64,
    #[serde(default)]
    pub transformation: Option<serde_json::Value>,
    #[serde(default)]
    pub note: Option<String>,
    #[serde(default)]
    pub lr_data: Option<String>,
    #[serde(default)]
    pub lr_data_length: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct AnnouncePropagationStep {
    pub step: u64,
    pub description: String,
    pub node: String,
    pub action: String,
    #[serde(default)]
    pub header_type: Option<String>,
    #[serde(default)]
    pub transport_type: Option<String>,
    #[serde(default)]
    pub hops_on_wire: Option<u64>,
    #[serde(default)]
    pub raw_packet: Option<String>,
    #[serde(default)]
    pub raw_packet_length: Option<u64>,
    #[serde(default)]
    pub packet_hash: Option<String>,
    #[serde(default)]
    pub received_header_type: Option<String>,
    #[serde(default)]
    pub received_transport_id: Option<String>,
    #[serde(default)]
    pub hops_after_increment: Option<u64>,
    #[serde(default)]
    pub received_from: Option<String>,
    #[serde(default)]
    pub received_from_source: Option<String>,
    #[serde(default)]
    pub path_table_entry: Option<serde_json::Value>,
    #[serde(default)]
    pub rebroadcast_header_type: Option<String>,
    #[serde(default)]
    pub rebroadcast_transport_type: Option<String>,
    #[serde(default)]
    pub rebroadcast_transport_id: Option<String>,
    #[serde(default)]
    pub rebroadcast_hops: Option<u64>,
    #[serde(default)]
    pub rebroadcast_context: Option<String>,
    #[serde(default)]
    pub rebroadcast_raw: Option<String>,
    #[serde(default)]
    pub rebroadcast_raw_length: Option<u64>,
    #[serde(default)]
    pub rebroadcast_packet_hash: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AnnouncePropagationVector {
    pub description: String,
    pub announce_source: String,
    pub destination_hash: String,
    pub announce_payload: String,
    #[serde(default)]
    pub announce_payload_length: Option<u64>,
    pub random_blob: String,
    #[serde(default)]
    pub random_hash: Option<String>,
    pub chain: Vec<AnnouncePropagationStep>,
}

#[derive(Debug, Deserialize)]
pub struct LinkRequestForwardingVector {
    pub description: String,
    pub scenario: String,
    pub relay_node: String,
    #[serde(default)]
    pub relay_node_hash: Option<String>,
    pub destination_hash: String,
    #[serde(default)]
    pub next_hop: Option<String>,
    #[serde(default)]
    pub remaining_hops: Option<u64>,
    #[serde(default)]
    pub hops_at_relay: Option<u64>,
    #[serde(default)]
    pub lr_data: Option<String>,
    #[serde(default)]
    pub lr_data_length: Option<u64>,
    pub arriving_raw: String,
    pub arriving_raw_length: u64,
    #[serde(default)]
    pub arriving_header_type: Option<String>,
    pub arriving_packet_hash: String,
    pub relayed_raw: String,
    pub relayed_raw_length: u64,
    pub relayed_packet_hash: String,
    #[serde(default)]
    pub relayed_header_type: Option<String>,
    #[serde(default)]
    pub relayed_transport_type: Option<String>,
    #[serde(default)]
    pub relayed_transport_id: Option<String>,
    #[serde(default)]
    pub link_id: Option<String>,
    #[serde(default)]
    pub link_id_note: Option<String>,
    #[serde(default)]
    pub relay_rule: Option<String>,
    #[serde(default)]
    pub size_decrease: Option<u64>,
    #[serde(default)]
    pub size_change: Option<serde_json::Value>,
    #[serde(default)]
    pub mtu_signalling_bytes: Option<String>,
    #[serde(default)]
    pub ecpubsize: Option<u64>,
    #[serde(default)]
    pub link_mtu_size: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct LinkTableEntryVector {
    pub description: String,
    pub relay_node: String,
    pub destination_hash: String,
    pub link_id: String,
    #[serde(default)]
    pub link_id_derivation: Option<serde_json::Value>,
    #[serde(default)]
    pub entry_fields: Option<LinkTableEntryFields>,
    #[serde(default)]
    pub proof_timeout_calculation: Option<serde_json::Value>,
    pub raw_packet: String,
    #[serde(default)]
    pub lr_data: Option<String>,
    #[serde(default)]
    pub lr_data_length: Option<u64>,
    #[serde(default)]
    pub ecpubsize: Option<u64>,
    #[serde(default)]
    pub excess_bytes: Option<u64>,
    #[serde(default)]
    pub hashable_part_full_length: Option<u64>,
    #[serde(default)]
    pub hashable_part_trimmed_length: Option<u64>,
    #[serde(default)]
    pub hashable_part_trimmed: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ReverseTableEntryVector {
    pub description: String,
    #[serde(default)]
    pub packet_type: Option<String>,
    #[serde(default)]
    pub destination_hash: Option<String>,
    #[serde(default)]
    pub transport_id: Option<String>,
    #[serde(default)]
    pub raw_packet: Option<String>,
    #[serde(default)]
    pub raw_packet_length: Option<u64>,
    #[serde(default)]
    pub hashable_part: Option<String>,
    #[serde(default)]
    pub truncated_hash_key: Option<String>,
    #[serde(default)]
    pub entry_fields: Option<serde_json::Value>,
    #[serde(default)]
    pub entry_indices: Option<serde_json::Value>,
    #[serde(default)]
    pub reverse_timeout_seconds: Option<u64>,
    #[serde(default)]
    pub reverse_timeout: Option<u64>,
    #[serde(default)]
    pub timestamp: Option<u64>,
    #[serde(default)]
    pub check_time: Option<u64>,
    #[serde(default)]
    pub age_seconds: Option<u64>,
    #[serde(default)]
    pub condition: Option<String>,
    #[serde(default)]
    pub condition_evaluation: Option<String>,
    #[serde(default)]
    pub is_expired: Option<bool>,
    #[serde(default)]
    pub note: Option<String>,
    #[serde(default)]
    pub hops_on_wire: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct PathTableQueryVector {
    pub description: String,
    pub destination_hash: String,
    pub path_table_entry_exists: bool,
    #[serde(default)]
    pub path_table_next_hop: Option<String>,
    #[serde(default)]
    pub path_table_hops: Option<u64>,
    pub has_path_result: bool,
    pub hops_to_result: Option<u64>,
    pub next_hop_result: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
    #[serde(default)]
    pub pathfinder_m: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct HeaderStrippingVector {
    pub description: String,
    pub packet_type: String,
    pub destination_hash: String,
    #[serde(default)]
    pub transport_id: Option<String>,
    pub remaining_hops: u64,
    pub hops_after_increment: u64,
    #[serde(default)]
    pub payload: Option<String>,
    #[serde(default)]
    pub proof_payload: Option<String>,
    pub original_flags: String,
    #[serde(default)]
    pub original_header_type: Option<String>,
    #[serde(default)]
    pub original_transport_type: Option<String>,
    pub original_raw: String,
    pub original_raw_length: u64,
    pub original_packet_hash: String,
    pub stripped_flags: String,
    pub expected_flags: String,
    #[serde(default)]
    pub stripped_header_type: Option<String>,
    #[serde(default)]
    pub stripped_transport_type: Option<String>,
    pub stripped_raw: String,
    pub stripped_raw_length: u64,
    pub stripped_packet_hash: String,
    pub size_decrease: u64,
    #[serde(default)]
    pub transformation: Option<serde_json::Value>,
    #[serde(default)]
    pub lr_data: Option<String>,
    #[serde(default)]
    pub lr_data_length: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct LinkTableRoutingVector {
    pub description: String,
    pub link_id: String,
    #[serde(default)]
    pub link_entry: Option<LinkRoutingEntry>,
    #[serde(default)]
    pub received_on: Option<String>,
    #[serde(default)]
    pub packet_hops: Option<u64>,
    #[serde(default)]
    pub expected_hops_check: Option<String>,
    #[serde(default)]
    pub expected_hops: Option<u64>,
    #[serde(default)]
    pub outbound_to: Option<String>,
    #[serde(default)]
    pub matches: Option<serde_json::Value>,
    #[serde(default)]
    pub should_forward: Option<bool>,
    #[serde(default)]
    pub raw_packet: Option<String>,
    #[serde(default)]
    pub original_raw: Option<String>,
    #[serde(default)]
    pub forwarded_raw: Option<String>,
    #[serde(default)]
    pub packet_hash: Option<String>,
    #[serde(default)]
    pub rule: Option<String>,
    #[serde(default)]
    pub packets_identical: Option<bool>,
    #[serde(default)]
    pub transformation: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct MultiHopRoutingVectors {
    pub description: String,
    pub source: String,
    pub topology: serde_json::Value,
    pub constants: serde_json::Value,
    pub algorithms: serde_json::Value,
    pub header_transformation_vectors: Vec<HeaderTransformationVector>,
    pub announce_propagation_vectors: Vec<AnnouncePropagationVector>,
    pub link_request_forwarding_vectors: Vec<LinkRequestForwardingVector>,
    pub link_table_entry_vectors: Vec<LinkTableEntryVector>,
    pub reverse_table_entry_vectors: Vec<ReverseTableEntryVector>,
    pub path_table_query_vectors: Vec<PathTableQueryVector>,
    pub header_stripping_vectors: Vec<HeaderStrippingVector>,
    pub link_table_routing_vectors: Vec<LinkTableRoutingVector>,
}

pub fn load() -> MultiHopRoutingVectors {
    let json = include_str!("../../../.test-vectors/multi_hop_routing.json");
    serde_json::from_str(json).expect("Failed to deserialize multi_hop_routing.json")
}
