//! Resource transfer management for the node.
//!
//! Tracks outgoing and incoming resource transfers over active links.
//! The ResourceManager is a pure state tracker — it does NOT hold crypto keys
//! or send packets. The Node mediates those via LinkManager.

use std::collections::HashMap;

use reticulum_core::types::LinkId;
use reticulum_protocol::link::types::DerivedKey;
use reticulum_protocol::resource::advertisement::{ResourceAdvertisement, ResourceFlags};
use reticulum_protocol::resource::constants::SDU;
use reticulum_protocol::resource::hashmap::ResourceHashmap;
use reticulum_protocol::resource::transfer::prepare_resource;

use crate::resource_ops;

/// State of an outgoing resource transfer.
#[derive(Debug)]
#[allow(dead_code)]
enum OutgoingState {
    Advertised,
    Transferring,
    AwaitingProof,
    Complete,
}

/// An outgoing resource transfer (we are the sender).
#[derive(Debug)]
struct OutgoingTransfer {
    link_id: LinkId,
    /// The encrypted data split into SDU-sized parts.
    parts: Vec<Vec<u8>>,
    /// Expected proof from the receiver.
    expected_proof: [u8; 32],
    state: OutgoingState,
}

/// An incoming resource transfer (we are the receiver).
#[derive(Debug)]
#[allow(dead_code)]
struct IncomingTransfer {
    advertisement: ResourceAdvertisement,
    flags: ResourceFlags,
    hashmap: ResourceHashmap,
    /// Received parts indexed by position.
    parts: Vec<Option<Vec<u8>>>,
    received_count: usize,
    resource_hash: [u8; 32],
    random_hash: [u8; 4],
}

/// Result from receive_part when all parts have been received.
pub struct PartComplete {
    /// If true, more parts are still needed — send this request.
    pub needs_more_parts: Option<Vec<u8>>,
    /// If true, all parts received — ready to assemble.
    pub all_received: bool,
}

/// Manages resource transfers for the node.
#[derive(Default)]
pub struct ResourceManager {
    /// Outgoing transfers keyed by resource_hash.
    outgoing: HashMap<[u8; 32], OutgoingTransfer>,
    /// Incoming transfers keyed by link_id (one per link, simplified MVP).
    incoming: HashMap<LinkId, IncomingTransfer>,
}

impl ResourceManager {
    /// Create a new empty ResourceManager.
    pub fn new() -> Self {
        Self {
            outgoing: HashMap::new(),
            incoming: HashMap::new(),
        }
    }

    /// Prepare a resource for sending over a link.
    ///
    /// Returns `(resource_hash, advertisement_msgpack_bytes)`.
    pub fn prepare_outgoing(
        &mut self,
        link_id: LinkId,
        data: &[u8],
        derived_key: &DerivedKey,
    ) -> Result<([u8; 32], Vec<u8>), String> {
        // Generate random IV and random_hash for this resource
        use rand::RngCore;
        let mut rng = rand::thread_rng();
        let mut iv = [0u8; 16];
        rng.fill_bytes(&mut iv);
        let mut random_hash = [0u8; 4];
        rng.fill_bytes(&mut random_hash);

        let prepared = prepare_resource(
            data,
            derived_key.as_bytes(),
            &iv,
            random_hash,
            None,  // no metadata for MVP
            false, // no compression for MVP
            1,     // segment_index
            1,     // total_segments
            None,  // no original_hash override
            None,  // no request_id
        )
        .map_err(|e| format!("prepare_resource failed: {e}"))?;

        let resource_hash = prepared.resource_hash;
        let adv_bytes = prepared.advertisement.to_msgpack();

        // Split encrypted data into SDU-sized parts
        let parts: Vec<Vec<u8>> = prepared
            .encrypted_data
            .chunks(SDU)
            .map(|c| c.to_vec())
            .collect();

        tracing::info!(
            resource_hash = %hex::encode(resource_hash),
            link_id = %hex::encode(link_id.as_ref()),
            parts = parts.len(),
            data_len = data.len(),
            encrypted_len = prepared.encrypted_data.len(),
            "resource prepared for sending"
        );

        self.outgoing.insert(
            resource_hash,
            OutgoingTransfer {
                link_id,
                parts,
                expected_proof: prepared.expected_proof,
                state: OutgoingState::Advertised,
            },
        );

        Ok((resource_hash, adv_bytes))
    }

    /// Handle a part request from the receiver.
    ///
    /// Returns the requested part data chunks.
    pub fn handle_part_request(
        &mut self,
        request_data: &[u8],
    ) -> Result<(LinkId, Vec<Vec<u8>>), String> {
        let selection = resource_ops::select_parts_for_request(request_data, &[])?;

        let transfer = self
            .outgoing
            .get_mut(&selection.resource_hash)
            .ok_or_else(|| {
                format!(
                    "unknown resource hash: {}",
                    hex::encode(selection.resource_hash)
                )
            })?;

        transfer.state = OutgoingState::Transferring;

        // Re-select with the actual parts now that we've validated the resource hash
        let selection = resource_ops::select_parts_for_request(request_data, &transfer.parts)?;

        tracing::info!(
            resource_hash = %hex::encode(selection.resource_hash),
            parts_sent = selection.selected_parts.len(),
            "handling part request"
        );

        Ok((transfer.link_id, selection.selected_parts))
    }

    /// Handle a proof from the receiver.
    ///
    /// Returns true if the proof is valid and the transfer is complete.
    pub fn handle_proof(&mut self, proof_data: &[u8]) -> Result<bool, String> {
        // Peek at the resource hash to find the transfer (validate with dummy first)
        let peek = resource_ops::validate_resource_proof(proof_data, &[0u8; 32])?;
        let resource_hash = match &peek {
            resource_ops::ProofValidation::Valid { resource_hash }
            | resource_ops::ProofValidation::Invalid { resource_hash } => *resource_hash,
        };

        let transfer = self
            .outgoing
            .get_mut(&resource_hash)
            .ok_or_else(|| format!("unknown resource hash: {}", hex::encode(resource_hash)))?;

        let validation =
            resource_ops::validate_resource_proof(proof_data, &transfer.expected_proof)?;

        match validation {
            resource_ops::ProofValidation::Valid { resource_hash } => {
                transfer.state = OutgoingState::Complete;
                tracing::info!(
                    resource_hash = %hex::encode(resource_hash),
                    "resource_proof_verified"
                );
                Ok(true)
            }
            resource_ops::ProofValidation::Invalid { resource_hash } => {
                tracing::warn!(
                    resource_hash = %hex::encode(resource_hash),
                    "resource proof validation failed"
                );
                Ok(false)
            }
        }
    }

    /// Accept a resource advertisement from a sender.
    ///
    /// Returns `(resource_hash, part_request_bytes)` — the initial part request
    /// to send back requesting all parts.
    pub fn accept_advertisement(
        &mut self,
        link_id: LinkId,
        adv_bytes: &[u8],
    ) -> Result<([u8; 32], Vec<u8>), String> {
        let parsed = resource_ops::parse_advertisement(adv_bytes)?;

        tracing::info!(
            resource_hash = %hex::encode(parsed.resource_hash),
            link_id = %hex::encode(link_id.as_ref()),
            num_parts = parsed.num_parts,
            transfer_size = parsed.advertisement.transfer_size,
            data_size = parsed.advertisement.data_size,
            compressed = parsed.flags.compressed,
            "accepted resource advertisement"
        );

        let parts = vec![None; parsed.num_parts];

        self.incoming.insert(
            link_id,
            IncomingTransfer {
                advertisement: parsed.advertisement,
                flags: parsed.flags,
                hashmap: parsed.hashmap,
                parts,
                received_count: 0,
                resource_hash: parsed.resource_hash,
                random_hash: parsed.random_hash,
            },
        );

        Ok((parsed.resource_hash, parsed.initial_request))
    }

    /// Receive a resource part.
    ///
    /// Matches the part by verifying its map hash against the hashmap.
    /// Returns a `PartComplete` indicating whether more parts are needed
    /// or all parts have been received.
    pub fn receive_part(
        &mut self,
        link_id: &LinkId,
        part_data: &[u8],
    ) -> Result<PartComplete, String> {
        let transfer = self.incoming.get_mut(link_id).ok_or_else(|| {
            format!(
                "no incoming transfer for link {}",
                hex::encode(link_id.as_ref())
            )
        })?;

        // Find which part this is by matching its map hash
        let matched_index =
            resource_ops::match_resource_part(&transfer.parts, &transfer.hashmap, part_data);

        match matched_index {
            Some(idx) => {
                transfer.parts[idx] = Some(part_data.to_vec());
                transfer.received_count += 1;

                tracing::debug!(
                    resource_hash = %hex::encode(transfer.resource_hash),
                    part_index = idx,
                    received = transfer.received_count,
                    total = transfer.parts.len(),
                    "received resource part"
                );

                let all_received = transfer.received_count == transfer.parts.len();

                Ok(PartComplete {
                    needs_more_parts: None, // MVP: we requested all upfront
                    all_received,
                })
            }
            None => {
                tracing::warn!(
                    link_id = %hex::encode(link_id.as_ref()),
                    "received unmatched resource part"
                );
                Ok(PartComplete {
                    needs_more_parts: None,
                    all_received: false,
                })
            }
        }
    }

    /// Assemble a completed resource and compute the proof.
    ///
    /// Returns `(original_data, proof_payload_bytes)`.
    pub fn assemble_and_prove(
        &mut self,
        link_id: &LinkId,
        derived_key: &DerivedKey,
    ) -> Result<(Vec<u8>, Vec<u8>), String> {
        let transfer = self.incoming.get(link_id).ok_or_else(|| {
            format!(
                "no incoming transfer for link {}",
                hex::encode(link_id.as_ref())
            )
        })?;

        let (data, proof_bytes) = resource_ops::collect_and_assemble(
            &transfer.parts,
            derived_key,
            &transfer.random_hash,
            &transfer.resource_hash,
            transfer.flags.compressed,
        )?;

        tracing::info!(
            resource_hash = %hex::encode(transfer.resource_hash),
            data_len = data.len(),
            "resource_received"
        );

        Ok((data, proof_bytes))
    }

    /// Check if a resource transfer (outgoing) is complete.
    pub fn is_complete(&self, resource_hash: &[u8; 32]) -> bool {
        self.outgoing
            .get(resource_hash)
            .is_some_and(|t| matches!(t.state, OutgoingState::Complete))
    }

    /// Check if there's an incoming transfer for this link.
    pub fn has_incoming(&self, link_id: &LinkId) -> bool {
        self.incoming.contains_key(link_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reticulum_protocol::link::types::DerivedKey;

    fn make_test_derived_key() -> DerivedKey {
        let mut key = [0u8; 64];
        for (i, b) in key.iter_mut().enumerate() {
            *b = (i * 7 + 13) as u8;
        }
        DerivedKey::new(key)
    }

    #[test]
    fn prepare_and_accept_roundtrip() {
        let mut mgr = ResourceManager::new();
        let link_id = LinkId::new([0xAA; 16]);
        let key = make_test_derived_key();

        let data = b"Hello from resource transfer test!";

        // Prepare outgoing
        let (resource_hash, adv_bytes) = mgr.prepare_outgoing(link_id, data, &key).unwrap();
        assert!(!adv_bytes.is_empty());

        // Accept advertisement (simulating receiver)
        let recv_link_id = LinkId::new([0xBB; 16]);
        let (recv_hash, request_bytes) =
            mgr.accept_advertisement(recv_link_id, &adv_bytes).unwrap();
        assert_eq!(recv_hash, resource_hash);
        assert!(!request_bytes.is_empty());
    }

    #[test]
    fn full_resource_transfer_roundtrip() {
        let mut sender_mgr = ResourceManager::new();
        let mut receiver_mgr = ResourceManager::new();
        let sender_link = LinkId::new([0xAA; 16]);
        let receiver_link = LinkId::new([0xBB; 16]);
        let key = make_test_derived_key();

        let data = b"This is test resource data for a full roundtrip transfer!";

        // 1. Sender prepares resource
        let (resource_hash, adv_bytes) = sender_mgr
            .prepare_outgoing(sender_link, data, &key)
            .unwrap();

        // 2. Receiver accepts advertisement
        let (_recv_hash, request_bytes) = receiver_mgr
            .accept_advertisement(receiver_link, &adv_bytes)
            .unwrap();

        // 3. Sender handles part request
        let (_link, parts) = sender_mgr.handle_part_request(&request_bytes).unwrap();

        // 4. Receiver receives each part
        for part in &parts {
            let _result = receiver_mgr.receive_part(&receiver_link, part).unwrap();
        }

        // 5. Receiver assembles and proves
        let (received_data, proof_bytes) = receiver_mgr
            .assemble_and_prove(&receiver_link, &key)
            .unwrap();
        assert_eq!(received_data, data);

        // 6. Sender validates proof
        let valid = sender_mgr.handle_proof(&proof_bytes).unwrap();
        assert!(valid);
        assert!(sender_mgr.is_complete(&resource_hash));
    }

    #[test]
    fn larger_resource_multipart() {
        let mut sender_mgr = ResourceManager::new();
        let mut receiver_mgr = ResourceManager::new();
        let sender_link = LinkId::new([0x11; 16]);
        let receiver_link = LinkId::new([0x22; 16]);
        let key = make_test_derived_key();

        // ~2KB of data (will produce multiple SDU-sized parts after encryption)
        let data: Vec<u8> = (0..2000u16).map(|i| (i % 256) as u8).collect();

        // Full transfer
        let (_resource_hash, adv_bytes) = sender_mgr
            .prepare_outgoing(sender_link, &data, &key)
            .unwrap();
        let (_recv_hash, request_bytes) = receiver_mgr
            .accept_advertisement(receiver_link, &adv_bytes)
            .unwrap();
        let (_link, parts) = sender_mgr.handle_part_request(&request_bytes).unwrap();

        assert!(
            parts.len() > 1,
            "expected multiple parts for 2KB data, got {}",
            parts.len()
        );

        let mut all_received = false;
        for part in &parts {
            let result = receiver_mgr.receive_part(&receiver_link, part).unwrap();
            if result.all_received {
                all_received = true;
            }
        }
        assert!(all_received);

        let (received_data, proof_bytes) = receiver_mgr
            .assemble_and_prove(&receiver_link, &key)
            .unwrap();
        assert_eq!(received_data, data);

        let valid = sender_mgr.handle_proof(&proof_bytes).unwrap();
        assert!(valid);
    }

    #[test]
    fn prepare_outgoing_returns_hash_and_adv() {
        let mut mgr = ResourceManager::new();
        let link_id = LinkId::new([0x33; 16]);
        let key = make_test_derived_key();

        let (resource_hash, adv_bytes) = mgr.prepare_outgoing(link_id, b"test data", &key).unwrap();

        assert_ne!(resource_hash, [0u8; 32]);
        assert!(!adv_bytes.is_empty());
        assert!(mgr.outgoing.contains_key(&resource_hash));
    }

    #[test]
    fn accept_advertisement_stores_state() {
        let mut sender_mgr = ResourceManager::new();
        let mut receiver_mgr = ResourceManager::new();
        let sender_link = LinkId::new([0x44; 16]);
        let receiver_link = LinkId::new([0x55; 16]);
        let key = make_test_derived_key();

        let (_hash, adv_bytes) = sender_mgr
            .prepare_outgoing(sender_link, b"accept test", &key)
            .unwrap();

        assert!(!receiver_mgr.has_incoming(&receiver_link));
        let (_recv_hash, _request) = receiver_mgr
            .accept_advertisement(receiver_link, &adv_bytes)
            .unwrap();
        assert!(receiver_mgr.has_incoming(&receiver_link));
    }

    #[test]
    fn receive_part_returns_completion() {
        let mut sender_mgr = ResourceManager::new();
        let mut receiver_mgr = ResourceManager::new();
        let sender_link = LinkId::new([0x66; 16]);
        let receiver_link = LinkId::new([0x77; 16]);
        let key = make_test_derived_key();

        let data = b"completion test data";
        let (_hash, adv_bytes) = sender_mgr
            .prepare_outgoing(sender_link, data, &key)
            .unwrap();
        let (_recv_hash, request_bytes) = receiver_mgr
            .accept_advertisement(receiver_link, &adv_bytes)
            .unwrap();
        let (_link, parts) = sender_mgr.handle_part_request(&request_bytes).unwrap();

        let mut final_result = None;
        for part in &parts {
            final_result = Some(receiver_mgr.receive_part(&receiver_link, part).unwrap());
        }
        assert!(final_result.unwrap().all_received);
    }

    #[test]
    fn handle_part_request_unknown_hash() {
        let mut mgr = ResourceManager::new();
        // Construct a fake request with a resource hash that doesn't exist
        // Format: 0x00 flag + resource_hash(32) + map_hashes
        let mut fake_request = vec![0x00u8];
        fake_request.extend_from_slice(&[0xDE; 32]);
        fake_request.extend_from_slice(&[0xAD; 4]); // one map hash

        let result = mgr.handle_part_request(&fake_request);
        assert!(result.is_err());
    }

    #[test]
    fn handle_proof_verifies() {
        let mut sender_mgr = ResourceManager::new();
        let mut receiver_mgr = ResourceManager::new();
        let sender_link = LinkId::new([0x88; 16]);
        let receiver_link = LinkId::new([0x99; 16]);
        let key = make_test_derived_key();

        let (resource_hash, adv_bytes) = sender_mgr
            .prepare_outgoing(sender_link, b"proof test", &key)
            .unwrap();
        let (_recv_hash, request_bytes) = receiver_mgr
            .accept_advertisement(receiver_link, &adv_bytes)
            .unwrap();
        let (_link, parts) = sender_mgr.handle_part_request(&request_bytes).unwrap();
        for part in &parts {
            receiver_mgr.receive_part(&receiver_link, part).unwrap();
        }
        let (_data, proof_bytes) = receiver_mgr
            .assemble_and_prove(&receiver_link, &key)
            .unwrap();

        let valid = sender_mgr.handle_proof(&proof_bytes).unwrap();
        assert!(valid);
        assert!(sender_mgr.is_complete(&resource_hash));
    }

    #[test]
    fn not_complete_before_proof() {
        let mut mgr = ResourceManager::new();
        let link_id = LinkId::new([0xAB; 16]);
        let key = make_test_derived_key();

        let (resource_hash, _adv) = mgr
            .prepare_outgoing(link_id, b"not complete test", &key)
            .unwrap();
        assert!(!mgr.is_complete(&resource_hash));
    }

    #[test]
    fn test_multiple_resources_same_link() {
        let mut mgr = ResourceManager::new();
        let link_id = LinkId::new([0xC1; 16]);
        let key = make_test_derived_key();

        let (hash1, adv1) = mgr
            .prepare_outgoing(link_id, b"resource one", &key)
            .unwrap();
        let (hash2, adv2) = mgr
            .prepare_outgoing(link_id, b"resource two", &key)
            .unwrap();

        assert_ne!(hash1, hash2);
        assert_ne!(adv1, adv2);
        assert!(mgr.outgoing.contains_key(&hash1));
        assert!(mgr.outgoing.contains_key(&hash2));
        assert_eq!(mgr.outgoing.len(), 2);
    }

    #[test]
    fn test_duplicate_part_reception_idempotent() {
        let mut sender_mgr = ResourceManager::new();
        let mut receiver_mgr = ResourceManager::new();
        let sender_link = LinkId::new([0xC2; 16]);
        let receiver_link = LinkId::new([0xC3; 16]);
        let key = make_test_derived_key();

        let data = b"duplicate part test data for checking idempotency";
        let (_hash, adv) = sender_mgr
            .prepare_outgoing(sender_link, data, &key)
            .unwrap();
        let (_recv_hash, req) = receiver_mgr
            .accept_advertisement(receiver_link, &adv)
            .unwrap();
        let (_link, parts) = sender_mgr.handle_part_request(&req).unwrap();

        // Deliver the first part twice
        let result1 = receiver_mgr
            .receive_part(&receiver_link, &parts[0])
            .unwrap();
        let count_after_first = receiver_mgr
            .incoming
            .get(&receiver_link)
            .unwrap()
            .received_count;

        // Second delivery of the same part — the map hash won't match an empty slot
        // so it should be a no-op (unmatched part)
        let result2 = receiver_mgr
            .receive_part(&receiver_link, &parts[0])
            .unwrap();
        let count_after_dup = receiver_mgr
            .incoming
            .get(&receiver_link)
            .unwrap()
            .received_count;

        // received_count should not increase on duplicate
        assert_eq!(count_after_first, count_after_dup);

        // Now deliver remaining parts normally
        for part in &parts[1..] {
            receiver_mgr.receive_part(&receiver_link, part).unwrap();
        }

        // Assembly should succeed
        let (received_data, _proof) = receiver_mgr
            .assemble_and_prove(&receiver_link, &key)
            .unwrap();
        assert_eq!(received_data, data);

        let _ = (result1, result2); // suppress unused warnings
    }

    #[test]
    fn test_out_of_order_part_reception() {
        let mut sender_mgr = ResourceManager::new();
        let mut receiver_mgr = ResourceManager::new();
        let sender_link = LinkId::new([0xC4; 16]);
        let receiver_link = LinkId::new([0xC5; 16]);
        let key = make_test_derived_key();

        // Use enough data to produce multiple parts
        let data: Vec<u8> = (0..2000u16).map(|i| (i % 256) as u8).collect();
        let (_hash, adv) = sender_mgr
            .prepare_outgoing(sender_link, &data, &key)
            .unwrap();
        let (_recv_hash, req) = receiver_mgr
            .accept_advertisement(receiver_link, &adv)
            .unwrap();
        let (_link, parts) = sender_mgr.handle_part_request(&req).unwrap();
        assert!(parts.len() > 1, "need multiple parts for this test");

        // Deliver parts in reverse order
        let mut all_received = false;
        for part in parts.iter().rev() {
            let result = receiver_mgr.receive_part(&receiver_link, part).unwrap();
            if result.all_received {
                all_received = true;
            }
        }
        assert!(all_received);

        let (received_data, proof) = receiver_mgr
            .assemble_and_prove(&receiver_link, &key)
            .unwrap();
        assert_eq!(received_data, data);

        let valid = sender_mgr.handle_proof(&proof).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_many_concurrent_outgoing_resources() {
        let mut mgr = ResourceManager::new();
        let link_id = LinkId::new([0xC6; 16]);
        let key = make_test_derived_key();

        let mut hashes = Vec::new();
        for i in 0u8..50 {
            let data = format!("resource-{i}");
            let (hash, _adv) = mgr
                .prepare_outgoing(link_id, data.as_bytes(), &key)
                .unwrap();
            hashes.push(hash);
        }

        assert_eq!(mgr.outgoing.len(), 50);
        // All hashes should be unique
        let unique: std::collections::HashSet<_> = hashes.iter().collect();
        assert_eq!(unique.len(), 50);
    }

    #[test]
    fn test_receive_part_no_incoming() {
        let mut mgr = ResourceManager::new();
        let unknown_link = LinkId::new([0xC7; 16]);

        let result = mgr.receive_part(&unknown_link, b"some part data");
        assert!(result.is_err());
    }

    #[test]
    fn test_assemble_no_incoming() {
        let mut mgr = ResourceManager::new();
        let unknown_link = LinkId::new([0xC8; 16]);
        let key = make_test_derived_key();

        let result = mgr.assemble_and_prove(&unknown_link, &key);
        assert!(result.is_err());
    }

    #[test]
    fn test_handle_proof_wrong_hash() {
        let mut mgr = ResourceManager::new();
        // Build a proof payload with a resource hash that doesn't exist in outgoing
        // Format: resource_hash(32) || proof(32)
        let mut fake_proof = vec![0u8; 64];
        fake_proof[..32].copy_from_slice(&[0xDE; 32]); // unknown resource_hash
        fake_proof[32..].copy_from_slice(&[0xAD; 32]); // fake proof

        let result = mgr.handle_proof(&fake_proof);
        assert!(result.is_err());
    }

    #[test]
    fn test_accept_advertisement_replaces_existing() {
        let mut sender_mgr = ResourceManager::new();
        let mut receiver_mgr = ResourceManager::new();
        let sender_link = LinkId::new([0xC9; 16]);
        let receiver_link = LinkId::new([0xCA; 16]);
        let key = make_test_derived_key();

        // First advertisement
        let (hash1, adv1) = sender_mgr
            .prepare_outgoing(sender_link, b"first resource", &key)
            .unwrap();
        let (recv_hash1, _req1) = receiver_mgr
            .accept_advertisement(receiver_link, &adv1)
            .unwrap();
        assert_eq!(recv_hash1, hash1);
        assert!(receiver_mgr.has_incoming(&receiver_link));

        // Second advertisement on same link — should replace
        let (hash2, adv2) = sender_mgr
            .prepare_outgoing(sender_link, b"second resource", &key)
            .unwrap();
        let (recv_hash2, _req2) = receiver_mgr
            .accept_advertisement(receiver_link, &adv2)
            .unwrap();
        assert_eq!(recv_hash2, hash2);

        // Still only one incoming for this link (replaced)
        assert_eq!(receiver_mgr.incoming.len(), 1);
        let transfer = receiver_mgr.incoming.get(&receiver_link).unwrap();
        assert_eq!(transfer.resource_hash, hash2);
    }

    // --- Timeout and recovery path tests ---

    #[test]
    fn test_proof_mismatch_returns_false() {
        let mut sender_mgr = ResourceManager::new();
        let mut receiver_mgr = ResourceManager::new();
        let sender_link = LinkId::new([0xD1; 16]);
        let receiver_link = LinkId::new([0xD2; 16]);
        let key = make_test_derived_key();

        let (resource_hash, adv_bytes) = sender_mgr
            .prepare_outgoing(sender_link, b"proof mismatch test", &key)
            .unwrap();
        let (_recv_hash, request_bytes) = receiver_mgr
            .accept_advertisement(receiver_link, &adv_bytes)
            .unwrap();
        let (_link, parts) = sender_mgr.handle_part_request(&request_bytes).unwrap();
        for part in &parts {
            receiver_mgr.receive_part(&receiver_link, part).unwrap();
        }
        let (_data, mut proof_bytes) = receiver_mgr
            .assemble_and_prove(&receiver_link, &key)
            .unwrap();

        // Tamper with the proof bytes (the proof hash is in bytes 32..64)
        if proof_bytes.len() >= 64 {
            proof_bytes[32] ^= 0xFF;
            proof_bytes[33] ^= 0xFF;
        }

        let valid = sender_mgr.handle_proof(&proof_bytes).unwrap();
        assert!(!valid, "tampered proof should not validate");
        assert!(
            !sender_mgr.is_complete(&resource_hash),
            "transfer should not be marked complete on bad proof"
        );
    }

    #[test]
    fn test_proof_for_unknown_resource_returns_error() {
        let mut mgr = ResourceManager::new();
        // Proof payload: resource_hash(32) || proof(32)
        let mut fake_proof = vec![0u8; 64];
        fake_proof[..32].copy_from_slice(&[0xFA; 32]);
        fake_proof[32..].copy_from_slice(&[0xFB; 32]);

        let result = mgr.handle_proof(&fake_proof);
        assert!(result.is_err());
    }

    #[test]
    fn test_part_request_for_unknown_resource_returns_error() {
        let mut mgr = ResourceManager::new();
        // Format: 0x00 flag + resource_hash(32) + map_hash(4)
        let mut fake_request = vec![0x00u8];
        fake_request.extend_from_slice(&[0xEE; 32]);
        fake_request.extend_from_slice(&[0xAB; 4]);

        let result = mgr.handle_part_request(&fake_request);
        assert!(result.is_err());
    }

    #[test]
    fn test_receive_part_for_unknown_link_returns_error() {
        let mut mgr = ResourceManager::new();
        let unknown_link = LinkId::new([0xD3; 16]);

        let result = mgr.receive_part(&unknown_link, b"some random part data");
        assert!(result.is_err());
    }

    #[test]
    fn test_receive_unmatched_part_returns_not_all_received() {
        let mut sender_mgr = ResourceManager::new();
        let mut receiver_mgr = ResourceManager::new();
        let sender_link = LinkId::new([0xD4; 16]);
        let receiver_link = LinkId::new([0xD5; 16]);
        let key = make_test_derived_key();

        let (_hash, adv_bytes) = sender_mgr
            .prepare_outgoing(sender_link, b"unmatched part test data", &key)
            .unwrap();
        let (_recv_hash, _request_bytes) = receiver_mgr
            .accept_advertisement(receiver_link, &adv_bytes)
            .unwrap();

        // Send garbage data that won't match any map hash
        let garbage = vec![0xDE; 100];
        let result = receiver_mgr.receive_part(&receiver_link, &garbage).unwrap();
        assert!(
            !result.all_received,
            "garbage part should not complete transfer"
        );
    }

    #[test]
    fn test_assemble_incomplete_transfer_returns_error() {
        let mut sender_mgr = ResourceManager::new();
        let mut receiver_mgr = ResourceManager::new();
        let sender_link = LinkId::new([0xD6; 16]);
        let receiver_link = LinkId::new([0xD7; 16]);
        let key = make_test_derived_key();

        // Use enough data to produce multiple parts
        let data: Vec<u8> = (0..2000u16).map(|i| (i % 256) as u8).collect();
        let (_hash, adv_bytes) = sender_mgr
            .prepare_outgoing(sender_link, &data, &key)
            .unwrap();
        let (_recv_hash, request_bytes) = receiver_mgr
            .accept_advertisement(receiver_link, &adv_bytes)
            .unwrap();
        let (_link, parts) = sender_mgr.handle_part_request(&request_bytes).unwrap();
        assert!(parts.len() > 1, "need multiple parts for this test");

        // Only receive the first part
        let result = receiver_mgr
            .receive_part(&receiver_link, &parts[0])
            .unwrap();
        assert!(!result.all_received);

        // Attempt assembly with incomplete data — should fail
        let assembly = receiver_mgr.assemble_and_prove(&receiver_link, &key);
        assert!(
            assembly.is_err(),
            "assembly of incomplete transfer should fail"
        );
    }

    #[test]
    fn test_duplicate_advertisement_overwrites_no_panic() {
        let mut sender_mgr = ResourceManager::new();
        let mut receiver_mgr = ResourceManager::new();
        let sender_link = LinkId::new([0xD8; 16]);
        let receiver_link = LinkId::new([0xD9; 16]);
        let key = make_test_derived_key();

        let (_hash1, adv1) = sender_mgr
            .prepare_outgoing(sender_link, b"first data", &key)
            .unwrap();
        let (_hash2, adv2) = sender_mgr
            .prepare_outgoing(sender_link, b"second data", &key)
            .unwrap();

        // Accept the same link_id twice with different advertisements
        let (recv1, _req1) = receiver_mgr
            .accept_advertisement(receiver_link, &adv1)
            .unwrap();
        let (recv2, _req2) = receiver_mgr
            .accept_advertisement(receiver_link, &adv2)
            .unwrap();

        assert_ne!(
            recv1, recv2,
            "different data should produce different hashes"
        );
        assert_eq!(
            receiver_mgr.incoming.len(),
            1,
            "second should replace first"
        );
        assert_eq!(
            receiver_mgr
                .incoming
                .get(&receiver_link)
                .unwrap()
                .resource_hash,
            recv2,
            "should hold the second resource"
        );
    }

    #[test]
    fn test_receive_part_after_all_received_is_idempotent() {
        let mut sender_mgr = ResourceManager::new();
        let mut receiver_mgr = ResourceManager::new();
        let sender_link = LinkId::new([0xDA; 16]);
        let receiver_link = LinkId::new([0xDB; 16]);
        let key = make_test_derived_key();

        let data = b"idempotent receive test data";
        let (_hash, adv_bytes) = sender_mgr
            .prepare_outgoing(sender_link, data, &key)
            .unwrap();
        let (_recv_hash, request_bytes) = receiver_mgr
            .accept_advertisement(receiver_link, &adv_bytes)
            .unwrap();
        let (_link, parts) = sender_mgr.handle_part_request(&request_bytes).unwrap();

        // Receive all parts
        for part in &parts {
            receiver_mgr.receive_part(&receiver_link, part).unwrap();
        }

        // Receive the first part again — should not panic
        let extra_result = receiver_mgr.receive_part(&receiver_link, &parts[0]);
        assert!(
            extra_result.is_ok(),
            "duplicate part after completion should not panic"
        );
    }
}
