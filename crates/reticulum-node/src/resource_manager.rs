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
use reticulum_protocol::resource::transfer::{
    assemble_resource, decode_part_request, decode_proof_payload, encode_part_request,
    encode_proof_payload, prepare_resource, validate_proof,
};

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
        let req =
            decode_part_request(request_data).map_err(|e| format!("decode part request: {e}"))?;

        let transfer = self
            .outgoing
            .get_mut(&req.resource_hash)
            .ok_or_else(|| format!("unknown resource hash: {}", hex::encode(req.resource_hash)))?;

        transfer.state = OutgoingState::Transferring;

        // Find parts matching the requested map hashes
        // The receiver sends back the map hashes of parts it needs.
        // For our simple MVP, the receiver requests ALL parts initially.
        // We match by iterating our parts and checking if their map hash is in the request.
        let mut result = Vec::new();

        // Build a hashmap to verify which parts are requested
        // For MVP: if the receiver sends all map hashes from the advertisement,
        // we send all parts in order.
        for part in &transfer.parts {
            result.push(part.clone());
        }

        tracing::info!(
            resource_hash = %hex::encode(req.resource_hash),
            parts_sent = result.len(),
            "handling part request"
        );

        Ok((transfer.link_id, result))
    }

    /// Handle a proof from the receiver.
    ///
    /// Returns true if the proof is valid and the transfer is complete.
    pub fn handle_proof(&mut self, proof_data: &[u8]) -> Result<bool, String> {
        let (resource_hash, _proof) =
            decode_proof_payload(proof_data).map_err(|e| format!("decode proof: {e}"))?;

        let transfer = self
            .outgoing
            .get_mut(&resource_hash)
            .ok_or_else(|| format!("unknown resource hash: {}", hex::encode(resource_hash)))?;

        if validate_proof(proof_data, &transfer.expected_proof) {
            transfer.state = OutgoingState::Complete;
            tracing::info!(
                resource_hash = %hex::encode(resource_hash),
                "resource_proof_verified"
            );
            Ok(true)
        } else {
            tracing::warn!(
                resource_hash = %hex::encode(resource_hash),
                "resource proof validation failed"
            );
            Ok(false)
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
        let adv = ResourceAdvertisement::from_msgpack(adv_bytes)
            .map_err(|e| format!("decode advertisement: {e}"))?;

        let flags = adv.decoded_flags();
        let resource_hash = adv.resource_hash;
        let random_hash = adv.random_hash;

        // Build hashmap from advertisement
        let hashmap = ResourceHashmap::from_bytes(&adv.hashmap, random_hash)
            .map_err(|e| format!("decode hashmap: {e}"))?;

        let num_parts = hashmap.len();

        // Build initial part request: request all parts
        let all_map_hashes: Vec<[u8; 4]> = (0..num_parts)
            .map(|i| *hashmap.get(i).unwrap())
            .collect();

        let request_bytes = encode_part_request(false, &resource_hash, &all_map_hashes, None);

        // Store incoming transfer state
        let parts = vec![None; num_parts];

        tracing::info!(
            resource_hash = %hex::encode(resource_hash),
            link_id = %hex::encode(link_id.as_ref()),
            num_parts,
            transfer_size = adv.transfer_size,
            data_size = adv.data_size,
            compressed = flags.compressed,
            "accepted resource advertisement"
        );

        self.incoming.insert(
            link_id,
            IncomingTransfer {
                advertisement: adv,
                flags,
                hashmap,
                parts,
                received_count: 0,
                resource_hash,
                random_hash,
            },
        );

        Ok((resource_hash, request_bytes))
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
        let transfer = self
            .incoming
            .get_mut(link_id)
            .ok_or_else(|| format!("no incoming transfer for link {}", hex::encode(link_id.as_ref())))?;

        // Find which part this is by matching its map hash
        let computed_hash = transfer.hashmap.compute_map_hash(part_data);
        let mut matched_index = None;

        for (i, stored) in transfer.parts.iter().enumerate() {
            if stored.is_none()
                && let Some(expected) = transfer.hashmap.get(i)
                && *expected == computed_hash
            {
                matched_index = Some(i);
                break;
            }
        }

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
        let transfer = self
            .incoming
            .get(link_id)
            .ok_or_else(|| format!("no incoming transfer for link {}", hex::encode(link_id.as_ref())))?;

        // Collect all parts in order
        let parts: Vec<Vec<u8>> = transfer
            .parts
            .iter()
            .enumerate()
            .map(|(i, p)| {
                p.clone()
                    .ok_or_else(|| format!("missing part {i}"))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let assembled = assemble_resource(
            &parts,
            derived_key.as_bytes(),
            &transfer.random_hash,
            &transfer.resource_hash,
            transfer.flags.compressed,
        )
        .map_err(|e| format!("assemble_resource failed: {e}"))?;

        let proof_bytes = encode_proof_payload(&assembled.resource_hash, &assembled.proof);

        tracing::info!(
            resource_hash = %hex::encode(assembled.resource_hash),
            data_len = assembled.data_with_metadata.len(),
            "resource_received"
        );

        Ok((assembled.data_with_metadata, proof_bytes))
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
        let (recv_hash, request_bytes) = mgr.accept_advertisement(recv_link_id, &adv_bytes).unwrap();
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
        let (resource_hash, adv_bytes) = sender_mgr.prepare_outgoing(sender_link, data, &key).unwrap();

        // 2. Receiver accepts advertisement
        let (_recv_hash, request_bytes) = receiver_mgr.accept_advertisement(receiver_link, &adv_bytes).unwrap();

        // 3. Sender handles part request
        let (_link, parts) = sender_mgr.handle_part_request(&request_bytes).unwrap();

        // 4. Receiver receives each part
        for part in &parts {
            let _result = receiver_mgr.receive_part(&receiver_link, part).unwrap();
        }

        // 5. Receiver assembles and proves
        let (received_data, proof_bytes) = receiver_mgr.assemble_and_prove(&receiver_link, &key).unwrap();
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
        let (resource_hash, adv_bytes) = sender_mgr.prepare_outgoing(sender_link, &data, &key).unwrap();
        let (_recv_hash, request_bytes) = receiver_mgr.accept_advertisement(receiver_link, &adv_bytes).unwrap();
        let (_link, parts) = sender_mgr.handle_part_request(&request_bytes).unwrap();

        assert!(parts.len() > 1, "expected multiple parts for 2KB data, got {}", parts.len());

        let mut all_received = false;
        for part in &parts {
            let result = receiver_mgr.receive_part(&receiver_link, part).unwrap();
            if result.all_received {
                all_received = true;
            }
        }
        assert!(all_received);

        let (received_data, proof_bytes) = receiver_mgr.assemble_and_prove(&receiver_link, &key).unwrap();
        assert_eq!(received_data, data);

        let valid = sender_mgr.handle_proof(&proof_bytes).unwrap();
        assert!(valid);
    }
}
