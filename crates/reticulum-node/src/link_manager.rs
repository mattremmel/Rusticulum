//! Link lifecycle management for the node.
//!
//! Manages the complete link lifecycle: initiation, handshake, data exchange,
//! and teardown. Supports both responder mode (accepting incoming link requests)
//! and initiator mode (connecting to discovered destinations).

use std::collections::HashMap;

use reticulum_core::announce::Announce;
use reticulum_core::constants::{DestinationType, HeaderType, MTU, PacketType, TransportType};
use reticulum_core::destination;
use reticulum_core::identity::Identity;
use reticulum_core::packet::context::ContextType;
use reticulum_core::packet::flags::PacketFlags;
use reticulum_core::packet::wire::RawPacket;
use reticulum_core::types::{DestinationHash, LinkId};

use reticulum_protocol::link::state::{LinkActive, LinkHandshake, LinkPending};
use reticulum_protocol::link::types::LinkMode;

use crate::config::LinkTargetEntry;

/// Information about a locally registered destination that accepts links.
#[allow(dead_code)]
struct LocalDestInfo {
    app_name: String,
    aspects: Vec<String>,
    dest_hash: DestinationHash,
}

/// Manages the link lifecycle for the node.
pub struct LinkManager {
    /// Local destinations that accept links: dest_hash → info
    local_destinations: HashMap<DestinationHash, LocalDestInfo>,
    /// Known remote identities from announces: dest_hash → Identity (public-only)
    known_identities: HashMap<DestinationHash, Identity>,
    /// Link targets for auto-linking on announce receipt
    link_targets: Vec<LinkTargetEntry>,
    /// Pending links as initiator: link_id → (LinkPending, target dest_hash)
    pending_initiator: HashMap<LinkId, (LinkPending, DestinationHash)>,
    /// Pending links as responder: link_id → LinkHandshake
    pending_responder: HashMap<LinkId, LinkHandshake>,
    /// Active links: link_id → LinkActive
    active_links: HashMap<LinkId, LinkActive>,
    /// Destinations queued for link initiation
    pending_link_targets: Vec<(DestinationHash, Option<String>)>,
    /// Auto-data to send after link establishment (link_id → data)
    auto_data_queue: HashMap<LinkId, String>,
}

impl LinkManager {
    /// Create a new empty LinkManager.
    pub fn new(link_targets: Vec<LinkTargetEntry>) -> Self {
        Self {
            local_destinations: HashMap::new(),
            known_identities: HashMap::new(),
            link_targets,
            pending_initiator: HashMap::new(),
            pending_responder: HashMap::new(),
            active_links: HashMap::new(),
            pending_link_targets: Vec::new(),
            auto_data_queue: HashMap::new(),
        }
    }

    /// Register a local destination that accepts links.
    pub fn register_local_destination(
        &mut self,
        dest_hash: DestinationHash,
        app_name: &str,
        aspects: &[String],
    ) {
        let info = LocalDestInfo {
            app_name: app_name.to_string(),
            aspects: aspects.to_vec(),
            dest_hash,
        };
        tracing::debug!(
            dest_hash = %hex::encode(dest_hash.as_ref()),
            app_name = app_name,
            "registered local destination for link acceptance"
        );
        self.local_destinations.insert(dest_hash, info);
    }

    /// Store a remote identity learned from a validated announce.
    /// Returns true if we should auto-link to this destination.
    pub fn register_identity_from_announce(
        &mut self,
        dest_hash: DestinationHash,
        announce: &Announce,
    ) -> bool {
        // Extract identity from announce public key bytes
        let identity = match Identity::from_public_bytes(&announce.public_key) {
            Ok(id) => id,
            Err(e) => {
                tracing::warn!(
                    dest_hash = %hex::encode(dest_hash.as_ref()),
                    "failed to construct identity from announce: {e}"
                );
                return false;
            }
        };

        self.known_identities.insert(dest_hash, identity);

        // Check if we should auto-link
        let name_hash = &announce.name_hash;
        for target in &self.link_targets {
            let aspect_refs: Vec<&str> = target.aspects.iter().map(|s| s.as_str()).collect();
            let target_nh = destination::name_hash(&target.app_name, &aspect_refs);
            if target_nh.as_ref() == name_hash.as_ref() {
                // Don't re-link to a destination we already have a link to or are pending with
                if !self.has_link_to_dest(&dest_hash) {
                    tracing::info!(
                        dest_hash = %hex::encode(dest_hash.as_ref()),
                        app_name = %target.app_name,
                        "queuing auto-link to announced destination"
                    );
                    self.pending_link_targets
                        .push((dest_hash, target.auto_data.clone()));
                    return true;
                }
            }
        }

        false
    }

    /// Check if we already have a pending or active link to a destination.
    fn has_link_to_dest(&self, dest_hash: &DestinationHash) -> bool {
        self.pending_initiator
            .values()
            .any(|(_, dh)| dh == dest_hash)
            || self.active_links.values().any(|_| {
                // We don't track dest_hash in active links directly,
                // but for now we rely on the pending_initiator check
                false
            })
    }

    /// Drain destinations queued for link initiation.
    pub fn drain_pending_targets(&mut self) -> Vec<(DestinationHash, Option<String>)> {
        std::mem::take(&mut self.pending_link_targets)
    }

    /// Initiate a link to a remote destination (as initiator).
    ///
    /// Returns the raw packet bytes to broadcast.
    pub fn initiate_link(
        &mut self,
        dest_hash: DestinationHash,
        auto_data: Option<String>,
    ) -> Option<Vec<u8>> {
        let identity = self.known_identities.get(&dest_hash)?;
        let _ = identity; // We need the identity later for proof verification

        // Build a LINKREQUEST packet
        // flags: HEADER_1 | BROADCAST | SINGLE | LINKREQUEST
        let flags = PacketFlags {
            header_type: HeaderType::Header1,
            context_flag: false,
            transport_type: TransportType::Broadcast,
            destination_type: DestinationType::Single,
            packet_type: PacketType::LinkRequest,
        };

        // Create LinkPending with random ephemeral keys
        // We need the hashable part to compute the link_id, but we need the packet
        // to compute the hashable part. Build a temporary packet to get hashable_part.
        let (pending, request_data) = {
            // Build a temporary packet to compute hashable_part
            let temp_packet = RawPacket {
                flags,
                hops: 0,
                transport_id: None,
                destination: dest_hash,
                context: ContextType::None,
                data: vec![0u8; 67], // placeholder data (64 + 3 signalling)
            };
            let hashable = temp_packet.hashable_part();

            // Now create the actual LinkPending
            match LinkPending::new_initiator(
                dest_hash,
                MTU as u32,
                LinkMode::default(),
                0, // hops (local, assume 0 for first attempt)
                &hashable,
                67, // data_len with signalling
            ) {
                Ok(result) => result,
                Err(e) => {
                    tracing::warn!(
                        dest_hash = %hex::encode(dest_hash.as_ref()),
                        "failed to create link request: {e}"
                    );
                    return None;
                }
            }
        };

        // Now build the real packet with the actual request data
        let packet = RawPacket {
            flags,
            hops: 0,
            transport_id: None,
            destination: dest_hash,
            context: ContextType::None,
            data: request_data,
        };

        // Recompute link_id from the real packet's hashable_part
        let hashable = packet.hashable_part();
        let link_id = LinkPending::compute_link_id(&hashable, packet.data.len());

        tracing::info!(
            link_id = %hex::encode(link_id.as_ref()),
            dest_hash = %hex::encode(dest_hash.as_ref()),
            "initiating link request"
        );

        // Store auto_data if configured
        if let Some(data) = auto_data {
            self.auto_data_queue.insert(link_id, data);
        }

        // The pending's link_id was computed from placeholder data.
        // We need to fix it by reconstructing with the real hashable part.
        // Actually, we should just reconstruct properly.
        // Let's rebuild from scratch with the correct approach.

        // Drop the miscomputed pending and rebuild
        let raw = packet.serialize();

        let real_pending = {
            let real_hashable = packet.hashable_part();
            let eph_x25519 = pending.eph_x25519_private;
            let eph_ed25519 = pending.eph_ed25519_private;
            match LinkPending::new_initiator_deterministic(
                dest_hash,
                MTU as u32,
                LinkMode::default(),
                0,
                eph_x25519,
                eph_ed25519,
                &real_hashable,
                packet.data.len(),
            ) {
                Ok((p, _)) => p,
                Err(e) => {
                    tracing::warn!("failed to rebuild link pending: {e}");
                    return None;
                }
            }
        };

        self.pending_initiator
            .insert(real_pending.link_id, (real_pending, dest_hash));

        Some(raw)
    }

    /// Handle an incoming LINKREQUEST packet (as responder).
    ///
    /// Returns the LRPROOF packet bytes to broadcast, if accepted.
    pub fn handle_link_request(
        &mut self,
        packet: &RawPacket,
        our_identity: &Identity,
    ) -> Option<Vec<u8>> {
        // Check if this destination is one we accept links for
        if !self.local_destinations.contains_key(&packet.destination) {
            return None;
        }

        let ed25519_prv = our_identity.ed25519_private()?;
        let ed25519_pub = our_identity.ed25519_public();

        let hashable = packet.hashable_part();

        let (handshake, proof_data) = match LinkHandshake::from_link_request(
            &packet.data,
            &hashable,
            packet.data.len(),
            ed25519_prv,
            ed25519_pub,
            MTU as u32,
            LinkMode::default(),
            packet.hops as u32,
        ) {
            Ok(result) => result,
            Err(e) => {
                tracing::warn!("failed to process link request: {e}");
                return None;
            }
        };

        let link_id = handshake.link_id;

        tracing::info!(
            link_id = %hex::encode(link_id.as_ref()),
            "accepted link request, sending proof"
        );

        // Build LRPROOF packet
        // flags: HEADER_1 | BROADCAST | LINK | PROOF = 0x0F
        // destination = link_id
        // context = Lrproof (0xFF)
        let proof_packet = RawPacket {
            flags: PacketFlags {
                header_type: HeaderType::Header1,
                context_flag: false,
                transport_type: TransportType::Broadcast,
                destination_type: DestinationType::Link,
                packet_type: PacketType::Proof,
            },
            hops: 0,
            transport_id: None,
            destination: link_id_to_dest_hash(&link_id),
            context: ContextType::Lrproof,
            data: proof_data,
        };

        self.pending_responder.insert(link_id, handshake);

        Some(proof_packet.serialize())
    }

    /// Handle an incoming LRPROOF packet (as initiator).
    ///
    /// Returns the LRRTT packet bytes to broadcast, if valid.
    pub fn handle_lrproof(&mut self, packet: &RawPacket) -> Option<Vec<u8>> {
        let link_id = dest_hash_to_link_id(&packet.destination);

        let (pending, dest_hash) = self.pending_initiator.remove(&link_id)?;

        // Get the responder's identity Ed25519 public key
        let identity = self.known_identities.get(&dest_hash)?;
        let responder_ed25519_pub = identity.ed25519_public();

        let (active, encrypted_rtt) =
            match pending.receive_proof(&packet.data, responder_ed25519_pub) {
                Ok(result) => result,
                Err(e) => {
                    tracing::warn!(
                        link_id = %hex::encode(link_id.as_ref()),
                        "failed to verify link proof: {e}"
                    );
                    return None;
                }
            };

        tracing::info!(
            link_id = %hex::encode(link_id.as_ref()),
            rtt = active.rtt,
            "link_established (initiator)"
        );

        // Build LRRTT packet
        // flags: HEADER_1 | BROADCAST | LINK | DATA = 0x0C
        // destination = link_id
        // context = Lrrtt (0xFE)
        let rtt_packet = RawPacket {
            flags: PacketFlags {
                header_type: HeaderType::Header1,
                context_flag: false,
                transport_type: TransportType::Broadcast,
                destination_type: DestinationType::Link,
                packet_type: PacketType::Data,
            },
            hops: 0,
            transport_id: None,
            destination: link_id_to_dest_hash(&active.link_id),
            context: ContextType::Lrrtt,
            data: encrypted_rtt,
        };

        self.active_links.insert(active.link_id, active);

        Some(rtt_packet.serialize())
    }

    /// Handle an incoming LRRTT packet (as responder).
    ///
    /// Returns the link_id if the link was successfully established.
    pub fn handle_lrrtt(&mut self, packet: &RawPacket) -> Option<LinkId> {
        let link_id = dest_hash_to_link_id(&packet.destination);
        let handshake = self.pending_responder.remove(&link_id)?;

        let active = match handshake.receive_rtt(&packet.data) {
            Ok(a) => a,
            Err(e) => {
                tracing::warn!(
                    link_id = %hex::encode(link_id.as_ref()),
                    "failed to process LRRTT: {e}"
                );
                return None;
            }
        };

        tracing::info!(
            link_id = %hex::encode(link_id.as_ref()),
            rtt = active.rtt,
            "link_established (responder)"
        );

        let id = active.link_id;
        self.active_links.insert(id, active);
        Some(id)
    }

    /// Handle incoming link data (encrypted).
    ///
    /// Returns the decrypted plaintext.
    pub fn handle_link_data(&mut self, packet: &RawPacket) -> Option<Vec<u8>> {
        let link_id = dest_hash_to_link_id(&packet.destination);
        let active = self.active_links.get_mut(&link_id)?;

        match active.decrypt(&packet.data) {
            Ok(plaintext) => {
                active.record_inbound(packet.data.len() as u64);
                Some(plaintext)
            }
            Err(e) => {
                tracing::warn!(
                    link_id = %hex::encode(link_id.as_ref()),
                    "failed to decrypt link data: {e}"
                );
                None
            }
        }
    }

    /// Encrypt and build a data packet for an active link.
    ///
    /// Returns the raw packet bytes to broadcast.
    pub fn encrypt_and_send(&mut self, link_id: &LinkId, plaintext: &[u8]) -> Option<Vec<u8>> {
        let active = self.active_links.get_mut(link_id)?;

        let ciphertext = match active.encrypt(plaintext) {
            Ok(ct) => ct,
            Err(e) => {
                tracing::warn!(
                    link_id = %hex::encode(link_id.as_ref()),
                    "failed to encrypt link data: {e}"
                );
                return None;
            }
        };

        active.record_outbound(ciphertext.len() as u64);

        // Build data packet: HEADER_1 | BROADCAST | LINK | DATA, context=None
        let packet = RawPacket {
            flags: PacketFlags {
                header_type: HeaderType::Header1,
                context_flag: false,
                transport_type: TransportType::Broadcast,
                destination_type: DestinationType::Link,
                packet_type: PacketType::Data,
            },
            hops: 0,
            transport_id: None,
            destination: link_id_to_dest_hash(link_id),
            context: ContextType::None,
            data: ciphertext,
        };

        Some(packet.serialize())
    }

    /// Check if a link_id belongs to any of our pending or active links.
    pub fn has_pending_or_active(&self, dest_hash: &DestinationHash) -> bool {
        let link_id = dest_hash_to_link_id(dest_hash);
        self.pending_initiator.contains_key(&link_id)
            || self.pending_responder.contains_key(&link_id)
            || self.active_links.contains_key(&link_id)
    }

    /// Drain auto-data that should be sent for newly established links.
    pub fn drain_auto_data(&mut self, link_id: &LinkId) -> Option<String> {
        self.auto_data_queue.remove(link_id)
    }

    /// Get the number of active links.
    pub fn active_link_count(&self) -> usize {
        self.active_links.len()
    }
}

/// Convert a LinkId to a DestinationHash (they're both 16 bytes).
fn link_id_to_dest_hash(link_id: &LinkId) -> DestinationHash {
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(link_id.as_ref());
    DestinationHash::new(bytes)
}

/// Convert a DestinationHash back to a LinkId.
fn dest_hash_to_link_id(dest_hash: &DestinationHash) -> LinkId {
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(dest_hash.as_ref());
    LinkId::new(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use reticulum_core::destination;

    #[test]
    fn test_link_id_dest_hash_roundtrip() {
        let link_id = LinkId::new([0xAB; 16]);
        let dh = link_id_to_dest_hash(&link_id);
        let back = dest_hash_to_link_id(&dh);
        assert_eq!(link_id.as_ref(), back.as_ref());
    }

    #[test]
    fn test_register_local_destination() {
        let mut mgr = LinkManager::new(vec![]);
        let dh = DestinationHash::new([0x01; 16]);
        mgr.register_local_destination(dh, "test_app", &["link".to_string(), "v1".to_string()]);
        assert!(mgr.local_destinations.contains_key(&dh));
    }

    #[test]
    fn test_drain_pending_targets() {
        let mut mgr = LinkManager::new(vec![]);
        assert!(mgr.drain_pending_targets().is_empty());

        mgr.pending_link_targets
            .push((DestinationHash::new([0x01; 16]), Some("hello".to_string())));
        let targets = mgr.drain_pending_targets();
        assert_eq!(targets.len(), 1);
        assert!(mgr.drain_pending_targets().is_empty());
    }

    #[test]
    fn test_full_handshake_rust_only() {
        // Simulate a complete handshake between two identities
        let responder_identity = Identity::generate();
        let _initiator_identity = Identity::generate();

        // Set up responder's LinkManager
        let aspect_refs = &["link", "v1"];
        let nh = destination::name_hash("link_test", aspect_refs);
        let resp_dh = destination::destination_hash(&nh, responder_identity.hash());

        let mut resp_mgr = LinkManager::new(vec![]);
        resp_mgr.register_local_destination(
            resp_dh,
            "link_test",
            &["link".to_string(), "v1".to_string()],
        );

        // Set up initiator's LinkManager with the responder identity
        let mut init_mgr = LinkManager::new(vec![]);
        // Store responder's identity
        let resp_pub_identity =
            Identity::from_public_bytes(&responder_identity.public_key_bytes()).unwrap();
        init_mgr.known_identities.insert(resp_dh, resp_pub_identity);

        // Step 1: Initiator creates LINKREQUEST
        let lr_raw = init_mgr
            .initiate_link(resp_dh, Some("hello".to_string()))
            .expect("should create link request");

        // Step 2: Responder processes LINKREQUEST
        let lr_packet = RawPacket::parse(&lr_raw).expect("should parse link request");
        assert_eq!(lr_packet.flags.packet_type, PacketType::LinkRequest);
        assert_eq!(lr_packet.flags.destination_type, DestinationType::Single);

        let proof_raw = resp_mgr
            .handle_link_request(&lr_packet, &responder_identity)
            .expect("should accept link request");

        // Step 3: Initiator processes LRPROOF
        let proof_packet = RawPacket::parse(&proof_raw).expect("should parse proof");
        assert_eq!(proof_packet.flags.packet_type, PacketType::Proof);
        assert_eq!(proof_packet.flags.destination_type, DestinationType::Link);
        assert_eq!(proof_packet.context, ContextType::Lrproof);

        let rtt_raw = init_mgr
            .handle_lrproof(&proof_packet)
            .expect("should accept proof");

        // Initiator should now have an active link
        assert_eq!(init_mgr.active_links.len(), 1);

        // Step 4: Responder processes LRRTT
        let rtt_packet = RawPacket::parse(&rtt_raw).expect("should parse LRRTT");
        assert_eq!(rtt_packet.context, ContextType::Lrrtt);

        let link_id = resp_mgr
            .handle_lrrtt(&rtt_packet)
            .expect("should complete handshake");

        // Responder should now have an active link
        assert_eq!(resp_mgr.active_links.len(), 1);

        // Step 5: Test encrypted data exchange
        let test_data = b"hello from initiator";
        let data_raw = init_mgr
            .encrypt_and_send(&link_id, test_data)
            .expect("should encrypt data");

        let data_packet = RawPacket::parse(&data_raw).expect("should parse data");
        assert_eq!(data_packet.flags.destination_type, DestinationType::Link);
        assert_eq!(data_packet.context, ContextType::None);

        let plaintext = resp_mgr
            .handle_link_data(&data_packet)
            .expect("should decrypt data");
        assert_eq!(plaintext, test_data);

        // Step 6: Auto-data should be drainable
        let auto = init_mgr.drain_auto_data(&link_id);
        assert_eq!(auto.as_deref(), Some("hello"));
    }

    #[test]
    fn test_handle_link_request_unknown_destination() {
        let identity = Identity::generate();
        let mut mgr = LinkManager::new(vec![]);

        // Build a fake link request packet
        let packet = RawPacket {
            flags: PacketFlags {
                header_type: HeaderType::Header1,
                context_flag: false,
                transport_type: TransportType::Broadcast,
                destination_type: DestinationType::Single,
                packet_type: PacketType::LinkRequest,
            },
            hops: 0,
            transport_id: None,
            destination: DestinationHash::new([0xFF; 16]),
            context: ContextType::None,
            data: vec![0u8; 64],
        };

        // Should return None since no local destinations registered
        assert!(mgr.handle_link_request(&packet, &identity).is_none());
    }
}
