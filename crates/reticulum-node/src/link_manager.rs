//! Link lifecycle management for the node.
//!
//! Manages the complete link lifecycle: initiation, handshake, data exchange,
//! and teardown. Supports both responder mode (accepting incoming link requests)
//! and initiator mode (connecting to discovered destinations).

use std::collections::{HashMap, HashSet};

use reticulum_core::announce::Announce;
use reticulum_core::constants::MTU;
use reticulum_core::destination;
use reticulum_core::identity::Identity;
use reticulum_core::packet::context::ContextType;
use reticulum_core::packet::wire::RawPacket;
use reticulum_core::types::{DestinationHash, LinkId};

use reticulum_protocol::link::state::{LinkActive, LinkHandshake, LinkPending};
use reticulum_protocol::link::types::LinkMode;

use crate::link_packets::{
    build_delivery_proof_data, build_link_data_packet, build_link_data_packet_with_context,
    build_linkrequest_packet, build_lrproof_packet, build_lrrtt_packet, build_proof_packet,
    dest_hash_to_link_id,
};

use crate::config::LinkTargetEntry;

/// Actions to perform automatically after a link is established.
#[derive(Debug, Clone, Default)]
pub struct LinkAutoActions {
    pub auto_data: Option<String>,
    pub auto_resource: Option<String>,
    pub auto_channel: Option<String>,
    pub auto_buffer: Option<String>,
    pub auto_request_path: Option<String>,
    pub auto_request_data: Option<String>,
}

impl LinkAutoActions {
    fn from_target(target: &LinkTargetEntry) -> Self {
        Self {
            auto_data: target.auto_data.clone(),
            auto_resource: target.auto_resource.clone(),
            auto_channel: target.auto_channel.clone(),
            auto_buffer: target.auto_buffer.clone(),
            auto_request_path: target.auto_request_path.clone(),
            auto_request_data: target.auto_request_data.clone(),
        }
    }
}

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
    /// Ed25519 signing key seeds for active links: link_id → 32-byte seed
    /// Initiator: ephemeral Ed25519 key; Responder: identity Ed25519 key
    signing_keys: HashMap<LinkId, [u8; 32]>,
    /// Destinations we have active links to (for dedup on re-announce)
    linked_destinations: HashSet<DestinationHash>,
    /// Destinations queued for link initiation
    pending_link_targets: Vec<(DestinationHash, LinkAutoActions)>,
    /// Auto-data to send after link establishment (link_id → data)
    auto_data_queue: HashMap<LinkId, String>,
    /// Auto-resource to send after link establishment (link_id → data)
    auto_resource_queue: HashMap<LinkId, String>,
    /// Auto-channel message to send after link establishment (link_id → msg)
    auto_channel_queue: HashMap<LinkId, String>,
    /// Auto-buffer data to stream after link establishment (link_id → data)
    auto_buffer_queue: HashMap<LinkId, String>,
    /// Auto-request to send after link establishment (link_id → (path, data))
    auto_request_queue: HashMap<LinkId, (String, String)>,
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
            signing_keys: HashMap::new(),
            linked_destinations: HashSet::new(),
            pending_link_targets: Vec::new(),
            auto_data_queue: HashMap::new(),
            auto_resource_queue: HashMap::new(),
            auto_channel_queue: HashMap::new(),
            auto_buffer_queue: HashMap::new(),
            auto_request_queue: HashMap::new(),
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
        // Skip our own announces — don't self-link
        if self.local_destinations.contains_key(&dest_hash) {
            tracing::debug!(
                dest_hash = %hex::encode(dest_hash.as_ref()),
                "ignoring announce from our own destination"
            );
            return false;
        }

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
                        .push((dest_hash, LinkAutoActions::from_target(target)));
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
            || self.linked_destinations.contains(dest_hash)
    }

    /// Drain destinations queued for link initiation.
    pub fn drain_pending_targets(&mut self) -> Vec<(DestinationHash, LinkAutoActions)> {
        std::mem::take(&mut self.pending_link_targets)
    }

    /// Initiate a link to a remote destination (as initiator).
    ///
    /// Returns the raw packet bytes to broadcast.
    pub fn initiate_link(
        &mut self,
        dest_hash: DestinationHash,
        actions: LinkAutoActions,
    ) -> Option<Vec<u8>> {
        let identity = self.known_identities.get(&dest_hash)?;
        let _ = identity; // We need the identity later for proof verification

        // Two-pass LINKREQUEST construction: we need the hashable_part to compute
        // the link_id, but the hashable_part depends on the packet data, which
        // depends on ephemeral keys generated by LinkPending.

        // Pass 1: temporary packet with placeholder data to get initial hashable_part
        let (pending, request_data) = {
            let temp_raw = build_linkrequest_packet(dest_hash, vec![0u8; 67]);
            let temp_packet = RawPacket::parse(&temp_raw).expect("just built a valid packet");
            let hashable = temp_packet.hashable_part();

            match LinkPending::new_initiator(
                dest_hash,
                MTU as u32,
                LinkMode::default(),
                0,
                &hashable,
                67,
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

        // Pass 2: real packet with actual request data
        let raw = build_linkrequest_packet(dest_hash, request_data);
        let real_packet = RawPacket::parse(&raw).expect("just built a valid packet");
        let hashable = real_packet.hashable_part();
        let link_id = LinkPending::compute_link_id(&hashable, real_packet.data.len());

        tracing::info!(
            link_id = %hex::encode(link_id.as_ref()),
            dest_hash = %hex::encode(dest_hash.as_ref()),
            "initiating link request"
        );

        // Store auto-actions if configured
        if let Some(data) = actions.auto_data {
            self.auto_data_queue.insert(link_id, data);
        }
        if let Some(resource) = actions.auto_resource {
            self.auto_resource_queue.insert(link_id, resource);
        }
        if let Some(channel) = actions.auto_channel {
            self.auto_channel_queue.insert(link_id, channel);
        }
        if let Some(buffer) = actions.auto_buffer {
            self.auto_buffer_queue.insert(link_id, buffer);
        }
        if let Some(path) = actions.auto_request_path {
            let data = actions.auto_request_data.unwrap_or_default();
            self.auto_request_queue.insert(link_id, (path, data));
        }

        // Rebuild LinkPending with the real hashable_part
        let real_pending = {
            let eph_x25519 = pending.eph_x25519_private;
            let eph_ed25519 = pending.eph_ed25519_private;
            match LinkPending::new_initiator_deterministic(
                dest_hash,
                MTU as u32,
                LinkMode::default(),
                0,
                eph_x25519,
                eph_ed25519,
                &hashable,
                real_packet.data.len(),
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

        // Store identity Ed25519 seed for signing delivery proofs later
        let ed25519_seed = ed25519_prv.to_bytes();
        self.signing_keys.insert(link_id, ed25519_seed);

        tracing::info!(
            link_id = %hex::encode(link_id.as_ref()),
            "accepted link request, sending proof"
        );

        self.pending_responder.insert(link_id, handshake);

        Some(build_lrproof_packet(&link_id, proof_data))
    }

    /// Handle an incoming LRPROOF packet (as initiator).
    ///
    /// Returns the LRRTT packet bytes to broadcast, if valid.
    pub fn handle_lrproof(&mut self, packet: &RawPacket) -> Option<Vec<u8>> {
        let link_id = dest_hash_to_link_id(&packet.destination);

        let (pending, dest_hash) = self.pending_initiator.remove(&link_id)?;

        // Extract ephemeral Ed25519 seed BEFORE receive_proof consumes LinkPending
        let ed25519_seed = pending.eph_ed25519_private.to_bytes();

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

        let activated_link_id = active.link_id;
        let rtt_raw = build_lrrtt_packet(&activated_link_id, encrypted_rtt);

        self.active_links.insert(activated_link_id, active);
        self.linked_destinations.insert(dest_hash);
        // Store ephemeral Ed25519 seed for signing delivery proofs
        self.signing_keys.insert(activated_link_id, ed25519_seed);

        Some(rtt_raw)
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

        Some(build_link_data_packet(link_id, ciphertext))
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

    /// Drain auto-resource that should be sent for newly established links.
    pub fn drain_auto_resource(&mut self, link_id: &LinkId) -> Option<String> {
        self.auto_resource_queue.remove(link_id)
    }

    /// Drain auto-channel message for newly established links.
    pub fn drain_auto_channel(&mut self, link_id: &LinkId) -> Option<String> {
        self.auto_channel_queue.remove(link_id)
    }

    /// Drain auto-buffer data for newly established links.
    pub fn drain_auto_buffer(&mut self, link_id: &LinkId) -> Option<String> {
        self.auto_buffer_queue.remove(link_id)
    }

    /// Drain auto-request for newly established links.
    pub fn drain_auto_request(&mut self, link_id: &LinkId) -> Option<(String, String)> {
        self.auto_request_queue.remove(link_id)
    }

    /// Get the number of active links.
    pub fn active_link_count(&self) -> usize {
        self.active_links.len()
    }

    /// Encrypt and build a data packet with a specific context type.
    ///
    /// Like `encrypt_and_send` but sets `context_flag = true` and the given context.
    pub fn encrypt_and_send_with_context(
        &mut self,
        link_id: &LinkId,
        plaintext: &[u8],
        context: ContextType,
    ) -> Option<Vec<u8>> {
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

        Some(build_link_data_packet_with_context(link_id, ciphertext, context))
    }

    /// Build a link data packet with raw (unencrypted) data and a specific context.
    ///
    /// Used for RESOURCE packets where the resource layer handles its own encryption
    /// and the packet/link layer must NOT add another encryption layer.
    pub fn send_raw_with_context(
        &mut self,
        link_id: &LinkId,
        raw_data: &[u8],
        context: ContextType,
    ) -> Option<Vec<u8>> {
        let active = self.active_links.get_mut(link_id)?;
        active.record_outbound(raw_data.len() as u64);

        Some(build_link_data_packet_with_context(link_id, raw_data.to_vec(), context))
    }

    /// Extract raw data from a link packet without decrypting.
    ///
    /// Used for RESOURCE packets where the resource layer handles its own encryption
    /// and the packet/link layer must NOT decrypt.
    pub fn get_raw_link_data(&mut self, packet: &RawPacket) -> Option<Vec<u8>> {
        let link_id = dest_hash_to_link_id(&packet.destination);
        let active = self.active_links.get_mut(&link_id)?;
        active.record_inbound(packet.data.len() as u64);
        Some(packet.data.clone())
    }

    /// Get the derived key for an active link.
    pub fn get_derived_key(&self, link_id: &LinkId) -> Option<&reticulum_protocol::link::types::DerivedKey> {
        self.active_links.get(link_id).map(|a| &a.derived_key)
    }

    /// Get the RTT for an active link.
    pub fn get_rtt(&self, link_id: &LinkId) -> Option<f64> {
        self.active_links.get(link_id).map(|a| a.rtt)
    }

    /// Generate a delivery proof for an incoming link packet.
    ///
    /// Returns the serialized proof packet bytes. The proof format is:
    /// `packet_hash(32) + Ed25519_signature(64)` = 96 bytes, sent as a PROOF packet
    /// with `flags=0x0F, dest=link_id, context=None`.
    ///
    /// Python's Link.sign() uses Ed25519 (not HMAC), producing 64-byte signatures.
    /// The peer validates with Ed25519 verify using `peer_sig_pub`.
    pub fn prove_packet(&self, link_id: &LinkId, packet: &RawPacket) -> Option<Vec<u8>> {
        let _active = self.active_links.get(link_id)?;
        let ed25519_seed = self.signing_keys.get(link_id)?;

        let packet_hash = packet.packet_hash();
        let hash_bytes: [u8; 32] = packet_hash.as_ref().try_into().expect("PacketHash is 32 bytes");

        let proof_data = build_delivery_proof_data(&hash_bytes, ed25519_seed);

        Some(build_proof_packet(link_id, proof_data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reticulum_core::constants::{DestinationType, HeaderType, PacketType, TransportType};
    use reticulum_core::destination;
    use reticulum_core::packet::flags::PacketFlags;

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
            .push((DestinationHash::new([0x01; 16]), LinkAutoActions::default()));
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
            .initiate_link(
                resp_dh,
                LinkAutoActions {
                    auto_data: Some("hello".to_string()),
                    ..Default::default()
                },
            )
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
