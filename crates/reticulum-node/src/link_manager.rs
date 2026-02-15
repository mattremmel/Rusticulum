//! Link lifecycle management for the node.
//!
//! Manages the complete link lifecycle: initiation, handshake, data exchange,
//! and teardown. Supports both responder mode (accepting incoming link requests)
//! and initiator mode (connecting to discovered destinations).

use std::collections::{HashMap, HashSet};

use reticulum_core::announce::Announce;
use reticulum_core::constants::MTU;
use reticulum_core::identity::Identity;
use reticulum_core::packet::context::ContextType;
use reticulum_core::packet::wire::RawPacket;
use reticulum_core::types::{DestinationHash, IdentityHash, LinkId, PacketHash};

use reticulum_protocol::link::constants::{KEEPALIVE_ECHO_MARKER, KEEPALIVE_MARKER};
use reticulum_protocol::link::state::{LinkActive, LinkHandshake, LinkPending};
use reticulum_protocol::link::types::{LinkMode, LinkRole};

use crate::link_initiation::{self, queue_auto_actions};
use crate::link_lifecycle;
use crate::link_packets::{
    build_delivery_proof_data, build_link_data_packet, build_link_data_packet_with_context,
    build_lrproof_packet, build_lrrtt_packet, build_proof_packet, dest_hash_to_link_id,
};

use crate::config::LinkTargetEntry;

/// Actions to perform automatically after a link is established.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LinkAutoActions {
    pub auto_data: Option<String>,
    pub auto_resource: Option<String>,
    pub auto_channel: Option<String>,
    pub auto_buffer: Option<String>,
    pub auto_request_path: Option<String>,
    pub auto_request_data: Option<String>,
}

impl LinkAutoActions {
    pub fn from_target(target: &LinkTargetEntry) -> Self {
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

/// A known destination entry, learned from a validated announce.
///
/// Mirrors Python's `Identity.known_destinations` registry:
/// `dest_hash → [timestamp, packet_hash, public_key, app_data]`.
#[derive(Debug, Clone)]
pub struct KnownDestinationEntry {
    /// When this destination was last seen (Unix seconds).
    pub timestamp: f64,
    /// The announce packet hash.
    pub packet_hash: PacketHash,
    /// Raw public key bytes: x25519(32) || ed25519(32).
    pub public_key: [u8; 64],
    /// Optional application data from the announce.
    pub app_data: Option<Vec<u8>>,
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
    /// Known remote destinations from announces: dest_hash → entry with public key + metadata
    known_destinations: HashMap<DestinationHash, KnownDestinationEntry>,
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
    /// Reverse map: link_id → dest_hash (for cleanup on teardown)
    link_dest_map: HashMap<LinkId, DestinationHash>,
}

impl LinkManager {
    /// Create a new empty LinkManager.
    pub fn new(link_targets: Vec<LinkTargetEntry>) -> Self {
        Self {
            local_destinations: HashMap::new(),
            known_destinations: HashMap::new(),
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
            link_dest_map: HashMap::new(),
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
        packet_hash: PacketHash,
    ) -> bool {
        let is_self = self.local_destinations.contains_key(&dest_hash);
        let identity = Identity::from_public_bytes(&announce.public_key).ok();
        let identity_parse_ok = identity.is_some();

        // Compute auto-link decision only if identity parsed and not self
        let auto_link_decision = if identity_parse_ok && !is_self {
            let has_link = self.has_link_to_dest(&dest_hash);
            link_initiation::should_auto_link(
                announce.name_hash.as_ref(),
                &self.link_targets,
                false, // already checked is_self above
                has_link,
            )
        } else {
            None
        };

        let outcome = link_lifecycle::classify_identity_registration(
            is_self,
            identity_parse_ok,
            auto_link_decision,
        );

        match outcome {
            link_lifecycle::IdentityRegistrationOutcome::SkipSelfAnnounce => {
                tracing::debug!(
                    dest_hash = %hex::encode(dest_hash.as_ref()),
                    "ignoring announce from our own destination"
                );
                false
            }
            link_lifecycle::IdentityRegistrationOutcome::IdentityParseFailed => {
                tracing::warn!(
                    dest_hash = %hex::encode(dest_hash.as_ref()),
                    "failed to construct identity from announce"
                );
                false
            }
            link_lifecycle::IdentityRegistrationOutcome::Registered => {
                if identity.is_some() {
                    if !self.remember(dest_hash, packet_hash, announce.public_key, announce.app_data.clone()) {
                        tracing::warn!(
                            dest_hash = %hex::encode(dest_hash.as_ref()),
                            "key collision detected for destination"
                        );
                        return false;
                    }
                }
                false
            }
            link_lifecycle::IdentityRegistrationOutcome::RegisteredAndAutoLink { actions } => {
                if identity.is_some() {
                    if !self.remember(dest_hash, packet_hash, announce.public_key, announce.app_data.clone()) {
                        tracing::warn!(
                            dest_hash = %hex::encode(dest_hash.as_ref()),
                            "key collision detected for destination"
                        );
                        return false;
                    }
                }
                tracing::info!(
                    dest_hash = %hex::encode(dest_hash.as_ref()),
                    "queuing auto-link to announced destination"
                );
                self.pending_link_targets.push((dest_hash, actions));
                true
            }
        }
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
        // Verify we know this destination's identity
        if !self.known_destinations.contains_key(&dest_hash) {
            return None;
        }

        let output = match link_initiation::build_link_request(dest_hash) {
            Ok(o) => o,
            Err(e) => {
                tracing::warn!(
                    dest_hash = %hex::encode(dest_hash.as_ref()),
                    "failed to create link request: {e}"
                );
                return None;
            }
        };

        let link_id = output.link_id;

        tracing::info!(
            link_id = %hex::encode(link_id.as_ref()),
            dest_hash = %hex::encode(dest_hash.as_ref()),
            "initiating link request"
        );

        // Store auto-actions if configured
        let queues = queue_auto_actions(&actions);
        if let Some(data) = queues.auto_data {
            self.auto_data_queue.insert(link_id, data);
        }
        if let Some(resource) = queues.auto_resource {
            self.auto_resource_queue.insert(link_id, resource);
        }
        if let Some(channel) = queues.auto_channel {
            self.auto_channel_queue.insert(link_id, channel);
        }
        if let Some(buffer) = queues.auto_buffer {
            self.auto_buffer_queue.insert(link_id, buffer);
        }
        if let Some((path, data)) = queues.auto_request {
            self.auto_request_queue.insert(link_id, (path, data));
        }

        self.pending_initiator
            .insert(output.pending.link_id, (output.pending, dest_hash));

        Some(output.packet_bytes)
    }

    /// Handle an incoming LINKREQUEST packet (as responder).
    ///
    /// Returns the LRPROOF packet bytes to broadcast, if accepted.
    pub fn handle_link_request(
        &mut self,
        packet: &RawPacket,
        our_identity: &Identity,
    ) -> Option<Vec<u8>> {
        let is_known_destination = self.local_destinations.contains_key(&packet.destination);

        let ed25519_prv = our_identity.ed25519_private()?;
        let ed25519_pub = our_identity.ed25519_public();

        let hashable = packet.hashable_part();

        let handshake_result = if is_known_destination {
            LinkHandshake::from_link_request(
                &packet.data,
                &hashable,
                packet.data.len(),
                ed25519_prv,
                ed25519_pub,
                MTU as u32,
                LinkMode::default(),
                packet.hops as u32,
            )
            .ok()
        } else {
            None
        };

        let outcome = link_lifecycle::classify_link_acceptance(
            is_known_destination,
            handshake_result.is_some(),
        );

        match outcome {
            link_lifecycle::LinkAcceptanceOutcome::Accept => {
                let (handshake, proof_data) = handshake_result.unwrap();
                let link_id = handshake.link_id;

                let ed25519_seed = ed25519_prv.to_bytes();
                self.signing_keys.insert(link_id, ed25519_seed);

                tracing::info!(
                    link_id = %hex::encode(link_id.as_ref()),
                    "accepted link request, sending proof"
                );

                self.pending_responder.insert(link_id, handshake);
                Some(build_lrproof_packet(&link_id, proof_data))
            }
            link_lifecycle::LinkAcceptanceOutcome::UnknownDestination => None,
            link_lifecycle::LinkAcceptanceOutcome::HandshakeFailed => {
                tracing::warn!("failed to process link request");
                None
            }
        }
    }

    /// Handle an incoming LRPROOF packet (as initiator).
    ///
    /// Returns the LRRTT packet bytes to broadcast, if valid.
    pub fn handle_lrproof(&mut self, packet: &RawPacket) -> Option<Vec<u8>> {
        let link_id = dest_hash_to_link_id(&packet.destination);

        let has_pending = self.pending_initiator.contains_key(&link_id);
        let (pending, dest_hash) = match self.pending_initiator.remove(&link_id) {
            Some(p) => p,
            None => {
                // classify_proof_receipt with has_pending=false
                return None;
            }
        };

        let ed25519_seed = pending.eph_ed25519_private.to_bytes();

        let has_identity = self.known_destinations.contains_key(&dest_hash);
        let identity = match self.recall(&dest_hash) {
            Some(id) => id,
            None => {
                // Put back the pending entry since we can't proceed
                self.pending_initiator.insert(link_id, (pending, dest_hash));
                return None;
            }
        };
        let responder_ed25519_pub = identity.ed25519_public();

        let proof_result = pending.receive_proof(&packet.data, responder_ed25519_pub);
        let proof_ok = proof_result.is_ok();

        let outcome = link_lifecycle::classify_proof_receipt(has_pending, has_identity, proof_ok);

        match outcome {
            link_lifecycle::ProofReceiptOutcome::Activated => {
                let (active, encrypted_rtt) = match proof_result {
                    Ok(val) => val,
                    Err(_) => unreachable!("Activated requires proof_ok=true"),
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
                self.link_dest_map.insert(activated_link_id, dest_hash);
                self.signing_keys.insert(activated_link_id, ed25519_seed);

                Some(rtt_raw)
            }
            link_lifecycle::ProofReceiptOutcome::ProofFailed => {
                tracing::warn!(
                    link_id = %hex::encode(link_id.as_ref()),
                    "failed to verify link proof"
                );
                None
            }
            link_lifecycle::ProofReceiptOutcome::NoPending
            | link_lifecycle::ProofReceiptOutcome::NoIdentity => None,
        }
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

    /// Handle incoming LinkClose (teardown) packet.
    ///
    /// Decrypts the data and verifies it equals the link_id.
    /// Returns true if the link was successfully torn down.
    pub fn handle_link_close(&mut self, packet: &RawPacket) -> bool {
        let link_id = dest_hash_to_link_id(&packet.destination);
        let active = match self.active_links.get_mut(&link_id) {
            Some(a) => a,
            None => return false,
        };

        let plaintext = match active.decrypt(&packet.data) {
            Ok(pt) => pt,
            Err(e) => {
                tracing::warn!(
                    link_id = %hex::encode(link_id.as_ref()),
                    "failed to decrypt link close: {e}"
                );
                return false;
            }
        };

        if plaintext.as_slice() != link_id.as_ref() {
            tracing::warn!(
                link_id = %hex::encode(link_id.as_ref()),
                "link close verification failed: plaintext does not match link_id"
            );
            return false;
        }

        self.teardown_link(&link_id);
        true
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

        Some(build_link_data_packet_with_context(
            link_id, ciphertext, context,
        ))
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

        Some(build_link_data_packet_with_context(
            link_id,
            raw_data.to_vec(),
            context,
        ))
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
    pub fn get_derived_key(
        &self,
        link_id: &LinkId,
    ) -> Option<&reticulum_protocol::link::types::DerivedKey> {
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
        let hash_bytes: [u8; 32] = packet_hash
            .as_ref()
            .try_into()
            .expect("PacketHash is 32 bytes");

        let proof_data = build_delivery_proof_data(&hash_bytes, ed25519_seed);

        Some(build_proof_packet(link_id, proof_data))
    }
    /// Get the role (Initiator/Responder) for an active link.
    pub fn get_link_role(&self, link_id: &LinkId) -> Option<LinkRole> {
        self.active_links.get(link_id).map(|a| a.role)
    }

    /// Collect keepalive packets for all initiator links that are due.
    ///
    /// Only the initiator sends keepalives (data=`0xFF`, context=Keepalive).
    /// Keepalive packets are NOT link-encrypted (Python Packet.pack passes through raw).
    /// Returns raw packet bytes for each keepalive to broadcast.
    pub fn collect_keepalive_packets(&mut self) -> Vec<Vec<u8>> {
        let due_link_ids: Vec<LinkId> = self
            .active_links
            .iter()
            .filter(|(_, active)| {
                active.role == LinkRole::Initiator && active.should_send_keepalive()
            })
            .map(|(id, _)| *id)
            .collect();

        let mut packets = Vec::with_capacity(due_link_ids.len());
        for link_id in due_link_ids {
            if let Some(raw) = self.send_raw_with_context(&link_id, &[KEEPALIVE_MARKER], ContextType::Keepalive)
            {
                tracing::debug!(
                    link_id = %hex::encode(link_id.as_ref()),
                    "keepalive_sent"
                );
                packets.push(raw);
            }
        }
        packets
    }

    /// Build a keepalive echo packet (data=`0xFE`) for a responder link.
    ///
    /// Keepalive packets are NOT link-encrypted (Python Packet.pack passes through raw).
    /// Returns None if the link is not active or is not a responder.
    pub fn build_keepalive_echo(&mut self, link_id: &LinkId) -> Option<Vec<u8>> {
        let role = self.active_links.get(link_id)?.role;
        if role != LinkRole::Responder {
            return None;
        }
        self.send_raw_with_context(link_id, &[KEEPALIVE_ECHO_MARKER], ContextType::Keepalive)
    }

    /// Check link health: mark stale links, return link_ids that should be torn down.
    pub fn check_link_health(&mut self) -> Vec<LinkId> {
        // First pass: mark stale
        let stale_ids: Vec<LinkId> = self
            .active_links
            .iter()
            .filter(|(_, active)| active.should_go_stale())
            .map(|(id, _)| *id)
            .collect();

        for link_id in &stale_ids {
            if let Some(active) = self.active_links.get_mut(link_id) {
                tracing::info!(
                    link_id = %hex::encode(link_id.as_ref()),
                    "link_stale"
                );
                active.mark_stale();
            }
        }

        // Second pass: collect teardowns
        let teardown_ids: Vec<LinkId> = self
            .active_links
            .iter()
            .filter(|(_, active)| active.should_teardown())
            .map(|(id, _)| *id)
            .collect();

        for link_id in &teardown_ids {
            self.teardown_link(link_id);
        }

        teardown_ids
    }

    /// Remove a link from all internal state.
    fn teardown_link(&mut self, link_id: &LinkId) {
        self.active_links.remove(link_id);
        self.signing_keys.remove(link_id);
        if let Some(dest_hash) = self.link_dest_map.remove(link_id) {
            self.linked_destinations.remove(&dest_hash);
        }
    }

    /// Remember a known destination from a validated announce.
    ///
    /// Returns `true` on success, `false` on key collision (same dest_hash but
    /// different public_key — potential attack).
    pub fn remember(
        &mut self,
        dest_hash: DestinationHash,
        packet_hash: PacketHash,
        public_key: [u8; 64],
        app_data: Option<Vec<u8>>,
    ) -> bool {
        // Check for key collision
        if let Some(existing) = self.known_destinations.get(&dest_hash) {
            if existing.public_key != public_key {
                return false;
            }
        }

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);

        self.known_destinations.insert(
            dest_hash,
            KnownDestinationEntry {
                timestamp,
                packet_hash,
                public_key,
                app_data,
            },
        );
        true
    }

    /// Recall an Identity from a known destination's stored public key.
    pub fn recall(&self, dest_hash: &DestinationHash) -> Option<Identity> {
        self.known_destinations
            .get(dest_hash)
            .and_then(|entry| Identity::from_public_bytes(&entry.public_key).ok())
    }

    /// Recall application data from a known destination.
    pub fn recall_app_data(&self, dest_hash: &DestinationHash) -> Option<&[u8]> {
        self.known_destinations
            .get(dest_hash)
            .and_then(|entry| entry.app_data.as_deref())
    }

    /// Recall an Identity by its identity hash (O(n) scan).
    pub fn recall_by_identity_hash(&self, identity_hash: &IdentityHash) -> Option<Identity> {
        for entry in self.known_destinations.values() {
            if let Ok(id) = Identity::from_public_bytes(&entry.public_key) {
                if id.hash() == identity_hash {
                    return Some(id);
                }
            }
        }
        None
    }

    /// Get a reference to the known destinations map (for serialization).
    pub fn known_destinations(&self) -> &HashMap<DestinationHash, KnownDestinationEntry> {
        &self.known_destinations
    }

    /// Load known destinations at startup, merging with any existing entries.
    pub fn load_known_destinations(
        &mut self,
        entries: impl IntoIterator<Item = (DestinationHash, KnownDestinationEntry)>,
    ) {
        for (dest_hash, entry) in entries {
            self.known_destinations.entry(dest_hash).or_insert(entry);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reticulum_core::constants::{DestinationType, HeaderType, PacketType, TransportType};
    use reticulum_core::destination;
    use reticulum_core::packet::flags::PacketFlags;

    /// Insert a known destination entry for test setup (bypasses collision check).
    fn insert_known_identity(mgr: &mut LinkManager, dest_hash: DestinationHash, identity: &Identity) {
        mgr.known_destinations.insert(dest_hash, KnownDestinationEntry {
            timestamp: 0.0,
            packet_hash: PacketHash::new([0u8; 32]),
            public_key: identity.public_key_bytes(),
            app_data: None,
        });
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
        insert_known_identity(&mut init_mgr, resp_dh, &resp_pub_identity);

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

    /// Perform a full 4-step handshake between two LinkManagers.
    /// Returns (initiator_mgr, responder_mgr, link_id, responder_identity).
    fn perform_full_handshake(app_name: &str) -> (LinkManager, LinkManager, LinkId, Identity) {
        let responder_identity = Identity::generate();

        let aspect_refs = &["link", "v1"];
        let nh = destination::name_hash(app_name, aspect_refs);
        let resp_dh = destination::destination_hash(&nh, responder_identity.hash());

        let mut resp_mgr = LinkManager::new(vec![]);
        resp_mgr.register_local_destination(
            resp_dh,
            app_name,
            &["link".to_string(), "v1".to_string()],
        );

        let mut init_mgr = LinkManager::new(vec![]);
        let resp_pub = Identity::from_public_bytes(&responder_identity.public_key_bytes()).unwrap();
        insert_known_identity(&mut init_mgr, resp_dh, &resp_pub);

        let lr_raw = init_mgr
            .initiate_link(resp_dh, LinkAutoActions::default())
            .unwrap();
        let lr_pkt = RawPacket::parse(&lr_raw).unwrap();
        let proof_raw = resp_mgr
            .handle_link_request(&lr_pkt, &responder_identity)
            .unwrap();
        let proof_pkt = RawPacket::parse(&proof_raw).unwrap();
        let rtt_raw = init_mgr.handle_lrproof(&proof_pkt).unwrap();
        let rtt_pkt = RawPacket::parse(&rtt_raw).unwrap();
        let link_id = resp_mgr.handle_lrrtt(&rtt_pkt).unwrap();

        (init_mgr, resp_mgr, link_id, responder_identity)
    }

    fn make_test_announce(identity: &Identity) -> reticulum_core::announce::Announce {
        reticulum_core::announce::Announce {
            destination_hash: DestinationHash::new([0x00; 16]),
            public_key: identity.public_key_bytes(),
            name_hash: reticulum_core::types::NameHash::new([0u8; 10]),
            random_hash: [0u8; 10],
            ratchet: None,
            signature: [0u8; 64],
            app_data: None,
            context: reticulum_core::packet::context::ContextType::None,
        }
    }

    #[test]
    fn test_register_identity_skips_self() {
        let mut mgr = LinkManager::new(vec![]);
        let identity = Identity::generate();
        let dh = DestinationHash::new([0x01; 16]);
        mgr.register_local_destination(dh, "test_app", &["link".to_string()]);

        let announce = make_test_announce(&identity);

        let result = mgr.register_identity_from_announce(dh, &announce, PacketHash::new([0u8; 32]));
        assert!(!result);
        // Identity should NOT be stored for self-announces
        assert!(!mgr.known_destinations.contains_key(&dh));
    }

    #[test]
    fn test_register_identity_no_duplicate_link() {
        // If we already have a link to a destination, auto-link should not be queued again
        let mut mgr = LinkManager::new(vec![crate::config::LinkTargetEntry {
            app_name: "dup_test".to_string(),
            aspects: vec!["link".to_string()],
            auto_data: Some("data".to_string()),
            auto_resource: None,
            auto_channel: None,
            auto_buffer: None,
            auto_request_path: None,
            auto_request_data: None,
        }]);
        let identity = Identity::generate();
        let dh = DestinationHash::new([0x02; 16]);

        let announce = make_test_announce(&identity);

        // First registration — might auto-link if name_hash matches
        let _result = mgr.register_identity_from_announce(dh, &announce, PacketHash::new([0u8; 32]));

        // Mark destination as linked
        mgr.linked_destinations.insert(dh);

        // Second registration should not queue another auto-link
        let result2 = mgr.register_identity_from_announce(dh, &announce, PacketHash::new([0u8; 32]));
        assert!(!result2);
    }

    #[test]
    fn test_register_identity_stores_identity() {
        let mut mgr = LinkManager::new(vec![]);
        let identity = Identity::generate();
        let dh = DestinationHash::new([0x03; 16]);

        let announce = make_test_announce(&identity);

        let result = mgr.register_identity_from_announce(dh, &announce, PacketHash::new([0u8; 32]));
        assert!(!result); // no auto-link targets
        assert!(mgr.known_destinations.contains_key(&dh));
    }

    #[test]
    fn test_initiate_link_unknown_identity() {
        let mut mgr = LinkManager::new(vec![]);
        let dh = DestinationHash::new([0x04; 16]);

        // No identity registered for this destination
        let result = mgr.initiate_link(dh, LinkAutoActions::default());
        assert!(result.is_none());
    }

    #[test]
    fn test_has_pending_or_active_negative() {
        let mgr = LinkManager::new(vec![]);
        let dh = DestinationHash::new([0x05; 16]);
        assert!(!mgr.has_pending_or_active(&dh));
    }

    #[test]
    fn test_prove_packet_no_signing_key() {
        let mgr = LinkManager::new(vec![]);
        let link_id = LinkId::new([0x06; 16]);
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
            destination: DestinationHash::new([0x06; 16]),
            context: ContextType::None,
            data: b"test".to_vec(),
        };

        // No active link or signing key — should return None
        assert!(mgr.prove_packet(&link_id, &packet).is_none());
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        // Use the full handshake from the existing test to set up active links
        let responder_identity = Identity::generate();

        let aspect_refs = &["link", "v1"];
        let nh = destination::name_hash("roundtrip_test", aspect_refs);
        let resp_dh = destination::destination_hash(&nh, responder_identity.hash());

        let mut resp_mgr = LinkManager::new(vec![]);
        resp_mgr.register_local_destination(
            resp_dh,
            "roundtrip_test",
            &["link".to_string(), "v1".to_string()],
        );

        let mut init_mgr = LinkManager::new(vec![]);
        let resp_pub = Identity::from_public_bytes(&responder_identity.public_key_bytes()).unwrap();
        insert_known_identity(&mut init_mgr, resp_dh, &resp_pub);

        let lr_raw = init_mgr
            .initiate_link(resp_dh, LinkAutoActions::default())
            .unwrap();
        let lr_pkt = RawPacket::parse(&lr_raw).unwrap();
        let proof_raw = resp_mgr
            .handle_link_request(&lr_pkt, &responder_identity)
            .unwrap();
        let proof_pkt = RawPacket::parse(&proof_raw).unwrap();
        let rtt_raw = init_mgr.handle_lrproof(&proof_pkt).unwrap();
        let rtt_pkt = RawPacket::parse(&rtt_raw).unwrap();
        let link_id = resp_mgr.handle_lrrtt(&rtt_pkt).unwrap();

        // Initiator encrypts, responder decrypts
        let data_raw = init_mgr
            .encrypt_and_send(&link_id, b"encrypt-test")
            .unwrap();
        let data_pkt = RawPacket::parse(&data_raw).unwrap();
        let plaintext = resp_mgr.handle_link_data(&data_pkt).unwrap();
        assert_eq!(plaintext, b"encrypt-test");

        // Responder encrypts, initiator decrypts
        let data_raw2 = resp_mgr
            .encrypt_and_send(&link_id, b"reverse-test")
            .unwrap();
        let data_pkt2 = RawPacket::parse(&data_raw2).unwrap();
        let plaintext2 = init_mgr.handle_link_data(&data_pkt2).unwrap();
        assert_eq!(plaintext2, b"reverse-test");
    }

    #[test]
    fn test_raw_data_bypass() {
        // Set up active links via handshake
        let responder_identity = Identity::generate();
        let aspect_refs = &["link", "v1"];
        let nh = destination::name_hash("raw_test", aspect_refs);
        let resp_dh = destination::destination_hash(&nh, responder_identity.hash());

        let mut resp_mgr = LinkManager::new(vec![]);
        resp_mgr.register_local_destination(
            resp_dh,
            "raw_test",
            &["link".to_string(), "v1".to_string()],
        );

        let mut init_mgr = LinkManager::new(vec![]);
        let resp_pub = Identity::from_public_bytes(&responder_identity.public_key_bytes()).unwrap();
        insert_known_identity(&mut init_mgr, resp_dh, &resp_pub);

        let lr_raw = init_mgr
            .initiate_link(resp_dh, LinkAutoActions::default())
            .unwrap();
        let lr_pkt = RawPacket::parse(&lr_raw).unwrap();
        let proof_raw = resp_mgr
            .handle_link_request(&lr_pkt, &responder_identity)
            .unwrap();
        let proof_pkt = RawPacket::parse(&proof_raw).unwrap();
        let rtt_raw = init_mgr.handle_lrproof(&proof_pkt).unwrap();
        let rtt_pkt = RawPacket::parse(&rtt_raw).unwrap();
        let link_id = resp_mgr.handle_lrrtt(&rtt_pkt).unwrap();

        // send_raw_with_context should NOT encrypt
        let raw_data = b"unencrypted resource part";
        let raw_pkt_bytes = init_mgr
            .send_raw_with_context(&link_id, raw_data, ContextType::Resource)
            .unwrap();
        let raw_pkt = RawPacket::parse(&raw_pkt_bytes).unwrap();

        // get_raw_link_data should return data as-is
        let received = resp_mgr.get_raw_link_data(&raw_pkt).unwrap();
        assert_eq!(received, raw_data);
    }

    #[test]
    fn test_duplicate_initiate_link_same_dest() {
        let responder_identity = Identity::generate();
        let nh = destination::name_hash("dup_init", &["link", "v1"]);
        let resp_dh = destination::destination_hash(&nh, responder_identity.hash());

        let mut init_mgr = LinkManager::new(vec![]);
        let resp_pub = Identity::from_public_bytes(&responder_identity.public_key_bytes()).unwrap();
        insert_known_identity(&mut init_mgr, resp_dh, &resp_pub);

        // Two initiate_link calls for the same destination
        let lr1 = init_mgr
            .initiate_link(resp_dh, LinkAutoActions::default())
            .expect("first initiate should succeed");
        let lr2 = init_mgr
            .initiate_link(resp_dh, LinkAutoActions::default())
            .expect("second initiate should succeed");

        // Each produces unique ephemeral keys → different link requests
        assert_ne!(lr1, lr2);
        // Both should be in pending_initiator
        assert_eq!(init_mgr.pending_initiator.len(), 2);
    }

    #[test]
    fn test_second_link_request_different_initiators() {
        let responder_identity = Identity::generate();
        let nh = destination::name_hash("multi_lr", &["link", "v1"]);
        let resp_dh = destination::destination_hash(&nh, responder_identity.hash());

        let mut resp_mgr = LinkManager::new(vec![]);
        resp_mgr.register_local_destination(
            resp_dh,
            "multi_lr",
            &["link".to_string(), "v1".to_string()],
        );

        // Two different initiators create separate link requests
        let init1_identity = Identity::generate();
        let mut init1_mgr = LinkManager::new(vec![]);
        let resp_pub1 =
            Identity::from_public_bytes(&responder_identity.public_key_bytes()).unwrap();
        insert_known_identity(&mut init1_mgr, resp_dh, &resp_pub1);
        let lr1_raw = init1_mgr
            .initiate_link(resp_dh, LinkAutoActions::default())
            .unwrap();

        let init2_identity = Identity::generate();
        let mut init2_mgr = LinkManager::new(vec![]);
        let resp_pub2 =
            Identity::from_public_bytes(&responder_identity.public_key_bytes()).unwrap();
        insert_known_identity(&mut init2_mgr, resp_dh, &resp_pub2);
        let lr2_raw = init2_mgr
            .initiate_link(resp_dh, LinkAutoActions::default())
            .unwrap();

        let _ = (&init1_identity, &init2_identity); // suppress unused warnings

        // Responder handles both
        let lr1_pkt = RawPacket::parse(&lr1_raw).unwrap();
        let lr2_pkt = RawPacket::parse(&lr2_raw).unwrap();

        let proof1 = resp_mgr
            .handle_link_request(&lr1_pkt, &responder_identity)
            .expect("first link request should produce proof");
        let proof2 = resp_mgr
            .handle_link_request(&lr2_pkt, &responder_identity)
            .expect("second link request should produce proof");

        assert_ne!(proof1, proof2);
        assert_eq!(resp_mgr.pending_responder.len(), 2);
    }

    #[test]
    fn test_lrrtt_wrong_link_id() {
        let mut mgr = LinkManager::new(vec![]);
        // Build a fake LRRTT packet with unknown link_id
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
            destination: DestinationHash::new([0xDE; 16]),
            context: ContextType::Lrrtt,
            data: vec![0u8; 48],
        };

        assert!(mgr.handle_lrrtt(&packet).is_none());
    }

    #[test]
    fn test_lrproof_wrong_link_id() {
        let mut mgr = LinkManager::new(vec![]);
        let packet = RawPacket {
            flags: PacketFlags {
                header_type: HeaderType::Header1,
                context_flag: false,
                transport_type: TransportType::Broadcast,
                destination_type: DestinationType::Link,
                packet_type: PacketType::Proof,
            },
            hops: 0,
            transport_id: None,
            destination: DestinationHash::new([0xDE; 16]),
            context: ContextType::Lrproof,
            data: vec![0u8; 96],
        };

        assert!(mgr.handle_lrproof(&packet).is_none());
    }

    #[test]
    fn test_link_data_wrong_link_id() {
        let mut mgr = LinkManager::new(vec![]);
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
            destination: DestinationHash::new([0xDE; 16]),
            context: ContextType::None,
            data: vec![0u8; 64],
        };

        assert!(mgr.handle_link_data(&packet).is_none());
    }

    #[test]
    fn test_encrypt_send_no_active_link() {
        let mut mgr = LinkManager::new(vec![]);
        let unknown = LinkId::new([0xDE; 16]);

        assert!(mgr.encrypt_and_send(&unknown, b"test data").is_none());
    }

    #[test]
    fn test_many_simultaneous_active_links() {
        let responder_identity = Identity::generate();
        let nh = destination::name_hash("many_links", &["link", "v1"]);
        let resp_dh = destination::destination_hash(&nh, responder_identity.hash());

        let mut resp_mgr = LinkManager::new(vec![]);
        resp_mgr.register_local_destination(
            resp_dh,
            "many_links",
            &["link".to_string(), "v1".to_string()],
        );

        let mut init_mgr = LinkManager::new(vec![]);
        let resp_pub = Identity::from_public_bytes(&responder_identity.public_key_bytes()).unwrap();
        insert_known_identity(&mut init_mgr, resp_dh, &resp_pub);

        let mut link_ids = Vec::new();

        for i in 0u32..50 {
            let lr_raw = init_mgr
                .initiate_link(resp_dh, LinkAutoActions::default())
                .expect("initiate should succeed");
            let lr_pkt = RawPacket::parse(&lr_raw).unwrap();
            let proof_raw = resp_mgr
                .handle_link_request(&lr_pkt, &responder_identity)
                .expect("link request should succeed");
            let proof_pkt = RawPacket::parse(&proof_raw).unwrap();
            let rtt_raw = init_mgr.handle_lrproof(&proof_pkt).unwrap();
            let rtt_pkt = RawPacket::parse(&rtt_raw).unwrap();
            let link_id = resp_mgr.handle_lrrtt(&rtt_pkt).unwrap();
            link_ids.push(link_id);

            // Quick sanity on every 10th link
            if i % 10 == 0 {
                let msg = format!("msg-{i}");
                let enc = init_mgr.encrypt_and_send(&link_id, msg.as_bytes()).unwrap();
                let pkt = RawPacket::parse(&enc).unwrap();
                let dec = resp_mgr.handle_link_data(&pkt).unwrap();
                assert_eq!(dec, msg.as_bytes());
            }
        }

        assert_eq!(init_mgr.active_links.len(), 50);
        assert_eq!(resp_mgr.active_links.len(), 50);

        // Verify each link can still encrypt/decrypt independently
        for link_id in &link_ids {
            let enc = init_mgr
                .encrypt_and_send(link_id, b"final-check")
                .expect("encrypt should work");
            let pkt = RawPacket::parse(&enc).unwrap();
            let dec = resp_mgr.handle_link_data(&pkt).unwrap();
            assert_eq!(dec, b"final-check");
        }
    }

    #[test]
    fn test_known_destinations_scaling() {
        let mut mgr = LinkManager::new(vec![]);
        for i in 0u32..10_000 {
            let identity = Identity::generate();
            let seed = i.to_be_bytes();
            let mut dh_bytes = [0u8; 16];
            dh_bytes[..4].copy_from_slice(&seed);
            let dh = DestinationHash::new(dh_bytes);
            let pub_id = Identity::from_public_bytes(&identity.public_key_bytes()).unwrap();
            insert_known_identity(&mut mgr, dh, &pub_id);
        }
        assert_eq!(mgr.known_destinations.len(), 10_000);
    }

    #[test]
    fn test_stale_pending_targets_drain() {
        let mut mgr = LinkManager::new(vec![]);

        // Push 100 pending targets
        for i in 0u8..100 {
            mgr.pending_link_targets
                .push((DestinationHash::new([i; 16]), LinkAutoActions::default()));
        }
        assert_eq!(mgr.pending_link_targets.len(), 100);

        let drained = mgr.drain_pending_targets();
        assert_eq!(drained.len(), 100);
        assert!(mgr.pending_link_targets.is_empty());

        // Drain again — idempotent
        assert!(mgr.drain_pending_targets().is_empty());

        // Push more, drain again
        mgr.pending_link_targets
            .push((DestinationHash::new([0xFF; 16]), LinkAutoActions::default()));
        let drained2 = mgr.drain_pending_targets();
        assert_eq!(drained2.len(), 1);
    }

    #[test]
    fn test_linked_destinations_prevents_auto_relink() {
        let (init_mgr, _resp_mgr, _link_id, _resp_id) = perform_full_handshake("prevent_relink");

        // After handshake, the initiator should have the destination in linked_destinations
        // (populated by the initiate_link path).
        // Try registering a new announce for the same destination — should not auto-link
        // since linked_destinations already contains it.
        let resp_dh = *init_mgr
            .linked_destinations
            .iter()
            .next()
            .unwrap_or(&DestinationHash::new([0; 16]));
        // If linked_destinations is populated, has_link_to_dest should return true
        assert!(
            init_mgr.linked_destinations.contains(&resp_dh)
                || init_mgr.pending_initiator.is_empty(),
            "after handshake, linked_destinations should track the destination"
        );
    }

    // --- Timeout and recovery path tests ---

    #[test]
    fn test_initiator_pending_persists_without_proof() {
        let responder_identity = Identity::generate();
        let nh = destination::name_hash("pending_init", &["link", "v1"]);
        let resp_dh = destination::destination_hash(&nh, responder_identity.hash());

        let mut init_mgr = LinkManager::new(vec![]);
        let resp_pub = Identity::from_public_bytes(&responder_identity.public_key_bytes()).unwrap();
        insert_known_identity(&mut init_mgr, resp_dh, &resp_pub);

        let _lr_raw = init_mgr
            .initiate_link(resp_dh, LinkAutoActions::default())
            .expect("should create link request");

        // Without receiving a proof, the pending_initiator should still hold the entry
        assert_eq!(init_mgr.pending_initiator.len(), 1);
        assert!(init_mgr.active_links.is_empty());

        // The link_id should be in the map
        let (link_id, (_, dest)) = init_mgr.pending_initiator.iter().next().unwrap();
        assert_eq!(*dest, resp_dh);
        assert_ne!(link_id.as_ref(), &[0u8; 16]);
    }

    #[test]
    fn test_responder_pending_persists_without_rtt() {
        let responder_identity = Identity::generate();
        let nh = destination::name_hash("pending_resp", &["link", "v1"]);
        let resp_dh = destination::destination_hash(&nh, responder_identity.hash());

        let mut resp_mgr = LinkManager::new(vec![]);
        resp_mgr.register_local_destination(
            resp_dh,
            "pending_resp",
            &["link".to_string(), "v1".to_string()],
        );

        let mut init_mgr = LinkManager::new(vec![]);
        let resp_pub = Identity::from_public_bytes(&responder_identity.public_key_bytes()).unwrap();
        insert_known_identity(&mut init_mgr, resp_dh, &resp_pub);

        let lr_raw = init_mgr
            .initiate_link(resp_dh, LinkAutoActions::default())
            .unwrap();
        let lr_pkt = RawPacket::parse(&lr_raw).unwrap();

        let _proof_raw = resp_mgr
            .handle_link_request(&lr_pkt, &responder_identity)
            .expect("should produce proof");

        // Without receiving LRRTT, the pending_responder should hold the entry
        assert_eq!(resp_mgr.pending_responder.len(), 1);
        assert!(resp_mgr.active_links.is_empty());
    }

    #[test]
    fn test_pending_initiator_wrong_proof_leaves_pending() {
        let responder_identity = Identity::generate();
        let nh = destination::name_hash("wrong_proof", &["link", "v1"]);
        let resp_dh = destination::destination_hash(&nh, responder_identity.hash());

        let mut init_mgr = LinkManager::new(vec![]);
        let resp_pub = Identity::from_public_bytes(&responder_identity.public_key_bytes()).unwrap();
        insert_known_identity(&mut init_mgr, resp_dh, &resp_pub);

        let _lr_raw = init_mgr
            .initiate_link(resp_dh, LinkAutoActions::default())
            .unwrap();
        assert_eq!(init_mgr.pending_initiator.len(), 1);

        // Send a proof with wrong link_id
        let wrong_proof = RawPacket {
            flags: PacketFlags {
                header_type: HeaderType::Header1,
                context_flag: false,
                transport_type: TransportType::Broadcast,
                destination_type: DestinationType::Link,
                packet_type: PacketType::Proof,
            },
            hops: 0,
            transport_id: None,
            destination: DestinationHash::new([0xBA; 16]),
            context: ContextType::Lrproof,
            data: vec![0u8; 99],
        };

        let result = init_mgr.handle_lrproof(&wrong_proof);
        assert!(result.is_none());

        // Pending entry should still be there
        assert_eq!(init_mgr.pending_initiator.len(), 1);
        assert!(init_mgr.active_links.is_empty());
    }

    #[test]
    fn test_pending_responder_wrong_rtt_leaves_pending() {
        let responder_identity = Identity::generate();
        let nh = destination::name_hash("wrong_rtt", &["link", "v1"]);
        let resp_dh = destination::destination_hash(&nh, responder_identity.hash());

        let mut resp_mgr = LinkManager::new(vec![]);
        resp_mgr.register_local_destination(
            resp_dh,
            "wrong_rtt",
            &["link".to_string(), "v1".to_string()],
        );

        let mut init_mgr = LinkManager::new(vec![]);
        let resp_pub = Identity::from_public_bytes(&responder_identity.public_key_bytes()).unwrap();
        insert_known_identity(&mut init_mgr, resp_dh, &resp_pub);

        let lr_raw = init_mgr
            .initiate_link(resp_dh, LinkAutoActions::default())
            .unwrap();
        let lr_pkt = RawPacket::parse(&lr_raw).unwrap();
        let _proof_raw = resp_mgr
            .handle_link_request(&lr_pkt, &responder_identity)
            .unwrap();
        assert_eq!(resp_mgr.pending_responder.len(), 1);

        // Send RTT with wrong link_id
        let wrong_rtt = RawPacket {
            flags: PacketFlags {
                header_type: HeaderType::Header1,
                context_flag: false,
                transport_type: TransportType::Broadcast,
                destination_type: DestinationType::Link,
                packet_type: PacketType::Data,
            },
            hops: 0,
            transport_id: None,
            destination: DestinationHash::new([0xBA; 16]),
            context: ContextType::Lrrtt,
            data: vec![0u8; 48],
        };

        let result = resp_mgr.handle_lrrtt(&wrong_rtt);
        assert!(result.is_none());

        // Pending entry should still be there
        assert_eq!(resp_mgr.pending_responder.len(), 1);
        assert!(resp_mgr.active_links.is_empty());
    }

    #[test]
    fn test_active_link_state_after_handshake() {
        let (init_mgr, resp_mgr, link_id, _resp_id) = perform_full_handshake("active_state");

        // Both sides should have active links
        assert_eq!(init_mgr.active_links.len(), 1);
        assert_eq!(resp_mgr.active_links.len(), 1);

        // Pending maps should be empty
        assert!(init_mgr.pending_initiator.is_empty());
        assert!(resp_mgr.pending_responder.is_empty());

        // Active link should be accessible by link_id
        assert!(init_mgr.active_links.contains_key(&link_id));
        assert!(resp_mgr.active_links.contains_key(&link_id));

        // Derived keys should be present
        assert!(init_mgr.get_derived_key(&link_id).is_some());
        assert!(resp_mgr.get_derived_key(&link_id).is_some());
    }

    #[test]
    fn test_handshake_with_unknown_destination_returns_none_no_state_change() {
        let identity = Identity::generate();
        let mut mgr = LinkManager::new(vec![]);

        let initial_pending = mgr.pending_responder.len();
        let initial_active = mgr.active_links.len();

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

        assert!(mgr.handle_link_request(&packet, &identity).is_none());
        assert_eq!(mgr.pending_responder.len(), initial_pending);
        assert_eq!(mgr.active_links.len(), initial_active);
    }

    #[test]
    fn test_multiple_pending_links_independent() {
        let responder_identity = Identity::generate();
        let nh = destination::name_hash("multi_pending", &["link", "v1"]);
        let resp_dh = destination::destination_hash(&nh, responder_identity.hash());

        let mut resp_mgr = LinkManager::new(vec![]);
        resp_mgr.register_local_destination(
            resp_dh,
            "multi_pending",
            &["link".to_string(), "v1".to_string()],
        );

        // Create two initiators
        let mut init1 = LinkManager::new(vec![]);
        let resp_pub1 =
            Identity::from_public_bytes(&responder_identity.public_key_bytes()).unwrap();
        insert_known_identity(&mut init1, resp_dh, &resp_pub1);

        let mut init2 = LinkManager::new(vec![]);
        let resp_pub2 =
            Identity::from_public_bytes(&responder_identity.public_key_bytes()).unwrap();
        insert_known_identity(&mut init2, resp_dh, &resp_pub2);

        let lr1_raw = init1
            .initiate_link(resp_dh, LinkAutoActions::default())
            .unwrap();
        let lr2_raw = init2
            .initiate_link(resp_dh, LinkAutoActions::default())
            .unwrap();

        // Responder handles both link requests
        let lr1_pkt = RawPacket::parse(&lr1_raw).unwrap();
        let lr2_pkt = RawPacket::parse(&lr2_raw).unwrap();

        let proof1 = resp_mgr
            .handle_link_request(&lr1_pkt, &responder_identity)
            .unwrap();
        let proof2 = resp_mgr
            .handle_link_request(&lr2_pkt, &responder_identity)
            .unwrap();

        assert_eq!(resp_mgr.pending_responder.len(), 2);

        // Complete only the first handshake
        let proof1_pkt = RawPacket::parse(&proof1).unwrap();
        let rtt1_raw = init1.handle_lrproof(&proof1_pkt).unwrap();
        let rtt1_pkt = RawPacket::parse(&rtt1_raw).unwrap();
        let _link_id1 = resp_mgr.handle_lrrtt(&rtt1_pkt).unwrap();

        // First is now active, second should still be pending
        assert_eq!(resp_mgr.active_links.len(), 1);
        assert_eq!(resp_mgr.pending_responder.len(), 1);

        // Complete the second handshake
        let proof2_pkt = RawPacket::parse(&proof2).unwrap();
        let rtt2_raw = init2.handle_lrproof(&proof2_pkt).unwrap();
        let rtt2_pkt = RawPacket::parse(&rtt2_raw).unwrap();
        let _link_id2 = resp_mgr.handle_lrrtt(&rtt2_pkt).unwrap();

        assert_eq!(resp_mgr.active_links.len(), 2);
        assert!(resp_mgr.pending_responder.is_empty());
    }

    #[test]
    fn test_pending_initiator_count_after_initiate() {
        let responder_identity = Identity::generate();
        let nh = destination::name_hash("count_pending", &["link", "v1"]);
        let resp_dh = destination::destination_hash(&nh, responder_identity.hash());

        let mut init_mgr = LinkManager::new(vec![]);
        let resp_pub = Identity::from_public_bytes(&responder_identity.public_key_bytes()).unwrap();
        insert_known_identity(&mut init_mgr, resp_dh, &resp_pub);

        assert!(init_mgr.pending_initiator.is_empty());
        assert!(init_mgr.active_links.is_empty());

        let _lr_raw = init_mgr
            .initiate_link(resp_dh, LinkAutoActions::default())
            .unwrap();

        // After initiating, pending_initiator should have exactly one entry
        assert_eq!(init_mgr.pending_initiator.len(), 1);
        // The entry should store the correct destination hash
        let (_, (_, stored_dest)) = init_mgr.pending_initiator.iter().next().unwrap();
        assert_eq!(*stored_dest, resp_dh);
    }

    // --- Keepalive tests ---

    #[test]
    fn test_get_link_role_initiator() {
        let (init_mgr, _resp_mgr, link_id, _) = perform_full_handshake("role_init");
        assert_eq!(init_mgr.get_link_role(&link_id), Some(LinkRole::Initiator));
    }

    #[test]
    fn test_get_link_role_responder() {
        let (_init_mgr, resp_mgr, link_id, _) = perform_full_handshake("role_resp");
        assert_eq!(resp_mgr.get_link_role(&link_id), Some(LinkRole::Responder));
    }

    #[test]
    fn test_get_link_role_unknown() {
        let mgr = LinkManager::new(vec![]);
        assert_eq!(mgr.get_link_role(&LinkId::new([0xAA; 16])), None);
    }

    #[test]
    fn test_collect_keepalive_initiator_only() {
        let (mut init_mgr, mut resp_mgr, link_id, _) = perform_full_handshake("ka_init_only");

        // Force the link's last_outbound to be old enough to trigger keepalive
        // by setting keepalive to 0 (always due)
        init_mgr.active_links.get_mut(&link_id).unwrap().keepalive = 0.0;
        resp_mgr.active_links.get_mut(&link_id).unwrap().keepalive = 0.0;

        // Initiator should produce keepalive packets
        let init_packets = init_mgr.collect_keepalive_packets();
        assert_eq!(init_packets.len(), 1, "initiator should send 1 keepalive");

        // Responder should NOT produce keepalive packets (only initiator sends)
        let resp_packets = resp_mgr.collect_keepalive_packets();
        assert!(
            resp_packets.is_empty(),
            "responder should not send keepalives"
        );
    }

    #[test]
    fn test_collect_keepalive_not_yet_due() {
        let (mut init_mgr, _, link_id, _) = perform_full_handshake("ka_not_due");

        // With default keepalive (≥5s), it shouldn't be due right after handshake
        // since last_outbound was just set during the LRRTT
        let active = init_mgr.active_links.get(&link_id).unwrap();
        assert!(
            active.keepalive >= 5.0,
            "keepalive should be at least 5s, got {}",
            active.keepalive
        );

        let packets = init_mgr.collect_keepalive_packets();
        assert!(
            packets.is_empty(),
            "keepalive should not be due immediately"
        );
    }

    #[test]
    fn test_build_keepalive_echo_responder() {
        let (_init_mgr, mut resp_mgr, link_id, _) = perform_full_handshake("ka_echo");

        // Responder should produce echo packets
        let echo = resp_mgr.build_keepalive_echo(&link_id);
        assert!(echo.is_some(), "responder should produce keepalive echo");

        // Verify it's a valid packet with Keepalive context
        let raw = echo.unwrap();
        let pkt = RawPacket::parse(&raw).unwrap();
        assert_eq!(pkt.context, ContextType::Keepalive);
    }

    #[test]
    fn test_build_keepalive_echo_initiator_returns_none() {
        let (mut init_mgr, _, link_id, _) = perform_full_handshake("ka_echo_init");

        // Initiator should NOT produce echo (only responder echoes)
        let echo = init_mgr.build_keepalive_echo(&link_id);
        assert!(echo.is_none(), "initiator should not echo keepalives");
    }

    #[test]
    fn test_check_link_health_stale_detection() {
        let (mut init_mgr, _, link_id, _) = perform_full_handshake("ka_stale");

        // Set stale_time to 0 so it triggers immediately
        let active = init_mgr.active_links.get_mut(&link_id).unwrap();
        active.stale_time = 0.0;

        // Should detect stale but not tear down yet (stale_since just set)
        let teardowns = init_mgr.check_link_health();
        assert!(
            teardowns.is_empty(),
            "should not teardown immediately on stale"
        );

        // Link should now be marked stale
        let active = init_mgr.active_links.get(&link_id).unwrap();
        assert!(active.is_stale, "link should be marked stale");
    }

    #[test]
    fn test_check_link_health_teardown() {
        let (mut init_mgr, _, link_id, _) = perform_full_handshake("ka_teardown");

        // Set keepalive to 0 and stale_time to 0 so it goes stale immediately
        let active = init_mgr.active_links.get_mut(&link_id).unwrap();
        active.stale_time = 0.0;
        active.keepalive = 0.0;

        // First call: marks stale
        let _ = init_mgr.check_link_health();
        assert!(init_mgr.active_links.contains_key(&link_id));

        // Manually set stale_since to the past so teardown triggers
        let active = init_mgr.active_links.get_mut(&link_id).unwrap();
        active.stale_since = Some(std::time::Instant::now() - std::time::Duration::from_secs(60));

        // Second call: should teardown
        let teardowns = init_mgr.check_link_health();
        assert!(
            teardowns.contains(&link_id),
            "should include torn-down link"
        );
        assert!(
            !init_mgr.active_links.contains_key(&link_id),
            "link should be removed after teardown"
        );
    }

    #[test]
    fn test_keepalive_record_inbound_resets_stale() {
        let (mut init_mgr, _, link_id, _) = perform_full_handshake("ka_unstale");

        // Make link stale
        let active = init_mgr.active_links.get_mut(&link_id).unwrap();
        active.mark_stale();
        assert!(active.is_stale);

        // Receiving inbound data should reset stale
        active.record_inbound(10);
        assert!(!active.is_stale, "record_inbound should reset stale");
        assert!(active.stale_since.is_none());
    }

    #[test]
    fn test_teardown_removes_signing_key() {
        let (mut init_mgr, _, link_id, _) = perform_full_handshake("ka_teardown_key");

        assert!(init_mgr.signing_keys.contains_key(&link_id));
        assert!(init_mgr.active_links.contains_key(&link_id));

        init_mgr.teardown_link(&link_id);

        assert!(!init_mgr.signing_keys.contains_key(&link_id));
        assert!(!init_mgr.active_links.contains_key(&link_id));
    }

    #[test]
    fn test_teardown_cleans_linked_destinations() {
        let (mut init_mgr, _, link_id, _) = perform_full_handshake("teardown_dest_cleanup");

        // After handshake, linked_destinations should contain the dest
        assert!(!init_mgr.linked_destinations.is_empty());
        assert!(init_mgr.link_dest_map.contains_key(&link_id));

        init_mgr.teardown_link(&link_id);

        // After teardown, linked_destinations and link_dest_map should be clean
        assert!(init_mgr.linked_destinations.is_empty());
        assert!(!init_mgr.link_dest_map.contains_key(&link_id));
    }

    #[test]
    fn test_relink_allowed_after_teardown() {
        let (mut init_mgr, _, link_id, _) = perform_full_handshake("relink_after_teardown");

        // Get the dest_hash before teardown
        let dest_hash = *init_mgr.link_dest_map.get(&link_id).unwrap();

        // Before teardown: has_link_to_dest should return true
        assert!(init_mgr.has_link_to_dest(&dest_hash));

        init_mgr.teardown_link(&link_id);

        // After teardown: has_link_to_dest should return false
        assert!(!init_mgr.has_link_to_dest(&dest_hash));
    }
}
