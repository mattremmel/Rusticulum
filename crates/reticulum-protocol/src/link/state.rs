//! Link type-state machine.
//!
//! Four structs represent the link lifecycle: `LinkPending` → `LinkHandshake` →
//! `LinkActive` → `LinkClosed`. Each struct holds only the data relevant to that
//! state. The `LinkState` enum wraps all four for runtime dispatch.
//!
//! # Handshake protocol
//!
//! ```text
//! INITIATOR                                RESPONDER
//!     |-- LINKREQUEST [eph_x25519(32) +       |
//!     |   eph_ed25519(32) + signalling(3)] -->|
//!     |                                       |
//!     |<-- LRPROOF [signature(64) +           |
//!     |    resp_x25519(32) + signalling(3)]   |
//!     |                                       |
//!     |   Both: ECDH → HKDF(64) → Token      |
//!     |                                       |
//!     |-- LRRTT [Token.encrypt(msgpack(rtt))]>|
//!     |                                       |
//!     |        === LINK ACTIVE ===            |
//! ```

use std::io::Cursor;
use std::time::Instant;

use reticulum_core::types::{DestinationHash, LinkId};
use reticulum_crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature};
use reticulum_crypto::hmac::{hmac_sha256, hmac_sha256_verify};
use reticulum_crypto::sha::sha256;
use reticulum_crypto::token::Token;
use reticulum_crypto::x25519::{X25519PrivateKey, X25519PublicKey};

use super::constants::{
    AES_BLOCKSIZE, ECPUBSIZE, ESTABLISHMENT_TIMEOUT_PER_HOP, HEADER_MINSIZE, IFAC_MIN_SIZE,
    KEEPALIVE_DEFAULT, KEEPALIVE_MAX, KEEPALIVE_MAX_RTT, KEEPALIVE_MIN, KEEPALIVE_TIMEOUT_FACTOR,
    LINK_KEYSIZE, SIGNATURE_SIZE, STALE_FACTOR, STALE_GRACE, TOKEN_OVERHEAD,
    TRAFFIC_TIMEOUT_FACTOR,
};
use super::types::{DerivedKey, LinkMode, LinkRole, LinkStats, TeardownReason};
use crate::error::LinkError;

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Encode an RTT value as MessagePack float64.
fn encode_rtt_msgpack(rtt: f64) -> Vec<u8> {
    let mut buf = Vec::new();
    rmpv::encode::write_value(&mut buf, &rmpv::Value::F64(rtt))
        .expect("msgpack encoding to Vec never fails");
    buf
}

/// Decode an RTT value from MessagePack.
fn decode_rtt_msgpack(data: &[u8]) -> Result<f64, LinkError> {
    let mut cursor = Cursor::new(data);
    let value = rmpv::decode::read_value(&mut cursor)
        .map_err(|e| LinkError::HandshakeFailed(format!("invalid RTT msgpack: {e}")))?;
    match value {
        rmpv::Value::F64(v) => Ok(v),
        rmpv::Value::F32(v) => Ok(v as f64),
        _ => Err(LinkError::HandshakeFailed(
            "RTT must be a float".to_string(),
        )),
    }
}

/// Perform the ECDH + HKDF key derivation common to both sides.
fn derive_link_key(
    our_x25519_prv: &X25519PrivateKey,
    peer_x25519_pub: &X25519PublicKey,
    link_id: &LinkId,
) -> DerivedKey {
    let shared_key = our_x25519_prv.diffie_hellman(peer_x25519_pub);

    let derived_bytes = reticulum_crypto::hkdf::hkdf(64, &shared_key, Some(link_id.as_ref()), None);

    let mut dk_arr = [0u8; 64];
    dk_arr.copy_from_slice(&derived_bytes);
    DerivedKey::new(dk_arr)
}

// ---------------------------------------------------------------------------
// LinkPending
// ---------------------------------------------------------------------------

/// A link that has been requested but not yet completed the ECDH exchange.
pub struct LinkPending {
    pub link_id: LinkId,
    pub destination_hash: DestinationHash,
    pub role: LinkRole,
    pub mode: LinkMode,
    pub mtu: u32,

    pub eph_x25519_private: X25519PrivateKey,
    pub eph_x25519_public: X25519PublicKey,
    pub eph_ed25519_private: Ed25519PrivateKey,
    pub eph_ed25519_public: Ed25519PublicKey,

    pub request_time: Instant,
    pub establishment_timeout: f64,
}

impl LinkPending {
    /// Create a new initiator-side pending link with random ephemeral keys.
    ///
    /// Returns `(LinkPending, request_data)` where `request_data` is the payload
    /// to send in the LINKREQUEST packet:
    /// `eph_x25519_pub(32) || eph_ed25519_pub(32) || signalling(3)`
    pub fn new_initiator(
        destination_hash: DestinationHash,
        mtu: u32,
        mode: LinkMode,
        hops: u32,
        hashable_part: &[u8],
        data_len: usize,
    ) -> Result<(Self, Vec<u8>), LinkError> {
        let eph_x25519 = X25519PrivateKey::generate();
        let eph_ed25519 = Ed25519PrivateKey::generate();
        Self::new_initiator_inner(
            destination_hash,
            mtu,
            mode,
            hops,
            eph_x25519,
            eph_ed25519,
            hashable_part,
            data_len,
        )
    }

    /// Create a new initiator-side pending link with deterministic ephemeral keys.
    /// Used for test vector validation.
    #[allow(clippy::too_many_arguments)]
    pub fn new_initiator_deterministic(
        destination_hash: DestinationHash,
        mtu: u32,
        mode: LinkMode,
        hops: u32,
        eph_x25519: X25519PrivateKey,
        eph_ed25519: Ed25519PrivateKey,
        hashable_part: &[u8],
        data_len: usize,
    ) -> Result<(Self, Vec<u8>), LinkError> {
        Self::new_initiator_inner(
            destination_hash,
            mtu,
            mode,
            hops,
            eph_x25519,
            eph_ed25519,
            hashable_part,
            data_len,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_initiator_inner(
        destination_hash: DestinationHash,
        mtu: u32,
        mode: LinkMode,
        hops: u32,
        eph_x25519: X25519PrivateKey,
        eph_ed25519: Ed25519PrivateKey,
        hashable_part: &[u8],
        data_len: usize,
    ) -> Result<(Self, Vec<u8>), LinkError> {
        let eph_x25519_pub = eph_x25519.public_key();
        let eph_ed25519_pub = eph_ed25519.public_key();

        // Build request data: x25519_pub || ed25519_pub || signalling
        let mut request_data = Vec::with_capacity(ECPUBSIZE + 3);
        request_data.extend_from_slice(&eph_x25519_pub.to_bytes());
        request_data.extend_from_slice(&eph_ed25519_pub.to_bytes());

        let signalling = super::mtu::encode(mtu, mode)?;
        request_data.extend_from_slice(&signalling);

        let link_id = Self::compute_link_id(hashable_part, data_len);

        let timeout = ESTABLISHMENT_TIMEOUT_PER_HOP * hops.max(1) as f64 + KEEPALIVE_DEFAULT;

        Ok((
            Self {
                link_id,
                destination_hash,
                role: LinkRole::Initiator,
                mode,
                mtu,
                eph_x25519_private: eph_x25519,
                eph_x25519_public: eph_x25519_pub,
                eph_ed25519_private: eph_ed25519,
                eph_ed25519_public: eph_ed25519_pub,
                request_time: Instant::now(),
                establishment_timeout: timeout,
            },
            request_data,
        ))
    }

    /// Compute the link ID from a packet's hashable part.
    ///
    /// If the request data is longer than ECPUBSIZE (64), the extra bytes
    /// (signalling) are stripped before hashing.
    /// `link_id = SHA256(hashable_stripped)[:16]`
    pub fn compute_link_id(hashable_part: &[u8], data_len: usize) -> LinkId {
        let diff = data_len.saturating_sub(ECPUBSIZE);
        let stripped = if diff > 0 && hashable_part.len() >= diff {
            &hashable_part[..hashable_part.len() - diff]
        } else {
            hashable_part
        };
        let hash = sha256(stripped);
        let mut id = [0u8; 16];
        id.copy_from_slice(&hash[..16]);
        LinkId::new(id)
    }

    /// Whether the establishment timeout has elapsed.
    pub fn is_timed_out(&self) -> bool {
        self.request_time.elapsed().as_secs_f64() > self.establishment_timeout
    }

    /// Process a received LRPROOF on the initiator side.
    ///
    /// Performs ECDH with the responder's ephemeral X25519 public key,
    /// derives the shared key via HKDF, verifies the responder's Ed25519
    /// signature, and transitions directly to `LinkActive`.
    ///
    /// Returns `(LinkActive, encrypted_rtt)` where `encrypted_rtt` is the
    /// LRRTT packet payload to send back.
    pub fn receive_proof(
        self,
        proof_data: &[u8],
        responder_ed25519_pub: &Ed25519PublicKey,
    ) -> Result<(LinkActive, Vec<u8>), LinkError> {
        let rtt = self.request_time.elapsed().as_secs_f64();
        self.receive_proof_inner(proof_data, responder_ed25519_pub, rtt, None)
    }

    /// Process a received LRPROOF with deterministic RTT and IV (for testing).
    pub fn receive_proof_deterministic(
        self,
        proof_data: &[u8],
        responder_ed25519_pub: &Ed25519PublicKey,
        rtt: f64,
        iv: &[u8; 16],
    ) -> Result<(LinkActive, Vec<u8>), LinkError> {
        self.receive_proof_inner(proof_data, responder_ed25519_pub, rtt, Some(iv))
    }

    fn receive_proof_inner(
        self,
        proof_data: &[u8],
        responder_ed25519_pub: &Ed25519PublicKey,
        rtt: f64,
        fixed_iv: Option<&[u8; 16]>,
    ) -> Result<(LinkActive, Vec<u8>), LinkError> {
        // Parse proof_data: signature(64) + x25519_pub(32) + [signalling(3)]
        let min_len = SIGNATURE_SIZE + LINK_KEYSIZE;
        if proof_data.len() < min_len {
            return Err(LinkError::InvalidProof);
        }

        let signature_bytes: [u8; 64] = proof_data[..SIGNATURE_SIZE].try_into().unwrap();
        let peer_x25519_bytes: [u8; 32] = proof_data[SIGNATURE_SIZE..min_len].try_into().unwrap();
        let signalling_bytes = if proof_data.len() > min_len {
            &proof_data[min_len..]
        } else {
            &[]
        };

        let peer_x25519_pub = X25519PublicKey::from_bytes(peer_x25519_bytes);
        let signature = Ed25519Signature::from_bytes(signature_bytes);

        // ECDH + HKDF
        let derived_key =
            derive_link_key(&self.eph_x25519_private, &peer_x25519_pub, &self.link_id);

        tracing::debug!(link_id = ?self.link_id, "initiator ECDH + HKDF complete");

        // Build signed_data: link_id + peer_x25519_pub + responder_ed25519_pub + [signalling]
        let mut signed_data = Vec::with_capacity(16 + 32 + 32 + signalling_bytes.len());
        signed_data.extend_from_slice(self.link_id.as_ref());
        signed_data.extend_from_slice(&peer_x25519_bytes);
        signed_data.extend_from_slice(&responder_ed25519_pub.to_bytes());
        signed_data.extend_from_slice(signalling_bytes);

        // Verify signature
        responder_ed25519_pub
            .verify(&signed_data, &signature)
            .map_err(|_| LinkError::SignatureVerificationFailed)?;

        tracing::info!(link_id = ?self.link_id, "link proof verified (initiator)");

        // Encode RTT as msgpack and encrypt with Token
        let rtt_msgpack = encode_rtt_msgpack(rtt);
        let token = Token::new(derived_key.as_bytes());
        let encrypted_rtt = match fixed_iv {
            Some(iv) => token.encrypt_with_iv(&rtt_msgpack, iv),
            None => token.encrypt(&rtt_msgpack),
        };

        // Compute keepalive and related values
        let keepalive = LinkActive::compute_keepalive(rtt);
        let stale_time = LinkActive::compute_stale_time(keepalive);
        let mdu = LinkActive::compute_mdu(self.mtu);

        let now = Instant::now();
        let active = LinkActive {
            link_id: self.link_id,
            derived_key,
            role: LinkRole::Initiator,
            mode: self.mode,
            rtt,
            mtu: self.mtu,
            mdu,
            keepalive,
            stale_time,
            activated_at: now,
            last_inbound: now,
            last_outbound: now,
            stats: LinkStats::default(),
            is_stale: false,
            stale_since: None,
        };

        tracing::info!(
            link_id = ?active.link_id,
            rtt = rtt,
            keepalive = keepalive,
            "link activated (initiator)"
        );

        Ok((active, encrypted_rtt))
    }
}

impl std::fmt::Debug for LinkPending {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinkPending")
            .field("link_id", &self.link_id)
            .field("role", &self.role)
            .field("mode", &self.mode)
            .field("mtu", &self.mtu)
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// LinkHandshake
// ---------------------------------------------------------------------------

/// A link where the ECDH exchange is complete but not yet fully activated.
///
/// On the responder side, this state is entered after processing the initiator's
/// LINKREQUEST and sending the LRPROOF. The responder waits for the LRRTT
/// packet to transition to `LinkActive`.
pub struct LinkHandshake {
    pub link_id: LinkId,
    pub derived_key: DerivedKey,
    pub peer_ed25519_public: Ed25519PublicKey,
    pub role: LinkRole,
    pub mode: LinkMode,
    pub mtu: u32,
    pub request_time: Instant,
    pub establishment_timeout: f64,
}

impl LinkHandshake {
    /// Create a `LinkHandshake` from a received LINKREQUEST (responder side).
    ///
    /// Parses the initiator's public keys from `request_data`, generates an
    /// ephemeral X25519 key, performs ECDH + HKDF, signs the proof with the
    /// responder's identity Ed25519 key, and returns `(handshake, proof_data)`.
    ///
    /// The `proof_data` should be sent in the LRPROOF packet.
    #[allow(clippy::too_many_arguments)]
    pub fn from_link_request(
        request_data: &[u8],
        hashable_part: &[u8],
        data_len: usize,
        identity_ed25519_prv: &Ed25519PrivateKey,
        identity_ed25519_pub: &Ed25519PublicKey,
        mtu: u32,
        mode: LinkMode,
        hops: u32,
    ) -> Result<(Self, Vec<u8>), LinkError> {
        let eph_x25519 = X25519PrivateKey::generate();
        Self::from_link_request_inner(
            request_data,
            hashable_part,
            data_len,
            identity_ed25519_prv,
            identity_ed25519_pub,
            mtu,
            mode,
            hops,
            eph_x25519,
        )
    }

    /// Deterministic version of `from_link_request` for testing.
    #[allow(clippy::too_many_arguments)]
    pub fn from_link_request_deterministic(
        request_data: &[u8],
        hashable_part: &[u8],
        data_len: usize,
        identity_ed25519_prv: &Ed25519PrivateKey,
        identity_ed25519_pub: &Ed25519PublicKey,
        mtu: u32,
        mode: LinkMode,
        hops: u32,
        eph_x25519: X25519PrivateKey,
    ) -> Result<(Self, Vec<u8>), LinkError> {
        Self::from_link_request_inner(
            request_data,
            hashable_part,
            data_len,
            identity_ed25519_prv,
            identity_ed25519_pub,
            mtu,
            mode,
            hops,
            eph_x25519,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn from_link_request_inner(
        request_data: &[u8],
        hashable_part: &[u8],
        data_len: usize,
        identity_ed25519_prv: &Ed25519PrivateKey,
        identity_ed25519_pub: &Ed25519PublicKey,
        mtu: u32,
        mode: LinkMode,
        hops: u32,
        eph_x25519: X25519PrivateKey,
    ) -> Result<(Self, Vec<u8>), LinkError> {
        // Parse request_data: x25519_pub(32) + ed25519_pub(32) + [signalling(3)]
        if request_data.len() < ECPUBSIZE {
            return Err(LinkError::HandshakeFailed(
                "request data too short".to_string(),
            ));
        }

        let peer_x25519_bytes: [u8; 32] = request_data[..32].try_into().unwrap();
        let peer_ed25519_bytes: [u8; 32] = request_data[32..64].try_into().unwrap();
        let has_signalling = request_data.len() > ECPUBSIZE;

        let peer_x25519_pub = X25519PublicKey::from_bytes(peer_x25519_bytes);
        let peer_ed25519_pub = Ed25519PublicKey::from_bytes(peer_ed25519_bytes)?;

        // Compute link_id from the packet-level hashable part
        let link_id = LinkPending::compute_link_id(hashable_part, data_len);

        // Our ephemeral X25519 public key
        let eph_x25519_pub = eph_x25519.public_key();

        // ECDH + HKDF
        let derived_key = derive_link_key(&eph_x25519, &peer_x25519_pub, &link_id);

        tracing::debug!(link_id = ?link_id, "responder ECDH + HKDF complete");

        // Build responder's signalling bytes (only if initiator sent them)
        let resp_signalling: Vec<u8> = if has_signalling {
            super::mtu::encode(mtu, mode)?.to_vec()
        } else {
            Vec::new()
        };

        // Build signed_data: link_id + our_x25519_pub + identity_ed25519_pub + [signalling]
        let mut signed_data = Vec::with_capacity(16 + 32 + 32 + resp_signalling.len());
        signed_data.extend_from_slice(link_id.as_ref());
        signed_data.extend_from_slice(&eph_x25519_pub.to_bytes());
        signed_data.extend_from_slice(&identity_ed25519_pub.to_bytes());
        signed_data.extend_from_slice(&resp_signalling);

        // Sign with identity Ed25519 key
        let signature = identity_ed25519_prv.sign(&signed_data);

        // Build proof_data: signature(64) + x25519_pub(32) + [signalling(3)]
        let mut proof_data =
            Vec::with_capacity(SIGNATURE_SIZE + LINK_KEYSIZE + resp_signalling.len());
        proof_data.extend_from_slice(&signature.to_bytes());
        proof_data.extend_from_slice(&eph_x25519_pub.to_bytes());
        proof_data.extend_from_slice(&resp_signalling);

        let timeout = ESTABLISHMENT_TIMEOUT_PER_HOP * hops.max(1) as f64 + KEEPALIVE_DEFAULT;

        let handshake = Self {
            link_id,
            derived_key,
            peer_ed25519_public: peer_ed25519_pub,
            role: LinkRole::Responder,
            mode,
            mtu,
            request_time: Instant::now(),
            establishment_timeout: timeout,
        };

        tracing::info!(link_id = ?handshake.link_id, "link request accepted (responder)");

        Ok((handshake, proof_data))
    }

    /// Process an LRRTT packet and transition to `LinkActive` (responder side).
    ///
    /// Decrypts the token, extracts the initiator's RTT measurement, and
    /// uses the larger of the initiator's RTT and our own measured RTT.
    pub fn receive_rtt(self, encrypted_rtt: &[u8]) -> Result<LinkActive, LinkError> {
        // Decrypt using Token with derived key
        let token = Token::new(self.derived_key.as_bytes());
        let plaintext = token.decrypt(encrypted_rtt)?;

        // Decode msgpack → f64
        let initiator_rtt = decode_rtt_msgpack(&plaintext)?;

        // Use the larger of the initiator's sent RTT and our own measurement
        let measured_rtt = self.request_time.elapsed().as_secs_f64();
        let rtt = initiator_rtt.max(measured_rtt);

        let keepalive = LinkActive::compute_keepalive(rtt);
        let stale_time = LinkActive::compute_stale_time(keepalive);
        let mdu = LinkActive::compute_mdu(self.mtu);

        let now = Instant::now();
        let active = LinkActive {
            link_id: self.link_id,
            derived_key: self.derived_key,
            role: self.role,
            mode: self.mode,
            rtt,
            mtu: self.mtu,
            mdu,
            keepalive,
            stale_time,
            activated_at: now,
            last_inbound: now,
            last_outbound: now,
            stats: LinkStats::default(),
            is_stale: false,
            stale_since: None,
        };

        tracing::info!(
            link_id = ?active.link_id,
            rtt = rtt,
            keepalive = keepalive,
            "link activated (responder)"
        );

        Ok(active)
    }

    /// Whether the establishment timeout has elapsed.
    pub fn is_timed_out(&self) -> bool {
        self.request_time.elapsed().as_secs_f64() > self.establishment_timeout
    }
}

impl std::fmt::Debug for LinkHandshake {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinkHandshake")
            .field("link_id", &self.link_id)
            .field("role", &self.role)
            .field("mode", &self.mode)
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// LinkActive
// ---------------------------------------------------------------------------

/// A fully established, active link.
pub struct LinkActive {
    pub link_id: LinkId,
    pub derived_key: DerivedKey,
    pub role: LinkRole,
    pub mode: LinkMode,

    pub rtt: f64,
    pub mtu: u32,
    pub mdu: u32,
    pub keepalive: f64,
    pub stale_time: f64,

    pub activated_at: Instant,
    pub last_inbound: Instant,
    pub last_outbound: Instant,
    pub stats: LinkStats,

    pub is_stale: bool,
    pub stale_since: Option<Instant>,
}

impl LinkActive {
    /// Encrypt data using the link's derived key (Token format).
    ///
    /// Returns `IV(16) || ciphertext || HMAC(32)`.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, LinkError> {
        let token = Token::new(self.derived_key.as_bytes());
        Ok(token.encrypt(plaintext))
    }

    /// Encrypt data with a specific IV (for deterministic testing).
    pub fn encrypt_with_iv(&self, plaintext: &[u8], iv: &[u8; 16]) -> Result<Vec<u8>, LinkError> {
        let token = Token::new(self.derived_key.as_bytes());
        Ok(token.encrypt_with_iv(plaintext, iv))
    }

    /// Decrypt data using the link's derived key (Token format).
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, LinkError> {
        let token = Token::new(self.derived_key.as_bytes());
        Ok(token.decrypt(ciphertext)?)
    }

    /// Sign data using the link's derived signing key (HMAC-SHA256).
    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        hmac_sha256(self.derived_key.signing_key(), data).to_vec()
    }

    /// Verify a signature against data using the link's derived signing key.
    pub fn verify(&self, data: &[u8], signature: &[u8]) -> bool {
        if let Ok(sig_arr) = <&[u8; 32]>::try_from(signature) {
            hmac_sha256_verify(self.derived_key.signing_key(), data, sig_arr).is_ok()
        } else {
            false
        }
    }

    /// Whether it's time to send a keepalive packet.
    pub fn should_send_keepalive(&self) -> bool {
        self.last_outbound.elapsed().as_secs_f64() > self.keepalive
    }

    /// Whether the link should transition to stale.
    pub fn should_go_stale(&self) -> bool {
        !self.is_stale && self.last_inbound.elapsed().as_secs_f64() > self.stale_time
    }

    /// Mark the link as stale.
    pub fn mark_stale(&mut self) {
        self.is_stale = true;
        self.stale_since = Some(Instant::now());
    }

    /// Whether the link should be torn down.
    ///
    /// For non-stale links: tears down if no inbound traffic for
    /// `keepalive * KEEPALIVE_TIMEOUT_FACTOR`.
    /// For stale links: tears down after `STALE_GRACE` seconds of staleness.
    pub fn should_teardown(&self) -> bool {
        if self.is_stale
            && let Some(since) = self.stale_since
        {
            return since.elapsed().as_secs_f64() > STALE_GRACE;
        }
        self.last_inbound.elapsed().as_secs_f64() > self.keepalive * KEEPALIVE_TIMEOUT_FACTOR
    }

    /// Record an inbound packet, updating stats and un-staling the link.
    pub fn record_inbound(&mut self, bytes: u64) {
        self.last_inbound = Instant::now();
        self.stats.rx_packets += 1;
        self.stats.rx_bytes += bytes;
        if self.is_stale {
            self.is_stale = false;
            self.stale_since = None;
        }
    }

    /// Record an outbound packet, updating stats.
    pub fn record_outbound(&mut self, bytes: u64) {
        self.last_outbound = Instant::now();
        self.stats.tx_packets += 1;
        self.stats.tx_bytes += bytes;
    }

    /// Tear down the link and return the closed state.
    pub fn teardown(self, reason: TeardownReason) -> LinkClosed {
        LinkClosed {
            link_id: self.link_id,
            teardown_reason: reason,
            stats: self.stats,
            activated_at: self.activated_at,
            closed_at: Instant::now(),
        }
    }

    /// Compute the keepalive interval from a measured RTT.
    ///
    /// `keepalive = max(min(rtt * (KEEPALIVE_MAX / KEEPALIVE_MAX_RTT), KEEPALIVE_MAX), KEEPALIVE_MIN)`
    pub fn compute_keepalive(rtt: f64) -> f64 {
        (rtt * (KEEPALIVE_MAX / KEEPALIVE_MAX_RTT)).clamp(KEEPALIVE_MIN, KEEPALIVE_MAX)
    }

    /// Compute the maximum data unit size for a given MTU.
    ///
    /// `MDU = floor((mtu - IFAC_MIN_SIZE - HEADER_MINSIZE - TOKEN_OVERHEAD) / AES_BLOCKSIZE) * AES_BLOCKSIZE - 1`
    pub fn compute_mdu(mtu: u32) -> u32 {
        let usable =
            mtu as i64 - IFAC_MIN_SIZE as i64 - HEADER_MINSIZE as i64 - TOKEN_OVERHEAD as i64;
        if usable <= 0 {
            return 0;
        }
        let blocks = usable as u32 / AES_BLOCKSIZE as u32;
        blocks * AES_BLOCKSIZE as u32 - 1
    }

    /// Compute the stale time from a keepalive interval.
    pub fn compute_stale_time(keepalive: f64) -> f64 {
        keepalive * STALE_FACTOR
    }

    /// Compute the traffic timeout from a keepalive interval.
    pub fn compute_traffic_timeout(keepalive: f64) -> f64 {
        keepalive * TRAFFIC_TIMEOUT_FACTOR
    }
}

impl std::fmt::Debug for LinkActive {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinkActive")
            .field("link_id", &self.link_id)
            .field("role", &self.role)
            .field("rtt", &self.rtt)
            .field("is_stale", &self.is_stale)
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// LinkClosed
// ---------------------------------------------------------------------------

/// A link that has been torn down.
#[derive(Debug)]
pub struct LinkClosed {
    pub link_id: LinkId,
    pub teardown_reason: TeardownReason,
    pub stats: LinkStats,
    pub activated_at: Instant,
    pub closed_at: Instant,
}

// ---------------------------------------------------------------------------
// LinkState enum
// ---------------------------------------------------------------------------

/// Runtime-dispatch wrapper over the four link states.
#[allow(clippy::large_enum_variant)]
pub enum LinkState {
    Pending(LinkPending),
    Handshake(LinkHandshake),
    Active(LinkActive),
    Closed(LinkClosed),
}

impl LinkState {
    /// The link ID, available in all states.
    pub fn link_id(&self) -> &LinkId {
        match self {
            Self::Pending(s) => &s.link_id,
            Self::Handshake(s) => &s.link_id,
            Self::Active(s) => &s.link_id,
            Self::Closed(s) => &s.link_id,
        }
    }

    /// A string name for the current state.
    pub fn state_name(&self) -> &'static str {
        match self {
            Self::Pending(_) => "PENDING",
            Self::Handshake(_) => "HANDSHAKE",
            Self::Active(_) => "ACTIVE",
            Self::Closed(_) => "CLOSED",
        }
    }

    /// Whether the link is in the active state.
    pub fn is_active(&self) -> bool {
        matches!(self, Self::Active(_))
    }

    /// Whether the link is closed.
    pub fn is_closed(&self) -> bool {
        matches!(self, Self::Closed(_))
    }
}

impl std::fmt::Debug for LinkState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending(s) => s.fmt(f),
            Self::Handshake(s) => s.fmt(f),
            Self::Active(s) => s.fmt(f),
            Self::Closed(s) => s.fmt(f),
        }
    }
}
