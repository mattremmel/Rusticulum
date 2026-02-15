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

use reticulum_core::constants::TOKEN_OVERHEAD;

use super::constants::{
    AES_BLOCKSIZE, ECPUBSIZE, ESTABLISHMENT_TIMEOUT_PER_HOP, HEADER_MINSIZE, IFAC_MIN_SIZE,
    KEEPALIVE_DEFAULT, KEEPALIVE_MAX, KEEPALIVE_MAX_RTT, KEEPALIVE_MIN, KEEPALIVE_TIMEOUT_FACTOR,
    LINK_KEYSIZE, SIGNATURE_SIZE, STALE_FACTOR, STALE_GRACE, TRAFFIC_TIMEOUT_FACTOR,
};
use super::types::{DerivedKey, LinkMode, LinkRole, LinkStats, TeardownReason};
use crate::error::LinkError;

// ---------------------------------------------------------------------------
// Pure time-decision functions
// ---------------------------------------------------------------------------

/// Whether a keepalive should be sent, given seconds since last outbound.
pub fn should_send_keepalive_at(elapsed_outbound: f64, keepalive: f64) -> bool {
    elapsed_outbound > keepalive
}

/// Whether a link should transition to stale, given current stale flag and
/// seconds since last inbound.
pub fn should_go_stale_at(is_stale: bool, elapsed_inbound: f64, stale_time: f64) -> bool {
    !is_stale && elapsed_inbound > stale_time
}

/// Whether a link should be torn down.
///
/// For stale links with a known `stale_since` elapsed time: tears down after
/// `STALE_GRACE` seconds. For non-stale links (or stale without `stale_since`):
/// tears down if no inbound traffic for `keepalive * KEEPALIVE_TIMEOUT_FACTOR`.
pub fn should_teardown_at(
    is_stale: bool,
    elapsed_stale: Option<f64>,
    elapsed_inbound: f64,
    keepalive: f64,
) -> bool {
    if is_stale && let Some(stale_elapsed) = elapsed_stale {
        return stale_elapsed > STALE_GRACE;
    }
    elapsed_inbound > keepalive * KEEPALIVE_TIMEOUT_FACTOR
}

/// Whether the establishment timeout has elapsed.
pub fn is_establishment_timed_out_at(elapsed: f64, timeout: f64) -> bool {
    elapsed > timeout
}

// ---------------------------------------------------------------------------
// Handshake data parsing/building
// ---------------------------------------------------------------------------

/// Parsed fields from an LRPROOF data payload.
#[derive(Debug, Clone)]
pub struct ParsedProofData {
    /// Ed25519 signature (64 bytes).
    pub signature: [u8; 64],
    /// Responder's ephemeral X25519 public key (32 bytes).
    pub x25519_public: [u8; 32],
    /// Optional signalling bytes (MTU/mode negotiation).
    pub signalling: Vec<u8>,
}

/// Parsed fields from a LINKREQUEST data payload.
#[derive(Debug, Clone)]
pub struct ParsedRequestData {
    /// Initiator's ephemeral X25519 public key (32 bytes).
    pub x25519_public: [u8; 32],
    /// Initiator's ephemeral Ed25519 public key (32 bytes).
    pub ed25519_public: [u8; 32],
    /// Optional signalling bytes (MTU/mode negotiation).
    pub signalling: Vec<u8>,
}

/// Parse an LRPROOF data payload into its component fields.
///
/// Layout: `signature(64) || x25519_pub(32) || [signalling(3)]`
pub fn parse_proof_data(data: &[u8]) -> Result<ParsedProofData, LinkError> {
    let min_len = SIGNATURE_SIZE + LINK_KEYSIZE;
    if data.len() < min_len {
        return Err(LinkError::InvalidProof);
    }

    let signature: [u8; 64] = data[..SIGNATURE_SIZE]
        .try_into()
        .map_err(|_| LinkError::InvalidProof)?;
    let x25519_public: [u8; 32] = data[SIGNATURE_SIZE..min_len]
        .try_into()
        .map_err(|_| LinkError::InvalidProof)?;
    let signalling = if data.len() > min_len {
        data[min_len..].to_vec()
    } else {
        Vec::new()
    };

    Ok(ParsedProofData {
        signature,
        x25519_public,
        signalling,
    })
}

/// Parse a LINKREQUEST data payload into its component fields.
///
/// Layout: `x25519_pub(32) || ed25519_pub(32) || [signalling(3)]`
pub fn parse_request_data(data: &[u8]) -> Result<ParsedRequestData, LinkError> {
    if data.len() < ECPUBSIZE {
        return Err(LinkError::RequestDataTooShort);
    }

    let x25519_public: [u8; 32] = data[..32]
        .try_into()
        .map_err(|_| LinkError::RequestDataConversion)?;
    let ed25519_public: [u8; 32] = data[32..64]
        .try_into()
        .map_err(|_| LinkError::RequestDataConversion)?;
    let signalling = if data.len() > ECPUBSIZE {
        data[ECPUBSIZE..].to_vec()
    } else {
        Vec::new()
    };

    Ok(ParsedRequestData {
        x25519_public,
        ed25519_public,
        signalling,
    })
}

/// Build the signed data for link handshake verification.
///
/// Layout: `link_id(16) || x25519_pub(32) || ed25519_pub(32) || [signalling]`
pub fn build_signed_data(
    link_id: &[u8],
    x25519_pub: &[u8],
    ed25519_pub: &[u8],
    signalling: &[u8],
) -> Vec<u8> {
    let mut data =
        Vec::with_capacity(link_id.len() + x25519_pub.len() + ed25519_pub.len() + signalling.len());
    data.extend_from_slice(link_id);
    data.extend_from_slice(x25519_pub);
    data.extend_from_slice(ed25519_pub);
    data.extend_from_slice(signalling);
    data
}

/// Build an LRPROOF data payload from its component fields.
///
/// Layout: `signature(64) || x25519_pub(32) || [signalling]`
pub fn build_proof_data(signature: &[u8], x25519_pub: &[u8], signalling: &[u8]) -> Vec<u8> {
    let mut data = Vec::with_capacity(signature.len() + x25519_pub.len() + signalling.len());
    data.extend_from_slice(signature);
    data.extend_from_slice(x25519_pub);
    data.extend_from_slice(signalling);
    data
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Encode an RTT value as MessagePack float64.
#[must_use]
fn encode_rtt_msgpack(rtt: f64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(9);
    // SAFETY: encoding to a Vec<u8> never fails (infallible Write impl).
    rmpv::encode::write_value(&mut buf, &rmpv::Value::F64(rtt))
        .expect("msgpack encoding to Vec never fails");
    buf
}

/// Decode an RTT value from MessagePack.
fn decode_rtt_msgpack(data: &[u8]) -> Result<f64, LinkError> {
    let mut cursor = Cursor::new(data);
    let value =
        rmpv::decode::read_value(&mut cursor).map_err(|_| LinkError::InvalidRttFormat)?;
    match value {
        rmpv::Value::F64(v) => Ok(v),
        rmpv::Value::F32(v) => Ok(v as f64),
        _ => Err(LinkError::InvalidRttFormat),
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
#[must_use]
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
        is_establishment_timed_out_at(
            self.request_time.elapsed().as_secs_f64(),
            self.establishment_timeout,
        )
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
        raw_proof_data: &[u8],
        responder_ed25519_pub: &Ed25519PublicKey,
        rtt: f64,
        fixed_iv: Option<&[u8; 16]>,
    ) -> Result<(LinkActive, Vec<u8>), LinkError> {
        let parsed = parse_proof_data(raw_proof_data)?;

        let peer_x25519_pub = X25519PublicKey::from_bytes(parsed.x25519_public);
        let signature = Ed25519Signature::from_bytes(parsed.signature);

        // ECDH + HKDF
        let derived_key =
            derive_link_key(&self.eph_x25519_private, &peer_x25519_pub, &self.link_id);

        tracing::debug!(link_id = ?self.link_id, "initiator ECDH + HKDF complete");

        let signed_data = build_signed_data(
            self.link_id.as_ref(),
            &parsed.x25519_public,
            &responder_ed25519_pub.to_bytes(),
            &parsed.signalling,
        );

        // Verify signature
        responder_ed25519_pub
            .verify(&signed_data, &signature)
            .map_err(|_| LinkError::SignatureVerificationFailed)?;

        tracing::info!(link_id = ?self.link_id, "link proof verified (initiator)");

        // Encode RTT as msgpack and encrypt with Token
        let rtt_msgpack = encode_rtt_msgpack(rtt);
        let token = Token::new(&derived_key.to_bytes());
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
#[must_use]
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
        let parsed = parse_request_data(request_data)?;

        let peer_x25519_pub = X25519PublicKey::from_bytes(parsed.x25519_public);
        let peer_ed25519_pub = Ed25519PublicKey::from_bytes(parsed.ed25519_public)?;

        // Compute link_id from the packet-level hashable part
        let link_id = LinkPending::compute_link_id(hashable_part, data_len);

        // Our ephemeral X25519 public key
        let eph_x25519_pub = eph_x25519.public_key();

        // ECDH + HKDF
        let derived_key = derive_link_key(&eph_x25519, &peer_x25519_pub, &link_id);

        tracing::debug!(link_id = ?link_id, "responder ECDH + HKDF complete");

        // Build responder's signalling bytes (only if initiator sent them)
        let resp_signalling: Vec<u8> = if !parsed.signalling.is_empty() {
            super::mtu::encode(mtu, mode)?.to_vec()
        } else {
            Vec::new()
        };

        let signed_data = build_signed_data(
            link_id.as_ref(),
            &eph_x25519_pub.to_bytes(),
            &identity_ed25519_pub.to_bytes(),
            &resp_signalling,
        );

        // Sign with identity Ed25519 key
        let signature = identity_ed25519_prv.sign(&signed_data);

        let proof_data = build_proof_data(
            &signature.to_bytes(),
            &eph_x25519_pub.to_bytes(),
            &resp_signalling,
        );

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
        let token = Token::new(&self.derived_key.to_bytes());
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
        is_establishment_timed_out_at(
            self.request_time.elapsed().as_secs_f64(),
            self.establishment_timeout,
        )
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
#[must_use]
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
        tracing::trace!(plaintext_len = plaintext.len(), "encrypting link data");
        let token = Token::new(&self.derived_key.to_bytes());
        Ok(token.encrypt(plaintext))
    }

    /// Encrypt data with a specific IV (for deterministic testing).
    pub fn encrypt_with_iv(&self, plaintext: &[u8], iv: &[u8; 16]) -> Result<Vec<u8>, LinkError> {
        let token = Token::new(&self.derived_key.to_bytes());
        Ok(token.encrypt_with_iv(plaintext, iv))
    }

    /// Decrypt data using the link's derived key (Token format).
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, LinkError> {
        tracing::trace!(ciphertext_len = ciphertext.len(), "decrypting link data");
        let token = Token::new(&self.derived_key.to_bytes());
        Ok(token.decrypt(ciphertext)?)
    }

    /// Sign data using the link's derived signing key (HMAC-SHA256).
    #[must_use]
    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        hmac_sha256(self.derived_key.signing_key(), data).to_vec()
    }

    /// Verify a signature against data using the link's derived signing key.
    #[must_use]
    pub fn verify(&self, data: &[u8], signature: &[u8]) -> bool {
        if let Ok(sig_arr) = <&[u8; 32]>::try_from(signature) {
            hmac_sha256_verify(self.derived_key.signing_key(), data, sig_arr).is_ok()
        } else {
            false
        }
    }

    /// Whether it's time to send a keepalive packet.
    pub fn should_send_keepalive(&self) -> bool {
        should_send_keepalive_at(self.last_outbound.elapsed().as_secs_f64(), self.keepalive)
    }

    /// Whether the link should transition to stale.
    pub fn should_go_stale(&self) -> bool {
        should_go_stale_at(
            self.is_stale,
            self.last_inbound.elapsed().as_secs_f64(),
            self.stale_time,
        )
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
        let elapsed_stale = self.stale_since.map(|s| s.elapsed().as_secs_f64());
        should_teardown_at(
            self.is_stale,
            elapsed_stale,
            self.last_inbound.elapsed().as_secs_f64(),
            self.keepalive,
        )
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
    #[must_use]
    pub fn compute_keepalive(rtt: f64) -> f64 {
        (rtt * (KEEPALIVE_MAX / KEEPALIVE_MAX_RTT)).clamp(KEEPALIVE_MIN, KEEPALIVE_MAX)
    }

    /// Compute the maximum data unit size for a given MTU.
    ///
    /// `MDU = floor((mtu - IFAC_MIN_SIZE - HEADER_MINSIZE - TOKEN_OVERHEAD) / AES_BLOCKSIZE) * AES_BLOCKSIZE - 1`
    #[must_use]
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
#[must_use]
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

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // should_send_keepalive_at
    // -----------------------------------------------------------------------

    #[test]
    fn keepalive_under_threshold() {
        assert!(!should_send_keepalive_at(9.9, 10.0));
    }

    #[test]
    fn keepalive_over_threshold() {
        assert!(should_send_keepalive_at(10.1, 10.0));
    }

    #[test]
    fn keepalive_exact_boundary() {
        // Exact equality is NOT over threshold (uses strict >)
        assert!(!should_send_keepalive_at(10.0, 10.0));
    }

    // -----------------------------------------------------------------------
    // should_go_stale_at
    // -----------------------------------------------------------------------

    #[test]
    fn stale_already_stale_guard() {
        // Already stale → never transitions again
        assert!(!should_go_stale_at(true, 999.0, 10.0));
    }

    #[test]
    fn stale_under_threshold() {
        assert!(!should_go_stale_at(false, 9.9, 10.0));
    }

    #[test]
    fn stale_over_threshold() {
        assert!(should_go_stale_at(false, 10.1, 10.0));
    }

    #[test]
    fn stale_exact_boundary() {
        assert!(!should_go_stale_at(false, 10.0, 10.0));
    }

    // -----------------------------------------------------------------------
    // should_teardown_at
    // -----------------------------------------------------------------------

    #[test]
    fn teardown_stale_under_grace() {
        assert!(!should_teardown_at(true, Some(4.9), 999.0, 10.0));
    }

    #[test]
    fn teardown_stale_over_grace() {
        assert!(should_teardown_at(true, Some(5.1), 999.0, 10.0));
    }

    #[test]
    fn teardown_stale_exact_grace() {
        // Exact STALE_GRACE is NOT over threshold (strict >)
        assert!(!should_teardown_at(true, Some(STALE_GRACE), 999.0, 10.0));
    }

    #[test]
    fn teardown_stale_no_since_falls_through() {
        // Stale but no stale_since → falls through to inbound check
        // keepalive=10, factor=4 → threshold=40
        assert!(!should_teardown_at(true, None, 39.9, 10.0));
        assert!(should_teardown_at(true, None, 40.1, 10.0));
    }

    #[test]
    fn teardown_not_stale_under_timeout() {
        // keepalive=10, factor=4 → threshold=40
        assert!(!should_teardown_at(false, None, 39.9, 10.0));
    }

    #[test]
    fn teardown_not_stale_over_timeout() {
        assert!(should_teardown_at(false, None, 40.1, 10.0));
    }

    #[test]
    fn teardown_not_stale_exact_timeout() {
        assert!(!should_teardown_at(false, None, 40.0, 10.0));
    }

    // -----------------------------------------------------------------------
    // is_establishment_timed_out_at
    // -----------------------------------------------------------------------

    #[test]
    fn establishment_under_timeout() {
        assert!(!is_establishment_timed_out_at(5.0, 6.0));
    }

    #[test]
    fn establishment_over_timeout() {
        assert!(is_establishment_timed_out_at(7.0, 6.0));
    }

    #[test]
    fn establishment_exact_boundary() {
        assert!(!is_establishment_timed_out_at(6.0, 6.0));
    }

    #[test]
    fn establishment_zero_elapsed() {
        assert!(!is_establishment_timed_out_at(0.0, 6.0));
    }

    // -----------------------------------------------------------------------
    // Relationship: compute_traffic_timeout matches keepalive * factor
    // -----------------------------------------------------------------------

    #[test]
    fn traffic_timeout_matches_keepalive_times_factor() {
        for ka in [5.0, 10.0, 100.0, 360.0] {
            let timeout = LinkActive::compute_traffic_timeout(ka);
            let expected = ka * TRAFFIC_TIMEOUT_FACTOR;
            assert!(
                (timeout - expected).abs() < 1e-10,
                "traffic_timeout({ka}) = {timeout}, expected {expected}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // parse_proof_data
    // -----------------------------------------------------------------------

    #[test]
    fn parse_proof_exact_min_size() {
        // 64 + 32 = 96 bytes minimum
        let mut data = vec![0xAA; 64]; // signature
        data.extend_from_slice(&[0xBB; 32]); // x25519
        let parsed = parse_proof_data(&data).unwrap();
        assert_eq!(parsed.signature, [0xAA; 64]);
        assert_eq!(parsed.x25519_public, [0xBB; 32]);
        assert!(parsed.signalling.is_empty());
    }

    #[test]
    fn parse_proof_with_signalling() {
        let mut data = vec![0xAA; 64];
        data.extend_from_slice(&[0xBB; 32]);
        data.extend_from_slice(&[0x01, 0x02, 0x03]); // 3 signalling bytes
        let parsed = parse_proof_data(&data).unwrap();
        assert_eq!(parsed.signature, [0xAA; 64]);
        assert_eq!(parsed.x25519_public, [0xBB; 32]);
        assert_eq!(parsed.signalling, vec![0x01, 0x02, 0x03]);
    }

    #[test]
    fn parse_proof_too_short() {
        let data = vec![0x00; 95]; // one byte short
        assert!(parse_proof_data(&data).is_err());
    }

    #[test]
    fn parse_proof_empty() {
        assert!(parse_proof_data(&[]).is_err());
    }

    // -----------------------------------------------------------------------
    // parse_request_data
    // -----------------------------------------------------------------------

    #[test]
    fn parse_request_exact_min_size() {
        let mut data = vec![0xCC; 32]; // x25519
        data.extend_from_slice(&[0xDD; 32]); // ed25519
        let parsed = parse_request_data(&data).unwrap();
        assert_eq!(parsed.x25519_public, [0xCC; 32]);
        assert_eq!(parsed.ed25519_public, [0xDD; 32]);
        assert!(parsed.signalling.is_empty());
    }

    #[test]
    fn parse_request_with_signalling() {
        let mut data = vec![0xCC; 32];
        data.extend_from_slice(&[0xDD; 32]);
        data.extend_from_slice(&[0x04, 0x05, 0x06]);
        let parsed = parse_request_data(&data).unwrap();
        assert_eq!(parsed.x25519_public, [0xCC; 32]);
        assert_eq!(parsed.ed25519_public, [0xDD; 32]);
        assert_eq!(parsed.signalling, vec![0x04, 0x05, 0x06]);
    }

    #[test]
    fn parse_request_too_short() {
        let data = vec![0x00; 63];
        assert!(parse_request_data(&data).is_err());
    }

    #[test]
    fn parse_request_empty() {
        assert!(parse_request_data(&[]).is_err());
    }

    // -----------------------------------------------------------------------
    // build_signed_data
    // -----------------------------------------------------------------------

    #[test]
    fn build_signed_data_no_signalling() {
        let link_id = [0x11; 16];
        let x25519 = [0x22; 32];
        let ed25519 = [0x33; 32];
        let result = build_signed_data(&link_id, &x25519, &ed25519, &[]);
        assert_eq!(result.len(), 80);
        assert_eq!(&result[..16], &[0x11; 16]);
        assert_eq!(&result[16..48], &[0x22; 32]);
        assert_eq!(&result[48..80], &[0x33; 32]);
    }

    #[test]
    fn build_signed_data_with_signalling() {
        let link_id = [0x11; 16];
        let x25519 = [0x22; 32];
        let ed25519 = [0x33; 32];
        let sig = [0x44, 0x55, 0x66];
        let result = build_signed_data(&link_id, &x25519, &ed25519, &sig);
        assert_eq!(result.len(), 83);
        assert_eq!(&result[80..], &[0x44, 0x55, 0x66]);
    }

    #[test]
    fn build_signed_data_field_offsets() {
        let link_id = vec![1u8; 16];
        let x25519 = vec![2u8; 32];
        let ed25519 = vec![3u8; 32];
        let result = build_signed_data(&link_id, &x25519, &ed25519, &[]);
        // Verify field boundaries
        assert!(result[0..16].iter().all(|&b| b == 1));
        assert!(result[16..48].iter().all(|&b| b == 2));
        assert!(result[48..80].iter().all(|&b| b == 3));
    }

    // -----------------------------------------------------------------------
    // build_proof_data
    // -----------------------------------------------------------------------

    #[test]
    fn build_proof_data_no_signalling() {
        let sig = [0xAA; 64];
        let x25519 = [0xBB; 32];
        let result = build_proof_data(&sig, &x25519, &[]);
        assert_eq!(result.len(), 96);
        assert_eq!(&result[..64], &[0xAA; 64]);
        assert_eq!(&result[64..96], &[0xBB; 32]);
    }

    #[test]
    fn build_proof_data_with_signalling() {
        let sig = [0xAA; 64];
        let x25519 = [0xBB; 32];
        let signalling = [0x01, 0x02, 0x03];
        let result = build_proof_data(&sig, &x25519, &signalling);
        assert_eq!(result.len(), 99);
        assert_eq!(&result[96..], &[0x01, 0x02, 0x03]);
    }

    // -----------------------------------------------------------------------
    // Roundtrip: build_proof_data -> parse_proof_data
    // -----------------------------------------------------------------------

    #[test]
    fn proof_data_roundtrip() {
        let sig = [0x42; 64];
        let x25519 = [0x99; 32];
        let signalling = [0xAB, 0xCD, 0xEF];
        let built = build_proof_data(&sig, &x25519, &signalling);
        let parsed = parse_proof_data(&built).unwrap();
        assert_eq!(parsed.signature, sig);
        assert_eq!(parsed.x25519_public, x25519);
        assert_eq!(parsed.signalling, signalling);
    }

    // -----------------------------------------------------------------------
    // decode_rtt_msgpack failure paths
    // -----------------------------------------------------------------------

    #[test]
    fn test_decode_rtt_msgpack_garbage() {
        let garbage = [0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04];
        let result = decode_rtt_msgpack(&garbage);
        assert!(result.is_err(), "garbage bytes should fail RTT decode");
    }

    #[test]
    fn test_decode_rtt_msgpack_non_float() {
        // Encode an integer (42) in msgpack
        let mut buf = Vec::new();
        rmpv::encode::write_value(&mut buf, &rmpv::Value::Integer(42.into())).unwrap();
        let result = decode_rtt_msgpack(&buf);
        assert!(result.is_err(), "integer should not decode as RTT float");
        assert!(
            matches!(result.unwrap_err(), LinkError::InvalidRttFormat),
            "error should be InvalidRttFormat"
        );
    }
}
