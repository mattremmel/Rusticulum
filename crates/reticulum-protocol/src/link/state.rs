//! Link type-state machine.
//!
//! Four structs represent the link lifecycle: `LinkPending` → `LinkHandshake` →
//! `LinkActive` → `LinkClosed`. Each struct holds only the data relevant to that
//! state. The `LinkState` enum wraps all four for runtime dispatch.

use std::time::Instant;

use reticulum_core::types::{DestinationHash, LinkId};
use reticulum_crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey};
use reticulum_crypto::sha::sha256;
use reticulum_crypto::x25519::{X25519PrivateKey, X25519PublicKey};

use super::constants::{
    AES_BLOCKSIZE, ECPUBSIZE, ESTABLISHMENT_TIMEOUT_PER_HOP, HEADER_MINSIZE, IFAC_MIN_SIZE,
    KEEPALIVE_DEFAULT, KEEPALIVE_MAX, KEEPALIVE_MAX_RTT, KEEPALIVE_MIN, KEEPALIVE_TIMEOUT_FACTOR,
    STALE_FACTOR, STALE_GRACE, TOKEN_OVERHEAD, TRAFFIC_TIMEOUT_FACTOR,
};
use super::types::{DerivedKey, LinkMode, LinkRole, LinkStats, TeardownReason};
use crate::error::LinkError;

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
pub struct LinkHandshake {
    pub link_id: LinkId,
    pub derived_key: DerivedKey,
    pub eph_ed25519_private: Ed25519PrivateKey,
    pub peer_ed25519_public: Ed25519PublicKey,
    pub role: LinkRole,
    pub mode: LinkMode,
    pub mtu: u32,
    pub request_time: Instant,
    pub establishment_timeout: f64,
}

impl LinkHandshake {
    /// Create from a pending link on the responder side.
    /// Implemented in c7u.2 (link handshake).
    pub fn from_pending_responder(
        _pending: LinkPending,
        _peer_x25519_public: &X25519PublicKey,
    ) -> Result<(Self, Vec<u8>), LinkError> {
        todo!("Implemented in c7u.2: responder ECDH + proof generation")
    }

    /// Create from a pending link on the initiator side after receiving proof.
    /// Implemented in c7u.2 (link handshake).
    pub fn from_pending_initiator_with_proof(
        _pending: LinkPending,
        _proof_data: &[u8],
    ) -> Result<Self, LinkError> {
        todo!("Implemented in c7u.2: initiator proof validation + ECDH")
    }

    /// Process an RTT measurement packet and transition to active.
    /// Implemented in c7u.2 (link handshake).
    pub fn receive_rtt(self, _rtt_data: &[u8]) -> Result<LinkActive, LinkError> {
        todo!("Implemented in c7u.2: decrypt RTT token and activate link")
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
    /// Implemented in c7u.2 (link handshake).
    pub fn encrypt(&self, _plaintext: &[u8]) -> Result<Vec<u8>, LinkError> {
        todo!("Implemented in c7u.2: Token encrypt with derived_key")
    }

    /// Decrypt data using the link's derived key (Token format).
    /// Implemented in c7u.2 (link handshake).
    pub fn decrypt(&self, _ciphertext: &[u8]) -> Result<Vec<u8>, LinkError> {
        todo!("Implemented in c7u.2: Token decrypt with derived_key")
    }

    /// Sign data using the link's derived signing key.
    /// Implemented in c7u.2 (link handshake).
    pub fn sign(&self, _data: &[u8]) -> Vec<u8> {
        todo!("Implemented in c7u.2: HMAC-SHA256 with signing_key")
    }

    /// Verify a signature against data using the link's derived signing key.
    /// Implemented in c7u.2 (link handshake).
    pub fn verify(&self, _data: &[u8], _signature: &[u8]) -> bool {
        todo!("Implemented in c7u.2: HMAC-SHA256 verify with signing_key")
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
