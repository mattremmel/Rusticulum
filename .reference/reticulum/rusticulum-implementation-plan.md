# Reticulum Rust Implementation Plan

## Context

The Python reference implementation of Reticulum (v1.1.3) is complete and has comprehensive test vectors (39 JSON files) covering every protocol layer. These vectors are fully self-contained and can validate an alternate implementation without running the Python code. The goal is to build a clean, idiomatic Rust implementation that can interoperate with the reference implementation, using these test vectors to verify correctness at every step.

The Python implementation is heavily stateful with large monolithic classes, global singletons, and threading. The Rust implementation should reflect the _logical_ protocol architecture with strong types, explicit state machines, zero global mutable state, and async I/O where appropriate.

---

## Part 1: Protocol Architecture Overview

### Layer Stack (Bottom to Top)

```
Physical Mediums (TCP, UDP, Serial, LoRa, I2P)
       |
Interface Layer (HDLC/KISS framing, byte-stuffing)
       |
Packet Layer (wire format: flags + header + payload)
       |
Identity & Addressing (X25519+Ed25519 keypairs, destination hashes)
       |
Transport (routing, announce propagation, path discovery, dedup)
       |
Link (encrypted bidirectional sessions, 3-packet handshake)
       |
Channel (message envelopes, sequencing, window control)
       |
Resource (large transfers, windowing, segmentation, proofs)
Buffer (stream protocol, compression, EOF)
Request/Response (RPC-style over links)
       |
Application
```

### Cryptographic Primitive Chain

Everything builds on these primitives, in this dependency order:

1. **SHA-256 / SHA-512** - Foundation hash functions
2. **HMAC-SHA256** - Keyed hashing (used by HKDF, Token)
3. **HKDF-SHA256** - Key derivation (RFC 5869, empty salt = 32 zero bytes)
4. **PKCS7** - Padding for AES-CBC (16-byte block size)
5. **AES-256-CBC** - Symmetric encryption (with PKCS7 padding)
6. **Token** - Modified Fernet: `IV(16) || AES-256-CBC(PKCS7(plaintext)) || HMAC-SHA256(signing_key, IV || ciphertext)`. Key split: 64 bytes → `signing_key = key[0:32]`, `encryption_key = key[32:64]`. **No version byte, no timestamp** (unlike standard Fernet).
7. **X25519** - Elliptic curve Diffie-Hellman key exchange
8. **Ed25519** - Digital signatures (sign/verify)

### Addressing Model

```
name_hash       = SHA256("app_name.aspect1.aspect2".encode("utf-8"))[0:10]   (10 bytes)
identity_hash   = SHA256(x25519_pub || ed25519_pub)[0:16]                     (16 bytes)
destination_hash = SHA256(name_hash || identity_hash)[0:16]                    (16 bytes)
```

### Identity Encryption (Envelope)

```
1. Generate ephemeral X25519 keypair
2. ECDH: shared_secret = ephemeral_prv.exchange(target_pub_or_ratchet)
3. derived_key = HKDF(length=64, ikm=shared_secret, salt=identity_hash, info=b"")
4. token = Token(derived_key).encrypt(plaintext)
5. output = ephemeral_pub(32) || token(48+ bytes)
```

### Packet Wire Format

**Flags byte (1 byte):**

```
Bit 7:    header_type   (0=HEADER_1, 1=HEADER_2)
Bit 6:    context_flag  (0=unset, 1=set)
Bit 5:    transport_type (0=BROADCAST, 1=TRANSPORT)
Bits 4-3: destination_type (00=SINGLE, 01=GROUP, 10=PLAIN, 11=LINK)
Bits 1-0: packet_type (00=DATA, 01=ANNOUNCE, 10=LINKREQUEST, 11=PROOF)
```

**HEADER_1** (19+ bytes): `flags(1) + hops(1) + dest_hash(16) + context(1) + data(...)`
**HEADER_2** (35+ bytes): `flags(1) + hops(1) + transport_id(16) + dest_hash(16) + context(1) + data(...)`

**Hashable part** (for packet hash computation): mask flags to lower 4 bits only, strip hops byte, strip transport_id if HEADER_2.

### Link Handshake (3 Packets)

```
INITIATOR                                    RESPONDER
    |                                            |
    |-- LINKREQUEST [eph_x25519(32) +            |
    |   eph_ed25519(32) + mtu_signal(3?)] ----> |
    |                                            |
    |   link_id = SHA256(hashable_part)[0:16]    |
    |   (strip mtu signalling from hashable)     |
    |                                            |
    | <---- LRPROOF [signature(64) +             |
    |        resp_x25519(32) + mtu_signal(3?)]   |
    |                                            |
    |   Both sides: ECDH → HKDF(64, shared,      |
    |     salt=link_id) → Token(derived_key)     |
    |                                            |
    |-- LRRTT [Token.encrypt(msgpack(rtt))] ---> |
    |                                            |
    |         === LINK ACTIVE ===                |
```

### Key Constants

| Constant             | Value    | Notes                                   |
| -------------------- | -------- | --------------------------------------- |
| MTU                  | 500      | Maximum transmission unit               |
| HEADER_MINSIZE       | 19       | HEADER_1                                |
| HEADER_MAXSIZE       | 37       | HEADER_2                                |
| MDU                  | 462      | Max data unit: MTU - HEADER_MAXSIZE - 1 |
| TRUNCATED_HASHLENGTH | 16 bytes | Destination/identity hash               |
| HASHLENGTH           | 32 bytes | Full SHA-256                            |
| KEYSIZE              | 64 bytes | 32 X25519 + 32 Ed25519                  |
| SIGLENGTH            | 64 bytes | Ed25519 signature                       |
| NAME_HASH_LENGTH     | 10 bytes | Truncated app name hash                 |
| TOKEN_OVERHEAD       | 48 bytes | 16 IV + 32 HMAC                         |
| ECPUBSIZE            | 64 bytes | Ephemeral pub in link request           |

---

## Part 2: Rust Crate Architecture

### Workspace Layout

```
reticulum-rs/
  Cargo.toml                  # [workspace]
  test-vectors/               # JSON files copied from reference repo
  crates/
    reticulum-crypto/         # Pure crypto primitives (no protocol concepts)
    reticulum-core/           # Types, constants, wire formats, identity, addressing
    reticulum-protocol/       # Protocol state machines (link, resource, channel, buffer)
    reticulum-transport/      # Routing, announce propagation, path tables
    reticulum-interfaces/     # TCP, UDP, Serial, Local with framing
    reticulum-node/           # Orchestration, config, storage
```

**Dependency graph:**

```
reticulum-crypto  (leaf - no protocol deps, no async, no I/O)
       ↑
reticulum-core    (types + wire formats, depends on crypto)
       ↑
reticulum-protocol (state machines, depends on core, no I/O)
       ↑
reticulum-transport (routing, depends on protocol, async)
       ↑
reticulum-interfaces (I/O, depends on core for framing, async)
       ↑
reticulum-node    (orchestrator, depends on everything, async)
```

Key principle: **protocol state machines produce actions, not I/O**. A link handshake returns `Vec<u8>` bytes to send, not a socket write. This makes everything testable without networking.

### `reticulum-crypto` Modules

```
sha256, sha512    - Hash wrappers
hmac              - HMAC-SHA256
hkdf              - HKDF-SHA256 (empty salt → 32 zero bytes, counter = (i+1) % 256)
pkcs7             - PKCS7 pad/unpad (16-byte block)
aes_cbc           - AES-256-CBC encrypt/decrypt
token             - Modified Fernet (Token)
                    Internal encrypt_with_iv() for deterministic test vectors
```

Recommended crates: `sha2`, `hmac`, `aes`, `cbc` (RustCrypto family), `x25519-dalek`, `ed25519-dalek`, `rand`.

### `reticulum-core` Modules

```
constants         - All protocol constants
types             - Newtypes: TruncatedHash([u8;16]), FullHash([u8;32]),
                    DestinationHash, IdentityHash, NameHash([u8;10]),
                    LinkId, PacketHash, X25519Pub([u8;32]), Ed25519Pub([u8;32]),
                    PublicKey{encryption, signing}, Signature([u8;64])
identity          - Identity struct (private+public or public-only),
                    hash derivation, encrypt/decrypt/sign/verify, ratchets
destination       - DestinationType enum, hash derivation, proof strategies
packet/
  flags           - PacketFlags encode/decode (single byte ↔ struct)
  header          - HEADER_1/HEADER_2 layouts
  types           - PacketType, ContextType, DestinationType, HeaderType enums
  wire            - RawPacket<'a> zero-copy parse/serialize, hashable_part()
announce          - Announce construction, validation, ratchet support
framing/
  hdlc            - FLAG=0x7E, ESC=0x7D, ESC_MASK=0x20
  kiss            - FEND=0xC0, FESC=0xDB, TFEND=0xDC, TFESC=0xDD
```

### `reticulum-protocol` Modules

```
link/
  state           - LinkPending → LinkHandshake → LinkActive → LinkClosed
  handshake       - Initiator/responder logic, key derivation
  mtu             - MTU signalling encode/decode (3 bytes, 21-bit MTU + 3-bit mode)
  keepalive       - Interval calculation: max(min(rtt * 360/1.75, 360), 5)
resource/
  advertisement   - Msgpack dict {t,d,n,h,r,o,i,l,q,f,m}
  state           - Queued → Advertised → Transferring → AwaitingProof → Complete
  window          - WindowState: adapt on success/timeout, speed class thresholds
  hashmap         - 4-byte truncated hashes, HASHMAP_MAX_LEN=74
  transfer        - Part sequencing, proof = SHA256(data || resource_hash)
  segment         - Split resources: MAX_EFFICIENT_SIZE = 1,048,575
channel/
  envelope        - 6-byte header: msg_type(2) + sequence(2) + length(2)
  sequencing      - Sequence tracking (wraps at 0xFFFF), window control
  state           - Window adaptation based on RTT thresholds
buffer/
  stream          - 2-byte header: bit15=EOF, bit14=compressed, bits13-0=stream_id
  compression     - bz2 with 4 retry attempts at decreasing sizes
request           - Request/Response over links (msgpack [timestamp, path_hash, data])
```

### `reticulum-transport` Modules

```
router            - Packet dispatch, destination registry
path_table        - Path entries with TTL (7 days normal, 1 day AP, 6h roaming)
announce          - Propagation rules (2% bandwidth cap, hop limit 128, dedup)
dedup             - Packet hash set (max 1M entries, cull at 50%)
ifac              - Interface access codes (hardcoded salt, HMAC suffix)
```

### `reticulum-interfaces` Modules

```
traits            - Interface trait (async transmit/receive, bitrate, mode)
tcp               - TCP with HDLC framing
udp               - UDP broadcast/unicast
local             - IPC via Unix socket
auto              - IPv6 multicast discovery
```

---

## Part 3: Key Type Design

### Newtypes (prevent mixing raw byte arrays)

```rust
pub struct TruncatedHash([u8; 16]);    // implements Copy, Eq, Hash, AsRef<[u8]>
pub struct FullHash([u8; 32]);
pub struct DestinationHash(TruncatedHash);
pub struct IdentityHash(TruncatedHash);
pub struct NameHash([u8; 10]);
pub struct LinkId(TruncatedHash);
pub struct PacketHash(FullHash);
pub struct Signature([u8; 64]);

pub struct PublicKey {
    pub encryption: X25519Pub,   // [u8; 32]
    pub signing: Ed25519Pub,     // [u8; 32]
}
```

All implement `TryFrom<&[u8]>`, `AsRef<[u8]>`, `Display` (hex), serde `Serialize`/`Deserialize`.

### Identity (public-only or full)

```rust
pub struct Identity { /* private fields */ }

impl Identity {
    pub fn generate() -> Self;
    pub fn from_private_bytes(bytes: &[u8; 64]) -> Result<Self>;
    pub fn from_public_bytes(bytes: &[u8; 64]) -> Result<Self>;
    pub fn hash(&self) -> IdentityHash;
    pub fn public_key(&self) -> PublicKey;
    pub fn has_private_key(&self) -> bool;
    pub fn sign(&self, message: &[u8]) -> Result<Signature>;
    pub fn verify(&self, signature: &Signature, message: &[u8]) -> bool;
    pub fn encrypt(&self, plaintext: &[u8], ratchet: Option<&[u8; 32]>) -> Result<Vec<u8>>;
    pub fn decrypt(&self, ciphertext: &[u8], ratchets: &[[u8; 32]]) -> Result<Vec<u8>>;
}
```

### Packet (zero-copy parse)

```rust
pub struct RawPacket<'a> {
    pub flags: PacketFlags,
    pub hops: u8,
    pub transport_id: Option<DestinationHash>,
    pub destination: DestinationHash,
    pub context: ContextType,
    pub data: &'a [u8],
}

impl<'a> RawPacket<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self>;
    pub fn serialize(&self) -> Vec<u8>;
    pub fn hashable_part(&self) -> Vec<u8>;
    pub fn packet_hash(&self) -> PacketHash;
}
```

### Link State Machine (type-state pattern)

```rust
pub struct LinkPending { /* ephemeral keys, destination, request_time */ }
pub struct LinkHandshake { /* derived_key, token, peer_sig_pub */ }
pub struct LinkActive { /* token, rtt, mdu, keepalive_interval */ }

impl LinkPending {
    // Responder receives LINKREQUEST
    pub fn accept(identity: &Identity, packet: &RawPacket)
        -> Result<(LinkHandshake, Vec<u8>)>;  // returns LRPROOF bytes

    // Initiator receives LRPROOF
    pub fn complete(self, proof_data: &[u8], dest_identity: &Identity)
        -> Result<(LinkActive, Vec<u8>)>;      // returns LRRTT bytes
}

impl LinkHandshake {
    pub fn receive_rtt(self, encrypted: &[u8]) -> Result<LinkActive>;
}

impl LinkActive {
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>>;
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>>;
    pub fn should_send_keepalive(&self, now: Instant) -> bool;
    pub fn is_stale(&self, now: Instant) -> bool;
}
```

For runtime use, wrap in `enum LinkState { Pending(..), Handshake(..), Active(..), Closed }` behind `Arc<Mutex<..>>` for shared async access.

### Resource Window

```rust
pub struct WindowState {
    pub current: usize,      // starts at WINDOW_INITIAL (4)
    pub min: usize,          // WINDOW_MIN (2)
    pub max: usize,          // changes with speed class
    pub flexibility: usize,  // WINDOW_FLEXIBILITY (4)
}

impl WindowState {
    pub fn on_success(&mut self);      // current = min(current + 1, max)
    pub fn on_timeout(&mut self);      // current = max(current - 1, min)
    pub fn set_speed_class(&mut self, bytes_per_sec: f64);
    // <250 B/s → max=4, <6250 B/s → max=10, else → max=75
}
```

### Channel Envelope

```rust
pub struct Envelope {
    pub msg_type: u16,
    pub sequence: u16,
    pub payload: Vec<u8>,
}

impl Envelope {
    pub fn pack(&self) -> Vec<u8>;              // 6-byte header + payload
    pub fn unpack(data: &[u8]) -> Result<Self>; // parse 6-byte header
    pub const OVERHEAD: usize = 6;
}
```

---

## Part 4: Implementation Phases and Test Vector Integration

### Phase 1: Crypto Primitives (`reticulum-crypto`)

Build and test each primitive in dependency order. For each, load the corresponding JSON test vector file via `include_str!` and `serde_json::from_str`.

| Step | Module             | Test Vector File                      | What to Validate                                           |
| ---- | ------------------ | ------------------------------------- | ---------------------------------------------------------- |
| 1.1  | `sha256`, `sha512` | `hashes.json`                         | Hash empty, block-aligned, multi-block, large inputs       |
| 1.2  | `hmac`             | `token.json` → `hmac_sha256` array    | HMAC with various key/message combos                       |
| 1.3  | `pkcs7`            | `token.json` → `pkcs7_padding` array  | Pad/unpad for all remainder classes                        |
| 1.4  | `aes_cbc`          | (tested via token)                    | AES-256-CBC with known IV                                  |
| 1.5  | `hkdf`             | `hkdf.json`                           | RFC 5869 cases + Reticulum ECDH vector; verify PRK and OKM |
| 1.6  | `token`            | `token.json` → encryption vectors     | Decrypt known tokens; encrypt with fixed IV and compare    |
| 1.7  | `x25519`           | `keypairs.json` → `shared_secrets`    | Load private key, derive public, ECDH exchange             |
| 1.8  | `ed25519`          | `keypairs.json` → `signature_vectors` | Sign known messages, verify known signatures               |

**Test pattern for crypto:**

```rust
#[test]
fn test_hkdf_rfc5869() {
    let vectors: HkdfTestFile = serde_json::from_str(include_str!("../../test-vectors/hkdf.json")).unwrap();
    for v in &vectors.rfc5869_vectors {
        let ikm = hex::decode(&v.ikm).unwrap();
        let salt = hex::decode(&v.salt).unwrap();
        let info = hex::decode(&v.info).unwrap();
        let expected = hex::decode(&v.okm).unwrap();
        let result = hkdf(v.length, &ikm, &salt, &info);
        assert_eq!(result, expected, "Failed: {}", v.description);
    }
}
```

### Phase 2: Core Types and Wire Formats (`reticulum-core`)

| Step | Module               | Test Vector File                               | What to Validate                                                                                   |
| ---- | -------------------- | ---------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| 2.1  | `constants`, `types` | (compile-time)                                 | Type definitions, trait impls                                                                      |
| 2.2  | `identity`           | `keypairs.json`                                | Load keypairs, derive identity_hash, encrypt/decrypt with known ephemeral                          |
| 2.3  | `destination`        | `destination_hashes.json`                      | Compute name_hash, destination_hash for each app/aspect combo                                      |
| 2.4  | `packet/flags`       | `packet_headers.json`                          | Encode/decode every flag combination                                                               |
| 2.5  | `packet/wire`        | `packets_data.json`                            | Parse raw packets, verify fields; serialize and compare bytes                                      |
| 2.6  | `framing/hdlc`       | `interface_framing.json` → `hdlc`              | Frame/unframe with escape sequences (ESC before FLAG order!)                                       |
| 2.7  | `framing/kiss`       | `interface_framing.json` → `kiss` (if present) | Frame/unframe with FEND/FESC                                                                       |
| 2.8  | `announce`           | `announces.json`                               | Construct announces from keypair + app data, verify signature matches; validate received announces |

**Test pattern for wire formats (bidirectional):**

```rust
#[test]
fn test_packet_roundtrip() {
    let vectors: PacketTestFile = serde_json::from_str(include_str!("../../test-vectors/packets_data.json")).unwrap();
    for v in &vectors.packets {
        // Parse known bytes → verify fields
        let raw = hex::decode(&v.raw_packet).unwrap();
        let packet = RawPacket::parse(&raw).unwrap();
        assert_eq!(packet.flags.packet_type, expected_packet_type(&v.packet_type));
        assert_eq!(packet.destination.as_ref(), hex::decode(&v.destination_hash).unwrap());
        // Serialize from fields → verify matches raw bytes
        let reserialized = packet.serialize();
        assert_eq!(reserialized, raw);
    }
}
```

### Phase 3: Protocol State Machines (`reticulum-protocol`)

| Step | Module                   | Test Vector File                     | What to Validate                                                         |
| ---- | ------------------------ | ------------------------------------ | ------------------------------------------------------------------------ |
| 3.1  | `link/handshake`         | `links.json`                         | Feed LINKREQUEST data, verify LRPROOF output, verify derived_key matches |
| 3.2  | `link/mtu`               | `links.json`                         | Encode/decode MTU signalling bytes                                       |
| 3.3  | `link/keepalive`         | `retry_timers.json`                  | Compute keepalive interval from RTT, verify against expected             |
| 3.4  | `channel/envelope`       | `channels.json` → `envelope_vectors` | Pack/unpack 6-byte envelopes                                             |
| 3.5  | `channel/sequencing`     | `channels.json`                      | Sequence wrapping at 0xFFFF, window adaptation                           |
| 3.6  | `resource/window`        | `window_adaptation.json`             | Window growth/shrink under various speed classes                         |
| 3.7  | `resource/advertisement` | `resources.json`                     | Parse/construct msgpack advertisements                                   |
| 3.8  | `resource/hashmap`       | `resource_transfers.json`            | Compute 4-byte part hashes, build hashmap segments                       |
| 3.9  | `resource/transfer`      | `resource_transfers.json`            | Full transfer simulation: encrypt parts, assemble, verify proof          |
| 3.10 | `buffer/stream`          | `buffer_transfers.json`              | Stream header encoding, chunking, compression attempts                   |
| 3.11 | `request`                | `requests.json`                      | Request/response msgpack format                                          |

**Test pattern for state machines:**

```rust
#[test]
fn test_link_handshake() {
    let vectors: LinkTestFile = serde_json::from_str(include_str!("../../test-vectors/links.json")).unwrap();
    for v in &vectors.handshake_vectors {
        // Create initiator with known ephemeral keys
        let pending = LinkPending::new_deterministic(
            &hex::decode(&v.initiator_ephemeral_x25519_prv).unwrap(),
            &hex::decode(&v.initiator_ephemeral_ed25519_prv).unwrap(),
            /* destination */
        );
        // Verify LINKREQUEST data matches
        assert_eq!(pending.request_data(), hex::decode(&v.link_request_data).unwrap());
        // Feed LRPROOF, verify derived key matches
        let (active, rtt_data) = pending.complete(&hex::decode(&v.lrproof_data).unwrap(), &identity).unwrap();
        assert_eq!(active.derived_key(), hex::decode(&v.derived_key).unwrap());
    }
}
```

### Phase 4: Transport (`reticulum-transport`)

| Step | Module       | Test Vector File                             | What to Validate                                        |
| ---- | ------------ | -------------------------------------------- | ------------------------------------------------------- |
| 4.1  | `path_table` | `path_requests.json`, `path_expiration.json` | Path entry creation, TTL enforcement, expiration        |
| 4.2  | `announce`   | `announces.json` (propagation rules)         | Rate limiting (2% cap), hop counting, dedup             |
| 4.3  | `router`     | `multi_hop_routing.json`                     | Multi-hop packet forwarding, transport header insertion |
| 4.4  | `dedup`      | (unit tests)                                 | Hash set with 1M limit, 50% culling                     |
| 4.5  | `ifac`       | (unit tests with hardcoded salt)             | HMAC suffix computation and validation                  |

### Phase 5: Interfaces and Node (`reticulum-interfaces`, `reticulum-node`)

No test vectors needed — this is async I/O glue code. Test with integration tests against the Python reference.

| Step | Module            | Testing                                              |
| ---- | ----------------- | ---------------------------------------------------- |
| 5.1  | `Interface` trait | Define async transmit/receive                        |
| 5.2  | TCP interface     | HDLC framing (uses vectors from 2.6) over TCP stream |
| 5.3  | UDP interface     | Raw packet send/recv                                 |
| 5.4  | Local interface   | IPC via Unix socket                                  |
| 5.5  | Node              | Config parsing, interface startup, router wiring     |

### Phase 6: Integration and Interop

1. Docker: run Python reference as a peer node
2. Test announce exchange (Rust announces, Python validates and vice versa)
3. Test link establishment (Rust initiator → Python responder and vice versa)
4. Test resource transfer in both directions
5. Test channel/buffer protocol
6. Multi-hop routing through mixed Rust/Python transport nodes

---

## Part 5: Test Vector File Schemas

Quick reference for the JSON structure of each file, so you know what serde types to define.

### `keypairs.json`

```
{ keypairs: [{ index, private_key, x25519_private, ed25519_private,
               public_key, x25519_public, ed25519_public,
               identity_hash, destination_hashes: {...} }],
  signature_vectors: [{ keypair_index, message, signature }],
  shared_secrets: [{ keypair_a, keypair_b, shared_secret }] }
```

### `hashes.json`

```
{ sha256_vectors: [{ input, expected }],
  sha512_vectors: [{ input, expected }] }
```

### `hkdf.json`

```
{ rfc5869_vectors: [{ ikm, salt, info, length, prk, okm }],
  reticulum_vector: { shared_key, salt, info, length, prk, derived_key } }
```

### `token.json`

```
{ pkcs7_padding: [{ input, block_size, padded }],
  hmac_sha256: [{ key, message, digest }],
  encryption_vectors: [{ key, plaintext, iv, ciphertext_with_hmac }] }
```

### `destination_hashes.json`

```
{ single_destinations: [{ app_name, aspects, name_hash,
  identity_hash, addr_hash_material, destination_hash, keypair_index }] }
```

### `packet_headers.json`

```
{ flag_byte_layout: {...}, packet_type_values: {...},
  context_type_values: {...}, constants: {...},
  header_vectors: [{ flags_byte, header_type, packet_type, ... }] }
```

### `announces.json`

```
{ valid_announces: [{ keypair_index, app_name, aspects, name_hash,
  destination_hash, random_hash, ratchet (optional), signed_data,
  signature, announce_payload, flags_byte, raw_packet, packet_hash }] }
```

### `links.json`

```
{ handshake_vectors: [{ initiator_keypair, responder_keypair,
  ephemeral_keys, link_request_data, link_id, lrproof_data,
  derived_key, mtu_signalling }] }
```

### `interface_framing.json`

```
{ hdlc: { FLAG, ESC, ESC_MASK, vectors: [{ raw, framed, description }] },
  kiss: { ... } }
```

### `channels.json`

```
{ envelope_vectors: [{ msg_type, sequence, data, packed_hex }],
  window_thresholds: {...} }
```

### `resources.json` / `resource_transfers.json`

```
resources: { advertisement_vectors: [{ msgpack_dict, packed }], ... }
resource_transfers: { transfers: [{ data_hex, advertisement, parts: [...],
  proof, derived_key }] }
```

### `buffer_transfers.json`

```
{ small_transfer_vectors: [{ data, messages: [{ chunk_hex,
  stream_packed_hex, envelope_packed_hex, compressed, is_eof,
  sequence, offset }] }] }
```

---

## Part 6: Recommended Rust Dependencies

```toml
# Cargo.toml (workspace)
[workspace.dependencies]
# Crypto (RustCrypto family - pure Rust, no OpenSSL)
sha2 = "0.10"
hmac = "0.12"
hkdf = "0.12"           # or implement manually (~20 lines)
aes = "0.8"
cbc = "0.1"
x25519-dalek = "2"
ed25519-dalek = "2"
rand = "0.8"

# Serialization
serde = { version = "1", features = ["derive"] }
serde_json = "1"        # test vector loading
rmpv = "1"              # msgpack (raw values, precise control over encoding)
hex = "0.4"

# Async
tokio = { version = "1", features = ["full"] }

# Compression
bzip2 = "0.4"

# Error handling
thiserror = "2"

# Logging
tracing = "0.1"

# CLI (for reticulum-node/cli)
clap = { version = "4", features = ["derive"] }

# Testing
criterion = "0.5"       # benchmarks
```

### `no_std` Note

`reticulum-crypto` and `reticulum-core` should be designed for optional `no_std` support (with `alloc`). Avoid `std::time`, `std::net`, etc. in these crates. Use feature flags:

```toml
[features]
default = ["std"]
std = []
```

---

## Part 7: Key Differences from Python Architecture

| Python                                             | Rust                                   |
| -------------------------------------------------- | -------------------------------------- |
| `Reticulum.__instance` singleton                   | `Node` struct, passed by `Arc`         |
| Class-level mutable dicts (`Transport.path_table`) | Owned by `Router` struct               |
| `threading.Thread`                                 | `tokio::spawn`                         |
| `isinstance()` / duck typing                       | Enum variants + pattern matching       |
| Exceptions                                         | `Result<T, E>`                         |
| Raw `bytes` everywhere                             | Newtype wrappers                       |
| Large classes (Link=1300 lines)                    | Split into state types + focused impls |
| 6+ callback fields per class                       | Event enums / `tokio::mpsc` channels   |
| Global import-time side effects                    | Explicit initialization                |
| `umsgpack` (vendored)                              | `rmpv` crate                           |

---

## Part 8: Subtle Protocol Details to Get Right

1. **HKDF empty salt**: When salt is `None` or empty, use 32 zero bytes (not the HMAC default of hash-length zeros — same in this case since SHA-256 has 32-byte output, but be explicit).

2. **HKDF counter**: The expand phase counter is `(i+1) % 256` where i is 0-indexed. For normal key lengths this doesn't matter, but it's a divergence from some HKDF implementations.

3. **Link ID computation**: The hashable part of a LINKREQUEST packet must have MTU signalling bytes stripped before hashing. The hashable part only includes up to ECPUBSIZE (64) bytes of data.

4. **Packet hashable part**: Flags byte is masked to `flags & 0x0F` (keep only destination_type and packet_type). Hops byte is excluded. For HEADER_2, transport_id is excluded.

5. **HDLC escape order**: ESC bytes (0x7D) must be escaped BEFORE FLAG bytes (0x7E). Reversing this corrupts data containing ESC bytes.

6. **Announce signed_data**: Includes destination_hash as the FIRST field — `dest_hash + public_key + name_hash + random_hash + [ratchet] + [app_data]`. The destination_hash is NOT part of the wire payload.

7. **Random hash in announces**: `os.urandom(5) + int(time.time()).to_bytes(5, "big")` = 10 bytes total.

8. **Resource advertisement keys**: Must use exact single-character msgpack keys (`"t"`, `"d"`, `"n"`, etc.) for wire compatibility.

9. **MTU signalling encoding**: 3 bytes = `struct.pack(">I", value)[1:]` where `value = (mtu & 0x1FFFFF) + (((mode << 5) & 0xE0) << 16)`. The mode occupies the top 3 bits of the first byte.

10. **Token key split**: For 64-byte keys: `signing_key = key[0:32]`, `encryption_key = key[32:64]`. This is the OPPOSITE order from what you might expect (signing first, encryption second).

---

## Verification Strategy

At each phase, run `cargo test` to validate against test vectors. The workflow:

1. **`cargo test -p reticulum-crypto`** — All crypto primitives pass against JSON vectors
2. **`cargo test -p reticulum-core`** — Identity, destination, packet, announce, framing pass
3. **`cargo test -p reticulum-protocol`** — Link handshake, resource transfer, channel, buffer pass
4. **`cargo test -p reticulum-transport`** — Path table, announce propagation, routing pass
5. **Integration test**: Docker compose with Python reference node, verify bidirectional communication
