#!/usr/bin/env python3
"""
Extract multi-hop routing test vectors from the Reticulum reference
implementation into a JSON file for consumption by alternative
implementations.

Covers:
  - Header transformation (HEADER_1 → HEADER_2 injection for transport)
  - Announce propagation through multi-hop chains
  - Link request forwarding at transport nodes
  - Link table entry construction
  - Reverse table entry construction
  - Path table query functions (has_path, next_hop, hops_to)
  - Header stripping (HEADER_2 → HEADER_1 at final hop)
  - Link table bidirectional routing

Network topology uses 4 keypairs:
  Node A (kp0) — source/receiver
  Node B (kp1) — transport relay 1
  Node C (kp2) — transport relay 2
  Node D (kp3) — destination/announce origin

All vectors are computed manually (no live Destination/Transport objects)
to avoid Transport init. Real RNS.Identity objects are used for signing.

Usage:
    python3 test_vectors/extract_multi_hop_routing.py

Output:
    test_vectors/multi_hop_routing.json
"""

import hashlib
import json
import os
import struct
import sys

repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, repo_root)

OUTPUT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "multi_hop_routing.json")
KEYPAIRS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keypairs.json")

# --- Constants (reproduced to avoid Transport init) ---
HEADER_1 = 0x00
HEADER_2 = 0x01
DATA = 0x00
ANNOUNCE = 0x01
LINKREQUEST = 0x02
PROOF = 0x03
BROADCAST = 0x00
TRANSPORT = 0x01
SINGLE = 0x00
PLAIN = 0x02
FLAG_SET = 0x01
FLAG_UNSET = 0x00
NONE_CONTEXT = 0x00
PATH_RESPONSE = 0x0B
LRPROOF = 0xFF

MTU = 500
TRUNCATED_HASHLENGTH_BYTES = 16
KEYSIZE_BYTES = 64
NAME_HASH_LENGTH_BYTES = 10
SIGLENGTH_BYTES = 64
RATCHETSIZE_BYTES = 32
RANDOM_HASH_LENGTH = 10

ECPUBSIZE = 64           # Link.ECPUBSIZE = 32+32
LINK_MTU_SIZE = 3        # Link.LINK_MTU_SIZE
ESTABLISHMENT_TIMEOUT_PER_HOP = 6  # Reticulum.DEFAULT_PER_HOP_TIMEOUT
REVERSE_TIMEOUT = 480    # 8*60
PATHFINDER_M = 128       # Max hops
PATHFINDER_E = 604800    # One week

# Path table entry indices
IDX_PT_TIMESTAMP = 0
IDX_PT_NEXT_HOP = 1
IDX_PT_HOPS = 2
IDX_PT_EXPIRES = 3
IDX_PT_RANDBLOBS = 4
IDX_PT_RVCD_IF = 5
IDX_PT_PACKET = 6

# Link table entry indices
IDX_LT_TIMESTAMP = 0
IDX_LT_NH_TRID = 1
IDX_LT_NH_IF = 2
IDX_LT_REM_HOPS = 3
IDX_LT_RCVD_IF = 4
IDX_LT_HOPS = 5
IDX_LT_DSTHASH = 6
IDX_LT_VALIDATED = 7
IDX_LT_PROOF_TMO = 8

# Reverse table entry indices
IDX_RT_RCVD_IF = 0
IDX_RT_OUTB_IF = 1
IDX_RT_TIMESTAMP = 2

# Fixed timestamp for deterministic test vectors
FIXED_TIMESTAMP = 1700000000

# Deterministic random prefixes
DETERMINISTIC_RANDOM_PREFIXES = [
    bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE]),
    bytes([0x11, 0x22, 0x33, 0x44, 0x55]),
    bytes([0xDE, 0xAD, 0xBE, 0xEF, 0x01]),
    bytes([0xCA, 0xFE, 0xBA, 0xBE, 0x02]),
    bytes([0xF0, 0x0D, 0xBA, 0xD0, 0x03]),
]


# --- Helper Functions ---

def load_keypairs():
    with open(KEYPAIRS_PATH, "r") as f:
        data = json.load(f)
    return data["keypairs"]


def load_identity(kp):
    """Load an RNS.Identity from a keypair dict."""
    import RNS
    identity = RNS.Identity(create_keys=False)
    identity.load_private_key(bytes.fromhex(kp["private_key"]))
    return identity


def pack_flags(header_type, context_flag, transport_type, dest_type, packet_type):
    return (header_type << 6) | (context_flag << 5) | (transport_type << 4) | (dest_type << 2) | packet_type


def build_header_1(flags_byte, hops, dest_hash, context_byte):
    header = struct.pack("!B", flags_byte)
    header += struct.pack("!B", hops)
    header += dest_hash
    header += bytes([context_byte])
    return header


def build_header_2(flags_byte, hops, transport_id, dest_hash, context_byte):
    header = struct.pack("!B", flags_byte)
    header += struct.pack("!B", hops)
    header += transport_id
    header += dest_hash
    header += bytes([context_byte])
    return header


def get_hashable_part(raw):
    """Compute hashable_part matching Packet.get_hashable_part()."""
    flags = raw[0]
    header_type = (flags & 0b01000000) >> 6
    hashable_part = bytes([flags & 0x0F])
    if header_type == HEADER_2:
        hashable_part += raw[TRUNCATED_HASHLENGTH_BYTES + 2:]
    else:
        hashable_part += raw[2:]
    return hashable_part


def compute_packet_hash(raw_packet):
    """Compute packet hash = SHA256(hashable_part)."""
    hashable_part = get_hashable_part(raw_packet)
    full_hash = hashlib.sha256(hashable_part).digest()
    truncated_hash = full_hash[:TRUNCATED_HASHLENGTH_BYTES]
    return hashable_part, full_hash, truncated_hash


def compute_link_id(raw_packet, data_len):
    """
    Compute link_id matching Link.link_id_from_lr_packet().

    hashable_part from get_hashable_part(), then if data > ECPUBSIZE,
    trim the trailing diff bytes.
    """
    hashable_part = get_hashable_part(raw_packet)
    if data_len > ECPUBSIZE:
        diff = data_len - ECPUBSIZE
        hashable_part = hashable_part[:-diff]
    return hashlib.sha256(hashable_part).digest()[:TRUNCATED_HASHLENGTH_BYTES]


def make_name_hash(app_name, *aspects):
    """Compute name_hash = SHA256(expand_name(None, app_name, *aspects))[:10]"""
    name = app_name
    for aspect in aspects:
        name += "." + aspect
    return hashlib.sha256(name.encode("utf-8")).digest()[:NAME_HASH_LENGTH_BYTES]


def make_identity_hash(public_key_bytes):
    """Compute identity hash = SHA256(public_key)[:16]"""
    return hashlib.sha256(public_key_bytes).digest()[:TRUNCATED_HASHLENGTH_BYTES]


def make_destination_hash(name_hash, identity_hash):
    """Compute destination hash = SHA256(name_hash + identity_hash)[:16]"""
    return hashlib.sha256(name_hash + identity_hash).digest()[:TRUNCATED_HASHLENGTH_BYTES]


def make_random_hash(deterministic_bytes, timestamp):
    """Build the 10-byte random_hash: 5 random bytes + 5-byte big-endian timestamp."""
    return deterministic_bytes[:5] + int(timestamp).to_bytes(5, "big")


def make_announce_payload(identity, name_hash, dest_hash, random_hash,
                          ratchet_pub=b"", app_data=None):
    """
    Construct announce payload manually, matching Destination.announce().

    signed_data = dest_hash + public_key + name_hash + random_hash + ratchet + [app_data]
    signature = identity.sign(signed_data)
    payload = public_key + name_hash + random_hash + ratchet + signature + [app_data]
    """
    public_key = identity.get_public_key()
    signed_data = dest_hash + public_key + name_hash + random_hash + ratchet_pub
    if app_data is not None:
        signed_data += app_data

    signature = identity.sign(signed_data)

    payload = public_key + name_hash + random_hash + ratchet_pub + signature
    if app_data is not None:
        payload += app_data

    return {
        "public_key": public_key,
        "signed_data": signed_data,
        "signature": signature,
        "payload": payload,
    }


def inject_into_transport(raw, next_hop):
    """
    Transform HEADER_1 packet into HEADER_2 for transport.
    Matches Transport.outbound() (Transport.py:980-991).

    new_flags = (HEADER_2 << 6) | (TRANSPORT << 4) | (original_flags & 0x0F)
    new_raw = flags + hops_byte + next_hop(16) + dest_hash_and_rest
    """
    original_flags = raw[0]
    new_flags = (HEADER_2 << 6) | (TRANSPORT << 4) | (original_flags & 0x0F)
    new_raw = struct.pack("!B", new_flags)
    new_raw += raw[1:2]           # hops byte
    new_raw += next_hop           # 16-byte transport_id
    new_raw += raw[2:]            # dest_hash + context + payload
    return new_raw


def relay_packet(raw, hops, next_hop, remaining_hops):
    """
    Relay packet at a transport node.
    Matches Transport.inbound() (Transport.py:1427-1449).

    remaining_hops > 1:  keep HEADER_2, update hops and transport_id to next_hop
    remaining_hops == 1: strip to HEADER_1 (BROADCAST)
    remaining_hops == 0: keep same header, just update hops byte
    """
    if remaining_hops > 1:
        # Keep HEADER_2, update transport_id to next_hop
        new_raw = raw[0:1]
        new_raw += struct.pack("!B", hops)
        new_raw += next_hop
        new_raw += raw[TRUNCATED_HASHLENGTH_BYTES + 2:]
    elif remaining_hops == 1:
        # Strip to HEADER_1
        flags = raw[0]
        new_flags = (HEADER_1 << 6) | (BROADCAST << 4) | (flags & 0x0F)
        new_raw = struct.pack("!B", new_flags)
        new_raw += struct.pack("!B", hops)
        new_raw += raw[TRUNCATED_HASHLENGTH_BYTES + 2:]
    elif remaining_hops == 0:
        # Just update hops byte
        new_raw = raw[0:1]
        new_raw += struct.pack("!B", hops)
        new_raw += raw[2:]
    return new_raw


# --- Topology Setup ---

def setup_topology(keypairs):
    """Set up the 4-node topology and compute common addresses."""
    app_name = "rns_unit_tests"
    aspects = ["link", "establish"]
    name_hash = make_name_hash(app_name, *aspects)

    nodes = {}
    for i, role in enumerate(["A", "B", "C", "D"]):
        kp = keypairs[i]
        identity = load_identity(kp)
        identity_hash = bytes.fromhex(kp["identity_hash"])
        dest_hash = make_destination_hash(name_hash, identity_hash)
        nodes[role] = {
            "keypair_index": i,
            "identity": identity,
            "identity_hash": identity_hash,
            "dest_hash": dest_hash,
            "public_key": identity.get_public_key(),
        }

    return nodes, name_hash, app_name, aspects


# --- Vector Extraction Functions ---

def extract_header_transformation_vectors(nodes, name_hash):
    """
    Category 1: HEADER_1 → HEADER_2 injection.

    When outbound() finds path_table[dest][hops] > 1, it transforms
    HEADER_1 to HEADER_2 by inserting transport_id = next_hop.
    (Transport.py:980-991)
    """
    vectors = []

    # Vector 1: DATA packet, 3-hop path (A→B→C→D)
    # Node A sends to Node D's destination, path says next_hop=B, hops=3
    dest_hash_D = nodes["D"]["dest_hash"]
    next_hop_B = nodes["B"]["identity_hash"]
    payload = b"Hello from Node A to Node D"

    flags_h1 = pack_flags(HEADER_1, FLAG_UNSET, BROADCAST, SINGLE, DATA)
    raw_h1 = build_header_1(flags_h1, 0, dest_hash_D, NONE_CONTEXT) + payload

    raw_h2 = inject_into_transport(raw_h1, next_hop_B)

    _, _, h1_hash = compute_packet_hash(raw_h1)
    _, _, h2_hash = compute_packet_hash(raw_h2)

    vectors.append({
        "description": "DATA packet HEADER_1→HEADER_2 injection, 3-hop path A→B→C→D",
        "scenario": "Node A sends DATA to Node D, path_table says hops=3, next_hop=B",
        "source_node": "A (kp0)",
        "destination_node": "D (kp3)",
        "next_hop_node": "B (kp1)",
        "path_hops": 3,
        "packet_type": "DATA",
        "destination_hash": dest_hash_D.hex(),
        "next_hop": next_hop_B.hex(),
        "payload": payload.hex(),
        "original_flags": f"{flags_h1:02x}",
        "original_header_type": "HEADER_1",
        "original_transport_type": "BROADCAST",
        "original_raw": raw_h1.hex(),
        "original_raw_length": len(raw_h1),
        "original_packet_hash": h1_hash.hex(),
        "transformed_flags": f"{raw_h2[0]:02x}",
        "transformed_header_type": "HEADER_2",
        "transformed_transport_type": "TRANSPORT",
        "transformed_raw": raw_h2.hex(),
        "transformed_raw_length": len(raw_h2),
        "transformed_packet_hash": h2_hash.hex(),
        "size_increase": len(raw_h2) - len(raw_h1),
        "transformation": {
            "new_flags": f"(HEADER_2 << 6) | (TRANSPORT << 4) | (original_flags & 0x0F) = {raw_h2[0]:02x}",
            "new_raw": "flags(1) + hops(1) + next_hop(16) + original_raw[2:]",
            "note": "Size increases by 16 bytes (transport_id inserted)",
        },
    })

    # Vector 2: LINKREQUEST packet, 2-hop path (A→B→D)
    next_hop_B = nodes["B"]["identity_hash"]
    # LINKREQUEST data = ECPUBSIZE (64) bytes of public key material
    lr_data = hashlib.sha256(b"deterministic_lr_pubkey_data").digest() * 2  # 64 bytes

    flags_lr_h1 = pack_flags(HEADER_1, FLAG_UNSET, BROADCAST, SINGLE, LINKREQUEST)
    raw_lr_h1 = build_header_1(flags_lr_h1, 0, dest_hash_D, NONE_CONTEXT) + lr_data

    raw_lr_h2 = inject_into_transport(raw_lr_h1, next_hop_B)

    _, _, lr_h1_hash = compute_packet_hash(raw_lr_h1)
    _, _, lr_h2_hash = compute_packet_hash(raw_lr_h2)

    vectors.append({
        "description": "LINKREQUEST packet HEADER_1→HEADER_2 injection, 2-hop path A→B→D",
        "scenario": "Node A sends LINKREQUEST to Node D, path_table says hops=2, next_hop=B",
        "source_node": "A (kp0)",
        "destination_node": "D (kp3)",
        "next_hop_node": "B (kp1)",
        "path_hops": 2,
        "packet_type": "LINKREQUEST",
        "destination_hash": dest_hash_D.hex(),
        "next_hop": next_hop_B.hex(),
        "lr_data": lr_data.hex(),
        "lr_data_length": len(lr_data),
        "original_flags": f"{flags_lr_h1:02x}",
        "original_raw": raw_lr_h1.hex(),
        "original_raw_length": len(raw_lr_h1),
        "original_packet_hash": lr_h1_hash.hex(),
        "transformed_flags": f"{raw_lr_h2[0]:02x}",
        "transformed_raw": raw_lr_h2.hex(),
        "transformed_raw_length": len(raw_lr_h2),
        "transformed_packet_hash": lr_h2_hash.hex(),
        "size_increase": len(raw_lr_h2) - len(raw_lr_h1),
    })

    # Vector 3: Shared instance case, 1-hop path (A→B)
    # When connected to shared instance and hops == 1, same transformation applies
    # (Transport.py:1000-1011)
    dest_hash_B = nodes["B"]["dest_hash"]
    next_hop_B_direct = nodes["B"]["identity_hash"]
    payload_shared = b"Shared instance packet"

    flags_shared_h1 = pack_flags(HEADER_1, FLAG_UNSET, BROADCAST, SINGLE, DATA)
    raw_shared_h1 = build_header_1(flags_shared_h1, 0, dest_hash_B, NONE_CONTEXT) + payload_shared

    raw_shared_h2 = inject_into_transport(raw_shared_h1, next_hop_B_direct)

    _, _, shared_h1_hash = compute_packet_hash(raw_shared_h1)
    _, _, shared_h2_hash = compute_packet_hash(raw_shared_h2)

    vectors.append({
        "description": "DATA packet HEADER_1→HEADER_2 for shared instance, 1-hop path",
        "scenario": "Node A behind shared instance sends to Node B, hops=1, next_hop=B",
        "source_node": "A (kp0)",
        "destination_node": "B (kp1)",
        "next_hop_node": "B (kp1)",
        "path_hops": 1,
        "is_shared_instance": True,
        "packet_type": "DATA",
        "destination_hash": dest_hash_B.hex(),
        "next_hop": next_hop_B_direct.hex(),
        "payload": payload_shared.hex(),
        "original_flags": f"{flags_shared_h1:02x}",
        "original_raw": raw_shared_h1.hex(),
        "original_raw_length": len(raw_shared_h1),
        "original_packet_hash": shared_h1_hash.hex(),
        "transformed_flags": f"{raw_shared_h2[0]:02x}",
        "transformed_raw": raw_shared_h2.hex(),
        "transformed_raw_length": len(raw_shared_h2),
        "transformed_packet_hash": shared_h2_hash.hex(),
        "size_increase": len(raw_shared_h2) - len(raw_shared_h1),
        "note": "Same transformation as multi-hop, but triggered by is_connected_to_shared_instance && hops==1",
    })

    return vectors


def extract_announce_propagation_vectors(nodes, name_hash):
    """
    Category 2: Multi-hop announce propagation chain.

    Simulates announce from Node D propagating D→C→B→A, showing at each node:
    - Wire bytes (HEADER_1 at origin, HEADER_2 at relays)
    - packet.hops after increment
    - received_from (dest_hash for HEADER_1, transport_id for HEADER_2)
    - path_table_entry fields
    - Rebroadcast packet bytes
    """
    vectors = []

    # --- 4-node chain: D announces, propagates D→C→B→A ---
    identity_D = nodes["D"]["identity"]
    identity_hash_D = nodes["D"]["identity_hash"]
    dest_hash_D = nodes["D"]["dest_hash"]
    random_hash = make_random_hash(DETERMINISTIC_RANDOM_PREFIXES[3], FIXED_TIMESTAMP)

    result = make_announce_payload(identity_D, name_hash, dest_hash_D, random_hash)
    announce_payload = result["payload"]

    random_blob = announce_payload[KEYSIZE_BYTES + NAME_HASH_LENGTH_BYTES:
                                   KEYSIZE_BYTES + NAME_HASH_LENGTH_BYTES + RANDOM_HASH_LENGTH]

    chain = []

    # Step 1: Node D originates announce (HEADER_1, BROADCAST)
    flags_origin = pack_flags(HEADER_1, FLAG_UNSET, BROADCAST, SINGLE, ANNOUNCE)
    raw_origin = build_header_1(flags_origin, 0, dest_hash_D, NONE_CONTEXT) + announce_payload
    _, _, origin_hash = compute_packet_hash(raw_origin)

    chain.append({
        "step": 1,
        "description": "Node D originates announce (HEADER_1, BROADCAST, hops=0)",
        "node": "D (kp3)",
        "action": "originate",
        "header_type": "HEADER_1",
        "transport_type": "BROADCAST",
        "hops_on_wire": 0,
        "raw_packet": raw_origin.hex(),
        "raw_packet_length": len(raw_origin),
        "packet_hash": origin_hash.hex(),
    })

    # Step 2: Node C receives from D (hops becomes 1), creates path_table entry
    # Received as HEADER_1, so received_from = packet.destination_hash = dest_hash_D
    hops_at_C = 0 + 1  # packet.hops += 1 at inbound
    received_from_C = dest_hash_D  # HEADER_1 → received_from = destination_hash
    expires_C = FIXED_TIMESTAMP + PATHFINDER_E

    # Node C rebroadcasts as HEADER_2 with own transport_id
    identity_hash_C = nodes["C"]["identity_hash"]
    flags_rebroadcast_C = pack_flags(HEADER_2, FLAG_UNSET, TRANSPORT, SINGLE, ANNOUNCE)
    raw_rebroadcast_C = build_header_2(flags_rebroadcast_C, hops_at_C, identity_hash_C,
                                        dest_hash_D, NONE_CONTEXT) + announce_payload
    _, _, rebroadcast_C_hash = compute_packet_hash(raw_rebroadcast_C)

    chain.append({
        "step": 2,
        "description": "Node C receives announce from D (hops=1), creates path entry, rebroadcasts",
        "node": "C (kp2)",
        "action": "relay",
        "received_header_type": "HEADER_1",
        "hops_after_increment": hops_at_C,
        "received_from": received_from_C.hex(),
        "received_from_source": "destination_hash (HEADER_1 has no transport_id)",
        "path_table_entry": {
            "destination_hash": dest_hash_D.hex(),
            "timestamp": FIXED_TIMESTAMP,
            "next_hop": received_from_C.hex(),
            "hops": hops_at_C,
            "expires": expires_C,
            "random_blobs": [random_blob.hex()],
        },
        "rebroadcast_header_type": "HEADER_2",
        "rebroadcast_transport_type": "TRANSPORT",
        "rebroadcast_transport_id": identity_hash_C.hex(),
        "rebroadcast_hops": hops_at_C,
        "rebroadcast_context": f"{NONE_CONTEXT:02x}",
        "rebroadcast_raw": raw_rebroadcast_C.hex(),
        "rebroadcast_raw_length": len(raw_rebroadcast_C),
        "rebroadcast_packet_hash": rebroadcast_C_hash.hex(),
    })

    # Step 3: Node B receives from C (hops becomes 2)
    # Received as HEADER_2, so received_from = transport_id = identity_hash_C
    hops_at_B = hops_at_C + 1  # 2
    received_from_B = identity_hash_C  # HEADER_2 → received_from = transport_id
    expires_B = FIXED_TIMESTAMP + PATHFINDER_E

    # Node B rebroadcasts as HEADER_2 with own transport_id
    identity_hash_B = nodes["B"]["identity_hash"]
    flags_rebroadcast_B = pack_flags(HEADER_2, FLAG_UNSET, TRANSPORT, SINGLE, ANNOUNCE)
    raw_rebroadcast_B = build_header_2(flags_rebroadcast_B, hops_at_B, identity_hash_B,
                                        dest_hash_D, NONE_CONTEXT) + announce_payload
    _, _, rebroadcast_B_hash = compute_packet_hash(raw_rebroadcast_B)

    chain.append({
        "step": 3,
        "description": "Node B receives announce from C (hops=2), creates path entry, rebroadcasts",
        "node": "B (kp1)",
        "action": "relay",
        "received_header_type": "HEADER_2",
        "received_transport_id": identity_hash_C.hex(),
        "hops_after_increment": hops_at_B,
        "received_from": received_from_B.hex(),
        "received_from_source": "transport_id from HEADER_2 packet",
        "path_table_entry": {
            "destination_hash": dest_hash_D.hex(),
            "timestamp": FIXED_TIMESTAMP,
            "next_hop": received_from_B.hex(),
            "hops": hops_at_B,
            "expires": expires_B,
            "random_blobs": [random_blob.hex()],
        },
        "rebroadcast_header_type": "HEADER_2",
        "rebroadcast_transport_type": "TRANSPORT",
        "rebroadcast_transport_id": identity_hash_B.hex(),
        "rebroadcast_hops": hops_at_B,
        "rebroadcast_context": f"{NONE_CONTEXT:02x}",
        "rebroadcast_raw": raw_rebroadcast_B.hex(),
        "rebroadcast_raw_length": len(raw_rebroadcast_B),
        "rebroadcast_packet_hash": rebroadcast_B_hash.hex(),
    })

    # Step 4: Node A receives from B (hops becomes 3)
    hops_at_A = hops_at_B + 1  # 3
    received_from_A = identity_hash_B  # HEADER_2 → received_from = transport_id
    expires_A = FIXED_TIMESTAMP + PATHFINDER_E

    chain.append({
        "step": 4,
        "description": "Node A receives announce from B (hops=3), creates path entry (endpoint)",
        "node": "A (kp0)",
        "action": "receive",
        "received_header_type": "HEADER_2",
        "received_transport_id": identity_hash_B.hex(),
        "hops_after_increment": hops_at_A,
        "received_from": received_from_A.hex(),
        "received_from_source": "transport_id from HEADER_2 packet",
        "path_table_entry": {
            "destination_hash": dest_hash_D.hex(),
            "timestamp": FIXED_TIMESTAMP,
            "next_hop": received_from_A.hex(),
            "hops": hops_at_A,
            "expires": expires_A,
            "random_blobs": [random_blob.hex()],
        },
    })

    vectors.append({
        "description": "4-node announce propagation chain: D→C→B→A",
        "announce_source": "D (kp3)",
        "destination_hash": dest_hash_D.hex(),
        "announce_payload": announce_payload.hex(),
        "announce_payload_length": len(announce_payload),
        "random_blob": random_blob.hex(),
        "random_hash": random_hash.hex(),
        "chain": chain,
    })

    # --- 2-node chain: D announces, propagates D→A ---
    random_hash_2 = make_random_hash(DETERMINISTIC_RANDOM_PREFIXES[0], FIXED_TIMESTAMP)
    result_2 = make_announce_payload(identity_D, name_hash, dest_hash_D, random_hash_2)
    announce_payload_2 = result_2["payload"]
    random_blob_2 = announce_payload_2[KEYSIZE_BYTES + NAME_HASH_LENGTH_BYTES:
                                        KEYSIZE_BYTES + NAME_HASH_LENGTH_BYTES + RANDOM_HASH_LENGTH]

    chain_2 = []

    # Step 1: Node D originates
    raw_origin_2 = build_header_1(flags_origin, 0, dest_hash_D, NONE_CONTEXT) + announce_payload_2
    _, _, origin_hash_2 = compute_packet_hash(raw_origin_2)

    chain_2.append({
        "step": 1,
        "description": "Node D originates announce (HEADER_1, hops=0)",
        "node": "D (kp3)",
        "action": "originate",
        "header_type": "HEADER_1",
        "hops_on_wire": 0,
        "raw_packet": raw_origin_2.hex(),
        "packet_hash": origin_hash_2.hex(),
    })

    # Step 2: Node A receives directly (hops=1)
    hops_at_A_2 = 1
    received_from_A_2 = dest_hash_D  # HEADER_1

    chain_2.append({
        "step": 2,
        "description": "Node A receives announce directly from D (hops=1)",
        "node": "A (kp0)",
        "action": "receive",
        "received_header_type": "HEADER_1",
        "hops_after_increment": hops_at_A_2,
        "received_from": received_from_A_2.hex(),
        "received_from_source": "destination_hash (HEADER_1)",
        "path_table_entry": {
            "destination_hash": dest_hash_D.hex(),
            "timestamp": FIXED_TIMESTAMP,
            "next_hop": received_from_A_2.hex(),
            "hops": hops_at_A_2,
            "expires": FIXED_TIMESTAMP + PATHFINDER_E,
            "random_blobs": [random_blob_2.hex()],
        },
    })

    vectors.append({
        "description": "2-node announce propagation: D→A (direct)",
        "announce_source": "D (kp3)",
        "destination_hash": dest_hash_D.hex(),
        "announce_payload": announce_payload_2.hex(),
        "random_blob": random_blob_2.hex(),
        "chain": chain_2,
    })

    return vectors


def extract_link_request_forwarding_vectors(nodes, name_hash):
    """
    Category 3: Link request forwarding at transport nodes.

    Transport.py:1427-1510. When transport_id == our_hash, relay looks up path_table:
    - remaining_hops > 1: Update transport_id to next_hop, update hops byte
    - remaining_hops == 1: Strip to HEADER_1 (BROADCAST)
    - remaining_hops == 0: Just update hops byte
    """
    vectors = []

    dest_hash_D = nodes["D"]["dest_hash"]
    identity_hash_A = nodes["A"]["identity_hash"]
    identity_hash_B = nodes["B"]["identity_hash"]
    identity_hash_C = nodes["C"]["identity_hash"]

    # Deterministic LINKREQUEST payload (ECPUBSIZE = 64 bytes of key material)
    lr_pubkey = hashlib.sha256(b"deterministic_lr_pubkey_material_0").digest()
    lr_sigkey = hashlib.sha256(b"deterministic_lr_sigkey_material_0").digest()
    lr_data = lr_pubkey + lr_sigkey  # 64 bytes = ECPUBSIZE

    # --- Vector 1: 3-hop relay at Node B (remaining_hops=2 > 1) ---
    # Path: A→B→C→D. Packet arrives at B with transport_id=B, hops=1 (incremented at B)
    # B's path_table says: dest_hash_D → next_hop=C, remaining_hops=2

    flags_h2 = pack_flags(HEADER_2, FLAG_UNSET, TRANSPORT, SINGLE, LINKREQUEST)
    # Packet as it arrives at B (before hops increment, hops=0 on wire)
    raw_arrive_B = build_header_2(flags_h2, 0, identity_hash_B, dest_hash_D, NONE_CONTEXT) + lr_data

    # After inbound() increments hops: packet.hops = 1
    hops_at_B = 1

    # B's path_table: next_hop=C, remaining_hops=2
    next_hop_C = identity_hash_C
    remaining_hops_at_B = 2

    # remaining_hops > 1: update transport_id to next_hop, update hops byte
    raw_relay_B = relay_packet(raw_arrive_B, hops_at_B, next_hop_C, remaining_hops_at_B)

    _, _, arrive_hash = compute_packet_hash(raw_arrive_B)
    _, _, relay_hash = compute_packet_hash(raw_relay_B)

    # Compute link_id for this LINKREQUEST
    link_id = compute_link_id(raw_arrive_B, len(lr_data))

    vectors.append({
        "description": "LINKREQUEST relay at Node B, remaining_hops=2 (>1), update transport_id",
        "scenario": "Path A→B→C→D. Packet arrives at B, B forwards to C",
        "relay_node": "B (kp1)",
        "relay_node_hash": identity_hash_B.hex(),
        "destination_hash": dest_hash_D.hex(),
        "next_hop": next_hop_C.hex(),
        "remaining_hops": remaining_hops_at_B,
        "hops_at_relay": hops_at_B,
        "lr_data": lr_data.hex(),
        "lr_data_length": len(lr_data),
        "arriving_raw": raw_arrive_B.hex(),
        "arriving_raw_length": len(raw_arrive_B),
        "arriving_packet_hash": arrive_hash.hex(),
        "relayed_raw": raw_relay_B.hex(),
        "relayed_raw_length": len(raw_relay_B),
        "relayed_packet_hash": relay_hash.hex(),
        "relayed_header_type": "HEADER_2",
        "relayed_transport_id": next_hop_C.hex(),
        "link_id": link_id.hex(),
        "relay_rule": "remaining_hops > 1: keep HEADER_2, replace transport_id with next_hop, update hops",
    })

    # --- Vector 2: Relay at Node C, remaining_hops=1 → strip to HEADER_1 ---
    # Packet arrives at C from B with transport_id=C, hops=1 on wire
    raw_arrive_C = build_header_2(flags_h2, 1, identity_hash_C, dest_hash_D, NONE_CONTEXT) + lr_data

    # After inbound() increments hops: packet.hops = 2
    hops_at_C = 2
    remaining_hops_at_C = 1

    # remaining_hops == 1: strip to HEADER_1
    raw_relay_C = relay_packet(raw_arrive_C, hops_at_C, None, remaining_hops_at_C)

    _, _, arrive_C_hash = compute_packet_hash(raw_arrive_C)
    _, _, relay_C_hash = compute_packet_hash(raw_relay_C)

    link_id_C = compute_link_id(raw_arrive_C, len(lr_data))

    vectors.append({
        "description": "LINKREQUEST relay at Node C, remaining_hops=1, strip to HEADER_1",
        "scenario": "Path A→B→C→D. Packet arrives at C from B, C strips transport and broadcasts",
        "relay_node": "C (kp2)",
        "relay_node_hash": identity_hash_C.hex(),
        "destination_hash": dest_hash_D.hex(),
        "remaining_hops": remaining_hops_at_C,
        "hops_at_relay": hops_at_C,
        "lr_data": lr_data.hex(),
        "lr_data_length": len(lr_data),
        "arriving_raw": raw_arrive_C.hex(),
        "arriving_raw_length": len(raw_arrive_C),
        "arriving_header_type": "HEADER_2",
        "arriving_packet_hash": arrive_C_hash.hex(),
        "relayed_raw": raw_relay_C.hex(),
        "relayed_raw_length": len(raw_relay_C),
        "relayed_header_type": "HEADER_1",
        "relayed_transport_type": "BROADCAST",
        "relayed_packet_hash": relay_C_hash.hex(),
        "size_decrease": len(raw_arrive_C) - len(raw_relay_C),
        "link_id": link_id_C.hex(),
        "relay_rule": "remaining_hops == 1: strip HEADER_2 to HEADER_1, set transport_type=BROADCAST",
    })

    # --- Vector 3: remaining_hops=0 case ---
    # This happens when destination is directly on the transport node
    raw_arrive_0 = build_header_2(flags_h2, 2, identity_hash_B, dest_hash_D, NONE_CONTEXT) + lr_data
    hops_at_0 = 3
    remaining_hops_0 = 0

    raw_relay_0 = relay_packet(raw_arrive_0, hops_at_0, None, remaining_hops_0)

    _, _, arrive_0_hash = compute_packet_hash(raw_arrive_0)
    _, _, relay_0_hash = compute_packet_hash(raw_relay_0)

    vectors.append({
        "description": "LINKREQUEST relay with remaining_hops=0, just update hops byte",
        "scenario": "Destination is local to transport node, remaining_hops=0",
        "relay_node": "B (kp1)",
        "relay_node_hash": identity_hash_B.hex(),
        "destination_hash": dest_hash_D.hex(),
        "remaining_hops": remaining_hops_0,
        "hops_at_relay": hops_at_0,
        "arriving_raw": raw_arrive_0.hex(),
        "arriving_raw_length": len(raw_arrive_0),
        "arriving_packet_hash": arrive_0_hash.hex(),
        "relayed_raw": raw_relay_0.hex(),
        "relayed_raw_length": len(raw_relay_0),
        "relayed_packet_hash": relay_0_hash.hex(),
        "size_change": len(raw_relay_0) - len(raw_arrive_0),
        "relay_rule": "remaining_hops == 0: keep header unchanged, just update hops byte",
    })

    # --- Vector 4: LINKREQUEST with MTU signalling bytes ---
    # lr_data has ECPUBSIZE + LINK_MTU_SIZE bytes
    mtu_bytes = bytes([0x00, 0x01, 0xF4])  # 500 MTU encoded as 3 bytes
    lr_data_mtu = lr_data + mtu_bytes  # 67 bytes

    raw_arrive_mtu = build_header_2(flags_h2, 0, identity_hash_B, dest_hash_D, NONE_CONTEXT) + lr_data_mtu
    hops_mtu = 1
    remaining_hops_mtu = 2

    raw_relay_mtu = relay_packet(raw_arrive_mtu, hops_mtu, next_hop_C, remaining_hops_mtu)

    _, _, arrive_mtu_hash = compute_packet_hash(raw_arrive_mtu)
    _, _, relay_mtu_hash = compute_packet_hash(raw_relay_mtu)

    link_id_mtu = compute_link_id(raw_arrive_mtu, len(lr_data_mtu))

    vectors.append({
        "description": "LINKREQUEST with MTU signalling bytes (ECPUBSIZE + LINK_MTU_SIZE)",
        "scenario": "LINKREQUEST with 67-byte data (64 key + 3 MTU), link_id trims MTU bytes",
        "relay_node": "B (kp1)",
        "destination_hash": dest_hash_D.hex(),
        "lr_data": lr_data_mtu.hex(),
        "lr_data_length": len(lr_data_mtu),
        "mtu_signalling_bytes": mtu_bytes.hex(),
        "ecpubsize": ECPUBSIZE,
        "link_mtu_size": LINK_MTU_SIZE,
        "arriving_raw": raw_arrive_mtu.hex(),
        "arriving_raw_length": len(raw_arrive_mtu),
        "arriving_packet_hash": arrive_mtu_hash.hex(),
        "relayed_raw": raw_relay_mtu.hex(),
        "relayed_raw_length": len(raw_relay_mtu),
        "relayed_packet_hash": relay_mtu_hash.hex(),
        "link_id": link_id_mtu.hex(),
        "link_id_note": "link_id computed from hashable_part with MTU bytes trimmed (data > ECPUBSIZE)",
    })

    return vectors


def extract_link_table_entry_vectors(nodes, name_hash):
    """
    Category 4: Link table entry construction.

    When forwarding LINKREQUEST, a link_table entry is created (Transport.py:1482-1493).

    link_id = truncated_hash(hashable_part) where hashable_part is trimmed if
    data > ECPUBSIZE (Link.py:341-347).

    proof_timeout = extra_link_proof_timeout + now + ESTABLISHMENT_TIMEOUT_PER_HOP * max(1, remaining_hops)
    """
    vectors = []

    dest_hash_D = nodes["D"]["dest_hash"]
    identity_hash_B = nodes["B"]["identity_hash"]
    identity_hash_C = nodes["C"]["identity_hash"]

    # Deterministic LINKREQUEST payload
    lr_pubkey = hashlib.sha256(b"deterministic_lr_pubkey_material_0").digest()
    lr_sigkey = hashlib.sha256(b"deterministic_lr_sigkey_material_0").digest()
    lr_data = lr_pubkey + lr_sigkey  # 64 bytes

    flags_h2 = pack_flags(HEADER_2, FLAG_UNSET, TRANSPORT, SINGLE, LINKREQUEST)

    # --- Vector 1: Link table entry at Node B (remaining_hops=2) ---
    raw_at_B = build_header_2(flags_h2, 0, identity_hash_B, dest_hash_D, NONE_CONTEXT) + lr_data
    hops_at_B = 1  # after increment
    remaining_hops_B = 2
    next_hop_B = identity_hash_C

    link_id_B = compute_link_id(raw_at_B, len(lr_data))

    # extra_link_proof_timeout for a typical interface
    # For simplicity, assume interface.bitrate = 1000000 (1 Mbps) → extra = (1/1000000)*8*500 = 0.004
    # But in test vectors we'll use 0 (no interface) as the reference does
    extra_timeout = 0.0  # None interface → extra_link_proof_timeout returns 0
    proof_timeout_B = extra_timeout + FIXED_TIMESTAMP + ESTABLISHMENT_TIMEOUT_PER_HOP * max(1, remaining_hops_B)

    vectors.append({
        "description": "Link table entry at Node B, remaining_hops=2",
        "relay_node": "B (kp1)",
        "destination_hash": dest_hash_D.hex(),
        "link_id": link_id_B.hex(),
        "link_id_derivation": {
            "step_1": "hashable_part = get_hashable_part(raw_packet)",
            "step_2": "if len(data) > ECPUBSIZE: hashable_part = hashable_part[:-diff]",
            "step_3": "link_id = SHA256(hashable_part)[:16]",
            "data_length": len(lr_data),
            "ecpubsize": ECPUBSIZE,
            "trimmed": len(lr_data) > ECPUBSIZE,
        },
        "entry_fields": {
            "IDX_LT_TIMESTAMP": FIXED_TIMESTAMP,
            "IDX_LT_NH_TRID": next_hop_B.hex(),
            "IDX_LT_NH_IF": "outbound_interface (object reference)",
            "IDX_LT_REM_HOPS": remaining_hops_B,
            "IDX_LT_RCVD_IF": "receiving_interface (object reference)",
            "IDX_LT_HOPS": hops_at_B,
            "IDX_LT_DSTHASH": dest_hash_D.hex(),
            "IDX_LT_VALIDATED": False,
            "IDX_LT_PROOF_TMO": proof_timeout_B,
        },
        "proof_timeout_calculation": {
            "extra_link_proof_timeout": extra_timeout,
            "now": FIXED_TIMESTAMP,
            "establishment_timeout_per_hop": ESTABLISHMENT_TIMEOUT_PER_HOP,
            "remaining_hops": remaining_hops_B,
            "max_1_remaining": max(1, remaining_hops_B),
            "formula": f"extra({extra_timeout}) + now({FIXED_TIMESTAMP}) + {ESTABLISHMENT_TIMEOUT_PER_HOP} * max(1, {remaining_hops_B})",
            "result": proof_timeout_B,
        },
        "raw_packet": raw_at_B.hex(),
        "lr_data": lr_data.hex(),
        "lr_data_length": len(lr_data),
    })

    # --- Vector 2: Link table entry at Node C (remaining_hops=1) ---
    raw_at_C = build_header_2(flags_h2, 1, identity_hash_C, dest_hash_D, NONE_CONTEXT) + lr_data
    hops_at_C = 2  # after increment
    remaining_hops_C = 1

    link_id_C = compute_link_id(raw_at_C, len(lr_data))

    proof_timeout_C = extra_timeout + FIXED_TIMESTAMP + ESTABLISHMENT_TIMEOUT_PER_HOP * max(1, remaining_hops_C)

    vectors.append({
        "description": "Link table entry at Node C, remaining_hops=1",
        "relay_node": "C (kp2)",
        "destination_hash": dest_hash_D.hex(),
        "link_id": link_id_C.hex(),
        "entry_fields": {
            "IDX_LT_TIMESTAMP": FIXED_TIMESTAMP,
            "IDX_LT_NH_TRID": "next_hop (destination is 1 hop away)",
            "IDX_LT_NH_IF": "outbound_interface (object reference)",
            "IDX_LT_REM_HOPS": remaining_hops_C,
            "IDX_LT_RCVD_IF": "receiving_interface (object reference)",
            "IDX_LT_HOPS": hops_at_C,
            "IDX_LT_DSTHASH": dest_hash_D.hex(),
            "IDX_LT_VALIDATED": False,
            "IDX_LT_PROOF_TMO": proof_timeout_C,
        },
        "proof_timeout_calculation": {
            "extra_link_proof_timeout": extra_timeout,
            "now": FIXED_TIMESTAMP,
            "establishment_timeout_per_hop": ESTABLISHMENT_TIMEOUT_PER_HOP,
            "remaining_hops": remaining_hops_C,
            "max_1_remaining": max(1, remaining_hops_C),
            "formula": f"extra({extra_timeout}) + now({FIXED_TIMESTAMP}) + {ESTABLISHMENT_TIMEOUT_PER_HOP} * max(1, {remaining_hops_C})",
            "result": proof_timeout_C,
        },
        "raw_packet": raw_at_C.hex(),
    })

    # --- Vector 3: Link table entry with MTU signalling bytes ---
    mtu_bytes = bytes([0x00, 0x01, 0xF4])
    lr_data_mtu = lr_data + mtu_bytes  # 67 bytes

    raw_at_B_mtu = build_header_2(flags_h2, 0, identity_hash_B, dest_hash_D, NONE_CONTEXT) + lr_data_mtu

    link_id_B_mtu = compute_link_id(raw_at_B_mtu, len(lr_data_mtu))

    # Also compute the non-trimmed hash for comparison
    hashable_full = get_hashable_part(raw_at_B_mtu)
    hashable_trimmed = hashable_full[:-(len(lr_data_mtu) - ECPUBSIZE)]

    vectors.append({
        "description": "Link table entry with MTU signalling bytes (data > ECPUBSIZE)",
        "relay_node": "B (kp1)",
        "destination_hash": dest_hash_D.hex(),
        "lr_data_length": len(lr_data_mtu),
        "ecpubsize": ECPUBSIZE,
        "excess_bytes": len(lr_data_mtu) - ECPUBSIZE,
        "link_id": link_id_B_mtu.hex(),
        "hashable_part_full_length": len(hashable_full),
        "hashable_part_trimmed_length": len(hashable_trimmed),
        "hashable_part_trimmed": hashable_trimmed.hex(),
        "note": "When data > ECPUBSIZE, hashable_part is trimmed by (data_len - ECPUBSIZE) bytes before hashing",
        "raw_packet": raw_at_B_mtu.hex(),
    })

    return vectors


def extract_reverse_table_entry_vectors(nodes, name_hash):
    """
    Category 5: Reverse table entry construction.

    For non-LINKREQUEST forwarded packets, a reverse_table entry maps
    truncated_hash → [recv_if, outbound_if, timestamp].
    (Transport.py:1495-1501)

    Key: SHA256(hashable_part)[:16] via getTruncatedHash().
    Expiration: REVERSE_TIMEOUT = 480 seconds, culled when
    time.time() > entry[2] + 480 (strict >, Transport.py:610).
    """
    vectors = []

    dest_hash_D = nodes["D"]["dest_hash"]
    identity_hash_B = nodes["B"]["identity_hash"]
    identity_hash_C = nodes["C"]["identity_hash"]

    # DATA packet forwarded through transport
    payload = b"Data packet for reverse table test"
    flags_h2 = pack_flags(HEADER_2, FLAG_UNSET, TRANSPORT, SINGLE, DATA)
    raw_data = build_header_2(flags_h2, 0, identity_hash_B, dest_hash_D, NONE_CONTEXT) + payload

    # Compute truncated hash (the key for reverse_table)
    hashable = get_hashable_part(raw_data)
    truncated_hash = hashlib.sha256(hashable).digest()[:TRUNCATED_HASHLENGTH_BYTES]

    vectors.append({
        "description": "Reverse table entry creation for forwarded DATA packet",
        "packet_type": "DATA",
        "destination_hash": dest_hash_D.hex(),
        "transport_id": identity_hash_B.hex(),
        "raw_packet": raw_data.hex(),
        "raw_packet_length": len(raw_data),
        "hashable_part": hashable.hex(),
        "truncated_hash_key": truncated_hash.hex(),
        "entry_fields": {
            "IDX_RT_RCVD_IF": "receiving_interface (object reference)",
            "IDX_RT_OUTB_IF": "outbound_interface (object reference)",
            "IDX_RT_TIMESTAMP": FIXED_TIMESTAMP,
        },
        "entry_indices": {
            "IDX_RT_RCVD_IF": IDX_RT_RCVD_IF,
            "IDX_RT_OUTB_IF": IDX_RT_OUTB_IF,
            "IDX_RT_TIMESTAMP": IDX_RT_TIMESTAMP,
        },
        "reverse_timeout_seconds": REVERSE_TIMEOUT,
    })

    # Expiration boundary vectors
    vectors.append({
        "description": "Reverse table expiration: entry at 479s is still valid (not expired)",
        "timestamp": FIXED_TIMESTAMP,
        "check_time": FIXED_TIMESTAMP + 479,
        "age_seconds": 479,
        "reverse_timeout": REVERSE_TIMEOUT,
        "condition": f"time.time() > entry[2] + {REVERSE_TIMEOUT}",
        "condition_evaluation": f"{FIXED_TIMESTAMP + 479} > {FIXED_TIMESTAMP + REVERSE_TIMEOUT}",
        "is_expired": False,
        "note": "479 < 480, so condition is False → entry is valid",
    })

    vectors.append({
        "description": "Reverse table expiration: entry at 480s is still valid (not expired, strict >)",
        "timestamp": FIXED_TIMESTAMP,
        "check_time": FIXED_TIMESTAMP + 480,
        "age_seconds": 480,
        "reverse_timeout": REVERSE_TIMEOUT,
        "condition": f"time.time() > entry[2] + {REVERSE_TIMEOUT}",
        "condition_evaluation": f"{FIXED_TIMESTAMP + 480} > {FIXED_TIMESTAMP + REVERSE_TIMEOUT}",
        "is_expired": False,
        "note": "480 == 480, strict > means equal is NOT expired",
    })

    vectors.append({
        "description": "Reverse table expiration: entry at 481s IS expired",
        "timestamp": FIXED_TIMESTAMP,
        "check_time": FIXED_TIMESTAMP + 481,
        "age_seconds": 481,
        "reverse_timeout": REVERSE_TIMEOUT,
        "condition": f"time.time() > entry[2] + {REVERSE_TIMEOUT}",
        "condition_evaluation": f"{FIXED_TIMESTAMP + 481} > {FIXED_TIMESTAMP + REVERSE_TIMEOUT}",
        "is_expired": True,
        "note": "481 > 480, so condition is True → entry is expired",
    })

    # Second DATA packet for different reverse entry
    payload_2 = b"Second data packet"
    raw_data_2 = build_header_2(flags_h2, 1, identity_hash_C, dest_hash_D, NONE_CONTEXT) + payload_2
    hashable_2 = get_hashable_part(raw_data_2)
    truncated_hash_2 = hashlib.sha256(hashable_2).digest()[:TRUNCATED_HASHLENGTH_BYTES]

    vectors.append({
        "description": "Reverse table entry for different packet (different transport_id, hops)",
        "packet_type": "DATA",
        "destination_hash": dest_hash_D.hex(),
        "transport_id": identity_hash_C.hex(),
        "hops_on_wire": 1,
        "raw_packet": raw_data_2.hex(),
        "hashable_part": hashable_2.hex(),
        "truncated_hash_key": truncated_hash_2.hex(),
        "note": "Different hashable_part produces different reverse table key",
    })

    return vectors


def extract_path_table_query_vectors(nodes, name_hash):
    """
    Category 6: Path table query functions.

    Transport.py:2409-2442: has_path(), next_hop(), hops_to().
    """
    vectors = []

    dest_hash_D = nodes["D"]["dest_hash"]
    identity_hash_B = nodes["B"]["identity_hash"]
    dest_hash_A = nodes["A"]["dest_hash"]
    identity_hash_D = nodes["D"]["identity_hash"]

    # Vector 1: 3-hop path exists
    vectors.append({
        "description": "Path query for 3-hop path: has_path=True, hops_to=3, next_hop=B",
        "destination_hash": dest_hash_D.hex(),
        "path_table_entry_exists": True,
        "path_table_next_hop": identity_hash_B.hex(),
        "path_table_hops": 3,
        "has_path_result": True,
        "hops_to_result": 3,
        "next_hop_result": identity_hash_B.hex(),
        "note": "Transport.has_path() returns True, hops_to() returns entry[IDX_PT_HOPS], next_hop() returns entry[IDX_PT_NEXT_HOP]",
    })

    # Vector 2: 1-hop direct path
    vectors.append({
        "description": "Path query for 1-hop direct path: has_path=True, hops_to=1, next_hop=D",
        "destination_hash": dest_hash_D.hex(),
        "path_table_entry_exists": True,
        "path_table_next_hop": identity_hash_D.hex(),
        "path_table_hops": 1,
        "has_path_result": True,
        "hops_to_result": 1,
        "next_hop_result": identity_hash_D.hex(),
        "note": "Direct path: next_hop is the destination's identity_hash (received_from = dest_hash for HEADER_1)",
    })

    # Vector 3: Unknown destination
    unknown_dest = hashlib.sha256(b"unknown_destination_for_test").digest()[:TRUNCATED_HASHLENGTH_BYTES]
    vectors.append({
        "description": "Path query for unknown destination: has_path=False, hops_to=PATHFINDER_M(128)",
        "destination_hash": unknown_dest.hex(),
        "path_table_entry_exists": False,
        "has_path_result": False,
        "hops_to_result": PATHFINDER_M,
        "next_hop_result": None,
        "pathfinder_m": PATHFINDER_M,
        "note": "When destination not in path_table: has_path()=False, hops_to()=PATHFINDER_M(128), next_hop()=None",
    })

    # Vector 4: Zero-hop path (local destination)
    vectors.append({
        "description": "Path query for 0-hop local destination",
        "destination_hash": dest_hash_A.hex(),
        "path_table_entry_exists": True,
        "path_table_next_hop": nodes["A"]["identity_hash"].hex(),
        "path_table_hops": 0,
        "has_path_result": True,
        "hops_to_result": 0,
        "next_hop_result": nodes["A"]["identity_hash"].hex(),
    })

    return vectors


def extract_header_stripping_vectors(nodes, name_hash):
    """
    Category 7: HEADER_2 → HEADER_1 stripping at final hop.

    When remaining_hops == 1, strip transport headers (Transport.py:1439-1444):
    new_flags = (HEADER_1 << 6) | (BROADCAST << 4) | (flags & 0x0F)
    new_raw = flags(1) + hops(1) + raw[18:]  (skip transport_id)
    """
    vectors = []

    dest_hash_D = nodes["D"]["dest_hash"]
    identity_hash_C = nodes["C"]["identity_hash"]

    # --- Vector 1: DATA packet stripping ---
    payload = b"Data to be stripped of transport headers"
    flags_h2 = pack_flags(HEADER_2, FLAG_UNSET, TRANSPORT, SINGLE, DATA)
    raw_h2 = build_header_2(flags_h2, 1, identity_hash_C, dest_hash_D, NONE_CONTEXT) + payload

    # After inbound() increments: hops=2
    hops_stripped = 2
    remaining_hops = 1

    # Strip: HEADER_1, BROADCAST
    raw_stripped = relay_packet(raw_h2, hops_stripped, None, remaining_hops)

    _, _, h2_hash = compute_packet_hash(raw_h2)
    _, _, h1_hash = compute_packet_hash(raw_stripped)

    # Verify the stripped packet flags
    stripped_flags = raw_stripped[0]
    expected_flags = (HEADER_1 << 6) | (BROADCAST << 4) | (flags_h2 & 0x0F)

    vectors.append({
        "description": "DATA packet HEADER_2→HEADER_1 stripping at final hop",
        "packet_type": "DATA",
        "destination_hash": dest_hash_D.hex(),
        "transport_id": identity_hash_C.hex(),
        "remaining_hops": remaining_hops,
        "hops_after_increment": hops_stripped,
        "payload": payload.hex(),
        "original_flags": f"{flags_h2:02x}",
        "original_header_type": "HEADER_2",
        "original_transport_type": "TRANSPORT",
        "original_raw": raw_h2.hex(),
        "original_raw_length": len(raw_h2),
        "original_packet_hash": h2_hash.hex(),
        "stripped_flags": f"{stripped_flags:02x}",
        "expected_flags": f"{expected_flags:02x}",
        "stripped_header_type": "HEADER_1",
        "stripped_transport_type": "BROADCAST",
        "stripped_raw": raw_stripped.hex(),
        "stripped_raw_length": len(raw_stripped),
        "stripped_packet_hash": h1_hash.hex(),
        "size_decrease": len(raw_h2) - len(raw_stripped),
        "transformation": {
            "new_flags": f"(HEADER_1 << 6) | (BROADCAST << 4) | (flags & 0x0F) = {expected_flags:02x}",
            "new_raw": "flags(1) + hops(1) + original_raw[18:] (skip 16-byte transport_id)",
            "note": "Size decreases by 16 bytes (transport_id removed)",
        },
    })

    # --- Vector 2: LINKREQUEST packet stripping ---
    lr_pubkey = hashlib.sha256(b"deterministic_lr_pubkey_material_strip").digest()
    lr_sigkey = hashlib.sha256(b"deterministic_lr_sigkey_material_strip").digest()
    lr_data = lr_pubkey + lr_sigkey  # 64 bytes

    flags_lr_h2 = pack_flags(HEADER_2, FLAG_UNSET, TRANSPORT, SINGLE, LINKREQUEST)
    raw_lr_h2 = build_header_2(flags_lr_h2, 2, identity_hash_C, dest_hash_D, NONE_CONTEXT) + lr_data

    hops_lr_stripped = 3
    raw_lr_stripped = relay_packet(raw_lr_h2, hops_lr_stripped, None, 1)

    _, _, lr_h2_hash = compute_packet_hash(raw_lr_h2)
    _, _, lr_h1_hash = compute_packet_hash(raw_lr_stripped)

    lr_stripped_flags = raw_lr_stripped[0]
    lr_expected_flags = (HEADER_1 << 6) | (BROADCAST << 4) | (flags_lr_h2 & 0x0F)

    vectors.append({
        "description": "LINKREQUEST packet HEADER_2→HEADER_1 stripping at final hop",
        "packet_type": "LINKREQUEST",
        "destination_hash": dest_hash_D.hex(),
        "transport_id": identity_hash_C.hex(),
        "remaining_hops": 1,
        "hops_after_increment": hops_lr_stripped,
        "lr_data": lr_data.hex(),
        "lr_data_length": len(lr_data),
        "original_flags": f"{flags_lr_h2:02x}",
        "original_raw": raw_lr_h2.hex(),
        "original_raw_length": len(raw_lr_h2),
        "original_packet_hash": lr_h2_hash.hex(),
        "stripped_flags": f"{lr_stripped_flags:02x}",
        "expected_flags": f"{lr_expected_flags:02x}",
        "stripped_raw": raw_lr_stripped.hex(),
        "stripped_raw_length": len(raw_lr_stripped),
        "stripped_packet_hash": lr_h1_hash.hex(),
        "size_decrease": len(raw_lr_h2) - len(raw_lr_stripped),
    })

    # --- Vector 3: PROOF packet stripping ---
    proof_payload = hashlib.sha256(b"deterministic_proof_data").digest()  # 32 bytes

    flags_proof_h2 = pack_flags(HEADER_2, FLAG_UNSET, TRANSPORT, SINGLE, PROOF)
    raw_proof_h2 = build_header_2(flags_proof_h2, 0, identity_hash_C, dest_hash_D, NONE_CONTEXT) + proof_payload

    hops_proof_stripped = 1
    raw_proof_stripped = relay_packet(raw_proof_h2, hops_proof_stripped, None, 1)

    _, _, proof_h2_hash = compute_packet_hash(raw_proof_h2)
    _, _, proof_h1_hash = compute_packet_hash(raw_proof_stripped)

    proof_stripped_flags = raw_proof_stripped[0]
    proof_expected_flags = (HEADER_1 << 6) | (BROADCAST << 4) | (flags_proof_h2 & 0x0F)

    vectors.append({
        "description": "PROOF packet HEADER_2→HEADER_1 stripping at final hop",
        "packet_type": "PROOF",
        "destination_hash": dest_hash_D.hex(),
        "remaining_hops": 1,
        "hops_after_increment": hops_proof_stripped,
        "proof_payload": proof_payload.hex(),
        "original_flags": f"{flags_proof_h2:02x}",
        "original_raw": raw_proof_h2.hex(),
        "original_raw_length": len(raw_proof_h2),
        "original_packet_hash": proof_h2_hash.hex(),
        "stripped_flags": f"{proof_stripped_flags:02x}",
        "expected_flags": f"{proof_expected_flags:02x}",
        "stripped_raw": raw_proof_stripped.hex(),
        "stripped_raw_length": len(raw_proof_stripped),
        "stripped_packet_hash": proof_h1_hash.hex(),
        "size_decrease": len(raw_proof_h2) - len(raw_proof_stripped),
    })

    return vectors


def extract_link_table_routing_vectors(nodes, name_hash):
    """
    Category 8: Bidirectional link forwarding via link_table.

    Transport.py:1514-1548. After link established, packets routed via link_table:
    - Same interface: repeat if hops == remaining_hops OR hops == taken_hops
    - Different interfaces: transmit on opposite interface, checking expected hop count
    """
    vectors = []

    dest_hash_D = nodes["D"]["dest_hash"]
    identity_hash_B = nodes["B"]["identity_hash"]

    # Simulate a link_table entry at Node B
    # Link from A(hops=1) through B(remaining=2) to D
    taken_hops = 1
    remaining_hops = 2

    # --- Vector 1: Same-interface routing (nh_if == rcvd_if) ---
    # When both interfaces are the same, accept if hops matches either value
    payload_same = b"Same interface data"

    # Use HEADER_1 for link data (after link established, packets use link_id as dest_hash)
    link_id = hashlib.sha256(b"deterministic_link_id_for_test").digest()[:TRUNCATED_HASHLENGTH_BYTES]

    flags_data = pack_flags(HEADER_1, FLAG_UNSET, BROADCAST, SINGLE, DATA)

    # Packet with hops == remaining_hops (2)
    raw_same_rem = build_header_1(flags_data, remaining_hops, link_id, NONE_CONTEXT) + payload_same
    new_raw_same_rem = raw_same_rem[0:1] + struct.pack("!B", remaining_hops) + raw_same_rem[2:]

    _, _, same_rem_hash = compute_packet_hash(raw_same_rem)

    vectors.append({
        "description": "Link table routing: same interface, hops matches remaining_hops",
        "link_id": link_id.hex(),
        "link_entry": {
            "IDX_LT_REM_HOPS": remaining_hops,
            "IDX_LT_HOPS": taken_hops,
            "interfaces_same": True,
        },
        "packet_hops": remaining_hops,
        "matches": "remaining_hops",
        "should_forward": True,
        "raw_packet": raw_same_rem.hex(),
        "forwarded_raw": new_raw_same_rem.hex(),
        "packet_hash": same_rem_hash.hex(),
        "rule": "Same interface: forward if packet.hops == link_entry[IDX_LT_REM_HOPS] OR packet.hops == link_entry[IDX_LT_HOPS]",
    })

    # Packet with hops == taken_hops (1)
    raw_same_taken = build_header_1(flags_data, taken_hops, link_id, NONE_CONTEXT) + payload_same
    new_raw_same_taken = raw_same_taken[0:1] + struct.pack("!B", taken_hops) + raw_same_taken[2:]

    _, _, same_taken_hash = compute_packet_hash(raw_same_taken)

    vectors.append({
        "description": "Link table routing: same interface, hops matches taken_hops",
        "link_id": link_id.hex(),
        "link_entry": {
            "IDX_LT_REM_HOPS": remaining_hops,
            "IDX_LT_HOPS": taken_hops,
            "interfaces_same": True,
        },
        "packet_hops": taken_hops,
        "matches": "taken_hops",
        "should_forward": True,
        "raw_packet": raw_same_taken.hex(),
        "forwarded_raw": new_raw_same_taken.hex(),
        "packet_hash": same_taken_hash.hex(),
    })

    # --- Vector 2: Different interface routing (forward direction: nh_if → rcvd_if) ---
    # Packet received on nh_if, check hops == remaining_hops, transmit on rcvd_if
    raw_cross_fwd = build_header_1(flags_data, remaining_hops, link_id, NONE_CONTEXT) + b"Cross interface forward"
    new_raw_cross_fwd = raw_cross_fwd[0:1] + struct.pack("!B", remaining_hops) + raw_cross_fwd[2:]

    _, _, cross_fwd_hash = compute_packet_hash(raw_cross_fwd)

    vectors.append({
        "description": "Link table routing: different interfaces, received on nh_if, forward to rcvd_if",
        "link_id": link_id.hex(),
        "link_entry": {
            "IDX_LT_REM_HOPS": remaining_hops,
            "IDX_LT_HOPS": taken_hops,
            "interfaces_same": False,
        },
        "received_on": "nh_if",
        "packet_hops": remaining_hops,
        "expected_hops_check": "packet.hops == link_entry[IDX_LT_REM_HOPS]",
        "outbound_to": "rcvd_if",
        "should_forward": True,
        "raw_packet": raw_cross_fwd.hex(),
        "forwarded_raw": new_raw_cross_fwd.hex(),
        "packet_hash": cross_fwd_hash.hex(),
        "rule": "Received on nh_if: check hops == remaining_hops, transmit on rcvd_if",
    })

    # --- Vector 3: Different interface routing (reverse direction: rcvd_if → nh_if) ---
    # Packet received on rcvd_if, check hops == taken_hops, transmit on nh_if
    raw_cross_rev = build_header_1(flags_data, taken_hops, link_id, NONE_CONTEXT) + b"Cross interface reverse"
    new_raw_cross_rev = raw_cross_rev[0:1] + struct.pack("!B", taken_hops) + raw_cross_rev[2:]

    _, _, cross_rev_hash = compute_packet_hash(raw_cross_rev)

    vectors.append({
        "description": "Link table routing: different interfaces, received on rcvd_if, forward to nh_if",
        "link_id": link_id.hex(),
        "link_entry": {
            "IDX_LT_REM_HOPS": remaining_hops,
            "IDX_LT_HOPS": taken_hops,
            "interfaces_same": False,
        },
        "received_on": "rcvd_if",
        "packet_hops": taken_hops,
        "expected_hops_check": "packet.hops == link_entry[IDX_LT_HOPS]",
        "outbound_to": "nh_if",
        "should_forward": True,
        "raw_packet": raw_cross_rev.hex(),
        "forwarded_raw": new_raw_cross_rev.hex(),
        "packet_hash": cross_rev_hash.hex(),
        "rule": "Received on rcvd_if: check hops == taken_hops, transmit on nh_if",
    })

    # --- Vector 4: Hop count mismatch rejection ---
    # Packet with wrong hop count should not be forwarded
    wrong_hops = 5  # neither remaining_hops(2) nor taken_hops(1)
    raw_mismatch = build_header_1(flags_data, wrong_hops, link_id, NONE_CONTEXT) + b"Wrong hop count"

    _, _, mismatch_hash = compute_packet_hash(raw_mismatch)

    vectors.append({
        "description": "Link table routing: hop count mismatch, packet NOT forwarded",
        "link_id": link_id.hex(),
        "link_entry": {
            "IDX_LT_REM_HOPS": remaining_hops,
            "IDX_LT_HOPS": taken_hops,
            "interfaces_same": True,
        },
        "packet_hops": wrong_hops,
        "should_forward": False,
        "raw_packet": raw_mismatch.hex(),
        "packet_hash": mismatch_hash.hex(),
        "rule": "Hop count 5 matches neither remaining_hops(2) nor taken_hops(1) → not forwarded",
    })

    # --- Vector 5: Hop count mismatch on different interfaces ---
    # Received on nh_if but hops != remaining_hops
    wrong_hops_cross = 3
    raw_mismatch_cross = build_header_1(flags_data, wrong_hops_cross, link_id, NONE_CONTEXT) + b"Wrong hops cross"

    _, _, mismatch_cross_hash = compute_packet_hash(raw_mismatch_cross)

    vectors.append({
        "description": "Link table routing: different interfaces, hop count mismatch on nh_if side",
        "link_id": link_id.hex(),
        "link_entry": {
            "IDX_LT_REM_HOPS": remaining_hops,
            "IDX_LT_HOPS": taken_hops,
            "interfaces_same": False,
        },
        "received_on": "nh_if",
        "packet_hops": wrong_hops_cross,
        "expected_hops": remaining_hops,
        "should_forward": False,
        "raw_packet": raw_mismatch_cross.hex(),
        "packet_hash": mismatch_cross_hash.hex(),
        "rule": f"Received on nh_if: hops({wrong_hops_cross}) != remaining_hops({remaining_hops}) → not forwarded",
    })

    # --- Vector 6: Forwarded packet wire format ---
    # The actual relayed bytes: raw[0:1] + pack("!B", hops) + raw[2:]
    payload_relay = b"Relayed link packet"
    raw_original = build_header_1(flags_data, taken_hops, link_id, NONE_CONTEXT) + payload_relay

    # Forwarded packet: same content but hops byte re-packed
    new_raw_relay = raw_original[0:1] + struct.pack("!B", taken_hops) + raw_original[2:]

    _, _, relay_hash = compute_packet_hash(raw_original)

    vectors.append({
        "description": "Link table routing: wire format of forwarded packet",
        "link_id": link_id.hex(),
        "original_raw": raw_original.hex(),
        "forwarded_raw": new_raw_relay.hex(),
        "packets_identical": raw_original == new_raw_relay,
        "transformation": "new_raw = raw[0:1] + pack('!B', packet.hops) + raw[2:]",
        "note": "Forwarded packet preserves all bytes; hops byte re-packed from packet.hops field",
    })

    return vectors


# --- Verification ---

def verify(output):
    """Verify all test vectors for internal consistency."""
    import RNS

    print("Verifying...")

    # 1. Verify header transformation vectors
    for vec in output["header_transformation_vectors"]:
        original = bytes.fromhex(vec["original_raw"])
        transformed = bytes.fromhex(vec["transformed_raw"])
        next_hop = bytes.fromhex(vec["next_hop"])

        # Verify transformation
        result = inject_into_transport(original, next_hop)
        assert result == transformed, (
            f"Header transformation mismatch: {vec['description']}"
        )

        # Verify size increase is 16 bytes
        assert vec["size_increase"] == TRUNCATED_HASHLENGTH_BYTES, (
            f"Size increase should be {TRUNCATED_HASHLENGTH_BYTES}: {vec['description']}"
        )

        # Verify packet hashes
        _, _, orig_hash = compute_packet_hash(original)
        assert orig_hash.hex() == vec["original_packet_hash"]
        _, _, trans_hash = compute_packet_hash(transformed)
        assert trans_hash.hex() == vec["transformed_packet_hash"]

        # Verify the packet hashes are the same (hashable_part skips transport_id)
        assert orig_hash == trans_hash, (
            f"HEADER_1 and HEADER_2 packet hashes should be identical: {vec['description']}"
        )

    print(f"  [OK] All {len(output['header_transformation_vectors'])} header transformation vectors verified")

    # 2. Verify announce propagation vectors
    for vec in output["announce_propagation_vectors"]:
        chain = vec["chain"]
        for step in chain:
            if "raw_packet" in step:
                raw = bytes.fromhex(step["raw_packet"])
                _, _, pkt_hash = compute_packet_hash(raw)
                assert pkt_hash.hex() == step["packet_hash"], (
                    f"Announce propagation packet hash mismatch: step {step['step']}"
                )
            if "rebroadcast_raw" in step:
                raw_rb = bytes.fromhex(step["rebroadcast_raw"])
                _, _, rb_hash = compute_packet_hash(raw_rb)
                assert rb_hash.hex() == step["rebroadcast_packet_hash"], (
                    f"Rebroadcast packet hash mismatch: step {step['step']}"
                )

        # Verify hop increments
        for i, step in enumerate(chain):
            if "hops_after_increment" in step:
                if i == 1:  # First relay
                    assert step["hops_after_increment"] == 1
                elif "hops_after_increment" in step:
                    assert step["hops_after_increment"] == chain[i-1].get("hops_after_increment", 0) + 1 or \
                           step["hops_after_increment"] == chain[i-1].get("hops_on_wire", 0) + 1

    print(f"  [OK] All {len(output['announce_propagation_vectors'])} announce propagation vectors verified")

    # 3. Verify link request forwarding vectors
    for vec in output["link_request_forwarding_vectors"]:
        arriving = bytes.fromhex(vec["arriving_raw"])
        relayed = bytes.fromhex(vec["relayed_raw"])

        _, _, arr_hash = compute_packet_hash(arriving)
        assert arr_hash.hex() == vec["arriving_packet_hash"]

        _, _, rel_hash = compute_packet_hash(relayed)
        assert rel_hash.hex() == vec["relayed_packet_hash"]

        # Verify link_id if present
        if "link_id" in vec:
            lr_data = bytes.fromhex(vec["lr_data"])
            computed_link_id = compute_link_id(arriving, len(lr_data))
            assert computed_link_id.hex() == vec["link_id"], (
                f"Link ID mismatch: {vec['description']}"
            )

    print(f"  [OK] All {len(output['link_request_forwarding_vectors'])} link request forwarding vectors verified")

    # 4. Verify link table entry vectors
    for vec in output["link_table_entry_vectors"]:
        raw = bytes.fromhex(vec["raw_packet"])
        if "lr_data_length" in vec:
            computed_link_id = compute_link_id(raw, vec["lr_data_length"])
            assert computed_link_id.hex() == vec["link_id"], (
                f"Link table entry link_id mismatch: {vec['description']}"
            )
        if "proof_timeout_calculation" in vec:
            calc = vec["proof_timeout_calculation"]
            expected = calc["extra_link_proof_timeout"] + calc["now"] + \
                       calc["establishment_timeout_per_hop"] * calc["max_1_remaining"]
            assert calc["result"] == expected, (
                f"Proof timeout mismatch: {vec['description']}"
            )

    print(f"  [OK] All {len(output['link_table_entry_vectors'])} link table entry vectors verified")

    # 5. Verify reverse table entry vectors
    for vec in output["reverse_table_entry_vectors"]:
        if "raw_packet" in vec:
            raw = bytes.fromhex(vec["raw_packet"])
            hashable = get_hashable_part(raw)
            if "hashable_part" in vec:
                assert hashable.hex() == vec["hashable_part"]
            if "truncated_hash_key" in vec:
                trunc = hashlib.sha256(hashable).digest()[:TRUNCATED_HASHLENGTH_BYTES]
                assert trunc.hex() == vec["truncated_hash_key"]

        if "is_expired" in vec:
            ts = vec["timestamp"]
            check = vec["check_time"]
            expired = check > ts + REVERSE_TIMEOUT
            assert expired == vec["is_expired"], (
                f"Reverse table expiration mismatch: {vec['description']}"
            )

    print(f"  [OK] All {len(output['reverse_table_entry_vectors'])} reverse table entry vectors verified")

    # 6. Verify path table query vectors
    for vec in output["path_table_query_vectors"]:
        if not vec["path_table_entry_exists"]:
            assert vec["has_path_result"] == False
            assert vec["hops_to_result"] == PATHFINDER_M
            assert vec["next_hop_result"] is None
        else:
            assert vec["has_path_result"] == True
            assert vec["hops_to_result"] == vec["path_table_hops"]
            assert vec["next_hop_result"] == vec["path_table_next_hop"]

    print(f"  [OK] All {len(output['path_table_query_vectors'])} path table query vectors verified")

    # 7. Verify header stripping vectors
    for vec in output["header_stripping_vectors"]:
        original = bytes.fromhex(vec["original_raw"])
        stripped = bytes.fromhex(vec["stripped_raw"])

        # Verify stripped flags
        assert vec["stripped_flags"] == vec["expected_flags"]

        # Verify size decrease is 16 bytes
        assert vec["size_decrease"] == TRUNCATED_HASHLENGTH_BYTES

        # Verify packet hashes
        _, _, orig_hash = compute_packet_hash(original)
        assert orig_hash.hex() == vec["original_packet_hash"]
        _, _, strip_hash = compute_packet_hash(stripped)
        assert strip_hash.hex() == vec["stripped_packet_hash"]

        # HEADER_2→HEADER_1 should preserve packet hash
        assert orig_hash == strip_hash, (
            f"Stripped packet hash should match original: {vec['description']}"
        )

    print(f"  [OK] All {len(output['header_stripping_vectors'])} header stripping vectors verified")

    # 8. Verify link table routing vectors
    for vec in output["link_table_routing_vectors"]:
        raw_key = "raw_packet" if "raw_packet" in vec else "original_raw"
        raw = bytes.fromhex(vec[raw_key])
        if "packet_hash" in vec:
            _, _, pkt_hash = compute_packet_hash(raw)
            assert pkt_hash.hex() == vec["packet_hash"]

        if "should_forward" in vec and vec["should_forward"] and "forwarded_raw" in vec:
            fwd = bytes.fromhex(vec["forwarded_raw"])
            # Verify forwarded packet structure
            assert fwd[0:1] == raw[0:1]  # flags unchanged
            assert fwd[2:] == raw[2:]    # rest unchanged

    print(f"  [OK] All {len(output['link_table_routing_vectors'])} link table routing vectors verified")

    # 9. JSON round-trip
    json_str = json.dumps(output, indent=2)
    assert json.loads(json_str) == output, "JSON round-trip failed"
    print("  [OK] JSON round-trip integrity verified")


def verify_library_constants():
    """Verify local constants match the actual RNS library values."""
    import RNS

    assert MTU == RNS.Reticulum.MTU
    assert TRUNCATED_HASHLENGTH_BYTES == RNS.Reticulum.TRUNCATED_HASHLENGTH // 8
    assert KEYSIZE_BYTES == RNS.Identity.KEYSIZE // 8
    assert NAME_HASH_LENGTH_BYTES == RNS.Identity.NAME_HASH_LENGTH // 8
    assert SIGLENGTH_BYTES == RNS.Identity.SIGLENGTH // 8
    assert RATCHETSIZE_BYTES == RNS.Identity.RATCHETSIZE // 8

    assert HEADER_1 == RNS.Packet.HEADER_1
    assert HEADER_2 == RNS.Packet.HEADER_2
    assert DATA == RNS.Packet.DATA
    assert ANNOUNCE == RNS.Packet.ANNOUNCE
    assert LINKREQUEST == RNS.Packet.LINKREQUEST
    assert PROOF == RNS.Packet.PROOF
    assert PATH_RESPONSE == RNS.Packet.PATH_RESPONSE
    assert LRPROOF == RNS.Packet.LRPROOF
    assert NONE_CONTEXT == RNS.Packet.NONE
    assert FLAG_SET == RNS.Packet.FLAG_SET
    assert FLAG_UNSET == RNS.Packet.FLAG_UNSET

    assert BROADCAST == RNS.Transport.BROADCAST
    assert TRANSPORT == RNS.Transport.TRANSPORT
    assert SINGLE == RNS.Destination.SINGLE
    assert PLAIN == RNS.Destination.PLAIN

    assert ECPUBSIZE == RNS.Link.ECPUBSIZE
    assert LINK_MTU_SIZE == RNS.Link.LINK_MTU_SIZE
    assert ESTABLISHMENT_TIMEOUT_PER_HOP == RNS.Link.ESTABLISHMENT_TIMEOUT_PER_HOP
    assert ESTABLISHMENT_TIMEOUT_PER_HOP == RNS.Reticulum.DEFAULT_PER_HOP_TIMEOUT

    assert REVERSE_TIMEOUT == RNS.Transport.REVERSE_TIMEOUT
    assert PATHFINDER_M == RNS.Transport.PATHFINDER_M
    assert PATHFINDER_E == RNS.Transport.PATHFINDER_E

    print("  [OK] All library constants verified")


def main():
    print("Extracting multi-hop routing test vectors...")

    print("Verifying library constants...")
    verify_library_constants()

    keypairs = load_keypairs()
    print(f"  Loaded {len(keypairs)} keypairs")

    nodes, name_hash, app_name, aspects = setup_topology(keypairs)
    print(f"  Set up 4-node topology: A(kp0), B(kp1), C(kp2), D(kp3)")

    header_transform = extract_header_transformation_vectors(nodes, name_hash)
    print(f"  Extracted {len(header_transform)} header transformation vectors")

    announce_prop = extract_announce_propagation_vectors(nodes, name_hash)
    print(f"  Extracted {len(announce_prop)} announce propagation vectors")

    lr_forwarding = extract_link_request_forwarding_vectors(nodes, name_hash)
    print(f"  Extracted {len(lr_forwarding)} link request forwarding vectors")

    lt_entries = extract_link_table_entry_vectors(nodes, name_hash)
    print(f"  Extracted {len(lt_entries)} link table entry vectors")

    rt_entries = extract_reverse_table_entry_vectors(nodes, name_hash)
    print(f"  Extracted {len(rt_entries)} reverse table entry vectors")

    pt_queries = extract_path_table_query_vectors(nodes, name_hash)
    print(f"  Extracted {len(pt_queries)} path table query vectors")

    header_strip = extract_header_stripping_vectors(nodes, name_hash)
    print(f"  Extracted {len(header_strip)} header stripping vectors")

    lt_routing = extract_link_table_routing_vectors(nodes, name_hash)
    print(f"  Extracted {len(lt_routing)} link table routing vectors")

    output = {
        "description": "Reticulum v1.1.3 reference implementation - multi-hop routing test vectors",
        "source": "RNS/Transport.py, RNS/Packet.py, RNS/Link.py",
        "topology": {
            "node_A": {"keypair_index": 0, "role": "source/receiver", "identity_hash": nodes["A"]["identity_hash"].hex()},
            "node_B": {"keypair_index": 1, "role": "transport relay 1", "identity_hash": nodes["B"]["identity_hash"].hex()},
            "node_C": {"keypair_index": 2, "role": "transport relay 2", "identity_hash": nodes["C"]["identity_hash"].hex()},
            "node_D": {"keypair_index": 3, "role": "destination/announce origin", "identity_hash": nodes["D"]["identity_hash"].hex()},
        },
        "constants": {
            "header_1": HEADER_1,
            "header_2": HEADER_2,
            "data": DATA,
            "announce": ANNOUNCE,
            "linkrequest": LINKREQUEST,
            "proof": PROOF,
            "broadcast": BROADCAST,
            "transport": TRANSPORT,
            "single": SINGLE,
            "plain": PLAIN,
            "ecpubsize": ECPUBSIZE,
            "link_mtu_size": LINK_MTU_SIZE,
            "establishment_timeout_per_hop": ESTABLISHMENT_TIMEOUT_PER_HOP,
            "reverse_timeout_seconds": REVERSE_TIMEOUT,
            "pathfinder_m": PATHFINDER_M,
            "pathfinder_e_seconds": PATHFINDER_E,
            "truncated_hashlength_bytes": TRUNCATED_HASHLENGTH_BYTES,
        },
        "algorithms": {
            "header_1_to_2_injection": {
                "new_flags": "(HEADER_2 << 6) | (TRANSPORT << 4) | (original_flags & 0x0F)",
                "new_raw": "flags(1) + hops(1) + next_hop(16) + original_raw[2:]",
                "size_change": "+16 bytes (transport_id inserted)",
            },
            "header_2_to_1_stripping": {
                "new_flags": "(HEADER_1 << 6) | (BROADCAST << 4) | (flags & 0x0F)",
                "new_raw": "flags(1) + hops(1) + original_raw[18:] (skip transport_id)",
                "size_change": "-16 bytes (transport_id removed)",
            },
            "relay_remaining_gt_1": {
                "action": "Update transport_id to next_hop, update hops byte",
                "new_raw": "raw[0:1] + hops(1) + next_hop(16) + raw[18:]",
            },
            "relay_remaining_eq_0": {
                "action": "Just update hops byte",
                "new_raw": "raw[0:1] + hops(1) + raw[2:]",
            },
            "packet_hash_invariant": "HEADER_1 and HEADER_2 versions of the same packet have identical packet hashes (hashable_part skips transport_id)",
            "link_id": "SHA256(hashable_part[:-(data_len - ECPUBSIZE)] if data > ECPUBSIZE else hashable_part)[:16]",
            "reverse_table_key": "SHA256(hashable_part)[:16] = getTruncatedHash()",
            "reverse_expiration": "Expired when time.time() > entry[2] + REVERSE_TIMEOUT (strict >)",
            "announce_received_from": "HEADER_1: destination_hash, HEADER_2: transport_id",
        },
        "header_transformation_vectors": header_transform,
        "announce_propagation_vectors": announce_prop,
        "link_request_forwarding_vectors": lr_forwarding,
        "link_table_entry_vectors": lt_entries,
        "reverse_table_entry_vectors": rt_entries,
        "path_table_query_vectors": pt_queries,
        "header_stripping_vectors": header_strip,
        "link_table_routing_vectors": lt_routing,
    }

    verify(output)

    print(f"Writing {OUTPUT_PATH}...")
    with open(OUTPUT_PATH, "w") as f:
        json.dump(output, f, indent=2)
        f.write("\n")

    print("Done.")


if __name__ == "__main__":
    main()
