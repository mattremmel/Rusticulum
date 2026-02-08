#!/usr/bin/env python3
"""
Extract path request/response protocol test vectors from the Reticulum
reference implementation into a JSON file for consumption by alternative
implementations.

Covers:
  - PLAIN destination hash for the path request endpoint
  - Path request packet wire format
  - Path request handler parsing logic
  - Path response packets (announces with PATH_RESPONSE context)
  - Path table entry construction
  - Duplicate detection via unique tags
  - Grace period / retransmit delay timing

All vectors are computed manually (no live Destination/Transport objects)
to avoid Transport init. Real RNS.Identity objects are used for signing.

Usage:
    python3 test_vectors/extract_path_requests.py

Output:
    test_vectors/path_requests.json
"""

import hashlib
import json
import os
import struct
import sys

repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, repo_root)

OUTPUT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "path_requests.json")
KEYPAIRS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keypairs.json")

# --- Constants (reproduced to avoid Transport init) ---
HEADER_1 = 0x00
HEADER_2 = 0x01
DATA = 0x00
ANNOUNCE = 0x01
BROADCAST = 0x00
TRANSPORT = 0x01
SINGLE = 0x00
PLAIN = 0x02
FLAG_SET = 0x01
FLAG_UNSET = 0x00
NONE_CONTEXT = 0x00
PATH_RESPONSE = 0x0B

MTU = 500
HEADER_MINSIZE = 19   # 2 + 1 + 16
HEADER_MAXSIZE = 35   # 2 + 1 + 16*2
TRUNCATED_HASHLENGTH_BYTES = 16
KEYSIZE_BYTES = 64
NAME_HASH_LENGTH_BYTES = 10
SIGLENGTH_BYTES = 64
RATCHETSIZE_BYTES = 32
RANDOM_HASH_LENGTH = 10

# Transport timing constants
PATH_REQUEST_TIMEOUT = 15
PATH_REQUEST_GRACE = 0.4
PATH_REQUEST_RG = 1.5
PATH_REQUEST_MI = 20

# Path expiration constants
PATHFINDER_E = 60 * 60 * 24 * 7      # 604800 — one week
AP_PATH_TIME = 60 * 60 * 24          # 86400  — one day
ROAMING_PATH_TIME = 60 * 60 * 6      # 21600  — six hours

# Retransmission constants
PATHFINDER_R = 1
PATHFINDER_G = 5
PATHFINDER_RW = 0.5

# Path table entry indices
IDX_PT_TIMESTAMP = 0
IDX_PT_NEXT_HOP = 1
IDX_PT_HOPS = 2
IDX_PT_EXPIRES = 3
IDX_PT_RANDBLOBS = 4
IDX_PT_RVCD_IF = 5
IDX_PT_PACKET = 6

# Interface modes
MODE_ACCESS_POINT = 0x03
MODE_ROAMING = 0x04
MODE_GATEWAY = 0x06

# Fixed timestamp for deterministic test vectors
FIXED_TIMESTAMP = 1700000000

# Transport APP_NAME
TRANSPORT_APP_NAME = "rnstransport"


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


def compute_packet_hash(raw_packet):
    """Compute packet hash matching Packet.get_hashable_part() + Identity.full_hash()."""
    flags = raw_packet[0]
    header_type = (flags & 0b01000000) >> 6
    hashable_part = bytes([flags & 0x0F])
    if header_type == HEADER_2:
        hashable_part += raw_packet[TRUNCATED_HASHLENGTH_BYTES + 2:]
    else:
        hashable_part += raw_packet[2:]
    full_hash = hashlib.sha256(hashable_part).digest()
    truncated_hash = full_hash[:TRUNCATED_HASHLENGTH_BYTES]
    return hashable_part, full_hash, truncated_hash


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
    """Compute destination hash = SHA256(name_hash + identity_hash)[:16] for SINGLE destinations."""
    return hashlib.sha256(name_hash + identity_hash).digest()[:TRUNCATED_HASHLENGTH_BYTES]


def make_plain_destination_hash(app_name, *aspects):
    """
    Compute destination hash for a PLAIN destination (no identity).
    PLAIN: name_hash = SHA256(full_name)[:10], dest_hash = SHA256(name_hash)[:16]
    """
    name_hash = make_name_hash(app_name, *aspects)
    return name_hash, hashlib.sha256(name_hash).digest()[:TRUNCATED_HASHLENGTH_BYTES]


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


# Deterministic random prefixes (reused from extract_announces.py)
DETERMINISTIC_RANDOM_PREFIXES = [
    bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE]),
    bytes([0x11, 0x22, 0x33, 0x44, 0x55]),
    bytes([0xDE, 0xAD, 0xBE, 0xEF, 0x01]),
    bytes([0xCA, 0xFE, 0xBA, 0xBE, 0x02]),
    bytes([0xF0, 0x0D, 0xBA, 0xD0, 0x03]),
]

# Deterministic request tags
def make_request_tag(index):
    """Generate deterministic 16-byte request tag for test vector index."""
    return hashlib.sha256(f"reticulum_test_request_tag_{index}".encode("utf-8")).digest()[:TRUNCATED_HASHLENGTH_BYTES]


# --- Vector Extraction Functions ---

def extract_path_request_destination():
    """Category 1: The well-known PLAIN destination hash for path requests."""
    app_name = TRANSPORT_APP_NAME
    aspects = ["path", "request"]
    full_name = app_name + "." + ".".join(aspects)

    name_hash, dest_hash = make_plain_destination_hash(app_name, *aspects)

    return [{
        "description": f"PLAIN destination hash for '{full_name}'",
        "full_name": full_name,
        "app_name": app_name,
        "aspects": aspects,
        "destination_type": "PLAIN",
        "name_hash": name_hash.hex(),
        "destination_hash": dest_hash.hex(),
        "derivation": {
            "step_1": f"name_hash = SHA256('{full_name}'.encode('utf-8'))[:10]",
            "step_2": "destination_hash = SHA256(name_hash)[:16]",
            "note": "PLAIN destinations have no identity, so addr_hash_material = name_hash only",
        },
    }]


def extract_path_request_packets(keypairs):
    """Category 2: Full wire-format path request packets."""
    vectors = []

    # The path request destination hash (PLAIN)
    _, pr_dest_hash = make_plain_destination_hash(TRANSPORT_APP_NAME, "path", "request")

    # Path request packets use: HEADER_1, DATA, BROADCAST, PLAIN, context=NONE
    flags = pack_flags(HEADER_1, FLAG_UNSET, BROADCAST, PLAIN, DATA)

    # Vector 1: Transport-disabled, 32-byte payload (dest_hash + tag)
    kp0 = keypairs[0]
    identity0 = load_identity(kp0)
    target_identity_hash = bytes.fromhex(kp0["identity_hash"])
    target_name_hash = make_name_hash("rns_unit_tests", "link", "establish")
    target_dest_hash = make_destination_hash(target_name_hash, target_identity_hash)
    tag0 = make_request_tag(0)
    path_request_data = target_dest_hash + tag0  # 16 + 16 = 32 bytes
    header = build_header_1(flags, 0, pr_dest_hash, NONE_CONTEXT)
    raw = header + path_request_data
    _, _, packet_hash = compute_packet_hash(raw)

    vectors.append({
        "description": "Path request, transport-disabled, 32-byte payload (dest + tag)",
        "transport_enabled": False,
        "target_destination_hash": target_dest_hash.hex(),
        "request_tag": tag0.hex(),
        "transport_id": None,
        "path_request_data": path_request_data.hex(),
        "path_request_data_length": len(path_request_data),
        "flags_byte": f"{flags:02x}",
        "hops": 0,
        "context": f"{NONE_CONTEXT:02x}",
        "path_request_dest_hash": pr_dest_hash.hex(),
        "header": header.hex(),
        "raw_packet": raw.hex(),
        "raw_packet_length": len(raw),
        "packet_hash": packet_hash.hex(),
        "payload_layout": "target_dest_hash(16) + request_tag(16) = 32 bytes",
    })

    # Vector 2: Transport-enabled, 48-byte payload (dest_hash + transport_id + tag)
    kp1 = keypairs[1]
    identity1 = load_identity(kp1)
    transport_id = bytes.fromhex(kp1["identity_hash"])  # Transport node's identity hash
    tag1 = make_request_tag(1)
    path_request_data = target_dest_hash + transport_id + tag1  # 16 + 16 + 16 = 48 bytes
    header = build_header_1(flags, 0, pr_dest_hash, NONE_CONTEXT)
    raw = header + path_request_data
    _, _, packet_hash = compute_packet_hash(raw)

    vectors.append({
        "description": "Path request, transport-enabled, 48-byte payload (dest + transport_id + tag)",
        "transport_enabled": True,
        "target_destination_hash": target_dest_hash.hex(),
        "request_tag": tag1.hex(),
        "transport_id": transport_id.hex(),
        "path_request_data": path_request_data.hex(),
        "path_request_data_length": len(path_request_data),
        "flags_byte": f"{flags:02x}",
        "hops": 0,
        "context": f"{NONE_CONTEXT:02x}",
        "path_request_dest_hash": pr_dest_hash.hex(),
        "header": header.hex(),
        "raw_packet": raw.hex(),
        "raw_packet_length": len(raw),
        "packet_hash": packet_hash.hex(),
        "payload_layout": "target_dest_hash(16) + transport_identity_hash(16) + request_tag(16) = 48 bytes",
    })

    # Vector 3: Transport-disabled, different tag
    tag2 = make_request_tag(2)
    path_request_data = target_dest_hash + tag2
    header = build_header_1(flags, 0, pr_dest_hash, NONE_CONTEXT)
    raw = header + path_request_data
    _, _, packet_hash = compute_packet_hash(raw)

    vectors.append({
        "description": "Path request, transport-disabled, different tag (tag index 2)",
        "transport_enabled": False,
        "target_destination_hash": target_dest_hash.hex(),
        "request_tag": tag2.hex(),
        "transport_id": None,
        "path_request_data": path_request_data.hex(),
        "path_request_data_length": len(path_request_data),
        "flags_byte": f"{flags:02x}",
        "hops": 0,
        "context": f"{NONE_CONTEXT:02x}",
        "path_request_dest_hash": pr_dest_hash.hex(),
        "header": header.hex(),
        "raw_packet": raw.hex(),
        "raw_packet_length": len(raw),
        "packet_hash": packet_hash.hex(),
    })

    # Vector 4: Transport-enabled, different keypairs (kp2 as transport, kp3's dest as target)
    kp2 = keypairs[2]
    kp3 = keypairs[3]
    identity2 = load_identity(kp2)
    transport_id_2 = bytes.fromhex(kp2["identity_hash"])
    target_identity_hash_3 = bytes.fromhex(kp3["identity_hash"])
    target_dest_hash_3 = make_destination_hash(target_name_hash, target_identity_hash_3)
    tag3 = make_request_tag(3)
    path_request_data = target_dest_hash_3 + transport_id_2 + tag3
    header = build_header_1(flags, 0, pr_dest_hash, NONE_CONTEXT)
    raw = header + path_request_data
    _, _, packet_hash = compute_packet_hash(raw)

    vectors.append({
        "description": "Path request, transport-enabled, keypair 2 as transport, keypair 3's dest as target",
        "transport_enabled": True,
        "target_destination_hash": target_dest_hash_3.hex(),
        "request_tag": tag3.hex(),
        "transport_id": transport_id_2.hex(),
        "path_request_data": path_request_data.hex(),
        "path_request_data_length": len(path_request_data),
        "flags_byte": f"{flags:02x}",
        "hops": 0,
        "context": f"{NONE_CONTEXT:02x}",
        "path_request_dest_hash": pr_dest_hash.hex(),
        "header": header.hex(),
        "raw_packet": raw.hex(),
        "raw_packet_length": len(raw),
        "packet_hash": packet_hash.hex(),
    })

    # Vector 5: All-zeros target (edge case)
    zero_dest = bytes(TRUNCATED_HASHLENGTH_BYTES)
    tag4 = make_request_tag(4)
    path_request_data = zero_dest + tag4
    header = build_header_1(flags, 0, pr_dest_hash, NONE_CONTEXT)
    raw = header + path_request_data
    _, _, packet_hash = compute_packet_hash(raw)

    vectors.append({
        "description": "Path request, all-zeros target destination (edge case)",
        "transport_enabled": False,
        "target_destination_hash": zero_dest.hex(),
        "request_tag": tag4.hex(),
        "transport_id": None,
        "path_request_data": path_request_data.hex(),
        "path_request_data_length": len(path_request_data),
        "flags_byte": f"{flags:02x}",
        "hops": 0,
        "context": f"{NONE_CONTEXT:02x}",
        "path_request_dest_hash": pr_dest_hash.hex(),
        "header": header.hex(),
        "raw_packet": raw.hex(),
        "raw_packet_length": len(raw),
        "packet_hash": packet_hash.hex(),
    })

    return vectors


def extract_path_request_parsing(keypairs):
    """
    Category 3: Path request handler parsing logic.

    Based on Transport.path_request_handler() (Transport.py:2646-2693).
    The handler parses the data payload to extract:
      - destination_hash (first 16 bytes)
      - requesting_transport_instance (next 16 bytes if data > 32)
      - tag_bytes (remaining bytes, truncated to 16 max)
      - unique_tag = destination_hash + tag_bytes
    """
    vectors = []

    HASH_LEN = TRUNCATED_HASHLENGTH_BYTES  # 16

    # Helper to simulate parsing
    def parse_path_request(data):
        """Replicate path_request_handler parsing logic."""
        if len(data) < HASH_LEN:
            return {"result": "ignored", "reason": "too_short"}

        destination_hash = data[:HASH_LEN]

        # Transport instance ID: present if data > 2*HASH_LEN
        if len(data) > HASH_LEN * 2:
            requesting_transport_instance = data[HASH_LEN:HASH_LEN * 2]
        else:
            requesting_transport_instance = None

        # Tag bytes extraction
        tag_bytes = None
        if len(data) > HASH_LEN * 2:
            tag_bytes = data[HASH_LEN * 2:]
        elif len(data) > HASH_LEN:
            tag_bytes = data[HASH_LEN:]

        if tag_bytes is not None:
            if len(tag_bytes) > HASH_LEN:
                tag_bytes = tag_bytes[:HASH_LEN]
            unique_tag = destination_hash + tag_bytes
            return {
                "result": "processed",
                "destination_hash": destination_hash,
                "requesting_transport_instance": requesting_transport_instance,
                "tag_bytes": tag_bytes,
                "unique_tag": unique_tag,
            }
        else:
            return {
                "result": "ignored",
                "reason": "tagless",
                "destination_hash": destination_hash,
            }

    # Build deterministic test data
    dest_a = hashlib.sha256(b"test_destination_a").digest()[:HASH_LEN]
    dest_b = hashlib.sha256(b"test_destination_b").digest()[:HASH_LEN]
    transport_a = hashlib.sha256(b"test_transport_a").digest()[:HASH_LEN]
    tag_full = hashlib.sha256(b"test_tag_full").digest()[:HASH_LEN]
    tag_short_8 = hashlib.sha256(b"test_tag_short_8").digest()[:8]
    tag_short_4 = hashlib.sha256(b"test_tag_short_4").digest()[:4]
    tag_long = hashlib.sha256(b"test_tag_long").digest()  # 32 bytes (oversized)

    # Vector 1: 48-byte data (transport-enabled) -> dest + transport + tag
    data_1 = dest_a + transport_a + tag_full
    parsed_1 = parse_path_request(data_1)
    vectors.append({
        "description": "48-byte data: transport-enabled path request with full 16-byte tag",
        "input_data": data_1.hex(),
        "input_data_length": len(data_1),
        "expected_destination_hash": dest_a.hex(),
        "expected_requesting_transport_instance": transport_a.hex(),
        "expected_tag_bytes": tag_full.hex(),
        "expected_tag_length": len(tag_full),
        "expected_unique_tag": (dest_a + tag_full).hex(),
        "expected_result": "processed",
    })

    # Vector 2: 32-byte data (no transport) -> dest + tag
    data_2 = dest_a + tag_full
    parsed_2 = parse_path_request(data_2)
    vectors.append({
        "description": "32-byte data: transport-disabled path request with 16-byte tag",
        "input_data": data_2.hex(),
        "input_data_length": len(data_2),
        "expected_destination_hash": dest_a.hex(),
        "expected_requesting_transport_instance": None,
        "expected_tag_bytes": tag_full.hex(),
        "expected_tag_length": len(tag_full),
        "expected_unique_tag": (dest_a + tag_full).hex(),
        "expected_result": "processed",
    })

    # Vector 3: 40-byte data (partial tag, 8 bytes) -> transport-enabled, 8-byte tag
    data_3 = dest_a + transport_a + tag_short_8
    parsed_3 = parse_path_request(data_3)
    vectors.append({
        "description": "40-byte data: transport-enabled path request with 8-byte tag",
        "input_data": data_3.hex(),
        "input_data_length": len(data_3),
        "expected_destination_hash": dest_a.hex(),
        "expected_requesting_transport_instance": transport_a.hex(),
        "expected_tag_bytes": tag_short_8.hex(),
        "expected_tag_length": len(tag_short_8),
        "expected_unique_tag": (dest_a + tag_short_8).hex(),
        "expected_result": "processed",
    })

    # Vector 4: 20-byte data (dest + 4-byte tag, no transport)
    data_4 = dest_a + tag_short_4
    parsed_4 = parse_path_request(data_4)
    vectors.append({
        "description": "20-byte data: transport-disabled path request with 4-byte tag",
        "input_data": data_4.hex(),
        "input_data_length": len(data_4),
        "expected_destination_hash": dest_a.hex(),
        "expected_requesting_transport_instance": None,
        "expected_tag_bytes": tag_short_4.hex(),
        "expected_tag_length": len(tag_short_4),
        "expected_unique_tag": (dest_a + tag_short_4).hex(),
        "expected_result": "processed",
    })

    # Vector 5: 16-byte data (dest only, no tag) -> ignored (tagless)
    data_5 = dest_a
    parsed_5 = parse_path_request(data_5)
    vectors.append({
        "description": "16-byte data: destination hash only, no tag — ignored as tagless",
        "input_data": data_5.hex(),
        "input_data_length": len(data_5),
        "expected_destination_hash": dest_a.hex(),
        "expected_requesting_transport_instance": None,
        "expected_tag_bytes": None,
        "expected_unique_tag": None,
        "expected_result": "ignored",
        "ignore_reason": "tagless",
    })

    # Vector 6: 64-byte data (oversized tag) -> tag truncated to 16 bytes
    data_6 = dest_a + transport_a + tag_long
    parsed_6 = parse_path_request(data_6)
    vectors.append({
        "description": "64-byte data: oversized 32-byte tag truncated to 16 bytes",
        "input_data": data_6.hex(),
        "input_data_length": len(data_6),
        "expected_destination_hash": dest_a.hex(),
        "expected_requesting_transport_instance": transport_a.hex(),
        "expected_tag_bytes": tag_long[:HASH_LEN].hex(),
        "expected_tag_length": HASH_LEN,
        "expected_unique_tag": (dest_a + tag_long[:HASH_LEN]).hex(),
        "expected_result": "processed",
        "note": "Tag was 32 bytes but truncated to TRUNCATED_HASHLENGTH//8 = 16",
    })

    # Vector 7: 15-byte data -> too short, ignored entirely
    data_7 = dest_a[:15]
    parsed_7 = parse_path_request(data_7)
    vectors.append({
        "description": "15-byte data: too short for destination hash — ignored",
        "input_data": data_7.hex(),
        "input_data_length": len(data_7),
        "expected_destination_hash": None,
        "expected_requesting_transport_instance": None,
        "expected_tag_bytes": None,
        "expected_unique_tag": None,
        "expected_result": "ignored",
        "ignore_reason": "too_short",
    })

    return vectors


def extract_path_response_packets(keypairs):
    """
    Category 4: Announce packets with context=PATH_RESPONSE, HEADER_2, TRANSPORT.

    A path response is an announce relayed by a transport node. It uses HEADER_2
    with transport_id set to the relaying transport node's identity hash.
    """
    vectors = []

    app_name = "rns_unit_tests"
    aspects = ["link", "establish"]
    name_hash = make_name_hash(app_name, *aspects)

    # Vector 1: Basic path response (no ratchet)
    # Keypair 0 is the announce source, keypair 1 is the transport relay node
    kp0 = keypairs[0]
    kp1 = keypairs[1]
    identity0 = load_identity(kp0)
    identity_hash_0 = bytes.fromhex(kp0["identity_hash"])
    dest_hash_0 = make_destination_hash(name_hash, identity_hash_0)
    transport_id_1 = bytes.fromhex(kp1["identity_hash"])
    random_hash = make_random_hash(DETERMINISTIC_RANDOM_PREFIXES[0], FIXED_TIMESTAMP)

    flags = pack_flags(HEADER_2, FLAG_UNSET, TRANSPORT, SINGLE, ANNOUNCE)
    result = make_announce_payload(identity0, name_hash, dest_hash_0, random_hash)

    header = build_header_2(flags, 0, transport_id_1, dest_hash_0, PATH_RESPONSE)
    raw = header + result["payload"]
    _, _, packet_hash = compute_packet_hash(raw)

    vectors.append({
        "description": "Basic path response: keypair 0 announced, keypair 1 as transport relay, no ratchet",
        "source_keypair_index": 0,
        "transport_keypair_index": 1,
        "app_name": app_name,
        "aspects": aspects,
        "destination_hash": dest_hash_0.hex(),
        "transport_id": transport_id_1.hex(),
        "random_hash": random_hash.hex(),
        "flags_byte": f"{flags:02x}",
        "context_flag": FLAG_UNSET,
        "hops": 0,
        "context": f"{PATH_RESPONSE:02x}",
        "signed_data": result["signed_data"].hex(),
        "signature": result["signature"].hex(),
        "announce_payload": result["payload"].hex(),
        "announce_payload_length": len(result["payload"]),
        "header": header.hex(),
        "header_length": len(header),
        "raw_packet": raw.hex(),
        "raw_packet_length": len(raw),
        "packet_hash": packet_hash.hex(),
        "header_type": "HEADER_2",
        "transport_type": "TRANSPORT",
    })

    # Vector 2: Path response with ratchet (context_flag=FLAG_SET)
    from RNS.Cryptography.X25519 import X25519PrivateKey
    ratchet_priv = bytes.fromhex("a0b1c2d3e4f5061728394a5b6c7d8e9f00112233445566778899aabbccddeeff")
    ratchet_pub = X25519PrivateKey.from_private_bytes(ratchet_priv).public_key().public_bytes()

    flags_ratchet = pack_flags(HEADER_2, FLAG_SET, TRANSPORT, SINGLE, ANNOUNCE)
    result_r = make_announce_payload(identity0, name_hash, dest_hash_0, random_hash,
                                     ratchet_pub=ratchet_pub)
    header_r = build_header_2(flags_ratchet, 0, transport_id_1, dest_hash_0, PATH_RESPONSE)
    raw_r = header_r + result_r["payload"]
    _, _, packet_hash_r = compute_packet_hash(raw_r)

    vectors.append({
        "description": "Path response with ratchet: keypair 0, transport keypair 1, context_flag=FLAG_SET",
        "source_keypair_index": 0,
        "transport_keypair_index": 1,
        "destination_hash": dest_hash_0.hex(),
        "transport_id": transport_id_1.hex(),
        "ratchet_public_key": ratchet_pub.hex(),
        "flags_byte": f"{flags_ratchet:02x}",
        "context_flag": FLAG_SET,
        "hops": 0,
        "context": f"{PATH_RESPONSE:02x}",
        "signed_data": result_r["signed_data"].hex(),
        "signature": result_r["signature"].hex(),
        "announce_payload": result_r["payload"].hex(),
        "announce_payload_length": len(result_r["payload"]),
        "header": header_r.hex(),
        "raw_packet": raw_r.hex(),
        "raw_packet_length": len(raw_r),
        "packet_hash": packet_hash_r.hex(),
    })

    # Vector 3: Different hop counts (5 hops)
    flags_h5 = pack_flags(HEADER_2, FLAG_UNSET, TRANSPORT, SINGLE, ANNOUNCE)
    kp2 = keypairs[2]
    identity2 = load_identity(kp2)
    identity_hash_2 = bytes.fromhex(kp2["identity_hash"])
    dest_hash_2 = make_destination_hash(name_hash, identity_hash_2)
    random_hash_2 = make_random_hash(DETERMINISTIC_RANDOM_PREFIXES[2], FIXED_TIMESTAMP)
    transport_id_3 = bytes.fromhex(keypairs[3]["identity_hash"])

    result_h5 = make_announce_payload(identity2, name_hash, dest_hash_2, random_hash_2)
    header_h5 = build_header_2(flags_h5, 5, transport_id_3, dest_hash_2, PATH_RESPONSE)
    raw_h5 = header_h5 + result_h5["payload"]
    _, _, packet_hash_h5 = compute_packet_hash(raw_h5)

    vectors.append({
        "description": "Path response with 5 hops: keypair 2 announced, keypair 3 as transport",
        "source_keypair_index": 2,
        "transport_keypair_index": 3,
        "destination_hash": dest_hash_2.hex(),
        "transport_id": transport_id_3.hex(),
        "random_hash": random_hash_2.hex(),
        "flags_byte": f"{flags_h5:02x}",
        "context_flag": FLAG_UNSET,
        "hops": 5,
        "context": f"{PATH_RESPONSE:02x}",
        "signed_data": result_h5["signed_data"].hex(),
        "signature": result_h5["signature"].hex(),
        "announce_payload": result_h5["payload"].hex(),
        "announce_payload_length": len(result_h5["payload"]),
        "header": header_h5.hex(),
        "raw_packet": raw_h5.hex(),
        "raw_packet_length": len(raw_h5),
        "packet_hash": packet_hash_h5.hex(),
    })

    # Vector 4: Path response with app_data
    app_data = b"Test Node v1.0"
    result_ad = make_announce_payload(identity0, name_hash, dest_hash_0, random_hash,
                                      app_data=app_data)
    flags_ad = pack_flags(HEADER_2, FLAG_UNSET, TRANSPORT, SINGLE, ANNOUNCE)
    header_ad = build_header_2(flags_ad, 2, transport_id_1, dest_hash_0, PATH_RESPONSE)
    raw_ad = header_ad + result_ad["payload"]
    _, _, packet_hash_ad = compute_packet_hash(raw_ad)

    vectors.append({
        "description": "Path response with app_data 'Test Node v1.0', 2 hops",
        "source_keypair_index": 0,
        "transport_keypair_index": 1,
        "destination_hash": dest_hash_0.hex(),
        "transport_id": transport_id_1.hex(),
        "random_hash": random_hash.hex(),
        "app_data": app_data.hex(),
        "app_data_utf8": app_data.decode("utf-8"),
        "flags_byte": f"{flags_ad:02x}",
        "context_flag": FLAG_UNSET,
        "hops": 2,
        "context": f"{PATH_RESPONSE:02x}",
        "signed_data": result_ad["signed_data"].hex(),
        "signature": result_ad["signature"].hex(),
        "announce_payload": result_ad["payload"].hex(),
        "announce_payload_length": len(result_ad["payload"]),
        "header": header_ad.hex(),
        "raw_packet": raw_ad.hex(),
        "raw_packet_length": len(raw_ad),
        "packet_hash": packet_hash_ad.hex(),
    })

    return vectors


def extract_path_table_entries(keypairs):
    """
    Category 5: Path table entry construction.

    path_table[destination_hash] = [timestamp, next_hop, hops, expires, random_blobs, receiving_interface, packet_hash]

    Expiration depends on the receiving interface's mode:
    - Access Point: timestamp + AP_PATH_TIME (86400)
    - Roaming:      timestamp + ROAMING_PATH_TIME (21600)
    - Default:      timestamp + PATHFINDER_E (604800)
    """
    vectors = []

    kp0 = keypairs[0]
    identity0 = load_identity(kp0)
    identity_hash_0 = bytes.fromhex(kp0["identity_hash"])
    name_hash = make_name_hash("rns_unit_tests", "link", "establish")
    dest_hash_0 = make_destination_hash(name_hash, identity_hash_0)
    random_hash_0 = make_random_hash(DETERMINISTIC_RANDOM_PREFIXES[0], FIXED_TIMESTAMP)

    # Compute a packet hash for a basic announce
    flags = pack_flags(HEADER_1, FLAG_UNSET, BROADCAST, SINGLE, ANNOUNCE)
    result = make_announce_payload(identity0, name_hash, dest_hash_0, random_hash_0)
    raw = build_header_1(flags, 0, dest_hash_0, NONE_CONTEXT) + result["payload"]
    _, _, pkt_hash = compute_packet_hash(raw)

    # Random blob is extracted from announce payload at:
    # payload[KEYSIZE//8 + NAME_HASH_LENGTH//8 : KEYSIZE//8 + NAME_HASH_LENGTH//8 + 10]
    # = payload[64+10 : 64+10+10] = payload[74:84] = random_hash
    random_blob = result["payload"][KEYSIZE_BYTES + NAME_HASH_LENGTH_BYTES:
                                    KEYSIZE_BYTES + NAME_HASH_LENGTH_BYTES + RANDOM_HASH_LENGTH]
    assert random_blob == random_hash_0, "Random blob extraction mismatch"

    # The next_hop for a direct (HEADER_1) announce is the destination_hash itself
    # (received_from = packet.destination_hash when no transport_id)
    next_hop = dest_hash_0

    # Vector 1: Default mode (no special interface mode) -> expires = ts + PATHFINDER_E
    timestamp = FIXED_TIMESTAMP
    expires = timestamp + PATHFINDER_E
    entry = [timestamp, next_hop.hex(), 0, expires, [random_blob.hex()], "interface_placeholder", pkt_hash.hex()]
    vectors.append({
        "description": "Default mode path table entry: expires in one week (604800s)",
        "destination_hash": dest_hash_0.hex(),
        "interface_mode": "default",
        "interface_mode_value": None,
        "timestamp": timestamp,
        "next_hop": next_hop.hex(),
        "hops": 0,
        "expires": expires,
        "expires_in_seconds": PATHFINDER_E,
        "random_blobs": [random_blob.hex()],
        "packet_hash": pkt_hash.hex(),
        "entry_indices": {
            "IDX_PT_TIMESTAMP": IDX_PT_TIMESTAMP,
            "IDX_PT_NEXT_HOP": IDX_PT_NEXT_HOP,
            "IDX_PT_HOPS": IDX_PT_HOPS,
            "IDX_PT_EXPIRES": IDX_PT_EXPIRES,
            "IDX_PT_RANDBLOBS": IDX_PT_RANDBLOBS,
            "IDX_PT_RVCD_IF": IDX_PT_RVCD_IF,
            "IDX_PT_PACKET": IDX_PT_PACKET,
        },
    })

    # Vector 2: Access Point mode -> expires = ts + AP_PATH_TIME
    expires_ap = timestamp + AP_PATH_TIME
    vectors.append({
        "description": "Access Point mode path table entry: expires in one day (86400s)",
        "destination_hash": dest_hash_0.hex(),
        "interface_mode": "MODE_ACCESS_POINT",
        "interface_mode_value": MODE_ACCESS_POINT,
        "timestamp": timestamp,
        "next_hop": next_hop.hex(),
        "hops": 0,
        "expires": expires_ap,
        "expires_in_seconds": AP_PATH_TIME,
        "random_blobs": [random_blob.hex()],
        "packet_hash": pkt_hash.hex(),
    })

    # Vector 3: Roaming mode -> expires = ts + ROAMING_PATH_TIME
    expires_roam = timestamp + ROAMING_PATH_TIME
    vectors.append({
        "description": "Roaming mode path table entry: expires in six hours (21600s)",
        "destination_hash": dest_hash_0.hex(),
        "interface_mode": "MODE_ROAMING",
        "interface_mode_value": MODE_ROAMING,
        "timestamp": timestamp,
        "next_hop": next_hop.hex(),
        "hops": 0,
        "expires": expires_roam,
        "expires_in_seconds": ROAMING_PATH_TIME,
        "random_blobs": [random_blob.hex()],
        "packet_hash": pkt_hash.hex(),
    })

    # Vector 4: With growing random_blobs list (multiple announces for same dest)
    random_hash_1 = make_random_hash(DETERMINISTIC_RANDOM_PREFIXES[1], FIXED_TIMESTAMP + 100)
    random_hash_2 = make_random_hash(DETERMINISTIC_RANDOM_PREFIXES[2], FIXED_TIMESTAMP + 200)
    random_hash_3 = make_random_hash(DETERMINISTIC_RANDOM_PREFIXES[3], FIXED_TIMESTAMP + 300)
    blobs = [random_hash_0, random_hash_1, random_hash_2, random_hash_3]
    vectors.append({
        "description": "Path table entry with 4 random_blobs from successive announces",
        "destination_hash": dest_hash_0.hex(),
        "interface_mode": "default",
        "interface_mode_value": None,
        "timestamp": timestamp,
        "next_hop": next_hop.hex(),
        "hops": 0,
        "expires": expires,
        "expires_in_seconds": PATHFINDER_E,
        "random_blobs": [b.hex() for b in blobs],
        "random_blobs_count": len(blobs),
        "max_random_blobs_memory": 64,
        "max_random_blobs_persist": 32,
        "packet_hash": pkt_hash.hex(),
        "note": "random_blobs are kept up to MAX_RANDOM_BLOBS (64) in memory, PERSIST_RANDOM_BLOBS (32) on disk",
    })

    # Vector 5: Different hop counts (via transport relay)
    kp1 = keypairs[1]
    transport_id_1 = bytes.fromhex(kp1["identity_hash"])
    # When received via transport, next_hop = transport_id
    vectors.append({
        "description": "Path table entry with 3 hops, next_hop is transport relay",
        "destination_hash": dest_hash_0.hex(),
        "interface_mode": "default",
        "interface_mode_value": None,
        "timestamp": timestamp,
        "next_hop": transport_id_1.hex(),
        "hops": 3,
        "expires": expires,
        "expires_in_seconds": PATHFINDER_E,
        "random_blobs": [random_blob.hex()],
        "packet_hash": pkt_hash.hex(),
        "note": "When received via HEADER_2 (transport), next_hop = transport_id from packet",
    })

    return vectors


def extract_duplicate_detection():
    """
    Category 6: Tag deduplication via unique_tag.

    unique_tag = destination_hash + tag_bytes
    If unique_tag is already in discovery_pr_tags, the request is ignored.
    """
    vectors = []

    HASH_LEN = TRUNCATED_HASHLENGTH_BYTES

    dest_a = hashlib.sha256(b"dedup_dest_a").digest()[:HASH_LEN]
    dest_b = hashlib.sha256(b"dedup_dest_b").digest()[:HASH_LEN]
    tag_1 = hashlib.sha256(b"dedup_tag_1").digest()[:HASH_LEN]
    tag_2 = hashlib.sha256(b"dedup_tag_2").digest()[:HASH_LEN]
    tag_short = hashlib.sha256(b"dedup_tag_short").digest()[:4]

    # Vector 1: First request -> new, processed
    unique_tag_1 = dest_a + tag_1
    vectors.append({
        "description": "First path request with dest_a + tag_1: new unique_tag, processed",
        "destination_hash": dest_a.hex(),
        "tag_bytes": tag_1.hex(),
        "unique_tag": unique_tag_1.hex(),
        "unique_tag_length": len(unique_tag_1),
        "expected_result": "processed",
        "tags_state_before": [],
        "tags_state_after": [unique_tag_1.hex()],
    })

    # Vector 2: Same dest + same tag -> duplicate, ignored
    vectors.append({
        "description": "Duplicate path request with dest_a + tag_1: unique_tag already seen, ignored",
        "destination_hash": dest_a.hex(),
        "tag_bytes": tag_1.hex(),
        "unique_tag": unique_tag_1.hex(),
        "unique_tag_length": len(unique_tag_1),
        "expected_result": "duplicate",
        "tags_state_before": [unique_tag_1.hex()],
        "tags_state_after": [unique_tag_1.hex()],
    })

    # Vector 3: Same tag, different dest -> new (different unique_tag)
    unique_tag_3 = dest_b + tag_1
    vectors.append({
        "description": "Same tag_1 but different dest_b: new unique_tag, processed",
        "destination_hash": dest_b.hex(),
        "tag_bytes": tag_1.hex(),
        "unique_tag": unique_tag_3.hex(),
        "unique_tag_length": len(unique_tag_3),
        "expected_result": "processed",
        "tags_state_before": [unique_tag_1.hex()],
        "tags_state_after": [unique_tag_1.hex(), unique_tag_3.hex()],
    })

    # Vector 4: Different tag, same dest -> new
    unique_tag_4 = dest_a + tag_2
    vectors.append({
        "description": "Different tag_2 with same dest_a: new unique_tag, processed",
        "destination_hash": dest_a.hex(),
        "tag_bytes": tag_2.hex(),
        "unique_tag": unique_tag_4.hex(),
        "unique_tag_length": len(unique_tag_4),
        "expected_result": "processed",
        "tags_state_before": [unique_tag_1.hex(), unique_tag_3.hex()],
        "tags_state_after": [unique_tag_1.hex(), unique_tag_3.hex(), unique_tag_4.hex()],
    })

    # Vector 5: Short tag (4 bytes) -> 20-byte unique_tag
    unique_tag_5 = dest_a + tag_short
    vectors.append({
        "description": "Short 4-byte tag with dest_a: 20-byte unique_tag, processed",
        "destination_hash": dest_a.hex(),
        "tag_bytes": tag_short.hex(),
        "unique_tag": unique_tag_5.hex(),
        "unique_tag_length": len(unique_tag_5),
        "expected_result": "processed",
        "tags_state_before": [unique_tag_1.hex(), unique_tag_3.hex(), unique_tag_4.hex()],
        "tags_state_after": [unique_tag_1.hex(), unique_tag_3.hex(), unique_tag_4.hex(), unique_tag_5.hex()],
    })

    return vectors


def extract_grace_period():
    """
    Category 7: Timing for retransmit_timeout when answering path requests.

    From Transport.path_request() (Transport.py:2749-2769):
    - From local client:        delay = 0 (immediate)
    - Normal interface:         delay = PATH_REQUEST_GRACE (0.4s)
    - Roaming interface:        delay = PATH_REQUEST_GRACE + PATH_REQUEST_RG (0.4 + 1.5 = 1.9s)
    - Next hop is local client: delay = 0 (immediate)
    """
    vectors = []

    base_time = float(FIXED_TIMESTAMP)

    # Vector 1: From local client -> immediate
    vectors.append({
        "description": "Path request from local client: immediate retransmit (delay = 0)",
        "is_from_local_client": True,
        "interface_mode": None,
        "next_hop_is_local_client": False,
        "retransmit_delay_seconds": 0.0,
        "retransmit_timeout": base_time,
        "base_timestamp": base_time,
        "retries": PATHFINDER_R,
        "block_rebroadcasts": True,
        "algorithm": "retransmit_timeout = now (immediate)",
    })

    # Vector 2: Normal interface -> delay = PATH_REQUEST_GRACE
    vectors.append({
        "description": "Path request on normal interface: delay = PATH_REQUEST_GRACE (0.4s)",
        "is_from_local_client": False,
        "interface_mode": "default",
        "next_hop_is_local_client": False,
        "retransmit_delay_seconds": PATH_REQUEST_GRACE,
        "retransmit_timeout": base_time + PATH_REQUEST_GRACE,
        "base_timestamp": base_time,
        "retries": PATHFINDER_R,
        "block_rebroadcasts": True,
        "algorithm": "retransmit_timeout = now + PATH_REQUEST_GRACE",
    })

    # Vector 3: Roaming interface -> delay = GRACE + RG
    vectors.append({
        "description": "Path request on roaming interface: delay = GRACE + RG (0.4 + 1.5 = 1.9s)",
        "is_from_local_client": False,
        "interface_mode": "MODE_ROAMING",
        "interface_mode_value": MODE_ROAMING,
        "next_hop_is_local_client": False,
        "retransmit_delay_seconds": PATH_REQUEST_GRACE + PATH_REQUEST_RG,
        "retransmit_timeout": base_time + PATH_REQUEST_GRACE + PATH_REQUEST_RG,
        "base_timestamp": base_time,
        "retries": PATHFINDER_R,
        "block_rebroadcasts": True,
        "algorithm": "retransmit_timeout = now + PATH_REQUEST_GRACE + PATH_REQUEST_RG",
    })

    # Vector 4: Next hop is local client -> immediate
    vectors.append({
        "description": "Path request where next hop is on local client interface: immediate retransmit",
        "is_from_local_client": False,
        "interface_mode": "default",
        "next_hop_is_local_client": True,
        "retransmit_delay_seconds": 0.0,
        "retransmit_timeout": base_time,
        "base_timestamp": base_time,
        "retries": PATHFINDER_R,
        "block_rebroadcasts": True,
        "algorithm": "retransmit_timeout = now (next hop is local client)",
    })

    return vectors


# --- Verification ---

def verify(output):
    """Verify all test vectors for internal consistency."""
    import RNS

    print("Verifying...")

    # 1. Verify PLAIN destination hash against RNS library
    pr_dest_vec = output["path_request_destination_vectors"][0]
    rns_dest_hash = RNS.Destination.hash(None, TRANSPORT_APP_NAME, "path", "request")
    assert rns_dest_hash.hex() == pr_dest_vec["destination_hash"], (
        f"PLAIN dest hash mismatch: computed={pr_dest_vec['destination_hash']}, "
        f"rns={rns_dest_hash.hex()}"
    )
    print(f"  [OK] PLAIN destination hash verified against RNS.Destination.hash()")

    # 2. Verify packet hashes
    for vec in output["path_request_packet_vectors"]:
        raw = bytes.fromhex(vec["raw_packet"])
        _, _, packet_hash = compute_packet_hash(raw)
        assert packet_hash.hex() == vec["packet_hash"], (
            f"Packet hash mismatch: {vec['description']}"
        )
    print(f"  [OK] All {len(output['path_request_packet_vectors'])} path request packet hashes verified")

    # 3. Verify parsing logic by re-implementing inline
    HASH_LEN = TRUNCATED_HASHLENGTH_BYTES
    for vec in output["path_request_parsing_vectors"]:
        data = bytes.fromhex(vec["input_data"])

        if len(data) < HASH_LEN:
            assert vec["expected_result"] == "ignored"
            assert vec.get("ignore_reason") == "too_short"
            continue

        destination_hash = data[:HASH_LEN]

        if vec["expected_destination_hash"] is not None:
            assert destination_hash.hex() == vec["expected_destination_hash"]

        if len(data) > HASH_LEN * 2:
            rti = data[HASH_LEN:HASH_LEN * 2]
        else:
            rti = None

        if vec["expected_requesting_transport_instance"] is not None:
            assert rti is not None
            assert rti.hex() == vec["expected_requesting_transport_instance"]
        elif vec["expected_result"] != "ignored" or vec.get("ignore_reason") != "too_short":
            assert rti == (None if vec["expected_requesting_transport_instance"] is None else rti)

        tag_bytes = None
        if len(data) > HASH_LEN * 2:
            tag_bytes = data[HASH_LEN * 2:]
        elif len(data) > HASH_LEN:
            tag_bytes = data[HASH_LEN:]

        if tag_bytes is not None:
            if len(tag_bytes) > HASH_LEN:
                tag_bytes = tag_bytes[:HASH_LEN]
            unique_tag = destination_hash + tag_bytes

            if vec["expected_tag_bytes"] is not None:
                assert tag_bytes.hex() == vec["expected_tag_bytes"]
            if vec["expected_unique_tag"] is not None:
                assert unique_tag.hex() == vec["expected_unique_tag"]
        else:
            assert vec["expected_result"] == "ignored"
            assert vec.get("ignore_reason") == "tagless"

    print(f"  [OK] All {len(output['path_request_parsing_vectors'])} parsing vectors verified")

    # 4. Verify path response announce signatures
    for vec in output["path_response_packet_vectors"]:
        payload = bytes.fromhex(vec["announce_payload"])
        public_key = payload[:KEYSIZE_BYTES]
        name_hash_p = payload[KEYSIZE_BYTES:KEYSIZE_BYTES + NAME_HASH_LENGTH_BYTES]
        random_hash_p = payload[KEYSIZE_BYTES + NAME_HASH_LENGTH_BYTES:
                                KEYSIZE_BYTES + NAME_HASH_LENGTH_BYTES + RANDOM_HASH_LENGTH]

        if vec["context_flag"] == FLAG_SET:
            ratchet_p = payload[KEYSIZE_BYTES + NAME_HASH_LENGTH_BYTES + RANDOM_HASH_LENGTH:
                                KEYSIZE_BYTES + NAME_HASH_LENGTH_BYTES + RANDOM_HASH_LENGTH + RATCHETSIZE_BYTES]
            sig_start = KEYSIZE_BYTES + NAME_HASH_LENGTH_BYTES + RANDOM_HASH_LENGTH + RATCHETSIZE_BYTES
        else:
            ratchet_p = b""
            sig_start = KEYSIZE_BYTES + NAME_HASH_LENGTH_BYTES + RANDOM_HASH_LENGTH

        signature_p = payload[sig_start:sig_start + SIGLENGTH_BYTES]
        app_data_p = payload[sig_start + SIGLENGTH_BYTES:]

        dest_hash_p = bytes.fromhex(vec["destination_hash"])
        signed_data = dest_hash_p + public_key + name_hash_p + random_hash_p + ratchet_p
        if app_data_p:
            signed_data += app_data_p

        verify_identity = RNS.Identity(create_keys=False)
        verify_identity.load_public_key(public_key)
        assert verify_identity.validate(signature_p, signed_data), (
            f"Path response signature failed: {vec['description']}"
        )

        # Verify packet hash
        raw = bytes.fromhex(vec["raw_packet"])
        _, _, pkt_hash = compute_packet_hash(raw)
        assert pkt_hash.hex() == vec["packet_hash"], (
            f"Path response packet hash mismatch: {vec['description']}"
        )

    print(f"  [OK] All {len(output['path_response_packet_vectors'])} path response signatures and packet hashes verified")

    # 5. Verify path table entry timing
    for vec in output["path_table_entry_vectors"]:
        ts = vec["timestamp"]
        exp_in = vec["expires_in_seconds"]
        assert vec["expires"] == ts + exp_in, (
            f"Expiration mismatch: {vec['description']}"
        )
    print(f"  [OK] All {len(output['path_table_entry_vectors'])} path table entry timings verified")

    # 6. Verify duplicate detection logic
    tags_seen = []
    for vec in output["duplicate_detection_vectors"]:
        unique_tag = vec["unique_tag"]
        assert vec["tags_state_before"] == tags_seen, (
            f"Tags state_before mismatch: {vec['description']}"
        )
        if unique_tag in tags_seen:
            assert vec["expected_result"] == "duplicate"
        else:
            assert vec["expected_result"] == "processed"
            tags_seen.append(unique_tag)
        assert vec["tags_state_after"] == tags_seen, (
            f"Tags state_after mismatch: {vec['description']}"
        )
    print(f"  [OK] All {len(output['duplicate_detection_vectors'])} duplicate detection vectors verified")

    # 7. Verify grace period timing
    for vec in output["grace_period_vectors"]:
        expected_timeout = vec["base_timestamp"] + vec["retransmit_delay_seconds"]
        assert abs(vec["retransmit_timeout"] - expected_timeout) < 0.001, (
            f"Grace period timing mismatch: {vec['description']}"
        )
    print(f"  [OK] All {len(output['grace_period_vectors'])} grace period vectors verified")

    # 8. JSON round-trip
    json_str = json.dumps(output, indent=2)
    assert json.loads(json_str) == output, "JSON round-trip failed"
    print("  [OK] JSON round-trip integrity verified")


def verify_library_constants():
    """Verify local constants match the actual RNS library values."""
    import RNS
    from RNS.Interfaces.Interface import Interface

    assert MTU == RNS.Reticulum.MTU
    assert HEADER_MINSIZE == RNS.Reticulum.HEADER_MINSIZE
    assert HEADER_MAXSIZE == RNS.Reticulum.HEADER_MAXSIZE
    assert TRUNCATED_HASHLENGTH_BYTES == RNS.Reticulum.TRUNCATED_HASHLENGTH // 8
    assert KEYSIZE_BYTES == RNS.Identity.KEYSIZE // 8
    assert NAME_HASH_LENGTH_BYTES == RNS.Identity.NAME_HASH_LENGTH // 8
    assert SIGLENGTH_BYTES == RNS.Identity.SIGLENGTH // 8
    assert RATCHETSIZE_BYTES == RNS.Identity.RATCHETSIZE // 8

    assert HEADER_1 == RNS.Packet.HEADER_1
    assert HEADER_2 == RNS.Packet.HEADER_2
    assert DATA == RNS.Packet.DATA
    assert ANNOUNCE == RNS.Packet.ANNOUNCE
    assert PATH_RESPONSE == RNS.Packet.PATH_RESPONSE
    assert NONE_CONTEXT == RNS.Packet.NONE
    assert FLAG_SET == RNS.Packet.FLAG_SET
    assert FLAG_UNSET == RNS.Packet.FLAG_UNSET

    assert BROADCAST == RNS.Transport.BROADCAST
    assert TRANSPORT == RNS.Transport.TRANSPORT
    assert SINGLE == RNS.Destination.SINGLE
    assert PLAIN == RNS.Destination.PLAIN

    assert PATH_REQUEST_TIMEOUT == RNS.Transport.PATH_REQUEST_TIMEOUT
    assert PATH_REQUEST_GRACE == RNS.Transport.PATH_REQUEST_GRACE
    assert PATH_REQUEST_RG == RNS.Transport.PATH_REQUEST_RG
    assert PATH_REQUEST_MI == RNS.Transport.PATH_REQUEST_MI
    assert PATHFINDER_E == RNS.Transport.PATHFINDER_E
    assert AP_PATH_TIME == RNS.Transport.AP_PATH_TIME
    assert ROAMING_PATH_TIME == RNS.Transport.ROAMING_PATH_TIME
    assert PATHFINDER_R == RNS.Transport.PATHFINDER_R

    assert MODE_ACCESS_POINT == Interface.MODE_ACCESS_POINT
    assert MODE_ROAMING == Interface.MODE_ROAMING
    assert MODE_GATEWAY == Interface.MODE_GATEWAY

    print("  [OK] All library constants verified")


def main():
    print("Extracting path request/response test vectors...")

    print("Verifying library constants...")
    verify_library_constants()

    keypairs = load_keypairs()
    print(f"  Loaded {len(keypairs)} keypairs")

    pr_dest = extract_path_request_destination()
    print(f"  Extracted {len(pr_dest)} path request destination vectors")

    pr_packets = extract_path_request_packets(keypairs)
    print(f"  Extracted {len(pr_packets)} path request packet vectors")

    pr_parsing = extract_path_request_parsing(keypairs)
    print(f"  Extracted {len(pr_parsing)} path request parsing vectors")

    pr_responses = extract_path_response_packets(keypairs)
    print(f"  Extracted {len(pr_responses)} path response packet vectors")

    pt_entries = extract_path_table_entries(keypairs)
    print(f"  Extracted {len(pt_entries)} path table entry vectors")

    dedup = extract_duplicate_detection()
    print(f"  Extracted {len(dedup)} duplicate detection vectors")

    grace = extract_grace_period()
    print(f"  Extracted {len(grace)} grace period vectors")

    output = {
        "description": "Reticulum v1.1.3 reference implementation - path request/response test vectors",
        "source": "RNS/Transport.py, RNS/Destination.py, RNS/Packet.py",
        "constants": {
            "mtu_bytes": MTU,
            "header_minsize_bytes": HEADER_MINSIZE,
            "header_maxsize_bytes": HEADER_MAXSIZE,
            "truncated_hash_length_bytes": TRUNCATED_HASHLENGTH_BYTES,
            "keysize_bytes": KEYSIZE_BYTES,
            "name_hash_length_bytes": NAME_HASH_LENGTH_BYTES,
            "signature_length_bytes": SIGLENGTH_BYTES,
            "ratchetsize_bytes": RATCHETSIZE_BYTES,
            "path_request_timeout_seconds": PATH_REQUEST_TIMEOUT,
            "path_request_grace_seconds": PATH_REQUEST_GRACE,
            "path_request_rg_seconds": PATH_REQUEST_RG,
            "path_request_mi_seconds": PATH_REQUEST_MI,
            "pathfinder_e_seconds": PATHFINDER_E,
            "ap_path_time_seconds": AP_PATH_TIME,
            "roaming_path_time_seconds": ROAMING_PATH_TIME,
            "pathfinder_r_retries": PATHFINDER_R,
            "mode_access_point": MODE_ACCESS_POINT,
            "mode_roaming": MODE_ROAMING,
            "mode_gateway": MODE_GATEWAY,
        },
        "algorithm": {
            "plain_destination_hash": "SHA256(SHA256(full_name.encode('utf-8'))[:10])[:16]  — no identity for PLAIN type",
            "path_request_data_no_transport": "target_dest_hash(16) + request_tag(16) = 32 bytes",
            "path_request_data_with_transport": "target_dest_hash(16) + transport_identity_hash(16) + request_tag(16) = 48 bytes",
            "path_request_packet": "HEADER_1 | DATA | BROADCAST | PLAIN | context=NONE, dest=path_request_dest_hash",
            "path_response_packet": "HEADER_2 | ANNOUNCE | TRANSPORT | SINGLE | context=PATH_RESPONSE(0x0B), transport_id=relay_node_hash",
            "unique_tag": "destination_hash(16) + tag_bytes(1-16) — used for deduplication",
            "path_table_entry": "[timestamp, next_hop, hops, expires, random_blobs[], receiving_interface, packet_hash]",
            "expiration": {
                "default": "timestamp + PATHFINDER_E (604800s = 1 week)",
                "access_point": "timestamp + AP_PATH_TIME (86400s = 1 day)",
                "roaming": "timestamp + ROAMING_PATH_TIME (21600s = 6 hours)",
            },
            "retransmit_delay": {
                "from_local_client": "0 (immediate)",
                "normal_interface": "PATH_REQUEST_GRACE (0.4s)",
                "roaming_interface": "PATH_REQUEST_GRACE + PATH_REQUEST_RG (1.9s)",
                "next_hop_local_client": "0 (immediate)",
            },
        },
        "path_request_destination_vectors": pr_dest,
        "path_request_packet_vectors": pr_packets,
        "path_request_parsing_vectors": pr_parsing,
        "path_response_packet_vectors": pr_responses,
        "path_table_entry_vectors": pt_entries,
        "duplicate_detection_vectors": dedup,
        "grace_period_vectors": grace,
    }

    verify(output)

    print(f"Writing {OUTPUT_PATH}...")
    with open(OUTPUT_PATH, "w") as f:
        json.dump(output, f, indent=2)
        f.write("\n")

    print("Done.")


if __name__ == "__main__":
    main()
