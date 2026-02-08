#!/usr/bin/env python3
"""
Extract path expiration and TTL enforcement test vectors from the Reticulum
reference implementation into a JSON file for consumption by alternative
implementations.

Covers:
  - TTL enforcement by interface mode (default, AP, roaming)
  - expire_path() behavior (timestamp zeroing)
  - Timestamp refresh on packet forwarding
  - Announce-based path refresh (equal/better hops)
  - Expired path replacement by higher-hop announce
  - More recent emission override
  - Unresponsive path replacement
  - Re-discovery triggers (pending link closure, proof timeout, throttle)
  - Interface disappearance during culling

All vectors are computed manually (no live Transport objects) to avoid
Transport init. Decision logic matches Transport.py source of truth.

Usage:
    python3 test_vectors/extract_path_expiration.py

Output:
    test_vectors/path_expiration.json
"""

import hashlib
import json
import os
import sys

repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, repo_root)

OUTPUT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "path_expiration.json")
KEYPAIRS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keypairs.json")

# --- Constants (reproduced to avoid Transport init) ---

# Path expiration TTLs
PATHFINDER_E = 60 * 60 * 24 * 7      # 604800 — one week (default path TTL)
AP_PATH_TIME = 60 * 60 * 24          # 86400  — one day (Access Point mode)
ROAMING_PATH_TIME = 60 * 60 * 6      # 21600  — six hours (Roaming mode)
DESTINATION_TIMEOUT = 60 * 60 * 24 * 7  # 604800 — used in culling (same value as PATHFINDER_E)

# Transport timing
PATH_REQUEST_TIMEOUT = 15
PATH_REQUEST_MI = 20

# Transport states
STATE_UNKNOWN = 0x00
STATE_UNRESPONSIVE = 0x01
STATE_RESPONSIVE = 0x02

# Interface modes
MODE_ACCESS_POINT = 0x03
MODE_ROAMING = 0x04
MODE_GATEWAY = 0x06
MODE_BOUNDARY = 0x05

# Path table entry indices
IDX_PT_TIMESTAMP = 0
IDX_PT_NEXT_HOP = 1
IDX_PT_HOPS = 2
IDX_PT_EXPIRES = 3
IDX_PT_RANDBLOBS = 4
IDX_PT_RVCD_IF = 5
IDX_PT_PACKET = 6

# Link table entry indices
IDX_LT_DSTHASH = 0
IDX_LT_RCVD_IF = 1
IDX_LT_NH_IF = 2
IDX_LT_TIMESTAMP = 3
IDX_LT_HOPS = 4
IDX_LT_PROOF_TMO = 8

# Max random blobs
MAX_RANDOM_BLOBS = 64
PERSIST_RANDOM_BLOBS = 32

# Fixed timestamp for deterministic test vectors
FIXED_TIMESTAMP = 1700000000

TRUNCATED_HASHLENGTH_BYTES = 16


# --- Helper Functions ---

def load_keypairs():
    with open(KEYPAIRS_PATH, "r") as f:
        data = json.load(f)
    return data["keypairs"]


def deterministic_hash(label):
    """Generate a deterministic 16-byte hash from a label string."""
    return hashlib.sha256(label.encode("utf-8")).digest()[:TRUNCATED_HASHLENGTH_BYTES]


def deterministic_packet_hash(label):
    """Generate a deterministic 16-byte packet hash from a label string."""
    return hashlib.sha256(("packet_hash_" + label).encode("utf-8")).digest()[:TRUNCATED_HASHLENGTH_BYTES]


def make_random_blob(prefix_bytes, timestamp):
    """Build the 10-byte random_blob: 5 prefix bytes + 5-byte big-endian timestamp."""
    return prefix_bytes[:5] + int(timestamp).to_bytes(5, "big")


def timebase_from_random_blob(random_blob):
    """Extract emission timestamp from random_blob[5:10]."""
    return int.from_bytes(random_blob[5:10], "big")


def timebase_from_random_blobs(random_blobs):
    """Get max emission timestamp from list of random blobs."""
    timebase = 0
    for blob in random_blobs:
        emitted = timebase_from_random_blob(blob)
        if emitted > timebase:
            timebase = emitted
    return timebase


# Deterministic random prefixes
DETERMINISTIC_RANDOM_PREFIXES = [
    bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE]),
    bytes([0x11, 0x22, 0x33, 0x44, 0x55]),
    bytes([0xDE, 0xAD, 0xBE, 0xEF, 0x01]),
    bytes([0xCA, 0xFE, 0xBA, 0xBE, 0x02]),
    bytes([0xF0, 0x0D, 0xBA, 0xD0, 0x03]),
]


def ttl_for_mode(mode):
    """Return TTL seconds for a given interface mode."""
    if mode == MODE_ACCESS_POINT:
        return AP_PATH_TIME
    elif mode == MODE_ROAMING:
        return ROAMING_PATH_TIME
    else:
        return DESTINATION_TIMEOUT


# --- Vector Extraction Functions ---

def extract_ttl_enforcement():
    """
    Category 1: TTL enforcement by interface mode.

    Source: Transport.py:701-721 — culling logic recomputes expiry from
    entry[IDX_PT_TIMESTAMP] + mode-dependent TTL, then checks:
        time.time() > destination_expiry  (strict greater-than)

    For each mode, 3 checkpoints:
      - timestamp + ttl - 1 → valid (not yet expired)
      - timestamp + ttl     → valid (boundary, strict >)
      - timestamp + ttl + 1 → expired
    """
    vectors = []
    timestamp = FIXED_TIMESTAMP
    dest_hash = deterministic_hash("ttl_enforcement_dest")
    next_hop = deterministic_hash("ttl_enforcement_next_hop")
    packet_hash = deterministic_packet_hash("ttl_enforcement")
    random_blob = make_random_blob(DETERMINISTIC_RANDOM_PREFIXES[0], timestamp)

    modes = [
        {
            "name": "default",
            "mode_value": None,
            "ttl": DESTINATION_TIMEOUT,
            "ttl_constant": "DESTINATION_TIMEOUT",
            "description_prefix": "Default mode",
        },
        {
            "name": "MODE_ACCESS_POINT",
            "mode_value": MODE_ACCESS_POINT,
            "ttl": AP_PATH_TIME,
            "ttl_constant": "AP_PATH_TIME",
            "description_prefix": "Access Point mode",
        },
        {
            "name": "MODE_ROAMING",
            "mode_value": MODE_ROAMING,
            "ttl": ROAMING_PATH_TIME,
            "ttl_constant": "ROAMING_PATH_TIME",
            "description_prefix": "Roaming mode",
        },
    ]

    for mode_info in modes:
        ttl = mode_info["ttl"]
        expiry = timestamp + ttl

        checkpoints = [
            {
                "label": "before_expiry",
                "check_time": expiry - 1,
                "expected_valid": True,
                "reason": f"check_time ({expiry - 1}) is not > destination_expiry ({expiry})",
            },
            {
                "label": "at_expiry",
                "check_time": expiry,
                "expected_valid": True,
                "reason": f"check_time ({expiry}) is not > destination_expiry ({expiry}); uses strict greater-than",
            },
            {
                "label": "after_expiry",
                "check_time": expiry + 1,
                "expected_valid": False,
                "reason": f"check_time ({expiry + 1}) > destination_expiry ({expiry}); path is expired",
            },
        ]

        for cp in checkpoints:
            vectors.append({
                "description": f"{mode_info['description_prefix']}: {cp['label']} (TTL={ttl}s, check at T+{cp['check_time'] - timestamp})",
                "interface_mode": mode_info["name"],
                "interface_mode_value": mode_info["mode_value"],
                "ttl_constant": mode_info["ttl_constant"],
                "ttl_seconds": ttl,
                "path_entry": {
                    "timestamp": timestamp,
                    "next_hop": next_hop.hex(),
                    "hops": 2,
                    "expires": expiry,
                    "random_blobs": [random_blob.hex()],
                    "packet_hash": packet_hash.hex(),
                },
                "check_time": cp["check_time"],
                "destination_expiry": expiry,
                "expected_valid": cp["expected_valid"],
                "comparison": f"time.time() > destination_expiry  →  {cp['check_time']} > {expiry}  →  {cp['check_time'] > expiry}",
                "reason": cp["reason"],
            })

    return vectors


def extract_expire_path():
    """
    Category 2: expire_path() behavior.

    Source: Transport.py:2483-2489
        if destination_hash in path_table:
            path_table[destination_hash][IDX_PT_TIMESTAMP] = 0
            tables_last_culled = 0
            return True
        else:
            return False

    Setting timestamp=0 means effective expiry = 0 + mode_ttl, which is
    always in the past (e.g., 604800 < any reasonable now).
    """
    vectors = []
    timestamp = FIXED_TIMESTAMP
    dest_hash = deterministic_hash("expire_path_dest")
    next_hop = deterministic_hash("expire_path_next_hop")
    packet_hash = deterministic_packet_hash("expire_path")
    random_blob = make_random_blob(DETERMINISTIC_RANDOM_PREFIXES[1], timestamp)

    # Vector 1: Existing path → timestamp set to 0, return True
    for mode_name, mode_value, ttl, ttl_name in [
        ("default", None, DESTINATION_TIMEOUT, "DESTINATION_TIMEOUT"),
        ("MODE_ACCESS_POINT", MODE_ACCESS_POINT, AP_PATH_TIME, "AP_PATH_TIME"),
        ("MODE_ROAMING", MODE_ROAMING, ROAMING_PATH_TIME, "ROAMING_PATH_TIME"),
    ]:
        effective_expiry_after = 0 + ttl
        vectors.append({
            "description": f"expire_path() on existing path ({mode_name}): timestamp→0, effective expiry={effective_expiry_after}",
            "destination_hash": dest_hash.hex(),
            "path_exists": True,
            "expected_return": True,
            "interface_mode": mode_name,
            "interface_mode_value": mode_value,
            "before": {
                "timestamp": timestamp,
                "next_hop": next_hop.hex(),
                "hops": 3,
                "expires": timestamp + ttl,
                "random_blobs": [random_blob.hex()],
                "packet_hash": packet_hash.hex(),
            },
            "after": {
                "timestamp": 0,
                "note": "Only IDX_PT_TIMESTAMP is modified; tables_last_culled also set to 0",
            },
            "effective_expiry_after_expire": effective_expiry_after,
            "effective_expiry_formula": f"0 + {ttl_name} = {effective_expiry_after}",
            "now_at_check": timestamp,
            "would_be_culled": timestamp > effective_expiry_after,
            "culling_check": f"{timestamp} > {effective_expiry_after} → {timestamp > effective_expiry_after}",
        })

    # Vector: Non-existent path → return False
    missing_dest = deterministic_hash("expire_path_missing_dest")
    vectors.append({
        "description": "expire_path() on non-existent path: returns False",
        "destination_hash": missing_dest.hex(),
        "path_exists": False,
        "expected_return": False,
        "note": "No modification to path_table or tables_last_culled",
    })

    return vectors


def extract_timestamp_refresh():
    """
    Category 3: Timestamp refresh on packet forwarding.

    Source: Transport.py:990, 1010, 1504
        path_table[destination_hash][IDX_PT_TIMESTAMP] = time.time()

    When a packet is forwarded through a path, the entry's timestamp is
    refreshed, extending the effective expiry.
    """
    vectors = []
    T = FIXED_TIMESTAMP
    dest_hash = deterministic_hash("timestamp_refresh_dest")
    next_hop = deterministic_hash("timestamp_refresh_next_hop")
    packet_hash = deterministic_packet_hash("timestamp_refresh")
    random_blob = make_random_blob(DETERMINISTIC_RANDOM_PREFIXES[2], T)

    for mode_name, mode_value, ttl, ttl_name in [
        ("default", None, DESTINATION_TIMEOUT, "DESTINATION_TIMEOUT"),
        ("MODE_ACCESS_POINT", MODE_ACCESS_POINT, AP_PATH_TIME, "AP_PATH_TIME"),
        ("MODE_ROAMING", MODE_ROAMING, ROAMING_PATH_TIME, "ROAMING_PATH_TIME"),
    ]:
        original_expiry = T + ttl
        # Packet forwarded at T2, halfway through TTL
        T2 = T + ttl // 2
        new_effective_expiry = T2 + ttl

        # Without refresh, check at original_expiry + 1 → expired
        # With refresh, check at original_expiry + 1 → still valid
        check_time = original_expiry + 1

        vectors.append({
            "description": f"Timestamp refresh on packet forward ({mode_name}): extends expiry by TTL from T2",
            "interface_mode": mode_name,
            "interface_mode_value": mode_value,
            "ttl_seconds": ttl,
            "ttl_constant": ttl_name,
            "path_entry_initial": {
                "timestamp": T,
                "next_hop": next_hop.hex(),
                "hops": 3,
                "expires": original_expiry,
                "random_blobs": [random_blob.hex()],
                "packet_hash": packet_hash.hex(),
            },
            "original_expiry": original_expiry,
            "packet_forward_time": T2,
            "path_entry_after_forward": {
                "timestamp": T2,
                "note": "Only IDX_PT_TIMESTAMP is updated; expires field in entry is NOT changed by forwarding",
            },
            "new_effective_expiry": new_effective_expiry,
            "effective_expiry_formula": f"T2 + {ttl_name} = {T2} + {ttl} = {new_effective_expiry}",
            "check_time": check_time,
            "without_refresh_valid": not (check_time > original_expiry),
            "with_refresh_valid": not (check_time > new_effective_expiry),
            "note": "Culling recomputes expiry from entry[TIMESTAMP] + mode_ttl, so refreshed timestamp extends the path lifetime",
        })

    return vectors


def extract_announce_refresh():
    """
    Category 4: Announce-based path refresh — equal/better hops.

    Source: Transport.py:1614-1631
    Decision logic for existing path with equal or fewer hops:
      - packet.hops <= existing_hops
      - Check: random_blob not in random_blobs AND announce_emitted > path_timebase
      - If both true: should_add = True
      - Otherwise: should_add = False
    """
    vectors = []
    T = FIXED_TIMESTAMP
    dest_hash = deterministic_hash("announce_refresh_dest")
    next_hop = deterministic_hash("announce_refresh_next_hop")
    packet_hash = deterministic_packet_hash("announce_refresh")

    # Existing path: 3 hops, created at T, with one random blob at emission T
    existing_blob = make_random_blob(DETERMINISTIC_RANDOM_PREFIXES[0], T)
    existing_hops = 3
    existing_path_timebase = timebase_from_random_blobs([existing_blob])

    # Vector 1: Better hops (new < old), new blob, newer emission → should_add=True
    new_blob_1 = make_random_blob(DETERMINISTIC_RANDOM_PREFIXES[1], T + 100)
    new_emission_1 = timebase_from_random_blob(new_blob_1)
    vectors.append({
        "description": "Better hop count (2 < 3), new blob, newer emission → should_add",
        "existing_entry": {
            "timestamp": T,
            "next_hop": next_hop.hex(),
            "hops": existing_hops,
            "expires": T + PATHFINDER_E,
            "random_blobs": [existing_blob.hex()],
            "packet_hash": packet_hash.hex(),
        },
        "existing_path_timebase": existing_path_timebase,
        "new_announce": {
            "hops": 2,
            "random_blob": new_blob_1.hex(),
            "announce_emitted": new_emission_1,
        },
        "conditions": {
            "hops_comparison": "new (2) <= existing (3) → equal/better path branch",
            "blob_seen": False,
            "emission_newer_than_timebase": new_emission_1 > existing_path_timebase,
        },
        "should_add": True,
    })

    # Vector 2: Equal hops, new blob, newer emission → should_add=True
    new_blob_2 = make_random_blob(DETERMINISTIC_RANDOM_PREFIXES[2], T + 200)
    new_emission_2 = timebase_from_random_blob(new_blob_2)
    vectors.append({
        "description": "Equal hop count (3 == 3), new blob, newer emission → should_add",
        "existing_entry": {
            "timestamp": T,
            "next_hop": next_hop.hex(),
            "hops": existing_hops,
            "expires": T + PATHFINDER_E,
            "random_blobs": [existing_blob.hex()],
            "packet_hash": packet_hash.hex(),
        },
        "existing_path_timebase": existing_path_timebase,
        "new_announce": {
            "hops": 3,
            "random_blob": new_blob_2.hex(),
            "announce_emitted": new_emission_2,
        },
        "conditions": {
            "hops_comparison": "new (3) <= existing (3) → equal/better path branch",
            "blob_seen": False,
            "emission_newer_than_timebase": new_emission_2 > existing_path_timebase,
        },
        "should_add": True,
    })

    # Vector 3: Equal hops, replay (blob already seen) → should_add=False
    vectors.append({
        "description": "Equal hop count (3 == 3), blob already seen (replay) → should_add=False",
        "existing_entry": {
            "timestamp": T,
            "next_hop": next_hop.hex(),
            "hops": existing_hops,
            "expires": T + PATHFINDER_E,
            "random_blobs": [existing_blob.hex()],
            "packet_hash": packet_hash.hex(),
        },
        "existing_path_timebase": existing_path_timebase,
        "new_announce": {
            "hops": 3,
            "random_blob": existing_blob.hex(),
            "announce_emitted": timebase_from_random_blob(existing_blob),
        },
        "conditions": {
            "hops_comparison": "new (3) <= existing (3) → equal/better path branch",
            "blob_seen": True,
            "emission_newer_than_timebase": "N/A (short-circuit: blob seen)",
        },
        "should_add": False,
        "reason": "random_blob already in random_blobs → announce replay blocked",
    })

    # Vector 4: Equal hops, new blob, stale emission (older than timebase) → should_add=False
    stale_blob = make_random_blob(DETERMINISTIC_RANDOM_PREFIXES[3], T - 100)
    stale_emission = timebase_from_random_blob(stale_blob)
    vectors.append({
        "description": "Equal hop count (3 == 3), new blob, stale emission (older than timebase) → should_add=False",
        "existing_entry": {
            "timestamp": T,
            "next_hop": next_hop.hex(),
            "hops": existing_hops,
            "expires": T + PATHFINDER_E,
            "random_blobs": [existing_blob.hex()],
            "packet_hash": packet_hash.hex(),
        },
        "existing_path_timebase": existing_path_timebase,
        "new_announce": {
            "hops": 3,
            "random_blob": stale_blob.hex(),
            "announce_emitted": stale_emission,
        },
        "conditions": {
            "hops_comparison": "new (3) <= existing (3) → equal/better path branch",
            "blob_seen": False,
            "emission_newer_than_timebase": stale_emission > existing_path_timebase,
        },
        "should_add": False,
        "reason": f"announce_emitted ({stale_emission}) not > path_timebase ({existing_path_timebase})",
    })

    # Vector 5: Equal hops, new blob, emission equal to timebase → should_add=False
    equal_blob = make_random_blob(DETERMINISTIC_RANDOM_PREFIXES[4], T)
    equal_emission = timebase_from_random_blob(equal_blob)
    vectors.append({
        "description": "Equal hop count (3 == 3), new blob, emission equal to timebase → should_add=False",
        "existing_entry": {
            "timestamp": T,
            "next_hop": next_hop.hex(),
            "hops": existing_hops,
            "expires": T + PATHFINDER_E,
            "random_blobs": [existing_blob.hex()],
            "packet_hash": packet_hash.hex(),
        },
        "existing_path_timebase": existing_path_timebase,
        "new_announce": {
            "hops": 3,
            "random_blob": equal_blob.hex(),
            "announce_emitted": equal_emission,
        },
        "conditions": {
            "hops_comparison": "new (3) <= existing (3) → equal/better path branch",
            "blob_seen": False,
            "emission_newer_than_timebase": equal_emission > existing_path_timebase,
        },
        "should_add": False,
        "reason": f"announce_emitted ({equal_emission}) not > path_timebase ({existing_path_timebase}); requires strict greater-than",
    })

    return vectors


def extract_expired_path_replacement():
    """
    Category 5: Expired path replacement by higher-hop announce.

    Source: Transport.py:1646-1659
    When packet.hops > existing_hops AND path is expired (now >= path_expires):
      - new blob not seen → should_add=True
      - blob already seen → should_add=False
    """
    vectors = []
    T = FIXED_TIMESTAMP
    dest_hash = deterministic_hash("expired_replacement_dest")
    next_hop = deterministic_hash("expired_replacement_next_hop")
    packet_hash = deterministic_packet_hash("expired_replacement")

    existing_blob = make_random_blob(DETERMINISTIC_RANDOM_PREFIXES[0], T)
    existing_hops = 2
    existing_expires = T + PATHFINDER_E

    # now is after expiry
    now = existing_expires + 100

    # Vector 1: Expired path, higher hops, new blob → should_add=True
    new_blob = make_random_blob(DETERMINISTIC_RANDOM_PREFIXES[1], T + 500)
    vectors.append({
        "description": "Expired path, higher hop announce (5 > 2), new blob → should_add",
        "existing_entry": {
            "timestamp": T,
            "next_hop": next_hop.hex(),
            "hops": existing_hops,
            "expires": existing_expires,
            "random_blobs": [existing_blob.hex()],
            "packet_hash": packet_hash.hex(),
        },
        "now": now,
        "path_expired": now >= existing_expires,
        "new_announce": {
            "hops": 5,
            "random_blob": new_blob.hex(),
        },
        "conditions": {
            "hops_comparison": "new (5) > existing (2) → higher-hop branch",
            "path_expired": True,
            "blob_seen": False,
        },
        "should_add": True,
    })

    # Vector 2: Expired path, higher hops, blob already seen → should_add=False
    vectors.append({
        "description": "Expired path, higher hop announce (5 > 2), blob already seen → should_add=False",
        "existing_entry": {
            "timestamp": T,
            "next_hop": next_hop.hex(),
            "hops": existing_hops,
            "expires": existing_expires,
            "random_blobs": [existing_blob.hex()],
            "packet_hash": packet_hash.hex(),
        },
        "now": now,
        "path_expired": now >= existing_expires,
        "new_announce": {
            "hops": 5,
            "random_blob": existing_blob.hex(),
        },
        "conditions": {
            "hops_comparison": "new (5) > existing (2) → higher-hop branch",
            "path_expired": True,
            "blob_seen": True,
        },
        "should_add": False,
        "reason": "Blob already seen — avoids loops even for expired paths",
    })

    # Vector 3: Expired path at exact boundary (now == expires), new blob → should_add=True
    now_boundary = existing_expires
    new_blob_3 = make_random_blob(DETERMINISTIC_RANDOM_PREFIXES[2], T + 600)
    vectors.append({
        "description": "Expired path at exact boundary (now == expires), higher hops, new blob → should_add",
        "existing_entry": {
            "timestamp": T,
            "next_hop": next_hop.hex(),
            "hops": existing_hops,
            "expires": existing_expires,
            "random_blobs": [existing_blob.hex()],
            "packet_hash": packet_hash.hex(),
        },
        "now": now_boundary,
        "path_expired": now_boundary >= existing_expires,
        "new_announce": {
            "hops": 4,
            "random_blob": new_blob_3.hex(),
        },
        "conditions": {
            "hops_comparison": "new (4) > existing (2) → higher-hop branch",
            "path_expired": True,
            "path_expired_note": "Uses >= comparison: now >= path_expires",
            "blob_seen": False,
        },
        "should_add": True,
    })

    return vectors


def extract_emission_override():
    """
    Category 6: More recent emission override for non-expired higher-hop paths.

    Source: Transport.py:1660-1670
    When hops > existing AND path NOT expired:
      - announce_emitted > path_announce_emitted AND new blob → should_add=True
      - announce_emitted > path_announce_emitted AND blob seen → should_add=False
      - announce_emitted <= path_announce_emitted → should_add=False (falls through)
    """
    vectors = []
    T = FIXED_TIMESTAMP
    dest_hash = deterministic_hash("emission_override_dest")
    next_hop = deterministic_hash("emission_override_next_hop")
    packet_hash = deterministic_packet_hash("emission_override")

    existing_blob = make_random_blob(DETERMINISTIC_RANDOM_PREFIXES[0], T)
    existing_hops = 2
    existing_expires = T + PATHFINDER_E
    path_announce_emitted = timebase_from_random_blob(existing_blob)

    # now is well before expiry
    now = T + 1000

    # Vector 1: More recent emission, new blob → should_add=True
    new_blob_1 = make_random_blob(DETERMINISTIC_RANDOM_PREFIXES[1], T + 500)
    new_emission_1 = timebase_from_random_blob(new_blob_1)
    vectors.append({
        "description": "Non-expired path, higher hops (4 > 2), more recent emission, new blob → should_add",
        "existing_entry": {
            "timestamp": T,
            "next_hop": next_hop.hex(),
            "hops": existing_hops,
            "expires": existing_expires,
            "random_blobs": [existing_blob.hex()],
            "packet_hash": packet_hash.hex(),
        },
        "path_announce_emitted": path_announce_emitted,
        "now": now,
        "path_expired": now >= existing_expires,
        "new_announce": {
            "hops": 4,
            "random_blob": new_blob_1.hex(),
            "announce_emitted": new_emission_1,
        },
        "conditions": {
            "hops_comparison": "new (4) > existing (2) → higher-hop branch",
            "path_expired": False,
            "emission_more_recent": new_emission_1 > path_announce_emitted,
            "blob_seen": False,
        },
        "should_add": True,
    })

    # Vector 2: More recent emission, but blob already seen → should_add=False
    vectors.append({
        "description": "Non-expired path, higher hops (4 > 2), more recent emission, blob seen → should_add=False",
        "existing_entry": {
            "timestamp": T,
            "next_hop": next_hop.hex(),
            "hops": existing_hops,
            "expires": existing_expires,
            "random_blobs": [existing_blob.hex()],
            "packet_hash": packet_hash.hex(),
        },
        "path_announce_emitted": path_announce_emitted,
        "now": now,
        "path_expired": now >= existing_expires,
        "new_announce": {
            "hops": 4,
            "random_blob": existing_blob.hex(),
            "announce_emitted": new_emission_1,
        },
        "conditions": {
            "hops_comparison": "new (4) > existing (2) → higher-hop branch",
            "path_expired": False,
            "emission_more_recent": new_emission_1 > path_announce_emitted,
            "blob_seen": True,
        },
        "should_add": False,
        "reason": "Blob already seen despite more recent emission",
    })

    # Vector 3: Older emission, new blob → should_add=False
    old_blob = make_random_blob(DETERMINISTIC_RANDOM_PREFIXES[2], T - 500)
    old_emission = timebase_from_random_blob(old_blob)
    vectors.append({
        "description": "Non-expired path, higher hops (4 > 2), older emission → should_add=False",
        "existing_entry": {
            "timestamp": T,
            "next_hop": next_hop.hex(),
            "hops": existing_hops,
            "expires": existing_expires,
            "random_blobs": [existing_blob.hex()],
            "packet_hash": packet_hash.hex(),
        },
        "path_announce_emitted": path_announce_emitted,
        "now": now,
        "path_expired": now >= existing_expires,
        "new_announce": {
            "hops": 4,
            "random_blob": old_blob.hex(),
            "announce_emitted": old_emission,
        },
        "conditions": {
            "hops_comparison": "new (4) > existing (2) → higher-hop branch",
            "path_expired": False,
            "emission_more_recent": old_emission > path_announce_emitted,
            "blob_seen": False,
        },
        "should_add": False,
        "reason": f"announce_emitted ({old_emission}) not > path_announce_emitted ({path_announce_emitted})",
    })

    # Vector 4: Equal emission, not unresponsive → should_add=False
    equal_blob = make_random_blob(DETERMINISTIC_RANDOM_PREFIXES[3], T)
    equal_emission = timebase_from_random_blob(equal_blob)
    vectors.append({
        "description": "Non-expired path, higher hops (4 > 2), equal emission, not unresponsive → should_add=False",
        "existing_entry": {
            "timestamp": T,
            "next_hop": next_hop.hex(),
            "hops": existing_hops,
            "expires": existing_expires,
            "random_blobs": [existing_blob.hex()],
            "packet_hash": packet_hash.hex(),
        },
        "path_announce_emitted": path_announce_emitted,
        "now": now,
        "path_expired": now >= existing_expires,
        "new_announce": {
            "hops": 4,
            "random_blob": equal_blob.hex(),
            "announce_emitted": equal_emission,
        },
        "conditions": {
            "hops_comparison": "new (4) > existing (2) → higher-hop branch",
            "path_expired": False,
            "emission_more_recent": equal_emission > path_announce_emitted,
            "emission_equal": equal_emission == path_announce_emitted,
            "path_state": "STATE_RESPONSIVE",
            "path_is_unresponsive": False,
        },
        "should_add": False,
        "reason": "Equal emission, path is not unresponsive → no replacement",
    })

    return vectors


def extract_unresponsive_replacement():
    """
    Category 7: Unresponsive path replacement.

    Source: Transport.py:1676-1681
    When hops > existing, path NOT expired, announce_emitted == path_announce_emitted:
      - path_is_unresponsive() → should_add=True
      - path is responsive or unknown → should_add=False
    """
    vectors = []
    T = FIXED_TIMESTAMP
    dest_hash = deterministic_hash("unresponsive_dest")
    next_hop = deterministic_hash("unresponsive_next_hop")
    packet_hash = deterministic_packet_hash("unresponsive")

    existing_blob = make_random_blob(DETERMINISTIC_RANDOM_PREFIXES[0], T)
    existing_hops = 2
    existing_expires = T + PATHFINDER_E
    path_announce_emitted = timebase_from_random_blob(existing_blob)

    now = T + 1000

    # Same emission timestamp as existing path
    new_blob = make_random_blob(DETERMINISTIC_RANDOM_PREFIXES[1], T)
    new_emission = timebase_from_random_blob(new_blob)
    assert new_emission == path_announce_emitted

    # Vector 1: Unresponsive → should_add=True
    vectors.append({
        "description": "Higher hops (5 > 2), equal emission, path is UNRESPONSIVE → should_add",
        "existing_entry": {
            "timestamp": T,
            "next_hop": next_hop.hex(),
            "hops": existing_hops,
            "expires": existing_expires,
            "random_blobs": [existing_blob.hex()],
            "packet_hash": packet_hash.hex(),
        },
        "path_announce_emitted": path_announce_emitted,
        "now": now,
        "path_expired": now >= existing_expires,
        "new_announce": {
            "hops": 5,
            "random_blob": new_blob.hex(),
            "announce_emitted": new_emission,
        },
        "conditions": {
            "hops_comparison": "new (5) > existing (2) → higher-hop branch",
            "path_expired": False,
            "emission_equal": True,
            "path_state": "STATE_UNRESPONSIVE",
            "path_state_value": STATE_UNRESPONSIVE,
            "path_is_unresponsive": True,
        },
        "should_add": True,
    })

    # Vector 2: Responsive → should_add=False
    vectors.append({
        "description": "Higher hops (5 > 2), equal emission, path is RESPONSIVE → should_add=False",
        "existing_entry": {
            "timestamp": T,
            "next_hop": next_hop.hex(),
            "hops": existing_hops,
            "expires": existing_expires,
            "random_blobs": [existing_blob.hex()],
            "packet_hash": packet_hash.hex(),
        },
        "path_announce_emitted": path_announce_emitted,
        "now": now,
        "path_expired": now >= existing_expires,
        "new_announce": {
            "hops": 5,
            "random_blob": new_blob.hex(),
            "announce_emitted": new_emission,
        },
        "conditions": {
            "hops_comparison": "new (5) > existing (2) → higher-hop branch",
            "path_expired": False,
            "emission_equal": True,
            "path_state": "STATE_RESPONSIVE",
            "path_state_value": STATE_RESPONSIVE,
            "path_is_unresponsive": False,
        },
        "should_add": False,
    })

    # Vector 3: Unknown state → should_add=False
    vectors.append({
        "description": "Higher hops (5 > 2), equal emission, path is UNKNOWN → should_add=False",
        "existing_entry": {
            "timestamp": T,
            "next_hop": next_hop.hex(),
            "hops": existing_hops,
            "expires": existing_expires,
            "random_blobs": [existing_blob.hex()],
            "packet_hash": packet_hash.hex(),
        },
        "path_announce_emitted": path_announce_emitted,
        "now": now,
        "path_expired": now >= existing_expires,
        "new_announce": {
            "hops": 5,
            "random_blob": new_blob.hex(),
            "announce_emitted": new_emission,
        },
        "conditions": {
            "hops_comparison": "new (5) > existing (2) → higher-hop branch",
            "path_expired": False,
            "emission_equal": True,
            "path_state": "STATE_UNKNOWN",
            "path_state_value": STATE_UNKNOWN,
            "path_is_unresponsive": False,
        },
        "should_add": False,
        "note": "path_is_unresponsive() only returns True for STATE_UNRESPONSIVE, not STATE_UNKNOWN",
    })

    return vectors


def extract_rediscovery_triggers():
    """
    Category 8: Re-discovery triggers.

    Various conditions that cause path re-discovery to be initiated.

    Sources:
      - Transport.py:472-493 — pending link CLOSED (non-transport)
      - Transport.py:630-699 — link table proof timeout
      - Transport.py:723-729 — discovery path request timeout
      - PATH_REQUEST_MI throttle (20s minimum interval)
    """
    vectors = []
    T = FIXED_TIMESTAMP
    dest_hash = deterministic_hash("rediscovery_dest")

    # Vector 1: Pending link CLOSED, non-transport, not throttled → expire + rediscover
    vectors.append({
        "description": "Pending link CLOSED (non-transport instance), PATH_REQUEST_MI not throttled → expire_path + request_path",
        "trigger": "pending_link_closed",
        "transport_enabled": False,
        "is_connected_to_shared_instance": False,
        "destination_hash": dest_hash.hex(),
        "last_path_request_time": T - PATH_REQUEST_MI - 1,
        "now": T,
        "time_since_last_request": PATH_REQUEST_MI + 1,
        "path_request_mi_seconds": PATH_REQUEST_MI,
        "throttle_check": f"{T} - {T - PATH_REQUEST_MI - 1} = {PATH_REQUEST_MI + 1} > {PATH_REQUEST_MI} → not throttled",
        "expected_actions": ["expire_path(destination_hash)", "request_path(destination_hash)"],
        "source_lines": "Transport.py:472-493",
    })

    # Vector 2: Pending link CLOSED, non-transport, throttled → expire only, no request
    vectors.append({
        "description": "Pending link CLOSED (non-transport instance), PATH_REQUEST_MI throttled → expire_path only",
        "trigger": "pending_link_closed",
        "transport_enabled": False,
        "is_connected_to_shared_instance": False,
        "destination_hash": dest_hash.hex(),
        "last_path_request_time": T - PATH_REQUEST_MI + 5,
        "now": T,
        "time_since_last_request": PATH_REQUEST_MI - 5,
        "path_request_mi_seconds": PATH_REQUEST_MI,
        "throttle_check": f"{T} - {T - PATH_REQUEST_MI + 5} = {PATH_REQUEST_MI - 5} < {PATH_REQUEST_MI} → throttled",
        "expected_actions": ["expire_path(destination_hash)"],
        "note": "Path is expired but no new request due to throttle",
        "source_lines": "Transport.py:472-493",
    })

    # Vector 3: Pending link CLOSED, non-transport, connected to shared instance → expire only
    vectors.append({
        "description": "Pending link CLOSED (non-transport, shared instance) → expire_path, shared instance handles request",
        "trigger": "pending_link_closed",
        "transport_enabled": False,
        "is_connected_to_shared_instance": True,
        "destination_hash": dest_hash.hex(),
        "last_path_request_time": 0,
        "now": T,
        "expected_actions": ["expire_path(destination_hash)"],
        "note": "Connected to shared instance; the shared instance handles path requests",
        "source_lines": "Transport.py:472-493",
    })

    # Vector 4: Pending link CLOSED, transport enabled → link removed, no expire_path
    vectors.append({
        "description": "Pending link CLOSED (transport instance) → link removed only, no expire_path",
        "trigger": "pending_link_closed",
        "transport_enabled": True,
        "destination_hash": dest_hash.hex(),
        "now": T,
        "expected_actions": ["remove from pending_links"],
        "note": "Transport instances do not expire paths on pending link closure",
        "source_lines": "Transport.py:477",
    })

    # Vector 5: Link table proof timeout, path missing → rediscover
    link_dest_hash = deterministic_hash("rediscovery_link_dest")
    vectors.append({
        "description": "Link table proof timeout, path no longer exists → request_path (no throttle check)",
        "trigger": "link_proof_timeout",
        "destination_hash": link_dest_hash.hex(),
        "path_exists": False,
        "lr_taken_hops": 3,
        "now": T,
        "expected_actions": ["request_path(destination_hash)"],
        "note": "When path is missing, path_request_conditions=True regardless of throttle",
        "source_lines": "Transport.py:644-646",
    })

    # Vector 6: Link table proof timeout, local client (hops=0), not throttled → rediscover
    vectors.append({
        "description": "Link table proof timeout, local client link (hops=0), not throttled → request_path",
        "trigger": "link_proof_timeout",
        "destination_hash": link_dest_hash.hex(),
        "path_exists": True,
        "lr_taken_hops": 0,
        "last_path_request_time": T - PATH_REQUEST_MI - 1,
        "now": T,
        "path_request_throttle": False,
        "expected_actions": ["request_path(destination_hash)"],
        "source_lines": "Transport.py:651-653",
    })

    # Vector 7: Link table proof timeout, destination was 1 hop away → rediscover + mark unresponsive
    vectors.append({
        "description": "Link table proof timeout, destination 1 hop away, transport enabled → request_path + mark_path_unresponsive",
        "trigger": "link_proof_timeout",
        "destination_hash": link_dest_hash.hex(),
        "path_exists": True,
        "hops_to_destination": 1,
        "lr_taken_hops": 2,
        "transport_enabled": True,
        "last_path_request_time": T - PATH_REQUEST_MI - 1,
        "now": T,
        "path_request_throttle": False,
        "expected_actions": ["mark_path_unresponsive(destination_hash)", "request_path(destination_hash)"],
        "note": "Also calls expire_path if not transport_enabled",
        "source_lines": "Transport.py:660-676",
    })

    # Vector 8: Link table proof timeout, throttled → no request
    vectors.append({
        "description": "Link table proof timeout, local client (hops=0), throttled → no request",
        "trigger": "link_proof_timeout",
        "destination_hash": link_dest_hash.hex(),
        "path_exists": True,
        "lr_taken_hops": 0,
        "last_path_request_time": T - 5,
        "now": T,
        "path_request_throttle": True,
        "throttle_check": f"{T} - {T - 5} = 5 < {PATH_REQUEST_MI} → throttled",
        "expected_actions": [],
        "note": "Request suppressed due to PATH_REQUEST_MI throttle",
        "source_lines": "Transport.py:639,651",
    })

    # Vector 9: Discovery path request timeout → entry removed
    vectors.append({
        "description": "Discovery path request timeout after PATH_REQUEST_TIMEOUT → entry removed",
        "trigger": "discovery_path_request_timeout",
        "destination_hash": dest_hash.hex(),
        "discovery_entry": {
            "destination_hash": dest_hash.hex(),
            "timeout": T + PATH_REQUEST_TIMEOUT,
            "requesting_interface": "interface_placeholder",
        },
        "check_time_before_timeout": T + PATH_REQUEST_TIMEOUT - 1,
        "check_before_expired": False,
        "check_time_after_timeout": T + PATH_REQUEST_TIMEOUT + 1,
        "check_after_expired": True,
        "path_request_timeout_seconds": PATH_REQUEST_TIMEOUT,
        "expected_action": "Remove entry from discovery_path_requests",
        "expiry_check": f"time.time() > entry['timeout']  (strict greater-than)",
        "source_lines": "Transport.py:728-729",
    })

    # Vector 10: PATH_REQUEST_MI throttle examples
    vectors.append({
        "description": "PATH_REQUEST_MI throttle: 19s since last → blocked, 20s → allowed, 21s → allowed",
        "trigger": "path_request_throttle",
        "path_request_mi_seconds": PATH_REQUEST_MI,
        "examples": [
            {
                "last_request_time": T - 19,
                "now": T,
                "time_since_last": 19,
                "throttled": True,
                "check": f"{T} - {T - 19} = 19 < {PATH_REQUEST_MI} → throttled",
            },
            {
                "last_request_time": T - 20,
                "now": T,
                "time_since_last": 20,
                "throttled": False,
                "check": f"{T} - {T - 20} = 20 >= {PATH_REQUEST_MI} → not throttled (uses strict <)",
            },
            {
                "last_request_time": T - 21,
                "now": T,
                "time_since_last": 21,
                "throttled": False,
                "check": f"{T} - {T - 21} = 21 >= {PATH_REQUEST_MI} → not throttled",
            },
        ],
        "throttle_comparison": "time.time() - last_path_request < PATH_REQUEST_MI  (strict less-than)",
        "source_lines": "Transport.py:488,639",
    })

    return vectors


def extract_interface_disappearance():
    """
    Category 9: Interface disappearance during culling.

    Source: Transport.py:718-721
        elif not attached_interface in Transport.interfaces:
            stale_paths.append(destination_hash)

    Paths attached to interfaces no longer in Transport.interfaces are
    removed during culling, regardless of TTL.
    """
    vectors = []
    T = FIXED_TIMESTAMP
    dest_hash_1 = deterministic_hash("iface_disappear_dest_1")
    dest_hash_2 = deterministic_hash("iface_disappear_dest_2")
    next_hop = deterministic_hash("iface_disappear_next_hop")
    packet_hash_1 = deterministic_packet_hash("iface_disappear_1")
    packet_hash_2 = deterministic_packet_hash("iface_disappear_2")
    random_blob = make_random_blob(DETERMINISTIC_RANDOM_PREFIXES[0], T)

    # Vector 1: Path with valid TTL but interface gone → removed
    vectors.append({
        "description": "Path has valid TTL but attached interface no longer in Transport.interfaces → removed",
        "destination_hash": dest_hash_1.hex(),
        "path_entry": {
            "timestamp": T,
            "next_hop": next_hop.hex(),
            "hops": 2,
            "expires": T + PATHFINDER_E,
            "random_blobs": [random_blob.hex()],
            "attached_interface": "interface_A",
            "packet_hash": packet_hash_1.hex(),
        },
        "active_interfaces": ["interface_B", "interface_C"],
        "now": T + 100,
        "ttl_expired": False,
        "interface_present": False,
        "expected_removed": True,
        "reason": "Interface not in Transport.interfaces; checked independently of TTL",
        "source_lines": "Transport.py:718-721",
    })

    # Vector 2: Path with valid TTL and interface present → kept
    vectors.append({
        "description": "Path has valid TTL and attached interface still present → kept",
        "destination_hash": dest_hash_2.hex(),
        "path_entry": {
            "timestamp": T,
            "next_hop": next_hop.hex(),
            "hops": 1,
            "expires": T + PATHFINDER_E,
            "random_blobs": [random_blob.hex()],
            "attached_interface": "interface_B",
            "packet_hash": packet_hash_2.hex(),
        },
        "active_interfaces": ["interface_B", "interface_C"],
        "now": T + 100,
        "ttl_expired": False,
        "interface_present": True,
        "expected_removed": False,
    })

    # Vector 3: Path with expired TTL and interface present → removed (by TTL, not interface)
    vectors.append({
        "description": "Path has expired TTL, interface present → removed by TTL check (not interface check)",
        "destination_hash": dest_hash_1.hex(),
        "path_entry": {
            "timestamp": T,
            "next_hop": next_hop.hex(),
            "hops": 2,
            "expires": T + PATHFINDER_E,
            "random_blobs": [random_blob.hex()],
            "attached_interface": "interface_B",
            "packet_hash": packet_hash_1.hex(),
        },
        "active_interfaces": ["interface_B", "interface_C"],
        "now": T + PATHFINDER_E + 1,
        "ttl_expired": True,
        "interface_present": True,
        "expected_removed": True,
        "reason": "TTL expired: now > timestamp + DESTINATION_TIMEOUT",
        "note": "TTL check happens first (line 714); interface check is elif (line 718)",
    })

    # Vector 4: Path with expired TTL and interface gone → removed (by TTL check first)
    vectors.append({
        "description": "Path has expired TTL and interface gone → removed (TTL check evaluated first)",
        "destination_hash": dest_hash_2.hex(),
        "path_entry": {
            "timestamp": T,
            "next_hop": next_hop.hex(),
            "hops": 1,
            "expires": T + AP_PATH_TIME,
            "random_blobs": [random_blob.hex()],
            "attached_interface": "interface_A",
            "packet_hash": packet_hash_2.hex(),
        },
        "interface_mode": "MODE_ACCESS_POINT",
        "interface_mode_value": MODE_ACCESS_POINT,
        "active_interfaces": ["interface_B"],
        "now": T + AP_PATH_TIME + 1,
        "ttl_expired": True,
        "interface_present": False,
        "expected_removed": True,
        "reason": "Both TTL expired and interface missing; TTL check at line 714 fires first since it's if/elif",
    })

    return vectors


# --- Verification ---

def verify(output):
    """Verify all test vectors for internal consistency."""
    print("Verifying...")

    # 1. TTL enforcement vectors
    for vec in output["ttl_enforcement_vectors"]:
        check = vec["check_time"]
        expiry = vec["destination_expiry"]
        expected = vec["expected_valid"]
        # Source: time.time() > destination_expiry (strict >)
        computed_expired = check > expiry
        computed_valid = not computed_expired
        assert computed_valid == expected, (
            f"TTL enforcement mismatch: {vec['description']}: "
            f"check_time={check}, expiry={expiry}, expected_valid={expected}, got={computed_valid}"
        )
    print(f"  [OK] All {len(output['ttl_enforcement_vectors'])} TTL enforcement vectors verified")

    # 2. expire_path vectors
    for vec in output["expire_path_vectors"]:
        if vec["path_exists"]:
            assert vec["expected_return"] == True
            assert vec["after"]["timestamp"] == 0
            ttl = ttl_for_mode(vec.get("interface_mode_value"))
            assert vec["effective_expiry_after_expire"] == 0 + ttl
            # Check that expired path would be culled at current time
            assert vec["now_at_check"] > vec["effective_expiry_after_expire"]
        else:
            assert vec["expected_return"] == False
    print(f"  [OK] All {len(output['expire_path_vectors'])} expire_path vectors verified")

    # 3. Timestamp refresh vectors
    for vec in output["timestamp_refresh_vectors"]:
        T2 = vec["packet_forward_time"]
        ttl = vec["ttl_seconds"]
        orig_exp = vec["original_expiry"]
        new_exp = vec["new_effective_expiry"]
        check = vec["check_time"]

        assert new_exp == T2 + ttl
        assert check == orig_exp + 1
        # Without refresh: check > original expiry
        assert vec["without_refresh_valid"] == (not (check > orig_exp))
        # With refresh: check not > new expiry
        assert vec["with_refresh_valid"] == (not (check > new_exp))
    print(f"  [OK] All {len(output['timestamp_refresh_vectors'])} timestamp refresh vectors verified")

    # 4. Announce refresh vectors
    for vec in output["announce_refresh_vectors"]:
        existing_blobs_hex = vec["existing_entry"]["random_blobs"]
        existing_blobs = [bytes.fromhex(b) for b in existing_blobs_hex]
        new_blob = bytes.fromhex(vec["new_announce"]["random_blob"])
        new_hops = vec["new_announce"]["hops"]
        existing_hops = vec["existing_entry"]["hops"]
        new_emission = vec["new_announce"]["announce_emitted"]
        path_timebase = vec["existing_path_timebase"]

        blob_seen = new_blob in existing_blobs
        assert blob_seen == vec["conditions"]["blob_seen"]
        assert new_hops <= existing_hops

        if not blob_seen and new_emission > path_timebase:
            assert vec["should_add"] == True
        else:
            assert vec["should_add"] == False
    print(f"  [OK] All {len(output['announce_refresh_vectors'])} announce refresh vectors verified")

    # 5. Expired path replacement vectors
    for vec in output["expired_path_replacement_vectors"]:
        existing_blobs = [bytes.fromhex(b) for b in vec["existing_entry"]["random_blobs"]]
        new_blob = bytes.fromhex(vec["new_announce"]["random_blob"])
        now = vec["now"]
        path_expires = vec["existing_entry"]["expires"]
        new_hops = vec["new_announce"]["hops"]
        existing_hops = vec["existing_entry"]["hops"]

        assert new_hops > existing_hops
        assert now >= path_expires

        blob_seen = new_blob in existing_blobs
        assert blob_seen == vec["conditions"]["blob_seen"]

        if not blob_seen:
            assert vec["should_add"] == True
        else:
            assert vec["should_add"] == False
    print(f"  [OK] All {len(output['expired_path_replacement_vectors'])} expired path replacement vectors verified")

    # 6. Emission override vectors
    for vec in output["emission_override_vectors"]:
        existing_blobs = [bytes.fromhex(b) for b in vec["existing_entry"]["random_blobs"]]
        new_blob = bytes.fromhex(vec["new_announce"]["random_blob"])
        now = vec["now"]
        path_expires = vec["existing_entry"]["expires"]
        new_hops = vec["new_announce"]["hops"]
        existing_hops = vec["existing_entry"]["hops"]
        new_emission = vec["new_announce"]["announce_emitted"]
        path_emitted = vec["path_announce_emitted"]

        assert new_hops > existing_hops
        assert not (now >= path_expires)  # path NOT expired

        blob_seen = new_blob in existing_blobs

        if new_emission > path_emitted and not blob_seen:
            assert vec["should_add"] == True
        else:
            assert vec["should_add"] == False
    print(f"  [OK] All {len(output['emission_override_vectors'])} emission override vectors verified")

    # 7. Unresponsive replacement vectors
    for vec in output["unresponsive_replacement_vectors"]:
        new_hops = vec["new_announce"]["hops"]
        existing_hops = vec["existing_entry"]["hops"]
        assert new_hops > existing_hops

        now = vec["now"]
        path_expires = vec["existing_entry"]["expires"]
        assert not (now >= path_expires)

        new_emission = vec["new_announce"]["announce_emitted"]
        path_emitted = vec["path_announce_emitted"]
        assert new_emission == path_emitted

        is_unresponsive = vec["conditions"]["path_is_unresponsive"]
        assert vec["should_add"] == is_unresponsive
    print(f"  [OK] All {len(output['unresponsive_replacement_vectors'])} unresponsive replacement vectors verified")

    # 8. Rediscovery trigger vectors — structural checks
    for vec in output["rediscovery_trigger_vectors"]:
        assert "trigger" in vec
        assert "description" in vec
    print(f"  [OK] All {len(output['rediscovery_trigger_vectors'])} rediscovery trigger vectors verified")

    # 9. Interface disappearance vectors
    for vec in output["interface_disappearance_vectors"]:
        assert "expected_removed" in vec
        iface = vec["path_entry"]["attached_interface"]
        iface_present = iface in vec["active_interfaces"]
        assert iface_present == vec["interface_present"]

        now = vec["now"]
        ts = vec["path_entry"]["timestamp"]
        mode_val = vec.get("interface_mode_value")
        ttl = ttl_for_mode(mode_val)
        ttl_expired = now > (ts + ttl)
        assert ttl_expired == vec["ttl_expired"]

        if ttl_expired or not iface_present:
            assert vec["expected_removed"] == True
        else:
            assert vec["expected_removed"] == False
    print(f"  [OK] All {len(output['interface_disappearance_vectors'])} interface disappearance vectors verified")

    # JSON round-trip
    json_str = json.dumps(output, indent=2)
    assert json.loads(json_str) == output, "JSON round-trip failed"
    print("  [OK] JSON round-trip integrity verified")


def verify_library_constants():
    """Verify local constants match the actual RNS library values."""
    import RNS
    from RNS.Interfaces.Interface import Interface

    assert PATHFINDER_E == RNS.Transport.PATHFINDER_E
    assert AP_PATH_TIME == RNS.Transport.AP_PATH_TIME
    assert ROAMING_PATH_TIME == RNS.Transport.ROAMING_PATH_TIME
    assert DESTINATION_TIMEOUT == RNS.Transport.DESTINATION_TIMEOUT
    assert PATH_REQUEST_TIMEOUT == RNS.Transport.PATH_REQUEST_TIMEOUT
    assert PATH_REQUEST_MI == RNS.Transport.PATH_REQUEST_MI

    assert STATE_UNKNOWN == RNS.Transport.STATE_UNKNOWN
    assert STATE_UNRESPONSIVE == RNS.Transport.STATE_UNRESPONSIVE
    assert STATE_RESPONSIVE == RNS.Transport.STATE_RESPONSIVE

    assert MODE_ACCESS_POINT == Interface.MODE_ACCESS_POINT
    assert MODE_ROAMING == Interface.MODE_ROAMING
    assert MODE_GATEWAY == Interface.MODE_GATEWAY
    assert MODE_BOUNDARY == Interface.MODE_BOUNDARY

    print("  [OK] All library constants verified")


def main():
    print("Extracting path expiration and TTL enforcement test vectors...")

    print("Verifying library constants...")
    verify_library_constants()

    ttl_enforcement = extract_ttl_enforcement()
    print(f"  Extracted {len(ttl_enforcement)} TTL enforcement vectors")

    expire_path = extract_expire_path()
    print(f"  Extracted {len(expire_path)} expire_path vectors")

    timestamp_refresh = extract_timestamp_refresh()
    print(f"  Extracted {len(timestamp_refresh)} timestamp refresh vectors")

    announce_refresh = extract_announce_refresh()
    print(f"  Extracted {len(announce_refresh)} announce refresh vectors")

    expired_replacement = extract_expired_path_replacement()
    print(f"  Extracted {len(expired_replacement)} expired path replacement vectors")

    emission_override = extract_emission_override()
    print(f"  Extracted {len(emission_override)} emission override vectors")

    unresponsive_replacement = extract_unresponsive_replacement()
    print(f"  Extracted {len(unresponsive_replacement)} unresponsive replacement vectors")

    rediscovery_triggers = extract_rediscovery_triggers()
    print(f"  Extracted {len(rediscovery_triggers)} rediscovery trigger vectors")

    interface_disappearance = extract_interface_disappearance()
    print(f"  Extracted {len(interface_disappearance)} interface disappearance vectors")

    output = {
        "description": "Reticulum v1.1.3 - path expiration and TTL enforcement test vectors",
        "source": "RNS/Transport.py",
        "constants": {
            "pathfinder_e_seconds": PATHFINDER_E,
            "ap_path_time_seconds": AP_PATH_TIME,
            "roaming_path_time_seconds": ROAMING_PATH_TIME,
            "destination_timeout_seconds": DESTINATION_TIMEOUT,
            "path_request_timeout_seconds": PATH_REQUEST_TIMEOUT,
            "path_request_mi_seconds": PATH_REQUEST_MI,
            "state_unknown": STATE_UNKNOWN,
            "state_unresponsive": STATE_UNRESPONSIVE,
            "state_responsive": STATE_RESPONSIVE,
            "mode_access_point": MODE_ACCESS_POINT,
            "mode_roaming": MODE_ROAMING,
            "mode_gateway": MODE_GATEWAY,
            "mode_boundary": MODE_BOUNDARY,
            "max_random_blobs": MAX_RANDOM_BLOBS,
            "persist_random_blobs": PERSIST_RANDOM_BLOBS,
        },
        "algorithm": {
            "culling_expiry_check": "time.time() > entry[IDX_PT_TIMESTAMP] + mode_ttl  (strict greater-than)",
            "culling_ttl_by_mode": {
                "MODE_ACCESS_POINT": "entry[TIMESTAMP] + AP_PATH_TIME (86400s)",
                "MODE_ROAMING": "entry[TIMESTAMP] + ROAMING_PATH_TIME (21600s)",
                "default": "entry[TIMESTAMP] + DESTINATION_TIMEOUT (604800s)",
            },
            "expire_path_effect": "entry[IDX_PT_TIMESTAMP] = 0, tables_last_culled = 0; forces next culling cycle to remove the path",
            "timestamp_refresh": "entry[IDX_PT_TIMESTAMP] = time.time() on packet forward (Transport.py:990, 1010, 1504)",
            "announce_refresh_equal_better_hops": {
                "condition": "packet.hops <= existing_hops",
                "accept": "random_blob NOT in random_blobs AND announce_emitted > path_timebase",
                "reject": "blob already seen OR emission not newer than timebase",
            },
            "announce_higher_hops_expired_path": {
                "condition": "packet.hops > existing_hops AND now >= path_expires",
                "accept": "random_blob NOT in random_blobs",
                "reject": "blob already seen",
            },
            "announce_higher_hops_emission_override": {
                "condition": "packet.hops > existing_hops AND now < path_expires AND announce_emitted > path_announce_emitted",
                "accept": "random_blob NOT in random_blobs",
                "reject": "blob already seen",
            },
            "announce_higher_hops_unresponsive": {
                "condition": "packet.hops > existing_hops AND now < path_expires AND announce_emitted == path_announce_emitted",
                "accept": "path_is_unresponsive() returns True (STATE_UNRESPONSIVE)",
                "reject": "path state is RESPONSIVE or UNKNOWN",
            },
            "path_request_throttle": "time.time() - last_path_request < PATH_REQUEST_MI (strict less-than, 20s)",
            "discovery_timeout": "time.time() > entry['timeout'] (strict greater-than, timeout = creation + 15s)",
        },
        "ttl_enforcement_vectors": ttl_enforcement,
        "expire_path_vectors": expire_path,
        "timestamp_refresh_vectors": timestamp_refresh,
        "announce_refresh_vectors": announce_refresh,
        "expired_path_replacement_vectors": expired_replacement,
        "emission_override_vectors": emission_override,
        "unresponsive_replacement_vectors": unresponsive_replacement,
        "rediscovery_trigger_vectors": rediscovery_triggers,
        "interface_disappearance_vectors": interface_disappearance,
    }

    verify(output)

    print(f"Writing {OUTPUT_PATH}...")
    with open(OUTPUT_PATH, "w") as f:
        json.dump(output, f, indent=2)
        f.write("\n")

    print("Done.")


if __name__ == "__main__":
    main()
