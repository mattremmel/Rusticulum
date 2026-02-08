#!/usr/bin/env python3
"""
Extract retry timer and timeout test vectors from the Reticulum reference
implementation into a JSON file for consumption by alternative implementations.

All vectors are computed using formulas reproduced from the reference source.
No live Transport/Link/Resource objects are created.

Covers:
  - Link keepalive timing (RTT -> keepalive interval, stale threshold)
  - Link establishment timeout (hops -> timeout)
  - Resource retry timing (retry progression, part timeout, proof timeout)
  - Resource advertisement retry timing
  - Channel timeout formula (tries x RTT x tx_ring_length matrix)

Usage:
    python3 test_vectors/extract_retry_timers.py

Output:
    test_vectors/retry_timers.json
"""

import json
import math
import os
import sys

repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, repo_root)

OUTPUT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "retry_timers.json")

# --- Link constants (from RNS/Link.py) ---

KEEPALIVE_MAX_RTT        = 1.75
KEEPALIVE_MAX            = 360
KEEPALIVE_MIN            = 5
KEEPALIVE                = KEEPALIVE_MAX  # default before any RTT measured
STALE_FACTOR             = 2
STALE_GRACE              = 5
KEEPALIVE_TIMEOUT_FACTOR = 4
TRAFFIC_TIMEOUT_FACTOR   = 6
TRAFFIC_TIMEOUT_MIN_MS   = 5

# From RNS/Reticulum.py
DEFAULT_PER_HOP_TIMEOUT  = 6

# --- Resource constants (from RNS/Resource.py) ---

RESOURCE_WINDOW              = 4
RESOURCE_WINDOW_MIN          = 2
RESOURCE_WINDOW_MAX_SLOW     = 10
RESOURCE_WINDOW_MAX_VERY_SLOW = 4
RESOURCE_WINDOW_MAX_FAST     = 75
RESOURCE_WINDOW_FLEXIBILITY  = 4

PART_TIMEOUT_FACTOR           = 4
PART_TIMEOUT_FACTOR_AFTER_RTT = 2
PROOF_TIMEOUT_FACTOR          = 3
MAX_RETRIES                   = 16
MAX_ADV_RETRIES               = 4
SENDER_GRACE_TIME             = 10.0
PROCESSING_GRACE              = 1.0
RETRY_GRACE_TIME              = 0.25
PER_RETRY_DELAY               = 0.5
WATCHDOG_MAX_SLEEP            = 1
RESPONSE_MAX_GRACE_TIME       = 10

# SDU (from Resource.py: SDU = RNS.Packet.MDU)
MTU = 500
HEADER_MINSIZE = 19
IFAC_MIN_SIZE = 1
TOKEN_OVERHEAD = 48
AES128_BLOCKSIZE = 16
LINK_MDU = math.floor((MTU - IFAC_MIN_SIZE - HEADER_MINSIZE - TOKEN_OVERHEAD) / AES128_BLOCKSIZE) * AES128_BLOCKSIZE - 1
RESOURCE_SDU = LINK_MDU

# --- Channel constants (from RNS/Channel.py) ---

CHANNEL_MAX_TRIES = 5

# Channel window constants
CHANNEL_WINDOW = 2
CHANNEL_WINDOW_MIN = 2
CHANNEL_WINDOW_MIN_LIMIT_SLOW = 2
CHANNEL_WINDOW_MIN_LIMIT_MEDIUM = 5
CHANNEL_WINDOW_MIN_LIMIT_FAST = 16
CHANNEL_WINDOW_MAX_SLOW = 5
CHANNEL_WINDOW_MAX_MEDIUM = 12
CHANNEL_WINDOW_MAX_FAST = 48


# ============================================================
# Formula implementations
# ============================================================

def link_keepalive(rtt):
    """
    Compute keepalive interval from RTT.
    From RNS/Link.py:848-850.
    """
    keepalive = max(min(rtt * (KEEPALIVE_MAX / KEEPALIVE_MAX_RTT), KEEPALIVE_MAX), KEEPALIVE_MIN)
    stale_time = keepalive * STALE_FACTOR
    return keepalive, stale_time


def link_establishment_timeout(hops):
    """
    Compute link establishment timeout.
    From RNS/Link.py:75 and usage in link establishment.
    ESTABLISHMENT_TIMEOUT_PER_HOP * max(1, hops) + KEEPALIVE
    """
    return DEFAULT_PER_HOP_TIMEOUT * max(1, hops) + KEEPALIVE


def channel_timeout(tries, rtt, tx_ring_length):
    """
    Compute channel packet timeout.
    From RNS/Channel.py:545-547.
    """
    return pow(1.5, tries - 1) * max(rtt * 2.5, 0.025) * (tx_ring_length + 1.5)


def resource_part_timeout_no_rtt_rate(part_timeout_factor, sdu, eifr, extra_wait):
    """
    Compute resource part timeout when no req_resp_rtt_rate data.
    From RNS/Resource.py:602.
    sleep_time = last_activity + part_timeout_factor * ((3*sdu)/eifr) + RETRY_GRACE_TIME + extra_wait - time.time()
    Returns the timeout duration (relative to last_activity).
    """
    return part_timeout_factor * ((3 * sdu) / eifr) + RETRY_GRACE_TIME + extra_wait


def resource_part_timeout_with_rtt_rate(part_timeout_factor, outstanding_parts, sdu, eifr, extra_wait):
    """
    Compute resource part timeout when RTT rate data is available.
    From RNS/Resource.py:600.
    sleep_time = last_activity + part_timeout_factor * expected_tof_remaining + RETRY_GRACE_TIME + extra_wait - time.time()
    """
    expected_tof_remaining = (outstanding_parts * sdu * 8) / eifr
    return part_timeout_factor * expected_tof_remaining + RETRY_GRACE_TIME + extra_wait


def resource_proof_timeout(rtt):
    """
    Compute resource proof timeout.
    From RNS/Resource.py:638-640.
    sleep_time = last_part_sent + (rtt * PROOF_TIMEOUT_FACTOR + SENDER_GRACE_TIME) - time.time()
    """
    return rtt * PROOF_TIMEOUT_FACTOR + SENDER_GRACE_TIME


def resource_sender_max_wait(rtt):
    """
    Compute the maximum wait time for the sender side.
    From RNS/Resource.py:627-628.
    max_extra_wait = sum([(r+1) * PER_RETRY_DELAY for r in range(MAX_RETRIES)])
    max_wait = rtt * TRAFFIC_TIMEOUT_FACTOR * MAX_RETRIES + SENDER_GRACE_TIME + max_extra_wait
    """
    max_extra_wait = sum([(r + 1) * PER_RETRY_DELAY for r in range(MAX_RETRIES)])
    return rtt * TRAFFIC_TIMEOUT_FACTOR * MAX_RETRIES + SENDER_GRACE_TIME + max_extra_wait


# ============================================================
# Vector extraction
# ============================================================

def extract_link_keepalive_vectors():
    """Generate keepalive timing vectors for various RTT values."""
    vectors = []
    rtt_values = [0.001, 0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 1.75, 5.0, 10.0]

    for rtt in rtt_values:
        keepalive, stale_time = link_keepalive(rtt)
        # Timeout after stale: rtt * KEEPALIVE_TIMEOUT_FACTOR + STALE_GRACE
        stale_timeout = rtt * KEEPALIVE_TIMEOUT_FACTOR + STALE_GRACE
        total_timeout = stale_time + stale_timeout

        vectors.append({
            "rtt": rtt,
            "keepalive_interval": keepalive,
            "stale_time": stale_time,
            "stale_timeout": stale_timeout,
            "total_timeout": total_timeout,
            "description": f"RTT={rtt}s -> keepalive={keepalive:.4f}s, stale={stale_time:.4f}s",
        })

    return vectors


def extract_link_establishment_vectors():
    """Generate link establishment timeout vectors for various hop counts."""
    vectors = []

    for hops in range(0, 21):
        timeout = link_establishment_timeout(hops)
        vectors.append({
            "hops": hops,
            "timeout": timeout,
            "description": f"{hops} hops -> {timeout}s timeout",
        })

    return vectors


def extract_resource_retry_vectors():
    """Generate resource retry timing progression vectors."""
    vectors = []

    # Test with several RTT values and EIFR rates
    test_scenarios = [
        {"rtt": 0.1, "eifr_bps": 100000, "description": "Fast link (100 Kbps, 100ms RTT)"},
        {"rtt": 0.5, "eifr_bps": 50000, "description": "Medium link (50 Kbps, 500ms RTT)"},
        {"rtt": 2.0, "eifr_bps": 5000, "description": "Slow link (5 Kbps, 2s RTT)"},
        {"rtt": 5.0, "eifr_bps": 1000, "description": "Very slow link (1 Kbps, 5s RTT)"},
    ]

    for scenario in test_scenarios:
        rtt = scenario["rtt"]
        eifr = scenario["eifr_bps"]
        retries = []

        for retry in range(MAX_RETRIES + 1):
            extra_wait = retry * PER_RETRY_DELAY

            # Before RTT data: use PART_TIMEOUT_FACTOR, no outstanding parts
            timeout_no_rtt = resource_part_timeout_no_rtt_rate(
                PART_TIMEOUT_FACTOR, RESOURCE_SDU, eifr, extra_wait
            )

            # After RTT data: use PART_TIMEOUT_FACTOR_AFTER_RTT with varying outstanding parts
            outstanding = min(RESOURCE_WINDOW_MAX_SLOW, max(1, RESOURCE_WINDOW_MAX_SLOW - retry))
            timeout_with_rtt = resource_part_timeout_with_rtt_rate(
                PART_TIMEOUT_FACTOR_AFTER_RTT, outstanding, RESOURCE_SDU, eifr, extra_wait
            )

            retries.append({
                "retry_number": retry,
                "extra_wait": extra_wait,
                "timeout_before_rtt_data": round(timeout_no_rtt, 6),
                "timeout_after_rtt_data": round(timeout_with_rtt, 6),
                "outstanding_parts_assumed": outstanding,
            })

        # Proof timeout for this RTT
        proof_to = resource_proof_timeout(rtt)

        # Sender max wait
        sender_max = resource_sender_max_wait(rtt)

        vectors.append({
            "description": scenario["description"],
            "rtt": rtt,
            "eifr_bps": eifr,
            "sdu": RESOURCE_SDU,
            "retry_progression": retries,
            "proof_timeout": round(proof_to, 6),
            "sender_max_wait": round(sender_max, 6),
        })

    return vectors


def extract_resource_adv_retry_vectors():
    """Generate resource advertisement retry vectors."""
    vectors = []

    rtt_values = [0.1, 0.5, 1.0, 2.0, 5.0]

    for rtt in rtt_values:
        # Advertisement timeout = rtt * TRAFFIC_TIMEOUT_FACTOR
        adv_timeout = rtt * TRAFFIC_TIMEOUT_FACTOR
        retries = []

        for attempt in range(MAX_ADV_RETRIES + 1):
            retries.append({
                "attempt": attempt,
                "is_initial": attempt == 0,
                "timeout_per_attempt": round(adv_timeout + PROCESSING_GRACE, 6),
                "retries_remaining": MAX_ADV_RETRIES - attempt,
            })

        vectors.append({
            "description": f"Advertisement retry at RTT={rtt}s",
            "rtt": rtt,
            "timeout_per_attempt": round(adv_timeout + PROCESSING_GRACE, 6),
            "max_retries": MAX_ADV_RETRIES,
            "attempts": retries,
        })

    return vectors


def extract_channel_timeout_vectors():
    """Generate channel timeout matrix vectors."""
    vectors = []

    tries_values = [1, 2, 3, 4, 5]
    rtt_values = [0.01, 0.05, 0.1, 0.5, 1.0, 2.0, 5.0]
    tx_ring_values = [1, 2, 3, 4, 5]

    matrix = []
    for tries in tries_values:
        for rtt in rtt_values:
            for tx_ring in tx_ring_values:
                timeout = channel_timeout(tries, rtt, tx_ring)
                matrix.append({
                    "tries": tries,
                    "rtt": rtt,
                    "tx_ring_length": tx_ring,
                    "timeout": round(timeout, 10),
                })

    # Also provide some specific worked examples with explanations
    worked_examples = []
    example_params = [
        (1, 0.1, 1, "First try, 100ms RTT, 1 packet in flight"),
        (3, 0.5, 3, "Third try, 500ms RTT, 3 packets in flight"),
        (5, 2.0, 5, "Max tries, 2s RTT, 5 packets in flight"),
        (1, 0.001, 1, "First try, 1ms RTT (uses min 0.025), 1 packet in flight"),
    ]

    for tries, rtt, tx_ring, desc in example_params:
        timeout = channel_timeout(tries, rtt, tx_ring)
        base_factor = pow(1.5, tries - 1)
        rtt_component = max(rtt * 2.5, 0.025)
        ring_component = tx_ring + 1.5

        worked_examples.append({
            "description": desc,
            "tries": tries,
            "rtt": rtt,
            "tx_ring_length": tx_ring,
            "pow_1_5_tries_minus_1": round(base_factor, 10),
            "max_rtt_times_2_5_or_0_025": round(rtt_component, 10),
            "tx_ring_plus_1_5": ring_component,
            "timeout": round(timeout, 10),
            "formula": f"pow(1.5, {tries}-1) * max({rtt}*2.5, 0.025) * ({tx_ring}+1.5) = {round(base_factor, 6)} * {round(rtt_component, 6)} * {ring_component} = {round(timeout, 6)}",
        })

    return matrix, worked_examples


def build_output(keepalive_vectors, establishment_vectors, resource_retry_vectors,
                 adv_retry_vectors, channel_matrix, channel_examples):
    return {
        "description": "Reticulum v1.1.3 reference implementation - Retry timer and timeout test vectors",
        "sources": [
            "RNS/Link.py (keepalive, establishment timeout)",
            "RNS/Resource.py (part timeout, proof timeout, retry progression)",
            "RNS/Channel.py (channel packet timeout)",
        ],
        "link_keepalive": {
            "description": "Link keepalive interval and stale timeout derived from RTT",
            "constants": {
                "KEEPALIVE_MAX": KEEPALIVE_MAX,
                "KEEPALIVE_MIN": KEEPALIVE_MIN,
                "KEEPALIVE_MAX_RTT": KEEPALIVE_MAX_RTT,
                "KEEPALIVE_DEFAULT": KEEPALIVE,
                "STALE_FACTOR": STALE_FACTOR,
                "STALE_GRACE": STALE_GRACE,
                "KEEPALIVE_TIMEOUT_FACTOR": KEEPALIVE_TIMEOUT_FACTOR,
            },
            "formulas": {
                "keepalive": "max(min(rtt * (KEEPALIVE_MAX / KEEPALIVE_MAX_RTT), KEEPALIVE_MAX), KEEPALIVE_MIN)",
                "stale_time": "keepalive * STALE_FACTOR",
                "stale_timeout": "rtt * KEEPALIVE_TIMEOUT_FACTOR + STALE_GRACE",
                "total_link_timeout": "stale_time + stale_timeout",
            },
            "timeout_sequence": [
                "1. Link sends keepalive every 'keepalive' seconds of inactivity",
                "2. If no traffic for 'stale_time', link is marked STALE, final keepalive sent",
                "3. If no traffic for additional 'stale_timeout' after going stale, link is torn down",
            ],
            "vectors": keepalive_vectors,
        },
        "link_establishment": {
            "description": "Link establishment timeout based on hop count",
            "constants": {
                "DEFAULT_PER_HOP_TIMEOUT": DEFAULT_PER_HOP_TIMEOUT,
                "KEEPALIVE_DEFAULT": KEEPALIVE,
            },
            "formula": "DEFAULT_PER_HOP_TIMEOUT * max(1, hops) + KEEPALIVE",
            "note": "For 0 hops, max(1, 0) = 1, so minimum is DEFAULT_PER_HOP_TIMEOUT + KEEPALIVE",
            "vectors": establishment_vectors,
        },
        "resource_retry": {
            "description": "Resource transfer retry timing and timeout progression",
            "constants": {
                "PART_TIMEOUT_FACTOR": PART_TIMEOUT_FACTOR,
                "PART_TIMEOUT_FACTOR_AFTER_RTT": PART_TIMEOUT_FACTOR_AFTER_RTT,
                "PROOF_TIMEOUT_FACTOR": PROOF_TIMEOUT_FACTOR,
                "MAX_RETRIES": MAX_RETRIES,
                "MAX_ADV_RETRIES": MAX_ADV_RETRIES,
                "SENDER_GRACE_TIME": SENDER_GRACE_TIME,
                "PROCESSING_GRACE": PROCESSING_GRACE,
                "RETRY_GRACE_TIME": RETRY_GRACE_TIME,
                "PER_RETRY_DELAY": PER_RETRY_DELAY,
                "TRAFFIC_TIMEOUT_FACTOR": TRAFFIC_TIMEOUT_FACTOR,
                "SDU": RESOURCE_SDU,
            },
            "formulas": {
                "extra_wait": "retry_number * PER_RETRY_DELAY",
                "part_timeout_before_rtt": "PART_TIMEOUT_FACTOR * ((3 * SDU) / EIFR) + RETRY_GRACE_TIME + extra_wait",
                "part_timeout_after_rtt": "PART_TIMEOUT_FACTOR_AFTER_RTT * ((outstanding_parts * SDU * 8) / EIFR) + RETRY_GRACE_TIME + extra_wait",
                "proof_timeout": "rtt * PROOF_TIMEOUT_FACTOR + SENDER_GRACE_TIME",
                "sender_max_wait": "rtt * TRAFFIC_TIMEOUT_FACTOR * MAX_RETRIES + SENDER_GRACE_TIME + sum((r+1)*PER_RETRY_DELAY for r in range(MAX_RETRIES))",
            },
            "timeout_sequence": [
                "1. Initial part timeout uses PART_TIMEOUT_FACTOR (4x) with estimated flight time",
                "2. After first RTT measurement, switches to PART_TIMEOUT_FACTOR_AFTER_RTT (2x)",
                "3. Each retry adds PER_RETRY_DELAY * retry_number to the timeout",
                "4. On timeout: window and window_max decrease, then request_next() is called",
                "5. After all parts sent, switches to PROOF_TIMEOUT_FACTOR (3x) for proof wait",
                "6. Sender side uses a single max_wait encompassing all possible retries",
            ],
            "vectors": resource_retry_vectors,
        },
        "resource_advertisement_retry": {
            "description": "Resource advertisement retry timing",
            "constants": {
                "MAX_ADV_RETRIES": MAX_ADV_RETRIES,
                "TRAFFIC_TIMEOUT_FACTOR": TRAFFIC_TIMEOUT_FACTOR,
                "PROCESSING_GRACE": PROCESSING_GRACE,
            },
            "formula": "timeout = rtt * TRAFFIC_TIMEOUT_FACTOR + PROCESSING_GRACE",
            "note": "If no part requests received within timeout, advertisement is resent up to MAX_ADV_RETRIES times",
            "vectors": adv_retry_vectors,
        },
        "channel_timeout": {
            "description": "Channel packet timeout formula",
            "constants": {
                "MAX_TRIES": CHANNEL_MAX_TRIES,
            },
            "formula": "pow(1.5, tries-1) * max(rtt*2.5, 0.025) * (tx_ring_length + 1.5)",
            "notes": [
                "tries starts at 1 for the initial send",
                "When rtt*2.5 < 0.025, the minimum 0.025 is used",
                "tx_ring_length is the current number of unacknowledged envelopes",
                "On timeout, tries is incremented and packet is resent",
                "If tries exceeds MAX_TRIES (5), the link is torn down",
            ],
            "worked_examples": channel_examples,
            "full_matrix": channel_matrix,
        },
    }


def verify(output):
    """Verify all computed values."""
    # Verify keepalive vectors
    for vec in output["link_keepalive"]["vectors"]:
        ka, st = link_keepalive(vec["rtt"])
        assert abs(ka - vec["keepalive_interval"]) < 1e-10, f"Keepalive mismatch at RTT={vec['rtt']}"
        assert abs(st - vec["stale_time"]) < 1e-10, f"Stale time mismatch at RTT={vec['rtt']}"
    print(f"  [OK] All {len(output['link_keepalive']['vectors'])} keepalive vectors verified")

    # Verify establishment vectors
    for vec in output["link_establishment"]["vectors"]:
        timeout = link_establishment_timeout(vec["hops"])
        assert timeout == vec["timeout"], f"Establishment timeout mismatch at hops={vec['hops']}"
    print(f"  [OK] All {len(output['link_establishment']['vectors'])} establishment timeout vectors verified")

    # Verify channel timeout matrix
    for entry in output["channel_timeout"]["full_matrix"]:
        computed = channel_timeout(entry["tries"], entry["rtt"], entry["tx_ring_length"])
        assert abs(computed - entry["timeout"]) < 1e-6, f"Channel timeout mismatch: tries={entry['tries']}, rtt={entry['rtt']}, ring={entry['tx_ring_length']}"
    print(f"  [OK] All {len(output['channel_timeout']['full_matrix'])} channel timeout matrix entries verified")

    # Verify resource retry vectors (spot check)
    for scenario in output["resource_retry"]["vectors"]:
        rtt = scenario["rtt"]
        proof_to = resource_proof_timeout(rtt)
        assert abs(proof_to - scenario["proof_timeout"]) < 1e-6, f"Proof timeout mismatch at RTT={rtt}"
        sender_max = resource_sender_max_wait(rtt)
        assert abs(sender_max - scenario["sender_max_wait"]) < 1e-6, f"Sender max wait mismatch at RTT={rtt}"
    print(f"  [OK] All {len(output['resource_retry']['vectors'])} resource retry scenarios verified")

    # JSON round-trip
    json_str = json.dumps(output, indent=2)
    assert json.loads(json_str) == output, "JSON round-trip failed"
    print("  [OK] JSON round-trip integrity verified")


def main():
    print("Extracting retry timer vectors...")

    print("  Extracting link keepalive vectors...")
    keepalive_vectors = extract_link_keepalive_vectors()
    print(f"    {len(keepalive_vectors)} keepalive vectors")

    print("  Extracting link establishment timeout vectors...")
    establishment_vectors = extract_link_establishment_vectors()
    print(f"    {len(establishment_vectors)} establishment vectors")

    print("  Extracting resource retry vectors...")
    resource_retry_vectors = extract_resource_retry_vectors()
    print(f"    {len(resource_retry_vectors)} retry scenarios")

    print("  Extracting resource advertisement retry vectors...")
    adv_retry_vectors = extract_resource_adv_retry_vectors()
    print(f"    {len(adv_retry_vectors)} advertisement retry vectors")

    print("  Extracting channel timeout vectors...")
    channel_matrix, channel_examples = extract_channel_timeout_vectors()
    print(f"    {len(channel_matrix)} matrix entries, {len(channel_examples)} worked examples")

    print("Building output...")
    output = build_output(
        keepalive_vectors, establishment_vectors, resource_retry_vectors,
        adv_retry_vectors, channel_matrix, channel_examples,
    )

    print("Verifying...")
    verify(output)

    print(f"Writing {OUTPUT_PATH}...")
    with open(OUTPUT_PATH, "w") as f:
        json.dump(output, f, indent=2)
        f.write("\n")

    print("Done.")


if __name__ == "__main__":
    main()
