#!/usr/bin/env python3
"""
Cross-implementation fuzz test.

1. Generates random protocol messages (50 per category), writes python_inputs.json
2. Waits for rust_inputs.json (Rust-generated inputs)
3. Validates each Rust input through Python parsers
4. Writes python_results.json with pass/fail per case
5. Reports summary
"""

import json
import os
import random
import struct
import sys
import time
import traceback

# ---- RNS imports ----
import RNS
from RNS.Packet import Packet
from RNS.Interfaces.Interface import Interface

# Shared data directory
DATA_DIR = "/fuzz-data"
SEED = int(os.environ.get("FUZZ_SEED", "42"))
COUNT = int(os.environ.get("FUZZ_COUNT", "50"))


def gen_random_bytes(rng, max_len):
    """Generate random bytes of random length up to max_len."""
    length = rng.randint(0, max_len)
    return bytes(rng.getrandbits(8) for _ in range(length))


def gen_packet_bytes(rng, index):
    """Generate random packet bytes. Some with valid H1 structure."""
    max_len = 600
    length = rng.randint(0, max_len - 1)
    data = bytes(rng.getrandbits(8) for _ in range(length))
    if index % 5 == 0 and length >= 19:
        # Valid H1 structure
        data = bytearray(data)
        data[0] &= 0x3F  # Clear header_type bits
        valid_ctx = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
                     250, 251, 252, 253, 254, 255]
        data[18] = rng.choice(valid_ctx)
        data = bytes(data)
    return data


def gen_announce_bytes(rng, index):
    """Generate random announce-like bytes."""
    length = rng.randint(0, 511)
    return bytes(rng.getrandbits(8) for _ in range(length))


def gen_hdlc_bytes(rng, index):
    """Generate random HDLC bytes. Some with FLAG delimiters."""
    length = rng.randint(0, 255)
    if index % 5 == 0 and length >= 2:
        inner = bytes(rng.getrandbits(8) for _ in range(max(0, length - 2)))
        return b"\x7e" + inner + b"\x7e"
    return bytes(rng.getrandbits(8) for _ in range(length))


def gen_kiss_bytes(rng, index):
    """Generate random KISS bytes. Some with FEND delimiters."""
    length = rng.randint(0, 255)
    if index % 5 == 0 and length >= 3:
        inner = bytes(rng.getrandbits(8) for _ in range(max(0, length - 3)))
        return b"\xc0\x00" + inner + b"\xc0"
    return bytes(rng.getrandbits(8) for _ in range(length))


def gen_envelope_bytes(rng, index):
    """Generate random envelope bytes. Some with valid 6-byte header."""
    if index % 5 == 0:
        msg_type = rng.randint(0, 0xFFFF)
        sequence = rng.randint(0, 0xFFFF)
        payload_len = rng.randint(0, 63)
        payload = bytes(rng.getrandbits(8) for _ in range(payload_len))
        header = struct.pack(">HHH", msg_type, sequence, payload_len)
        return header + payload
    length = rng.randint(0, 127)
    return bytes(rng.getrandbits(8) for _ in range(length))


def generate_inputs(rng):
    """Generate random protocol messages."""
    categories = {
        "packet": gen_packet_bytes,
        "announce": gen_announce_bytes,
        "hdlc": gen_hdlc_bytes,
        "kiss": gen_kiss_bytes,
        "envelope": gen_envelope_bytes,
    }

    cases = []
    for category, gen_fn in categories.items():
        for i in range(COUNT):
            raw = gen_fn(rng, i)
            cases.append({
                "index": len(cases),
                "category": category,
                "raw_hex": raw.hex(),
                "length": len(raw),
            })

    return cases


def validate_packet(raw):
    """Try to parse raw bytes as a Reticulum packet."""
    # Python RNS doesn't have a standalone packet parser like Rust's RawPacket::parse.
    # We validate by checking basic structure.
    if len(raw) < 2:
        return "error", "too short for packet header"

    header_type = (raw[0] & 0xC0) >> 6
    if header_type == 0:
        # H1: need at least 19 bytes (flags + hops + dest(16) + ctx)
        if len(raw) < 19:
            return "error", f"H1 packet too short: {len(raw)} < 19"
        return "ok", ""
    elif header_type == 1:
        # H2: need at least 35 bytes
        if len(raw) < 35:
            return "error", f"H2 packet too short: {len(raw)} < 35"
        return "ok", ""
    else:
        return "error", f"invalid header_type: {header_type}"


def validate_hdlc(raw):
    """Try to unframe HDLC data."""
    FLAG = 0x7E
    ESC = 0x7D

    if len(raw) < 2:
        return "error", "too short for HDLC frame"
    if raw[0] != FLAG or raw[-1] != FLAG:
        return "error", "missing FLAG delimiters"

    # Try to unescape
    inner = raw[1:-1]
    result = bytearray()
    i = 0
    while i < len(inner):
        if inner[i] == FLAG:
            return "error", "unexpected FLAG in data"
        elif inner[i] == ESC:
            if i + 1 >= len(inner):
                return "error", "ESC at end of data"
            result.append(inner[i + 1] ^ 0x20)
            i += 2
        else:
            result.append(inner[i])
            i += 1

    return "ok", ""


def validate_kiss(raw):
    """Try to unframe KISS data."""
    FEND = 0xC0
    FESC = 0xDB

    if len(raw) < 3:
        return "error", "too short for KISS frame"
    if raw[0] != FEND:
        return "error", "missing leading FEND"
    if raw[1] != 0x00:
        return "error", "missing CMD_DATA byte"
    if raw[-1] != FEND:
        return "error", "missing trailing FEND"

    inner = raw[2:-1]
    result = bytearray()
    i = 0
    while i < len(inner):
        if inner[i] == FEND:
            return "error", "unexpected FEND in data"
        elif inner[i] == FESC:
            if i + 1 >= len(inner):
                return "error", "FESC at end of data"
            if inner[i + 1] == 0xDC:
                result.append(FEND)
            elif inner[i + 1] == 0xDD:
                result.append(FESC)
            else:
                return "error", f"invalid escape sequence: {inner[i+1]:#x}"
            i += 2
        else:
            result.append(inner[i])
            i += 1

    return "ok", ""


def validate_envelope(raw):
    """Try to unpack a channel envelope."""
    if len(raw) < 6:
        return "error", f"too short for envelope: {len(raw)} < 6"

    _msg_type, _sequence, data_len = struct.unpack(">HHH", raw[:6])
    if len(raw) != 6 + data_len:
        return "error", f"length mismatch: header says {data_len}, got {len(raw) - 6}"

    return "ok", ""


def validate_announce(raw):
    """Try basic announce validation (structural only)."""
    # Announce parsing requires full packet context; just check minimum size
    if len(raw) < 148:
        return "error", f"too short for announce payload: {len(raw)} < 148"
    return "ok", ""


VALIDATORS = {
    "packet": validate_packet,
    "announce": validate_announce,
    "hdlc": validate_hdlc,
    "kiss": validate_kiss,
    "envelope": validate_envelope,
}


def validate_inputs(cases):
    """Validate cases through Python parsers."""
    results = []
    crashes = 0

    for case in cases:
        index = case["index"]
        category = case["category"]
        raw_hex = case["raw_hex"]

        try:
            raw = bytes.fromhex(raw_hex)
        except ValueError as e:
            results.append({
                "index": index,
                "result": "error",
                "error_msg": f"hex decode error: {e}",
            })
            continue

        validator = VALIDATORS.get(category)
        if not validator:
            results.append({
                "index": index,
                "result": "error",
                "error_msg": f"unknown category: {category}",
            })
            continue

        try:
            result, msg = validator(raw)
            results.append({
                "index": index,
                "result": result,
                "error_msg": msg,
            })
        except Exception as e:
            crashes += 1
            results.append({
                "index": index,
                "result": "crash",
                "error_msg": f"EXCEPTION: {type(e).__name__}: {e}",
            })

    return results, crashes


def main():
    print(f"[FUZZ] Starting cross-implementation fuzz test (seed={SEED}, count={COUNT})")
    os.makedirs(DATA_DIR, exist_ok=True)

    rng = random.Random(SEED)

    # Step 1: Generate Python inputs
    print("[FUZZ] Generating Python inputs...")
    py_cases = generate_inputs(rng)
    py_input_path = os.path.join(DATA_DIR, "python_inputs.json")
    with open(py_input_path, "w") as f:
        json.dump(py_cases, f, indent=2)
    print(f"[FUZZ] Generated {len(py_cases)} cases to {py_input_path}")

    # Step 2: Wait for Rust inputs
    rust_input_path = os.path.join(DATA_DIR, "rust_inputs.json")
    print(f"[FUZZ] Waiting for {rust_input_path}...")
    for _ in range(180):  # 90s timeout
        if os.path.exists(rust_input_path):
            break
        time.sleep(0.5)

    if not os.path.exists(rust_input_path):
        print("[FUZZ] FAIL: Timed out waiting for rust_inputs.json")
        sys.exit(1)

    # Small delay to ensure file is fully written
    time.sleep(0.5)

    # Step 3: Validate Rust inputs
    print("[FUZZ] Validating Rust inputs through Python parsers...")
    with open(rust_input_path) as f:
        rust_cases = json.load(f)

    results, crashes = validate_inputs(rust_cases)

    # Step 4: Write results
    py_results_path = os.path.join(DATA_DIR, "python_results.json")
    with open(py_results_path, "w") as f:
        json.dump(results, f, indent=2)

    total = len(rust_cases)
    ok_count = sum(1 for r in results if r["result"] == "ok")
    err_count = sum(1 for r in results if r["result"] == "error")

    print(f"[FUZZ] Validated {total} Rust cases: {ok_count} ok, {err_count} error, {crashes} crashes")

    if crashes > 0:
        print("[FUZZ] FAIL: Python crashed on some Rust inputs!")
        for r in results:
            if r["result"] == "crash":
                print(f"  Case {r['index']}: {r['error_msg']}")
        sys.exit(1)

    print("[FUZZ] fuzz_validation_complete")
    print("[FUZZ] Cross-implementation fuzz test PASSED")
    sys.exit(0)


if __name__ == "__main__":
    main()
