#!/usr/bin/env python3
"""
Extract Channel/Buffer protocol test vectors from the Reticulum reference
implementation into a JSON file for consumption by alternative implementations.

All vectors are computed manually (no live Channel/Link objects) to avoid
Transport init. Pure computation using struct, bz2, and umsgpack.

Covers:
  - Channel constants (window, sequence, RTT thresholds)
  - Envelope encoding/decoding (6-byte header + data)
  - Message serialization via umsgpack
  - Sequence number management and wraparound
  - StreamDataMessage encoding/decoding (2-byte header + data)
  - Window initialization (RTT-based)
  - Window adaptation (delivery/timeout state machine)
  - Timeout calculation formula
  - Channel MDU computation
  - System message type validation boundaries
  - Full round-trip integration vectors

Usage:
    python3 test_vectors/extract_channels.py

Output:
    test_vectors/channels.json
"""

import bz2
import json
import math
import os
import struct
import sys

repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, repo_root)

OUTPUT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "channels.json")

# --- Channel constants (reproduced from RNS/Channel.py) ---

WINDOW = 2
WINDOW_MIN = 2
WINDOW_MIN_LIMIT_SLOW = 2
WINDOW_MIN_LIMIT_MEDIUM = 5
WINDOW_MIN_LIMIT_FAST = 16
WINDOW_MAX_SLOW = 5
WINDOW_MAX_MEDIUM = 12
WINDOW_MAX_FAST = 48
WINDOW_MAX = WINDOW_MAX_FAST
FAST_RATE_THRESHOLD = 10
RTT_FAST = 0.18
RTT_MEDIUM = 0.75
RTT_SLOW = 1.45
WINDOW_FLEXIBILITY = 4
SEQ_MAX = 0xFFFF
SEQ_MODULUS = SEQ_MAX + 1
MAX_TRIES = 5

# --- Buffer/StreamDataMessage constants (from RNS/Buffer.py) ---

STREAM_ID_MAX = 0x3FFF
STREAM_DATA_OVERHEAD = 2 + 6  # 2 for stream header, 6 for channel envelope

# System message type boundary
SYSTEM_MSG_BOUNDARY = 0xF000
SMT_STREAM_DATA = 0xFF00

# --- Link MDU (from existing test vectors pattern) ---

MTU = 500
HEADER_MINSIZE = 19
IFAC_MIN_SIZE = 1
TOKEN_OVERHEAD = 48
AES128_BLOCKSIZE = 16
LINK_MDU = math.floor((MTU - IFAC_MIN_SIZE - HEADER_MINSIZE - TOKEN_OVERHEAD) / AES128_BLOCKSIZE) * AES128_BLOCKSIZE - 1


# ============================================================
# Helper functions
# ============================================================

def envelope_pack(msgtype, sequence, data):
    """Pack a channel envelope: struct.pack('>HHH', msgtype, seq, len(data)) + data"""
    return struct.pack(">HHH", msgtype, sequence, len(data)) + data


def envelope_unpack(raw):
    """Unpack a channel envelope. Returns (msgtype, sequence, length, data)."""
    msgtype, sequence, length = struct.unpack(">HHH", raw[:6])
    data = raw[6:]
    return msgtype, sequence, length, data


def stream_data_pack(stream_id, data, eof=False, compressed=False):
    """Pack a StreamDataMessage: 2-byte header + data."""
    header_val = (0x3FFF & stream_id) | (0x8000 if eof else 0x0000) | (0x4000 if compressed else 0x0000)
    return struct.pack(">H", header_val) + (data if data else bytes())


def stream_data_unpack(raw):
    """Unpack a StreamDataMessage. Returns (stream_id, eof, compressed, data)."""
    header = struct.unpack(">H", raw[:2])[0]
    eof = (0x8000 & header) > 0
    compressed = (0x4000 & header) > 0
    stream_id = header & 0x3FFF
    data = raw[2:]
    if compressed:
        data = bz2.decompress(data)
    return stream_id, eof, compressed, data


def get_packet_timeout_time(tries, rtt, tx_ring_length):
    """Compute packet timeout: pow(1.5, tries-1) * max(rtt*2.5, 0.025) * (tx_ring_length + 1.5)"""
    return pow(1.5, tries - 1) * max(rtt * 2.5, 0.025) * (tx_ring_length + 1.5)


def sim_emplace(ring, new_seq, next_rx_seq):
    """Reproduce Channel._emplace_envelope() (Channel.py:388-409) purely computationally.

    ring: list of sequence numbers (ordered)
    Returns (success: bool, ring_after: list)
    """
    ring = list(ring)  # copy
    for i, existing_seq in enumerate(ring):
        if new_seq == existing_seq:
            return False, ring  # duplicate
        if new_seq < existing_seq and not (next_rx_seq - new_seq) > (SEQ_MAX // 2):
            ring.insert(i, new_seq)
            return True, ring
    ring.append(new_seq)
    return True, ring


def sim_receive(ring, next_rx_seq, incoming_seq):
    """Reproduce Channel._receive() (Channel.py:421-465) purely computationally.

    ring: list of sequence numbers in the rx_ring
    Returns (accepted, reason, delivered_seqs, ring_after, next_rx_after)
      - accepted: True if envelope was accepted (not old, not duplicate)
      - reason: string describing what happened
      - delivered_seqs: list of sequences delivered contiguously
      - ring_after: ring state after processing
      - next_rx_after: next_rx_sequence after processing
    """
    # Step 1: Old-sequence rejection (lines 427-435)
    if incoming_seq < next_rx_seq:
        window_overflow = (next_rx_seq + WINDOW_MAX) % SEQ_MODULUS
        if window_overflow < next_rx_seq:
            if incoming_seq > window_overflow:
                return False, "old_sequence_rejected", [], list(ring), next_rx_seq
            # else: incoming is in wraparound window, proceed
        else:
            return False, "old_sequence_rejected", [], list(ring), next_rx_seq

    # Step 2: Emplace (duplicate detection) (line 437)
    is_new, ring_after = sim_emplace(ring, incoming_seq, next_rx_seq)
    if not is_new:
        return False, "duplicate_rejected", [], ring_after, next_rx_seq

    # Step 3: Contiguous delivery scan (lines 443-453)
    delivered = []
    for seq in list(ring_after):
        if seq == next_rx_seq:
            delivered.append(seq)
            next_rx_seq = (next_rx_seq + 1) % SEQ_MODULUS
            if next_rx_seq == 0:
                for seq2 in list(ring_after):
                    if seq2 == next_rx_seq:
                        delivered.append(seq2)
                        next_rx_seq = (next_rx_seq + 1) % SEQ_MODULUS

    # Remove delivered from ring
    for d in delivered:
        ring_after.remove(d)

    return True, "accepted", delivered, ring_after, next_rx_seq


def sim_delivery_step(rtt, window, window_max, window_min, fast_rate_rounds, medium_rate_rounds):
    """Reproduce Channel._packet_tx_op() delivery logic (lines 488-527) purely computationally.

    Simulates one successful delivery callback: window growth and rate tracking.
    Returns (window, window_max, window_min, fast_rate_rounds, medium_rate_rounds, upgrade_triggered).
    """
    upgrade_triggered = None

    # Window growth (line 498-499)
    if window < window_max:
        window += 1

    # Rate tracking (lines 504-527)
    if rtt != 0:
        if rtt > RTT_FAST:
            fast_rate_rounds = 0

            if rtt > RTT_MEDIUM:
                medium_rate_rounds = 0
            else:
                medium_rate_rounds += 1
                if window_max < WINDOW_MAX_MEDIUM and medium_rate_rounds == FAST_RATE_THRESHOLD:
                    window_max = WINDOW_MAX_MEDIUM
                    window_min = WINDOW_MIN_LIMIT_MEDIUM
                    upgrade_triggered = "medium"
        else:
            fast_rate_rounds += 1
            if window_max < WINDOW_MAX_FAST and fast_rate_rounds == FAST_RATE_THRESHOLD:
                window_max = WINDOW_MAX_FAST
                window_min = WINDOW_MIN_LIMIT_FAST
                upgrade_triggered = "fast"

    return window, window_max, window_min, fast_rate_rounds, medium_rate_rounds, upgrade_triggered


def sim_timeout_retry_step(tries, rtt, tx_ring_length, window, window_max, window_min,
                           window_flexibility, max_tries=MAX_TRIES):
    """Reproduce Channel._packet_timeout() retry logic (lines 549-576) purely computationally.

    Simulates one timeout callback.
    Returns (outcome, tries_after, timeout, window, window_max).
      outcome: "fail" if tries >= max_tries, else "retry"
    """
    if tries >= max_tries:
        return "fail", tries, None, window, window_max

    tries += 1
    timeout = get_packet_timeout_time(tries, rtt, tx_ring_length)

    if window > window_min:
        window -= 1
        if window_max > (window_min + window_flexibility):
            window_max -= 1

    return "retry", tries, timeout, window, window_max


# ============================================================
# Extraction functions
# ============================================================

def extract_constants():
    """Extract all Channel and Buffer constants."""
    return {
        "channel": {
            "WINDOW": WINDOW,
            "WINDOW_MIN": WINDOW_MIN,
            "WINDOW_MIN_LIMIT_SLOW": WINDOW_MIN_LIMIT_SLOW,
            "WINDOW_MIN_LIMIT_MEDIUM": WINDOW_MIN_LIMIT_MEDIUM,
            "WINDOW_MIN_LIMIT_FAST": WINDOW_MIN_LIMIT_FAST,
            "WINDOW_MAX_SLOW": WINDOW_MAX_SLOW,
            "WINDOW_MAX_MEDIUM": WINDOW_MAX_MEDIUM,
            "WINDOW_MAX_FAST": WINDOW_MAX_FAST,
            "WINDOW_MAX": WINDOW_MAX,
            "FAST_RATE_THRESHOLD": FAST_RATE_THRESHOLD,
            "WINDOW_FLEXIBILITY": WINDOW_FLEXIBILITY,
            "SEQ_MAX": SEQ_MAX,
            "SEQ_MODULUS": SEQ_MODULUS,
        },
        "rtt_thresholds": {
            "RTT_FAST": RTT_FAST,
            "RTT_MEDIUM": RTT_MEDIUM,
            "RTT_SLOW": RTT_SLOW,
            "note": "RTT <= RTT_FAST → fast link; RTT_FAST < RTT <= RTT_MEDIUM → medium; RTT_MEDIUM < RTT <= RTT_SLOW → slow; RTT > RTT_SLOW → very slow",
        },
        "buffer": {
            "STREAM_ID_MAX": STREAM_ID_MAX,
            "STREAM_DATA_OVERHEAD": STREAM_DATA_OVERHEAD,
            "STREAM_DATA_OVERHEAD_note": "2 bytes stream header + 6 bytes channel envelope",
            "SMT_STREAM_DATA": SMT_STREAM_DATA,
        },
        "system_message_boundary": {
            "boundary": SYSTEM_MSG_BOUNDARY,
            "boundary_hex": f"0x{SYSTEM_MSG_BOUNDARY:04x}",
            "note": "MSGTYPE >= 0xf000 are system-reserved; user types must be < 0xf000",
        },
        "envelope_format": {
            "header_size": 6,
            "layout": "struct.pack('>HHH', msgtype, sequence, data_length) + data",
            "field_sizes": {"msgtype": 2, "sequence": 2, "data_length": 2},
        },
    }


def extract_envelope_vectors():
    """Generate envelope encoding/decoding test vectors."""
    vectors = []

    # Case 0: Small message
    data_0 = bytes(range(10))
    raw_0 = envelope_pack(0x1234, 0, data_0)
    mt, seq, length, dec_data = envelope_unpack(raw_0)
    vectors.append({
        "index": 0,
        "description": "Small message (10 bytes data, msgtype=0x1234, seq=0)",
        "msgtype": 0x1234,
        "sequence": 0,
        "data_hex": data_0.hex(),
        "data_length": len(data_0),
        "packed_hex": raw_0.hex(),
        "packed_length": len(raw_0),
        "header_hex": raw_0[:6].hex(),
        "decoded_msgtype": mt,
        "decoded_sequence": seq,
        "decoded_length": length,
        "decoded_data_hex": dec_data.hex(),
    })

    # Case 1: Max-size message (fill close to LINK_MDU)
    # Channel MDU for a 500-byte outlet.mdu = 500 - 6 = 494
    # But envelope data can be up to 0xFFFF; let's use a 456-byte payload
    data_1 = bytes([i % 256 for i in range(456)])
    raw_1 = envelope_pack(0xABCD, 100, data_1)
    mt, seq, length, dec_data = envelope_unpack(raw_1)
    vectors.append({
        "index": 1,
        "description": "Large message (456 bytes data, msgtype=0xabcd, seq=100)",
        "msgtype": 0xABCD,
        "sequence": 100,
        "data_hex": data_1.hex(),
        "data_length": len(data_1),
        "packed_hex": raw_1.hex(),
        "packed_length": len(raw_1),
        "header_hex": raw_1[:6].hex(),
        "decoded_msgtype": mt,
        "decoded_sequence": seq,
        "decoded_length": length,
        "decoded_data_hex": dec_data.hex(),
    })

    # Case 2: Empty message
    data_2 = b""
    raw_2 = envelope_pack(0x5678, 65535, data_2)
    mt, seq, length, dec_data = envelope_unpack(raw_2)
    vectors.append({
        "index": 2,
        "description": "Empty message (0 bytes data, msgtype=0x5678, seq=65535)",
        "msgtype": 0x5678,
        "sequence": 65535,
        "data_hex": data_2.hex(),
        "data_length": len(data_2),
        "packed_hex": raw_2.hex(),
        "packed_length": len(raw_2),
        "header_hex": raw_2[:6].hex(),
        "decoded_msgtype": mt,
        "decoded_sequence": seq,
        "decoded_length": length,
        "decoded_data_hex": dec_data.hex(),
    })

    # Case 3: System message type (SMT_STREAM_DATA)
    data_3 = bytes(range(20))
    raw_3 = envelope_pack(0xFF00, 5, data_3)
    mt, seq, length, dec_data = envelope_unpack(raw_3)
    vectors.append({
        "index": 3,
        "description": "System message type (SMT_STREAM_DATA=0xff00, seq=5, 20 bytes data)",
        "msgtype": 0xFF00,
        "sequence": 5,
        "data_hex": data_3.hex(),
        "data_length": len(data_3),
        "packed_hex": raw_3.hex(),
        "packed_length": len(raw_3),
        "header_hex": raw_3[:6].hex(),
        "decoded_msgtype": mt,
        "decoded_sequence": seq,
        "decoded_length": length,
        "decoded_data_hex": dec_data.hex(),
    })

    return vectors


def extract_message_serialization_vectors():
    """Generate message serialization vectors using umsgpack."""
    from RNS.vendor import umsgpack

    vectors = []

    # Case 0: Simple tuple (matches MessageTest pattern)
    id_0 = "test-id-001"
    data_0 = "hello world"
    packed_0 = umsgpack.packb((id_0, data_0))
    unpacked_0 = umsgpack.unpackb(packed_0)
    vectors.append({
        "index": 0,
        "description": "Simple string tuple (id, data) — matches MessageTest pattern",
        "input_tuple": [id_0, data_0],
        "packed_hex": packed_0.hex(),
        "packed_length": len(packed_0),
        "unpacked": list(unpacked_0),
        "note": "umsgpack.packb((id, data)) → bytes; unpackb reverses",
    })

    # Case 1: Empty strings
    packed_1 = umsgpack.packb(("", ""))
    unpacked_1 = umsgpack.unpackb(packed_1)
    vectors.append({
        "index": 1,
        "description": "Empty strings tuple",
        "input_tuple": ["", ""],
        "packed_hex": packed_1.hex(),
        "packed_length": len(packed_1),
        "unpacked": list(unpacked_1),
    })

    # Case 2: Binary data
    binary_data = bytes(range(32))
    packed_2 = umsgpack.packb(("bin-id", binary_data))
    unpacked_2 = umsgpack.unpackb(packed_2)
    vectors.append({
        "index": 2,
        "description": "Tuple with binary data field",
        "input_tuple": ["bin-id", binary_data.hex()],
        "input_note": "Second element is raw bytes (shown as hex); msgpack encodes as bin type",
        "packed_hex": packed_2.hex(),
        "packed_length": len(packed_2),
        "unpacked_id": unpacked_2[0],
        "unpacked_data_hex": unpacked_2[1].hex(),
    })

    # Case 3: Large data (400 bytes — near channel MDU)
    large_data = bytes([i % 256 for i in range(400)])
    packed_3 = umsgpack.packb(("large-msg", large_data))
    unpacked_3 = umsgpack.unpackb(packed_3)
    vectors.append({
        "index": 3,
        "description": "Tuple with large binary data (400 bytes — near channel MDU)",
        "input_tuple": ["large-msg", large_data.hex()],
        "input_note": "Second element is 400 raw bytes (shown as hex)",
        "packed_hex": packed_3.hex(),
        "packed_length": len(packed_3),
        "unpacked_id": unpacked_3[0],
        "unpacked_data_hex": unpacked_3[1].hex(),
        "unpacked_data_length": len(unpacked_3[1]),
    })

    return vectors


def extract_sequence_number_vectors():
    """Generate sequence number management vectors."""
    vectors = []

    # Normal increment
    vectors.append({
        "index": 0,
        "description": "Normal sequence increment",
        "current_seq": 0,
        "next_seq": (0 + 1) % SEQ_MODULUS,
        "formula": "(current + 1) % SEQ_MODULUS",
    })

    vectors.append({
        "index": 1,
        "description": "Mid-range sequence increment",
        "current_seq": 32767,
        "next_seq": (32767 + 1) % SEQ_MODULUS,
        "formula": "(current + 1) % SEQ_MODULUS",
    })

    # Wraparound
    vectors.append({
        "index": 2,
        "description": "Sequence wraparound at SEQ_MAX",
        "current_seq": SEQ_MAX,
        "next_seq": (SEQ_MAX + 1) % SEQ_MODULUS,
        "formula": "(65535 + 1) % 65536 = 0",
    })

    # RX window validation vectors
    # The receive window check from Channel._receive():
    #   if envelope.sequence < self._next_rx_sequence:
    #       window_overflow = (self._next_rx_sequence + Channel.WINDOW_MAX) % Channel.SEQ_MODULUS
    #       if window_overflow < self._next_rx_sequence:
    #           if envelope.sequence > window_overflow:
    #               → reject (invalid)
    #       else:
    #           → reject (invalid)

    # Case 3: Valid future sequence (accepted)
    next_rx = 10
    incoming = 10  # exact match
    vectors.append({
        "index": 3,
        "description": "RX validation: exact match (accepted)",
        "type": "rx_validation",
        "next_rx_sequence": next_rx,
        "incoming_sequence": incoming,
        "accepted": True,
        "reason": "incoming >= next_rx_sequence, so old-sequence check is skipped",
    })

    # Case 4: Valid future sequence (accepted, ahead by 5)
    next_rx = 10
    incoming = 15
    vectors.append({
        "index": 4,
        "description": "RX validation: future sequence within window (accepted)",
        "type": "rx_validation",
        "next_rx_sequence": next_rx,
        "incoming_sequence": incoming,
        "accepted": True,
        "reason": "incoming (15) >= next_rx_sequence (10), not old",
    })

    # Case 5: Old sequence (rejected, no wraparound)
    next_rx = 100
    incoming = 50
    window_overflow = (next_rx + WINDOW_MAX) % SEQ_MODULUS  # (100 + 48) % 65536 = 148
    # window_overflow (148) >= next_rx (100), so the else branch rejects
    vectors.append({
        "index": 5,
        "description": "RX validation: old sequence, no wraparound (rejected)",
        "type": "rx_validation",
        "next_rx_sequence": next_rx,
        "incoming_sequence": incoming,
        "window_max": WINDOW_MAX,
        "window_overflow": window_overflow,
        "accepted": False,
        "reason": f"incoming ({incoming}) < next_rx ({next_rx}); window_overflow ({window_overflow}) >= next_rx ({next_rx}) → reject",
    })

    # Case 6: Wraparound edge — next_rx near max, incoming wrapped to 0+
    # next_rx_seq = 65530, WINDOW_MAX=48
    # window_overflow = (65530 + 48) % 65536 = 42
    # window_overflow (42) < next_rx (65530) → check if envelope.sequence > window_overflow
    # incoming = 10 → 10 <= 42 → NOT rejected (accepted — it's in the wraparound window)
    next_rx = 65530
    incoming = 10
    window_overflow = (next_rx + WINDOW_MAX) % SEQ_MODULUS  # 42
    vectors.append({
        "index": 6,
        "description": "RX validation: wraparound, incoming in valid window (accepted)",
        "type": "rx_validation",
        "next_rx_sequence": next_rx,
        "incoming_sequence": incoming,
        "window_max": WINDOW_MAX,
        "window_overflow": window_overflow,
        "accepted": True,
        "reason": f"incoming ({incoming}) < next_rx ({next_rx}); window_overflow ({window_overflow}) < next_rx ({next_rx}); incoming ({incoming}) <= window_overflow ({window_overflow}) → accepted",
    })

    # Case 7: Wraparound edge — incoming outside window (rejected)
    # next_rx = 65530, incoming = 50 (too far ahead of window_overflow=42)
    next_rx = 65530
    incoming = 50
    window_overflow = (next_rx + WINDOW_MAX) % SEQ_MODULUS  # 42
    vectors.append({
        "index": 7,
        "description": "RX validation: wraparound, incoming beyond window (rejected)",
        "type": "rx_validation",
        "next_rx_sequence": next_rx,
        "incoming_sequence": incoming,
        "window_max": WINDOW_MAX,
        "window_overflow": window_overflow,
        "accepted": False,
        "reason": f"incoming ({incoming}) < next_rx ({next_rx}); window_overflow ({window_overflow}) < next_rx ({next_rx}); incoming ({incoming}) > window_overflow ({window_overflow}) → rejected",
    })

    return vectors


def extract_stream_data_vectors():
    """Generate StreamDataMessage encoding/decoding vectors."""
    vectors = []

    # Case 0: Simple data, no flags
    data_0 = b"Hello, Reticulum!"
    packed_0 = stream_data_pack(0, data_0)
    sid, eof, comp, dec_data = stream_data_unpack(packed_0)
    vectors.append({
        "index": 0,
        "description": "Simple data, stream_id=0, no flags",
        "stream_id": 0,
        "eof": False,
        "compressed": False,
        "data_hex": data_0.hex(),
        "data_length": len(data_0),
        "packed_hex": packed_0.hex(),
        "packed_length": len(packed_0),
        "header_hex": packed_0[:2].hex(),
        "header_value": struct.unpack(">H", packed_0[:2])[0],
        "decoded_stream_id": sid,
        "decoded_eof": eof,
        "decoded_compressed": comp,
        "decoded_data_hex": dec_data.hex(),
    })

    # Case 1: EOF marker, no data
    packed_1 = stream_data_pack(0, b"", eof=True)
    sid, eof, comp, dec_data = stream_data_unpack(packed_1)
    vectors.append({
        "index": 1,
        "description": "EOF marker with empty data, stream_id=0",
        "stream_id": 0,
        "eof": True,
        "compressed": False,
        "data_hex": "",
        "data_length": 0,
        "packed_hex": packed_1.hex(),
        "packed_length": len(packed_1),
        "header_hex": packed_1[:2].hex(),
        "header_value": struct.unpack(">H", packed_1[:2])[0],
        "header_value_hex": f"0x{struct.unpack('>H', packed_1[:2])[0]:04x}",
        "decoded_stream_id": sid,
        "decoded_eof": eof,
        "decoded_compressed": comp,
        "decoded_data_hex": dec_data.hex(),
    })

    # Case 2: Compressed data
    original_2 = b"AAAAAAAAAA" * 50  # highly compressible
    compressed_2 = bz2.compress(original_2)
    packed_2 = stream_data_pack(5, compressed_2, compressed=True)
    sid, eof, comp, dec_data = stream_data_unpack(packed_2)
    vectors.append({
        "index": 2,
        "description": "Compressed data, stream_id=5",
        "stream_id": 5,
        "eof": False,
        "compressed": True,
        "original_data_hex": original_2.hex(),
        "original_data_length": len(original_2),
        "compressed_data_hex": compressed_2.hex(),
        "compressed_data_length": len(compressed_2),
        "packed_hex": packed_2.hex(),
        "packed_length": len(packed_2),
        "header_hex": packed_2[:2].hex(),
        "header_value": struct.unpack(">H", packed_2[:2])[0],
        "header_value_hex": f"0x{struct.unpack('>H', packed_2[:2])[0]:04x}",
        "decoded_stream_id": sid,
        "decoded_eof": eof,
        "decoded_compressed": comp,
        "decoded_data_hex": dec_data.hex(),
        "decoded_data_length": len(dec_data),
        "decompression_verified": dec_data == original_2,
    })

    # Case 3: Compressed + EOF
    original_3 = b"BBBBBBBBBB" * 30
    compressed_3 = bz2.compress(original_3)
    packed_3 = stream_data_pack(100, compressed_3, eof=True, compressed=True)
    sid, eof, comp, dec_data = stream_data_unpack(packed_3)
    vectors.append({
        "index": 3,
        "description": "Compressed + EOF, stream_id=100",
        "stream_id": 100,
        "eof": True,
        "compressed": True,
        "original_data_hex": original_3.hex(),
        "original_data_length": len(original_3),
        "compressed_data_hex": compressed_3.hex(),
        "compressed_data_length": len(compressed_3),
        "packed_hex": packed_3.hex(),
        "packed_length": len(packed_3),
        "header_hex": packed_3[:2].hex(),
        "header_value": struct.unpack(">H", packed_3[:2])[0],
        "header_value_hex": f"0x{struct.unpack('>H', packed_3[:2])[0]:04x}",
        "decoded_stream_id": sid,
        "decoded_eof": eof,
        "decoded_compressed": comp,
        "decoded_data_hex": dec_data.hex(),
        "decoded_data_length": len(dec_data),
        "decompression_verified": dec_data == original_3,
    })

    # Case 4: Max stream_id
    data_4 = b"\x01\x02\x03\x04"
    packed_4 = stream_data_pack(STREAM_ID_MAX, data_4)
    sid, eof, comp, dec_data = stream_data_unpack(packed_4)
    vectors.append({
        "index": 4,
        "description": f"Max stream_id ({STREAM_ID_MAX}), no flags",
        "stream_id": STREAM_ID_MAX,
        "eof": False,
        "compressed": False,
        "data_hex": data_4.hex(),
        "data_length": len(data_4),
        "packed_hex": packed_4.hex(),
        "packed_length": len(packed_4),
        "header_hex": packed_4[:2].hex(),
        "header_value": struct.unpack(">H", packed_4[:2])[0],
        "header_value_hex": f"0x{struct.unpack('>H', packed_4[:2])[0]:04x}",
        "decoded_stream_id": sid,
        "decoded_eof": eof,
        "decoded_compressed": comp,
        "decoded_data_hex": dec_data.hex(),
    })

    # Case 5: All flags set with max stream_id
    data_5 = b"\xDE\xAD"
    compressed_5 = bz2.compress(data_5)
    packed_5 = stream_data_pack(STREAM_ID_MAX, compressed_5, eof=True, compressed=True)
    sid, eof, comp, dec_data = stream_data_unpack(packed_5)
    vectors.append({
        "index": 5,
        "description": f"All flags set (eof+compressed) with max stream_id ({STREAM_ID_MAX})",
        "stream_id": STREAM_ID_MAX,
        "eof": True,
        "compressed": True,
        "original_data_hex": data_5.hex(),
        "original_data_length": len(data_5),
        "compressed_data_hex": compressed_5.hex(),
        "compressed_data_length": len(compressed_5),
        "packed_hex": packed_5.hex(),
        "packed_length": len(packed_5),
        "header_hex": packed_5[:2].hex(),
        "header_value": struct.unpack(">H", packed_5[:2])[0],
        "header_value_hex": f"0x{struct.unpack('>H', packed_5[:2])[0]:04x}",
        "header_breakdown": {
            "stream_id_bits": f"0x{STREAM_ID_MAX:04x} (bits 0-13)",
            "compressed_bit": "0x4000 (bit 14)",
            "eof_bit": "0x8000 (bit 15)",
            "combined": f"0x{STREAM_ID_MAX | 0x4000 | 0x8000:04x}",
        },
        "decoded_stream_id": sid,
        "decoded_eof": eof,
        "decoded_compressed": comp,
        "decoded_data_hex": dec_data.hex(),
        "decompression_verified": dec_data == data_5,
    })

    return vectors


def extract_window_init_vectors():
    """Generate window initialization vectors based on RTT."""
    vectors = []

    # Very slow link (RTT > RTT_SLOW=1.45)
    rtt_very_slow = 2.0
    vectors.append({
        "index": 0,
        "description": f"Very slow link (RTT={rtt_very_slow} > RTT_SLOW={RTT_SLOW})",
        "rtt": rtt_very_slow,
        "window": 1,
        "window_max": 1,
        "window_min": 1,
        "window_flexibility": 1,
        "condition": f"rtt ({rtt_very_slow}) > RTT_SLOW ({RTT_SLOW})",
    })

    # Slow link (RTT == RTT_SLOW, boundary — NOT greater, so normal init)
    rtt_boundary = RTT_SLOW
    vectors.append({
        "index": 1,
        "description": f"RTT at boundary (RTT={rtt_boundary} == RTT_SLOW={RTT_SLOW}): uses normal init",
        "rtt": rtt_boundary,
        "window": WINDOW,
        "window_max": WINDOW_MAX_SLOW,
        "window_min": WINDOW_MIN,
        "window_flexibility": WINDOW_FLEXIBILITY,
        "condition": f"rtt ({rtt_boundary}) <= RTT_SLOW ({RTT_SLOW}) → normal init",
    })

    # Normal link (RTT < RTT_SLOW)
    rtt_normal = 0.5
    vectors.append({
        "index": 2,
        "description": f"Normal link (RTT={rtt_normal} < RTT_SLOW={RTT_SLOW})",
        "rtt": rtt_normal,
        "window": WINDOW,
        "window_max": WINDOW_MAX_SLOW,
        "window_min": WINDOW_MIN,
        "window_flexibility": WINDOW_FLEXIBILITY,
        "condition": f"rtt ({rtt_normal}) <= RTT_SLOW ({RTT_SLOW}) → normal init",
    })

    # Fast link
    rtt_fast = 0.01
    vectors.append({
        "index": 3,
        "description": f"Fast link (RTT={rtt_fast})",
        "rtt": rtt_fast,
        "window": WINDOW,
        "window_max": WINDOW_MAX_SLOW,
        "window_min": WINDOW_MIN,
        "window_flexibility": WINDOW_FLEXIBILITY,
        "condition": f"rtt ({rtt_fast}) <= RTT_SLOW ({RTT_SLOW}) → normal init (window grows via adaptation)",
        "note": "All non-very-slow links start with WINDOW_MAX_SLOW; fast/medium upgrades happen during delivery callbacks",
    })

    # Just above boundary
    rtt_just_above = 1.46
    vectors.append({
        "index": 4,
        "description": f"Just above boundary (RTT={rtt_just_above} > RTT_SLOW={RTT_SLOW})",
        "rtt": rtt_just_above,
        "window": 1,
        "window_max": 1,
        "window_min": 1,
        "window_flexibility": 1,
        "condition": f"rtt ({rtt_just_above}) > RTT_SLOW ({RTT_SLOW}) → very slow init",
    })

    return vectors


def extract_window_adaptation_vectors():
    """Generate window adaptation state machine vectors."""
    vectors = []

    # --- Delivery (success) scenarios ---

    # Case 0: Normal growth — window increments by 1
    vectors.append({
        "index": 0,
        "description": "Delivery: window grows by 1 (below max)",
        "event": "delivery",
        "before": {"window": 2, "window_max": 5, "window_min": 2,
                   "fast_rate_rounds": 0, "medium_rate_rounds": 0},
        "rtt": 0.5,
        "after": {"window": 3, "window_max": 5, "window_min": 2,
                  "fast_rate_rounds": 0, "medium_rate_rounds": 1},
        "note": "RTT (0.5) > RTT_FAST (0.18) → fast_rate_rounds reset to 0; RTT <= RTT_MEDIUM (0.75) → medium_rate_rounds += 1",
    })

    # Case 1: Window at max — no growth
    vectors.append({
        "index": 1,
        "description": "Delivery: window at max, no growth",
        "event": "delivery",
        "before": {"window": 5, "window_max": 5, "window_min": 2,
                   "fast_rate_rounds": 0, "medium_rate_rounds": 0},
        "rtt": 0.5,
        "after": {"window": 5, "window_max": 5, "window_min": 2,
                  "fast_rate_rounds": 0, "medium_rate_rounds": 1},
        "note": "window (5) >= window_max (5) → no increment",
    })

    # Case 2: Fast RTT, incrementing fast_rate_rounds
    vectors.append({
        "index": 2,
        "description": "Delivery: fast RTT, fast_rate_rounds increments",
        "event": "delivery",
        "before": {"window": 3, "window_max": 5, "window_min": 2,
                   "fast_rate_rounds": 5, "medium_rate_rounds": 0},
        "rtt": 0.01,
        "after": {"window": 4, "window_max": 5, "window_min": 2,
                  "fast_rate_rounds": 6, "medium_rate_rounds": 0},
        "note": "RTT (0.01) <= RTT_FAST (0.18) → fast_rate_rounds += 1 (5→6)",
    })

    # Case 3: Fast RTT reaches threshold — upgrade to FAST window
    vectors.append({
        "index": 3,
        "description": "Delivery: fast_rate_rounds reaches threshold, upgrade to FAST",
        "event": "delivery",
        "before": {"window": 4, "window_max": 5, "window_min": 2,
                   "fast_rate_rounds": 9, "medium_rate_rounds": 0},
        "rtt": 0.01,
        "after": {"window": 5, "window_max": WINDOW_MAX_FAST, "window_min": WINDOW_MIN_LIMIT_FAST,
                  "fast_rate_rounds": 10, "medium_rate_rounds": 0},
        "note": f"fast_rate_rounds reaches FAST_RATE_THRESHOLD ({FAST_RATE_THRESHOLD}) → window_max upgraded to WINDOW_MAX_FAST ({WINDOW_MAX_FAST}), window_min to WINDOW_MIN_LIMIT_FAST ({WINDOW_MIN_LIMIT_FAST})",
    })

    # Case 4: Medium RTT reaches threshold — upgrade to MEDIUM window
    vectors.append({
        "index": 4,
        "description": "Delivery: medium_rate_rounds reaches threshold, upgrade to MEDIUM",
        "event": "delivery",
        "before": {"window": 4, "window_max": 5, "window_min": 2,
                   "fast_rate_rounds": 0, "medium_rate_rounds": 9},
        "rtt": 0.5,
        "after": {"window": 5, "window_max": WINDOW_MAX_MEDIUM, "window_min": WINDOW_MIN_LIMIT_MEDIUM,
                  "fast_rate_rounds": 0, "medium_rate_rounds": 10},
        "note": f"medium_rate_rounds reaches FAST_RATE_THRESHOLD ({FAST_RATE_THRESHOLD}) → window_max upgraded to WINDOW_MAX_MEDIUM ({WINDOW_MAX_MEDIUM}), window_min to WINDOW_MIN_LIMIT_MEDIUM ({WINDOW_MIN_LIMIT_MEDIUM})",
    })

    # Case 5: Slow RTT — both counters reset
    vectors.append({
        "index": 5,
        "description": "Delivery: slow RTT resets both rate counters",
        "event": "delivery",
        "before": {"window": 3, "window_max": 5, "window_min": 2,
                   "fast_rate_rounds": 5, "medium_rate_rounds": 7},
        "rtt": 1.0,
        "after": {"window": 4, "window_max": 5, "window_min": 2,
                  "fast_rate_rounds": 0, "medium_rate_rounds": 0},
        "note": "RTT (1.0) > RTT_MEDIUM (0.75) → both fast_rate_rounds and medium_rate_rounds reset to 0",
    })

    # Case 6: RTT == 0 — no rate adaptation (just window growth)
    vectors.append({
        "index": 6,
        "description": "Delivery: RTT == 0, no rate adaptation",
        "event": "delivery",
        "before": {"window": 2, "window_max": 5, "window_min": 2,
                   "fast_rate_rounds": 3, "medium_rate_rounds": 3},
        "rtt": 0,
        "after": {"window": 3, "window_max": 5, "window_min": 2,
                  "fast_rate_rounds": 3, "medium_rate_rounds": 3},
        "note": "RTT == 0 → rate adaptation block is skipped entirely; counters unchanged",
    })

    # --- Timeout (failure) scenarios ---

    # Case 7: Timeout — both window and window_max shrink
    vectors.append({
        "index": 7,
        "description": "Timeout: window and window_max both shrink",
        "event": "timeout",
        "before": {"window": 4, "window_max": 12, "window_min": 2,
                   "window_flexibility": WINDOW_FLEXIBILITY},
        "after": {"window": 3, "window_max": 11, "window_min": 2,
                  "window_flexibility": WINDOW_FLEXIBILITY},
        "note": "window (4) > window_min (2) → window -= 1 (4→3); window_max (12) > window_min + flexibility (2+4=6) → window_max -= 1 (12→11)",
    })

    # Case 8: Timeout at window floor — no shrink
    vectors.append({
        "index": 8,
        "description": "Timeout: window at minimum, no shrink",
        "event": "timeout",
        "before": {"window": 2, "window_max": 5, "window_min": 2,
                   "window_flexibility": WINDOW_FLEXIBILITY},
        "after": {"window": 2, "window_max": 5, "window_min": 2,
                  "window_flexibility": WINDOW_FLEXIBILITY},
        "note": "window (2) <= window_min (2) → no shrink; window_max (5) <= window_min + flexibility (2+4=6) → no max shrink",
    })

    # Case 9: Timeout — both shrink on fast link
    vectors.append({
        "index": 9,
        "description": "Timeout: both window and window_max shrink (fast link)",
        "event": "timeout",
        "before": {"window": 20, "window_max": 48, "window_min": 16,
                   "window_flexibility": WINDOW_FLEXIBILITY},
        "after": {"window": 19, "window_max": 47, "window_min": 16,
                  "window_flexibility": WINDOW_FLEXIBILITY},
        "note": "window (20) > window_min (16) → window -= 1 (20→19); window_max (48) > window_min + flexibility (16+4=20) → window_max -= 1 (48→47)",
    })

    # Case 10: Timeout — window shrinks but window_max at floor
    vectors.append({
        "index": 10,
        "description": "Timeout: window shrinks but window_max at floor",
        "event": "timeout",
        "before": {"window": 4, "window_max": 6, "window_min": 2,
                   "window_flexibility": WINDOW_FLEXIBILITY},
        "after": {"window": 3, "window_max": 6, "window_min": 2,
                  "window_flexibility": WINDOW_FLEXIBILITY},
        "note": "window (4) > window_min (2) → window -= 1 (4→3); window_max (6) > window_min + flexibility (2+4=6)? 6 > 6 is False → window_max unchanged",
    })

    return vectors


def extract_timeout_vectors():
    """Generate timeout calculation vectors.

    Formula: pow(1.5, tries-1) * max(rtt*2.5, 0.025) * (tx_ring_length + 1.5)
    """
    vectors = []

    cases = [
        # (tries, rtt, tx_ring_length, description)
        (1, 0.01, 0, "First try, fast RTT, empty queue"),
        (1, 0.01, 1, "First try, fast RTT, 1 in queue"),
        (2, 0.01, 1, "Second try, fast RTT, 1 in queue"),
        (3, 0.5, 2, "Third try, medium RTT, 2 in queue"),
        (5, 1.0, 5, "Fifth try, slow RTT, 5 in queue"),
        (1, 0.0, 0, "First try, zero RTT, empty queue (floor kicks in)"),
        (1, 0.005, 0, "First try, very low RTT (below floor), empty queue"),
        (4, 0.3, 3, "Fourth try, moderate RTT, 3 in queue"),
    ]

    for idx, (tries, rtt, tx_ring_len, desc) in enumerate(cases):
        timeout = get_packet_timeout_time(tries, rtt, tx_ring_len)
        rtt_factor = max(rtt * 2.5, 0.025)
        exp_factor = pow(1.5, tries - 1)
        ring_factor = tx_ring_len + 1.5

        vectors.append({
            "index": idx,
            "description": desc,
            "tries": tries,
            "rtt": rtt,
            "tx_ring_length": tx_ring_len,
            "timeout": round(timeout, 10),
            "formula": "pow(1.5, tries-1) * max(rtt*2.5, 0.025) * (tx_ring_length + 1.5)",
            "breakdown": {
                "exponential_factor": round(exp_factor, 10),
                "rtt_factor": round(rtt_factor, 10),
                "rtt_factor_note": f"max({rtt}*2.5, 0.025) = max({round(rtt*2.5, 10)}, 0.025) = {round(rtt_factor, 10)}",
                "ring_factor": round(ring_factor, 10),
            },
            "computation": f"{round(exp_factor, 6)} * {round(rtt_factor, 6)} * {round(ring_factor, 6)} = {round(timeout, 10)}",
        })

    return vectors


def extract_mdu_vectors():
    """Generate Channel MDU computation vectors.

    Formula: min(outlet_mdu - 6, 0xFFFF)
    """
    vectors = []

    cases = [
        # (outlet_mdu, description)
        (500, "Standard outlet MDU (500)"),
        (LINK_MDU, f"Link MDU ({LINK_MDU})"),
        (100, "Small outlet MDU (100)"),
        (6, "Minimum viable outlet MDU (6) — yields MDU of 0"),
        (7, "Outlet MDU of 7 — yields MDU of 1"),
        (70000, "Very large outlet MDU — capped at 0xFFFF"),
    ]

    for idx, (outlet_mdu, desc) in enumerate(cases):
        channel_mdu = outlet_mdu - 6
        if channel_mdu > 0xFFFF:
            channel_mdu = 0xFFFF

        vectors.append({
            "index": idx,
            "description": desc,
            "outlet_mdu": outlet_mdu,
            "channel_mdu": channel_mdu,
            "formula": "min(outlet_mdu - 6, 0xFFFF)",
            "computation": f"min({outlet_mdu} - 6, 65535) = min({outlet_mdu - 6}, 65535) = {channel_mdu}",
        })

    return vectors


def extract_system_message_vectors():
    """Generate system message type boundary vectors."""
    vectors = []

    # User-valid types
    for msgtype, desc in [(0x0000, "Minimum user type"), (0x0001, "Low user type"),
                          (0xABCD, "Typical user type"), (0xEFFF, "Maximum user type")]:
        vectors.append({
            "msgtype": msgtype,
            "msgtype_hex": f"0x{msgtype:04x}",
            "description": desc,
            "is_system": False,
            "is_valid_user_type": True,
        })

    # System-reserved types
    for msgtype, desc in [(0xF000, "Minimum system type (boundary)"),
                          (0xFF00, "SMT_STREAM_DATA"),
                          (0xFFFF, "Maximum system type")]:
        vectors.append({
            "msgtype": msgtype,
            "msgtype_hex": f"0x{msgtype:04x}",
            "description": desc,
            "is_system": True,
            "is_valid_user_type": False,
        })

    return vectors


def extract_round_trip_vectors():
    """Generate full round-trip integration vectors.

    Pack message → envelope → wire bytes → decode envelope → verify fields.
    """
    from RNS.vendor import umsgpack

    vectors = []

    # Case 0: Simple message round-trip
    msg_id = "rt-test-001"
    msg_data = "round trip test"
    msg_packed = umsgpack.packb((msg_id, msg_data))
    msgtype = 0xABCD
    sequence = 42

    # Pack into envelope
    envelope_raw = envelope_pack(msgtype, sequence, msg_packed)

    # Unpack envelope
    dec_msgtype, dec_seq, dec_len, dec_data = envelope_unpack(envelope_raw)

    # Unpack message
    dec_tuple = umsgpack.unpackb(dec_data)

    vectors.append({
        "index": 0,
        "description": "Simple message round-trip (pack → envelope → decode)",
        "message": {"id": msg_id, "data": msg_data, "msgtype": msgtype},
        "message_packed_hex": msg_packed.hex(),
        "sequence": sequence,
        "envelope_raw_hex": envelope_raw.hex(),
        "envelope_length": len(envelope_raw),
        "decoded_msgtype": dec_msgtype,
        "decoded_sequence": dec_seq,
        "decoded_data_length": dec_len,
        "decoded_message_id": dec_tuple[0],
        "decoded_message_data": dec_tuple[1],
        "verified": dec_tuple[0] == msg_id and dec_tuple[1] == msg_data,
    })

    # Case 1: StreamDataMessage round-trip via envelope
    stream_id = 7
    stream_data = b"stream payload data"
    stream_msg_packed = stream_data_pack(stream_id, stream_data)
    stream_envelope = envelope_pack(SMT_STREAM_DATA, 0, stream_msg_packed)

    # Decode
    dec_msgtype2, dec_seq2, dec_len2, dec_data2 = envelope_unpack(stream_envelope)
    dec_sid, dec_eof, dec_comp, dec_stream_data = stream_data_unpack(dec_data2)

    vectors.append({
        "index": 1,
        "description": "StreamDataMessage round-trip via channel envelope",
        "stream_id": stream_id,
        "stream_data_hex": stream_data.hex(),
        "stream_msg_packed_hex": stream_msg_packed.hex(),
        "envelope_msgtype": SMT_STREAM_DATA,
        "envelope_sequence": 0,
        "envelope_raw_hex": stream_envelope.hex(),
        "envelope_length": len(stream_envelope),
        "decoded_envelope_msgtype": dec_msgtype2,
        "decoded_envelope_sequence": dec_seq2,
        "decoded_stream_id": dec_sid,
        "decoded_stream_eof": dec_eof,
        "decoded_stream_compressed": dec_comp,
        "decoded_stream_data_hex": dec_stream_data.hex(),
        "verified": dec_stream_data == stream_data and dec_sid == stream_id,
    })

    # Case 2: Sequence wraparound round-trip
    msg_id3 = "wrap-test"
    msg_data3 = "at max sequence"
    msg_packed3 = umsgpack.packb((msg_id3, msg_data3))
    sequence3 = SEQ_MAX  # 65535
    envelope3 = envelope_pack(0x1234, sequence3, msg_packed3)
    dec3_mt, dec3_seq, dec3_len, dec3_data = envelope_unpack(envelope3)
    dec3_tuple = umsgpack.unpackb(dec3_data)

    vectors.append({
        "index": 2,
        "description": "Message at SEQ_MAX (65535) — wraparound boundary",
        "message": {"id": msg_id3, "data": msg_data3, "msgtype": 0x1234},
        "message_packed_hex": msg_packed3.hex(),
        "sequence": sequence3,
        "next_sequence": (sequence3 + 1) % SEQ_MODULUS,
        "envelope_raw_hex": envelope3.hex(),
        "envelope_length": len(envelope3),
        "decoded_msgtype": dec3_mt,
        "decoded_sequence": dec3_seq,
        "decoded_message_id": dec3_tuple[0],
        "decoded_message_data": dec3_tuple[1],
        "verified": dec3_tuple[0] == msg_id3 and dec3_tuple[1] == msg_data3 and dec3_seq == SEQ_MAX,
    })

    return vectors


def extract_send_receive_vectors():
    """Generate send/receive progression and multi-type dispatch vectors.

    Simulates a channel conversation using two MessageBase-like types:
      - Alpha (MSGTYPE=0xabcd): serializes (id_str, data_str) via umsgpack
      - Beta  (MSGTYPE=0x1234): serializes (tag_str, payload_bytes) via umsgpack

    Produces vectors covering:
      - TX send progression: _next_sequence state across 3 sends
      - RX receive progression: _next_rx_sequence state across 3 receives
      - Non-serialized field loss: fields not in pack() don't survive round-trip
      - Full round-trip for each message type
    """
    from RNS.vendor import umsgpack

    vectors = []

    ALPHA_MSGTYPE = 0xABCD
    BETA_MSGTYPE = 0x1234

    # Define the three messages in conversation order
    # msg 0: Alpha("alpha-msg-0", "hello")
    # msg 1: Beta("beta-msg-1", b"\xde\xad\xbe\xef")
    # msg 2: Alpha("alpha-msg-2", "test round two")
    messages = [
        {"type": "Alpha", "msgtype": ALPHA_MSGTYPE,
         "fields": ("alpha-msg-0", "hello"),
         "pack": lambda: umsgpack.packb(("alpha-msg-0", "hello"))},
        {"type": "Beta", "msgtype": BETA_MSGTYPE,
         "fields": ("beta-msg-1", b"\xde\xad\xbe\xef"),
         "pack": lambda: umsgpack.packb(("beta-msg-1", b"\xde\xad\xbe\xef"))},
        {"type": "Alpha", "msgtype": ALPHA_MSGTYPE,
         "fields": ("alpha-msg-2", "test round two"),
         "pack": lambda: umsgpack.packb(("alpha-msg-2", "test round two"))},
    ]

    # Pre-compute packed data and envelopes
    packed_data = [m["pack"]() for m in messages]
    envelopes = [envelope_pack(messages[i]["msgtype"], i, packed_data[i]) for i in range(3)]

    # --- Vector 0: TX send progression ---
    tx_steps = []
    next_sequence = 0
    for i in range(3):
        seq_before = next_sequence
        msg_packed = packed_data[i]
        env_raw = envelope_pack(messages[i]["msgtype"], next_sequence, msg_packed)
        next_sequence = (next_sequence + 1) % SEQ_MODULUS
        tx_steps.append({
            "step": i,
            "message_type": messages[i]["type"],
            "msgtype": messages[i]["msgtype"],
            "msgtype_hex": f"0x{messages[i]['msgtype']:04x}",
            "tx_sequence_before": seq_before,
            "tx_sequence_after": next_sequence,
            "message_packed_hex": msg_packed.hex(),
            "message_packed_length": len(msg_packed),
            "envelope_raw_hex": env_raw.hex(),
            "envelope_length": len(env_raw),
        })

    vectors.append({
        "index": 0,
        "type": "tx_send_progression",
        "description": "3 sends with seq 0,1,2 using Alpha and Beta types; tracks _next_sequence state",
        "steps": tx_steps,
        "final_next_sequence": next_sequence,
    })

    # --- Vector 1: RX receive progression ---
    # Receiver processes the same 3 envelopes in order
    rx_steps = []
    next_rx_sequence = 0
    message_factories = {ALPHA_MSGTYPE: "Alpha", BETA_MSGTYPE: "Beta"}

    for i in range(3):
        rx_seq_before = next_rx_sequence
        env_raw = envelopes[i]
        dec_msgtype, dec_seq, dec_len, dec_data = envelope_unpack(env_raw)
        dec_fields = umsgpack.unpackb(dec_data)
        factory_used = message_factories.get(dec_msgtype, "unknown")
        next_rx_sequence = (next_rx_sequence + 1) % SEQ_MODULUS

        # Represent decoded fields as JSON-safe values
        decoded = []
        for f in dec_fields:
            if isinstance(f, bytes):
                decoded.append({"type": "bytes", "hex": f.hex()})
            else:
                decoded.append({"type": "str", "value": f})

        rx_steps.append({
            "step": i,
            "envelope_raw_hex": env_raw.hex(),
            "rx_sequence_before": rx_seq_before,
            "rx_sequence_after": next_rx_sequence,
            "decoded_msgtype": dec_msgtype,
            "decoded_msgtype_hex": f"0x{dec_msgtype:04x}",
            "decoded_sequence": dec_seq,
            "decoded_data_length": dec_len,
            "factory_used": factory_used,
            "decoded_fields": decoded,
        })

    vectors.append({
        "index": 1,
        "type": "rx_receive_progression",
        "description": "3 receives of the same envelopes; MSGTYPE-based factory dispatch; tracks _next_rx_sequence state",
        "steps": rx_steps,
        "final_next_rx_sequence": next_rx_sequence,
    })

    # --- Vector 2: Non-serialized field loss ---
    # Alpha packs only (id, data). If we add a "timestamp" field, it doesn't
    # survive pack/unpack. Show that packed bytes only contain the serialized fields.
    alpha_id = "field-loss-test"
    alpha_data = "some data"
    extra_field = "2025-01-01T00:00:00Z"  # not part of pack()
    alpha_packed = umsgpack.packb((alpha_id, alpha_data))
    alpha_unpacked = umsgpack.unpackb(alpha_packed)

    vectors.append({
        "index": 2,
        "type": "non_serialized_field_loss",
        "description": "Fields not in pack() don't survive round-trip unpack()",
        "original_fields": {
            "id": alpha_id,
            "data": alpha_data,
            "timestamp": extra_field,
        },
        "serialized_fields": ["id", "data"],
        "non_serialized_fields": ["timestamp"],
        "packed_hex": alpha_packed.hex(),
        "packed_length": len(alpha_packed),
        "unpacked_fields": list(alpha_unpacked),
        "unpacked_field_count": len(alpha_unpacked),
        "timestamp_preserved": False,
        "note": "Only fields included in pack() survive; timestamp is lost",
    })

    # --- Vector 3: Full round-trip for Alpha ---
    alpha_rt_id = "alpha-rt-001"
    alpha_rt_data = "alpha round trip verification"
    alpha_rt_packed = umsgpack.packb((alpha_rt_id, alpha_rt_data))
    alpha_rt_seq = 42
    alpha_rt_env = envelope_pack(ALPHA_MSGTYPE, alpha_rt_seq, alpha_rt_packed)
    dec_mt, dec_sq, dec_ln, dec_dt = envelope_unpack(alpha_rt_env)
    dec_tup = umsgpack.unpackb(dec_dt)

    vectors.append({
        "index": 3,
        "type": "full_round_trip",
        "description": "Complete send-receive integrity check for Alpha message",
        "message_type": "Alpha",
        "msgtype": ALPHA_MSGTYPE,
        "msgtype_hex": f"0x{ALPHA_MSGTYPE:04x}",
        "original_id": alpha_rt_id,
        "original_data": alpha_rt_data,
        "sequence": alpha_rt_seq,
        "message_packed_hex": alpha_rt_packed.hex(),
        "envelope_raw_hex": alpha_rt_env.hex(),
        "envelope_length": len(alpha_rt_env),
        "decoded_msgtype": dec_mt,
        "decoded_sequence": dec_sq,
        "decoded_data_length": dec_ln,
        "decoded_id": dec_tup[0],
        "decoded_data": dec_tup[1],
        "verified": dec_tup[0] == alpha_rt_id and dec_tup[1] == alpha_rt_data and dec_mt == ALPHA_MSGTYPE and dec_sq == alpha_rt_seq,
    })

    # --- Vector 4: Full round-trip for Beta ---
    beta_rt_tag = "beta-rt-002"
    beta_rt_payload = bytes([0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0xFF, 0x01, 0x02])
    beta_rt_packed = umsgpack.packb((beta_rt_tag, beta_rt_payload))
    beta_rt_seq = 99
    beta_rt_env = envelope_pack(BETA_MSGTYPE, beta_rt_seq, beta_rt_packed)
    dec_mt2, dec_sq2, dec_ln2, dec_dt2 = envelope_unpack(beta_rt_env)
    dec_tup2 = umsgpack.unpackb(dec_dt2)

    vectors.append({
        "index": 4,
        "type": "full_round_trip",
        "description": "Complete send-receive integrity check for Beta message",
        "message_type": "Beta",
        "msgtype": BETA_MSGTYPE,
        "msgtype_hex": f"0x{BETA_MSGTYPE:04x}",
        "original_tag": beta_rt_tag,
        "original_payload_hex": beta_rt_payload.hex(),
        "sequence": beta_rt_seq,
        "message_packed_hex": beta_rt_packed.hex(),
        "envelope_raw_hex": beta_rt_env.hex(),
        "envelope_length": len(beta_rt_env),
        "decoded_msgtype": dec_mt2,
        "decoded_sequence": dec_sq2,
        "decoded_data_length": dec_ln2,
        "decoded_tag": dec_tup2[0],
        "decoded_payload_hex": dec_tup2[1].hex(),
        "verified": dec_tup2[0] == beta_rt_tag and dec_tup2[1] == beta_rt_payload and dec_mt2 == BETA_MSGTYPE and dec_sq2 == beta_rt_seq,
    })

    return vectors


def extract_handler_chaining_vectors():
    """Generate handler chaining behavioral vectors for _run_callbacks().

    From Channel._run_callbacks():
        cbs = self._message_callbacks.copy()
        for cb in cbs:
            try:
                if cb(message):
                    return
            except Exception as e:
                RNS.log(...)

    Behavior:
      - Handlers called in registration order
      - If handler returns truthy → short-circuit (stop calling further handlers)
      - If handler returns falsy or None → continue to next handler
      - If handler raises → exception is caught, continue to next handler
      - Duplicate handlers (same callable) are prevented by add_message_handler()

    All vectors share a single reference envelope (Alpha MSGTYPE=0xABCD, sequence=0).
    """
    from RNS.vendor import umsgpack

    # Pre-compute reference envelope for all vectors
    ref_msgtype = 0xABCD
    ref_sequence = 0
    ref_packed = umsgpack.packb(("handler-chain-test", "test data"))
    ref_envelope = envelope_pack(ref_msgtype, ref_sequence, ref_packed)

    vectors = []

    # Vector 0: Single handler returns True → short-circuit at h0
    vectors.append({
        "index": 0,
        "description": "Single handler returns True — short-circuits at handler_0",
        "handlers": [{"name": "handler_0", "returns": True, "raises": None}],
        "message_envelope_hex": ref_envelope.hex(),
        "message_msgtype": ref_msgtype,
        "message_msgtype_hex": f"0x{ref_msgtype:04x}",
        "expected_calls": ["handler_0"],
        "expected_call_count": 1,
        "short_circuited": True,
        "short_circuit_handler": "handler_0",
    })

    # Vector 1: Single handler returns False → no short-circuit
    vectors.append({
        "index": 1,
        "description": "Single handler returns False — no short-circuit",
        "handlers": [{"name": "handler_0", "returns": False, "raises": None}],
        "message_envelope_hex": ref_envelope.hex(),
        "message_msgtype": ref_msgtype,
        "message_msgtype_hex": f"0x{ref_msgtype:04x}",
        "expected_calls": ["handler_0"],
        "expected_call_count": 1,
        "short_circuited": False,
        "short_circuit_handler": None,
    })

    # Vector 2: Single handler returns None → no short-circuit
    vectors.append({
        "index": 2,
        "description": "Single handler returns None — no short-circuit (None is falsy)",
        "handlers": [{"name": "handler_0", "returns": None, "raises": None}],
        "message_envelope_hex": ref_envelope.hex(),
        "message_msgtype": ref_msgtype,
        "message_msgtype_hex": f"0x{ref_msgtype:04x}",
        "expected_calls": ["handler_0"],
        "expected_call_count": 1,
        "short_circuited": False,
        "short_circuit_handler": None,
    })

    # Vector 3: Two handlers, first returns True → short-circuit at h0
    vectors.append({
        "index": 3,
        "description": "Two handlers, first returns True — short-circuits at handler_0, handler_1 not called",
        "handlers": [
            {"name": "handler_0", "returns": True, "raises": None},
            {"name": "handler_1", "returns": False, "raises": None},
        ],
        "message_envelope_hex": ref_envelope.hex(),
        "message_msgtype": ref_msgtype,
        "message_msgtype_hex": f"0x{ref_msgtype:04x}",
        "expected_calls": ["handler_0"],
        "expected_call_count": 1,
        "short_circuited": True,
        "short_circuit_handler": "handler_0",
    })

    # Vector 4: Two handlers, first False, second True → short-circuit at h1
    vectors.append({
        "index": 4,
        "description": "Two handlers, first returns False, second returns True — short-circuits at handler_1",
        "handlers": [
            {"name": "handler_0", "returns": False, "raises": None},
            {"name": "handler_1", "returns": True, "raises": None},
        ],
        "message_envelope_hex": ref_envelope.hex(),
        "message_msgtype": ref_msgtype,
        "message_msgtype_hex": f"0x{ref_msgtype:04x}",
        "expected_calls": ["handler_0", "handler_1"],
        "expected_call_count": 2,
        "short_circuited": True,
        "short_circuit_handler": "handler_1",
    })

    # Vector 5: Two handlers, both False → no short-circuit
    vectors.append({
        "index": 5,
        "description": "Two handlers, both return False — no short-circuit, all called",
        "handlers": [
            {"name": "handler_0", "returns": False, "raises": None},
            {"name": "handler_1", "returns": False, "raises": None},
        ],
        "message_envelope_hex": ref_envelope.hex(),
        "message_msgtype": ref_msgtype,
        "message_msgtype_hex": f"0x{ref_msgtype:04x}",
        "expected_calls": ["handler_0", "handler_1"],
        "expected_call_count": 2,
        "short_circuited": False,
        "short_circuit_handler": None,
    })

    # Vector 6: Three handlers, middle returns True → short-circuit at h1
    vectors.append({
        "index": 6,
        "description": "Three handlers, middle returns True — short-circuits at handler_1, handler_2 not called",
        "handlers": [
            {"name": "handler_0", "returns": False, "raises": None},
            {"name": "handler_1", "returns": True, "raises": None},
            {"name": "handler_2", "returns": False, "raises": None},
        ],
        "message_envelope_hex": ref_envelope.hex(),
        "message_msgtype": ref_msgtype,
        "message_msgtype_hex": f"0x{ref_msgtype:04x}",
        "expected_calls": ["handler_0", "handler_1"],
        "expected_call_count": 2,
        "short_circuited": True,
        "short_circuit_handler": "handler_1",
    })

    # Vector 7: First raises exception, second returns True → exception caught, h1 short-circuits
    vectors.append({
        "index": 7,
        "description": "First handler raises exception (caught), second returns True — short-circuits at handler_1",
        "handlers": [
            {"name": "handler_0", "returns": None, "raises": "ValueError"},
            {"name": "handler_1", "returns": True, "raises": None},
        ],
        "message_envelope_hex": ref_envelope.hex(),
        "message_msgtype": ref_msgtype,
        "message_msgtype_hex": f"0x{ref_msgtype:04x}",
        "expected_calls": ["handler_0", "handler_1"],
        "expected_call_count": 2,
        "short_circuited": True,
        "short_circuit_handler": "handler_1",
    })

    # Vector 8: Only handler raises exception → exception caught, no short-circuit
    vectors.append({
        "index": 8,
        "description": "Only handler raises exception — caught and logged, no short-circuit",
        "handlers": [
            {"name": "handler_0", "returns": None, "raises": "RuntimeError"},
        ],
        "message_envelope_hex": ref_envelope.hex(),
        "message_msgtype": ref_msgtype,
        "message_msgtype_hex": f"0x{ref_msgtype:04x}",
        "expected_calls": ["handler_0"],
        "expected_call_count": 1,
        "short_circuited": False,
        "short_circuit_handler": None,
    })

    # Vector 9: Duplicate handler prevention — h0 added twice, h1 once
    # add_message_handler checks "if callback not in self._message_callbacks"
    # so duplicate is silently ignored; effective list is [h0, h1]
    vectors.append({
        "index": 9,
        "description": "Duplicate handler prevention — handler_0 added twice (second ignored), handler_1 returns True",
        "handlers": [
            {"name": "handler_0", "returns": False, "raises": None},
            {"name": "handler_0_duplicate", "returns": False, "raises": None,
             "note": "Same callable as handler_0; add_message_handler silently ignores duplicate"},
            {"name": "handler_1", "returns": True, "raises": None},
        ],
        "effective_handlers": ["handler_0", "handler_1"],
        "message_envelope_hex": ref_envelope.hex(),
        "message_msgtype": ref_msgtype,
        "message_msgtype_hex": f"0x{ref_msgtype:04x}",
        "expected_calls": ["handler_0", "handler_1"],
        "expected_call_count": 2,
        "short_circuited": True,
        "short_circuit_handler": "handler_1",
    })

    return vectors


def extract_registration_validation_vectors():
    """Generate registration validation vectors for _register_message_type().

    From Channel._register_message_type():
        Gate 1 (subclass):    if not issubclass(message_class, MessageBase) → CE ME_INVALID_MSG_TYPE
        Gate 2 (msgtype_none): if message_class.MSGTYPE is None → CE ME_INVALID_MSG_TYPE
        Gate 3 (system_type): if MSGTYPE >= 0xf000 and not is_system_type → CE ME_INVALID_MSG_TYPE
        Gate 4 (constructor): try message_class() except → CE ME_INVALID_MSG_TYPE
        Success:              self._message_factories[message_class.MSGTYPE] = message_class

    All CE types are ME_INVALID_MSG_TYPE (value 1).
    """
    CE_INVALID = 1  # CEType.ME_INVALID_MSG_TYPE

    vectors = []

    # Vector 0: Valid user type (0xABCD) — all gates pass
    vectors.append({
        "index": 0,
        "description": "Valid user type (0xABCD) — all validation gates pass",
        "msgtype": 0xABCD,
        "msgtype_hex": "0xabcd",
        "is_subclass_of_message_base": True,
        "msgtype_is_none": False,
        "constructor_succeeds": True,
        "use_internal_api": False,
        "is_system_type_flag": False,
        "expected_result": "success",
        "validation_gate": None,
        "ce_type": None,
        "factory_registered": True,
    })

    # Vector 1: MSGTYPE is None — fails at gate 2
    vectors.append({
        "index": 1,
        "description": "MSGTYPE is None — fails msgtype_none gate",
        "msgtype": None,
        "msgtype_hex": None,
        "is_subclass_of_message_base": True,
        "msgtype_is_none": True,
        "constructor_succeeds": True,
        "use_internal_api": False,
        "is_system_type_flag": False,
        "expected_result": "raises",
        "validation_gate": "msgtype_none",
        "ce_type": CE_INVALID,
        "factory_registered": False,
    })

    # Vector 2: Not a MessageBase subclass — fails at gate 1
    vectors.append({
        "index": 2,
        "description": "Not a MessageBase subclass — fails subclass gate",
        "msgtype": 0xABCD,
        "msgtype_hex": "0xabcd",
        "is_subclass_of_message_base": False,
        "msgtype_is_none": False,
        "constructor_succeeds": True,
        "use_internal_api": False,
        "is_system_type_flag": False,
        "expected_result": "raises",
        "validation_gate": "subclass",
        "ce_type": CE_INVALID,
        "factory_registered": False,
    })

    # Vector 3: System type (0xF000) via public API — fails at gate 3
    vectors.append({
        "index": 3,
        "description": "System type (0xF000) via public register_message_type — fails system_type gate",
        "msgtype": 0xF000,
        "msgtype_hex": "0xf000",
        "is_subclass_of_message_base": True,
        "msgtype_is_none": False,
        "constructor_succeeds": True,
        "use_internal_api": False,
        "is_system_type_flag": False,
        "expected_result": "raises",
        "validation_gate": "system_type",
        "ce_type": CE_INVALID,
        "factory_registered": False,
    })

    # Vector 4: System type (0xF000) via internal API with is_system_type=True — succeeds
    vectors.append({
        "index": 4,
        "description": "System type (0xF000) via _register_message_type with is_system_type=True — succeeds",
        "msgtype": 0xF000,
        "msgtype_hex": "0xf000",
        "is_subclass_of_message_base": True,
        "msgtype_is_none": False,
        "constructor_succeeds": True,
        "use_internal_api": True,
        "is_system_type_flag": True,
        "expected_result": "success",
        "validation_gate": None,
        "ce_type": None,
        "factory_registered": True,
    })

    # Vector 5: System type (0xFFFF) via public API — fails at gate 3
    vectors.append({
        "index": 5,
        "description": "System type (0xFFFF) via public register_message_type — fails system_type gate",
        "msgtype": 0xFFFF,
        "msgtype_hex": "0xffff",
        "is_subclass_of_message_base": True,
        "msgtype_is_none": False,
        "constructor_succeeds": True,
        "use_internal_api": False,
        "is_system_type_flag": False,
        "expected_result": "raises",
        "validation_gate": "system_type",
        "ce_type": CE_INVALID,
        "factory_registered": False,
    })

    # Vector 6: Max user type (0xEFFF) — all gates pass
    vectors.append({
        "index": 6,
        "description": "Max user type (0xEFFF) — just below system boundary, all gates pass",
        "msgtype": 0xEFFF,
        "msgtype_hex": "0xefff",
        "is_subclass_of_message_base": True,
        "msgtype_is_none": False,
        "constructor_succeeds": True,
        "use_internal_api": False,
        "is_system_type_flag": False,
        "expected_result": "success",
        "validation_gate": None,
        "ce_type": None,
        "factory_registered": True,
    })

    # Vector 7: No-arg constructor raises — fails at gate 4
    vectors.append({
        "index": 7,
        "description": "No-arg constructor raises exception — fails constructor gate",
        "msgtype": 0xBBBB,
        "msgtype_hex": "0xbbbb",
        "is_subclass_of_message_base": True,
        "msgtype_is_none": False,
        "constructor_succeeds": False,
        "use_internal_api": False,
        "is_system_type_flag": False,
        "expected_result": "raises",
        "validation_gate": "constructor",
        "ce_type": CE_INVALID,
        "factory_registered": False,
    })

    return vectors


def extract_sequence_dedup_vectors():
    """Generate sequence number handling and deduplication test vectors.

    Simulates Channel._receive() and Channel._emplace_envelope() state machines
    to produce vectors covering:
      - Duplicate rejection (in-ring and post-delivery old-sequence)
      - Out-of-order arrival with in-order delivery
      - Gap with partial delivery
      - Wraparound during contiguous delivery
      - Duplicate across wraparound boundary
      - Ring ordering verification
      - Extended TX progression across wraparound
      - Wraparound-aware ring ordering
    """
    from RNS.vendor import umsgpack

    MSGTYPE = 0xABCD

    def make_envelope(seq, payload_str):
        """Create envelope raw bytes for a given sequence and payload string."""
        packed = umsgpack.packb(("dedup-test", payload_str))
        return envelope_pack(MSGTYPE, seq, packed)

    vectors = []

    # === Scenario 0: Basic duplicate rejection ===
    # Send seq 5, then seq 5 again (duplicate in ring), then send seq 5 after delivery (old)
    scenario_0_steps = []
    ring = []
    next_rx = 5

    # Step 0: Receive seq 5 — accepted, delivered immediately
    env = make_envelope(5, "msg-5")
    accepted, reason, delivered, ring, next_rx = sim_receive(ring, next_rx, 5)
    scenario_0_steps.append({
        "step": 0,
        "incoming_sequence": 5,
        "envelope_raw_hex": env.hex(),
        "accepted": accepted,
        "reason": reason,
        "delivered_sequences": delivered,
        "ring_after": list(ring),
        "next_rx_after": next_rx,
    })

    # Step 1: Receive seq 6, then try seq 6 again (duplicate in ring before delivery)
    # First, receive seq 7 (out of order, buffered)
    env7 = make_envelope(7, "msg-7")
    accepted, reason, delivered, ring, next_rx = sim_receive(ring, next_rx, 7)
    scenario_0_steps.append({
        "step": 1,
        "incoming_sequence": 7,
        "envelope_raw_hex": env7.hex(),
        "accepted": accepted,
        "reason": reason,
        "delivered_sequences": delivered,
        "ring_after": list(ring),
        "next_rx_after": next_rx,
    })

    # Step 2: Receive seq 7 again — duplicate in ring
    env7dup = make_envelope(7, "msg-7-dup")
    accepted, reason, delivered, ring, next_rx = sim_receive(ring, next_rx, 7)
    scenario_0_steps.append({
        "step": 2,
        "incoming_sequence": 7,
        "envelope_raw_hex": env7dup.hex(),
        "accepted": accepted,
        "reason": reason,
        "delivered_sequences": delivered,
        "ring_after": list(ring),
        "next_rx_after": next_rx,
    })

    # Step 3: Receive seq 5 again — old sequence (already delivered, next_rx=6)
    env5old = make_envelope(5, "msg-5-old")
    accepted, reason, delivered, ring, next_rx = sim_receive(ring, next_rx, 5)
    scenario_0_steps.append({
        "step": 3,
        "incoming_sequence": 5,
        "envelope_raw_hex": env5old.hex(),
        "accepted": accepted,
        "reason": reason,
        "delivered_sequences": delivered,
        "ring_after": list(ring),
        "next_rx_after": next_rx,
    })

    vectors.append({
        "index": 0,
        "description": "Basic duplicate rejection: in-ring duplicate and post-delivery old sequence",
        "initial_state": {"ring": [], "next_rx_sequence": 5},
        "steps": scenario_0_steps,
    })

    # === Scenario 1: Out-of-order with in-order delivery ===
    # Messages arrive as seq 2, 0, 1 → delivered 0, 1, 2
    scenario_1_steps = []
    ring = []
    next_rx = 0

    # Step 0: Receive seq 2 — buffered, not delivered
    env = make_envelope(2, "msg-2")
    accepted, reason, delivered, ring, next_rx = sim_receive(ring, next_rx, 2)
    scenario_1_steps.append({
        "step": 0,
        "incoming_sequence": 2,
        "envelope_raw_hex": env.hex(),
        "accepted": accepted,
        "reason": reason,
        "delivered_sequences": delivered,
        "ring_after": list(ring),
        "next_rx_after": next_rx,
    })

    # Step 1: Receive seq 0 — delivered immediately
    env = make_envelope(0, "msg-0")
    accepted, reason, delivered, ring, next_rx = sim_receive(ring, next_rx, 0)
    scenario_1_steps.append({
        "step": 1,
        "incoming_sequence": 0,
        "envelope_raw_hex": env.hex(),
        "accepted": accepted,
        "reason": reason,
        "delivered_sequences": delivered,
        "ring_after": list(ring),
        "next_rx_after": next_rx,
    })

    # Step 2: Receive seq 1 — triggers delivery of 1 and buffered 2
    env = make_envelope(1, "msg-1")
    accepted, reason, delivered, ring, next_rx = sim_receive(ring, next_rx, 1)
    scenario_1_steps.append({
        "step": 2,
        "incoming_sequence": 1,
        "envelope_raw_hex": env.hex(),
        "accepted": accepted,
        "reason": reason,
        "delivered_sequences": delivered,
        "ring_after": list(ring),
        "next_rx_after": next_rx,
    })

    vectors.append({
        "index": 1,
        "description": "Out-of-order arrival (2,0,1) with contiguous in-order delivery",
        "initial_state": {"ring": [], "next_rx_sequence": 0},
        "steps": scenario_1_steps,
    })

    # === Scenario 2: Gap with partial delivery ===
    # Receive 0, 1, 3, 4 — delivers 0,1 then buffers 3,4; receive 2 → delivers 2,3,4
    scenario_2_steps = []
    ring = []
    next_rx = 0

    for seq in [0, 1, 3, 4]:
        env = make_envelope(seq, f"msg-{seq}")
        accepted, reason, delivered, ring, next_rx = sim_receive(ring, next_rx, seq)
        scenario_2_steps.append({
            "step": len(scenario_2_steps),
            "incoming_sequence": seq,
            "envelope_raw_hex": env.hex(),
            "accepted": accepted,
            "reason": reason,
            "delivered_sequences": delivered,
            "ring_after": list(ring),
            "next_rx_after": next_rx,
        })

    # Now receive seq 2 — fills the gap, delivers 2, 3, 4
    env = make_envelope(2, "msg-2")
    accepted, reason, delivered, ring, next_rx = sim_receive(ring, next_rx, 2)
    scenario_2_steps.append({
        "step": len(scenario_2_steps),
        "incoming_sequence": 2,
        "envelope_raw_hex": env.hex(),
        "accepted": accepted,
        "reason": reason,
        "delivered_sequences": delivered,
        "ring_after": list(ring),
        "next_rx_after": next_rx,
    })

    vectors.append({
        "index": 2,
        "description": "Gap with partial delivery: 0,1 delivered; 3,4 buffered; 2 fills gap delivering 2,3,4",
        "initial_state": {"ring": [], "next_rx_sequence": 0},
        "steps": scenario_2_steps,
    })

    # === Scenario 3: Wraparound during contiguous delivery ===
    # next_rx starts at 65534, receive 65534, 65535, 0 — all delivered contiguously
    scenario_3_steps = []
    ring = []
    next_rx = 65534

    for seq in [65534, 65535, 0]:
        env = make_envelope(seq, f"msg-{seq}")
        accepted, reason, delivered, ring, next_rx = sim_receive(ring, next_rx, seq)
        scenario_3_steps.append({
            "step": len(scenario_3_steps),
            "incoming_sequence": seq,
            "envelope_raw_hex": env.hex(),
            "accepted": accepted,
            "reason": reason,
            "delivered_sequences": delivered,
            "ring_after": list(ring),
            "next_rx_after": next_rx,
        })

    vectors.append({
        "index": 3,
        "description": "Wraparound during contiguous delivery: seq 65534,65535,0 delivered across boundary",
        "initial_state": {"ring": [], "next_rx_sequence": 65534},
        "steps": scenario_3_steps,
    })

    # === Scenario 4: Duplicate across wraparound boundary ===
    # Start at next_rx=65534, deliver 65534,65535,0,1 → next_rx=2
    # Then try old sequences from both sides of the boundary
    scenario_4_steps = []
    ring = []
    next_rx = 65534

    for seq in [65534, 65535, 0, 1]:
        env = make_envelope(seq, f"msg-{seq}")
        accepted, reason, delivered, ring, next_rx = sim_receive(ring, next_rx, seq)
        scenario_4_steps.append({
            "step": len(scenario_4_steps),
            "incoming_sequence": seq,
            "envelope_raw_hex": env.hex(),
            "accepted": accepted,
            "reason": reason,
            "delivered_sequences": delivered,
            "ring_after": list(ring),
            "next_rx_after": next_rx,
        })

    # Try old seq 65535 (pre-wraparound) — should be rejected
    env = make_envelope(65535, "msg-65535-old")
    accepted, reason, delivered, ring, next_rx = sim_receive(ring, next_rx, 65535)
    scenario_4_steps.append({
        "step": len(scenario_4_steps),
        "incoming_sequence": 65535,
        "envelope_raw_hex": env.hex(),
        "accepted": accepted,
        "reason": reason,
        "delivered_sequences": delivered,
        "ring_after": list(ring),
        "next_rx_after": next_rx,
    })

    # Try old seq 0 (post-wraparound) — should be rejected
    env = make_envelope(0, "msg-0-old")
    accepted, reason, delivered, ring, next_rx = sim_receive(ring, next_rx, 0)
    scenario_4_steps.append({
        "step": len(scenario_4_steps),
        "incoming_sequence": 0,
        "envelope_raw_hex": env.hex(),
        "accepted": accepted,
        "reason": reason,
        "delivered_sequences": delivered,
        "ring_after": list(ring),
        "next_rx_after": next_rx,
    })

    vectors.append({
        "index": 4,
        "description": "Duplicate across wraparound: deliver 65534-1, then reject old 65535 and old 0",
        "initial_state": {"ring": [], "next_rx_sequence": 65534},
        "steps": scenario_4_steps,
    })

    # === Scenario 5: Ring ordering verification ===
    # Insert 6 out-of-order sequences, verify ring stays sorted
    scenario_5_steps = []
    ring = []
    next_rx = 10

    for seq in [15, 12, 18, 10, 14, 11]:
        env = make_envelope(seq, f"msg-{seq}")
        accepted, reason, delivered, ring, next_rx = sim_receive(ring, next_rx, seq)
        scenario_5_steps.append({
            "step": len(scenario_5_steps),
            "incoming_sequence": seq,
            "envelope_raw_hex": env.hex(),
            "accepted": accepted,
            "reason": reason,
            "delivered_sequences": delivered,
            "ring_after": list(ring),
            "next_rx_after": next_rx,
        })

    vectors.append({
        "index": 5,
        "description": "Ring ordering: 6 out-of-order inserts maintain sorted ring with contiguous delivery",
        "initial_state": {"ring": [], "next_rx_sequence": 10},
        "steps": scenario_5_steps,
    })

    # === Scenario 6: Extended TX progression across wraparound ===
    # 12 sends crossing 65535→0 boundary
    scenario_6_steps = []
    tx_seq = 65530

    for i in range(12):
        env = make_envelope(tx_seq, f"tx-msg-{i}")
        scenario_6_steps.append({
            "step": i,
            "tx_sequence": tx_seq,
            "envelope_raw_hex": env.hex(),
            "next_tx_sequence": (tx_seq + 1) % SEQ_MODULUS,
        })
        tx_seq = (tx_seq + 1) % SEQ_MODULUS

    vectors.append({
        "index": 6,
        "type": "tx_wraparound_progression",
        "description": "Extended TX progression: 12 sends from seq 65530, crossing 65535→0 boundary",
        "initial_tx_sequence": 65530,
        "steps": scenario_6_steps,
        "final_tx_sequence": tx_seq,
    })

    # === Scenario 7: Wraparound-aware ring ordering ===
    # next_rx near SEQ_MAX, out-of-order arrivals spanning the boundary
    scenario_7_steps = []
    ring = []
    next_rx = 65533

    # Receive: 0 (wrapped), 65535, 65534, 65533 — ring should order correctly
    for seq in [0, 65535, 65534, 65533]:
        env = make_envelope(seq, f"msg-{seq}")
        accepted, reason, delivered, ring, next_rx = sim_receive(ring, next_rx, seq)
        scenario_7_steps.append({
            "step": len(scenario_7_steps),
            "incoming_sequence": seq,
            "envelope_raw_hex": env.hex(),
            "accepted": accepted,
            "reason": reason,
            "delivered_sequences": delivered,
            "ring_after": list(ring),
            "next_rx_after": next_rx,
        })

    vectors.append({
        "index": 7,
        "description": "Wraparound-aware ring ordering: next_rx=65533, arrivals 0,65535,65534,65533 sort correctly",
        "initial_state": {"ring": [], "next_rx_sequence": 65533},
        "steps": scenario_7_steps,
    })

    return vectors


def extract_retry_sequence_vectors():
    """Generate full retry lifecycle test vectors.

    Each vector traces a single message from initial send through escalating
    timeouts to either exhaustion (fail) or successful delivery (delivered).
    Uses sim_timeout_retry_step() and sim_delivery_step() to replicate
    Channel._packet_timeout() and Channel._packet_tx_op() logic.

    6 vectors covering:
      0: Full retry to exhaustion, slow link
      1: Retry with delivery mid-sequence
      2: Retry exhaustion, fast link
      3: Retry with window_max shrink
      4: Retry on very slow link (all clamped)
      5: Single timeout then delivery
    """
    vectors = []

    # --- Vector 0: Full retry to exhaustion, slow link (RTT=0.5, ring=1) ---
    rtt = 0.5
    tx_ring_length = 1
    window = 3
    window_max = WINDOW_MAX_SLOW  # 5
    window_min = WINDOW_MIN  # 2
    window_flexibility = WINDOW_FLEXIBILITY  # 4
    tries = 0
    steps = []

    initial_state = {
        "tries": tries, "rtt": rtt, "tx_ring_length": tx_ring_length,
        "window": window, "window_max": window_max, "window_min": window_min,
        "window_flexibility": window_flexibility,
    }

    for step_idx in range(MAX_TRIES + 1):  # up to 6 attempts to show the fail
        w_before = window
        wm_before = window_max
        t_before = tries
        outcome, tries, timeout, window, window_max = sim_timeout_retry_step(
            tries, rtt, tx_ring_length, window, window_max, window_min, window_flexibility)

        step = {
            "step": step_idx,
            "event": "timeout",
            "tries_before": t_before,
            "tries_after": tries,
            "window_before": w_before,
            "window_after": window,
            "window_max_before": wm_before,
            "window_max_after": window_max,
            "tx_ring_length": tx_ring_length,
            "outcome": outcome,
        }
        if timeout is not None:
            step["timeout"] = round(timeout, 10)
            step["timeout_breakdown"] = {
                "exponential_factor": round(pow(1.5, tries - 1), 10),
                "rtt_factor": round(max(rtt * 2.5, 0.025), 10),
                "ring_factor": round(tx_ring_length + 1.5, 10),
            }
        steps.append(step)
        if outcome == "fail":
            break

    vectors.append({
        "index": 0,
        "description": "Full retry to exhaustion on slow link (RTT=0.5, tx_ring=1)",
        "initial_state": initial_state,
        "steps": steps,
        "final_state": {
            "tries": tries, "window": window, "window_max": window_max,
            "outcome": "fail",
        },
    })

    # --- Vector 1: Retry with delivery mid-sequence (RTT=0.1, ring=1) ---
    rtt = 0.1
    tx_ring_length = 1
    window = 3
    window_max = WINDOW_MAX_SLOW  # 5
    window_min = WINDOW_MIN  # 2
    window_flexibility = WINDOW_FLEXIBILITY  # 4
    fast_rate_rounds = 0
    medium_rate_rounds = 0
    tries = 0
    steps = []

    initial_state = {
        "tries": tries, "rtt": rtt, "tx_ring_length": tx_ring_length,
        "window": window, "window_max": window_max, "window_min": window_min,
        "window_flexibility": window_flexibility,
        "fast_rate_rounds": fast_rate_rounds, "medium_rate_rounds": medium_rate_rounds,
    }

    # Step 0: First timeout
    w_before, wm_before, t_before = window, window_max, tries
    outcome, tries, timeout, window, window_max = sim_timeout_retry_step(
        tries, rtt, tx_ring_length, window, window_max, window_min, window_flexibility)
    steps.append({
        "step": 0, "event": "timeout",
        "tries_before": t_before, "tries_after": tries,
        "window_before": w_before, "window_after": window,
        "window_max_before": wm_before, "window_max_after": window_max,
        "tx_ring_length": tx_ring_length, "outcome": outcome,
        "timeout": round(timeout, 10),
        "timeout_breakdown": {
            "exponential_factor": round(pow(1.5, tries - 1), 10),
            "rtt_factor": round(max(rtt * 2.5, 0.025), 10),
            "ring_factor": round(tx_ring_length + 1.5, 10),
        },
    })

    # Step 1: Delivery on retry (tx_ring shrinks by 1)
    w_before, wm_before = window, window_max
    fr_before, mr_before = fast_rate_rounds, medium_rate_rounds
    window, window_max, window_min, fast_rate_rounds, medium_rate_rounds, upgrade = sim_delivery_step(
        rtt, window, window_max, window_min, fast_rate_rounds, medium_rate_rounds)
    steps.append({
        "step": 1, "event": "delivery",
        "window_before": w_before, "window_after": window,
        "window_max_before": wm_before, "window_max_after": window_max,
        "fast_rate_rounds_before": fr_before, "fast_rate_rounds_after": fast_rate_rounds,
        "medium_rate_rounds_before": mr_before, "medium_rate_rounds_after": medium_rate_rounds,
        "upgrade_triggered": upgrade, "outcome": "delivered",
    })

    vectors.append({
        "index": 1,
        "description": "Retry with delivery mid-sequence (RTT=0.1, tx_ring=1): 1 timeout then delivery on retry",
        "initial_state": initial_state,
        "steps": steps,
        "final_state": {
            "tries": tries, "window": window, "window_max": window_max,
            "fast_rate_rounds": fast_rate_rounds, "medium_rate_rounds": medium_rate_rounds,
            "outcome": "delivered",
        },
    })

    # --- Vector 2: Retry exhaustion, fast link (RTT=0.01, ring=0) ---
    rtt = 0.01
    tx_ring_length = 0
    window = 2
    window_max = WINDOW_MAX_SLOW  # 5
    window_min = WINDOW_MIN  # 2
    window_flexibility = WINDOW_FLEXIBILITY
    tries = 0
    steps = []

    initial_state = {
        "tries": tries, "rtt": rtt, "tx_ring_length": tx_ring_length,
        "window": window, "window_max": window_max, "window_min": window_min,
        "window_flexibility": window_flexibility,
    }

    for step_idx in range(MAX_TRIES + 1):
        w_before, wm_before, t_before = window, window_max, tries
        outcome, tries, timeout, window, window_max = sim_timeout_retry_step(
            tries, rtt, tx_ring_length, window, window_max, window_min, window_flexibility)
        step = {
            "step": step_idx, "event": "timeout",
            "tries_before": t_before, "tries_after": tries,
            "window_before": w_before, "window_after": window,
            "window_max_before": wm_before, "window_max_after": window_max,
            "tx_ring_length": tx_ring_length, "outcome": outcome,
        }
        if timeout is not None:
            step["timeout"] = round(timeout, 10)
            step["timeout_breakdown"] = {
                "exponential_factor": round(pow(1.5, tries - 1), 10),
                "rtt_factor": round(max(rtt * 2.5, 0.025), 10),
                "ring_factor": round(tx_ring_length + 1.5, 10),
            }
        steps.append(step)
        if outcome == "fail":
            break

    vectors.append({
        "index": 2,
        "description": "Retry exhaustion on fast link (RTT=0.01, tx_ring=0): window already at min, exponential timeout escalation",
        "initial_state": initial_state,
        "steps": steps,
        "final_state": {
            "tries": tries, "window": window, "window_max": window_max,
            "outcome": "fail",
        },
    })

    # --- Vector 3: Retry with window_max shrink (RTT=0.3, ring=2, medium-upgraded) ---
    rtt = 0.3
    tx_ring_length = 2
    window = 8
    window_max = WINDOW_MAX_MEDIUM  # 12
    window_min = WINDOW_MIN_LIMIT_MEDIUM  # 5
    window_flexibility = WINDOW_FLEXIBILITY  # 4
    tries = 0
    steps = []

    initial_state = {
        "tries": tries, "rtt": rtt, "tx_ring_length": tx_ring_length,
        "window": window, "window_max": window_max, "window_min": window_min,
        "window_flexibility": window_flexibility,
    }

    for step_idx in range(MAX_TRIES + 1):
        w_before, wm_before, t_before = window, window_max, tries
        outcome, tries, timeout, window, window_max = sim_timeout_retry_step(
            tries, rtt, tx_ring_length, window, window_max, window_min, window_flexibility)
        step = {
            "step": step_idx, "event": "timeout",
            "tries_before": t_before, "tries_after": tries,
            "window_before": w_before, "window_after": window,
            "window_max_before": wm_before, "window_max_after": window_max,
            "tx_ring_length": tx_ring_length, "outcome": outcome,
        }
        if timeout is not None:
            step["timeout"] = round(timeout, 10)
            step["timeout_breakdown"] = {
                "exponential_factor": round(pow(1.5, tries - 1), 10),
                "rtt_factor": round(max(rtt * 2.5, 0.025), 10),
                "ring_factor": round(tx_ring_length + 1.5, 10),
            }
        steps.append(step)
        if outcome == "fail":
            break

    vectors.append({
        "index": 3,
        "description": "Retry with window_max shrink (RTT=0.3, tx_ring=2): medium-upgraded link, window_max shrinks then hits floor",
        "initial_state": initial_state,
        "steps": steps,
        "final_state": {
            "tries": tries, "window": window, "window_max": window_max,
            "outcome": "fail",
        },
    })

    # --- Vector 4: Retry on very slow link (RTT=2.0) ---
    rtt = 2.0
    tx_ring_length = 0
    window = 1
    window_max = 1
    window_min = 1
    window_flexibility = 1
    tries = 0
    steps = []

    initial_state = {
        "tries": tries, "rtt": rtt, "tx_ring_length": tx_ring_length,
        "window": window, "window_max": window_max, "window_min": window_min,
        "window_flexibility": window_flexibility,
    }

    for step_idx in range(MAX_TRIES + 1):
        w_before, wm_before, t_before = window, window_max, tries
        outcome, tries, timeout, window, window_max = sim_timeout_retry_step(
            tries, rtt, tx_ring_length, window, window_max, window_min, window_flexibility)
        step = {
            "step": step_idx, "event": "timeout",
            "tries_before": t_before, "tries_after": tries,
            "window_before": w_before, "window_after": window,
            "window_max_before": wm_before, "window_max_after": window_max,
            "tx_ring_length": tx_ring_length, "outcome": outcome,
        }
        if timeout is not None:
            step["timeout"] = round(timeout, 10)
            step["timeout_breakdown"] = {
                "exponential_factor": round(pow(1.5, tries - 1), 10),
                "rtt_factor": round(max(rtt * 2.5, 0.025), 10),
                "ring_factor": round(tx_ring_length + 1.5, 10),
            }
        steps.append(step)
        if outcome == "fail":
            break

    vectors.append({
        "index": 4,
        "description": "Retry on very slow link (RTT=2.0): window=1/max=1/min=1, all clamped, extreme timeout values",
        "initial_state": initial_state,
        "steps": steps,
        "final_state": {
            "tries": tries, "window": window, "window_max": window_max,
            "outcome": "fail",
        },
    })

    # --- Vector 5: Single timeout then delivery (RTT=0.5, ring=3) ---
    rtt = 0.5
    tx_ring_length = 3
    window = 4
    window_max = WINDOW_MAX_SLOW  # 5
    window_min = WINDOW_MIN  # 2
    window_flexibility = WINDOW_FLEXIBILITY
    fast_rate_rounds = 0
    medium_rate_rounds = 0
    tries = 0
    steps = []

    initial_state = {
        "tries": tries, "rtt": rtt, "tx_ring_length": tx_ring_length,
        "window": window, "window_max": window_max, "window_min": window_min,
        "window_flexibility": window_flexibility,
        "fast_rate_rounds": fast_rate_rounds, "medium_rate_rounds": medium_rate_rounds,
    }

    # Step 0: Timeout
    w_before, wm_before, t_before = window, window_max, tries
    outcome, tries, timeout, window, window_max = sim_timeout_retry_step(
        tries, rtt, tx_ring_length, window, window_max, window_min, window_flexibility)
    steps.append({
        "step": 0, "event": "timeout",
        "tries_before": t_before, "tries_after": tries,
        "window_before": w_before, "window_after": window,
        "window_max_before": wm_before, "window_max_after": window_max,
        "tx_ring_length": tx_ring_length, "outcome": outcome,
        "timeout": round(timeout, 10),
        "timeout_breakdown": {
            "exponential_factor": round(pow(1.5, tries - 1), 10),
            "rtt_factor": round(max(rtt * 2.5, 0.025), 10),
            "ring_factor": round(tx_ring_length + 1.5, 10),
        },
    })

    # Step 1: Delivery
    w_before, wm_before = window, window_max
    fr_before, mr_before = fast_rate_rounds, medium_rate_rounds
    window, window_max, window_min, fast_rate_rounds, medium_rate_rounds, upgrade = sim_delivery_step(
        rtt, window, window_max, window_min, fast_rate_rounds, medium_rate_rounds)
    steps.append({
        "step": 1, "event": "delivery",
        "window_before": w_before, "window_after": window,
        "window_max_before": wm_before, "window_max_after": window_max,
        "fast_rate_rounds_before": fr_before, "fast_rate_rounds_after": fast_rate_rounds,
        "medium_rate_rounds_before": mr_before, "medium_rate_rounds_after": medium_rate_rounds,
        "upgrade_triggered": upgrade, "outcome": "delivered",
    })

    vectors.append({
        "index": 5,
        "description": "Single timeout then delivery (RTT=0.5, tx_ring=3): quick recovery, shows tx_ring_length effect",
        "initial_state": initial_state,
        "steps": steps,
        "final_state": {
            "tries": tries, "window": window, "window_max": window_max,
            "fast_rate_rounds": fast_rate_rounds, "medium_rate_rounds": medium_rate_rounds,
            "outcome": "delivered",
        },
    })

    return vectors


def extract_window_adaptation_sequence_vectors():
    """Generate multi-step window adaptation sequence vectors.

    Each vector traces window state evolution over a sequence of deliveries
    and/or timeouts, using sim_delivery_step() and sim_timeout_retry_step().

    5 vectors covering:
      0: 12 fast deliveries triggering SLOW→FAST upgrade
      1: 12 medium deliveries triggering SLOW→MEDIUM upgrade
      2: Mixed delivery/timeout oscillation (8 steps)
      3: Timeout cascade to minimum (5 steps)
      4: RTT transition: fast→slow→fast (10 steps)
    """
    vectors = []

    # --- Vector 0: 12 fast deliveries, SLOW→FAST upgrade ---
    window = WINDOW  # 2
    window_max = WINDOW_MAX_SLOW  # 5
    window_min = WINDOW_MIN  # 2
    fast_rate_rounds = 0
    medium_rate_rounds = 0
    rtt = 0.05  # fast
    steps = []

    initial_state = {
        "window": window, "window_max": window_max, "window_min": window_min,
        "fast_rate_rounds": fast_rate_rounds, "medium_rate_rounds": medium_rate_rounds,
    }

    for i in range(12):
        w_before, wm_before, wmin_before = window, window_max, window_min
        fr_before, mr_before = fast_rate_rounds, medium_rate_rounds
        window, window_max, window_min, fast_rate_rounds, medium_rate_rounds, upgrade = sim_delivery_step(
            rtt, window, window_max, window_min, fast_rate_rounds, medium_rate_rounds)
        steps.append({
            "step": i, "event": "delivery", "rtt": rtt,
            "window_before": w_before, "window_after": window,
            "window_max_before": wm_before, "window_max_after": window_max,
            "window_min_before": wmin_before, "window_min_after": window_min,
            "fast_rate_rounds_before": fr_before, "fast_rate_rounds_after": fast_rate_rounds,
            "medium_rate_rounds_before": mr_before, "medium_rate_rounds_after": medium_rate_rounds,
            "upgrade_triggered": upgrade,
        })

    vectors.append({
        "index": 0,
        "description": "12 fast deliveries (RTT=0.05): SLOW→FAST upgrade at step 9",
        "initial_state": initial_state,
        "rtt": rtt,
        "steps": steps,
        "final_state": {
            "window": window, "window_max": window_max, "window_min": window_min,
            "fast_rate_rounds": fast_rate_rounds, "medium_rate_rounds": medium_rate_rounds,
        },
    })

    # --- Vector 1: 12 medium deliveries, SLOW→MEDIUM upgrade ---
    window = WINDOW  # 2
    window_max = WINDOW_MAX_SLOW  # 5
    window_min = WINDOW_MIN  # 2
    fast_rate_rounds = 0
    medium_rate_rounds = 0
    rtt = 0.5  # medium (RTT_FAST < 0.5 <= RTT_MEDIUM)
    steps = []

    initial_state = {
        "window": window, "window_max": window_max, "window_min": window_min,
        "fast_rate_rounds": fast_rate_rounds, "medium_rate_rounds": medium_rate_rounds,
    }

    for i in range(12):
        w_before, wm_before, wmin_before = window, window_max, window_min
        fr_before, mr_before = fast_rate_rounds, medium_rate_rounds
        window, window_max, window_min, fast_rate_rounds, medium_rate_rounds, upgrade = sim_delivery_step(
            rtt, window, window_max, window_min, fast_rate_rounds, medium_rate_rounds)
        steps.append({
            "step": i, "event": "delivery", "rtt": rtt,
            "window_before": w_before, "window_after": window,
            "window_max_before": wm_before, "window_max_after": window_max,
            "window_min_before": wmin_before, "window_min_after": window_min,
            "fast_rate_rounds_before": fr_before, "fast_rate_rounds_after": fast_rate_rounds,
            "medium_rate_rounds_before": mr_before, "medium_rate_rounds_after": medium_rate_rounds,
            "upgrade_triggered": upgrade,
        })

    vectors.append({
        "index": 1,
        "description": "12 medium deliveries (RTT=0.5): SLOW→MEDIUM upgrade at step 9",
        "initial_state": initial_state,
        "rtt": rtt,
        "steps": steps,
        "final_state": {
            "window": window, "window_max": window_max, "window_min": window_min,
            "fast_rate_rounds": fast_rate_rounds, "medium_rate_rounds": medium_rate_rounds,
        },
    })

    # --- Vector 2: Mixed delivery/timeout oscillation (8 steps) ---
    window = 3
    window_max = WINDOW_MAX_SLOW  # 5
    window_min = WINDOW_MIN  # 2
    window_flexibility = WINDOW_FLEXIBILITY
    fast_rate_rounds = 0
    medium_rate_rounds = 0
    rtt = 0.5
    tx_ring_length = 1
    tries = 0
    steps = []

    initial_state = {
        "window": window, "window_max": window_max, "window_min": window_min,
        "window_flexibility": window_flexibility,
        "fast_rate_rounds": fast_rate_rounds, "medium_rate_rounds": medium_rate_rounds,
    }

    # Alternate: deliver, deliver, timeout, deliver, timeout, deliver, timeout, deliver
    events = ["delivery", "delivery", "timeout", "delivery", "timeout", "delivery", "timeout", "delivery"]

    for i, event in enumerate(events):
        if event == "delivery":
            w_before, wm_before, wmin_before = window, window_max, window_min
            fr_before, mr_before = fast_rate_rounds, medium_rate_rounds
            window, window_max, window_min, fast_rate_rounds, medium_rate_rounds, upgrade = sim_delivery_step(
                rtt, window, window_max, window_min, fast_rate_rounds, medium_rate_rounds)
            steps.append({
                "step": i, "event": "delivery", "rtt": rtt,
                "window_before": w_before, "window_after": window,
                "window_max_before": wm_before, "window_max_after": window_max,
                "window_min_before": wmin_before, "window_min_after": window_min,
                "fast_rate_rounds_before": fr_before, "fast_rate_rounds_after": fast_rate_rounds,
                "medium_rate_rounds_before": mr_before, "medium_rate_rounds_after": medium_rate_rounds,
                "upgrade_triggered": upgrade,
            })
        else:  # timeout
            w_before, wm_before = window, window_max
            t_before = tries
            outcome, tries, timeout, window, window_max = sim_timeout_retry_step(
                tries, rtt, tx_ring_length, window, window_max, window_min, window_flexibility)
            steps.append({
                "step": i, "event": "timeout",
                "tries_before": t_before, "tries_after": tries,
                "window_before": w_before, "window_after": window,
                "window_max_before": wm_before, "window_max_after": window_max,
                "tx_ring_length": tx_ring_length, "outcome": outcome,
                "timeout": round(timeout, 10) if timeout is not None else None,
            })

    vectors.append({
        "index": 2,
        "description": "Mixed delivery/timeout oscillation (8 steps, RTT=0.5): window grows on delivery, shrinks on timeout",
        "initial_state": initial_state,
        "rtt": rtt,
        "steps": steps,
        "final_state": {
            "window": window, "window_max": window_max, "window_min": window_min,
            "fast_rate_rounds": fast_rate_rounds, "medium_rate_rounds": medium_rate_rounds,
        },
    })

    # --- Vector 3: Timeout cascade to minimum (5 steps) ---
    window = 8
    window_max = WINDOW_MAX_MEDIUM  # 12
    window_min = WINDOW_MIN_LIMIT_MEDIUM  # 5
    window_flexibility = WINDOW_FLEXIBILITY  # 4
    rtt = 0.3
    tx_ring_length = 2
    tries = 0
    steps = []

    initial_state = {
        "window": window, "window_max": window_max, "window_min": window_min,
        "window_flexibility": window_flexibility,
    }

    for i in range(5):
        w_before, wm_before = window, window_max
        t_before = tries
        outcome, tries, timeout, window, window_max = sim_timeout_retry_step(
            tries, rtt, tx_ring_length, window, window_max, window_min, window_flexibility)
        steps.append({
            "step": i, "event": "timeout",
            "tries_before": t_before, "tries_after": tries,
            "window_before": w_before, "window_after": window,
            "window_max_before": wm_before, "window_max_after": window_max,
            "tx_ring_length": tx_ring_length, "outcome": outcome,
            "timeout": round(timeout, 10) if timeout is not None else None,
        })
        if outcome == "fail":
            break

    vectors.append({
        "index": 3,
        "description": "Timeout cascade to minimum (5 steps, RTT=0.3): window shrinks 8→5 (clamped), window_max shrinks 12→9",
        "initial_state": initial_state,
        "rtt": rtt,
        "steps": steps,
        "final_state": {
            "window": window, "window_max": window_max,
        },
    })

    # --- Vector 4: RTT transition fast→slow→fast (10 steps) ---
    window = WINDOW  # 2
    window_max = WINDOW_MAX_SLOW  # 5
    window_min = WINDOW_MIN  # 2
    fast_rate_rounds = 0
    medium_rate_rounds = 0
    steps = []

    initial_state = {
        "window": window, "window_max": window_max, "window_min": window_min,
        "fast_rate_rounds": fast_rate_rounds, "medium_rate_rounds": medium_rate_rounds,
    }

    # 4 fast, 2 slow, 4 fast
    rtt_sequence = [0.05, 0.05, 0.05, 0.05, 1.0, 1.0, 0.05, 0.05, 0.05, 0.05]

    for i, rtt in enumerate(rtt_sequence):
        w_before, wm_before, wmin_before = window, window_max, window_min
        fr_before, mr_before = fast_rate_rounds, medium_rate_rounds
        window, window_max, window_min, fast_rate_rounds, medium_rate_rounds, upgrade = sim_delivery_step(
            rtt, window, window_max, window_min, fast_rate_rounds, medium_rate_rounds)
        steps.append({
            "step": i, "event": "delivery", "rtt": rtt,
            "window_before": w_before, "window_after": window,
            "window_max_before": wm_before, "window_max_after": window_max,
            "window_min_before": wmin_before, "window_min_after": window_min,
            "fast_rate_rounds_before": fr_before, "fast_rate_rounds_after": fast_rate_rounds,
            "medium_rate_rounds_before": mr_before, "medium_rate_rounds_after": medium_rate_rounds,
            "upgrade_triggered": upgrade,
            "note": f"{'fast' if rtt <= RTT_FAST else 'slow'} RTT",
        })

    vectors.append({
        "index": 4,
        "description": "RTT transition fast→slow→fast (10 deliveries): slow resets rate counters, fast accumulation restarts",
        "initial_state": initial_state,
        "rtt_sequence": rtt_sequence,
        "steps": steps,
        "final_state": {
            "window": window, "window_max": window_max, "window_min": window_min,
            "fast_rate_rounds": fast_rate_rounds, "medium_rate_rounds": medium_rate_rounds,
        },
    })

    return vectors


def extract_packet_loss_scenario_vectors():
    """Generate combined retry + window adaptation test vectors with multiple in-flight messages.

    Simulates realistic scenarios where multiple messages are sent and some
    experience packet loss (timeouts) while others are delivered successfully.

    4 vectors covering:
      0: 5 messages, #2 and #4 time out then retry
      1: Burst loss: 3 of 5 timeout
      2: Interleaved send-deliver on fast link with 1 loss
      3: Total loss: all messages exhaust retries
    """
    vectors = []

    # --- Vector 0: 5 messages, #2 and #4 time out ---
    rtt = 0.5
    window = 4
    window_max = WINDOW_MAX_SLOW  # 5
    window_min = WINDOW_MIN  # 2
    window_flexibility = WINDOW_FLEXIBILITY
    fast_rate_rounds = 0
    medium_rate_rounds = 0
    events = []

    initial_state = {
        "rtt": rtt, "window": window, "window_max": window_max,
        "window_min": window_min, "window_flexibility": window_flexibility,
        "fast_rate_rounds": fast_rate_rounds, "medium_rate_rounds": medium_rate_rounds,
    }

    # Track per-message state: {seq: tries}
    msg_tries = {}
    tx_ring = []  # list of seqs currently in flight

    # Send 5 messages
    for seq in range(5):
        tx_ring.append(seq)
        msg_tries[seq] = 0
        events.append({
            "event": "send", "sequence": seq,
            "tx_ring": list(tx_ring), "tx_ring_length": len(tx_ring),
            "window": window, "window_max": window_max,
        })

    # Deliver 0 on time
    seq = 0
    tx_ring.remove(seq)
    w_before, wm_before = window, window_max
    fr_before, mr_before = fast_rate_rounds, medium_rate_rounds
    window, window_max, window_min, fast_rate_rounds, medium_rate_rounds, upgrade = sim_delivery_step(
        rtt, window, window_max, window_min, fast_rate_rounds, medium_rate_rounds)
    events.append({
        "event": "delivery", "sequence": seq,
        "window_before": w_before, "window_after": window,
        "window_max_before": wm_before, "window_max_after": window_max,
        "tx_ring": list(tx_ring), "tx_ring_length": len(tx_ring),
        "upgrade_triggered": upgrade, "outcome": "delivered",
    })

    # Deliver 1 on time
    seq = 1
    tx_ring.remove(seq)
    w_before, wm_before = window, window_max
    fr_before, mr_before = fast_rate_rounds, medium_rate_rounds
    window, window_max, window_min, fast_rate_rounds, medium_rate_rounds, upgrade = sim_delivery_step(
        rtt, window, window_max, window_min, fast_rate_rounds, medium_rate_rounds)
    events.append({
        "event": "delivery", "sequence": seq,
        "window_before": w_before, "window_after": window,
        "window_max_before": wm_before, "window_max_after": window_max,
        "tx_ring": list(tx_ring), "tx_ring_length": len(tx_ring),
        "upgrade_triggered": upgrade, "outcome": "delivered",
    })

    # Timeout on #2
    seq = 2
    w_before, wm_before = window, window_max
    t_before = msg_tries[seq]
    outcome, msg_tries[seq], timeout, window, window_max = sim_timeout_retry_step(
        msg_tries[seq], rtt, len(tx_ring), window, window_max, window_min, window_flexibility)
    events.append({
        "event": "timeout", "sequence": seq,
        "tries_before": t_before, "tries_after": msg_tries[seq],
        "window_before": w_before, "window_after": window,
        "window_max_before": wm_before, "window_max_after": window_max,
        "tx_ring": list(tx_ring), "tx_ring_length": len(tx_ring),
        "timeout": round(timeout, 10) if timeout else None,
        "outcome": outcome,
    })

    # Deliver 3 on time
    seq = 3
    tx_ring.remove(seq)
    w_before, wm_before = window, window_max
    fr_before, mr_before = fast_rate_rounds, medium_rate_rounds
    window, window_max, window_min, fast_rate_rounds, medium_rate_rounds, upgrade = sim_delivery_step(
        rtt, window, window_max, window_min, fast_rate_rounds, medium_rate_rounds)
    events.append({
        "event": "delivery", "sequence": seq,
        "window_before": w_before, "window_after": window,
        "window_max_before": wm_before, "window_max_after": window_max,
        "tx_ring": list(tx_ring), "tx_ring_length": len(tx_ring),
        "upgrade_triggered": upgrade, "outcome": "delivered",
    })

    # Timeout on #4
    seq = 4
    w_before, wm_before = window, window_max
    t_before = msg_tries[seq]
    outcome, msg_tries[seq], timeout, window, window_max = sim_timeout_retry_step(
        msg_tries[seq], rtt, len(tx_ring), window, window_max, window_min, window_flexibility)
    events.append({
        "event": "timeout", "sequence": seq,
        "tries_before": t_before, "tries_after": msg_tries[seq],
        "window_before": w_before, "window_after": window,
        "window_max_before": wm_before, "window_max_after": window_max,
        "tx_ring": list(tx_ring), "tx_ring_length": len(tx_ring),
        "timeout": round(timeout, 10) if timeout else None,
        "outcome": outcome,
    })

    # Retry delivery for #2
    seq = 2
    tx_ring.remove(seq)
    w_before, wm_before = window, window_max
    fr_before, mr_before = fast_rate_rounds, medium_rate_rounds
    window, window_max, window_min, fast_rate_rounds, medium_rate_rounds, upgrade = sim_delivery_step(
        rtt, window, window_max, window_min, fast_rate_rounds, medium_rate_rounds)
    events.append({
        "event": "delivery", "sequence": seq,
        "window_before": w_before, "window_after": window,
        "window_max_before": wm_before, "window_max_after": window_max,
        "tx_ring": list(tx_ring), "tx_ring_length": len(tx_ring),
        "upgrade_triggered": upgrade, "outcome": "delivered",
        "note": "retry delivery",
    })

    # Retry delivery for #4
    seq = 4
    tx_ring.remove(seq)
    w_before, wm_before = window, window_max
    fr_before, mr_before = fast_rate_rounds, medium_rate_rounds
    window, window_max, window_min, fast_rate_rounds, medium_rate_rounds, upgrade = sim_delivery_step(
        rtt, window, window_max, window_min, fast_rate_rounds, medium_rate_rounds)
    events.append({
        "event": "delivery", "sequence": seq,
        "window_before": w_before, "window_after": window,
        "window_max_before": wm_before, "window_max_after": window_max,
        "tx_ring": list(tx_ring), "tx_ring_length": len(tx_ring),
        "upgrade_triggered": upgrade, "outcome": "delivered",
        "note": "retry delivery",
    })

    vectors.append({
        "index": 0,
        "description": "5 messages, #2 and #4 time out then retry-deliver: window oscillates",
        "initial_state": initial_state,
        "events": events,
        "final_state": {
            "window": window, "window_max": window_max,
            "tx_ring": list(tx_ring),
        },
    })

    # --- Vector 1: Burst loss, 3 of 5 timeout ---
    rtt = 0.3
    window = 4
    window_max = WINDOW_MAX_SLOW  # 5
    window_min = WINDOW_MIN  # 2
    window_flexibility = WINDOW_FLEXIBILITY
    fast_rate_rounds = 0
    medium_rate_rounds = 0
    events = []
    msg_tries = {}
    tx_ring = []

    initial_state = {
        "rtt": rtt, "window": window, "window_max": window_max,
        "window_min": window_min, "window_flexibility": window_flexibility,
        "fast_rate_rounds": fast_rate_rounds, "medium_rate_rounds": medium_rate_rounds,
    }

    # Send 5
    for seq in range(5):
        tx_ring.append(seq)
        msg_tries[seq] = 0
        events.append({
            "event": "send", "sequence": seq,
            "tx_ring": list(tx_ring), "tx_ring_length": len(tx_ring),
            "window": window, "window_max": window_max,
        })

    # Deliver 0
    seq = 0
    tx_ring.remove(seq)
    w_before, wm_before = window, window_max
    window, window_max, window_min, fast_rate_rounds, medium_rate_rounds, upgrade = sim_delivery_step(
        rtt, window, window_max, window_min, fast_rate_rounds, medium_rate_rounds)
    events.append({
        "event": "delivery", "sequence": seq,
        "window_before": w_before, "window_after": window,
        "window_max_before": wm_before, "window_max_after": window_max,
        "tx_ring": list(tx_ring), "tx_ring_length": len(tx_ring),
        "upgrade_triggered": upgrade, "outcome": "delivered",
    })

    # Deliver 1
    seq = 1
    tx_ring.remove(seq)
    w_before, wm_before = window, window_max
    window, window_max, window_min, fast_rate_rounds, medium_rate_rounds, upgrade = sim_delivery_step(
        rtt, window, window_max, window_min, fast_rate_rounds, medium_rate_rounds)
    events.append({
        "event": "delivery", "sequence": seq,
        "window_before": w_before, "window_after": window,
        "window_max_before": wm_before, "window_max_after": window_max,
        "tx_ring": list(tx_ring), "tx_ring_length": len(tx_ring),
        "upgrade_triggered": upgrade, "outcome": "delivered",
    })

    # Timeout 2, 3, 4 in sequence
    for seq in [2, 3, 4]:
        w_before, wm_before = window, window_max
        t_before = msg_tries[seq]
        outcome, msg_tries[seq], timeout, window, window_max = sim_timeout_retry_step(
            msg_tries[seq], rtt, len(tx_ring), window, window_max, window_min, window_flexibility)
        events.append({
            "event": "timeout", "sequence": seq,
            "tries_before": t_before, "tries_after": msg_tries[seq],
            "window_before": w_before, "window_after": window,
            "window_max_before": wm_before, "window_max_after": window_max,
            "tx_ring": list(tx_ring), "tx_ring_length": len(tx_ring),
            "timeout": round(timeout, 10) if timeout else None,
            "outcome": outcome,
        })

    # Retry delivers all 3
    for seq in [2, 3, 4]:
        tx_ring.remove(seq)
        w_before, wm_before = window, window_max
        window, window_max, window_min, fast_rate_rounds, medium_rate_rounds, upgrade = sim_delivery_step(
            rtt, window, window_max, window_min, fast_rate_rounds, medium_rate_rounds)
        events.append({
            "event": "delivery", "sequence": seq,
            "window_before": w_before, "window_after": window,
            "window_max_before": wm_before, "window_max_after": window_max,
            "tx_ring": list(tx_ring), "tx_ring_length": len(tx_ring),
            "upgrade_triggered": upgrade, "outcome": "delivered",
            "note": "retry delivery",
        })

    vectors.append({
        "index": 1,
        "description": "Burst loss: 3 of 5 timeout (RTT=0.3): window cascades down, retries eventually deliver",
        "initial_state": initial_state,
        "events": events,
        "final_state": {
            "window": window, "window_max": window_max,
            "tx_ring": list(tx_ring),
        },
    })

    # --- Vector 2: Interleaved send-deliver on fast link with 1 loss ---
    rtt = 0.05
    window = 2
    window_max = WINDOW_MAX_SLOW  # 5
    window_min = WINDOW_MIN  # 2
    window_flexibility = WINDOW_FLEXIBILITY
    fast_rate_rounds = 0
    medium_rate_rounds = 0
    events = []
    msg_tries = {}
    tx_ring = []

    initial_state = {
        "rtt": rtt, "window": window, "window_max": window_max,
        "window_min": window_min, "window_flexibility": window_flexibility,
        "fast_rate_rounds": fast_rate_rounds, "medium_rate_rounds": medium_rate_rounds,
    }

    # Send 0, deliver 0, send 1, deliver 1, send 2, timeout 2, send 3, deliver 3, deliver 2 (retry)
    # Send 0
    tx_ring.append(0)
    msg_tries[0] = 0
    events.append({
        "event": "send", "sequence": 0,
        "tx_ring": list(tx_ring), "tx_ring_length": len(tx_ring),
        "window": window, "window_max": window_max,
    })

    # Deliver 0
    tx_ring.remove(0)
    w_before, wm_before = window, window_max
    window, window_max, window_min, fast_rate_rounds, medium_rate_rounds, upgrade = sim_delivery_step(
        rtt, window, window_max, window_min, fast_rate_rounds, medium_rate_rounds)
    events.append({
        "event": "delivery", "sequence": 0,
        "window_before": w_before, "window_after": window,
        "window_max_before": wm_before, "window_max_after": window_max,
        "tx_ring": list(tx_ring), "tx_ring_length": len(tx_ring),
        "fast_rate_rounds": fast_rate_rounds,
        "upgrade_triggered": upgrade, "outcome": "delivered",
    })

    # Send 1
    tx_ring.append(1)
    msg_tries[1] = 0
    events.append({
        "event": "send", "sequence": 1,
        "tx_ring": list(tx_ring), "tx_ring_length": len(tx_ring),
        "window": window, "window_max": window_max,
    })

    # Deliver 1
    tx_ring.remove(1)
    w_before, wm_before = window, window_max
    window, window_max, window_min, fast_rate_rounds, medium_rate_rounds, upgrade = sim_delivery_step(
        rtt, window, window_max, window_min, fast_rate_rounds, medium_rate_rounds)
    events.append({
        "event": "delivery", "sequence": 1,
        "window_before": w_before, "window_after": window,
        "window_max_before": wm_before, "window_max_after": window_max,
        "tx_ring": list(tx_ring), "tx_ring_length": len(tx_ring),
        "fast_rate_rounds": fast_rate_rounds,
        "upgrade_triggered": upgrade, "outcome": "delivered",
    })

    # Send 2
    tx_ring.append(2)
    msg_tries[2] = 0
    events.append({
        "event": "send", "sequence": 2,
        "tx_ring": list(tx_ring), "tx_ring_length": len(tx_ring),
        "window": window, "window_max": window_max,
    })

    # Timeout 2
    w_before, wm_before = window, window_max
    t_before = msg_tries[2]
    outcome, msg_tries[2], timeout, window, window_max = sim_timeout_retry_step(
        msg_tries[2], rtt, len(tx_ring), window, window_max, window_min, window_flexibility)
    events.append({
        "event": "timeout", "sequence": 2,
        "tries_before": t_before, "tries_after": msg_tries[2],
        "window_before": w_before, "window_after": window,
        "window_max_before": wm_before, "window_max_after": window_max,
        "tx_ring": list(tx_ring), "tx_ring_length": len(tx_ring),
        "timeout": round(timeout, 10) if timeout else None,
        "outcome": outcome,
    })

    # Send 3
    tx_ring.append(3)
    msg_tries[3] = 0
    events.append({
        "event": "send", "sequence": 3,
        "tx_ring": list(tx_ring), "tx_ring_length": len(tx_ring),
        "window": window, "window_max": window_max,
    })

    # Deliver 3
    tx_ring.remove(3)
    w_before, wm_before = window, window_max
    window, window_max, window_min, fast_rate_rounds, medium_rate_rounds, upgrade = sim_delivery_step(
        rtt, window, window_max, window_min, fast_rate_rounds, medium_rate_rounds)
    events.append({
        "event": "delivery", "sequence": 3,
        "window_before": w_before, "window_after": window,
        "window_max_before": wm_before, "window_max_after": window_max,
        "tx_ring": list(tx_ring), "tx_ring_length": len(tx_ring),
        "fast_rate_rounds": fast_rate_rounds,
        "upgrade_triggered": upgrade, "outcome": "delivered",
    })

    # Deliver 2 (retry)
    tx_ring.remove(2)
    w_before, wm_before = window, window_max
    window, window_max, window_min, fast_rate_rounds, medium_rate_rounds, upgrade = sim_delivery_step(
        rtt, window, window_max, window_min, fast_rate_rounds, medium_rate_rounds)
    events.append({
        "event": "delivery", "sequence": 2,
        "window_before": w_before, "window_after": window,
        "window_max_before": wm_before, "window_max_after": window_max,
        "tx_ring": list(tx_ring), "tx_ring_length": len(tx_ring),
        "fast_rate_rounds": fast_rate_rounds,
        "upgrade_triggered": upgrade, "outcome": "delivered",
        "note": "retry delivery",
    })

    vectors.append({
        "index": 2,
        "description": "Interleaved send-deliver on fast link (RTT=0.05) with 1 loss: window grows then briefly shrinks",
        "initial_state": initial_state,
        "events": events,
        "final_state": {
            "window": window, "window_max": window_max,
            "fast_rate_rounds": fast_rate_rounds,
            "tx_ring": list(tx_ring),
        },
    })

    # --- Vector 3: Total loss, all messages exhaust retries ---
    rtt = 0.5
    window = 3
    window_max = WINDOW_MAX_SLOW  # 5
    window_min = WINDOW_MIN  # 2
    window_flexibility = WINDOW_FLEXIBILITY
    events = []
    msg_tries = {}
    tx_ring = []

    initial_state = {
        "rtt": rtt, "window": window, "window_max": window_max,
        "window_min": window_min, "window_flexibility": window_flexibility,
    }

    # Send 2 messages
    for seq in range(2):
        tx_ring.append(seq)
        msg_tries[seq] = 0
        events.append({
            "event": "send", "sequence": seq,
            "tx_ring": list(tx_ring), "tx_ring_length": len(tx_ring),
            "window": window, "window_max": window_max,
        })

    # Alternate timeouts on msg 0 and msg 1 until one hits max_tries
    # In Channel.py, retry_envelope() checks tries >= max_tries BEFORE incrementing.
    # So when tries reaches max_tries (5), the next timeout call returns "fail".
    shutdown = False
    while not shutdown:
        for seq in [0, 1]:
            w_before, wm_before = window, window_max
            t_before = msg_tries[seq]
            outcome, msg_tries[seq], timeout, window, window_max = sim_timeout_retry_step(
                msg_tries[seq], rtt, len(tx_ring), window, window_max, window_min, window_flexibility)
            events.append({
                "event": "timeout", "sequence": seq,
                "tries_before": t_before, "tries_after": msg_tries[seq],
                "window_before": w_before, "window_after": window,
                "window_max_before": wm_before, "window_max_after": window_max,
                "tx_ring": list(tx_ring), "tx_ring_length": len(tx_ring),
                "timeout": round(timeout, 10) if timeout else None,
                "outcome": outcome,
            })
            if outcome == "fail":
                shutdown = True
                break

    vectors.append({
        "index": 3,
        "description": "Total loss: 2 messages both exhaust retries, first triggers shutdown",
        "initial_state": initial_state,
        "events": events,
        "final_state": {
            "window": window, "window_max": window_max,
            "tx_ring": list(tx_ring),
            "outcome": "shutdown",
        },
    })

    return vectors


# ============================================================
# Verification
# ============================================================

def verify(output):
    """Cross-validate all vectors."""
    from RNS.vendor import umsgpack

    print("  Verifying...")

    # 1. Envelope round-trip
    for ev in output["envelope_vectors"]:
        raw = bytes.fromhex(ev["packed_hex"])
        mt, seq, length, data = envelope_unpack(raw)
        assert mt == ev["msgtype"], f"Envelope {ev['index']}: msgtype mismatch"
        assert seq == ev["sequence"], f"Envelope {ev['index']}: sequence mismatch"
        assert length == ev["data_length"], f"Envelope {ev['index']}: length mismatch"
        assert data.hex() == ev["data_hex"], f"Envelope {ev['index']}: data mismatch"
        # Verify re-pack
        repacked = envelope_pack(mt, seq, data)
        assert repacked == raw, f"Envelope {ev['index']}: repack mismatch"
    print(f"    [OK] {len(output['envelope_vectors'])} envelope vectors verified")

    # 2. Message serialization round-trip
    for mv in output["message_serialization_vectors"]:
        packed = bytes.fromhex(mv["packed_hex"])
        unpacked = umsgpack.unpackb(packed)
        if mv["index"] <= 1:
            assert list(unpacked) == mv["input_tuple"], f"Msg {mv['index']}: unpack mismatch"
        repacked = umsgpack.packb(unpacked)
        assert repacked == packed, f"Msg {mv['index']}: repack mismatch"
    print(f"    [OK] {len(output['message_serialization_vectors'])} message serialization vectors verified")

    # 3. Sequence number arithmetic
    for sv in output["sequence_number_vectors"]:
        if sv.get("type") != "rx_validation":
            curr = sv["current_seq"]
            expected_next = (curr + 1) % SEQ_MODULUS
            assert expected_next == sv["next_seq"], f"Seq {sv['index']}: next_seq mismatch"
    print(f"    [OK] {len(output['sequence_number_vectors'])} sequence number vectors verified")

    # 4. Stream data round-trip
    for sdv in output["stream_data_vectors"]:
        packed = bytes.fromhex(sdv["packed_hex"])
        sid, eof, comp, data = stream_data_unpack(packed)
        assert sid == sdv["stream_id"], f"Stream {sdv['index']}: stream_id mismatch"
        assert eof == sdv["eof"], f"Stream {sdv['index']}: eof mismatch"
        assert comp == sdv["compressed"], f"Stream {sdv['index']}: compressed mismatch"
        if not comp:
            assert data.hex() == sdv["data_hex"], f"Stream {sdv['index']}: data mismatch"
        else:
            assert data.hex() == sdv["original_data_hex"], f"Stream {sdv['index']}: decompressed data mismatch"
    print(f"    [OK] {len(output['stream_data_vectors'])} stream data vectors verified")

    # 5. Timeout formula verification
    for tv in output["timeout_vectors"]:
        computed = get_packet_timeout_time(tv["tries"], tv["rtt"], tv["tx_ring_length"])
        assert abs(computed - tv["timeout"]) < 1e-6, f"Timeout {tv['index']}: mismatch {computed} != {tv['timeout']}"
    print(f"    [OK] {len(output['timeout_vectors'])} timeout vectors verified")

    # 6. MDU computation
    for mv in output["mdu_vectors"]:
        expected = mv["outlet_mdu"] - 6
        if expected > 0xFFFF:
            expected = 0xFFFF
        assert expected == mv["channel_mdu"], f"MDU {mv['index']}: mismatch"
    print(f"    [OK] {len(output['mdu_vectors'])} MDU vectors verified")

    # 7. Round-trip integration
    for rv in output["round_trip_vectors"]:
        assert rv["verified"] is True, f"Round-trip {rv['index']}: verification failed"
    print(f"    [OK] {len(output['round_trip_vectors'])} round-trip vectors verified")

    # 8. Window adaptation logical consistency
    for wv in output["window_adaptation_vectors"]:
        if wv["event"] == "timeout":
            before = wv["before"]
            after = wv["after"]
            if before["window"] > before["window_min"]:
                assert after["window"] == before["window"] - 1, f"Window adapt {wv['index']}: window shrink failed"
            else:
                assert after["window"] == before["window"], f"Window adapt {wv['index']}: window should not shrink"

            flex = before["window_flexibility"]
            if before["window"] > before["window_min"] and before["window_max"] > (before["window_min"] + flex):
                assert after["window_max"] == before["window_max"] - 1, f"Window adapt {wv['index']}: window_max shrink failed"
            else:
                assert after["window_max"] == before["window_max"], f"Window adapt {wv['index']}: window_max should not shrink"
    print(f"    [OK] {len(output['window_adaptation_vectors'])} window adaptation vectors verified")

    # 9. System message boundaries
    for smv in output["system_message_vectors"]:
        is_sys = smv["msgtype"] >= SYSTEM_MSG_BOUNDARY
        assert is_sys == smv["is_system"], f"System msg {smv['msgtype_hex']}: boundary check failed"
    print(f"    [OK] {len(output['system_message_vectors'])} system message vectors verified")

    # 10. Send/receive vectors
    for srv in output["send_receive_vectors"]:
        vtype = srv["type"]

        if vtype == "tx_send_progression":
            steps = srv["steps"]
            assert len(steps) == 3, "tx_send_progression: expected 3 steps"
            for i, step in enumerate(steps):
                # Verify envelope decodes to correct msgtype/seq/data
                env_raw = bytes.fromhex(step["envelope_raw_hex"])
                dec_mt, dec_seq, dec_len, dec_data = envelope_unpack(env_raw)
                assert dec_mt == step["msgtype"], f"tx step {i}: msgtype mismatch"
                assert dec_seq == step["tx_sequence_before"], f"tx step {i}: sequence mismatch"
                assert dec_data.hex() == step["message_packed_hex"], f"tx step {i}: data mismatch"
                # Verify sequence increments
                assert step["tx_sequence_after"] == (step["tx_sequence_before"] + 1) % SEQ_MODULUS, \
                    f"tx step {i}: sequence increment wrong"
            assert srv["final_next_sequence"] == 3, "tx_send_progression: final sequence should be 3"

        elif vtype == "rx_receive_progression":
            steps = srv["steps"]
            assert len(steps) == 3, "rx_receive_progression: expected 3 steps"
            for i, step in enumerate(steps):
                env_raw = bytes.fromhex(step["envelope_raw_hex"])
                dec_mt, dec_seq, dec_len, dec_data = envelope_unpack(env_raw)
                assert dec_mt == step["decoded_msgtype"], f"rx step {i}: msgtype mismatch"
                assert dec_seq == step["decoded_sequence"], f"rx step {i}: sequence mismatch"
                # Verify rx_sequence advances
                assert step["rx_sequence_after"] == (step["rx_sequence_before"] + 1) % SEQ_MODULUS, \
                    f"rx step {i}: rx_sequence increment wrong"
            assert srv["final_next_rx_sequence"] == 3, "rx_receive_progression: final rx_sequence should be 3"

        elif vtype == "non_serialized_field_loss":
            packed = bytes.fromhex(srv["packed_hex"])
            unpacked = umsgpack.unpackb(packed)
            assert len(unpacked) == srv["unpacked_field_count"], f"non_serialized_field_loss: field count mismatch"
            assert srv["timestamp_preserved"] is False, "non_serialized_field_loss: timestamp should not be preserved"
            assert "timestamp" in srv["non_serialized_fields"], "non_serialized_field_loss: timestamp should be listed"

        elif vtype == "full_round_trip":
            assert srv["verified"] is True, f"send_receive full_round_trip {srv['index']}: verification failed"
            # Re-verify from envelope bytes
            env_raw = bytes.fromhex(srv["envelope_raw_hex"])
            dec_mt, dec_seq, dec_len, dec_data = envelope_unpack(env_raw)
            assert dec_mt == srv["decoded_msgtype"], f"send_receive full_round_trip {srv['index']}: msgtype mismatch"
            assert dec_seq == srv["decoded_sequence"], f"send_receive full_round_trip {srv['index']}: sequence mismatch"

    print(f"    [OK] {len(output['send_receive_vectors'])} send/receive vectors verified")

    # 11. Handler chaining vectors
    for hv in output["handler_chaining_vectors"]:
        # Verify envelope bytes decode correctly
        env_raw = bytes.fromhex(hv["message_envelope_hex"])
        dec_mt, dec_seq, dec_len, dec_data = envelope_unpack(env_raw)
        assert dec_mt == hv["message_msgtype"], f"Handler chain {hv['index']}: msgtype mismatch"

        # Verify expected_calls are in registration order (subset of handler names)
        handler_names = []
        for h in hv["handlers"]:
            if "duplicate" not in h["name"]:
                handler_names.append(h["name"])
        effective = hv.get("effective_handlers", handler_names)
        for i, call in enumerate(hv["expected_calls"]):
            assert call in effective, f"Handler chain {hv['index']}: expected call {call} not in effective handlers"
            if i > 0:
                prev_idx = effective.index(hv["expected_calls"][i - 1])
                curr_idx = effective.index(call)
                assert curr_idx > prev_idx, f"Handler chain {hv['index']}: calls not in registration order"

        # Verify short_circuit_handler consistency
        if hv["short_circuited"]:
            assert hv["short_circuit_handler"] is not None, f"Handler chain {hv['index']}: short-circuited but no handler"
            assert hv["short_circuit_handler"] == hv["expected_calls"][-1], \
                f"Handler chain {hv['index']}: short_circuit_handler should be last called handler"
            # The short-circuit handler must return truthy (True) — not raises
            sc_handler = next(h for h in hv["handlers"] if h["name"] == hv["short_circuit_handler"])
            assert sc_handler["returns"] is True, f"Handler chain {hv['index']}: short_circuit_handler must return True"
        else:
            assert hv["short_circuit_handler"] is None, f"Handler chain {hv['index']}: not short-circuited but has handler"

        assert hv["expected_call_count"] == len(hv["expected_calls"]), \
            f"Handler chain {hv['index']}: call count mismatch"
    print(f"    [OK] {len(output['handler_chaining_vectors'])} handler chaining vectors verified")

    # 12. Registration validation vectors
    for rv in output["registration_validation_vectors"]:
        if rv["expected_result"] == "success":
            assert rv["factory_registered"] is True, f"Reg validation {rv['index']}: success should register factory"
            assert rv["validation_gate"] is None, f"Reg validation {rv['index']}: success should have no gate"
            assert rv["ce_type"] is None, f"Reg validation {rv['index']}: success should have no ce_type"
        else:
            assert rv["expected_result"] == "raises", f"Reg validation {rv['index']}: unexpected result"
            assert rv["factory_registered"] is False, f"Reg validation {rv['index']}: raises should not register factory"
            assert rv["validation_gate"] is not None, f"Reg validation {rv['index']}: raises should have a gate"
            assert rv["ce_type"] == 1, f"Reg validation {rv['index']}: CE type should be ME_INVALID_MSG_TYPE (1)"
            assert rv["validation_gate"] in ("subclass", "msgtype_none", "system_type", "constructor"), \
                f"Reg validation {rv['index']}: unknown gate {rv['validation_gate']}"

        # Verify system_type gate logic
        if rv["msgtype"] is not None and rv["msgtype"] >= SYSTEM_MSG_BOUNDARY:
            if not rv["is_system_type_flag"]:
                # Should fail at system_type gate (unless earlier gate fails first)
                if rv["is_subclass_of_message_base"] and not rv["msgtype_is_none"]:
                    assert rv["validation_gate"] == "system_type", \
                        f"Reg validation {rv['index']}: system type via public API should fail at system_type gate"
            else:
                # is_system_type=True bypasses the gate
                if rv["is_subclass_of_message_base"] and not rv["msgtype_is_none"] and rv["constructor_succeeds"]:
                    assert rv["expected_result"] == "success", \
                        f"Reg validation {rv['index']}: system type with is_system_type=True should succeed"
    print(f"    [OK] {len(output['registration_validation_vectors'])} registration validation vectors verified")

    # 13. Sequence dedup vectors
    for sv in output["sequence_dedup_vectors"]:
        if sv.get("type") == "tx_wraparound_progression":
            # TX scenario: verify sequence arithmetic and envelope decoding
            tx_seq = sv["initial_tx_sequence"]
            for step in sv["steps"]:
                assert step["tx_sequence"] == tx_seq, \
                    f"Seq dedup {sv['index']} step {step['step']}: tx_sequence mismatch"
                assert step["next_tx_sequence"] == (tx_seq + 1) % SEQ_MODULUS, \
                    f"Seq dedup {sv['index']} step {step['step']}: next_tx_sequence mismatch"
                # Verify envelope decodes correctly
                env_raw = bytes.fromhex(step["envelope_raw_hex"])
                dec_mt, dec_seq, dec_len, dec_data = envelope_unpack(env_raw)
                assert dec_seq == tx_seq, \
                    f"Seq dedup {sv['index']} step {step['step']}: envelope sequence mismatch"
                assert dec_mt == 0xABCD, \
                    f"Seq dedup {sv['index']} step {step['step']}: envelope msgtype mismatch"
                tx_seq = (tx_seq + 1) % SEQ_MODULUS
            assert tx_seq == sv["final_tx_sequence"], \
                f"Seq dedup {sv['index']}: final tx sequence mismatch"
        else:
            # RX scenario: replay through sim_receive
            initial = sv["initial_state"]
            ring = list(initial["ring"])
            next_rx = initial["next_rx_sequence"]

            for step in sv["steps"]:
                incoming = step["incoming_sequence"]
                accepted, reason, delivered, ring, next_rx = sim_receive(ring, next_rx, incoming)
                assert accepted == step["accepted"], \
                    f"Seq dedup {sv['index']} step {step['step']}: accepted mismatch (got {accepted}, expected {step['accepted']})"
                assert reason == step["reason"], \
                    f"Seq dedup {sv['index']} step {step['step']}: reason mismatch (got {reason}, expected {step['reason']})"
                assert delivered == step["delivered_sequences"], \
                    f"Seq dedup {sv['index']} step {step['step']}: delivered mismatch (got {delivered}, expected {step['delivered_sequences']})"
                assert ring == step["ring_after"], \
                    f"Seq dedup {sv['index']} step {step['step']}: ring mismatch (got {ring}, expected {step['ring_after']})"
                assert next_rx == step["next_rx_after"], \
                    f"Seq dedup {sv['index']} step {step['step']}: next_rx mismatch (got {next_rx}, expected {step['next_rx_after']})"

                # Verify envelope bytes decode correctly
                env_raw = bytes.fromhex(step["envelope_raw_hex"])
                dec_mt, dec_seq, dec_len, dec_data = envelope_unpack(env_raw)
                assert dec_seq == incoming, \
                    f"Seq dedup {sv['index']} step {step['step']}: envelope sequence mismatch"
    print(f"    [OK] {len(output['sequence_dedup_vectors'])} sequence dedup vectors verified")

    # 14. Retry sequence vectors
    for rv in output["retry_sequence_vectors"]:
        init = rv["initial_state"]
        tries = init["tries"]
        rtt = init["rtt"]
        tx_ring_length = init["tx_ring_length"]
        window = init["window"]
        window_max = init["window_max"]
        window_min = init["window_min"]
        window_flexibility = init["window_flexibility"]
        fast_rate_rounds = init.get("fast_rate_rounds", 0)
        medium_rate_rounds = init.get("medium_rate_rounds", 0)

        for step in rv["steps"]:
            if step["event"] == "timeout":
                assert step["tries_before"] == tries, \
                    f"Retry seq {rv['index']} step {step['step']}: tries_before mismatch"
                assert step["window_before"] == window, \
                    f"Retry seq {rv['index']} step {step['step']}: window_before mismatch"
                assert step["window_max_before"] == window_max, \
                    f"Retry seq {rv['index']} step {step['step']}: window_max_before mismatch"

                outcome, tries, timeout, window, window_max = sim_timeout_retry_step(
                    step["tries_before"], rtt, tx_ring_length, window, window_max,
                    window_min, window_flexibility)

                assert tries == step["tries_after"], \
                    f"Retry seq {rv['index']} step {step['step']}: tries_after mismatch (got {tries}, expected {step['tries_after']})"
                assert outcome == step["outcome"], \
                    f"Retry seq {rv['index']} step {step['step']}: outcome mismatch (got {outcome}, expected {step['outcome']})"
                assert window == step["window_after"], \
                    f"Retry seq {rv['index']} step {step['step']}: window_after mismatch"
                assert window_max == step["window_max_after"], \
                    f"Retry seq {rv['index']} step {step['step']}: window_max_after mismatch"
                if timeout is not None:
                    assert abs(timeout - step["timeout"]) < 1e-6, \
                        f"Retry seq {rv['index']} step {step['step']}: timeout mismatch"
            elif step["event"] == "delivery":
                assert step["window_before"] == window, \
                    f"Retry seq {rv['index']} step {step['step']}: window_before mismatch"
                window, window_max, window_min, fast_rate_rounds, medium_rate_rounds, upgrade = sim_delivery_step(
                    rtt, window, window_max, window_min, fast_rate_rounds, medium_rate_rounds)
                assert window == step["window_after"], \
                    f"Retry seq {rv['index']} step {step['step']}: window_after mismatch"
                assert window_max == step["window_max_after"], \
                    f"Retry seq {rv['index']} step {step['step']}: window_max_after mismatch"
    print(f"    [OK] {len(output['retry_sequence_vectors'])} retry sequence vectors verified")

    # 15. Window adaptation sequence vectors
    for wv in output["window_adaptation_sequence_vectors"]:
        init = wv["initial_state"]
        window = init["window"]
        window_max = init["window_max"]
        window_min = init["window_min"]
        fast_rate_rounds = init.get("fast_rate_rounds", 0)
        medium_rate_rounds = init.get("medium_rate_rounds", 0)
        window_flexibility = init.get("window_flexibility", WINDOW_FLEXIBILITY)
        tries = 0

        for step in wv["steps"]:
            if step["event"] == "delivery":
                rtt = step["rtt"]
                assert step["window_before"] == window, \
                    f"Window adapt seq {wv['index']} step {step['step']}: window_before mismatch"
                assert step["window_max_before"] == window_max, \
                    f"Window adapt seq {wv['index']} step {step['step']}: window_max_before mismatch"
                assert step["fast_rate_rounds_before"] == fast_rate_rounds, \
                    f"Window adapt seq {wv['index']} step {step['step']}: fast_rate_rounds_before mismatch"
                assert step["medium_rate_rounds_before"] == medium_rate_rounds, \
                    f"Window adapt seq {wv['index']} step {step['step']}: medium_rate_rounds_before mismatch"

                window, window_max, window_min, fast_rate_rounds, medium_rate_rounds, upgrade = sim_delivery_step(
                    rtt, window, window_max, window_min, fast_rate_rounds, medium_rate_rounds)

                assert window == step["window_after"], \
                    f"Window adapt seq {wv['index']} step {step['step']}: window_after mismatch"
                assert window_max == step["window_max_after"], \
                    f"Window adapt seq {wv['index']} step {step['step']}: window_max_after mismatch"
                assert fast_rate_rounds == step["fast_rate_rounds_after"], \
                    f"Window adapt seq {wv['index']} step {step['step']}: fast_rate_rounds_after mismatch"
                assert medium_rate_rounds == step["medium_rate_rounds_after"], \
                    f"Window adapt seq {wv['index']} step {step['step']}: medium_rate_rounds_after mismatch"
                assert upgrade == step["upgrade_triggered"], \
                    f"Window adapt seq {wv['index']} step {step['step']}: upgrade_triggered mismatch"
            elif step["event"] == "timeout":
                rtt_for_timeout = wv.get("rtt", step.get("rtt", 0.5))
                tx_ring_length = step.get("tx_ring_length", 1)
                assert step["window_before"] == window, \
                    f"Window adapt seq {wv['index']} step {step['step']}: window_before mismatch"
                assert step["window_max_before"] == window_max, \
                    f"Window adapt seq {wv['index']} step {step['step']}: window_max_before mismatch"

                outcome, tries, timeout, window, window_max = sim_timeout_retry_step(
                    step["tries_before"], rtt_for_timeout, tx_ring_length, window, window_max,
                    window_min, window_flexibility)

                assert window == step["window_after"], \
                    f"Window adapt seq {wv['index']} step {step['step']}: window_after mismatch"
                assert window_max == step["window_max_after"], \
                    f"Window adapt seq {wv['index']} step {step['step']}: window_max_after mismatch"
    print(f"    [OK] {len(output['window_adaptation_sequence_vectors'])} window adaptation sequence vectors verified")

    # 16. Packet loss scenario vectors
    for pv in output["packet_loss_scenario_vectors"]:
        init = pv["initial_state"]
        window = init["window"]
        window_max = init["window_max"]
        window_min = init["window_min"]
        window_flexibility = init["window_flexibility"]
        rtt = init["rtt"]
        fast_rate_rounds = init.get("fast_rate_rounds", 0)
        medium_rate_rounds = init.get("medium_rate_rounds", 0)
        msg_tries = {}
        tx_ring = []

        for ev in pv["events"]:
            if ev["event"] == "send":
                tx_ring.append(ev["sequence"])
                msg_tries[ev["sequence"]] = 0
                assert ev["tx_ring"] == tx_ring, \
                    f"Packet loss {pv['index']} send seq {ev['sequence']}: tx_ring mismatch"
            elif ev["event"] == "delivery":
                seq = ev["sequence"]
                if seq in tx_ring:
                    tx_ring.remove(seq)
                assert ev["window_before"] == window, \
                    f"Packet loss {pv['index']} delivery seq {seq}: window_before mismatch"
                window, window_max, window_min, fast_rate_rounds, medium_rate_rounds, upgrade = sim_delivery_step(
                    rtt, window, window_max, window_min, fast_rate_rounds, medium_rate_rounds)
                assert window == ev["window_after"], \
                    f"Packet loss {pv['index']} delivery seq {seq}: window_after mismatch (got {window}, expected {ev['window_after']})"
                assert window_max == ev["window_max_after"], \
                    f"Packet loss {pv['index']} delivery seq {seq}: window_max_after mismatch"
                assert ev["tx_ring"] == tx_ring, \
                    f"Packet loss {pv['index']} delivery seq {seq}: tx_ring mismatch"
            elif ev["event"] == "timeout":
                seq = ev["sequence"]
                assert ev["window_before"] == window, \
                    f"Packet loss {pv['index']} timeout seq {seq}: window_before mismatch"
                assert ev["tries_before"] == msg_tries[seq], \
                    f"Packet loss {pv['index']} timeout seq {seq}: tries_before mismatch"
                outcome, msg_tries[seq], timeout, window, window_max = sim_timeout_retry_step(
                    msg_tries[seq], rtt, len(tx_ring), window, window_max,
                    window_min, window_flexibility)
                assert outcome == ev["outcome"], \
                    f"Packet loss {pv['index']} timeout seq {seq}: outcome mismatch"
                assert msg_tries[seq] == ev["tries_after"], \
                    f"Packet loss {pv['index']} timeout seq {seq}: tries_after mismatch"
                assert window == ev["window_after"], \
                    f"Packet loss {pv['index']} timeout seq {seq}: window_after mismatch"
                assert window_max == ev["window_max_after"], \
                    f"Packet loss {pv['index']} timeout seq {seq}: window_max_after mismatch"
                if timeout is not None:
                    assert abs(timeout - ev["timeout"]) < 1e-6, \
                        f"Packet loss {pv['index']} timeout seq {seq}: timeout mismatch"
    print(f"    [OK] {len(output['packet_loss_scenario_vectors'])} packet loss scenario vectors verified")

    # JSON round-trip
    json_str = json.dumps(output, indent=2)
    assert json.loads(json_str) == output, "JSON round-trip failed"
    print("    [OK] JSON round-trip integrity verified")


def verify_library_constants():
    """Verify our local constants match the actual RNS Channel/Buffer classes."""
    from RNS.Channel import Channel as RNSChannel, SystemMessageTypes
    from RNS.Buffer import StreamDataMessage

    assert WINDOW == RNSChannel.WINDOW, f"WINDOW: {WINDOW} != {RNSChannel.WINDOW}"
    assert WINDOW_MIN == RNSChannel.WINDOW_MIN, f"WINDOW_MIN: {WINDOW_MIN} != {RNSChannel.WINDOW_MIN}"
    assert WINDOW_MIN_LIMIT_SLOW == RNSChannel.WINDOW_MIN_LIMIT_SLOW
    assert WINDOW_MIN_LIMIT_MEDIUM == RNSChannel.WINDOW_MIN_LIMIT_MEDIUM
    assert WINDOW_MIN_LIMIT_FAST == RNSChannel.WINDOW_MIN_LIMIT_FAST
    assert WINDOW_MAX_SLOW == RNSChannel.WINDOW_MAX_SLOW
    assert WINDOW_MAX_MEDIUM == RNSChannel.WINDOW_MAX_MEDIUM
    assert WINDOW_MAX_FAST == RNSChannel.WINDOW_MAX_FAST
    assert WINDOW_MAX == RNSChannel.WINDOW_MAX
    assert FAST_RATE_THRESHOLD == RNSChannel.FAST_RATE_THRESHOLD
    assert RTT_FAST == RNSChannel.RTT_FAST
    assert RTT_MEDIUM == RNSChannel.RTT_MEDIUM
    assert RTT_SLOW == RNSChannel.RTT_SLOW
    assert WINDOW_FLEXIBILITY == RNSChannel.WINDOW_FLEXIBILITY
    assert SEQ_MAX == RNSChannel.SEQ_MAX
    assert SEQ_MODULUS == RNSChannel.SEQ_MODULUS

    assert STREAM_ID_MAX == StreamDataMessage.STREAM_ID_MAX
    assert STREAM_DATA_OVERHEAD == StreamDataMessage.OVERHEAD
    assert SMT_STREAM_DATA == SystemMessageTypes.SMT_STREAM_DATA

    print("  [OK] All library constants verified")


# ============================================================
# Main
# ============================================================

def main():
    print("Extracting channel/buffer protocol test vectors...")

    print("Verifying library constants...")
    verify_library_constants()

    print("Extracting constants...")
    constants = extract_constants()

    print("Extracting envelope vectors...")
    envelope_vectors = extract_envelope_vectors()
    print(f"  Extracted {len(envelope_vectors)} envelope vectors")

    print("Extracting message serialization vectors...")
    msg_vectors = extract_message_serialization_vectors()
    print(f"  Extracted {len(msg_vectors)} message serialization vectors")

    print("Extracting sequence number vectors...")
    seq_vectors = extract_sequence_number_vectors()
    print(f"  Extracted {len(seq_vectors)} sequence number vectors")

    print("Extracting stream data vectors...")
    stream_vectors = extract_stream_data_vectors()
    print(f"  Extracted {len(stream_vectors)} stream data vectors")

    print("Extracting window initialization vectors...")
    window_init_vectors = extract_window_init_vectors()
    print(f"  Extracted {len(window_init_vectors)} window init vectors")

    print("Extracting window adaptation vectors...")
    window_adapt_vectors = extract_window_adaptation_vectors()
    print(f"  Extracted {len(window_adapt_vectors)} window adaptation vectors")

    print("Extracting timeout vectors...")
    timeout_vectors = extract_timeout_vectors()
    print(f"  Extracted {len(timeout_vectors)} timeout vectors")

    print("Extracting MDU vectors...")
    mdu_vectors = extract_mdu_vectors()
    print(f"  Extracted {len(mdu_vectors)} MDU vectors")

    print("Extracting system message vectors...")
    sys_msg_vectors = extract_system_message_vectors()
    print(f"  Extracted {len(sys_msg_vectors)} system message vectors")

    print("Extracting round-trip vectors...")
    rt_vectors = extract_round_trip_vectors()
    print(f"  Extracted {len(rt_vectors)} round-trip vectors")

    print("Extracting send/receive vectors...")
    sr_vectors = extract_send_receive_vectors()
    print(f"  Extracted {len(sr_vectors)} send/receive vectors")

    print("Extracting handler chaining vectors...")
    hc_vectors = extract_handler_chaining_vectors()
    print(f"  Extracted {len(hc_vectors)} handler chaining vectors")

    print("Extracting registration validation vectors...")
    rv_vectors = extract_registration_validation_vectors()
    print(f"  Extracted {len(rv_vectors)} registration validation vectors")

    print("Extracting sequence dedup vectors...")
    sd_vectors = extract_sequence_dedup_vectors()
    print(f"  Extracted {len(sd_vectors)} sequence dedup vectors")

    print("Extracting retry sequence vectors...")
    retry_vectors = extract_retry_sequence_vectors()
    print(f"  Extracted {len(retry_vectors)} retry sequence vectors")

    print("Extracting window adaptation sequence vectors...")
    was_vectors = extract_window_adaptation_sequence_vectors()
    print(f"  Extracted {len(was_vectors)} window adaptation sequence vectors")

    print("Extracting packet loss scenario vectors...")
    pls_vectors = extract_packet_loss_scenario_vectors()
    print(f"  Extracted {len(pls_vectors)} packet loss scenario vectors")

    output = {
        "description": "Reticulum v1.1.3 - channel/buffer protocol test vectors",
        "source": "RNS/Channel.py, RNS/Buffer.py",
        "constants": constants,
        "envelope_vectors": envelope_vectors,
        "message_serialization_vectors": msg_vectors,
        "sequence_number_vectors": seq_vectors,
        "stream_data_vectors": stream_vectors,
        "window_init_vectors": window_init_vectors,
        "window_adaptation_vectors": window_adapt_vectors,
        "timeout_vectors": timeout_vectors,
        "mdu_vectors": mdu_vectors,
        "system_message_vectors": sys_msg_vectors,
        "round_trip_vectors": rt_vectors,
        "send_receive_vectors": sr_vectors,
        "handler_chaining_vectors": hc_vectors,
        "registration_validation_vectors": rv_vectors,
        "sequence_dedup_vectors": sd_vectors,
        "retry_sequence_vectors": retry_vectors,
        "window_adaptation_sequence_vectors": was_vectors,
        "packet_loss_scenario_vectors": pls_vectors,
    }

    verify(output)

    print(f"Writing {OUTPUT_PATH}...")
    with open(OUTPUT_PATH, "w") as f:
        json.dump(output, f, indent=2)
        f.write("\n")

    print("Done.")


if __name__ == "__main__":
    main()
