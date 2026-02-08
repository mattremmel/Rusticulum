#!/usr/bin/env python3
"""
Extract interface framing test vectors from the Reticulum reference
implementation into a JSON file for consumption by alternative implementations.

All vectors are computed manually (no live Transport/Interface objects).

Covers:
  - HDLC framing (FLAG, ESC, escape/unescape, frame/deframe)
  - KISS framing (FEND, FESC, TFEND, TFESC, escape/unescape, frame/deframe)
  - IFAC (Interface Access Code) key derivation, apply, and verify
  - Full pipeline vectors: raw -> IFAC apply -> frame -> deframe -> IFAC verify -> recovered

Usage:
    python3 test_vectors/extract_interface_framing.py

Output:
    test_vectors/interface_framing.json
"""

import hashlib
import json
import os
import sys

repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, repo_root)

import RNS
from RNS.Cryptography import HKDF

OUTPUT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "interface_framing.json")

# --- HDLC constants (from RNS/Interfaces/TCPInterface.py:44-47) ---
HDLC_FLAG     = 0x7E
HDLC_ESC      = 0x7D
HDLC_ESC_MASK = 0x20

# --- KISS constants (from RNS/Interfaces/TCPInterface.py:55-60) ---
KISS_FEND     = 0xC0
KISS_FESC     = 0xDB
KISS_TFEND    = 0xDC
KISS_TFESC    = 0xDD
KISS_CMD_DATA = 0x00

# --- IFAC constants (from RNS/Reticulum.py:152) ---
IFAC_SALT = bytes.fromhex("adf54d882c9a9b80771eb4995d702d4a3e733391b2a0f53f416d9f907e55cff8")
DEFAULT_IFAC_SIZE = 16


# ============================================================
# HDLC implementation (mirrors TCPInterface.py HDLC class)
# ============================================================

def hdlc_escape(data):
    """Escape HDLC special bytes. Order matters: ESC first, then FLAG."""
    data = data.replace(bytes([HDLC_ESC]), bytes([HDLC_ESC, HDLC_ESC ^ HDLC_ESC_MASK]))
    data = data.replace(bytes([HDLC_FLAG]), bytes([HDLC_ESC, HDLC_FLAG ^ HDLC_ESC_MASK]))
    return data

def hdlc_unescape(data):
    """Unescape HDLC special bytes. Reverse order: FLAG first, then ESC."""
    data = data.replace(bytes([HDLC_ESC, HDLC_FLAG ^ HDLC_ESC_MASK]), bytes([HDLC_FLAG]))
    data = data.replace(bytes([HDLC_ESC, HDLC_ESC ^ HDLC_ESC_MASK]), bytes([HDLC_ESC]))
    return data

def hdlc_frame(data):
    """Frame data with HDLC: FLAG + escape(data) + FLAG."""
    return bytes([HDLC_FLAG]) + hdlc_escape(data) + bytes([HDLC_FLAG])

def hdlc_deframe(frame):
    """Deframe HDLC: strip leading/trailing FLAG, unescape."""
    assert frame[0] == HDLC_FLAG and frame[-1] == HDLC_FLAG
    return hdlc_unescape(frame[1:-1])


# ============================================================
# KISS implementation (mirrors TCPInterface.py KISS class)
# ============================================================

def kiss_escape(data):
    """Escape KISS special bytes. Order matters: FESC first, then FEND."""
    data = data.replace(bytes([KISS_FESC]), bytes([KISS_FESC, KISS_TFESC]))
    data = data.replace(bytes([KISS_FEND]), bytes([KISS_FESC, KISS_TFEND]))
    return data

def kiss_unescape(data):
    """Unescape KISS special bytes. Reverse order: FEND first, then FESC."""
    data = data.replace(bytes([KISS_FESC, KISS_TFEND]), bytes([KISS_FEND]))
    data = data.replace(bytes([KISS_FESC, KISS_TFESC]), bytes([KISS_FESC]))
    return data

def kiss_frame(data):
    """Frame data with KISS: FEND + CMD_DATA + escape(data) + FEND."""
    return bytes([KISS_FEND, KISS_CMD_DATA]) + kiss_escape(data) + bytes([KISS_FEND])

def kiss_deframe(frame):
    """Deframe KISS: strip FEND+CMD, trailing FEND, unescape."""
    assert frame[0] == KISS_FEND and frame[-1] == KISS_FEND
    assert frame[1] == KISS_CMD_DATA
    return kiss_unescape(frame[2:-1])


# ============================================================
# IFAC implementation (mirrors Transport.py transmit/inbound
# and Reticulum.py _add_interface)
# ============================================================

def ifac_derive_key(ifac_netname=None, ifac_netkey=None):
    """
    Derive IFAC key and identity from netname/netkey.
    Mirrors RNS/Reticulum.py:973-991.
    Returns (ifac_key, ifac_identity).
    """
    ifac_origin = b""
    if ifac_netname is not None:
        ifac_origin += hashlib.sha256(ifac_netname.encode("utf-8")).digest()
    if ifac_netkey is not None:
        ifac_origin += hashlib.sha256(ifac_netkey.encode("utf-8")).digest()

    ifac_origin_hash = hashlib.sha256(ifac_origin).digest()
    ifac_key = HKDF.hkdf(
        length=64,
        derive_from=ifac_origin_hash,
        salt=IFAC_SALT,
        context=None,
    )

    ifac_identity = RNS.Identity.from_bytes(ifac_key)
    return ifac_key, ifac_identity


def ifac_apply(raw, ifac_identity, ifac_key, ifac_size=DEFAULT_IFAC_SIZE):
    """
    Apply IFAC to a raw packet for transmission.
    Mirrors RNS/Transport.py:893-930.
    Returns the masked raw bytes ready for wire framing.
    """
    # Calculate packet access code
    ifac = ifac_identity.sign(raw)[-ifac_size:]

    # Generate mask
    mask = HKDF.hkdf(
        length=len(raw) + ifac_size,
        derive_from=ifac,
        salt=ifac_key,
        context=None,
    )

    # Set IFAC flag
    new_header = bytes([raw[0] | 0x80, raw[1]])

    # Assemble new payload with IFAC
    new_raw = new_header + ifac + raw[2:]

    # Mask payload
    i = 0
    masked_raw = b""
    for byte in new_raw:
        if i == 0:
            # Mask first header byte, but keep IFAC flag set
            masked_raw += bytes([byte ^ mask[i] | 0x80])
        elif i == 1 or i > ifac_size + 1:
            # Mask second header byte and payload
            masked_raw += bytes([byte ^ mask[i]])
        else:
            # Don't mask the IFAC itself
            masked_raw += bytes([byte])
        i += 1

    return masked_raw


def ifac_verify(raw, ifac_identity, ifac_key, ifac_size=DEFAULT_IFAC_SIZE):
    """
    Verify and strip IFAC from a received raw packet.
    Mirrors RNS/Transport.py:1240-1303.
    Returns the recovered raw packet, or None if verification fails.
    """
    if len(raw) <= 2:
        return None

    # Check IFAC flag
    if raw[0] & 0x80 != 0x80:
        return None

    if len(raw) <= 2 + ifac_size:
        return None

    # Extract IFAC
    ifac = raw[2:2 + ifac_size]

    # Generate mask
    mask = HKDF.hkdf(
        length=len(raw),
        derive_from=ifac,
        salt=ifac_key,
        context=None,
    )

    # Unmask payload
    i = 0
    unmasked_raw = b""
    for byte in raw:
        if i <= 1 or i > ifac_size + 1:
            # Unmask header bytes and payload
            unmasked_raw += bytes([byte ^ mask[i]])
        else:
            # Don't unmask IFAC itself
            unmasked_raw += bytes([byte])
        i += 1
    raw = unmasked_raw

    # Unset IFAC flag
    new_header = bytes([raw[0] & 0x7f, raw[1]])

    # Re-assemble packet
    new_raw = new_header + raw[2 + ifac_size:]

    # Calculate expected IFAC
    expected_ifac = ifac_identity.sign(new_raw)[-ifac_size:]

    # Check it
    if ifac == expected_ifac:
        return new_raw
    else:
        return None


# ============================================================
# Test vector generation
# ============================================================

def deterministic_data(idx, length):
    """Generate deterministic test data."""
    result = b""
    while len(result) < length:
        result += hashlib.sha256(b"test_data_" + str(idx).encode() + b"_" + str(len(result)).encode()).digest()
    return result[:length]


def extract_hdlc_vectors():
    """Generate HDLC framing test vectors."""
    vectors = []

    # Vector 1: Normal packet (no special bytes)
    data1 = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x10, 0x20, 0x30])
    escaped1 = hdlc_escape(data1)
    frame1 = hdlc_frame(data1)
    assert hdlc_deframe(frame1) == data1
    vectors.append({
        "description": "Normal packet with no special bytes needing escape",
        "input": data1.hex(),
        "escaped": escaped1.hex(),
        "framed": frame1.hex(),
        "escaped_length": len(escaped1),
        "framed_length": len(frame1),
    })

    # Vector 2: Packet containing ESC byte (0x7D)
    data2 = bytes([0x01, 0x7D, 0x03, 0x04])
    escaped2 = hdlc_escape(data2)
    frame2 = hdlc_frame(data2)
    assert hdlc_deframe(frame2) == data2
    vectors.append({
        "description": "Packet containing ESC byte (0x7D -> 0x7D 0x5D)",
        "input": data2.hex(),
        "escaped": escaped2.hex(),
        "framed": frame2.hex(),
        "escaped_length": len(escaped2),
        "framed_length": len(frame2),
    })

    # Vector 3: Packet containing FLAG byte (0x7E)
    data3 = bytes([0x01, 0x7E, 0x03, 0x04])
    escaped3 = hdlc_escape(data3)
    frame3 = hdlc_frame(data3)
    assert hdlc_deframe(frame3) == data3
    vectors.append({
        "description": "Packet containing FLAG byte (0x7E -> 0x7D 0x5E)",
        "input": data3.hex(),
        "escaped": escaped3.hex(),
        "framed": frame3.hex(),
        "escaped_length": len(escaped3),
        "framed_length": len(frame3),
    })

    # Vector 4: Packet with both ESC and FLAG
    data4 = bytes([0x7D, 0x7E, 0x7D, 0x7E])
    escaped4 = hdlc_escape(data4)
    frame4 = hdlc_frame(data4)
    assert hdlc_deframe(frame4) == data4
    vectors.append({
        "description": "Packet with both ESC (0x7D) and FLAG (0x7E) bytes, alternating",
        "input": data4.hex(),
        "escaped": escaped4.hex(),
        "framed": frame4.hex(),
        "escaped_length": len(escaped4),
        "framed_length": len(frame4),
    })

    # Vector 5: Worst case - all special bytes
    data5 = bytes([HDLC_ESC] * 4 + [HDLC_FLAG] * 4)
    escaped5 = hdlc_escape(data5)
    frame5 = hdlc_frame(data5)
    assert hdlc_deframe(frame5) == data5
    vectors.append({
        "description": "Worst case: all special bytes (4x ESC + 4x FLAG), maximum expansion",
        "input": data5.hex(),
        "escaped": escaped5.hex(),
        "framed": frame5.hex(),
        "escaped_length": len(escaped5),
        "framed_length": len(frame5),
    })

    # Vector 6: MTU-size packet (500 bytes) with special bytes at boundaries
    data6 = bytearray(deterministic_data(0, 500))
    # Place special bytes at start, middle, and end
    data6[0] = HDLC_FLAG
    data6[1] = HDLC_ESC
    data6[249] = HDLC_FLAG
    data6[250] = HDLC_ESC
    data6[498] = HDLC_ESC
    data6[499] = HDLC_FLAG
    data6 = bytes(data6)
    escaped6 = hdlc_escape(data6)
    frame6 = hdlc_frame(data6)
    assert hdlc_deframe(frame6) == data6
    vectors.append({
        "description": "MTU-size packet (500 bytes) with special bytes at boundaries (0, 1, 249, 250, 498, 499)",
        "input": data6.hex(),
        "escaped": escaped6.hex(),
        "framed": frame6.hex(),
        "escaped_length": len(escaped6),
        "framed_length": len(frame6),
    })

    # Vector 7: Adjacent ESC bytes (edge case for replace order)
    data7 = bytes([HDLC_ESC, HDLC_ESC, HDLC_FLAG, HDLC_FLAG, HDLC_ESC])
    escaped7 = hdlc_escape(data7)
    frame7 = hdlc_frame(data7)
    assert hdlc_deframe(frame7) == data7
    vectors.append({
        "description": "Adjacent special bytes testing escape order: ESC ESC FLAG FLAG ESC",
        "input": data7.hex(),
        "escaped": escaped7.hex(),
        "framed": frame7.hex(),
        "escaped_length": len(escaped7),
        "framed_length": len(frame7),
    })

    # Vector 8: Empty data
    data8 = b""
    escaped8 = hdlc_escape(data8)
    frame8 = hdlc_frame(data8)
    assert hdlc_deframe(frame8) == data8
    vectors.append({
        "description": "Empty data (frame is just FLAG FLAG)",
        "input": data8.hex(),
        "escaped": escaped8.hex(),
        "framed": frame8.hex(),
        "escaped_length": len(escaped8),
        "framed_length": len(frame8),
    })

    return vectors


def extract_kiss_vectors():
    """Generate KISS framing test vectors."""
    vectors = []

    # Vector 1: Normal packet (no special bytes)
    data1 = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x10, 0x20, 0x30])
    escaped1 = kiss_escape(data1)
    frame1 = kiss_frame(data1)
    assert kiss_deframe(frame1) == data1
    vectors.append({
        "description": "Normal packet with no special bytes needing escape",
        "input": data1.hex(),
        "escaped": escaped1.hex(),
        "framed": frame1.hex(),
        "escaped_length": len(escaped1),
        "framed_length": len(frame1),
    })

    # Vector 2: Packet containing FEND byte (0xC0)
    data2 = bytes([0x01, 0xC0, 0x03, 0x04])
    escaped2 = kiss_escape(data2)
    frame2 = kiss_frame(data2)
    assert kiss_deframe(frame2) == data2
    vectors.append({
        "description": "Packet containing FEND byte (0xC0 -> 0xDB 0xDC)",
        "input": data2.hex(),
        "escaped": escaped2.hex(),
        "framed": frame2.hex(),
        "escaped_length": len(escaped2),
        "framed_length": len(frame2),
    })

    # Vector 3: Packet containing FESC byte (0xDB)
    data3 = bytes([0x01, 0xDB, 0x03, 0x04])
    escaped3 = kiss_escape(data3)
    frame3 = kiss_frame(data3)
    assert kiss_deframe(frame3) == data3
    vectors.append({
        "description": "Packet containing FESC byte (0xDB -> 0xDB 0xDD)",
        "input": data3.hex(),
        "escaped": escaped3.hex(),
        "framed": frame3.hex(),
        "escaped_length": len(escaped3),
        "framed_length": len(frame3),
    })

    # Vector 4: Packet with both FEND and FESC
    data4 = bytes([0xC0, 0xDB, 0xC0, 0xDB])
    escaped4 = kiss_escape(data4)
    frame4 = kiss_frame(data4)
    assert kiss_deframe(frame4) == data4
    vectors.append({
        "description": "Packet with both FEND (0xC0) and FESC (0xDB) bytes, alternating",
        "input": data4.hex(),
        "escaped": escaped4.hex(),
        "framed": frame4.hex(),
        "escaped_length": len(escaped4),
        "framed_length": len(frame4),
    })

    # Vector 5: Worst case - all special bytes
    data5 = bytes([KISS_FESC] * 4 + [KISS_FEND] * 4)
    escaped5 = kiss_escape(data5)
    frame5 = kiss_frame(data5)
    assert kiss_deframe(frame5) == data5
    vectors.append({
        "description": "Worst case: all special bytes (4x FESC + 4x FEND), maximum expansion",
        "input": data5.hex(),
        "escaped": escaped5.hex(),
        "framed": frame5.hex(),
        "escaped_length": len(escaped5),
        "framed_length": len(frame5),
    })

    # Vector 6: MTU-size packet (500 bytes) with special bytes at boundaries
    data6 = bytearray(deterministic_data(1, 500))
    data6[0] = KISS_FEND
    data6[1] = KISS_FESC
    data6[249] = KISS_FEND
    data6[250] = KISS_FESC
    data6[498] = KISS_FESC
    data6[499] = KISS_FEND
    data6 = bytes(data6)
    escaped6 = kiss_escape(data6)
    frame6 = kiss_frame(data6)
    assert kiss_deframe(frame6) == data6
    vectors.append({
        "description": "MTU-size packet (500 bytes) with special bytes at boundaries (0, 1, 249, 250, 498, 499)",
        "input": data6.hex(),
        "escaped": escaped6.hex(),
        "framed": frame6.hex(),
        "escaped_length": len(escaped6),
        "framed_length": len(frame6),
    })

    # Vector 7: Adjacent FESC bytes (edge case for replace order)
    data7 = bytes([KISS_FESC, KISS_FESC, KISS_FEND, KISS_FEND, KISS_FESC])
    escaped7 = kiss_escape(data7)
    frame7 = kiss_frame(data7)
    assert kiss_deframe(frame7) == data7
    vectors.append({
        "description": "Adjacent special bytes testing escape order: FESC FESC FEND FEND FESC",
        "input": data7.hex(),
        "escaped": escaped7.hex(),
        "framed": frame7.hex(),
        "escaped_length": len(escaped7),
        "framed_length": len(frame7),
    })

    # Vector 8: Empty data
    data8 = b""
    escaped8 = kiss_escape(data8)
    frame8 = kiss_frame(data8)
    assert kiss_deframe(frame8) == data8
    vectors.append({
        "description": "Empty data (frame is FEND CMD_DATA FEND)",
        "input": data8.hex(),
        "escaped": escaped8.hex(),
        "framed": frame8.hex(),
        "escaped_length": len(escaped8),
        "framed_length": len(frame8),
    })

    return vectors


def extract_consecutive_frame_vectors():
    """Generate vectors for consecutive frames on the same wire."""
    packets = [
        bytes([0x01, 0x02, 0x03]),
        bytes([0x7D, 0x7E, 0xC0, 0xDB]),
        bytes([0x04, 0x05, 0x06]),
    ]

    hdlc_frames = b""
    kiss_frames = b""
    for p in packets:
        hdlc_frames += hdlc_frame(p)
        kiss_frames += kiss_frame(p)

    return {
        "description": "Three consecutive frames on the same wire",
        "packets": [p.hex() for p in packets],
        "hdlc_concatenated": hdlc_frames.hex(),
        "kiss_concatenated": kiss_frames.hex(),
        "hdlc_separator": "7e",
        "kiss_separator": "c0",
        "note": "Consecutive frames share boundary markers (last FLAG/FEND of frame N serves as first FLAG/FEND of frame N+1 in some implementations, but Reticulum uses distinct delimiters)",
    }


def extract_ifac_key_derivation_vectors():
    """Generate IFAC key derivation test vectors."""
    vectors = []

    # Vector 1: netname only
    netname1 = "testnet"
    ifac_key1, ifac_identity1 = ifac_derive_key(ifac_netname=netname1)
    ifac_origin1 = hashlib.sha256(netname1.encode("utf-8")).digest()
    ifac_origin_hash1 = hashlib.sha256(ifac_origin1).digest()
    vectors.append({
        "description": "IFAC key derivation with netname only",
        "ifac_netname": netname1,
        "ifac_netkey": None,
        "ifac_origin": ifac_origin1.hex(),
        "ifac_origin_hash": ifac_origin_hash1.hex(),
        "ifac_key": ifac_key1.hex(),
        "identity_public_key": ifac_identity1.pub_bytes.hex() + ifac_identity1.sig_pub_bytes.hex(),
    })

    # Vector 2: netkey only
    netkey2 = "secretpassword"
    ifac_key2, ifac_identity2 = ifac_derive_key(ifac_netkey=netkey2)
    ifac_origin2 = hashlib.sha256(netkey2.encode("utf-8")).digest()
    ifac_origin_hash2 = hashlib.sha256(ifac_origin2).digest()
    vectors.append({
        "description": "IFAC key derivation with netkey only",
        "ifac_netname": None,
        "ifac_netkey": netkey2,
        "ifac_origin": ifac_origin2.hex(),
        "ifac_origin_hash": ifac_origin_hash2.hex(),
        "ifac_key": ifac_key2.hex(),
        "identity_public_key": ifac_identity2.pub_bytes.hex() + ifac_identity2.sig_pub_bytes.hex(),
    })

    # Vector 3: both netname and netkey
    netname3 = "mynetwork"
    netkey3 = "mypassword"
    ifac_key3, ifac_identity3 = ifac_derive_key(ifac_netname=netname3, ifac_netkey=netkey3)
    ifac_origin3 = hashlib.sha256(netname3.encode("utf-8")).digest() + hashlib.sha256(netkey3.encode("utf-8")).digest()
    ifac_origin_hash3 = hashlib.sha256(ifac_origin3).digest()
    vectors.append({
        "description": "IFAC key derivation with both netname and netkey",
        "ifac_netname": netname3,
        "ifac_netkey": netkey3,
        "ifac_origin": ifac_origin3.hex(),
        "ifac_origin_hash": ifac_origin_hash3.hex(),
        "ifac_key": ifac_key3.hex(),
        "identity_public_key": ifac_identity3.pub_bytes.hex() + ifac_identity3.sig_pub_bytes.hex(),
    })

    return vectors


def extract_ifac_apply_verify_vectors():
    """Generate IFAC apply and verify test vectors."""
    vectors = []

    # Use a fixed netname/netkey for all IFAC vectors
    netname = "testnet"
    netkey = "testkey"
    ifac_key, ifac_identity = ifac_derive_key(ifac_netname=netname, ifac_netkey=netkey)

    for ifac_size in [8, 16]:
        # Vector: Simple packet
        raw1 = bytes([0x00, 0x01]) + deterministic_data(10, 30)
        masked1 = ifac_apply(raw1, ifac_identity, ifac_key, ifac_size)
        recovered1 = ifac_verify(masked1, ifac_identity, ifac_key, ifac_size)
        assert recovered1 == raw1, f"IFAC roundtrip failed for ifac_size={ifac_size}"

        # Show intermediate values
        ifac1 = ifac_identity.sign(raw1)[-ifac_size:]
        mask1 = HKDF.hkdf(
            length=len(raw1) + ifac_size,
            derive_from=ifac1,
            salt=ifac_key,
            context=None,
        )

        vectors.append({
            "description": f"IFAC apply+verify roundtrip (ifac_size={ifac_size})",
            "ifac_netname": netname,
            "ifac_netkey": netkey,
            "ifac_size": ifac_size,
            "raw_packet": raw1.hex(),
            "ifac_value": ifac1.hex(),
            "mask": mask1.hex(),
            "masked_packet": masked1.hex(),
            "recovered_packet": recovered1.hex(),
            "ifac_flag_set": bool(masked1[0] & 0x80),
            "notes": {
                "mask_byte_0": "XOR with header byte 0, then force IFAC flag (| 0x80)",
                "mask_byte_1": "XOR with header byte 1",
                "mask_bytes_2_to_ifac_size_plus_1": "Not masked (IFAC travels in clear)",
                "mask_remaining": "XOR with payload bytes",
            },
        })

    # Vector: Tampered packet should fail verification
    raw_tamper = bytes([0x00, 0x01]) + deterministic_data(20, 30)
    masked_tamper = ifac_apply(raw_tamper, ifac_identity, ifac_key, DEFAULT_IFAC_SIZE)
    tampered = bytearray(masked_tamper)
    tampered[-1] ^= 0xFF  # flip last byte
    tampered = bytes(tampered)
    recovered_tamper = ifac_verify(tampered, ifac_identity, ifac_key, DEFAULT_IFAC_SIZE)
    assert recovered_tamper is None, "Tampered packet should fail IFAC verification"

    vectors.append({
        "description": "IFAC rejection on tampered packet (last byte flipped)",
        "ifac_netname": netname,
        "ifac_netkey": netkey,
        "ifac_size": DEFAULT_IFAC_SIZE,
        "raw_packet": raw_tamper.hex(),
        "masked_packet": masked_tamper.hex(),
        "tampered_packet": tampered.hex(),
        "verification_result": "rejected",
    })

    # Vector: Wrong IFAC key should fail verification
    _, wrong_identity = ifac_derive_key(ifac_netname="wrongnet")
    wrong_key, _ = ifac_derive_key(ifac_netname="wrongnet")
    raw_wrong = bytes([0x00, 0x01]) + deterministic_data(30, 30)
    masked_wrong = ifac_apply(raw_wrong, ifac_identity, ifac_key, DEFAULT_IFAC_SIZE)
    recovered_wrong = ifac_verify(masked_wrong, wrong_identity, wrong_key, DEFAULT_IFAC_SIZE)
    assert recovered_wrong is None, "Wrong IFAC key should fail verification"

    vectors.append({
        "description": "IFAC rejection with wrong IFAC key (different netname)",
        "sender_netname": netname,
        "sender_netkey": netkey,
        "receiver_netname": "wrongnet",
        "receiver_netkey": None,
        "ifac_size": DEFAULT_IFAC_SIZE,
        "raw_packet": raw_wrong.hex(),
        "masked_packet": masked_wrong.hex(),
        "verification_result": "rejected",
    })

    # Vector: No IFAC flag set on received packet (should be rejected)
    raw_noflag = bytes([0x00, 0x01]) + deterministic_data(40, 30)
    # Don't apply IFAC, just send raw — receiver with IFAC expects flag
    assert raw_noflag[0] & 0x80 == 0x00, "Raw packet should not have IFAC flag"
    vectors.append({
        "description": "Packet without IFAC flag rejected by IFAC-enabled receiver",
        "ifac_size": DEFAULT_IFAC_SIZE,
        "raw_packet": raw_noflag.hex(),
        "ifac_flag_set": False,
        "verification_result": "rejected",
        "note": "Receiver with IFAC enabled drops packets without IFAC flag (0x80) set",
    })

    return vectors


def extract_full_pipeline_vectors():
    """Generate full pipeline test vectors: raw -> IFAC apply -> frame -> deframe -> IFAC verify -> recovered."""
    vectors = []

    netname = "pipeline_test"
    netkey = "pipeline_key"
    ifac_key, ifac_identity = ifac_derive_key(ifac_netname=netname, ifac_netkey=netkey)
    ifac_size = DEFAULT_IFAC_SIZE

    # A realistic-looking packet (header + destination_hash + payload)
    test_packets = [
        {
            "description": "Small packet through HDLC pipeline",
            "raw": bytes([0x00, 0x01]) + deterministic_data(100, 20),
            "framing": "hdlc",
        },
        {
            "description": "Small packet through KISS pipeline",
            "raw": bytes([0x00, 0x01]) + deterministic_data(101, 20),
            "framing": "kiss",
        },
        {
            "description": "Packet with special bytes through HDLC pipeline",
            "raw": bytes([0x00, 0x01, 0x7D, 0x7E]) + deterministic_data(102, 28),
            "framing": "hdlc",
        },
        {
            "description": "Packet with special bytes through KISS pipeline",
            "raw": bytes([0x00, 0x01, 0xC0, 0xDB]) + deterministic_data(103, 28),
            "framing": "kiss",
        },
        {
            "description": "MTU-size packet through HDLC pipeline",
            "raw": bytes([0x00, 0x01]) + deterministic_data(104, 498),
            "framing": "hdlc",
        },
        {
            "description": "MTU-size packet through KISS pipeline",
            "raw": bytes([0x00, 0x01]) + deterministic_data(105, 498),
            "framing": "kiss",
        },
    ]

    for tp in test_packets:
        raw = tp["raw"]
        framing = tp["framing"]

        # Step 1: IFAC apply
        masked = ifac_apply(raw, ifac_identity, ifac_key, ifac_size)

        # Step 2: Frame
        if framing == "hdlc":
            framed = hdlc_frame(masked)
        else:
            framed = kiss_frame(masked)

        # Step 3: Deframe
        if framing == "hdlc":
            deframed = hdlc_deframe(framed)
        else:
            deframed = kiss_deframe(framed)

        assert deframed == masked, "Deframe should recover masked packet"

        # Step 4: IFAC verify
        recovered = ifac_verify(deframed, ifac_identity, ifac_key, ifac_size)
        assert recovered == raw, "Full pipeline should recover original raw packet"

        vectors.append({
            "description": tp["description"],
            "framing": framing,
            "ifac_netname": netname,
            "ifac_netkey": netkey,
            "ifac_size": ifac_size,
            "step_0_raw": raw.hex(),
            "step_1_ifac_applied": masked.hex(),
            "step_2_framed": framed.hex(),
            "step_3_deframed": deframed.hex(),
            "step_4_ifac_verified": recovered.hex(),
        })

    # Pipeline without IFAC (raw -> frame -> deframe -> raw)
    raw_no_ifac = bytes([0x00, 0x01]) + deterministic_data(200, 30)
    for framing in ["hdlc", "kiss"]:
        if framing == "hdlc":
            framed = hdlc_frame(raw_no_ifac)
            deframed = hdlc_deframe(framed)
        else:
            framed = kiss_frame(raw_no_ifac)
            deframed = kiss_deframe(framed)
        assert deframed == raw_no_ifac

        vectors.append({
            "description": f"Pipeline without IFAC through {framing.upper()}",
            "framing": framing,
            "ifac_netname": None,
            "ifac_netkey": None,
            "ifac_size": 0,
            "step_0_raw": raw_no_ifac.hex(),
            "step_1_ifac_applied": raw_no_ifac.hex(),
            "step_2_framed": framed.hex(),
            "step_3_deframed": deframed.hex(),
            "step_4_ifac_verified": raw_no_ifac.hex(),
            "note": "No IFAC configured; packet passes through without modification",
        })

    return vectors


def build_output(hdlc_vectors, kiss_vectors, consecutive_vectors,
                 ifac_key_vectors, ifac_apply_vectors, pipeline_vectors):
    return {
        "description": "Reticulum v1.1.3 reference implementation - Interface framing test vectors",
        "sources": [
            "RNS/Interfaces/TCPInterface.py (HDLC, KISS classes)",
            "RNS/Transport.py (transmit/inbound with IFAC)",
            "RNS/Reticulum.py (_add_interface IFAC key derivation)",
        ],
        "hdlc": {
            "description": "HDLC-style byte-stuffing framing used by TCP, Serial, Local, Pipe, I2P interfaces",
            "constants": {
                "FLAG": "0x7E",
                "ESC": "0x7D",
                "ESC_MASK": "0x20",
            },
            "escape_rules": [
                {"input_byte": "0x7D (ESC)", "escaped_to": "0x7D 0x5D", "note": "ESC is escaped FIRST (before FLAG)"},
                {"input_byte": "0x7E (FLAG)", "escaped_to": "0x7D 0x5E", "note": "FLAG is escaped SECOND (after ESC)"},
            ],
            "frame_format": "FLAG + escape(data) + FLAG",
            "escape_order_note": "The reference implementation uses two sequential replace() calls: ESC first, then FLAG. This order is critical — reversing it would corrupt ESC bytes.",
            "vectors": hdlc_vectors,
        },
        "kiss": {
            "description": "KISS framing used by TCP KISS, KISS serial, RNode, AX25KISS interfaces",
            "constants": {
                "FEND": "0xC0",
                "FESC": "0xDB",
                "TFEND": "0xDC",
                "TFESC": "0xDD",
                "CMD_DATA": "0x00",
            },
            "escape_rules": [
                {"input_byte": "0xDB (FESC)", "escaped_to": "0xDB 0xDD", "note": "FESC is escaped FIRST (before FEND)"},
                {"input_byte": "0xC0 (FEND)", "escaped_to": "0xDB 0xDC", "note": "FEND is escaped SECOND (after FESC)"},
            ],
            "frame_format": "FEND + CMD_DATA + escape(data) + FEND",
            "escape_order_note": "The reference implementation uses two sequential replace() calls: FESC first, then FEND. This order is critical — reversing it would corrupt FESC bytes.",
            "vectors": kiss_vectors,
        },
        "consecutive_frames": consecutive_vectors,
        "ifac": {
            "description": "Interface Access Code (IFAC) authentication layer between raw packets and wire framing",
            "constants": {
                "IFAC_SALT": IFAC_SALT.hex(),
                "default_ifac_size": DEFAULT_IFAC_SIZE,
                "valid_ifac_sizes": [8, 16],
            },
            "key_derivation": {
                "description": "IFAC key derivation from netname and/or netkey",
                "algorithm": [
                    "1. ifac_origin = SHA256(netname.encode('utf-8')) || SHA256(netkey.encode('utf-8')) (concatenate whichever are set)",
                    "2. ifac_origin_hash = SHA256(ifac_origin)",
                    "3. ifac_key = HKDF(length=64, derive_from=ifac_origin_hash, salt=IFAC_SALT, context=None)",
                    "4. ifac_identity = Identity.from_bytes(ifac_key) — first 32 bytes are X25519 key, last 32 are Ed25519 seed",
                ],
                "vectors": ifac_key_vectors,
            },
            "transmit_apply": {
                "description": "IFAC application on transmit (Transport.transmit)",
                "algorithm": [
                    "1. ifac = identity.sign(raw)[-ifac_size:]  (last ifac_size bytes of Ed25519 signature)",
                    "2. mask = HKDF(length=len(raw)+ifac_size, derive_from=ifac, salt=ifac_key, context=None)",
                    "3. new_header = [raw[0] | 0x80, raw[1]]  (set IFAC flag in header byte 0)",
                    "4. new_raw = new_header + ifac + raw[2:]  (insert IFAC after header)",
                    "5. Mask byte-by-byte:",
                    "   - byte 0: XOR with mask[0], then force | 0x80 (keep IFAC flag)",
                    "   - byte 1: XOR with mask[1]",
                    "   - bytes 2..ifac_size+1: NOT masked (IFAC travels in clear)",
                    "   - bytes ifac_size+2..end: XOR with mask[i]",
                ],
            },
            "receive_verify": {
                "description": "IFAC verification on receive (Transport.inbound)",
                "algorithm": [
                    "1. Check IFAC flag: raw[0] & 0x80 == 0x80",
                    "2. Extract IFAC: ifac = raw[2:2+ifac_size]",
                    "3. mask = HKDF(length=len(raw), derive_from=ifac, salt=ifac_key, context=None)",
                    "4. Unmask byte-by-byte:",
                    "   - bytes 0..1: XOR with mask[i]",
                    "   - bytes 2..ifac_size+1: NOT unmasked (IFAC in clear)",
                    "   - bytes ifac_size+2..end: XOR with mask[i]",
                    "5. Clear IFAC flag: new_header = [raw[0] & 0x7F, raw[1]]",
                    "6. Reassemble: new_raw = new_header + raw[2+ifac_size:]",
                    "7. Verify: identity.sign(new_raw)[-ifac_size:] == ifac",
                ],
                "masking_asymmetry_note": "Transmit masks AFTER setting IFAC flag and forces flag with OR. Receive unmasks FIRST (including header), THEN clears flag with AND. The mask values differ between transmit and receive because the masked packet has different length (includes IFAC bytes).",
            },
            "vectors": ifac_apply_vectors,
        },
        "full_pipeline": {
            "description": "Complete transmit/receive pipeline: raw -> IFAC apply -> wire frame -> deframe -> IFAC verify -> recovered",
            "pipeline_order_transmit": [
                "1. Raw packet",
                "2. IFAC apply (if configured): sign, mask, insert IFAC",
                "3. Wire framing: HDLC or KISS escape + delimit",
            ],
            "pipeline_order_receive": [
                "1. Wire deframing: strip delimiters, unescape",
                "2. IFAC verify (if configured): extract IFAC, unmask, verify signature",
                "3. Recovered raw packet",
            ],
            "vectors": pipeline_vectors,
        },
    }


def verify(output):
    """Verify all vectors round-trip correctly."""
    # Verify HDLC vectors
    for i, vec in enumerate(output["hdlc"]["vectors"]):
        data = bytes.fromhex(vec["input"])
        escaped = hdlc_escape(data)
        assert escaped.hex() == vec["escaped"], f"HDLC vector {i} escape mismatch"
        framed = hdlc_frame(data)
        assert framed.hex() == vec["framed"], f"HDLC vector {i} frame mismatch"
        assert hdlc_deframe(framed) == data, f"HDLC vector {i} deframe mismatch"
    print(f"  [OK] All {len(output['hdlc']['vectors'])} HDLC vectors verified")

    # Verify KISS vectors
    for i, vec in enumerate(output["kiss"]["vectors"]):
        data = bytes.fromhex(vec["input"])
        escaped = kiss_escape(data)
        assert escaped.hex() == vec["escaped"], f"KISS vector {i} escape mismatch"
        framed = kiss_frame(data)
        assert framed.hex() == vec["framed"], f"KISS vector {i} frame mismatch"
        assert kiss_deframe(framed) == data, f"KISS vector {i} deframe mismatch"
    print(f"  [OK] All {len(output['kiss']['vectors'])} KISS vectors verified")

    # Verify IFAC key derivation vectors
    for i, vec in enumerate(output["ifac"]["key_derivation"]["vectors"]):
        ifac_key, ifac_identity = ifac_derive_key(
            ifac_netname=vec["ifac_netname"],
            ifac_netkey=vec["ifac_netkey"],
        )
        assert ifac_key.hex() == vec["ifac_key"], f"IFAC key vector {i} mismatch"
    print(f"  [OK] All {len(output['ifac']['key_derivation']['vectors'])} IFAC key derivation vectors verified")

    # Verify IFAC apply/verify vectors
    roundtrip_count = 0
    for vec in output["ifac"]["vectors"]:
        if vec.get("verification_result") == "rejected":
            continue
        ifac_key, ifac_identity = ifac_derive_key(
            ifac_netname=vec["ifac_netname"],
            ifac_netkey=vec["ifac_netkey"],
        )
        raw = bytes.fromhex(vec["raw_packet"])
        masked = ifac_apply(raw, ifac_identity, ifac_key, vec["ifac_size"])
        assert masked.hex() == vec["masked_packet"], f"IFAC apply mismatch"
        recovered = ifac_verify(masked, ifac_identity, ifac_key, vec["ifac_size"])
        assert recovered == raw, f"IFAC verify mismatch"
        roundtrip_count += 1
    print(f"  [OK] {roundtrip_count} IFAC apply/verify roundtrips verified")

    # Verify full pipeline vectors
    pipeline_count = 0
    for vec in output["full_pipeline"]["vectors"]:
        raw = bytes.fromhex(vec["step_0_raw"])
        recovered = bytes.fromhex(vec["step_4_ifac_verified"])
        assert raw == recovered, f"Pipeline vector roundtrip mismatch"
        pipeline_count += 1
    print(f"  [OK] All {pipeline_count} full pipeline vectors verified")

    # JSON round-trip
    json_str = json.dumps(output, indent=2)
    assert json.loads(json_str) == output, "JSON round-trip failed"
    print("  [OK] JSON round-trip integrity verified")


def main():
    print("Extracting interface framing vectors...")

    print("  Extracting HDLC vectors...")
    hdlc_vectors = extract_hdlc_vectors()
    print(f"    {len(hdlc_vectors)} HDLC vectors")

    print("  Extracting KISS vectors...")
    kiss_vectors = extract_kiss_vectors()
    print(f"    {len(kiss_vectors)} KISS vectors")

    print("  Extracting consecutive frame vectors...")
    consecutive_vectors = extract_consecutive_frame_vectors()

    print("  Extracting IFAC key derivation vectors...")
    ifac_key_vectors = extract_ifac_key_derivation_vectors()
    print(f"    {len(ifac_key_vectors)} IFAC key vectors")

    print("  Extracting IFAC apply/verify vectors...")
    ifac_apply_vectors = extract_ifac_apply_verify_vectors()
    print(f"    {len(ifac_apply_vectors)} IFAC apply/verify vectors")

    print("  Extracting full pipeline vectors...")
    pipeline_vectors = extract_full_pipeline_vectors()
    print(f"    {len(pipeline_vectors)} pipeline vectors")

    print("Building output...")
    output = build_output(
        hdlc_vectors, kiss_vectors, consecutive_vectors,
        ifac_key_vectors, ifac_apply_vectors, pipeline_vectors,
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
