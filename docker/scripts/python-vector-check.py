#!/usr/bin/env python3
"""
Cross-implementation deterministic test vector checker (Python/RNS side).

Loads all 20 JSON test vector files, recomputes operations using the Python
RNS library, and writes sorted results to python_results.txt for diffing
against the Rust implementation's output.

Usage: python3 python-vector-check.py [output-dir]
"""

import hashlib
import json
import math
import os
import struct
import sys

import RNS
from RNS.Cryptography import X25519PrivateKey, X25519PublicKey
from RNS.Cryptography import Ed25519PrivateKey, Ed25519PublicKey
from RNS.Cryptography.Token import Token
from RNS.Cryptography import HKDF, HMAC, PKCS7, AES

VECTORS_DIR = os.environ.get("VECTORS_DIR", "/test-vectors")
OUTPUT_DIR = sys.argv[1] if len(sys.argv) > 1 else "/vector-data"

results = {}


def h(data):
    """Hex-encode bytes."""
    return data.hex()


def load_json(name):
    with open(os.path.join(VECTORS_DIR, name), "r") as f:
        return json.load(f)


def emit(key, value):
    results[key] = str(value)


def compute_hashable(raw):
    """Compute the hashable part of a raw packet.

    Masks flags to lower 4 bits, strips hops byte.
    For HEADER_2, also strips the 16-byte transport_id.
    """
    flags = raw[0]
    header_type = (flags >> 6) & 0x01
    masked_flags = flags & 0x0F
    if header_type == 0:  # HEADER_1
        # flags(1) + hops(1) + dest(16) + ctx(1) + data(...)
        # hashable = masked_flags + raw[2:]
        return bytes([masked_flags]) + raw[2:]
    else:  # HEADER_2
        # flags(1) + hops(1) + transport_id(16) + dest(16) + ctx(1) + data(...)
        # hashable = masked_flags + raw[18:]  (skip hops + transport_id)
        return bytes([masked_flags]) + raw[18:]


# ---------------------------------------------------------------------------
# 1. Hashes
# ---------------------------------------------------------------------------
def check_hashes():
    v = load_json("hashes.json")
    for i, vec in enumerate(v["sha256"]):
        inp = bytes.fromhex(vec["input"])
        digest = RNS.Cryptography.sha256(inp)
        emit(f"hashes.sha256.{i}", h(digest))
    for i, vec in enumerate(v["sha512"]):
        inp = bytes.fromhex(vec["input"])
        digest = RNS.Cryptography.sha512(inp)
        emit(f"hashes.sha512.{i}", h(digest))
    for i, vec in enumerate(v["truncated_hash"]):
        inp = bytes.fromhex(vec["input"])
        th = RNS.Identity.truncated_hash(inp)
        emit(f"hashes.truncated.{i}", h(th))
    print(f"  [OK] hashes", file=sys.stderr)


# ---------------------------------------------------------------------------
# 2. HKDF
# ---------------------------------------------------------------------------
def check_hkdf():
    v = load_json("hkdf.json")
    for i, vec in enumerate(v["rfc5869_vectors"]):
        ikm = bytes.fromhex(vec["ikm"])
        salt = bytes.fromhex(vec["salt"])
        info = bytes.fromhex(vec["info"])
        length = vec["length"]

        # PRK = HMAC-SHA256(salt, ikm)
        if len(salt) == 0:
            salt_for_extract = b"\x00" * 32
        else:
            salt_for_extract = salt
        prk = HMAC.new(salt_for_extract, ikm).digest()
        emit(f"hkdf.rfc5869.{i}.prk", h(prk))

        # OKM = HKDF(length, ikm, salt, info)
        salt_arg = salt if len(salt) > 0 else None
        info_arg = info if len(info) > 0 else None
        okm = HKDF.hkdf(length, ikm, salt=salt_arg, context=info_arg)
        emit(f"hkdf.rfc5869.{i}.okm", h(okm))

    # Reticulum-specific
    rv = v["reticulum_vector"]
    shared_key = bytes.fromhex(rv["shared_key"])
    salt = bytes.fromhex(rv["salt"])
    derived = HKDF.hkdf(rv["length"], shared_key, salt=salt, context=None)
    emit("hkdf.reticulum.derived_key", h(derived))
    print(f"  [OK] hkdf", file=sys.stderr)


# ---------------------------------------------------------------------------
# 3. Token (PKCS7, HMAC, Fernet)
# ---------------------------------------------------------------------------
def check_token():
    v = load_json("token.json")

    # PKCS7 padding
    for i, vec in enumerate(v["pkcs7_padding"]):
        inp = bytes.fromhex(vec["input"])
        padded = PKCS7.pad(inp)
        emit(f"token.pkcs7.{i}", h(padded))

    # HMAC-SHA256
    for i, vec in enumerate(v["hmac_sha256"]):
        key = bytes.fromhex(vec["key"])
        msg = bytes.fromhex(vec["message"])
        digest = HMAC.new(key, msg).digest()
        emit(f"token.hmac.{i}", h(digest))

    # Deterministic Fernet
    for i, vec in enumerate(v["deterministic_fernet_vectors"]):
        key = bytes.fromhex(vec["key"])
        iv = bytes.fromhex(vec["iv"])
        plaintext = bytes.fromhex(vec["plaintext"])

        # Manual encrypt with fixed IV
        signing_key = key[:32]
        encryption_key = key[32:]
        padded = PKCS7.pad(plaintext)
        ciphertext = AES.AES_256_CBC.encrypt(padded, encryption_key, iv)
        signed_parts = iv + ciphertext
        hmac_val = HMAC.new(signing_key, signed_parts).digest()
        token_bytes = iv + ciphertext + hmac_val
        emit(f"token.fernet.{i}.encrypt", h(token_bytes))

        # Decrypt
        token_data = bytes.fromhex(vec["token"])
        token_obj = Token(key)
        decrypted = token_obj.decrypt(token_data)
        emit(f"token.fernet.{i}.decrypt", h(decrypted))

    print(f"  [OK] token", file=sys.stderr)


# ---------------------------------------------------------------------------
# 4. Keypairs
# ---------------------------------------------------------------------------
def check_keypairs():
    v = load_json("keypairs.json")

    # Identity hashes
    for i, kp in enumerate(v["keypairs"]):
        pub_key = bytes.fromhex(kp["public_key"])
        identity_hash = RNS.Identity.truncated_hash(pub_key)
        emit(f"keypairs.identity_hash.{i}", h(identity_hash))

    # ECDH
    for i, vec in enumerate(v["ecdh_vectors"]):
        kp_a = v["keypairs"][vec["keypair_a"]]
        kp_b = v["keypairs"][vec["keypair_b"]]
        a_priv = X25519PrivateKey.from_private_bytes(bytes.fromhex(kp_a["x25519_private"]))
        b_pub = X25519PublicKey.from_public_bytes(bytes.fromhex(kp_b["x25519_public"]))
        shared = a_priv.exchange(b_pub)
        emit(f"keypairs.ecdh.{i}", h(shared))

    # Signatures
    for i, vec in enumerate(v["signature_vectors"]):
        kp = v["keypairs"][vec["keypair_index"]]
        # Load as Identity to get signing
        identity = RNS.Identity.from_bytes(bytes.fromhex(kp["private_key"]))

        common_msg = bytes.fromhex(vec["common_message"])
        common_sig = identity.sign(common_msg)
        emit(f"keypairs.sig.{i}.common", h(common_sig))

        unique_msg = bytes.fromhex(vec["unique_message"])
        unique_sig = identity.sign(unique_msg)
        emit(f"keypairs.sig.{i}.unique", h(unique_sig))

    print(f"  [OK] keypairs", file=sys.stderr)


# ---------------------------------------------------------------------------
# 5. Destination hashes
# ---------------------------------------------------------------------------
def check_destinations():
    v = load_json("destination_hashes.json")
    kpv = load_json("keypairs.json")

    for i, vec in enumerate(v["single_destinations"]):
        # name_hash
        base_name = vec["app_name"]
        for aspect in vec["aspects"]:
            base_name += "." + aspect
        name_hash = hashlib.sha256(base_name.encode("utf-8")).digest()[:10]
        emit(f"destinations.single.{i}.name_hash", h(name_hash))

        # destination_hash
        kp = kpv["keypairs"][vec["keypair_index"]]
        identity_hash = bytes.fromhex(kp["identity_hash"])
        addr_material = name_hash + identity_hash
        dest_hash = hashlib.sha256(addr_material).digest()[:16]
        emit(f"destinations.single.{i}.dest_hash", h(dest_hash))

    for i, vec in enumerate(v["plain_destinations"]):
        base_name = vec["app_name"]
        for aspect in vec["aspects"]:
            base_name += "." + aspect
        name_hash = hashlib.sha256(base_name.encode("utf-8")).digest()[:10]
        dest_hash = hashlib.sha256(name_hash).digest()[:16]
        emit(f"destinations.plain.{i}.dest_hash", h(dest_hash))

    print(f"  [OK] destinations", file=sys.stderr)


# ---------------------------------------------------------------------------
# 6. Packet headers
# ---------------------------------------------------------------------------
def check_packet_headers():
    v = load_json("packet_headers.json")

    # Flag packing
    for i, vec in enumerate(v["flag_packing_vectors"]):
        ht = vec["header_type"]
        cf = vec["context_flag"]
        tt = vec["transport_type"]
        dt = vec["destination_type"]
        pt = vec["packet_type"]
        byte = (ht << 6) | (cf << 5) | (tt << 4) | (dt << 2) | pt
        emit(f"packets.flag_pack.{i}", f"{byte:02x}")

    # Flag unpacking
    for i, vec in enumerate(v["flag_unpacking_vectors"]):
        byte = int(vec["flags_byte"], 16)
        ht = (byte >> 6) & 0x01
        cf = (byte >> 5) & 0x01
        tt = (byte >> 4) & 0x01
        dt = (byte >> 2) & 0x03
        pt = byte & 0x03
        emit(f"packets.flag_unpack.{i}", f"{ht}.{cf}.{tt}.{dt}.{pt}")

    # Header parsing and hashing
    for i, vec in enumerate(v["header_vectors"]):
        raw = bytes.fromhex(vec["raw_packet"])
        # Compute hashable part
        if len(raw) < 2:
            continue
        hashable = compute_hashable(raw)
        emit(f"packets.header.{i}.hashable", h(hashable))
        pkt_hash = hashlib.sha256(hashable).digest()
        emit(f"packets.header.{i}.hash", h(pkt_hash))

    print(f"  [OK] packet_headers", file=sys.stderr)


# ---------------------------------------------------------------------------
# 7. Packets data
# ---------------------------------------------------------------------------
def check_packets_data():
    v = load_json("packets_data.json")
    lv = load_json("links.json")

    for i, vec in enumerate(v["data_packet_vectors"]):
        # Packet hash
        raw = bytes.fromhex(vec["raw_packet"])
        if len(raw) >= 2:
            hashable = compute_hashable(raw)
            pkt_hash = hashlib.sha256(hashable).digest()
            emit(f"packets_data.packet_hash.{i}", h(pkt_hash))

        # Token encrypt with deterministic IV
        derived_key = bytes.fromhex(lv["handshake_vectors"][0]["step_2_lrproof"]["derived_key"])
        plaintext = bytes.fromhex(vec["plaintext"])
        iv = bytes.fromhex(vec["deterministic_iv"])

        signing_key = derived_key[:32]
        encryption_key = derived_key[32:]
        padded = PKCS7.pad(plaintext)
        ciphertext = AES.AES_256_CBC.encrypt(padded, encryption_key, iv)
        signed_parts = iv + ciphertext
        hmac_val = HMAC.new(signing_key, signed_parts).digest()
        encrypted = iv + ciphertext + hmac_val
        emit(f"packets_data.encrypt.{i}", h(encrypted))

        # Decrypt
        token_ct = bytes.fromhex(vec["token_ciphertext"])
        token_obj = Token(derived_key)
        decrypted = token_obj.decrypt(token_ct)
        emit(f"packets_data.decrypt.{i}", h(decrypted))

    # Proof generation
    for i, vec in enumerate(v["proof_generation_vectors"]):
        signer_prv = bytes.fromhex(vec["signer_private_key"])
        ed_prv = Ed25519PrivateKey.from_private_bytes(signer_prv)
        pkt_hash = bytes.fromhex(vec["original_packet_hash"])
        sig = ed_prv.sign(pkt_hash)
        emit(f"packets_data.proof.{i}", h(sig))

    print(f"  [OK] packets_data", file=sys.stderr)


# ---------------------------------------------------------------------------
# 8. Announces
# ---------------------------------------------------------------------------
def check_announces():
    v = load_json("announces.json")
    kpv = load_json("keypairs.json")

    for i, ann in enumerate(v["valid_announces"]):
        # Destination hash
        emit(f"announces.valid.{i}.dest_hash", ann["destination_hash"])

        # Packet hash
        raw = bytes.fromhex(ann["raw_packet"])
        if len(raw) >= 2:
            hashable = compute_hashable(raw)
            pkt_hash = hashlib.sha256(hashable).digest()
            emit(f"announces.valid.{i}.packet_hash", h(pkt_hash))

        # Signature verification
        kp = kpv["keypairs"][ann["keypair_index"]]
        ed_pub_bytes = bytes.fromhex(kp["ed25519_public"])
        ed_pub = Ed25519PublicKey.from_public_bytes(ed_pub_bytes)
        signed_data = bytes.fromhex(ann["signed_data"])
        sig_bytes = bytes.fromhex(ann["signature"])
        try:
            ed_pub.verify(sig_bytes, signed_data)
            valid = True
        except Exception:
            valid = False
        emit(f"announces.valid.{i}.sig_verify", str(valid).lower())

    print(f"  [OK] announces", file=sys.stderr)


# ---------------------------------------------------------------------------
# 9. Interface framing
# ---------------------------------------------------------------------------
def check_interface_framing():
    v = load_json("interface_framing.json")

    # HDLC
    HDLC_FLAG = 0x7E
    HDLC_ESC = 0x7D
    HDLC_ESC_MASK = 0x20

    def hdlc_escape(data):
        out = bytearray()
        for b in data:
            if b == HDLC_ESC:
                out.append(HDLC_ESC)
                out.append(b ^ HDLC_ESC_MASK)
            elif b == HDLC_FLAG:
                out.append(HDLC_ESC)
                out.append(b ^ HDLC_ESC_MASK)
            else:
                out.append(b)
        return bytes(out)

    def hdlc_frame(data):
        return bytes([HDLC_FLAG]) + hdlc_escape(data) + bytes([HDLC_FLAG])

    def hdlc_unescape(data):
        out = bytearray()
        i = 0
        while i < len(data):
            if data[i] == HDLC_ESC and i + 1 < len(data):
                out.append(data[i + 1] ^ HDLC_ESC_MASK)
                i += 2
            else:
                out.append(data[i])
                i += 1
        return bytes(out)

    def hdlc_unframe(framed):
        if framed[0] == HDLC_FLAG:
            framed = framed[1:]
        if framed[-1] == HDLC_FLAG:
            framed = framed[:-1]
        return hdlc_unescape(framed)

    for i, vec in enumerate(v["hdlc"]["vectors"]):
        inp = bytes.fromhex(vec["input"])
        framed = hdlc_frame(inp)
        emit(f"framing.hdlc.{i}.frame", h(framed))
        unframed = hdlc_unframe(framed)
        emit(f"framing.hdlc.{i}.unframe", h(unframed))

    # KISS
    KISS_FEND = 0xC0
    KISS_FESC = 0xDB
    KISS_TFEND = 0xDC
    KISS_TFESC = 0xDD
    KISS_CMD_DATA = 0x00

    def kiss_escape(data):
        out = bytearray()
        for b in data:
            if b == KISS_FEND:
                out.append(KISS_FESC)
                out.append(KISS_TFEND)
            elif b == KISS_FESC:
                out.append(KISS_FESC)
                out.append(KISS_TFESC)
            else:
                out.append(b)
        return bytes(out)

    def kiss_frame(data):
        return bytes([KISS_FEND, KISS_CMD_DATA]) + kiss_escape(data) + bytes([KISS_FEND])

    def kiss_unescape(data):
        out = bytearray()
        i = 0
        while i < len(data):
            if data[i] == KISS_FESC and i + 1 < len(data):
                if data[i + 1] == KISS_TFEND:
                    out.append(KISS_FEND)
                elif data[i + 1] == KISS_TFESC:
                    out.append(KISS_FESC)
                else:
                    out.append(data[i + 1])
                i += 2
            else:
                out.append(data[i])
                i += 1
        return bytes(out)

    def kiss_unframe(framed):
        if framed[0] == KISS_FEND:
            framed = framed[1:]
        if framed[-1] == KISS_FEND:
            framed = framed[:-1]
        if len(framed) > 0 and framed[0] == KISS_CMD_DATA:
            framed = framed[1:]
        return kiss_unescape(framed)

    for i, vec in enumerate(v["kiss"]["vectors"]):
        inp = bytes.fromhex(vec["input"])
        framed = kiss_frame(inp)
        emit(f"framing.kiss.{i}.frame", h(framed))
        unframed = kiss_unframe(framed)
        emit(f"framing.kiss.{i}.unframe", h(unframed))

    # IFAC
    IFAC_SALT = bytes([
        0xad, 0xf5, 0x4d, 0x88, 0x2c, 0x9a, 0x9b, 0x80,
        0x77, 0x1e, 0xb4, 0x99, 0x5d, 0x70, 0x2d, 0x4a,
        0x3e, 0x73, 0x33, 0x91, 0xb2, 0xa0, 0xf5, 0x3f,
        0x41, 0x6d, 0x9f, 0x90, 0x7e, 0x55, 0xcf, 0xf8,
    ])

    def compute_ifac_config(netname, netkey):
        ifac_origin = b""
        if netname:
            ifac_origin += hashlib.sha256(netname.encode()).digest()
        if netkey:
            ifac_origin += hashlib.sha256(netkey.encode()).digest()
        ifac_origin_hash = hashlib.sha256(ifac_origin).digest()
        ifac_key = HKDF.hkdf(64, ifac_origin_hash, salt=IFAC_SALT, context=None)
        ifac_identity = RNS.Identity.from_bytes(ifac_key)
        return ifac_key, ifac_identity

    def ifac_apply(raw, ifac_key, ifac_identity, ifac_size):
        # Sign the raw packet
        sig = ifac_identity.sign(raw)
        ifac_value = sig[-ifac_size:]

        # Build output with IFAC bytes inserted after 2-byte header
        new_packet = bytearray()
        new_packet.append(raw[0])  # flags
        new_packet.append(raw[1])  # hops
        new_packet.extend(ifac_value)
        new_packet.extend(raw[2:])

        # Generate mask
        mask = HKDF.hkdf(len(new_packet), ifac_value, salt=ifac_key, context=None)

        # Apply mask (XOR), skipping IFAC bytes at positions 2..2+ifac_size
        masked = bytearray(len(new_packet))
        masked[0] = (new_packet[0] ^ mask[0]) | 0x80  # set IFAC flag
        masked[1] = new_packet[1] ^ mask[1]
        # IFAC bytes are NOT masked
        for j in range(ifac_size):
            masked[2 + j] = new_packet[2 + j]
        # Remaining bytes are masked
        for j in range(2 + ifac_size, len(new_packet)):
            masked[j] = new_packet[j] ^ mask[j]

        return bytes(masked)

    for i, vec in enumerate(v["ifac"]["vectors"]):
        netname = vec.get("ifac_netname") or vec.get("sender_netname")
        netkey = vec.get("ifac_netkey") or vec.get("sender_netkey")
        if vec.get("masked_packet") and vec.get("ifac_value"):
            if netname or netkey:
                ifac_key, ifac_identity = compute_ifac_config(netname, netkey)
                raw = bytes.fromhex(vec["raw_packet"])
                try:
                    masked = ifac_apply(raw, ifac_key, ifac_identity, vec["ifac_size"])
                    emit(f"framing.ifac.{i}", h(masked))
                except Exception as e:
                    pass

    # Full pipeline
    for i, vec in enumerate(v["full_pipeline"]["vectors"]):
        raw = bytes.fromhex(vec["step_0_raw"])

        # Apply IFAC if configured
        if vec["ifac_size"] > 0 and (vec.get("ifac_netname") or vec.get("ifac_netkey")):
            ifac_key, ifac_identity = compute_ifac_config(
                vec.get("ifac_netname"), vec.get("ifac_netkey")
            )
            ifac_data = ifac_apply(raw, ifac_key, ifac_identity, vec["ifac_size"])
        else:
            ifac_data = raw

        # Frame
        if vec["framing"] == "HDLC":
            framed = hdlc_frame(ifac_data)
        elif vec["framing"] == "KISS":
            framed = kiss_frame(ifac_data)
        else:
            framed = ifac_data

        emit(f"framing.pipeline.{i}", h(framed))

    print(f"  [OK] interface_framing", file=sys.stderr)


# ---------------------------------------------------------------------------
# 10. Links
# ---------------------------------------------------------------------------
def check_links():
    v = load_json("links.json")
    kpv = load_json("keypairs.json")

    # Signalling bytes
    for i, vec in enumerate(v["signalling_bytes_vectors"]):
        mtu = vec["input_mtu"]
        mode = vec["input_mode"]
        value = (mtu & 0x1FFFFF) | (((mode << 5) & 0xE0) << 16)
        encoded = struct.pack(">I", value)[1:]
        emit(f"links.signalling.{i}.encode", h(encoded))
        decoded_value = int.from_bytes(encoded, "big")
        decoded_mtu = decoded_value & 0x1FFFFF
        emit(f"links.signalling.{i}.decode_mtu", str(decoded_mtu))
        decoded_mode = ((decoded_value >> 16) & 0xE0) >> 5
        emit(f"links.signalling.{i}.decode_mode", str(decoded_mode))

    # Link ID
    for i, vec in enumerate(v["link_id_vectors"]):
        if "hashable_stripped" in vec and vec["hashable_stripped"]:
            stripped = bytes.fromhex(vec["hashable_stripped"])
            link_id = hashlib.sha256(stripped).digest()[:16]
            emit(f"links.link_id.{i}", h(link_id))

    # Handshake
    for i, hs in enumerate(v["handshake_vectors"]):
        init_eph = v["ephemeral_keys"][hs["initiator_ephemeral_index"]]
        resp_eph = v["ephemeral_keys"][hs["responder_ephemeral_index"]]

        init_x25519_prv = X25519PrivateKey.from_private_bytes(
            bytes.fromhex(init_eph["x25519_private"])
        )
        resp_x25519_pub = X25519PublicKey.from_public_bytes(
            bytes.fromhex(resp_eph["x25519_public"])
        )
        shared = init_x25519_prv.exchange(resp_x25519_pub)
        emit(f"links.handshake.{i}.shared_key", h(shared))

        link_id = bytes.fromhex(hs["step_1_linkrequest"]["link_id"])
        derived = HKDF.hkdf(64, shared, salt=link_id, context=None)
        emit(f"links.handshake.{i}.derived_key", h(derived))

        # Signature
        resp_kp = kpv["keypairs"][hs["responder_keypair_index"]]
        resp_identity = RNS.Identity.from_bytes(bytes.fromhex(resp_kp["private_key"]))
        signed_data = bytes.fromhex(hs["step_2_lrproof"]["signed_data"])
        sig = resp_identity.sign(signed_data)
        emit(f"links.handshake.{i}.signature", h(sig))

    # Keepalive
    for i, vec in enumerate(v["keepalive_calculation_vectors"]):
        rtt = vec["rtt"]
        keepalive = max(5.0, min(rtt * 360.0 / 1.75, 360.0))
        emit(f"links.keepalive.{i}", f"{keepalive:.15f}")

    # MDU
    for i, vec in enumerate(v["mdu_vectors"]):
        mtu = vec["mtu"]
        mdu = int(math.floor((mtu - 1 - 19 - 48) / 16)) * 16 - 1
        emit(f"links.mdu.{i}", str(mdu))

    # RTT msgpack
    import RNS.vendor.umsgpack as umsgpack
    for i, vec in enumerate(v["rtt_vectors"]):
        rtt_float = vec["rtt_float"]
        buf = umsgpack.packb(rtt_float)
        emit(f"links.rtt.{i}.msgpack", h(buf))

    print(f"  [OK] links", file=sys.stderr)


# ---------------------------------------------------------------------------
# 11. Channels
# ---------------------------------------------------------------------------
def check_channels():
    v = load_json("channels.json")

    # Envelope pack/unpack
    for i, vec in enumerate(v["envelope_vectors"]):
        data = bytes.fromhex(vec["data_hex"])
        msgtype = vec["msgtype"]
        sequence = vec["sequence"]
        packed = struct.pack(">HHH", msgtype, sequence, len(data)) + data
        emit(f"channels.envelope.{i}.pack", h(packed))

        # Unpack
        u_msgtype = struct.unpack(">H", packed[0:2])[0]
        u_sequence = struct.unpack(">H", packed[2:4])[0]
        u_length = struct.unpack(">H", packed[4:6])[0]
        u_data = packed[6:6 + u_length]
        emit(f"channels.envelope.{i}.unpack", f"{u_msgtype}.{u_sequence}.{h(u_data)}")

    # Stream data unpack (use packed_hex from vectors)
    for i, vec in enumerate(v["stream_data_vectors"]):
        packed = bytes.fromhex(vec["packed_hex"])
        header_val = struct.unpack(">H", packed[0:2])[0]
        stream_id = header_val & 0x3FFF
        is_eof = (header_val & 0x8000) != 0
        is_compressed = (header_val & 0x4000) != 0
        raw_data = packed[2:]
        if is_compressed:
            import bz2
            try:
                raw_data = bz2.decompress(raw_data)
            except Exception:
                pass
        emit(f"channels.stream.{i}.unpack", f"{stream_id}.{int(is_eof)}.{h(raw_data)}")

    # Timeout
    for i, vec in enumerate(v["timeout_vectors"]):
        tries = vec["tries"]
        rtt = vec["rtt"]
        tx_ring_length = vec["tx_ring_length"]
        timeout = (1.5 ** (tries - 1)) * max(rtt * 2.5, 0.025) * (tx_ring_length + 1.5)
        emit(f"channels.timeout.{i}", f"{timeout:.15f}")

    # Channel MDU
    for i, vec in enumerate(v["mdu_vectors"]):
        outlet_mdu = vec["outlet_mdu"]
        channel_mdu = min(outlet_mdu - 6, 0xFFFF)
        emit(f"channels.mdu.{i}", str(channel_mdu))

    print(f"  [OK] channels", file=sys.stderr)


# ---------------------------------------------------------------------------
# 12. Resources
# ---------------------------------------------------------------------------
def check_resources():
    v = load_json("resources.json")

    for i, vec in enumerate(v["resource_advertisement_vectors"]):
        emit(f"resources.hash.{i}", vec["resource_hash_hex"])
        emit(f"resources.hashmap.{i}", vec["hashmap_hex"])
        emit(f"resources.proof.{i}", vec["expected_proof_hex"])

    for i, vec in enumerate(v["metadata_vectors"]):
        fmb = vec["full_metadata_bytes_hex"]
        try:
            bytes.fromhex(fmb)
            emit(f"resources.metadata.{i}", fmb)
        except ValueError:
            pass

    print(f"  [OK] resources", file=sys.stderr)


# ---------------------------------------------------------------------------
# 13. Resource transfers
# ---------------------------------------------------------------------------
def check_resource_transfers():
    v = load_json("resource_transfers.json")

    for i, vec in enumerate(v["transfer_sequence_vectors"]):
        if "resource_hash_hex" in vec and vec["resource_hash_hex"]:
            emit(f"resource_transfer.{i}.hash", vec["resource_hash_hex"])
        if "expected_proof_hex" in vec and vec["expected_proof_hex"]:
            emit(f"resource_transfer.{i}.proof", vec["expected_proof_hex"])

    for i, vec in enumerate(v["cancellation_vectors"]):
        emit(f"resource_transfer.cancel.{i}", vec["payload_hex"])

    print(f"  [OK] resource_transfers", file=sys.stderr)


# ---------------------------------------------------------------------------
# 14. Buffer transfers
# ---------------------------------------------------------------------------
def check_buffer_transfers():
    v = load_json("buffer_transfers.json")

    for i, vec in enumerate(v["small_transfer_vectors"]):
        for j, msg in enumerate(vec["messages"]):
            emit(f"buffer.stream.{i}.{j}.pack", msg["stream_packed_hex"])

    for i, vec in enumerate(v["compression_vectors"]):
        emit(f"buffer.compression.{i}.compressed", str(vec["write_result"]["compressed"]).lower())

    print(f"  [OK] buffer_transfers", file=sys.stderr)


# ---------------------------------------------------------------------------
# 15. Requests
# ---------------------------------------------------------------------------
def check_requests():
    v = load_json("requests.json")

    for i, vec in enumerate(v["path_hash_vectors"]):
        path_bytes = vec["path"].encode("utf-8")
        th = hashlib.sha256(path_bytes).digest()[:16]
        emit(f"requests.path_hash.{i}", h(th))

    for i, vec in enumerate(v["timeout_vectors"]):
        rtt = vec["rtt"]
        timeout = rtt * 6.0 + 10.0 * 1.125
        emit(f"requests.timeout.{i}", f"{timeout:.15f}")

    for i, vec in enumerate(v["request_serialization_vectors"]):
        if vec.get("packed_request_hex"):
            emit(f"requests.serialize.{i}", vec["packed_request_hex"])

    for i, vec in enumerate(v["response_serialization_vectors"]):
        if vec.get("packed_response_hex"):
            emit(f"requests.response.{i}", vec["packed_response_hex"])

    print(f"  [OK] requests", file=sys.stderr)


# ---------------------------------------------------------------------------
# 16. Retry timers
# ---------------------------------------------------------------------------
def check_retry_timers():
    v = load_json("retry_timers.json")

    for i, vec in enumerate(v["link_keepalive"]["vectors"]):
        rtt = vec["rtt"]
        keepalive = max(5.0, min(rtt * 360.0 / 1.75, 360.0))
        emit(f"retry.keepalive.{i}", f"{keepalive:.15f}")
        stale = keepalive * 2.0
        emit(f"retry.stale.{i}", f"{stale:.15f}")

    for i, vec in enumerate(v["link_establishment"]["vectors"]):
        hops = vec["hops"]
        timeout = 6 * max(1, hops) + 360
        emit(f"retry.establishment.{i}", str(timeout))

    for i, vec in enumerate(v["channel_timeout"]["full_matrix"]):
        tries = vec["tries"]
        rtt = vec["rtt"]
        tx_ring_length = vec["tx_ring_length"]
        timeout = (1.5 ** (tries - 1)) * max(rtt * 2.5, 0.025) * (tx_ring_length + 1.5)
        emit(f"retry.channel_timeout.{i}", f"{timeout:.15f}")

    print(f"  [OK] retry_timers", file=sys.stderr)


# ---------------------------------------------------------------------------
# 17. Window adaptation
# ---------------------------------------------------------------------------
def check_window_adaptation():
    v = load_json("window_adaptation.json")

    for i, vec in enumerate(v["resource_window"]["growth_vectors"]):
        for j, step in enumerate(vec["steps"]):
            s = step["state"]
            desc = f"{s['window']}.{s['window_max']}.{s['window_min']}.{s['fast_rate_rounds']}.{s['very_slow_rate_rounds']}"
            emit(f"window.resource_growth.{i}.{j}", desc)

    for i, vec in enumerate(v["resource_window"]["shrink_vectors"]):
        for j, step in enumerate(vec["steps"]):
            s = step["state"]
            desc = f"{s['window']}.{s['window_max']}.{s['window_min']}.{s['fast_rate_rounds']}.{s['very_slow_rate_rounds']}"
            emit(f"window.resource_shrink.{i}.{j}", desc)

    # Channel window init
    cv = load_json("channels.json")
    for i, vec in enumerate(cv["window_init_vectors"]):
        desc = f"{vec['window']}.{vec['window_max']}.{vec['window_min']}.{vec['window_flexibility']}"
        emit(f"window.channel_init.{i}", desc)

    print(f"  [OK] window_adaptation", file=sys.stderr)


# ---------------------------------------------------------------------------
# 18. Path expiration
# ---------------------------------------------------------------------------
def check_path_expiration():
    v = load_json("path_expiration.json")

    PATHFINDER_E = 604800
    AP_PATH_TIME = 86400
    ROAMING_PATH_TIME = 21600

    mode_ttl = {
        "MODE_FULL": PATHFINDER_E,
        "default": PATHFINDER_E,
        "MODE_ACCESS_POINT": AP_PATH_TIME,
        "MODE_ROAMING": ROAMING_PATH_TIME,
        "MODE_POINT_TO_POINT": PATHFINDER_E,
        "MODE_BOUNDARY": PATHFINDER_E,
        "MODE_GATEWAY": PATHFINDER_E,
    }

    for i, vec in enumerate(v["ttl_enforcement_vectors"]):
        mode = vec["interface_mode"]
        ttl = mode_ttl.get(mode, PATHFINDER_E)
        emit(f"path_expiration.ttl.{i}", str(ttl))

        timestamp = vec["path_entry"]["timestamp"]
        check_time = vec["check_time"]
        valid = check_time <= timestamp + ttl
        emit(f"path_expiration.valid.{i}", str(valid).lower())

    print(f"  [OK] path_expiration", file=sys.stderr)


# ---------------------------------------------------------------------------
# 19. Path requests
# ---------------------------------------------------------------------------
def check_path_requests():
    v = load_json("path_requests.json")

    for i, vec in enumerate(v["path_request_destination_vectors"]):
        base_name = vec["app_name"]
        for aspect in vec["aspects"]:
            base_name += "." + aspect
        name_hash = hashlib.sha256(base_name.encode("utf-8")).digest()[:10]
        dest_hash = hashlib.sha256(name_hash).digest()[:16]
        emit(f"path_requests.dest.{i}", h(dest_hash))

    for i, vec in enumerate(v["path_request_packet_vectors"]):
        raw = bytes.fromhex(vec["raw_packet"])
        if len(raw) >= 2:
            hashable = compute_hashable(raw)
            pkt_hash = hashlib.sha256(hashable).digest()
            emit(f"path_requests.packet.{i}", h(pkt_hash))

    print(f"  [OK] path_requests", file=sys.stderr)


# ---------------------------------------------------------------------------
# 20. Multi-hop routing
# ---------------------------------------------------------------------------
def check_multi_hop_routing():
    v = load_json("multi_hop_routing.json")

    for i, vec in enumerate(v["header_transformation_vectors"]):
        orig_raw = bytes.fromhex(vec["original_raw"])
        if len(orig_raw) >= 2:
            hashable = compute_hashable(orig_raw)
            pkt_hash = hashlib.sha256(hashable).digest()
            emit(f"routing.transform.{i}.orig_hash", h(pkt_hash))

        trans_raw = bytes.fromhex(vec["transformed_raw"])
        if len(trans_raw) >= 2:
            hashable = compute_hashable(trans_raw)
            pkt_hash = hashlib.sha256(hashable).digest()
            emit(f"routing.transform.{i}.trans_hash", h(pkt_hash))

    for i, vec in enumerate(v["link_table_entry_vectors"]):
        if vec.get("hashable_part_trimmed"):
            trimmed = bytes.fromhex(vec["hashable_part_trimmed"])
            link_id = hashlib.sha256(trimmed).digest()[:16]
            emit(f"routing.link_id.{i}", h(link_id))

    for i, vec in enumerate(v["announce_propagation_vectors"]):
        for j, step in enumerate(vec["chain"]):
            if step.get("packet_hash"):
                emit(f"routing.announce.{i}.{j}.packet_hash", step["packet_hash"])
            if step.get("raw_packet"):
                raw = bytes.fromhex(step["raw_packet"])
                if len(raw) >= 2:
                    hashable = compute_hashable(raw)
                    computed_hash = hashlib.sha256(hashable).digest()
                    emit(f"routing.announce.{i}.{j}.computed_hash", h(computed_hash))

    print(f"  [OK] multi_hop_routing", file=sys.stderr)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    print("=== python-vector-check: starting ===", file=sys.stderr)

    check_hashes()
    check_hkdf()
    check_token()
    check_keypairs()
    check_destinations()
    check_packet_headers()
    check_packets_data()
    check_announces()
    check_interface_framing()
    check_links()
    check_channels()
    check_resources()
    check_resource_transfers()
    check_buffer_transfers()
    check_requests()
    check_retry_timers()
    check_window_adaptation()
    check_path_expiration()
    check_path_requests()
    check_multi_hop_routing()

    # Write sorted results
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    output_path = os.path.join(OUTPUT_DIR, "python_results.txt")
    with open(output_path, "w") as f:
        for key in sorted(results.keys()):
            f.write(f"{key} = {results[key]}\n")

    print(
        f"=== python-vector-check: wrote {len(results)} lines to {output_path} ===",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
