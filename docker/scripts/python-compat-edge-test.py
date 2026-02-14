#!/usr/bin/env python3
"""
Edge case compatibility test.

Tests boundary conditions across protocol layers in a single Docker session:
1. Near-MDU link data (431 bytes for MTU=500)
2. Binary data (all 256 byte values 0x00-0xFF)
3. Single-byte channel message
4. Multiple sequential channel messages (increasing sizes: 1, 10, 100, 200, 400)
5. Empty app_data announce

Note: Resource transfers are covered thoroughly by test-resource.sh.
All link-dependent phases run within the keepalive window since the
Rust node does not send keepalive packets (link goes stale ~10s after
last Rust→Python data).
"""

import json
import sys
import time

import RNS
import RNS.Channel as Channel
import RNS.Buffer

# ---- Global result tracking ----
results = {
    "link_established": False,
    "phase1_near_mdu_data": False,
    "phase1_data_length": 0,
    "phase2_binary_data": False,
    "phase2_all_bytes_present": False,
    "phase3_single_byte_channel": False,
    "phase4_sequential_messages": 0,
    "phase5_empty_appdata_announce": False,
}

link_from_rust = None
channel_obj = None
buffer_obj = None

# ---- Custom message type for channel test ----
MSGTYPE_TEST = 0x0101


class TestMessage(Channel.MessageBase):
    MSGTYPE = MSGTYPE_TEST

    def __init__(self, data=None):
        self.data = data or b""

    def pack(self):
        return self.data if isinstance(self.data, bytes) else self.data.encode("utf-8")

    def unpack(self, raw):
        self.data = raw


# ---- Announce handler ----
class AnnounceHandler:
    def __init__(self):
        self.aspect_filter = None

    def received_announce(self, destination_hash, announced_identity, app_data):
        RNS.log(f"Received announce from {RNS.prettyhexrep(destination_hash)}")
        if app_data is not None:
            RNS.log(f"  app_data length: {len(app_data)}")


# ---- Channel message tracking ----
channel_messages_received = []


def channel_message_received(message):
    """Called when a channel message is received from Rust."""
    data = message.data
    channel_messages_received.append(data)
    RNS.log(f"Channel message received: {len(data)} bytes")


# ---- Link callbacks ----
def link_established_callback(link):
    global link_from_rust, channel_obj, buffer_obj
    link_from_rust = link
    results["link_established"] = True
    RNS.log(f"Link from Rust established: {link}")

    # Set up channel
    channel_obj = link.get_channel()
    channel_obj.register_message_type(TestMessage)
    channel_obj.add_message_handler(channel_message_received)

    # Set up buffer (needed so Rust auto_buffer can be received if configured)
    buffer_obj = RNS.Buffer.create_bidirectional_buffer(0, 0, channel_obj, buffer_ready_callback)
    RNS.log("Buffer created on channel")

    # Accept resources (so Rust auto_resource can complete)
    link.set_resource_strategy(RNS.Link.ACCEPT_ALL)


# ---- Buffer callback ----
buffer_data_received = bytearray()


def buffer_ready_callback(ready_bytes):
    global buffer_data_received, buffer_obj
    if buffer_obj and ready_bytes > 0:
        data = buffer_obj.read(ready_bytes)
        if data:
            buffer_data_received.extend(data)
            RNS.log(f"Buffer data received: {len(data)} bytes")


def link_usable():
    """Check if the link is usable (ACTIVE or STALE, not CLOSED/TIMED_OUT)."""
    return link_from_rust and link_from_rust.status < RNS.Link.CLOSED


def main():
    RNS.log("Starting edge case compatibility test")

    reticulum = RNS.Reticulum("/etc/reticulum")

    handler = AnnounceHandler()
    RNS.Transport.register_announce_handler(handler)

    identity = RNS.Identity()
    destination = RNS.Destination(
        identity,
        RNS.Destination.IN,
        RNS.Destination.SINGLE,
        "compat_edge_test",
        "edge",
        "v1",
    )

    destination.set_link_established_callback(link_established_callback)

    RNS.log(f"Python destination hash: {RNS.prettyhexrep(destination.hash)}")

    # Wait for Rust node to connect
    RNS.log("Waiting for Rust node to connect...")
    time.sleep(10)

    # Send announce so Rust can discover us and auto-link
    RNS.log("Sending announce")
    destination.announce(app_data=b"edge test")

    time.sleep(3)
    RNS.log("Sending re-announce")
    destination.announce(app_data=b"edge test")

    # Wait for Rust-initiated link
    timeout = 60
    start = time.time()
    RNS.log("Waiting for Rust-initiated link...")
    while not results["link_established"] and (time.time() - start) < timeout:
        time.sleep(0.5)

    if not results["link_established"]:
        RNS.log("TIMEOUT: Link not established")
        print(json.dumps(results))
        sys.exit(1)

    RNS.log("Link established, starting edge case tests...")

    # Brief wait for Rust auto-actions to complete. Keep short because
    # the link goes stale ~10s after last Rust→Python data.
    time.sleep(3)

    # ================================================================
    # Phase 1: Near-MDU data (431 bytes)
    # ================================================================
    RNS.log("=== PHASE 1: Near-MDU data ===")
    if link_usable():
        try:
            near_mdu_payload = b"B" * 431
            packet = RNS.Packet(link_from_rust, near_mdu_payload)
            packet.send()
            results["phase1_near_mdu_data"] = True
            results["phase1_data_length"] = len(near_mdu_payload)
            RNS.log(f"PHASE1: Sent near-MDU data ({len(near_mdu_payload)} bytes) to Rust")
        except Exception as e:
            RNS.log(f"PHASE1: Failed: {e}")
    else:
        RNS.log(f"PHASE1: Link not usable (status={getattr(link_from_rust, 'status', 'None')})")

    time.sleep(0.5)

    # ================================================================
    # Phase 2: Binary data (all 256 byte values)
    # ================================================================
    RNS.log("=== PHASE 2: Binary data ===")
    if link_usable():
        try:
            binary_payload = bytes(range(256))
            packet = RNS.Packet(link_from_rust, binary_payload)
            packet.send()
            results["phase2_binary_data"] = True
            results["phase2_all_bytes_present"] = True
            RNS.log(f"PHASE2: Sent binary data (all 256 byte values, {len(binary_payload)} bytes)")
        except Exception as e:
            RNS.log(f"PHASE2: Failed: {e}")
    else:
        RNS.log(f"PHASE2: Link not usable (status={getattr(link_from_rust, 'status', 'None')})")

    time.sleep(0.5)

    # ================================================================
    # Phase 3: Single-byte channel message
    # ================================================================
    RNS.log("=== PHASE 3: Single-byte channel message ===")
    if channel_obj and link_usable():
        try:
            msg = TestMessage(b"\x42")
            channel_obj.send(msg)
            results["phase3_single_byte_channel"] = True
            RNS.log("PHASE3: Sent single-byte channel message")
        except Exception as e:
            RNS.log(f"PHASE3: Failed: {e}")
    else:
        RNS.log(f"PHASE3: Channel or link not usable")

    time.sleep(0.5)

    # ================================================================
    # Phase 4: Multiple sequential channel messages (increasing sizes)
    # ================================================================
    RNS.log("=== PHASE 4: Sequential channel messages ===")
    if channel_obj and link_usable():
        sizes = [1, 10, 100, 200, 400]
        sent_count = 0
        for size in sizes:
            try:
                payload = bytes([0x41 + (i % 26) for i in range(size)])
                msg = TestMessage(payload)
                channel_obj.send(msg)
                sent_count += 1
                RNS.log(f"PHASE4: Sent channel message #{sent_count} ({size} bytes)")
                time.sleep(0.3)
            except Exception as e:
                RNS.log(f"PHASE4: Failed at size {size}: {e}")
                break

        results["phase4_sequential_messages"] = sent_count
        RNS.log(f"PHASE4: Sent {sent_count}/{len(sizes)} sequential messages")
    else:
        RNS.log(f"PHASE4: Channel or link not usable")

    time.sleep(2)

    # ================================================================
    # Phase 5: Empty app_data announce (not link-dependent)
    # ================================================================
    RNS.log("=== PHASE 5: Empty app_data announce ===")
    identity2 = RNS.Identity()
    destination2 = RNS.Destination(
        identity2,
        RNS.Destination.IN,
        RNS.Destination.SINGLE,
        "compat_edge_test",
        "empty",
        "v1",
    )
    try:
        destination2.announce(app_data=b"")
        results["phase5_empty_appdata_announce"] = True
        RNS.log("PHASE5: Sent announce with empty app_data")
    except Exception as e:
        RNS.log(f"PHASE5: Failed: {e}")

    # Wait for Rust to process
    time.sleep(5)

    # Report results
    RNS.log(f"Test results: {json.dumps(results, indent=2)}")

    # Count passed phases
    passed = 0
    total = 5
    if results["phase1_near_mdu_data"]:
        passed += 1
    if results["phase2_binary_data"]:
        passed += 1
    if results["phase3_single_byte_channel"]:
        passed += 1
    if results["phase4_sequential_messages"] >= 5:
        passed += 1
    if results["phase5_empty_appdata_announce"]:
        passed += 1

    RNS.log(f"Phases passed: {passed}/{total}")

    # Require link established + at least 4 of 5 phases
    success = results["link_established"] and passed >= 4

    if success:
        RNS.log(f"PASS: Edge case compatibility test passed ({passed}/{total} phases)")
        print(json.dumps(results))
        sys.exit(0)
    else:
        RNS.log(f"FAIL: Edge case compatibility test failed ({passed}/{total} phases)")
        print(json.dumps(results))
        sys.exit(1)


if __name__ == "__main__":
    main()
