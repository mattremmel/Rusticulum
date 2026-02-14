#!/usr/bin/env python3
"""
Multi-hop channel + buffer test: Python endpoints communicating through a Rust relay.

Two roles controlled by ROLE environment variable:
  - "announcer" (Python-A): creates destination, announces, accepts links, handles channel/buffer
  - "linker" (Python-B): discovers announcer, initiates link through relay, sends channel/buffer data

Topology: Python-A <-- Rust-Relay --> Python-B
"""

import json
import os
import sys
import time

import RNS
import RNS.Channel as Channel
import RNS.Buffer

ROLE = os.environ.get("ROLE", "announcer")
APP_NAME = "multihop_channel_test"
ASPECTS = ["channel", "v1"]

results = {
    "role": ROLE,
    "announce_sent": False,
    "announce_received": False,
    "link_established": False,
    "channel_sent": False,
    "channel_received": False,
    "channel_data": None,
    "buffer_sent": False,
    "buffer_received": False,
    "buffer_data": None,
}

discovered_hash = None
discovered_identity = None
established_link = None
channel_obj = None
buffer_obj = None
buffer_data_received = bytearray()

MSGTYPE_TEST = 0x0101


class TestMessage(Channel.MessageBase):
    MSGTYPE = MSGTYPE_TEST

    def __init__(self, data=None):
        self.data = data or b""

    def pack(self):
        return self.data if isinstance(self.data, bytes) else self.data.encode("utf-8")

    def unpack(self, raw):
        self.data = raw


class AnnounceHandler:
    """Class-based announce handler required by RNS Transport API."""

    def __init__(self):
        self.aspect_filter = None

    def received_announce(self, destination_hash, announced_identity, app_data):
        global discovered_hash, discovered_identity
        RNS.log(f"[{ROLE}] Received announce from {RNS.prettyhexrep(destination_hash)}")
        if app_data:
            RNS.log(f"[{ROLE}]   app_data: {app_data}")
        if discovered_hash is None:
            discovered_hash = destination_hash
            discovered_identity = announced_identity
            results["announce_received"] = True
            RNS.log(f"[{ROLE}] Discovered peer: {RNS.prettyhexrep(destination_hash)}")


def channel_message_received(message):
    """Called when a channel message is received."""
    RNS.log(f"[{ROLE}] Channel message received: type={hex(message.MSGTYPE)}, data={message.data}")
    results["channel_received"] = True
    if isinstance(message.data, bytes):
        results["channel_data"] = message.data.decode("utf-8", errors="replace")
    else:
        results["channel_data"] = str(message.data)


def buffer_ready_callback(ready_bytes):
    """Called when buffer data is available."""
    global buffer_data_received, buffer_obj
    if buffer_obj and ready_bytes > 0:
        data = buffer_obj.read(ready_bytes)
        if data:
            buffer_data_received.extend(data)
            results["buffer_received"] = True
            results["buffer_data"] = buffer_data_received.decode("utf-8", errors="replace")
            RNS.log(f"[{ROLE}] Buffer data received: {len(data)} bytes, total: {len(buffer_data_received)}")


def setup_channel_and_buffer(link):
    """Set up channel and buffer on the given link."""
    global channel_obj, buffer_obj
    channel_obj = link.get_channel()
    channel_obj.register_message_type(TestMessage)
    channel_obj.add_message_handler(channel_message_received)
    buffer_obj = RNS.Buffer.create_bidirectional_buffer(0, 0, channel_obj, buffer_ready_callback)
    RNS.log(f"[{ROLE}] Channel and buffer set up")


def link_established_callback(link):
    """Called when an incoming link is established (announcer side)."""
    global established_link
    established_link = link
    results["link_established"] = True
    RNS.log(f"[{ROLE}] Link established (incoming): {link}")
    link.set_resource_strategy(RNS.Link.ACCEPT_ALL)
    setup_channel_and_buffer(link)


def link_ready_callback(link):
    """Called when linker's outbound link is established."""
    global established_link
    established_link = link
    results["link_established"] = True
    RNS.log(f"[{ROLE}] Link established (outgoing): {link}")
    link.set_resource_strategy(RNS.Link.ACCEPT_ALL)
    setup_channel_and_buffer(link)


def run_announcer():
    """Python-A: announce, accept links, handle channel/buffer messages."""
    RNS.log("[announcer] Starting")
    reticulum = RNS.Reticulum("/etc/reticulum")

    identity = RNS.Identity()
    destination = RNS.Destination(
        identity,
        RNS.Destination.IN,
        RNS.Destination.SINGLE,
        APP_NAME,
        *ASPECTS,
    )
    destination.set_link_established_callback(link_established_callback)

    RNS.log(f"[announcer] Destination hash: {RNS.prettyhexrep(destination.hash)}")

    # Wait for Rust relay to connect
    RNS.log("[announcer] Waiting for relay connection...")
    time.sleep(15)

    # Send announces periodically
    for i in range(5):
        RNS.log(f"[announcer] Sending announce (attempt {i+1})")
        destination.announce(app_data=b"python-a channel test")
        results["announce_sent"] = True
        time.sleep(5)
        if results["link_established"]:
            break

    # Wait for link
    timeout = 90
    start = time.time()
    while (time.time() - start) < timeout:
        if results["link_established"]:
            break
        time.sleep(1)

    if not results["link_established"]:
        RNS.log("[announcer] FAIL: no link established")
        RNS.log(f"[announcer] Results: {json.dumps(results, indent=2)}")
        sys.exit(1)

    # Wait for channel message from linker, then send response
    time.sleep(5)

    if channel_obj is not None:
        try:
            msg = TestMessage(b"channel echo from announcer")
            channel_obj.send(msg)
            results["channel_sent"] = True
            RNS.log("[announcer] Sent channel message")
        except Exception as e:
            RNS.log(f"[announcer] Failed to send channel message: {e}")

    # Send buffer data
    if buffer_obj is not None:
        try:
            buffer_obj.write(b"buffer data from announcer")
            buffer_obj.flush()
            results["buffer_sent"] = True
            RNS.log("[announcer] Sent buffer data")
        except Exception as e:
            RNS.log(f"[announcer] Failed to send buffer data: {e}")

    # Wait for all exchanges to complete
    time.sleep(15)

    RNS.log(f"[announcer] Results: {json.dumps(results, indent=2)}")

    if results["link_established"] and (results["channel_received"] or results["buffer_received"]):
        RNS.log("[announcer] PASS")
        sys.exit(0)
    else:
        RNS.log("[announcer] FAIL")
        sys.exit(1)


def run_linker():
    """Python-B: discover announcer, initiate link through relay, send channel/buffer."""
    RNS.log("[linker] Starting")
    reticulum = RNS.Reticulum("/etc/reticulum")

    handler = AnnounceHandler()
    RNS.Transport.register_announce_handler(handler)

    RNS.log("[linker] Waiting for announce from Python-A (through Rust relay)...")

    # Wait for announce discovery
    timeout = 90
    start = time.time()
    while (time.time() - start) < timeout:
        if discovered_hash is not None:
            break
        time.sleep(1)

    if discovered_hash is None:
        RNS.log("[linker] FAIL: did not discover announcer")
        RNS.log(f"[linker] Results: {json.dumps(results, indent=2)}")
        sys.exit(1)

    # Initiate link through relay
    RNS.log("[linker] Initiating link to announcer through Rust relay...")
    try:
        dest = RNS.Destination(
            discovered_identity,
            RNS.Destination.OUT,
            RNS.Destination.SINGLE,
            APP_NAME,
            *ASPECTS,
        )
        link = RNS.Link(dest, established_callback=link_ready_callback)
    except Exception as e:
        RNS.log(f"[linker] Failed to create link: {e}")
        sys.exit(1)

    # Wait for link establishment
    link_timeout = 60
    link_start = time.time()
    while (time.time() - link_start) < link_timeout:
        if results["link_established"]:
            break
        time.sleep(1)

    if not results["link_established"]:
        RNS.log("[linker] FAIL: link not established")
        RNS.log(f"[linker] Results: {json.dumps(results, indent=2)}")
        sys.exit(1)

    # Send channel message
    time.sleep(2)
    if channel_obj is not None:
        try:
            msg = TestMessage(b"channel msg from linker via relay")
            channel_obj.send(msg)
            results["channel_sent"] = True
            RNS.log("[linker] Sent channel message")
        except Exception as e:
            RNS.log(f"[linker] Failed to send channel message: {e}")

    # Send buffer data
    time.sleep(2)
    if buffer_obj is not None:
        try:
            buffer_obj.write(b"buffer data from linker via relay")
            buffer_obj.flush()
            results["buffer_sent"] = True
            RNS.log("[linker] Sent buffer data")
        except Exception as e:
            RNS.log(f"[linker] Failed to send buffer data: {e}")

    # Wait for responses
    time.sleep(15)

    RNS.log(f"[linker] Results: {json.dumps(results, indent=2)}")

    if results["link_established"] and results["channel_sent"]:
        RNS.log("[linker] PASS")
        sys.exit(0)
    else:
        RNS.log("[linker] FAIL")
        sys.exit(1)


if __name__ == "__main__":
    if ROLE == "announcer":
        run_announcer()
    elif ROLE == "linker":
        run_linker()
    else:
        print(f"Unknown ROLE: {ROLE}")
        sys.exit(1)
