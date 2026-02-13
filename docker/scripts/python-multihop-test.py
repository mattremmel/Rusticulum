#!/usr/bin/env python3
"""
Multi-hop test: Python endpoints communicating through a Rust relay.

Two roles controlled by ROLE environment variable:
  - "announcer" (Python-A): creates destination, announces, accepts links, waits for data
  - "linker" (Python-B): discovers announcer, initiates link through relay, sends data

Topology: Python-A <-- Rust-Relay --> Python-B
"""

import json
import os
import sys
import time

import RNS

ROLE = os.environ.get("ROLE", "announcer")
APP_NAME = "multihop_test"
ASPECTS = ["announce", "v1"]

results = {
    "role": ROLE,
    "announce_sent": False,
    "announce_received": False,
    "link_established": False,
    "data_sent": False,
    "data_received": False,
}

discovered_hash = None
discovered_identity = None
established_link = None


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


def link_established_callback(link):
    """Called when a link is established (announcer side: incoming link)."""
    global established_link
    established_link = link
    results["link_established"] = True
    RNS.log(f"[{ROLE}] Link established (incoming): {link}")
    link.set_packet_callback(packet_callback)


def link_ready_callback(link):
    """Called when linker's outbound link is established."""
    global established_link
    established_link = link
    results["link_established"] = True
    RNS.log(f"[{ROLE}] Link established (outgoing): {link}")
    link.set_packet_callback(packet_callback)

    # Send data over the link
    try:
        data = b"hello through rust relay"
        packet = RNS.Packet(link, data)
        packet.send()
        results["data_sent"] = True
        RNS.log(f"[{ROLE}] Sent data: {data}")
    except Exception as e:
        RNS.log(f"[{ROLE}] Failed to send data: {e}")


def packet_callback(message, packet):
    """Called when data arrives on an established link."""
    text = message.decode("utf-8") if isinstance(message, bytes) else str(message)
    results["data_received"] = True
    RNS.log(f"[{ROLE}] Received data: {text}")


def run_announcer():
    """Python-A: announce, accept links, wait for data."""
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
        destination.announce(app_data=b"hello from python-a")
        results["announce_sent"] = True
        time.sleep(5)

        if results["link_established"]:
            break

    # Wait for link and data
    timeout = 90
    start = time.time()
    while (time.time() - start) < timeout:
        if results["data_received"]:
            RNS.log("[announcer] Data received, test complete")
            break
        time.sleep(1)

    # Brief wait for any final processing
    time.sleep(2)

    RNS.log(f"[announcer] Results: {json.dumps(results, indent=2)}")

    if results["link_established"]:
        RNS.log("[announcer] PASS")
        sys.exit(0)
    else:
        RNS.log("[announcer] FAIL: no link established")
        sys.exit(1)


def run_linker():
    """Python-B: discover announcer, initiate link through relay, send data."""
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

    # Wait for link establishment and data exchange
    link_timeout = 60
    link_start = time.time()
    while (time.time() - link_start) < link_timeout:
        if results["data_sent"]:
            break
        time.sleep(1)

    # Brief wait for any final processing
    time.sleep(3)

    RNS.log(f"[linker] Results: {json.dumps(results, indent=2)}")

    if results["link_established"] and results["data_sent"]:
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
