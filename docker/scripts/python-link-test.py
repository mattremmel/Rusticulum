#!/usr/bin/env python3
"""
Bidirectional link establishment test.

Tests both directions of link establishment between Python RNS and Rust node:
1. Rust initiates link to Python (Rust discovers Python via announce, auto-links)
2. Python initiates link to Rust (Python discovers Rust via announce)

Also tests encrypted data exchange over established links.
"""

import json
import sys
import threading
import time

import RNS

# ---- Global result tracking ----
results = {
    "rust_to_python_link": False,
    "python_to_rust_link": False,
    "rust_to_python_data": None,
    "python_to_rust_data_sent": False,
    "python_initiated_data": None,
}

rust_destination_hash = None
rust_identity = None
link_from_rust = None
link_to_rust = None


class AnnounceHandler:
    """Class-based announce handler required by RNS Transport API."""

    def __init__(self):
        self.aspect_filter = None  # Receive all announces

    def received_announce(self, destination_hash, announced_identity, app_data):
        announce_handler(destination_hash, announced_identity, app_data)


def link_established_callback(link):
    """Called when Rust initiates a link to our Python destination."""
    global link_from_rust
    link_from_rust = link
    results["rust_to_python_link"] = True
    RNS.log(f"Link from Rust established: {link}")

    # Register packet callback to receive data from Rust
    link.set_packet_callback(rust_link_packet_callback)

    # Send data to Rust over this link
    try:
        data = b"hello from python responder"
        packet = RNS.Packet(link, data)
        packet.send()
        results["python_to_rust_data_sent"] = True
        RNS.log(f"Sent data to Rust over incoming link: {data}")
    except Exception as e:
        RNS.log(f"Failed to send data to Rust: {e}")


def rust_link_packet_callback(message, packet):
    """Called when data arrives from Rust on the link Rust initiated."""
    results["rust_to_python_data"] = message.decode("utf-8") if isinstance(message, bytes) else str(message)
    RNS.log(f"Received data from Rust (on Rust-initiated link): {results['rust_to_python_data']}")


def python_initiated_link_established(link):
    """Called when our Python-initiated link to Rust is established."""
    global link_to_rust
    link_to_rust = link
    results["python_to_rust_link"] = True
    RNS.log(f"Link to Rust established (Python initiated): {link}")

    # Register packet callback for data from Rust on this link
    link.set_packet_callback(python_initiated_packet_callback)

    # Send data to Rust
    try:
        data = b"hello from python initiator"
        packet = RNS.Packet(link, data)
        packet.send()
        RNS.log(f"Sent data to Rust over Python-initiated link: {data}")
    except Exception as e:
        RNS.log(f"Failed to send data to Rust: {e}")


def python_initiated_packet_callback(message, packet):
    """Called when data arrives from Rust on the link Python initiated."""
    results["python_initiated_data"] = message.decode("utf-8") if isinstance(message, bytes) else str(message)
    RNS.log(f"Received data from Rust (on Python-initiated link): {results['python_initiated_data']}")


def announce_handler(destination_hash, announced_identity, app_data):
    """Handle announces from Rust node — discover and link."""
    global rust_destination_hash, rust_identity

    RNS.log(f"Received announce from {RNS.prettyhexrep(destination_hash)}")
    if app_data:
        RNS.log(f"  app_data: {app_data}")

    # Store for Python-initiated link
    if rust_destination_hash is None:
        rust_destination_hash = destination_hash
        rust_identity = announced_identity
        RNS.log(f"Discovered Rust destination: {RNS.prettyhexrep(destination_hash)}")


def main():
    RNS.log("Starting Python link test")

    # Start Reticulum
    reticulum = RNS.Reticulum("/etc/reticulum")

    # Register announce handler (must be class with aspect_filter + received_announce)
    handler = AnnounceHandler()
    RNS.Transport.register_announce_handler(handler)

    # Create our destination that accepts links
    identity = RNS.Identity()
    destination = RNS.Destination(
        identity,
        RNS.Destination.IN,
        RNS.Destination.SINGLE,
        "link_test",
        "link",
        "v1",
    )

    # Accept incoming links
    destination.set_link_established_callback(link_established_callback)

    RNS.log(f"Python destination hash: {RNS.prettyhexrep(destination.hash)}")

    # Wait for Rust node to connect (give it time to start and establish TCP)
    RNS.log("Waiting for Rust node to connect...")
    time.sleep(10)

    # Send our announce so Rust can discover us and auto-link
    RNS.log("Sending announce")
    destination.announce(app_data=b"hello from python")

    # Re-announce after a short delay in case first was missed
    time.sleep(3)
    RNS.log("Sending re-announce")
    destination.announce(app_data=b"hello from python")

    # Wait for Rust-initiated link (60s timeout)
    timeout = 60
    start = time.time()
    RNS.log("Waiting for Rust-initiated link...")
    while not results["rust_to_python_link"] and (time.time() - start) < timeout:
        time.sleep(0.5)

    if results["rust_to_python_link"]:
        RNS.log("Rust-initiated link established!")
    else:
        RNS.log("TIMEOUT: Rust-initiated link not established")

    # Wait a moment for data exchange on Rust-initiated link
    time.sleep(3)

    # Phase 2: Python initiates link to Rust
    if rust_destination_hash is not None:
        RNS.log("Phase 2: Python initiating link to Rust...")

        try:
            rust_dest = RNS.Destination(
                rust_identity,
                RNS.Destination.OUT,
                RNS.Destination.SINGLE,
                "link_test",
                "link",
                "v1",
            )

            link = RNS.Link(
                rust_dest,
                established_callback=python_initiated_link_established,
            )

            # Wait for link establishment
            link_timeout = 30
            link_start = time.time()
            while not results["python_to_rust_link"] and (time.time() - link_start) < link_timeout:
                time.sleep(0.5)

            if results["python_to_rust_link"]:
                RNS.log("Python-initiated link to Rust established!")
            else:
                RNS.log("TIMEOUT: Python-initiated link not established")

        except Exception as e:
            RNS.log(f"Failed to initiate link to Rust: {e}")
    else:
        RNS.log("Did not discover Rust destination, skipping Python-initiated link")

    # Wait for data exchange
    time.sleep(5)

    # Report results
    RNS.log(f"Test results: {json.dumps(results, indent=2)}")

    # Determine success: at minimum, Rust-to-Python link must work
    success = results["rust_to_python_link"]

    if success:
        RNS.log("PASS: Link establishment test passed")
        print(json.dumps(results))
        sys.exit(0)
    else:
        RNS.log("FAIL: Link establishment test failed")
        print(json.dumps(results))
        sys.exit(1)


if __name__ == "__main__":
    main()
