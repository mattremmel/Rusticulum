#!/usr/bin/env python3
"""
IFAC (Interface Access Control) test.

Tests that Rust and Python nodes can communicate over IFAC-protected interfaces
when they share the same network name and key.

Python listens with IFAC on its TCP server interface.
Rust connects as TCP client with matching IFAC credentials.
Both sides should be able to exchange announces and establish links.
"""

import json
import sys
import time

import RNS

# ---- Global result tracking ----
results = {
    "announce_received_from_rust": False,
    "link_established": False,
    "data_received": False,
    "data_content": None,
}

link_from_rust = None


class AnnounceHandler:
    """Class-based announce handler required by RNS Transport API."""

    def __init__(self):
        self.aspect_filter = None

    def received_announce(self, destination_hash, announced_identity, app_data):
        RNS.log(f"Received announce from {RNS.prettyhexrep(destination_hash)}")
        if app_data:
            RNS.log(f"  app_data: {app_data}")
        results["announce_received_from_rust"] = True


def link_established_callback(link):
    """Called when Rust initiates a link."""
    global link_from_rust
    link_from_rust = link
    results["link_established"] = True
    RNS.log(f"Link from Rust established: {link}")
    link.set_packet_callback(packet_callback)
    link.set_resource_strategy(RNS.Link.ACCEPT_ALL)


def packet_callback(message, packet):
    """Called when data arrives on an established link."""
    text = message.decode("utf-8") if isinstance(message, bytes) else str(message)
    results["data_received"] = True
    results["data_content"] = text
    RNS.log(f"Received data over IFAC link: {text}")


def main():
    RNS.log("Starting Python IFAC test")

    # Start Reticulum with IFAC-enabled config
    reticulum = RNS.Reticulum("/etc/reticulum")

    # Register announce handler
    handler = AnnounceHandler()
    RNS.Transport.register_announce_handler(handler)

    # Create our destination
    identity = RNS.Identity()
    destination = RNS.Destination(
        identity,
        RNS.Destination.IN,
        RNS.Destination.SINGLE,
        "ifac_test",
        "auth",
        "v1",
    )

    # Accept incoming links
    destination.set_link_established_callback(link_established_callback)

    RNS.log(f"Python destination hash: {RNS.prettyhexrep(destination.hash)}")

    # Wait for Rust node to connect
    RNS.log("Waiting for Rust node to connect over IFAC interface...")
    time.sleep(10)

    # Send announce so Rust can discover us
    RNS.log("Sending announce (IFAC protected)")
    destination.announce(app_data=b"python ifac test")

    time.sleep(3)
    RNS.log("Sending re-announce")
    destination.announce(app_data=b"python ifac test")

    # Wait for link establishment
    timeout = 60
    start = time.time()
    RNS.log("Waiting for Rust-initiated link...")
    while not results["link_established"] and (time.time() - start) < timeout:
        time.sleep(0.5)

    if not results["link_established"]:
        RNS.log("TIMEOUT: No link established over IFAC")
        print(json.dumps(results))
        sys.exit(1)

    # Wait for data exchange
    data_timeout = 30
    data_start = time.time()
    while not results["data_received"] and (time.time() - data_start) < data_timeout:
        time.sleep(0.5)

    # Send data back to Rust
    if link_from_rust is not None:
        try:
            packet = RNS.Packet(link_from_rust, b"ifac response from python")
            packet.send()
            RNS.log("Sent data back to Rust over IFAC link")
        except Exception as e:
            RNS.log(f"Failed to send data: {e}")

    time.sleep(5)

    # Report results
    RNS.log(f"Test results: {json.dumps(results, indent=2)}")

    success = results["link_established"]

    if success:
        RNS.log("PASS: IFAC test passed")
        print(json.dumps(results))
        sys.exit(0)
    else:
        RNS.log("FAIL: IFAC test failed")
        print(json.dumps(results))
        sys.exit(1)


if __name__ == "__main__":
    main()
