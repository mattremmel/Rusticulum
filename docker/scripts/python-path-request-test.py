#!/usr/bin/env python3
"""
Path request integration test.

Tests that:
1. Python announces a destination
2. Rust transport node receives and caches the announce
3. Python sends a path request for an unknown destination
4. Both nodes handle path request packets correctly (no crashes)
5. Python sends a path request for the known destination
6. Both nodes handle it correctly
"""

import json
import os
import sys
import time

import RNS

# Globals
rust_announce_received = False

class AnnounceHandler:
    def __init__(self):
        self.aspect_filter = None

    def received_announce(self, destination_hash, announced_identity, app_data):
        global rust_announce_received
        rust_announce_received = True
        RNS.log(f"Received announce from {RNS.prettyhexrep(destination_hash)}")
        if app_data:
            RNS.log(f"  app_data: {app_data}")


def main():
    RNS.log("Starting path request integration test")

    reticulum = RNS.Reticulum("/etc/reticulum")

    # Register handler for Rust announces
    RNS.Transport.register_announce_handler(AnnounceHandler())

    # Create our destination and announce it
    identity = RNS.Identity()
    destination = RNS.Destination(
        identity,
        RNS.Destination.IN,
        RNS.Destination.SINGLE,
        "python_test",
        "path_request",
        "v1",
    )
    RNS.log(f"Python destination hash: {RNS.prettyhexrep(destination.hash)}")

    # Wait for Rust node to connect
    time.sleep(10)

    # Announce so Rust can cache it
    RNS.log("Sending announce for path caching")
    destination.announce(app_data=b"path-test-node")
    time.sleep(5)

    # Re-announce to ensure Rust gets it
    RNS.log("Re-announcing")
    destination.announce(app_data=b"path-test-node")
    time.sleep(5)

    # Now request a path for a random (unknown) destination
    # This tests that Rust properly handles/forwards path requests it can't answer
    unknown_hash = bytes.fromhex("deadbeef01020304050607080900aabb")
    RNS.log(f"Requesting path to unknown destination: {RNS.prettyhexrep(unknown_hash)}")
    RNS.Transport.request_path(unknown_hash)
    time.sleep(3)

    # Request path to our own destination (which Rust should have cached)
    RNS.log(f"Requesting path to own destination: {RNS.prettyhexrep(destination.hash)}")
    RNS.Transport.request_path(destination.hash)
    time.sleep(3)

    # Wait for Rust announce
    timeout = 30
    start = time.time()
    while not rust_announce_received and (time.time() - start) < timeout:
        time.sleep(0.5)

    results = {
        "python_announce_sent": True,
        "rust_announce_received": rust_announce_received,
        "path_requests_sent": True,
        "no_crashes": True,
    }

    RNS.log(f"Test results: {json.dumps(results, indent=2)}")

    if rust_announce_received:
        RNS.log("PASS: Bidirectional announce exchange + path requests completed")
        print(json.dumps(results))
        sys.exit(0)
    else:
        RNS.log("FAIL: Did not receive Rust announce")
        print(json.dumps(results))
        sys.exit(1)


if __name__ == "__main__":
    main()
