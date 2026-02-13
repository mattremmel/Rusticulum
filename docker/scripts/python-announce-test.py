#!/usr/bin/env python3
"""
Bidirectional announce exchange test.

This script replaces rnsd for the announce integration test. It:
1. Starts a Reticulum instance with a TCP Server on port 4242
2. Creates a destination and announces it
3. Listens for announces from the Rust node
4. Reports results as JSON and exits with 0 (pass) or 1 (fail)
"""

import json
import sys
import time

import RNS

# Globals for announce handler
rust_announce_received = False
rust_announce_data = None

def announce_handler(destination_hash, announced_identity, app_data):
    global rust_announce_received, rust_announce_data
    rust_announce_received = True
    rust_announce_data = app_data
    RNS.log(f"Received announce from {RNS.prettyhexrep(destination_hash)}")
    if app_data:
        RNS.log(f"  app_data: {app_data}")

def main():
    RNS.log("Starting Python announce test")

    # Start Reticulum with the config that has TCP Server on 4242
    reticulum = RNS.Reticulum("/etc/reticulum")

    # Register announce handler for Rust node announces
    RNS.Transport.register_announce_handler(announce_handler)

    # Create our own destination
    identity = RNS.Identity()
    destination = RNS.Destination(
        identity,
        RNS.Destination.IN,
        RNS.Destination.SINGLE,
        "python_test",
        "announce",
        "v1",
    )

    RNS.log(f"Python destination hash: {RNS.prettyhexrep(destination.hash)}")

    # Wait for Rust node to connect
    RNS.log("Waiting for Rust node to connect...")
    time.sleep(5)

    # Send our announce
    RNS.log("Sending announce with app_data='hello from python'")
    destination.announce(app_data=b"hello from python")

    # Poll for Rust announce (30s timeout)
    timeout = 30
    start = time.time()
    while not rust_announce_received and (time.time() - start) < timeout:
        time.sleep(0.5)

    # Build results
    results = {
        "python_announce_sent": True,
        "python_destination_hash": destination.hexhash,
        "rust_announce_received": rust_announce_received,
        "rust_announce_data": rust_announce_data.decode("utf-8") if rust_announce_data else None,
    }

    RNS.log(f"Test results: {json.dumps(results, indent=2)}")

    if rust_announce_received:
        RNS.log("PASS: Received announce from Rust node")
        print(json.dumps(results))
        sys.exit(0)
    else:
        RNS.log("FAIL: Did not receive announce from Rust node within timeout")
        print(json.dumps(results))
        sys.exit(1)

if __name__ == "__main__":
    main()
