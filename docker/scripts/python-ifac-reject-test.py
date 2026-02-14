#!/usr/bin/env python3
"""
IFAC rejection test (negative test).

Verifies that mismatched IFAC keys prevent communication.
Python has ifac_netkey="python_secret_key", Rust has network_key="rust_different_key".

Expected behavior: No announces should be received, no links should be established.
The test succeeds if NO communication happens within the timeout period.
"""

import json
import sys
import time

import RNS

# ---- Global result tracking ----
results = {
    "announce_received": False,
    "link_established": False,
}


class AnnounceHandler:
    """Class-based announce handler required by RNS Transport API."""

    def __init__(self):
        self.aspect_filter = None

    def received_announce(self, destination_hash, announced_identity, app_data):
        RNS.log(f"UNEXPECTED: Received announce from {RNS.prettyhexrep(destination_hash)}")
        results["announce_received"] = True


def link_established_callback(link):
    """Called if a link is somehow established (should NOT happen)."""
    results["link_established"] = True
    RNS.log(f"UNEXPECTED: Link established: {link}")


def main():
    RNS.log("Starting Python IFAC rejection test (negative test)")
    RNS.log("Expected: NO communication should succeed (mismatched IFAC keys)")

    # Start Reticulum with IFAC config (different key from Rust)
    reticulum = RNS.Reticulum("/etc/reticulum")

    # Register announce handler
    handler = AnnounceHandler()
    RNS.Transport.register_announce_handler(handler)

    # Create destination
    identity = RNS.Identity()
    destination = RNS.Destination(
        identity,
        RNS.Destination.IN,
        RNS.Destination.SINGLE,
        "ifac_reject_test",
        "auth",
        "v1",
    )

    destination.set_link_established_callback(link_established_callback)

    RNS.log(f"Python destination hash: {RNS.prettyhexrep(destination.hash)}")

    # Wait for connection
    time.sleep(10)

    # Send announces (Rust should drop them due to IFAC mismatch)
    RNS.log("Sending announces (should be rejected by Rust due to IFAC mismatch)")
    destination.announce(app_data=b"python ifac reject test")
    time.sleep(5)
    destination.announce(app_data=b"python ifac reject test")

    # Wait to see if anything happens (it shouldn't)
    RNS.log("Waiting 30s to verify no communication occurs...")
    time.sleep(30)

    # Report results
    RNS.log(f"Test results: {json.dumps(results, indent=2)}")

    # Success = NO communication happened
    if not results["announce_received"] and not results["link_established"]:
        RNS.log("PASS: No communication occurred (IFAC mismatch correctly prevented it)")
        print(json.dumps(results))
        sys.exit(0)
    else:
        RNS.log("FAIL: Communication occurred despite mismatched IFAC keys!")
        print(json.dumps(results))
        sys.exit(1)


if __name__ == "__main__":
    main()
