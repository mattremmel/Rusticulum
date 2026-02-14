#!/usr/bin/env python3
"""
Storage persistence test.

Tests that Rust node preserves its identity across restarts.
This script runs continuously, announcing periodically and accepting links.
The bash runner will stop/restart the Rust container and verify identity persists.

Flow:
1. Announce, wait for Rust link (phase 1)
2. Rust container is stopped externally
3. Keep announcing periodically
4. Rust container is restarted externally
5. Wait for second Rust link (phase 2)
6. Report both phases
"""

import json
import sys
import time

import RNS

# ---- Global result tracking ----
results = {
    "phase1_link": False,
    "phase1_data": None,
    "phase2_link": False,
    "phase2_data": None,
    "link_count": 0,
}

current_link = None
link_count = 0


class AnnounceHandler:
    """Class-based announce handler required by RNS Transport API."""

    def __init__(self):
        self.aspect_filter = None

    def received_announce(self, destination_hash, announced_identity, app_data):
        RNS.log(f"Received announce from {RNS.prettyhexrep(destination_hash)}")
        if app_data:
            RNS.log(f"  app_data: {app_data}")


def packet_callback(message, packet):
    """Called when data arrives on an established link."""
    global link_count
    text = message.decode("utf-8") if isinstance(message, bytes) else str(message)
    RNS.log(f"Received data (link #{link_count}): {text}")
    if link_count <= 1:
        results["phase1_data"] = text
    else:
        results["phase2_data"] = text


def link_established_callback(link):
    """Called when Rust initiates a link."""
    global current_link, link_count
    link_count += 1
    current_link = link
    results["link_count"] = link_count
    RNS.log(f"Link #{link_count} from Rust established: {link}")
    link.set_packet_callback(packet_callback)
    link.set_resource_strategy(RNS.Link.ACCEPT_ALL)

    if link_count <= 1:
        results["phase1_link"] = True
    else:
        results["phase2_link"] = True


def main():
    RNS.log("Starting Python storage persistence test")

    # Start Reticulum
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
        "storage_test",
        "persist",
        "v1",
    )

    destination.set_link_established_callback(link_established_callback)

    RNS.log(f"Python destination hash: {RNS.prettyhexrep(destination.hash)}")

    # Keep announcing periodically for the full test duration
    # The bash script will manage Rust container stop/restart
    total_time = 110  # Run for ~110s total
    announce_interval = 8
    start = time.time()

    RNS.log("Starting periodic announce loop...")

    while (time.time() - start) < total_time:
        RNS.log(f"Sending announce (link_count={link_count})")
        destination.announce(app_data=b"python storage test")
        time.sleep(announce_interval)

    # Final report
    RNS.log(f"Test results: {json.dumps(results, indent=2)}")

    # We need at least phase 1 link. Phase 2 is the real test.
    if results["phase1_link"] and results["phase2_link"]:
        RNS.log("PASS: Both phases established links (identity persisted)")
        print(json.dumps(results))
        sys.exit(0)
    elif results["phase1_link"]:
        RNS.log("PARTIAL: Phase 1 link established but phase 2 failed")
        print(json.dumps(results))
        sys.exit(1)
    else:
        RNS.log("FAIL: No links established at all")
        print(json.dumps(results))
        sys.exit(1)


if __name__ == "__main__":
    main()
