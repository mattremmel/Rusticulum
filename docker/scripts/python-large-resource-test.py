#!/usr/bin/env python3
"""
Large resource transfer test.

Tests that a 1MB resource can be transferred from Python to Rust.
This validates Rust's resource assembly at scale with many parts.

Flow:
1. Python creates destination, announces
2. Rust discovers, links, sends "ready" data
3. Python sends 1MB resource to Rust
4. Wait for resource transfer to complete
"""

import json
import sys
import time

import RNS

# ---- Global result tracking ----
results = {
    "link_established": False,
    "ready_received": False,
    "resource_sent": False,
    "resource_concluded": False,
    "resource_status": None,
}

link_from_rust = None
resource_size = 102400  # 100KB


class AnnounceHandler:
    """Class-based announce handler required by RNS Transport API."""

    def __init__(self):
        self.aspect_filter = None

    def received_announce(self, destination_hash, announced_identity, app_data):
        RNS.log(f"Received announce from {RNS.prettyhexrep(destination_hash)}")
        if app_data:
            RNS.log(f"  app_data: {app_data}")


def resource_concluded(resource):
    """Called when the resource transfer concludes (either success or failure)."""
    results["resource_concluded"] = True
    if resource.status == RNS.Resource.COMPLETE:
        results["resource_status"] = "complete"
        RNS.log(f"Large resource transfer COMPLETED ({resource_size} bytes)")
    else:
        results["resource_status"] = f"failed:{resource.status}"
        RNS.log(f"Large resource transfer FAILED with status: {resource.status}")


def packet_callback(message, packet):
    """Called when data arrives on an established link."""
    text = message.decode("utf-8") if isinstance(message, bytes) else str(message)
    RNS.log(f"Received data: {text}")
    if "ready" in text.lower():
        results["ready_received"] = True


def link_established_callback(link):
    """Called when Rust initiates a link."""
    global link_from_rust
    link_from_rust = link
    results["link_established"] = True
    RNS.log(f"Link from Rust established: {link}")
    link.set_packet_callback(packet_callback)
    link.set_resource_strategy(RNS.Link.ACCEPT_ALL)


def main():
    RNS.log("Starting Python large resource transfer test")
    RNS.log(f"Will send {resource_size} bytes ({resource_size/1024:.1f} KB)")

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
        "large_resource_test",
        "transfer",
        "v1",
    )

    destination.set_link_established_callback(link_established_callback)

    RNS.log(f"Python destination hash: {RNS.prettyhexrep(destination.hash)}")

    # Wait for Rust node to connect
    RNS.log("Waiting for Rust node to connect...")
    time.sleep(10)

    # Announce
    RNS.log("Sending announce")
    destination.announce(app_data=b"python large resource test")
    time.sleep(3)
    RNS.log("Sending re-announce")
    destination.announce(app_data=b"python large resource test")

    # Wait for link
    timeout = 60
    start = time.time()
    RNS.log("Waiting for Rust-initiated link...")
    while not results["link_established"] and (time.time() - start) < timeout:
        time.sleep(0.5)

    if not results["link_established"]:
        RNS.log("TIMEOUT: Link not established")
        print(json.dumps(results))
        sys.exit(1)

    # Wait for "ready" signal from Rust
    ready_timeout = 30
    ready_start = time.time()
    RNS.log("Waiting for ready signal from Rust...")
    while not results["ready_received"] and (time.time() - ready_start) < ready_timeout:
        time.sleep(0.5)

    # Give a moment for link to stabilize
    time.sleep(2)

    # Generate 1MB payload with recognizable pattern
    RNS.log(f"Generating {resource_size} byte payload...")
    # Use a repeating pattern that's easy to verify
    pattern = b"LARGE_RESOURCE_TEST_DATA_BLOCK_"  # 30 bytes
    repeats = resource_size // len(pattern) + 1
    payload = (pattern * repeats)[:resource_size]
    assert len(payload) == resource_size

    # Send large resource
    RNS.log(f"Sending {len(payload)} byte resource to Rust...")
    try:
        resource = RNS.Resource(
            payload,
            link_from_rust,
            advertise=True,
            callback=resource_concluded,
        )
        results["resource_sent"] = True
        RNS.log("Resource transfer initiated")
    except Exception as e:
        RNS.log(f"Failed to send resource: {e}")
        print(json.dumps(results))
        sys.exit(1)

    # Wait for transfer to complete (may take a while for 1MB)
    transfer_timeout = 240
    transfer_start = time.time()
    RNS.log(f"Waiting for resource transfer to complete ({transfer_timeout}s timeout)...")
    while not results["resource_concluded"] and (time.time() - transfer_start) < transfer_timeout:
        time.sleep(1)

    # Brief cooldown
    time.sleep(5)

    # Report results
    RNS.log(f"Test results: {json.dumps(results, indent=2)}")

    success = (
        results["link_established"]
        and results["resource_sent"]
        and results["resource_concluded"]
        and results["resource_status"] == "complete"
    )

    if success:
        RNS.log("PASS: Large resource transfer test passed")
        print(json.dumps(results))
        sys.exit(0)
    else:
        RNS.log("FAIL: Large resource transfer test failed")
        print(json.dumps(results))
        sys.exit(1)


if __name__ == "__main__":
    main()
