#!/usr/bin/env python3
"""
Bidirectional resource transfer test.

Tests resource transfers in both directions between Python RNS and Rust node:
1. Rust sends a resource to Python (auto_resource after link establishment)
2. Python sends a resource back to Rust

Both sides must receive and verify the other's resource.
"""

import json
import sys
import time

import RNS

# ---- Global result tracking ----
results = {
    "rust_to_python_link": False,
    "rust_to_python_resource": False,
    "rust_to_python_resource_data": None,
    "python_to_rust_resource_sent": False,
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


def resource_concluded(resource):
    """Called when a resource transfer from Rust concludes."""
    if resource.status == RNS.Resource.COMPLETE:
        data = resource.data.read()
        results["rust_to_python_resource"] = True
        results["rust_to_python_resource_data"] = data.decode("utf-8", errors="replace")
        RNS.log(f"Resource from Rust received: {len(data)} bytes")
        RNS.log(f"  data: {data[:200]}")
    else:
        RNS.log(f"Resource from Rust failed with status: {resource.status}")


def link_established_callback(link):
    """Called when Rust initiates a link to our Python destination."""
    global link_from_rust
    link_from_rust = link
    results["rust_to_python_link"] = True
    RNS.log(f"Link from Rust established: {link}")

    # Accept incoming resources
    link.set_resource_strategy(RNS.Link.ACCEPT_ALL)
    link.set_resource_concluded_callback(resource_concluded)


def main():
    RNS.log("Starting Python resource transfer test")

    # Start Reticulum
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
        "resource_test",
        "transfer",
        "v1",
    )

    # Accept incoming links
    destination.set_link_established_callback(link_established_callback)

    RNS.log(f"Python destination hash: {RNS.prettyhexrep(destination.hash)}")

    # Wait for Rust node to connect
    RNS.log("Waiting for Rust node to connect...")
    time.sleep(10)

    # Send announce so Rust can discover us and auto-link
    RNS.log("Sending announce")
    destination.announce(app_data=b"python resource test")

    # Re-announce
    time.sleep(3)
    RNS.log("Sending re-announce")
    destination.announce(app_data=b"python resource test")

    # Wait for Rust-initiated link
    timeout = 60
    start = time.time()
    RNS.log("Waiting for Rust-initiated link...")
    while not results["rust_to_python_link"] and (time.time() - start) < timeout:
        time.sleep(0.5)

    if not results["rust_to_python_link"]:
        RNS.log("TIMEOUT: Rust-initiated link not established")
        print(json.dumps(results))
        sys.exit(1)

    RNS.log("Link established, waiting for resource from Rust...")

    # Wait for resource from Rust (30s timeout)
    res_timeout = 30
    res_start = time.time()
    while not results["rust_to_python_resource"] and (time.time() - res_start) < res_timeout:
        time.sleep(0.5)

    if results["rust_to_python_resource"]:
        RNS.log("Resource from Rust received!")
    else:
        RNS.log("TIMEOUT: Resource from Rust not received")

    # Phase 2: Send resource from Python to Rust
    if link_from_rust is not None:
        RNS.log("Sending resource from Python to Rust...")
        try:
            resource_data = b"Hello from Python via resource transfer! " * 50  # ~2KB
            resource = RNS.Resource(resource_data, link_from_rust, advertise=True)
            results["python_to_rust_resource_sent"] = True
            RNS.log(f"Python resource sent: {len(resource_data)} bytes")

            # Wait for resource transfer to complete
            time.sleep(10)
        except Exception as e:
            RNS.log(f"Failed to send resource from Python: {e}")
    else:
        RNS.log("No link to Rust, skipping Python→Rust resource")

    # Wait for everything to settle
    time.sleep(5)

    # Report results
    RNS.log(f"Test results: {json.dumps(results, indent=2)}")

    # Success requires at minimum: link established + resource received from Rust
    success = results["rust_to_python_link"] and results["rust_to_python_resource"]

    if success:
        RNS.log("PASS: Resource transfer test passed")
        print(json.dumps(results))
        sys.exit(0)
    else:
        RNS.log("FAIL: Resource transfer test failed")
        print(json.dumps(results))
        sys.exit(1)


if __name__ == "__main__":
    main()
