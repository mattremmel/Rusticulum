#!/usr/bin/env python3
"""
Link keepalive interop test.

Verifies that Rust node sends keepalive packets to keep links alive during
idle periods. Without keepalives, Python RNS marks links stale after
stale_time (2 * keepalive ≈ 10s for low-RTT links) and closes them.

Test flow:
1. Python creates destination, accepts links
2. Rust connects via announce discovery and auto-links
3. Both exchange initial data to confirm link works
4. Both sides idle for 30+ seconds (3x the stale_time)
5. Python checks link is still ACTIVE (kept alive by keepalive packets)
6. Python sends data to confirm link still works after idle period

With Docker RTT ≈ 0.001s, keepalive = 5s (minimum), stale_time = 10s.
Waiting 30s means 3x the stale_time — without keepalives the link dies.
"""

import json
import sys
import time

import RNS


results = {
    "link_established": False,
    "initial_data_received": False,
    "link_alive_after_idle": False,
    "post_idle_data_sent": False,
    "post_idle_data_received": False,
    "idle_duration": 0,
    "link_status_during_idle": None,
    "link_status_after_idle": None,
}

link_from_rust = None


class AnnounceHandler:
    """Class-based announce handler required by RNS Transport API."""

    def __init__(self):
        self.aspect_filter = None

    def received_announce(self, destination_hash, announced_identity, app_data):
        RNS.log(f"Received announce from {RNS.prettyhexrep(destination_hash)}")


def link_established_callback(link):
    """Called when Rust initiates a link to our Python destination."""
    global link_from_rust
    link_from_rust = link
    results["link_established"] = True
    RNS.log(f"Link from Rust established: {link}")

    # Register packet callback to receive data from Rust
    link.set_packet_callback(packet_callback)


def packet_callback(message, packet):
    """Called when data arrives from Rust."""
    text = message.decode("utf-8") if isinstance(message, bytes) else str(message)
    RNS.log(f"Received data from Rust: {text}")

    if not results["initial_data_received"]:
        results["initial_data_received"] = True
    elif not results["post_idle_data_received"]:
        results["post_idle_data_received"] = True


def main():
    RNS.log("Starting Python keepalive test")

    # Start Reticulum
    reticulum = RNS.Reticulum("/etc/reticulum")

    handler = AnnounceHandler()
    RNS.Transport.register_announce_handler(handler)

    # Create destination that accepts links
    identity = RNS.Identity()
    destination = RNS.Destination(
        identity,
        RNS.Destination.IN,
        RNS.Destination.SINGLE,
        "keepalive_test",
        "link",
        "v1",
    )
    destination.set_link_established_callback(link_established_callback)

    RNS.log(f"Python destination hash: {RNS.prettyhexrep(destination.hash)}")

    # Wait for Rust node to connect
    RNS.log("Waiting for Rust node to connect...")
    time.sleep(10)

    # Send announce so Rust can discover us
    RNS.log("Sending announce")
    destination.announce(app_data=b"keepalive test")

    time.sleep(3)
    RNS.log("Sending re-announce")
    destination.announce(app_data=b"keepalive test")

    # Wait for link establishment (60s timeout)
    timeout = 60
    start = time.time()
    RNS.log("Waiting for Rust-initiated link...")
    while not results["link_established"] and (time.time() - start) < timeout:
        time.sleep(0.5)

    if not results["link_established"]:
        RNS.log("FAIL: Link not established within timeout")
        print(json.dumps(results))
        sys.exit(1)

    RNS.log("Link established! Waiting for initial data exchange...")
    time.sleep(5)

    # Send initial data to Rust to confirm link works
    try:
        data = b"pre-idle data from python"
        packet = RNS.Packet(link_from_rust, data)
        packet.send()
        RNS.log(f"Sent pre-idle data: {data}")
    except Exception as e:
        RNS.log(f"Failed to send pre-idle data: {e}")

    time.sleep(2)

    # === IDLE PERIOD ===
    # Wait 30+ seconds without sending any application data.
    # With keepalive=5s, stale_time=10s, this is 3x the stale timeout.
    # Without keepalives, the link would be long dead.
    idle_seconds = 35
    RNS.log(f"Starting idle period of {idle_seconds}s...")
    RNS.log(f"  Link status before idle: {link_from_rust.status}")
    results["link_status_during_idle"] = str(link_from_rust.status)

    # Check link status periodically during idle
    idle_start = time.time()
    link_died_during_idle = False
    while (time.time() - idle_start) < idle_seconds:
        time.sleep(5)
        elapsed = time.time() - idle_start
        status = link_from_rust.status
        RNS.log(f"  Idle check at {elapsed:.0f}s: link status = {status}")
        if status != RNS.Link.ACTIVE:
            RNS.log(f"  WARN: Link went non-active at {elapsed:.0f}s (status={status})")
            link_died_during_idle = True
            break

    actual_idle = time.time() - idle_start
    results["idle_duration"] = round(actual_idle, 1)
    results["link_status_after_idle"] = str(link_from_rust.status)

    # === POST-IDLE CHECK ===
    if link_from_rust.status == RNS.Link.ACTIVE:
        results["link_alive_after_idle"] = True
        RNS.log(f"Link is still ACTIVE after {actual_idle:.1f}s idle period!")

        # Send data to confirm link still works
        try:
            data = b"post-idle data from python"
            packet = RNS.Packet(link_from_rust, data)
            packet.send()
            results["post_idle_data_sent"] = True
            RNS.log(f"Sent post-idle data: {data}")
        except Exception as e:
            RNS.log(f"Failed to send post-idle data: {e}")

        # Wait for response
        time.sleep(5)
    else:
        RNS.log(f"FAIL: Link died during idle (status={link_from_rust.status})")

    # Report results
    RNS.log(f"Test results: {json.dumps(results, indent=2)}")

    # Success criteria: link must survive idle period
    success = (
        results["link_established"]
        and results["link_alive_after_idle"]
        and results["post_idle_data_sent"]
    )

    if success:
        RNS.log("PASS: Keepalive test passed — link survived idle period")
        print(json.dumps(results))
        sys.exit(0)
    else:
        RNS.log("FAIL: Keepalive test failed")
        print(json.dumps(results))
        sys.exit(1)


if __name__ == "__main__":
    main()
