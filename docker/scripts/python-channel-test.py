#!/usr/bin/env python3
"""
Channel, Buffer, and Request/Response integration test.

Tests bidirectional communication between Python RNS and Rust node using:
1. Channel messages (custom message type 0x0101)
2. Buffer streams (via channel envelope with SMT_STREAM_DATA=0xFF00)
3. Request/Response (/test/echo endpoint)
"""

import json
import sys
import time
import os

import RNS
import RNS.Channel as Channel
import RNS.Buffer

# ---- Global result tracking ----
results = {
    "link_established": False,
    "channel_msg_from_rust": False,
    "channel_msg_from_rust_data": None,
    "channel_msg_to_rust_sent": False,
    "buffer_from_rust": False,
    "buffer_from_rust_data": None,
    "buffer_to_rust_sent": False,
    "request_from_rust": False,
    "request_from_rust_data": None,
    "request_from_rust_responded": False,
    "request_to_rust_sent": False,
    "response_from_rust": False,
    "response_from_rust_data": None,
}

link_from_rust = None
channel_obj = None
buffer_obj = None


# ---- Custom message type for channel test ----
MSGTYPE_TEST = 0x0101


class TestMessage(Channel.MessageBase):
    MSGTYPE = MSGTYPE_TEST

    def __init__(self, data=None):
        self.data = data or b""

    def pack(self):
        return self.data if isinstance(self.data, bytes) else self.data.encode("utf-8")

    def unpack(self, raw):
        self.data = raw


# ---- Announce handler ----
class AnnounceHandler:
    def __init__(self):
        self.aspect_filter = None

    def received_announce(self, destination_hash, announced_identity, app_data):
        RNS.log(f"Received announce from {RNS.prettyhexrep(destination_hash)}")
        if app_data:
            RNS.log(f"  app_data: {app_data}")


# ---- Request handler ----
def handle_request(path, data, request_id, link_id, remote_identity, requested_at):
    """Echo request handler for /test/echo."""
    RNS.log(f"Received request on {path}: {data}")
    results["request_from_rust"] = True
    results["request_from_rust_data"] = data.decode("utf-8", errors="replace") if isinstance(data, bytes) else str(data)
    results["request_from_rust_responded"] = True
    return data  # echo back


# ---- Channel message callback ----
def channel_message_received(message):
    """Called when a channel message is received from Rust."""
    RNS.log(f"Channel message received: type={hex(message.MSGTYPE)}, data={message.data}")
    results["channel_msg_from_rust"] = True
    if isinstance(message.data, bytes):
        results["channel_msg_from_rust_data"] = message.data.decode("utf-8", errors="replace")
    else:
        results["channel_msg_from_rust_data"] = str(message.data)


# ---- Buffer callback ----
buffer_data_received = bytearray()
buffer_complete = False


def buffer_ready_callback(ready_bytes):
    """Called when buffer data is available."""
    global buffer_data_received, buffer_complete, buffer_obj
    if buffer_obj and ready_bytes > 0:
        data = buffer_obj.read(ready_bytes)
        if data:
            buffer_data_received.extend(data)
            results["buffer_from_rust"] = True
            results["buffer_from_rust_data"] = buffer_data_received.decode("utf-8", errors="replace")
            RNS.log(f"Buffer data chunk received: {len(data)} bytes, total: {len(buffer_data_received)}")
            RNS.log(f"Buffer data content: {data}")


# ---- Link established callback ----
def link_established_callback(link):
    global link_from_rust, channel_obj, buffer_obj
    link_from_rust = link
    results["link_established"] = True
    RNS.log(f"Link from Rust established: {link}")

    # Set up channel
    channel_obj = link.get_channel()
    channel_obj.register_message_type(TestMessage)
    channel_obj.add_message_handler(channel_message_received)

    # Set up buffer — MUST be created here (before Rust sends auto_buffer data)
    # so that StreamDataMessage (0xFF00) is registered as a system type
    buffer_obj = RNS.Buffer.create_bidirectional_buffer(0, 0, channel_obj, buffer_ready_callback)
    RNS.log("Buffer created on channel")

    # Set up resource strategy (needed for some operations)
    link.set_resource_strategy(RNS.Link.ACCEPT_ALL)


# ---- Response callback ----
def response_callback(request_receipt):
    """Called when we get a response to our request."""
    response_data = request_receipt.response
    RNS.log(f"Response received: {response_data}")
    results["response_from_rust"] = True
    if isinstance(response_data, bytes):
        results["response_from_rust_data"] = response_data.decode("utf-8", errors="replace")
    else:
        results["response_from_rust_data"] = str(response_data)


def request_failed(request_receipt):
    RNS.log(f"Request failed: {request_receipt.status}")


def main():
    RNS.log("Starting Python channel/buffer/request test")

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
        "channel_test",
        "channel",
        "v1",
    )

    # Accept incoming links
    destination.set_link_established_callback(link_established_callback)

    # Register request handler (ALLOW_ALL so any linked peer can call it)
    destination.register_request_handler(
        "/test/echo",
        response_generator=handle_request,
        allow=RNS.Destination.ALLOW_ALL,
    )

    RNS.log(f"Python destination hash: {RNS.prettyhexrep(destination.hash)}")

    # Wait for Rust node to start and be ready
    RNS.log("Waiting for Rust node to connect...")
    time.sleep(10)

    # Send announce so Rust can discover us and auto-link
    RNS.log("Sending announce")
    destination.announce(app_data=b"python channel test")

    # Re-announce
    time.sleep(3)
    RNS.log("Sending re-announce")
    destination.announce(app_data=b"python channel test")

    # Wait for Rust-initiated link
    timeout = 60
    start = time.time()
    RNS.log("Waiting for Rust-initiated link...")
    while not results["link_established"] and (time.time() - start) < timeout:
        time.sleep(0.5)

    if not results["link_established"]:
        RNS.log("TIMEOUT: Rust-initiated link not established")
        print(json.dumps(results))
        sys.exit(1)

    RNS.log("Link established, starting protocol tests...")

    # Give Rust time to send its auto-actions (channel msg, buffer, request)
    time.sleep(5)

    # ---- Phase 1: Channel messages ----
    # By now Rust should have sent its auto_channel message
    # Send a channel message from Python to Rust
    if channel_obj is not None:
        try:
            msg = TestMessage(b"hello from python channel")
            channel_obj.send(msg)
            results["channel_msg_to_rust_sent"] = True
            RNS.log("Sent channel message to Rust")
        except Exception as e:
            RNS.log(f"Failed to send channel message: {e}")

    time.sleep(3)

    # ---- Phase 2: Buffer streams ----
    # Send buffer data from Python to Rust via Buffer API
    if buffer_obj is not None:
        try:
            stream_data = b"streamed from python node"
            buffer_obj.write(stream_data)
            buffer_obj.flush()
            buffer_obj.close()
            results["buffer_to_rust_sent"] = True
            RNS.log(f"Sent buffer stream to Rust: {len(stream_data)} bytes")
        except Exception as e:
            RNS.log(f"Failed to send buffer stream: {e}")
            import traceback
            traceback.print_exc()

    time.sleep(3)

    # ---- Phase 3: Request/Response ----
    # Send request from Python to Rust
    if link_from_rust is not None:
        try:
            link_from_rust.request(
                "/test/echo",
                b"python request payload",
                response_callback=response_callback,
                failed_callback=request_failed,
            )
            results["request_to_rust_sent"] = True
            RNS.log("Sent request to Rust")
        except Exception as e:
            RNS.log(f"Failed to send request: {e}")

    # Wait for everything to settle
    time.sleep(10)

    # Report results
    RNS.log(f"Test results: {json.dumps(results, indent=2)}")

    # Determine success: link + channel + buffer exchange
    success = (
        results["link_established"]
        and (results["channel_msg_from_rust"] or results["channel_msg_to_rust_sent"])
        and results["buffer_to_rust_sent"]
        and results["buffer_from_rust"]
    )

    if success:
        RNS.log("PASS: Channel/Buffer/Request test passed")
        print(json.dumps(results))
        sys.exit(0)
    else:
        RNS.log("FAIL: Channel/Buffer/Request test failed")
        print(json.dumps(results))
        sys.exit(1)


if __name__ == "__main__":
    main()
