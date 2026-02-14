#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCKER_DIR="$(dirname "$SCRIPT_DIR")"
LOG_FILE="${DOCKER_DIR}/multihop-data-test.log"

cd "$DOCKER_DIR"

echo "=== Building and starting containers for multihop data test ==="
docker compose -f docker-compose.multihop-data-test.yml up -d --build 2>&1 | tee "$LOG_FILE"

echo "=== Waiting for data transfers through relay (120s) ==="
sleep 120

# Wait for all containers to finish
for SVC in rust-a rust-b python-relay; do
    CTR=$(docker compose -f docker-compose.multihop-data-test.yml ps -q "$SVC" 2>/dev/null)
    if [ -n "$CTR" ]; then
        timeout 30 docker wait "$CTR" 2>/dev/null || true
    fi
done

echo "=== Collecting logs ==="
docker compose -f docker-compose.multihop-data-test.yml logs >> "$LOG_FILE" 2>&1

# Check Rust-B received announce from Rust-A (through Python relay)
RUST_B_ANNOUNCE=false
if grep -q "rust-b.*announce_validated" "$LOG_FILE"; then
    echo "PASS: Rust-B received announce from Rust-A through relay"
    RUST_B_ANNOUNCE=true
else
    echo "FAIL: Rust-B did not receive any announces"
fi

# Check link establishment
RUST_B_LINK=false
if grep -q "rust-b.*link_established" "$LOG_FILE"; then
    echo "PASS: Rust-B established a link"
    RUST_B_LINK=true
else
    echo "FAIL: Rust-B did not establish any links"
fi

RUST_A_LINK=false
if grep -q "rust-a.*link_established" "$LOG_FILE"; then
    echo "PASS: Rust-A established a link"
    RUST_A_LINK=true
else
    echo "FAIL: Rust-A did not establish any links"
fi

# Check data exchange through relay
RUST_A_DATA=false
if grep -q "rust-a.*link_data_received" "$LOG_FILE"; then
    echo "PASS: Rust-A received link data through relay"
    RUST_A_DATA=true
else
    echo "FAIL: Rust-A did not receive link data"
fi

# Check resource transfer through relay
RUST_A_RESOURCE=false
if grep -q "rust-a.*resource_received" "$LOG_FILE"; then
    echo "PASS: Rust-A received resource through relay"
    RUST_A_RESOURCE=true
else
    echo "INFO: Rust-A did not receive resource through relay"
fi

# Check channel message through relay
RUST_A_CHANNEL=false
if grep -q "rust-a.*channel_message_received" "$LOG_FILE"; then
    echo "PASS: Rust-A received channel message through relay"
    RUST_A_CHANNEL=true
else
    echo "INFO: Rust-A did not receive channel message through relay"
fi

echo "=== Tearing down ==="
docker compose -f docker-compose.multihop-data-test.yml down -v

echo ""
echo "=== Results ==="
echo "Rust-B received announce:      $RUST_B_ANNOUNCE"
echo "Rust-B link established:       $RUST_B_LINK"
echo "Rust-A link established:       $RUST_A_LINK"
echo "Rust-A data received:          $RUST_A_DATA"
echo "Rust-A resource received:      $RUST_A_RESOURCE"
echo "Rust-A channel received:       $RUST_A_CHANNEL"
echo "Full logs saved to: $LOG_FILE"
echo ""

if [ "$RUST_B_ANNOUNCE" = true ] && [ "$RUST_B_LINK" = true ] && [ "$RUST_A_LINK" = true ] && [ "$RUST_A_DATA" = true ]; then
    echo "=== Multi-hop data test PASSED ==="
    exit 0
else
    echo "=== Multi-hop data test FAILED ==="
    exit 1
fi
