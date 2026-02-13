#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCKER_DIR="$(dirname "$SCRIPT_DIR")"
LOG_FILE="${DOCKER_DIR}/multihop-test.log"

cd "$DOCKER_DIR"

echo "=== Building and starting containers for multihop test (Python relay) ==="
docker compose -f docker-compose.multihop-test.yml up -d --build 2>&1 | tee "$LOG_FILE"

echo "=== Waiting for Rust nodes to process announces (90s) ==="
sleep 90

echo "=== Collecting logs ==="
docker compose -f docker-compose.multihop-test.yml logs >> "$LOG_FILE" 2>&1

# Check Rust-B received announce from Rust-A (through Python relay)
RUST_B_ANNOUNCE=false
if docker compose -f docker-compose.multihop-test.yml logs rust-b 2>&1 | grep -q "announce_validated"; then
    echo "PASS: Rust-B received announce from Rust-A through relay"
    RUST_B_ANNOUNCE=true
else
    echo "FAIL: Rust-B did not receive any announces"
fi

# Check Rust-A received announce from Rust-B's discovery (Rust-B doesn't announce,
# but Rust-A's announce should reach Rust-B)
RUST_A_ANNOUNCE=false
if docker compose -f docker-compose.multihop-test.yml logs rust-a 2>&1 | grep -q "announce_validated"; then
    echo "INFO: Rust-A also received an announce (may be from relay)"
    RUST_A_ANNOUNCE=true
fi

# Check link establishment
RUST_B_LINK=false
if docker compose -f docker-compose.multihop-test.yml logs rust-b 2>&1 | grep -q "link_established"; then
    echo "PASS: Rust-B established a link"
    RUST_B_LINK=true
else
    echo "FAIL: Rust-B did not establish any links"
fi

RUST_A_LINK=false
if docker compose -f docker-compose.multihop-test.yml logs rust-a 2>&1 | grep -q "link_established"; then
    echo "PASS: Rust-A established a link"
    RUST_A_LINK=true
else
    echo "FAIL: Rust-A did not establish any links"
fi

# Check data exchange
RUST_A_DATA=false
if docker compose -f docker-compose.multihop-test.yml logs rust-a 2>&1 | grep -q "link_data_received"; then
    echo "PASS: Rust-A received link data"
    RUST_A_DATA=true
else
    echo "INFO: Rust-A did not receive link data"
fi

RUST_B_DATA=false
if docker compose -f docker-compose.multihop-test.yml logs rust-b 2>&1 | grep -q "link_data_sent"; then
    echo "PASS: Rust-B sent link data"
    RUST_B_DATA=true
else
    echo "INFO: Rust-B did not send link data"
fi

echo "=== Tearing down ==="
docker compose -f docker-compose.multihop-test.yml down -v

echo ""
echo "=== Results ==="
echo "Rust-B received announce:  $RUST_B_ANNOUNCE"
echo "Rust-B link established:   $RUST_B_LINK"
echo "Rust-A link established:   $RUST_A_LINK"
echo "Rust-A data received:      $RUST_A_DATA"
echo "Rust-B data sent:          $RUST_B_DATA"
echo "Full logs saved to: $LOG_FILE"
echo ""

if [ "$RUST_B_ANNOUNCE" = true ] && [ "$RUST_B_LINK" = true ] && [ "$RUST_A_LINK" = true ]; then
    echo "=== Multi-hop test (Python relay) PASSED ==="
    exit 0
else
    echo "=== Multi-hop test (Python relay) FAILED ==="
    exit 1
fi
