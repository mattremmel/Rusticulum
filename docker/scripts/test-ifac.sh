#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCKER_DIR="$(dirname "$SCRIPT_DIR")"
LOG_FILE="${DOCKER_DIR}/ifac-test.log"

cd "$DOCKER_DIR"

echo "=== Building and starting containers for IFAC test ==="
docker compose -f docker-compose.ifac-test.yml up -d --build 2>&1 | tee "$LOG_FILE"

echo "=== Waiting for IFAC-protected communication (120s timeout) ==="
TIMEOUT=120

# Wait for Python test script to finish
PYTHON_CONTAINER=$(docker compose -f docker-compose.ifac-test.yml ps -q python-rns 2>/dev/null)

if [ -n "$PYTHON_CONTAINER" ]; then
    PYTHON_EXIT=$(timeout "$TIMEOUT" docker wait "$PYTHON_CONTAINER" 2>/dev/null || echo "")
    if [ -n "$PYTHON_EXIT" ]; then
        echo "Python test script exited with code: $PYTHON_EXIT"
    fi
else
    echo "WARNING: Could not find python-rns container"
    PYTHON_EXIT=""
fi

# Wait for Rust node to finish
RUST_CONTAINER=$(docker compose -f docker-compose.ifac-test.yml ps -q rust-node 2>/dev/null)
if [ -n "$RUST_CONTAINER" ]; then
    timeout 30 docker wait "$RUST_CONTAINER" 2>/dev/null || true
fi

echo "=== Collecting logs ==="
docker compose -f docker-compose.ifac-test.yml logs >> "$LOG_FILE" 2>&1

# Check Python test result
PYTHON_PASS=false
if [ "$PYTHON_EXIT" = "0" ]; then
    echo "PASS: Python test script reports success (IFAC communication worked)"
    PYTHON_PASS=true
elif [ -z "$PYTHON_EXIT" ]; then
    echo "FAIL: Python test script did not exit within ${TIMEOUT}s"
else
    echo "FAIL: Python test script exited with code $PYTHON_EXIT"
fi

# Check Rust logs
RUST_ANNOUNCE=false
if grep -q "rust-node.*announce_validated" "$LOG_FILE"; then
    echo "PASS: Rust received IFAC-protected announce"
    RUST_ANNOUNCE=true
else
    echo "FAIL: Rust did not receive any announces"
fi

RUST_LINK=false
if grep -q "rust-node.*link_established" "$LOG_FILE"; then
    echo "PASS: Rust established link over IFAC"
    RUST_LINK=true
else
    echo "FAIL: Rust did not establish any links"
fi

RUST_DATA=false
if grep -q "rust-node.*link_data_received" "$LOG_FILE"; then
    echo "PASS: Rust received data over IFAC link"
    RUST_DATA=true
else
    echo "INFO: Rust did not receive link data"
fi

echo "=== Tearing down ==="
docker compose -f docker-compose.ifac-test.yml down -v

echo ""
echo "=== Results ==="
echo "Python reports success:     $PYTHON_PASS"
echo "Rust received announce:     $RUST_ANNOUNCE"
echo "Rust link established:      $RUST_LINK"
echo "Rust data received:         $RUST_DATA"
echo "Full logs saved to: $LOG_FILE"
echo ""

if [ "$PYTHON_PASS" = true ] && [ "$RUST_LINK" = true ]; then
    echo "=== IFAC test PASSED ==="
    exit 0
else
    echo "=== IFAC test FAILED ==="
    exit 1
fi
