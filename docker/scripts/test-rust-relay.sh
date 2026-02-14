#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCKER_DIR="$(dirname "$SCRIPT_DIR")"
LOG_FILE="${DOCKER_DIR}/rust-relay-test.log"

cd "$DOCKER_DIR"

echo "=== Building and starting containers for Rust relay test ==="
docker compose -f docker-compose.rust-relay-test.yml up -d --build 2>&1 | tee "$LOG_FILE"

echo "=== Waiting for Python test scripts to complete (180s timeout) ==="
TIMEOUT=180

# Wait for both Python containers to exit
PYTHON_A_CONTAINER=$(docker compose -f docker-compose.rust-relay-test.yml ps -q python-a 2>/dev/null)
PYTHON_B_CONTAINER=$(docker compose -f docker-compose.rust-relay-test.yml ps -q python-b 2>/dev/null)

PYTHON_A_EXIT=""
PYTHON_B_EXIT=""

if [ -n "$PYTHON_A_CONTAINER" ]; then
    PYTHON_A_EXIT=$(timeout "$TIMEOUT" docker wait "$PYTHON_A_CONTAINER" 2>/dev/null || echo "")
    if [ -n "$PYTHON_A_EXIT" ]; then
        echo "Python-A (announcer) exited with code: $PYTHON_A_EXIT"
    else
        echo "WARNING: Python-A did not exit within timeout"
    fi
fi

if [ -n "$PYTHON_B_CONTAINER" ]; then
    PYTHON_B_EXIT=$(timeout "$TIMEOUT" docker wait "$PYTHON_B_CONTAINER" 2>/dev/null || echo "")
    if [ -n "$PYTHON_B_EXIT" ]; then
        echo "Python-B (linker) exited with code: $PYTHON_B_EXIT"
    else
        echo "WARNING: Python-B did not exit within timeout"
    fi
fi

# Also wait for rust-relay to finish (it may still be running)
RUST_CONTAINER=$(docker compose -f docker-compose.rust-relay-test.yml ps -q rust-relay 2>/dev/null)
if [ -n "$RUST_CONTAINER" ]; then
    timeout 30 docker wait "$RUST_CONTAINER" 2>/dev/null || true
fi

echo "=== Collecting logs ==="
docker compose -f docker-compose.rust-relay-test.yml logs >> "$LOG_FILE" 2>&1

# Check Python-A results
PYTHON_A_PASS=false
if [ "$PYTHON_A_EXIT" = "0" ]; then
    echo "PASS: Python-A (announcer) reports success"
    PYTHON_A_PASS=true
else
    echo "FAIL: Python-A (announcer) exited with code $PYTHON_A_EXIT"
fi

# Check Python-B results
PYTHON_B_PASS=false
if [ "$PYTHON_B_EXIT" = "0" ]; then
    echo "PASS: Python-B (linker) reports success"
    PYTHON_B_PASS=true
else
    echo "FAIL: Python-B (linker) exited with code $PYTHON_B_EXIT"
fi

# Check Rust relay logs
RUST_ANNOUNCE=false
if grep -q "announce_validated" "$LOG_FILE"; then
    echo "PASS: Rust relay processed announces"
    RUST_ANNOUNCE=true
else
    echo "INFO: Rust relay did not log announce processing"
fi

RUST_RELAY=false
if grep -q "transport_relay" "$LOG_FILE"; then
    echo "PASS: Rust relay forwarded packets"
    RUST_RELAY=true
else
    echo "INFO: Rust relay did not log transport relay activity"
fi

echo "=== Tearing down ==="
docker compose -f docker-compose.rust-relay-test.yml down -v

echo ""
echo "=== Results ==="
echo "Python-A (announcer) pass: $PYTHON_A_PASS"
echo "Python-B (linker) pass:    $PYTHON_B_PASS"
echo "Rust relay announces:      $RUST_ANNOUNCE"
echo "Rust relay forwarding:     $RUST_RELAY"
echo "Full logs saved to: $LOG_FILE"
echo ""

if [ "$PYTHON_A_PASS" = true ] && [ "$PYTHON_B_PASS" = true ]; then
    echo "=== Rust relay test PASSED ==="
    exit 0
else
    echo "=== Rust relay test FAILED ==="
    exit 1
fi
