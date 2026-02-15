#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCKER_DIR="$(dirname "$SCRIPT_DIR")"
LOG_FILE="${DOCKER_DIR}/multihop-channel-test.log"

source "$SCRIPT_DIR/test-helpers.sh"

PROJECT=rusticulum-multihop-channel
COMPOSE_FILES="-f docker-compose.multihop-channel-test.yml"
COMPOSE_CMD="docker compose -p $PROJECT $COMPOSE_FILES"

cd "$DOCKER_DIR"

echo "=== Building and starting containers for multihop channel test (Rust relay) ==="
compose_up 2>&1 | tee "$LOG_FILE"

echo "=== Waiting for channel exchanges through Rust relay (180s timeout) ==="
TIMEOUT=180

# Capture container IDs while containers are still running
PYTHON_A_CONTAINER=$($COMPOSE_CMD ps -q python-a 2>/dev/null)
PYTHON_B_CONTAINER=$($COMPOSE_CMD ps -q python-b 2>/dev/null)

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

# Wait for rust-relay to finish
RUST_CONTAINER=$($COMPOSE_CMD ps -q "rust-relay" 2>/dev/null)
if [ -n "$RUST_CONTAINER" ]; then
    timeout 30 docker wait "$RUST_CONTAINER" 2>/dev/null || true
fi

echo "=== Collecting logs ==="
$COMPOSE_CMD logs >> "$LOG_FILE" 2>&1

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

# Check Rust relay forwarded packets
RUST_RELAY_ACTIVE=false
if grep -q "rust-relay.*announce_validated" "$LOG_FILE"; then
    echo "PASS: Rust relay received announces"
    RUST_RELAY_ACTIVE=true
else
    echo "INFO: No announce_validated in Rust relay logs"
fi

echo "=== Tearing down ==="
compose_down

echo ""
echo "=== Results ==="
echo "Python-A (announcer) pass:  $PYTHON_A_PASS"
echo "Python-B (linker) pass:     $PYTHON_B_PASS"
echo "Rust relay active:          $RUST_RELAY_ACTIVE"
echo "Full logs saved to: $LOG_FILE"
echo ""

if [ "$PYTHON_A_PASS" = true ] && [ "$PYTHON_B_PASS" = true ]; then
    echo "=== Multi-hop channel test (Rust relay) PASSED ==="
    exit 0
else
    echo "=== Multi-hop channel test (Rust relay) FAILED ==="
    exit 1
fi
