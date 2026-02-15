#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCKER_DIR="$(dirname "$SCRIPT_DIR")"
LOG_FILE="${DOCKER_DIR}/announce-test.log"

source "$SCRIPT_DIR/test-helpers.sh"

PROJECT=rusticulum-announce
COMPOSE_FILES="-f docker-compose.yml -f docker-compose.announce-test.yml"
COMPOSE_CMD="docker compose -p $PROJECT $COMPOSE_FILES"

cd "$DOCKER_DIR"

echo "=== Building and starting containers for announce test ==="
compose_up 2>&1 | tee "$LOG_FILE"

echo "=== Waiting for python-rns test script to complete (120s timeout) ==="
TIMEOUT=120

# Get the container name/ID for python-rns
PYTHON_CONTAINER=$($COMPOSE_CMD ps -q python-rns 2>/dev/null)

if [ -n "$PYTHON_CONTAINER" ]; then
    # Use 'docker wait' which reliably blocks until exit and returns the exit code
    PYTHON_EXIT=$(timeout "$TIMEOUT" docker wait "$PYTHON_CONTAINER" 2>/dev/null || echo "")
    if [ -n "$PYTHON_EXIT" ]; then
        echo "Python test script exited with code: $PYTHON_EXIT"
    fi
else
    echo "WARNING: Could not find python-rns container"
    PYTHON_EXIT=""
fi

# Also wait for rust-node to finish (it may still be running)
RUST_CONTAINER=$($COMPOSE_CMD ps -q rust-node 2>/dev/null)
if [ -n "$RUST_CONTAINER" ]; then
    timeout 30 docker wait "$RUST_CONTAINER" 2>/dev/null || true
fi

echo "=== Collecting logs ==="
$COMPOSE_CMD logs >> "$LOG_FILE" 2>&1

# Check Python test result
PYTHON_PASS=false
if [ "$PYTHON_EXIT" = "0" ]; then
    echo "PASS: Python test script reports success (received Rust announce)"
    PYTHON_PASS=true
elif [ -z "$PYTHON_EXIT" ]; then
    echo "FAIL: Python test script did not exit within ${TIMEOUT}s"
else
    echo "FAIL: Python test script exited with code $PYTHON_EXIT"
fi

# Check Rust logs for announce_validated
RUST_PASS=false
if grep -q "announce_validated" "$LOG_FILE"; then
    echo "PASS: Rust node validated a received announce"
    RUST_PASS=true
else
    echo "FAIL: Rust node did not validate any announces"
fi

echo "=== Tearing down ==="
compose_down

echo ""
echo "=== Results ==="
echo "Python received Rust announce: $PYTHON_PASS"
echo "Rust validated Python announce: $RUST_PASS"
echo "Full logs saved to: $LOG_FILE"
echo ""

if [ "$PYTHON_PASS" = true ] && [ "$RUST_PASS" = true ]; then
    echo "=== Bidirectional announce exchange test PASSED ==="
    exit 0
else
    echo "=== Bidirectional announce exchange test FAILED ==="
    exit 1
fi
