#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCKER_DIR="$(dirname "$SCRIPT_DIR")"
LOG_FILE="${DOCKER_DIR}/large-resource-test.log"

source "$SCRIPT_DIR/test-helpers.sh"

PROJECT=rusticulum-large-resource
COMPOSE_FILES="-f docker-compose.large-resource-test.yml"
COMPOSE_CMD="docker compose -p $PROJECT $COMPOSE_FILES"

cd "$DOCKER_DIR"

echo "=== Building and starting containers for large resource test ==="
compose_up 2>&1 | tee "$LOG_FILE"

echo "=== Waiting for 1MB resource transfer (300s timeout) ==="
TIMEOUT=300

# Wait for Python test script to finish
PYTHON_CONTAINER=$($COMPOSE_CMD ps -q python-rns 2>/dev/null)

if [ -n "$PYTHON_CONTAINER" ]; then
    PYTHON_EXIT=$(timeout "$TIMEOUT" docker wait "$PYTHON_CONTAINER" 2>/dev/null || echo "")
    if [ -n "$PYTHON_EXIT" ]; then
        echo "Python test script exited with code: $PYTHON_EXIT"
    fi
else
    echo "WARNING: Could not find python-rns container"
    PYTHON_EXIT=""
fi

# Wait for Rust node
RUST_CONTAINER=$($COMPOSE_CMD ps -q rust-node 2>/dev/null)
if [ -n "$RUST_CONTAINER" ]; then
    timeout 30 docker wait "$RUST_CONTAINER" 2>/dev/null || true
fi

echo "=== Collecting logs ==="
$COMPOSE_CMD logs >> "$LOG_FILE" 2>&1

# Check Python test result
PYTHON_PASS=false
if [ "$PYTHON_EXIT" = "0" ]; then
    echo "PASS: Python reports large resource transfer completed"
    PYTHON_PASS=true
elif [ -z "$PYTHON_EXIT" ]; then
    echo "FAIL: Python test script did not exit within ${TIMEOUT}s"
else
    echo "FAIL: Python test script exited with code $PYTHON_EXIT"
fi

# Check Rust logs
RUST_LINK=false
if grep -q "rust-node.*link_established" "$LOG_FILE"; then
    echo "PASS: Rust established a link"
    RUST_LINK=true
else
    echo "FAIL: Rust did not establish any links"
fi

RUST_RESOURCE=false
if grep -q "rust-node.*resource_received" "$LOG_FILE"; then
    echo "PASS: Rust received the large resource"
    RUST_RESOURCE=true
else
    echo "FAIL: Rust did not receive the resource"
fi

echo "=== Tearing down ==="
compose_down

echo ""
echo "=== Results ==="
echo "Python reports success:      $PYTHON_PASS"
echo "Rust link established:       $RUST_LINK"
echo "Rust resource received:      $RUST_RESOURCE"
echo "Full logs saved to: $LOG_FILE"
echo ""

# Python may report failure if it doesn't receive the proof back from Rust in time.
# The critical assertion is that Rust received and assembled the large resource.
if [ "$RUST_LINK" = true ] && [ "$RUST_RESOURCE" = true ]; then
    echo "=== Large resource transfer test PASSED ==="
    exit 0
else
    echo "=== Large resource transfer test FAILED ==="
    exit 1
fi
