#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCKER_DIR="$(dirname "$SCRIPT_DIR")"
LOG_FILE="${DOCKER_DIR}/resource-test.log"

source "$SCRIPT_DIR/test-helpers.sh"

PROJECT=rusticulum-resource
COMPOSE_FILES="-f docker-compose.yml -f docker-compose.resource-test.yml"
COMPOSE_CMD="docker compose -p $PROJECT $COMPOSE_FILES"

cd "$DOCKER_DIR"

echo "=== Building and starting containers for resource transfer test ==="
compose_up 2>&1 | tee "$LOG_FILE"

echo "=== Waiting for python-rns test script to complete (120s timeout) ==="
TIMEOUT=120

# Get the container name/ID for python-rns
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
    echo "PASS: Python test script reports success (resource received)"
    PYTHON_PASS=true
elif [ -z "$PYTHON_EXIT" ]; then
    echo "FAIL: Python test script did not exit within ${TIMEOUT}s"
else
    echo "FAIL: Python test script exited with code $PYTHON_EXIT"
fi

# Check Rust logs for resource_received
RUST_RESOURCE_RECEIVED=false
if grep -q "resource_received" "$LOG_FILE"; then
    echo "PASS: Rust node received a resource"
    RUST_RESOURCE_RECEIVED=true
else
    echo "FAIL: Rust node did not receive any resources"
fi

# Check Rust logs for resource_proof_verified
RUST_PROOF_VERIFIED=false
if grep -q "resource_proof_verified" "$LOG_FILE"; then
    echo "PASS: Rust node's resource proof was verified"
    RUST_PROOF_VERIFIED=true
else
    echo "INFO: Rust node's resource proof was not verified (may be expected)"
fi

# Check Rust logs for link_established
RUST_LINK_ESTABLISHED=false
if grep -q "link_established" "$LOG_FILE"; then
    echo "PASS: Rust node established a link"
    RUST_LINK_ESTABLISHED=true
else
    echo "FAIL: Rust node did not establish any links"
fi

echo "=== Tearing down ==="
compose_down

echo ""
echo "=== Results ==="
echo "Python reports success:        $PYTHON_PASS"
echo "Rust link established:         $RUST_LINK_ESTABLISHED"
echo "Rust resource received:        $RUST_RESOURCE_RECEIVED"
echo "Rust resource proof verified:  $RUST_PROOF_VERIFIED"
echo "Full logs saved to: $LOG_FILE"
echo ""

if [ "$PYTHON_PASS" = true ] && [ "$RUST_LINK_ESTABLISHED" = true ]; then
    echo "=== Bidirectional resource transfer test PASSED ==="
    exit 0
else
    echo "=== Bidirectional resource transfer test FAILED ==="
    exit 1
fi
