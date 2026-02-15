#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCKER_DIR="$(dirname "$SCRIPT_DIR")"
LOG_FILE="${DOCKER_DIR}/keepalive-test.log"

source "$SCRIPT_DIR/test-helpers.sh"

PROJECT=rusticulum-keepalive
COMPOSE_FILES="-f docker-compose.yml -f docker-compose.keepalive-test.yml"
COMPOSE_CMD="docker compose -p $PROJECT $COMPOSE_FILES"

cd "$DOCKER_DIR"

echo "=== Building and starting containers for keepalive test ==="
compose_up 2>&1 | tee "$LOG_FILE"

echo "=== Waiting for python-rns keepalive test to complete (180s timeout) ==="
TIMEOUT=180

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
    echo "PASS: Python reports keepalive test success"
    PYTHON_PASS=true
elif [ -z "$PYTHON_EXIT" ]; then
    echo "FAIL: Python test did not exit within ${TIMEOUT}s"
else
    echo "FAIL: Python test exited with code $PYTHON_EXIT"
fi

# Check Rust logs for link_established
RUST_LINK_ESTABLISHED=false
if grep -q "link_established" "$LOG_FILE"; then
    echo "PASS: Rust node established a link"
    RUST_LINK_ESTABLISHED=true
else
    echo "FAIL: Rust node did not establish any links"
fi

# Check Rust logs for keepalive_sent
RUST_KEEPALIVE_SENT=false
if grep -q "keepalive_sent" "$LOG_FILE"; then
    echo "PASS: Rust node sent keepalive packets"
    RUST_KEEPALIVE_SENT=true
else
    echo "FAIL: Rust node did not send any keepalive packets"
fi

# Check Rust logs for keepalive_processed
RUST_KEEPALIVE_RECV=false
if grep -q "keepalive_processed" "$LOG_FILE"; then
    echo "PASS: Rust node received keepalive echo"
    RUST_KEEPALIVE_RECV=true
else
    echo "INFO: Rust node did not log keepalive echo receipt"
fi

echo "=== Tearing down ==="
compose_down

echo ""
echo "=== Results ==="
echo "Python reports success:      $PYTHON_PASS"
echo "Rust link established:       $RUST_LINK_ESTABLISHED"
echo "Rust keepalive sent:         $RUST_KEEPALIVE_SENT"
echo "Rust keepalive echo recv:    $RUST_KEEPALIVE_RECV"
echo "Full logs saved to: $LOG_FILE"
echo ""

if [ "$PYTHON_PASS" = true ] && [ "$RUST_LINK_ESTABLISHED" = true ] && [ "$RUST_KEEPALIVE_SENT" = true ]; then
    echo "=== Keepalive interop test PASSED ==="
    exit 0
else
    echo "=== Keepalive interop test FAILED ==="
    exit 1
fi
