#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCKER_DIR="$(dirname "$SCRIPT_DIR")"
LOG_FILE="${DOCKER_DIR}/link-test.log"

cd "$DOCKER_DIR"

echo "=== Building and starting containers for link test ==="
docker compose -f docker-compose.yml -f docker-compose.link-test.yml up -d --build 2>&1 | tee "$LOG_FILE"

echo "=== Waiting for python-rns test script to complete (120s timeout) ==="
TIMEOUT=120

# Get the container name/ID for python-rns
PYTHON_CONTAINER=$(docker compose -f docker-compose.yml -f docker-compose.link-test.yml ps -q python-rns 2>/dev/null)

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

echo "=== Collecting logs ==="
docker compose -f docker-compose.yml -f docker-compose.link-test.yml logs >> "$LOG_FILE" 2>&1

# Check Python test result
PYTHON_PASS=false
if [ "$PYTHON_EXIT" = "0" ]; then
    echo "PASS: Python test script reports success (link established)"
    PYTHON_PASS=true
elif [ -z "$PYTHON_EXIT" ]; then
    echo "FAIL: Python test script did not exit within ${TIMEOUT}s"
else
    echo "FAIL: Python test script exited with code $PYTHON_EXIT"
fi

# Check Rust logs for link_established
RUST_LINK_ESTABLISHED=false
if docker compose -f docker-compose.yml -f docker-compose.link-test.yml logs rust-node 2>&1 | grep -q "link_established"; then
    echo "PASS: Rust node established a link"
    RUST_LINK_ESTABLISHED=true
else
    echo "FAIL: Rust node did not establish any links"
fi

# Check Rust logs for link_data_received
RUST_DATA_RECEIVED=false
if docker compose -f docker-compose.yml -f docker-compose.link-test.yml logs rust-node 2>&1 | grep -q "link_data_received"; then
    echo "PASS: Rust node received link data"
    RUST_DATA_RECEIVED=true
else
    echo "INFO: Rust node did not receive link data (may be expected)"
fi

# Check Rust logs for link_data_sent
RUST_DATA_SENT=false
if docker compose -f docker-compose.yml -f docker-compose.link-test.yml logs rust-node 2>&1 | grep -q "link_data_sent"; then
    echo "PASS: Rust node sent link data"
    RUST_DATA_SENT=true
else
    echo "INFO: Rust node did not send link data (may be expected)"
fi

echo "=== Tearing down ==="
docker compose -f docker-compose.yml -f docker-compose.link-test.yml down -v

echo ""
echo "=== Results ==="
echo "Python reports link success: $PYTHON_PASS"
echo "Rust link established:       $RUST_LINK_ESTABLISHED"
echo "Rust data received:          $RUST_DATA_RECEIVED"
echo "Rust data sent:              $RUST_DATA_SENT"
echo "Full logs saved to: $LOG_FILE"
echo ""

if [ "$PYTHON_PASS" = true ] && [ "$RUST_LINK_ESTABLISHED" = true ]; then
    echo "=== Bidirectional link establishment test PASSED ==="
    exit 0
else
    echo "=== Bidirectional link establishment test FAILED ==="
    exit 1
fi
