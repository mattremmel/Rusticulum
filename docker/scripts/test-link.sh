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
ELAPSED=0
PYTHON_EXIT=

while [ $ELAPSED -lt $TIMEOUT ]; do
    # Check if python-rns container has exited
    STATUS=$(docker compose -f docker-compose.yml -f docker-compose.link-test.yml ps --format json python-rns 2>/dev/null | python3 -c "
import sys, json
data = json.loads(sys.stdin.read())
if isinstance(data, list):
    data = data[0]
print(data.get('State', 'unknown'))
" 2>/dev/null || echo "unknown")

    if [ "$STATUS" = "exited" ]; then
        PYTHON_EXIT=$(docker compose -f docker-compose.yml -f docker-compose.link-test.yml ps --format json python-rns 2>/dev/null | python3 -c "
import sys, json
data = json.loads(sys.stdin.read())
if isinstance(data, list):
    data = data[0]
print(data.get('ExitCode', -1))
" 2>/dev/null || echo "-1")
        echo "Python test script exited with code: $PYTHON_EXIT"
        break
    fi

    sleep 2
    ELAPSED=$((ELAPSED + 2))
done

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
