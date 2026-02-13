#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCKER_DIR="$(dirname "$SCRIPT_DIR")"
LOG_FILE="${DOCKER_DIR}/announce-test.log"

cd "$DOCKER_DIR"

echo "=== Building and starting containers for announce test ==="
docker compose -f docker-compose.yml -f docker-compose.announce-test.yml up -d --build 2>&1 | tee "$LOG_FILE"

echo "=== Waiting for python-rns test script to complete (90s timeout) ==="
TIMEOUT=90
ELAPSED=0
PYTHON_EXIT=

while [ $ELAPSED -lt $TIMEOUT ]; do
    # Check if python-rns container has exited
    STATUS=$(docker compose -f docker-compose.yml -f docker-compose.announce-test.yml ps --format json python-rns 2>/dev/null | python3 -c "
import sys, json
data = json.loads(sys.stdin.read())
if isinstance(data, list):
    data = data[0]
print(data.get('State', 'unknown'))
" 2>/dev/null || echo "unknown")

    if [ "$STATUS" = "exited" ]; then
        PYTHON_EXIT=$(docker compose -f docker-compose.yml -f docker-compose.announce-test.yml ps --format json python-rns 2>/dev/null | python3 -c "
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
docker compose -f docker-compose.yml -f docker-compose.announce-test.yml logs >> "$LOG_FILE" 2>&1

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
if docker compose -f docker-compose.yml -f docker-compose.announce-test.yml logs rust-node 2>&1 | grep -q "announce_validated"; then
    echo "PASS: Rust node validated a received announce"
    RUST_PASS=true
else
    echo "FAIL: Rust node did not validate any announces"
fi

echo "=== Tearing down ==="
docker compose -f docker-compose.yml -f docker-compose.announce-test.yml down -v

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
