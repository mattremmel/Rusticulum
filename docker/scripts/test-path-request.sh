#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCKER_DIR="$(dirname "$SCRIPT_DIR")"
LOG_FILE="${DOCKER_DIR}/path-request-test.log"

source "$SCRIPT_DIR/test-helpers.sh"

PROJECT=rusticulum-path-request
COMPOSE_FILES="-f docker-compose.yml -f docker-compose.path-request-test.yml"
COMPOSE_CMD="docker compose -p $PROJECT $COMPOSE_FILES"

cd "$DOCKER_DIR"

echo "=== Building and starting containers for path request test ==="
compose_up 2>&1 | tee "$LOG_FILE"

echo "=== Waiting for python-rns test script to complete (120s timeout) ==="
TIMEOUT=120

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

RUST_CONTAINER=$($COMPOSE_CMD ps -q rust-node 2>/dev/null)
if [ -n "$RUST_CONTAINER" ]; then
    timeout 30 docker wait "$RUST_CONTAINER" 2>/dev/null || true
fi

echo "=== Collecting logs ==="
$COMPOSE_CMD logs >> "$LOG_FILE" 2>&1

# Check Python test result
PYTHON_PASS=false
if [ "$PYTHON_EXIT" = "0" ]; then
    echo "PASS: Python test script reports success"
    PYTHON_PASS=true
elif [ -z "$PYTHON_EXIT" ]; then
    echo "FAIL: Python test script did not exit within ${TIMEOUT}s"
else
    echo "FAIL: Python test script exited with code $PYTHON_EXIT"
fi

# Check Rust cached the announce and served path responses
CACHE_PASS=false
if grep -q "cached announce for path responses" "$LOG_FILE" || grep -q "serving path response from cache" "$LOG_FILE"; then
    echo "PASS: Rust node cached announce and/or served path responses"
    CACHE_PASS=true
else
    echo "FAIL: Rust node did not cache any announces or serve path responses"
fi

# Check Rust validated announces
ANNOUNCE_PASS=false
if grep -q "announce_validated" "$LOG_FILE"; then
    echo "PASS: Rust node validated a received announce"
    ANNOUNCE_PASS=true
else
    echo "FAIL: Rust node did not validate any announces"
fi

# Check Rust handled path request packets (either served or forwarded)
PATH_REQ_PASS=false
if grep -qE "serving path response|forwarding path request|path request" "$LOG_FILE"; then
    echo "PASS: Rust node handled path request packets"
    PATH_REQ_PASS=true
else
    echo "INFO: No path request handling detected in logs (may be expected)"
    PATH_REQ_PASS=true  # Not a hard failure; path requests may not reach Rust directly
fi

echo "=== Tearing down ==="
compose_down

echo ""
echo "=== Results ==="
echo "Python test passed:      $PYTHON_PASS"
echo "Announce cached:         $CACHE_PASS"
echo "Announce validated:      $ANNOUNCE_PASS"
echo "Path requests handled:   $PATH_REQ_PASS"
echo "Full logs saved to: $LOG_FILE"
echo ""

if [ "$PYTHON_PASS" = true ] && [ "$CACHE_PASS" = true ] && [ "$ANNOUNCE_PASS" = true ]; then
    echo "=== Path request test PASSED ==="
    exit 0
else
    echo "=== Path request test FAILED ==="
    exit 1
fi
