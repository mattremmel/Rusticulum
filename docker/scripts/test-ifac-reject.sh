#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCKER_DIR="$(dirname "$SCRIPT_DIR")"
LOG_FILE="${DOCKER_DIR}/ifac-reject-test.log"

source "$SCRIPT_DIR/test-helpers.sh"

PROJECT=rusticulum-ifac-reject
COMPOSE_FILES="-f docker-compose.ifac-reject-test.yml"
COMPOSE_CMD="docker compose -p $PROJECT $COMPOSE_FILES"

cd "$DOCKER_DIR"

echo "=== Building and starting containers for IFAC rejection test ==="
compose_up 2>&1 | tee "$LOG_FILE"

echo "=== Waiting for IFAC rejection test (60s — expecting silence) ==="
TIMEOUT=60

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

# Check Python test result (should exit 0 = no communication happened)
PYTHON_PASS=false
if [ "$PYTHON_EXIT" = "0" ]; then
    echo "PASS: Python confirms no communication occurred (IFAC mismatch)"
    PYTHON_PASS=true
elif [ -z "$PYTHON_EXIT" ]; then
    echo "FAIL: Python test script did not exit within ${TIMEOUT}s"
else
    echo "FAIL: Python test script exited with code $PYTHON_EXIT"
fi

# Verify Rust did NOT receive any announces (inverted check)
NO_RUST_ANNOUNCE=true
if grep -q "rust-node.*announce_validated" "$LOG_FILE"; then
    echo "FAIL: Rust received an announce despite IFAC mismatch!"
    NO_RUST_ANNOUNCE=false
else
    echo "PASS: Rust correctly rejected all announces (IFAC mismatch)"
fi

# Verify Rust did NOT establish any links
NO_RUST_LINK=true
if grep -q "rust-node.*link_established" "$LOG_FILE"; then
    echo "FAIL: Rust established a link despite IFAC mismatch!"
    NO_RUST_LINK=false
else
    echo "PASS: Rust correctly established no links (IFAC mismatch)"
fi

# Check for IFAC verification failures in Rust logs (expected)
IFAC_FAILURES=false
if grep -q "IFAC verification failed" "$LOG_FILE"; then
    echo "INFO: Rust logged IFAC verification failures (expected)"
    IFAC_FAILURES=true
fi

echo "=== Tearing down ==="
compose_down

echo ""
echo "=== Results ==="
echo "Python confirms no communication:  $PYTHON_PASS"
echo "Rust rejected all announces:       $NO_RUST_ANNOUNCE"
echo "Rust established no links:         $NO_RUST_LINK"
echo "IFAC failures logged:              $IFAC_FAILURES"
echo "Full logs saved to: $LOG_FILE"
echo ""

if [ "$PYTHON_PASS" = true ] && [ "$NO_RUST_ANNOUNCE" = true ] && [ "$NO_RUST_LINK" = true ]; then
    echo "=== IFAC rejection test PASSED ==="
    exit 0
else
    echo "=== IFAC rejection test FAILED ==="
    exit 1
fi
