#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCKER_DIR="$(dirname "$SCRIPT_DIR")"
LOG_FILE="${DOCKER_DIR}/fuzz-test.log"

source "$SCRIPT_DIR/test-helpers.sh"

PROJECT=rusticulum-fuzz
COMPOSE_FILES="-f docker-compose.yml -f docker-compose.fuzz-test.yml"
COMPOSE_CMD="docker compose -p $PROJECT $COMPOSE_FILES"

cd "$DOCKER_DIR"

echo "=== Building and starting containers for cross-implementation fuzz test ==="
compose_up 2>&1 | tee "$LOG_FILE"

echo "=== Waiting for Python fuzz test to complete (120s timeout) ==="

PYTHON_CONTAINER=$($COMPOSE_CMD ps -q python-rns 2>/dev/null)

PYTHON_EXIT=""
if [ -n "$PYTHON_CONTAINER" ]; then
    PYTHON_EXIT=$(timeout 120 docker wait "$PYTHON_CONTAINER" 2>/dev/null || echo "timeout")
    echo "Python fuzz test exited with code: $PYTHON_EXIT"
else
    echo "WARNING: Could not find python-rns container"
fi

echo "=== Waiting for Rust fuzz-gen to complete (120s timeout) ==="
RUST_CONTAINER=$($COMPOSE_CMD ps -q rust-node 2>/dev/null)
RUST_EXIT=""
if [ -n "$RUST_CONTAINER" ]; then
    RUST_EXIT=$(timeout 120 docker wait "$RUST_CONTAINER" 2>/dev/null || echo "timeout")
    echo "Rust fuzz-gen exited with code: $RUST_EXIT"
fi

echo "=== Collecting logs ==="
$COMPOSE_CMD logs >> "$LOG_FILE" 2>&1

# Check Python result
PYTHON_PASS=false
if [ "$PYTHON_EXIT" = "0" ]; then
    echo "PASS: Python fuzz test reports success"
    PYTHON_PASS=true
else
    echo "FAIL: Python fuzz test exit=$PYTHON_EXIT"
fi

# Check Rust result
RUST_PASS=false
if [ "$RUST_EXIT" = "0" ]; then
    echo "PASS: Rust fuzz-gen reports success"
    RUST_PASS=true
else
    echo "INFO: Rust fuzz-gen exit=$RUST_EXIT (checking logs for completion)"
fi

# Check for validation complete markers in both sides' logs
PYTHON_VALIDATED=false
if grep -q "fuzz_validation_complete" "$LOG_FILE"; then
    echo "PASS: Found fuzz_validation_complete in logs"
    PYTHON_VALIDATED=true
else
    echo "FAIL: fuzz_validation_complete not found in logs"
fi

PYTHON_NO_CRASH=false
if grep -q "Cross-implementation fuzz test PASSED" "$LOG_FILE"; then
    echo "PASS: Python reports no crashes"
    PYTHON_NO_CRASH=true
else
    echo "FAIL: Python did not report test passed"
fi

RUST_NO_CRASH=false
if grep -q "Fuzz-gen: done" "$LOG_FILE"; then
    echo "PASS: Rust fuzz-gen completed"
    RUST_NO_CRASH=true
    RUST_PASS=true
else
    echo "FAIL: Rust fuzz-gen did not complete"
fi

echo "=== Tearing down ==="
compose_down

echo ""
echo "=== Results ==="
echo "Python fuzz test passed:     $PYTHON_PASS"
echo "Python no crashes:           $PYTHON_NO_CRASH"
echo "Rust fuzz-gen passed:        $RUST_PASS"
echo "Validation complete:         $PYTHON_VALIDATED"
echo "Full logs saved to: $LOG_FILE"
echo ""

if [ "$PYTHON_PASS" = true ] && [ "$PYTHON_VALIDATED" = true ] && [ "$RUST_PASS" = true ] && [ "$PYTHON_NO_CRASH" = true ] && [ "$RUST_NO_CRASH" = true ]; then
    echo "=== Cross-implementation fuzz test PASSED ==="
    exit 0
else
    echo "=== Cross-implementation fuzz test FAILED ==="
    exit 1
fi
