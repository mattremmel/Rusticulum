#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCKER_DIR="$(dirname "$SCRIPT_DIR")"
LOG_FILE="${DOCKER_DIR}/vector-check-test.log"

cd "$DOCKER_DIR"

COMPOSE="docker compose -f docker-compose.yml -f docker-compose.vector-check-test.yml"

echo "=== Building and starting containers for vector-check test ==="
$COMPOSE up -d --build 2>&1 | tee "$LOG_FILE"

echo "=== Waiting for Python vector-check to complete (180s timeout) ==="
PYTHON_CONTAINER=$($COMPOSE ps -a -q python-rns 2>/dev/null)
PYTHON_EXIT=""
if [ -n "$PYTHON_CONTAINER" ]; then
    PYTHON_EXIT=$(timeout 180 docker wait "$PYTHON_CONTAINER" 2>/dev/null || echo "timeout")
    echo "Python vector-check exited with code: $PYTHON_EXIT"
else
    echo "WARNING: Could not find python-rns container"
fi

echo "=== Waiting for Rust vector-check to complete (180s timeout) ==="
RUST_CONTAINER=$($COMPOSE ps -a -q rust-node 2>/dev/null)
RUST_EXIT=""
if [ -n "$RUST_CONTAINER" ]; then
    RUST_EXIT=$(timeout 180 docker wait "$RUST_CONTAINER" 2>/dev/null || echo "timeout")
    echo "Rust vector-check exited with code: $RUST_EXIT"
fi

echo "=== Collecting logs ==="
$COMPOSE logs >> "$LOG_FILE" 2>&1

# Check exit codes
PYTHON_PASS=false
if [ "$PYTHON_EXIT" = "0" ]; then
    echo "PASS: Python vector-check completed successfully"
    PYTHON_PASS=true
else
    echo "FAIL: Python vector-check exit=$PYTHON_EXIT"
fi

RUST_PASS=false
if [ "$RUST_EXIT" = "0" ]; then
    echo "PASS: Rust vector-check completed successfully"
    RUST_PASS=true
else
    echo "FAIL: Rust vector-check exit=$RUST_EXIT"
fi

# Diff the results using a temporary container
echo "=== Comparing results ==="
VOLUME_NAME=$(docker volume ls -q | grep vector-data | head -1 || true)
if [ -z "$VOLUME_NAME" ]; then
    VOLUME_NAME="docker_vector-data"
fi

DIFF_EXIT=0
DIFF_OUTPUT=$(docker run --rm -v "${VOLUME_NAME}:/data" alpine sh -c '
    if [ ! -f /data/rust_results.txt ]; then
        echo "ERROR: rust_results.txt not found"
        exit 2
    fi
    if [ ! -f /data/python_results.txt ]; then
        echo "ERROR: python_results.txt not found"
        exit 2
    fi
    RUST_LINES=$(wc -l < /data/rust_results.txt)
    PYTHON_LINES=$(wc -l < /data/python_results.txt)
    echo "Rust lines: $RUST_LINES"
    echo "Python lines: $PYTHON_LINES"
    diff /data/rust_results.txt /data/python_results.txt
' 2>&1) || DIFF_EXIT=$?

echo "$DIFF_OUTPUT"

DIFF_PASS=false
if [ $DIFF_EXIT -eq 0 ]; then
    echo "PASS: Results are identical"
    DIFF_PASS=true
else
    echo "FAIL: Results differ (diff exit=$DIFF_EXIT)"
    echo "$DIFF_OUTPUT" | head -40
fi

echo "=== Tearing down ==="
$COMPOSE down -v

echo ""
echo "=== Results ==="
echo "Python completed:  $PYTHON_PASS"
echo "Rust completed:    $RUST_PASS"
echo "Results identical: $DIFF_PASS"
echo "Full logs saved to: $LOG_FILE"
echo ""

if [ "$PYTHON_PASS" = true ] && [ "$RUST_PASS" = true ] && [ "$DIFF_PASS" = true ]; then
    echo "=== Vector check test PASSED ==="
    exit 0
else
    echo "=== Vector check test FAILED ==="
    exit 1
fi
