#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCKER_DIR="$(dirname "$SCRIPT_DIR")"
LOG_FILE="${DOCKER_DIR}/integration-test.log"

cd "$DOCKER_DIR"

echo "=== Building and starting containers ==="
docker compose up -d --build 2>&1 | tee "$LOG_FILE"

echo "=== Waiting for services to be healthy (60s timeout) ==="
TIMEOUT=60
ELAPSED=0
while [ $ELAPSED -lt $TIMEOUT ]; do
    if docker compose ps --format json | grep -q '"Health":"healthy"'; then
        echo "Python RNS is healthy"
        break
    fi
    sleep 2
    ELAPSED=$((ELAPSED + 2))
done

if [ $ELAPSED -ge $TIMEOUT ]; then
    echo "FAIL: Services did not become healthy within ${TIMEOUT}s"
    docker compose logs >> "$LOG_FILE" 2>&1
    docker compose down -v
    exit 1
fi

# Give the Rust node a moment to connect
sleep 5

echo "=== Collecting logs ==="
docker compose logs >> "$LOG_FILE" 2>&1

echo "=== Checking Rust node connection ==="
if docker compose logs rust-node 2>&1 | grep -q "connected to"; then
    echo "PASS: Rust node connected to Python RNS"
else
    echo "FAIL: Rust node did not connect"
    docker compose logs rust-node
    docker compose down -v
    exit 1
fi

echo "=== Tearing down ==="
docker compose down -v

echo "=== Integration test passed ==="
echo "Full logs saved to: $LOG_FILE"
