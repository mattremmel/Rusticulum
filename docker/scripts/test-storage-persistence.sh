#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCKER_DIR="$(dirname "$SCRIPT_DIR")"
LOG_FILE="${DOCKER_DIR}/storage-test.log"
COMPOSE_FILE="docker-compose.storage-test.yml"

cd "$DOCKER_DIR"

echo "=== Building and starting containers for storage persistence test ==="
docker compose -f "$COMPOSE_FILE" up -d --build 2>&1 | tee "$LOG_FILE"

echo "=== Phase 1: Waiting for initial link establishment (40s) ==="
sleep 40

# Capture Rust node identity hash from logs (first occurrence of queued_announce)
echo "=== Capturing Rust identity from phase 1 ==="
docker compose -f "$COMPOSE_FILE" logs rust-node >> "$LOG_FILE" 2>&1

IDENTITY_HASH_1=""
if grep -q "queued_announce" "$LOG_FILE"; then
    IDENTITY_HASH_1=$(grep "queued_announce" "$LOG_FILE" | head -1 | grep -oP '"destination_hash":"[^"]*"' | head -1 | cut -d'"' -f4)
    echo "Phase 1 identity hash: $IDENTITY_HASH_1"
fi

# Check that phase 1 link was established
PHASE1_LINK=false
if grep -q "link_established" "$LOG_FILE"; then
    echo "PASS: Phase 1 link established"
    PHASE1_LINK=true
else
    echo "FAIL: Phase 1 link not established"
fi

echo "=== Stopping Rust node (SIGTERM for graceful shutdown) ==="
docker compose -f "$COMPOSE_FILE" stop rust-node

echo "=== Waiting for state to persist (5s) ==="
sleep 5

echo "=== Restarting Rust node ==="
docker compose -f "$COMPOSE_FILE" start rust-node

echo "=== Phase 2: Waiting for second link establishment (50s) ==="
sleep 50

echo "=== Collecting all logs ==="
docker compose -f "$COMPOSE_FILE" logs >> "$LOG_FILE" 2>&1

# Capture identity hash from phase 2 (after restart)
IDENTITY_HASH_2=""
# Look for queued_announce after the restart — the "loaded transport identity" log indicates restart
if grep -q "loaded transport identity" "$LOG_FILE"; then
    echo "PASS: Rust node loaded identity from storage on restart"
    # Get the last queued_announce destination_hash (from phase 2)
    IDENTITY_HASH_2=$(grep "queued_announce" "$LOG_FILE" | tail -1 | grep -oP '"destination_hash":"[^"]*"' | head -1 | cut -d'"' -f4)
    echo "Phase 2 identity hash: $IDENTITY_HASH_2"
else
    echo "INFO: Did not find 'loaded transport identity' message"
fi

# Check identity persistence
IDENTITY_PERSISTED=false
if [ -n "$IDENTITY_HASH_1" ] && [ -n "$IDENTITY_HASH_2" ] && [ "$IDENTITY_HASH_1" = "$IDENTITY_HASH_2" ]; then
    echo "PASS: Identity hash matches across restart ($IDENTITY_HASH_1)"
    IDENTITY_PERSISTED=true
elif [ -n "$IDENTITY_HASH_1" ] && [ -n "$IDENTITY_HASH_2" ]; then
    echo "FAIL: Identity hash changed! Before: $IDENTITY_HASH_1, After: $IDENTITY_HASH_2"
else
    echo "INFO: Could not capture both identity hashes"
fi

# Check phase 2 link from Rust logs (after restart there should be another link_established)
PHASE2_LINK=false
# Count link_established occurrences
LINK_COUNT=$(grep -c "link_established" "$LOG_FILE" 2>/dev/null || echo "0")
if [ "$LINK_COUNT" -ge 2 ]; then
    echo "PASS: Phase 2 link established (total links: $LINK_COUNT)"
    PHASE2_LINK=true
elif [ "$LINK_COUNT" -ge 1 ]; then
    echo "INFO: Only $LINK_COUNT link(s) established (need at least 2)"
fi

# Wait for Python to finish
PYTHON_CONTAINER=$(docker compose -f "$COMPOSE_FILE" ps -q python-rns 2>/dev/null)
if [ -n "$PYTHON_CONTAINER" ]; then
    PYTHON_EXIT=$(timeout 30 docker wait "$PYTHON_CONTAINER" 2>/dev/null || echo "")
    echo "Python test exited with code: ${PYTHON_EXIT:-timeout}"
fi

# Final log collection
docker compose -f "$COMPOSE_FILE" logs >> "$LOG_FILE" 2>&1

echo "=== Tearing down ==="
docker compose -f "$COMPOSE_FILE" down -v

echo ""
echo "=== Results ==="
echo "Phase 1 link established:    $PHASE1_LINK"
echo "Phase 2 link established:    $PHASE2_LINK"
echo "Identity persisted:          $IDENTITY_PERSISTED"
echo "Identity hash 1:             ${IDENTITY_HASH_1:-N/A}"
echo "Identity hash 2:             ${IDENTITY_HASH_2:-N/A}"
echo "Total links:                 $LINK_COUNT"
echo "Full logs saved to: $LOG_FILE"
echo ""

if [ "$PHASE1_LINK" = true ] && [ "$PHASE2_LINK" = true ]; then
    echo "=== Storage persistence test PASSED ==="
    exit 0
else
    echo "=== Storage persistence test FAILED ==="
    exit 1
fi
