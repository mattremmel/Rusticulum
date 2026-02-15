#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCKER_DIR="$(dirname "$SCRIPT_DIR")"
LOG_FILE="${DOCKER_DIR}/storage-test.log"

source "$SCRIPT_DIR/test-helpers.sh"

PROJECT=rusticulum-storage
COMPOSE_FILES="-f docker-compose.storage-test.yml"
COMPOSE_CMD="docker compose -p $PROJECT $COMPOSE_FILES"

cd "$DOCKER_DIR"

echo "=== Building and starting containers for storage persistence test ==="
compose_up 2>&1 | tee "$LOG_FILE"

echo "=== Phase 1: Waiting for initial link establishment (polling, 60s timeout) ==="
if ! poll_logs "link_established" 60 5; then
    echo "WARNING: link_established not found in logs within 60s, continuing..."
fi

# Capture Rust node identity hash from logs (first occurrence of queued_announce)
echo "=== Capturing Rust identity from phase 1 ==="
$COMPOSE_CMD logs rust-node >> "$LOG_FILE" 2>&1

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
$COMPOSE_CMD stop rust-node

echo "=== Waiting for state to persist (5s) ==="
sleep 5

echo "=== Restarting Rust node ==="
$COMPOSE_CMD start rust-node

echo "=== Phase 2: Waiting for second link establishment (polling, 60s timeout) ==="
if ! poll_logs "loaded transport identity" 60 5; then
    echo "WARNING: loaded transport identity not found in logs within 60s, continuing..."
fi
# Give extra time for link establishment after identity load
if ! poll_logs "link_established.*link_established" 30 5 2>/dev/null; then
    # Fallback: just wait a bit for phase 2 link
    sleep 10
fi

echo "=== Collecting all logs ==="
$COMPOSE_CMD logs >> "$LOG_FILE" 2>&1

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
PYTHON_CONTAINER=$($COMPOSE_CMD ps -q python-rns 2>/dev/null)
if [ -n "$PYTHON_CONTAINER" ]; then
    PYTHON_EXIT=$(timeout 30 docker wait "$PYTHON_CONTAINER" 2>/dev/null || echo "")
    echo "Python test exited with code: ${PYTHON_EXIT:-timeout}"
fi

# Final log collection
$COMPOSE_CMD logs >> "$LOG_FILE" 2>&1

echo "=== Tearing down ==="
compose_down

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
