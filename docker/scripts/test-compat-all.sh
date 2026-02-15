#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCKER_DIR="$(dirname "$SCRIPT_DIR")"
REPORT_FILE="${DOCKER_DIR}/compat-report.log"

# Parse flags
SEQUENTIAL=false
for arg in "$@"; do
    case "$arg" in
        --sequential) SEQUENTIAL=true ;;
    esac
done

# All test scripts grouped into parallel batches
BATCH1=(
    "test-announce.sh:Announce Exchange"
    "test-link.sh:Link Establishment"
    "test-resource.sh:Resource Transfer"
    "test-channel.sh:Channel/Buffer/Request"
)

BATCH2=(
    "test-ifac.sh:IFAC Auth"
    "test-ifac-reject.sh:IFAC Rejection"
    "test-compat-edge.sh:Edge Cases"
    "test-keepalive.sh:Keepalive"
)

BATCH3=(
    "test-multihop.sh:Multi-Hop Routing"
    "test-rust-relay.sh:Rust Relay"
    "test-multihop-data.sh:Multi-Hop Data"
    "test-multihop-channel.sh:Multi-Hop Channel"
)

BATCH4=(
    "test-compat-stress.sh:Stress Test"
    "test-large-resource.sh:Large Resource"
    "test-storage-persistence.sh:Storage Persistence"
    "test-fuzz.sh:Fuzz Cross-Impl"
    "test-vector-check.sh:Vector Check"
)

ALL_BATCHES=("BATCH1" "BATCH2" "BATCH3" "BATCH4")

# Flatten all tests for sequential mode and counting
ALL_TESTS=("${BATCH1[@]}" "${BATCH2[@]}" "${BATCH3[@]}" "${BATCH4[@]}")

# Track results
declare -A TEST_RESULTS
declare -A TEST_DURATIONS
declare -a TEST_ORDER

TOTAL=0
PASSED=0
FAILED=0

echo "=============================================="
echo "  Rusticulum Compatibility Test Suite"
echo "  $(date '+%Y-%m-%d %H:%M:%S')"
if [ "$SEQUENTIAL" = true ]; then
    echo "  Mode: Sequential"
else
    echo "  Mode: Parallel (4 batches)"
fi
echo "=============================================="
echo ""

# Start fresh report log
{
    echo "=============================================="
    echo "  Rusticulum Compatibility Test Suite"
    echo "  $(date '+%Y-%m-%d %H:%M:%S')"
    echo "=============================================="
    echo ""
} > "$REPORT_FILE"

# Pre-build Docker images (skip in sequential mode for backward compat)
if [ "$SEQUENTIAL" = false ]; then
    echo "=== Pre-building Docker images ==="
    cd "$DOCKER_DIR"
    docker compose -f docker-compose.yml build 2>&1 | tee -a "$REPORT_FILE"
    docker compose -f docker-compose.multihop-test.yml build 2>&1 | tee -a "$REPORT_FILE"
    docker compose -f docker-compose.rust-relay-test.yml build 2>&1 | tee -a "$REPORT_FILE"
    docker compose -f docker-compose.multihop-channel-test.yml build 2>&1 | tee -a "$REPORT_FILE"
    docker compose -f docker-compose.ifac-test.yml build 2>&1 | tee -a "$REPORT_FILE"
    docker compose -f docker-compose.ifac-reject-test.yml build 2>&1 | tee -a "$REPORT_FILE"
    docker compose -f docker-compose.large-resource-test.yml build 2>&1 | tee -a "$REPORT_FILE"
    docker compose -f docker-compose.storage-test.yml build 2>&1 | tee -a "$REPORT_FILE"
    # keepalive-test.yml is an overlay on docker-compose.yml (already built above)
    export RUSTICULUM_SKIP_BUILD=1
    echo "=== Pre-build complete ==="
    echo ""
fi

# run_test SCRIPT NAME
# Runs a single test, records result. For use in both sequential and parallel modes.
run_test() {
    local script="$1"
    local name="$2"
    local result_dir="$3"

    local start_time end_time duration exit_code
    start_time=$(date +%s)

    if "$SCRIPT_DIR/$script" > "$result_dir/${script}.log" 2>&1; then
        exit_code=0
    else
        exit_code=1
    fi

    end_time=$(date +%s)
    duration=$((end_time - start_time))

    echo "$exit_code" > "$result_dir/${script}.exit"
    echo "$duration" > "$result_dir/${script}.duration"
}

# run_batch BATCH_ENTRIES...
# Runs all tests in a batch in parallel, waits for all to complete.
run_batch() {
    local batch_name="$1"
    shift
    local entries=("$@")

    local result_dir
    result_dir=$(mktemp -d)
    local pids=()
    local scripts=()

    echo "----------------------------------------------"
    echo "  Batch: $batch_name (${#entries[@]} tests in parallel)"
    echo "----------------------------------------------"

    for entry in "${entries[@]}"; do
        IFS=':' read -r script name <<< "$entry"
        run_test "$script" "$name" "$result_dir" &
        pids+=($!)
        scripts+=("$entry")
    done

    # Wait for all background jobs
    for pid in "${pids[@]}"; do
        wait "$pid" 2>/dev/null || true
    done

    # Collect results
    for entry in "${scripts[@]}"; do
        IFS=':' read -r script name <<< "$entry"
        TOTAL=$((TOTAL + 1))
        TEST_ORDER+=("$name")

        local exit_code duration
        exit_code=$(cat "$result_dir/${script}.exit" 2>/dev/null || echo "1")
        duration=$(cat "$result_dir/${script}.duration" 2>/dev/null || echo "0")

        # Append test log to report
        {
            echo "----------------------------------------------"
            echo "  $name"
            echo "----------------------------------------------"
            cat "$result_dir/${script}.log" 2>/dev/null || true
            echo ""
        } >> "$REPORT_FILE"

        if [ "$exit_code" = "0" ]; then
            TEST_RESULTS["$name"]="PASS"
            TEST_DURATIONS["$name"]="${duration}s"
            PASSED=$((PASSED + 1))
            echo "  $name: PASS (${duration}s)"
        else
            TEST_RESULTS["$name"]="FAIL"
            TEST_DURATIONS["$name"]="${duration}s"
            FAILED=$((FAILED + 1))
            echo "  $name: FAIL (${duration}s)"
        fi
    done

    rm -rf "$result_dir"
    echo ""
}

if [ "$SEQUENTIAL" = true ]; then
    # Sequential mode: run tests one at a time (original behavior)
    for entry in "${ALL_TESTS[@]}"; do
        IFS=':' read -r script name <<< "$entry"
        TOTAL=$((TOTAL + 1))
        TEST_ORDER+=("$name")

        echo "----------------------------------------------"
        echo "[$TOTAL/${#ALL_TESTS[@]}] Running: $name"
        echo "----------------------------------------------"

        {
            echo "----------------------------------------------"
            echo "[$TOTAL/${#ALL_TESTS[@]}] Running: $name"
            echo "----------------------------------------------"
        } >> "$REPORT_FILE"

        START_TIME=$(date +%s)

        if "$SCRIPT_DIR/$script" >> "$REPORT_FILE" 2>&1; then
            END_TIME=$(date +%s)
            DURATION=$((END_TIME - START_TIME))
            TEST_RESULTS["$name"]="PASS"
            TEST_DURATIONS["$name"]="${DURATION}s"
            PASSED=$((PASSED + 1))
            echo "  Result: PASS (${DURATION}s)"
        else
            END_TIME=$(date +%s)
            DURATION=$((END_TIME - START_TIME))
            TEST_RESULTS["$name"]="FAIL"
            TEST_DURATIONS["$name"]="${DURATION}s"
            FAILED=$((FAILED + 1))
            echo "  Result: FAIL (${DURATION}s)"
        fi

        echo "" >> "$REPORT_FILE"
    done
else
    # Parallel mode: run tests in batches
    BATCH_NUM=0
    for batch_var in "${ALL_BATCHES[@]}"; do
        BATCH_NUM=$((BATCH_NUM + 1))
        # Get the batch array by name
        declare -n batch_ref="$batch_var"
        run_batch "Batch $BATCH_NUM" "${batch_ref[@]}"
    done
fi

echo ""
echo "=============================================="
echo "  Summary"
echo "=============================================="
echo ""
printf "%-30s %-8s %s\n" "Test" "Result" "Duration"
printf "%-30s %-8s %s\n" "----" "------" "--------"

for name in "${TEST_ORDER[@]}"; do
    printf "%-30s %-8s %s\n" "$name" "${TEST_RESULTS[$name]}" "${TEST_DURATIONS[$name]}"
done

echo ""
echo "Total: $TOTAL  Passed: $PASSED  Failed: $FAILED"
echo ""
echo "Full report saved to: $REPORT_FILE"

# Also write summary to report
{
    echo ""
    echo "=============================================="
    echo "  Summary"
    echo "=============================================="
    echo ""
    printf "%-30s %-8s %s\n" "Test" "Result" "Duration"
    printf "%-30s %-8s %s\n" "----" "------" "--------"
    for name in "${TEST_ORDER[@]}"; do
        printf "%-30s %-8s %s\n" "$name" "${TEST_RESULTS[$name]}" "${TEST_DURATIONS[$name]}"
    done
    echo ""
    echo "Total: $TOTAL  Passed: $PASSED  Failed: $FAILED"
} >> "$REPORT_FILE"

if [ "$FAILED" -eq 0 ]; then
    echo "=== ALL TESTS PASSED ==="
    exit 0
else
    echo "=== $FAILED TEST(S) FAILED ==="
    exit 1
fi
