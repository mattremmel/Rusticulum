#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCKER_DIR="$(dirname "$SCRIPT_DIR")"
REPORT_FILE="${DOCKER_DIR}/compat-report.log"

# All test scripts in execution order
TESTS=(
    "test-announce.sh:Announce Exchange"
    "test-link.sh:Link Establishment"
    "test-resource.sh:Resource Transfer"
    "test-channel.sh:Channel/Buffer/Request"
    "test-multihop.sh:Multi-Hop Routing"
    "test-rust-relay.sh:Rust Relay"
    "test-compat-edge.sh:Edge Cases"
    "test-compat-stress.sh:Stress Test"
)

# Track results
declare -a TEST_NAMES
declare -a TEST_RESULTS
declare -a TEST_DURATIONS

TOTAL=0
PASSED=0
FAILED=0

echo "=============================================="
echo "  Rusticulum Compatibility Test Suite"
echo "  $(date '+%Y-%m-%d %H:%M:%S')"
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

for entry in "${TESTS[@]}"; do
    IFS=':' read -r script name <<< "$entry"
    TOTAL=$((TOTAL + 1))
    TEST_NAMES+=("$name")

    echo "----------------------------------------------"
    echo "[$TOTAL/${#TESTS[@]}] Running: $name"
    echo "----------------------------------------------"

    {
        echo "----------------------------------------------"
        echo "[$TOTAL/${#TESTS[@]}] Running: $name"
        echo "----------------------------------------------"
    } >> "$REPORT_FILE"

    START_TIME=$(date +%s)

    if "$SCRIPT_DIR/$script" >> "$REPORT_FILE" 2>&1; then
        END_TIME=$(date +%s)
        DURATION=$((END_TIME - START_TIME))
        TEST_RESULTS+=("PASS")
        TEST_DURATIONS+=("${DURATION}s")
        PASSED=$((PASSED + 1))
        echo "  Result: PASS (${DURATION}s)"
    else
        END_TIME=$(date +%s)
        DURATION=$((END_TIME - START_TIME))
        TEST_RESULTS+=("FAIL")
        TEST_DURATIONS+=("${DURATION}s")
        FAILED=$((FAILED + 1))
        echo "  Result: FAIL (${DURATION}s)"
    fi

    echo "" >> "$REPORT_FILE"
done

echo ""
echo "=============================================="
echo "  Summary"
echo "=============================================="
echo ""
printf "%-30s %-8s %s\n" "Test" "Result" "Duration"
printf "%-30s %-8s %s\n" "----" "------" "--------"

for i in "${!TEST_NAMES[@]}"; do
    printf "%-30s %-8s %s\n" "${TEST_NAMES[$i]}" "${TEST_RESULTS[$i]}" "${TEST_DURATIONS[$i]}"
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
    for i in "${!TEST_NAMES[@]}"; do
        printf "%-30s %-8s %s\n" "${TEST_NAMES[$i]}" "${TEST_RESULTS[$i]}" "${TEST_DURATIONS[$i]}"
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
