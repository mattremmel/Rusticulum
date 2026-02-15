#!/usr/bin/env bash
# Shared helper functions for Docker integration tests.
# Source this file at the top of each test script.
#
# Each test script must set COMPOSE_CMD before calling these functions:
#   COMPOSE_CMD="docker compose -p $PROJECT $COMPOSE_FILES"

# poll_logs MARKER TIMEOUT_SECS [POLL_INTERVAL]
# Polls `docker compose logs` for MARKER string.
# Returns 0 on match, 1 on timeout.
poll_logs() {
    local marker="$1"
    local timeout_secs="$2"
    local poll_interval="${3:-5}"
    local elapsed=0

    while [ "$elapsed" -lt "$timeout_secs" ]; do
        if $COMPOSE_CMD logs --no-color --no-log-prefix 2>/dev/null | grep -q "$marker"; then
            return 0
        fi
        sleep "$poll_interval"
        elapsed=$((elapsed + poll_interval))
    done
    return 1
}

# compose_up [EXTRA_ARGS...]
# Starts containers. Skips --build when RUSTICULUM_SKIP_BUILD=1.
compose_up() {
    if [ "${RUSTICULUM_SKIP_BUILD:-0}" = "1" ]; then
        $COMPOSE_CMD up -d "$@"
    else
        $COMPOSE_CMD up -d --build "$@"
    fi
}

# compose_down [EXTRA_ARGS...]
# Tears down containers and volumes.
compose_down() {
    $COMPOSE_CMD down -v "$@"
}
