#!/usr/bin/env python3
"""
Extract resource window adaptation test vectors from the Reticulum reference
implementation into a JSON file for consumption by alternative implementations.

All vectors are computed using formulas reproduced from the reference source.
No live Transport/Link/Resource objects are created.

Covers:
  - Resource window growth on successful window completion
  - Resource window shrink on timeout/retry
  - Rate-based window_max transitions (slow -> fast, slow -> very slow)
  - Multi-step growth sequences at different rates
  - Side-by-side comparison with channel (RTT-based) window adaptation

Usage:
    python3 test_vectors/extract_window_adaptation.py

Output:
    test_vectors/window_adaptation.json
"""

import json
import math
import os
import sys

repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, repo_root)

OUTPUT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "window_adaptation.json")

# --- Resource window constants (from RNS/Resource.py) ---

WINDOW               = 4
WINDOW_MIN            = 2
WINDOW_MAX_SLOW       = 10
WINDOW_MAX_VERY_SLOW  = 4
WINDOW_MAX_FAST       = 75
WINDOW_FLEXIBILITY    = 4

# Rate thresholds
RATE_FAST             = (50 * 1000) / 8   # 6250 bytes/sec
RATE_VERY_SLOW        = (2 * 1000) / 8    # 250 bytes/sec

# Rate round thresholds
FAST_RATE_THRESHOLD       = WINDOW_MAX_SLOW - WINDOW - 2  # = 4
VERY_SLOW_RATE_THRESHOLD  = 2

# --- Channel window constants (from RNS/Channel.py) ---

CH_WINDOW             = 2
CH_WINDOW_MIN         = 2
CH_WINDOW_MIN_LIMIT_SLOW   = 2
CH_WINDOW_MIN_LIMIT_MEDIUM = 5
CH_WINDOW_MIN_LIMIT_FAST   = 16
CH_WINDOW_MAX_SLOW    = 5
CH_WINDOW_MAX_MEDIUM  = 12
CH_WINDOW_MAX_FAST    = 48
CH_WINDOW_FLEXIBILITY = 4
CH_FAST_RATE_THRESHOLD = 10
CH_RTT_FAST           = 0.18
CH_RTT_MEDIUM         = 0.75
CH_RTT_SLOW           = 1.45


# ============================================================
# Resource window state machine
# ============================================================

class ResourceWindowState:
    """Simulates the resource window adaptation state machine."""

    def __init__(self):
        self.window = WINDOW
        self.window_max = WINDOW_MAX_SLOW
        self.window_min = WINDOW_MIN
        self.window_flexibility = WINDOW_FLEXIBILITY
        self.fast_rate_rounds = 0
        self.very_slow_rate_rounds = 0

    def snapshot(self):
        return {
            "window": self.window,
            "window_max": self.window_max,
            "window_min": self.window_min,
            "fast_rate_rounds": self.fast_rate_rounds,
            "very_slow_rate_rounds": self.very_slow_rate_rounds,
        }

    def on_window_complete(self, rate):
        """
        Called when all outstanding parts in the current window have been received.
        Mirrors RNS/Resource.py:886-913.
        """
        # Window growth
        if self.window < self.window_max:
            self.window += 1
            if (self.window - self.window_min) > (self.window_flexibility - 1):
                self.window_min += 1

        # Rate tracking
        if rate > RATE_FAST and self.fast_rate_rounds < FAST_RATE_THRESHOLD:
            self.fast_rate_rounds += 1
            if self.fast_rate_rounds == FAST_RATE_THRESHOLD:
                self.window_max = WINDOW_MAX_FAST

        if self.fast_rate_rounds == 0 and rate < RATE_VERY_SLOW and self.very_slow_rate_rounds < VERY_SLOW_RATE_THRESHOLD:
            self.very_slow_rate_rounds += 1
            if self.very_slow_rate_rounds == VERY_SLOW_RATE_THRESHOLD:
                self.window_max = WINDOW_MAX_VERY_SLOW

    def on_timeout(self):
        """
        Called when a part request times out.
        Mirrors RNS/Resource.py:612-617.
        """
        if self.window > self.window_min:
            self.window -= 1
            if self.window_max > self.window_min:
                self.window_max -= 1
                if (self.window_max - self.window) > (self.window_flexibility - 1):
                    self.window_max -= 1


# ============================================================
# Channel window state machine (for comparison)
# ============================================================

class ChannelWindowState:
    """Simulates the channel window adaptation state machine."""

    def __init__(self, rtt):
        self.rtt = rtt
        if rtt <= CH_RTT_FAST:
            self.window = CH_WINDOW_MAX_FAST
            self.window_max = CH_WINDOW_MAX_FAST
            self.window_min = CH_WINDOW_MIN_LIMIT_FAST
        elif rtt <= CH_RTT_MEDIUM:
            self.window = CH_WINDOW_MAX_MEDIUM
            self.window_max = CH_WINDOW_MAX_MEDIUM
            self.window_min = CH_WINDOW_MIN_LIMIT_MEDIUM
        elif rtt <= CH_RTT_SLOW:
            self.window = CH_WINDOW_MAX_SLOW
            self.window_max = CH_WINDOW_MAX_SLOW
            self.window_min = CH_WINDOW_MIN_LIMIT_SLOW
        else:
            self.window = CH_WINDOW
            self.window_max = CH_WINDOW_MAX_SLOW
            self.window_min = CH_WINDOW_MIN
        self.window_flexibility = CH_WINDOW_FLEXIBILITY
        self.fast_rate_rounds = 0

    def snapshot(self):
        return {
            "window": self.window,
            "window_max": self.window_max,
            "window_min": self.window_min,
            "fast_rate_rounds": self.fast_rate_rounds,
        }

    def on_delivery(self):
        """Channel window growth on successful delivery."""
        if self.window < self.window_max:
            self.window += 1
            if (self.window - self.window_min) > (self.window_flexibility - 1):
                self.window_min += 1
        if self.fast_rate_rounds < CH_FAST_RATE_THRESHOLD:
            self.fast_rate_rounds += 1

    def on_timeout(self):
        """Channel window shrink on timeout."""
        tail = max(self.window_flexibility, 4)
        if self.window > tail:
            self.window = max(self.window - tail, tail)
        self.window_min = CH_WINDOW_MIN
        self.fast_rate_rounds = 0


# ============================================================
# Vector extraction
# ============================================================

def extract_growth_vectors():
    """Generate window growth sequences at different rates."""
    vectors = []

    rate_scenarios = [
        {
            "description": "Fast rate (10 Kbps) — triggers WINDOW_MAX_FAST after threshold rounds",
            "rate": 10000,  # > RATE_FAST (6250)
            "steps": 25,
        },
        {
            "description": "Medium rate (2 Kbps) — stays at WINDOW_MAX_SLOW",
            "rate": 2000,   # between RATE_VERY_SLOW (250) and RATE_FAST (6250)
            "steps": 15,
        },
        {
            "description": "Very slow rate (100 bps) — triggers WINDOW_MAX_VERY_SLOW cap",
            "rate": 100,    # < RATE_VERY_SLOW (250)
            "steps": 10,
        },
        {
            "description": "Borderline fast rate (exactly 6250 bps = RATE_FAST threshold)",
            "rate": 6250,   # NOT > RATE_FAST (6250), so should NOT trigger fast
            "steps": 15,
        },
        {
            "description": "Just above fast rate (6251 bps)",
            "rate": 6251,   # > RATE_FAST, should trigger fast after threshold
            "steps": 20,
        },
    ]

    for scenario in rate_scenarios:
        state = ResourceWindowState()
        steps = []
        steps.append({
            "step": 0,
            "event": "initial",
            "rate": None,
            "state": state.snapshot(),
        })

        for i in range(1, scenario["steps"] + 1):
            state.on_window_complete(scenario["rate"])
            steps.append({
                "step": i,
                "event": "window_complete",
                "rate": scenario["rate"],
                "state": state.snapshot(),
            })

        vectors.append({
            "description": scenario["description"],
            "rate_bytes_per_sec": scenario["rate"],
            "rate_is_above_fast": scenario["rate"] > RATE_FAST,
            "rate_is_below_very_slow": scenario["rate"] < RATE_VERY_SLOW,
            "steps": steps,
        })

    return vectors


def extract_shrink_vectors():
    """Generate window shrink sequences on timeout."""
    vectors = []

    # Scenario 1: Shrink from initial state
    state1 = ResourceWindowState()
    steps1 = [{"step": 0, "event": "initial", "state": state1.snapshot()}]
    for i in range(1, 6):
        state1.on_timeout()
        steps1.append({"step": i, "event": "timeout", "state": state1.snapshot()})
    vectors.append({
        "description": "Timeout shrink from initial state (window=4, window_max=10)",
        "steps": steps1,
    })

    # Scenario 2: Grow first, then shrink
    state2 = ResourceWindowState()
    steps2 = [{"step": 0, "event": "initial", "state": state2.snapshot()}]
    step_num = 1
    # Grow for 8 rounds at fast rate
    for i in range(8):
        state2.on_window_complete(10000)
        steps2.append({"step": step_num, "event": "window_complete", "rate": 10000, "state": state2.snapshot()})
        step_num += 1
    # Then 6 timeouts
    for i in range(6):
        state2.on_timeout()
        steps2.append({"step": step_num, "event": "timeout", "state": state2.snapshot()})
        step_num += 1
    vectors.append({
        "description": "Grow at fast rate for 8 rounds, then 6 timeouts",
        "steps": steps2,
    })

    # Scenario 3: Alternating success and timeout (unstable link)
    state3 = ResourceWindowState()
    steps3 = [{"step": 0, "event": "initial", "state": state3.snapshot()}]
    step_num = 1
    for i in range(10):
        state3.on_window_complete(3000)  # medium rate
        steps3.append({"step": step_num, "event": "window_complete", "rate": 3000, "state": state3.snapshot()})
        step_num += 1
        state3.on_timeout()
        steps3.append({"step": step_num, "event": "timeout", "state": state3.snapshot()})
        step_num += 1
    vectors.append({
        "description": "Alternating success and timeout (unstable medium-rate link)",
        "steps": steps3,
    })

    # Scenario 4: Timeout with double-decrement (window_max - window > flexibility - 1)
    state4 = ResourceWindowState()
    # Manually set up a state where double-decrement will trigger
    state4.window = 4
    state4.window_max = 10
    state4.window_min = 2
    steps4 = [{"step": 0, "event": "initial (gap=6, flexibility=4)", "state": state4.snapshot()}]
    step_num = 1
    for i in range(5):
        state4.on_timeout()
        gap = state4.window_max - state4.window
        steps4.append({
            "step": step_num,
            "event": "timeout",
            "gap_after": gap,
            "double_decrement_possible": gap > (WINDOW_FLEXIBILITY - 1),
            "state": state4.snapshot(),
        })
        step_num += 1
    vectors.append({
        "description": "Timeout with double-decrement analysis (window_max decrements extra when gap exceeds flexibility-1)",
        "note": "When (window_max - window) > (flexibility - 1), window_max gets an additional decrement",
        "steps": steps4,
    })

    return vectors


def extract_rate_transition_vectors():
    """Generate vectors showing rate-based window_max transitions."""
    vectors = []

    # Scenario 1: Transition from slow to fast
    state1 = ResourceWindowState()
    steps1 = [{"step": 0, "event": "initial", "state": state1.snapshot()}]
    step_num = 1

    # Medium rate for a few rounds (no transition)
    for i in range(3):
        state1.on_window_complete(3000)
        steps1.append({"step": step_num, "event": "window_complete", "rate": 3000, "state": state1.snapshot()})
        step_num += 1

    # Fast rate — should trigger after FAST_RATE_THRESHOLD rounds
    for i in range(FAST_RATE_THRESHOLD + 2):
        state1.on_window_complete(10000)
        steps1.append({
            "step": step_num,
            "event": "window_complete",
            "rate": 10000,
            "state": state1.snapshot(),
            "note": f"fast_rate_rounds={state1.fast_rate_rounds}" + (" — WINDOW_MAX_FAST activated!" if state1.window_max == WINDOW_MAX_FAST and steps1[-2]["state"]["window_max"] != WINDOW_MAX_FAST else ""),
        })
        step_num += 1

    vectors.append({
        "description": f"Slow-to-fast transition: fast_rate_rounds reaches FAST_RATE_THRESHOLD ({FAST_RATE_THRESHOLD}) and window_max jumps to {WINDOW_MAX_FAST}",
        "fast_rate_threshold": FAST_RATE_THRESHOLD,
        "steps": steps1,
    })

    # Scenario 2: Very slow rate cap
    state2 = ResourceWindowState()
    steps2 = [{"step": 0, "event": "initial", "state": state2.snapshot()}]
    step_num = 1
    for i in range(VERY_SLOW_RATE_THRESHOLD + 2):
        state2.on_window_complete(100)  # very slow
        steps2.append({
            "step": step_num,
            "event": "window_complete",
            "rate": 100,
            "state": state2.snapshot(),
            "note": f"very_slow_rate_rounds={state2.very_slow_rate_rounds}" + (" — WINDOW_MAX_VERY_SLOW activated!" if state2.window_max == WINDOW_MAX_VERY_SLOW and steps2[-2]["state"]["window_max"] != WINDOW_MAX_VERY_SLOW else ""),
        })
        step_num += 1
    vectors.append({
        "description": f"Very slow rate cap: very_slow_rate_rounds reaches VERY_SLOW_RATE_THRESHOLD ({VERY_SLOW_RATE_THRESHOLD}) and window_max drops to {WINDOW_MAX_VERY_SLOW}",
        "very_slow_rate_threshold": VERY_SLOW_RATE_THRESHOLD,
        "steps": steps2,
    })

    # Scenario 3: Very slow only triggers if fast_rate_rounds is 0
    state3 = ResourceWindowState()
    steps3 = [{"step": 0, "event": "initial", "state": state3.snapshot()}]
    step_num = 1
    # One round of fast rate bumps fast_rate_rounds to 1
    state3.on_window_complete(10000)
    steps3.append({"step": step_num, "event": "window_complete", "rate": 10000, "state": state3.snapshot()})
    step_num += 1
    # Now very slow rate — should NOT trigger because fast_rate_rounds > 0
    for i in range(4):
        state3.on_window_complete(100)
        steps3.append({
            "step": step_num,
            "event": "window_complete",
            "rate": 100,
            "state": state3.snapshot(),
            "note": f"fast_rate_rounds={state3.fast_rate_rounds}, very_slow blocked because fast_rate_rounds != 0",
        })
        step_num += 1
    vectors.append({
        "description": "Very slow cap blocked when fast_rate_rounds > 0 (one fast round prevents very-slow detection)",
        "steps": steps3,
    })

    return vectors


def extract_comparison_vectors():
    """Generate side-by-side resource vs channel window adaptation comparison."""
    vectors = []

    # Scenario: 20 successful rounds
    rtt = 0.5  # medium RTT for channel

    res_state = ResourceWindowState()
    ch_state = ChannelWindowState(rtt)

    steps = []
    steps.append({
        "step": 0,
        "event": "initial",
        "resource": res_state.snapshot(),
        "channel": ch_state.snapshot(),
    })

    for i in range(1, 21):
        res_state.on_window_complete(5000)  # medium rate
        ch_state.on_delivery()
        steps.append({
            "step": i,
            "event": "success",
            "resource": res_state.snapshot(),
            "channel": ch_state.snapshot(),
        })

    vectors.append({
        "description": "20 consecutive successes: resource (rate-based, 5000 B/s) vs channel (RTT-based, 0.5s)",
        "resource_rate": 5000,
        "channel_rtt": rtt,
        "steps": steps,
    })

    # Scenario: 5 successes then 3 timeouts
    res_state2 = ResourceWindowState()
    ch_state2 = ChannelWindowState(rtt)

    steps2 = []
    steps2.append({
        "step": 0,
        "event": "initial",
        "resource": res_state2.snapshot(),
        "channel": ch_state2.snapshot(),
    })

    step_num = 1
    for i in range(5):
        res_state2.on_window_complete(5000)
        ch_state2.on_delivery()
        steps2.append({
            "step": step_num,
            "event": "success",
            "resource": res_state2.snapshot(),
            "channel": ch_state2.snapshot(),
        })
        step_num += 1

    for i in range(3):
        res_state2.on_timeout()
        ch_state2.on_timeout()
        steps2.append({
            "step": step_num,
            "event": "timeout",
            "resource": res_state2.snapshot(),
            "channel": ch_state2.snapshot(),
        })
        step_num += 1

    vectors.append({
        "description": "5 successes then 3 timeouts: resource vs channel window behavior",
        "resource_rate": 5000,
        "channel_rtt": rtt,
        "steps": steps2,
    })

    return vectors


def build_output(growth_vectors, shrink_vectors, rate_vectors, comparison_vectors):
    return {
        "description": "Reticulum v1.1.3 reference implementation - Window adaptation test vectors",
        "sources": [
            "RNS/Resource.py (resource window adaptation)",
            "RNS/Channel.py (channel window adaptation, for comparison)",
        ],
        "resource_window": {
            "description": "Resource window adaptation is rate-based (bytes/sec throughput), not RTT-based",
            "constants": {
                "WINDOW": WINDOW,
                "WINDOW_MIN": WINDOW_MIN,
                "WINDOW_MAX_SLOW": WINDOW_MAX_SLOW,
                "WINDOW_MAX_VERY_SLOW": WINDOW_MAX_VERY_SLOW,
                "WINDOW_MAX_FAST": WINDOW_MAX_FAST,
                "WINDOW_FLEXIBILITY": WINDOW_FLEXIBILITY,
                "RATE_FAST": RATE_FAST,
                "RATE_VERY_SLOW": RATE_VERY_SLOW,
                "FAST_RATE_THRESHOLD": FAST_RATE_THRESHOLD,
                "VERY_SLOW_RATE_THRESHOLD": VERY_SLOW_RATE_THRESHOLD,
            },
            "initial_state": {
                "window": WINDOW,
                "window_max": WINDOW_MAX_SLOW,
                "window_min": WINDOW_MIN,
                "window_flexibility": WINDOW_FLEXIBILITY,
                "fast_rate_rounds": 0,
                "very_slow_rate_rounds": 0,
            },
            "growth_algorithm": [
                "On successful window completion (all outstanding_parts received):",
                "1. if window < window_max: window += 1",
                "2. if (window - window_min) > (flexibility - 1): window_min += 1",
                "3. Rate tracking from req_data_rtt_rate (bytes transferred / RTT):",
                "   a. if rate > RATE_FAST and fast_rate_rounds < FAST_RATE_THRESHOLD: fast_rate_rounds += 1",
                "   b. if fast_rate_rounds == FAST_RATE_THRESHOLD: window_max = WINDOW_MAX_FAST",
                "   c. if fast_rate_rounds == 0 and rate < RATE_VERY_SLOW and very_slow_rate_rounds < VERY_SLOW_RATE_THRESHOLD: very_slow_rate_rounds += 1",
                "   d. if very_slow_rate_rounds == VERY_SLOW_RATE_THRESHOLD: window_max = WINDOW_MAX_VERY_SLOW",
            ],
            "shrink_algorithm": [
                "On part request timeout:",
                "1. if window > window_min: window -= 1",
                "2. if window_max > window_min: window_max -= 1",
                "3. if (window_max - window) > (flexibility - 1): window_max -= 1  (double decrement)",
            ],
            "growth_vectors": growth_vectors,
            "shrink_vectors": shrink_vectors,
            "rate_transition_vectors": rate_vectors,
        },
        "channel_window": {
            "description": "Channel window adaptation is RTT-based (for comparison with resource window)",
            "constants": {
                "WINDOW": CH_WINDOW,
                "WINDOW_MIN": CH_WINDOW_MIN,
                "WINDOW_MIN_LIMIT_SLOW": CH_WINDOW_MIN_LIMIT_SLOW,
                "WINDOW_MIN_LIMIT_MEDIUM": CH_WINDOW_MIN_LIMIT_MEDIUM,
                "WINDOW_MIN_LIMIT_FAST": CH_WINDOW_MIN_LIMIT_FAST,
                "WINDOW_MAX_SLOW": CH_WINDOW_MAX_SLOW,
                "WINDOW_MAX_MEDIUM": CH_WINDOW_MAX_MEDIUM,
                "WINDOW_MAX_FAST": CH_WINDOW_MAX_FAST,
                "WINDOW_FLEXIBILITY": CH_WINDOW_FLEXIBILITY,
                "FAST_RATE_THRESHOLD": CH_FAST_RATE_THRESHOLD,
                "RTT_FAST": CH_RTT_FAST,
                "RTT_MEDIUM": CH_RTT_MEDIUM,
                "RTT_SLOW": CH_RTT_SLOW,
            },
            "initialization_note": "Channel window is initialized based on RTT at link establishment, not grown from a minimum",
            "key_differences": [
                "Resource: starts at WINDOW=4, grows by 1 per successful window",
                "Channel: starts at window_max for RTT class (e.g., 48 for fast links)",
                "Resource: rate-based transitions (bytes/sec thresholds)",
                "Channel: RTT-based initialization (RTT class determines starting window)",
                "Resource: timeout shrinks by 1 (with possible double-decrement)",
                "Channel: timeout shrinks by max(flexibility, 4) and resets window_min to WINDOW_MIN",
            ],
        },
        "comparison_vectors": comparison_vectors,
    }


def verify(output):
    """Verify all window adaptation vectors."""
    # Verify growth vectors
    for scenario in output["resource_window"]["growth_vectors"]:
        state = ResourceWindowState()
        rate = scenario["rate_bytes_per_sec"]
        for step in scenario["steps"]:
            if step["event"] == "initial":
                assert state.snapshot() == step["state"], f"Initial state mismatch in {scenario['description']}"
            elif step["event"] == "window_complete":
                state.on_window_complete(rate)
                assert state.snapshot() == step["state"], f"Step {step['step']} mismatch in {scenario['description']}"
    print(f"  [OK] All {len(output['resource_window']['growth_vectors'])} growth scenarios verified")

    # Verify shrink vectors
    for scenario in output["resource_window"]["shrink_vectors"]:
        state = ResourceWindowState()
        # Handle custom initial state for scenario 4
        if "gap" in (scenario["steps"][0].get("event") or ""):
            state.window = scenario["steps"][0]["state"]["window"]
            state.window_max = scenario["steps"][0]["state"]["window_max"]
            state.window_min = scenario["steps"][0]["state"]["window_min"]

        for step in scenario["steps"]:
            if step["event"].startswith("initial"):
                continue
            elif step["event"] == "window_complete":
                state.on_window_complete(step.get("rate", 3000))
            elif step["event"] == "timeout":
                state.on_timeout()
            assert state.snapshot() == step["state"], f"Step {step['step']} mismatch in {scenario['description']}: got {state.snapshot()}, expected {step['state']}"
    print(f"  [OK] All {len(output['resource_window']['shrink_vectors'])} shrink scenarios verified")

    # Verify rate transition vectors
    for scenario in output["resource_window"]["rate_transition_vectors"]:
        state = ResourceWindowState()
        for step in scenario["steps"]:
            if step["event"] == "initial":
                continue
            elif step["event"] == "window_complete":
                state.on_window_complete(step["rate"])
            assert state.snapshot() == step["state"], f"Step {step['step']} mismatch in {scenario['description']}: got {state.snapshot()}, expected {step['state']}"
    print(f"  [OK] All {len(output['resource_window']['rate_transition_vectors'])} rate transition scenarios verified")

    # Verify comparison vectors
    for scenario in output["comparison_vectors"]:
        res_state = ResourceWindowState()
        ch_state = ChannelWindowState(scenario["channel_rtt"])
        rate = scenario["resource_rate"]
        for step in scenario["steps"]:
            if step["event"] == "initial":
                assert res_state.snapshot() == step["resource"]
                assert ch_state.snapshot() == step["channel"]
            elif step["event"] == "success":
                res_state.on_window_complete(rate)
                ch_state.on_delivery()
                assert res_state.snapshot() == step["resource"], f"Resource step {step['step']} mismatch"
                assert ch_state.snapshot() == step["channel"], f"Channel step {step['step']} mismatch"
            elif step["event"] == "timeout":
                res_state.on_timeout()
                ch_state.on_timeout()
                assert res_state.snapshot() == step["resource"], f"Resource timeout step {step['step']} mismatch"
                assert ch_state.snapshot() == step["channel"], f"Channel timeout step {step['step']} mismatch"
    print(f"  [OK] All {len(output['comparison_vectors'])} comparison scenarios verified")

    # JSON round-trip
    json_str = json.dumps(output, indent=2)
    assert json.loads(json_str) == output, "JSON round-trip failed"
    print("  [OK] JSON round-trip integrity verified")


def main():
    print("Extracting window adaptation vectors...")

    print("  Extracting growth vectors...")
    growth_vectors = extract_growth_vectors()
    print(f"    {len(growth_vectors)} growth scenarios")

    print("  Extracting shrink vectors...")
    shrink_vectors = extract_shrink_vectors()
    print(f"    {len(shrink_vectors)} shrink scenarios")

    print("  Extracting rate transition vectors...")
    rate_vectors = extract_rate_transition_vectors()
    print(f"    {len(rate_vectors)} rate transition scenarios")

    print("  Extracting comparison vectors...")
    comparison_vectors = extract_comparison_vectors()
    print(f"    {len(comparison_vectors)} comparison scenarios")

    print("Building output...")
    output = build_output(growth_vectors, shrink_vectors, rate_vectors, comparison_vectors)

    print("Verifying...")
    verify(output)

    print(f"Writing {OUTPUT_PATH}...")
    with open(OUTPUT_PATH, "w") as f:
        json.dump(output, f, indent=2)
        f.write("\n")

    print("Done.")


if __name__ == "__main__":
    main()
