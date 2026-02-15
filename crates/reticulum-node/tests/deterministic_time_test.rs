//! Demonstrates deterministic time testing with `tokio::test(start_paused = true)`.
//!
//! When `start_paused` is enabled, tokio's internal clock starts at the current
//! wall-clock time but does NOT advance automatically. Instead, the runtime
//! auto-advances time whenever all tasks are blocked on a timer, or you can
//! explicitly call `tokio::time::advance()`.
//!
//! This pattern is useful for testing timer-driven logic without wall-clock
//! delays — ideal for the node's maintenance loop (announce retransmission
//! ticks, table cull ticks) and interface reconnection timers.

use std::time::Duration;

/// Verify that a `tokio::time::interval` fires the expected number of times
/// when we advance the clock manually. With a 5-second interval, advancing
/// 12 seconds should produce exactly 2 ticks (at t=5s and t=10s).
#[tokio::test(start_paused = true)]
async fn maintenance_tick_fires_deterministically() {
    let mut interval = tokio::time::interval(Duration::from_secs(5));

    // The first tick fires immediately (interval semantics).
    interval.tick().await;

    // Advance 12 seconds — should allow 2 more ticks (at t=5s and t=10s).
    tokio::time::advance(Duration::from_secs(12)).await;

    let mut tick_count = 0;
    loop {
        tokio::select! {
            _ = interval.tick() => {
                tick_count += 1;
            }
            // yield once so the runtime can process pending timers
            _ = tokio::task::yield_now() => {
                break;
            }
        }
    }

    assert_eq!(tick_count, 2, "expected 2 ticks within a 12s advance of a 5s interval");
}

/// Verify that `tokio::time::timeout` fires without any wall-clock wait.
/// With paused time, advancing 30 seconds is instantaneous, and a 10-second
/// timeout will trigger immediately.
#[tokio::test(start_paused = true)]
async fn timeout_fires_without_wall_clock_wait() {
    // Advance 30 seconds (instantaneous in paused mode).
    tokio::time::advance(Duration::from_secs(30)).await;

    // A future that never resolves, guarded by a 10-second timeout.
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        std::future::pending::<()>(),
    )
    .await;

    assert!(result.is_err(), "timeout should fire (Elapsed error)");
}

/// Verify that `tokio::time::sleep` completes without wall-clock delay
/// when the clock is paused and the runtime auto-advances.
#[tokio::test(start_paused = true)]
async fn sleep_completes_via_auto_advance() {
    // In paused mode, the runtime auto-advances when all tasks are blocked
    // on timers. This 60-second sleep completes instantly.
    tokio::time::sleep(Duration::from_secs(60)).await;

    // If we reached here, auto-advance worked — no 60-second wall-clock wait.
}
