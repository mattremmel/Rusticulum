//! Shared cancellation token for coordinating background task shutdown.
//!
//! Every interface implementation needs:
//! - An `AtomicBool` to track online/connected status
//! - A `watch` channel to signal background tasks to stop
//! - Storage for `JoinHandle`s so we can await graceful shutdown
//!
//! [`ShutdownToken`] bundles these together to reduce boilerplate.

use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::Mutex;
use tokio::sync::watch;
use tokio::task::JoinHandle;

/// A cancellation token that coordinates shutdown of background tasks.
///
/// Typical usage:
///
/// 1. Create with [`ShutdownToken::new()`].
/// 2. Call [`subscribe()`](Self::subscribe) to get a `watch::Receiver<bool>`
///    for each background task.
/// 3. Background tasks check the receiver in `tokio::select!` loops.
/// 4. After spawning, register handles with [`add_task()`](Self::add_task)
///    or [`set_task()`](Self::set_task).
/// 5. When stopping, call [`signal_stop()`](Self::signal_stop) then
///    [`join_all()`](Self::join_all).
pub struct ShutdownToken {
    /// Sender side of the watch channel; sending `true` signals shutdown.
    stop_tx: watch::Sender<bool>,
    /// Receiver side, cloned for each subscriber.
    stop_rx: watch::Receiver<bool>,
    /// Whether the interface is currently online/connected.
    online: AtomicBool,
    /// Background task handles to await on shutdown.
    task_handles: Mutex<Vec<JoinHandle<()>>>,
}

impl ShutdownToken {
    /// Create a new shutdown token in the "not online" state.
    pub fn new() -> Self {
        let (stop_tx, stop_rx) = watch::channel(false);

        Self {
            stop_tx,
            stop_rx,
            online: AtomicBool::new(false),
            task_handles: Mutex::new(Vec::new()),
        }
    }

    /// Get a new subscription to the stop signal.
    ///
    /// Each background task should hold its own cloned receiver and check
    /// it in a `tokio::select!` branch:
    ///
    /// ```ignore
    /// tokio::select! {
    ///     result = some_io_op => { /* handle */ }
    ///     _ = stop_rx.changed() => { break; }
    /// }
    /// ```
    pub fn subscribe(&self) -> watch::Receiver<bool> {
        self.stop_rx.clone()
    }

    /// Check whether the stop signal has been sent.
    pub fn is_stopped(&self) -> bool {
        *self.stop_rx.borrow()
    }

    // -- Online state --

    /// Mark the interface as online.
    pub fn set_online(&self) {
        self.online.store(true, Ordering::SeqCst);
    }

    /// Mark the interface as offline.
    pub fn set_offline(&self) {
        self.online.store(false, Ordering::SeqCst);
    }

    /// Whether the interface is currently online.
    pub fn is_online(&self) -> bool {
        self.online.load(Ordering::SeqCst)
    }

    // -- Task management --

    /// Register a single background task handle (replaces any existing handles).
    pub async fn set_task(&self, handle: JoinHandle<()>) {
        let mut handles = self.task_handles.lock().await;
        handles.clear();
        handles.push(handle);
    }

    /// Register an additional background task handle.
    pub async fn add_task(&self, handle: JoinHandle<()>) {
        self.task_handles.lock().await.push(handle);
    }

    /// Replace all task handles at once (useful for multi-task interfaces like Auto).
    pub async fn set_tasks(&self, new_handles: Vec<JoinHandle<()>>) {
        *self.task_handles.lock().await = new_handles;
    }

    // -- Shutdown sequence --

    /// Send the stop signal to all subscribers.
    ///
    /// This is idempotent: calling it multiple times is harmless.
    pub fn signal_stop(&self) {
        let _ = self.stop_tx.send(true);
    }

    /// Send the stop signal and mark the interface as offline.
    ///
    /// Convenience method combining [`signal_stop()`](Self::signal_stop)
    /// and [`set_offline()`](Self::set_offline).
    pub fn signal_stop_and_go_offline(&self) {
        self.signal_stop();
        self.set_offline();
    }

    /// Await all registered background tasks, draining the handle list.
    ///
    /// Any `JoinError`s (panics, cancellations) are silently ignored.
    pub async fn join_all(&self) {
        let handles: Vec<JoinHandle<()>> = self.task_handles.lock().await.drain(..).collect();
        for handle in handles {
            let _ = handle.await;
        }
    }
}

impl Default for ShutdownToken {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_token_starts_not_online_and_not_stopped() {
        let token = ShutdownToken::new();
        assert!(!token.is_online());
        assert!(!token.is_stopped());
    }

    #[test]
    fn online_state_transitions() {
        let token = ShutdownToken::new();

        token.set_online();
        assert!(token.is_online());

        token.set_offline();
        assert!(!token.is_online());
    }

    #[test]
    fn signal_stop_is_visible_to_subscribers() {
        let token = ShutdownToken::new();
        let rx = token.subscribe();

        assert!(!*rx.borrow());
        token.signal_stop();
        assert!(*rx.borrow());
    }

    #[test]
    fn signal_stop_and_go_offline_does_both() {
        let token = ShutdownToken::new();
        token.set_online();
        assert!(token.is_online());

        token.signal_stop_and_go_offline();
        assert!(!token.is_online());
        assert!(token.is_stopped());
    }

    #[test]
    fn signal_stop_is_idempotent() {
        let token = ShutdownToken::new();
        token.signal_stop();
        token.signal_stop(); // should not panic
        assert!(token.is_stopped());
    }

    #[tokio::test]
    async fn join_all_completes_when_task_finishes() {
        let token = ShutdownToken::new();
        let rx = token.subscribe();

        let handle = tokio::spawn(async move {
            let mut rx = rx;
            let _ = rx.changed().await;
        });
        token.add_task(handle).await;

        token.signal_stop();
        token.join_all().await;

        // Handles should be drained after join_all.
        let handles = token.task_handles.lock().await;
        assert!(handles.is_empty());
    }

    #[tokio::test]
    async fn set_task_replaces_previous() {
        let token = ShutdownToken::new();

        let h1 = tokio::spawn(async {});
        let h2 = tokio::spawn(async {});

        token.add_task(h1).await;
        assert_eq!(token.task_handles.lock().await.len(), 1);

        token.set_task(h2).await;
        assert_eq!(token.task_handles.lock().await.len(), 1);
    }

    #[tokio::test]
    async fn set_tasks_replaces_all() {
        let token = ShutdownToken::new();

        token.add_task(tokio::spawn(async {})).await;
        assert_eq!(token.task_handles.lock().await.len(), 1);

        let new_handles = vec![tokio::spawn(async {}), tokio::spawn(async {})];
        token.set_tasks(new_handles).await;
        assert_eq!(token.task_handles.lock().await.len(), 2);
    }

    #[tokio::test]
    async fn join_all_on_empty_handles() {
        let token = ShutdownToken::new();
        // join_all() with no tasks should complete immediately
        token.join_all().await;
        let handles = token.task_handles.lock().await;
        assert!(handles.is_empty());
    }

    #[test]
    fn subscribe_after_stop_sees_true() {
        let token = ShutdownToken::new();
        token.signal_stop();
        // Subscribe after stop — should immediately see true
        let rx = token.subscribe();
        assert!(*rx.borrow());
    }

    #[tokio::test]
    async fn add_task_accumulates() {
        let token = ShutdownToken::new();

        let h1 = tokio::spawn(async {});
        let h2 = tokio::spawn(async {});
        let h3 = tokio::spawn(async {});

        token.add_task(h1).await;
        assert_eq!(token.task_handles.lock().await.len(), 1);

        token.add_task(h2).await;
        assert_eq!(token.task_handles.lock().await.len(), 2);

        token.add_task(h3).await;
        assert_eq!(token.task_handles.lock().await.len(), 3);
    }

    #[tokio::test]
    async fn multiple_subscribers_all_see_stop() {
        let token = ShutdownToken::new();
        let rx1 = token.subscribe();
        let rx2 = token.subscribe();
        let rx3 = token.subscribe();

        token.signal_stop();

        assert!(*rx1.borrow());
        assert!(*rx2.borrow());
        assert!(*rx3.borrow());
    }
}
