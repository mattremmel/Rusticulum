//! Tracing subscriber configuration for Reticulum nodes.
//!
//! Log levels follow these conventions:
//! - ERROR: Unrecoverable failures, protocol violations
//! - WARN: Recoverable errors, unexpected but handled conditions
//! - INFO: High-level protocol events (link established, announce received)
//! - DEBUG: Detailed protocol state changes, packet parsing, crypto operations
//! - TRACE: Wire-level data, raw bytes, state machine transitions

use tracing_subscriber::EnvFilter;

/// Initialize the tracing subscriber with sensible defaults.
///
/// Log level can be controlled via the `RUST_LOG` environment variable.
/// Defaults to `info` if not set.
pub fn init() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::fmt().with_env_filter(filter).init();
}

/// Initialize the tracing subscriber with JSON output.
///
/// Useful for structured logging in containerized environments.
/// Activated by setting `RUST_LOG_FORMAT=json`.
pub fn init_json() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::fmt()
        .json()
        .with_env_filter(filter)
        .init();
}

/// Initialize the tracing subscriber for tests.
///
/// Uses `try_init` to avoid panicking if called multiple times.
pub fn init_for_tests() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("debug"));

    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_test_writer()
        .try_init();
}
