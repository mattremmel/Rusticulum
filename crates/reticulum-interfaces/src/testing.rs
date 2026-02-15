//! Generic conformance assertions for [`Interface`] implementations.
//!
//! These helpers validate invariants that every interface should satisfy,
//! regardless of its transport (TCP, UDP, Unix socket, etc.).
//!
//! # Usage
//!
//! ```rust,ignore
//! use reticulum_interfaces::testing;
//!
//! let iface = MyInterface::new(config, id);
//! testing::assert_has_name(&iface);
//! testing::assert_not_connected_before_start(&iface);
//! testing::assert_transmit_before_start_fails(&iface).await;
//! ```

use crate::error::InterfaceError;
use crate::traits::Interface;

/// Assert that the interface has a non-empty name.
pub fn assert_has_name(iface: &impl Interface) {
    assert!(
        !iface.name().is_empty(),
        "interface name must not be empty"
    );
}

/// Assert that the interface reports `is_connected() == false` before `start()`.
pub fn assert_not_connected_before_start(iface: &impl Interface) {
    assert!(
        !iface.is_connected(),
        "interface should not be connected before start()"
    );
}

/// Assert that transmitting before `start()` returns an error.
pub async fn assert_transmit_before_start_fails(iface: &impl Interface) {
    let result = iface.transmit(&[0x42; 20]).await;
    assert!(
        result.is_err(),
        "transmit should fail before start()"
    );
}

/// Assert that `stop()` succeeds and `is_connected()` becomes false afterward.
pub async fn assert_stop_is_clean(iface: &impl Interface) {
    let result = iface.stop().await;
    assert!(result.is_ok(), "stop() should succeed: {:?}", result.err());
    assert!(
        !iface.is_connected(),
        "is_connected() should be false after stop()"
    );
}

/// Assert that calling `stop()` a second time does not error or panic.
pub async fn assert_double_stop_is_idempotent(iface: &impl Interface) {
    // First stop may or may not have been called already — call it.
    let _ = iface.stop().await;
    // Second stop must not fail.
    let result = iface.stop().await;
    assert!(
        result.is_ok(),
        "second stop() should be idempotent: {:?}",
        result.err()
    );
}

/// Run all pre-start conformance checks on an interface.
///
/// This is a convenience that calls:
/// - [`assert_has_name`]
/// - [`assert_not_connected_before_start`]
/// - [`assert_transmit_before_start_fails`]
pub async fn assert_pre_start_conformance(iface: &impl Interface) {
    assert_has_name(iface);
    assert_not_connected_before_start(iface);
    assert_transmit_before_start_fails(iface).await;
}

/// Run all stop-related conformance checks on an interface.
///
/// This is a convenience that calls:
/// - [`assert_stop_is_clean`]
/// - [`assert_double_stop_is_idempotent`]
pub async fn assert_stop_conformance(iface: &impl Interface) {
    assert_stop_is_clean(iface).await;
    assert_double_stop_is_idempotent(iface).await;
}

/// Check that the interface declares consistent capabilities.
pub fn assert_capabilities_consistent(iface: &impl Interface) {
    // MTU must be positive.
    assert!(iface.mtu() > 0, "MTU must be positive");
    // Bitrate must be positive.
    assert!(iface.bitrate() > 0, "bitrate must be positive");
}

/// Check that the reported [`InterfaceError`] from transmit is an expected
/// pre-start error variant (NotConnected or Configuration).
pub async fn assert_transmit_error_is_expected(iface: &impl Interface) {
    let result = iface.transmit(&[0x42; 20]).await;
    match result {
        Err(InterfaceError::NotConnected) | Err(InterfaceError::Configuration(_)) => {}
        Err(e) => panic!("unexpected error variant from transmit before start: {e}"),
        Ok(()) => panic!("transmit should fail before start()"),
    }
}
