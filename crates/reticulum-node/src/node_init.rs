//! Pure initialization decision functions for node startup.
//!
//! These functions extract the decision logic from `Node::new()` and
//! `Node::run()` into stateless, testable functions.

/// How storage should be initialized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageInitPlan {
    /// Use a custom storage path.
    UseCustomPath(String),
    /// Use the default storage path.
    UseDefault,
    /// Storage is disabled.
    Disabled,
}

/// Decide how to initialize storage based on config.
pub fn plan_storage_init(enabled: bool, custom_path: Option<&str>) -> StorageInitPlan {
    if !enabled {
        return StorageInitPlan::Disabled;
    }
    match custom_path {
        Some(path) => StorageInitPlan::UseCustomPath(path.to_string()),
        None => StorageInitPlan::UseDefault,
    }
}

/// Configuration for periodic state persistence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistConfig {
    pub enabled: bool,
    pub interval_secs: u64,
}

/// Compute persistence configuration from raw config values.
///
/// Persistence is enabled only when `persist_secs > 0` AND storage is available.
/// When disabled, the interval defaults to 3600s (the timer still ticks but
/// the persistence branch is gated by `enabled`).
pub fn compute_persist_config(persist_secs: u64, has_storage: bool) -> PersistConfig {
    let enabled = persist_secs > 0 && has_storage;
    PersistConfig {
        enabled,
        interval_secs: if enabled { persist_secs } else { 3600 },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- plan_storage_init tests ----------------------------------------------

    #[test]
    fn storage_disabled() {
        assert_eq!(plan_storage_init(false, None), StorageInitPlan::Disabled);
    }

    #[test]
    fn storage_disabled_ignores_custom_path() {
        assert_eq!(
            plan_storage_init(false, Some("/tmp/store")),
            StorageInitPlan::Disabled,
        );
    }

    #[test]
    fn storage_enabled_default_path() {
        assert_eq!(plan_storage_init(true, None), StorageInitPlan::UseDefault);
    }

    #[test]
    fn storage_enabled_custom_path() {
        assert_eq!(
            plan_storage_init(true, Some("/tmp/store")),
            StorageInitPlan::UseCustomPath("/tmp/store".to_string()),
        );
    }

    // -- compute_persist_config tests -----------------------------------------

    #[test]
    fn persist_enabled_with_storage() {
        let cfg = compute_persist_config(300, true);
        assert!(cfg.enabled);
        assert_eq!(cfg.interval_secs, 300);
    }

    #[test]
    fn persist_disabled_zero_interval() {
        let cfg = compute_persist_config(0, true);
        assert!(!cfg.enabled);
        assert_eq!(cfg.interval_secs, 3600);
    }

    #[test]
    fn persist_disabled_no_storage() {
        let cfg = compute_persist_config(300, false);
        assert!(!cfg.enabled);
        assert_eq!(cfg.interval_secs, 3600);
    }

    #[test]
    fn persist_disabled_both_zero_and_no_storage() {
        let cfg = compute_persist_config(0, false);
        assert!(!cfg.enabled);
        assert_eq!(cfg.interval_secs, 3600);
    }

    #[test]
    fn persist_large_interval() {
        let cfg = compute_persist_config(86400, true);
        assert!(cfg.enabled);
        assert_eq!(cfg.interval_secs, 86400);
    }
}
