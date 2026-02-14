//! Pure identity and state loading decision logic.
//!
//! Extracted from [`crate::node::Node::start`] so that the three-way
//! identity loading fallback chain and the state load classification
//! can be tested without async I/O or a running Node.

/// Decision for identity loading.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityLoadDecision {
    /// Identity was loaded from storage successfully.
    Loaded,
    /// Storage exists but no identity file — generate and save a new one.
    GenerateAndSave,
    /// Storage exists but loading failed — generate without saving.
    GenerateFallback,
    /// No storage configured — skip identity persistence entirely.
    NoStorage,
}

/// Classify the identity load result into a decision.
///
/// `has_storage` indicates whether a Storage instance is available.
/// `load_result` represents the outcome of `storage.load_identity()`:
/// - `Some(Ok(true))` → identity was found and loaded
/// - `Some(Ok(false))` → file not found (no identity on disk)
/// - `Some(Err(()))` → loading failed (corrupt file, I/O error, etc.)
/// - `None` → storage not available (should match `has_storage == false`)
pub fn classify_identity_load(
    has_storage: bool,
    load_result: Option<Result<bool, ()>>,
) -> IdentityLoadDecision {
    if !has_storage {
        return IdentityLoadDecision::NoStorage;
    }

    match load_result {
        Some(Ok(true)) => IdentityLoadDecision::Loaded,
        Some(Ok(false)) => IdentityLoadDecision::GenerateAndSave,
        Some(Err(())) => IdentityLoadDecision::GenerateFallback,
        None => IdentityLoadDecision::NoStorage,
    }
}

/// Outcome of loading a state component (path table or hashlist).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateLoadOutcome {
    /// Successfully loaded with `count` entries.
    Loaded { count: usize },
    /// No entries loaded — use default empty state.
    UseDefault,
    /// Loading failed with an error message.
    Failed { error: String },
}

/// Classify the result of loading a state component.
///
/// This is generic for both path table and hashlist loading.
/// `result` maps the async load call:
/// - `Ok(count)` → loaded successfully, `count` may be 0
/// - `Err(msg)` → loading failed
pub fn classify_state_load(result: Result<usize, String>) -> StateLoadOutcome {
    match result {
        Ok(count) if count > 0 => StateLoadOutcome::Loaded { count },
        Ok(_) => StateLoadOutcome::UseDefault,
        Err(error) => StateLoadOutcome::Failed { error },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- classify_identity_load ---

    #[test]
    fn identity_loaded_from_storage() {
        let decision = classify_identity_load(true, Some(Ok(true)));
        assert_eq!(decision, IdentityLoadDecision::Loaded);
    }

    #[test]
    fn identity_not_found_generates_and_saves() {
        let decision = classify_identity_load(true, Some(Ok(false)));
        assert_eq!(decision, IdentityLoadDecision::GenerateAndSave);
    }

    #[test]
    fn identity_load_error_generates_fallback() {
        let decision = classify_identity_load(true, Some(Err(())));
        assert_eq!(decision, IdentityLoadDecision::GenerateFallback);
    }

    #[test]
    fn no_storage_returns_no_storage() {
        let decision = classify_identity_load(false, None);
        assert_eq!(decision, IdentityLoadDecision::NoStorage);
    }

    #[test]
    fn no_storage_ignores_result() {
        // Even if somehow a result is passed, has_storage=false takes precedence
        let decision = classify_identity_load(false, Some(Ok(true)));
        assert_eq!(decision, IdentityLoadDecision::NoStorage);
    }

    #[test]
    fn has_storage_but_none_result() {
        // Edge case: storage exists but load_result is None
        let decision = classify_identity_load(true, None);
        assert_eq!(decision, IdentityLoadDecision::NoStorage);
    }

    // --- classify_state_load ---

    #[test]
    fn state_loaded_with_entries() {
        let outcome = classify_state_load(Ok(42));
        assert_eq!(outcome, StateLoadOutcome::Loaded { count: 42 });
    }

    #[test]
    fn state_loaded_zero_uses_default() {
        let outcome = classify_state_load(Ok(0));
        assert_eq!(outcome, StateLoadOutcome::UseDefault);
    }

    #[test]
    fn state_loaded_one_entry() {
        let outcome = classify_state_load(Ok(1));
        assert_eq!(outcome, StateLoadOutcome::Loaded { count: 1 });
    }

    #[test]
    fn state_load_failed() {
        let outcome = classify_state_load(Err("I/O error".to_string()));
        assert_eq!(
            outcome,
            StateLoadOutcome::Failed {
                error: "I/O error".to_string()
            }
        );
    }

    #[test]
    fn state_error_message_preserved() {
        let msg = "deserialization error: unexpected byte 0xFF at offset 42".to_string();
        let outcome = classify_state_load(Err(msg.clone()));
        assert_eq!(outcome, StateLoadOutcome::Failed { error: msg });
    }

    #[test]
    fn state_large_count() {
        let outcome = classify_state_load(Ok(1_000_000));
        assert_eq!(
            outcome,
            StateLoadOutcome::Loaded {
                count: 1_000_000
            }
        );
    }
}
