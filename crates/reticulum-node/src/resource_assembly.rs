//! Pure resource part assembly decisions.
//!
//! Extracted from [`crate::node::Node::handle_resource_part`] so that the
//! three-level nested decision chain (receive → check derived key → assemble)
//! can be tested without a running Node or async I/O.

use crate::packet_helpers::format_data_preview;
use crate::resource_ops::AssembledOutput;

/// Successful assembly output.
pub type AssemblyOutput = AssembledOutput;

/// Input snapshot for the resource assembly decision.
#[derive(Debug, Clone)]
pub struct ResourcePartInput {
    /// Whether `resource_manager.receive_part()` succeeded.
    pub receive_ok: bool,
    /// Whether all parts have been received (from `ReceiveResult::all_received`).
    pub all_received: bool,
    /// Error message if `receive_part()` failed.
    pub receive_error: Option<String>,
    /// Whether a derived key is available for assembly.
    pub has_derived_key: bool,
    /// Result of `resource_manager.assemble_and_prove()`: Ok((data, proof)) or Err(msg).
    pub assembly_result: Option<Result<AssemblyOutput, String>>,
    /// Maximum preview length for data display.
    pub preview_len: usize,
}

/// Outcome of the resource assembly decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceAssemblyOutcome {
    /// Part received successfully, but not all parts are in yet.
    PartReceived,
    /// All parts received and assembled successfully.
    Assembled {
        data: Vec<u8>,
        proof_bytes: Vec<u8>,
        data_preview: String,
    },
    /// All parts received but no derived key available.
    NoDerivedKey,
    /// All parts received but assembly failed.
    AssemblyFailed { error: String },
    /// Part reception itself failed.
    PartError { error: String },
}

/// Plan the outcome of receiving a resource part.
///
/// This function captures the full decision tree from `handle_resource_part()`:
/// 1. If receive failed → `PartError`
/// 2. If not all parts → `PartReceived`
/// 3. If no derived key → `NoDerivedKey`
/// 4. If assembly failed → `AssemblyFailed`
/// 5. If assembly succeeded → `Assembled` with data preview
pub fn plan_resource_assembly(input: &ResourcePartInput) -> ResourceAssemblyOutcome {
    if !input.receive_ok {
        return ResourceAssemblyOutcome::PartError {
            error: input
                .receive_error
                .clone()
                .unwrap_or_else(|| "unknown error".to_string()),
        };
    }

    if !input.all_received {
        return ResourceAssemblyOutcome::PartReceived;
    }

    if !input.has_derived_key {
        return ResourceAssemblyOutcome::NoDerivedKey;
    }

    match &input.assembly_result {
        Some(Ok(output)) => {
            let data_preview = format_data_preview(&output.data, input.preview_len);
            ResourceAssemblyOutcome::Assembled {
                data: output.data.clone(),
                proof_bytes: output.proof_bytes.clone(),
                data_preview,
            }
        }
        Some(Err(e)) => ResourceAssemblyOutcome::AssemblyFailed { error: e.clone() },
        None => ResourceAssemblyOutcome::AssemblyFailed {
            error: "assembly not attempted".to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_input() -> ResourcePartInput {
        ResourcePartInput {
            receive_ok: true,
            all_received: true,
            has_derived_key: true,
            receive_error: None,
            assembly_result: Some(Ok(AssembledOutput {
                data: b"hello resource".to_vec(),
                proof_bytes: b"proof123".to_vec(),
            })),
            preview_len: 200,
        }
    }

    // --- happy path ---

    #[test]
    fn assembled_with_preview() {
        let input = base_input();
        let outcome = plan_resource_assembly(&input);
        match outcome {
            ResourceAssemblyOutcome::Assembled {
                data,
                proof_bytes,
                data_preview,
            } => {
                assert_eq!(data, b"hello resource");
                assert_eq!(proof_bytes, b"proof123");
                assert_eq!(data_preview, "hello resource");
            }
            other => panic!("expected Assembled, got {other:?}"),
        }
    }

    // --- receive error ---

    #[test]
    fn receive_error_with_message() {
        let input = ResourcePartInput {
            receive_ok: false,
            receive_error: Some("hash mismatch".to_string()),
            ..base_input()
        };
        let outcome = plan_resource_assembly(&input);
        assert_eq!(
            outcome,
            ResourceAssemblyOutcome::PartError {
                error: "hash mismatch".to_string()
            }
        );
    }

    #[test]
    fn receive_error_no_message() {
        let input = ResourcePartInput {
            receive_ok: false,
            receive_error: None,
            ..base_input()
        };
        let outcome = plan_resource_assembly(&input);
        assert_eq!(
            outcome,
            ResourceAssemblyOutcome::PartError {
                error: "unknown error".to_string()
            }
        );
    }

    // --- not all received ---

    #[test]
    fn not_all_received() {
        let input = ResourcePartInput {
            all_received: false,
            assembly_result: None,
            ..base_input()
        };
        let outcome = plan_resource_assembly(&input);
        assert_eq!(outcome, ResourceAssemblyOutcome::PartReceived);
    }

    // --- no derived key ---

    #[test]
    fn no_derived_key() {
        let input = ResourcePartInput {
            has_derived_key: false,
            assembly_result: None,
            ..base_input()
        };
        let outcome = plan_resource_assembly(&input);
        assert_eq!(outcome, ResourceAssemblyOutcome::NoDerivedKey);
    }

    // --- assembly error ---

    #[test]
    fn assembly_error() {
        let input = ResourcePartInput {
            assembly_result: Some(Err("decrypt failed".to_string())),
            ..base_input()
        };
        let outcome = plan_resource_assembly(&input);
        assert_eq!(
            outcome,
            ResourceAssemblyOutcome::AssemblyFailed {
                error: "decrypt failed".to_string()
            }
        );
    }

    #[test]
    fn assembly_not_attempted() {
        let input = ResourcePartInput {
            assembly_result: None,
            ..base_input()
        };
        let outcome = plan_resource_assembly(&input);
        assert_eq!(
            outcome,
            ResourceAssemblyOutcome::AssemblyFailed {
                error: "assembly not attempted".to_string()
            }
        );
    }

    // --- preview truncation ---

    #[test]
    fn preview_truncated() {
        let input = ResourcePartInput {
            assembly_result: Some(Ok(AssembledOutput {
                data: b"long resource data here".to_vec(),
                proof_bytes: b"proof".to_vec(),
            })),
            preview_len: 10,
            ..base_input()
        };
        let outcome = plan_resource_assembly(&input);
        match outcome {
            ResourceAssemblyOutcome::Assembled { data_preview, .. } => {
                assert_eq!(data_preview, "long resou");
            }
            other => panic!("expected Assembled, got {other:?}"),
        }
    }

    #[test]
    fn empty_data_assembly() {
        let input = ResourcePartInput {
            assembly_result: Some(Ok(AssembledOutput {
                data: vec![],
                proof_bytes: b"proof".to_vec(),
            })),
            ..base_input()
        };
        let outcome = plan_resource_assembly(&input);
        match outcome {
            ResourceAssemblyOutcome::Assembled {
                data, data_preview, ..
            } => {
                assert!(data.is_empty());
                assert_eq!(data_preview, "");
            }
            other => panic!("expected Assembled, got {other:?}"),
        }
    }

    // --- error message preservation ---

    #[test]
    fn error_messages_preserved_exactly() {
        let msg = "specific error: code 42 at offset 0xFF".to_string();
        let input = ResourcePartInput {
            receive_ok: false,
            receive_error: Some(msg.clone()),
            ..base_input()
        };
        let outcome = plan_resource_assembly(&input);
        assert_eq!(outcome, ResourceAssemblyOutcome::PartError { error: msg });
    }

    // --- priority: receive error takes precedence ---

    #[test]
    fn receive_error_takes_precedence_over_all_received() {
        let input = ResourcePartInput {
            receive_ok: false,
            all_received: true,
            receive_error: Some("bad part".to_string()),
            has_derived_key: true,
            assembly_result: Some(Ok(AssembledOutput {
                data: vec![1],
                proof_bytes: vec![2],
            })),
            preview_len: 200,
        };
        let outcome = plan_resource_assembly(&input);
        assert!(matches!(outcome, ResourceAssemblyOutcome::PartError { .. }));
    }

    #[test]
    fn no_derived_key_takes_precedence_over_assembly() {
        let input = ResourcePartInput {
            receive_ok: true,
            all_received: true,
            has_derived_key: false,
            receive_error: None,
            assembly_result: Some(Ok(AssembledOutput {
                data: vec![1],
                proof_bytes: vec![2],
            })),
            preview_len: 200,
        };
        let outcome = plan_resource_assembly(&input);
        assert_eq!(outcome, ResourceAssemblyOutcome::NoDerivedKey);
    }
}
