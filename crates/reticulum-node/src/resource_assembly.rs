//! Pure resource part assembly decisions.
//!
//! Extracted from [`crate::node::Node::handle_resource_part`] so that the
//! three-level nested decision chain (receive → check derived key → assemble)
//! can be tested without a running Node or async I/O.

use crate::packet_helpers::format_data_preview;
use crate::resource_manager::ResourceManagerError;
use crate::resource_ops::AssembledOutput;

/// Successful assembly output.
pub type AssemblyOutput = AssembledOutput;

/// Input snapshot for the resource assembly decision.
#[derive(Debug)]
pub struct ResourcePartInput {
    /// Whether `resource_manager.receive_part()` succeeded.
    pub receive_ok: bool,
    /// Whether all parts have been received (from `ReceiveResult::all_received`).
    pub all_received: bool,
    /// Error from `receive_part()` if it failed.
    pub receive_error: Option<ResourceManagerError>,
    /// Whether a derived key is available for assembly.
    pub has_derived_key: bool,
    /// Result of `resource_manager.assemble_and_prove()`.
    pub assembly_result: Option<Result<AssemblyOutput, ResourceManagerError>>,
    /// Maximum preview length for data display.
    pub preview_len: usize,
}

/// Outcome of the resource assembly decision.
#[derive(Debug)]
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
    AssemblyFailed { error: ResourceManagerError },
    /// Part reception itself failed.
    PartError { error: ResourceManagerError },
}

/// Plan the outcome of receiving a resource part.
///
/// This function captures the full decision tree from `handle_resource_part()`:
/// 1. If receive failed → `PartError`
/// 2. If not all parts → `PartReceived`
/// 3. If no derived key → `NoDerivedKey`
/// 4. If assembly failed → `AssemblyFailed`
/// 5. If assembly succeeded → `Assembled` with data preview
pub fn plan_resource_assembly(input: ResourcePartInput) -> ResourceAssemblyOutcome {
    if !input.receive_ok {
        return ResourceAssemblyOutcome::PartError {
            error: input
                .receive_error
                .unwrap_or_else(|| {
                    ResourceManagerError::Preparation("unknown error".to_string())
                }),
        };
    }

    if !input.all_received {
        return ResourceAssemblyOutcome::PartReceived;
    }

    if !input.has_derived_key {
        return ResourceAssemblyOutcome::NoDerivedKey;
    }

    match input.assembly_result {
        Some(Ok(output)) => {
            let data_preview = format_data_preview(&output.data, input.preview_len);
            ResourceAssemblyOutcome::Assembled {
                data: output.data,
                proof_bytes: output.proof_bytes,
                data_preview,
            }
        }
        Some(Err(e)) => ResourceAssemblyOutcome::AssemblyFailed { error: e },
        None => ResourceAssemblyOutcome::AssemblyFailed {
            error: ResourceManagerError::Preparation(
                "assembly not attempted".to_string(),
            ),
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
        let outcome = plan_resource_assembly(input);
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
            receive_error: Some(ResourceManagerError::Preparation(
                "hash mismatch".to_string(),
            )),
            ..base_input()
        };
        let outcome = plan_resource_assembly(input);
        match outcome {
            ResourceAssemblyOutcome::PartError { error } => {
                assert!(error.to_string().contains("hash mismatch"));
            }
            other => panic!("expected PartError, got {other:?}"),
        }
    }

    #[test]
    fn receive_error_no_message() {
        let input = ResourcePartInput {
            receive_ok: false,
            receive_error: None,
            ..base_input()
        };
        let outcome = plan_resource_assembly(input);
        match outcome {
            ResourceAssemblyOutcome::PartError { error } => {
                assert!(error.to_string().contains("unknown error"));
            }
            other => panic!("expected PartError, got {other:?}"),
        }
    }

    // --- not all received ---

    #[test]
    fn not_all_received() {
        let input = ResourcePartInput {
            all_received: false,
            assembly_result: None,
            ..base_input()
        };
        let outcome = plan_resource_assembly(input);
        assert!(matches!(outcome, ResourceAssemblyOutcome::PartReceived));
    }

    // --- no derived key ---

    #[test]
    fn no_derived_key() {
        let input = ResourcePartInput {
            has_derived_key: false,
            assembly_result: None,
            ..base_input()
        };
        let outcome = plan_resource_assembly(input);
        assert!(matches!(outcome, ResourceAssemblyOutcome::NoDerivedKey));
    }

    // --- assembly error ---

    #[test]
    fn assembly_error() {
        let input = ResourcePartInput {
            assembly_result: Some(Err(ResourceManagerError::Assembly(
                reticulum_protocol::error::ResourceError::DecryptionFailed(
                    "decrypt failed".to_string(),
                ),
            ))),
            ..base_input()
        };
        let outcome = plan_resource_assembly(input);
        match outcome {
            ResourceAssemblyOutcome::AssemblyFailed { error } => {
                assert!(error.to_string().contains("decrypt failed"));
            }
            other => panic!("expected AssemblyFailed, got {other:?}"),
        }
    }

    #[test]
    fn assembly_not_attempted() {
        let input = ResourcePartInput {
            assembly_result: None,
            ..base_input()
        };
        let outcome = plan_resource_assembly(input);
        match outcome {
            ResourceAssemblyOutcome::AssemblyFailed { error } => {
                assert!(error.to_string().contains("assembly not attempted"));
            }
            other => panic!("expected AssemblyFailed, got {other:?}"),
        }
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
        let outcome = plan_resource_assembly(input);
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
        let outcome = plan_resource_assembly(input);
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
        let msg = "specific error: code 42 at offset 0xFF";
        let input = ResourcePartInput {
            receive_ok: false,
            receive_error: Some(ResourceManagerError::Preparation(msg.to_string())),
            ..base_input()
        };
        let outcome = plan_resource_assembly(input);
        match outcome {
            ResourceAssemblyOutcome::PartError { error } => {
                assert!(error.to_string().contains(msg));
            }
            other => panic!("expected PartError, got {other:?}"),
        }
    }

    // --- priority: receive error takes precedence ---

    #[test]
    fn receive_error_takes_precedence_over_all_received() {
        let input = ResourcePartInput {
            receive_ok: false,
            all_received: true,
            receive_error: Some(ResourceManagerError::Preparation("bad part".to_string())),
            has_derived_key: true,
            assembly_result: Some(Ok(AssembledOutput {
                data: vec![1],
                proof_bytes: vec![2],
            })),
            preview_len: 200,
        };
        let outcome = plan_resource_assembly(input);
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
        let outcome = plan_resource_assembly(input);
        assert!(matches!(outcome, ResourceAssemblyOutcome::NoDerivedKey));
    }
}
