//! Pure post-transfer channel queue draining decisions.
//!
//! Complements [`crate::auto_data_plan`] by extracting the second phase of
//! auto-data handling: after link-manager queues have been transferred to the
//! channel manager, drain the channel manager queues into send actions.

/// A snapshot of channel manager queues after transfer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PostTransferSnapshot {
    /// Channel message ready to send (from `channel_manager.drain_auto_channel`).
    pub channel_message: Option<String>,
    /// Buffer data ready to send (from `channel_manager.drain_auto_buffer`).
    pub buffer_data: Option<String>,
    /// Request ready to send (from `channel_manager.drain_auto_request`): (path, data).
    pub request: Option<(String, String)>,
}

/// An action to execute after the transfer phase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PostTransferAction {
    /// Send a channel message.
    SendChannelMessage { message: String },
    /// Send a buffer stream.
    SendBufferStream { data: String },
    /// Send a request.
    SendRequest { path: String, data: String },
}

/// Plan post-transfer actions from a snapshot of channel manager queues.
///
/// The ordering is: channel message → buffer stream → request,
/// matching the drain order in the original `send_auto_data()`.
pub fn plan_post_transfer_actions(snapshot: &PostTransferSnapshot) -> Vec<PostTransferAction> {
    let mut actions = Vec::new();

    if let Some(ref message) = snapshot.channel_message {
        actions.push(PostTransferAction::SendChannelMessage {
            message: message.clone(),
        });
    }

    if let Some(ref data) = snapshot.buffer_data {
        actions.push(PostTransferAction::SendBufferStream {
            data: data.clone(),
        });
    }

    if let Some((ref path, ref data)) = snapshot.request {
        actions.push(PostTransferAction::SendRequest {
            path: path.clone(),
            data: data.clone(),
        });
    }

    actions
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- empty snapshot ---

    #[test]
    fn empty_snapshot_no_actions() {
        let snapshot = PostTransferSnapshot::default();
        let actions = plan_post_transfer_actions(&snapshot);
        assert!(actions.is_empty());
    }

    // --- single queue ---

    #[test]
    fn channel_message_only() {
        let snapshot = PostTransferSnapshot {
            channel_message: Some("hello".into()),
            ..Default::default()
        };
        let actions = plan_post_transfer_actions(&snapshot);
        assert_eq!(actions.len(), 1);
        assert_eq!(
            actions[0],
            PostTransferAction::SendChannelMessage {
                message: "hello".into()
            }
        );
    }

    #[test]
    fn buffer_data_only() {
        let snapshot = PostTransferSnapshot {
            buffer_data: Some("stream data".into()),
            ..Default::default()
        };
        let actions = plan_post_transfer_actions(&snapshot);
        assert_eq!(actions.len(), 1);
        assert_eq!(
            actions[0],
            PostTransferAction::SendBufferStream {
                data: "stream data".into()
            }
        );
    }

    #[test]
    fn request_only() {
        let snapshot = PostTransferSnapshot {
            request: Some(("/test/echo".into(), "ping".into())),
            ..Default::default()
        };
        let actions = plan_post_transfer_actions(&snapshot);
        assert_eq!(actions.len(), 1);
        assert_eq!(
            actions[0],
            PostTransferAction::SendRequest {
                path: "/test/echo".into(),
                data: "ping".into()
            }
        );
    }

    // --- all three queues ---

    #[test]
    fn all_three_in_order() {
        let snapshot = PostTransferSnapshot {
            channel_message: Some("msg".into()),
            buffer_data: Some("buf".into()),
            request: Some(("/path".into(), "req".into())),
        };
        let actions = plan_post_transfer_actions(&snapshot);
        assert_eq!(actions.len(), 3);
        assert_eq!(
            actions[0],
            PostTransferAction::SendChannelMessage {
                message: "msg".into()
            }
        );
        assert_eq!(
            actions[1],
            PostTransferAction::SendBufferStream {
                data: "buf".into()
            }
        );
        assert_eq!(
            actions[2],
            PostTransferAction::SendRequest {
                path: "/path".into(),
                data: "req".into()
            }
        );
    }

    // --- partial combinations ---

    #[test]
    fn channel_and_request_no_buffer() {
        let snapshot = PostTransferSnapshot {
            channel_message: Some("chan".into()),
            buffer_data: None,
            request: Some(("/api".into(), "data".into())),
        };
        let actions = plan_post_transfer_actions(&snapshot);
        assert_eq!(actions.len(), 2);
        assert!(matches!(
            &actions[0],
            PostTransferAction::SendChannelMessage { .. }
        ));
        assert!(matches!(
            &actions[1],
            PostTransferAction::SendRequest { .. }
        ));
    }

    #[test]
    fn buffer_and_request_no_channel() {
        let snapshot = PostTransferSnapshot {
            channel_message: None,
            buffer_data: Some("buf".into()),
            request: Some(("/x".into(), "y".into())),
        };
        let actions = plan_post_transfer_actions(&snapshot);
        assert_eq!(actions.len(), 2);
        assert!(matches!(
            &actions[0],
            PostTransferAction::SendBufferStream { .. }
        ));
        assert!(matches!(
            &actions[1],
            PostTransferAction::SendRequest { .. }
        ));
    }

    // --- content preservation ---

    #[test]
    fn content_preserved_exactly() {
        let snapshot = PostTransferSnapshot {
            channel_message: Some("special chars: €£¥ 🔑".into()),
            buffer_data: Some("binary-ish: \x00\x01\x02".into()),
            request: Some(("/path/with spaces".into(), "data\nwith\nnewlines".into())),
        };
        let actions = plan_post_transfer_actions(&snapshot);
        assert_eq!(actions.len(), 3);

        match &actions[0] {
            PostTransferAction::SendChannelMessage { message } => {
                assert_eq!(message, "special chars: €£¥ 🔑");
            }
            other => panic!("expected SendChannelMessage, got {other:?}"),
        }
        match &actions[1] {
            PostTransferAction::SendBufferStream { data } => {
                assert_eq!(data, "binary-ish: \x00\x01\x02");
            }
            other => panic!("expected SendBufferStream, got {other:?}"),
        }
        match &actions[2] {
            PostTransferAction::SendRequest { path, data } => {
                assert_eq!(path, "/path/with spaces");
                assert_eq!(data, "data\nwith\nnewlines");
            }
            other => panic!("expected SendRequest, got {other:?}"),
        }
    }
}
