//! Pure auto-data action planning.
//!
//! Separates the "what to send" decision from the "send it" I/O for
//! auto-data on newly established links. The planner takes a snapshot
//! of all queued data and produces an ordered list of actions.

/// An action to execute for auto-data on a newly established link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AutoDataAction {
    /// Register the link with the channel manager at the given RTT.
    RegisterChannel { rtt_millis: u64 },
    /// Transfer a channel message from link_manager to channel_manager queue.
    TransferChannelQueue { message: String },
    /// Transfer buffer data from link_manager to channel_manager queue.
    TransferBufferQueue { data: String },
    /// Transfer a request from link_manager to channel_manager queue.
    TransferRequestQueue { path: String, data: String },
    /// Send plain link data.
    SendLinkData { data: String },
    /// Send a resource transfer.
    SendResource { data: String },
    /// Send a channel message.
    SendChannelMessage { message: String },
    /// Send a buffer stream.
    SendBufferStream { data: String },
    /// Send a request.
    SendRequest { path: String, data: String },
}

/// A snapshot of all queued auto-data for a newly established link.
///
/// Captures the state of both link_manager and channel_manager queues
/// at a point in time, enabling pure planning without borrowing managers.
#[derive(Debug, Clone, Default)]
pub struct AutoQueueSnapshot {
    /// RTT for this link (in milliseconds, encoded as u64 for Eq/PartialEq).
    pub rtt_millis: u64,
    /// Auto channel message from link_manager queue.
    pub link_channel: Option<String>,
    /// Auto buffer data from link_manager queue.
    pub link_buffer: Option<String>,
    /// Auto request from link_manager queue (path, data).
    pub link_request: Option<(String, String)>,
    /// Auto plain data from link_manager.
    pub link_data: Option<String>,
    /// Auto resource data from link_manager.
    pub link_resource: Option<String>,
    /// Auto channel message from channel_manager queue.
    pub channel_message: Option<String>,
    /// Auto buffer data from channel_manager queue.
    pub channel_buffer: Option<String>,
    /// Auto request from channel_manager queue (path, data).
    pub channel_request: Option<(String, String)>,
}

/// Plan the sequence of auto-data actions for a newly established link.
///
/// The ordering is:
/// 1. Register channel (always first — needed for channel/buffer/request sends)
/// 2. Transfer queues from link_manager to channel_manager
/// 3. Send plain link data
/// 4. Send resource
/// 5. Send channel message
/// 6. Send buffer stream
/// 7. Send request
pub fn plan_auto_data_actions(snapshot: &AutoQueueSnapshot) -> Vec<AutoDataAction> {
    let mut actions = Vec::new();

    // 1. Always register channel first
    actions.push(AutoDataAction::RegisterChannel {
        rtt_millis: snapshot.rtt_millis,
    });

    // 2. Transfer queues from link_manager → channel_manager
    if let Some(ref msg) = snapshot.link_channel {
        actions.push(AutoDataAction::TransferChannelQueue {
            message: msg.clone(),
        });
    }
    if let Some(ref data) = snapshot.link_buffer {
        actions.push(AutoDataAction::TransferBufferQueue { data: data.clone() });
    }
    if let Some((ref path, ref data)) = snapshot.link_request {
        actions.push(AutoDataAction::TransferRequestQueue {
            path: path.clone(),
            data: data.clone(),
        });
    }

    // 3. Send plain link data
    if let Some(ref data) = snapshot.link_data {
        actions.push(AutoDataAction::SendLinkData { data: data.clone() });
    }

    // 4. Send resource
    if let Some(ref data) = snapshot.link_resource {
        actions.push(AutoDataAction::SendResource { data: data.clone() });
    }

    // 5. Send channel message (from channel_manager queue)
    if let Some(ref msg) = snapshot.channel_message {
        actions.push(AutoDataAction::SendChannelMessage {
            message: msg.clone(),
        });
    }

    // 6. Send buffer stream
    if let Some(ref data) = snapshot.channel_buffer {
        actions.push(AutoDataAction::SendBufferStream { data: data.clone() });
    }

    // 7. Send request
    if let Some((ref path, ref data)) = snapshot.channel_request {
        actions.push(AutoDataAction::SendRequest {
            path: path.clone(),
            data: data.clone(),
        });
    }

    actions
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_snapshot_only_registers() {
        let snapshot = AutoQueueSnapshot::default();
        let actions = plan_auto_data_actions(&snapshot);
        assert_eq!(actions.len(), 1);
        assert_eq!(
            actions[0],
            AutoDataAction::RegisterChannel { rtt_millis: 0 }
        );
    }

    #[test]
    fn register_always_first() {
        let snapshot = AutoQueueSnapshot {
            rtt_millis: 50,
            link_data: Some("hello".into()),
            ..Default::default()
        };
        let actions = plan_auto_data_actions(&snapshot);
        assert!(actions.len() >= 2);
        assert_eq!(
            actions[0],
            AutoDataAction::RegisterChannel { rtt_millis: 50 }
        );
    }

    #[test]
    fn link_data_only() {
        let snapshot = AutoQueueSnapshot {
            link_data: Some("test data".into()),
            ..Default::default()
        };
        let actions = plan_auto_data_actions(&snapshot);
        assert_eq!(actions.len(), 2);
        assert_eq!(
            actions[1],
            AutoDataAction::SendLinkData {
                data: "test data".into()
            }
        );
    }

    #[test]
    fn resource_only() {
        let snapshot = AutoQueueSnapshot {
            link_resource: Some("resource payload".into()),
            ..Default::default()
        };
        let actions = plan_auto_data_actions(&snapshot);
        assert_eq!(actions.len(), 2);
        assert_eq!(
            actions[1],
            AutoDataAction::SendResource {
                data: "resource payload".into()
            }
        );
    }

    #[test]
    fn channel_message_only() {
        let snapshot = AutoQueueSnapshot {
            channel_message: Some("chan msg".into()),
            ..Default::default()
        };
        let actions = plan_auto_data_actions(&snapshot);
        assert_eq!(actions.len(), 2);
        assert_eq!(
            actions[1],
            AutoDataAction::SendChannelMessage {
                message: "chan msg".into()
            }
        );
    }

    #[test]
    fn buffer_stream_only() {
        let snapshot = AutoQueueSnapshot {
            channel_buffer: Some("buffer data".into()),
            ..Default::default()
        };
        let actions = plan_auto_data_actions(&snapshot);
        assert_eq!(actions.len(), 2);
        assert_eq!(
            actions[1],
            AutoDataAction::SendBufferStream {
                data: "buffer data".into()
            }
        );
    }

    #[test]
    fn request_only() {
        let snapshot = AutoQueueSnapshot {
            channel_request: Some(("/test/echo".into(), "req data".into())),
            ..Default::default()
        };
        let actions = plan_auto_data_actions(&snapshot);
        assert_eq!(actions.len(), 2);
        assert_eq!(
            actions[1],
            AutoDataAction::SendRequest {
                path: "/test/echo".into(),
                data: "req data".into()
            }
        );
    }

    #[test]
    fn all_queues_full_order_verification() {
        let snapshot = AutoQueueSnapshot {
            rtt_millis: 100,
            link_channel: Some("lc".into()),
            link_buffer: Some("lb".into()),
            link_request: Some(("/path".into(), "lr".into())),
            link_data: Some("ld".into()),
            link_resource: Some("lres".into()),
            channel_message: Some("cm".into()),
            channel_buffer: Some("cb".into()),
            channel_request: Some(("/req".into(), "cr".into())),
        };
        let actions = plan_auto_data_actions(&snapshot);
        assert_eq!(actions.len(), 9);

        // Verify exact order
        assert_eq!(
            actions[0],
            AutoDataAction::RegisterChannel { rtt_millis: 100 }
        );
        assert_eq!(
            actions[1],
            AutoDataAction::TransferChannelQueue {
                message: "lc".into()
            }
        );
        assert_eq!(
            actions[2],
            AutoDataAction::TransferBufferQueue { data: "lb".into() }
        );
        assert_eq!(
            actions[3],
            AutoDataAction::TransferRequestQueue {
                path: "/path".into(),
                data: "lr".into()
            }
        );
        assert_eq!(
            actions[4],
            AutoDataAction::SendLinkData { data: "ld".into() }
        );
        assert_eq!(
            actions[5],
            AutoDataAction::SendResource {
                data: "lres".into()
            }
        );
        assert_eq!(
            actions[6],
            AutoDataAction::SendChannelMessage {
                message: "cm".into()
            }
        );
        assert_eq!(
            actions[7],
            AutoDataAction::SendBufferStream { data: "cb".into() }
        );
        assert_eq!(
            actions[8],
            AutoDataAction::SendRequest {
                path: "/req".into(),
                data: "cr".into()
            }
        );
    }

    #[test]
    fn transfer_before_send_ordering() {
        // Transfers (steps 2) must come before sends (steps 5-7)
        let snapshot = AutoQueueSnapshot {
            link_channel: Some("transfer me".into()),
            channel_message: Some("send me".into()),
            ..Default::default()
        };
        let actions = plan_auto_data_actions(&snapshot);
        let transfer_pos = actions
            .iter()
            .position(|a| matches!(a, AutoDataAction::TransferChannelQueue { .. }))
            .unwrap();
        let send_pos = actions
            .iter()
            .position(|a| matches!(a, AutoDataAction::SendChannelMessage { .. }))
            .unwrap();
        assert!(
            transfer_pos < send_pos,
            "transfer ({transfer_pos}) must come before send ({send_pos})"
        );
    }

    #[test]
    fn path_and_data_preserved_in_request() {
        let snapshot = AutoQueueSnapshot {
            link_request: Some(("/my/path".into(), "my data".into())),
            ..Default::default()
        };
        let actions = plan_auto_data_actions(&snapshot);
        let transfer = actions
            .iter()
            .find(|a| matches!(a, AutoDataAction::TransferRequestQueue { .. }))
            .unwrap();
        assert_eq!(
            *transfer,
            AutoDataAction::TransferRequestQueue {
                path: "/my/path".into(),
                data: "my data".into()
            }
        );
    }
}
