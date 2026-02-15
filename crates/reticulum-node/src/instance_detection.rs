//! Pure detection logic for determining shared instance mode.
//!
//! All functions are pure (no I/O). The actual socket bind/connect attempts
//! happen in `node.rs`, which feeds results here for classification.

use std::path::PathBuf;

use crate::instance_mode::InstanceMode;

/// Inputs gathered from socket bind/connect attempts.
pub struct DetectionInput {
    /// Whether shared instance mode is enabled in config.
    pub share_instance: bool,
    /// Result of attempting to bind the server socket.
    /// `None` if not attempted (e.g. non-Unix or share_instance=false).
    pub bind_succeeded: Option<bool>,
    /// Result of attempting to connect as a client.
    /// `None` if not attempted (e.g. bind succeeded, or share_instance=false).
    pub connect_succeeded: Option<bool>,
}

/// Decide the instance mode from detection inputs.
///
/// Logic:
/// - `share_instance == false` → `Standalone`
/// - bind succeeded → `SharedMaster`
/// - bind failed, connect succeeded → `SharedClient`
/// - both failed → `Standalone` (fallback)
pub fn decide_instance_mode(input: &DetectionInput) -> InstanceMode {
    if !input.share_instance {
        return InstanceMode::Standalone;
    }

    match (input.bind_succeeded, input.connect_succeeded) {
        (Some(true), _) => InstanceMode::SharedMaster,
        (Some(false), Some(true)) => InstanceMode::SharedClient,
        (Some(false), Some(false) | None) => InstanceMode::Standalone,
        (None, _) => InstanceMode::Standalone,
    }
}

/// Compute the socket path for a shared instance.
///
/// Delegates to `reticulum_interfaces::local::default_socket_path()`.
/// If `instance_name` is `None`, uses `"default"`.
#[cfg(unix)]
pub fn compute_socket_path(instance_name: Option<&str>) -> PathBuf {
    let name = instance_name.unwrap_or("default");
    reticulum_interfaces::local::default_socket_path(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn share_disabled_yields_standalone() {
        let input = DetectionInput {
            share_instance: false,
            bind_succeeded: None,
            connect_succeeded: None,
        };
        assert_eq!(decide_instance_mode(&input), InstanceMode::Standalone);
    }

    #[test]
    fn share_disabled_ignores_bind_result() {
        let input = DetectionInput {
            share_instance: false,
            bind_succeeded: Some(true),
            connect_succeeded: None,
        };
        assert_eq!(decide_instance_mode(&input), InstanceMode::Standalone);
    }

    #[test]
    fn bind_success_yields_master() {
        let input = DetectionInput {
            share_instance: true,
            bind_succeeded: Some(true),
            connect_succeeded: None,
        };
        assert_eq!(decide_instance_mode(&input), InstanceMode::SharedMaster);
    }

    #[test]
    fn bind_fail_connect_success_yields_client() {
        let input = DetectionInput {
            share_instance: true,
            bind_succeeded: Some(false),
            connect_succeeded: Some(true),
        };
        assert_eq!(decide_instance_mode(&input), InstanceMode::SharedClient);
    }

    #[test]
    fn both_fail_yields_standalone() {
        let input = DetectionInput {
            share_instance: true,
            bind_succeeded: Some(false),
            connect_succeeded: Some(false),
        };
        assert_eq!(decide_instance_mode(&input), InstanceMode::Standalone);
    }

    #[test]
    fn bind_fail_connect_not_attempted_yields_standalone() {
        let input = DetectionInput {
            share_instance: true,
            bind_succeeded: Some(false),
            connect_succeeded: None,
        };
        assert_eq!(decide_instance_mode(&input), InstanceMode::Standalone);
    }

    #[test]
    fn no_attempts_yields_standalone() {
        let input = DetectionInput {
            share_instance: true,
            bind_succeeded: None,
            connect_succeeded: None,
        };
        assert_eq!(decide_instance_mode(&input), InstanceMode::Standalone);
    }

    #[cfg(unix)]
    #[test]
    fn default_socket_path_uses_default_name() {
        let path = compute_socket_path(None);
        let expected = reticulum_interfaces::local::default_socket_path("default");
        assert_eq!(path, expected);
    }

    #[cfg(unix)]
    #[test]
    fn custom_socket_path() {
        let path = compute_socket_path(Some("mynet"));
        let expected = reticulum_interfaces::local::default_socket_path("mynet");
        assert_eq!(path, expected);
    }
}
