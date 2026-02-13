//! Access policy enforcement for request handlers.

use reticulum_core::types::IdentityHash;

use super::constants::AccessPolicy;

/// Check whether a remote peer is allowed to invoke a request handler.
pub fn check_access(
    policy: AccessPolicy,
    remote: Option<&IdentityHash>,
    allowed: &[IdentityHash],
) -> bool {
    match policy {
        AccessPolicy::AllowNone => false,
        AccessPolicy::AllowAll => true,
        AccessPolicy::AllowList => match remote {
            Some(identity) => allowed.iter().any(|a| a == identity),
            None => false,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_vectors() {
        let vectors = reticulum_test_vectors::requests::load();
        for tv in &vectors.policy_vectors {
            let policy = AccessPolicy::from_u8(tv.policy as u8)
                .unwrap_or_else(|| panic!("invalid policy {} at index={}", tv.policy, tv.index));

            let remote = tv.remote_identity_hash.as_ref().map(|hex| {
                let bytes = hex::decode(hex).unwrap();
                IdentityHash::try_from(bytes.as_slice()).unwrap()
            });

            let allowed: Vec<IdentityHash> = tv
                .allowed_list
                .as_ref()
                .map(|list| {
                    list.iter()
                        .map(|hex| {
                            let bytes = hex::decode(hex).unwrap();
                            IdentityHash::try_from(bytes.as_slice()).unwrap()
                        })
                        .collect()
                })
                .unwrap_or_default();

            let result = check_access(policy, remote.as_ref(), &allowed);
            assert_eq!(
                result, tv.expected_allowed,
                "index={}: policy={:?}, remote={:?}, expected={}, got={}",
                tv.index, policy, tv.remote_identity_hash, tv.expected_allowed, result,
            );
        }
    }
}
