//! Multicast address derivation and discovery token generation/verification.
//!
//! The multicast address is derived from the SHA-256 hash of the group ID.
//! The discovery token is SHA-256(group_id || link_local_addr_utf8).

use std::net::Ipv6Addr;

use reticulum_crypto::sha::sha256;

use super::{DiscoveryScope, MulticastAddressType};

/// Derive the IPv6 multicast discovery address from a group ID.
///
/// Algorithm (matching Python reference byte-for-byte):
/// ```text
/// g = SHA-256(group_id)
/// address = ff{type}{scope}:0:{g[2]g[3]}:{g[4]g[5]}:{g[6]g[7]}:{g[8]g[9]}:{g[10]g[11]}:{g[12]g[13]}
/// ```
///
/// Each pair `g[even]g[odd]` forms a big-endian u16 network-order segment.
pub fn derive_multicast_address(
    group_id: &[u8],
    scope: DiscoveryScope,
    addr_type: MulticastAddressType,
) -> Ipv6Addr {
    let g = sha256(group_id);

    // Build the 16-byte IPv6 address manually.
    // Byte layout of an IPv6 address: 16 octets.
    //
    // Octets 0-1: ff{type}{scope} → 0xFF, (type_nibble << 4 | scope_nibble)
    // Octets 2-3: 0x0000 (the "0" group in the Python format string)
    // Octets 4-5:   g[2], g[3]
    // Octets 6-7:   g[4], g[5]
    // Octets 8-9:   g[6], g[7]
    // Octets 10-11: g[8], g[9]
    // Octets 12-13: g[10], g[11]
    // Octets 14-15: g[12], g[13]

    let type_nibble = match addr_type {
        MulticastAddressType::Permanent => 0x0u8,
        MulticastAddressType::Temporary => 0x1u8,
    };
    let scope_nibble = match scope {
        DiscoveryScope::Link => 0x2u8,
        DiscoveryScope::Admin => 0x4u8,
        DiscoveryScope::Site => 0x5u8,
        DiscoveryScope::Organisation => 0x8u8,
        DiscoveryScope::Global => 0xEu8,
    };

    let octets: [u8; 16] = [
        0xFF,
        (type_nibble << 4) | scope_nibble,
        0x00,
        0x00,
        g[2],
        g[3],
        g[4],
        g[5],
        g[6],
        g[7],
        g[8],
        g[9],
        g[10],
        g[11],
        g[12],
        g[13],
    ];

    Ipv6Addr::from(octets)
}

/// Generate a 32-byte discovery token for announcing presence.
///
/// `token = SHA-256(group_id || link_local_addr_string)`
pub fn generate_discovery_token(group_id: &[u8], link_local_addr: &str) -> [u8; 32] {
    let mut input = Vec::with_capacity(group_id.len() + link_local_addr.len());
    input.extend_from_slice(group_id);
    input.extend_from_slice(link_local_addr.as_bytes());
    sha256(&input)
}

/// Verify a received discovery token against an expected sender address.
///
/// Returns `true` if the token matches `SHA-256(group_id || sender_addr_string)`.
pub fn verify_discovery_token(token: &[u8], group_id: &[u8], sender_addr: &str) -> bool {
    if token.len() != 32 {
        return false;
    }
    let expected = generate_discovery_token(group_id, sender_addr);
    // Constant-time comparison not needed here — tokens are not secrets.
    token == expected
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multicast_address_derivation_default_group() {
        // Derive the multicast address for the default "reticulum" group
        // with Temporary type and Link scope (the Python defaults).
        let addr = derive_multicast_address(
            b"reticulum",
            DiscoveryScope::Link,
            MulticastAddressType::Temporary,
        );

        // Verify the prefix bytes: ff12:0:...
        let octets = addr.octets();
        assert_eq!(octets[0], 0xFF);
        assert_eq!(octets[1], 0x12); // type=1, scope=2

        // Verify the zero group (octets 2-3).
        assert_eq!(octets[2], 0x00);
        assert_eq!(octets[3], 0x00);

        // Verify against independently computed SHA-256 of b"reticulum".
        let g = reticulum_crypto::sha::sha256(b"reticulum");
        assert_eq!(octets[4], g[2]);
        assert_eq!(octets[5], g[3]);
        assert_eq!(octets[6], g[4]);
        assert_eq!(octets[7], g[5]);
        assert_eq!(octets[8], g[6]);
        assert_eq!(octets[9], g[7]);
        assert_eq!(octets[10], g[8]);
        assert_eq!(octets[11], g[9]);
        assert_eq!(octets[12], g[10]);
        assert_eq!(octets[13], g[11]);
        assert_eq!(octets[14], g[12]);
        assert_eq!(octets[15], g[13]);

        // Also verify the string representation matches the Python format.
        // Python builds: "ff12:0:{g[3]+(g[2]<<8)}:{g[5]+(g[4]<<8)}:..."
        // which is the same as big-endian u16 groups from consecutive bytes.
        let addr_str = addr.to_string();
        assert!(addr_str.starts_with("ff12:"), "got: {addr_str}");
    }

    #[test]
    fn multicast_address_different_scopes() {
        let link = derive_multicast_address(
            b"test",
            DiscoveryScope::Link,
            MulticastAddressType::Temporary,
        );
        let site = derive_multicast_address(
            b"test",
            DiscoveryScope::Site,
            MulticastAddressType::Temporary,
        );
        let global = derive_multicast_address(
            b"test",
            DiscoveryScope::Global,
            MulticastAddressType::Permanent,
        );

        assert_eq!(link.octets()[1], 0x12);
        assert_eq!(site.octets()[1], 0x15);
        assert_eq!(global.octets()[1], 0x0E);

        // Same group → same hash-derived segments.
        assert_eq!(link.octets()[4..], site.octets()[4..]);
    }

    #[test]
    fn discovery_token_roundtrip() {
        let group_id = b"reticulum";
        let addr = "fe80::1";

        let token = generate_discovery_token(group_id, addr);
        assert_eq!(token.len(), 32);
        assert!(verify_discovery_token(&token, group_id, addr));
    }

    #[test]
    fn discovery_token_wrong_address() {
        let group_id = b"reticulum";
        let token = generate_discovery_token(group_id, "fe80::1");
        assert!(!verify_discovery_token(&token, group_id, "fe80::2"));
    }

    #[test]
    fn discovery_token_wrong_group() {
        let token = generate_discovery_token(b"group-a", "fe80::1");
        assert!(!verify_discovery_token(&token, b"group-b", "fe80::1"));
    }

    #[test]
    fn discovery_token_short_data() {
        assert!(!verify_discovery_token(&[0u8; 16], b"reticulum", "fe80::1"));
        assert!(!verify_discovery_token(&[], b"reticulum", "fe80::1"));
    }
}
