//! Network interface enumeration for IPv6 link-local addresses.
//!
//! Wraps platform-specific APIs (`getifaddrs` on Unix) to discover which
//! network interfaces have IPv6 link-local (fe80::/10) addresses.

use std::collections::HashMap;
use std::net::Ipv6Addr;

/// A discovered network interface with its IPv6 link-local address.
#[derive(Debug, Clone)]
pub struct Ipv6Interface {
    /// OS interface name (e.g. "en0", "eth0").
    pub name: String,
    /// IPv6 link-local address (fe80::/10) without scope suffix.
    pub addr: Ipv6Addr,
    /// OS interface index (for `IPV6_MULTICAST_IF`, `IPV6_JOIN_GROUP`).
    pub if_index: u32,
}

/// Platform-specific interface names that should be ignored by default.
#[cfg(target_os = "macos")]
const PLATFORM_IGNORE_IFS: &[&str] = &["awdl0", "llw0", "lo0", "en5"];

#[cfg(target_os = "linux")]
const PLATFORM_IGNORE_IFS: &[&str] = &["lo"];

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
const PLATFORM_IGNORE_IFS: &[&str] = &["lo0"];

/// Enumerate all network interfaces with IPv6 link-local addresses.
///
/// Returns one entry per interface. If an interface has multiple link-local
/// addresses, only the first one found is returned (matching Python behavior).
///
/// Interfaces in `PLATFORM_IGNORE_IFS` or `ignored` are skipped.
/// If `allowed` is non-empty, only those interface names are considered.
pub fn enumerate_ipv6_interfaces(
    allowed: &[String],
    ignored: &[String],
) -> std::io::Result<Vec<Ipv6Interface>> {
    let addrs = nix::ifaddrs::getifaddrs().map_err(std::io::Error::other)?;

    // Collect: ifname → (Ipv6Addr, if_index). First link-local wins per interface.
    let mut seen: HashMap<String, (Ipv6Addr, u32)> = HashMap::new();

    for ifaddr in addrs {
        let ifname = ifaddr.interface_name.clone();

        // Skip platform-ignored interfaces (unless explicitly allowed).
        if PLATFORM_IGNORE_IFS.contains(&ifname.as_str()) && !allowed.contains(&ifname) {
            continue;
        }

        // Skip user-ignored interfaces.
        if ignored.contains(&ifname) {
            continue;
        }

        // If allowlist is non-empty, skip interfaces not in it.
        if !allowed.is_empty() && !allowed.contains(&ifname) {
            continue;
        }

        // Already have a link-local for this interface.
        if seen.contains_key(&ifname) {
            continue;
        }

        // Check for IPv6 link-local address.
        if let Some(sock_addr) = ifaddr.address
            && let Some(sin6) = sock_addr.as_sockaddr_in6()
        {
            let ip = sin6.ip();
            if is_link_local(ip) {
                let if_index = nix::net::if_::if_nametoindex(ifname.as_str())
                    .map_err(std::io::Error::other)?;
                seen.insert(ifname, (ip, if_index));
            }
        }
    }

    let mut result: Vec<Ipv6Interface> = seen
        .into_iter()
        .map(|(name, (addr, if_index))| Ipv6Interface {
            name,
            addr,
            if_index,
        })
        .collect();

    // Sort by name for deterministic ordering.
    result.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(result)
}

/// Check whether an IPv6 address is link-local (fe80::/10).
fn is_link_local(addr: Ipv6Addr) -> bool {
    let octets = addr.octets();
    octets[0] == 0xFE && (octets[1] & 0xC0) == 0x80
}

/// Strip the `%ifname` scope suffix from an IPv6 link-local address string.
///
/// Also handles the BSD-style embedded scope (e.g. `fe80:1::...` → `fe80::...`).
pub fn descope_link_local(addr: &str) -> String {
    // Drop %ifname suffix (macOS/Linux).
    let without_scope = addr.split('%').next().unwrap_or(addr);

    // Drop embedded scope specifier (NetBSD, OpenBSD): fe80:XXXX:: → fe80::
    // Pattern: fe80: followed by hex digits, then ::
    if let Some(rest) = without_scope.strip_prefix("fe80:")
        && let Some(pos) = rest.find("::")
    {
        let between = &rest[..pos];
        // If the part between "fe80:" and "::" is pure hex, it's an embedded scope.
        if !between.is_empty() && between.chars().all(|c| c.is_ascii_hexdigit()) {
            return format!("fe80::{}", &rest[pos + 2..]);
        }
    }

    without_scope.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descope_removes_percent_suffix() {
        assert_eq!(descope_link_local("fe80::1%en0"), "fe80::1");
        assert_eq!(
            descope_link_local("fe80::abcd:1234%eth0"),
            "fe80::abcd:1234"
        );
    }

    #[test]
    fn descope_removes_embedded_scope() {
        // NetBSD/OpenBSD style: fe80:1::abcd → fe80::abcd
        assert_eq!(descope_link_local("fe80:1::abcd"), "fe80::abcd");
        assert_eq!(descope_link_local("fe80:a::1"), "fe80::1");
    }

    #[test]
    fn descope_preserves_normal_addresses() {
        assert_eq!(descope_link_local("fe80::1"), "fe80::1");
        assert_eq!(
            descope_link_local("fe80::abcd:ef01:2345:6789"),
            "fe80::abcd:ef01:2345:6789"
        );
    }

    #[test]
    fn descope_handles_both() {
        // Scope suffix takes precedence (split on %).
        assert_eq!(descope_link_local("fe80:1::abcd%en0"), "fe80::abcd");
    }

    #[test]
    fn descope_non_link_local_unchanged() {
        // Non-link-local addresses should pass through unchanged
        assert_eq!(descope_link_local("2001:db8::1"), "2001:db8::1");
        assert_eq!(descope_link_local("::1"), "::1");
        assert_eq!(descope_link_local("ff02::1"), "ff02::1");
    }

    #[test]
    fn descope_empty_string() {
        assert_eq!(descope_link_local(""), "");
    }

    #[test]
    fn is_link_local_check() {
        assert!(is_link_local("fe80::1".parse().unwrap()));
        assert!(is_link_local("fe80::abcd:1234:5678:9abc".parse().unwrap()));
        assert!(!is_link_local("::1".parse().unwrap()));
        assert!(!is_link_local("2001:db8::1".parse().unwrap()));
        assert!(!is_link_local("ff02::1".parse().unwrap()));
    }
}
