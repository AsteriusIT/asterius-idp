//! Working out who the client is, when something else spoke to them first.
//!
//! `X-Forwarded-For` and `Forwarded` are assertions, not facts: any client can
//! send either. They are worth believing only when the peer that sent them is
//! one we deployed, so this module resolves a client address from the socket
//! peer *and* the configured trusted proxy set, and falls back to the socket
//! peer whenever there is any doubt.
//!
//! Getting this wrong is not cosmetic. The client address feeds rate limiting
//! (`ast-p2l.3`), login abuse protection (`ast-2vk.9`) and the audit trail
//! (`ast-83p.11`); a spoofable client address means a spoofable rate-limit
//! bucket and an audit record naming the wrong person.

use axum::http::HeaderMap;
use ipnet::IpNet;
use std::net::IpAddr;

/// Where a request appears to have come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientAddr {
    /// The address to attribute the request to.
    pub ip: IpAddr,
    /// Whether a trusted proxy told us, rather than the socket.
    pub forwarded: bool,
}

/// Resolves the client address from the socket peer and any forwarding headers.
///
/// The rule is deliberately strict: the header is read only when the immediate
/// peer is inside `trusted_proxies`, and then only the entry the trusted peer
/// added — the right-most one that is not itself a trusted proxy. Walking from
/// the right is what stops a client from prepending `X-Forwarded-For: 1.2.3.4`
/// and choosing its own identity.
#[must_use]
pub fn resolve(peer: IpAddr, headers: &HeaderMap, trusted_proxies: &[IpNet]) -> ClientAddr {
    if !is_trusted(peer, trusted_proxies) {
        return ClientAddr {
            ip: peer,
            forwarded: false,
        };
    }

    let candidates: Vec<IpAddr> = forwarded_chain(headers);
    // Right to left: skip the hops we put there, and take the first address
    // that is not one of ours.
    for candidate in candidates.iter().rev() {
        if !is_trusted(*candidate, trusted_proxies) {
            return ClientAddr {
                ip: *candidate,
                forwarded: true,
            };
        }
    }
    ClientAddr {
        ip: peer,
        forwarded: false,
    }
}

fn is_trusted(ip: IpAddr, trusted_proxies: &[IpNet]) -> bool {
    trusted_proxies.iter().any(|net| net.contains(&ip))
}

/// Collects the forwarded chain, left to right, from either header spelling.
///
/// RFC 7239's `Forwarded` is preferred when present because it is the
/// standardised one; `X-Forwarded-For` is read otherwise. Values that do not
/// parse as an IP address are dropped rather than guessed at — an obfuscated
/// or malformed identifier is not something to attribute a request to.
fn forwarded_chain(headers: &HeaderMap) -> Vec<IpAddr> {
    let mut chain = Vec::new();

    let rfc7239: Vec<&str> = headers
        .get_all(axum::http::header::FORWARDED)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    if !rfc7239.is_empty() {
        for element in rfc7239.join(",").split(',') {
            for parameter in element.split(';') {
                let mut parts = parameter.splitn(2, '=');
                let (Some(key), Some(value)) = (parts.next(), parts.next()) else {
                    continue;
                };
                if !key.trim().eq_ignore_ascii_case("for") {
                    continue;
                }
                if let Some(ip) = parse_node(value.trim()) {
                    chain.push(ip);
                }
            }
        }
        return chain;
    }

    for value in headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|v| v.to_str().ok())
    {
        for hop in value.split(',') {
            if let Some(ip) = parse_node(hop.trim()) {
                chain.push(ip);
            }
        }
    }
    chain
}

/// Parses an RFC 7239 node identifier or a bare address.
///
/// Handles `"[2001:db8::1]:443"`, `192.0.2.1:443`, `_hidden` and `unknown`.
fn parse_node(raw: &str) -> Option<IpAddr> {
    let raw = raw.trim().trim_matches('"');
    if raw.is_empty() || raw.starts_with('_') || raw.eq_ignore_ascii_case("unknown") {
        return None;
    }
    // Bracketed IPv6, optionally with a port.
    if let Some(rest) = raw.strip_prefix('[') {
        let (inside, _) = rest.split_once(']')?;
        return inside.parse().ok();
    }
    if let Ok(ip) = raw.parse::<IpAddr>() {
        return Some(ip);
    }
    // Bare IPv4 with a port. A bare IPv6 with a port is ambiguous and is not
    // valid RFC 7239 anyway, so it is left to fail.
    raw.rsplit_once(':').and_then(|(host, _)| host.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("test address")
    }

    fn nets(cidrs: &[&str]) -> Vec<IpNet> {
        cidrs
            .iter()
            .map(|c| c.parse().expect("test cidr"))
            .collect()
    }

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(
                axum::http::HeaderName::from_bytes(name.as_bytes()).expect("header name"),
                HeaderValue::from_str(value).expect("header value"),
            );
        }
        map
    }

    /// The heart of it: a client that is not a trusted proxy cannot choose its
    /// own address, no matter what it claims.
    #[test]
    fn an_untrusted_peer_cannot_forge_its_address() {
        let trusted = nets(&["10.0.0.0/8"]);
        let claimed = headers(&[("x-forwarded-for", "1.2.3.4")]);
        let resolved = resolve(ip("203.0.113.7"), &claimed, &trusted);
        assert_eq!(
            resolved,
            ClientAddr {
                ip: ip("203.0.113.7"),
                forwarded: false
            }
        );
    }

    #[test]
    fn a_trusted_proxy_is_believed() {
        let trusted = nets(&["10.0.0.0/8"]);
        let forwarded = headers(&[("x-forwarded-for", "203.0.113.7")]);
        let resolved = resolve(ip("10.1.2.3"), &forwarded, &trusted);
        assert_eq!(
            resolved,
            ClientAddr {
                ip: ip("203.0.113.7"),
                forwarded: true
            }
        );
    }

    /// Two proxies in a row, and a client that prepended a lie before either of
    /// them saw the request. Walking from the right yields the address the
    /// outermost trusted proxy actually observed.
    #[test]
    fn the_chain_is_read_from_the_right_past_our_own_hops() {
        let trusted = nets(&["10.0.0.0/8", "192.168.0.0/16"]);
        let chain = headers(&[(
            "x-forwarded-for",
            "1.2.3.4, 203.0.113.7, 10.0.0.9, 192.168.1.1",
        )]);
        let resolved = resolve(ip("10.0.0.9"), &chain, &trusted);
        assert_eq!(resolved.ip, ip("203.0.113.7"));
        assert!(resolved.forwarded);
    }

    #[test]
    fn a_chain_of_nothing_but_our_own_proxies_falls_back_to_the_peer() {
        let trusted = nets(&["10.0.0.0/8"]);
        let chain = headers(&[("x-forwarded-for", "10.0.0.1, 10.0.0.2")]);
        let resolved = resolve(ip("10.0.0.2"), &chain, &trusted);
        assert_eq!(
            resolved,
            ClientAddr {
                ip: ip("10.0.0.2"),
                forwarded: false
            }
        );
    }

    #[test]
    fn rfc_7239_forwarded_is_preferred_over_the_de_facto_header() {
        let trusted = nets(&["10.0.0.0/8"]);
        let both = headers(&[
            ("forwarded", "for=203.0.113.7;proto=https"),
            ("x-forwarded-for", "1.2.3.4"),
        ]);
        assert_eq!(
            resolve(ip("10.0.0.1"), &both, &trusted).ip,
            ip("203.0.113.7")
        );
    }

    #[test]
    fn node_identifiers_with_ports_and_brackets_parse() {
        assert_eq!(parse_node("192.0.2.1"), Some(ip("192.0.2.1")));
        assert_eq!(parse_node("192.0.2.1:443"), Some(ip("192.0.2.1")));
        assert_eq!(parse_node("\"[2001:db8::1]:443\""), Some(ip("2001:db8::1")));
        assert_eq!(parse_node("[2001:db8::1]"), Some(ip("2001:db8::1")));
        assert_eq!(parse_node("2001:db8::1"), Some(ip("2001:db8::1")));
    }

    /// RFC 7239 §6.3 obfuscated identifiers, and anything else unparseable,
    /// must not be guessed at.
    #[test]
    fn obfuscated_and_malformed_nodes_are_dropped() {
        for hostile in ["_hidden", "unknown", "", "not-an-ip", "\"\""] {
            assert_eq!(parse_node(hostile), None, "accepted {hostile:?}");
        }
        let trusted = nets(&["10.0.0.0/8"]);
        let obfuscated = headers(&[("forwarded", "for=_secret")]);
        assert_eq!(
            resolve(ip("10.0.0.1"), &obfuscated, &trusted).ip,
            ip("10.0.0.1")
        );
    }

    /// With no trusted proxies configured at all, no header is ever believed.
    #[test]
    fn an_empty_trust_list_believes_nothing() {
        let claimed = headers(&[("x-forwarded-for", "1.2.3.4")]);
        let resolved = resolve(ip("10.0.0.1"), &claimed, &[]);
        assert_eq!(
            resolved,
            ClientAddr {
                ip: ip("10.0.0.1"),
                forwarded: false
            }
        );
    }

    /// A header split across several lines is one chain, not several.
    #[test]
    fn repeated_headers_are_one_chain() {
        let trusted = nets(&["10.0.0.0/8"]);
        let split = headers(&[
            ("x-forwarded-for", "203.0.113.7"),
            ("x-forwarded-for", "10.0.0.5"),
        ]);
        assert_eq!(
            resolve(ip("10.0.0.5"), &split, &trusted).ip,
            ip("203.0.113.7")
        );
    }
}
