//! Which URLs and which addresses this server will dereference.
//!
//! A `jwks_uri` is a URL a *client* wrote into its own registration, and the
//! server fetches it. That makes an outbound request an attacker can aim: at
//! the loopback interface, at a neighbour in the container network, at the
//! cloud metadata service that hands out this server's own credentials. RFC
//! 7591 §5 raises the general shape of it — an authorization server that
//! dereferences a URL from a registration document is doing work somebody else
//! asked for.
//!
//! Everything here is a pure function of a string or an address, with no I/O of
//! its own, so the rules can be table-tested exhaustively and the socket code
//! next door has nothing to decide.
//!
//! # Why the check binds to the connection, not to a lookup
//!
//! A guard that resolves a host, checks the addresses it got, and then hands
//! the *name* to a connect call has checked nothing. The resolver is free to
//! answer differently the second time, and an attacker who controls the name's
//! DNS will see to it that it does: the first answer is a public address that
//! passes, the second is `127.0.0.1`. That is DNS rebinding, and it is why most
//! SSRF allow-lists do not hold.
//!
//! The fetch in [`super::jwks`] resolves once, checks *every* address the
//! resolver returned, and then connects to one of those addresses —
//! `TcpStream::connect(SocketAddr)`, never `connect((host, port))`. After the
//! check, no name is passed to anything that could resolve it a second time, so
//! there is no second answer to poison. The name is used once more, as the TLS
//! server name, and there it is matched against a certificate rather than
//! resolved.
//!
//! # What this does not stop
//!
//! Stated plainly, because a guard whose limits are not written down gets
//! trusted for things it does not do:
//!
//! * **It does not stop a client pointing us at somebody else's public server.**
//!   That is indistinguishable from a client whose keys really are hosted
//!   elsewhere. What limits the damage is the caching in
//!   [`asterius_jose::ClientKeyCache`]: one fetch per client per minute, and a
//!   failure is remembered.
//! * **It does not see through a public address.** A host that is globally
//!   routable and proxies into a private network is a legal `jwks_uri` target
//!   as far as an address check can tell.
//! * **It does not defend an operator who gives internal services public
//!   addresses.** The address table describes the internet's reserved ranges,
//!   not one deployment's idea of "internal".
//! * **The IPv4 table is a deny-list.** IPv6 is the other way round — only
//!   global unicast is permitted — but IPv4's global space is "everything the
//!   registry has not reserved", so a *new* IANA special-purpose assignment
//!   would be reachable until the table below is updated.
//! * **It says nothing about what is listening.** It does stop the request
//!   reaching it: the connection is TLS, and a service that is not a TLS server
//!   holding a certificate for the requested name sees a `ClientHello` and
//!   nothing else.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use url::Url;

/// The longest `jwks_uri` this server will look at.
///
/// Registration stores what a client sends; this is the point where it becomes
/// a request. Nothing legitimate is close to it.
pub const MAX_URL_LEN: usize = 2048;

/// The port assumed when a `jwks_uri` names none.
pub const DEFAULT_PORT: u16 = 443;

/// A URL this server is willing to dereference, taken apart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// The host as written: a DNS name, or an IP literal that has already been
    /// checked against [`why_refused`].
    pub host: String,
    /// The port, defaulted to [`DEFAULT_PORT`].
    pub port: u16,
    /// What goes in the `Host` header.
    pub authority: String,
    /// The origin-form request target: path, and query if there is one.
    pub request_target: String,
}

/// Why a URL will not be dereferenced.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum UrlRefused {
    /// Longer than [`MAX_URL_LEN`].
    #[error("URL is {size} characters, limit is {limit}")]
    TooLong {
        /// How long it was.
        size: usize,
        /// The limit.
        limit: usize,
    },
    /// Not an absolute URL.
    #[error("not an absolute URL")]
    NotAUrl,
    /// Not `https`.
    #[error("scheme is {found:?}, must be https")]
    Scheme {
        /// The scheme offered.
        found: String,
    },
    /// Carries a userinfo component.
    #[error("must not carry a userinfo component")]
    Userinfo,
    /// Carries a fragment.
    #[error("must not carry a fragment")]
    Fragment,
    /// No host at all.
    #[error("must contain a host")]
    NoHost,
    /// A host that is not a public DNS name.
    #[error("host {host:?} is not a public DNS name")]
    HostShape {
        /// The host offered.
        host: String,
    },
    /// An IP literal in a range this server does not connect to.
    #[error("address {address} is {reason}")]
    Address {
        /// The literal.
        address: IpAddr,
        /// Which reserved range it falls in.
        reason: &'static str,
    },
}

/// Takes a client-supplied URL apart, or refuses it.
///
/// Refuses before any name resolution happens, so a URL that was never going to
/// be fetched costs no packets. An IP literal is checked here — there is no
/// resolution step to check it in later.
///
/// # Errors
///
/// Returns [`UrlRefused`] describing the first rule broken.
// fuzz-target: jwks_uri_target
pub fn check_url(raw: &str) -> Result<Target, UrlRefused> {
    if raw.len() > MAX_URL_LEN {
        return Err(UrlRefused::TooLong {
            size: raw.len(),
            limit: MAX_URL_LEN,
        });
    }
    let url = Url::parse(raw).map_err(|_| UrlRefused::NotAUrl)?;

    // OIDC Registration §2: a `jwks_uri` "MUST use the https scheme". FAPI 2.0
    // SP §5.4.2 says the same thing from the other end — a party serving a
    // `jwks_uri` "shall only serve the jwks_uri endpoint over TLS". Registration
    // already refused anything else; checked again here because this is the
    // function that opens the socket, and it must not depend on having been
    // called with something already validated.
    if url.scheme() != "https" {
        return Err(UrlRefused::Scheme {
            found: url.scheme().to_owned(),
        });
    }
    // `https://user:password@host/` is a credential we would put on the wire,
    // and `https://legitimate.example@attacker.example/` is a URL that reads as
    // one host and connects to another. Neither has any business in a
    // `jwks_uri`.
    if !url.username().is_empty() || url.password().is_some() {
        return Err(UrlRefused::Userinfo);
    }
    // A fragment is never sent to a server, so its only effect is to make two
    // spellings of one URL — and two spellings is one more than a cache key
    // should have.
    if url.fragment().is_some() {
        return Err(UrlRefused::Fragment);
    }

    let host = url.host().ok_or(UrlRefused::NoHost)?;
    let port = url.port_or_known_default().unwrap_or(DEFAULT_PORT);

    // An IP literal never reaches the resolver, so this is the only place it
    // can be checked.
    let host = match host {
        url::Host::Domain(name) => {
            // A name with no dot in it is not a name anybody can register on
            // the public internet — it is a container's service alias, a search
            // domain away from `vault` or `metadata`, or `localhost`. The
            // address check would catch where those resolve to, but refusing
            // them here refuses them for a reason an operator can read, and it
            // removes the whole class rather than the addresses it happens to
            // reach today. `https:///jwks` arrives here as the host `jwks`,
            // because WHATWG parsing reads the third slash that way, and this
            // is what stops it.
            if !name.contains('.') || name.starts_with('.') || name.ends_with('.') {
                return Err(UrlRefused::HostShape {
                    host: name.to_owned(),
                });
            }
            name.to_owned()
        }
        url::Host::Ipv4(address) => {
            refuse_address(IpAddr::V4(address))?;
            address.to_string()
        }
        url::Host::Ipv6(address) => {
            refuse_address(IpAddr::V6(address))?;
            address.to_string()
        }
    };

    let mut request_target = url.path().to_owned();
    if let Some(query) = url.query() {
        request_target.push('?');
        request_target.push_str(query);
    }

    Ok(Target {
        // `Url` has already normalised and percent-encoded the authority, so
        // this is a header value rather than an echo of what the client wrote.
        authority: url.authority().to_owned(),
        host,
        port,
        request_target,
    })
}

/// Turns a refused address into the error a caller reports.
fn refuse_address(address: IpAddr) -> Result<(), UrlRefused> {
    match why_refused(address) {
        Some(reason) => Err(UrlRefused::Address { address, reason }),
        None => Ok(()),
    }
}

/// Whether this server will open a connection to an address.
#[must_use]
pub fn is_permitted(address: IpAddr) -> bool {
    why_refused(address).is_none()
}

/// Why an address is not one this server will connect to, or `None` if it is.
///
/// The reason is a fixed string naming the range, for a log line an operator
/// can act on. It never reaches a client: to a client, every refusal is the
/// same "your keys could not be fetched", because the difference between
/// "blocked" and "unreachable" is a probe for what this server can see.
#[must_use]
pub fn why_refused(address: IpAddr) -> Option<&'static str> {
    match address {
        IpAddr::V4(address) => refuse_ipv4(address),
        IpAddr::V6(address) => refuse_ipv6(address),
    }
}

/// IPv4 ranges this server does not connect to.
///
/// The IANA IPv4 Special-Purpose Address Registry, plus multicast and the
/// class-E reserved block. A deny-list rather than an allow-list because IPv4's
/// global space is defined by subtraction: "public" means "not in this table".
///
/// `169.254.0.0/16` is the one worth naming twice. It is link-local
/// (RFC 3927), and it is where `169.254.169.254` lives — the address that hands
/// out this server's own cloud credentials to anything that asks.
const FORBIDDEN_V4: &[(Ipv4Addr, u32, &str)] = &[
    (Ipv4Addr::UNSPECIFIED, 8, "\"this network\" (0.0.0.0/8)"),
    (Ipv4Addr::new(10, 0, 0, 0), 8, "private (10.0.0.0/8)"),
    (
        Ipv4Addr::new(100, 64, 0, 0),
        10,
        "carrier-grade NAT (100.64.0.0/10)",
    ),
    (Ipv4Addr::new(127, 0, 0, 0), 8, "loopback (127.0.0.0/8)"),
    (
        Ipv4Addr::new(169, 254, 0, 0),
        16,
        "link-local, and the cloud metadata service (169.254.0.0/16)",
    ),
    (Ipv4Addr::new(172, 16, 0, 0), 12, "private (172.16.0.0/12)"),
    (
        Ipv4Addr::new(192, 0, 0, 0),
        24,
        "IETF protocol assignments (192.0.0.0/24)",
    ),
    (
        Ipv4Addr::new(192, 0, 2, 0),
        24,
        "documentation (192.0.2.0/24)",
    ),
    (
        Ipv4Addr::new(192, 31, 196, 0),
        24,
        "AS112 anycast (192.31.196.0/24)",
    ),
    (
        Ipv4Addr::new(192, 52, 193, 0),
        24,
        "AMT relay anycast (192.52.193.0/24)",
    ),
    (
        Ipv4Addr::new(192, 88, 99, 0),
        24,
        "deprecated 6to4 relay anycast (192.88.99.0/24)",
    ),
    (
        Ipv4Addr::new(192, 168, 0, 0),
        16,
        "private (192.168.0.0/16)",
    ),
    (
        Ipv4Addr::new(192, 175, 48, 0),
        24,
        "AS112 direct delegation (192.175.48.0/24)",
    ),
    (
        Ipv4Addr::new(198, 18, 0, 0),
        15,
        "benchmarking (198.18.0.0/15)",
    ),
    (
        Ipv4Addr::new(198, 51, 100, 0),
        24,
        "documentation (198.51.100.0/24)",
    ),
    (
        Ipv4Addr::new(203, 0, 113, 0),
        24,
        "documentation (203.0.113.0/24)",
    ),
    (Ipv4Addr::new(224, 0, 0, 0), 4, "multicast (224.0.0.0/4)"),
    (
        Ipv4Addr::new(240, 0, 0, 0),
        4,
        "reserved, including the broadcast address (240.0.0.0/4)",
    ),
];

fn refuse_ipv4(address: Ipv4Addr) -> Option<&'static str> {
    let value = u32::from(address);
    FORBIDDEN_V4
        .iter()
        .find(|(network, prefix, _)| {
            // A /0 would shift by 32, which is undefined for u32; no entry uses
            // one, and this keeps that true rather than assumed.
            let mask = u32::MAX.checked_shl(32 - prefix).unwrap_or(0);
            value & mask == u32::from(*network) & mask
        })
        .map(|(_, _, reason)| *reason)
}

/// IPv6 carve-outs *inside* global unicast.
///
/// Everything outside `2000::/3` is refused by default, so loopback, the
/// unspecified address, link-local `fe80::/10`, unique-local `fc00::/7` — which
/// is where AWS's IPv6 metadata address `fd00:ec2::254` lives — multicast,
/// NAT64 and the IPv4-mapped range never need an entry. These are the ranges
/// that *are* global unicast and still must not be dereferenced.
const FORBIDDEN_V6: &[(Ipv6Addr, u32, &str)] = &[
    (
        Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 0),
        32,
        "Teredo, which tunnels to an IPv4 address (2001::/32)",
    ),
    (
        Ipv6Addr::new(0x2001, 0x0002, 0, 0, 0, 0, 0, 0),
        48,
        "benchmarking (2001:2::/48)",
    ),
    (
        Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0),
        32,
        "documentation (2001:db8::/32)",
    ),
    (
        Ipv6Addr::new(0x2002, 0, 0, 0, 0, 0, 0, 0),
        16,
        "6to4, which tunnels to an IPv4 address (2002::/16)",
    ),
];

fn refuse_ipv6(address: Ipv6Addr) -> Option<&'static str> {
    // Default-deny, which IPv6 can afford: global unicast is exactly 2000::/3,
    // so everything else — loopback, link-local, unique-local, multicast, the
    // IPv4-mapped and IPv4-compatible ranges — is refused without an entry, and
    // a range invented tomorrow is refused too.
    let value = u128::from(address);
    if value >> 125 != 0b001 {
        return Some("not global unicast (outside 2000::/3)");
    }
    FORBIDDEN_V6
        .iter()
        .find(|(network, prefix, _)| {
            let mask = u128::MAX.checked_shl(128 - prefix).unwrap_or(0);
            value & mask == u128::from(*network) & mask
        })
        .map(|(_, _, reason)| *reason)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(literal: &str) -> IpAddr {
        literal.parse().expect("test address")
    }

    /// The addresses the story names, one by one. Every one of them is a place
    /// a client could otherwise send this server.
    #[test]
    fn the_reserved_ranges_are_all_refused() {
        for literal in [
            // Loopback.
            "127.0.0.1",
            "127.1.2.3",
            "::1",
            // The cloud metadata services.
            "169.254.169.254",
            "fd00:ec2::254",
            // Link-local.
            "169.254.0.1",
            "fe80::1",
            "febf:ffff::1",
            // Private and unique-local.
            "10.0.0.1",
            "10.255.255.255",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.0.1",
            "192.168.255.255",
            "fc00::1",
            "fdff:ffff::1",
            // Multicast.
            "224.0.0.1",
            "239.255.255.255",
            "ff02::1",
            // Unspecified, broadcast, and the rest of the registry.
            "0.0.0.0",
            "255.255.255.255",
            "100.64.0.1",
            "192.0.0.1",
            "198.18.0.1",
            "::",
        ] {
            assert!(
                why_refused(ip(literal)).is_some(),
                "{literal} would have been connected to"
            );
        }
    }

    /// The ranges above have edges, and an off-by-one at an edge is how
    /// `172.32.0.1` ends up blocked or `172.15.255.255` ends up reachable.
    #[test]
    fn the_edges_of_the_private_ranges_are_where_they_should_be() {
        for reachable in [
            "9.255.255.255",
            "11.0.0.0",
            "172.15.255.255",
            "172.32.0.0",
            "192.167.255.255",
            "192.169.0.0",
            "169.253.255.255",
            "169.255.0.0",
            "100.63.255.255",
            "100.128.0.0",
            "126.255.255.255",
            "128.0.0.0",
            "223.255.255.255",
        ] {
            assert!(
                is_permitted(ip(reachable)),
                "{reachable} is a public address and was refused"
            );
        }
    }

    #[test]
    fn ordinary_public_addresses_are_permitted() {
        for reachable in ["1.1.1.1", "8.8.8.8", "93.184.215.14", "2606:4700::1111"] {
            assert!(is_permitted(ip(reachable)), "{reachable} was refused");
        }
    }

    /// IPv6 is an allow-list, so a range nobody thought of is refused rather
    /// than reachable. `::ffff:127.0.0.1` is the one that matters: an
    /// IPv4-mapped loopback address is loopback.
    #[test]
    fn ipv6_refuses_everything_that_is_not_global_unicast() {
        for refused in [
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "::ffff:169.254.169.254",
            "::127.0.0.1",
            "64:ff9b::7f00:1",
            "100::1",
            "fec0::1",
            "1000::1",
        ] {
            assert!(
                why_refused(ip(refused)).is_some(),
                "{refused} would have been connected to"
            );
        }
        // Documentation and tunnelling ranges are inside 2000::/3 and need
        // their own entries.
        for refused in ["2001:db8::1", "2002:7f00:1::1", "2001::1", "2001:2::1"] {
            assert!(
                why_refused(ip(refused)).is_some(),
                "{refused} was permitted"
            );
        }
    }

    // ---- URL policy ------------------------------------------------------

    /// OIDC Registration §2: a `jwks_uri` "MUST use the https scheme". This is
    /// also what stops `file:///etc/passwd` and `http://` from being fetch
    /// targets.
    #[test]
    fn only_https_urls_are_dereferenced() {
        for refused in [
            "http://client.example/jwks",
            "file:///etc/passwd",
            "ftp://client.example/jwks",
            "gopher://client.example:70/",
            "data:application/json,{}",
            "not a url",
            "",
            "/relative/jwks",
        ] {
            assert!(check_url(refused).is_err(), "{refused} was accepted");
        }
    }

    /// A userinfo component makes a URL read as one host and connect to
    /// another, which is how a reviewer approves `https://good.example@evil`.
    #[test]
    fn a_url_carrying_userinfo_or_a_fragment_is_refused() {
        assert_eq!(
            check_url("https://good.example@evil.example/jwks"),
            Err(UrlRefused::Userinfo)
        );
        assert_eq!(
            check_url("https://user:pass@client.example/jwks"),
            Err(UrlRefused::Userinfo)
        );
        assert_eq!(
            check_url("https://client.example/jwks#keys"),
            Err(UrlRefused::Fragment)
        );
    }

    /// An IP literal skips the resolver, so it is checked at parse time or
    /// never.
    #[test]
    fn an_ip_literal_in_a_reserved_range_is_refused_at_parse_time() {
        for refused in [
            "https://127.0.0.1/jwks",
            "https://169.254.169.254/latest/meta-data/",
            "https://[::1]/jwks",
            "https://[fd00:ec2::254]/jwks",
            "https://10.0.0.1:8443/jwks",
            // Decimal and octal spellings of 127.0.0.1, which `Url` normalises
            // before this code sees them — asserted so that the normalisation
            // staying is not left to chance.
            "https://2130706433/jwks",
            "https://0177.0.0.1/jwks",
        ] {
            assert!(
                matches!(check_url(refused), Err(UrlRefused::Address { .. })),
                "{refused} was not refused as an address: {:?}",
                check_url(refused)
            );
        }
    }

    #[test]
    fn a_public_literal_is_accepted_and_keeps_its_port() {
        let target = check_url("https://93.184.215.14:8443/keys?v=2").expect("accepted");
        assert_eq!(target.host, "93.184.215.14");
        assert_eq!(target.port, 8443);
        assert_eq!(target.request_target, "/keys?v=2");
    }

    #[test]
    fn a_name_is_taken_apart_into_something_a_request_can_be_built_from() {
        let target = check_url("https://client.example/.well-known/jwks.json").expect("accepted");
        assert_eq!(target.host, "client.example");
        assert_eq!(target.port, DEFAULT_PORT);
        assert_eq!(target.authority, "client.example");
        assert_eq!(target.request_target, "/.well-known/jwks.json");

        let ported = check_url("https://client.example:8443/jwks").expect("accepted");
        assert_eq!(ported.authority, "client.example:8443");
        assert_eq!(ported.port, 8443);
    }

    #[test]
    fn an_over_long_url_is_refused_before_it_is_parsed() {
        let long = format!("https://client.example/{}", "a".repeat(MAX_URL_LEN));
        assert!(matches!(check_url(&long), Err(UrlRefused::TooLong { .. })));
    }

    /// The names that are not names. `https:///jwks` is the one worth spelling
    /// out: WHATWG parsing reads the third slash as part of the authority and
    /// hands back the *host* `jwks`, which in a container is one search domain
    /// away from an internal service.
    #[test]
    fn a_host_that_is_not_a_public_dns_name_is_refused() {
        for refused in [
            "https:///jwks",
            "https://",
            "https://localhost/jwks",
            "https://vault/v1/jwks",
            "https://metadata/computeMetadata/v1/",
            "https://client.example./jwks",
        ] {
            assert!(check_url(refused).is_err(), "{refused} was accepted");
        }
    }
}
