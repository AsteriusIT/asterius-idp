//! `Forwarded` and `X-Forwarded-For` parsing.
//!
//! These headers are attacker-controlled by definition, and their output picks
//! the rate-limit bucket and the audit identity. The invariant that matters:
//! an address is never believed from an untrusted peer, whatever the header
//! says.
#![no_main]

use asterius_server::http::forwarded;
use axum::http::{HeaderMap, HeaderName, HeaderValue};
use libfuzzer_sys::fuzz_target;
use std::net::IpAddr;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    let mut headers = HeaderMap::new();
    for (name, value) in [
        ("forwarded", text),
        ("x-forwarded-for", text),
        ("x-forwarded-host", text),
    ] {
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(value),
        ) {
            headers.append(name, value);
        }
    }

    let peer: IpAddr = "203.0.113.7".parse().expect("literal");
    let trusted = vec!["10.0.0.0/8".parse().expect("literal")];

    // Untrusted peer: the socket address wins, whatever the headers claim.
    let resolved = forwarded::resolve(peer, &headers, &trusted);
    assert_eq!(resolved.ip, peer, "an untrusted peer forged its address");
    assert!(!resolved.forwarded);

    // Trusted peer: anything may come back, but it must be a real address.
    let trusted_peer: IpAddr = "10.0.0.1".parse().expect("literal");
    let from_proxy = forwarded::resolve(trusted_peer, &headers, &trusted);
    assert!(from_proxy.ip.is_ipv4() || from_proxy.ip.is_ipv6());

    let _ = forwarded::resolve_host(trusted_peer, &headers, &trusted, None);
});
