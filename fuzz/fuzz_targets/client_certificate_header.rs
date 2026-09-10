//! The proxy header a client certificate arrives in (RFC 8705 §2,
//! `behind_proxy` mode).
//!
//! The value is attacker-controlled by definition — any caller can set a
//! header — and what it produces is the *client's identity*. Two invariants,
//! and the first is the one that matters:
//!
//! **An untrusted peer is never believed.** Whatever the header says, a peer
//! outside `trusted_proxies` yields no certificate. The header is not even
//! parsed on that path, so the X.509 reader is unreachable from an
//! unprivileged address.
//!
//! **A trusted peer yields a certificate or nothing.** Never a panic, and
//! never an allocation proportional to something the header chose: the length
//! bound is checked before any decoding.
#![no_main]

use asterius_server::mtls::{
    DEFAULT_CERTIFICATE_HEADER, MAX_CERTIFICATE_HEADER_LEN, from_proxy_header,
};
use axum::http::{HeaderMap, HeaderName, HeaderValue};
use libfuzzer_sys::fuzz_target;
use std::net::IpAddr;

fuzz_target!(|data: &[u8]| {
    let Ok(value) = HeaderValue::from_bytes(data) else {
        return;
    };
    let mut headers = HeaderMap::new();
    headers.insert(HeaderName::from_static(DEFAULT_CERTIFICATE_HEADER), value);

    let trusted: Vec<ipnet::IpNet> = vec!["10.0.0.0/8".parse().expect("literal")];
    let spoofer: IpAddr = "203.0.113.7".parse().expect("literal");
    let proxy: IpAddr = "10.1.2.3".parse().expect("literal");

    assert!(
        from_proxy_header(spoofer, &headers, &trusted, DEFAULT_CERTIFICATE_HEADER).is_none(),
        "a header from outside trusted_proxies produced a certificate"
    );
    assert!(
        from_proxy_header(proxy, &headers, &[], DEFAULT_CERTIFICATE_HEADER).is_none(),
        "an empty trusted set believed a peer"
    );

    if let Some(presented) =
        from_proxy_header(proxy, &headers, &trusted, DEFAULT_CERTIFICATE_HEADER)
    {
        // Nothing longer than the bound can have been decoded, because the
        // bound is checked on the header before the base64 is.
        assert!(presented.leaf.as_der().len() <= MAX_CERTIFICATE_HEADER_LEN);
        // The header carries a leaf and no chain: a proxy chain would be a
        // format this server guessed at.
        assert!(presented.intermediates.is_empty());
        // Whatever came back parses as a certificate, because `from_der` is
        // what admitted it.
        assert!(presented.leaf.subject().is_some());
    }

    // A header name the deployment did not configure is not read, whoever sent
    // it: the name is a deployment fact, and a second one would be a second
    // way to assert a client's identity.
    assert!(
        from_proxy_header(proxy, &headers, &trusted, "x-some-other-header").is_none(),
        "a header nobody configured was read"
    );
});
