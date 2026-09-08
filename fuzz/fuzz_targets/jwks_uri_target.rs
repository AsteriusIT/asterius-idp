//! The SSRF guard's URL half, over arbitrary strings.
//!
//! A `jwks_uri` is a string a client wrote, and this is the function that turns
//! it into a host, a port and a request line. The invariants are the ones that
//! would be a vulnerability rather than a bug:
//!
//! * An accepted URL is always `https`, and its host is never an IP literal in
//!   a range the guard refuses. Nothing may pass the URL check and then need
//!   the address check to save it.
//! * The pieces that become a request are usable as header and URI values.
//!   `Host: {authority}` with a CR or LF in it is request splitting, and the
//!   fact that `Url` percent-encodes them is a property worth asserting rather
//!   than trusting.
#![no_main]

use asterius_server::outbound::ssrf;
use axum::http::{HeaderValue, Uri};
use libfuzzer_sys::fuzz_target;
use std::net::IpAddr;

fuzz_target!(|data: &[u8]| {
    let Ok(raw) = std::str::from_utf8(data) else {
        return;
    };

    let Ok(target) = ssrf::check_url(raw) else {
        return;
    };

    // An IP literal that survived the URL check is one the address check
    // permits: there is no resolution step to catch it later.
    if let Ok(literal) = target.host.parse::<IpAddr>() {
        assert!(
            ssrf::is_permitted(literal),
            "{literal} passed the URL check and would have been connected to"
        );
    }

    // Nothing that reaches the request builder can carry a control character.
    assert!(
        HeaderValue::from_str(&target.authority).is_ok(),
        "an authority that cannot be a header value: {:?}",
        target.authority
    );
    assert!(
        target.request_target.parse::<Uri>().is_ok(),
        "a request target that is not a URI: {:?}",
        target.request_target
    );
    assert!(!target.authority.contains(['\r', '\n', ' ']));
    assert!(!target.request_target.contains(['\r', '\n', ' ']));
});
