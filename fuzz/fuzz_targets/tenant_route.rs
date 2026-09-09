//! `tenancy::route` — the first thing every request path meets.
//!
//! It runs before authentication and its output selects a tenant, so the
//! invariants are about what it may hand downstream: a tenant id that cannot
//! escape a path segment, and a rewritten path that is still a path.
#![no_main]

use asterius_oidc::tenancy;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(route) = tenancy::route(text) else {
        return;
    };

    assert!(
        route.path.starts_with('/'),
        "rewrote to a non-path: {:?}",
        route.path
    );
    // Segment-wise, not a substring check: `/t../x` contains ".." but has no
    // relative segment, and a file called `t..` is a perfectly ordinary name.
    // The first version of this assertion used `contains("..")` and the fuzzer
    // rightly found `/t../t/`.
    assert!(
        !route
            .path
            .split('/')
            .any(|segment| segment == "." || segment == ".."),
        "rewrote to a path with a relative segment: {:?}",
        route.path
    );

    if let Some(tenant) = &route.tenant {
        let id = tenant.as_str();
        assert!(!id.is_empty());
        assert!(id.len() <= 64, "tenant id too long: {id:?}");
        assert!(
            id.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_'),
            "tenant id escaped its character set: {id:?}"
        );
    }
});
