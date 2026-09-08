//! `Issuer::parse` — RFC 8414 §2, OIDC Discovery §3.
//!
//! The issuer decides which tenant's keys sign a token, so this parser is
//! reached before authentication on every request. Two invariants beyond "does
//! not panic":
//!
//! * **Canonical output.** Whatever comes out must survive being parsed again
//!   unchanged. `iss` is compared byte-for-byte by clients, so a value that
//!   normalises differently the second time would be a value clients reject.
//! * **No escape.** An accepted issuer is https, has a host, and carries no
//!   query or fragment — the properties the rest of the server assumes without
//!   re-checking.
#![no_main]

use asterius_domain::Issuer;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    let Ok(issuer) = Issuer::parse(text) else { return };

    let canonical = issuer.as_str();
    assert!(canonical.starts_with("https://"), "accepted non-https: {canonical:?}");
    assert!(!canonical.contains('?'), "accepted a query: {canonical:?}");
    assert!(!canonical.contains('#'), "accepted a fragment: {canonical:?}");
    assert!(!canonical.ends_with('/'), "not canonical, trailing slash: {canonical:?}");
    assert!(!issuer.authority().is_empty(), "accepted an empty authority: {canonical:?}");

    let reparsed = Issuer::parse(canonical).expect("a canonical issuer must re-parse");
    assert_eq!(reparsed.as_str(), canonical, "parsing is not idempotent");
});
