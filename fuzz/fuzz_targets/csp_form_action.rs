//! `FormActionOrigin::parse` — the one attacker-supplied string that reaches a
//! Content-Security-Policy.
//!
//! Everything else in the policy is a literal. A client's registered
//! `redirect_uri` origin is not, and it is interpolated into a header that a
//! browser parses as a security policy — so the invariant is not "does not
//! panic" but "cannot mean anything". An accepted origin must be unable to
//! close a directive, open another, add a source expression, or split the
//! response: whatever survives parsing has to render into a policy with the
//! same shape as the policy with no origin at all.
#![no_main]

use asterius_web::csp::{FormActionOrigin, Nonce, Policy};
use axum::http::HeaderValue;
use libfuzzer_sys::fuzz_target;

/// Ten directives, so nine separators. A rendered policy with a tenth has
/// grown a directive, which is the only interesting thing an origin could do.
const SEPARATORS: usize = 9;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(origin) = FormActionOrigin::parse(text) else {
        return;
    };

    // Nothing is rewritten (ADR-0005): what was registered is what is served,
    // and it re-parses to itself, so the two sides cannot drift.
    assert_eq!(origin.as_str(), text, "the origin was rewritten");
    assert!(FormActionOrigin::parse(origin.as_str()).is_ok());

    let nonce = Nonce::generate();
    let strict = Policy::strict().header_value(&nonce);
    let widened = Policy::strict()
        .with_form_post_to(origin.clone())
        .header_value(&nonce);

    // The origin adds one source expression to one directive, and nothing else.
    assert_eq!(
        widened.matches(';').count(),
        SEPARATORS,
        "the origin added a directive: {widened:?}"
    );
    assert_eq!(strict.matches(';').count(), SEPARATORS);
    assert!(
        widened.contains(&format!("form-action 'self' {};", origin.as_str())),
        "the origin did not land in form-action: {widened:?}"
    );

    // A header value that could carry CR, LF or NUL is a response-splitting
    // primitive; one with a stray quote is a source expression nobody wrote.
    assert!(
        widened.bytes().all(|byte| (0x20..0x7f).contains(&byte)),
        "the policy left printable ASCII: {widened:?}"
    );
    assert_eq!(
        widened.matches('\'').count(),
        strict.matches('\'').count(),
        "the origin added a quoted source: {widened:?}"
    );
    assert!(HeaderValue::try_from(widened.clone()).is_ok());

    // The directives an injected origin would want to reach are still there,
    // and still say 'none'.
    for untouched in [
        "default-src 'none'",
        "frame-ancestors 'none'",
        "base-uri 'none'",
        "object-src 'none'",
        "'strict-dynamic'",
    ] {
        assert!(widened.contains(untouched), "{untouched} lost: {widened:?}");
    }
    // The *quoted* form, because that is the only form that is a keyword.
    // CSP Level 3 §2.3.1 spells the dangerous sources 'unsafe-inline',
    // 'unsafe-eval' and 'unsafe-hashes', always inside single quotes; a
    // host-source is never quoted. Unquoted, `unsafe-` is just letters and a
    // hyphen — every one of them a legal host-char — so `unsafe-thing.example`
    // is a domain somebody can register and register as a redirect_uri, and
    // refusing it here would be this assertion inventing a rule CSP does not
    // have. What actually forecloses an injected keyword is the quote count
    // asserted above: a widened policy has exactly as many `'` as the strict
    // one, so no new quoted token can have appeared.
    assert!(!widened.contains("'unsafe-"), "{widened:?}");
    assert!(!widened.contains('*'), "{widened:?}");
});
