//! The interaction cookie parser — FAPI 2.0 SP §6.5.
//!
//! The cookie is one half of the pair that identifies a browser's claim on an
//! authorization flow; the other half is in the URL. A parser that is too
//! generous here throws away the `__Host-` prefix's browser-enforced
//! guarantees, and a parser that resolves ambiguity picks a winner an attacker
//! can choose.
//!
//! Properties:
//!
//! * **Only the exact name counts.** Accepting `asterius_ix`, or a differently
//!   cased `__host-`, would honour a cookie a sibling subdomain can set.
//! * **A repeated cookie is refused, never resolved.** Same reasoning as
//!   RFC 6749 §3.1 for form parameters: if two parties disagree about which
//!   copy counts, one request is validated and another runs.
//! * **Whatever comes back matches only itself.** The comparison is constant
//!   time, and an id parsed out of a header must equal the same id and no
//!   other.
//! * **Total.** A `Cookie` header is attacker-controlled and arbitrary bytes;
//!   parsing one must not panic.
#![no_main]

use asterius_web::interaction::{COOKIE_NAME, InteractionId, id_from_cookie_header};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(header) = std::str::from_utf8(data) else {
        return;
    };

    // The raw header, plus the same bytes dressed as a value of the real
    // cookie, so the target spends its budget on the parser rather than on
    // failing to find the name at all.
    let known = InteractionId::generate();
    let candidates = [
        header.to_owned(),
        format!("{COOKIE_NAME}={header}"),
        format!("{COOKIE_NAME}={}; {header}", known.expose()),
        format!("{header}; {COOKIE_NAME}={}", known.expose()),
    ];

    for candidate in &candidates {
        let Some(parsed) = id_from_cookie_header(candidate) else {
            continue;
        };

        // Accepting implies the exact name appeared. Nothing else may produce
        // an id.
        assert!(
            candidate.contains(COOKIE_NAME),
            "parsed an id from a header with no {COOKIE_NAME}: {candidate:?}"
        );

        // Never empty: an empty cookie is not an id, and treating it as one
        // would make every browser that sends `__Host-asterius_ix=` look like
        // the same interaction.
        assert!(!parsed.expose().is_empty(), "parsed an empty id");

        // Deterministic.
        let again = id_from_cookie_header(candidate).expect("parsed once, must parse twice");
        assert!(parsed.matches(&again), "parsing is not deterministic");

        // An id matches itself and not a freshly minted one. `generate` has
        // 256 bits, so a collision here is a broken generator rather than bad
        // luck.
        let other = InteractionId::generate();
        assert!(
            !parsed.matches(&other),
            "a parsed id matched an unrelated one"
        );
    }

    // A header with two of our cookies is always refused, however the fuzzer
    // spells the rest of it.
    let doubled = format!(
        "{COOKIE_NAME}={}; {COOKIE_NAME}={}; {header}",
        known.expose(),
        InteractionId::generate().expose()
    );
    assert!(
        id_from_cookie_header(&doubled).is_none(),
        "resolved two interaction cookies rather than refusing: {doubled:?}"
    );
});
