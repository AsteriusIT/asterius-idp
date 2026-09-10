//! `UiLocales::parse` — OIDC Core §3.1.2.1's `ui_locales`, and the negotiation
//! that reads it.
//!
//! The parameter is attacker-chosen: it arrives on a pushed authorization
//! request, is stored in `auth_requests.parameters`, is read back when the
//! browser reaches the interaction, and decides which words a person is shown
//! while they type a password. Nothing downstream re-checks it.
//!
//! The properties asserted here are the ones the rest of the server assumes:
//!
//! * **It never refuses.** §3.1.2.1: "If the OP does not support one of the
//!   requested languages, it MUST NOT return an error." There is no error type
//!   to return, so what is fuzzed is that there is no panic and no path that
//!   fails to produce a value either.
//! * **Every kept tag is shaped like a language tag** (RFC 5646 §2.1) and is
//!   bounded — because these strings are written into a `jsonb` column and read
//!   back on the sign-in path.
//! * **Order is preserved.** The whole meaning of the parameter is "ordered by
//!   preference", so the kept tags are a subsequence of what was sent, in the
//!   sent order.
//! * **A round trip is stable.** What `as_parameter` writes back, `parse` reads
//!   as the same list: the stored form and the wire form cannot drift.
//! * **Negotiation is total and honours the order.** For any input and any
//!   `Accept-Language`, a language comes out; and if any preference names a
//!   supported language, the chosen one is the *first* such preference — the
//!   client's order outranks both the browser and the tenant.
#![no_main]

use asterius_domain::locale::{Locale, UiLocales, is_language_tag, negotiate};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: (&str, &str, bool)| {
    let (raw, accept_language, french_tenant) = data;
    let default = if french_tenant {
        Locale::French
    } else {
        Locale::English
    };

    let asked = UiLocales::parse(Some(raw));

    // Bounded, well-shaped, and a subsequence of what was sent.
    assert!(
        asked.preferences().len() <= UiLocales::MAX,
        "more preferences kept than the bound allows: {raw:?}"
    );
    let mut sent = raw.split_whitespace();
    for tag in asked.preferences() {
        assert!(
            is_language_tag(tag) && tag.len() <= UiLocales::MAX_TAG_BYTES,
            "kept a tag that is not one: {tag:?}"
        );
        assert!(
            sent.any(|candidate| candidate == tag),
            "kept a tag that was not sent, or reordered the list: {raw:?}"
        );
    }

    // The wire form and the parsed form agree.
    let rewritten = UiLocales::parse(asked.as_parameter().as_deref());
    assert_eq!(
        rewritten, asked,
        "a round trip through the parameter changed the preferences: {raw:?}"
    );

    // Negotiation is total, and the client's order wins.
    let chosen = negotiate(&asked, Some(accept_language), default);
    if let Some(first) = asked
        .preferences()
        .iter()
        .find_map(|tag| Locale::matching(tag))
    {
        assert_eq!(
            chosen, first,
            "the first supported preference did not win: {raw:?}"
        );
    }

    // With no preference at all, the answer is the browser's or the tenant's,
    // never something neither named.
    let fallback = negotiate(&UiLocales::default(), Some(accept_language), default);
    assert!(
        Locale::SUPPORTED.contains(&fallback),
        "negotiation produced a language this build does not have"
    );
});
