//! The admin API's `Origin` / `Sec-Fetch-Site` reader — ADR-0009, RFC 9700 §4.7.
//!
//! This is the second of the three CSRF layers, and it is the one that reads
//! attacker-influenced headers: a cross-site page cannot forge `Origin` or
//! `Sec-Fetch-Site`, but it *can* choose to omit them, spell them oddly, or
//! send values no browser sends, and the reader has to answer the same way
//! whatever it is handed.
//!
//! Properties:
//!
//! * **Total.** Header values are arbitrary bytes.
//! * **Fetch metadata is never overruled.** `Sec-Fetch-Site: cross-site` is a
//!   refusal whatever `Origin` says. A reader that let a matching `Origin`
//!   rescue it would be trusting the weaker of the two signals.
//! * **A foreign origin is never same-site.** This is the property the whole
//!   layer exists for.
//! * **Silence is not consent, and not refusal either.** A request that says
//!   nothing is `Unstated`, so that the synchroniser token — layer one — is
//!   what decides it. Collapsing `Unstated` into `Same` would make omitting
//!   the headers a bypass.
//! * **A CSRF check never passes without the session's token**, however the
//!   headers are spelt.
#![no_main]

use asterius_admin_api::csrf::{self, Site};
use axum::http::{HeaderMap, HeaderValue};
use libfuzzer_sys::fuzz_target;

const ORIGIN: &str = "https://as.example";

fuzz_target!(|data: &[u8]| {
    let Ok(raw) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(value) = HeaderValue::from_str(raw) else {
        // A value a browser could never send. `HeaderValue` refuses it before
        // this code sees it, which is the correct layer for that refusal.
        return;
    };

    // Every shape a request can present: the fuzzer's bytes as each header,
    // alone and beside a well-formed partner.
    let shapes: [Vec<(&str, HeaderValue)>; 5] = [
        vec![("sec-fetch-site", value.clone())],
        vec![("origin", value.clone())],
        vec![("sec-fetch-site", value.clone()), ("origin", value.clone())],
        vec![
            ("sec-fetch-site", value.clone()),
            ("origin", HeaderValue::from_static(ORIGIN)),
        ],
        vec![
            ("sec-fetch-site", HeaderValue::from_static("cross-site")),
            ("origin", value.clone()),
        ],
    ];

    for shape in shapes {
        let mut headers = HeaderMap::new();
        for (name, header) in &shape {
            headers.insert(*name, header.clone());
        }

        let verdict = csrf::site(&headers, ORIGIN);

        // Deterministic: the same headers always produce the same verdict.
        assert_eq!(
            verdict,
            csrf::site(&headers, ORIGIN),
            "the verdict is not deterministic for {shape:?}"
        );

        let fetch_site = headers
            .get("sec-fetch-site")
            .and_then(|header| header.to_str().ok())
            .map(str::trim);

        // Fetch metadata is never overruled by `Origin`.
        if matches!(fetch_site, Some("same-site" | "cross-site")) {
            assert_eq!(
                verdict,
                Site::Cross,
                "a cross-site fetch was rescued by an Origin header: {shape:?}"
            );
        }

        // Nothing but this deployment's own origin — or a browser saying so —
        // is ever same-site.
        if verdict == Site::Same {
            let origin_matches = headers
                .get("origin")
                .and_then(|header| header.to_str().ok())
                .map(str::trim)
                .is_some_and(|origin| origin.eq_ignore_ascii_case(ORIGIN));
            assert!(
                matches!(fetch_site, Some("same-origin" | "none")) || origin_matches,
                "called a request same-site with neither signal saying so: {shape:?}"
            );
        }

        // `Unstated` means the request said nothing at all. If either header is
        // present the reader must have an opinion, or omitting a value the
        // reader does not understand would be a way to reach the weaker path.
        if verdict == Site::Unstated {
            assert!(
                headers.get("origin").is_none(),
                "an Origin header produced no verdict: {shape:?}"
            );
        }

        // The whole check: no spelling of these headers admits a mutation
        // without the session's own token.
        assert!(
            csrf::check(&headers, "a-session-id", ORIGIN).is_err(),
            "a request with no X-CSRF-Token was admitted: {shape:?}"
        );

        // And the session's own token is accepted unless the browser said the
        // request came from somewhere else.
        headers.insert(
            csrf::HEADER,
            HeaderValue::from_str(&csrf::token("a-session-id")).expect("a hex digest"),
        );
        assert_eq!(
            csrf::check(&headers, "a-session-id", ORIGIN).is_ok(),
            verdict != Site::Cross,
            "the check and the verdict disagree for {shape:?}"
        );

        // Another session's token is never accepted, whatever the headers say.
        headers.insert(
            csrf::HEADER,
            HeaderValue::from_str(&csrf::token("another-session")).expect("a hex digest"),
        );
        assert!(
            csrf::check(&headers, "a-session-id", ORIGIN).is_err(),
            "another session's token was accepted: {shape:?}"
        );
    }
});
