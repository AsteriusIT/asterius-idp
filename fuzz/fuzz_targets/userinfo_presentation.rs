//! How an access token may be presented at UserInfo — RFC 6750 §2–3,
//! RFC 9449 §7.1, FAPI 2.0 SP §5.3.4.
//!
//! `present` is the first thing an unauthenticated request reaches, and every
//! byte it reads was chosen by whoever sent it. The properties:
//!
//! * **Nothing accepts a token from the query string.** FAPI 2.0 SP §5.3.4:
//!   "shall not accept access tokens in the query parameters". A query naming
//!   `access_token` must refuse whatever the headers say, so that the refusal
//!   cannot be arranged away by also sending a good header.
//! * **An accepted credential is `token68`.** RFC 7235 §2.1. No spaces, no
//!   commas, no control characters — a value with one of those in it is two
//!   header fields that arrived as one, and accepting it would let a client
//!   and this server disagree about where the credential ends.
//! * **An accepted credential is a substring of the header**, so the parser
//!   returns what arrived rather than something it assembled.
//! * **Every refusal is one of RFC 6750 §3.1's three codes**, with the status
//!   that section gives it.
//! * **Parsing is total.** No input panics.
#![no_main]

use arbitrary::Arbitrary;
use asterius_oidc::userinfo::{self, Presentation, UserInfoError};
use libfuzzer_sys::fuzz_target;

/// RFC 6750 §3.1's codes, and nothing else.
const PERMITTED_CODES: &[&str] = &["invalid_request", "invalid_token", "insufficient_scope"];

#[derive(Arbitrary, Debug)]
struct Input {
    /// The `Authorization` header values, in order. Empty is "no credential",
    /// two is the repeated-header case.
    authorizations: Vec<String>,
    /// The raw query string, when there is one.
    query: Option<String>,
    /// The `scope` claim of a token that got as far as the scope check.
    scope: Option<String>,
}

fuzz_target!(|input: Input| {
    let headers: Vec<&str> = input.authorizations.iter().map(String::as_str).collect();
    let query = input.query.as_deref();

    match userinfo::present(&headers, query) {
        Ok(presented) => {
            // FAPI 2.0 SP §5.3.4: no query string ever produces a token.
            if let Some(query) = query {
                assert!(
                    !url::form_urlencoded::parse(query.as_bytes())
                        .any(|(name, _)| name == userinfo::QUERY_PARAMETER),
                    "accepted a presentation beside a query-string access token: {query:?}"
                );
            }

            let token = presented.token();
            assert!(!token.is_empty(), "accepted an empty credential");
            assert!(
                !token.contains(|c: char| c.is_whitespace() || c == ','),
                "accepted a credential that is not token68: {token:?}"
            );
            assert!(
                token.len() <= userinfo::MAX_CREDENTIAL_BYTES,
                "accepted an oversized credential"
            );

            // Exactly one header, and the credential came out of it.
            assert_eq!(headers.len(), 1, "accepted more than one Authorization");
            assert!(
                headers[0].ends_with(token),
                "returned a credential the header does not end with: {token:?}"
            );

            // The scheme is one of the two, matched case-insensitively.
            let scheme = headers[0].split(' ').next().unwrap_or_default();
            match presented {
                Presentation::Dpop(_) => assert!(scheme.eq_ignore_ascii_case("dpop")),
                Presentation::Bearer(_) => assert!(scheme.eq_ignore_ascii_case("bearer")),
            }
        }
        Err(refusal) => {
            assert!(
                PERMITTED_CODES.contains(&refusal.code()),
                "invented an error code: {}",
                refusal.code()
            );
            assert!(
                [400, 401, 403].contains(&refusal.status()),
                "unexpected status {}",
                refusal.status()
            );
            // The description is a constant per variant; nothing from the
            // request may reach a response header.
            assert!(!refusal.description().is_empty());

            // A query-string token is refused before anything else is read, so
            // it is the only refusal such a request can produce.
            if query.is_some_and(|query| {
                url::form_urlencoded::parse(query.as_bytes())
                    .any(|(name, _)| name == userinfo::QUERY_PARAMETER)
            }) {
                assert_eq!(refusal, UserInfoError::TokenInQuery);
            }
        }
    }

    // The scope check, over the same arbitrary input: `openid` and nothing
    // that merely looks like it (OIDC Core §5.3.1).
    let scope = input.scope.as_deref();
    let accepted = userinfo::check_scope(scope).is_ok();
    let carries_openid = scope
        .unwrap_or_default()
        .split(' ')
        .any(|value| value == userinfo::REQUIRED_SCOPE);
    assert_eq!(
        accepted, carries_openid,
        "scope {scope:?} was judged {accepted}"
    );

    // Every challenge is a well-formed header value: one line, printable.
    for challenge in userinfo::challenges(None) {
        assert!(
            !challenge.contains(['\r', '\n', '\0']),
            "a challenge carries a control character: {challenge:?}"
        );
    }
});
