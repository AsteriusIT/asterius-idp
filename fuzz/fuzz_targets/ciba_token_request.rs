//! The body of a CIBA token request — CIBA Core 1.0 §10.1, §11.
//!
//! The same two layers `ciba_form` feeds: the bytes arrive as
//! `application/x-www-form-urlencoded`, become pairs, and the one parameter
//! this grant defines is read out of them. Small as the parser is, it stands in
//! front of a table a client can poll at will, and its two answers decide
//! whether a request costs a comparison or a query.
//!
//! The properties asserted are the ones nothing downstream re-checks:
//!
//! * **An accepted value is exactly what the form carried, once.** A parser
//!   that took the first of two `auth_req_id`s would let a client find out
//!   which of two credentials this server prefers (RFC 6749 §3.2).
//! * **An accepted value could have been minted here** — §7.3's charset, and
//!   this server's length — so the digest handed to the store is never of a
//!   string this server would not have issued.
//! * **The digest is the one the store holds**: the same function that minted
//!   it would produce, so a poll with a real `auth_req_id` finds its row.
//! * **The two error codes are assigned by which layer refused**: a missing or
//!   repeated parameter is `invalid_request`; a malformed credential is
//!   `invalid_grant` (§11). A client acts on the code, and the two ask for
//!   different things.
//! * **Nothing renders the credential**: a parsed request's `Debug` is a
//!   digest.
//! * **Nothing panics**, on any byte sequence, including invalid UTF-8.
#![no_main]

use asterius_domain::sha256_hex;
use asterius_oidc::ciba::{AUTH_REQ_ID_BITS, TokenRequestError, token_request};
use asterius_oidc::form::Parameters;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|body: &[u8]| {
    let Ok(text) = std::str::from_utf8(body) else {
        return;
    };

    let pairs: Vec<(String, String)> = url::form_urlencoded::parse(text.as_bytes())
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    let params = Parameters::from_pairs(pairs.clone());

    let presented: Vec<&str> = pairs
        .iter()
        .filter(|(key, _)| key == "auth_req_id")
        .map(|(_, value)| value.as_str())
        .collect();

    match token_request(&params) {
        Ok(request) => {
            // Exactly one non-empty value was sent, and it is the one accepted.
            let non_empty: Vec<&str> = presented
                .iter()
                .copied()
                .filter(|value| !value.is_empty())
                .collect();
            assert_eq!(
                non_empty.len(),
                1,
                "accepted with {} auth_req_id values",
                non_empty.len()
            );
            let value = non_empty[0];

            // §7.3's charset and this server's length: 256 bits, base64url.
            assert_eq!(value.len(), AUTH_REQ_ID_BITS.div_ceil(6));
            assert!(
                value
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_'),
                "a value outside §7.3's charset was accepted: {value:?}"
            );

            // The digest the store is asked about is the one it was given at
            // issuance.
            assert_eq!(request.auth_req_id_digest, sha256_hex(value.as_bytes()));

            // The credential never renders.
            let rendered = format!("{request:?}");
            assert!(!rendered.contains(value), "the auth_req_id rendered itself");
        }
        Err(TokenRequestError::MissingAuthReqId) => {
            assert!(
                presented.iter().all(|value| value.is_empty()),
                "a present auth_req_id was reported missing"
            );
        }
        Err(TokenRequestError::DuplicateAuthReqId) => {
            assert!(
                presented.len() > 1,
                "a single auth_req_id was reported duplicated"
            );
        }
        Err(TokenRequestError::Malformed) => {
            assert_eq!(presented.len(), 1, "malformed is a verdict on one value");
        }
    }

    // Deterministic: the same form is the same answer.
    assert_eq!(token_request(&params), token_request(&params));
});
