//! `introspection::parse` and `introspection::describe` — the two halves of
//! RFC 7662 that read something somebody else wrote.
//!
//! The request body arrives from a resource server that has authenticated but
//! is otherwise untrusted, and the claim set the response is projected from
//! arrives inside a token. Four properties are worth a fuzzer rather than a
//! unit test:
//!
//! * **Neither panics.** The body is form-encoded bytes and the claims are
//!   arbitrary JSON; a panic on either is a 500 an attacker composes.
//! * **A parsed request is within the bound.** [`MAX_TOKEN_LEN`] is what
//!   stands in front of the hashing and base64 decoding the classifier does,
//!   so a value past it must never come back as a request.
//! * **`parse` never invents a token.** What comes out is a borrow of what
//!   went in, and it is never empty: an empty `token` is `MissingToken`, not a
//!   lookup key.
//! * **`describe` publishes a closed set of members, and never says
//!   `active: false`.** The projection is the only thing standing between the
//!   claims this server signs — roles, `amr`, whatever it learns next — and a
//!   third-party resource server. A claim that could smuggle itself through
//!   under a §2.2 member's name, or one that could flip `active`, would be a
//!   response asserting something no signature covers.
#![no_main]

use asterius_oidc::form::Parameters;
use asterius_oidc::introspection::{
    BEARER, IntrospectionError, IntrospectionResponse, MAX_TOKEN_LEN, describe, parse,
};
use libfuzzer_sys::fuzz_target;
use serde_json::Value;

/// RFC 7662 §2.2's members, plus RFC 9449 §6.2's `cnf`, RFC 8693 §4's `act`,
/// RFC 9396 §9.2's `authorization_details` and the private `grant_id`.
///
/// Written out here rather than imported: the point of the assertion is that
/// the published set is the one a reader of the specifications agreed to, and
/// a list imported from the code under test would agree with itself whatever
/// it said.
const PUBLISHABLE: &[&str] = &[
    "act",
    "active",
    "aud",
    "authorization_details",
    "client_id",
    "cnf",
    "exp",
    "grant_id",
    "iat",
    "iss",
    "jti",
    "nbf",
    "scope",
    "sub",
    "token_type",
];

fuzz_target!(|data: (String, String, bool)| {
    let (body, raw_claims, grant_id) = data;

    // Arbitrary JSON where the input is JSON, and otherwise an object whose
    // *member name* the fuzzer chose — which is the case worth reaching, since
    // the projection is a list of names and the question is whether a name
    // nobody put on it can be published.
    let claims: Value = serde_json::from_str(&raw_claims).unwrap_or_else(|_| {
        serde_json::json!({
            raw_claims.clone(): "chosen by the caller",
            "sub": raw_claims,
        })
    });

    // --- the request (§2.1) ---
    let pairs: Vec<(String, String)> = url::form_urlencoded::parse(body.as_bytes())
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    let params = Parameters::from_pairs(pairs);

    match parse(&params) {
        Ok(request) => {
            assert!(
                !request.token.is_empty(),
                "an empty token parsed as a request: {body:?}"
            );
            assert!(
                request.token.len() <= MAX_TOKEN_LEN,
                "a token past the bound parsed as a request"
            );
            // The token is handed on to the classifier, which hashes it and
            // decodes base64 out of it. It must be what arrived and nothing
            // else.
            assert!(
                body.contains(request.token) || body.contains('%') || body.contains('+'),
                "a token appeared that the body did not contain: {:?}",
                request.token
            );
        }
        Err(IntrospectionError::Duplicated(name)) => {
            assert!(
                name == "token" || name == "token_type_hint",
                "a parameter this endpoint does not read was reported duplicated: {name:?}"
            );
        }
        // `IntrospectionError` is `#[non_exhaustive]`, so the remaining
        // refusals are matched by shape rather than by name: what matters is
        // that every one of them is a refusal, not which.
        Err(_) => {}
    }

    // --- the response (§2.2) ---
    let response = describe(&claims, grant_id);

    // §2.2: `active` is REQUIRED, and `describe` is only ever called for a
    // token the caller may be told about. No claim may turn it off — the
    // inactive answer has exactly one constructor.
    assert!(
        response.is_active(),
        "a projected response was not active: {claims}"
    );

    for member in response.members() {
        assert!(
            PUBLISHABLE.contains(&member),
            "a member outside RFC 7662 §2.2 and its extensions was published: {member:?}"
        );
    }
    if !grant_id {
        assert!(
            !response.members().contains(&"grant_id"),
            "the private correlator was published by a tenant that withholds it"
        );
    }

    let json = response.into_json();
    // `token_type` is this server's assertion (RFC 6749 §7.1) and not the
    // token's: a claim of that name must not be able to change it.
    assert_eq!(
        json.get("token_type").and_then(Value::as_str),
        Some(BEARER),
        "a token chose its own token_type: {claims}"
    );
    // Whatever the claims, the two answers are distinguishable by exactly one
    // thing — `active` — and the inactive one carries nothing else. A
    // projection that could produce the inactive shape from a live token, or
    // an inactive answer that grew a member, would be §4's oracle.
    let inactive = IntrospectionResponse::inactive().into_json();
    assert_eq!(
        inactive,
        serde_json::json!({ "active": false }),
        "the inactive answer grew a member"
    );
    assert_ne!(
        json, inactive,
        "an active answer rendered as the inactive one"
    );
});
