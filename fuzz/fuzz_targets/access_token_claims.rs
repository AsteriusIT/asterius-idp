//! `AccessToken::build` — the claims set of every JWT access token this server
//! issues, and the two validators inside it.
//!
//! The inputs are not a client's bytes; they are a *grant*, which is worse. A
//! grant is assembled from an authorization request, stored in a table with
//! three `jsonb` columns and two `text[]` columns, read back weeks later, and
//! copied into a token that every resource server in the deployment trusts. So
//! the properties asserted here are the ones nothing downstream re-checks:
//!
//! * **Every token is sender-constrained.** FAPI 2.0 SP §5.3.2.1 item 4: the
//!   server "shall only issue sender-constrained access tokens". `cnf` is
//!   structurally non-optional — [`Confirmation`] has no empty value and
//!   `AccessToken::new` takes one by value — and this is the check that no
//!   input makes the structure produce an empty or malformed one anyway. A
//!   `cnf` holding a thumbprint of the wrong shape is a binding no resource
//!   server matches, which is a bearer token wearing a `cnf`.
//! * **No token is audienced at its own client.** RFC 9068 §3 and §5: `aud` is
//!   the resource, and a distinct identifier per resource is what stops
//!   cross-JWT confusion.
//! * **No accepted audience is unmatched.** RFC 8707 §2: absolute URI, no
//!   fragment. Re-parsed here with `url`, so "is it an audience a resource
//!   server can compare against" is answered by something other than the code
//!   under test.
//! * **No token can be mistaken for an ID token.** `nonce`, `at_hash`,
//!   `c_hash`, `s_hash`, `azp` and `sid` are unwritable from here, whatever the
//!   grant holds — which is the other half of RFC 9068 §2.1's explicit typing.
//! * **A scope cannot split.** The `scope` claim is space-delimited
//!   (RFC 9068 §2.2.3, RFC 8693 §4.2). Splitting it again must return exactly
//!   the grant's scopes: one stored scope containing a space would *become two
//!   scopes* at the resource server.
//! * **The lifetime is bounded.** `exp - iat` is in `(0, 900]`, whatever a
//!   caller asks for, so "short-lived" (FAPI 2.0 SP §6.1) is not a convention.
//! * **Building is a pure function.** The same grant gives the same claims. A
//!   builder that depended on anything else would mint two different tokens for
//!   one authorization on two replicas.
#![no_main]

use arbitrary::Arbitrary;
use asterius_domain::{ClaimName, ClientId, Grant, GrantId, Issuer, Kid, SubjectId, TenantId};
use asterius_oidc::tokens::{
    AccessToken, Audience, Authentication, Confirmation, IssuanceError, JwtId, UnsignedToken,
};
use libfuzzer_sys::fuzz_target;
use serde_json::Value;
use time::{Duration, OffsetDateTime};

/// Resource candidates, half of them the ones RFC 8707 §2 refuses, spelled the
/// ways somebody would type them into a seed script.
const RESOURCES: [&str; 10] = [
    "https://api.example/v1",
    "https://api.example/",
    "https://other.example/v2",
    "urn:example:resource",
    "https://api.example/v1#frag",
    "/v1",
    "api.example",
    "",
    "mailto:a@example.com",
    "https://api.example/v1?tenant=demo",
];

/// Scope candidates. The ones with a space or a quote are the escalation:
/// a single stored scope containing a space becomes two at the resource server.
const SCOPES: [&str; 8] = [
    "openid",
    "accounts",
    "payments accounts",
    "pay\"ments",
    "",
    "urn:example:scope",
    "offline_access",
    "a",
];

/// Thumbprint candidates: one real base64url SHA-256 digest, and the shapes
/// that must not pass for one.
const THUMBPRINTS: [&str; 7] = [
    "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I",
    "bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2",
    "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I=",
    "0ZcOCORZNYy+DWpqq30jZyJGHTN0d2HglBV3uiguA4I",
    "",
    "short",
    "d1970c0e4459358cbe0d6a6aab7d2367224461d33747761e0941577ba282e0aa",
];

/// The JSON shapes an `act` chain element can hold.
const ACTORS: [&str; 6] = [
    r#"{"sub":"admin@example.com"}"#,
    r#"{"sub":"svc","iss":"https://other.example"}"#,
    r#"{"sub":"a","act":{"sub":"b"}}"#,
    "\"admin\"",
    "[]",
    "null",
];

#[derive(Arbitrary, Debug)]
struct Input {
    scope_picks: Vec<u8>,
    scope_free: String,
    resource_picks: Vec<u8>,
    audience_picks: Vec<u8>,
    audience_free: String,
    jkt: u8,
    x5t: u8,
    both: bool,
    certificate_only: bool,
    actors: Vec<u8>,
    details: bool,
    subject: Option<String>,
    authenticated: bool,
    acr: Option<String>,
    amr: Vec<String>,
    lifetime_seconds: i32,
    grant_id_claim: bool,
    client_id: String,
    at: i32,
}

fn pick<'a>(table: &[&'a str], index: u8) -> &'a str {
    table[usize::from(index) % table.len()]
}

fn strings(table: &[&str], picks: &[u8], free: &str) -> Vec<String> {
    let mut out: Vec<String> = picks
        .iter()
        .take(48)
        .map(|index| pick(table, *index).to_owned())
        .collect();
    out.push(free.to_owned());
    out
}

fuzz_target!(|input: Input| {
    let issuer = Issuer::parse("https://as.example/t/demo").expect("a fixed issuer");
    let tenant = TenantId::new("demo");
    let created_at = OffsetDateTime::UNIX_EPOCH;
    let issued_at = OffsetDateTime::UNIX_EPOCH + Duration::seconds(i64::from(input.at));

    // A `client_id` the fuzzer chooses, so that "the audience is the client"
    // is reachable rather than hypothetical.
    let client_id = if input.client_id.is_empty() {
        "billing".to_owned()
    } else {
        input.client_id.clone()
    };

    let mut grant = Grant::new(tenant, ClientId::new(client_id.clone()), created_at);
    grant.id = GrantId::new("2c1d4b1e-0000-4000-8000-000000000001");
    grant.subject = input.subject.clone().map(SubjectId::new);
    grant.scopes = strings(&SCOPES, &input.scope_picks, &input.scope_free)
        .into_iter()
        .collect();
    grant.resources = strings(&RESOURCES, &input.resource_picks, "")
        .into_iter()
        .collect();
    grant.actor_chain = input
        .actors
        .iter()
        .take(16)
        .map(|index| serde_json::from_str(pick(&ACTORS, *index)).expect("a fixed shape parses"))
        .collect();
    if input.details {
        grant.authorization_details = vec![serde_json::json!({ "type": "payment_initiation" })];
    }

    let Ok(claimed) = grant.claim(issued_at) else {
        return;
    };

    // The audience: from the grant when it names usable resources, otherwise a
    // set the fuzzer chose, which is RFC 9068 §3's "default resource indicator"
    // slot and the one a deployment fills in.
    let audience = match Audience::new(strings(
        &RESOURCES,
        &input.audience_picks,
        &input.audience_free,
    )) {
        Ok(audience) => audience,
        // An unusable audience must be refused, not corrected.
        Err(error) => {
            assert_eq!(error, IssuanceError::Audience);
            return;
        }
    };
    for value in audience.values() {
        let parsed = url::Url::parse(value).expect("an accepted audience is a URL");
        assert!(
            parsed.fragment().is_none() && !parsed.cannot_be_a_base(),
            "an audience RFC 8707 §2 refuses was accepted: {value:?}"
        );
    }

    // The confirmation. Every constructor is fallible, and a refusal here is a
    // token that is never minted — which is the correct outcome, because the
    // alternative is a `cnf` nothing matches.
    let jkt = Kid::new(pick(&THUMBPRINTS, input.jkt));
    let x5t = pick(&THUMBPRINTS, input.x5t);
    let confirmation = if input.both {
        Confirmation::dpop_and_certificate(&jkt, x5t)
    } else if input.certificate_only {
        Confirmation::certificate(x5t)
    } else {
        Confirmation::dpop(&jkt)
    };
    let Ok(confirmation) = confirmation else {
        return;
    };

    let build = |confirmation: Confirmation| {
        let mut token = AccessToken::new(
            &issuer,
            &grant,
            &claimed,
            audience.clone(),
            confirmation,
            JwtId::from_bytes([9; 16]),
            issued_at,
        )
        .for_lifetime(Duration::seconds(i64::from(input.lifetime_seconds)));
        if input.authenticated {
            token = token.authenticated_by(Authentication {
                authenticated_at: created_at,
                acr: input.acr.clone(),
                amr: input.amr.iter().take(8).cloned().collect(),
            });
        }
        if input.grant_id_claim {
            token = token.with_grant_id();
        }
        token.build()
    };

    let first = build(confirmation.clone());

    // Pure: two replicas answering one token request must not disagree.
    assert_eq!(
        first,
        build(confirmation),
        "building an access token is not deterministic"
    );

    let Ok(unsigned) = first else { return };

    // --- explicit typing (RFC 9068 §2.1) ----------------------------------

    assert_eq!(unsigned.typ(), "at+jwt");
    assert_eq!(
        unsigned.required_algorithm(),
        None,
        "an access token constrained the signing algorithm"
    );

    let claims = unsigned.clone().into_claims();
    let object = claims.as_object().expect("a claims set is a JSON object");

    // --- everything RFC 9068 §2.2 makes REQUIRED ---------------------------

    for required in ["iss", "exp", "aud", "sub", "client_id", "iat", "jti"] {
        assert!(
            object.contains_key(required),
            "RFC 9068 §2.2 requires {required}"
        );
    }
    assert_eq!(object["client_id"], Value::String(client_id.clone()));
    assert!(
        !object["sub"].as_str().expect("sub is a string").is_empty(),
        "a token with an empty sub"
    );
    assert_eq!(object["jti"], Value::String("CQkJCQkJCQkJCQkJCQkJCQ".into()));

    // --- sender constraining (FAPI 2.0 SP §5.3.2.1 item 4) -----------------

    let cnf = object["cnf"]
        .as_object()
        .expect("cnf is a JSON object (RFC 7800 §3.1)");
    assert!(!cnf.is_empty(), "an access token carried an empty cnf");
    for (member, value) in cnf {
        assert!(
            member == "jkt" || member == "x5t#S256",
            "an unknown confirmation method reached a token: {member}"
        );
        let thumbprint = value.as_str().expect("a thumbprint is a string");
        assert_eq!(
            thumbprint.len(),
            Confirmation::THUMBPRINT_LEN,
            "a thumbprint no resource server can match: {thumbprint:?}"
        );
        assert!(
            thumbprint
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
            "a thumbprint outside base64url: {thumbprint:?}"
        );
    }

    // --- the audience is the resource (RFC 9068 §3, §5) --------------------

    let audiences: Vec<&str> = match &object["aud"] {
        Value::String(single) => vec![single.as_str()],
        Value::Array(many) => many
            .iter()
            .map(|value| value.as_str().expect("an audience is a string"))
            .collect(),
        other => panic!("aud is neither a string nor an array: {other}"),
    };
    assert!(!audiences.is_empty(), "an access token with an empty aud");
    for value in &audiences {
        assert_ne!(
            *value, client_id,
            "an access token was audienced at its own client"
        );
        let parsed = url::Url::parse(value).expect("an aud that is not a URL reached a token");
        assert!(parsed.fragment().is_none() && !parsed.cannot_be_a_base());
    }

    // --- nothing that belongs to an ID token -------------------------------

    for forbidden in ["nonce", "at_hash", "c_hash", "s_hash", "azp", "sid"] {
        assert!(
            !object.contains_key(forbidden),
            "an access token carried the ID token claim {forbidden}"
        );
    }
    // And nothing outside the profile's own vocabulary, so that a grant cannot
    // smuggle a claim in through a JSON column.
    for member in object.keys() {
        assert!(
            [
                "iss",
                "exp",
                "aud",
                "sub",
                "client_id",
                "iat",
                "jti",
                "cnf",
                "scope",
                "auth_time",
                "acr",
                "amr",
                "authorization_details",
                "act",
                "grant_id",
            ]
            .contains(&member.as_str()),
            "an access token carried an unexpected claim: {member}"
        );
    }

    // --- scopes cannot split (RFC 9068 §2.2.3) -----------------------------

    if let Some(scope) = object.get("scope") {
        let scope = scope.as_str().expect("scope is a string");
        let split: Vec<&str> = scope.split(' ').collect();
        assert_eq!(
            split.len(),
            grant.scopes.len(),
            "a stored scope split into two on the way into a token: {scope:?}"
        );
        for token in split {
            assert!(grant.scopes.contains(token), "a scope appeared from nowhere");
        }
    }

    // --- lifetime (FAPI 2.0 SP §6.1) ---------------------------------------

    let iat = object["iat"].as_i64().expect("iat is a number");
    let exp = object["exp"].as_i64().expect("exp is a number");
    assert_eq!(iat, issued_at.unix_timestamp());
    let lifetime = exp - iat;
    assert!(
        lifetime > 0 && lifetime <= AccessToken::MAX_LIFETIME.whole_seconds(),
        "a token lived for {lifetime}s"
    );

    // --- the act chain (RFC 8693 §4.1) -------------------------------------

    if let Some(mut act) = object.get("act") {
        let mut depth = 0_usize;
        while let Some(members) = act.as_object() {
            depth += 1;
            assert!(depth <= AccessToken::MAX_ACTORS, "an unbounded act chain");
            match members.get("act") {
                Some(inner) => act = inner,
                None => break,
            }
        }
    }

    // --- the size guard -----------------------------------------------------

    assert!(
        claims.to_string().len() <= 4 * 1024,
        "a claims set past the guard was minted"
    );

    // --- and no user-supplied claim is one the server issues ---------------
    //
    // The access token builder takes no claim map at all, so this is an
    // assertion about the closed vocabulary above rather than about a filter.
    // It is here because the list it checks against is the same one the ID
    // token builder enforces, and the two must not drift.
    for member in object.keys() {
        if ClaimName::SERVER_ISSUED.contains(&member.as_str()) {
            assert!(
                [
                    "iss", "exp", "aud", "sub", "client_id", "iat", "jti", "cnf", "scope",
                    "auth_time", "acr", "amr",
                    // RFC 8693 §4.1. Written whenever the grant carries an
                    // actor chain, which is why only a run that generated one
                    // ever reached this assertion.
                    "act",
                ]
                .contains(&member.as_str()),
                "a server-issued claim this profile does not define: {member}"
            );
        }
    }

    let _ = UnsignedToken::claims(&unsigned);
});
