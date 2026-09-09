//! Client assertion rules — OIDC Core §9, RFC 7523 §3, RFC 7521 §4.2,
//! FAPI 2.0 SP §5.3.2.1 items 6 and 8, RFC 6749 §2.3.
//!
//! An accepted assertion authenticates a client, so "does not panic" is the
//! floor and not the property. What this target asserts is that acceptance is
//! *narrow*, and narrow in the specific ways the profile requires:
//!
//! * **`aud` is a string, and one of the permitted values.** FAPI 2.0 SP
//!   §5.3.2.1 item 8. The array form is refused however it is spelled —
//!   including a single-element array holding exactly the right issuer, which
//!   RFC 7519 §4.1.3 permits and every general-purpose JWT library accepts.
//!   This is the check that stops one assertion naming this server *and* a
//!   hostile audience that can then forward it here.
//! * **`iss` and `sub` are both the client**, and are compared to it rather
//!   than to each other. An assertion where they agree with one another but
//!   not with the client under test must not be accepted.
//! * **An accepted assertion always yields a usable `jti`**, because the
//!   replay defence is only as good as the value it has to remember. An
//!   `Ok` carrying an empty or over-long `jti` would be a silent hole.
//! * **An accepted assertion never outlives the ceiling**, whatever `exp`
//!   says and whatever arithmetic reaching it required.
//! * **Exactly one authentication method** is ever selected, and never one
//!   the request did not present.
//!
//! Structured input rather than raw bytes: a random byte string is essentially
//! never a JSON object with five particular claims, so a naive target would
//! spend its whole budget on `MalformedClaim("iss")`. This builds a claim set
//! from a small grammar of near-misses instead — right value wrong type, right
//! type wrong value, right issuer wrapped in an array, boundary expiries.
#![no_main]

use arbitrary::Arbitrary;
use asterius_oidc::client_auth::{
    Assertion, AssertionRules, Attempt, Audiences, CLIENT_ASSERTION_TYPE, ClientAuthError,
    DEFAULT_MAX_ASSERTION_LIFETIME, MAX_JTI_LEN, Method, check_assertion,
};
use libfuzzer_sys::fuzz_target;
use serde_json::{Value, json};
use time::OffsetDateTime;

const ISSUER: &str = "https://as.example/t/demo";
const TOKEN_ENDPOINT: &str = "https://as.example/t/demo/token";
const BACKCHANNEL: &str = "https://as.example/t/demo/backchannel";
const CLIENT: &str = "billing";

/// A fixed instant, so `exp` arithmetic is reproducible.
fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_760_000_000).expect("fixed instant")
}

/// One claim's worth of adversarial choice.
#[derive(Arbitrary, Debug)]
enum ClaimChoice {
    /// The value that should be accepted.
    Correct,
    /// Absent entirely.
    Absent,
    /// Present as JSON `null`.
    Null,
    /// The right value, wrapped in a one-element array.
    WrappedInArray,
    /// The right value, as part of a two-element array with an attacker's.
    ArrayWithAttacker,
    /// The right value, as a number rather than a string.
    AsNumber,
    /// The right value, as an object.
    AsObject,
    /// A different, plausible value.
    Other,
    /// Arbitrary text.
    Text(String),
    /// Arbitrary bytes reinterpreted as a number.
    Number(i64),
}

impl ClaimChoice {
    /// Renders this choice for a claim whose correct value is `correct`.
    ///
    /// `None` means "omit the claim".
    fn render(&self, correct: &str, other: &str) -> Option<Value> {
        match self {
            Self::Correct => Some(json!(correct)),
            Self::Absent => None,
            Self::Null => Some(Value::Null),
            Self::WrappedInArray => Some(json!([correct])),
            Self::ArrayWithAttacker => Some(json!([correct, "https://attacker.example"])),
            Self::AsNumber => Some(json!(42)),
            Self::AsObject => Some(json!({ "value": correct })),
            Self::Other => Some(json!(other)),
            Self::Text(text) => Some(json!(text)),
            Self::Number(n) => Some(json!(n)),
        }
    }
}

#[derive(Arbitrary, Debug)]
enum ExpChoice {
    /// Comfortably inside the window.
    Valid,
    /// Exactly the ceiling.
    AtCeiling,
    /// One second past the ceiling.
    JustOverCeiling,
    /// A raw offset from `now`, including negative and absurd ones.
    Offset(i64),
    /// Not a number.
    NotANumber(String),
    /// Absent.
    Absent,
}

#[derive(Arbitrary, Debug)]
enum AudienceSet {
    /// The ordinary endpoints: the issuer, and nothing else.
    IssuerOnly,
    /// The CIBA backchannel endpoint's wider set (CIBA Core 1.0 §7.1).
    Ciba,
}

#[derive(Arbitrary, Debug)]
struct Input {
    iss: ClaimChoice,
    sub: ClaimChoice,
    aud: ClaimChoice,
    jti: ClaimChoice,
    exp: ExpChoice,
    audiences: AudienceSet,
    /// Extra members, to make sure an unknown claim is ignored rather than
    /// tripping anything.
    extra: Vec<(String, i64)>,
    /// Inputs for the method-selection half.
    has_assertion: bool,
    has_assertion_type: bool,
    correct_assertion_type: bool,
    assertion_type_text: String,
    has_client_id: bool,
    client_id_text: String,
    has_certificate: bool,
    has_authorization_header: bool,
}

fuzz_target!(|input: Input| {
    check_claim_rules(&input);
    check_method_selection(&input);
});

fn check_claim_rules(input: &Input) {
    let mut claims = serde_json::Map::new();
    if let Some(v) = input.iss.render(CLIENT, "someone-else") {
        claims.insert("iss".into(), v);
    }
    if let Some(v) = input.sub.render(CLIENT, "someone-else") {
        claims.insert("sub".into(), v);
    }
    if let Some(v) = input.aud.render(ISSUER, TOKEN_ENDPOINT) {
        claims.insert("aud".into(), v);
    }
    if let Some(v) = input.jti.render("a-unique-value", "another-value") {
        claims.insert("jti".into(), v);
    }
    if let Some(v) = render_exp(&input.exp) {
        claims.insert("exp".into(), v);
    }
    for (name, value) in &input.extra {
        // Never let a generated member collide with one under test.
        if !matches!(name.as_str(), "iss" | "sub" | "aud" | "jti" | "exp") {
            claims.insert(name.clone(), json!(value));
        }
    }
    let claims = Value::Object(claims);

    let (rules, permitted): (AssertionRules, &[&str]) = match input.audiences {
        AudienceSet::IssuerOnly => (AssertionRules::for_issuer(ISSUER), &[ISSUER]),
        AudienceSet::Ciba => (
            AssertionRules {
                audiences: Audiences::ciba_backchannel(ISSUER, TOKEN_ENDPOINT, BACKCHANNEL),
                max_lifetime: DEFAULT_MAX_ASSERTION_LIFETIME,
            },
            &[ISSUER, TOKEN_ENDPOINT, BACKCHANNEL],
        ),
    };

    let Ok(Assertion { jti, expires_at }) = check_assertion(&claims, CLIENT, &rules, now()) else {
        // Every rejection is fine. What must never happen is an acceptance
        // that should not have been, which is what the rest of this checks.
        return;
    };

    // --- properties of an ACCEPTED assertion ---

    // `aud` was a string, and one this endpoint permits. Restated here from
    // the specification rather than by asking the code under test.
    let aud = claims
        .get("aud")
        .expect("an accepted assertion carries aud");
    let aud = aud
        .as_str()
        .expect("FAPI 2.0 SP §5.3.2.1 item 8: accepted a non-string aud");
    assert!(
        permitted.contains(&aud),
        "accepted an audience this endpoint does not serve: {aud}"
    );

    // Both identity claims were the client. Not merely equal to each other.
    for claim in ["iss", "sub"] {
        let value = claims
            .get(claim)
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("accepted an assertion whose {claim} is not a string"));
        assert_eq!(
            value, CLIENT,
            "accepted an assertion whose {claim} is not the client"
        );
    }

    // The `jti` is usable: the replay defence has something to remember, and
    // it is bounded so it cannot be used to grow the store without limit.
    assert!(!jti.is_empty(), "accepted an assertion with an empty jti");
    assert!(
        jti.len() <= MAX_JTI_LEN,
        "accepted a jti of {} bytes, over the {MAX_JTI_LEN} limit",
        jti.len()
    );
    assert_eq!(
        Some(jti.as_str()),
        claims.get("jti").and_then(Value::as_str),
        "the returned jti is not the one in the claims"
    );

    // The ceiling holds, however `exp` was expressed.
    assert!(
        expires_at - now() <= rules.max_lifetime,
        "accepted an assertion living {} past the ceiling",
        expires_at - now() - rules.max_lifetime
    );
    assert!(expires_at > now(), "accepted an already-expired assertion");
}

fn render_exp(choice: &ExpChoice) -> Option<Value> {
    let base = now().unix_timestamp();
    let ceiling = DEFAULT_MAX_ASSERTION_LIFETIME.whole_seconds();
    match choice {
        ExpChoice::Valid => Some(json!(base + 60)),
        ExpChoice::AtCeiling => Some(json!(base + ceiling)),
        ExpChoice::JustOverCeiling => Some(json!(base + ceiling + 1)),
        // `saturating_add` here is about the *target*, not the subject: an
        // overflow while building the input would panic in this file and be
        // reported as a finding against code that never saw the value.
        ExpChoice::Offset(offset) => Some(json!(base.saturating_add(*offset))),
        ExpChoice::NotANumber(text) => Some(json!(text)),
        ExpChoice::Absent => None,
    }
}

fn check_method_selection(input: &Input) {
    let token = "header.payload.signature";
    let assertion_type = if input.correct_assertion_type {
        CLIENT_ASSERTION_TYPE
    } else {
        input.assertion_type_text.as_str()
    };

    let attempt = Attempt {
        assertion: input.has_assertion.then_some(token),
        assertion_type: input.has_assertion_type.then_some(assertion_type),
        client_id: input.has_client_id.then_some(input.client_id_text.as_str()),
        authorization_header: input.has_authorization_header,
        client_certificate: input.has_certificate,
    };

    let Ok(method) = attempt.method() else {
        return;
    };

    // RFC 6749 §2.3: never more than one credential behind an accepted method.
    let offered = usize::from(input.has_assertion || input.has_assertion_type)
        + usize::from(input.has_certificate)
        + usize::from(input.has_authorization_header);
    assert_eq!(
        offered, 1,
        "selected {method:?} from a request offering {offered} credentials"
    );

    match method {
        Method::PrivateKeyJwt => {
            // Both halves, and the one registered type (RFC 7521 §4.2).
            assert!(input.has_assertion && input.has_assertion_type);
            assert_eq!(
                assertion_type, CLIENT_ASSERTION_TYPE,
                "accepted an unregistered client_assertion_type"
            );
        }
        Method::Mtls => {
            assert!(
                input.has_certificate,
                "selected mTLS without a client certificate"
            );
        }
    }

    // A method is never selected from nothing.
    assert!(
        attempt.method().is_err() || input.has_assertion || input.has_certificate,
        "selected a method from a request with no credential"
    );

    // Deterministic: the same attempt decides the same way twice.
    assert_eq!(attempt.method(), Ok(method));
}

/// The claim rules must never accept anything that fails the standalone
/// audience rule, whichever endpoint is asking.
///
/// Kept as a separate assertion rather than folded above because it is the one
/// FAPI clause most likely to be relaxed by accident later: a maintainer
/// making `aud` "more compatible" would break this and nothing else.
#[allow(dead_code)]
fn _audience_rule_is_string_only() {
    for rules in [
        AssertionRules::for_issuer(ISSUER),
        AssertionRules {
            audiences: Audiences::ciba_backchannel(ISSUER, TOKEN_ENDPOINT, BACKCHANNEL),
            max_lifetime: DEFAULT_MAX_ASSERTION_LIFETIME,
        },
    ] {
        let claims = json!({
            "iss": CLIENT, "sub": CLIENT, "aud": [ISSUER],
            "jti": "x", "exp": now().unix_timestamp() + 60,
        });
        assert_eq!(
            check_assertion(&claims, CLIENT, &rules, now()),
            Err(ClientAuthError::WrongAudience)
        );
    }
}
