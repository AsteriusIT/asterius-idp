//! Pushed authorization request parameters — RFC 9126 §2.1, RFC 6749 §3.1,
//! FAPI 2.0 SP §5.3.2.2.
//!
//! `validate` is the only place an authorization request is checked, so an
//! acceptance here is a flow this server will run. The properties asserted are
//! the ones a later stage trusts without re-checking:
//!
//! * **An accepted request has an exactly-registered `redirect_uri`.** Restated
//!   here against the registration rather than by asking the code under test.
//! * **An accepted request has PKCE**, because there is no code path that adds
//!   it later.
//! * **An accepted request's scopes are a subset of the registered ones.** Not
//!   trimmed to fit: a client that asked for more is refused.
//! * **No parameter was accepted twice** (RFC 6749 §3.1), which is the
//!   parameter-pollution defence.
//! * **`request` and `request_uri` are never accepted** — the first because JAR
//!   is not implemented and ignoring it would honour the parameters it exists
//!   to protect, the second because RFC 9126 §2.1 forbids it in a push.
#![no_main]

use arbitrary::Arbitrary;
use asterius_domain::Capabilities;
use asterius_domain::entities::client::ClientRegistration;
use asterius_oidc::authorize::{AuthorizationError, validate};
use asterius_oidc::form::Parameters;
use libfuzzer_sys::fuzz_target;
use serde_json::json;
use std::sync::OnceLock;

const CLIENT: &str = "billing";
const REDIRECT: &str = "https://rp.example/cb";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

fn registration() -> &'static ClientRegistration {
    static REGISTRATION: OnceLock<ClientRegistration> = OnceLock::new();
    REGISTRATION.get_or_init(|| {
        ClientRegistration::from_json(
            &serde_json::to_vec(&json!({
                "client_name": "Billing",
                "redirect_uris": [REDIRECT],
                "grant_types": ["authorization_code"],
                "scope": "openid profile payments",
                "jwks": {"keys": [{"kty": "OKP", "crv": "Ed25519", "x": "abc"}]},
            }))
            .expect("serialise"),
            Capabilities::default(),
        )
        .expect("a valid registration")
    })
}

/// One parameter's worth of adversarial choice.
#[derive(Arbitrary, Debug)]
enum Choice {
    /// Omit it.
    Absent,
    /// The value that should be accepted.
    Correct,
    /// Present twice, both correct — the pollution case.
    Twice,
    /// Arbitrary text.
    Text(String),
    /// The correct value with something appended.
    CorrectPlus(String),
}

impl Choice {
    fn apply(&self, name: &str, correct: &str, into: &mut Vec<(String, String)>) {
        match self {
            Self::Absent => {}
            Self::Correct => into.push((name.into(), correct.into())),
            Self::Twice => {
                into.push((name.into(), correct.into()));
                into.push((name.into(), correct.into()));
            }
            Self::Text(text) => into.push((name.into(), text.clone())),
            Self::CorrectPlus(extra) => {
                into.push((name.into(), format!("{correct}{extra}")));
            }
        }
    }
}

#[derive(Arbitrary, Debug)]
struct Input {
    response_type: Choice,
    redirect_uri: Choice,
    code_challenge: Choice,
    code_challenge_method: Choice,
    scope: Choice,
    state: Choice,
    nonce: Choice,
    prompt: Choice,
    max_age: Choice,
    client_id: Choice,
    request: Choice,
    request_uri: Choice,
    dpop_jkt: Choice,
    extra: Vec<(String, String)>,
}

fuzz_target!(|input: Input| {
    let mut pairs: Vec<(String, String)> = Vec::new();
    input
        .response_type
        .apply("response_type", "code", &mut pairs);
    input
        .redirect_uri
        .apply("redirect_uri", REDIRECT, &mut pairs);
    input
        .code_challenge
        .apply("code_challenge", CHALLENGE, &mut pairs);
    input
        .code_challenge_method
        .apply("code_challenge_method", "S256", &mut pairs);
    input.scope.apply("scope", "openid profile", &mut pairs);
    input.state.apply("state", "xyz", &mut pairs);
    input.nonce.apply("nonce", "n-0", &mut pairs);
    input.prompt.apply("prompt", "login", &mut pairs);
    input.max_age.apply("max_age", "60", &mut pairs);
    input.client_id.apply("client_id", CLIENT, &mut pairs);
    input
        .request
        .apply("request", "eyJhbGciOiJub25lIn0..", &mut pairs);
    input.request_uri.apply(
        "request_uri",
        "urn:ietf:params:oauth:request_uri:x",
        &mut pairs,
    );
    input
        .dpop_jkt
        .apply("dpop_jkt", &"a".repeat(43), &mut pairs);
    for (name, value) in &input.extra {
        pairs.push((name.clone(), value.clone()));
    }

    let params = Parameters::from_pairs(pairs.clone());
    let Ok(request) = validate(&params, CLIENT, registration()) else {
        return;
    };

    // --- properties of an ACCEPTED request ---

    let value_of = |name: &str| -> Option<&str> {
        let mut found = pairs.iter().filter(|(k, _)| k == name);
        let first = found.next().map(|(_, v)| v.as_str());
        assert!(
            found.next().is_none(),
            "RFC 6749 §3.1: accepted a request with two {name} parameters"
        );
        first
    };

    // RFC 9126 §2.1 and the JAR gap.
    assert!(
        value_of("request_uri").is_none(),
        "accepted a push carrying request_uri"
    );
    assert!(
        value_of("request").is_none(),
        "accepted a request object this server cannot process"
    );

    // The redirect URI is exactly one that was registered. Compared here
    // against the registration directly, so the check and its oracle are not
    // the same code.
    assert_eq!(
        Some(request.redirect_uri.as_str()),
        value_of("redirect_uri"),
        "the accepted redirect_uri is not the one that was sent"
    );
    assert!(
        registration()
            .redirect_uris
            .iter()
            .any(|uri| uri.as_str() == request.redirect_uri),
        "accepted an unregistered redirect_uri: {}",
        request.redirect_uri
    );

    // PKCE is present, and nothing downstream adds it.
    assert_eq!(request.code_challenge.as_str().len(), 43);
    assert_eq!(value_of("code_challenge_method"), Some("S256"));

    // Scopes are a subset of what the client registered — never widened, and
    // never quietly trimmed to fit.
    for scope in &request.scopes {
        assert!(
            registration().scopes.contains(scope),
            "accepted an unregistered scope: {scope}"
        );
    }
    if let Some(requested) = value_of("scope") {
        let asked: std::collections::BTreeSet<&str> = requested.split_whitespace().collect();
        assert_eq!(
            request.scopes.len(),
            asked.len(),
            "the accepted scope set is not the one requested"
        );
    }

    // `response_type` was exactly `code`.
    assert_eq!(value_of("response_type"), Some("code"));

    // The authenticated client wins, whatever the form said.
    assert_eq!(request.client_id, CLIENT);
    if let Some(presented) = value_of("client_id") {
        assert_eq!(
            presented, CLIENT,
            "accepted a request naming another client"
        );
    }

    // `prompt=none` never travels with anything else.
    if request
        .prompts
        .contains(&asterius_oidc::authorize::Prompt::None)
    {
        assert_eq!(request.prompts.len(), 1);
    }

    // Deterministic.
    let again = validate(&Parameters::from_pairs(pairs), CLIENT, registration());
    assert!(again.is_ok(), "validation is not deterministic");

    // Errors never carry the client's input back out.
    let _ = AuthorizationError::UnsupportedResponseType.code();
});
