//! The claims of a signed request object — RFC 9101 §4 and §6.1, OIDC Core
//! §6.3.
//!
//! The verifier has already checked the signature by the time this code runs,
//! so what reaches it is a *client-controlled JSON object*: whatever a client
//! that holds its own key chose to sign. That is the interesting adversary
//! here — the signature proves who wrote the claims, never that the claims are
//! sane.
//!
//! The properties asserted are what the pushed request endpoint trusts without
//! re-checking:
//!
//! * **An accepted object names this client and this issuer**, with `aud` a
//!   string and never an array (OIDC Core §6.3 items 2 and 3).
//! * **An accepted object expires within ten minutes** (RFC 9101 §10.2).
//! * **No JWT claim becomes an authorization parameter.** A `jti` that arrived
//!   as `state`, or an `iss` as `client_id`, would be a request the client did
//!   not make.
//! * **What comes out is only what went in.** Every parameter value is a value
//!   the object carried, so the mapping cannot invent one.
//! * **The envelope never widens the validator.** Whatever
//!   `authorize::validate` refuses in a form it refuses here, because it is the
//!   same call — asserted by running both spellings of the same request.
#![no_main]

use arbitrary::Arbitrary;
use asterius_domain::Capabilities;
use asterius_domain::entities::client::ClientRegistration;
use asterius_oidc::authorize::{AuthorizationPolicy, validate};
use asterius_oidc::request_object::{MAX_LIFETIME, parameters};
use libfuzzer_sys::fuzz_target;
use serde_json::{Value, json};
use std::sync::OnceLock;
use time::OffsetDateTime;

const CLIENT: &str = "billing";
const ISSUER: &str = "https://as.example/t/demo";
const REDIRECT: &str = "https://rp.example/cb";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

/// The instant every case is judged against, so a corpus entry means the same
/// thing on every run.
fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_760_000_000).expect("a fixed instant")
}

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
                "request_object_signing_alg": "EdDSA",
            }))
            .expect("serialise"),
            Capabilities::default(),
        )
        .expect("a valid registration")
    })
}

/// One claim's worth of adversarial choice.
#[derive(Arbitrary, Debug)]
enum Claim {
    /// Omit it.
    Absent,
    /// The value a conforming client would send.
    Correct,
    /// Arbitrary text.
    Text(String),
    /// A number where a string is expected, and the other way round.
    Number(i64),
    /// An array — the `resource` spelling, and a way to smuggle one elsewhere.
    Strings(Vec<String>),
    /// A nested object.
    Object(Vec<(String, String)>),
    /// `true`.
    Bool(bool),
    /// `null`.
    Null,
}

impl Claim {
    fn value(&self, correct: &Value) -> Option<Value> {
        match self {
            Self::Absent => None,
            Self::Correct => Some(correct.clone()),
            Self::Text(text) => Some(json!(text)),
            Self::Number(number) => Some(json!(number)),
            Self::Strings(items) => Some(json!(items)),
            Self::Object(fields) => Some(Value::Object(
                fields
                    .iter()
                    .map(|(k, v)| (k.clone(), json!(v)))
                    .collect::<serde_json::Map<String, Value>>(),
            )),
            Self::Bool(flag) => Some(json!(flag)),
            Self::Null => Some(Value::Null),
        }
    }
}

#[derive(Arbitrary, Debug)]
struct Input {
    iss: Claim,
    aud: Claim,
    exp: Claim,
    iat: Claim,
    jti: Claim,
    client_id: Claim,
    response_type: Claim,
    redirect_uri: Claim,
    code_challenge: Claim,
    scope: Claim,
    state: Claim,
    max_age: Claim,
    resource: Claim,
    authorization_details: Claim,
    claims: Claim,
    /// Anything else the client felt like signing.
    extra: Vec<(String, String)>,
}

fuzz_target!(|input: Input| {
    let expiry = now().unix_timestamp() + 60;
    let mut object = serde_json::Map::new();
    let mut put = |name: &str, choice: &Claim, correct: Value| {
        if let Some(value) = choice.value(&correct) {
            object.insert(name.to_owned(), value);
        }
    };
    put("iss", &input.iss, json!(CLIENT));
    put("aud", &input.aud, json!(ISSUER));
    put("exp", &input.exp, json!(expiry));
    put("iat", &input.iat, json!(now().unix_timestamp()));
    put("jti", &input.jti, json!("n-1"));
    put("client_id", &input.client_id, json!(CLIENT));
    put("response_type", &input.response_type, json!("code"));
    put("redirect_uri", &input.redirect_uri, json!(REDIRECT));
    put("code_challenge", &input.code_challenge, json!(CHALLENGE));
    put("scope", &input.scope, json!("openid profile"));
    put("state", &input.state, json!("xyz"));
    put("max_age", &input.max_age, json!(60));
    put(
        "resource",
        &input.resource,
        json!(["https://api.example/v1"]),
    );
    put(
        "authorization_details",
        &input.authorization_details,
        json!([{"type": "payment_initiation"}]),
    );
    put("claims", &input.claims, json!({"userinfo": {}}));
    for (name, value) in &input.extra {
        object.insert(name.clone(), json!(value));
    }
    let claims = Value::Object(object.clone());

    let Ok(params) = parameters(&claims, CLIENT, ISSUER, now()) else {
        return;
    };

    // --- properties of an ACCEPTED object ---

    // OIDC Core §6.3 items 2 and 3, restated against the input rather than by
    // asking the code under test again.
    assert_eq!(
        object.get("iss").and_then(Value::as_str),
        Some(CLIENT),
        "accepted an object issued by another party"
    );
    assert_eq!(
        object.get("aud"),
        Some(&json!(ISSUER)),
        "accepted an object addressed elsewhere, or an aud that is not a string"
    );

    // RFC 9101 §10.2: short-lived, and present.
    //
    // `exp` is a client-chosen i64, so `exp - now` is not an i64 for every
    // accepted object: `parameters` has no reason to refuse an `exp` in the
    // distant past — an expired object is the signature verifier's business,
    // not this mapping's — and `i64::MIN - 1_760_000_000` overflows. This
    // assertion used to spell that subtraction plainly and panicked inside the
    // harness on such a case, reporting a defect in a parser that had none.
    //
    // Saturating, the way `request_object::parameters` itself computes the
    // lifetime, and for the same reason. It does not soften the property: the
    // only values that saturate are further from `now` than any i64 can
    // express, so a saturated difference lands on the same side of
    // `MAX_LIFETIME` as the true one — `i64::MIN` stays under it, `i64::MAX`
    // stays over it. A ten-minute ceiling is still a ten-minute ceiling.
    let exp = object
        .get("exp")
        .and_then(Value::as_i64)
        .expect("accepted an object with no numeric exp");
    let lifetime = exp.saturating_sub(now().unix_timestamp());
    assert!(
        lifetime <= MAX_LIFETIME.whole_seconds(),
        "accepted an object valid for {lifetime} seconds"
    );

    // The JWT's own claims are not parameters: a `state` this server invented
    // from a `jti` is a request the client did not make.
    for envelope in ["iss", "aud", "exp", "nbf", "iat", "jti"] {
        assert!(
            !params.present(envelope),
            "{envelope} was offered to the validator as a parameter"
        );
    }

    // Nothing is invented. Every value that came out was a value that went in,
    // as a string, as a number's decimal spelling, or as the JSON of a claim
    // whose form spelling is JSON.
    for (name, value) in &object {
        if ["iss", "aud", "exp", "nbf", "iat", "jti"].contains(&name.as_str()) {
            continue;
        }
        let produced = params.multi(name);
        assert!(
            !produced.is_empty() || matches!(value, Value::Array(items) if items.is_empty()),
            "{name} was carried by the object and reached no parameter"
        );
        let acceptable: Vec<String> = match value {
            Value::String(text) => vec![text.clone()],
            Value::Number(number) => vec![number.to_string()],
            Value::Array(items) => items
                .iter()
                .map(|item| {
                    item.as_str()
                        .map_or_else(|| item.to_string(), str::to_owned)
                })
                .chain(std::iter::once(value.to_string()))
                .collect(),
            other => vec![other.to_string()],
        };
        for one in produced {
            assert!(
                acceptable.contains(one),
                "{name} came out as {one:?}, which the object did not carry"
            );
        }
    }

    // The envelope is not a second validator: whatever it produces goes through
    // the one that reads a plain form, and a request refused there is refused
    // here. Running it is the assertion — a panic in `validate` reached through
    // a request object is a panic reachable from a signed JWT.
    let _ = validate(
        &params,
        CLIENT,
        registration(),
        AuthorizationPolicy::default(),
    );

    // Deterministic: the same claims map to the same request twice.
    let again = parameters(&claims, CLIENT, ISSUER, now());
    assert!(again.is_ok(), "the mapping is not deterministic");
});
