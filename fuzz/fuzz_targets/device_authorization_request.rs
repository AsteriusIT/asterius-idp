//! The body of `POST /device_authorization` — RFC 8628 §3.1, FAPI 2.0 SP
//! §5.3.2.1 item 3.
//!
//! Two layers, fed one buffer, because that is how the endpoint reads it: the
//! bytes arrive as `application/x-www-form-urlencoded`, become pairs, and are
//! then validated against the client's registration. Fuzzing only the second
//! half would miss what a repeated parameter or a `%`-mangled key does on the
//! way in.
//!
//! What an acceptance here means, and what the rest of the endpoint therefore
//! does not re-check:
//!
//! * **The scopes are a subset of the registered ones.** Restated against the
//!   registration rather than by asking the code under test. A device
//!   authorization is approved by a person who is shown these scopes and
//!   redeemed minutes later by a machine, so a scope that slipped in here is
//!   one nobody ever refused.
//! * **No parameter was accepted twice** (RFC 6749 §3.1) — the
//!   parameter-pollution defence, and the reason the endpoint parses pairs
//!   rather than a map.
//! * **`request` and `request_uri` are never accepted.** This endpoint unwraps
//!   no request object, so ignoring one would honour the parameters it exists
//!   to protect.
//! * **A `client_id` parameter can only agree.** The authenticated client is
//!   the client; the parameter is checked against it and is never the source
//!   of truth.
//! * **Nothing panics**, on any byte sequence, including invalid UTF-8 — which
//!   is why the input is bytes and the UTF-8 check is part of what is fuzzed.
#![no_main]

use asterius_domain::Capabilities;
use asterius_domain::entities::client::ClientRegistration;
use asterius_oidc::authorize::AuthorizationError;
use asterius_oidc::device::validate;
use asterius_oidc::form::Parameters;
use libfuzzer_sys::fuzz_target;
use serde_json::json;
use std::sync::OnceLock;

const CLIENT: &str = "agent";

fn registration() -> &'static ClientRegistration {
    static REGISTRATION: OnceLock<ClientRegistration> = OnceLock::new();
    REGISTRATION.get_or_init(|| {
        ClientRegistration::from_json(
            &serde_json::to_vec(&json!({
                "client_name": "Agent",
                "redirect_uris": [],
                "grant_types": ["urn:ietf:params:oauth:grant-type:device_code"],
                "response_types": [],
                "scope": "openid profile payments",
                "token_endpoint_auth_method": "private_key_jwt",
                "token_endpoint_auth_signing_alg": "ES256",
                "jwks": {"keys": [{"kty": "OKP", "crv": "Ed25519", "x": "abc"}]},
            }))
            .expect("the fixture serialises"),
            // The grant is behind a flag; a registration naming it is
            // refused where the flag is off.
            Capabilities {
                device_flow: true,
                ..Capabilities::default()
            },
        )
        .expect("the fixture registers")
    })
}

fuzz_target!(|body: &[u8]| {
    // The endpoint refuses a body that is not UTF-8 before it parses anything,
    // so a target that fed the parser lossy text would be fuzzing a decoder
    // this server does not have.
    let Ok(text) = std::str::from_utf8(body) else {
        return;
    };

    let pairs: Vec<(String, String)> = url::form_urlencoded::parse(text.as_bytes())
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    let params = Parameters::from_pairs(pairs.clone());

    let Ok(request) = validate(&params, CLIENT, registration()) else {
        return;
    };

    // Every accepted scope is one the client registered.
    for scope in &request.scopes {
        assert!(
            registration().scopes.contains(scope),
            "an unregistered scope was accepted: {scope:?}"
        );
    }

    // RFC 6749 §3.1: nothing this validator reads may have been sent twice.
    for name in ["scope", "client_id", "authorization_details"] {
        let seen = pairs.iter().filter(|(key, _)| key == name).count();
        assert!(seen <= 1, "{name} was accepted {seen} times");
    }

    // Neither of the two parameters this endpoint has no unwrapper for.
    assert!(
        !pairs
            .iter()
            .any(|(key, _)| key == "request" || key == "request_uri"),
        "a request object reached an endpoint that unwraps none"
    );

    // A `client_id` that disagreed with the authenticated client would mean an
    // authorization recorded against somebody else.
    for (key, value) in &pairs {
        if key == "client_id" {
            assert_eq!(value, CLIENT, "a client_id parameter naming another client");
        }
    }

    // The same input twice is the same answer: a validator whose result
    // depended on anything but its arguments could not be reasoned about at
    // all.
    let again = validate(&params, CLIENT, registration()).expect("accepted once, accepted twice");
    assert_eq!(again.scopes, request.scopes);

    // And a client that authenticated as somebody else gets the refusal rather
    // than the request, whenever the form names a `client_id` at all.
    if pairs.iter().any(|(key, _)| key == "client_id") {
        assert_eq!(
            validate(&params, "somebody-else", registration()),
            Err(AuthorizationError::ClientMismatch)
        );
    }
});
