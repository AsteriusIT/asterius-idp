//! The body of `POST /bc-authorize` — CIBA Core 1.0 §7.1, §7.2, FAPI-CIBA.
//!
//! Two layers, fed one buffer, because that is how the endpoint reads it: the
//! bytes arrive as `application/x-www-form-urlencoded`, become pairs, and are
//! then validated against the client's registration. Fuzzing only the second
//! half would miss what a repeated parameter or a `%`-mangled key does on the
//! way in.
//!
//! An acceptance here is a *pending approval on somebody's phone*, which is
//! what makes this validator worth fuzzing rather than only unit-testing. The
//! properties asserted are the ones nothing downstream re-checks:
//!
//! * **Exactly one hint**, and it is one the form actually carried. Zero would
//!   be a request about nobody; two would let a client send an
//!   `id_token_hint` for one person and a `login_hint` for another and find
//!   out which this server preferred.
//! * **`openid` is among the scopes** (§7.1) **and every scope is
//!   registered.** Restated against the registration rather than by asking the
//!   code under test. The person approves *these* scopes minutes later, so one
//!   that slipped in here is one nobody ever refused.
//! * **The lifetime is inside the tenant's bounds**, whatever
//!   `requested_expiry` asked for. A `requested_expiry` is a request, and the
//!   row's own schema constraint is five minutes.
//! * **The notification token matches the delivery mode** (§7.1): present and
//!   long enough in ping mode, absent in poll mode. It is the credential §10.2
//!   presents, so "absent in poll" is not tidiness — it is a credential that
//!   would otherwise exist with nothing to present it.
//! * **A `binding_message` is short and plain** (§13's
//!   `invalid_binding_message`). It is rendered on two devices so a person can
//!   compare them, and a message that can render differently in the two places
//!   defeats the only thing it is for.
//! * **No parameter was accepted twice** (RFC 6749 §3.1) — the
//!   parameter-pollution defence, and the reason the endpoint parses pairs
//!   rather than a map.
//! * **A `client_id` parameter can only agree.** The authenticated client is
//!   the client.
//! * **Nothing panics**, on any byte sequence, including invalid UTF-8 — which
//!   is why the input is bytes and the UTF-8 check is part of what is fuzzed.
#![no_main]

use asterius_domain::Capabilities;
use asterius_domain::entities::client::ClientRegistration;
use asterius_oidc::ciba::{
    self, CibaError, Hint, MAX_BINDING_MESSAGE_CHARS, MAX_LIFETIME, MIN_LIFETIME,
    MIN_NOTIFICATION_TOKEN_CHARS, RequestPolicy, validate,
};
use asterius_oidc::form::Parameters;
use asterius_oidc::grant_management::Policy;
use libfuzzer_sys::fuzz_target;
use serde_json::json;
use std::sync::OnceLock;

const CLIENT: &str = "agent";

/// A poll client and a ping client, because the two halves of §7.1's
/// `client_notification_token` rule are only reachable one mode at a time.
fn registrations() -> &'static [ClientRegistration; 2] {
    static REGISTRATIONS: OnceLock<[ClientRegistration; 2]> = OnceLock::new();
    REGISTRATIONS.get_or_init(|| [registration("poll"), registration("ping")])
}

fn registration(mode: &str) -> ClientRegistration {
    let mut document = json!({
        "client_name": "Agent",
        "redirect_uris": [],
        "grant_types": ["urn:openid:params:grant-type:ciba"],
        "response_types": [],
        "scope": "openid profile payments",
        "token_endpoint_auth_method": "private_key_jwt",
        "token_endpoint_auth_signing_alg": "ES256",
        "jwks": {"keys": [{"kty": "OKP", "crv": "Ed25519", "x": "abc"}]},
        "backchannel_token_delivery_mode": mode,
    });
    if mode == "ping" {
        document.as_object_mut().expect("object").insert(
            "backchannel_client_notification_endpoint".to_owned(),
            json!("https://rp.example/ciba"),
        );
    }
    ClientRegistration::from_json(
        &serde_json::to_vec(&document).expect("the fixture serialises"),
        // CIBA is behind a flag; a registration naming the grant is refused
        // where the flag is off.
        Capabilities {
            ciba: true,
            ..Capabilities::default()
        },
    )
    .expect("the fixture registers")
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

    for registration in registrations() {
        let policy = RequestPolicy::of(registration, Policy::default());
        let ping = registration
            .backchannel_token_delivery_mode
            .is_some_and(|mode| mode.notifies_the_client());

        // §7.1.1: a client that registered no signing algorithm cannot send a
        // signed request, and a `request_uri` is refused at an endpoint that
        // dereferences nothing. Both are decided before the parameters are
        // read, so a body carrying either never reaches `validate`.
        if ciba::submission(&params, registration).is_err() {
            continue;
        }

        let Ok(request) = validate(&params, CLIENT, registration, policy) else {
            continue;
        };

        // §7.1: "exactly one of the hints", and it came from the form.
        let name = request.hint.parameter();
        assert!(
            pairs
                .iter()
                .any(|(key, value)| key == name && value == request.hint.value()),
            "a hint was accepted that the form did not carry"
        );
        let hints = ["login_hint", "id_token_hint", "login_hint_token"]
            .into_iter()
            .filter(|hint| {
                pairs
                    .iter()
                    .any(|(key, value)| key == *hint && !value.is_empty())
            })
            .count();
        assert_eq!(hints, 1, "{hints} hints were accepted");

        // §7.1: `scope` MUST contain `openid`, and nothing outside the
        // registration is ever granted.
        assert!(
            request.scopes.contains("openid"),
            "a CIBA request without openid was accepted"
        );
        for scope in &request.scopes {
            assert!(
                registration.scopes.contains(scope),
                "an unregistered scope was accepted: {scope:?}"
            );
        }

        // §7.1's `requested_expiry` is a request, not an instruction.
        assert!(
            request.expires_in >= MIN_LIFETIME && request.expires_in <= MAX_LIFETIME,
            "a lifetime outside the tenant's bounds: {}",
            request.expires_in
        );

        // §7.1: REQUIRED in ping mode, MUST NOT be provided otherwise.
        match &request.client_notification_token {
            None => assert!(
                !ping,
                "a ping request was accepted with no notification token"
            ),
            Some(token) => {
                assert!(
                    ping,
                    "a poll request was accepted with a notification token"
                );
                assert!(
                    token.chars().count() >= MIN_NOTIFICATION_TOKEN_CHARS,
                    "a notification token too short to carry 128 bits"
                );
            }
        }

        // §13's `invalid_binding_message`: short, and plain enough to be read
        // off two screens and compared.
        if let Some(message) = &request.binding_message {
            assert!(
                message.chars().count() <= MAX_BINDING_MESSAGE_CHARS,
                "an over-long binding_message was accepted"
            );
            assert!(
                message
                    .chars()
                    .all(|c| c.is_alphanumeric() || c == ' ' || c == '-'),
                "a binding_message with something other than letters, digits, \
                 spaces and hyphens was accepted: {message:?}"
            );
        }

        // §7.1.2: a code is only ever accepted from a client registered to
        // send one, and this fixture is not.
        assert_eq!(
            request.user_code, None,
            "a user_code was accepted from a client that registers none"
        );

        // RFC 6749 §3.1: nothing this validator reads may have been sent
        // twice.
        for name in [
            "scope",
            "client_id",
            "login_hint",
            "id_token_hint",
            "login_hint_token",
            "binding_message",
            "user_code",
            "requested_expiry",
            "client_notification_token",
            "acr_values",
            "authorization_details",
        ] {
            let seen = pairs.iter().filter(|(key, _)| key == name).count();
            assert!(seen <= 1, "{name} was accepted {seen} times");
        }

        // A `client_id` that disagreed with the authenticated client would
        // mean an approval recorded against somebody else's client.
        for (key, value) in &pairs {
            if key == "client_id" {
                assert_eq!(value, CLIENT, "a client_id parameter naming another client");
            }
        }

        // The same input twice is the same answer: a validator whose result
        // depended on anything but its arguments could not be reasoned about
        // at all.
        let again =
            validate(&params, CLIENT, registration, policy).expect("accepted once, accepted twice");
        assert_eq!(again.scopes, request.scopes);
        assert_eq!(again.expires_in, request.expires_in);

        // And a client that authenticated as somebody else gets the refusal
        // rather than the request, whenever the form names a `client_id`.
        if pairs.iter().any(|(key, _)| key == "client_id") {
            assert_eq!(
                validate(&params, "somebody-else", registration, policy),
                Err(CibaError::Invalid("client_id"))
            );
        }

        // A hint never renders itself, wherever it is written.
        let rendered = format!("{:?}", request.hint);
        if let Hint::Login(value) | Hint::IdToken(value) | Hint::LoginToken(value) = &request.hint
            && !value.is_empty()
        {
            assert!(
                !rendered.contains(value.as_str()),
                "a hint rendered itself in Debug output"
            );
        }
    }
});
