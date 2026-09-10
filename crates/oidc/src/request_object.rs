//! Signed request objects (JAR, RFC 9101) — the envelope, not a second parser.
//!
//! A client may push its authorization request as a signed JWT instead of a
//! form: RFC 9126 §3 allows the `request` parameter in a pushed request, and
//! RFC 9101 §4 says what the JWT contains. This module turns the claims of a
//! request object that has **already been verified** into the same
//! [`Parameters`] a plain push produces, so that
//! [`crate::authorize::validate`] stays the one place an authorization request
//! is checked.
//!
//! That is the whole design, and it is the point of the module: a request
//! object is an *envelope*. If it had its own parameter reader, this server
//! would hold two definitions of an acceptable `authorization_details`, two of
//! an acceptable `claims`, two of an acceptable `resource` — and the one that
//! drifts is always the one fewer clients exercise. Here the JSON is mapped to
//! form values and handed to the validator that already exists.
//!
//! # What this module checks, and what it leaves to the verifier
//!
//! The signature, the `typ`, the algorithm and an `exp` in the past belong to
//! `asterius_jose::verify` and are checked there — this crate has no
//! cryptography and no clock of its own. What is left are the three claims
//! whose *rule* is narrower than a generic JWT policy can state:
//!
//! * **`iss` is the client** (OIDC Core §6.3 item 2, RFC 9101 §6.3). A request
//!   object issued by anyone else is not this client's request.
//! * **`aud` is this issuer, as a string.** RFC 7519 §4.1.3 permits an array
//!   and a generic verifier accepts one; OIDC Core §6.3 item 3 spells the
//!   value as the OP's issuer identifier. An array would be a request object
//!   minted for several authorization servers at once, which is a request
//!   object one of them can present to another.
//! * **`exp` is at most [`MAX_LIFETIME`] ahead.** RFC 9101 §10.2 asks for a
//!   short-lived object; one valid for a day is a standing instruction the
//!   client cannot withdraw.

use crate::form::Parameters;
use serde_json::Value;
use time::{Duration, OffsetDateTime};

/// The media type of a request object (RFC 9101 §10.8).
///
/// Required here rather than recommended: the whole feature is opt-in, so an
/// operator who switches it on gets the explicitly-typed profile FAPI 2.0
/// Message Signing will require, and there is no laxer mode to select. RFC
/// 8725 §3.11 is the general argument — a JWT minted for one purpose must not
/// be presentable as another, and only `typ` says which purpose that was.
pub const REQUEST_OBJECT_TYP: &str = "oauth-authz-req+jwt";

/// The longest a request object may still be valid for.
///
/// RFC 9101 §10.2 asks that a request object be short-lived without naming a
/// number. Ten minutes is the same order as every other short-lived artefact
/// here, and is generous next to the 60 seconds of clock drift FAPI 2.0 SP
/// §5.3.2.1 item 13 tolerates.
pub const MAX_LIFETIME: Duration = Duration::minutes(10);

/// Claims that belong to the JWT and are never authorization parameters.
///
/// RFC 9101 §4 puts the authorization request parameters *and* the JWT's own
/// registered claims in one object, so the two have to be told apart
/// somewhere. `client_id` is deliberately **not** here: OIDC Core §6.1 has it
/// as a request parameter as well, and [`crate::authorize::validate`] is the
/// place that reconciles it with the client that authenticated.
const ENVELOPE_CLAIMS: [&str; 6] = ["iss", "aud", "exp", "nbf", "iat", "jti"];

/// Parameters carried as JSON in a request object and as a JSON *string* in a
/// form (OIDC Core §6.1, RFC 9396 §3).
///
/// `claims` and `authorization_details` are the two, and re-encoding them is
/// exactly what makes this an envelope: the validator that reads the form
/// spelling reads this one too, with the same limits and the same errors.
const JSON_VALUED: [&str; 2] = ["authorization_details", "claims"];

/// Why a request object could not be turned into an authorization request.
///
/// Every variant renders as `invalid_request_object` (OIDC Core §3.1.2.6): the
/// client is authenticated and is entitled to know that the object, rather
/// than the form around it, was the problem.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RequestObjectError {
    /// The payload is not a JSON object.
    #[error("the request object payload is not a JSON object")]
    NotAnObject,
    /// A claim OIDC Core §6.3 requires is absent.
    #[error("the request object has no {0}")]
    Missing(&'static str),
    /// `iss` names somebody other than the client that authenticated.
    #[error("the request object was issued by another party")]
    IssuerIsNotTheClient,
    /// `aud` is an array, or names another authorization server.
    #[error("the request object is not addressed to this issuer as a string")]
    AudienceIsNotTheIssuer,
    /// `exp` is further ahead than [`MAX_LIFETIME`].
    #[error(
        "the request object is valid for longer than {} seconds",
        MAX_LIFETIME.whole_seconds()
    )]
    LifetimeTooLong,
    /// A claim's JSON has no form spelling, so no parameter rule could read it.
    #[error("the request object carries a {0} this server cannot read as a parameter")]
    Unrepresentable(String),
}

impl RequestObjectError {
    /// The OAuth error code to return (OIDC Core §3.1.2.6).
    ///
    /// One code for every variant. Which claim of a signed object displeased
    /// the server is a detail for the message, not a value a caller branches
    /// on, and `invalid_request` would send a client hunting for a typo in a
    /// form it did not send.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        "invalid_request_object"
    }
}

/// Turns the claims of a *verified* request object into request parameters.
///
/// `client_id` is the client that authenticated, never one read out of the
/// object; `issuer` is this tenant's issuer identifier. The result is fed to
/// [`crate::authorize::validate`] exactly as a form body would be, which is
/// what keeps one validator for both spellings.
///
/// # Errors
///
/// [`RequestObjectError`] for the claims a generic JWT policy cannot state —
/// see the module documentation.
// fuzz-target: request_object_claims
pub fn parameters(
    claims: &Value,
    client_id: &str,
    issuer: &str,
    now: OffsetDateTime,
) -> Result<Parameters, RequestObjectError> {
    let object = claims.as_object().ok_or(RequestObjectError::NotAnObject)?;

    // OIDC Core §6.3: `iss` is the client, `aud` is the OP. Checked before
    // anything is read out of the object, so nothing another party signed is
    // ever mapped to a parameter.
    match object.get("iss") {
        None => return Err(RequestObjectError::Missing("iss")),
        Some(Value::String(iss)) if iss == client_id => {}
        Some(_) => return Err(RequestObjectError::IssuerIsNotTheClient),
    }
    match object.get("aud") {
        None => return Err(RequestObjectError::Missing("aud")),
        Some(Value::String(aud)) if aud == issuer => {}
        Some(_) => return Err(RequestObjectError::AudienceIsNotTheIssuer),
    }

    // `exp` is required by the verifier's policy too. Requiring it in both
    // places costs a comparison and removes the case where one caller forgets.
    let expiry = object
        .get("exp")
        .and_then(Value::as_i64)
        .ok_or(RequestObjectError::Missing("exp"))?;
    if expiry.saturating_sub(now.unix_timestamp()) > MAX_LIFETIME.whole_seconds() {
        return Err(RequestObjectError::LifetimeTooLong);
    }

    let mut pairs: Vec<(String, String)> = Vec::new();
    for (name, value) in object {
        if ENVELOPE_CLAIMS.contains(&name.as_str()) {
            continue;
        }
        if JSON_VALUED.contains(&name.as_str()) {
            // A client that sends the form spelling inside the object is not
            // re-encoded: `"claims": "{...}"` is the same request.
            match value {
                Value::String(text) => pairs.push((name.clone(), text.clone())),
                other => pairs.push((name.clone(), other.to_string())),
            }
            continue;
        }
        match value {
            Value::String(text) => pairs.push((name.clone(), text.clone())),
            // `max_age` is a number in a request object and digits in a form.
            Value::Number(number) => pairs.push((name.clone(), number.to_string())),
            // RFC 8707 §2 defines `resource` as a repeatable parameter, which
            // is an array here and repeated pairs there. Every element has to
            // be a string, or the repetition would carry a value no parameter
            // rule could read.
            Value::Array(items) => {
                for item in items {
                    let Value::String(text) = item else {
                        return Err(RequestObjectError::Unrepresentable(name.clone()));
                    };
                    pairs.push((name.clone(), text.clone()));
                }
            }
            // An object where a parameter is expected, or a bare `true`, has
            // no form spelling. Refused rather than rendered as its JSON:
            // inventing one here would be the second parameter parser this
            // module exists to avoid.
            Value::Object(_) | Value::Bool(_) | Value::Null => {
                return Err(RequestObjectError::Unrepresentable(name.clone()));
            }
        }
    }

    Ok(Parameters::from_pairs(pairs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const CLIENT: &str = "billing";
    const ISSUER: &str = "https://as.example/t/demo";

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("a fixed instant")
    }

    /// The claims of a well-formed object, with `overrides` merged in. A
    /// `Value::Null` override removes the claim, which is how a test says
    /// "absent" without rewriting the whole object.
    fn claims(overrides: &Value) -> Value {
        let mut object = json!({
            "iss": CLIENT,
            "aud": ISSUER,
            "exp": now().unix_timestamp() + 60,
            "response_type": "code",
            "redirect_uri": "https://rp.example/cb",
        });
        let target = object.as_object_mut().expect("object");
        for (name, value) in overrides.as_object().expect("overrides are an object") {
            if value.is_null() {
                target.remove(name);
            } else {
                target.insert(name.clone(), value.clone());
            }
        }
        object
    }

    fn parsed(overrides: &Value) -> Parameters {
        parameters(&claims(overrides), CLIENT, ISSUER, now()).expect("a usable request object")
    }

    fn refused(overrides: &Value) -> RequestObjectError {
        parameters(&claims(overrides), CLIENT, ISSUER, now()).expect_err("must be refused")
    }

    /// RFC 9101 §6.1: the parameters are the claims of the JWT.
    #[test]
    fn every_claim_becomes_the_parameter_of_the_same_name() {
        // Arrange / Act
        let params = parsed(&json!({"scope": "openid profile", "state": "xyz"}));

        // Assert
        assert_eq!(params.get("response_type").expect("once"), Some("code"));
        assert_eq!(
            params.get("redirect_uri").expect("once"),
            Some("https://rp.example/cb")
        );
        assert_eq!(params.get("scope").expect("once"), Some("openid profile"));
        assert_eq!(params.get("state").expect("once"), Some("xyz"));
    }

    /// The JWT's own registered claims are not authorization parameters, and a
    /// request whose `state` was silently set to a `jti` would be a request the
    /// client did not make.
    #[test]
    fn the_jwts_own_claims_are_not_turned_into_parameters() {
        // Arrange / Act
        let params = parsed(&json!({"iat": now().unix_timestamp(), "jti": "n-1", "nbf": 0}));

        // Assert
        for envelope in ENVELOPE_CLAIMS {
            assert!(
                !params.present(envelope),
                "{envelope} was offered to the validator as a parameter"
            );
        }
    }

    /// OIDC Core §6.1: `client_id` is a request parameter as well as the
    /// signer's identity, and `authorize::validate` is what reconciles it.
    #[test]
    fn client_id_is_passed_through_to_the_validator() {
        let params = parsed(&json!({"client_id": CLIENT}));
        assert_eq!(params.get("client_id").expect("once"), Some(CLIENT));
    }

    /// OIDC Core §6.3 item 2.
    #[test]
    fn an_object_issued_by_another_party_is_refused() {
        assert_eq!(
            refused(&json!({"iss": "attacker"})),
            RequestObjectError::IssuerIsNotTheClient
        );
        assert_eq!(
            refused(&json!({"iss": null})),
            RequestObjectError::Missing("iss")
        );
    }

    /// OIDC Core §6.3 item 3: the audience is the issuer identifier, spelled as
    /// a string. An array would be one object addressed to several servers.
    #[test]
    fn an_audience_that_is_not_this_issuer_as_a_string_is_refused() {
        for aud in [
            json!("https://other.example"),
            json!([ISSUER]),
            json!([ISSUER, "https://other.example"]),
            json!(42),
        ] {
            assert_eq!(
                refused(&json!({"aud": aud.clone()})),
                RequestObjectError::AudienceIsNotTheIssuer,
                "accepted aud {aud}"
            );
        }
        assert_eq!(
            refused(&json!({"aud": null})),
            RequestObjectError::Missing("aud")
        );
    }

    /// RFC 9101 §10.2: short-lived. An object with no `exp` never stops being
    /// presentable.
    #[test]
    fn an_object_without_an_expiry_is_refused() {
        assert_eq!(
            refused(&json!({"exp": null})),
            RequestObjectError::Missing("exp")
        );
        assert_eq!(
            refused(&json!({"exp": "soon"})),
            RequestObjectError::Missing("exp"),
            "an exp that is not a number is as good as absent"
        );
    }

    /// The boundary itself: ten minutes is accepted, a second more is not.
    #[test]
    fn an_expiry_further_ahead_than_the_ceiling_is_refused() {
        let ceiling = now().unix_timestamp() + MAX_LIFETIME.whole_seconds();
        assert!(parameters(&claims(&json!({"exp": ceiling})), CLIENT, ISSUER, now()).is_ok());
        assert_eq!(
            refused(&json!({"exp": ceiling + 1})),
            RequestObjectError::LifetimeTooLong
        );
    }

    /// RFC 9396 §3 and OIDC Core §5.5: JSON inside the object, a JSON string in
    /// a form. The validator reads the form spelling, so the mapping re-encodes
    /// rather than parsing — a *second* parser is what this module refuses to
    /// be.
    #[test]
    fn json_valued_parameters_are_re_encoded_for_the_one_validator() {
        // Arrange
        let details = json!([{"type": "payment_initiation"}]);
        let requested = json!({"id_token": {"acr": {"essential": true}}});

        // Act
        let params = parsed(&json!({
            "authorization_details": details.clone(),
            "claims": requested.clone(),
        }));

        // Assert
        assert_eq!(
            params.get("authorization_details").expect("once"),
            Some(details.to_string().as_str())
        );
        assert_eq!(
            params.get("claims").expect("once"),
            Some(requested.to_string().as_str())
        );
    }

    /// A client that sends the form spelling inside the object made the same
    /// request, and must not have its JSON string re-quoted into another one.
    #[test]
    fn a_json_valued_parameter_already_sent_as_a_string_is_passed_through() {
        let params = parsed(&json!({"claims": "{\"userinfo\":{}}"}));
        assert_eq!(
            params.get("claims").expect("once"),
            Some("{\"userinfo\":{}}")
        );
    }

    /// RFC 8707 §2: `resource` is the repeatable parameter, so an array of them
    /// becomes repeated pairs rather than one value that means nothing.
    #[test]
    fn an_array_of_strings_becomes_a_repeated_parameter() {
        let params = parsed(&json!({"resource": ["https://a.example", "https://b.example"]}));
        assert_eq!(
            params.multi("resource"),
            ["https://a.example", "https://b.example"]
        );
    }

    /// `max_age` is seconds, and JSON has a number type for that.
    #[test]
    fn a_numeric_parameter_becomes_its_decimal_spelling() {
        let params = parsed(&json!({"max_age": 300}));
        assert_eq!(params.get("max_age").expect("once"), Some("300"));
    }

    /// Anything with no form spelling is refused rather than guessed at.
    #[test]
    fn a_parameter_with_no_form_spelling_is_refused() {
        for value in [json!({"a": 1}), json!(true), json!([1, 2])] {
            let error = refused(&json!({"login_hint": value.clone()}));
            assert_eq!(
                error,
                RequestObjectError::Unrepresentable("login_hint".to_owned()),
                "accepted a login_hint spelled {value}"
            );
        }

        // A claim explicitly signed as `null` is not the same as an absent one:
        // the client said something, and what it said has no form spelling. The
        // helper above reads `null` as "remove this claim", so this case is
        // built by hand.
        let mut explicit = claims(&json!({}));
        explicit
            .as_object_mut()
            .expect("object")
            .insert("login_hint".to_owned(), Value::Null);
        assert_eq!(
            parameters(&explicit, CLIENT, ISSUER, now()).expect_err("must be refused"),
            RequestObjectError::Unrepresentable("login_hint".to_owned())
        );
    }

    #[test]
    fn a_payload_that_is_not_an_object_is_refused() {
        for payload in [json!("string"), json!([1]), json!(7), json!(null)] {
            assert_eq!(
                parameters(&payload, CLIENT, ISSUER, now()).expect_err("must refuse"),
                RequestObjectError::NotAnObject
            );
        }
    }

    /// The client is entitled to know the object was the problem, and to one
    /// code for every way it can be (OIDC Core §3.1.2.6).
    #[test]
    fn every_refusal_names_the_request_object() {
        assert_eq!(
            RequestObjectError::NotAnObject.code(),
            "invalid_request_object"
        );
        assert_eq!(
            RequestObjectError::LifetimeTooLong.code(),
            "invalid_request_object"
        );
    }
}
