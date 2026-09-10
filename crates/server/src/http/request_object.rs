//! Verifying a signed request object pushed to `/par` (JAR, RFC 9101).
//!
//! The cryptographic half of `ast-gxh.9`. What a verified object *means* is
//! [`asterius_oidc::request_object`]'s job — this module answers the question
//! that needs keys and a network: did this client sign this JWT.
//!
//! # Why the request object is unwrapped here and not at `/authorize`
//!
//! RFC 9126 §3 allows `request` in a pushed request and forbids `request_uri`
//! there; ADR-0002 makes PAR the only way a flow starts. So this endpoint is
//! the only place a request object can arrive, and it is the place where the
//! client that signed it is on the connection and authenticated. A failure is
//! an error response to that client, never a redirect — see the module
//! documentation of [`crate::http::par`].
//!
//! # What is verified, and in what order
//!
//! 1. **The client registered an algorithm.** OIDC Registration §2's
//!    `request_object_signing_alg`. A client that registered none has not
//!    asked to send request objects, and *any* algorithm would otherwise be
//!    acceptable for it.
//! 2. **`typ` is `oauth-authz-req+jwt`**, then the algorithm, then the
//!    signature — [`asterius_jose::verify()`]'s order, which spends nothing
//!    cryptographic on a token that was not meant for this endpoint.
//! 3. **The algorithm is the one registered, and only that one.** Not the
//!    allow-list: RFC 9101 §6.3 has the object signed "using the algorithm
//!    specified in `request_object_signing_alg`", so a client that registered
//!    `ES256` and sends `PS256` is refused even though both are on ADR-0003's
//!    list. The alternative lets a client downgrade itself.
//! 4. **`iss`, `aud` and `exp`**, in
//!    [`asterius_oidc::request_object::parameters`].
//! 5. **The `client_id` outside the object equals `iss`.** RFC 9101 §6.1
//!    ignores parameters outside the JWT *except* the ones that authenticate
//!    the client, and `client_id` is one of those — so it is not ignored, it
//!    is reconciled.
//!
//! There is no `none`, at any step: [`asterius_domain::SigningAlgorithm`]
//! cannot parse it (ADR-0003), so it cannot be registered and cannot be
//! accepted here.

use asterius_domain::{Client, Tenant};
use asterius_jose::client_keys::ClientKeyCache;
use asterius_jose::verify::{Policy, TypRule, verify};
use asterius_oidc::form::Parameters;
use asterius_oidc::request_object::{REQUEST_OBJECT_TYP, RequestObjectError};
use time::OffsetDateTime;

/// Why a pushed `request` parameter could not become an authorization request.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    /// The `request` parameter was sent more than once (RFC 6749 §3.1).
    #[error("request appeared more than once")]
    Duplicated,
    /// The client registered no `request_object_signing_alg`.
    #[error("this client registered no request_object_signing_alg")]
    NoRegisteredAlgorithm,
    /// The JWT did not verify: shape, `typ`, algorithm, signature or lifetime.
    ///
    /// One variant for all of them, following the client-authentication path:
    /// telling a caller *which* of its guesses was closest is a probe this
    /// endpoint does not have to answer.
    #[error("the request object did not verify")]
    NotVerified,
    /// The client's keys could not be read.
    #[error("the client's keys are unavailable")]
    KeysUnavailable,
    /// A claim of the verified object is not one this server can act on.
    #[error(transparent)]
    Claims(#[from] RequestObjectError),
    /// `client_id` outside the object names a different client than `iss`.
    #[error("client_id outside the request object does not match iss")]
    ClientIdMismatch,
}

impl Refusal {
    /// The OAuth error code to return.
    ///
    /// `invalid_request_object` (OIDC Core §3.1.2.6) for everything about the
    /// object itself, and `invalid_request` for the two faults that are about
    /// the form around it — a repeated parameter and a `client_id` that
    /// disagrees with the signer.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Duplicated | Self::ClientIdMismatch => "invalid_request",
            // `KeysUnavailable` shares the code: the client's own `jwks_uri`
            // being unreachable is not a mistake it can fix in this request,
            // but it is the client's document that named it, and the honest
            // statement is the same one — the object could not be checked, so
            // it was not accepted.
            Self::NoRegisteredAlgorithm | Self::NotVerified | Self::KeysUnavailable => {
                "invalid_request_object"
            }
            Self::Claims(error) => error.code(),
        }
    }
}

/// Turns a pushed `request` parameter into the parameters to validate.
///
/// `outer` is the form as it arrived. The result replaces it entirely, which
/// is RFC 9101 §6.1: "the Authorization Server MUST only use the parameters in
/// the Request Object". The parameters that authenticated the client have
/// already been consumed by the time this runs, and `client_id` — the one that
/// is both — is reconciled here.
///
/// # Errors
///
/// [`Refusal`], whose [`code`](Refusal::code) is what the endpoint renders.
pub async fn parameters(
    keys: &ClientKeyCache,
    tenant: &Tenant,
    client: &Client,
    outer: &Parameters,
    now: OffsetDateTime,
) -> Result<Parameters, Refusal> {
    let object = outer
        .get("request")
        .map_err(|_| Refusal::Duplicated)?
        .unwrap_or_default();

    // OIDC Registration §2. A client that registered no algorithm never asked
    // to send request objects, and there is no default to fall back to that
    // would not be this server choosing the client's algorithm for it.
    let algorithm = client
        .registration
        .request_object_signing_alg
        .ok_or(Refusal::NoRegisteredAlgorithm)?;

    // Parsed, not trusted: the only thing read before verification is the
    // `kid`, and only to narrow an already-trusted set of the client's keys.
    let unverified = asterius_jose::jws::parse(object).map_err(|_| Refusal::NotVerified)?;
    let key_set = keys
        .resolve(
            &tenant.id,
            &client.id,
            &client.registration.jwks,
            unverified.kid().as_ref(),
            now,
        )
        .await
        .map_err(|_| Refusal::KeysUnavailable)?;

    // `expected_audience` is deliberately not set here: the generic check
    // accepts `aud` as an array (RFC 7519 §4.1.3) and OIDC Core §6.3 item 3
    // wants the issuer identifier. The stricter, string-only rule is applied
    // by `asterius_oidc::request_object::parameters` below, and setting both
    // would leave the laxer one deciding.
    let policy = Policy::new(TypRule::Exactly(REQUEST_OBJECT_TYP), vec![algorithm])
        .issued_by(client.id.as_str());
    let verified = verify(object, &policy, &key_set, now).map_err(|_| Refusal::NotVerified)?;

    // RFC 9101 §6.1: the parameters outside are ignored, except the ones that
    // authenticate the client. `client_id` is one of those, so it is checked
    // rather than dropped — a form naming one client and an object signed by
    // another is a request with two authors.
    if let Ok(Some(presented)) = outer.get("client_id")
        && presented != client.id.as_str()
    {
        return Err(Refusal::ClientIdMismatch);
    }

    Ok(asterius_oidc::request_object::parameters(
        &verified.claims,
        client.id.as_str(),
        tenant.issuer.as_str(),
        now,
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use asterius_oidc::request_object::RequestObjectError;

    /// A client is told which half of its request was wrong, and never which
    /// guess was closest.
    #[test]
    fn the_object_and_the_form_around_it_get_different_codes() {
        assert_eq!(Refusal::Duplicated.code(), "invalid_request");
        assert_eq!(Refusal::ClientIdMismatch.code(), "invalid_request");
        assert_eq!(Refusal::NotVerified.code(), "invalid_request_object");
        assert_eq!(
            Refusal::NoRegisteredAlgorithm.code(),
            "invalid_request_object"
        );
        assert_eq!(Refusal::KeysUnavailable.code(), "invalid_request_object");
        assert_eq!(
            Refusal::Claims(RequestObjectError::NotAnObject).code(),
            "invalid_request_object"
        );
    }

    /// A refusal is rendered into an error body, so anything it carries is
    /// something the client gets back. Nothing here may carry the object.
    #[test]
    fn a_refusal_never_quotes_the_request_object() {
        let token = "eyJhbGciOiJFUzI1NiJ9.e30.sig";
        for refusal in [
            Refusal::Duplicated,
            Refusal::NoRegisteredAlgorithm,
            Refusal::NotVerified,
            Refusal::KeysUnavailable,
            Refusal::ClientIdMismatch,
        ] {
            let rendered = refusal.to_string();
            assert!(!rendered.contains(token), "{rendered}");
            assert!(!rendered.contains("eyJ"), "{rendered}");
        }
    }
}
