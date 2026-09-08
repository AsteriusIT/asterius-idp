//! The token endpoint's front door: what is checked before a grant handler
//! sees a request, and what every error looks like.
//!
//! RFC 6749 §3.2 and §5.2, OIDC Core §3.1.3. One handler authenticates the
//! client, works out which grant is being asked for, and dispatches. The
//! grants themselves are separate stories; what lives here is the part that is
//! identical for all of them, because writing it once is the only way to be
//! sure `Cache-Control: no-store` is on every response rather than on four out
//! of six.
//!
//! # The order of the checks, and why
//!
//! A client learns different things from `unauthorized_client` and
//! `unsupported_grant_type`, so the order in which they are decided is a
//! disclosure decision, not a style one:
//!
//! 1. **The request's shape.** Duplicates, missing `grant_type`. Answerable
//!    without knowing who is asking.
//! 2. **Who is asking.** Client authentication. Everything after this point is
//!    a fact about a client that has proved who it is, which is what makes it
//!    safe to be specific.
//! 3. **Whether the grant exists at all.** `unsupported_grant_type`.
//! 4. **Whether *this* client may use it.** `unauthorized_client`.
//!
//! Steps 3 and 4 in the other order would let an unauthenticated caller
//! distinguish "this deployment does not do device flow" from "you are not
//! allowed to", and the second answer is about a client it has not proved it
//! is.

use asterius_domain::entities::client::GrantType;
use asterius_domain::{Capabilities, ClientRegistration};

use crate::form::{Duplicated, Parameters};

/// Why a token request was refused.
///
/// The variants are RFC 6749 §5.2's codes, plus the two shape failures that
/// section maps to `invalid_request`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TokenError {
    /// A parameter appeared more than once.
    ///
    /// RFC 6749 §3.2: "Request and response parameters MUST NOT be included
    /// more than once."
    #[error("parameter {0} appeared more than once")]
    DuplicateParameter(String),
    /// `grant_type` is absent.
    #[error("missing grant_type")]
    MissingGrantType,
    /// The request is malformed in some other way.
    #[error("the request is not well formed")]
    MalformedRequest,
    /// `grant_type` names something this server does not implement, or a
    /// feature this deployment has turned off.
    #[error("unsupported grant_type")]
    UnsupportedGrantType,
    /// The client is not registered for this grant.
    #[error("the client is not authorised for this grant type")]
    UnauthorizedClient,
    /// Client authentication failed. Carries the authenticator's own code, so
    /// that `invalid_request` and `invalid_client` stay distinguishable.
    #[error("client authentication failed")]
    ClientAuthentication {
        /// The OAuth code the authenticator chose.
        code: &'static str,
        /// The HTTP status it chose.
        status: u16,
    },
}

impl From<Duplicated> for TokenError {
    fn from(error: Duplicated) -> Self {
        Self::DuplicateParameter(error.0)
    }
}

impl TokenError {
    /// The OAuth 2.0 error code (RFC 6749 §5.2).
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::DuplicateParameter(_) | Self::MissingGrantType | Self::MalformedRequest => {
                "invalid_request"
            }
            Self::UnsupportedGrantType => "unsupported_grant_type",
            Self::UnauthorizedClient => "unauthorized_client",
            Self::ClientAuthentication { code, .. } => code,
        }
    }

    /// The HTTP status (RFC 6749 §5.2).
    ///
    /// 400 for everything except a failed client authentication, which the
    /// authenticator has already decided.
    #[must_use]
    pub const fn status(&self) -> u16 {
        match self {
            Self::ClientAuthentication { status, .. } => *status,
            _ => 400,
        }
    }
}

/// Which grant a request is asking for, once it is known to be one this
/// client may use.
///
/// Constructing it is the proof: there is no way to get a `Dispatch` for a
/// grant the deployment has disabled or the client did not register.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dispatch {
    grant: GrantType,
}

impl Dispatch {
    /// The grant to hand to a handler.
    #[must_use]
    pub const fn grant(self) -> GrantType {
        self.grant
    }
}

/// Decides which grant handler a request belongs to.
///
/// `registration` is the *authenticated* client's — the caller has already
/// established who is asking, which is what makes `unauthorized_client` a safe
/// answer rather than an oracle.
///
/// # Errors
///
/// Returns the first [`TokenError`] that applies, in the order documented on
/// this module.
// fuzz-target: token_form
pub fn dispatch(
    params: &Parameters,
    registration: &ClientRegistration,
    capabilities: &Capabilities,
) -> Result<Dispatch, TokenError> {
    let raw = params
        .get("grant_type")?
        .ok_or(TokenError::MissingGrantType)?;

    // Unknown to this implementation. RFC 6749 §5.2's `unsupported_grant_type`
    // is the honest answer: the value is not one we implement, whoever asked.
    let grant = GrantType::parse(raw).ok_or(TokenError::UnsupportedGrantType)?;

    // Known, but switched off in this deployment. Same code as "we never
    // implemented it": a client cannot act on the difference, and telling it
    // apart maps the operator's configuration for anyone who asks.
    if grant
        .required_feature()
        .is_some_and(|feature| !capabilities.is_enabled(feature))
    {
        return Err(TokenError::UnsupportedGrantType);
    }

    // Implemented, enabled, and not this client's. RFC 6749 §5.2:
    // "The authenticated client is not authorized to use this authorization
    // grant type."
    if !registration.allows(grant) {
        return Err(TokenError::UnauthorizedClient);
    }

    Ok(Dispatch { grant })
}

#[cfg(test)]
mod tests {
    use super::*;
    use asterius_domain::Capabilities;
    use serde_json::json;

    fn registration(grants: &[&str]) -> ClientRegistration {
        ClientRegistration::from_json(
            &serde_json::to_vec(&json!({
                "client_name": "Billing",
                "redirect_uris": ["https://rp.example/cb"],
                "grant_types": grants,
                "scope": "openid",
                "jwks": {"keys": [{"kty": "OKP", "crv": "Ed25519", "x": "abc"}]},
            }))
            .expect("serialise"),
            everything(),
        )
        .expect("a valid registration")
    }

    /// Every feature on, so a test about grants is not accidentally a test
    /// about flags.
    fn everything() -> Capabilities {
        Capabilities {
            mtls: true,
            grant_management: true,
            ciba: true,
            device_flow: true,
            token_exchange: true,
            ssf: true,
            authzen: true,
            dpop_nonce: true,
        }
    }

    fn params(pairs: &[(&str, &str)]) -> Parameters {
        Parameters::from_pairs(
            pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned())),
        )
    }

    #[test]
    fn a_registered_grant_dispatches() {
        let result = dispatch(
            &params(&[("grant_type", "authorization_code"), ("code", "abc")]),
            &registration(&["authorization_code"]),
            &everything(),
        )
        .expect("must dispatch");
        assert_eq!(result.grant(), GrantType::AuthorizationCode);
    }

    /// RFC 6749 §3.2.
    #[test]
    fn a_repeated_parameter_is_refused() {
        let error = dispatch(
            &params(&[
                ("grant_type", "authorization_code"),
                ("grant_type", "refresh_token"),
            ]),
            &registration(&["authorization_code", "refresh_token"]),
            &everything(),
        )
        .expect_err("must refuse");
        assert_eq!(
            error,
            TokenError::DuplicateParameter("grant_type".to_owned())
        );
        assert_eq!(error.code(), "invalid_request");
    }

    #[test]
    fn a_request_without_a_grant_type_is_malformed() {
        let error = dispatch(
            &params(&[("code", "abc")]),
            &registration(&["authorization_code"]),
            &everything(),
        )
        .expect_err("must refuse");
        assert_eq!(error, TokenError::MissingGrantType);
        assert_eq!(error.code(), "invalid_request");
    }

    #[test]
    fn an_unknown_grant_type_is_unsupported() {
        for unknown in [
            "password",
            "implicit",
            "client_credentials ",
            "AUTHORIZATION_CODE",
            "",
            "urn:ietf:params:oauth:grant-type:saml2-bearer",
        ] {
            let error = dispatch(
                &params(&[("grant_type", unknown)]),
                &registration(&["authorization_code"]),
                &everything(),
            )
            .expect_err("must refuse");
            assert_eq!(
                error,
                TokenError::UnsupportedGrantType,
                "accepted grant_type {unknown:?}"
            );
            assert_eq!(error.code(), "unsupported_grant_type");
        }
    }

    /// RFC 6749 §5.2: the *authenticated* client is not authorised.
    #[test]
    fn a_grant_the_client_did_not_register_is_unauthorized() {
        let error = dispatch(
            &params(&[("grant_type", "refresh_token")]),
            &registration(&["authorization_code"]),
            &everything(),
        )
        .expect_err("must refuse");
        assert_eq!(error, TokenError::UnauthorizedClient);
        assert_eq!(error.code(), "unauthorized_client");
    }

    /// A grant behind a feature flag that is off answers the same as one that
    /// was never implemented.
    ///
    /// Telling the two apart would let anyone who can reach this endpoint map
    /// which optional features an operator has enabled.
    #[test]
    fn a_disabled_feature_is_indistinguishable_from_an_unimplemented_grant() {
        let flagged: Vec<GrantType> = GrantType::ALL
            .into_iter()
            .filter(|g| g.required_feature().is_some())
            .collect();
        assert!(
            !flagged.is_empty(),
            "no grant is behind a feature flag; this test has nothing to check"
        );

        for grant in flagged {
            // Registered for it, but the deployment does not offer it.
            //
            // `authorization_code` rides along because RFC 7591 §2.1 ties
            // `response_types: ["code"]` to it, and `ClientRegistration`
            // enforces that — a client registered for CIBA alone is not a
            // valid registration document.
            let error = dispatch(
                &params(&[("grant_type", grant.as_str())]),
                &registration(&["authorization_code", grant.as_str()]),
                &Capabilities::default(),
            )
            .expect_err("must refuse");
            assert_eq!(
                error.code(),
                "unsupported_grant_type",
                "{} leaked that it is implemented but disabled",
                grant.as_str()
            );
        }
    }

    /// The order matters: a client registered for nothing, asking for
    /// something that does not exist, must be told the grant does not exist —
    /// not that it is unauthorised for it.
    #[test]
    fn an_unknown_grant_is_reported_before_authorisation_is_considered() {
        let error = dispatch(
            &params(&[("grant_type", "password")]),
            &registration(&["authorization_code"]),
            &everything(),
        )
        .expect_err("must refuse");
        assert_eq!(error, TokenError::UnsupportedGrantType);
    }

    /// Unknown parameters are ignored. RFC 6749 §3.2 does not forbid them, and
    /// a server that rejected them would break every client that adds an
    /// extension parameter this one has not heard of.
    #[test]
    fn unknown_parameters_are_ignored() {
        dispatch(
            &params(&[
                ("grant_type", "authorization_code"),
                ("code", "abc"),
                ("something_new", "value"),
                ("", ""),
                ("🙂", "emoji"),
            ]),
            &registration(&["authorization_code"]),
            &everything(),
        )
        .expect("an unknown parameter is not an error");
    }

    #[test]
    fn a_failed_client_authentication_keeps_its_own_code_and_status() {
        let error = TokenError::ClientAuthentication {
            code: "invalid_client",
            status: 401,
        };
        assert_eq!(error.code(), "invalid_client");
        assert_eq!(error.status(), 401);

        // Everything else is 400.
        for other in [
            TokenError::MissingGrantType,
            TokenError::UnsupportedGrantType,
            TokenError::UnauthorizedClient,
            TokenError::MalformedRequest,
        ] {
            assert_eq!(other.status(), 400, "{other}");
        }
    }

    /// An error rendered to a client must not quote its input back.
    #[test]
    fn a_rejection_does_not_echo_the_grant_type() {
        let error = dispatch(
            &params(&[("grant_type", "totally-made-up-value")]),
            &registration(&["authorization_code"]),
            &everything(),
        )
        .expect_err("must refuse");
        assert!(!error.to_string().contains("totally-made-up"), "{error}");
    }
}
