//! Verifying an access token this server issued.
//!
//! Two endpoints receive one back: UserInfo, which answers with claims, and
//! the revocation endpoint, which has to know whose token it is before it puts
//! a `jti` on the denylist. They ask the same question — "did *this* tenant
//! sign this, is it typed `at+jwt`, is it still inside its `exp`" — and the
//! answer must not depend on which of them is asking.
//!
//! So there is one function. The alternative was two copies of a `Policy`, and
//! the failure mode of two copies is not that one is wrong today: it is that
//! `issued_by` gets added to one of them.

use asterius_domain::keys::{KeyStore, SigningAlgorithm};
use asterius_domain::{DomainError, Tenant};
use asterius_jose::verify::{Policy, TypRule, VerificationError, Verified};
use serde_json::{Value, json};
use time::OffsetDateTime;

/// Why an access token was not accepted.
#[derive(Debug)]
pub enum Rejected {
    /// The token itself: a bad signature, the wrong `typ`, an expired one, an
    /// issuer that is not this tenant. Whatever it was, the caller's answer is
    /// "this is not a token" and never which check failed.
    Token(VerificationError),
    /// This deployment could not answer: its key set is missing or will not
    /// parse. Not the caller's fault and never described to them.
    Unavailable(DomainError),
}

impl From<DomainError> for Rejected {
    fn from(error: DomainError) -> Self {
        Self::Unavailable(error)
    }
}

/// Verifies a JWT access token against the keys this tenant publishes.
///
/// One verifier, the same one every other JWT this server receives goes
/// through: `typ` before anything cryptographic (RFC 9068 §2.1, which is what
/// stops an ID token being presented as an access token), the algorithm from
/// this server's list and never the token's, and the key chosen by a resolver
/// over the set `/jwks` serves.
///
/// The `aud` is deliberately not constrained. RFC 9068 §3 puts a *resource*
/// there, and neither caller is one of the tenant's resources: UserInfo treats
/// the `openid` scope as its authorization (OIDC Core §5.3), and RFC 7009's
/// revocation endpoint is authorized by the client authentication in front of
/// it. Requiring an audience here would mean inventing a resource identifier
/// for this server's own endpoints.
///
/// # Errors
///
/// [`Rejected::Token`] when the token is not one this tenant issued and can
/// still stand behind; [`Rejected::Unavailable`] when the tenant's key set
/// could not be read or parsed, which is a fact about the deployment.
pub async fn verify(
    tenant: &Tenant,
    keys: &dyn KeyStore,
    token: &str,
    now: OffsetDateTime,
) -> Result<Verified, Rejected> {
    let published = keys.published_keys(&tenant.id).await?;
    let document = json!({
        "keys": published
            .into_iter()
            .map(|key| key.public_jwk)
            .collect::<Vec<Value>>(),
    });
    let resolver = asterius_jose::client_keys::keys_from_jwk_set(&document).map_err(|error| {
        Rejected::Unavailable(DomainError::invalid(
            "jwks",
            format!("this tenant's own key set will not parse: {error}"),
        ))
    })?;
    if resolver.is_empty() {
        return Err(Rejected::Unavailable(DomainError::invalid(
            "jwks",
            "this tenant publishes no usable key",
        )));
    }

    let policy = Policy::new(
        TypRule::Exactly(asterius_oidc::tokens::access::ACCESS_TOKEN_TYP),
        SigningAlgorithm::ALL.to_vec(),
    )
    .issued_by(tenant.issuer.as_str());

    asterius_jose::verify::verify(token, &policy, &resolver, now).map_err(Rejected::Token)
}
