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

/// Whether a verified token was withdrawn in bulk before its own expiry.
///
/// The companion of the `jti` denylist, and the half the denylist cannot do.
/// A denylist entry needs somebody to have named the token; these two acts
/// name a *principal* and mean every token it holds:
///
/// * RFC 7592 §2.3 — deprovisioning a client "SHOULD immediately invalidate
///   ... currently active access tokens";
/// * RFC 7009 §2.1 — revoking a refresh token SHOULD "also invalidate all
///   access tokens based on the same authorization grant".
///
/// Neither can be written as a list. An RFC 9068 access token is a signed JWT
/// this server does not hold, and nothing here has ever inventoried the `jti`
/// values it signed — the alternative, a row per token issued, is a table that
/// grows at the rate tokens are minted and buys nothing else (`ast-1sk.2`).
/// What is stored instead is one row per withdrawal saying "nothing issued to
/// this principal before that instant", and `cutoff` is that instant, already
/// read for whichever of the token's client and grant carries one.
///
/// So the comparison is against `iat` and not against `exp`: the question is
/// when the token was *minted*, because a token minted after the withdrawal
/// belongs to whatever came next — a client registered again under the same
/// `client_id`, or the same grant used again — and inheriting the withdrawal
/// would make the mark permanent.
///
/// A token with no `iat` is withdrawn by any cutoff. The claim is required
/// (RFC 9068 §2.2), so its absence means the token cannot be shown to
/// post-date the withdrawal, and that is not a question to answer optimistically.
///
/// This is a pure function on purpose. The read that produces `cutoff` belongs
/// to whichever endpoint is verifying — it is the same store round trip as the
/// denylist — but the *rule* is one, so that a second resource path cannot
/// come to a different opinion about what a cutoff means.
#[must_use]
pub fn withdrawn(verified: &Verified, cutoff: Option<OffsetDateTime>) -> bool {
    let Some(cutoff) = cutoff else {
        return false;
    };
    let Some(issued_at) = verified.claims.get("iat").and_then(Value::as_i64) else {
        return true;
    };
    issued_at <= cutoff.unix_timestamp()
}

#[cfg(test)]
mod tests {
    use super::*;
    use asterius_jose::verify::Verified;

    /// A verified token carrying `iat`, which RFC 9068 §2.2 makes required and
    /// every access token this server signs therefore has.
    fn issued_at(seconds: i64) -> Verified {
        Verified {
            claims: json!({ "iat": seconds }),
            kid: None,
            algorithm: SigningAlgorithm::DEFAULT,
        }
    }

    #[test]
    fn a_token_older_than_the_cutoff_is_withdrawn() {
        // Arrange
        let token = issued_at(1_700_000_000);
        let cutoff = OffsetDateTime::from_unix_timestamp(1_700_000_100).expect("an instant");

        // Act
        let refused = withdrawn(&token, Some(cutoff));

        // Assert
        assert!(refused, "a token issued before the cutoff still verified");
    }

    #[test]
    fn a_token_issued_after_the_cutoff_stands() {
        // Arrange: the case that makes this a mark and not a ban. A client
        // registered again under the same `client_id`, or a grant that mints a
        // token after an old refresh token of its was revoked, must not
        // inherit the withdrawal.
        let token = issued_at(1_700_000_100);
        let cutoff = OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("an instant");

        // Act
        let refused = withdrawn(&token, Some(cutoff));

        // Assert
        assert!(!refused, "a token issued after the cutoff was refused");
    }

    #[test]
    fn a_token_issued_at_the_cutoff_is_withdrawn() {
        // Arrange: the boundary is inclusive on the token's side. A cutoff is
        // written with the clock reading of the act it records, `iat` is
        // whole seconds (RFC 7519 §2's NumericDate), and a token minted in the
        // same second as the withdrawal is a token the withdrawal was about.
        // The other reading would leave a one-second window in which a token
        // minted just before a deprovisioning survives it.
        let token = issued_at(1_700_000_000);
        let cutoff = OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("an instant");

        // Act
        let refused = withdrawn(&token, Some(cutoff));

        // Assert
        assert!(
            refused,
            "a token minted in the cutoff's own second survived"
        );
    }

    #[test]
    fn no_cutoff_withdraws_nothing() {
        // Arrange
        let token = issued_at(1_700_000_000);

        // Act
        let refused = withdrawn(&token, None);

        // Assert
        assert!(!refused, "a token was refused with no cutoff to refuse it");
    }

    #[test]
    fn a_token_with_no_issue_time_is_withdrawn_by_any_cutoff() {
        // Arrange: `iat` is what a cutoff is compared against, so a token
        // without one cannot be shown to post-date a withdrawal. RFC 9068 §2.2
        // requires the claim, so such a token is not one this server mints —
        // and the safe answer to an unanswerable question is the refusal.
        let token = Verified {
            claims: json!({ "sub": "somebody" }),
            kid: None,
            algorithm: SigningAlgorithm::DEFAULT,
        };
        let cutoff = OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("an instant");

        // Act
        let refused = withdrawn(&token, Some(cutoff));

        // Assert
        assert!(refused, "a token with no `iat` survived a withdrawal");
    }
}
