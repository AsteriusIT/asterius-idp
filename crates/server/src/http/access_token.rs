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

use crate::http::dpop::{self, DpopEndpoint};
use asterius_domain::keys::{KeyStore, SigningAlgorithm};
use asterius_domain::{DomainError, Tenant};
use asterius_jose::verify::{Policy, TypRule, VerificationError, Verified};
use asterius_oidc::userinfo::Presentation;
use axum::http::{HeaderMap, Method};
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
    let resolver = published(tenant, keys).await?;

    let policy = Policy::new(
        TypRule::Exactly(asterius_oidc::tokens::access::ACCESS_TOKEN_TYP),
        SigningAlgorithm::ALL.to_vec(),
    )
    .issued_by(tenant.issuer.as_str());

    asterius_jose::verify::verify(token, &policy, &resolver, now).map_err(Rejected::Token)
}

/// Verifies an ID token this server issued.
///
/// The same key set and the same clock as [`verify`], with OIDC Core §2's
/// `typ` instead of RFC 9068's. A separate function rather than a parameter,
/// because the whole point of the `typ` check is that the two kinds of token
/// are not interchangeable: a caller that could pass the rule in could pass
/// the wrong one.
///
/// The `aud` is not constrained here either. An ID token's audience is the
/// client it was issued to, and *which* client that has to be is a decision
/// of the caller — token exchange (RFC 8693 §5) requires it to be the acting
/// client, and nothing else in this server verifies one at all.
///
/// # Errors
///
/// [`Rejected::Token`] for a token this tenant did not issue or can no longer
/// stand behind, [`Rejected::Unavailable`] when the key set cannot be read.
pub async fn verify_id_token(
    tenant: &Tenant,
    keys: &dyn KeyStore,
    token: &str,
    now: OffsetDateTime,
) -> Result<Verified, Rejected> {
    let resolver = published(tenant, keys).await?;
    let policy = Policy::new(
        // OIDC Core never required a `typ`, and this server always writes one
        // (ADR-0002). `OptionalOneOf` accepts both, and the list is still
        // closed: a token announcing itself as `at+jwt` is refused here, which
        // is what stops an access token being exchanged as though it were an
        // assertion about an authentication.
        TypRule::OptionalOneOf(&[asterius_oidc::tokens::id_token::ID_TOKEN_TYP]),
        SigningAlgorithm::ALL.to_vec(),
    )
    .issued_by(tenant.issuer.as_str());

    asterius_jose::verify::verify(token, &policy, &resolver, now).map_err(Rejected::Token)
}

/// The resolver over the key set this tenant publishes.
///
/// Shared by the two verifiers above so that they cannot come to hold
/// different opinions about which keys are current.
async fn published(
    tenant: &Tenant,
    keys: &dyn KeyStore,
) -> Result<asterius_jose::client_keys::ClientKeySet, Rejected> {
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
    Ok(resolver)
}

/// One request presenting an access token at a protected resource.
///
/// A struct rather than eight arguments, because [`check_sender_constraint`]
/// is called from two endpoints and every one of the eight has to be *this*
/// request's: a proof is checked against the method and the URL it was made
/// for, and a certificate against the connection it arrived on.
pub struct Presented<'a> {
    /// The tenant the request arrived at.
    pub tenant: &'a Tenant,
    /// Checks the DPoP proof (RFC 9449 §7.1).
    pub dpop: &'a DpopEndpoint,
    /// The URL the proof's `htu` is compared against, as this server derives
    /// it (RFC 9449 §4.3 item 8).
    ///
    /// A [`dpop::ProofTarget`] rather than an [`Endpoint`](asterius_oidc::metadata::Endpoint), because not every
    /// endpoint that takes an access token is one URL of the registry: the
    /// Grant Management API addresses a resource *under* its endpoint (ID1
    /// §6.3), and the SSF management API is mounted outside the registry
    /// altogether (`ast-0ju.3`). All three derive the URL from the tenant's
    /// issuer and from nothing the caller sent.
    pub target: dpop::ProofTarget<'a>,
    /// The client certificate the request arrived with, if a trusted proxy
    /// forwarded one (RFC 8705 §2). `None` is "no certificate".
    pub certificate: Option<&'a asterius_oidc::mtls::ClientCertificate>,
    /// The router's method, which is a proof's `htm`.
    pub method: &'a Method,
    /// The request's headers, which is where a proof lives.
    pub headers: &'a HeaderMap,
    /// How the token was presented: the scheme, and the token itself.
    pub presented: Presentation<'a>,
    /// One clock reading for the whole request.
    pub now: OffsetDateTime,
}

impl std::fmt::Debug for Presented<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Presented")
            .field("target", &self.target)
            .field("now", &self.now)
            .finish_non_exhaustive()
    }
}

/// Why a token was not accepted from the caller that presented it.
#[derive(Debug)]
pub enum NotBound {
    /// The presentation does not match the token's `cnf`. RFC 6750 §3.1's
    /// `invalid_token`, whichever of the several ways it happened.
    Refused,
    /// A DPoP proof that did not check out (RFC 9449 §7.1), which has its own
    /// challenge and may carry a nonce.
    Dpop(dpop::Refusal),
}

/// Holds the presentation to the token's own `cnf` (RFC 9449 §7.1, RFC 8705 §3).
///
/// The `cnf` decides, and it holds exactly one member because
/// `TokenBinding` admits exactly one:
///
/// * `jkt` — a DPoP-bound token, usable only under the `DPoP` scheme and only
///   with a proof for the key it is bound to, whose `ath` hashes the token
///   that actually arrived;
/// * `x5t#S256` — a certificate-bound token (RFC 8705 §3), usable only by a
///   caller presenting that certificate. §3.1: "the client MUST use the same
///   certificate ... that was used for mutual TLS authentication" — here, the
///   certificate a trusted proxy forwarded on this request.
///
/// Anything else is refused. A token carrying neither is not
/// sender-constrained, which is not a token this profile has (FAPI 2.0 SP
/// §5.3.2.1 item 4); a token carrying both is one no registration can produce,
/// and honouring whichever half the caller can satisfy would make the binding
/// the caller's choice.
///
/// Shared between UserInfo and the Grant Management endpoint for the reason
/// [`verify`] is shared: two copies of this would not be wrong today, they
/// would be wrong the day one of them learns something.
///
/// # Errors
///
/// [`NotBound::Refused`] for a presentation the `cnf` does not admit, and
/// [`NotBound::Dpop`] for a proof that did not check out.
pub async fn check_sender_constraint(
    request: &Presented<'_>,
    verified: &Verified,
) -> Result<(), NotBound> {
    let confirmation = verified.claims.get("cnf");
    let jkt = confirmation
        .and_then(|cnf| cnf.get("jkt"))
        .and_then(Value::as_str);
    let x5t = confirmation
        .and_then(|cnf| cnf.get("x5t#S256"))
        .and_then(Value::as_str);

    let jkt = match (jkt, x5t) {
        (Some(jkt), None) => jkt,
        (None, Some(x5t)) => return check_certificate(request, x5t),
        (Some(_), Some(_)) | (None, None) => return Err(NotBound::Refused),
    };

    if !request.presented.is_dpop() {
        // RFC 9449 §7.1: "a DPoP-bound access token ... MUST be presented
        // using the DPoP authentication scheme". A client sending one as a
        // bearer token is asking for the binding to be ignored.
        return Err(NotBound::Refused);
    }

    let binding = request
        .dpop
        .check_with_access_token_under(
            request.tenant,
            request.target,
            request.method,
            request.headers,
            request.presented.token(),
            request.now,
        )
        .await
        .map_err(NotBound::Dpop)?
        // No `DPoP` header at all, beside a token bound to a key.
        .ok_or(NotBound::Refused)?;

    if binding.jkt.as_str() != jkt {
        // A valid proof for the wrong key: whoever sent this holds a DPoP key
        // and a token bound to a different one.
        return Err(NotBound::Refused);
    }
    Ok(())
}

/// RFC 8705 §3: the caller presents the certificate the token is bound to.
///
/// Three ways to fail, one answer. The token is a Bearer credential — §3 binds
/// the token, it does not define a scheme — so presenting it under `DPoP` is a
/// client claiming a binding its token does not carry. No certificate at all
/// is a deployment that terminates TLS without one reaching it: there is
/// nothing to compare, and answering anything but a refusal would turn a
/// sender-constrained token into a bearer one. And a certificate whose
/// thumbprint is not the token's is somebody else's connection.
fn check_certificate(request: &Presented<'_>, x5t: &str) -> Result<(), NotBound> {
    if request.presented.is_dpop() {
        return Err(NotBound::Refused);
    }
    let certificate = request.certificate.ok_or(NotBound::Refused)?;
    if certificate.thumbprint_b64url() != x5t {
        return Err(NotBound::Refused);
    }
    Ok(())
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
