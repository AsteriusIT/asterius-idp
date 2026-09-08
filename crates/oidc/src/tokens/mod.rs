//! Minting the two JWTs this server hands a client, and keeping them apart.
//!
//! An **access token** is authorisation: a resource server reads it to decide
//! whether the caller may do something. An **ID token** is an authentication
//! assertion: a client reads it to learn who signed in. They travel in the
//! same response, they are signed by the same tenant key, and confusing one
//! for the other is the reason RFC 8725 §3.11 asks for explicit typing at all
//! — RFC 9068 §2.1 says so in as many words:
//!
//! > See the Security Considerations section for details on the importance of
//! > preventing OpenID Connect ID Tokens (as defined by Section 2 of
//! > \[OpenID.Core\]) from being accepted as access tokens by resource servers
//! > implementing this profile.
//!
//! So the two builders live side by side, produce disjoint claim sets, and
//! carry different registered media types (`at+jwt` and `JWT`). Neither one
//! takes a free-form claim map: what an access token may say is fixed by
//! [`access`], what an ID token may say is fixed by [`id_token`], and the only
//! claims a *client* can influence are the ones claims resolution already
//! decided it may have.
//!
//! ## Nothing is minted without a revocable grant
//!
//! Every builder here takes an [`asterius_domain::ClaimedGrant`], which has
//! private fields and no constructor: the only way to obtain one is
//! `Grant::claim`, which refuses a revoked or expired grant. "Issue a token
//! with no grant" therefore does not compile, and "issue a token from a
//! revoked grant" does not run. FAPI 2.0 SP §6.8 item 4 asks for credentials
//! issued under one authorization to be linked so they can be revoked
//! together; this is the type that makes the link unforgettable.
//!
//! ## Signing is somebody else's job
//!
//! A builder returns an [`UnsignedToken`] — a media type and a claims set —
//! and stops. It reaches no key, so a protocol crate stays a protocol crate
//! (ADR-0001) and every claim rule here is testable without a signer. The
//! caller passes the result to [`asterius_domain::Signer`].
//!
//! One catch, and [`UnsignedToken::required_algorithm`] is where it lives: an
//! ID token's `at_hash` is computed with the hash that belongs to the
//! algorithm in the ID token's own JOSE header (OIDC Core §3.1.3.6), so its
//! claim set is only correct under one algorithm. The builder says which, and
//! a signer that ignores it produces a token the client will reject.
//!
//! That constraint is the second argument of [`asterius_domain::Signer::sign`],
//! so the whole handover is one expression and neither half can be forgotten:
//!
//! ```ignore
//! signer
//!     .sign(
//!         tenant,
//!         unsigned.required_algorithm(),
//!         unsigned.typ(),
//!         unsigned.claims(),
//!     )
//!     .await?
//! ```
//!
//! An access token and an ID token in one response are two of those calls with
//! two different answers, and may be signed by two different keys. That is not
//! an accident to be tidied up: an access token is verified by a resource
//! server from the JWKS by `kid`, an ID token by the one client that registered
//! an algorithm for it.

pub mod access;
pub mod id_token;

use asterius_domain::SigningAlgorithm;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde_json::Value;
use thiserror::Error;
use time::Duration;

pub use access::{AccessToken, Audience, Authentication, Confirmation};
pub use id_token::{IdToken, Session, token_hash};

/// Why a token could not be built.
///
/// Every variant renders as fixed text or as a name from a closed set. Nothing
/// here interpolates a scope, a claim value, a `sub` or an audience: these
/// messages reach an audit record and an operator's log, and a grant is full
/// of values a client chose.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum IssuanceError {
    /// The [`asterius_domain::ClaimedGrant`] is not a claim on the grant that
    /// was passed beside it.
    ///
    /// The claim carries the authority and the grant carries the scopes,
    /// resources and `authorization_details`. Mixing two grants would mint a
    /// token whose privileges came from one authorization and whose revocation
    /// link pointed at another — revocable, and revocable by the wrong person.
    #[error("the claimed grant does not match the grant it was passed with")]
    GrantMismatch,
    /// The lifetime is zero, negative, or longer than the builder's cap.
    #[error("a token lifetime must be positive and no longer than the profile's cap")]
    Lifetime,
    /// `aud` is empty, too large, or holds something that is not a resource
    /// identifier (RFC 8707 §2).
    #[error("an audience must be a non-empty set of absolute URIs without fragments")]
    Audience,
    /// `aud` names the client the token was issued to.
    ///
    /// RFC 9068 §3 and §5: the audience of an access token is the *resource*,
    /// and a distinct identifier per resource is what prevents cross-JWT
    /// confusion. A token whose audience is its own client is a token every
    /// resource server has to decide about for itself.
    #[error("the audience of an access token is the resource, never the client")]
    AudienceIsTheClient,
    /// A confirmation member is not a base64url-encoded SHA-256 thumbprint.
    #[error("a cnf thumbprint must be {len} base64url characters", len = Confirmation::THUMBPRINT_LEN)]
    Thumbprint,
    /// The `act` chain holds something other than JSON objects, or is deeper
    /// than [`AccessToken::MAX_ACTORS`].
    #[error(
        "an act chain is at most {} nested JSON objects",
        AccessToken::MAX_ACTORS
    )]
    ActorChain,
    /// An ID token was asked for from a grant with no resource owner.
    ///
    /// A `client_credentials` grant has nobody to assert anything about, and an
    /// ID token asserting a *client* would be an authentication assertion about
    /// a principal that never authenticated.
    #[error("an ID token needs a subject; this grant has no resource owner")]
    NoSubject,
    /// A `nonce` is empty or longer than [`crate::authorize::MAX_NONCE_LEN`].
    #[error("a nonce must be 1 to {} bytes", crate::authorize::MAX_NONCE_LEN)]
    Nonce,
    /// A `sid` is empty, too long, or not printable ASCII.
    #[error("a sid must be 1 to {} printable ASCII characters", Session::MAX_LEN)]
    Session,
    /// Claims resolution offered a claim the authorization server issues about
    /// the exchange.
    ///
    /// Carries the name, which is safe to render: it is a member of the fixed
    /// [`asterius_domain::ClaimName::SERVER_ISSUED`] list, not a value that
    /// came from anywhere.
    #[error("the claim `{0}` is issued by this server and cannot be supplied")]
    ServerIssuedClaim(&'static str),
    /// A released claim is not a name a user record may assert at all.
    #[error("a released claim name must be one claims resolution can produce")]
    UnreleasableClaim,
    /// The serialised claims set is larger than the builder's guard.
    #[error("the claims set is {size} bytes, limit is {limit}")]
    TooLarge {
        /// How large it came out.
        size: usize,
        /// The builder's bound.
        limit: usize,
    },
}

/// A claims set and its media type, ready for [`asterius_domain::Signer`].
///
/// Deliberately not a `Value` on its own. The `typ` is not decoration — it is
/// the header parameter that stops an ID token being replayed as an access
/// token — so it travels with the claims rather than being chosen again at the
/// call site, where it could be chosen differently.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub struct UnsignedToken {
    typ: &'static str,
    required_algorithm: Option<SigningAlgorithm>,
    claims: Value,
}

impl UnsignedToken {
    /// The explicit type header (RFC 8725 §3.11).
    #[must_use]
    pub const fn typ(&self) -> &'static str {
        self.typ
    }

    /// The claims, as they will be serialised into the payload.
    #[must_use]
    pub const fn claims(&self) -> &Value {
        &self.claims
    }

    /// The algorithm this claims set is only correct under, if there is one.
    ///
    /// `None` means any key on the allow-list will do — an access token says
    /// nothing about how it was signed, so the tenant's active key is the
    /// right answer.
    ///
    /// `Some` is a constraint the signer must honour, and an ID token always
    /// carries one. Two clauses make it so. OIDC Core §3.1.3.7 has the client
    /// check that `alg` is "the algorithm sent by the Client in the
    /// `id_token_signed_response_alg` parameter during Registration", so
    /// signing with the tenant's default instead would produce a token the
    /// client is entitled to reject. And OIDC Core §3.1.3.6 ties `at_hash` to
    /// "the hash algorithm used in the `alg` Header Parameter of the ID
    /// Token's JOSE Header", so a claims set built for one algorithm and
    /// signed under another carries a hash the client computes differently.
    #[must_use]
    pub const fn required_algorithm(&self) -> Option<SigningAlgorithm> {
        self.required_algorithm
    }

    /// The claims, consumed, for a caller about to sign them.
    #[must_use]
    pub fn into_claims(self) -> Value {
        self.claims
    }
}

/// A `jti`: 128 bits of entropy, base64url-encoded.
///
/// A newtype rather than a `String` because the entropy is the requirement.
/// FAPI 2.0 SP §5.4.1 item 4: "Credentials not intended for handling by
/// end-users (e.g., access tokens, refresh tokens, authorization codes, etc.)
/// shall be created with at least 128 bits of entropy such that an attacker
/// correctly guessing the value is computationally infeasible." RFC 9068 §2.2
/// makes `jti` REQUIRED on every JWT access token, and revocation is what it is
/// for: a `jti` is what goes on the denylist when a grant is revoked before
/// its tokens expire (`asterius_domain::LiveAccessToken`), so a guessable one
/// is a denial-of-service against somebody else's live token.
///
/// There is no constructor taking a caller's string. The two that exist both
/// start from sixteen bytes, so an identifier that reached this type has the
/// entropy by construction rather than by a length check that a base64 string
/// of zeros would also pass.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct JwtId(String);

impl JwtId {
    /// How many random bytes go into an identifier. 128 bits.
    pub const BYTES: usize = 16;

    /// Draws a fresh identifier from the operating system CSPRNG.
    ///
    /// # Panics
    ///
    /// If the CSPRNG is unavailable. There is nothing to fall back to: a
    /// predictable `jti` is a `jti` an attacker can put on the denylist ahead
    /// of the token that will carry it, and carrying on with a buffer of zeros
    /// would do exactly that.
    #[must_use]
    pub fn generate() -> Self {
        let mut bytes = [0_u8; Self::BYTES];
        getrandom::fill(&mut bytes).expect("the OS CSPRNG must be available");
        Self::from_bytes(bytes)
    }

    /// Wraps sixteen bytes whose length the type system already proves.
    ///
    /// For tests that need to assert a particular token, in the manner of
    /// `PairwiseSalt::from_bytes`. Anywhere a token is actually issued, use
    /// [`JwtId::generate`].
    #[must_use]
    pub fn from_bytes(bytes: [u8; Self::BYTES]) -> Self {
        Self(B64.encode(bytes))
    }

    /// The identifier, as it appears in the `jti` claim.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for JwtId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The guard on how much a builder will serialise.
///
/// Not a specification limit. An access token is copied into every request a
/// client makes to a resource server, and a JWT is base64: every byte here is
/// more than a byte on the wire and appears in proxy logs, in `Authorization`
/// header size limits, and in the memory of every intermediary. RFC 9068 §5
/// warns that a JWT access token's contents are visible to the client; a
/// second reason to keep it small is that there is less of it to be visible.
pub(crate) const MAX_ACCESS_TOKEN_CLAIMS_BYTES: usize = 4 * 1024;

/// The same guard for an ID token, which is allowed to be larger.
///
/// An ID token carries whatever claims resolution released into it, and a
/// `claims` parameter naming twenty attributes with language variants is a
/// legitimate request. It is also delivered once, in a token response, rather
/// than on every resource call — so the pressure that keeps an access token
/// small does not apply, and this bound is here to stop a token nothing can
/// hold rather than to keep one lean.
pub(crate) const MAX_ID_TOKEN_CLAIMS_BYTES: usize = 8 * 1024;

/// Serialises a claims set and refuses it if it is over the guard.
pub(crate) fn bounded(claims: Value, limit: usize) -> Result<Value, IssuanceError> {
    // `to_string` and not a length estimate: the thing that has to fit is the
    // JSON somebody will actually sign, and a multi-byte claim value costs
    // what it costs.
    let size = claims.to_string().len();
    if size > limit {
        return Err(IssuanceError::TooLarge { size, limit });
    }
    Ok(claims)
}

/// Whether a lifetime is one this server will issue.
pub(crate) fn usable_lifetime(
    lifetime: Duration,
    max: Duration,
) -> Result<Duration, IssuanceError> {
    if lifetime <= Duration::ZERO || lifetime > max {
        return Err(IssuanceError::Lifetime);
    }
    Ok(lifetime)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_generated_jti_is_128_bits_of_base64url() {
        let jti = JwtId::generate();
        // 16 bytes unpadded base64url is 22 characters, and every one of them
        // is a byte `LiveAccessToken::new` will store: the identifier becomes
        // half of a primary key in the revocation denylist.
        assert_eq!(jti.as_str().len(), 22);
        assert!(
            jti.as_str()
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        );
        assert!(
            asterius_domain::LiveAccessToken::new(jti.as_str(), time::OffsetDateTime::UNIX_EPOCH)
                .is_ok()
        );
    }

    #[test]
    fn two_generated_jtis_differ() {
        assert_ne!(JwtId::generate(), JwtId::generate());
    }

    #[test]
    fn a_jti_is_the_base64url_of_its_bytes() {
        assert_eq!(
            JwtId::from_bytes([0; 16]).as_str(),
            "AAAAAAAAAAAAAAAAAAAAAA"
        );
        assert_eq!(
            JwtId::from_bytes([0xff; 16]).as_str(),
            "_____________________w"
        );
    }

    #[test]
    fn a_lifetime_outside_the_window_is_refused() {
        assert_eq!(
            usable_lifetime(Duration::ZERO, Duration::seconds(900)),
            Err(IssuanceError::Lifetime)
        );
        assert_eq!(
            usable_lifetime(Duration::seconds(-1), Duration::seconds(900)),
            Err(IssuanceError::Lifetime)
        );
        assert_eq!(
            usable_lifetime(Duration::seconds(901), Duration::seconds(900)),
            Err(IssuanceError::Lifetime)
        );
        assert_eq!(
            usable_lifetime(Duration::seconds(900), Duration::seconds(900)),
            Ok(Duration::seconds(900))
        );
    }
}
