//! One JWT verifier, for every JWT this server is handed.
//!
//! Client assertions, DPoP proofs, request objects, `id_token_hint`, CIBA
//! signed requests, logout tokens received in tests: all of them are a JWS with
//! claims, and all of them are attacker-supplied. Writing the checks once and
//! parameterising them is not tidiness — it is the only way to be sure the
//! `crit` rule or the clock-skew bound is applied everywhere rather than in
//! whichever four of six places somebody remembered.
//!
//! The caller says what it expects. It cannot get a token back without saying:
//! [`Policy`] has no `Default`, because every field is a decision — which
//! `typ`, which algorithms, which issuer, which audience — and a default would
//! be a way to skip one.
//!
//! ## What is checked, and why in this order
//!
//! 1. **Size**, before anything is parsed. An 8 MiB "JWT" should cost a length
//!    comparison, not a base64 decode and a JSON parse.
//! 2. **Structure and `crit`** ([`crate::jws::parse`]). RFC 7515 §4.1.11:
//!    `crit` means "reject if you do not understand this", and we understand
//!    none of them.
//! 3. **Algorithm against the caller's list**, before a key is fetched. RFC
//!    8725 §3.1–3.2.
//! 4. **Signature**, against a key the *resolver* chose — never one the token
//!    named without corroboration.
//! 5. **Claims**, last. A claim in an unverified token is an attacker's
//!    assertion, so nothing about `exp` or `iss` is worth reading until the
//!    signature holds.

use crate::{JoseError, VerifyingKey, jws};
use asterius_domain::{Kid, SigningAlgorithm};
use serde_json::Value;
use std::collections::BTreeSet;
use time::{Duration, OffsetDateTime};

/// Largest JWT accepted, unless a policy says otherwise.
///
/// A client assertion with a long `aud` array and a request object with rich
/// `authorization_details` are the big ones, and both fit comfortably. Beyond
/// this it is not a token, it is a way to make the server do work.
pub const DEFAULT_MAX_BYTES: usize = 8 * 1024;

/// How far into the future an `iat` or `nbf` may be, by default.
///
/// FAPI 2.0 SP §5.3.2.1 item 13: a server **shall accept** timestamps between
/// 0 and 10 seconds in the future, and **shall reject** anything more than 60
/// seconds ahead. Ten is therefore the smallest permitted default, and the
/// least generous one that is still compliant.
pub const DEFAULT_FUTURE_SKEW: Duration = Duration::seconds(10);

/// The furthest into the future any policy may reach.
///
/// The same clause. Above this, a token is not "from a clock that drifted", it
/// is a token minted for later — and accepting it widens every replay window
/// the `jti` cache is sized for.
pub const MAX_FUTURE_SKEW: Duration = Duration::seconds(60);

/// What a caller requires of a token.
#[derive(Debug, Clone)]
pub struct Policy {
    /// What the token's `typ` header must be (RFC 8725 §3.11).
    pub typ: TypRule,
    /// Algorithms this caller will accept. Never read from the token.
    pub allowed_algorithms: Vec<SigningAlgorithm>,
    /// The `iss` the token must carry, when the caller knows it.
    pub expected_issuer: Option<String>,
    /// A value that must appear in `aud`, when the caller knows it.
    pub expected_audience: Option<String>,
    /// Whether `exp` is required. It usually is.
    pub require_expiry: bool,
    /// How far ahead an `iat` or `nbf` may be. Clamped to [`MAX_FUTURE_SKEW`].
    pub future_skew: Duration,
    /// Largest accepted token.
    pub max_bytes: usize,
}

/// What a token's `typ` header must be.
///
/// RFC 8725 §3.11 asks for explicit typing, and every token *this server*
/// issues carries a registered media type. Not every token this server
/// *receives* can: a client assertion is defined by RFC 7523, which predates
/// the recommendation and requires no `typ` at all, so demanding one would
/// reject conforming clients. The distinction is a decision per token type,
/// which is why it is spelled out here rather than assumed.
///
/// Comparison is case-insensitive and tolerates the `application/` prefix,
/// which RFC 7515 §4.1.9 explicitly permits a sender to omit — `JWT`,
/// `jwt` and `application/JWT` are the same media type, and treating them as
/// three would be a rejection with no security value behind it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypRule {
    /// The token must carry exactly this `typ`.
    ///
    /// The right answer for anything with a registered type: `at+jwt`,
    /// `dpop+jwt`, `logout+jwt`, `secevent+jwt`, `oauth-authz-req+jwt`. A token
    /// minted for one purpose must not be presentable as another.
    Exactly(&'static str),
    /// The token may omit `typ`, or carry one of these values.
    ///
    /// Only for token types whose own specification never required one. The
    /// list is still closed: an assertion that announces itself as `at+jwt` is
    /// refused, so this widens what is accepted without erasing the check.
    OptionalOneOf(&'static [&'static str]),
}

impl TypRule {
    /// Whether `claimed` satisfies this rule.
    #[must_use]
    pub fn accepts(&self, claimed: Option<&str>) -> bool {
        match self {
            Self::Exactly(expected) => claimed.is_some_and(|found| Self::same_type(found, expected)),
            Self::OptionalOneOf(accepted) => match claimed {
                None => true,
                Some(found) => accepted
                    .iter()
                    .any(|expected| Self::same_type(found, expected)),
            },
        }
    }

    /// Whether two `typ` values name the same media type.
    fn same_type(found: &str, expected: &str) -> bool {
        fn normalise(value: &str) -> &str {
            // RFC 7515 §4.1.9: a sender MAY omit the `application/` prefix, so
            // a receiver that treats its presence as a different type is
            // rejecting a spelling the specification invited.
            value
                .strip_prefix("application/")
                .or_else(|| value.strip_prefix("APPLICATION/"))
                .unwrap_or(value)
        }
        normalise(found).eq_ignore_ascii_case(normalise(expected))
    }

    /// How to describe this rule in an error, without allocating in the happy
    /// path.
    fn describe(&self) -> String {
        match self {
            Self::Exactly(expected) => (*expected).to_owned(),
            Self::OptionalOneOf(accepted) => format!("absent or one of [{}]", accepted.join(", ")),
        }
    }
}

impl Policy {
    /// A policy for tokens of media type `typ`, with the profile's defaults.
    ///
    /// Deliberately not `Default`: the `typ` and the algorithm list are
    /// decisions, and a caller that has not made them has not thought about
    /// what it is verifying.
    #[must_use]
    pub fn new(typ: TypRule, allowed_algorithms: Vec<SigningAlgorithm>) -> Self {
        Self {
            typ,
            allowed_algorithms,
            expected_issuer: None,
            expected_audience: None,
            require_expiry: true,
            future_skew: DEFAULT_FUTURE_SKEW,
            max_bytes: DEFAULT_MAX_BYTES,
        }
    }

    /// Requires this `iss`.
    #[must_use]
    pub fn issued_by(mut self, issuer: impl Into<String>) -> Self {
        self.expected_issuer = Some(issuer.into());
        self
    }

    /// Requires this value to appear in `aud`.
    #[must_use]
    pub fn for_audience(mut self, audience: impl Into<String>) -> Self {
        self.expected_audience = Some(audience.into());
        self
    }

    /// Widens the future-skew window, up to [`MAX_FUTURE_SKEW`].
    ///
    /// Anything larger is clamped rather than rejected: an operator who
    /// misconfigures this should get a compliant server, not a broken one.
    #[must_use]
    pub fn with_future_skew(mut self, skew: Duration) -> Self {
        self.future_skew = skew.min(MAX_FUTURE_SKEW).max(Duration::ZERO);
        self
    }

    /// Makes `exp` optional. Rare, and worth justifying at the call site.
    #[must_use]
    pub const fn without_expiry(mut self) -> Self {
        self.require_expiry = false;
        self
    }
}

/// Supplies the keys a token might have been signed with.
///
/// The resolver, not the token, decides which keys are candidates. A token's
/// `kid` is a hint used to narrow an already-trusted set — never a pointer the
/// verifier follows.
pub trait KeyResolver {
    /// Keys that could have signed a token bearing this `kid`.
    ///
    /// More than one is normal and is why FAPI 2.0 SP §5.4.3 exists: a client
    /// may publish two keys with the same `kid` and different algorithms, and
    /// a JWKS fetched mid-rotation may contain both the old and new key.
    fn candidates(&self, kid: Option<&Kid>) -> Vec<VerifyingKey>;
}

impl<F> KeyResolver for F
where
    F: Fn(Option<&Kid>) -> Vec<VerifyingKey>,
{
    fn candidates(&self, kid: Option<&Kid>) -> Vec<VerifyingKey> {
        self(kid)
    }
}

/// The claims of a verified token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    /// Every claim, as parsed.
    pub claims: Value,
    /// The key that verified it, so a caller can bind the result to it.
    pub kid: Option<Kid>,
    /// The algorithm that verified it.
    pub algorithm: SigningAlgorithm,
}

impl Verified {
    /// A string claim, if present.
    #[must_use]
    pub fn claim_str(&self, name: &str) -> Option<&str> {
        self.claims.get(name).and_then(Value::as_str)
    }
}

/// Why a token was rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum VerificationError {
    /// The token is larger than the policy allows.
    #[error("token is {size} bytes, limit is {limit}")]
    TooLarge {
        /// The offered size.
        size: usize,
        /// The policy's limit.
        limit: usize,
    },
    /// The token is not a well-formed JWS, or its header is unusable.
    #[error(transparent)]
    Jose(#[from] JoseError),
    /// The algorithm is outside the caller's list.
    #[error("algorithm {found:?} is not accepted here")]
    AlgorithmNotAllowed {
        /// The algorithm the token claimed.
        found: String,
    },
    /// No candidate key verified the signature.
    ///
    /// One error for "no key matched the kid", "the key did not verify" and
    /// "the key was the wrong type": telling them apart tells an attacker
    /// which of their guesses was closest.
    #[error("no key verified this token")]
    NoKeyVerified,
    /// The payload is not a JSON object.
    #[error("claims are not a JSON object")]
    MalformedClaims,
    /// The `typ` header is not one this caller accepts.
    #[error("unexpected typ: expected {expected}, found {}", found.as_deref().unwrap_or("none"))]
    UnexpectedType {
        /// What the policy would have accepted.
        expected: String,
        /// What the token carried, if anything.
        found: Option<String>,
    },
    /// A required claim is absent.
    #[error("missing required claim {0}")]
    MissingClaim(&'static str),
    /// A claim is present but not the required value.
    #[error("{claim} is {found:?}, expected {expected:?}")]
    ClaimMismatch {
        /// Which claim.
        claim: &'static str,
        /// What the policy required.
        expected: String,
        /// What the token carried.
        found: String,
    },
    /// The token has expired.
    #[error("expired at {expired_at}")]
    Expired {
        /// The `exp` the token carried.
        expired_at: i64,
    },
    /// The token is not valid yet, or was minted too far ahead.
    #[error("{claim} is {seconds_ahead}s in the future, limit is {limit}s")]
    TooFarAhead {
        /// Which timestamp claim.
        claim: &'static str,
        /// How far ahead it is.
        seconds_ahead: i64,
        /// The policy's window.
        limit: i64,
    },
}

/// Verifies a token against a policy.
///
/// `now` is passed in rather than read from the clock so that a caller can use
/// the same instant for every check in one request, and so that tests can pin
/// it instead of sleeping.
///
/// # Errors
///
/// Returns [`VerificationError`] describing the first check that failed.
// fuzz-target: jwt_verify
pub fn verify(
    token: &str,
    policy: &Policy,
    resolver: &impl KeyResolver,
    now: OffsetDateTime,
) -> Result<Verified, VerificationError> {
    // Before parsing: an oversized token should cost a comparison.
    if token.len() > policy.max_bytes {
        return Err(VerificationError::TooLarge {
            size: token.len(),
            limit: policy.max_bytes,
        });
    }

    // Structure, `crit`, and the allow-list at the crate level.
    let unverified = jws::parse(token)?;

    // `typ` before anything cryptographic. RFC 8725 §3.11: the cheapest way to
    // establish that this token was even meant for the thing about to consume
    // it, and there is no reason to fetch a key for a token of the wrong type.
    if !policy.typ.accepts(unverified.claimed_typ()) {
        return Err(VerificationError::UnexpectedType {
            expected: policy.typ.describe(),
            found: unverified.claimed_typ().map(ToOwned::to_owned),
        });
    }

    // The caller's list, which may be narrower than the crate's. RFC 8725
    // §3.1–3.2: the algorithm is decided by the verifier, and this is where
    // this verifier decides.
    let claimed = unverified.claimed_alg().to_owned();
    let algorithm = SigningAlgorithm::parse(&claimed)
        .filter(|alg| policy.allowed_algorithms.contains(alg))
        .ok_or(VerificationError::AlgorithmNotAllowed { found: claimed })?;

    let kid = unverified.kid();
    let payload = select_key_and_verify(&unverified, kid.as_ref(), algorithm, resolver)?;

    let claims: Value =
        serde_json::from_slice(&payload).map_err(|_| VerificationError::MalformedClaims)?;
    if !claims.is_object() {
        return Err(VerificationError::MalformedClaims);
    }

    check_claims(&claims, policy, now)?;

    Ok(Verified {
        claims,
        kid,
        algorithm,
    })
}

/// Picks a key among the candidates and verifies with it.
///
/// FAPI 2.0 SP §5.4.3: a `kid` may match more than one key, so a verifier
/// iterates the matches and selects by `alg`, `kty`, `crv` and `use` rather
/// than taking the first. Here the algorithm is already fixed, so candidates
/// whose algorithm differs are dropped and the rest are tried in turn — trying
/// is the only way to distinguish two keys that agree on every attribute,
/// which is exactly the mid-rotation case.
fn select_key_and_verify(
    unverified: &jws::Unverified,
    kid: Option<&Kid>,
    algorithm: SigningAlgorithm,
    resolver: &impl KeyResolver,
) -> Result<Vec<u8>, VerificationError> {
    let candidates: Vec<VerifyingKey> = resolver
        .candidates(kid)
        .into_iter()
        .filter(|key| key.algorithm() == algorithm)
        .collect();

    for key in candidates {
        // `verify` consumes, so each attempt re-parses. Cheap next to a
        // signature check, and it keeps `Unverified` non-reusable, which is
        // what stops a caller verifying once and reading the payload twice.
        let Ok(reparsed) = jws::parse(&format!(
            "{}.{}",
            unverified.signing_input(),
            base64::Engine::encode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                unverified.signature()
            )
        )) else {
            continue;
        };
        if let Ok(payload) = reparsed.verify(&key) {
            return Ok(payload);
        }
    }

    Err(VerificationError::NoKeyVerified)
}

/// Validates the time and identity claims. RFC 8725 §3.8–3.9.
fn check_claims(
    claims: &Value,
    policy: &Policy,
    now: OffsetDateTime,
) -> Result<(), VerificationError> {
    let unix_now = now.unix_timestamp();
    let skew = policy.future_skew.min(MAX_FUTURE_SKEW).whole_seconds();

    // exp — no leeway by default. A token whose lifetime has run out is not
    // "nearly valid"; the whole point of a short lifetime is that it ends.
    match numeric_claim(claims, "exp") {
        Some(exp) => {
            if exp <= unix_now {
                return Err(VerificationError::Expired { expired_at: exp });
            }
        }
        None if policy.require_expiry => return Err(VerificationError::MissingClaim("exp")),
        None => {}
    }

    // nbf and iat — FAPI 2.0 SP §5.3.2.1 item 13.
    for claim in ["nbf", "iat"] {
        if let Some(value) = numeric_claim(claims, claim) {
            let ahead = value - unix_now;
            if ahead > skew {
                return Err(VerificationError::TooFarAhead {
                    claim: if claim == "nbf" { "nbf" } else { "iat" },
                    seconds_ahead: ahead,
                    limit: skew,
                });
            }
        }
    }

    if let Some(expected) = &policy.expected_issuer {
        let found = claims
            .get("iss")
            .and_then(Value::as_str)
            .ok_or(VerificationError::MissingClaim("iss"))?;
        if found != expected {
            return Err(VerificationError::ClaimMismatch {
                claim: "iss",
                expected: expected.clone(),
                found: found.to_owned(),
            });
        }
    }

    if let Some(expected) = &policy.expected_audience {
        let audiences = audience_values(claims).ok_or(VerificationError::MissingClaim("aud"))?;
        if !audiences.contains(expected.as_str()) {
            return Err(VerificationError::ClaimMismatch {
                claim: "aud",
                expected: expected.clone(),
                found: audiences.into_iter().collect::<Vec<_>>().join(","),
            });
        }
    }

    Ok(())
}

/// Reads a NumericDate claim (RFC 7519 §2), which is a number of seconds.
///
/// A string is not a NumericDate, however numeric it looks. Accepting `"1700"`
/// is how a parser ends up with two ways to express the same claim, and two
/// ways is one more than a security check should have.
fn numeric_claim(claims: &Value, name: &str) -> Option<i64> {
    let value = claims.get(name)?;
    value.as_i64().or_else(|| {
        // A NumericDate may carry a fractional part.
        #[expect(
            clippy::cast_possible_truncation,
            reason = "seconds since the epoch; the fraction is what we are discarding"
        )]
        value.as_f64().map(|seconds| seconds.trunc() as i64)
    })
}

/// `aud` is a string or an array of strings (RFC 7519 §4.1.3).
fn audience_values(claims: &Value) -> Option<BTreeSet<&str>> {
    match claims.get("aud")? {
        Value::String(single) => Some(BTreeSet::from([single.as_str()])),
        Value::Array(many) => Some(many.iter().filter_map(Value::as_str).collect()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SigningKey;
    use serde_json::json;

    const TYP: &str = "oauth-authz-req+jwt";

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_760_000_000).expect("fixed instant")
    }

    fn policy() -> Policy {
        Policy::new(TypRule::Exactly(TYP), vec![SigningAlgorithm::EdDsa])
    }

    /// Builds a token and a resolver that offers only the key that signed it.
    fn token_with(
        algorithm: SigningAlgorithm,
        typ: &str,
        claims: &Value,
    ) -> (String, impl KeyResolver + use<>) {
        let key = SigningKey::generate(algorithm).expect("generate");
        let jws = jws::sign(&key, &Kid::new("k1"), typ, claims).expect("sign");
        let verifying = key.verifying_key().expect("public");
        (jws.as_str().to_owned(), move |_: Option<&Kid>| {
            vec![verifying.clone()]
        })
    }

    /// A token with no `typ` header at all.
    ///
    /// `jws::sign` always writes one, deliberately, so this builds the header
    /// by hand — which is the only way to produce what RFC 7523 permits a
    /// client to send.
    fn token_without_typ(
        algorithm: SigningAlgorithm,
        claims: &Value,
    ) -> (String, impl KeyResolver + use<>) {
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;

        let key = SigningKey::generate(algorithm).expect("generate");
        let header = json!({"alg": algorithm.as_str(), "kid": "k1"});
        let signing_input = format!(
            "{}.{}",
            B64.encode(serde_json::to_vec(&header).expect("json")),
            B64.encode(serde_json::to_vec(claims).expect("json"))
        );
        let signature = key.sign(signing_input.as_bytes()).expect("sign");
        let token = format!("{signing_input}.{}", B64.encode(signature));
        let verifying = key.verifying_key().expect("public");
        (token, move |_: Option<&Kid>| vec![verifying.clone()])
    }

    fn valid_claims() -> Value {
        json!({
            "iss": "https://client.example",
            "aud": "https://as.example/t/demo",
            "exp": now().unix_timestamp() + 300,
            "iat": now().unix_timestamp(),
            "jti": "abc",
        })
    }

    #[test]
    fn a_well_formed_token_verifies() {
        let (token, resolver) = token_with(SigningAlgorithm::EdDsa, TYP, &valid_claims());
        let verified = verify(&token, &policy(), &resolver, now()).expect("verify");
        assert_eq!(verified.claim_str("iss"), Some("https://client.example"));
        assert_eq!(verified.kid, Some(Kid::new("k1")));
        assert_eq!(verified.algorithm, SigningAlgorithm::EdDsa);
    }

    // ---- typ, crit, alg (RFC 8725 §3.1–3.3, §3.5, §3.11) -----------------

    #[test]
    fn a_token_of_the_wrong_type_is_refused() {
        // The rejection is now named. It used to surface as `NoKeyVerified`,
        // because the type was checked during key selection and a mismatch
        // simply exhausted the candidates — a true statement that told an
        // operator nothing about why.
        for wrong in ["at+jwt", "dpop+jwt", "logout+jwt", "JWT", ""] {
            let (token, resolver) = token_with(SigningAlgorithm::EdDsa, wrong, &valid_claims());
            assert_eq!(
                verify(&token, &policy(), &resolver, now()),
                Err(VerificationError::UnexpectedType {
                    expected: TYP.to_owned(),
                    found: Some(wrong.to_owned()),
                }),
                "accepted typ {wrong:?}"
            );
        }
    }

    /// A `typ` this policy demands cannot be satisfied by leaving it out.
    #[test]
    fn an_absent_type_is_refused_when_the_policy_names_one() {
        let (token, resolver) = token_without_typ(SigningAlgorithm::EdDsa, &valid_claims());
        assert_eq!(
            verify(&token, &policy(), &resolver, now()),
            Err(VerificationError::UnexpectedType {
                expected: TYP.to_owned(),
                found: None,
            })
        );
    }

    /// RFC 7523 defines no `typ` for a client assertion, so a policy for one
    /// must accept its absence — and must still refuse a token that announces
    /// itself as something else.
    #[test]
    fn an_optional_type_accepts_absence_and_the_listed_spellings_only() {
        let assertion = Policy::new(
            TypRule::OptionalOneOf(&["JWT", "client-authentication+jwt"]),
            vec![SigningAlgorithm::EdDsa],
        );

        let (token, resolver) = token_without_typ(SigningAlgorithm::EdDsa, &valid_claims());
        assert!(verify(&token, &assertion, &resolver, now()).is_ok(), "absent");

        // RFC 7515 §4.1.9 lets a sender omit the `application/` prefix, and
        // RFC 7519 §5.1 only *recommends* upper case, so all of these name the
        // same media type.
        for spelling in ["JWT", "jwt", "Jwt", "application/JWT", "application/jwt"] {
            let (token, resolver) =
                token_with(SigningAlgorithm::EdDsa, spelling, &valid_claims());
            assert!(
                verify(&token, &assertion, &resolver, now()).is_ok(),
                "refused {spelling:?}, which is the same media type as JWT"
            );
        }

        // Widened, not erased: a token minted as an access token is still not
        // a client assertion.
        let (token, resolver) = token_with(SigningAlgorithm::EdDsa, "at+jwt", &valid_claims());
        assert_eq!(
            verify(&token, &assertion, &resolver, now()),
            Err(VerificationError::UnexpectedType {
                expected: "absent or one of [JWT, client-authentication+jwt]".to_owned(),
                found: Some("at+jwt".to_owned()),
            })
        );
    }

    /// The caller's list is narrower than the crate's, and it wins.
    #[test]
    fn an_algorithm_outside_the_callers_list_is_refused() {
        let (token, resolver) = token_with(SigningAlgorithm::Es256, TYP, &valid_claims());
        let error = verify(&token, &policy(), &resolver, now()).expect_err("must refuse");
        assert_eq!(
            error,
            VerificationError::AlgorithmNotAllowed {
                found: "ES256".to_owned()
            }
        );
    }

    /// The RS/HS confusion test the ticket asks for: a token claiming a
    /// symmetric or absent algorithm must not reach a key at all.
    #[test]
    fn a_token_claiming_none_or_hs256_never_reaches_a_key() {
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;

        let (token, resolver) = token_with(SigningAlgorithm::EdDsa, TYP, &valid_claims());
        let segments: Vec<&str> = token.split('.').collect();

        for hostile in ["none", "HS256", "RS256"] {
            let header = json!({"alg": hostile, "typ": TYP, "kid": "k1"});
            let forged = format!(
                "{}.{}.{}",
                B64.encode(serde_json::to_vec(&header).expect("json")),
                segments[1],
                segments[2]
            );
            let error = verify(&forged, &policy(), &resolver, now()).expect_err("must refuse");
            // Refused by the crate-level allow-list before the policy is even
            // consulted, which is the strongest place to refuse it.
            assert!(
                matches!(
                    error,
                    VerificationError::Jose(JoseError::UnsupportedAlgorithm(_))
                        | VerificationError::AlgorithmNotAllowed { .. }
                ),
                "{hostile}: {error}"
            );
        }
    }

    // ---- signature and key selection -------------------------------------

    #[test]
    fn a_token_no_offered_key_signed_is_refused() {
        let (token, _) = token_with(SigningAlgorithm::EdDsa, TYP, &valid_claims());
        let stranger = SigningKey::generate(SigningAlgorithm::EdDsa).expect("generate");
        let resolver = move |_: Option<&Kid>| vec![stranger.verifying_key().expect("public")];
        assert_eq!(
            verify(&token, &policy(), &resolver, now()),
            Err(VerificationError::NoKeyVerified)
        );
    }

    #[test]
    fn a_resolver_with_no_keys_refuses_rather_than_succeeding_vacuously() {
        let (token, _) = token_with(SigningAlgorithm::EdDsa, TYP, &valid_claims());
        let empty = |_: Option<&Kid>| Vec::new();
        assert_eq!(
            verify(&token, &policy(), &empty, now()),
            Err(VerificationError::NoKeyVerified)
        );
    }

    /// FAPI 2.0 SP §5.4.3: a `kid` may match several keys, so the verifier
    /// tries the matches rather than taking the first. This is the
    /// mid-rotation case — two keys, same `kid`, only one of which signed.
    #[test]
    fn a_duplicate_kid_is_resolved_by_trying_every_candidate() {
        let signer = SigningKey::generate(SigningAlgorithm::EdDsa).expect("generate");
        let jws = jws::sign(&signer, &Kid::new("shared"), TYP, &valid_claims()).expect("sign");

        let decoy = SigningKey::generate(SigningAlgorithm::EdDsa).expect("generate");
        let real = signer.verifying_key().expect("public");
        let wrong = decoy.verifying_key().expect("public");

        // The decoy first, so passing cannot be an accident of ordering.
        let resolver = move |_: Option<&Kid>| vec![wrong.clone(), real.clone()];
        let verified = verify(jws.as_str(), &policy(), &resolver, now()).expect("verify");
        assert_eq!(verified.kid, Some(Kid::new("shared")));
    }

    /// Candidates whose algorithm differs are dropped before any signature
    /// check: a P-256 key must never be handed Ed25519 bytes.
    #[test]
    fn candidates_of_the_wrong_algorithm_are_not_tried() {
        let signer = SigningKey::generate(SigningAlgorithm::EdDsa).expect("generate");
        let jws = jws::sign(&signer, &Kid::new("k1"), TYP, &valid_claims()).expect("sign");
        let other_alg = SigningKey::generate(SigningAlgorithm::Es256).expect("generate");

        let wrong = other_alg.verifying_key().expect("public");
        let resolver = move |_: Option<&Kid>| vec![wrong.clone()];
        assert_eq!(
            verify(jws.as_str(), &policy(), &resolver, now()),
            Err(VerificationError::NoKeyVerified)
        );
    }

    // ---- clock (FAPI 2.0 SP §5.3.2.1 item 13) ----------------------------

    fn at_offset(claim: &str, offset: i64) -> (String, impl KeyResolver + use<>) {
        let mut claims = valid_claims();
        claims[claim] = json!(now().unix_timestamp() + offset);
        token_with(SigningAlgorithm::EdDsa, TYP, &claims)
    }

    /// "shall accept JWTs with an iat or nbf timestamp between 0 and 10
    /// seconds in the future".
    #[test]
    fn a_timestamp_up_to_ten_seconds_ahead_is_accepted() {
        for claim in ["iat", "nbf"] {
            for offset in [0, 1, 5, 10] {
                let (token, resolver) = at_offset(claim, offset);
                assert!(
                    verify(&token, &policy(), &resolver, now()).is_ok(),
                    "{claim} at +{offset}s was refused, which the profile forbids"
                );
            }
        }
    }

    #[test]
    fn a_timestamp_beyond_the_window_is_refused_by_default() {
        for claim in ["iat", "nbf"] {
            let (token, resolver) = at_offset(claim, 11);
            let error = verify(&token, &policy(), &resolver, now()).expect_err("must refuse");
            assert!(
                matches!(error, VerificationError::TooFarAhead { .. }),
                "{claim}: {error}"
            );
        }
    }

    /// "shall reject JWTs with an iat or nbf timestamp greater than 60 seconds
    /// in the future" — even when configuration asks for more.
    #[test]
    fn the_skew_window_cannot_be_widened_past_sixty_seconds() {
        let generous = policy().with_future_skew(Duration::seconds(3600));
        assert_eq!(generous.future_skew, MAX_FUTURE_SKEW);

        for claim in ["iat", "nbf"] {
            let (accepted, resolver) = at_offset(claim, 60);
            assert!(
                verify(&accepted, &generous, &resolver, now()).is_ok(),
                "{claim} at +60s"
            );

            let (refused, resolver) = at_offset(claim, 61);
            assert!(
                matches!(
                    verify(&refused, &generous, &resolver, now()),
                    Err(VerificationError::TooFarAhead { .. })
                ),
                "{claim} at +61s was accepted, which the profile forbids"
            );
        }
    }

    #[test]
    fn a_widened_window_accepts_what_the_default_refuses() {
        let (token, resolver) = at_offset("iat", 30);
        assert!(verify(&token, &policy(), &resolver, now()).is_err());
        let widened = policy().with_future_skew(Duration::seconds(45));
        assert!(verify(&token, &widened, &resolver, now()).is_ok());
    }

    #[test]
    fn an_expired_token_is_refused_with_no_leeway() {
        for offset in [0, -1, -300] {
            let mut claims = valid_claims();
            claims["exp"] = json!(now().unix_timestamp() + offset);
            let (token, resolver) = token_with(SigningAlgorithm::EdDsa, TYP, &claims);
            assert!(
                matches!(
                    verify(&token, &policy(), &resolver, now()),
                    Err(VerificationError::Expired { .. })
                ),
                "exp at {offset}s was accepted"
            );
        }
    }

    #[test]
    fn a_missing_expiry_is_refused_unless_the_caller_says_otherwise() {
        let mut claims = valid_claims();
        claims.as_object_mut().expect("object").remove("exp");
        let (token, resolver) = token_with(SigningAlgorithm::EdDsa, TYP, &claims);

        assert_eq!(
            verify(&token, &policy(), &resolver, now()),
            Err(VerificationError::MissingClaim("exp"))
        );
        assert!(verify(&token, &policy().without_expiry(), &resolver, now()).is_ok());
    }

    // ---- identity claims -------------------------------------------------

    #[test]
    fn the_issuer_must_be_the_expected_one() {
        let (token, resolver) = token_with(SigningAlgorithm::EdDsa, TYP, &valid_claims());
        let policy = policy().issued_by("https://client.example");
        assert!(verify(&token, &policy, &resolver, now()).is_ok());

        let wrong = policy.clone().issued_by("https://attacker.example");
        assert!(matches!(
            verify(&token, &wrong, &resolver, now()),
            Err(VerificationError::ClaimMismatch { claim: "iss", .. })
        ));
    }

    /// RFC 7519 §4.1.3: `aud` is a string or an array of strings, and both
    /// spellings must be checked the same way.
    #[test]
    fn the_audience_is_checked_in_both_of_its_spellings() {
        let us = "https://as.example/t/demo";

        for audience in [json!(us), json!([us]), json!(["https://other.example", us])] {
            let mut claims = valid_claims();
            claims["aud"] = audience.clone();
            let (token, resolver) = token_with(SigningAlgorithm::EdDsa, TYP, &claims);
            assert!(
                verify(&token, &policy().for_audience(us), &resolver, now()).is_ok(),
                "aud {audience} was refused"
            );
        }

        // An audience that does not include us must fail, however it is spelled.
        for audience in [
            json!("https://other.example"),
            json!(["https://other.example"]),
        ] {
            let mut claims = valid_claims();
            claims["aud"] = audience.clone();
            let (token, resolver) = token_with(SigningAlgorithm::EdDsa, TYP, &claims);
            assert!(
                matches!(
                    verify(&token, &policy().for_audience(us), &resolver, now()),
                    Err(VerificationError::ClaimMismatch { claim: "aud", .. })
                ),
                "aud {audience} was accepted"
            );
        }
    }

    /// RFC 7519 §2: a NumericDate is a number. A string that looks like one is
    /// not, and treating it as one would give two ways to express `exp`.
    #[test]
    fn a_timestamp_claim_that_is_not_a_number_is_not_a_timestamp() {
        let mut claims = valid_claims();
        claims["exp"] = json!("9999999999");
        let (token, resolver) = token_with(SigningAlgorithm::EdDsa, TYP, &claims);
        assert_eq!(
            verify(&token, &policy(), &resolver, now()),
            Err(VerificationError::MissingClaim("exp")),
            "a string was accepted as a NumericDate"
        );
    }

    // ---- size ------------------------------------------------------------

    #[test]
    fn an_oversized_token_is_refused_before_it_is_parsed() {
        let (_, resolver) = token_with(SigningAlgorithm::EdDsa, TYP, &valid_claims());
        let huge = "x".repeat(DEFAULT_MAX_BYTES + 1);
        assert!(matches!(
            verify(&huge, &policy(), &resolver, now()),
            Err(VerificationError::TooLarge { .. })
        ));
    }

    #[test]
    fn the_size_limit_is_a_policy_decision() {
        let mut claims = valid_claims();
        claims["padding"] = json!("p".repeat(4096));
        let (token, resolver) = token_with(SigningAlgorithm::EdDsa, TYP, &claims);

        assert!(verify(&token, &policy(), &resolver, now()).is_ok());

        let tight = Policy {
            max_bytes: 128,
            ..policy()
        };
        assert!(matches!(
            verify(&token, &tight, &resolver, now()),
            Err(VerificationError::TooLarge { .. })
        ));
    }

    #[test]
    fn a_payload_that_is_not_a_json_object_is_refused() {
        let key = SigningKey::generate(SigningAlgorithm::EdDsa).expect("generate");
        for payload in [json!("a string"), json!([1, 2, 3]), json!(42), json!(null)] {
            let jws = jws::sign(&key, &Kid::new("k1"), TYP, &payload).expect("sign");
            let verifying = key.verifying_key().expect("public");
            let resolver = move |_: Option<&Kid>| vec![verifying.clone()];
            assert_eq!(
                verify(jws.as_str(), &policy().without_expiry(), &resolver, now()),
                Err(VerificationError::MalformedClaims),
                "accepted payload {payload}"
            );
        }
    }
}
