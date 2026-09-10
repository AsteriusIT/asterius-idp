//! Client authentication: which method a request offered, and what a
//! `private_key_jwt` assertion must say.
//!
//! FAPI 2.0 SP §5.3.2.1 item 6 leaves exactly two ways for a client to
//! authenticate — mTLS (RFC 8705 §2) or `private_key_jwt` (OIDC Core §9). No
//! shared secret, in any spelling. This module owns the second one's *rules*:
//! which claims must be present, what they must say, and which OAuth error a
//! violation maps to.
//!
//! # What is here, and what is deliberately not
//!
//! Nothing here touches a key, a signature or a database. That is not an
//! accident of layering — it is what makes these rules testable as pure
//! functions over a claims object, and every one of the cases below runs in
//! microseconds with no fixture.
//!
//! The composition — resolve the client's keys, check the signature, apply
//! these rules, then consume the `jti` — lives in `asterius_server::client_auth`,
//! because verifying a signature needs `asterius-jose` and this crate must not
//! reach it (`scripts/check-layering.sh`).
//!
//! # Signature first. Always.
//!
//! [`check_assertion`] reads claims. **A claim in a token whose signature has
//! not been checked is an attacker's assertion, not the client's.** Every
//! function here assumes its caller has already verified the JWS against a key
//! that belongs to the client named by `sub`. Calling them on an unverified
//! token tells you what an attacker wanted you to believe.
//!
//! There is one caller, and it verifies first. If a second appears, it must
//! too.

use crate::mtls::ClientCertificate;
use serde_json::Value;
use time::{Duration, OffsetDateTime};

/// The `client_assertion_type` a `private_key_jwt` request must carry.
///
/// RFC 7521 §4.2. There is exactly one accepted value and it is compared
/// byte-for-byte: this is a fixed protocol constant, not a URL to be parsed.
pub const CLIENT_ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// The longest assertion lifetime accepted unless a tenant narrows it.
///
/// OIDC Core §9 requires `exp` but sets no bound, so a client could mint one
/// valid for a year and hand this server a credential it must remember for a
/// year to detect a replay. Ten minutes keeps the `jti` table proportional to
/// traffic rather than to the most optimistic client.
pub const DEFAULT_MAX_ASSERTION_LIFETIME: Duration = Duration::minutes(10);

/// The longest `jti` this server will store.
///
/// The value is chosen by the client and is only ever compared for equality,
/// so its length is pure cost. It is hashed before storage, which bounds the
/// row — but not the bytes parsed to get there.
pub const MAX_JTI_LEN: usize = 255;

/// Why client authentication failed.
///
/// Each variant maps to an OAuth error code through [`ClientAuthError::code`].
/// The split matters: `invalid_request` says "this request is malformed", and
/// `invalid_client` says "the credential did not check out". Returning the
/// second for the first would tell a client its key is wrong when its form
/// encoding is.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ClientAuthError {
    /// More than one authentication method in one request.
    ///
    /// RFC 6749 §2.3: a client "MUST NOT use more than one authentication
    /// method in each request". Two credentials means the server has to pick,
    /// and a server that picks is a server an attacker can steer.
    #[error("more than one client authentication method was presented")]
    MultipleMethods,
    /// No client authentication at all.
    #[error("no client authentication was presented")]
    NoMethod,
    /// `client_assertion` present without the matching type, or vice versa.
    #[error("client_assertion and client_assertion_type must be presented together")]
    IncompleteAssertion,
    /// `client_assertion_type` is not [`CLIENT_ASSERTION_TYPE`].
    #[error("unsupported client_assertion_type")]
    UnsupportedAssertionType,
    /// The `client_id` form parameter disagrees with the assertion's `sub`.
    ///
    /// RFC 7521 §4.2 permits `client_id` alongside the assertion, and OIDC
    /// Core §9 makes `sub` the client. When both are present and disagree, the
    /// request names two clients.
    #[error("client_id does not match the assertion subject")]
    ClientIdMismatch,
    /// The assertion is not a well-formed JWT, or its signature did not verify
    /// under any of the client's keys.
    ///
    /// Deliberately coarse. Which key was tried, and how far parsing got, are
    /// facts about this server's state that an unauthenticated caller has not
    /// earned.
    #[error("the client assertion did not verify")]
    AssertionNotVerified,
    /// A required claim is missing or the wrong JSON type.
    #[error("client assertion claim {0} is missing or malformed")]
    MalformedClaim(&'static str),
    /// `iss` or `sub` is not the authenticated client.
    #[error("client assertion issuer and subject must both be the client_id")]
    WrongSubject,
    /// `aud` is not a value this endpoint accepts.
    ///
    /// FAPI 2.0 SP §5.3.2.1 item 8 — see [`Audiences`].
    #[error("client assertion audience is not this server")]
    WrongAudience,
    /// The assertion is valid for longer than the tenant permits.
    #[error("client assertion lifetime exceeds the permitted maximum")]
    LifetimeTooLong,
    /// The assertion's `exp` has passed.
    ///
    /// The JWT verifier rejects this before [`check_assertion`] is reached, so
    /// in the composed path it is unreachable. It exists so that the rule is
    /// *also* true of this function alone — see the note on [`check_assertion`].
    #[error("client assertion has expired")]
    Expired,
    /// This `jti` has already been used inside its validity window.
    #[error("client assertion has already been used")]
    ReplayedAssertion,
    /// No such client, or the client is disabled.
    ///
    /// One variant for both, on purpose: distinguishing them tells an
    /// unauthenticated caller which `client_id` values exist.
    #[error("unknown or disabled client")]
    UnknownClient,
    /// The client is registered to authenticate some other way.
    #[error("the client is not registered for this authentication method")]
    WrongMethodForClient,
    /// The client's keys could not be resolved.
    #[error("the client's keys are unavailable")]
    KeysUnavailable,
}

impl ClientAuthError {
    /// The OAuth 2.0 error code for this failure (RFC 6749 §5.2).
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            // Malformed request: the client has not made a coherent attempt.
            Self::MultipleMethods | Self::IncompleteAssertion | Self::UnsupportedAssertionType => {
                "invalid_request"
            }
            // Everything else is a credential that did not check out. Note
            // that `NoMethod` is `invalid_client`: at these endpoints
            // authentication is required, so its absence is a failed
            // authentication and not a malformed request.
            _ => "invalid_client",
        }
    }

    /// The HTTP status this failure is reported with.
    ///
    /// RFC 6749 §5.2: `invalid_client` MAY be 401, and everything else is 400.
    /// The `WWW-Authenticate` header that section requires alongside a 401
    /// applies only when the client "attempted to authenticate via the
    /// Authorization request header field" — `private_key_jwt` is carried in
    /// the form body, so this server never has one to send.
    #[must_use]
    pub const fn status(&self) -> u16 {
        match self.code().as_bytes() {
            b"invalid_client" => 401,
            _ => 400,
        }
    }
}

/// What a request offered as client authentication.
///
/// Built from the request before anything is verified, so that "you sent two
/// credentials" is answered before either is examined.
#[derive(Debug, Clone, Copy, Default)]
pub struct Attempt<'a> {
    /// The `client_assertion` form parameter.
    pub assertion: Option<&'a str>,
    /// The `client_assertion_type` form parameter.
    pub assertion_type: Option<&'a str>,
    /// The `client_id` form parameter, which RFC 7521 §4.2 permits alongside
    /// an assertion.
    pub client_id: Option<&'a str>,
    /// Whether the request carried an `Authorization` header of any kind.
    ///
    /// This server accepts none — there is no `client_secret_basic` here — but
    /// a header *plus* an assertion is still two attempts, and RFC 6749 §2.3
    /// makes that the client's error rather than something to silently ignore.
    pub authorization_header: bool,
    /// The client certificate this request arrived with, if any.
    ///
    /// `Some` means a certificate reached this server from a source it trusts
    /// — its own TLS layer, or a proxy inside `trusted_proxies`. It does **not**
    /// mean the certificate has been validated against anything: RFC 8705 §2.1
    /// and §2.2 validate it in completely different ways, and which one applies
    /// is a fact about the *client*, which is not known yet at the point this
    /// is built.
    pub certificate: Option<&'a ClientCertificate>,
}

/// The authentication method a request is actually making a play for.
///
/// Closed, and deliberately not `#[non_exhaustive]`: FAPI 2.0 SP §5.3.2.1
/// item 6 permits exactly these two. If a third is ever added, every place
/// that dispatches on a method should stop compiling until it has an answer
/// for it — that is the point of a closed enum here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// A signed assertion (OIDC Core §9, RFC 7523 §2.2).
    PrivateKeyJwt,
    /// A client certificate at the TLS layer (RFC 8705 §2).
    Mtls,
}

impl Attempt<'_> {
    /// Which single method this request presents.
    ///
    /// # Errors
    ///
    /// [`ClientAuthError::MultipleMethods`] if it presents more than one,
    /// [`ClientAuthError::NoMethod`] if none, and
    /// [`ClientAuthError::IncompleteAssertion`] or
    /// [`ClientAuthError::UnsupportedAssertionType`] if the assertion pair is
    /// malformed.
    pub fn method(&self) -> Result<Method, ClientAuthError> {
        // Count attempts before judging any of them. A request carrying both a
        // certificate and an assertion is ambiguous however good each is.
        let assertion_offered = self.assertion.is_some() || self.assertion_type.is_some();
        let offered = usize::from(assertion_offered)
            + usize::from(self.certificate.is_some())
            + usize::from(self.authorization_header);
        if offered > 1 {
            return Err(ClientAuthError::MultipleMethods);
        }

        if assertion_offered {
            // Both halves or neither. One half is a client that thinks it
            // authenticated.
            let (Some(_), Some(kind)) = (self.assertion, self.assertion_type) else {
                return Err(ClientAuthError::IncompleteAssertion);
            };
            if kind != CLIENT_ASSERTION_TYPE {
                return Err(ClientAuthError::UnsupportedAssertionType);
            }
            return Ok(Method::PrivateKeyJwt);
        }

        if self.certificate.is_some() {
            return Ok(Method::Mtls);
        }

        // An `Authorization` header on its own is a method this server does
        // not implement, which is a failed authentication rather than a
        // malformed request.
        Err(ClientAuthError::NoMethod)
    }
}

/// The `aud` values one endpoint will accept in a client assertion.
///
/// FAPI 2.0 SP §5.3.2.1 item 8 is unusually specific: the server
///
/// > shall only accept its issuer identifier value (as defined in RFC8414) as
/// > a string in the `aud` claim received in client authentication assertions
///
/// Two separate requirements sit in that sentence, and this type enforces
/// both.
///
/// **The value.** Only the issuer identifier. OIDC Core §9 historically also
/// allowed the token endpoint's URL, and a lot of client software still sends
/// it; FAPI 2.0 withdraws that. An assertion is a bearer credential for the
/// audience it names, so accepting several spellings of "this server" means an
/// assertion minted for one endpoint is replayable at another.
///
/// **The form.** A JSON *string*, never an array — even a single-element array
/// containing the right issuer. This is the part that looks pedantic and is
/// not: an array lets a client mint one assertion naming this server *and*
/// somebody else, so a hostile audience can forward it here and be
/// authenticated as that client. Refusing the array form removes the
/// possibility rather than checking for it.
#[derive(Debug, Clone)]
pub struct Audiences(Vec<String>);

impl Audiences {
    /// The ordinary case: the issuer identifier, and nothing else.
    ///
    /// Correct at the token, PAR, introspection, revocation and
    /// device-authorization endpoints — everywhere except one.
    #[must_use]
    pub fn issuer_only(issuer: impl Into<String>) -> Self {
        Self(vec![issuer.into()])
    }

    /// The CIBA backchannel authentication endpoint's wider set.
    ///
    /// CIBA Core 1.0 §7.1 requires that endpoint to accept the issuer, the
    /// token endpoint URL, or the backchannel authentication endpoint URL. It
    /// is a documented deviation from FAPI's "issuer only", scoped to the one
    /// endpoint whose own specification demands it, and it is spelled out as
    /// its own constructor so it cannot be reached by default.
    #[must_use]
    pub fn ciba_backchannel(
        issuer: impl Into<String>,
        token_endpoint: impl Into<String>,
        backchannel_endpoint: impl Into<String>,
    ) -> Self {
        Self(vec![
            issuer.into(),
            token_endpoint.into(),
            backchannel_endpoint.into(),
        ])
    }

    /// Whether `claims["aud"]` names this server acceptably.
    fn accepts(&self, aud: Option<&Value>) -> bool {
        // A string, and only a string. `Value::as_str` returns `None` for an
        // array, which is the whole rule.
        aud.and_then(Value::as_str)
            .is_some_and(|found| self.0.iter().any(|allowed| allowed == found))
    }
}

/// How this endpoint judges an assertion.
#[derive(Debug, Clone)]
pub struct AssertionRules {
    /// What `aud` may say.
    pub audiences: Audiences,
    /// The longest permitted `exp - now`.
    pub max_lifetime: Duration,
}

impl AssertionRules {
    /// Rules for an endpoint that accepts only the issuer as `aud`.
    #[must_use]
    pub fn for_issuer(issuer: impl Into<String>) -> Self {
        Self {
            audiences: Audiences::issuer_only(issuer),
            max_lifetime: DEFAULT_MAX_ASSERTION_LIFETIME,
        }
    }

    /// Narrows the permitted lifetime.
    ///
    /// A tenant may shorten this. Lengthening past
    /// [`DEFAULT_MAX_ASSERTION_LIFETIME`] is clamped rather than refused: an
    /// operator who sets it badly should get a compliant server, not one that
    /// remembers a `jti` for a year.
    #[must_use]
    pub fn with_max_lifetime(mut self, lifetime: Duration) -> Self {
        self.max_lifetime = lifetime.clamp(Duration::ZERO, DEFAULT_MAX_ASSERTION_LIFETIME);
        self
    }
}

/// What a valid assertion established.
///
/// Returned rather than discarded because the caller still owes the replay
/// store a row, and it should not have to re-read the claims to build it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assertion {
    /// The `jti`, single-use within its lifetime.
    pub jti: String,
    /// The assertion's `exp`, which is when its replay entry may be dropped.
    pub expires_at: OffsetDateTime,
}

/// Applies the client-assertion rules to a **signature-verified** claim set.
///
/// `client_id` is the client the caller resolved keys for and verified the
/// signature against.
///
/// # Signature first
///
/// See the module documentation. This function cannot tell whether the token
/// it is reading was signed, and it does not try; it is the caller's job to
/// have checked, and every claim below is meaningless otherwise.
///
/// # What is checked here, and what was checked already
///
/// An `iat`/`nbf` too far ahead is enforced by the JWT verifier against FAPI
/// 2.0 SP §5.3.2.1 item 13 before this is reached. What is checked here is
/// what is specific to a *client assertion*: who it names, who it is for, that
/// it can be replay-detected, and that it does not last so long that detecting
/// a replay becomes this server's problem to store.
///
/// `exp` in the past is checked in *both* places. The verifier gets there
/// first, so the variant is unreachable in the composed path — but this
/// function is a public rule about client assertions, and "the caller happens
/// to check that" is not something a second caller inherits.
///
/// # Errors
///
/// Returns the first [`ClientAuthError`] that applies.
// fuzz-target: client_assertion
pub fn check_assertion(
    claims: &Value,
    client_id: &str,
    rules: &AssertionRules,
    now: OffsetDateTime,
) -> Result<Assertion, ClientAuthError> {
    // OIDC Core §9: `iss` and `sub` are both the client. Two claims saying the
    // same thing is not redundancy here — an assertion where they differ is
    // one party vouching for another, which is a different protocol.
    let issuer = claims
        .get("iss")
        .and_then(Value::as_str)
        .ok_or(ClientAuthError::MalformedClaim("iss"))?;
    let subject = claims
        .get("sub")
        .and_then(Value::as_str)
        .ok_or(ClientAuthError::MalformedClaim("sub"))?;
    if issuer != client_id || subject != client_id {
        return Err(ClientAuthError::WrongSubject);
    }

    if !rules.audiences.accepts(claims.get("aud")) {
        return Err(ClientAuthError::WrongAudience);
    }

    // RFC 7523 §3 item 7: `jti` is what makes single use enforceable. Without
    // it there is nothing to remember, so an assertion without one is refused
    // rather than accepted-and-not-tracked.
    let jti = claims
        .get("jti")
        .and_then(Value::as_str)
        .filter(|jti| !jti.is_empty() && jti.len() <= MAX_JTI_LEN)
        .ok_or(ClientAuthError::MalformedClaim("jti"))?;

    // `exp` is required by OIDC Core §9 and already known to be in the future.
    // What is new here is the ceiling.
    let exp = claims
        .get("exp")
        .and_then(Value::as_i64)
        .ok_or(ClientAuthError::MalformedClaim("exp"))?;
    let expires_at = OffsetDateTime::from_unix_timestamp(exp)
        .map_err(|_| ClientAuthError::MalformedClaim("exp"))?;
    // Both ends of the window, deliberately including the one the verifier has
    // already checked.
    //
    // Duplication here was a finding, not an oversight: the fuzz target
    // asserted that an accepted assertion is unexpired, and this function
    // accepted one that was, because it trusted a check that happens in its
    // caller. That is true of the caller that exists today and is not a
    // property of this function — and CIBA (`ast-lh3.4`) will add a second
    // caller. A rule that holds only in composition is a rule waiting for the
    // composition to change. This one cannot drift: "not expired" has no
    // policy knob to disagree about.
    if expires_at <= now {
        return Err(ClientAuthError::Expired);
    }
    if expires_at - now > rules.max_lifetime {
        return Err(ClientAuthError::LifetimeTooLong);
    }

    Ok(Assertion {
        jti: jti.to_owned(),
        expires_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const ISSUER: &str = "https://as.example/t/demo";
    const CLIENT: &str = "client-one";

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_760_000_000).expect("fixed instant")
    }

    fn rules() -> AssertionRules {
        AssertionRules::for_issuer(ISSUER)
    }

    fn valid_claims() -> Value {
        json!({
            "iss": CLIENT,
            "sub": CLIENT,
            "aud": ISSUER,
            "jti": "a-unique-value",
            "exp": now().unix_timestamp() + 60,
            "iat": now().unix_timestamp(),
        })
    }

    fn check(claims: &Value) -> Result<Assertion, ClientAuthError> {
        check_assertion(claims, CLIENT, &rules(), now())
    }

    #[test]
    fn a_conforming_assertion_is_accepted() {
        let assertion = check(&valid_claims()).expect("must accept");
        assert_eq!(assertion.jti, "a-unique-value");
        assert_eq!(
            assertion.expires_at.unix_timestamp(),
            now().unix_timestamp() + 60
        );
    }

    /// OIDC Core §9: `iss` and `sub` are the client, and nothing else is.
    #[test]
    fn issuer_and_subject_must_both_be_the_client() {
        for (iss, sub) in [
            ("someone-else", CLIENT),
            (CLIENT, "someone-else"),
            ("someone-else", "someone-else"),
        ] {
            let mut claims = valid_claims();
            claims["iss"] = json!(iss);
            claims["sub"] = json!(sub);
            assert_eq!(
                check(&claims),
                Err(ClientAuthError::WrongSubject),
                "accepted iss={iss} sub={sub}"
            );
        }
    }

    #[test]
    fn a_missing_or_non_string_identity_claim_is_refused() {
        for claim in ["iss", "sub"] {
            let mut claims = valid_claims();
            claims.as_object_mut().expect("object").remove(claim);
            assert_eq!(check(&claims), Err(ClientAuthError::MalformedClaim(claim)));

            let mut claims = valid_claims();
            claims[claim] = json!(42);
            assert_eq!(check(&claims), Err(ClientAuthError::MalformedClaim(claim)));
        }
    }

    /// FAPI 2.0 SP §5.3.2.1 item 8, the value half.
    #[test]
    fn only_the_issuer_identifier_is_an_acceptable_audience() {
        for wrong in [
            // The token endpoint URL, which OIDC Core §9 allowed and FAPI 2.0
            // withdrew. This is the one real clients get wrong.
            json!("https://as.example/t/demo/token"),
            json!("https://as.example/t/other"),
            json!("https://as.example"),
            // Trailing slash: a different issuer identifier, by RFC 8414 §2.
            json!("https://as.example/t/demo/"),
            json!(""),
            json!(null),
            json!(42),
            json!({"aud": ISSUER}),
        ] {
            let mut claims = valid_claims();
            claims["aud"] = wrong.clone();
            assert_eq!(
                check(&claims),
                Err(ClientAuthError::WrongAudience),
                "accepted aud {wrong}"
            );
        }
    }

    /// FAPI 2.0 SP §5.3.2.1 item 8, the *form* half: "as a string".
    ///
    /// The single-element array is the case worth having a test for. It
    /// contains the right issuer and nothing else, it is legal JWT (RFC 7519
    /// §4.1.3), and every general-purpose JWT library accepts it. FAPI does
    /// not, because the array form is what lets one assertion name two
    /// audiences.
    #[test]
    fn an_array_audience_is_refused_even_when_it_holds_only_the_issuer() {
        for array in [
            json!([ISSUER]),
            json!([ISSUER, "https://attacker.example"]),
            json!(["https://attacker.example", ISSUER]),
            json!([]),
        ] {
            let mut claims = valid_claims();
            claims["aud"] = array.clone();
            assert_eq!(
                check(&claims),
                Err(ClientAuthError::WrongAudience),
                "accepted array audience {array}"
            );
        }
    }

    /// CIBA Core 1.0 §7.1, the one endpoint that widens the set.
    #[test]
    fn the_backchannel_endpoint_accepts_ciba_audiences_but_still_only_as_strings() {
        let token = "https://as.example/t/demo/token";
        let backchannel = "https://as.example/t/demo/backchannel";
        let rules = AssertionRules {
            audiences: Audiences::ciba_backchannel(ISSUER, token, backchannel),
            max_lifetime: DEFAULT_MAX_ASSERTION_LIFETIME,
        };

        for accepted in [ISSUER, token, backchannel] {
            let mut claims = valid_claims();
            claims["aud"] = json!(accepted);
            assert!(
                check_assertion(&claims, CLIENT, &rules, now()).is_ok(),
                "refused {accepted}, which CIBA §7.1 requires"
            );
        }

        // Widened in value, not in form.
        let mut claims = valid_claims();
        claims["aud"] = json!([ISSUER]);
        assert_eq!(
            check_assertion(&claims, CLIENT, &rules, now()),
            Err(ClientAuthError::WrongAudience)
        );

        // And not widened to anything else.
        let mut claims = valid_claims();
        claims["aud"] = json!("https://as.example/t/demo/introspect");
        assert_eq!(
            check_assertion(&claims, CLIENT, &rules, now()),
            Err(ClientAuthError::WrongAudience)
        );
    }

    /// RFC 7523 §3 item 7.
    #[test]
    fn an_assertion_without_a_usable_jti_is_refused() {
        for jti in [json!(null), json!(""), json!(42), json!(["a"])] {
            let mut claims = valid_claims();
            claims["jti"] = jti.clone();
            assert_eq!(
                check(&claims),
                Err(ClientAuthError::MalformedClaim("jti")),
                "accepted jti {jti}"
            );
        }

        let mut claims = valid_claims();
        claims.as_object_mut().expect("object").remove("jti");
        assert_eq!(check(&claims), Err(ClientAuthError::MalformedClaim("jti")));
    }

    #[test]
    fn an_over_long_jti_is_refused_rather_than_stored() {
        let mut claims = valid_claims();
        claims["jti"] = json!("j".repeat(MAX_JTI_LEN + 1));
        assert_eq!(check(&claims), Err(ClientAuthError::MalformedClaim("jti")));

        claims["jti"] = json!("j".repeat(MAX_JTI_LEN));
        assert!(check(&claims).is_ok(), "the boundary itself is acceptable");
    }

    #[test]
    fn an_expired_assertion_is_refused_by_this_rule_too() {
        // The verifier rejects it first in the composed path. This asserts the
        // rule holds without that help, which is what a second caller gets.
        let mut claims = valid_claims();
        claims["exp"] = json!(now().unix_timestamp() - 1);
        assert_eq!(check(&claims), Err(ClientAuthError::Expired));

        claims["exp"] = json!(now().unix_timestamp());
        assert_eq!(
            check(&claims),
            Err(ClientAuthError::Expired),
            "an assertion expiring exactly now has expired"
        );

        claims["exp"] = json!(now().unix_timestamp() + 1);
        assert!(check(&claims).is_ok(), "one second of life is life");
    }

    #[test]
    fn an_assertion_valid_for_too_long_is_refused() {
        let mut claims = valid_claims();
        claims["exp"] = json!(now().unix_timestamp() + 601);
        assert_eq!(check(&claims), Err(ClientAuthError::LifetimeTooLong));

        claims["exp"] = json!(now().unix_timestamp() + 600);
        assert!(check(&claims).is_ok(), "exactly the maximum is acceptable");
    }

    #[test]
    fn a_tenant_may_shorten_the_permitted_lifetime_but_not_lengthen_it() {
        let strict = rules().with_max_lifetime(Duration::seconds(30));
        let mut claims = valid_claims();
        claims["exp"] = json!(now().unix_timestamp() + 60);
        assert_eq!(
            check_assertion(&claims, CLIENT, &strict, now()),
            Err(ClientAuthError::LifetimeTooLong)
        );

        // Clamped, not honoured: a misconfiguration yields a compliant server.
        let loose = rules().with_max_lifetime(Duration::days(365));
        assert_eq!(loose.max_lifetime, DEFAULT_MAX_ASSERTION_LIFETIME);
    }

    #[test]
    fn a_malformed_expiry_is_refused_rather_than_panicking() {
        for exp in [
            json!("1760000060"),
            json!(null),
            json!(i64::MAX),
            json!([1]),
        ] {
            let mut claims = valid_claims();
            claims["exp"] = exp.clone();
            assert_eq!(
                check(&claims),
                Err(ClientAuthError::MalformedClaim("exp")),
                "accepted exp {exp}"
            );
        }
    }

    // ---- method selection (RFC 6749 §2.3, RFC 7521 §4.2) -----------------

    fn assertion_attempt<'a>() -> Attempt<'a> {
        Attempt {
            assertion: Some("header.payload.signature"),
            assertion_type: Some(CLIENT_ASSERTION_TYPE),
            ..Attempt::default()
        }
    }

    #[test]
    fn a_well_formed_assertion_pair_selects_private_key_jwt() {
        assert_eq!(assertion_attempt().method(), Ok(Method::PrivateKeyJwt));
    }

    /// The smallest thing [`ClientCertificate::from_der`] accepts. What is in
    /// it does not matter here: `method` counts credentials, it does not read
    /// them.
    fn a_certificate() -> crate::mtls::ClientCertificate {
        crate::mtls::ClientCertificate::from_der(vec![
            0x30, 0x18, // Certificate
            0x30, 0x10, // tbsCertificate
            0x02, 0x01, 0x01, // serialNumber
            0x30, 0x00, // signature
            0x30, 0x00, // issuer
            0x30, 0x00, // validity
            0x30, 0x00, // subject: an empty Name
            0x30, 0x02, 0x30, 0x00, // subjectPublicKeyInfo
            0x30, 0x00, // signatureAlgorithm
            0x03, 0x00, // signature
        ])
        .expect("a minimal certificate")
    }

    #[test]
    fn a_client_certificate_alone_selects_mtls() {
        let certificate = a_certificate();
        let attempt = Attempt {
            certificate: Some(&certificate),
            ..Attempt::default()
        };
        assert_eq!(attempt.method(), Ok(Method::Mtls));
    }

    /// RFC 6749 §2.3: one method per request.
    #[test]
    fn presenting_two_methods_is_a_malformed_request() {
        let certificate = a_certificate();
        let both_transport = Attempt {
            certificate: Some(&certificate),
            ..assertion_attempt()
        };
        assert_eq!(
            both_transport.method(),
            Err(ClientAuthError::MultipleMethods)
        );

        let with_header = Attempt {
            authorization_header: true,
            ..assertion_attempt()
        };
        assert_eq!(with_header.method(), Err(ClientAuthError::MultipleMethods));

        let cert_and_header = Attempt {
            certificate: Some(&certificate),
            authorization_header: true,
            ..Attempt::default()
        };
        assert_eq!(
            cert_and_header.method(),
            Err(ClientAuthError::MultipleMethods)
        );
    }

    #[test]
    fn half_an_assertion_is_not_an_assertion() {
        let no_type = Attempt {
            assertion_type: None,
            ..assertion_attempt()
        };
        assert_eq!(no_type.method(), Err(ClientAuthError::IncompleteAssertion));

        let no_assertion = Attempt {
            assertion: None,
            ..assertion_attempt()
        };
        assert_eq!(
            no_assertion.method(),
            Err(ClientAuthError::IncompleteAssertion)
        );
    }

    /// RFC 7521 §4.2: one value, compared exactly.
    #[test]
    fn only_the_registered_assertion_type_urn_is_accepted() {
        for wrong in [
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer ",
            "URN:IETF:PARAMS:OAUTH:CLIENT-ASSERTION-TYPE:JWT-BEARER",
            "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "jwt-bearer",
            "",
        ] {
            let attempt = Attempt {
                assertion_type: Some(wrong),
                ..assertion_attempt()
            };
            assert_eq!(
                attempt.method(),
                Err(ClientAuthError::UnsupportedAssertionType),
                "accepted assertion type {wrong:?}"
            );
        }
    }

    #[test]
    fn a_request_with_no_credential_fails_authentication() {
        assert_eq!(Attempt::default().method(), Err(ClientAuthError::NoMethod));

        // A bare `Authorization` header is a method this server does not
        // implement — a failed authentication, not a malformed request.
        let header_only = Attempt {
            authorization_header: true,
            ..Attempt::default()
        };
        assert_eq!(header_only.method(), Err(ClientAuthError::NoMethod));
    }

    // ---- error mapping (RFC 6749 §5.2) -----------------------------------

    #[test]
    fn malformed_requests_and_failed_credentials_map_to_different_codes() {
        for malformed in [
            ClientAuthError::MultipleMethods,
            ClientAuthError::IncompleteAssertion,
            ClientAuthError::UnsupportedAssertionType,
        ] {
            assert_eq!(malformed.code(), "invalid_request", "{malformed}");
            assert_eq!(malformed.status(), 400, "{malformed}");
        }

        for failed in [
            ClientAuthError::NoMethod,
            ClientAuthError::UnknownClient,
            ClientAuthError::WrongSubject,
            ClientAuthError::WrongAudience,
            ClientAuthError::AssertionNotVerified,
            ClientAuthError::ReplayedAssertion,
            ClientAuthError::LifetimeTooLong,
            ClientAuthError::Expired,
            ClientAuthError::KeysUnavailable,
            ClientAuthError::WrongMethodForClient,
            ClientAuthError::ClientIdMismatch,
            ClientAuthError::MalformedClaim("jti"),
        ] {
            assert_eq!(failed.code(), "invalid_client", "{failed}");
            assert_eq!(failed.status(), 401, "{failed}");
        }
    }

    /// An error message is read by whoever is holding the wrong credential.
    /// It must not tell them which part was wrong in a way that helps.
    #[test]
    fn failure_messages_name_no_client_key_or_claim_value() {
        for error in [
            ClientAuthError::UnknownClient,
            ClientAuthError::AssertionNotVerified,
            ClientAuthError::KeysUnavailable,
        ] {
            let rendered = error.to_string();
            assert!(!rendered.contains(CLIENT), "{rendered}");
            assert!(!rendered.contains(ISSUER), "{rendered}");
        }
    }
}
