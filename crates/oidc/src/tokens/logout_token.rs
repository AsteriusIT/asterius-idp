//! The Logout Token: OIDC Back-Channel Logout 1.0 §2.4.
//!
//! A logout token says one thing — "this session, at this client, has ended" —
//! and it is the only JWT this server signs that is *not* a credential. That
//! asymmetry is what makes it dangerous, and it is why every prohibition in
//! §2.4 is arranged here as something a caller cannot express rather than
//! something a reviewer has to notice.
//!
//! | Rule (§2.4 unless noted) | How it is enforced |
//! |---|---|
//! | `typ` is `logout+jwt` (§2.4, §4.1) | [`LOGOUT_TOKEN_TYP`] is the only value this module hands a signer |
//! | `events` holds the back-channel logout member | written by [`ReadyLogoutToken::issue`], with no way to pass another |
//! | a `nonce` Claim MUST NOT be present | no API writes claims; the claim set is a fixed list of names |
//! | `sub` and/or `sid`, at least one | typestate: the two entry points are [`LogoutToken::about_session`] and [`LogoutToken::about_subject`] |
//! | `iss`, `aud`, `iat`, `jti` REQUIRED | all four are written unconditionally from typed arguments |
//! | `exp` REQUIRED | [`MAX_LOGOUT_TOKEN_LIFETIME`] caps it |
//!
//! # Why `nonce` is the one worth stating twice
//!
//! §2.4: "a `nonce` Claim MUST NOT be present". §2.6 step 10 has the relying
//! party *reject* a token that carries one, and the reason is in §4.1: a
//! logout token that looked enough like an ID token could be replayed at an
//! RP's authentication path, where `nonce` is precisely the claim that binds
//! an assertion to a login attempt. So a logout token carrying a `nonce` is
//! not a cosmetic defect — it is the cross-JWT confusion this specification's
//! security considerations are about.
//!
//! There is no builder method that takes one, and the claim map is built from
//! a fixed list inside [`ReadyLogoutToken::issue`]. The test
//! `a_logout_token_can_never_carry_a_nonce` asserts the property of the
//! rendered claims rather than of the API, because the API not having a method
//! is what a future edit would take away first.
//!
//! # Explicit typing, and what it stops
//!
//! RFC 8725 §3.11 and §4.1 of this specification: the `typ` header is what
//! keeps a logout token out of every other verifier in the deployment. An ID
//! token is `JWT`, an access token is `at+jwt`, a SET is `secevent+jwt`, a
//! DPoP proof is `dpop+jwt`. A logout token is signed by the same tenant key
//! as all of them, so `typ` is the only thing separating "this session ended"
//! from "this person is authenticated" — and the value is a constant here,
//! never a parameter, so the code that signs cannot forget it.

use super::{IssuanceError, JwtId, MAX_ID_TOKEN_CLAIMS_BYTES, UnsignedToken, bounded};
use crate::tokens::id_token::Session;
use asterius_domain::{ClientId, Issuer, SigningAlgorithm};
use serde_json::{Map, Value};
use time::{Duration, OffsetDateTime};

/// The explicit type header of a logout token (§2.4, §4.1).
///
/// > `typ`: REQUIRED. ... this profile specifies that the value is
/// > `logout+jwt`.
///
/// Not a parameter anywhere in this crate.
pub const LOGOUT_TOKEN_TYP: &str = "logout+jwt";

/// The member `events` carries (§2.4).
///
/// > `events`: REQUIRED. Claim whose value is a JSON object containing the
/// > member name `http://schemas.openid.net/event/backchannel-logout`.
///
/// §2.6 step 6 has the relying party check for exactly this name, so the
/// string is a constant rather than something a caller states.
pub const BACKCHANNEL_LOGOUT_EVENT: &str = "http://schemas.openid.net/event/backchannel-logout";

/// The longest a logout token is good for.
///
/// §2.4 makes `exp` REQUIRED and says nothing about how long it may be, so
/// this is a decision rather than a quotation. Two minutes, because a logout
/// token is delivered by an outbox whose first retry is seconds away and whose
/// receiver validates it the moment it arrives: nothing legitimate needs
/// longer, and a longer window is longer for a token captured in transit to be
/// replayed at an RP that does not deduplicate on `jti` (§2.6 step 11 makes
/// that check a MAY).
///
/// A row still backed off past this expiry delivers a token the receiver
/// refuses. That is the honest outcome: an RP that was unreachable for two
/// minutes needs a fresh statement about the session, not a stale one it
/// cannot tell from a replay.
pub const MAX_LOGOUT_TOKEN_LIFETIME: Duration = Duration::minutes(2);

/// The subject identifier a logout token names (§2.4).
///
/// A newtype so that the `sub` of a logout token is the same kind of value as
/// the `sub` of the ID token the relying party already holds — §2.6 step 4
/// has the RP match them, and a `sub` from anywhere but the client's own
/// sector is one no RP will recognise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogoutSubject(String);

impl LogoutSubject {
    /// Wraps the identifier this client knows the person by.
    ///
    /// # Errors
    ///
    /// [`IssuanceError::EmptySubject`] if it is empty. An empty `sub` would
    /// satisfy §2.4's "sub and/or sid" while naming nobody.
    pub fn new(subject: &str) -> Result<Self, IssuanceError> {
        if subject.is_empty() {
            return Err(IssuanceError::EmptySubject);
        }
        Ok(Self(subject.to_owned()))
    }

    /// The identifier, as it appears in `sub`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The entry point of the logout-token typestate. See the [module docs](self).
#[derive(Debug)]
pub struct LogoutToken;

impl LogoutToken {
    /// A token about a session (§2.4's `sid`).
    ///
    /// The form a client with `backchannel_logout_session_required` needs, and
    /// the form a pairwise client is best served by: a `sid` names the login
    /// without naming the person.
    pub fn about_session(session: Session) -> ReadyLogoutToken {
        ReadyLogoutToken {
            sid: Some(session),
            sub: None,
        }
    }

    /// A token about a subject (§2.4's `sub`).
    ///
    /// The `sub` must be the one *this client* was issued in its ID token —
    /// §2.6 step 4 — which for a pairwise client is its own sector's
    /// identifier and not the local one.
    pub fn about_subject(subject: LogoutSubject) -> ReadyLogoutToken {
        ReadyLogoutToken {
            sid: None,
            sub: Some(subject),
        }
    }
}

/// A logout token that names at least a session or a subject.
///
/// There is no constructor: the only two ways in are [`LogoutToken`]'s, so
/// §2.4's "MUST contain either a `sub` or a `sid` Claim" holds by construction
/// rather than by a check that could be skipped on one path.
#[derive(Debug)]
#[must_use]
pub struct ReadyLogoutToken {
    sid: Option<Session>,
    sub: Option<LogoutSubject>,
}

impl ReadyLogoutToken {
    /// Adds the session this token is also about (§2.4 "and MAY contain
    /// both").
    pub fn and_session(mut self, session: Session) -> Self {
        self.sid = Some(session);
        self
    }

    /// Adds the subject this token is also about.
    pub fn and_subject(mut self, subject: LogoutSubject) -> Self {
        self.sub = Some(subject);
        self
    }

    /// Builds the claims set for one relying party.
    ///
    /// `algorithm` is the client's `id_token_signed_response_alg`: §2.6 step 3
    /// has the RP "validate the Logout Token signature in the same manner as
    /// an ID Token", so a token signed under the tenant's default instead is
    /// one the client is entitled to reject. It travels back out through
    /// [`UnsignedToken::required_algorithm`], which is the argument the signer
    /// takes, so the two cannot drift apart at the call site.
    ///
    /// # Errors
    ///
    /// [`IssuanceError::Lifetime`] if `lifetime` is not positive or is over
    /// [`MAX_LOGOUT_TOKEN_LIFETIME`], and [`IssuanceError::TooLarge`] if the
    /// claims exceed the builder's guard.
    pub fn issue(
        self,
        issuer: &Issuer,
        audience: &ClientId,
        algorithm: SigningAlgorithm,
        issued_at: OffsetDateTime,
        lifetime: Duration,
    ) -> Result<UnsignedToken, IssuanceError> {
        let lifetime = super::usable_lifetime(lifetime, MAX_LOGOUT_TOKEN_LIFETIME)?;

        let mut claims = Map::new();
        // §2.4: `iss`, `aud`, `iat`, `exp`, `jti` — REQUIRED, every one.
        claims.insert("iss".to_owned(), Value::from(issuer.as_str()));
        // A single string, not an array: §2.6 step 4 has the RP check that it
        // is "the same as the `aud` Claim in the ID Token", and this server's
        // ID tokens are audible to exactly one client.
        claims.insert("aud".to_owned(), Value::from(audience.as_str()));
        claims.insert("iat".to_owned(), Value::from(issued_at.unix_timestamp()));
        claims.insert(
            "exp".to_owned(),
            Value::from((issued_at + lifetime).unix_timestamp()),
        );
        // 128 bits, from the same type the access token's `jti` uses. §2.6
        // step 11 lets an RP deduplicate on it, and a guessable one lets an
        // attacker pre-empt a genuine logout by burning the identifier first.
        claims.insert("jti".to_owned(), Value::from(JwtId::generate().as_str()));
        claims.insert(
            "events".to_owned(),
            serde_json::json!({ BACKCHANNEL_LOGOUT_EVENT: {} }),
        );
        if let Some(sub) = &self.sub {
            claims.insert("sub".to_owned(), Value::from(sub.as_str()));
        }
        if let Some(sid) = &self.sid {
            claims.insert("sid".to_owned(), Value::from(sid.as_str()));
        }
        //
        // What is *not* written here is the point of the module:
        //   * `nonce` — §2.4 MUST NOT, §2.6 step 10 rejects it, §4.1 says why.
        //   * `at_hash`, `acr`, `amr`, `auth_time` — an ID token's claims. A
        //     logout token that carried them would be an authentication
        //     assertion wearing another `typ`.
        // Neither is reachable: nothing outside this function writes to
        // `claims`, and this function writes a fixed set of names.

        Ok(UnsignedToken {
            typ: LOGOUT_TOKEN_TYP,
            required_algorithm: Some(algorithm),
            claims: bounded(Value::Object(claims), MAX_ID_TOKEN_CLAIMS_BYTES)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asterius_domain::SessionId;

    fn issuer() -> Issuer {
        Issuer::parse("https://op.example/t/demo").expect("a valid issuer")
    }

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_760_000_000).expect("a fixed instant")
    }

    fn session() -> Session {
        Session::new(&SessionId::new("a-session-identifier")).expect("a usable sid")
    }

    fn issued() -> Value {
        LogoutToken::about_session(session())
            .and_subject(LogoutSubject::new("the-pairwise-sub").expect("a subject"))
            .issue(
                &issuer(),
                &ClientId::new("rp-one"),
                SigningAlgorithm::Es256,
                now(),
                Duration::minutes(2),
            )
            .expect("the token issues")
            .into_claims()
    }

    /// §2.4 names five claims REQUIRED unconditionally: `iss`, `aud`, `iat`,
    /// `jti` and `exp`. A token missing any of them is one §2.6 step 5 has the
    /// relying party reject, which is a logout that silently does nothing.
    #[test]
    fn a_logout_token_carries_every_claim_the_specification_requires() {
        // Arrange / Act
        let claims = issued();

        // Assert
        assert_eq!(claims["iss"], Value::from("https://op.example/t/demo"));
        assert_eq!(claims["aud"], Value::from("rp-one"));
        assert_eq!(claims["iat"], Value::from(now().unix_timestamp()));
        assert!(claims["exp"].is_i64());
        assert!(
            claims["jti"].as_str().is_some_and(|jti| !jti.is_empty()),
            "a logout token needs a jti a receiver can deduplicate on"
        );
    }

    /// §2.4: `events` is "a JSON object containing the member name
    /// `http://schemas.openid.net/event/backchannel-logout`", whose value is
    /// an empty object. §2.6 step 6 is the relying party checking exactly
    /// that, so the shape is the interoperability.
    #[test]
    fn the_events_claim_names_the_back_channel_logout_event() {
        // Arrange / Act
        let claims = issued();

        // Assert
        assert_eq!(
            claims["events"],
            serde_json::json!({"http://schemas.openid.net/event/backchannel-logout": {}})
        );
    }

    /// §2.4: "a `nonce` Claim MUST NOT be present". §4.1 is why: a token that
    /// could pass for an ID token is one an RP's authentication path might
    /// accept, and `nonce` is the claim that path binds to.
    ///
    /// Asserted on the rendered claims rather than on the API, because "there
    /// is no method that sets one" is what a future edit removes first.
    #[test]
    fn a_logout_token_can_never_carry_a_nonce() {
        // Arrange / Act
        let claims = issued();

        // Assert
        assert!(claims.get("nonce").is_none());
        // The whole claim set, not just the absence of `nonce`: a token that
        // grew an `at_hash` or an `acr` would be an ID token in all but `typ`,
        // which is the confusion §4.1 is about.
        let names: Vec<&str> = claims
            .as_object()
            .expect("an object")
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            names,
            ["aud", "events", "exp", "iat", "iss", "jti", "sid", "sub"],
            "an unexpected claim reached a logout token"
        );
    }

    /// §4.1, and RFC 8725 §3.11: the explicit type is what stops this token
    /// being presented where an ID token, an access token or a SET is
    /// expected. It is a constant, so the assertion is that the constant is
    /// the one the specification names.
    #[test]
    fn a_logout_token_is_typed_logout_jwt() {
        // Arrange / Act
        let token = LogoutToken::about_session(session())
            .issue(
                &issuer(),
                &ClientId::new("rp-one"),
                SigningAlgorithm::EdDsa,
                now(),
                Duration::minutes(1),
            )
            .expect("the token issues");

        // Assert
        assert_eq!(token.typ(), "logout+jwt");
    }

    /// §2.6 step 3: the RP validates the signature "in the same manner as an
    /// ID Token", i.e. against its registered `id_token_signed_response_alg`.
    /// A claims set that did not carry the constraint would be signed with
    /// whatever key the tenant happened to have active.
    #[test]
    fn the_client_id_token_algorithm_is_the_one_that_must_sign() {
        // Arrange / Act
        let token = LogoutToken::about_session(session())
            .issue(
                &issuer(),
                &ClientId::new("rp-one"),
                SigningAlgorithm::EdDsa,
                now(),
                Duration::minutes(1),
            )
            .expect("the token issues");

        // Assert
        assert_eq!(token.required_algorithm(), Some(SigningAlgorithm::EdDsa));
    }

    /// A token about a session need not name the person (§2.4's "sub and/or
    /// sid"), which is what a pairwise client that requires a `sid` gets.
    #[test]
    fn a_token_about_a_session_alone_names_no_subject() {
        // Arrange / Act
        let claims = LogoutToken::about_session(session())
            .issue(
                &issuer(),
                &ClientId::new("rp-one"),
                SigningAlgorithm::Es256,
                now(),
                Duration::minutes(2),
            )
            .expect("the token issues")
            .into_claims();

        // Assert
        assert_eq!(claims["sid"], Value::from("a-session-identifier"));
        assert!(claims.get("sub").is_none());
    }

    /// The other half of "and/or": a token about a subject alone is valid, and
    /// carries no `sid`.
    #[test]
    fn a_token_about_a_subject_alone_names_no_session() {
        // Arrange / Act
        let claims = LogoutToken::about_subject(LogoutSubject::new("sub-1").expect("a subject"))
            .issue(
                &issuer(),
                &ClientId::new("rp-one"),
                SigningAlgorithm::Es256,
                now(),
                Duration::minutes(2),
            )
            .expect("the token issues")
            .into_claims();

        // Assert
        assert_eq!(claims["sub"], Value::from("sub-1"));
        assert!(claims.get("sid").is_none());
    }

    /// The lifetime cap is this server's decision, and it is enforced rather
    /// than documented: a token good for an hour is an hour in which a copy
    /// taken off the wire still logs the session out at an RP that does not
    /// deduplicate.
    #[test]
    fn a_lifetime_over_two_minutes_is_refused() {
        // Arrange / Act
        let refused = LogoutToken::about_session(session()).issue(
            &issuer(),
            &ClientId::new("rp-one"),
            SigningAlgorithm::Es256,
            now(),
            Duration::minutes(3),
        );

        // Assert
        assert!(matches!(refused, Err(IssuanceError::Lifetime)));
    }

    /// `exp` is `iat` plus the lifetime and nothing else — an off-by-a-unit
    /// here is a token every receiver refuses, or one that lives longer than
    /// the cap the test above enforces.
    #[test]
    fn the_expiry_is_the_issuing_instant_plus_the_lifetime() {
        // Arrange / Act
        let claims = LogoutToken::about_session(session())
            .issue(
                &issuer(),
                &ClientId::new("rp-one"),
                SigningAlgorithm::Es256,
                now(),
                Duration::seconds(30),
            )
            .expect("the token issues")
            .into_claims();

        // Assert
        assert_eq!(claims["exp"], Value::from(now().unix_timestamp() + 30));
    }

    /// Two logout tokens for one session are two events as far as a receiver
    /// deduplicating on `jti` is concerned (§2.6 step 11).
    #[test]
    fn two_logout_tokens_do_not_share_a_jti() {
        // Arrange / Act
        let first = issued();
        let second = issued();

        // Assert
        assert_ne!(first["jti"], second["jti"]);
    }

    /// An empty `sub` would satisfy "sub and/or sid" while naming nobody, and
    /// §2.6 step 4 would have the RP match it against an identifier it never
    /// issued.
    #[test]
    fn an_empty_subject_is_refused() {
        // Arrange / Act
        let refused = LogoutSubject::new("");

        // Assert
        assert!(matches!(refused, Err(IssuanceError::EmptySubject)));
    }
}
