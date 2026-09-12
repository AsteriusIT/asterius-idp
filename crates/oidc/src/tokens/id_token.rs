//! The ID token: an authentication assertion for one client, and nothing else.
//!
//! **An ID token is not an access token.** It says that a person authenticated,
//! when, how strongly, and under what identifier *this client* knows them by.
//! It is not authority to do anything, it must never be accepted at a resource
//! server, and it must never be presentable as an access token. RFC 9068 §2.1
//! puts the same warning the other way round — the reason `at+jwt` exists at
//! all is to stop an ID token being taken for one — so this module and
//! [`super::access`] produce disjoint claim sets under different media types,
//! and neither can write the other's claims.
//!
//! Three things follow from "it is an assertion about a person".
//!
//! ## It needs a person
//!
//! [`IdToken::build`] takes the `sub` from the `ClaimedGrant`, and refuses when
//! there is none. A `client_credentials` grant has no resource owner, and an
//! ID token asserting a *client* would be an authentication assertion about a
//! principal that never authenticated.
//!
//! The `sub` itself is not computed here. `PairwiseSalt::derive_subject`
//! (OIDC Core §8.1) minted it when the authorization completed and it was
//! written to the grant, so what this module emits is the identifier the
//! client has always known that person by — including across a refresh, which
//! is OIDC Core §12.2's "its `sub` Claim Value MUST be the same as in the ID
//! Token issued when the original authentication occurred".
//!
//! ## Its audience is exactly one client
//!
//! OIDC Core §2 makes `aud` REQUIRED and says it "MUST contain the OAuth 2.0
//! `client_id` of the Relying Party as an audience value". §3.1.3.7 has the
//! client reject a token that "contains additional audiences not trusted by the
//! Client", so this emits a single string and nothing else: an ID token audible
//! to two clients is an identity assertion one of them can replay at the other.
//!
//! ## The client cannot write its own claims into it
//!
//! Everything released here came through `crate::claims::resolve`, which is
//! keyed by `ReleasableClaim` and so has no way to produce `sub`, `aud`, `acr`,
//! `cnf`, `sid`, `nonce` or any other claim the authorization server issues
//! about the exchange. [`IdToken::releasing`] takes a plain map, because that
//! is what `ResolvedClaims` holds — so [`IdToken::build`] re-checks the
//! guarantee against `ClaimName::SERVER_ISSUED` rather than trusting that the
//! map came from where it should have. A stored user attribute overwriting the
//! `sub` an RP treats as the user's identity is the whole attack, and the
//! server-issued claims are written *after* the released ones as well, so the
//! order does not depend on the check.

use super::{IssuanceError, MAX_ID_TOKEN_CLAIMS_BYTES, UnsignedToken, bounded, usable_lifetime};
use crate::authorize::MAX_NONCE_LEN;
use crate::claims::ReleasableClaim;
use crate::tokens::access::Authentication;
use asterius_domain::{
    ClaimName, ClaimedGrant, HeldRoles, Issuer, RoleClaim, SessionId, SigningAlgorithm,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256, Sha512};
use std::collections::BTreeSet;
use time::{Duration, OffsetDateTime};

/// The explicit type header of an ID token.
///
/// OIDC Core defines no `typ` for an ID token and no media type was ever
/// registered for one, so `JWT` (RFC 7519 §5.1) is the honest value. It is set
/// anyway, because RFC 8725 §3.11 asks for explicit typing and because the
/// verifier's `TypRule::Exactly` can then hold an ID token to it — which is
/// what stops a token minted here being presented where an `at+jwt`,
/// `dpop+jwt` or `logout+jwt` is expected.
pub const ID_TOKEN_TYP: &str = "JWT";

// ---------------------------------------------------------------------------
// at_hash
// ---------------------------------------------------------------------------

/// The `at_hash` of an access token, under the ID token's signing algorithm.
///
/// OIDC Core §3.1.3.6, verbatim:
///
/// > Its value is the base64url encoding of the left-most half of the hash of
/// > the octets of the ASCII representation of the `access_token` value, where
/// > the hash algorithm used is the hash algorithm used in the `alg` Header
/// > Parameter of the ID Token's JOSE Header. For instance, if the `alg` is
/// > `RS256`, hash the `access_token` value with SHA-256, then take the
/// > left-most 128 bits and base64url-encode them.
///
/// Two details are easy to get wrong and are worth stating.
///
/// **"Left-most half", not "left-most 128 bits".** The 128 bits in that
/// sentence are what half of a SHA-256 digest happens to be. Under a 512-bit
/// hash the half is 256 bits, and truncating to 128 anyway would produce a
/// value no conforming client computes.
///
/// **EdDSA means SHA-512 here, and that needs an argument.** RFC 8037 §3.1
/// registers one `alg` value, `EdDSA`, for two variants: "The EdDSA variant
/// used is determined by the subtype of the key (Ed25519 for `Ed25519` and
/// Ed448 for `Ed448`)." So `alg` alone does not name a hash, which is why
/// OIDC Core's rule — "the hash algorithm used in the `alg` Header Parameter"
/// — has no mechanical answer for EdDSA in general, and why the OpenID
/// Foundation's own issue tracker (connect#1125) is where the ecosystem
/// settled it: Ed25519 hashes with SHA-512, Ed448 with SHAKE256.
///
/// Asterius is total here rather than ambiguous, because FAPI 2.0 SP §5.4.1
/// permits "`EdDSA` (using the `Ed25519` variant)" and ADR-0003 makes
/// `SigningAlgorithm::EdDsa` mean exactly that. Ed25519 is EdDSA instantiated
/// with `H(x) = SHA-512` (RFC 8032 §5.1), so the pairing is:
///
/// | `alg` | hash | half | `at_hash` length |
/// |---|---|---|---|
/// | `EdDSA` (Ed25519) | SHA-512 | 256 bits | 43 characters |
/// | `ES256` | SHA-256 | 128 bits | 22 characters |
/// | `PS256` | SHA-256 | 128 bits | 22 characters |
///
/// Ed448 is not reachable: it is not a `SigningAlgorithm` variant.
///
/// The same function computes `c_hash` and `s_hash` when those are needed —
/// OIDC Core §3.3.2.11 and FAPI 1.0 Advanced define them with the identical
/// construction over a different input — which is why it is named for what it
/// does rather than for the claim it currently fills.
#[must_use]
pub fn token_hash(algorithm: SigningAlgorithm, token: &str) -> String {
    // The octets of the ASCII representation: the token as it goes on the wire.
    // A compact JWS and an opaque token are both ASCII, so the bytes of the
    // `str` *are* those octets; there is nothing to transcode.
    let digest: Vec<u8> = match algorithm {
        SigningAlgorithm::EdDsa => Sha512::digest(token.as_bytes()).to_vec(),
        SigningAlgorithm::Es256 | SigningAlgorithm::Ps256 => {
            Sha256::digest(token.as_bytes()).to_vec()
        }
    };
    B64.encode(&digest[..digest.len() / 2])
}

// ---------------------------------------------------------------------------
// sid
// ---------------------------------------------------------------------------

/// The browser session an ID token reports (`sid`).
///
/// Back-Channel Logout 1.0 §2.1 defines the claim as it is used *in an ID
/// token* — "Session ID - String identifier for a Session. This represents a
/// Session of a User Agent or device for a logged-in End-User at an RP. […]
/// Its contents are opaque to the RP. Its syntax is the same as an OAuth 2.0
/// Client Identifier." — and says it belongs there only when the OP advertises
/// `backchannel_logout_session_supported`. §2.4 repeats the definition for the
/// Logout Token, which is the claim's other home.
///
/// A separate type, and optional at the builder, because that advertisement is
/// a tenant capability: a deployment that does not do back-channel logout
/// should not be emitting a session identifier an RP would then expect to see
/// again in a logout token that never arrives.
///
/// Validated rather than passed through, for the reason the definition gives:
/// an RP stores this and hands it back, and a value carrying a control
/// character or a newline is one that breaks whatever it is later interpolated
/// into.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session(String);

impl Session {
    /// The longest `sid` this server emits.
    pub const MAX_LEN: usize = 128;

    /// Wraps a session identifier for use as a `sid` claim.
    ///
    /// # Errors
    ///
    /// [`IssuanceError::Session`] if it is empty, longer than
    /// [`Session::MAX_LEN`], or holds anything outside printable ASCII —
    /// RFC 6749 Appendix A's `VSCHAR`, which is the "syntax […] the same as an
    /// OAuth 2.0 Client Identifier" the definition points at.
    pub fn new(id: &SessionId) -> Result<Self, IssuanceError> {
        let raw = id.as_str();
        if raw.is_empty()
            || raw.len() > Self::MAX_LEN
            || !raw.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
        {
            return Err(IssuanceError::Session);
        }
        Ok(Self(raw.to_owned()))
    }

    /// The identifier, as it appears in a `sid` claim.
    ///
    /// Read by [`super::logout_token`], which puts the same value in the
    /// logout token that the ID token carried — OIDC Back-Channel Logout 1.0
    /// §2.6 step 4 has the relying party match the two, so a second spelling
    /// of the session identifier would be a logout the RP cannot attribute.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// The builder
// ---------------------------------------------------------------------------

/// Builds the claims set of an ID token (OIDC Core §2, §3.1.3.6).
#[derive(Debug, Clone)]
#[must_use]
pub struct IdToken<'a> {
    issuer: &'a Issuer,
    claimed: &'a ClaimedGrant,
    algorithm: SigningAlgorithm,
    authentication: Authentication,
    access_token: &'a str,
    issued_at: OffsetDateTime,
    lifetime: Duration,
    nonce: Option<String>,
    session: Option<Session>,
    released: Map<String, Value>,
    roles: HeldRoles,
    role_claims: BTreeSet<RoleClaim>,
}

impl<'a> IdToken<'a> {
    /// The lifetime used unless a caller chooses another.
    ///
    /// An ID token is consumed once, immediately, by the client that asked for
    /// it: OIDC Core §3.1.3.7 is a list of checks a client performs on receipt,
    /// and nothing in the protocol presents one later. Five minutes is enough
    /// for a client whose clock is a little out and short enough that a token
    /// pasted into a ticket is stale by the time anyone reads it.
    pub const DEFAULT_LIFETIME: Duration = Duration::minutes(5);

    /// The longest lifetime this server will mint.
    pub const MAX_LIFETIME: Duration = Duration::minutes(15);

    /// An ID token for the client `claimed` was issued to.
    ///
    /// `algorithm` is the client's registered `id_token_signed_response_alg`,
    /// not the tenant's default. OIDC Core §3.1.3.7 has the client check that
    /// the header's `alg` is the one it registered, and §3.1.3.6 ties `at_hash`
    /// to that same algorithm — so the claims set is only correct under it, and
    /// [`UnsignedToken::required_algorithm`] carries that on to the signer.
    ///
    /// `authentication` is not optional. `auth_time` is only conditionally
    /// REQUIRED by OIDC Core §2 — "When a `max_age` request is made or when
    /// `auth_time` is requested as an Essential Claim, then this Claim is
    /// REQUIRED; otherwise, its inclusion is OPTIONAL" — but a client cannot
    /// implement a session policy against a claim that is sometimes there, and
    /// an authorization server that knows when somebody authenticated has no
    /// reason to withhold it. So it is always emitted, which also means the
    /// value has to be carried rather than guessed: on a refresh, §12.2 says it
    /// "MUST represent the time of the original authentication - not the time
    /// that the new ID token is issued".
    ///
    /// `access_token` is the token issued alongside, for `at_hash`. §3.1.3.6
    /// makes it OPTIONAL in the code flow, and it is emitted anyway: it costs a
    /// hash and it binds the two halves of one token response together, so a
    /// client that checks it cannot be handed an ID token from one exchange and
    /// an access token from another.
    pub fn new(
        issuer: &'a Issuer,
        claimed: &'a ClaimedGrant,
        algorithm: SigningAlgorithm,
        authentication: Authentication,
        access_token: &'a str,
        issued_at: OffsetDateTime,
    ) -> Self {
        Self {
            issuer,
            claimed,
            algorithm,
            authentication,
            access_token,
            issued_at,
            lifetime: Self::DEFAULT_LIFETIME,
            nonce: None,
            session: None,
            released: Map::new(),
            roles: HeldRoles::empty(),
            role_claims: BTreeSet::new(),
        }
    }

    /// Overrides the lifetime, up to [`IdToken::MAX_LIFETIME`].
    pub const fn for_lifetime(mut self, lifetime: Duration) -> Self {
        self.lifetime = lifetime;
        self
    }

    /// Echoes the `nonce` from the authorization request.
    ///
    /// OIDC Core §2: "The value is passed through unmodified from the
    /// Authentication Request to the ID Token. […] If present in the
    /// Authentication Request, Authorization Servers MUST include a `nonce`
    /// Claim in the ID Token with the Claim Value being the `nonce` value sent
    /// in the Authentication Request." Byte for byte, and case-sensitively: the
    /// client compares it with what it stored, and any normalisation here would
    /// be a comparison that fails for a client that did nothing wrong.
    ///
    /// Called exactly when the original request carried one, which on a refresh
    /// means not at all — §12.2: an ID token from a refresh "SHOULD NOT have a
    /// `nonce` Claim, even when the ID Token issued at the time of the original
    /// authentication contained `nonce`".
    pub fn with_nonce(mut self, nonce: impl Into<String>) -> Self {
        self.nonce = Some(nonce.into());
        self
    }

    /// Reports the browser session (`sid`), for a tenant that supports
    /// back-channel logout.
    pub fn for_session(mut self, session: Session) -> Self {
        self.session = Some(session);
        self
    }

    /// The claims `crate::claims::resolve` placed in the ID token.
    ///
    /// This is `ResolvedClaims::id_token` and nothing else. A claim reaches it
    /// only because the client named it under the `claims` parameter's
    /// `id_token` member — no scope ever puts a claim here (OIDC Core §5.4, and
    /// see `crate::claims`) — so the privacy decision was made before this
    /// builder saw anything.
    pub fn releasing(mut self, released: Map<String, Value>) -> Self {
        self.released = released;
        self
    }

    /// The application roles this token asserts, and which of the two claims
    /// carry them (`ast-mqt`).
    ///
    /// **Nothing is emitted unless `claims` names it.** An ID token is an
    /// authentication assertion; what somebody may *do* belongs in the access
    /// token, which is sender-constrained under this profile and does not pass
    /// through a browser. So the two role claims reach an ID token only when
    /// the client asked for them under OIDC Core §5.5's `claims` parameter, or
    /// registered `roles_in_id_token` — the same trade [`crate::claims`]
    /// describes for every other claim that can be asked into the ID token,
    /// made by the client for its own users.
    ///
    /// The disclosure is not widened by either route: `held` is narrowed to
    /// this token's own client by [`HeldRoles::for_client`] here, exactly as
    /// [`super::access::AccessToken::with_roles`] does it, so no call site can
    /// name a second client in `resource_access`. And the rendering is
    /// [`HeldRoles::claim`], shared with the access token, so a relying party
    /// reading `roles` from one and the other finds one shape.
    pub fn with_roles(mut self, held: &HeldRoles, claims: &BTreeSet<RoleClaim>) -> Self {
        self.roles = held.for_client(self.claimed.client());
        self.role_claims.clone_from(claims);
        self
    }

    /// Assembles the claims set.
    ///
    /// # Errors
    ///
    /// The first [`IssuanceError`] that applies.
    // fuzz-target: id_token_claims
    pub fn build(self) -> Result<UnsignedToken, IssuanceError> {
        let lifetime = usable_lifetime(self.lifetime, Self::MAX_LIFETIME)?;
        let subject = self.claimed.subject().ok_or(IssuanceError::NoSubject)?;
        // Present and empty is its own failure. OIDC Core §2 makes `sub`
        // REQUIRED, and §3.1.3.7 has the client compare it to the one it
        // already holds for this user — a comparison an empty string passes
        // against every other empty string.
        if subject.as_str().is_empty() {
            return Err(IssuanceError::EmptySubject);
        }
        let client_id = self.claimed.client().as_str();

        if let Some(nonce) = &self.nonce
            && (nonce.is_empty() || nonce.len() > MAX_NONCE_LEN)
        {
            return Err(IssuanceError::Nonce);
        }

        // The released claims go in *first*, so that every server-issued claim
        // below overwrites rather than being overwritten. The guard that
        // follows makes the overwrite unreachable; writing them in this order
        // means that removing the guard would still not produce a token whose
        // `sub` came from a user record.
        let mut claims = Map::new();
        for (name, value) in self.released {
            if let Some(reserved) = ClaimName::SERVER_ISSUED
                .iter()
                .find(|reserved| **reserved == name.as_str())
            {
                return Err(IssuanceError::ServerIssuedClaim(reserved));
            }
            // And a name that is not releasable at all: `ClaimName::parse`'s
            // rules — length, control and bidirectional formatting characters,
            // a `#` suffix that is not a language tag — plus the names a token
            // issuer computes although a bag may store them, which are the
            // role claims and `authorization_details` (`ast-8ft2`). `resolve`
            // cannot produce one, because its output is keyed by
            // `ReleasableClaim`; this is the check that the map actually came
            // from there.
            if ReleasableClaim::parse(&name).is_none() {
                return Err(IssuanceError::UnreleasableClaim);
            }
            claims.insert(name, value);
        }

        // OIDC Core §2, in the order that section lists them.
        claims.insert(
            "iss".to_owned(),
            Value::String(self.issuer.as_str().to_owned()),
        );
        claims.insert("sub".to_owned(), Value::String(subject.to_string()));
        // A single string, not an array: §3.1.3.7 has the client reject a token
        // carrying "additional audiences not trusted by the Client", and the
        // only audience an ID token has is the client that asked for it.
        claims.insert("aud".to_owned(), Value::String(client_id.to_owned()));
        claims.insert(
            "exp".to_owned(),
            Value::from((self.issued_at + lifetime).unix_timestamp()),
        );
        claims.insert(
            "iat".to_owned(),
            Value::from(self.issued_at.unix_timestamp()),
        );
        claims.insert(
            "auth_time".to_owned(),
            Value::from(self.authentication.authenticated_at.unix_timestamp()),
        );
        if let Some(nonce) = self.nonce {
            claims.insert("nonce".to_owned(), Value::String(nonce));
        }
        if let Some(acr) = &self.authentication.acr {
            claims.insert("acr".to_owned(), Value::String(acr.clone()));
        }
        if !self.authentication.amr.is_empty() {
            claims.insert(
                "amr".to_owned(),
                Value::Array(
                    self.authentication
                        .amr
                        .iter()
                        .cloned()
                        .map(Value::String)
                        .collect(),
                ),
            );
        }

        // `azp`, on which OIDC Core §2 is ambivalent: "Note that in practice,
        // the azp Claim only occurs when extensions beyond the scope of this
        // specification are used; therefore, implementations not using such
        // extensions are encouraged to not use azp and to ignore it when it
        // does occur." It is emitted anyway, and always, which is the part that
        // matters. §3.1.3.7 lets a client verify that `azp` is its own
        // `client_id`, and §12.2 warns that an extension may require the claim
        // to be present in a refreshed ID token exactly when it was present in
        // the original — a server that emitted it conditionally would be the
        // one that breaks that. Here `aud` is always the single client and
        // `azp` is always the same string, so the claim is redundant and
        // consistent rather than absent and sometimes surprising.
        claims.insert("azp".to_owned(), Value::String(client_id.to_owned()));

        // Back-Channel Logout 1.0 §2.1.
        if let Some(session) = &self.session {
            claims.insert("sid".to_owned(), Value::String(session.0.clone()));
        }

        // OIDC Core §3.1.3.6.
        claims.insert(
            "at_hash".to_owned(),
            Value::String(token_hash(self.algorithm, self.access_token)),
        );

        // The application roles (`ast-mqt`), when this issuance asked for
        // them. After the released claims and among the server-issued ones,
        // because these are computed from the assignment tables and not read
        // out of a user record: a claim bag cannot reach this name — a
        // `ReleasableClaim` is never one of them — and writing them here means
        // that would still be true if it could.
        for claim in &self.role_claims {
            if let Some(value) = self.roles.claim(*claim) {
                claims.insert(claim.as_str().to_owned(), value);
            }
        }

        Ok(UnsignedToken {
            typ: ID_TOKEN_TYP,
            required_algorithm: Some(self.algorithm),
            claims: bounded(Value::Object(claims), MAX_ID_TOKEN_CLAIMS_BYTES)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tokens::AUTHORISATION_CLAIMS;
    use asterius_domain::{
        ClientId, Grant, GrantId, PairwiseSalt, SectorIdentifier, SubjectId, TenantId, UserId,
    };
    use serde_json::json;

    fn issuer() -> Issuer {
        Issuer::parse("https://as.example/t/demo").expect("an issuer")
    }

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("a valid instant")
    }

    fn authenticated() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_699_999_000).expect("a valid instant")
    }

    fn grant_with(subject: Option<SubjectId>) -> Grant {
        let mut grant = Grant::new(TenantId::new("demo"), ClientId::new("billing"), now());
        grant.id = GrantId::new("2c1d4b1e-0000-4000-8000-000000000001");
        grant.subject = subject;
        grant
    }

    fn authentication() -> Authentication {
        Authentication {
            authenticated_at: authenticated(),
            acr: None,
            amr: Vec::new(),
        }
    }

    const ACCESS_TOKEN: &str = "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y";

    fn built() -> Value {
        let grant = grant_with(Some(SubjectId::new("SUBJECT-1")));
        let claimed = grant.claim(now()).expect("a live grant");
        IdToken::new(
            &issuer(),
            &claimed,
            SigningAlgorithm::Es256,
            authentication(),
            ACCESS_TOKEN,
            now(),
        )
        .build()
        .expect("a buildable token")
        .into_claims()
    }

    // --- at_hash (OIDC Core §3.1.3.6) -------------------------------------

    /// The pair OIDC Core publishes in Appendix A.3: an `access_token` of
    /// `jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y` and, in the ID token
    /// decoded just below it, `"at_hash": "77QmUPtjPfzWtF2AnpK9RQ"`. The
    /// example's `alg` is `RS256`, which pairs with SHA-256 — the same pairing
    /// ES256 and PS256 have — so the specification's own value is a vector for
    /// the 256-bit branch of this function, computed by somebody else years
    /// before this code existed.
    #[test]
    fn at_hash_matches_the_value_published_in_oidc_core_appendix_a_3() {
        for algorithm in [SigningAlgorithm::Es256, SigningAlgorithm::Ps256] {
            assert_eq!(
                token_hash(algorithm, "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y"),
                "77QmUPtjPfzWtF2AnpK9RQ"
            );
        }
    }

    /// The EdDSA branch, against `panva/oidc-token-hash` — the reference
    /// implementation the OpenID Foundation's own conformance tooling and most
    /// of the Node ecosystem use, whose README publishes this exact pair for
    /// `EdDSA` with the `Ed25519` curve. There is no vector for it in OIDC
    /// Core, because Core predates EdDSA in JOSE; connect#1125 is where the
    /// SHA-512 pairing was settled.
    #[test]
    fn at_hash_for_ed25519_matches_the_reference_implementations_vector() {
        const TOKEN: &str = "YmJiZTAwYmYtMzgyOC00NzhkLTkyOTItNjJjNDM3MGYzOWIy9sFhvH8K_x8UIHj\
                             1osisS57f5DduL-ar_qw5jl3lthwpMjm283aVMQXDmoqqqydDSqJfbhptzw8rUVw\
                             kuQbolw";
        assert_eq!(
            token_hash(SigningAlgorithm::EdDsa, TOKEN),
            "EGEAhGYyfuwDaVTifvrWSoD5MSy_5hZPy6I7Vm-7pTQ"
        );
        // And the same token under the 256-bit branch, from the same README.
        assert_eq!(
            token_hash(SigningAlgorithm::Es256, TOKEN),
            "x7vk7f6BvQj0jQHYFIk4ag"
        );
    }

    /// "Left-most *half*", not "left-most 128 bits". Getting this wrong under
    /// EdDSA produces a 22-character value no conforming client computes.
    #[test]
    fn the_hash_is_half_the_digest_whichever_digest_it_is() {
        assert_eq!(token_hash(SigningAlgorithm::EdDsa, "foobar").len(), 43);
        assert_eq!(token_hash(SigningAlgorithm::Es256, "foobar").len(), 22);
        // Independently: SHA-512("foobar") truncated to 32 bytes, base64url.
        assert_eq!(
            token_hash(SigningAlgorithm::EdDsa, "foobar"),
            "ClAmHr0aOQ_tK_Mm8mc8FFWCpjQtUjIElz0CGTN_gWE"
        );
        assert_eq!(
            token_hash(SigningAlgorithm::Es256, "foobar"),
            "w6uP8Tcg6K2QR905Rms8iQ"
        );
    }

    #[test]
    fn the_algorithm_chooses_the_hash_so_two_algorithms_disagree() {
        assert_ne!(
            token_hash(SigningAlgorithm::EdDsa, ACCESS_TOKEN),
            token_hash(SigningAlgorithm::Es256, ACCESS_TOKEN)
        );
        assert_eq!(
            token_hash(SigningAlgorithm::Ps256, ACCESS_TOKEN),
            token_hash(SigningAlgorithm::Es256, ACCESS_TOKEN)
        );
    }

    #[test]
    fn the_at_hash_claim_is_the_hash_of_the_token_that_was_issued() {
        let claims = built();
        assert_eq!(claims["at_hash"], json!("77QmUPtjPfzWtF2AnpK9RQ"));
        assert_eq!(
            claims["at_hash"],
            json!(token_hash(SigningAlgorithm::Es256, ACCESS_TOKEN))
        );
    }

    // --- OIDC Core §2: the claim set --------------------------------------

    #[test]
    fn every_claim_oidc_core_makes_required_is_present() {
        let claims = built();
        for required in ["iss", "sub", "aud", "exp", "iat"] {
            assert!(
                claims.get(required).is_some(),
                "OIDC Core §2 requires {required}"
            );
        }
        assert_eq!(claims["iss"], json!("https://as.example/t/demo"));
        assert_eq!(claims["sub"], json!("SUBJECT-1"));
        assert_eq!(claims["aud"], json!("billing"));
        assert_eq!(claims["azp"], json!("billing"));
        assert_eq!(claims["iat"], json!(1_700_000_000));
        assert_eq!(claims["exp"], json!(1_700_000_300));
    }

    /// §3.1.3.7: the client rejects a token with "additional audiences not
    /// trusted by the Client". One string, always.
    #[test]
    fn the_audience_is_the_client_as_a_single_string() {
        assert!(built()["aud"].is_string());
    }

    #[test]
    fn an_id_token_is_typed_and_names_the_algorithm_it_must_be_signed_with() {
        let grant = grant_with(Some(SubjectId::new("SUBJECT-1")));
        let claimed = grant.claim(now()).expect("a live grant");
        let unsigned = IdToken::new(
            &issuer(),
            &claimed,
            SigningAlgorithm::EdDsa,
            authentication(),
            ACCESS_TOKEN,
            now(),
        )
        .build()
        .expect("a buildable token");
        assert_eq!(unsigned.typ(), "JWT");
        assert_eq!(
            unsigned.required_algorithm(),
            Some(SigningAlgorithm::EdDsa),
            "an ID token must be signed with the client's registered algorithm"
        );
    }

    /// `auth_time` is the time of the authentication, never the time of
    /// issuance — OIDC Core §12.2 for the refresh case, and there is no reason
    /// for the two to differ in the first case either.
    #[test]
    fn auth_time_is_the_authentication_not_the_issuance() {
        let claims = built();
        assert_eq!(claims["auth_time"], json!(1_699_999_000));
        assert_ne!(claims["auth_time"], claims["iat"]);
    }

    #[test]
    fn acr_and_amr_appear_only_when_the_server_asserts_them() {
        let claims = built();
        assert!(claims.get("acr").is_none());
        assert!(claims.get("amr").is_none());

        let grant = grant_with(Some(SubjectId::new("SUBJECT-1")));
        let claimed = grant.claim(now()).expect("a live grant");
        let claims = IdToken::new(
            &issuer(),
            &claimed,
            SigningAlgorithm::Es256,
            Authentication {
                authenticated_at: authenticated(),
                acr: Some("urn:example:loa:2".to_owned()),
                amr: vec!["pwd".to_owned(), "otp".to_owned()],
            },
            ACCESS_TOKEN,
            now(),
        )
        .build()
        .expect("a buildable token")
        .into_claims();
        assert_eq!(claims["acr"], json!("urn:example:loa:2"));
        assert_eq!(claims["amr"], json!(["pwd", "otp"]));
    }

    // --- nonce (OIDC Core §2, §12.2) --------------------------------------

    /// "If present in the Authentication Request, Authorization Servers MUST
    /// include a `nonce` Claim in the ID Token with the Claim Value being the
    /// `nonce` value sent in the Authentication Request" — and, by omission,
    /// not otherwise.
    #[test]
    fn a_nonce_is_echoed_byte_exactly_and_exactly_when_one_was_sent() {
        assert!(built().get("nonce").is_none());

        let grant = grant_with(Some(SubjectId::new("SUBJECT-1")));
        let claimed = grant.claim(now()).expect("a live grant");
        for nonce in [
            "n-0S6_WzA2Mj",
            "N-0s6_wZa2mJ",
            " leading and trailing ",
            "\u{e9}\u{4e2d}",
            "n".repeat(MAX_NONCE_LEN).as_str(),
        ] {
            let claims = IdToken::new(
                &issuer(),
                &claimed,
                SigningAlgorithm::Es256,
                authentication(),
                ACCESS_TOKEN,
                now(),
            )
            .with_nonce(nonce)
            .build()
            .expect("a buildable token")
            .into_claims();
            assert_eq!(claims["nonce"], json!(nonce), "a nonce was rewritten");
        }
    }

    #[test]
    fn an_empty_or_oversized_nonce_is_refused() {
        let grant = grant_with(Some(SubjectId::new("SUBJECT-1")));
        let claimed = grant.claim(now()).expect("a live grant");
        for bad in [String::new(), "n".repeat(MAX_NONCE_LEN + 1)] {
            assert_eq!(
                IdToken::new(
                    &issuer(),
                    &claimed,
                    SigningAlgorithm::Es256,
                    authentication(),
                    ACCESS_TOKEN,
                    now(),
                )
                .with_nonce(bad)
                .build(),
                Err(IssuanceError::Nonce)
            );
        }
    }

    // --- sid (Back-Channel Logout 1.0 §2.1) -------------------------------

    #[test]
    fn sid_appears_only_when_a_session_is_reported() {
        assert!(built().get("sid").is_none());

        let grant = grant_with(Some(SubjectId::new("SUBJECT-1")));
        let claimed = grant.claim(now()).expect("a live grant");
        let session = Session::new(&SessionId::new("08a5019c-17e1-4977-8f42-65a12843ea02"))
            .expect("a session id");
        let claims = IdToken::new(
            &issuer(),
            &claimed,
            SigningAlgorithm::Es256,
            authentication(),
            ACCESS_TOKEN,
            now(),
        )
        .for_session(session)
        .build()
        .expect("a buildable token")
        .into_claims();
        assert_eq!(claims["sid"], json!("08a5019c-17e1-4977-8f42-65a12843ea02"));
    }

    /// The other half of the OpenID Foundation suite's finding (`ast-8p1`):
    /// `CheckForUnexpectedClaimsInIdToken` reported a name it did not know,
    /// and the name was `sid`. It stays — it is a registered claim and
    /// Back-Channel Logout 1.0 §2.1 is why the token has one — but it is only
    /// defensible for as long as the discovery document says so out loud.
    ///
    /// So this asserts the inclusion the finding was really about: every claim
    /// this builder emits about the exchange is a claim
    /// `metadata::claims_supported` advertises. A claim added here without a
    /// line there is exactly the surprise the suite flags, and it fails this
    /// test first.
    #[test]
    fn every_claim_the_builder_emits_is_one_the_discovery_document_advertises() {
        // Arrange: a token with every optional member populated, so that no
        // claim is absent merely because this fixture did not ask for it.
        let grant = grant_with(Some(SubjectId::new("SUBJECT-1")));
        let claimed = grant.claim(now()).expect("a live grant");
        let session = Session::new(&SessionId::new("08a5019c-17e1-4977-8f42-65a12843ea02"))
            .expect("a session id");

        // Act.
        let claims = IdToken::new(
            &issuer(),
            &claimed,
            SigningAlgorithm::Es256,
            Authentication {
                authenticated_at: authenticated(),
                acr: Some("urn:mace:incommon:iap:silver".to_owned()),
                amr: vec!["pwd".to_owned()],
            },
            ACCESS_TOKEN,
            now(),
        )
        .with_nonce("n-0S6_WzA2Mj")
        .for_session(session)
        .build()
        .expect("a buildable token")
        .into_claims();

        // Assert.
        let unexpected: Vec<&String> = claims
            .as_object()
            .expect("an object")
            .keys()
            .filter(|name| !crate::metadata::ID_TOKEN_CLAIMS.contains(&name.as_str()))
            .collect();
        assert!(
            unexpected.is_empty(),
            "emitted but not advertised: {unexpected:?}"
        );
    }

    #[test]
    fn a_session_id_that_is_not_printable_ascii_is_refused() {
        for bad in ["", "has space", "line\nbreak", "nul\0", &"s".repeat(129)] {
            assert_eq!(
                Session::new(&SessionId::new(bad)),
                Err(IssuanceError::Session),
                "accepted {bad:?}"
            );
        }
    }

    // --- The subject ------------------------------------------------------

    /// An ID token is an assertion about a person. A `client_credentials` grant
    /// has none, so there is nothing to assert.
    #[test]
    fn a_grant_with_no_resource_owner_gets_no_id_token() {
        let grant = grant_with(None);
        let claimed = grant.claim(now()).expect("a live grant");
        assert_eq!(
            IdToken::new(
                &issuer(),
                &claimed,
                SigningAlgorithm::Es256,
                authentication(),
                ACCESS_TOKEN,
                now(),
            )
            .build(),
            Err(IssuanceError::NoSubject)
        );
    }

    /// Present and empty is not the same as absent, and gets its own refusal.
    /// OIDC Core §3.1.3.7 has the client compare `sub` against the one it
    /// already holds for this user — a comparison every empty string passes
    /// against every other. Found by `cargo fuzz` (`ast-a05.17`).
    #[test]
    fn a_present_but_empty_subject_is_refused() {
        let grant = grant_with(Some(SubjectId::new("")));
        let claimed = grant.claim(now()).expect("a live grant");
        assert_eq!(
            IdToken::new(
                &issuer(),
                &claimed,
                SigningAlgorithm::Es256,
                authentication(),
                ACCESS_TOKEN,
                now(),
            )
            .build(),
            Err(IssuanceError::EmptySubject)
        );
    }

    /// OIDC Core §8.1: "Distinct Sector Identifier values MUST result in
    /// distinct Subject Identifier values." The derivation lives in
    /// `PairwiseSalt`; what is asserted here is that the ID token carries what
    /// it produced — a different `sub` per sector, the same one every time
    /// within a sector.
    #[test]
    fn a_pairwise_sub_differs_across_sectors_and_is_stable_within_one() {
        let salt = PairwiseSalt::from_bytes([0x2b; PairwiseSalt::LEN]);
        let user = UserId::generate();
        let here = SectorIdentifier::of_uri("https://rp.example/sector.json").expect("a sector");
        let there =
            SectorIdentifier::of_uri("https://other.example/sector.json").expect("a sector");

        let sub_here = |sector: &SectorIdentifier| {
            let grant = grant_with(Some(salt.derive_subject(sector, user)));
            let claimed = grant.claim(now()).expect("a live grant");
            IdToken::new(
                &issuer(),
                &claimed,
                SigningAlgorithm::Es256,
                authentication(),
                ACCESS_TOKEN,
                now(),
            )
            .build()
            .expect("a buildable token")
            .into_claims()["sub"]
                .clone()
        };

        assert_eq!(
            sub_here(&here),
            sub_here(&here),
            "a sub changed within one sector"
        );
        assert_ne!(
            sub_here(&here),
            sub_here(&there),
            "two sectors saw the same sub"
        );
        // And neither is the local account identifier: OIDC Core §8.1's
        // "MUST NOT be reversible by any party other than the OpenID Provider"
        // starts with not shipping the input.
        assert_ne!(sub_here(&here), json!(user.as_uuid().to_string()));
    }

    // --- The claims a client may not write --------------------------------

    /// The requirement in one test: nothing claims resolution hands over can
    /// take the place of a claim this server asserts. The guarantee is
    /// structural upstream — `ResolvedClaims` is built from `ReleasableClaim`
    /// keys — and this is the check that the structure is not the *only* thing
    /// standing between a stored user attribute and an RP's idea of who the
    /// user is.
    #[test]
    fn no_released_claim_can_overwrite_one_the_server_issues() {
        let grant = grant_with(Some(SubjectId::new("SUBJECT-1")));
        let claimed = grant.claim(now()).expect("a live grant");
        for reserved in ClaimName::SERVER_ISSUED {
            let mut released = Map::new();
            released.insert((*reserved).to_owned(), json!("attacker-chosen"));
            assert_eq!(
                IdToken::new(
                    &issuer(),
                    &claimed,
                    SigningAlgorithm::Es256,
                    authentication(),
                    ACCESS_TOKEN,
                    now(),
                )
                .releasing(released)
                .build(),
                Err(IssuanceError::ServerIssuedClaim(reserved)),
                "a released {reserved} was accepted"
            );
        }
    }

    #[test]
    fn a_released_claim_name_that_is_not_a_claim_name_is_refused() {
        let grant = grant_with(Some(SubjectId::new("SUBJECT-1")));
        let claimed = grant.claim(now()).expect("a live grant");
        for bad in ["", "\u{202e}given_name", "name#not a tag", &"n".repeat(200)] {
            let mut released = Map::new();
            released.insert(bad.to_owned(), json!("x"));
            assert_eq!(
                IdToken::new(
                    &issuer(),
                    &claimed,
                    SigningAlgorithm::Es256,
                    authentication(),
                    ACCESS_TOKEN,
                    now(),
                )
                .releasing(released)
                .build(),
                Err(IssuanceError::UnreleasableClaim),
                "accepted {bad:?}"
            );
        }
    }

    #[test]
    fn released_claims_are_carried_through_untouched() {
        let grant = grant_with(Some(SubjectId::new("SUBJECT-1")));
        let claimed = grant.claim(now()).expect("a live grant");
        let mut released = Map::new();
        released.insert("given_name".to_owned(), json!("Ada"));
        released.insert("name#ja-Kana-JP".to_owned(), json!("\u{30a2}\u{30c0}"));
        released.insert("email".to_owned(), json!("ada@example.com"));
        let claims = IdToken::new(
            &issuer(),
            &claimed,
            SigningAlgorithm::Es256,
            authentication(),
            ACCESS_TOKEN,
            now(),
        )
        .releasing(released)
        .build()
        .expect("a buildable token")
        .into_claims();
        assert_eq!(claims["given_name"], json!("Ada"));
        assert_eq!(claims["name#ja-Kana-JP"], json!("\u{30a2}\u{30c0}"));
        assert_eq!(claims["email"], json!("ada@example.com"));
        // And the server's own claims are still the server's.
        assert_eq!(claims["sub"], json!("SUBJECT-1"));
    }

    // --- Lifetime and size -------------------------------------------------

    #[test]
    fn a_lifetime_past_the_cap_is_refused() {
        let grant = grant_with(Some(SubjectId::new("SUBJECT-1")));
        let claimed = grant.claim(now()).expect("a live grant");
        for bad in [
            Duration::ZERO,
            Duration::seconds(-1),
            IdToken::MAX_LIFETIME + Duration::seconds(1),
        ] {
            assert_eq!(
                IdToken::new(
                    &issuer(),
                    &claimed,
                    SigningAlgorithm::Es256,
                    authentication(),
                    ACCESS_TOKEN,
                    now(),
                )
                .for_lifetime(bad)
                .build(),
                Err(IssuanceError::Lifetime)
            );
        }
    }

    #[test]
    fn a_claims_set_over_the_guard_is_refused() {
        let grant = grant_with(Some(SubjectId::new("SUBJECT-1")));
        let claimed = grant.claim(now()).expect("a live grant");
        let mut released = Map::new();
        released.insert(
            "given_name".to_owned(),
            json!("A".repeat(MAX_ID_TOKEN_CLAIMS_BYTES)),
        );
        assert!(matches!(
            IdToken::new(
                &issuer(),
                &claimed,
                SigningAlgorithm::Es256,
                authentication(),
                ACCESS_TOKEN,
                now(),
            )
            .releasing(released)
            .build(),
            Err(IssuanceError::TooLarge { .. })
        ));
    }

    /// RFC 9396 §7: `authorization_details` is what the resource server reads
    /// as the authority a token carries, and the authorization server computes
    /// it from the grant. A stored user attribute of that name reaching an ID
    /// token would be an administrator — or an importer — writing authorization
    /// data into an identity assertion (`ast-8ft2`, found by fuzzing).
    ///
    /// Walked over `AUTHORISATION_CLAIMS` rather than over a copy of it, so
    /// that a claim this issuer learns tomorrow is covered the day it is
    /// added — `grant_id` was the one this list was missing. The
    /// language-tagged spelling too: the reserved lists are compared against
    /// the base name everywhere else, and `grant_id#en` would otherwise be the
    /// one spelling that survives.
    #[test]
    fn no_released_claim_can_carry_authorisation_into_an_id_token() {
        let grant = grant_with(Some(SubjectId::new("SUBJECT-1")));
        let claimed = grant.claim(now()).expect("a live grant");
        let spellings = AUTHORISATION_CLAIMS
            .iter()
            .map(|name| (*name).to_owned())
            .chain(AUTHORISATION_CLAIMS.iter().map(|name| format!("{name}#en")));
        for name in spellings {
            // The ones the bag already refuses answer `ServerIssuedClaim`
            // first; this test is about the others, which reach the
            // releasable-name check.
            if ClaimName::SERVER_ISSUED.contains(&name.as_str()) {
                continue;
            }
            let mut released = Map::new();
            released.insert(name.clone(), json!([{"type": "payment_initiation"}]));
            assert_eq!(
                IdToken::new(
                    &issuer(),
                    &claimed,
                    SigningAlgorithm::Es256,
                    authentication(),
                    ACCESS_TOKEN,
                    now(),
                )
                .releasing(released)
                .build(),
                Err(IssuanceError::UnreleasableClaim),
                "a released {name} was accepted"
            );
        }
    }

    /// The other half of RFC 9068 §2.1's separation: an ID token carries none
    /// of the claims that make an access token authority. The list is the
    /// issuer's own, so this cannot fall behind it.
    #[test]
    fn an_id_token_carries_no_authorisation() {
        let claims = built();
        for forbidden in AUTHORISATION_CLAIMS {
            assert!(
                claims.get(*forbidden).is_none(),
                "an ID token carried the access token claim {forbidden}"
            );
        }
    }

    // --- Application roles (`ast-mqt`) -------------------------------------

    /// `billing` is the client `grant_with` issues to; `reporting` is the one
    /// whose roles must never appear in its token.
    fn held() -> HeldRoles {
        let mut held = HeldRoles::default();
        held.tenant
            .insert(asterius_domain::RoleName::parse("auditor").expect("a name"));
        held.clients.insert(
            ClientId::new("billing"),
            [asterius_domain::RoleName::parse("refund").expect("a name")]
                .into_iter()
                .collect(),
        );
        held.clients.insert(
            ClientId::new("reporting"),
            [asterius_domain::RoleName::parse("export").expect("a name")]
                .into_iter()
                .collect(),
        );
        held
    }

    fn built_with_roles(claims: &BTreeSet<RoleClaim>) -> Value {
        let grant = grant_with(Some(SubjectId::new("SUBJECT-1")));
        let claimed = grant.claim(now()).expect("a live grant");
        IdToken::new(
            &issuer(),
            &claimed,
            SigningAlgorithm::Es256,
            authentication(),
            ACCESS_TOKEN,
            now(),
        )
        .with_roles(&held(), claims)
        .build()
        .expect("a buildable token")
        .into_claims()
    }

    /// The default, and the one that matters: an ID token nobody asked to
    /// carry authority carries none.
    #[test]
    fn an_id_token_carries_no_role_claim_unless_one_was_asked_for() {
        let claims = built_with_roles(&BTreeSet::new());

        assert!(claims.get("roles").is_none());
        assert!(claims.get("resource_access").is_none());
    }

    #[test]
    fn the_tenant_roles_are_emitted_when_the_claim_is_asked_for() {
        let claims = built_with_roles(&[RoleClaim::Roles].into_iter().collect());

        assert_eq!(claims["roles"], json!(["auditor"]));
        assert!(claims.get("resource_access").is_none());
    }

    /// The same narrowing the access token gets, applied by the builder and
    /// not by the caller: a token names its own client and no other.
    #[test]
    fn resource_access_names_only_the_client_the_token_is_for() {
        let claims = built_with_roles(&[RoleClaim::ResourceAccess].into_iter().collect());

        assert_eq!(
            claims["resource_access"],
            json!({"billing": {"roles": ["refund"]}})
        );
    }

    /// A user record cannot assert authority, whatever a `claims` request
    /// says: `roles` is not a releasable claim name, so a released map keyed
    /// with it is refused rather than carried into the token.
    #[test]
    fn a_released_claim_named_roles_is_refused() {
        let grant = grant_with(Some(SubjectId::new("SUBJECT-1")));
        let claimed = grant.claim(now()).expect("a live grant");
        let mut released = Map::new();
        released.insert("roles".to_owned(), json!(["administrator"]));

        let error = IdToken::new(
            &issuer(),
            &claimed,
            SigningAlgorithm::Es256,
            authentication(),
            ACCESS_TOKEN,
            now(),
        )
        .releasing(released)
        .build()
        .expect_err("a refusal");

        assert_eq!(error, IssuanceError::UnreleasableClaim);
    }

    /// Absent rather than empty, for the reason `HeldRoles::claim` gives: an
    /// empty array is a statement a relying party may cache.
    #[test]
    fn a_person_holding_nothing_gets_no_claim_even_when_asked_for() {
        let grant = grant_with(Some(SubjectId::new("SUBJECT-1")));
        let claimed = grant.claim(now()).expect("a live grant");
        let claims = IdToken::new(
            &issuer(),
            &claimed,
            SigningAlgorithm::Es256,
            authentication(),
            ACCESS_TOKEN,
            now(),
        )
        .with_roles(
            &HeldRoles::default(),
            &RoleClaim::ALL.into_iter().collect::<BTreeSet<_>>(),
        )
        .build()
        .expect("a buildable token")
        .into_claims();

        assert!(claims.get("roles").is_none());
        assert!(claims.get("resource_access").is_none());
    }
}
