//! The JWT access token profile: RFC 9068, always audience- and
//! sender-constrained.
//!
//! Self-contained and signed. Opaque reference tokens are not implemented:
//! they would need a lookup on every resource call and a second revocation
//! path, and the thing they buy — instant revocation — is bought here instead
//! by short lifetimes plus a `jti` denylist
//! (`asterius_domain::LiveAccessToken`).
//!
//! Three properties are structural rather than checked, which is the whole
//! design of this module.
//!
//! ## There is no such thing as an access token without `cnf`
//!
//! FAPI 2.0 SP §5.3.2.1 item 4: an authorization server "shall only issue
//! sender-constrained access tokens". Not "should", and not "unless the client
//! asked otherwise" — a bearer access token is a credential that works for
//! whoever finds it in a log, a proxy or a browser history, which is FAPI 2.0's
//! attacker A5 and half of the reason the profile exists.
//!
//! So [`AccessToken::new`] takes a [`Confirmation`] by value, as a positional
//! argument. Not an `Option`, not a builder method a caller might not call, and
//! [`Confirmation`] has no `Default` and no empty constructor: every variant
//! carries at least one thumbprint. A token with no `cnf` is not a token this
//! module rejects — it is a call that does not compile.
//!
//! ## `aud` is the resource, never the client
//!
//! RFC 9068 §3: "If the request includes a `resource` parameter (as defined in
//! \[RFC8707\]), the resulting JWT access token `aud` claim SHOULD have the
//! same value as the `resource` parameter in the request", and "If the request
//! does not include a `resource` parameter, the authorization server MUST use a
//! default resource indicator in the `aud` claim." RFC 9068 §5 says why:
//! "To prevent cross-JWT confusion, authorization servers MUST use a distinct
//! identifier as an `aud` claim value to uniquely identify access tokens issued
//! by the same issuer for distinct resources."
//!
//! [`Audience`] is therefore non-empty by construction and holds only absolute
//! URIs without fragments (RFC 8707 §2), and [`AccessToken::build`] refuses an
//! audience that names the client the token was issued to. An access token
//! audienced at its own client is a token that every resource server has to
//! make its own decision about, which is the ambiguity RFC 9068 §3's "MUST NOT
//! issue a JWT access token if the authorization granted by the token would be
//! ambiguous" is about.
//!
//! ## The claim set is closed
//!
//! There is no parameter for "extra claims". Everything an access token can say
//! is a field of this builder, projected from the grant or from the
//! authentication event — so "no PII beyond `sub` unless a resource policy opts
//! in" is not a rule somebody has to remember at the call site, it is the
//! absence of an argument. RFC 9068 §5 asks for exactly this restraint, and
//! §6 spells out that a JWT access token is readable by the client that holds
//! it.
//!
//! In particular, `nonce` and `at_hash` are ID token claims and cannot appear
//! here, because nothing in this module can write them.
//!
//! ## A note on RS256
//!
//! RFC 9068 §2.1 says "Authorization servers and resource servers conforming to
//! this specification MUST include RS256 (as defined in \[RFC7518\]) among
//! their supported signature algorithms." Asterius does not, and this is a
//! deliberate, recorded deviation: FAPI 2.0 SP §5.4.1 permits only PS256, ES256
//! and EdDSA, and ADR-0003 records why the conflict is resolved in FAPI's
//! favour. The point is not reachable from this module — `SigningAlgorithm` has
//! no RS256 variant — which is the form the decision was meant to take.

use super::{
    IssuanceError, JwtId, MAX_ACCESS_TOKEN_CLAIMS_BYTES, UnsignedToken, bounded, usable_lifetime,
};
use asterius_domain::{ClaimedGrant, Grant, Issuer, Kid, TokenBinding};
use serde_json::{Map, Value};
use std::collections::BTreeSet;
use time::{Duration, OffsetDateTime};

/// The explicit type header of a JWT access token (RFC 9068 §2.1).
///
/// > JWT access tokens MUST include this media type in the `typ` header
/// > parameter to explicitly declare that the JWT represents an access token
/// > complying with this profile. Per the definition of `typ` in Section 4.1.9
/// > of \[RFC7515\], it is RECOMMENDED that the `application/` prefix be
/// > omitted. Therefore, the `typ` value used SHOULD be `at+jwt`.
pub const ACCESS_TOKEN_TYP: &str = "at+jwt";

// ---------------------------------------------------------------------------
// Sender constraining
// ---------------------------------------------------------------------------

/// The `cnf` claim of a sender-constrained access token (RFC 7800 §3.1).
///
/// Every variant carries a thumbprint, and there is no variant for "not bound
/// to anything". That is the enforcement of FAPI 2.0 SP §5.3.2.1 item 4: the
/// unconstrained case is not a value this type can hold, so no call site has to
/// remember to reject it.
///
/// The two members are the two methods the profile's item 5 allows:
///
/// * `jkt` — RFC 9449 §6.1, "the base64url encoding (as defined in
///   \[RFC7515\]) of the JWK SHA-256 Thumbprint (according to \[RFC7638\]) of
///   the DPoP public key (in JWK format) to which the access token is bound";
/// * `x5t#S256` — RFC 8705 §3.1, "a base64url-encoded SHA-256 \[SHS\] hash
///   (a.k.a. thumbprint, fingerprint, or digest) of the DER encoding of the
///   X.509 certificate".
///
/// Both are the same shape — an unpadded base64url SHA-256 digest, 43
/// characters — which is what [`Confirmation::THUMBPRINT_LEN`] checks. That is
/// a stronger guarantee than "non-empty": a `cnf` holding a truncated or
/// hex-encoded thumbprint would be a binding no resource server ever matches,
/// which is a token that silently behaves like a bearer token from the
/// server's point of view and like a broken one from the client's.
///
/// Exactly one of the two, never both, because `TokenBinding` admits exactly
/// one: a `cnf` carrying a `jkt` beside an `x5t#S256` would leave a resource
/// server to decide for itself which of them it is obliged to check, and a
/// binding that the verifier chooses is not one this server can state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Confirmation {
    /// The one member, already checked into shape. Private, so that the only
    /// way to a `Confirmation` is through a constructor that ran
    /// [`thumbprint`].
    method: Method,
}

/// Which `cnf` member a [`Confirmation`] carries.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Method {
    /// RFC 9449 §6.1's `jkt`.
    Dpop(String),
    /// RFC 8705 §3.1's `x5t#S256`.
    Certificate(String),
}

impl Confirmation {
    /// The length of an unpadded base64url SHA-256 digest.
    pub const THUMBPRINT_LEN: usize = 43;

    /// Binds a token to a DPoP key (RFC 9449 §6.1).
    ///
    /// The `jkt` is the value `asterius_jose::Proof::jkt` produces, so the
    /// thumbprint a token is bound to is the one a verified proof presented and
    /// not a value a caller assembled.
    ///
    /// # Errors
    ///
    /// [`IssuanceError::Thumbprint`] if it is not a base64url SHA-256 digest.
    pub fn dpop(jkt: &Kid) -> Result<Self, IssuanceError> {
        Ok(Self {
            method: Method::Dpop(thumbprint(jkt.as_str())?),
        })
    }

    /// Binds a token to a client certificate (RFC 8705 §3.1).
    ///
    /// The thumbprint is the one `asterius_oidc::mtls::ClientCertificate`
    /// computed over the DER a trusted proxy forwarded, so — as with `jkt` —
    /// what a token is bound to is what the endpoint actually saw.
    ///
    /// # Errors
    ///
    /// [`IssuanceError::Thumbprint`] if it is not a base64url SHA-256 digest.
    pub fn certificate(x5t_s256: &str) -> Result<Self, IssuanceError> {
        Ok(Self {
            method: Method::Certificate(thumbprint(x5t_s256)?),
        })
    }

    /// Which binding this confirmation expresses.
    ///
    /// So that a caller can check it against the client's registered
    /// `TokenBinding` before minting: a client registered for DPoP that somehow
    /// received a certificate-bound token would hold a credential its own
    /// software cannot present.
    #[must_use]
    pub const fn binding(&self) -> TokenBinding {
        match self.method {
            Method::Dpop(_) => TokenBinding::Dpop,
            Method::Certificate(_) => TokenBinding::Certificate,
        }
    }

    /// The `cnf` claim value.
    fn claim(&self) -> Value {
        let mut members = Map::new();
        let (name, value) = match &self.method {
            Method::Dpop(jkt) => ("jkt", jkt),
            Method::Certificate(x5t) => ("x5t#S256", x5t),
        };
        members.insert(name.to_owned(), Value::String(value.clone()));
        Value::Object(members)
    }
}

/// Checks that a string is an unpadded base64url SHA-256 digest.
///
/// A shape check, not a decode-and-re-encode: what has to be true is that the
/// value is the 43-character spelling both RFC 9449 §6.1 and RFC 8705 §3.1
/// define, so that a resource server computing the same digest gets the same
/// bytes. Padding, standard-alphabet base64 and hex are all refused, because
/// each of them is a thumbprint that compares unequal to the correct one.
// fuzz-target: access_token_claims
fn thumbprint(raw: &str) -> Result<String, IssuanceError> {
    if raw.len() != Confirmation::THUMBPRINT_LEN
        || !raw
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(IssuanceError::Thumbprint);
    }
    Ok(raw.to_owned())
}

// ---------------------------------------------------------------------------
// Audience
// ---------------------------------------------------------------------------

/// The resources an access token is good for (RFC 8707, RFC 9068 §3).
///
/// Non-empty by construction, because RFC 9068 §2.2 makes `aud` REQUIRED and
/// §3 makes the authorization server supply a default when the client named no
/// resource. An empty audience is not "unrestricted", it is a token no
/// conforming resource server accepts and every non-conforming one does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Audience(BTreeSet<String>);

impl Audience {
    /// The most resource indicators one token may be audienced at.
    ///
    /// The same bound a grant carries, and for the same reason: an audience is
    /// compared by every resource server that receives the token, and a token
    /// naming thirty-two of them has stopped being least privilege (FAPI 2.0 SP
    /// §5.3.2.1 item 14) whatever else it does.
    pub const MAX: usize = Grant::MAX_RESOURCES;

    /// Builds an audience from resource identifiers.
    ///
    /// # Errors
    ///
    /// [`IssuanceError::Audience`] if the set is empty, larger than
    /// [`Audience::MAX`], or holds anything that is not an absolute URI without
    /// a fragment (RFC 8707 §2).
    pub fn new<I, S>(resources: I) -> Result<Self, IssuanceError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut validated = BTreeSet::new();
        for resource in resources {
            let resource = resource.as_ref();
            let parsed = url::Url::parse(resource).map_err(|_| IssuanceError::Audience)?;
            if parsed.fragment().is_some() || parsed.cannot_be_a_base() {
                return Err(IssuanceError::Audience);
            }
            validated.insert(resource.to_owned());
        }
        if validated.is_empty() || validated.len() > Self::MAX {
            return Err(IssuanceError::Audience);
        }
        Ok(Self(validated))
    }

    /// The audience of a grant, or `None` when it names no resource.
    ///
    /// `None` is the case RFC 9068 §3 says the authorization server must fill
    /// in with a default resource indicator, and it is returned rather than
    /// invented here because this module does not know what a deployment's
    /// default resource is.
    #[must_use]
    pub fn of_grant(grant: &Grant) -> Option<Self> {
        Self::new(&grant.resources).ok()
    }

    /// The identifiers, sorted.
    pub fn values(&self) -> impl Iterator<Item = &str> {
        self.0.iter().map(String::as_str)
    }

    /// The `aud` claim value.
    ///
    /// A bare string when there is one audience, an array otherwise. RFC 7519
    /// §4.1.3 allows both and RFC 9068 §3's own example uses the string form;
    /// a one-element array would be correct and would still be the spelling
    /// some resource servers get wrong.
    fn claim(&self) -> Value {
        let mut values = self.0.iter();
        match (values.next(), self.0.len()) {
            (Some(single), 1) => Value::String(single.clone()),
            _ => Value::Array(self.0.iter().cloned().map(Value::String).collect()),
        }
    }
}

// ---------------------------------------------------------------------------
// Authentication information
// ---------------------------------------------------------------------------

/// What the authorization server enforced before the authorization response
/// (RFC 9068 §2.2.1).
///
/// > The claims listed in this section MAY be issued in the context of
/// > authorization grants involving the resource owner and reflect the types
/// > and strength of authentication in the access token that the authentication
/// > server enforced prior to returning the authorization response to the
/// > client. Their values are fixed and remain the same across all access
/// > tokens that derive from a given authorization response […]
///
/// "Fixed and remain the same" is the part that matters for a refresh: a token
/// minted an hour later from a refresh token carries the `auth_time` of the
/// original sign-in, not the time it was minted. That is the same rule OIDC
/// Core §12.2 states for the ID token, and it is why this is a value read off
/// the authorization event rather than a clock read at issuance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authentication {
    /// When the person actually authenticated.
    pub authenticated_at: OffsetDateTime,
    /// The `acr` the authentication satisfied, if the deployment asserts one.
    pub acr: Option<String>,
    /// The `amr` values, if the deployment asserts any.
    pub amr: Vec<String>,
}

// ---------------------------------------------------------------------------
// The builder
// ---------------------------------------------------------------------------

/// Builds the claims set of a JWT access token.
///
/// Everything RFC 9068 §2.2 makes REQUIRED is either a positional argument or
/// projected from the grant, so an incomplete token is a call that does not
/// compile rather than a token that fails validation at a resource server.
#[derive(Debug, Clone)]
#[must_use]
pub struct AccessToken<'a> {
    issuer: &'a Issuer,
    grant: &'a Grant,
    claimed: &'a ClaimedGrant,
    audience: Audience,
    confirmation: Confirmation,
    jti: JwtId,
    issued_at: OffsetDateTime,
    lifetime: Duration,
    authentication: Option<Authentication>,
    grant_id_claim: bool,
    scopes: Option<BTreeSet<String>>,
}

impl<'a> AccessToken<'a> {
    /// The lifetime used unless a caller chooses another.
    ///
    /// FAPI 2.0 SP §6.1 recommends short-lived access tokens with refresh
    /// tokens behind them, and notes the trade: "setting the access token
    /// lifetime too short can increase the load on and dependency on the
    /// authorization server". Five minutes is short enough that a token
    /// captured from a log is usually already dead and long enough that a
    /// normal request does not renew mid-flight.
    pub const DEFAULT_LIFETIME: Duration =
        asterius_domain::entities::tenant_settings::DEFAULT_ACCESS_TOKEN_LIFETIME;

    /// The longest lifetime this server will mint, whatever a caller asks for.
    ///
    /// A ceiling rather than a default, so that a tenant or a resource policy
    /// can lengthen a token within a bound the code owns. Fifteen minutes is
    /// the point past which "short-lived" stops being an accurate description
    /// and the `jti` denylist has to hold rows for a quarter of an hour after
    /// every revocation.
    /// The same constant the tenant settings validate against, aliased rather
    /// than repeated: `ast-5c6`'s finding was that a cap written down twice
    /// drifts into two mechanisms, and a tenant's configured lifetime is now
    /// handed straight to [`AccessToken::for_lifetime`].
    pub const MAX_LIFETIME: Duration =
        asterius_domain::entities::tenant_settings::MAX_ACCESS_TOKEN_LIFETIME;

    /// The deepest `act` chain that may be rendered (RFC 8693 §4.1).
    ///
    /// Each level is one more delegation hop; a chain longer than this is not
    /// a delegation story, it is a way to make every resource server walk a
    /// nested object.
    pub const MAX_ACTORS: usize = 8;

    /// A token for `claimed`, audienced at `audience`, bound to `confirmation`.
    ///
    /// `grant` and `claimed` are both required and are checked against each
    /// other in [`AccessToken::build`]: the claim carries the authority to mint,
    /// and the grant carries what may be minted.
    pub const fn new(
        issuer: &'a Issuer,
        grant: &'a Grant,
        claimed: &'a ClaimedGrant,
        audience: Audience,
        confirmation: Confirmation,
        jti: JwtId,
        issued_at: OffsetDateTime,
    ) -> Self {
        Self {
            issuer,
            grant,
            claimed,
            audience,
            confirmation,
            jti,
            issued_at,
            lifetime: Self::DEFAULT_LIFETIME,
            authentication: None,
            grant_id_claim: false,
            scopes: None,
        }
    }

    /// Narrows the `scope` claim to what the audience's resource servers
    /// understand (RFC 8707 §2).
    ///
    /// The grant remains the ceiling: anything here that the grant does not
    /// carry is dropped, so a caller cannot widen a token by calling this. What
    /// it can do is *narrow* — which is what a resource server's scope list is
    /// for, and why a token audienced at two of them carries only what both
    /// accept.
    ///
    /// Left unset, the grant's own scopes are the claim, which is what every
    /// grant with no resource-server scope list gets.
    pub fn restricted_to_scopes(mut self, scopes: BTreeSet<String>) -> Self {
        self.scopes = Some(
            scopes
                .into_iter()
                .filter(|scope| self.grant.scopes.contains(scope))
                .collect(),
        );
        self
    }

    /// Overrides the lifetime, up to [`AccessToken::MAX_LIFETIME`].
    pub const fn for_lifetime(mut self, lifetime: Duration) -> Self {
        self.lifetime = lifetime;
        self
    }

    /// Records how the resource owner authenticated (RFC 9068 §2.2.1).
    pub fn authenticated_by(mut self, authentication: Authentication) -> Self {
        self.authentication = Some(authentication);
        self
    }

    /// Adds the `grant_id` private claim.
    ///
    /// Off by default and a tenant option, because it is a correlator: a
    /// resource server holding two tokens can tell they came from the same
    /// authorization, which is useful for a deployment that operates its own
    /// resource servers and is a privacy leak in one that does not (RFC 9068
    /// §6). It is also what makes Grant Management's `DELETE` explicable to a
    /// resource server, which is why it exists at all.
    pub const fn with_grant_id(mut self) -> Self {
        self.grant_id_claim = true;
        self
    }

    /// The same, decided by the tenant's own setting.
    ///
    /// Exists so that a call site reads as "this tenant's answer" rather than
    /// as an `if` around a builder chain: every issuance path asks the same
    /// question of the same setting, and one of them quietly not asking it
    /// would be a token whose claim depends on which grant type minted it.
    pub const fn with_grant_id_when(self, carried: bool) -> Self {
        if carried { self.with_grant_id() } else { self }
    }

    /// Assembles the claims set.
    ///
    /// # Errors
    ///
    /// The first [`IssuanceError`] that applies.
    // fuzz-target: access_token_claims
    /// The `sub` claim.
    ///
    /// RFC 9068 §2.2 puts the `client_id` there for a grant with no resource
    /// owner, which is the `None` arm. A *present* but empty subject is
    /// neither case and must not be allowed to take the first: falling back
    /// would label a user's token as a client's.
    fn subject_claim(&self, client_id: &str) -> Result<String, IssuanceError> {
        let Some(subject) = self.claimed.subject() else {
            return Ok(client_id.to_owned());
        };
        let subject = subject.to_string();
        if subject.is_empty() {
            return Err(IssuanceError::EmptySubject);
        }
        Ok(subject)
    }

    /// The `scope` claim, or `None` when nothing is left to put in it.
    ///
    /// The grant's scopes, unless [`AccessToken::restricted_to_scopes`] has
    /// narrowed them to what the audience's resource servers understand — which
    /// can legitimately leave nothing, and a token with no `scope` is a token
    /// that authorises nothing rather than one that authorises everything (RFC
    /// 9068 §2.2.3 makes the claim optional; RFC 6749 §3.3 makes an absent
    /// scope the AS's own choice).
    ///
    /// Every scope is checked against the domain's own `scope-token` function
    /// rather than a copy of its rule. `GrantRecord::validate` refuses a
    /// splitting scope on the way in; this is the join that would do the
    /// damage, and a row edited by hand never met that check.
    fn scope_claim(&self) -> Result<Option<String>, IssuanceError> {
        let scopes = self.scopes.as_ref().unwrap_or(&self.grant.scopes);
        if scopes.is_empty() {
            return Ok(None);
        }
        if !scopes
            .iter()
            .all(|scope| asterius_domain::entities::grant::is_scope_token(scope))
        {
            return Err(IssuanceError::Scope);
        }
        Ok(Some(
            scopes
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join(" "),
        ))
    }

    pub fn build(self) -> Result<UnsignedToken, IssuanceError> {
        if self.grant.id != *self.claimed.id()
            || self.grant.client != *self.claimed.client()
            || self.grant.tenant != *self.claimed.tenant()
        {
            return Err(IssuanceError::GrantMismatch);
        }

        let lifetime = usable_lifetime(self.lifetime, Self::MAX_LIFETIME)?;
        let client_id = self.claimed.client().as_str();

        // RFC 9068 §5: a distinct `aud` per resource is what prevents cross-JWT
        // confusion, and the client is not a resource. A token audienced at its
        // own client is also an ID token's audience, which is the confusion
        // §2.1's explicit typing exists to prevent — being refused twice is the
        // right number of times.
        if self.audience.values().any(|value| value == client_id) {
            return Err(IssuanceError::AudienceIsTheClient);
        }

        let mut claims = Map::new();

        // RFC 9068 §2.2, in the order that section lists them.
        claims.insert(
            "iss".to_owned(),
            Value::String(self.issuer.as_str().to_owned()),
        );
        claims.insert(
            "exp".to_owned(),
            Value::from((self.issued_at + lifetime).unix_timestamp()),
        );
        claims.insert("aud".to_owned(), self.audience.claim());
        // §2.2: "In cases of access tokens obtained through grants where a
        // resource owner is involved […] the value of `sub` SHOULD correspond
        // to the subject identifier of the resource owner. In cases of access
        // tokens obtained through grants where no resource owner is involved,
        // such as the client credentials grant, the value of `sub` SHOULD
        // correspond to an identifier the authorization server uses to indicate
        // the client application." `ClaimedGrant::subject` is `None` in exactly
        // the second case, so the two arms are the two the RFC names.
        claims.insert(
            "sub".to_owned(),
            Value::String(self.subject_claim(client_id)?),
        );
        claims.insert("client_id".to_owned(), Value::String(client_id.to_owned()));
        claims.insert(
            "iat".to_owned(),
            Value::from(self.issued_at.unix_timestamp()),
        );
        claims.insert(
            "jti".to_owned(),
            Value::String(self.jti.as_str().to_owned()),
        );

        // Not optional here, however optional RFC 7800 makes it in general.
        claims.insert("cnf".to_owned(), self.confirmation.claim());

        // §2.2.3: "If an authorization request includes a scope parameter, the
        // corresponding issued JWT access token SHOULD include a `scope` claim
        // as defined in Section 4.2 of [RFC8693]." The grant's scopes, not the
        // request's: what was granted, not what was asked for. The join is safe
        // because `GrantRecord::validate` already holds every stored scope to
        // RFC 6749 §3.3's grammar, so none of them contains a space to split on.
        if let Some(scope) = self.scope_claim()? {
            claims.insert("scope".to_owned(), Value::String(scope));
        }

        // §2.2.1.
        if let Some(authentication) = &self.authentication {
            claims.insert(
                "auth_time".to_owned(),
                Value::from(authentication.authenticated_at.unix_timestamp()),
            );
            if let Some(acr) = &authentication.acr {
                claims.insert("acr".to_owned(), Value::String(acr.clone()));
            }
            if !authentication.amr.is_empty() {
                claims.insert(
                    "amr".to_owned(),
                    Value::Array(
                        authentication
                            .amr
                            .iter()
                            .cloned()
                            .map(Value::String)
                            .collect(),
                    ),
                );
            }
        }

        // RFC 9396 §9.1: "If the access token is a JWT [RFC7519], the AS is
        // RECOMMENDED to add the authorization details object, filtered to the
        // specific audience, as a top-level claim." The filtering is the
        // authorization-details story's (`ast-m9c.6`); what is stored on the
        // grant is already what was granted.
        if !self.grant.authorization_details.is_empty() {
            claims.insert(
                "authorization_details".to_owned(),
                Value::Array(self.grant.authorization_details.clone()),
            );
        }

        // RFC 8693 §4.1.
        if let Some(act) = actor_claim(&self.grant.actor_chain)? {
            claims.insert("act".to_owned(), act);
        }

        if self.grant_id_claim {
            claims.insert(
                "grant_id".to_owned(),
                Value::String(self.claimed.id().as_str().to_owned()),
            );
        }

        Ok(UnsignedToken {
            typ: ACCESS_TOKEN_TYP,
            // An access token says nothing about how it was signed, so any key
            // on the tenant's allow-list will do.
            required_algorithm: None,
            claims: bounded(Value::Object(claims), MAX_ACCESS_TOKEN_CLAIMS_BYTES)?,
        })
    }
}

/// Folds a grant's actor chain into the nested `act` claim (RFC 8693 §4.1).
///
/// > The outermost `act` claim represents the current actor while nested `act`
/// > claims represent prior actors.
///
/// A grant stores the chain innermost-actor-last, so the first element is the
/// current actor and each later one nests inside its predecessor. Rendering it
/// the other way round would name the *earliest* delegate as the party acting
/// now, which is precisely the claim a resource server authorises against.
///
/// Only objects, and only [`AccessToken::MAX_ACTORS`] of them: the column is
/// `jsonb` and `GrantRecord::validate` checks only that it is an array, so this
/// is where the elements are held to a shape. §4.1 also says non-identity
/// claims "are not meaningful when used within an `act` claim", which is why an
/// element carrying its own `act` is refused rather than merged — two nestings
/// of the same chain would be two different delegation histories.
// fuzz-target: access_token_claims
fn actor_claim(chain: &[Value]) -> Result<Option<Value>, IssuanceError> {
    if chain.is_empty() {
        return Ok(None);
    }
    if chain.len() > AccessToken::MAX_ACTORS {
        return Err(IssuanceError::ActorChain);
    }
    let mut nested: Option<Value> = None;
    for actor in chain.iter().rev() {
        let Value::Object(members) = actor else {
            return Err(IssuanceError::ActorChain);
        };
        if members.contains_key("act") {
            return Err(IssuanceError::ActorChain);
        }
        let mut members = members.clone();
        if let Some(inner) = nested {
            members.insert("act".to_owned(), inner);
        }
        nested = Some(Value::Object(members));
    }
    Ok(nested)
}

#[cfg(test)]
mod tests {
    use super::*;
    use asterius_domain::{ClientId, GrantId, SubjectId, TenantId};
    use serde_json::json;

    const JKT: &str = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I";
    const X5T: &str = "bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2";

    fn issuer() -> Issuer {
        Issuer::parse("https://as.example/t/demo").expect("an issuer")
    }

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("a valid instant")
    }

    fn grant() -> Grant {
        let mut grant = Grant::new(TenantId::new("demo"), ClientId::new("billing"), now());
        grant.id = GrantId::new("2c1d4b1e-0000-4000-8000-000000000001");
        grant.subject = Some(SubjectId::new("SUBJECT-1"));
        grant.scopes = ["accounts", "openid"]
            .into_iter()
            .map(ToOwned::to_owned)
            .collect();
        grant.resources = ["https://api.example/v1".to_owned()].into_iter().collect();
        grant
    }

    fn dpop() -> Confirmation {
        Confirmation::dpop(&Kid::new(JKT)).expect("a thumbprint")
    }

    fn token(grant: &Grant, claimed: &ClaimedGrant) -> Result<Value, IssuanceError> {
        AccessToken::new(
            &issuer(),
            grant,
            claimed,
            Audience::of_grant(grant).expect("the grant names a resource"),
            dpop(),
            JwtId::from_bytes([7; 16]),
            now(),
        )
        .build()
        .map(UnsignedToken::into_claims)
    }

    fn built() -> Value {
        let grant = grant();
        let claimed = grant.claim(now()).expect("a live grant");
        token(&grant, &claimed).expect("a buildable token")
    }

    /// RFC 9068 §2.2 makes `sub` REQUIRED, and §2.2 also says an access token
    /// from a grant with no resource owner puts the `client_id` there instead.
    /// An empty subject is neither: it is not absent, so it must not take the
    /// client-credentials fork and be minted as the client's own token; and it
    /// is not a subject, because every empty subject compares equal to every
    /// other. Found by `cargo fuzz run access_token_claims` (`ast-a05.17`).
    #[test]
    fn a_present_but_empty_subject_is_refused_rather_than_minted() {
        let mut grant = grant();
        grant.subject = Some(SubjectId::new(""));
        let claimed = grant.claim(now()).expect("a live grant");
        assert!(
            matches!(token(&grant, &claimed), Err(IssuanceError::EmptySubject)),
            "an empty subject was accepted"
        );
    }

    /// The other side of the fork, so the guard above cannot be "refuse every
    /// grant without a resource owner" by accident.
    #[test]
    fn an_absent_subject_still_falls_back_to_the_client() {
        let mut grant = grant();
        grant.subject = None;
        let claimed = grant.claim(now()).expect("a live grant");
        let claims = token(&grant, &claimed).expect("a buildable token");
        assert_eq!(claims["sub"], "billing");
    }

    /// The escalation `GrantRecord::validate` exists to stop, checked again at
    /// the join that would actually cause it. `scope` is space-delimited
    /// (RFC 9068 §2.2.3), so a stored scope containing a space arrives at the
    /// resource server as two scopes. Found by `cargo fuzz` (`ast-a05.17`),
    /// which builds a `Grant` in memory and so never passes the store's check.
    #[test]
    fn a_scope_that_would_split_in_the_claim_is_refused() {
        for bad in ["read write", "read\u{0}", "quoted\"scope", "back\\slash"] {
            let mut grant = grant();
            grant.scopes = [bad.to_owned()].into_iter().collect();
            let claimed = grant.claim(now()).expect("a live grant");
            assert!(
                matches!(token(&grant, &claimed), Err(IssuanceError::Scope)),
                "accepted a scope that would split: {bad:?}"
            );
        }
    }

    /// RFC 8707 §2: the authorization server may narrow what a token for a
    /// resource carries. The `scope` claim is then what that resource
    /// understands, not what the grant holds.
    #[test]
    fn a_scope_restriction_narrows_the_claim_to_what_the_resource_allows() {
        let grant = grant();
        let claimed = grant.claim(now()).expect("a live grant");
        let claims = AccessToken::new(
            &issuer(),
            &grant,
            &claimed,
            Audience::of_grant(&grant).expect("a resource"),
            dpop(),
            JwtId::from_bytes([7; 16]),
            now(),
        )
        .restricted_to_scopes(["accounts".to_owned()].into_iter().collect())
        .build()
        .expect("a buildable token")
        .into_claims();
        assert_eq!(claims["scope"], "accounts");
    }

    /// A restriction narrows and never widens: the grant is the ceiling, so a
    /// resource server's scope list cannot mint authority nobody consented to.
    #[test]
    fn a_scope_restriction_cannot_add_a_scope_the_grant_does_not_carry() {
        let grant = grant();
        let claimed = grant.claim(now()).expect("a live grant");
        let claims = AccessToken::new(
            &issuer(),
            &grant,
            &claimed,
            Audience::of_grant(&grant).expect("a resource"),
            dpop(),
            JwtId::from_bytes([7; 16]),
            now(),
        )
        .restricted_to_scopes(
            ["accounts".to_owned(), "payments".to_owned()]
                .into_iter()
                .collect(),
        )
        .build()
        .expect("a buildable token")
        .into_claims();
        assert_eq!(claims["scope"], "accounts");
    }

    /// A resource server that understands none of the grant's scopes gets a
    /// token with no `scope` at all — which authorises nothing, and is not the
    /// same as a token that omits the claim to mean "everything".
    #[test]
    fn a_restriction_that_leaves_nothing_omits_the_scope_claim() {
        let grant = grant();
        let claimed = grant.claim(now()).expect("a live grant");
        let claims = AccessToken::new(
            &issuer(),
            &grant,
            &claimed,
            Audience::of_grant(&grant).expect("a resource"),
            dpop(),
            JwtId::from_bytes([7; 16]),
            now(),
        )
        .restricted_to_scopes(BTreeSet::new())
        .build()
        .expect("a buildable token")
        .into_claims();
        assert!(claims.get("scope").is_none(), "{claims}");
    }

    // --- RFC 9068 §2.1 and §2.2: the shape -------------------------------

    #[test]
    fn an_access_token_is_typed_at_jwt_and_never_anything_else() {
        let grant = grant();
        let claimed = grant.claim(now()).expect("a live grant");
        let unsigned = AccessToken::new(
            &issuer(),
            &grant,
            &claimed,
            Audience::of_grant(&grant).expect("a resource"),
            dpop(),
            JwtId::from_bytes([1; 16]),
            now(),
        )
        .build()
        .expect("a buildable token");
        assert_eq!(unsigned.typ(), "at+jwt");
        assert_eq!(unsigned.required_algorithm(), None);
    }

    #[test]
    fn every_claim_rfc_9068_makes_required_is_present() {
        let claims = built();
        for required in ["iss", "exp", "aud", "sub", "client_id", "iat", "jti"] {
            assert!(
                claims.get(required).is_some(),
                "RFC 9068 §2.2 requires {required}"
            );
        }
        assert_eq!(claims["iss"], json!("https://as.example/t/demo"));
        assert_eq!(claims["sub"], json!("SUBJECT-1"));
        assert_eq!(claims["client_id"], json!("billing"));
        assert_eq!(claims["iat"], json!(1_700_000_000));
        assert_eq!(claims["exp"], json!(1_700_000_300));
        assert_eq!(claims["jti"], json!("BwcHBwcHBwcHBwcHBwcHBw"));
        assert_eq!(claims["scope"], json!("accounts openid"));
    }

    /// The one claim FAPI 2.0 SP §5.3.2.1 item 4 makes non-negotiable. There is
    /// no test for "a token without `cnf`" because there is no way to write the
    /// call: [`AccessToken::new`] takes a [`Confirmation`] by value.
    #[test]
    fn an_access_token_always_carries_cnf() {
        assert_eq!(built()["cnf"], json!({ "jkt": JKT }));
    }

    #[test]
    fn a_certificate_bound_token_carries_x5t_s256() {
        let grant = grant();
        let claimed = grant.claim(now()).expect("a live grant");
        let claims = AccessToken::new(
            &issuer(),
            &grant,
            &claimed,
            Audience::of_grant(&grant).expect("a resource"),
            Confirmation::certificate(X5T).expect("a thumbprint"),
            JwtId::from_bytes([2; 16]),
            now(),
        )
        .build()
        .expect("a buildable token")
        .into_claims();
        assert_eq!(claims["cnf"], json!({ "x5t#S256": X5T }));
    }

    #[test]
    fn a_confirmation_reports_the_binding_it_expresses() {
        assert_eq!(dpop().binding(), TokenBinding::Dpop);
        assert_eq!(dpop().claim(), json!({ "jkt": JKT }));
        assert_eq!(
            Confirmation::certificate(X5T)
                .expect("a thumbprint")
                .binding(),
            TokenBinding::Certificate
        );
    }

    /// A `cnf` holding a thumbprint of the wrong shape is a binding no resource
    /// server matches, which behaves like no binding at all.
    #[test]
    fn a_thumbprint_that_is_not_a_base64url_sha_256_is_refused() {
        for bad in [
            "",
            "short",
            // Padded.
            "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I=",
            // Standard-alphabet base64: `+` and `/` are not base64url.
            "0ZcOCORZNYy+DWpqq30jZyJGHTN0d2HglBV3uiguA4I",
            // Hex, which is the other way a thumbprint gets written down.
            "d1970c0e4459358cbe0d6a6aab7d2367224 61d33747761e0941577ba282e0",
            &"a".repeat(44),
            &"a".repeat(42),
        ] {
            assert_eq!(
                Confirmation::certificate(bad),
                Err(IssuanceError::Thumbprint),
                "accepted {bad:?}"
            );
            assert_eq!(
                Confirmation::dpop(&Kid::new(bad)),
                Err(IssuanceError::Thumbprint)
            );
        }
    }

    // --- RFC 9068 §3 and §5: the audience --------------------------------

    #[test]
    fn one_resource_is_a_string_and_several_are_an_array() {
        assert_eq!(
            Audience::new(["https://api.example/v1"])
                .expect("a resource")
                .claim(),
            json!("https://api.example/v1")
        );
        assert_eq!(
            Audience::new(["https://b.example/", "https://a.example/"])
                .expect("two resources")
                .claim(),
            json!(["https://a.example/", "https://b.example/"])
        );
    }

    #[test]
    fn an_audience_that_is_not_a_resource_identifier_is_refused() {
        for bad in [
            "",
            "/v1",
            "api.example",
            "https://api.example/v1#fragment",
            "mailto:someone@example.com",
        ] {
            assert_eq!(
                Audience::new([bad]),
                Err(IssuanceError::Audience),
                "accepted {bad:?}"
            );
        }
        assert_eq!(
            Audience::new(Vec::<String>::new()),
            Err(IssuanceError::Audience)
        );
        let too_many: Vec<String> = (0..=Audience::MAX)
            .map(|n| format!("https://api{n}.example/"))
            .collect();
        assert_eq!(Audience::new(too_many), Err(IssuanceError::Audience));
    }

    #[test]
    fn a_grant_with_no_resource_has_no_audience_of_its_own() {
        let mut grant = grant();
        grant.resources.clear();
        assert_eq!(Audience::of_grant(&grant), None);
    }

    /// RFC 9068 §3 and §5. The client is not a resource, and a token audienced
    /// at its own client is the cross-JWT confusion `at+jwt` exists to prevent.
    #[test]
    fn an_audience_naming_the_client_is_refused() {
        let mut grant = grant();
        grant.client = ClientId::new("https://api.example/v1");
        let claimed = grant.claim(now()).expect("a live grant");
        assert_eq!(
            token(&grant, &claimed),
            Err(IssuanceError::AudienceIsTheClient)
        );
    }

    // --- The grant is the authority --------------------------------------

    #[test]
    fn a_claim_on_another_grant_cannot_mint_this_ones_token() {
        let grant = grant();
        let mut other = grant.clone();
        other.id = GrantId::new("2c1d4b1e-0000-4000-8000-000000000002");
        let claimed = other.claim(now()).expect("a live grant");
        assert_eq!(token(&grant, &claimed), Err(IssuanceError::GrantMismatch));
    }

    #[test]
    fn a_claim_for_another_client_cannot_mint_this_ones_token() {
        let grant = grant();
        let mut other = grant.clone();
        other.client = ClientId::new("someone-else");
        let claimed = other.claim(now()).expect("a live grant");
        assert_eq!(token(&grant, &claimed), Err(IssuanceError::GrantMismatch));
    }

    #[test]
    fn a_claim_from_another_tenant_cannot_mint_this_ones_token() {
        let grant = grant();
        let mut other = grant.clone();
        other.tenant = TenantId::new("other");
        let claimed = other.claim(now()).expect("a live grant");
        assert_eq!(token(&grant, &claimed), Err(IssuanceError::GrantMismatch));
    }

    /// RFC 9068 §2.2's second `sub` arm: a client credentials grant has no
    /// resource owner, so the subject is the client.
    #[test]
    fn a_grant_with_no_resource_owner_gets_the_client_as_its_subject() {
        let mut grant = grant();
        grant.subject = None;
        let claimed = grant.claim(now()).expect("a live grant");
        assert_eq!(
            token(&grant, &claimed).expect("a buildable token")["sub"],
            json!("billing")
        );
    }

    // --- Lifetime ---------------------------------------------------------

    #[test]
    fn the_default_lifetime_is_five_minutes_and_the_cap_is_fifteen() {
        let grant = grant();
        let claimed = grant.claim(now()).expect("a live grant");
        let at_cap = AccessToken::new(
            &issuer(),
            &grant,
            &claimed,
            Audience::of_grant(&grant).expect("a resource"),
            dpop(),
            JwtId::from_bytes([3; 16]),
            now(),
        )
        .for_lifetime(AccessToken::MAX_LIFETIME)
        .build()
        .expect("a buildable token")
        .into_claims();
        assert_eq!(at_cap["exp"], json!(1_700_000_900));
        assert_eq!(built()["exp"], json!(1_700_000_300));
    }

    #[test]
    fn a_lifetime_past_the_cap_is_refused() {
        let grant = grant();
        let claimed = grant.claim(now()).expect("a live grant");
        for bad in [
            Duration::ZERO,
            Duration::seconds(-1),
            AccessToken::MAX_LIFETIME + Duration::seconds(1),
            Duration::hours(24),
        ] {
            assert_eq!(
                AccessToken::new(
                    &issuer(),
                    &grant,
                    &claimed,
                    Audience::of_grant(&grant).expect("a resource"),
                    dpop(),
                    JwtId::from_bytes([4; 16]),
                    now(),
                )
                .for_lifetime(bad)
                .build(),
                Err(IssuanceError::Lifetime),
                "accepted {bad}"
            );
        }
    }

    // --- What must never appear -------------------------------------------

    /// RFC 9068 §2.1's whole reason for existing, from the other side: an
    /// access token must not be mistakable for an ID token, and the surest way
    /// is for the ID-token-only claims to be unwritable here. There is no
    /// builder input that produces either, so this asserts the absence rather
    /// than a filter.
    #[test]
    fn id_token_only_claims_never_appear() {
        let mut grant = grant();
        grant.authorization_details = vec![json!({ "type": "payment_initiation" })];
        let claimed = grant.claim(now()).expect("a live grant");
        let claims = AccessToken::new(
            &issuer(),
            &grant,
            &claimed,
            Audience::of_grant(&grant).expect("a resource"),
            dpop(),
            JwtId::from_bytes([5; 16]),
            now(),
        )
        .authenticated_by(Authentication {
            authenticated_at: now(),
            acr: Some("urn:example:loa:2".to_owned()),
            amr: vec!["pwd".to_owned(), "otp".to_owned()],
        })
        .with_grant_id()
        .build()
        .expect("a buildable token")
        .into_claims();

        for forbidden in ["nonce", "at_hash", "c_hash", "s_hash", "azp", "sid"] {
            assert!(
                claims.get(forbidden).is_none(),
                "an access token carried the ID token claim {forbidden}"
            );
        }
        assert_eq!(claims["acr"], json!("urn:example:loa:2"));
        assert_eq!(claims["amr"], json!(["pwd", "otp"]));
        assert_eq!(claims["auth_time"], json!(1_700_000_000));
        assert_eq!(
            claims["authorization_details"],
            json!([{ "type": "payment_initiation" }])
        );
        assert_eq!(
            claims["grant_id"],
            json!("2c1d4b1e-0000-4000-8000-000000000001")
        );
    }

    #[test]
    fn the_grant_id_claim_is_off_unless_a_tenant_asks_for_it() {
        assert!(built().get("grant_id").is_none());
    }

    #[test]
    fn a_grant_with_no_scopes_carries_no_scope_claim() {
        let mut grant = grant();
        grant.scopes.clear();
        let claimed = grant.claim(now()).expect("a live grant");
        assert!(
            token(&grant, &claimed)
                .expect("a buildable token")
                .get("scope")
                .is_none()
        );
    }

    // --- RFC 8693 §4.1: the act chain -------------------------------------

    #[test]
    fn an_actor_chain_nests_with_the_current_actor_outermost() {
        assert_eq!(
            actor_claim(&[
                json!({ "sub": "admin@example.com" }),
                json!({ "sub": "service@example.com" }),
            ])
            .expect("a well-formed chain"),
            Some(json!({
                "sub": "admin@example.com",
                "act": { "sub": "service@example.com" }
            }))
        );
        assert_eq!(actor_claim(&[]).expect("no chain"), None);
    }

    #[test]
    fn an_actor_chain_that_is_not_objects_is_refused() {
        for bad in [json!("admin"), json!(1), json!(null), json!([])] {
            assert_eq!(actor_claim(&[bad]), Err(IssuanceError::ActorChain));
        }
        // An element that already nests would give the token two delegation
        // histories, and only one of them would be the one that was authorised.
        assert_eq!(
            actor_claim(&[json!({ "sub": "a", "act": { "sub": "b" } })]),
            Err(IssuanceError::ActorChain)
        );
        let too_deep: Vec<Value> = (0..=AccessToken::MAX_ACTORS)
            .map(|n| json!({ "sub": n.to_string() }))
            .collect();
        assert_eq!(actor_claim(&too_deep), Err(IssuanceError::ActorChain));
    }

    // --- The size guard ---------------------------------------------------

    #[test]
    fn a_claims_set_over_the_guard_is_refused() {
        let mut grant = grant();
        grant.authorization_details =
            vec![json!({ "type": "x".repeat(MAX_ACCESS_TOKEN_CLAIMS_BYTES) })];
        let claimed = grant.claim(now()).expect("a live grant");
        assert!(matches!(
            token(&grant, &claimed),
            Err(IssuanceError::TooLarge { .. })
        ));
    }

    /// A revoked grant cannot produce a `ClaimedGrant`, so it cannot reach this
    /// module at all. The assertion is here rather than only in the grant tests
    /// because it is the property this builder relies on for its own safety.
    #[test]
    fn a_revoked_grant_cannot_be_claimed_at_all() {
        let mut grant = grant();
        grant.revoked_at = Some(now());
        grant.revocation_reason = Some(asterius_domain::RevocationReason::UserRevoked);
        assert!(grant.claim(now()).is_err());
    }
}
