//! What every grant that mints tokens for a *user* has to do identically.
//!
//! Two grants reach this: `authorization_code` (`ast-a05.2`) and
//! `refresh_token` (`ast-a05.5`). They differ in what they check before they
//! mint — a code checks PKCE and a `redirect_uri`, a refresh token checks a
//! digest and a scope subset — and they agree exactly on what a minted token
//! says. That agreement is what lives here.
//!
//! It is worth sharing rather than writing twice because each of the four
//! functions below is a place where writing it twice would eventually mean two
//! different answers, and in each case the difference would be a security
//! statement:
//!
//! * `auth_time`, `acr` and `amr` are read from the session the *grant* was
//!   made in, never invented. A refresh happening six weeks later still says
//!   when the person actually authenticated, because a relying party uses that
//!   for step-up decisions.
//! * `sid` is the session's `public_sid` and never its lookup digest, which is
//!   rewritten on every rotation (`ast-o4u.5`).
//! * The claims in an ID token come from the grant and the user row, never
//!   from the request that asked for them.
//! * A missing session or a missing user is a server-side inconsistency and is
//!   reported as one, rather than papered over with a token that asserts less
//!   than it should about somebody this server can no longer describe.

use asterius_domain::keys::Signer;
use asterius_domain::ports::SessionRepository;
use asterius_domain::{Client, DomainError, Grant, Tenant};
use asterius_oidc::tokens::access::{Audience, Authentication};
use asterius_oidc::tokens::id_token::IdToken;
use asterius_store_pg::PgUserRepository;

/// What the session a grant was made in contributes to its tokens.
///
/// The two travel together because they come from one row and mean nothing
/// apart: `auth_time`, `acr` and `amr` say *when and how* the person
/// authenticated, and `sid` names the session they did it in.
#[derive(Debug)]
pub struct SessionFacts {
    /// `auth_time`, `acr` and `amr`.
    pub authentication: Authentication,
    /// The session's public identifier, never its lookup digest.
    pub sid: String,
}

/// `auth_time`, `acr` and `amr`, from the session the grant was made in.
///
/// Not optional, and not defaulted. OIDC Core §2 makes `auth_time` a statement
/// about when the user actually authenticated; inventing one from the grant's
/// own timestamps would produce a claim a relying party uses for step-up
/// decisions and that this server cannot stand behind. A grant whose session
/// has gone is a server-side inconsistency, so it is reported as one rather
/// than papered over.
///
/// # Errors
///
/// [`DomainError::Invalid`] when the grant names no session or the session is
/// gone, and a storage error when the session store could not be read.
pub async fn session_facts(
    sessions: &dyn SessionRepository,
    grant: &Grant,
) -> Result<SessionFacts, DomainError> {
    let digest = grant
        .session
        .as_ref()
        .ok_or_else(|| DomainError::invalid("grant", "a user-facing grant names no session"))?;
    let session = sessions.find(digest.as_str()).await?.ok_or_else(|| {
        DomainError::invalid(
            "session",
            "the session this grant was made in no longer exists",
        )
    })?;

    Ok(SessionFacts {
        authentication: Authentication {
            authenticated_at: session.authenticated_at,
            acr: session.acr.clone(),
            amr: session
                .amr
                .iter()
                .map(|method| method.as_str().to_owned())
                .collect(),
        },
        // Not `id_digest`: that is the lookup key and it is rewritten on every
        // rotation. See `Session::public_sid` (`ast-o4u.5`).
        sid: session.public_sid.clone(),
    })
}

/// The claims this grant releases into its ID token.
///
/// Read from the grant and from the user row, and from nothing else. The
/// request is not consulted: it says what a client asked for, and a consent
/// screen — or, at a refresh, weeks — separate that from what this token may
/// carry.
///
/// A grant with no user, or whose user is gone, is a server-side inconsistency
/// and is reported as one, the same treatment [`session_facts`] gives a
/// vanished session. Releasing nothing instead would mint an authentication
/// assertion about somebody this server can no longer describe.
///
/// # Errors
///
/// [`DomainError::Invalid`] when the grant names no user, the user is gone, or
/// the stored `claims` request no longer parses; a storage error otherwise.
pub async fn released_claims(
    users: &PgUserRepository,
    grant: &Grant,
) -> Result<serde_json::Map<String, serde_json::Value>, DomainError> {
    let id = grant
        .user
        .ok_or_else(|| DomainError::invalid("grant", "a user-facing grant names no user"))?;
    let user = users.find(id).await?.ok_or_else(|| {
        DomainError::invalid("user", "the user this grant was made for no longer exists")
    })?;
    let resolved = asterius_oidc::claims::resolve_for_grant(&user, grant)
        // The request was validated at PAR and re-serialised canonically onto
        // the grant, so a stored one that no longer parses is a damaged row
        // rather than a bad request.
        .map_err(|error| DomainError::invalid("claims", error.to_string()))?;
    Ok(resolved.id_token)
}

/// RFC 8707 §2.2's error code, for whichever grant is refusing a `resource`.
pub const INVALID_TARGET: &str = asterius_domain::InvalidTarget::CODE;

/// What a client is told when [`INVALID_TARGET`] applies.
///
/// One description for four facts — the value is not a resource indicator, this
/// tenant does not register it, the authorization request did not authorize it,
/// or there is no default audience to fall back on. Telling them apart would
/// let a client enumerate a tenant's resource servers one token request at a
/// time, and none of the four is actionable in a different way: register the
/// resource, or ask for one you were granted.
pub const TARGET_REFUSED: &str =
    "the resource parameter does not name a resource this token may be issued for";

/// What the `resource` parameters of a request decided about a token.
///
/// The two travel together because one decides the other: `audience` is the
/// `aud` claim (RFC 9068 §3), and `scopes` is what those resource servers
/// understand, which is what the `scope` claim may say (RFC 8707 §2).
#[derive(Debug)]
pub struct Targeting {
    /// The `aud` of the access token.
    pub audience: Audience,
    /// The grant's scopes, narrowed to what every named resource server
    /// understands.
    pub scopes: std::collections::BTreeSet<String>,
}

/// Why a request could not be turned into an audience.
#[derive(Debug)]
pub enum TargetingError {
    /// RFC 8707 §2.2: the `resource` values are not ones this client may be
    /// issued a token for — unregistered, outside what the authorization
    /// request authorized, or absent when the client has no default audience
    /// at all.
    InvalidTarget,
    /// The registry could not be read. Not the same answer as "you named
    /// something unregistered": an outage must not look like a configuration
    /// change.
    Storage(DomainError),
}

impl From<DomainError> for TargetingError {
    fn from(error: DomainError) -> Self {
        Self::Storage(error)
    }
}

/// Decides the `aud` and the `scope` of an access token (RFC 8707, RFC 9068
/// §3).
///
/// `requested` is the `resource` parameters of the *token* request, and the
/// grant carries what the *authorization* request settled on. The registry
/// decides what exists; [`asterius_domain::ResourceRegistry::targets`] holds
/// the rules and this function holds the two inputs it cannot know: what this
/// tenant registered, and what this client's default audiences are.
///
/// # The default audience, and why it is the client's before it is the
/// tenant's
///
/// A client that names no `resource` still gets an audience-bound token,
/// because RFC 9068 §2.2 makes `aud` REQUIRED and §3 asks the AS for "a default
/// resource indicator". This server takes the narrowest default available: the
/// client's own registered allow-list when it has one — a client allowed one
/// API gets tokens for that API and nothing else — and the tenant's
/// `default_resource` only for a client with no allow-list at all, which is the
/// audience such a client's tokens have always carried.
///
/// Either way the default is filtered through the registry, so a resource
/// server an operator has withdrawn stops being a default audience rather than
/// quietly continuing to receive tokens. A client with no allow-list under a
/// tenant whose default resource is not registered has no audience at all, and
/// gets `invalid_target` instead of a token nobody can safely accept.
///
/// # Errors
///
/// [`TargetingError::InvalidTarget`] for a request no audience can be derived
/// from, and [`TargetingError::Storage`] if the registry cannot be read.
pub async fn targeting(
    resource_servers: &dyn asterius_domain::ResourceServerRepository,
    tenant: &Tenant,
    client: &Client,
    grant: &Grant,
    requested: &std::collections::BTreeSet<String>,
) -> Result<Targeting, TargetingError> {
    let registry = asterius_domain::ResourceRegistry::new(resource_servers.list().await?);

    let defaults: std::collections::BTreeSet<String> = if client.registration.resources.is_empty() {
        [tenant.default_resource.clone()].into_iter().collect()
    } else {
        client.registration.resources.clone()
    };

    let targets = registry
        .targets(requested, &grant.resources, &defaults)
        .map_err(|_| TargetingError::InvalidTarget)?;
    let scopes = registry.permitted_scopes(&targets, &grant.scopes);
    let audience = Audience::new(&targets).map_err(|_| TargetingError::InvalidTarget)?;

    Ok(Targeting { audience, scopes })
}

/// What one issuance contributes to its ID token.
///
/// A struct rather than five more parameters, because four of the five are
/// values the issuance computed a moment earlier and the fifth — `released` —
/// is the one a reader has to be able to see is *the grant's*. A signature
/// long enough that its arguments are matched by position is a signature in
/// which the request's claims could be passed instead.
#[derive(Debug)]
pub struct IdTokenParts<'a> {
    /// The authority the tokens are minted from.
    pub claimed: &'a asterius_domain::ClaimedGrant,
    /// `auth_time`, `acr`, `amr` and `sid`.
    pub session: &'a SessionFacts,
    /// The signed access token, for OIDC Core §3.1.3.6's `at_hash`.
    pub access_token: &'a str,
    /// `nonce`, echoed byte-exact when the authorization request carried one.
    ///
    /// Always `None` at a refresh: OIDC Core §12.2 lists `nonce` among the
    /// claims an ID token returned from a refresh "MAY" omit, and there is no
    /// new authorization request to echo one from. Echoing the original would
    /// be worse than omitting it — a client comparing `nonce` against a value
    /// it generated for a browser round trip that happened weeks ago would be
    /// checking a replay defence against a request it is not making.
    pub nonce: Option<&'a str>,
    /// The claims the grant covers, from [`released_claims`].
    pub released: serde_json::Map<String, serde_json::Value>,
}

/// Builds and signs an ID token.
///
/// The access token is signed first and handed in whole, because OIDC Core
/// §3.1.3.6's `at_hash` is over the *signed* token and is computed under the
/// ID token's own `alg`. The algorithm is the client's registered
/// `id_token_signed_response_alg`, carried into the signer rather than left to
/// whichever key it would otherwise reach for — a tenant with no key of that
/// algorithm refuses (`ast-a05.12`, `ast-a05.14`).
///
/// `sid` is the session's `public_sid`, never its `id_digest`: the digest is
/// the lookup key the session store takes and it is rewritten on every
/// rotation, while OIDC Back-Channel Logout 1.0 §2.4 needs a value a relying
/// party can still recognise afterwards (`ast-o4u.5`).
///
/// # Errors
///
/// [`DomainError::Invalid`] when the claims will not assemble,
/// [`DomainError::NoSigningKey`] when the tenant holds no key of the client's
/// registered algorithm, and a storage error otherwise.
pub async fn sign_id_token(
    signer: &dyn Signer,
    tenant: &Tenant,
    client: &Client,
    parts: IdTokenParts<'_>,
    now: time::OffsetDateTime,
) -> Result<String, DomainError> {
    let IdTokenParts {
        claimed,
        session,
        access_token,
        nonce,
        released,
    } = parts;
    let mut builder = IdToken::new(
        &tenant.issuer,
        claimed,
        client.registration.id_token_signed_response_alg,
        session.authentication.clone(),
        access_token,
        now,
    );
    // OIDC Core §3.1.3.7 item 11: echoed byte-exact, and only when the
    // authorization request carried one.
    if let Some(nonce) = nonce {
        builder = builder.with_nonce(nonce);
    }
    builder = builder.for_session(
        asterius_oidc::tokens::id_token::Session::new(&asterius_domain::SessionId::new(
            session.sid.clone(),
        ))
        .map_err(|e| DomainError::invalid("sid", e.to_string()))?,
    );
    // `releasing` takes a plain map, so `IdToken::build` re-checks it against
    // `ClaimName::SERVER_ISSUED` rather than trusting that it came from
    // `claims::resolve`.
    builder = builder.releasing(released);
    let unsigned = builder
        .build()
        .map_err(|e| DomainError::invalid("id_token", e.to_string()))?;

    let token = signer
        .sign(
            &tenant.id,
            unsigned.required_algorithm(),
            unsigned.typ(),
            unsigned.claims(),
        )
        .await?;
    Ok(token.as_str().to_owned())
}
