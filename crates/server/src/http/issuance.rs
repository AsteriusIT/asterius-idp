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
//!   made in — or, once that row is gone, from the copy the grant took of it
//!   (`ast-dlk`) — and never invented. A refresh happening six weeks later
//!   still says when the person actually authenticated, because a relying
//!   party uses that for step-up decisions.
//! * `sid` is the session's `public_sid` and never its lookup digest, which is
//!   rewritten on every rotation (`ast-o4u.5`), and it is omitted rather than
//!   guessed at when there is no session left to name.
//! * The claims in an ID token come from the grant and the user row, never
//!   from the request that asked for them.
//! * A missing user — or a missing session with no recorded authentication to
//!   fall back on — is a server-side inconsistency and is reported as one,
//!   rather than papered over with a token that asserts less than it should
//!   about somebody this server can no longer describe.

use asterius_domain::entities::client::TokenBinding;
use asterius_domain::keys::Signer;
use asterius_domain::ports::SessionRepository;
use asterius_domain::{Client, DomainError, Grant, Kid, Tenant};
use asterius_oidc::mtls::ClientCertificate;
use asterius_oidc::tokens::access::{Audience, Authentication, Confirmation};
use asterius_oidc::tokens::id_token::IdToken;
use asterius_store_pg::{PgUserRepository, RefreshBinding};

// ---------------------------------------------------------------------------
// Sender constraining (RFC 9449 §6, RFC 8705 §3)
// ---------------------------------------------------------------------------

/// What this request proved possession of.
///
/// Both halves are facts about *this* request that the endpoint edge resolved
/// once: the DPoP key a verified proof presented, and the certificate a
/// trusted proxy forwarded (RFC 8705 §2, `crate::mtls::from_proxy_header`).
/// The client's registered `TokenBinding` then decides which of them the token
/// is bound to, so that "how is this client's token constrained" is answered
/// from the registration and never from what the caller happened to send.
///
/// This type is the reason all three grants agree. Each of them mints under
/// [`Self::confirmation`], so a grant added later cannot arrive at a different
/// reading of the same registration — and none of them can arrive at no
/// reading at all, because [`Confirmation`] has no unbound value.
#[derive(Debug, Clone, Copy)]
pub struct SenderConstraint<'a> {
    /// The thumbprint of the DPoP proof presented with this request, if one
    /// verified (RFC 9449 §4.3).
    pub proof_key: Option<&'a Kid>,
    /// The client certificate this request arrived with, if the deployment saw
    /// one from a source it trusts (RFC 8705 §2).
    pub certificate: Option<&'a ClientCertificate>,
}

/// RFC 6749 §5.1's `token_type`, for a token bound the way this client's are.
///
/// `DPoP` for a DPoP-bound token (RFC 9449 §5: it "is not a bearer token", and
/// a resource server must refuse one sent as though it were), `Bearer` for a
/// certificate-bound one (RFC 8705 §3.1, whose example response carries
/// `"token_type":"Bearer"` — §3 binds the token without defining a scheme for
/// it).
///
/// Read from the registration rather than from the `cnf` the handler just
/// built, because they are the same decision and the registration is the one
/// that survives into the next request.
#[must_use]
pub const fn token_type(client: &Client) -> &'static str {
    match client.registration.token_binding {
        TokenBinding::Dpop => "DPoP",
        TokenBinding::Certificate => "Bearer",
    }
}

/// Why a token request could not be bound to anything.
#[derive(Debug)]
pub enum ConstraintError {
    /// A DPoP-bound client sent no proof. FAPI 2.0 SP §5.3.2.1 item 5 admits
    /// no token for it that would not need one — including for a client that
    /// authenticated with a certificate but did not register certificate
    /// binding.
    ProofRequired,
    /// A certificate-bound client presented no certificate this server
    /// believes in (RFC 8705 §3): there is nothing to put in `x5t#S256`.
    CertificateRequired,
    /// A certificate-bound client also sent a DPoP proof.
    ///
    /// RFC 8705 §3.1 and RFC 9449 §6.1 each define one `cnf` member, and a
    /// client registers one binding method: a request offering both is asking
    /// for a token whose binding this server would have to choose. It is
    /// `invalid_request` rather than `invalid_grant` — the credential is fine,
    /// the request is not — and it is what a client that has half-migrated
    /// between the two methods sees.
    TwoBindingsOffered,
    /// The thumbprint would not go into a `cnf`. This deployment's fault:
    /// both inputs are values this server computed.
    Unusable(DomainError),
}

impl SenderConstraint<'_> {
    /// The `cnf` this client's access token carries.
    ///
    /// # Errors
    ///
    /// [`ConstraintError`], which the calling grant renders in its own error
    /// shape: the three client-facing variants are statements about the
    /// request, and [`ConstraintError::Unusable`] is one about this server.
    pub fn confirmation(&self, client: &Client) -> Result<Confirmation, ConstraintError> {
        match client.registration.token_binding {
            TokenBinding::Dpop => {
                let jkt = self.proof_key.ok_or(ConstraintError::ProofRequired)?;
                Confirmation::dpop(jkt).map_err(|error| {
                    ConstraintError::Unusable(DomainError::invalid("cnf", error.to_string()))
                })
            }
            TokenBinding::Certificate => {
                if self.proof_key.is_some() {
                    return Err(ConstraintError::TwoBindingsOffered);
                }
                let certificate = self
                    .certificate
                    .ok_or(ConstraintError::CertificateRequired)?;
                Confirmation::certificate(&certificate.thumbprint_b64url()).map_err(|error| {
                    ConstraintError::Unusable(DomainError::invalid("cnf", error.to_string()))
                })
            }
        }
    }

    /// What a refresh token minted beside that access token is bound to.
    ///
    /// The same decision, in the shape the row takes: a grant whose access
    /// tokens are certificate-bound has certificate-bound refresh tokens, so
    /// that neither credential is redeemable by a caller who cannot present
    /// what the other one needs.
    ///
    /// # Errors
    ///
    /// [`ConstraintError`], for the reasons [`Self::confirmation`] gives.
    pub fn refresh_binding(&self, client: &Client) -> Result<RefreshBinding, ConstraintError> {
        match client.registration.token_binding {
            TokenBinding::Dpop => {
                let jkt = self.proof_key.ok_or(ConstraintError::ProofRequired)?;
                Ok(RefreshBinding::Dpop(jkt.as_str().to_owned()))
            }
            TokenBinding::Certificate => {
                if self.proof_key.is_some() {
                    return Err(ConstraintError::TwoBindingsOffered);
                }
                let certificate = self
                    .certificate
                    .ok_or(ConstraintError::CertificateRequired)?;
                Ok(RefreshBinding::Certificate(certificate.thumbprint()))
            }
        }
    }

    /// Whether the caller presented the certificate `thumbprint` names.
    ///
    /// RFC 8705 §3's check, at the two places a certificate-bound credential
    /// comes back: redeeming a refresh token, and — through
    /// `crate::http::userinfo` — presenting an access token. Absent
    /// certificate is `false`, because "no certificate" and "the wrong
    /// certificate" are the same answer to "may this caller use this
    /// credential".
    #[must_use]
    pub fn presents(&self, thumbprint: &[u8; 32]) -> bool {
        self.certificate
            .is_some_and(|certificate| certificate.thumbprint() == *thumbprint)
    }
}

/// What the session a grant was made in contributes to its tokens.
///
/// The two travel together because they come from one row and mean nothing
/// apart: `auth_time`, `acr` and `amr` say *when and how* the person
/// authenticated, and `sid` names the session they did it in.
#[derive(Debug)]
pub struct SessionFacts {
    /// `auth_time`, `acr` and `amr`.
    pub authentication: Authentication,
    /// The session's public identifier, never its lookup digest — and `None`
    /// when there is no session left to name and the facts came from the
    /// grant's own copy of them.
    pub sid: Option<String>,
}

/// `auth_time`, `acr` and `amr` — from the session while it exists, and from
/// the grant's own copy once it does not.
///
/// Never defaulted and never invented. OIDC Core §2 makes `auth_time` a
/// statement about when the user actually authenticated, and a claim a relying
/// party makes step-up decisions on is not something to guess at from the
/// grant's timestamps.
///
/// **Two sources, in this order, and the order is the decision.** The session
/// wins while it is there: a step-up (`ast-2vk.7`) rotates it onto a stronger
/// `acr`, a fuller `amr` and a newer instant, and the person really did
/// authenticate again, so reporting the older snapshot would understate what
/// this token is worth. The grant's copy is the fallback, because §11 defines
/// `offline_access` as access "when the End-User is not present" and the
/// session row is exactly what a sign-out, a sweep or a retention policy takes
/// away (`ast-dlk`). That copy is *not* moved by a step-up — see
/// [`GrantAuthentication`](asterius_domain::GrantAuthentication): it records
/// the authentication that produced this grant, and a fallback reporting one
/// that happened afterwards would put an `auth_time` on a token that the
/// authorization it names never had.
///
/// [`SessionFacts::sid`] is `None` in the second case, and that is the signal a
/// caller reads to tell the two apart: a grant that is not entitled to outlive
/// its session must be refused rather than refreshed.
///
/// # Errors
///
/// [`DomainError::Invalid`] when the session is gone and the grant records no
/// authentication of its own — a user-facing grant written before `ast-dlk`,
/// or a client-only one that never had a person behind it — and a storage
/// error when the session store could not be read.
pub async fn session_facts(
    sessions: &dyn SessionRepository,
    grant: &Grant,
) -> Result<SessionFacts, DomainError> {
    let session = match grant.session.as_ref() {
        Some(digest) => sessions.find(digest.as_str()).await?,
        None => None,
    };

    if let Some(session) = session {
        return Ok(SessionFacts {
            authentication: Authentication {
                authenticated_at: session.authenticated_at,
                acr: session.acr.clone(),
                amr: session
                    .amr
                    .iter()
                    .map(|method| method.as_str().to_owned())
                    .collect(),
            },
            // Not `id_digest`: that is the lookup key and it is rewritten on
            // every rotation. See `Session::public_sid` (`ast-o4u.5`).
            sid: Some(session.public_sid.clone()),
        });
    }

    let recorded = grant.authentication.as_ref().ok_or_else(|| {
        DomainError::invalid(
            "session",
            "the session this grant was made in is gone and the grant records no authentication",
        )
    })?;
    Ok(SessionFacts {
        authentication: Authentication {
            authenticated_at: recorded.authenticated_at,
            acr: recorded.acr.clone(),
            amr: recorded
                .amr
                .iter()
                .map(|method| method.as_str().to_owned())
                .collect(),
        },
        // OIDC Back-Channel Logout 1.0 §2.4 has `sid` name a session a relying
        // party can be told about later. There is none left to name, and the
        // digest of a deleted row would name nothing — so the claim is omitted
        // rather than filled with a value no logout could ever match.
        sid: None,
    })
}

/// Remembers that this client took part in the session (OIDC Back-Channel
/// Logout 1.0 §2.3).
///
/// > OPs supporting back-channel logout need to keep track of the set of
/// > logged-in RPs for the End-User's session at the OP.
///
/// That set is what the end-session endpoint reads to decide who is sent a
/// logout token, so a client that is not recorded here is a client no logout
/// ever reaches — the notification would be built correctly and delivered to
/// nobody. This is the write that makes the list exist, and it belongs beside
/// the ID token rather than at sign-in: an ID token is what makes a relying
/// party a *participant* in the sense §2.3 means, and a client that only
/// obtained an access token has no session with this person to end.
///
/// A grant with no session records nothing: `client_credentials` has no
/// resource owner, and a grant whose session row is gone names a session no
/// logout will ever read.
///
/// Never fatal. A failure here costs a future logout one notification, which
/// is bad; refusing to issue a token the client is entitled to, because a
/// bookkeeping row could not be written, is worse — and the operator gets the
/// error either way.
pub async fn remember_participant(
    sessions: &dyn SessionRepository,
    grant: &Grant,
    now: time::OffsetDateTime,
) {
    let Some(session) = grant.session.as_ref() else {
        return;
    };
    if let Err(error) = sessions
        .record_participant(session.as_str(), &grant.client, now)
        .await
    {
        tracing::error!(
            %error,
            tenant = %grant.tenant,
            client = %grant.client,
            "cannot record a client as a participant of a session; a back-channel \
             logout will not reach it"
        );
    }
}

/// The claims this grant releases into its ID token.
///
/// Read from the grant and from the user row, and from nothing else. The
/// request is not consulted: it says what a client asked for, and a consent
/// screen — or, at a refresh, weeks — separate that from what this token may
/// carry.
///
/// A grant with no user, or whose user is gone, is a server-side inconsistency
/// and is reported as one, the same treatment [`session_facts`] gives a grant
/// it can say nothing about. Releasing nothing instead would mint an
/// authentication
/// assertion about somebody this server can no longer describe.
///
/// # Errors
///
/// [`DomainError::Invalid`] when the grant names no user, the user is gone, or
/// the stored `claims` request no longer parses; a storage error otherwise.
pub async fn released_claims(
    users: &PgUserRepository,
    grant: &Grant,
    client: &Client,
    held: &asterius_domain::HeldRoles,
) -> Result<ReleasedToIdToken, DomainError> {
    let id = grant
        .user
        .ok_or_else(|| DomainError::invalid("grant", "a user-facing grant names no user"))?;
    let user = users.find(id).await?.ok_or_else(|| {
        DomainError::invalid("user", "the user this grant was made for no longer exists")
    })?;
    // The request was validated at PAR and re-serialised canonically onto the
    // grant, so a stored one that no longer parses is a damaged row rather
    // than a bad request.
    let requested = asterius_oidc::claims::ClaimsRequest::from_json(&grant.claims)
        .map_err(|error| DomainError::invalid("claims", error.to_string()))?;
    let locales = asterius_oidc::claims::ClaimsLocales::from_tags(&grant.claims_locales);
    let resolved = asterius_oidc::claims::resolve(&user, &grant.scopes, &requested, &locales);
    Ok(ReleasedToIdToken {
        claims: resolved.id_token,
        role_claims: role_claims(&requested, client),
        held: held.clone(),
    })
}

/// What an ID token releases about the person, from the grant and nothing else.
///
/// The three travel together because they are one decision read off one grant:
/// what the `claims` request covers, which role claims this issuance says, and
/// the roles it says them from. Splitting them across the parameters of
/// [`sign_id_token`] would let a caller pass a `claims` request from one grant
/// beside the roles of another.
#[derive(Debug, Default)]
pub struct ReleasedToIdToken {
    /// The claims the grant's `claims` request covers.
    pub claims: serde_json::Map<String, serde_json::Value>,
    /// Which application-role claims this issuance carries (`ast-mqt`).
    pub role_claims: std::collections::BTreeSet<asterius_domain::RoleClaim>,
    /// What the person holds — the same value the access token of this
    /// response was minted from, so the two cannot disagree. The builder
    /// narrows it to this client.
    pub held: asterius_domain::HeldRoles,
}

/// Which role claims an ID token carries (`ast-mqt`).
///
/// Two routes, and they are a union rather than a precedence: a client that
/// registered `roles_in_id_token` gets both claims in every ID token, and a
/// client that did not gets exactly the ones the authorization's `claims`
/// parameter named. Both are the *client's* request for its own tokens —
/// nothing here widens what a token may say about anybody, because the roles
/// are narrowed to the token's own client when they are rendered
/// (`IdToken::with_roles`).
///
/// The request is read from the grant, so a refresh six weeks later carries
/// what was asked for at the authorization; the registration is read live, so
/// a client that turned the setting off stops receiving them on the next
/// issuance rather than on the next authorization.
fn role_claims(
    requested: &asterius_oidc::claims::ClaimsRequest,
    client: &Client,
) -> std::collections::BTreeSet<asterius_domain::RoleClaim> {
    if client.registration.roles_in_id_token.is_issued() {
        return asterius_domain::RoleClaim::ALL.into_iter().collect();
    }
    requested.role_claims().clone()
}

/// The application roles this grant's user holds (`ast-095`).
///
/// Read from the assignment tables and from nothing else — not from the grant,
/// not from the request. A role is authority an administrator granted, and it
/// is current at the moment a token is minted: a token refreshed after a role
/// was withdrawn must not still assert it, which is why this is read on every
/// issuance rather than frozen onto the grant at consent.
///
/// A grant with no resource owner holds nothing. That is not a failure: a
/// `client_credentials` token is about the client, and there is nobody whose
/// roles it could carry.
///
/// # Errors
///
/// [`DomainError::Storage`] if the read fails, or [`DomainError::Invalid`] for
/// a stored name this build refuses. Both are refusals rather than an empty
/// set: a token minted with *fewer* roles than the person holds is an
/// authorization decision taken by an outage.
pub async fn held_roles(
    roles: &dyn asterius_domain::ports::ApplicationRoleDirectory,
    grant: &Grant,
) -> Result<asterius_domain::HeldRoles, DomainError> {
    let Some(user) = grant.user else {
        return Ok(asterius_domain::HeldRoles::default());
    };
    roles.held_by(&grant.tenant, user).await
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
    implicit: ImplicitResources,
) -> Result<Targeting, TargetingError> {
    let registry = asterius_domain::ResourceRegistry::new(
        grant_management_resource(tenant, implicit.grant_management)
            .into_iter()
            .chain(ssf_resource(tenant, implicit.ssf))
            .chain(ssf_poll_resource(tenant, implicit.ssf))
            .chain(resource_servers.list().await?),
    );

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

/// The APIs this server hosts itself, as audiences a token may be minted for.
///
/// Two of this server's own endpoints are protected resources rather than
/// protocol endpoints — the Grant Management API and the SSF management API —
/// and neither has a row in the `resource_servers` registry: the identifier is
/// derived from the tenant's issuer, so there is nothing for an operator to
/// choose and nothing to keep in step. What an operator *does* choose is
/// whether the feature is on, which is what these two flags carry.
///
/// A struct rather than two booleans in the argument list, because two
/// adjacent booleans at four call sites is a swap nobody would see.
#[derive(Debug, Clone, Copy)]
pub struct ImplicitResources {
    /// Whether this tenant offers the Grant Management API (ID1 §6.2).
    pub grant_management: bool,
    /// Whether this tenant offers the SSF management API (SSF 1.0 §8).
    ///
    /// `false` for every grant but `client_credentials`, whatever the tenant
    /// has switched on: SSF 1.0 §8 makes the receiver a registered client
    /// acting on its own behalf, so a user-delegated token audienced at the
    /// stream configuration endpoint would be a person's authorization
    /// standing behind a stream they were never asked about.
    pub ssf: bool,
}

/// The SSF management API as a resource server of this tenant (SSF 1.0 §8,
/// `ast-0ju.3`).
///
/// The same argument [`grant_management_resource`] makes, and the same shape:
/// the identifier is the stream configuration endpoint, derived from the
/// tenant's issuer, so a deployment that switched SSF on would otherwise
/// advertise a transmitter, mount the endpoint, and then answer
/// `invalid_target` to every receiver asking for a token to call it.
///
/// The scopes are exactly one — [`asterius_ssf::stream::SCOPE_MANAGE`] — so a
/// receiver registered for `payments` and `ssf.manage` gets a stream
/// configuration token that cannot touch payments, and a payments token that
/// cannot configure a stream (RFC 8707 §2).
fn ssf_resource(tenant: &Tenant, offered: bool) -> Option<asterius_domain::ResourceServer> {
    if !offered {
        return None;
    }
    let url = format!(
        "{}{}",
        tenant.issuer.as_str(),
        crate::http::ssf::CONFIGURATION_PATH
    );
    let identifier = asterius_domain::ResourceIdentifier::parse(&url).ok()?;
    Some(asterius_domain::ResourceServer {
        identifier,
        scopes: Some(
            [asterius_ssf::stream::SCOPE_MANAGE.to_owned()]
                .into_iter()
                .collect(),
        ),
        // No opinion: the tenant's own access-token lifetime applies.
        default_token_lifetime: None,
    })
}

/// The SSF polling endpoint as a resource server of this tenant (RFC 8936,
/// SSF 1.0 §7.1.1, `ast-0ju.7`).
///
/// A *second* implicit resource rather than a second scope on the first, and
/// the separation is the point. Configuring a stream and reading its events
/// are done by different parts of a receiver — one an administrative act, the
/// other a loop that runs all day — so they are two audiences and two scopes
/// (RFC 8707 §2): a polling token cannot delete the stream it polls, and a
/// management token cannot read its events.
///
/// The identifier is the *base* polling endpoint, not the per-stream URL of
/// §6.1.2: a receiver holds one token for this transmitter and polls every
/// stream it owns with it, and which streams those are is decided by the
/// `client_id` the endpoint looks up rather than by a copy of that decision
/// baked into an audience.
fn ssf_poll_resource(tenant: &Tenant, offered: bool) -> Option<asterius_domain::ResourceServer> {
    if !offered {
        return None;
    }
    let url = format!("{}{}", tenant.issuer.as_str(), crate::http::ssf::POLL_PATH);
    let identifier = asterius_domain::ResourceIdentifier::parse(&url).ok()?;
    Some(asterius_domain::ResourceServer {
        identifier,
        scopes: Some(
            [asterius_ssf::stream::SCOPE_POLL.to_owned()]
                .into_iter()
                .collect(),
        ),
        default_token_lifetime: None,
    })
}

/// The Grant Management API as a resource server of this tenant (§6.2).
///
/// `None` where the deployment does not offer the feature, which is what keeps
/// this in step with the router and the metadata: a resource nobody can call
/// is an audience no token should carry.
///
/// # Why it is implicit
///
/// §6.3 makes the resource URL the grant management endpoint plus the grant
/// id, and §6.2 makes that endpoint a property of the tenant's issuer. So the
/// identifier is already decided — there is nothing for an operator to choose
/// — and the `resource_servers` registry exists for the APIs this server knows
/// nothing about. Requiring a row would mean a deployment that switched Grant
/// Management on, advertised `grant_management_endpoint`, mounted the route,
/// and then answered `invalid_target` to every client that asked for a token
/// to call it, until somebody ran one more command.
///
/// It is placed *before* the stored list, so an operator who registers the
/// same identifier — to give it a lifetime of its own, say — overrides this
/// rather than fighting it: `ResourceRegistry::new` keeps the last entry for a
/// duplicate identifier.
///
/// The scopes are exactly §6.1's two. That is what makes the `scope` claim of
/// a token audienced here carry those and nothing else (RFC 8707 §2): a client
/// registered for `payments` and `grant_management_revoke` gets a grant
/// management token that cannot touch payments, and a payments token that
/// cannot revoke a grant.
///
/// An identifier that will not parse is `None` rather than an error. It is
/// built from the tenant's own issuer, so that cannot happen for a tenant this
/// server would serve at all — and a token endpoint that refused every request
/// because of it would be a worse failure than a missing audience.
fn grant_management_resource(
    tenant: &Tenant,
    offered: bool,
) -> Option<asterius_domain::ResourceServer> {
    if !offered {
        return None;
    }
    let url = asterius_oidc::metadata::Endpoint::GrantManagement.url(&tenant.issuer);
    let identifier = asterius_domain::ResourceIdentifier::parse(&url).ok()?;
    Some(asterius_domain::ResourceServer {
        identifier,
        scopes: Some(
            [
                asterius_oidc::grant_management::SCOPE_QUERY.to_owned(),
                asterius_oidc::grant_management::SCOPE_REVOKE.to_owned(),
            ]
            .into_iter()
            .collect(),
        ),
        // No opinion: the tenant's own access-token lifetime applies, which is
        // the one an operator has already set.
        default_token_lifetime: None,
    })
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
    pub released: ReleasedToIdToken,
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
    // OIDC Back-Channel Logout 1.0 §2.4: `sid` names a session a relying party
    // can be told about when it ends. A grant whose session is already gone has
    // none to name — §2.4 makes the claim OPTIONAL in an ID token, and omitting
    // it is the only honest answer; a value here would name a row that no
    // logout notification could ever match.
    if let Some(sid) = session.sid.as_deref() {
        builder = builder.for_session(
            asterius_oidc::tokens::id_token::Session::new(&asterius_domain::SessionId::new(sid))
                .map_err(|e| DomainError::invalid("sid", e.to_string()))?,
        );
    }
    // `releasing` takes a plain map, so `IdToken::build` re-checks it against
    // `ClaimName::SERVER_ISSUED` rather than trusting that it came from
    // `claims::resolve`.
    builder = builder.releasing(released.claims);
    // The application roles (`ast-mqt`), and only the ones this issuance is
    // allowed to say. An empty set is the default and emits nothing; the
    // builder narrows what it is given to this token's own client.
    builder = builder.with_roles(&released.held, &released.role_claims);
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

#[cfg(test)]
mod tests {
    use super::*;
    use asterius_domain::entities::session::AuthenticationMethod;
    use asterius_domain::{
        Capabilities, ClientId, ClientRegistration, ClientStatus, GrantAuthentication, Participant,
        Session, SessionId, SessionRevocation, TenantId,
    };
    use serde_json::json;
    use time::{Duration, OffsetDateTime};

    const DIGEST: &str = "the-lookup-digest-of-a-session";

    // -----------------------------------------------------------------------
    // The SSF implicit resources (SSF 1.0 §7.1.1, `ast-0ju.7`)
    // -----------------------------------------------------------------------

    /// A tenant, for the two tests below and nothing else.
    fn ssf_tenant() -> Tenant {
        Tenant {
            id: TenantId::new("demo"),
            issuer: asterius_domain::Issuer::parse("https://as.example/t/demo").expect("issuer"),
            default_resource: "https://api.example/".to_owned(),
            custom_host: None,
            display_name: "demo".to_owned(),
            status: asterius_domain::TenantStatus::Active,
            refresh: asterius_domain::RefreshPolicy::default(),
            created_at: epoch(),
            updated_at: epoch(),
        }
    }

    /// §7.1.1: the polling endpoint is protected, so a receiver must be able
    /// to ask for a token audienced at it — and that token carries the poll
    /// scope and not the management one.
    #[test]
    fn the_polling_endpoint_is_an_audience_a_receiver_can_ask_for() {
        // Arrange, act
        let resource = ssf_poll_resource(&ssf_tenant(), true).expect("an implicit resource");

        // Assert
        assert_eq!(
            resource.identifier.as_str(),
            "https://as.example/t/demo/ssf/poll"
        );
        assert_eq!(
            resource.scopes,
            Some(
                [asterius_ssf::stream::SCOPE_POLL.to_owned()]
                    .into_iter()
                    .collect()
            )
        );
    }

    /// A resource nobody can call is an audience no token should carry: a
    /// deployment without SSF offers neither of the two.
    #[test]
    fn a_deployment_without_ssf_offers_no_polling_audience() {
        // Arrange, act
        let resource = ssf_poll_resource(&ssf_tenant(), false);

        // Assert
        assert!(resource.is_none());
    }

    // -----------------------------------------------------------------------
    // Sender constraining
    // -----------------------------------------------------------------------

    /// The smallest registration this server accepts, bound the way the
    /// argument says. Built through `ClientRegistration::validate` rather than
    /// assembled field by field, so a binding that registration would refuse
    /// cannot be tested as though it were reachable.
    fn client_bound_by(certificate: bool) -> Client {
        let document = json!({
            "client_name": "billing",
            "redirect_uris": ["https://client.example/cb"],
            "token_endpoint_auth_method": "private_key_jwt",
            "jwks": {"keys": [{"kty": "OKP", "crv": "Ed25519", "x": "abc"}]},
            "dpop_bound_access_tokens": !certificate,
            "tls_client_certificate_bound_access_tokens": certificate,
        });
        let capabilities = Capabilities {
            mtls: true,
            ..Capabilities::default()
        };
        let registration = ClientRegistration::from_json(
            &serde_json::to_vec(&document).expect("serialise"),
            capabilities,
        )
        .expect("a registration this server accepts");
        Client {
            tenant: TenantId::new("demo"),
            id: ClientId::new("billing"),
            registration,
            status: ClientStatus::Active,
            created_at: epoch(),
            updated_at: epoch(),
        }
    }

    /// A DER `Certificate` with the shape `ClientCertificate::from_der` reads
    /// and nothing else in it. Nothing here signs or validates anything: what
    /// is compared is the SHA-256 of the bytes, and `serial` is what makes two
    /// of these different certificates.
    fn certificate(serial: u8) -> ClientCertificate {
        fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
            let length = u8::try_from(value.len()).expect("a short fixture");
            let mut encoded = vec![tag, length];
            encoded.extend_from_slice(value);
            encoded
        }
        const SEQUENCE: u8 = 0x30;

        // TBSCertificate: serialNumber, signature, issuer, validity, subject,
        // subjectPublicKeyInfo — RFC 5280 §4.1, in that order.
        let mut tbs = tlv(0x02, &[serial]);
        for _ in 0..5 {
            tbs.extend(tlv(SEQUENCE, &[]));
        }
        // Certificate: tbsCertificate, signatureAlgorithm, signature.
        let mut certificate = tlv(SEQUENCE, &tbs);
        certificate.extend(tlv(SEQUENCE, &[]));
        certificate.extend(tlv(0x03, &[0x00]));
        ClientCertificate::from_der(tlv(SEQUENCE, &certificate)).expect("a DER certificate")
    }

    /// RFC 8705 §3.1: the `cnf` is the thumbprint of the certificate the
    /// endpoint actually saw.
    #[test]
    fn a_certificate_bound_client_mints_a_token_confirmed_by_its_certificate() {
        let client = client_bound_by(true);
        let certificate = certificate(1);

        let confirmation = SenderConstraint {
            proof_key: None,
            certificate: Some(&certificate),
        }
        .confirmation(&client)
        .expect("a certificate to bind to");

        assert_eq!(confirmation.binding(), TokenBinding::Certificate);
        assert_eq!(
            confirmation,
            Confirmation::certificate(&certificate.thumbprint_b64url()).expect("a thumbprint")
        );
    }

    /// A client registers one binding method, so a request that offers two is
    /// refused rather than silently resolved.
    #[test]
    fn a_certificate_bound_request_that_also_proves_a_dpop_key_is_refused() {
        let client = client_bound_by(true);
        let certificate = certificate(1);
        let jkt = Kid::new("a".repeat(43));

        let error = SenderConstraint {
            proof_key: Some(&jkt),
            certificate: Some(&certificate),
        }
        .confirmation(&client)
        .expect_err("two bindings offered");

        assert!(
            matches!(error, ConstraintError::TwoBindingsOffered),
            "{error:?}"
        );
    }

    /// There is nothing to put in `x5t#S256`, and no unbound token to fall
    /// back to.
    #[test]
    fn a_certificate_bound_client_without_a_certificate_gets_no_token() {
        let error = SenderConstraint {
            proof_key: None,
            certificate: None,
        }
        .confirmation(&client_bound_by(true))
        .expect_err("nothing to bind to");

        assert!(
            matches!(error, ConstraintError::CertificateRequired),
            "{error:?}"
        );
    }

    /// FAPI 2.0 SP §5.3.2.1 item 5: a client that authenticates with a
    /// certificate but did not register certificate binding still has to send
    /// a DPoP proof. Presenting a certificate is not a substitute for it.
    #[test]
    fn a_dpop_client_that_presents_a_certificate_must_still_prove_its_key() {
        let client = client_bound_by(false);
        let certificate = certificate(1);

        let error = SenderConstraint {
            proof_key: None,
            certificate: Some(&certificate),
        }
        .confirmation(&client)
        .expect_err("no proof");

        assert!(matches!(error, ConstraintError::ProofRequired), "{error:?}");

        let jkt = Kid::new("a".repeat(43));
        let confirmation = SenderConstraint {
            proof_key: Some(&jkt),
            certificate: Some(&certificate),
        }
        .confirmation(&client)
        .expect("a proven key");
        assert_eq!(confirmation.binding(), TokenBinding::Dpop);
    }

    /// The refresh token is bound the same way the access token beside it is.
    #[test]
    fn a_refresh_token_is_bound_the_way_its_client_is() {
        let certificate = certificate(1);
        let jkt = Kid::new("a".repeat(43));

        assert_eq!(
            SenderConstraint {
                proof_key: None,
                certificate: Some(&certificate),
            }
            .refresh_binding(&client_bound_by(true))
            .expect("a certificate"),
            RefreshBinding::Certificate(certificate.thumbprint())
        );
        assert_eq!(
            SenderConstraint {
                proof_key: Some(&jkt),
                certificate: None,
            }
            .refresh_binding(&client_bound_by(false))
            .expect("a key"),
            RefreshBinding::Dpop(jkt.as_str().to_owned())
        );
    }

    /// "No certificate" and "a different certificate" are one answer.
    #[test]
    fn a_credential_is_held_only_by_the_certificate_it_was_issued_under() {
        let issued_under = certificate(1);
        let another = certificate(2);

        assert!(
            SenderConstraint {
                proof_key: None,
                certificate: Some(&issued_under),
            }
            .presents(&issued_under.thumbprint())
        );
        assert!(
            !SenderConstraint {
                proof_key: None,
                certificate: Some(&another),
            }
            .presents(&issued_under.thumbprint())
        );
        assert!(
            !SenderConstraint {
                proof_key: None,
                certificate: None,
            }
            .presents(&issued_under.thumbprint())
        );
    }

    fn epoch() -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH
    }

    /// One session, or none — which is the whole question [`session_facts`]
    /// asks the store.
    #[derive(Debug, Default)]
    struct FakeSessions {
        session: Option<Session>,
    }

    impl FakeSessions {
        /// A session as a step-up left it: a later instant, a stronger `acr`
        /// and one more method than the authorization recorded.
        fn stepped_up() -> Self {
            Self {
                session: Some(Session {
                    tenant: TenantId::new("demo"),
                    id_digest: DIGEST.to_owned(),
                    public_sid: "the-public-sid".to_owned(),
                    user: uuid::Uuid::from_u128(1),
                    created_at: epoch(),
                    authenticated_at: epoch() + Duration::hours(2),
                    last_seen_at: epoch() + Duration::hours(2),
                    expires_at: epoch() + Duration::hours(8),
                    idle_expires_at: epoch() + Duration::hours(3),
                    acr: Some("urn:asterius:acr:passkey-uv".to_owned()),
                    amr: vec![
                        AuthenticationMethod::Password,
                        AuthenticationMethod::Passkey,
                    ],
                    revoked: None,
                }),
            }
        }

        /// What a sweep, a sign-out or a retention policy leaves behind.
        fn purged() -> Self {
            Self::default()
        }
    }

    #[async_trait::async_trait]
    impl SessionRepository for FakeSessions {
        async fn find(&self, id_digest: &str) -> Result<Option<Session>, DomainError> {
            Ok(self
                .session
                .clone()
                .filter(|session| session.id_digest == id_digest))
        }

        async fn begin(&self, _session: &Session) -> Result<(), DomainError> {
            unimplemented!("not reached by session_facts")
        }
        async fn touch(
            &self,
            _id_digest: &str,
            _now: OffsetDateTime,
            _idle: Duration,
        ) -> Result<(), DomainError> {
            unimplemented!("not reached by session_facts")
        }
        async fn rotate(
            &self,
            _old_digest: &str,
            _new_digest: &str,
            _methods: &[AuthenticationMethod],
            _acr: Option<&str>,
            _now: OffsetDateTime,
        ) -> Result<(), DomainError> {
            unimplemented!("not reached by session_facts")
        }
        async fn revoke(
            &self,
            _id_digest: &str,
            _reason: SessionRevocation,
            _now: OffsetDateTime,
        ) -> Result<(), DomainError> {
            unimplemented!("not reached by session_facts")
        }
        async fn revoke_all_for_user(
            &self,
            _user: uuid::Uuid,
            _reason: SessionRevocation,
            _now: OffsetDateTime,
        ) -> Result<u64, DomainError> {
            unimplemented!("not reached by session_facts")
        }
        async fn record_participant(
            &self,
            _id_digest: &str,
            _client: &ClientId,
            _now: OffsetDateTime,
        ) -> Result<(), DomainError> {
            unimplemented!("not reached by session_facts")
        }
        async fn participants(&self, _id_digest: &str) -> Result<Vec<Participant>, DomainError> {
            unimplemented!("not reached by session_facts")
        }
    }

    /// A grant made in that session, carrying the copy the authorization took.
    fn a_user_grant() -> Grant {
        let mut grant = Grant::new(TenantId::new("demo"), ClientId::new("billing"), epoch());
        grant.scopes = ["openid".to_owned(), "offline_access".to_owned()]
            .into_iter()
            .collect();
        grant.session = Some(SessionId::new(DIGEST));
        grant.authentication = Some(GrantAuthentication {
            authenticated_at: epoch(),
            acr: Some("urn:asterius:acr:password".to_owned()),
            amr: vec![AuthenticationMethod::Password],
        });
        grant
    }

    /// **The session wins while it is there** — including after a step-up
    /// (`ast-2vk.7`) that moved it past the copy the grant holds.
    ///
    /// OIDC Core §2's `auth_time` is when the End-User authentication
    /// occurred, and after a step-up the person really did authenticate again:
    /// a token reporting the older snapshot would understate the context a
    /// relying party is being asked to trust.
    #[tokio::test]
    async fn a_live_session_is_the_answer_even_when_a_step_up_moved_it() {
        let sessions = FakeSessions::stepped_up();
        let grant = a_user_grant();

        let facts = session_facts(&sessions, &grant)
            .await
            .expect("a live session answers");

        assert_eq!(
            facts.authentication.authenticated_at,
            epoch() + Duration::hours(2),
            "the grant's older snapshot was reported over the live session"
        );
        assert_eq!(
            facts.authentication.acr.as_deref(),
            Some("urn:asterius:acr:passkey-uv")
        );
        assert_eq!(facts.authentication.amr, vec!["pwd", "swk"]);
        assert_eq!(facts.sid.as_deref(), Some("the-public-sid"));
    }

    /// **A purged session falls back to the grant's own copy** (`ast-dlk`).
    ///
    /// OIDC Core §11 makes `offline_access` access "when the End-User is not
    /// present", so the row that records presence is exactly the one that may
    /// be gone. What comes back is the authentication that produced *this*
    /// grant — not the step-up above, which this grant never had — and no
    /// `sid`, because there is no session left for a logout to name.
    #[tokio::test]
    async fn a_purged_session_falls_back_to_the_grants_own_copy() {
        let sessions = FakeSessions::purged();
        let grant = a_user_grant();

        let facts = session_facts(&sessions, &grant)
            .await
            .expect("the grant's copy answers");

        assert_eq!(facts.authentication.authenticated_at, epoch());
        assert_eq!(
            facts.authentication.acr.as_deref(),
            Some("urn:asterius:acr:password")
        );
        assert_eq!(facts.authentication.amr, vec!["pwd"]);
        assert_eq!(
            facts.sid, None,
            "a session that no longer exists was still named in a sid"
        );
    }

    /// **A client-only grant has nothing to fall back on** (`ast-a05.8`).
    ///
    /// RFC 6749 §4.4 is a client acting for itself: no session, no person, and
    /// so no `auth_time` — the three columns are null. The fallback must not
    /// invent one, and the refusal is what stops a token that asserts an
    /// authentication nobody performed.
    #[tokio::test]
    async fn a_client_only_grant_has_no_authentication_to_fall_back_on() {
        let sessions = FakeSessions::purged();
        let grant = Grant::new(TenantId::new("demo"), ClientId::new("billing"), epoch());

        let error = session_facts(&sessions, &grant)
            .await
            .expect_err("nothing to report");

        assert!(
            matches!(
                error,
                DomainError::Invalid {
                    field: "session",
                    ..
                }
            ),
            "unexpected error: {error}"
        );
    }
}
