//! The grant: the revocable unit of authority every token traces back to.
//!
//! FAPI 2.0 Security Profile (Final, 22 February 2025) §6.8 "Key Compromise"
//! item 4, *Credential linking*: "When multiple credentials are issued as part
//! of the same authorization, it is recommended that their relationship be
//! explicitly established and recorded. This way, if one credential in a linked
//! set is compromised, all related credentials can be revoked."
//!
//! That is the whole reason this type exists, and it decides its shape. An
//! authorization produces several credentials — an authorization code, one or
//! more access tokens, a refresh token, later an exchanged token — and the
//! thing that must be revocable is the *authorization*, not each credential
//! individually. So the link is not a nullable convenience column: a token that
//! exists without a grant is a token nobody can revoke, which is the failure a
//! revocation mechanism exists to prevent.
//!
//! Two consequences run through everything below.
//!
//! **A token can only be minted from a grant that permits it.** The one way to
//! obtain a [`ClaimedGrant`] — the value every issuance path requires — is
//! [`Grant::claim`], which refuses a grant that is revoked or expired. There is
//! no constructor, so "issue a token without a grant" and "issue a token from a
//! revoked grant" are not states a caller can express.
//!
//! **The status is computed, never stored.** A grant is `expired` the instant
//! `expires_at` passes, and no process runs at that instant; a `status` column
//! would therefore say `active` about a grant that is not, until a sweep got
//! round to it. [`Grant::status`] derives the answer from three stamps — the
//! revocation, the expiry, and the first claim — so it cannot be stale and
//! cannot disagree with the row it came from.
//!
//! The three stamps are stored; the *status* is not. That distinction is the
//! whole design: `revoked_at` and `claimed_at` record things that happened, and
//! a thing that happened does not go stale, whereas `expired` is a comparison
//! against the current clock and goes stale the moment it is written down.
//!
//! ## Lifecycle
//!
//! Grant Management for OAuth 2.0 (`oauth-v2-grant-management-03`,
//! Implementer's Draft 1, 9 May 2023) §5.6 "Lifecycle of the grant": "Grant, as
//! a set of authorized permissions, is created by the AS on authorization
//! request completion. For the initial authorization flow, a grant should be
//! considered active when associated tokens have been successfully claimed by
//! the client. If the tokens haven't been claimed the grant should be deleted
//! by the AS after a reasonable timeout."
//!
//! So the states are [`GrantStatus`], and `pending` is not a synonym for "new":
//! it means *nobody has taken a credential out of this yet*, which is exactly
//! the condition under which the draft says to delete it.

use crate::entities::session::AuthenticationMethod;
use crate::{ClientId, GrantId, SessionId, SubjectId, TenantId, UserId};
use std::collections::BTreeSet;
use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

/// Where a grant is in its life.
///
/// A closed set of four. Free text or an open enum would let a sweep, an
/// administrator or a future migration invent a fifth state, and every consumer
/// of a fifth state has to guess whether it may issue a token from it — which
/// is the one question this type exists to answer without guessing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum GrantStatus {
    /// Created by an authorization flow, but no credential has been claimed
    /// from it yet. Grant Management ID1 §5.6: a grant in this state is the one
    /// the authorization server should delete after a timeout.
    Pending,
    /// A credential has been claimed. The grant is authority a live token
    /// depends on.
    Active,
    /// Withdrawn. Terminal: nothing brings a grant back, because the point of
    /// revocation is that the decision cannot be undone by whoever caused it.
    Revoked,
    /// Past `expires_at`. No credential may be minted from it, but a person may
    /// still revoke it — see [`GrantStatus::may_become`].
    Expired,
}

impl GrantStatus {
    /// Every state, in the order a grant passes through them.
    pub const ALL: [Self; 4] = [Self::Pending, Self::Active, Self::Revoked, Self::Expired];

    /// The spelling used in a stored value, an audit record and the Grant
    /// Management query response.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    /// Parses the stored spelling, or `None` for anything else.
    ///
    /// There is deliberately no fallback. Every default a reader could pick is
    /// wrong in one direction: `active` mints tokens from a grant nobody
    /// vouched for, `revoked` silently cuts off a working integration.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|status| status.as_str() == value)
    }

    /// Whether a credential may be claimed from a grant in this state.
    ///
    /// The only two that qualify are the two that are not endings. A `revoked`
    /// grant answering "yes" here would make revocation advisory.
    #[must_use]
    pub const fn may_issue(self) -> bool {
        matches!(self, Self::Pending | Self::Active)
    }

    /// Whether `self -> next` is a transition the lifecycle allows.
    ///
    /// Spelled out rather than implied, because the illegal ones are the
    /// interesting ones:
    ///
    /// * `pending -> active` — a credential was claimed (Grant Management ID1
    ///   §5.6). This is the only way `active` is ever reached.
    /// * `pending -> revoked`, `active -> revoked`, `expired -> revoked` — a
    ///   withdrawal. Expiry is allowed to be followed by revocation because
    ///   expiry ends a grant's authority and not its record: a person revoking
    ///   a grant that lapsed a minute ago is saying "and never again", and
    ///   refusing them would be an error message for an action that harms
    ///   nothing.
    /// * `pending -> expired`, `active -> expired` — the clock passed
    ///   `expires_at`.
    ///
    /// And the ones that are refused: **`revoked -> anything`**, because a
    /// revocation that something can undo is not a revocation; `active ->
    /// pending`, because a claimed credential cannot be unclaimed; `expired ->
    /// active` and `expired -> pending`, because time does not run backwards
    /// and nothing here extends an expiry.
    #[must_use]
    pub const fn may_become(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Pending, Self::Active | Self::Revoked | Self::Expired)
                | (Self::Active, Self::Revoked | Self::Expired)
                | (Self::Expired, Self::Revoked)
        )
    }
}

impl std::fmt::Display for GrantStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why a grant was withdrawn.
///
/// A closed vocabulary rather than the free text the column would hold. Two
/// reasons: a revocation reason is queried and alerted on, and a trail where
/// `user_revoked` and `revoked by user` both occur is a trail nobody can query;
/// and a free-text column next to a grant is somewhere a support tool would
/// eventually write a ticket number, a user's name or an IP address, none of
/// which belong in a record kept for as long as this one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RevocationReason {
    /// The person the grant is about withdrew it — a grants dashboard, or
    /// Grant Management ID1 §6.5 `DELETE`.
    UserRevoked,
    /// The client asked, at the revocation endpoint (RFC 7009 §2.1).
    ClientRevoked,
    /// An administrator or an automated policy withdrew it.
    AdminRevoked,
    /// An authorization code was presented twice, so everything derived from
    /// that authorization is suspect (RFC 6749 §10.5).
    CodeReplayed,
    /// The browser session the grant was created in ended.
    SessionEnded,
    /// A key that signed credentials for this grant is no longer trusted
    /// (FAPI 2.0 SP §6.8).
    KeyCompromise,
    /// Replaced by another grant — Grant Management ID1 §5.2's `replace`, which
    /// "shall invalidate existing refresh tokens".
    Superseded,
}

impl RevocationReason {
    /// Every reason.
    pub const ALL: [Self; 7] = [
        Self::UserRevoked,
        Self::ClientRevoked,
        Self::AdminRevoked,
        Self::CodeReplayed,
        Self::SessionEnded,
        Self::KeyCompromise,
        Self::Superseded,
    ];

    /// The stored spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UserRevoked => "user_revoked",
            Self::ClientRevoked => "client_revoked",
            Self::AdminRevoked => "admin_revoked",
            Self::CodeReplayed => "code_replayed",
            Self::SessionEnded => "session_ended",
            Self::KeyCompromise => "key_compromise",
            Self::Superseded => "superseded",
        }
    }

    /// Parses the stored spelling, or `None` for anything else.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|reason| reason.as_str() == value)
    }
}

impl std::fmt::Display for RevocationReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why a grant, or a row claiming to be one, was refused.
///
/// Every variant renders as fixed text, or as a value from one of this
/// module's own closed vocabularies. Nothing here interpolates a scope, a
/// resource, a claim name or a `jti`: the message reaches an audit record and,
/// through [`DomainError`](crate::DomainError), an operator's log, and a grant
/// carries values that came from a client.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum GrantError {
    /// A credential was asked for from a grant that cannot issue one.
    #[error("no credential may be claimed from a {0} grant")]
    NotIssuable(GrantStatus),
    /// A stored revocation is half-written: a stamp with no reason, or a
    /// reason with no stamp. Either way the row cannot say whether the grant is
    /// revoked, and "probably not" is the wrong guess.
    #[error("revoked_at and revocation_reason must be set together")]
    IncoherentRevocation,
    /// The stored `revocation_reason` is not one this server writes.
    #[error("revocation_reason is not a known reason")]
    UnknownRevocationReason,
    /// `expires_at` is at or before `created_at`: a grant that ended before it
    /// began is a row nobody can reason about.
    #[error("expires_at must be after created_at")]
    ExpiryPrecedesCreation,
    /// A scope token breaks RFC 6749 §3.3's grammar.
    #[error("a scope token must be printable ASCII other than space, '\"' and '\\'")]
    ScopeToken,
    /// Too many scopes, or one that is too long.
    #[error(
        "a grant holds at most {} scopes of at most {} bytes",
        Grant::MAX_SCOPES,
        Grant::MAX_SCOPE_LEN
    )]
    ScopeSize,
    /// A `resource` is not an absolute URI, or carries a fragment
    /// (RFC 8707 §2).
    #[error("a resource must be an absolute URI without a fragment")]
    Resource,
    /// Too many resource indicators.
    #[error("a grant holds at most {} resources", Grant::MAX_RESOURCES)]
    ResourceSize,
    /// The `claims` column does not hold a JSON object (OIDC Core §5.5).
    #[error("claims must be a JSON object")]
    ClaimsShape,
    /// A `claims_locales` entry is not shaped like a language tag, or there
    /// are too many of them (OIDC Core §5.2, RFC 5646 §2.1).
    #[error(
        "a grant holds at most {} language tags of at most {} bytes",
        Grant::MAX_CLAIMS_LOCALES,
        Grant::MAX_LOCALE_LEN
    )]
    ClaimsLocale,
    /// The `authorization_details` column does not hold a JSON array
    /// (RFC 9396 §2).
    #[error("authorization_details must be a JSON array")]
    AuthorizationDetailsShape,
    /// The `actor_chain` column does not hold a JSON array (RFC 8693 §4.1).
    #[error("actor_chain must be a JSON array")]
    ActorChainShape,
    /// A `jti` that cannot be stored, matched or read back.
    #[error("a jti must be 1 to {} bytes of printable ASCII", Grant::MAX_JTI_LEN)]
    Jti,
    /// A stored authentication is half-written: an `acr` or an `amr` with no
    /// instant. OIDC Core §2 makes `auth_time` the fact the other two describe,
    /// so a row without it cannot say when the authentication it names
    /// happened — and a token minted from it would assert a context with no
    /// time attached.
    #[error("acr and amr may only be stored with the authenticated_at they describe")]
    IncoherentAuthentication,
}

// ---------------------------------------------------------------------------
// The authentication behind a grant
// ---------------------------------------------------------------------------

/// When and how the person authenticated, as the authorization recorded it.
///
/// The `auth_time`, `acr` and `amr` of OIDC Core §2, copied onto the grant at
/// the moment the authorization completed — the one moment where the session
/// they come from is certainly there.
///
/// **Why the grant holds a copy at all.** §11 defines `offline_access` as
/// access "when the End-User is not present", so such a grant is meant to
/// outlive the browser session it was made in; a sweep, a sign-out or a
/// retention policy takes that row away. Read the three from the session and
/// from nowhere else, and the server has no honest `auth_time` left to assert
/// and must refuse to refresh — which makes `offline_access` mean the opposite
/// of what §11 says (`ast-dlk`, the residue `ast-uwv.3` named).
///
/// **Why it is one value and not three fields.** They are one fact. An `acr`
/// without the instant it was reached at is an authentication context nobody
/// can place in time, and a reader would have to decide for itself whether to
/// assert it. `Option<GrantAuthentication>` has no such state: either the
/// authorization recorded an authentication or it did not.
///
/// **Why a snapshot rather than the live session.** OIDC Core §2 defines
/// `auth_time` as the time "when the End-User authentication occurred" — the
/// authentication that produced *this* grant. A later step-up (`ast-2vk.7`)
/// rotates the session onto a stronger `acr` and a newer instant, and while
/// that session exists it is the live answer, because the person really did
/// authenticate again. This copy is not rewritten by it: it is what the
/// fallback has left to say once the session is gone, and moving it would make
/// the fallback report an authentication that happened after the authorization
/// it describes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantAuthentication {
    /// OIDC Core §2's `auth_time`: when the person authenticated.
    pub authenticated_at: OffsetDateTime,
    /// The authentication context class the sign-in reached, if the tenant's
    /// ladder has a rung for it.
    pub acr: Option<String>,
    /// How they authenticated, in the order it happened (RFC 8176).
    pub amr: Vec<AuthenticationMethod>,
}

// ---------------------------------------------------------------------------
// The grant
// ---------------------------------------------------------------------------

/// One authorization, and everything issued under it.
///
/// Deliberately not `#[non_exhaustive]`, for the reason
/// [`Tenant`](crate::Tenant) gives: adapters build entities from rows, and
/// sealing the struct would only push them through a constructor taking the
/// same fields in the same order with less type checking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    /// Which tenant's grant this is.
    pub tenant: TenantId,
    /// The identifier. A v4 UUID: the column is `uuid`, and
    /// [`Grant::new`] is the only thing that mints one, so a grant id is never
    /// a value a client chose.
    pub id: GrantId,
    /// The client the authorization was granted to.
    pub client: ClientId,
    /// The local account. `None` for a `client_credentials` grant, which is a
    /// client acting for itself and has no resource owner.
    pub user: Option<UserId>,
    /// The `sub` the client sees. `None` for the same reason as `user`.
    pub subject: Option<SubjectId>,
    /// The scopes this authorization covers (RFC 6749 §3.3).
    pub scopes: BTreeSet<String>,
    /// The OIDC Core §5.5 `claims` request this authorization covers, as a JSON
    /// object.
    ///
    /// The *parsed* request, canonically serialised — see
    /// `asterius_oidc::claims::ClaimsRequest::to_json`. Not the document the
    /// client pushed: a grant records the decision, and a member this server
    /// declined to understand was no part of it.
    pub claims: serde_json::Value,
    /// The OIDC Core §5.2 `claims_locales` preference, most preferred first.
    ///
    /// A column of its own rather than a member of `claims`, because it is not
    /// part of the §5.5 request object and a reader that parsed `claims` as one
    /// would have to know to skip it. Order is meaning here — "ordered by
    /// preference" is the whole of the parameter — so it is a `Vec` and not a
    /// set.
    ///
    /// It lives on the grant because it belongs to the authorization it was
    /// expressed in. A token request arriving later carries no such parameter,
    /// so reading it anywhere else would mean answering a refresh in whatever
    /// language the last caller happened to imply.
    pub claims_locales: Vec<String>,
    /// The RFC 9396 §2 `authorization_details`, as a JSON array. Their
    /// per-type schemas belong to the RAR story; what is enforced here is that
    /// the column holds the shape the specification names.
    pub authorization_details: Vec<serde_json::Value>,
    /// The RFC 8707 resource indicators this authorization is audience-bound
    /// to.
    pub resources: BTreeSet<String>,
    /// The RFC 8693 §4.1 `act` chain, innermost actor last. Non-empty only for
    /// a grant reached through token exchange.
    pub actor_chain: Vec<serde_json::Value>,
    /// The grant this one was narrowed from, for an exchanged token. A child
    /// grant is minted at the token endpoint, so it is claimed the moment it
    /// exists.
    pub parent: Option<GrantId>,
    /// The browser session the authorization happened in, when there was one.
    pub session: Option<SessionId>,
    /// When and how the person authenticated, as [`session`](Self::session)
    /// reported it at the moment the authorization completed.
    ///
    /// `None` for a grant with no resource owner — a `client_credentials`
    /// grant authenticates a client, not a person, and RFC 9068 §2.2's answer
    /// to "who is this about" is the `client_id`.
    ///
    /// See [`GrantAuthentication`] for why the grant keeps a copy of something
    /// the session already holds.
    pub authentication: Option<GrantAuthentication>,
    /// When the authorization completed.
    pub created_at: OffsetDateTime,
    /// When the row last changed. Grant Management ID1 §6.4's
    /// `last_updated_at`.
    pub updated_at: OffsetDateTime,
    /// When the authorization lapses, if it does.
    pub expires_at: Option<OffsetDateTime>,
    /// When it was withdrawn.
    pub revoked_at: Option<OffsetDateTime>,
    /// Why it was withdrawn. Set exactly when `revoked_at` is.
    pub revocation_reason: Option<RevocationReason>,
    /// When the first credential was claimed from this grant, if one ever was.
    ///
    /// Grant Management ID1 §5.6 turns on this one fact: a grant is `active`
    /// "when associated tokens have been successfully claimed by the client",
    /// and one that was never claimed "should be deleted by the AS after a
    /// reasonable timeout". So the sweep that deletes abandoned grants and the
    /// status a grants dashboard shows are the same question, and this is the
    /// answer to it.
    ///
    /// It is a stamp rather than a flag because the instant is worth having and
    /// costs nothing extra in a `timestamptz` column, and because "first claim"
    /// is a fact with a time, not a boolean somebody flipped.
    ///
    /// **Stored, not derived.** The adapter used to compute it from the
    /// credentials that reference the grant, which is appealing — a flag can
    /// disagree with reality, and the credentials are reality — but there is
    /// one credential that leaves nothing behind to look at. A bare access
    /// token is a stateless JWT (RFC 9068) and nothing records that it was
    /// issued; the authorization code it came from is gone inside 60 seconds
    /// (FAPI 2.0 SP §5.3.2.1 item 11). A code-flow grant whose only live
    /// credential is
    /// such a token therefore has nothing pointing at it at all, and a
    /// derivation reads it as abandoned — so the sweep deletes the only row
    /// that could ever have revoked that token. See
    /// `PgGrantRepository::purge_unclaimed` in `asterius-store-pg`.
    pub claimed_at: Option<OffsetDateTime>,
}

impl Grant {
    /// The most scopes one grant may hold.
    ///
    /// The same bound registration uses. A grant's scopes are a subset of a
    /// client's, so a larger grant is either a bug or an attempt to make the
    /// `scope` claim of every access token enormous.
    pub const MAX_SCOPES: usize = 64;
    /// The longest a single scope token may be.
    pub const MAX_SCOPE_LEN: usize = 128;
    /// The most resource indicators one grant may be bound to.
    pub const MAX_RESOURCES: usize = 32;
    /// The most `claims_locales` tags one grant may carry.
    ///
    /// The same bound `asterius_oidc::claims::ClaimsLocales::MAX` applies at
    /// the authorization endpoint, restated here because a row is not written
    /// only by that path. Each tag costs a pass over the claim set for every
    /// claim resolved, on every issuance for the life of the grant.
    pub const MAX_CLAIMS_LOCALES: usize = 8;
    /// The longest single language tag a grant may carry.
    ///
    /// RFC 5646 §2.1 allows a primary subtag of 8 characters and a chain of
    /// subtags of 8; 35 covers every tag in the IANA registry with room to
    /// spare and refuses free text wearing a tag's shape.
    pub const MAX_LOCALE_LEN: usize = 35;
    /// The longest a `jti` handed to [`LiveAccessToken::new`] may be.
    ///
    /// It becomes half of a primary key in `access_token_denylist`; RFC 9068
    /// §2.2 requires a `jti` on every access token this server issues and
    /// `ast-a05.3` mints them at 128 bits, so anything approaching this bound
    /// did not come from here.
    pub const MAX_JTI_LEN: usize = 255;

    /// Creates a grant for `client`, minting its identifier.
    ///
    /// The identifier is drawn here and nowhere else. A grant id appears in the
    /// Grant Management resource URL (ID1 §6.3) and, by tenant option, as a
    /// claim in every access token, so it is a v4 UUID rather than anything a
    /// caller could pass in and accidentally make guessable or reused.
    ///
    /// Everything else is a public field: a grant is assembled from an
    /// authorization request, and a constructor with fourteen parameters would
    /// be a worse way to say so.
    #[must_use]
    pub fn new(tenant: TenantId, client: ClientId, created_at: OffsetDateTime) -> Self {
        Self {
            tenant,
            id: GrantId::new(Uuid::new_v4().to_string()),
            client,
            user: None,
            subject: None,
            scopes: BTreeSet::new(),
            claims: serde_json::Value::Object(serde_json::Map::new()),
            claims_locales: Vec::new(),
            authorization_details: Vec::new(),
            resources: BTreeSet::new(),
            actor_chain: Vec::new(),
            parent: None,
            session: None,
            authentication: None,
            created_at,
            updated_at: created_at,
            expires_at: None,
            claimed_at: None,
            revoked_at: None,
            revocation_reason: None,
        }
    }

    /// Where this grant is at `now`.
    ///
    /// The precedence is revoked, then expired, then claimed. Revocation wins
    /// over expiry because a revoked grant that lapsed afterwards is still a
    /// grant somebody withdrew, and an audit trail that forgets that has lost
    /// the more important of the two facts.
    #[must_use]
    pub fn status(&self, now: OffsetDateTime) -> GrantStatus {
        if self.revoked_at.is_some() {
            return GrantStatus::Revoked;
        }
        if self.expires_at.is_some_and(|expiry| expiry <= now) {
            return GrantStatus::Expired;
        }
        if self.claimed_at.is_some() {
            GrantStatus::Active
        } else {
            GrantStatus::Pending
        }
    }

    /// Takes the authority to mint one credential from this grant.
    ///
    /// This is the only constructor of [`ClaimedGrant`], and every issuance
    /// path takes a [`ClaimedGrant`] rather than a [`GrantId`]. So "issue a
    /// token with no grant" does not compile, and "issue a token from a revoked
    /// grant" does not run.
    ///
    /// # Errors
    ///
    /// [`GrantError::NotIssuable`] when the grant is revoked or expired.
    pub fn claim(&self, now: OffsetDateTime) -> Result<ClaimedGrant, GrantError> {
        let status = self.status(now);
        if !status.may_issue() {
            return Err(GrantError::NotIssuable(status));
        }
        Ok(ClaimedGrant {
            tenant: self.tenant.clone(),
            grant: self.id.clone(),
            client: self.client.clone(),
            subject: self.subject.clone(),
        })
    }
}

/// The authority to mint one credential, and the grant it is minted under.
///
/// The point of the type is what it makes impossible. Every issuance path —
/// authorization code, refresh, `client_credentials`, token exchange, device,
/// CIBA — takes one of these, so the `grant_id` written next to a credential is
/// not an argument a caller can leave out, pass `None` for, or invent. It can
/// only have come from [`Grant::claim`], which read a live grant.
///
/// Fields are private and there is no constructor, which is the enforcement.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub struct ClaimedGrant {
    tenant: TenantId,
    grant: GrantId,
    client: ClientId,
    subject: Option<SubjectId>,
}

impl ClaimedGrant {
    /// The tenant the credential belongs to.
    #[must_use]
    pub const fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    /// The grant the credential must record, so that revoking the grant reaches
    /// it.
    #[must_use]
    pub const fn id(&self) -> &GrantId {
        &self.grant
    }

    /// The client the credential is issued to.
    #[must_use]
    pub const fn client(&self) -> &ClientId {
        &self.client
    }

    /// The `sub` the credential carries, or `None` for `client_credentials`.
    #[must_use]
    pub const fn subject(&self) -> Option<&SubjectId> {
        self.subject.as_ref()
    }
}

// ---------------------------------------------------------------------------
// Access tokens caught by a cascade
// ---------------------------------------------------------------------------

/// An access token that is still within its `exp` when its grant is revoked.
///
/// Revoking a grant has to reach the access tokens already minted from it, and
/// a signed JWT cannot be recalled — so its `jti` goes on the denylist until
/// the moment it would have expired anyway. FAPI 2.0 SP §6.8 item 3 is the
/// trade this pays for: stateless tokens are cheap to verify and impossible to
/// withdraw, so the withdrawal has to be made stateful somewhere.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveAccessToken {
    jti: String,
    expires_at: OffsetDateTime,
}

impl LiveAccessToken {
    /// Records a live access token, checking that its `jti` can be stored.
    ///
    /// The `jti` becomes half of a primary key in a `text` column. A NUL byte
    /// in it makes PostgreSQL refuse the statement, which would abort the whole
    /// revocation transaction and leave a grant somebody asked to revoke still
    /// standing — a rejected write is a worse outcome here than anywhere else,
    /// because the caller's next move is to report success. An empty `jti`
    /// stores a row nothing can ever match.
    ///
    /// # Errors
    ///
    /// [`GrantError::Jti`] when the identifier is empty, longer than
    /// [`Grant::MAX_JTI_LEN`], or contains anything outside printable ASCII.
    // fuzz-target: grant_record
    pub fn new(jti: impl Into<String>, expires_at: OffsetDateTime) -> Result<Self, GrantError> {
        let jti = jti.into();
        if jti.is_empty() || jti.len() > Grant::MAX_JTI_LEN {
            return Err(GrantError::Jti);
        }
        if !jti.bytes().all(|byte| (0x21..=0x7e).contains(&byte)) {
            return Err(GrantError::Jti);
        }
        Ok(Self { jti, expires_at })
    }

    /// The identifier, as it goes onto the denylist.
    #[must_use]
    pub fn jti(&self) -> &str {
        &self.jti
    }

    /// When the token would have expired on its own, which is when the
    /// denylist row stops earning its keep.
    #[must_use]
    pub const fn expires_at(&self) -> OffsetDateTime {
        self.expires_at
    }
}

// ---------------------------------------------------------------------------
// The stored row
// ---------------------------------------------------------------------------

/// A `grants` row, before it is trusted.
///
/// Rows get edited by hand during incidents and written by seed scripts, and
/// three of this table's columns are `jsonb` and two are `text[]` — shapes the
/// database will hold whatever is put in them. So the guarantee has to come
/// from here, and it is the same guarantee the client repository makes: **a row
/// is validated by the same code on the way out as the values were on the way
/// in.**
///
/// The scope grammar is the case worth naming. A grant's scopes are joined with
/// spaces into the `scope` claim of an access token (RFC 9068 §2.2.3) and into
/// the `scope` member of a token response (RFC 6749 §5.1). A single stored
/// scope containing a space therefore *becomes two scopes* at the resource
/// server, which is a privilege escalation written with one keystroke in a
/// `psql` session. RFC 6749 §3.3's grammar is what makes that unrepresentable,
/// and it is checked on the way out because that is the direction the attack
/// travels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantRecord {
    /// `grant_id`.
    pub id: GrantId,
    /// `client_id`.
    pub client: ClientId,
    /// `user_id`.
    pub user: Option<UserId>,
    /// `subject`.
    pub subject: Option<String>,
    /// `scopes`.
    pub scopes: Vec<String>,
    /// `claims`.
    pub claims: serde_json::Value,
    /// `claims_locales`.
    pub claims_locales: Vec<String>,
    /// `authorization_details`.
    pub authorization_details: serde_json::Value,
    /// `resources`.
    pub resources: Vec<String>,
    /// `actor_chain`.
    pub actor_chain: serde_json::Value,
    /// `parent_grant_id`.
    pub parent: Option<GrantId>,
    /// `session_id`.
    pub session: Option<String>,
    /// `authenticated_at`.
    pub authenticated_at: Option<OffsetDateTime>,
    /// `acr`.
    pub acr: Option<String>,
    /// `amr`, as the RFC 8176 spellings the column holds.
    pub amr: Vec<String>,
    /// `created_at`.
    pub created_at: OffsetDateTime,
    /// `updated_at`.
    pub updated_at: OffsetDateTime,
    /// `expires_at`.
    pub expires_at: Option<OffsetDateTime>,
    /// `claimed_at`.
    pub claimed_at: Option<OffsetDateTime>,
    /// `revoked_at`.
    pub revoked_at: Option<OffsetDateTime>,
    /// `revocation_reason`.
    pub revocation_reason: Option<String>,
}

impl GrantRecord {
    /// Turns a row into a grant, or refuses it.
    ///
    /// # Errors
    ///
    /// A [`GrantError`] naming the first rule the row breaks. No variant
    /// carries a byte of the row.
    // fuzz-target: grant_record
    pub fn validate(self, tenant: &TenantId) -> Result<Grant, GrantError> {
        // A half-written revocation first: everything after this reads the row
        // as if it knows whether the grant is live, and it would not.
        let revocation_reason = match (self.revoked_at, self.revocation_reason.as_deref()) {
            (Some(_), Some(reason)) => {
                Some(RevocationReason::parse(reason).ok_or(GrantError::UnknownRevocationReason)?)
            }
            (None, None) => None,
            _ => return Err(GrantError::IncoherentRevocation),
        };

        if self
            .expires_at
            .is_some_and(|expiry| expiry <= self.created_at)
        {
            return Err(GrantError::ExpiryPrecedesCreation);
        }

        // The authentication next, for the same reason: `acr` and `amr`
        // describe an instant, and a row that names the one without the other
        // cannot be read as either "no authentication" or "this one".
        let authentication = match self.authenticated_at {
            Some(authenticated_at) => Some(GrantAuthentication {
                authenticated_at,
                acr: self.acr,
                // An unrecognised `amr` is dropped rather than failing the
                // load, exactly as `PgSessionRepository` does for the session
                // it was copied from: the label was written by some version of
                // this server, and refusing the row would break a refresh
                // during a rolling deployment. The two must agree, or the same
                // grant would be readable through one path and not the other.
                amr: self
                    .amr
                    .iter()
                    .filter_map(|value| AuthenticationMethod::parse(value))
                    .collect(),
            }),
            None if self.acr.is_none() && self.amr.is_empty() => None,
            None => return Err(GrantError::IncoherentAuthentication),
        };

        let scopes = validate_scopes(&self.scopes)?;
        let resources = validate_resources(&self.resources)?;

        if !self.claims.is_object() {
            return Err(GrantError::ClaimsShape);
        }
        validate_claims_locales(&self.claims_locales)?;
        let serde_json::Value::Array(authorization_details) = self.authorization_details else {
            return Err(GrantError::AuthorizationDetailsShape);
        };
        let serde_json::Value::Array(actor_chain) = self.actor_chain else {
            return Err(GrantError::ActorChainShape);
        };

        Ok(Grant {
            tenant: tenant.clone(),
            id: self.id,
            client: self.client,
            user: self.user,
            subject: self.subject.map(SubjectId::new),
            scopes,
            claims: self.claims,
            claims_locales: self.claims_locales,
            authorization_details,
            resources,
            actor_chain,
            parent: self.parent,
            session: self.session.map(SessionId::new),
            authentication,
            created_at: self.created_at,
            updated_at: self.updated_at,
            expires_at: self.expires_at,
            claimed_at: self.claimed_at,
            revoked_at: self.revoked_at,
            revocation_reason,
        })
    }
}

/// RFC 6749 §3.3: `scope = scope-token *( SP scope-token )`, where a
/// `scope-token` is `1*( %x21 / %x23-5B / %x5D-7E )` — printable ASCII other
/// than space, `"` and `\`.
///
/// The grammar is restated here rather than borrowed from
/// [`ClientMetadata`](crate::ClientMetadata) because the two are checking
/// different things at different boundaries: that one parses a space-delimited
/// string a client sent at registration, this one checks the already-split
/// array a row holds. A unit test asserts the two agree on every token, which
/// is what keeps a second implementation from becoming a second rule.
/// Whether one scope matches RFC 6749 §3.3's `scope-token` grammar.
///
/// `%x21 / %x23-5B / %x5D-7E`: printable ASCII other than space, `"` and `\`.
/// Public because the token builders check it again on the way *out*. That is
/// not a second rule — it is this one, called twice — and calling it rather
/// than restating it is the difference. The escalation it prevents is worth
/// two calls: `scope` is a space-delimited claim (RFC 9068 §2.2.3), so one
/// stored scope containing a space becomes *two scopes* at a resource server.
#[must_use]
pub fn is_scope_token(scope: &str) -> bool {
    scope
        .bytes()
        .all(|byte| matches!(byte, 0x21 | 0x23..=0x5b | 0x5d..=0x7e))
}

fn validate_scopes(scopes: &[String]) -> Result<BTreeSet<String>, GrantError> {
    if scopes.len() > Grant::MAX_SCOPES {
        return Err(GrantError::ScopeSize);
    }
    let mut validated = BTreeSet::new();
    for scope in scopes {
        if scope.is_empty() || scope.len() > Grant::MAX_SCOPE_LEN {
            return Err(GrantError::ScopeSize);
        }
        if !is_scope_token(scope) {
            return Err(GrantError::ScopeToken);
        }
        validated.insert(scope.clone());
    }
    Ok(validated)
}

/// RFC 8707 §2: a resource indicator "MUST be an absolute URI" and "MUST NOT
/// include a fragment component".
///
/// The value ends up in the `aud` of an access token, which is what a resource
/// server compares its own identifier against. A relative or fragment-bearing
/// audience is one that comparison can never match, so a token minted from such
/// a grant would be a token nothing accepts — and a `resource` that is not a
/// URI at all is a string somebody put there by hand.
fn validate_resources(resources: &[String]) -> Result<BTreeSet<String>, GrantError> {
    if resources.len() > Grant::MAX_RESOURCES {
        return Err(GrantError::ResourceSize);
    }
    let mut validated = BTreeSet::new();
    for resource in resources {
        let parsed = url::Url::parse(resource).map_err(|_| GrantError::Resource)?;
        if parsed.fragment().is_some() || parsed.cannot_be_a_base() {
            return Err(GrantError::Resource);
        }
        validated.insert(resource.clone());
    }
    Ok(validated)
}

/// OIDC Core §5.2 carries BCP 47 language tags, whose basic shape RFC 5646
/// §2.1 gives: alphanumeric subtags joined with `-`, the first alphabetic.
///
/// A shape check and not a registry lookup. What has to be true is that the
/// value cannot be arbitrary text — it is read back at every issuance and used
/// to select between the stored spellings of a claim — not that somebody
/// speaks it.
///
/// Refused rather than dropped, unlike at the authorization endpoint. The two
/// are different questions: a client that misspells a tag should get the
/// fallback instead of an error page, but a *row* holding a tag this server
/// would never have written is a row nothing should mint a token from.
fn validate_claims_locales(locales: &[String]) -> Result<(), GrantError> {
    if locales.len() > Grant::MAX_CLAIMS_LOCALES {
        return Err(GrantError::ClaimsLocale);
    }
    for tag in locales {
        if tag.len() > Grant::MAX_LOCALE_LEN {
            return Err(GrantError::ClaimsLocale);
        }
        let mut subtags = tag.split('-');
        let primary = subtags.next().unwrap_or_default();
        if !(1..=8).contains(&primary.len()) || !primary.bytes().all(|b| b.is_ascii_alphabetic()) {
            return Err(GrantError::ClaimsLocale);
        }
        if !subtags.all(|subtag| {
            (1..=8).contains(&subtag.len()) && subtag.bytes().all(|b| b.is_ascii_alphanumeric())
        }) {
            return Err(GrantError::ClaimsLocale);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Capabilities, ClientRegistration};
    use serde_json::json;
    use time::Duration;

    fn epoch() -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH
    }

    fn a_grant() -> Grant {
        Grant::new(TenantId::new("demo"), ClientId::new("billing"), epoch())
    }

    fn a_record() -> GrantRecord {
        GrantRecord {
            id: GrantId::new("2c1d4b1e-0000-4000-8000-000000000001"),
            client: ClientId::new("billing"),
            user: None,
            subject: Some("sub-1".to_owned()),
            scopes: vec!["openid".to_owned(), "payments".to_owned()],
            claims: json!({}),
            claims_locales: vec!["fr-CA".to_owned(), "fr".to_owned()],
            authorization_details: json!([]),
            resources: vec!["https://api.example/".to_owned()],
            actor_chain: json!([]),
            parent: None,
            session: None,
            authenticated_at: None,
            acr: None,
            amr: Vec::new(),
            created_at: epoch(),
            updated_at: epoch(),
            expires_at: None,
            claimed_at: None,
            revoked_at: None,
            revocation_reason: None,
        }
    }

    // --- the closed vocabularies -------------------------------------------

    /// A status outside the four must not resolve to a status at all: every
    /// default a reader could pick either mints tokens from a grant nobody
    /// vouched for, or silently cuts off a working integration.
    #[test]
    fn a_status_outside_the_four_does_not_parse() {
        for status in GrantStatus::ALL {
            assert_eq!(GrantStatus::parse(status.as_str()), Some(status));
            assert_eq!(status.to_string(), status.as_str());
        }
        for rejected in ["", "ACTIVE", "active ", "deleted", "consumed", "null", "0"] {
            assert_eq!(GrantStatus::parse(rejected), None, "accepted {rejected:?}");
        }
    }

    #[test]
    fn a_revocation_reason_outside_the_list_does_not_parse() {
        for reason in RevocationReason::ALL {
            assert_eq!(RevocationReason::parse(reason.as_str()), Some(reason));
            assert_eq!(reason.to_string(), reason.as_str());
        }
        for rejected in ["", "user", "revoked by user", "USER_REVOKED", "ticket-4711"] {
            assert_eq!(
                RevocationReason::parse(rejected),
                None,
                "accepted {rejected:?}"
            );
        }
    }

    // --- the state machine --------------------------------------------------

    /// The whole lifecycle in one table. Grant Management ID1 §5.6 gives
    /// `pending -> active`; the rest is what revocation and expiry mean.
    #[test]
    fn the_lifecycle_allows_exactly_these_transitions() {
        use GrantStatus::{Active, Expired, Pending, Revoked};
        let legal = [
            (Pending, Active),
            (Pending, Revoked),
            (Pending, Expired),
            (Active, Revoked),
            (Active, Expired),
            (Expired, Revoked),
        ];
        for from in GrantStatus::ALL {
            for to in GrantStatus::ALL {
                assert_eq!(
                    from.may_become(to),
                    legal.contains(&(from, to)),
                    "{from} -> {to}"
                );
            }
        }
    }

    /// The one the ticket names. A revocation something can undo is not a
    /// revocation, so `revoked` has no outgoing edge at all — not even to
    /// itself.
    #[test]
    fn a_revoked_grant_never_becomes_anything_else() {
        for to in GrantStatus::ALL {
            assert!(
                !GrantStatus::Revoked.may_become(to),
                "revoked -> {to} was allowed"
            );
        }
        assert!(!GrantStatus::Revoked.may_issue());
        assert!(!GrantStatus::Expired.may_issue());
        assert!(GrantStatus::Pending.may_issue());
        assert!(GrantStatus::Active.may_issue());
    }

    /// Status is a question about a moment, which is why it is a function of
    /// `now` and not a column. The same row is `active` at one instant and
    /// `expired` at the next, with nothing written in between.
    #[test]
    fn a_grant_expires_without_anybody_writing_a_row() {
        let mut grant = a_grant();
        grant.claimed_at = Some(epoch());
        grant.expires_at = Some(epoch() + Duration::minutes(10));

        assert_eq!(grant.status(epoch()), GrantStatus::Active);
        assert_eq!(
            grant.status(epoch() + Duration::minutes(9)),
            GrantStatus::Active
        );
        // At the instant of expiry, not after it: `exp` is exclusive.
        assert_eq!(
            grant.status(epoch() + Duration::minutes(10)),
            GrantStatus::Expired
        );
    }

    /// Grant Management ID1 §5.6: "a grant should be considered active when
    /// associated tokens have been successfully claimed by the client."
    #[test]
    fn a_grant_is_pending_until_a_credential_is_claimed_from_it() {
        let mut grant = a_grant();
        assert_eq!(grant.status(epoch()), GrantStatus::Pending);
        grant.claimed_at = Some(epoch());
        assert_eq!(grant.status(epoch()), GrantStatus::Active);
    }

    /// Revocation outranks expiry. A grant that was withdrawn and then lapsed
    /// is still a grant somebody withdrew, and that is the fact an
    /// investigation needs.
    #[test]
    fn revocation_outranks_expiry() {
        let mut grant = a_grant();
        grant.claimed_at = Some(epoch());
        grant.expires_at = Some(epoch() + Duration::minutes(1));
        grant.revoked_at = Some(epoch());
        grant.revocation_reason = Some(RevocationReason::UserRevoked);
        assert_eq!(
            grant.status(epoch() + Duration::hours(1)),
            GrantStatus::Revoked
        );
    }

    // --- the claim ----------------------------------------------------------

    /// The type-level half of "every token links to a revocable grant": the
    /// only way to obtain the authority to mint one is to read a live grant.
    #[test]
    fn a_claim_carries_the_grant_the_credential_must_record() {
        let mut grant = a_grant();
        grant.subject = Some(SubjectId::new("sub-1"));
        let claimed = grant.claim(epoch()).expect("a fresh grant is claimable");

        assert_eq!(claimed.id(), &grant.id);
        assert_eq!(claimed.client(), &grant.client);
        assert_eq!(claimed.tenant(), &grant.tenant);
        assert_eq!(claimed.subject(), Some(&SubjectId::new("sub-1")));
    }

    #[test]
    fn a_revoked_or_expired_grant_refuses_to_be_claimed() {
        let mut revoked = a_grant();
        revoked.revoked_at = Some(epoch());
        revoked.revocation_reason = Some(RevocationReason::UserRevoked);
        assert_eq!(
            revoked.claim(epoch()),
            Err(GrantError::NotIssuable(GrantStatus::Revoked))
        );

        let mut expired = a_grant();
        expired.expires_at = Some(epoch() + Duration::seconds(1));
        assert_eq!(
            expired.claim(epoch() + Duration::seconds(1)),
            Err(GrantError::NotIssuable(GrantStatus::Expired))
        );
        assert!(expired.claim(epoch()).is_ok(), "refused before its expiry");
    }

    /// A minted id is a v4 UUID, because the column is `uuid` and because a
    /// grant id appears in a Grant Management resource URL.
    #[test]
    fn a_minted_grant_id_is_a_fresh_uuid() {
        let first = a_grant();
        let second = a_grant();
        assert_ne!(first.id, second.id);
        let parsed = Uuid::parse_str(first.id.as_str()).expect("a minted id is a UUID");
        assert_eq!(parsed.get_version_num(), 4);
    }

    // --- the stored row -----------------------------------------------------

    #[test]
    fn a_well_formed_row_becomes_a_grant() {
        let grant = a_record()
            .validate(&TenantId::new("demo"))
            .expect("a well-formed row");
        assert_eq!(grant.tenant, TenantId::new("demo"));
        assert_eq!(grant.status(epoch()), GrantStatus::Pending);
        assert_eq!(
            grant.scopes.iter().map(String::as_str).collect::<Vec<_>>(),
            ["openid", "payments"]
        );
    }

    /// A row that cannot say whether the grant is revoked must not load, and
    /// "probably not" is the wrong guess: it would put a withdrawn
    /// authorization back to work.
    #[test]
    fn a_half_written_revocation_does_not_load() {
        let mut stamp_only = a_record();
        stamp_only.revoked_at = Some(epoch());
        assert_eq!(
            stamp_only.validate(&TenantId::new("demo")),
            Err(GrantError::IncoherentRevocation)
        );

        let mut reason_only = a_record();
        reason_only.revocation_reason = Some("user_revoked".to_owned());
        assert_eq!(
            reason_only.validate(&TenantId::new("demo")),
            Err(GrantError::IncoherentRevocation)
        );

        let mut unknown = a_record();
        unknown.revoked_at = Some(epoch());
        unknown.revocation_reason = Some("because I said so".to_owned());
        assert_eq!(
            unknown.validate(&TenantId::new("demo")),
            Err(GrantError::UnknownRevocationReason)
        );
    }

    /// The escalation this validator exists for: one stored scope containing a
    /// space becomes two scopes once it is joined into a `scope` claim.
    #[test]
    fn a_scope_that_would_split_in_a_token_is_refused() {
        for bad in [
            "payments accounts",
            "payments\taccounts",
            "pay\"ments",
            "pay\\ments",
            "payments\n",
            "",
            "pay ments",
            "\u{202e}stnemyap",
        ] {
            let mut record = a_record();
            record.scopes = vec![bad.to_owned()];
            assert!(
                record.validate(&TenantId::new("demo")).is_err(),
                "accepted the scope {bad:?}"
            );
        }

        let mut too_many = a_record();
        too_many.scopes = (0..=Grant::MAX_SCOPES).map(|i| format!("s{i}")).collect();
        assert_eq!(
            too_many.validate(&TenantId::new("demo")),
            Err(GrantError::ScopeSize)
        );

        let mut too_long = a_record();
        too_long.scopes = vec!["s".repeat(Grant::MAX_SCOPE_LEN + 1)];
        assert_eq!(
            too_long.validate(&TenantId::new("demo")),
            Err(GrantError::ScopeSize)
        );
    }

    /// Two implementations of one grammar are two rules waiting to disagree.
    /// This is the assertion that keeps them honest: registration and the grant
    /// row must accept exactly the same scope tokens.
    #[test]
    fn the_scope_grammar_agrees_with_the_one_registration_uses() {
        for candidate in [
            "openid",
            "payments",
            "urn:example:scope",
            "a",
            "~!#$%&'()*+,-./",
            "0123456789:;<=>?@",
            "[]^_`{|}",
            "openid payments",
            "open\"id",
            "open\\id",
            "open\tid",
            "",
        ] {
            let document = serde_json::to_vec(&json!({
                "client_name": "Billing",
                "redirect_uris": ["https://rp.example/cb"],
                "grant_types": ["authorization_code"],
                "scope": candidate,
                "jwks_uri": "https://rp.example/jwks",
            }))
            .expect("serialise");
            // Registration splits on the space, so a candidate containing one
            // is two valid tokens there and one invalid token here. Every other
            // difference would be a real disagreement.
            let registration_accepts =
                ClientRegistration::from_json(&document, Capabilities::default()).is_ok_and(
                    |client| client.scopes.len() == 1 && client.scopes.contains(candidate),
                );

            let mut record = a_record();
            record.scopes = vec![candidate.to_owned()];
            let grant_accepts = record.validate(&TenantId::new("demo")).is_ok();

            assert_eq!(
                registration_accepts, grant_accepts,
                "registration and the grant row disagree about the scope {candidate:?}"
            );
        }
    }

    /// RFC 8707 §2. A resource that is not an absolute, fragment-free URI is an
    /// `aud` no resource server can ever match.
    #[test]
    fn a_resource_that_is_not_an_absolute_uri_is_refused() {
        for bad in [
            "/api",
            "api.example",
            "https://api.example/#frag",
            "https://api.example#",
            "",
            "mailto:someone@example.com",
        ] {
            let mut record = a_record();
            record.resources = vec![bad.to_owned()];
            assert!(
                record.validate(&TenantId::new("demo")).is_err(),
                "accepted the resource {bad:?}"
            );
        }
        for good in ["https://api.example/", "https://api.example/v1?x=1"] {
            let mut record = a_record();
            record.resources = vec![good.to_owned()];
            assert!(
                record.validate(&TenantId::new("demo")).is_ok(),
                "refused the resource {good:?}"
            );
        }
    }

    /// The three `jsonb` columns the database enforces nothing about. An
    /// `authorization_details` that is a string would be copied straight into
    /// an access token as one (RFC 9396 §8.1).
    #[test]
    fn a_json_column_holding_the_wrong_shape_does_not_load() {
        type Break = fn(&mut GrantRecord);
        let cases: [(Break, GrantError); 6] = [
            (|r| r.claims = json!([]), GrantError::ClaimsShape),
            (|r| r.claims = json!("everything"), GrantError::ClaimsShape),
            (
                |r| r.authorization_details = json!({}),
                GrantError::AuthorizationDetailsShape,
            ),
            (
                |r| r.authorization_details = json!(null),
                GrantError::AuthorizationDetailsShape,
            ),
            (|r| r.actor_chain = json!({}), GrantError::ActorChainShape),
            (|r| r.actor_chain = json!(7), GrantError::ActorChainShape),
        ];
        for (break_it, expected) in cases {
            let mut record = a_record();
            break_it(&mut record);
            assert_eq!(record.validate(&TenantId::new("demo")), Err(expected));
        }
    }

    /// A stored language tag is read back at every issuance and used to pick
    /// between the stored spellings of a claim, so a row holding free text
    /// where a tag belongs is refused rather than carried.
    #[test]
    fn a_claims_locale_that_is_not_a_language_tag_does_not_load() {
        for bad in [
            "fr_CA",
            "-fr",
            "fr-",
            "1234",
            "français",
            "abcdefghi",
            "fr-abcdefghi",
        ] {
            let mut record = a_record();
            record.claims_locales = vec![bad.to_owned()];
            assert_eq!(
                record.validate(&TenantId::new("demo")),
                Err(GrantError::ClaimsLocale),
                "accepted the language tag {bad:?}"
            );
        }
    }

    /// The order is the meaning of the parameter (OIDC Core §5.2), so it is
    /// preserved exactly and not sorted or deduplicated on the way in.
    #[test]
    fn claims_locales_load_in_the_order_they_were_stored() {
        let mut record = a_record();
        record.claims_locales = vec!["ja-Kana-JP".to_owned(), "en-GB".to_owned(), "en".to_owned()];

        let grant = record.validate(&TenantId::new("demo")).expect("a grant");

        assert_eq!(grant.claims_locales, ["ja-Kana-JP", "en-GB", "en"]);
    }

    #[test]
    fn a_grant_that_ended_before_it_began_does_not_load() {
        let mut record = a_record();
        record.created_at = epoch() + Duration::hours(1);
        record.expires_at = Some(epoch());
        assert_eq!(
            record.validate(&TenantId::new("demo")),
            Err(GrantError::ExpiryPrecedesCreation)
        );
    }

    // --- the denylist entry -------------------------------------------------

    /// A `jti` that PostgreSQL refuses would abort the revocation transaction
    /// carrying it, so the check happens before the transaction opens.
    #[test]
    fn a_jti_that_could_not_be_stored_is_refused_before_the_transaction() {
        for bad in ["", "with space", "with\0nul", "with\nnewline", "café"] {
            assert_eq!(
                LiveAccessToken::new(bad, epoch()).err(),
                Some(GrantError::Jti),
                "accepted the jti {bad:?}"
            );
        }
        assert_eq!(
            LiveAccessToken::new("j".repeat(Grant::MAX_JTI_LEN + 1), epoch()).err(),
            Some(GrantError::Jti)
        );

        let token = LiveAccessToken::new("aBc-123_x.y~z", epoch()).expect("a base64url jti");
        assert_eq!(token.jti(), "aBc-123_x.y~z");
        assert_eq!(token.expires_at(), epoch());
    }

    // --- the authentication the grant carries (`ast-dlk`) -------------------

    /// The three columns are one fact, and they come back as one value: an
    /// `offline_access` grant is meant to outlive its session (OIDC Core §11),
    /// so this copy is the only `auth_time` left once the row is purged.
    #[test]
    fn a_stored_authentication_becomes_one_value() {
        let mut record = a_record();
        record.authenticated_at = Some(epoch());
        record.acr = Some("urn:asterius:acr:passkey-uv".to_owned());
        record.amr = vec!["swk".to_owned()];

        let grant = record
            .validate(&TenantId::new("demo"))
            .expect("a whole authentication");

        assert_eq!(
            grant.authentication,
            Some(GrantAuthentication {
                authenticated_at: epoch(),
                acr: Some("urn:asterius:acr:passkey-uv".to_owned()),
                amr: vec![AuthenticationMethod::Passkey],
            })
        );
    }

    /// A `client_credentials` grant (RFC 6749 §4.4) authenticates a client and
    /// not a person, so there is no authentication to record — and `None` is
    /// what the fallback reads as "this grant never had one".
    #[test]
    fn a_grant_with_no_authentication_carries_none() {
        let record = a_record();

        let grant = record
            .validate(&TenantId::new("demo"))
            .expect("a grant with no authentication");

        assert_eq!(grant.authentication, None);
    }

    /// An `acr` with no instant is a half-written authentication. OIDC Core §2
    /// makes `auth_time` the fact the context describes, so a token minted
    /// from such a row would assert a context with no time attached.
    #[test]
    fn an_acr_without_an_instant_is_refused() {
        let mut record = a_record();
        record.acr = Some("urn:asterius:acr:passkey-uv".to_owned());

        let error = record
            .validate(&TenantId::new("demo"))
            .expect_err("a half-written authentication");

        assert!(matches!(error, GrantError::IncoherentAuthentication));
    }

    /// An unrecognised `amr` label is dropped rather than failing the load,
    /// because `PgSessionRepository` does the same for the session this was
    /// copied from — and a refresh that failed on a label a newer version of
    /// this server wrote would break during a rolling deployment.
    #[test]
    fn an_unknown_amr_label_is_dropped_rather_than_refused() {
        let mut record = a_record();
        record.authenticated_at = Some(epoch());
        record.amr = vec!["pwd".to_owned(), "a-method-from-the-future".to_owned()];

        let grant = record
            .validate(&TenantId::new("demo"))
            .expect("an unfamiliar label does not fail the row");

        assert_eq!(
            grant.authentication.expect("an authentication").amr,
            vec![AuthenticationMethod::Password]
        );
    }
}
