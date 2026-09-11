//! Ports: the traits through which protocol code reaches the outside world.
//!
//! Adapters live in `asterius-store-pg`, `asterius-jose` and the server crate.
//! Protocol crates depend on these traits and never on an implementation.

use crate::audit::AuditEvent;
use crate::{
    ApplicationRole, AuthenticationMethod, AuthorizationDetailsType, Client, ClientId,
    ClientMetadataError, ClientRegistration, ClientStatus, CodeBinding, Consumed, DomainError,
    Enrolment, FirstPartyDestination, Grant, InitialAccessToken, InitialAccessTokenReservation,
    InteractionRecord, IssuedRecovery, Issuer, NewInitialAccessToken, NewPasskey, Participant,
    PushedRequest, RegisteredPasskey, ResourceServer, RoleName, RoleOwner, Secret,
    SectorIdentifier, Session, SessionRevocation, SubjectId, Tenant, TenantId, TenantSettings,
    Theme, User, UserId, entities::application_role::HeldRoles, entities::theme::ImageFormat,
};
use serde_json::Value;
use std::fmt::Debug;
use time::OffsetDateTime;
use uuid::Uuid;

/// Source of the current time.
///
/// Every expiry, `iat`/`exp` and lifetime check goes through a clock so that
/// tests can pin time instead of sleeping.
pub trait Clock: Debug + Send + Sync + 'static {
    /// The current instant, in UTC.
    fn now(&self) -> OffsetDateTime;
}

/// The real clock, backed by the operating system.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

// ---------------------------------------------------------------------------
// Repositories
// ---------------------------------------------------------------------------

/// Looks tenants up. The one repository that is not itself tenant-scoped —
/// something has to resolve a host or a path to a tenant before scoping is
/// possible.
#[async_trait::async_trait]
pub trait TenantRepository: Debug + Send + Sync {
    /// Finds a tenant by id.
    async fn find_by_id(&self, id: &TenantId) -> Result<Option<Tenant>, DomainError>;

    /// Finds a tenant by its canonical issuer.
    async fn find_by_issuer(&self, issuer: &Issuer) -> Result<Option<Tenant>, DomainError>;

    /// Finds a tenant by its vanity host.
    async fn find_by_host(&self, host: &str) -> Result<Option<Tenant>, DomainError>;

    /// Lists every tenant, ordered by id.
    async fn list(&self) -> Result<Vec<Tenant>, DomainError>;

    /// Creates or replaces a tenant.
    async fn upsert(&self, tenant: &Tenant) -> Result<(), DomainError>;

    /// Deletes a tenant and, by cascade, everything that belongs to it.
    async fn delete(&self, id: &TenantId) -> Result<(), DomainError>;
}

/// Reads and writes one tenant's settings.
///
/// Separate from [`TenantRepository`] rather than two more methods on it, and
/// for a reason that is not tidiness: the settings document is where a
/// FAPI-capped lifetime lives, so the write path has to be reachable *only*
/// with a [`crate::TenantSettings`] — a value that cannot exist without having
/// been through [`crate::TenantSettings::validated`]. A `settings: Value`
/// parameter beside the tenant row would accept anything an admin handler
/// happened to build.
#[async_trait::async_trait]
pub trait TenantSettingsRepository: Debug + Send + Sync {
    /// The settings of one tenant, or the defaults if it has never expressed
    /// an opinion.
    ///
    /// # Errors
    ///
    /// [`DomainError::Invalid`] for a stored document this build refuses —
    /// which is deliberate, see [`crate::TenantSettings::from_json`] — or a
    /// storage failure.
    async fn settings(&self, tenant: &TenantId) -> Result<TenantSettings, DomainError>;

    /// Replaces one tenant's settings.
    ///
    /// # Errors
    ///
    /// A storage failure, or [`DomainError::NotFound`] if no such tenant
    /// exists.
    async fn save(&self, tenant: &TenantId, settings: &TenantSettings) -> Result<(), DomainError>;
}

/// Reads and writes one tenant's design tokens and the images they name
/// (`ast-ndk.1`).
///
/// Its own port, and its own table, for two reasons the settings port does not
/// have. The first is size: a logo is a blob, and a blob in the `tenants` row
/// would be read by every request that resolves a tenant. The second is the
/// write path, which is the same argument [`TenantSettingsRepository`] makes:
/// the only way to reach `save` is with a [`crate::Theme`], which cannot exist
/// without having been through the schema, the palette contrast check and the
/// URL rules — and the only way to reach `store_asset` is with bytes some
/// adapter has already decoded and re-encoded.
///
/// # Assets are content-addressed and not deleted here
///
/// [`ThemeRepository::store_asset`] is keyed by the digest of the *stored*
/// bytes, so uploading the same logo twice is one row and the second upload is
/// idempotent. Nothing removes an asset a theme has stopped naming: an
/// administrator who reverts a logo change within the minute would otherwise
/// find the old one gone, and the table is bounded by the number of uploads a
/// tenant makes, not by traffic.
#[async_trait::async_trait]
pub trait ThemeRepository: Debug + Send + Sync {
    /// One tenant's theme, or the defaults if it has never set one.
    ///
    /// # Errors
    ///
    /// [`DomainError::Invalid`] for a stored document this build refuses —
    /// deliberately, like [`TenantSettingsRepository::settings`]: a palette
    /// that quietly reverted to the shipped default is a brand an
    /// administrator believes is in force and is not — or a storage failure.
    async fn theme(&self, tenant: &TenantId) -> Result<Theme, DomainError>;

    /// Replaces one tenant's theme.
    ///
    /// # Errors
    ///
    /// A storage failure, or [`DomainError::NotFound`] if no such tenant
    /// exists.
    async fn save_theme(&self, tenant: &TenantId, theme: &Theme) -> Result<(), DomainError>;

    /// Stores re-encoded image bytes under their own digest.
    ///
    /// The digest is the caller's, computed over the bytes it is storing, and
    /// the adapter does not recompute it: the one producer of both is the
    /// upload adapter, and a second hasher here would be a second thing to get
    /// wrong. What the adapter does guarantee is that a second call with the
    /// same digest changes nothing.
    ///
    /// # Errors
    ///
    /// A storage failure, or [`DomainError::NotFound`] for an unknown tenant.
    async fn store_asset(&self, tenant: &TenantId, asset: &StoredAsset) -> Result<(), DomainError>;

    /// The bytes of one asset, for the handler that serves it.
    ///
    /// Scoped to the tenant: a digest is guessable in the sense that anybody
    /// who has seen a logo knows it, and one tenant must not be able to serve
    /// another's asset by naming it.
    ///
    /// # Errors
    ///
    /// A storage failure. A digest nothing stored is `Ok(None)`, because a
    /// theme naming an asset that is gone is a page without a logo, not an
    /// error.
    async fn asset(
        &self,
        tenant: &TenantId,
        digest: &str,
    ) -> Result<Option<StoredAsset>, DomainError>;
}

/// An image this server decoded, re-encoded and stored.
///
/// The bytes are the *output* of a re-encoding, never an upload: nothing in
/// this workspace builds one of these from what arrived on a request, and the
/// only producer is `asterius_admin_api::theme_image`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredAsset {
    /// `sha-256` of [`StoredAsset::bytes`], in lowercase hex. Also the path
    /// segment the asset is served under.
    pub digest: String,
    /// What the bytes are, and what they are served as.
    pub format: ImageFormat,
    /// The re-encoded image.
    pub bytes: Vec<u8>,
}

/// One tenant's registered resource servers (RFC 8707).
///
/// Read on the request path — a pushed authorization request, and every token
/// request that names a `resource` — so the whole registry comes back in one
/// call and is matched in memory: a client may name several resources, and a
/// query each would make the number of round trips a property of the request
/// body.
#[async_trait::async_trait]
pub trait ResourceServerRepository: Debug + Send + Sync {
    /// Every resource server this tenant has registered, ordered by
    /// identifier.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the store cannot be reached, or
    /// [`DomainError::Invalid`] if a stored row is not a resource indicator —
    /// which is a row edited by hand, since the schema refuses one on the way
    /// in. A caller must not read either as "this tenant has registered
    /// nothing": that would refuse every token request during an outage while
    /// looking like a configuration change rather than a failure.
    async fn list(&self) -> Result<Vec<ResourceServer>, DomainError>;
}

/// One tenant's registered authorization details types (RFC 9396 §2.1).
///
/// The same shape as [`ResourceServerRepository`] and for the same reason: it
/// is read on the request path — every pushed authorization request that
/// carries `authorization_details`, and the metadata document that advertises
/// §9.1's `authorization_details_types_supported` — and one request may name
/// several types.
#[async_trait::async_trait]
pub trait AuthorizationDetailsTypeRepository: Debug + Send + Sync {
    /// Every type this tenant has registered, ordered by name.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the store cannot be reached, or
    /// [`DomainError::Invalid`] if a stored schema is not one this server can
    /// validate against. Neither may be read as "this tenant has registered
    /// nothing": that would turn an outage into what looks like a deliberate
    /// withdrawal of every type, and admit nothing while advertising nothing.
    async fn list(&self) -> Result<Vec<AuthorizationDetailsType>, DomainError>;
}

/// Something that can only be reached through a tenant.
///
/// Every repository except [`TenantRepository`] is obtained from a scope rather
/// than constructed directly, so there is no way to phrase a query that has not
/// already chosen a tenant. The tenant is not a parameter the caller might
/// forget; it is a precondition of holding the handle at all.
///
/// This is as close to a compile-time guarantee as Rust gets without
/// type-level tenants: it does not stop code from opening the *wrong* scope,
/// but it does stop code from opening *no* scope, which is the mistake that
/// actually happens — a `WHERE` clause missing a predicate in a hand-written
/// query.
pub trait TenantScoped {
    /// The tenant every operation on this handle is confined to.
    fn tenant(&self) -> &TenantId;
}

// ---------------------------------------------------------------------------
// Outbound fetches
// ---------------------------------------------------------------------------

/// Dereferences a URL that a *client* chose.
///
/// The only port whose input is attacker-controlled end to end: a `jwks_uri`, a
/// `sector_identifier_uri` (OIDC Registration §5) or the JWKS of a software
/// statement issuer is a string a client wrote into its own registration, and
/// an implementation of this trait is the server going and fetching it. RFC 7591 §5 raises the
/// general shape of the problem — an authorization server that dereferences a
/// URL from a registration document is doing work an attacker asked for, at an
/// address an attacker chose.
///
/// An implementation is therefore not merely an HTTP client. It is the boundary
/// that decides which addresses this process will ever connect to, how long it
/// will wait, and how many bytes it will read. `asterius_server::outbound` has
/// the one that ships, and states precisely what its guard does and does not
/// stop.
///
/// The port hands back a body and nothing else. Status codes, media types,
/// redirects and the size cap are HTTP's vocabulary and stay in the adapter:
/// protocol code above this line has no use for them, and a port that leaked
/// them would invite a second implementation to interpret them differently.
#[async_trait::async_trait]
pub trait ClientUrlFetcher: Debug + Send + Sync {
    /// Fetches the document at `url`.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Invalid`] when the URL is one this server refuses
    /// to dereference at all, and [`DomainError::Storage`] when the fetch was
    /// attempted and failed. A caller should treat both the same way — as "no
    /// keys, and do not ask again immediately" — because the difference is
    /// useful to an operator reading a log and to nobody else.
    async fn fetch(&self, url: &str) -> Result<Vec<u8>, DomainError>;
}

/// Remembers, across replicas and restarts, that fetching a `jwks_uri` failed.
///
/// The in-process negative cache in `asterius-jose`'s client key cache is
/// correct and it is per replica: N replicas each try an unreachable
/// third-party `jwks_uri` once per backoff window instead of once between them,
/// and a restart forgets the failure entirely. ADR-0001 expects more than one
/// replica, and ADR-0006 makes the treatment of client-supplied URLs a
/// *policy*; a policy whose rate depends on how many processes happen to be
/// running is not one. This port is where "do not fetch this URL again yet"
/// becomes a shared fact.
///
/// Keyed by `(tenant, client, jwks_uri)` rather than by client alone: a client
/// that re-registers with a different URL has not inherited the old URL's
/// outage, and one URL's failure says nothing about another's.
///
/// # What an implementation must not store
///
/// The URL itself is a client-supplied string that may carry a query parameter
/// the client considers a secret, and the error is a *reason*, never the
/// response body: a body is attacker-controlled bytes of arbitrary size, and a
/// database column is not where they belong. An implementation is expected to
/// key by a digest of the URL and to bound the error text.
///
/// # Failures here are advisory
///
/// A caller treats an error from this port as "nothing is known" and falls back
/// to its in-process state. The store being unreachable must not be the reason
/// a client cannot authenticate; the worst it can cost is the traffic this port
/// exists to suppress.
#[async_trait::async_trait]
pub trait ClientKeyFetchBackoff: Debug + Send + Sync {
    /// When the next fetch of `jwks_uri` for this client may be attempted, if
    /// a failure is on record.
    ///
    /// `None` means no failure is remembered — nothing here ever says "go ahead
    /// now", only "not before this instant".
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Storage`] if the store could not be reached.
    async fn next_attempt_at(
        &self,
        tenant: &TenantId,
        client: &ClientId,
        jwks_uri: &str,
    ) -> Result<Option<OffsetDateTime>, DomainError>;

    /// Records a failed fetch, and the instant before which no replica should
    /// try again.
    ///
    /// `error` is a short reason for an operator. Implementations bound it.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Storage`] if the store could not be reached.
    async fn record_failure(
        &self,
        tenant: &TenantId,
        client: &ClientId,
        jwks_uri: &str,
        error: &str,
        attempted_at: OffsetDateTime,
        next_attempt_at: OffsetDateTime,
    ) -> Result<(), DomainError>;

    /// Forgets any recorded failure for this client and URL.
    ///
    /// Called after a fetch succeeds: the backoff describes the last attempt,
    /// and the last attempt worked.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Storage`] if the store could not be reached.
    async fn clear(
        &self,
        tenant: &TenantId,
        client: &ClientId,
        jwks_uri: &str,
    ) -> Result<(), DomainError>;
}

/// Reads the clients of one tenant.
///
/// Tenant-scoped, like the repository that implements it: a `client_id` means
/// nothing outside its tenant, and a port that took the tenant as an argument
/// would be one more place for the wrong one to be passed.
#[async_trait::async_trait]
pub trait ClientRepository: Debug + Send + Sync {
    /// Finds a client by id, or `None` if this tenant has no such client.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Storage`] if the store could not be reached.
    /// A caller must not treat that as `None`: "the database is down" and
    /// "no such client" are the same to a client and must not be the same
    /// here, because one of them is a reason to stop.
    async fn find(&self, client_id: &ClientId) -> Result<Option<Client>, DomainError>;
}

/// Creates the clients of one tenant.
///
/// Separate from [`ClientRepository`] rather than a method on it, because the
/// two have different readerships: every protocol endpoint reads clients, and
/// exactly one — dynamic client registration (`ast-m9c.4`) — creates them.
/// Folding creation into the port that PAR and the token endpoint hold would
/// hand a write capability to code that has no business having one, and would
/// make every test double for a read-only endpoint implement a write it never
/// calls.
#[async_trait::async_trait]
pub trait ClientRegistry: Debug + Send + Sync {
    /// Stores a newly registered client and the digest of the registration
    /// access token that will manage it.
    ///
    /// Creation, never replacement: a caller that reached here has just minted
    /// an unguessable `client_id`, so a row already under that id is a
    /// collision and not an update. Silently overwriting would let a repeat of
    /// the same call retire a live client's keys and redirect URIs.
    ///
    /// `registration_access_token` is the SHA-256 digest of the token, never
    /// the token: see [`crate::credentials`] for why the bare digest is the
    /// right at-rest form for a value with this much entropy, and why storing
    /// the token itself would put a bearer credential in every backup.
    ///
    /// Returns the client **as stored**. RFC 7591 §3.2.1 requires the response
    /// to carry the metadata the server actually registered — including values
    /// it defaulted or replaced — so the caller renders its response from what
    /// comes back here rather than from what it sent, and cannot describe a
    /// client that does not exist.
    ///
    /// # The trail entry is an argument, not a later call (`ast-zq9`)
    ///
    /// `audit` is the `client.registered` record for this registration, and an
    /// implementation must commit it with the row or commit neither. The
    /// endpoint that calls this is reachable without a client credential, and
    /// it used to append the record after the row had committed: a crash or an
    /// audit-store failure in that window left a live client — with redirect
    /// URIs and a registration access token — that the trail never mentions,
    /// and the request still had to return 201 because the only copy of that
    /// token was already gone. Making the record a parameter removes the
    /// window instead of choosing which half of it to lose: there is no call a
    /// caller can forget and no moment in which one half exists without the
    /// other.
    ///
    /// A failure to write the record is therefore a failure to register, and
    /// the client learns the registration did not happen — which is true,
    /// because nothing was kept.
    ///
    /// # Errors
    ///
    /// [`DomainError::Conflict`] if the `client_id` is already taken, or if the
    /// tenant does not exist. [`DomainError::Invalid`] if the entity belongs to
    /// another tenant, if `audit` is another tenant's record, or if the store
    /// refuses either write. [`DomainError::Storage`] otherwise. In every case
    /// neither the client nor the record was kept.
    async fn register(
        &self,
        client: &Client,
        registration_access_token: &[u8; 32],
        audit: &AuditEvent,
    ) -> Result<Client, DomainError>;
}

/// Records that a client authenticated (`ast-cu3`).
///
/// Its own port and not a method on [`ClientRepository`], for the reason
/// [`ClientRegistry`] is separate: every protocol endpoint reads clients, and
/// folding a write into that port would hand a write capability to code that
/// has no business having one and would make every read-only test double
/// implement a write it never calls.
///
/// There is one caller — the client authenticator, which both the token
/// endpoint and PAR go through — so "when was this client last used" has one
/// definition and cannot drift between two endpoints that both authenticate.
#[async_trait::async_trait]
pub trait ClientUsageRecorder: Debug + Send + Sync {
    /// Notes that `client_id` authenticated at `now`.
    ///
    /// Implementations may coarsen: this is read by a retention sweep whose
    /// unit is days, so an adapter that writes at most once an hour per client
    /// is honouring the contract and is keeping a write off the hot path. What
    /// an implementation must not do is move the recorded instant *backwards*.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the store could not be reached. The caller
    /// logs it and proceeds: a client that has authenticated must not be
    /// refused because a bookkeeping write failed, and the consequence of a
    /// lost write is at worst one sweep considering a live client idle — which
    /// is why the sweep's window is days rather than minutes.
    async fn record_use(
        &self,
        tenant: &TenantId,
        client_id: &ClientId,
        now: OffsetDateTime,
    ) -> Result<(), DomainError>;
}

/// The initial access tokens of one tenant (`ast-cu3`).
///
/// Two readerships that must not be one method: the admin API issues and lists
/// (`ast-f7m.5`'s console), and `POST /register` spends. Spending is
/// [`Self::reserve`] followed by exactly one of [`Self::release`] or nothing,
/// which is why there is no `redeem` that both checks and charges: a
/// registration refused after admission — a malformed document, a policy
/// violation, an unreachable `sector_identifier_uri` — must not consume a
/// client's quota, and a quota checked before the write and charged after it
/// is a quota two concurrent requests can both pass.
///
/// The digest is the SHA-256 of the presented token and never the token: see
/// [`crate::credentials`].
#[async_trait::async_trait]
pub trait InitialAccessTokenStore: Debug + Send + Sync {
    /// Stores a newly minted token and returns the row as stored.
    ///
    /// # Errors
    ///
    /// [`DomainError::Conflict`] if the tenant does not exist or the digest is
    /// already stored, [`DomainError::Storage`] otherwise.
    async fn issue(&self, token: &NewInitialAccessToken)
    -> Result<InitialAccessToken, DomainError>;

    /// Charges one use against the token with this digest, atomically.
    ///
    /// Atomically is the whole contract: the check and the increment are one
    /// statement, so two requests presenting the last use of a token cannot
    /// both be admitted. A caller that does not go on to register a client
    /// must call [`Self::release`].
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the store could not be reached. "No such
    /// token" is [`InitialAccessTokenReservation::Unknown`] and not an error:
    /// it is the ordinary answer to a caller presenting a wrong credential.
    async fn reserve(
        &self,
        tenant: &TenantId,
        digest: &[u8; 32],
        now: OffsetDateTime,
    ) -> Result<InitialAccessTokenReservation, DomainError>;

    /// Gives back a use charged by [`Self::reserve`].
    ///
    /// Saturating at zero, so that a release with no matching reservation
    /// cannot mint quota. Takes the row id rather than the digest, because the
    /// caller holding a reservation has one and holding the digest again would
    /// mean holding the credential longer than the admission decision needs
    /// it.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the store could not be reached. A row that
    /// has since been deleted is not an error: there is nothing to give back.
    async fn release(&self, tenant: &TenantId, id: Uuid) -> Result<(), DomainError>;

    /// Every token of this tenant, newest first, without digests.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the store could not be reached.
    async fn list(&self, tenant: &TenantId) -> Result<Vec<InitialAccessToken>, DomainError>;
}

/// What the RFC 7592 client configuration endpoint needs before it acts.
///
/// Deliberately not the client. Authenticating a management request needs two
/// cheap columns — the digest of the registration access token and whether the
/// client is suspended — and neither of them is metadata. Reading the whole
/// registration first would put the endpoint's authentication decision behind
/// [`ClientMetadata::validate`], so a client whose stored row no longer
/// satisfies today's profile (an operator turned mTLS off; a column was edited
/// by hand) could not authenticate — and therefore could not use the one
/// endpoint that exists to fix or remove it. Failing that way round is worse
/// than not checking, because the record stays and nobody can reach it.
///
/// [`ClientMetadata::validate`]: crate::ClientMetadata::validate
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedClient {
    /// SHA-256 of the registration access token that manages this client, or
    /// `None` if it has none.
    ///
    /// `None` is not "any token will do": it is a client that was never issued
    /// a configuration endpoint at all — one created by the admin API or a seed
    /// script rather than by RFC 7591 registration. OIDC Registration §3.2 says
    /// an implementation "MUST either return both a Client Configuration
    /// Endpoint and a Registration Access Token or neither of them", so such a
    /// client has neither, and every management request for it is refused.
    ///
    /// The digest, never the token: see [`crate::credentials`].
    pub registration_access_token: Option<[u8; 32]>,
    /// The token this client's current one replaced, while its grace window
    /// lasts (`ast-m9c.12`).
    ///
    /// `None` almost always: it exists only between a rotation and the earlier
    /// of the window's end and the first use of the successor.
    pub previous_registration_access_token: Option<PreviousRegistrationAccessToken>,
    /// Whether the client is serving or suspended.
    pub status: ClientStatus,
    /// The agent profile the row carries (`ast-lh3.1`), or `None` for a client
    /// that is not an agent.
    ///
    /// Here, and not only on the [`Client`] the repository rebuilds, because
    /// RFC 7592 §2.2's update is judged against it *before* anything is
    /// written: an agent's limits are the tenant's and a client rewriting its
    /// own metadata cannot leave them. The endpoint that refuses has to answer
    /// `400 invalid_client_metadata`, which means it needs the limits in hand
    /// while it still holds the document — not a storage error afterwards.
    pub agent: Option<crate::AgentProfile>,
}

/// A registration access token that has been rotated out but is still accepted.
///
/// The answer to the one problem RFC 7592 §5's rotation "MAY" creates for a
/// server that issues no client secret: the response carrying the new token can
/// be lost, and a client that never saw it would be locked out of its own
/// registration for good with no way back. For a bounded window after a
/// rotation, the predecessor still authenticates, so the client's retry
/// succeeds and is handed the new token again.
///
/// The window is **cover for a lost response, not a period of coexistence**,
/// and the difference is enforced rather than documented: the first request
/// authenticated by the successor retires this immediately, because at that
/// moment the client has demonstrably received the new token and the old one is
/// a spare key with no purpose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PreviousRegistrationAccessToken {
    /// SHA-256 of the rotated-out token. The digest, never the token.
    pub digest: [u8; 32],
    /// When it stops being accepted, whatever else happens.
    ///
    /// Always set: a predecessor with no end is a second permanent credential,
    /// which is worse than the lockout the grace exists to prevent.
    pub grace_expires_at: OffsetDateTime,
}

impl PreviousRegistrationAccessToken {
    /// Whether the grace window is still open at `now`.
    ///
    /// Exclusive at the far end — a token whose window ends exactly now is
    /// refused — so that "expired" and "not yet expired" cannot both be true of
    /// the same instant.
    #[must_use]
    pub fn is_within_grace(&self, now: OffsetDateTime) -> bool {
        now < self.grace_expires_at
    }
}

/// Reads and writes one client's own registration (RFC 7592).
///
/// Separate from both [`ClientRepository`] and [`ClientRegistry`], and narrower
/// than either would be with these methods bolted on. Exactly one caller holds
/// it — the client configuration endpoint — and it is the only code in the
/// server that may replace or delete a client on the client's own say-so. A
/// `replace` on the read port would hand that capability to PAR and the token
/// endpoint; a `deprovision` on the registration port would hand it to
/// `POST /register`.
#[async_trait::async_trait]
pub trait ClientConfiguration: Debug + Send + Sync {
    /// What is needed to decide whether a management request may proceed.
    ///
    /// Returns `None` when this tenant has no such client. The caller must not
    /// turn that into a 404: OIDC Registration §4.4 says endpoints "MUST NOT
    /// return the HTTP 404 Not Found status code" for exactly this case,
    /// because the answer would enumerate registrations.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the store could not be reached. A caller
    /// must not treat that as `None`: "the database is down" and "no such
    /// client" are the same to a caller and must not be the same here.
    async fn managed(&self, client_id: &ClientId) -> Result<Option<ManagedClient>, DomainError>;

    /// Replaces a client's registration metadata wholesale (RFC 7592 §2.2).
    ///
    /// A replacement, never a merge. §2.2 is explicit: "Valid values of client
    /// metadata fields in this request MUST replace, not augment, the values
    /// previously associated with this client. Omitted fields MUST be treated
    /// as null or empty values by the server". An implementation that read the
    /// stored row and filled in what the document left out would keep a client
    /// on redirect URIs it asked to drop, which is the security bug this rule
    /// exists to prevent.
    ///
    /// What is *not* in the registration document is not the client's to
    /// change and must survive untouched: the registration access token, the
    /// per-client resource allow-list (`ast-m9c.6`), the agent profile
    /// (`ast-lh3.1`), the software statement, the status and the creation time.
    /// RFC 7592 §2.2 makes the same point about `client_secret` — a client
    /// "MUST NOT be allowed to overwrite its existing client secret with its
    /// own chosen value".
    ///
    /// Returns the client **as stored**, for the same reason
    /// [`ClientRegistry::register`] does: RFC 7592 §3 requires the response to
    /// carry "all registered metadata about this client, including any fields
    /// provisioned by the authorization server itself".
    ///
    /// # Errors
    ///
    /// [`DomainError::NotFound`] if the client vanished between the
    /// authentication and the write. [`DomainError::Invalid`] if the entity
    /// belongs to another tenant or the stored row does not validate.
    /// [`DomainError::Storage`] otherwise.
    async fn replace(&self, client: &Client) -> Result<Client, DomainError>;

    /// Deprovisions a client (RFC 7592 §2.3).
    ///
    /// A real delete. §2.3 says a successful delete "will invalidate the
    /// `client_id`, `client_secret`, and `registration_access_token` for this
    /// client, thereby preventing the `client_id` from being used at either the
    /// authorization endpoint or token endpoint", and §5 makes the token part a
    /// MUST: "If a client is deprovisioned from a server, any outstanding
    /// registration access token for that client MUST be invalidated at the
    /// same time." Removing the row does all of that at once, and leaves no
    /// state in which authentication succeeds but the action cannot.
    ///
    /// `now` is what makes §2.3's SHOULD about "currently active access
    /// tokens" answerable. Those are signed JWTs this server does not hold, so
    /// no cascade can reach them; what the implementation writes instead is a
    /// cutoff at `now`, and the resource path refuses any access token of this
    /// client issued before it (`ast-m9c.13`). It is the caller's clock
    /// reading rather than the database's so that the audit event and the
    /// cutoff cannot disagree about when the client was deprovisioned.
    ///
    /// # Errors
    ///
    /// [`DomainError::NotFound`] if no such client exists in this tenant, or a
    /// storage error.
    async fn deprovision(
        &self,
        client_id: &ClientId,
        now: OffsetDateTime,
    ) -> Result<(), DomainError>;

    /// Burns a registration access token wherever in this tenant it is held.
    ///
    /// The credential-side counterpart of [`Self::managed`]: that one asks
    /// "what does this `client_id` hold", this one asks "who holds this
    /// digest", and the answer is thrown away rather than returned. RFC 7592
    /// §2.1, §2.2 and §2.3 each say a registration access token presented for a
    /// client that does not exist "SHOULD be immediately revoked", so a token
    /// that turns up at the wrong configuration URL stops working everywhere,
    /// including at the URL where it would have worked.
    ///
    /// **Returns nothing on purpose.** Whether a row was hit is the one fact
    /// the caller must not learn: OIDC Registration §4.4 requires the refusal
    /// for "no such client" and for "the token is invalid" to be the same
    /// answer, and a `bool` here is a value a future branch could be written
    /// against. An implementation that wants to record the difference does so
    /// in its own logs, where the requester cannot read it.
    ///
    /// Scoped to the tenant like every other method on this port, and that is
    /// load-bearing rather than incidental: a digest presented at one tenant
    /// must not be able to revoke another tenant's credential.
    ///
    /// Implementations must resolve the digest by index. A caller reaches this
    /// on an unauthenticated request, so a scan would make the revocation
    /// itself the denial-of-service.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the store could not be reached. A caller has
    /// already decided to refuse by the time it gets here, so the failure is
    /// worth logging and must not change the answer.
    async fn revoke_registration_access_token(&self, digest: &[u8; 32]) -> Result<(), DomainError>;

    /// Issues a new registration access token and demotes the current one
    /// (`ast-m9c.12`, RFC 7592 §5).
    ///
    /// One statement, and it has to be: the digest the client will authenticate
    /// with next and the digest it may still authenticate with in the meantime
    /// are two columns of one row, and a caller that could observe them
    /// half-written could observe a client with no credential at all.
    ///
    /// The demotion is unconditional. Whatever the row held before — including
    /// a predecessor from an earlier rotation whose window had not closed —
    /// becomes exactly one predecessor, expiring at `grace_expires_at`. A
    /// client cannot accumulate live credentials by updating itself in a loop,
    /// which is what a scheme that kept every generation would allow.
    ///
    /// # Errors
    ///
    /// [`DomainError::NotFound`] if the client vanished between the
    /// authentication and the write, so that a caller never tells a client its
    /// token was replaced on a row that is not there. [`DomainError::Storage`]
    /// otherwise.
    async fn rotate_registration_access_token(
        &self,
        client_id: &ClientId,
        digest: &[u8; 32],
        grace_expires_at: OffsetDateTime,
    ) -> Result<(), DomainError>;

    /// Drops a client's rotated-out registration access token now.
    ///
    /// Called the moment a request authenticates with the *successor*: at that
    /// point the client has provably received the new token, so the window's
    /// remaining seconds protect nothing and keeping the predecessor alive
    /// would only widen the time in which a copy of it is worth stealing. This
    /// is what makes the grace cover for a lost response rather than a period
    /// in which a client has two credentials.
    ///
    /// Idempotent, and not an error when there is nothing to retire: it runs on
    /// every authenticated request, and a client that has never rotated is the
    /// ordinary case.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the store could not be reached. Never
    /// `NotFound`.
    async fn retire_previous_registration_access_token(
        &self,
        client_id: &ClientId,
    ) -> Result<(), DomainError>;
}

/// The clients of a deployment, as an administrator manages them.
///
/// A fourth client port beside [`ClientRepository`], [`ClientRegistry`] and
/// [`ClientConfiguration`], and the reason is readership again: those three are
/// held by protocol endpoints acting on a *client's* say-so, and this one is
/// held by the admin API acting on an administrator's. Folding "list every
/// client in this tenant" onto the port the token endpoint holds would hand an
/// enumeration capability to code that authenticates one client at a time.
///
/// # It takes the tenant as an argument
///
/// Unlike the other three, which are opened on a tenant scope. The admin API
/// holds one handle for the process (`asterius_admin_api::AdminBackend`) and
/// passes the tenant the request was routed to, exactly as
/// [`crate::keys::KeyAdministration`] does. Opening the scope stays in the
/// composition root, which is one place rather than one per handler.
///
/// # What it deliberately cannot do
///
/// There is no `delete`. RFC 7592 §2.3 deprovisioning is the client's own act
/// and has its own port; an administrator taking a client out of service
/// suspends it instead — [`ClientStatus::Disabled`] through [`Self::replace`]
/// — which stops it authenticating while leaving the grants and the audit rows
/// that name it attached to something that still exists.
#[async_trait::async_trait]
pub trait ClientAdministration: Debug + Send + Sync {
    /// Every client in `tenant`, ordered by `client_id`.
    ///
    /// # Errors
    ///
    /// [`DomainError::Invalid`] if a stored row no longer describes a client
    /// this profile accepts — which an administrator has to be told about,
    /// because the console is where it would be fixed — or a storage failure.
    async fn list(&self, tenant: &TenantId) -> Result<Vec<Client>, DomainError>;

    /// One client, or `None` if this tenant has no such client.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the store could not be reached, which a
    /// caller must not treat as `None`.
    async fn find(
        &self,
        tenant: &TenantId,
        client_id: &ClientId,
    ) -> Result<Option<Client>, DomainError>;

    /// Stores a client an administrator created, and returns it **as stored**.
    ///
    /// No registration access token is issued and none is stored: OIDC
    /// Registration §3.2 requires an implementation to "return both a Client
    /// Configuration Endpoint and a Registration Access Token or neither of
    /// them", and a client created here has neither — it is managed from the
    /// console, and [`ManagedClient::registration_access_token`] being `None`
    /// is what refuses every RFC 7592 request for it.
    ///
    /// Returned as stored, for the reason [`ClientRegistry::register`] gives:
    /// this profile provisions several fields the caller did not send, and a
    /// console that rendered its own request back would show an administrator a
    /// client that does not exist.
    ///
    /// # Errors
    ///
    /// [`DomainError::Conflict`] if the `client_id` is taken or the tenant does
    /// not exist, [`DomainError::Invalid`] if the entity belongs to another
    /// tenant, or a storage failure.
    async fn create(&self, client: &Client) -> Result<Client, DomainError>;

    /// Replaces a client's registration wholesale, and returns it as stored.
    ///
    /// A replacement and not a merge, for the reason RFC 7592 §2.2 makes its
    /// update one: a form that filled in what an administrator deleted would
    /// leave a client on redirect URIs somebody has just removed.
    ///
    /// # Errors
    ///
    /// [`DomainError::NotFound`] if the client vanished between the read and
    /// the write, [`DomainError::Invalid`] if the entity belongs to another
    /// tenant, or a storage failure.
    async fn replace(&self, client: &Client) -> Result<Client, DomainError>;

    /// Verifies a `sector_identifier_uri` (OIDC Registration §5), through the
    /// deployment's one outbound path.
    ///
    /// On this port rather than left to the caller, because the caller is the
    /// admin API and it may not hold an HTTP client: ADR-0006 gives this
    /// deployment exactly one place that dereferences a URL somebody else
    /// wrote, and a second one built for the console would be a second SSRF
    /// guard to keep in step. An implementation is expected to call the same
    /// function `POST /register` calls, so that a document the console accepts
    /// is a document dynamic registration would accept.
    ///
    /// # Errors
    ///
    /// [`ClientMetadataError`] carrying the RFC 7591 §3.2.2 code the
    /// registration endpoint would have answered with.
    async fn verify_sector(
        &self,
        registration: &ClientRegistration,
    ) -> Result<(), ClientMetadataError>;
}

/// Stores pushed authorization requests for one tenant.
///
/// Tenant-scoped, like the other repositories: a `request_uri` issued by one
/// tenant means nothing at another, and a port that took the tenant as an
/// argument would be one more place to pass the wrong one.
#[async_trait::async_trait]
pub trait AuthRequestRepository: Debug + Send + Sync {
    /// Stores a validated request.
    ///
    /// # Errors
    ///
    /// [`DomainError::Conflict`] if the digest already exists — which, at 256
    /// bits of entropy, means something is wrong with the generator rather
    /// than that a collision occurred. [`DomainError::Storage`] otherwise.
    async fn push(&self, request: &PushedRequest) -> Result<(), DomainError>;

    /// Spends a reference, if it is live.
    ///
    /// Must be atomic. FAPI 2.0 SP §5.3.2.2 Note 3 puts one-time use at the
    /// *completion* of authorization, not at page load, so two tabs that both
    /// reach the consent screen are fine and two that both submit are not —
    /// and the second must lose. A read followed by a write would let both
    /// win, which is the whole attack.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the store could not be reached. Never
    /// treat that as [`Consumed::NotFound`].
    async fn consume(&self, digest: &str, now: OffsetDateTime) -> Result<Consumed, DomainError>;

    /// Reads a reference without spending it.
    ///
    /// For rendering the consent screen, which may happen more than once.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the store could not be reached.
    async fn peek(
        &self,
        digest: &str,
        now: OffsetDateTime,
    ) -> Result<Option<PushedRequest>, DomainError>;
}

/// The same rows, reached by the browser's credential.
///
/// A separate port from [`AuthRequestRepository`] because it has a separate
/// caller. The client holds the `request_uri` and talks to the PAR and token
/// endpoints; the browser holds the interaction id and talks to the
/// interaction pages. Neither credential is derivable from the other, and
/// neither caller has any business reaching the other's operations — a PAR
/// handler that could destroy an interaction, or an interaction page that
/// could consume a `request_uri`, is a confusion waiting to be written.
///
/// One adapter implements both, because it is one table. That is a fact about
/// the storage, not about the callers.
#[async_trait::async_trait]
pub trait InteractionRepository: Debug + Send + Sync {
    /// Gives a pushed request a second identity: the browser's.
    ///
    /// Called once, by `/authorize`, when a user agent arrives with a
    /// `request_uri`. After this the row can be found by either credential —
    /// the client's `request_uri` or the browser's interaction id — and
    /// neither is derivable from the other.
    ///
    /// # Errors
    ///
    /// [`DomainError::NotFound`] if the request is gone or already consumed,
    /// and [`DomainError::Conflict`] if it already has an interaction: a
    /// second `/authorize` on one `request_uri` is a replay, not a retry, and
    /// re-keying the row would hand the second browser the first one's flow.
    async fn begin_interaction(
        &self,
        request_uri_digest: &str,
        interaction_digest: &str,
        now: OffsetDateTime,
    ) -> Result<(), DomainError>;

    /// Finds an interaction by the browser's credential.
    ///
    /// Returns `None` for absent, expired and already-consumed alike: the
    /// difference is a fact for the log, and a browser that could tell them
    /// apart could probe for live interactions.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the store could not be reached.
    async fn by_interaction(
        &self,
        interaction_digest: &str,
        now: OffsetDateTime,
    ) -> Result<Option<InteractionRecord>, DomainError>;

    /// Records progress through the interaction.
    ///
    /// # Errors
    ///
    /// [`DomainError::NotFound`] if the interaction is gone, expired or
    /// consumed — progress must not resurrect one.
    async fn save_interaction_state(
        &self,
        interaction_digest: &str,
        state: &Value,
        session: Option<&str>,
        now: OffsetDateTime,
    ) -> Result<(), DomainError>;

    /// Spends the request, at the moment an authorization response is about to
    /// be sent.
    ///
    /// This is where FAPI 2.0 SP §5.3.2.2 Note 3's one-time use actually
    /// happens. Not at page load — a user who reloads the consent screen has
    /// done nothing wrong — but here, at *completion*, which is the only point
    /// where spending it prevents anything. Two tabs that both reach the
    /// consent screen are fine; two that both submit must produce one
    /// authorization response, and this is the statement that decides which.
    ///
    /// Must be atomic for the same reason [`AuthRequestRepository::consume`]
    /// must be: a read followed by a write lets both tabs win, and both
    /// winning means two codes minted from one authorization.
    ///
    /// # Errors
    ///
    /// [`DomainError::NotFound`] when there was nothing live to spend —
    /// already completed, expired, or gone. A caller must treat that as "some
    /// other request completed this one" and must not send an authorization
    /// response of its own.
    async fn complete_interaction(
        &self,
        interaction_digest: &str,
        now: OffsetDateTime,
    ) -> Result<(), DomainError>;

    /// Destroys an interaction and the request behind it.
    ///
    /// Used when the id in the path and the id in the cookie disagree. That is
    /// not a recoverable error: somebody is being deceived and this server
    /// cannot tell which party, so the flow ends for both rather than
    /// continuing for whichever one asked last.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the delete fails. Absent is not an error —
    /// destroying something already gone is the outcome that was wanted.
    async fn destroy_interaction(&self, interaction_digest: &str) -> Result<(), DomainError>;

    /// Opens an interaction that has no client behind it (ADR-0009).
    ///
    /// The first-party surface — today the admin console — needs a session,
    /// and a session is what the login flow produces. So it opens an
    /// interaction of its own rather than an authorization: no `request_uri`,
    /// no client, no scopes, and a destination that is a
    /// [`FirstPartyDestination`] variant rather than anything a request
    /// carried.
    ///
    /// # Errors
    ///
    /// [`DomainError::Conflict`] if the id is already in use, which at 256
    /// bits means the generator is broken. [`DomainError::Storage`] otherwise.
    async fn begin_first_party_interaction(
        &self,
        interaction_digest: &str,
        destination: FirstPartyDestination,
        expires_at: OffsetDateTime,
        now: OffsetDateTime,
    ) -> Result<(), DomainError>;
}

/// Verifies a user's credential.
///
/// One implementation per method — a password today, a passkey next — so the
/// interaction handler dispatches rather than branching on a `kind` column.
///
/// # Why it returns a user rather than a session
///
/// Creating the session is the *handler's* job, because that is where the
/// cookie is set and where the rotation happens. A verifier that returned a
/// session would be deciding a browser concern from inside the credential
/// store.
#[async_trait::async_trait]
pub trait CredentialVerifier: Debug + Send + Sync {
    /// Checks `password` for `username`, returning the user on success.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the store could not be reached. A *wrong*
    /// credential is `Ok(None)`: it is an ordinary outcome, and conflating it
    /// with an outage turns every database blip into "your password is wrong".
    ///
    /// # Timing
    ///
    /// An implementation must take the same time whether the user exists or
    /// not. A verifier that returns early for an unknown username is an
    /// account-enumeration oracle that no amount of identical error text will
    /// hide.
    async fn verify(
        &self,
        username: &str,
        password: Secret<String>,
    ) -> Result<Option<uuid::Uuid>, DomainError>;
}

/// Reads an account back by its identifier.
///
/// Deliberately one method. A page that has authenticated somebody through a
/// session cookie holds a [`UserId`] and needs the account behind it — to name
/// the person on screen, and to refuse a credential to an account that is no
/// longer allowed to authenticate. That is not enough to justify exposing the
/// whole user repository through a port, and the display-name question proper
/// (`preferred_username`, locales, claims) is `ast-2vk.8`.
#[async_trait::async_trait]
pub trait UserDirectory: Debug + Send + Sync {
    /// The account, or `None` if this tenant has no such user.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the read fails.
    async fn by_id(&self, id: UserId) -> Result<Option<User>, DomainError>;
}

/// Outstanding passkey enrolments and the credentials they produce.
///
/// One port rather than two because the challenge and the credential are the
/// two ends of a single ceremony, and a handler that could reach one without
/// the other could spend a challenge with nowhere to put the result.
///
/// # Why the challenge is stored rather than signed
///
/// A self-contained, signed challenge would need no table, and it would also
/// have no way to be *spent*. Single use is the property that matters most
/// here (WebAuthn L3 §13.4.3), and single use is a row that can be deleted.
#[async_trait::async_trait]
pub trait PasskeyRepository: Debug + Send + Sync {
    /// Opens — or reopens — the enrolment belonging to `session`.
    ///
    /// Called when the page is rendered. A second call replaces the first,
    /// including any challenge it had outstanding: the page a user is looking
    /// at is the one whose token works.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the write fails, or
    /// [`DomainError::NotFound`] if the session is not one this tenant has.
    async fn open_enrolment(
        &self,
        session_digest: &str,
        csrf_digest: &str,
        expires_at: OffsetDateTime,
    ) -> Result<(), DomainError>;

    /// Attaches a freshly drawn challenge to an unexpired enrolment.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the write fails. A missing or expired
    /// enrolment is `Ok(false)`, which is an ordinary outcome: the page was
    /// left open.
    async fn issue_challenge(
        &self,
        session_digest: &str,
        challenge: &[u8],
        expires_at: OffsetDateTime,
        now: OffsetDateTime,
    ) -> Result<bool, DomainError>;

    /// Reads the enrolment for `session`, if it has not expired.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the read fails.
    async fn enrolment(
        &self,
        session_digest: &str,
        now: OffsetDateTime,
    ) -> Result<Option<Enrolment>, DomainError>;

    /// Takes the outstanding challenge and removes it in the same statement.
    ///
    /// The whole point of this method: an implementation that read and then
    /// deleted would let two concurrent finishes both succeed against one
    /// challenge, which is the replay the challenge exists to prevent.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the statement fails. No outstanding
    /// challenge is `Ok(None)`.
    async fn spend_challenge(
        &self,
        session_digest: &str,
        now: OffsetDateTime,
    ) -> Result<Option<Vec<u8>>, DomainError>;

    /// Stores a verified credential and returns the id of its row.
    ///
    /// # Errors
    ///
    /// [`DomainError::Conflict`] if this credential id is already registered
    /// **anywhere in the tenant** — the unique index is what decides that, not
    /// a prior read, because a prior read races. [`DomainError::Storage`]
    /// otherwise.
    async fn register(&self, passkey: &NewPasskey) -> Result<uuid::Uuid, DomainError>;

    /// Attaches a freshly drawn authentication challenge to an interaction.
    ///
    /// Bound to the interaction rather than to a session, because at this
    /// point in a login there is no session: the browser holds an interaction
    /// id, the server holds its digest, and that pair is the only thing that
    /// says these two requests are the same visitor. The same binding the
    /// synchroniser token already has.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the write fails. An interaction that has
    /// expired or been consumed is `Ok(false)`.
    async fn issue_assertion_challenge(
        &self,
        interaction_digest: &str,
        challenge: &[u8],
        expires_at: OffsetDateTime,
        now: OffsetDateTime,
    ) -> Result<bool, DomainError>;

    /// Takes the outstanding authentication challenge and clears it in the
    /// same statement.
    ///
    /// Single use, and for a sharper reason than at enrolment: a replayed
    /// assertion is a sign-in as somebody else, not a duplicate credential.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the statement fails. No outstanding
    /// challenge is `Ok(None)`.
    async fn spend_assertion_challenge(
        &self,
        interaction_digest: &str,
        now: OffsetDateTime,
    ) -> Result<Option<Vec<u8>>, DomainError>;

    /// Finds a credential by the id an assertion named.
    ///
    /// Tenant-wide, because a discoverable credential arrives with no
    /// username: the credential id *is* the identification, and the user it
    /// belongs to is what this answers. Disabled credentials are not found —
    /// a credential blocked for a counter regression must not sign anybody in
    /// on the next attempt.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the read fails.
    async fn by_credential_id(
        &self,
        credential_id: &[u8],
    ) -> Result<Option<RegisteredPasskey>, DomainError>;

    /// Records an accepted assertion against a credential.
    ///
    /// `sign_count` is `None` for an authenticator that does not count
    /// (WebAuthn L3 §6.1.1), which must leave the stored zero alone rather
    /// than writing one that would look like progress.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the write fails.
    async fn record_assertion(
        &self,
        credential: uuid::Uuid,
        sign_count: Option<u32>,
        now: OffsetDateTime,
    ) -> Result<(), DomainError>;

    /// Blocks a credential, and says when.
    ///
    /// The policy half of §7.2 step 21: a counter that went backwards is a
    /// signal that the credential exists in two places, and one of them is not
    /// the user's. Blocking is a decision about a credential whose private key
    /// demonstrably signed a fresh challenge, so it is not something an
    /// attacker without that key can provoke.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the write fails.
    async fn disable(&self, credential: uuid::Uuid, now: OffsetDateTime)
    -> Result<(), DomainError>;

    /// The credential ids this user already has, for `excludeCredentials`.
    ///
    /// A courtesy rather than a control: it stops an authenticator offering to
    /// make a second credential for an account it already holds one for. The
    /// enforcement is the unique index.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the read fails.
    async fn credential_ids(&self, user: &UserId) -> Result<Vec<Vec<u8>>, DomainError>;
}

/// Server-side sessions for one tenant.
#[async_trait::async_trait]
pub trait SessionRepository: Debug + Send + Sync {
    /// Writes a new session.
    ///
    /// # Errors
    ///
    /// [`DomainError::Conflict`] if the digest already exists, which at 256
    /// bits means a broken generator rather than bad luck.
    async fn begin(&self, session: &Session) -> Result<(), DomainError>;

    /// Loads a session by the digest of its id.
    ///
    /// Returns the row whatever state it is in — expiry and revocation are
    /// [`Session::status`]'s job, and a caller that needs to *report* why a
    /// session is unusable needs the row to ask.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the store could not be reached.
    async fn find(&self, id_digest: &str) -> Result<Option<Session>, DomainError>;

    /// Moves the idle deadline forward.
    ///
    /// # Errors
    ///
    /// [`DomainError::NotFound`] if the session is gone, expired or revoked —
    /// touching must not resurrect one.
    async fn touch(
        &self,
        id_digest: &str,
        now: OffsetDateTime,
        idle: time::Duration,
    ) -> Result<(), DomainError>;

    /// Replaces a session's id with a fresh one, atomically.
    ///
    /// This is the session-fixation defence, and it has to be one statement:
    /// two, and there is an instant where both ids work, or neither does. The
    /// old digest stops resolving the moment this returns.
    ///
    /// `authenticated_at` moves too, because the reason to rotate is always
    /// that the user has just proved something.
    ///
    /// `methods` and `acr` are what the session is worth *after* the thing that
    /// was just proved — the caller composes them, because only it knows
    /// whether this was a step-up onto an existing authentication (`ast-2vk.7`,
    /// where the methods accumulate) or a re-proof of the same one. `acr` is
    /// `None` for a tenant whose ladder has no rung for what happened, and it
    /// overwrites: a rotation that left a stale `acr` behind would report an
    /// authentication context the current `amr` no longer supports.
    ///
    /// # Errors
    ///
    /// [`DomainError::NotFound`] if the old session is not there to rotate.
    async fn rotate(
        &self,
        old_digest: &str,
        new_digest: &str,
        methods: &[AuthenticationMethod],
        acr: Option<&str>,
        now: OffsetDateTime,
    ) -> Result<(), DomainError>;

    /// Ends one session.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the store could not be reached. Revoking an
    /// already-revoked session keeps the first reason: the first answer to
    /// "why was I signed out" is the true one.
    async fn revoke(
        &self,
        id_digest: &str,
        reason: SessionRevocation,
        now: OffsetDateTime,
    ) -> Result<(), DomainError>;

    /// Ends every session a user has.
    ///
    /// Returns how many were ended. Used when a credential changes, when an
    /// account closes, and by an administrator.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the store could not be reached.
    async fn revoke_all_for_user(
        &self,
        user: uuid::Uuid,
        reason: SessionRevocation,
        now: OffsetDateTime,
    ) -> Result<u64, DomainError>;

    /// Records that a client took part in a session.
    ///
    /// Called when an ID token is issued. Back-channel logout needs the list.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the store could not be reached.
    async fn record_participant(
        &self,
        id_digest: &str,
        client: &ClientId,
        now: OffsetDateTime,
    ) -> Result<(), DomainError>;

    /// Every client that took part.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the store could not be reached.
    async fn participants(&self, id_digest: &str) -> Result<Vec<Participant>, DomainError>;
}

/// Recording a completed authorization, and reading back what earlier ones
/// recorded.
///
/// Two methods, and the second is not a widening of the first: claiming,
/// revoking and the Grant Management queries stay on the concrete adapter,
/// where the token endpoint and the dashboard reach them. What the
/// authorization endpoint needs is to write one grant and to *read what this
/// person has already agreed to* — because a server that cannot read that has
/// no consent memory, must show the screen every time, and can never answer a
/// satisfiable `prompt=none` request silently (`asterius_oidc::consent_memory`).
#[async_trait::async_trait]
pub trait GrantRepository: Debug + Send + Sync {
    /// Writes a new grant.
    ///
    /// # Errors
    ///
    /// [`DomainError::Invalid`] when the grant belongs to another tenant, and
    /// [`DomainError::Storage`] otherwise.
    async fn create(&self, grant: &Grant) -> Result<(), DomainError>;

    /// Every grant this tenant holds for `subject`, revoked ones included.
    ///
    /// Unfiltered on purpose. Which grants count as a standing agreement is a
    /// consent rule — not revoked, not expired, the right client — and
    /// `asterius_oidc::consent_memory::Remembered::of_client` is where that
    /// rule lives, with a test per clause. Expressing it as a `where` clause
    /// here would put it in SQL, where nothing that reads it can be tested
    /// without a database and where "revoked grants are excluded" is a fact
    /// about a query rather than about consent.
    ///
    /// # Errors
    ///
    /// [`DomainError::Invalid`] when a stored row is not one the grant model
    /// accepts, and [`DomainError::Storage`] otherwise.
    async fn for_subject(&self, subject: &SubjectId) -> Result<Vec<Grant>, DomainError>;
}

/// Amending a grant a client already holds — Grant Management ID1 §5.2.
///
/// # Why this is not two more methods on [`GrantRepository`]
///
/// Because it is an Implementer's Draft. The two operations here exist only for
/// `grant_management_action`, they are reachable only when
/// [`crate::Feature::GrantManagement`] is on, and the draft that defines them is
/// still moving. A separate port means the flag switches a *capability* off
/// rather than leaving dead methods on the trait every consent path implements,
/// and it means a change to the draft cannot reach the handlers that only ever
/// create grants.
#[async_trait::async_trait]
pub trait GrantAmendments: Debug + Send + Sync {
    /// The grant a `grant_id` names, if this tenant holds one.
    ///
    /// `None` is "this tenant has no such grant", which is what the endpoint
    /// reports as `invalid_grant_id` (§5.4). Whether the grant belongs to the
    /// client that asked, and to the person who signed in, is the caller's to
    /// decide — those are protocol rules and they live in
    /// `asterius_oidc::grant_management`.
    ///
    /// # Errors
    ///
    /// [`DomainError::Invalid`] when the id is not one this store could hold or
    /// the stored row is not one the grant model accepts, and
    /// [`DomainError::Storage`] otherwise. Never `Ok(None)` because the store
    /// was unreachable: "we cannot tell" must not be spelled like "no such
    /// grant", or an outage looks to a client like its grant was withdrawn.
    async fn find(&self, id: &crate::GrantId) -> Result<Option<Grant>, DomainError>;

    /// Writes the amended permissions and invalidates what the grant has
    /// already paid for.
    ///
    /// §5.2: `merge` and `replace` "shall invalidate existing refresh tokens".
    /// One operation and not two, because the two halves must not be able to
    /// commit apart: a grant whose scopes were widened while the old refresh
    /// token still lives is a token that can be exchanged for the *new*
    /// authorization without anyone having asked for it, and a grant whose
    /// tokens were revoked while the write failed is a client locked out of an
    /// authorization it still holds.
    ///
    /// The access tokens already minted from the grant are withdrawn by the
    /// same mechanism revocation uses — a cutoff instant for the grant, not a
    /// second path — because they are stateless JWTs (RFC 9068) and cannot be
    /// listed. `ast-m9c.13` is where that mechanism lives.
    ///
    /// # Errors
    ///
    /// [`DomainError::NotFound`] when this tenant has no such live grant,
    /// [`DomainError::Invalid`] when the grant belongs to another tenant, and
    /// [`DomainError::Storage`] otherwise — in which case nothing was written
    /// and nothing was revoked.
    async fn amend(&self, grant: &Grant, now: OffsetDateTime) -> Result<(), DomainError>;
}

/// Issuing an authorization code — and nothing else.
///
/// Split from redemption for the same reason [`InteractionRepository`] is
/// split from [`AuthRequestRepository`]: two callers, two credentials, and
/// neither has any business reaching the other's operation. The authorization
/// endpoint talks to a browser and mints codes; the token endpoint talks to an
/// authenticated client and spends them. An issuing handler that *could* spend
/// a code is a confusion waiting to be written, and one adapter implements
/// both because it is one table — a fact about the storage, not the callers.
#[async_trait::async_trait]
pub trait CodeIssuer: Debug + Send + Sync {
    /// Stores a freshly minted code under the digest of its value.
    ///
    /// # Errors
    ///
    /// [`DomainError::Conflict`] if the digest exists, which at 256 bits means
    /// the generator is broken rather than that a collision occurred.
    /// [`DomainError::Storage`] otherwise.
    async fn issue(
        &self,
        digest: &str,
        binding: &CodeBinding,
        now: OffsetDateTime,
    ) -> Result<(), DomainError>;
}

/// Withdrawing the long-lived credentials issued under one browser session.
///
/// A port of one method, held by the end-session endpoint, because the *policy*
/// is the tenant's (`TenantSettings::revoke_refresh_on_logout`) and the
/// *statement* is the adapter's. Keeping them apart is what lets the logout
/// handler be tested without a database and the SQL be tested without a
/// handler.
///
/// Not part of the session repository: ending a session and withdrawing a grant
/// are two decisions, and a deployment that has not chosen the second must not
/// be one edit away from making it.
#[async_trait::async_trait]
pub trait SessionCredentials: Debug + Send + Sync {
    /// Revokes every refresh token issued under a grant of this session, and
    /// withdraws the access tokens those grants minted (RFC 7009 §2.1).
    ///
    /// `session` is the session's lookup identifier — the one grants reference
    /// — not the `public_sid` a logout token carries.
    ///
    /// Returns how many refresh tokens were revoked. Zero is an ordinary
    /// answer, not a failure.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if nothing could be written. Nothing was: the
    /// tokens stay live, which is visible, rather than being reported as a
    /// withdrawal that did not happen.
    async fn revoke_refresh_for_session(
        &self,
        session: &str,
        now: OffsetDateTime,
    ) -> Result<u64, DomainError>;
}

/// The `sub` one client sees for one user.
///
/// A port rather than a function because the answer is *stored*: OIDC Core §8
/// makes a Subject Identifier "locally unique and never reassigned", so the
/// first derivation is the one that counts and every later call must return
/// it, not recompute it. That makes this a lookup with a write behind it, and
/// therefore an adapter's job.
#[async_trait::async_trait]
pub trait SubjectResolver: Debug + Send + Sync {
    /// The identifier `user` is known by in `sector`, minting it on first use.
    ///
    /// # Errors
    ///
    /// [`DomainError::Invalid`] when the tenant has no pairwise salt — a
    /// refusal to mint, never a fallback to a default one, because a `sub`
    /// derived under a predictable salt is both re-derivable by anyone who
    /// knows the algorithm and impossible to withdraw once a relying party has
    /// it. [`DomainError::Conflict`] when the derived value is already held by
    /// somebody else, and [`DomainError::NotFound`] when the user is gone.
    async fn subject(
        &self,
        user: UserId,
        sector: &SectorIdentifier,
    ) -> Result<SubjectId, DomainError>;
}

/// What a `jti` is being remembered for.
///
/// A closed vocabulary, matching the `purpose` check constraint on the
/// `jti_replay` table. Two token types share the table and must not share a
/// namespace: a DPoP proof and a client assertion that happened to choose the
/// same `jti` are unrelated events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReplayPurpose {
    /// A `private_key_jwt` client assertion (OIDC Core §9, RFC 7523 §3).
    ClientAssertion,
    /// A DPoP proof (RFC 9449 §4.3).
    DpopProof,
    /// An `Idempotency-Key` presented at a `POST` on the admin API.
    ///
    /// The same question — "has this identifier been used before, atomically,
    /// across replicas?" — so the same port rather than a second table with
    /// its own race. Namespaced by the administrator who chose the value, for
    /// the reason the `subject` argument documents: a shared namespace would
    /// let one administrator burn another's keys.
    AdminIdempotency,
}

impl ReplayPurpose {
    /// The stored spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ClientAssertion => "client_assertion",
            Self::DpopProof => "dpop_proof",
            Self::AdminIdempotency => "admin_idempotency",
        }
    }
}

/// Whether a single-use identifier had been seen before.
///
/// An enum rather than a `bool` on purpose. The caller's next move is to
/// authenticate someone or refuse them, and `if !seen` versus `if seen` is a
/// one-character edit between those two outcomes. A named variant has to be
/// read to be written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum ReplayCheck {
    /// Not seen before. The identifier is now recorded.
    FirstUse,
    /// Already recorded within its validity window.
    Replay,
}

/// Enforces single use of a `jti`.
///
/// RFC 7523 §3 item 7 makes `jti` the mechanism for detecting a replayed
/// assertion, and FAPI 2.0's attacker model (A1, a client whose credential has
/// leaked; A3a, an attacker who can read a request in flight) is exactly the
/// case it defends: an assertion is a bearer credential, and anything that
/// obtains one has until `exp` to use it.
///
/// # Why this is a port
///
/// Because it must be shared. A per-process cache would let *n* replicas each
/// accept the same assertion once, which is not single use — it is single use
/// per replica, a distinction an attacker gets to choose the value of.
#[async_trait::async_trait]
pub trait ReplayGuard: Debug + Send + Sync {
    /// Records `jti` and reports whether this is its first use.
    ///
    /// Must be atomic: two concurrent requests carrying the same `jti` must
    /// see exactly one [`ReplayCheck::FirstUse`] between them. A read followed
    /// by a write is not sufficient — that is the race an attacker replaying a
    /// captured assertion is trying to win.
    ///
    /// `subject` namespaces the identifier to whoever chose it — the
    /// `client_id` for a client assertion, the key thumbprint for a DPoP
    /// proof. RFC 7523 §3 item 7 scopes uniqueness to the issuer, and a shared
    /// namespace would let one client burn `jti` values for every other.
    ///
    /// Entries may be dropped once `expires_at` has passed: after that the
    /// token fails on `exp` and the row stops earning its keep.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Storage`] if the store could not be reached. A
    /// caller must treat that as a failure to authenticate, never as
    /// [`ReplayCheck::FirstUse`] — an unavailable replay store is not
    /// permission to accept a replay.
    async fn claim(
        &self,
        tenant: &TenantId,
        purpose: ReplayPurpose,
        subject: &str,
        jti: &str,
        expires_at: OffsetDateTime,
    ) -> Result<ReplayCheck, DomainError>;
}

/// The single-use tokens an account recovery is carried by.
///
/// # Why `spend` is one method and not a read plus a delete
///
/// Single use is the entire security of the mechanism, and single use is a
/// property of one statement. A store that read the row, let the handler check
/// it, and deleted it afterwards would give two requests arriving together two
/// successful resets from one mailed link — which is exactly what somebody who
/// obtained the link once, and races the real owner, wants.
///
/// # Why the store never returns the token
///
/// It never has it. Rows hold [`crate::RecoveryToken::digest`] and callers
/// look up by digest, so a database copy contains no usable reset link
/// (NIST SP 800-63B §5.1.1.2 on storing authenticator secrets; OWASP's Forgot
/// Password Cheat Sheet says the same about reset tokens).
#[async_trait::async_trait]
pub trait RecoveryTokenStore: Debug + Send + Sync {
    /// Writes a freshly drawn token and invalidates every earlier one for the
    /// same user, in one statement.
    ///
    /// Invalidating the earlier ones is not tidiness. A person who clicks
    /// "send me a link" three times has three live account takeovers sitting
    /// in a mailbox, and the two they did not use are the two nobody will
    /// notice being used. The newest link is the one that works.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the write fails.
    async fn issue(&self, issued: &IssuedRecovery) -> Result<(), DomainError>;

    /// Consumes the token behind `digest`, returning whose account it resets.
    ///
    /// Atomic, and it is the only place expiry is enforced against a clock the
    /// caller does not control. `Ok(None)` covers every ordinary refusal —
    /// unknown, already spent, expired, invalidated by a credential change —
    /// as one answer, because a browser that could tell them apart could probe
    /// for live reset links.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the statement fails.
    async fn spend(&self, digest: &str, now: OffsetDateTime)
    -> Result<Option<UserId>, DomainError>;

    /// Whose account this token resets, without spending it.
    ///
    /// For rendering the page a link leads to: it names the account so that
    /// somebody holding an old link, or two accounts, can see which one they
    /// are about to change. It applies the same expiry predicate as
    /// [`Self::spend`] so that a dead link produces an error page instead of a
    /// form that will fail after the person has typed a password twice.
    ///
    /// This is not a weaker `spend` and must never be used in its place: a
    /// handler that peeked, decided, and then wrote would have reintroduced
    /// exactly the two-statement race `spend` exists to close. Nothing here
    /// is an oracle — the caller already holds a 256-bit token, so learning
    /// whether *that* token is live tells them nothing they could not learn by
    /// submitting the form.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the read fails.
    async fn peek(&self, digest: &str, now: OffsetDateTime) -> Result<Option<UserId>, DomainError>;

    /// Invalidates every outstanding token for one user.
    ///
    /// Called when a credential changes by any route — a reset that completed,
    /// a password changed from a signed-in session, an administrator. A live
    /// reset link that survives the change it was meant to cause is a way back
    /// in for whoever prompted it.
    ///
    /// Returns how many were invalidated, for the trail.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the write fails.
    async fn invalidate_for_user(
        &self,
        user: UserId,
        now: OffsetDateTime,
    ) -> Result<u64, DomainError>;
}

// ---------------------------------------------------------------------------
// Application roles
// ---------------------------------------------------------------------------

/// The catalogues of application roles, and who holds what (`ast-095`).
///
/// Deployment-wide rather than tenant-scoped, with `tenant` on every method,
/// following [`crate::UserAdministration`]: the admin API holds one handle and
/// the tenant it acts on is the one the request resolved to, so a handler
/// cannot be given a repository bound to the wrong tenant by construction of
/// the wiring.
///
/// **This is not [`crate::Role`].** Nothing on this port can grant authority
/// over this server; every name it carries is a [`RoleName`], which the
/// administrative vocabulary is not.
#[async_trait::async_trait]
pub trait ApplicationRoleDirectory: Debug + Send + Sync {
    /// Adds a role to a catalogue.
    ///
    /// Returns `false` if a role of that name is already defined there, which
    /// is not an error: the catalogue ends in the state the caller asked for.
    /// The description of an existing role is *not* overwritten, so a repeated
    /// create cannot quietly rewrite what somebody documented.
    ///
    /// # Errors
    ///
    /// [`DomainError::Conflict`] if the role names a client that does not
    /// exist, [`DomainError::Storage`] otherwise.
    async fn define(&self, role: &ApplicationRole) -> Result<bool, DomainError>;

    /// One catalogue, ordered by name.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the read fails, or [`DomainError::Invalid`]
    /// for a stored name this build's parser refuses — a row from a newer
    /// schema, which must not be silently dropped from a list an administrator
    /// is about to act on.
    async fn catalogue(
        &self,
        tenant: &TenantId,
        owner: &RoleOwner,
    ) -> Result<Vec<ApplicationRole>, DomainError>;

    /// Removes a role from a catalogue.
    ///
    /// Returns `false` if there was nothing to remove.
    ///
    /// # Errors
    ///
    /// [`DomainError::Conflict`] if somebody still holds it — the schema
    /// refuses the delete rather than cascading it; see
    /// `0023_application_roles.sql` for why that direction was chosen.
    /// [`DomainError::Storage`] otherwise.
    async fn remove(
        &self,
        tenant: &TenantId,
        owner: &RoleOwner,
        name: &RoleName,
    ) -> Result<bool, DomainError>;

    /// Gives `user` a role from a catalogue.
    ///
    /// Returns `false` if they already held it. A role that is not in the
    /// catalogue is a [`DomainError::Conflict`] and not a silent creation:
    /// assignment must never be a way to invent a name that ends up in a
    /// token.
    ///
    /// # Errors
    ///
    /// [`DomainError::Conflict`] if the user or the role does not exist,
    /// [`DomainError::Storage`] otherwise.
    async fn assign(
        &self,
        tenant: &TenantId,
        user: UserId,
        owner: &RoleOwner,
        name: &RoleName,
        now: OffsetDateTime,
    ) -> Result<bool, DomainError>;

    /// Takes a role away from `user`. Returns `false` if they did not hold it.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the write fails.
    async fn withdraw(
        &self,
        tenant: &TenantId,
        user: UserId,
        owner: &RoleOwner,
        name: &RoleName,
    ) -> Result<bool, DomainError>;

    /// Everything one account holds, in the shape a token needs it.
    ///
    /// One call rather than one per client, because it is on the hot path of
    /// every access token issued to a user.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the read fails, or [`DomainError::Invalid`]
    /// for a stored name this build's parser refuses. Refused rather than
    /// skipped: a token minted with a *subset* of somebody's roles is an
    /// authorization decision taken by a parse failure.
    async fn held_by(&self, tenant: &TenantId, user: UserId) -> Result<HeldRoles, DomainError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_clock_moves_forward() {
        let clock = SystemClock;
        assert!(clock.now() <= clock.now());
    }
}
