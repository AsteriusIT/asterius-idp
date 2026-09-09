//! Ports: the traits through which protocol code reaches the outside world.
//!
//! Adapters live in `asterius-store-pg`, `asterius-jose` and the server crate.
//! Protocol crates depend on these traits and never on an implementation.

use crate::{
    AuthenticationMethod, Client, ClientId, ClientStatus, CodeBinding, Consumed, DomainError,
    Enrolment, Grant, InteractionRecord, Issuer, NewPasskey, Participant, PushedRequest, Secret,
    SectorIdentifier, Session, SessionRevocation, SubjectId, Tenant, TenantId, User, UserId,
};
use serde_json::Value;
use std::fmt::Debug;
use time::OffsetDateTime;

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
/// The only port whose input is attacker-controlled end to end: a `jwks_uri` is
/// a string a client wrote into its own registration, and an implementation of
/// this trait is the server going and fetching it. RFC 7591 §5 raises the
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
pub trait JwksFetcher: Debug + Send + Sync {
    /// Fetches the JWK Set document at `url`.
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
    /// # Errors
    ///
    /// [`DomainError::Conflict`] if the `client_id` is already taken, or if the
    /// tenant does not exist. [`DomainError::Invalid`] if the entity belongs to
    /// another tenant or the store refuses it. [`DomainError::Storage`]
    /// otherwise.
    async fn register(
        &self,
        client: &Client,
        registration_access_token: &[u8; 32],
    ) -> Result<Client, DomainError>;
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
    /// Whether the client is serving or suspended.
    pub status: ClientStatus,
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
    /// # Errors
    ///
    /// [`DomainError::NotFound`] if no such client exists in this tenant, or a
    /// storage error.
    async fn deprovision(&self, client_id: &ClientId) -> Result<(), DomainError>;

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
    /// # Errors
    ///
    /// [`DomainError::NotFound`] if the old session is not there to rotate.
    async fn rotate(
        &self,
        old_digest: &str,
        new_digest: &str,
        methods: &[AuthenticationMethod],
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

/// Recording a completed authorization.
///
/// Deliberately one method. The authorization endpoint's whole relationship
/// with a grant is that it creates one; reading, claiming and revoking belong
/// to the token endpoint, the introspection endpoint and the grants dashboard,
/// and none of those is reachable from a browser mid-consent. A port carrying
/// all four would hand every one of those operations to a handler that needs
/// exactly one of them.
#[async_trait::async_trait]
pub trait GrantRepository: Debug + Send + Sync {
    /// Writes a new grant.
    ///
    /// # Errors
    ///
    /// [`DomainError::Invalid`] when the grant belongs to another tenant, and
    /// [`DomainError::Storage`] otherwise.
    async fn create(&self, grant: &Grant) -> Result<(), DomainError>;
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
}

impl ReplayPurpose {
    /// The stored spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ClientAssertion => "client_assertion",
            Self::DpopProof => "dpop_proof",
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_clock_moves_forward() {
        let clock = SystemClock;
        assert!(clock.now() <= clock.now());
    }
}
