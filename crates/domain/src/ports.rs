//! Ports: the traits through which protocol code reaches the outside world.
//!
//! Adapters live in `asterius-store-pg`, `asterius-jose` and the server crate.
//! Protocol crates depend on these traits and never on an implementation.

use crate::{
    AuthenticationMethod, Client, ClientId, Consumed, DomainError, InteractionRecord, Issuer,
    Participant, PushedRequest, Secret, Session, SessionRevocation, Tenant, TenantId,
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
