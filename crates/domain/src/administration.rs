//! Administering an account: the port the console's user screen reaches
//! through, and the receipts it hands back.
//!
//! # Why the summaries are not the entities
//!
//! [`SessionSummary`] is not [`crate::Session`], and that is the point.
//! `Session::id_digest` is a *lookup key* — it is what
//! [`crate::ports::SessionRepository::find`] takes — and the console has no
//! use for it: an operator revokes a session by the identifier the rest of the
//! deployment already publishes, the `sid` of OIDC Back-Channel Logout 1.0
//! §2.4. Handing the API the whole row and asking it to redact would make "the
//! digest never reaches a browser" a property of a rendering function somebody
//! could widen. There is no digest on this side of the port, so there is
//! nothing to redact.
//!
//! [`CredentialSummary`] carries the same reasoning one step further: there is
//! no public key, no signature counter and no password hash on it, because a
//! credentials screen answers "what can this person sign in with, and when did
//! they last do it" and nothing on that list is material.
//!
//! # Why a revocation returns a receipt
//!
//! Disabling an account revokes its sessions, and OIDC Back-Channel Logout 1.0
//! §2.5 says the relying parties that took part must be told. [`Terminated`]
//! is what the adapter reports back: how many sessions ended and how many
//! logout tokens were queued for delivery. The number is *queued* and not
//! *delivered*, for the reason `crates/server/src/http/logout.rs` gives about
//! the same count — delivery is the outbox's, is retried, and may end in a
//! dead letter, so an audit record claiming three relying parties were
//! notified would be a control an auditor would believe and should not.

use crate::entities::grant::Grant;
use crate::entities::user::{User, UserStatus};
use crate::error::DomainError;
use crate::ids::{GrantId, TenantId};
use crate::{AcceptedPassword, AuthenticationMethod, UserId};
use std::fmt::Debug;
use time::OffsetDateTime;
use uuid::Uuid;

/// One of a person's browser sessions, as an operator sees it.
///
/// No `id_digest`: see the module documentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionSummary {
    /// The identifier this session is known by outside the server — the `sid`
    /// of an ID token and of a logout token. The value an operator revokes by.
    pub public_sid: String,
    /// When the session began.
    pub created_at: OffsetDateTime,
    /// When the person last actually proved who they are (`auth_time`).
    pub authenticated_at: OffsetDateTime,
    /// When it was last used.
    pub last_seen_at: OffsetDateTime,
    /// The absolute deadline.
    pub expires_at: OffsetDateTime,
    /// How the person authenticated, in the order it happened.
    pub amr: Vec<AuthenticationMethod>,
    /// The authentication context class, when policy assigned one.
    pub acr: Option<String>,
    /// When it was revoked, and the stored spelling of why.
    pub revoked: Option<(OffsetDateTime, &'static str)>,
}

impl SessionSummary {
    /// Whether this session could still be presented.
    #[must_use]
    pub fn is_live(&self, now: OffsetDateTime) -> bool {
        self.revoked.is_none() && self.expires_at > now
    }
}

/// One passkey, as the credentials screen renders it.
///
/// No public key and no signature counter: neither answers a question an
/// operator asks, and the second is a value a support agent could be talked
/// into reading out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasskeySummary {
    /// The credential row, which is what a removal names. Not the WebAuthn
    /// credential id: that one is chosen by the authenticator and is a
    /// correlator across relying parties.
    pub id: Uuid,
    /// The label the person or the enrolment gave it.
    pub label: Option<String>,
    /// The relying party id it is scoped to.
    pub rp_id: String,
    /// The authenticator model, where the registration recorded one
    /// (WebAuthn L3 §6.4.1). `None` for an authenticator that declined to say,
    /// which is every all-zero AAGUID.
    ///
    /// Read by the self-service list (`ast-1xd`) to name a credential whose
    /// owner never labelled one: "the passkey you enrolled on 3 March" is a
    /// row a person can act on, and the model is what makes two of them tell
    /// apart.
    pub aaguid: Option<Uuid>,
    /// When it was enrolled.
    pub created_at: OffsetDateTime,
    /// When it was last asserted, if it ever was.
    pub last_used_at: Option<OffsetDateTime>,
    /// When it was blocked, if it was — a counter regression, or a removal.
    pub disabled_at: Option<OffsetDateTime>,
}

/// What a person can sign in with.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CredentialSummary {
    /// Whether a usable password credential exists.
    pub password: bool,
    /// Every passkey, blocked ones included: an operator investigating a lock
    /// needs to see the credential that caused it.
    pub passkeys: Vec<PasskeySummary>,
}

/// What ending sessions did, and who was told.
///
/// See the module documentation for why `logout_tokens_queued` counts rows in
/// the outbox rather than relying parties that answered.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Terminated {
    /// How many live sessions were revoked by this call.
    pub sessions_revoked: usize,
    /// How many back-channel logout tokens were queued for delivery.
    pub logout_tokens_queued: usize,
}

/// What forcing a reset did (`ast-2vk.10`).
///
/// Three facts and not one, because they fail separately: a password can be
/// invalidated by a deployment that cannot send mail, and an operator has to
/// know which of them happened before they tell somebody to check their inbox.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PasswordReset {
    /// Whether a password credential was invalidated.
    pub password_invalidated: bool,
    /// Whether a recovery message was handed to the notification port.
    pub recovery_sent: bool,
    /// What ending the account's sessions did: a forced reset ends them, for
    /// the reason `SessionRevocation::CredentialChange` names.
    pub terminated: Terminated,
}

/// A new account, as the console asks for one.
///
/// The password is an [`AcceptedPassword`] and therefore cannot be a value
/// that has not passed policy: there is no constructor that skips the deny
/// list (`ast-895`), so "the console can create an account on `changeme`" is
/// not a review question.
///
/// `None` is an account with no password, which is the shape a deployment that
/// enrols a passkey afterwards wants — not an account anybody can sign into.
#[derive(Debug)]
pub struct NewAccount {
    /// The account itself, with its claims.
    pub user: User,
    /// The initial password, if there is one.
    pub password: Option<AcceptedPassword>,
}

/// Administering the accounts of one deployment (`ast-f7m.6`).
///
/// One port rather than six handles, for the reason
/// `asterius_admin_api::backend` gives about [`crate::ports::TenantRepository`]:
/// disabling an account has to revoke its sessions *and* notify the relying
/// parties, and a caller holding two handles is a caller who can do the first
/// and forget the second.
#[async_trait::async_trait]
pub trait UserAdministration: Debug + Send + Sync {
    /// One page of this tenant's accounts, ordered by username.
    ///
    /// `term` is matched against the username and the email address, and an
    /// empty one matches everything. `after` is the username the previous page
    /// ended on, which is what makes this a range scan rather than an offset.
    /// `limit` is already clamped by the caller.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the store could not be reached.
    async fn search(
        &self,
        tenant: &TenantId,
        term: &str,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Vec<User>, DomainError>;

    /// One account, in the tenant the request was routed to.
    ///
    /// The tenant is an argument and not read off the id, which is what makes
    /// "an administrator of A cannot read an account of B by naming its uuid"
    /// a query predicate rather than a check somebody remembered.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the store could not be reached.
    async fn find(&self, tenant: &TenantId, id: UserId) -> Result<Option<User>, DomainError>;

    /// Creates an account, and its password if one was given.
    ///
    /// # Errors
    ///
    /// [`DomainError::Conflict`] if the username or the address is taken, and
    /// [`DomainError::Storage`] otherwise.
    async fn create(&self, account: NewAccount) -> Result<User, DomainError>;

    /// Switches an account on or off.
    ///
    /// Disabling revokes every live session and notifies the participating
    /// relying parties; enabling revokes nothing, so its receipt is empty.
    ///
    /// # Errors
    ///
    /// [`DomainError::NotFound`] for an account this tenant does not hold, and
    /// [`DomainError::Storage`] otherwise.
    async fn set_status(
        &self,
        tenant: &TenantId,
        id: UserId,
        status: UserStatus,
        now: OffsetDateTime,
    ) -> Result<Terminated, DomainError>;

    /// Replaces an account's claims and its verification flags.
    ///
    /// Takes the whole [`User`] because OIDC Core §5.1's `email_verified` is a
    /// column and the rest of the claims are a bag: an operator editing both
    /// in one screen saves both in one write, or the two can disagree.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the write fails.
    async fn save(&self, user: &User) -> Result<User, DomainError>;

    /// This account's browser sessions, newest first.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the store could not be reached.
    async fn sessions(
        &self,
        tenant: &TenantId,
        user: UserId,
    ) -> Result<Vec<SessionSummary>, DomainError>;

    /// Ends one session, named by its `sid`, and notifies its participants.
    ///
    /// # Errors
    ///
    /// [`DomainError::NotFound`] if this tenant has no such session, and
    /// [`DomainError::Storage`] otherwise.
    async fn revoke_session(
        &self,
        tenant: &TenantId,
        public_sid: &str,
        now: OffsetDateTime,
    ) -> Result<Terminated, DomainError>;

    /// The authorizations this account has granted, newest first.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the store could not be reached.
    async fn grants(&self, tenant: &TenantId, user: UserId) -> Result<Vec<Grant>, DomainError>;

    /// Withdraws one authorization, with Grant Management ID1 §6.5's
    /// semantics: the refresh tokens go, the access-token cutoff is written,
    /// and the grant is stamped last.
    ///
    /// `false` means there was nothing live to withdraw, which is what a
    /// second call finds.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the transaction fails.
    async fn revoke_grant(
        &self,
        tenant: &TenantId,
        grant: &GrantId,
        now: OffsetDateTime,
    ) -> Result<bool, DomainError>;

    /// What this account can sign in with.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the store could not be reached.
    async fn credentials(
        &self,
        tenant: &TenantId,
        user: UserId,
    ) -> Result<CredentialSummary, DomainError>;

    /// Blocks one passkey.
    ///
    /// The row is kept and stamped rather than deleted, for the reason a
    /// retired signing key's row is kept: an incident review has to be able to
    /// see that the credential existed and when it stopped being usable.
    ///
    /// `false` is a credential this tenant does not hold, or one already
    /// blocked.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the write fails.
    async fn remove_passkey(
        &self,
        tenant: &TenantId,
        user: UserId,
        credential: Uuid,
        now: OffsetDateTime,
    ) -> Result<bool, DomainError>;

    /// Forces a password reset: invalidates the password, ends the sessions,
    /// and mails a recovery link (`ast-2vk.10`).
    ///
    /// Not "sets a password an operator chose". A password an administrator
    /// knows is a shared secret between two people, and NIST SP 800-63B
    /// §5.1.1.2 has nothing good to say about one; the recovery path already
    /// exists, already binds to a mailbox, and already forces a new credential
    /// in the same request.
    ///
    /// # Errors
    ///
    /// [`DomainError::NotFound`] for an account this tenant does not hold, and
    /// [`DomainError::Storage`] otherwise.
    async fn force_password_reset(
        &self,
        tenant: &TenantId,
        user: UserId,
        now: OffsetDateTime,
    ) -> Result<PasswordReset, DomainError>;
}
