//! Server-side sessions: who is signed in, since when, and how strongly.
//!
//! A session is the thing that lets a second authorization request skip the
//! login form. It is therefore a credential in its own right — whoever holds
//! the cookie is the user, for every client that asks — and it is treated like
//! one: high entropy, stored only as a digest, rotated whenever the
//! authentication behind it changes, and revocable.
//!
//! # Why the id rotates
//!
//! Session fixation. If an attacker can plant a session id in a victim's
//! browser *before* they sign in — through a subdomain, a stale cookie, a
//! shared machine — then after the victim authenticates, the attacker's
//! pre-known id is a valid authenticated session. Rotating on login means the
//! id that authenticates is one the attacker never saw. The same argument
//! applies to a step-up: the session that comes out the other side carries more
//! authority than the one that went in, so it gets a new name.
//!
//! OWASP ASVS V3 asks for exactly this, and it is the one session rule that
//! cannot be retrofitted — a design that reuses the id has nowhere to put the
//! rotation later.
//!
//! # Two clocks
//!
//! An **idle** timeout and an **absolute** lifetime, both per tenant. The idle
//! one bounds an unattended browser; the absolute one bounds a session that is
//! kept alive deliberately. Only having the first means a session that is used
//! once an hour lives forever, which is how a stolen cookie outlives the
//! employment of the person it was stolen from.

use crate::{ClientId, TenantId, credentials::OpaqueToken, sha256_hex};
use std::fmt;
use time::{Duration, OffsetDateTime};

/// The cookie a session id travels in.
///
/// `__Host-` for the same browser-enforced reasons as the interaction cookie:
/// set over HTTPS, no `Domain`, `Path=/`. Without the prefix a compromised
/// sibling subdomain can plant a session id, which is the fixation attack the
/// rotation above defends against from the other side.
pub const COOKIE_NAME: &str = "__Host-asterius_session";

/// Bits of entropy in a session id.
pub const ID_BITS: usize = 256;

/// How long a session may sit unused, unless a tenant says otherwise.
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::hours(1);

/// How long a session may live at all, unless a tenant says otherwise.
pub const DEFAULT_ABSOLUTE_LIFETIME: Duration = Duration::hours(12);

/// A session id, as held by the browser.
///
/// Redacted in `Debug`, compared in constant time, stored as a digest.
pub struct SessionId(OpaqueToken);

impl SessionId {
    /// Mints a new id.
    #[must_use]
    pub fn generate() -> Self {
        Self(OpaqueToken::generate_bits::<ID_BITS>())
    }

    /// Takes an id off the wire. Nothing about it is trustworthy yet.
    #[must_use]
    pub fn from_presented(value: String) -> Self {
        Self(OpaqueToken::from_presented(value))
    }

    /// The value to put in a cookie.
    #[must_use]
    pub fn expose(&self) -> &str {
        self.0.expose()
    }

    /// The value to store.
    #[must_use]
    pub fn digest(&self) -> String {
        sha256_hex(self.0.expose().as_bytes())
    }

    /// Whether two ids are the same, in constant time.
    #[must_use]
    pub fn matches(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0)
    }
}

impl fmt::Debug for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionId([REDACTED])")
    }
}

/// Why a session stopped being usable.
///
/// A closed vocabulary rather than free text, so the column cannot collect
/// ticket numbers and so a CAEP `session-revoked` event (`ast-0ju.8`) has a
/// reason it can map.
///
/// Deliberately *not* the grant's `RevocationReason`. That one is about
/// authorization — `CodeReplayed`, `KeyCompromise`, `Superseded` — and this
/// one is about a browser. They meet at exactly one point: ending a session
/// revokes the grants made in it, with the grant's own `SessionEnded`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SessionRevocation {
    /// The user signed out.
    UserLogout,
    /// An administrator ended it.
    Administrative,
    /// The user's credential changed, so every session predating it is stale.
    CredentialChange,
    /// Superseded by rotation: this id was replaced by a fresher one.
    Rotated,
    /// The account was disabled or deleted.
    AccountClosed,
    /// Something about the session looked wrong.
    Suspicious,
}

impl SessionRevocation {
    /// The stored spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UserLogout => "user_logout",
            Self::Administrative => "administrative",
            Self::CredentialChange => "credential_change",
            Self::Rotated => "rotated",
            Self::AccountClosed => "account_closed",
            Self::Suspicious => "suspicious",
        }
    }

    /// Reads a stored value back.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        [
            Self::UserLogout,
            Self::Administrative,
            Self::CredentialChange,
            Self::Rotated,
            Self::AccountClosed,
            Self::Suspicious,
        ]
        .into_iter()
        .find(|r| r.as_str() == value)
    }
}

/// Whether a session may still be used.
///
/// Computed from the row rather than stored, for the same reason a grant's
/// status is: a stored value is wrong from the instant an expiry passes until
/// a sweep arrives, and the sweep is not on the request path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionStatus {
    /// Usable.
    Active,
    /// Past its idle timeout.
    Idle,
    /// Past its absolute lifetime.
    Expired,
    /// Revoked, and why.
    Revoked(SessionRevocation),
}

impl SessionStatus {
    /// Whether a request may proceed on this session.
    #[must_use]
    pub const fn is_usable(self) -> bool {
        matches!(self, Self::Active)
    }
}

/// How the user authenticated (OIDC Core §2, `amr`).
///
/// Recorded so that a step-up policy (`ast-2vk.7`) can tell what has already
/// been done, and so an ID token can say it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum AuthenticationMethod {
    /// A password (RFC 8176 `pwd`).
    Password,
    /// A passkey or other WebAuthn credential (RFC 8176 `swk`/`hwk` — this
    /// server does not distinguish software from hardware, because it cannot
    /// verify the difference).
    Passkey,
    /// A one-time code (RFC 8176 `otp`).
    OneTimeCode,
    /// The session was already established (RFC 8176 does not define this;
    /// OIDC Core §2 permits it and it is what a skipped login looks like).
    ExistingSession,
}

impl AuthenticationMethod {
    /// The `amr` value, from the RFC 8176 registry where one exists.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Password => "pwd",
            Self::Passkey => "swk",
            Self::OneTimeCode => "otp",
            Self::ExistingSession => "session",
        }
    }

    /// Reads a stored value back.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        [
            Self::Password,
            Self::Passkey,
            Self::OneTimeCode,
            Self::ExistingSession,
        ]
        .into_iter()
        .find(|m| m.as_str() == value)
    }
}

/// A signed-in user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    /// Which tenant.
    pub tenant: TenantId,
    /// The digest of the id. The id itself lives only in the browser.
    pub id_digest: String,
    /// The identifier this session is known by *outside* the server: the `sid`
    /// claim of an ID Token and of a Logout Token (OIDC Back-Channel Logout
    /// 1.0 §2.4, OIDC Session Management §5).
    ///
    /// Separate from [`Session::id_digest`] for two reasons, and either alone
    /// would be enough.
    ///
    /// The digest is a *lookup key*: it is what
    /// [`crate::ports::SessionRepository::find`] takes, so a relying party
    /// handed it would hold the value that names this row. Publishing an
    /// internal key as a side effect of issuing a token is the kind of thing
    /// that is harmless until the day some other code path accepts it.
    ///
    /// And the digest *changes*. Rotating the session id is the session
    /// fixation defence — a new cookie value at every privilege change — but
    /// it is the same login, the same person and the same thing an RP would
    /// later be asked to log out. A `sid` that changed underneath a relying
    /// party would make one session look like several, and would leave
    /// back-channel logout naming a session nobody recognises. So this is
    /// generated once, at [`Session::begin`], and rotation does not touch it.
    pub public_sid: String,
    /// Who is signed in.
    pub user: uuid::Uuid,
    /// When the session began.
    pub created_at: OffsetDateTime,
    /// `auth_time` as it will appear in an ID token — when the user last
    /// actually proved who they are, which is *not* `created_at` after a
    /// step-up.
    pub authenticated_at: OffsetDateTime,
    /// When it was last used.
    pub last_seen_at: OffsetDateTime,
    /// The absolute deadline.
    pub expires_at: OffsetDateTime,
    /// The idle deadline, moved forward on use.
    pub idle_expires_at: OffsetDateTime,
    /// The authentication context class, when policy assigns one.
    pub acr: Option<String>,
    /// How the user authenticated, in the order it happened.
    pub amr: Vec<AuthenticationMethod>,
    /// When and why it was revoked.
    pub revoked: Option<(OffsetDateTime, SessionRevocation)>,
}

impl Session {
    /// Starts a session for a freshly authenticated user.
    ///
    /// `id` is consumed by the caller to set the cookie; only its digest is
    /// kept here.
    #[must_use]
    pub fn begin(
        tenant: TenantId,
        id: &SessionId,
        user: uuid::Uuid,
        methods: Vec<AuthenticationMethod>,
        now: OffsetDateTime,
        limits: Lifetimes,
    ) -> Self {
        Self {
            tenant,
            id_digest: id.digest(),
            // 256 bits, the same as the session id itself. It is not a
            // credential — holding it authenticates nobody — but it is handed
            // to every relying party the user signs in to, so it must not be
            // guessable from one RP to another's.
            public_sid: OpaqueToken::generate_bits::<ID_BITS>().expose().to_owned(),
            user,
            created_at: now,
            authenticated_at: now,
            last_seen_at: now,
            expires_at: now + limits.absolute,
            idle_expires_at: now + limits.idle,
            acr: None,
            amr: methods,
            revoked: None,
        }
    }

    /// What this session is worth at `now`.
    ///
    /// The order matters: revocation beats both clocks, because a revoked
    /// session that has also expired should be reported as revoked — an
    /// operator asking why a user was signed out wants the deliberate reason,
    /// not the incidental one.
    #[must_use]
    pub fn status(&self, now: OffsetDateTime) -> SessionStatus {
        if let Some((_, reason)) = self.revoked {
            return SessionStatus::Revoked(reason);
        }
        if self.expires_at <= now {
            return SessionStatus::Expired;
        }
        if self.idle_expires_at <= now {
            return SessionStatus::Idle;
        }
        SessionStatus::Active
    }

    /// Whether `now` is past the `max_age` an authorization request asked for.
    ///
    /// OIDC Core §3.1.2.1: `max_age` is measured from `auth_time`, not from
    /// when the session began. A session that has been stepped up is *younger*
    /// than its own creation for this purpose, which is the point.
    #[must_use]
    pub fn needs_reauthentication(&self, max_age: Option<u32>, now: OffsetDateTime) -> bool {
        max_age.is_some_and(|max_age| {
            now - self.authenticated_at > Duration::seconds(i64::from(max_age))
        })
    }
}

/// How long a tenant's sessions live.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lifetimes {
    /// How long a session may sit unused.
    pub idle: Duration,
    /// How long it may live at all.
    pub absolute: Duration,
}

impl Default for Lifetimes {
    fn default() -> Self {
        Self {
            idle: DEFAULT_IDLE_TIMEOUT,
            absolute: DEFAULT_ABSOLUTE_LIFETIME,
        }
    }
}

impl Lifetimes {
    /// Clamps a configured pair into something coherent.
    ///
    /// An idle timeout longer than the absolute lifetime is not a stricter
    /// setting, it is a setting with no effect — the absolute clock would
    /// always win. Rather than silently ignore it, the idle timeout is capped,
    /// so what an operator configured and what the server does are the same
    /// thing.
    #[must_use]
    pub fn clamped(self) -> Self {
        let absolute = self.absolute.max(Duration::minutes(1));
        Self {
            idle: self.idle.clamp(Duration::minutes(1), absolute),
            absolute,
        }
    }
}

/// A client that took part in a session.
///
/// Back-channel logout needs this list: when a session ends, every client that
/// was issued an ID token in it has to be told.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Participant {
    /// The client.
    pub client: ClientId,
    /// When it first took part.
    pub first_seen_at: OffsetDateTime,
    /// When it last did.
    pub last_seen_at: OffsetDateTime,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_760_000_000).expect("fixed instant")
    }

    fn session() -> Session {
        Session::begin(
            TenantId::new("demo"),
            &SessionId::generate(),
            uuid::Uuid::from_u128(1),
            vec![AuthenticationMethod::Password],
            now(),
            Lifetimes::default(),
        )
    }

    #[test]
    fn ids_do_not_repeat_and_are_stored_as_digests() {
        let mut seen = HashSet::new();
        for _ in 0..2_000 {
            let id = SessionId::generate();
            assert!(seen.insert(id.expose().to_owned()), "an id repeated");
            assert_eq!(id.digest().len(), 64);
            assert!(!id.digest().contains(id.expose()));
        }
    }

    #[test]
    fn an_id_is_redacted_in_debug() {
        let id = SessionId::generate();
        let rendered = format!("{id:?}");
        assert!(!rendered.contains(id.expose()), "{rendered}");
    }

    #[test]
    fn a_fresh_session_is_active() {
        assert_eq!(session().status(now()), SessionStatus::Active);
    }

    /// Two clocks. Only having the idle one means a session used once an hour
    /// lives forever.
    #[test]
    fn both_clocks_end_a_session() {
        let session = session();

        let idle = now() + DEFAULT_IDLE_TIMEOUT;
        assert_eq!(session.status(idle), SessionStatus::Idle);

        let absolute = now() + DEFAULT_ABSOLUTE_LIFETIME;
        assert_eq!(
            session.status(absolute),
            SessionStatus::Expired,
            "the absolute clock must win once both have passed"
        );

        assert!(!session.status(idle).is_usable());
        assert!(!session.status(absolute).is_usable());
    }

    /// A revoked session reports the deliberate reason, not the incidental one.
    #[test]
    fn revocation_beats_expiry() {
        let mut session = session();
        session.revoked = Some((now(), SessionRevocation::UserLogout));

        for at in [
            now(),
            now() + DEFAULT_IDLE_TIMEOUT,
            now() + DEFAULT_ABSOLUTE_LIFETIME,
            now() + Duration::days(365),
        ] {
            assert_eq!(
                session.status(at),
                SessionStatus::Revoked(SessionRevocation::UserLogout),
                "at {at}"
            );
        }
    }

    /// OIDC Core §3.1.2.1: `max_age` is measured from `auth_time`.
    #[test]
    fn max_age_is_measured_from_the_last_authentication_not_the_first() {
        let mut session = session();
        // Signed in an hour ago, stepped up a minute ago.
        session.created_at = now() - Duration::hours(1);
        session.authenticated_at = now() - Duration::minutes(1);

        assert!(
            !session.needs_reauthentication(Some(300), now()),
            "a session stepped up a minute ago satisfies max_age=300"
        );
        assert!(
            session.needs_reauthentication(Some(30), now()),
            "a session authenticated a minute ago does not satisfy max_age=30"
        );
        // No `max_age` asked for: nothing to fail.
        assert!(!session.needs_reauthentication(None, now()));
    }

    #[test]
    fn max_age_zero_always_requires_reauthentication() {
        let mut session = session();
        session.authenticated_at = now() - Duration::seconds(1);
        assert!(
            session.needs_reauthentication(Some(0), now()),
            "max_age=0 means authenticate now"
        );
    }

    /// An idle timeout longer than the absolute lifetime has no effect, so it
    /// is capped rather than silently ignored.
    #[test]
    fn lifetimes_are_clamped_into_something_coherent() {
        let backwards = Lifetimes {
            idle: Duration::hours(48),
            absolute: Duration::hours(12),
        }
        .clamped();
        assert_eq!(backwards.idle, Duration::hours(12));
        assert_eq!(backwards.absolute, Duration::hours(12));

        // Neither clock can be zero or negative: a session that expires when it
        // is created is a login loop.
        let silly = Lifetimes {
            idle: Duration::ZERO,
            absolute: Duration::seconds(-1),
        }
        .clamped();
        assert!(silly.idle >= Duration::minutes(1));
        assert!(silly.absolute >= Duration::minutes(1));
        assert!(silly.idle <= silly.absolute);

        // An ordinary pair is left alone.
        let ordinary = Lifetimes::default().clamped();
        assert_eq!(ordinary, Lifetimes::default());
    }

    #[test]
    fn every_revocation_reason_round_trips() {
        for reason in [
            SessionRevocation::UserLogout,
            SessionRevocation::Administrative,
            SessionRevocation::CredentialChange,
            SessionRevocation::Rotated,
            SessionRevocation::AccountClosed,
            SessionRevocation::Suspicious,
        ] {
            assert_eq!(SessionRevocation::parse(reason.as_str()), Some(reason));
        }
        assert_eq!(SessionRevocation::parse("something_else"), None);
        assert_eq!(SessionRevocation::parse(""), None);
    }

    #[test]
    fn every_authentication_method_round_trips() {
        for method in [
            AuthenticationMethod::Password,
            AuthenticationMethod::Passkey,
            AuthenticationMethod::OneTimeCode,
            AuthenticationMethod::ExistingSession,
        ] {
            assert_eq!(AuthenticationMethod::parse(method.as_str()), Some(method));
        }
        assert_eq!(AuthenticationMethod::parse("mfa"), None);
    }

    /// `auth_time` starts equal to the creation time and is what a step-up
    /// moves — a distinction the ID token depends on.
    #[test]
    fn a_new_session_authenticated_when_it_began() {
        let session = session();
        assert_eq!(session.created_at, session.authenticated_at);
        assert_eq!(session.last_seen_at, now());
        assert_eq!(session.amr, vec![AuthenticationMethod::Password]);
        assert!(session.revoked.is_none());
    }
}
