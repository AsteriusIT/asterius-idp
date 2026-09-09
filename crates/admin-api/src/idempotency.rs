//! Idempotency keys on `POST`, so a retried creation creates once.
//!
//! A console that times out on `POST /tenants` cannot tell whether the tenant
//! was created. Without a key its only choices are to retry — and maybe create
//! two — or not to, and maybe create none. The key makes the retry safe: the
//! second request carries the same one and is refused rather than executed.
//!
//! # At most once, not "replay the first answer"
//!
//! This is the deliberate half-measure, and naming it is better than implying
//! more. A full implementation stores the first response and returns it
//! verbatim to every repeat, which needs a table holding response bodies, a
//! retention rule for it, and a decision about what to do with a request that
//! arrives while the first is still in flight. What is here gives the property
//! that actually protects the data — **the operation runs at most once per
//! key** — and reports the repeat as [`AdminError::IdempotencyReplay`] (409)
//! rather than replaying a body it did not keep. A console that sees 409 knows
//! its earlier request landed, which is precisely the question it could not
//! answer before. `ast-f7m.3`'s screens can ask for the stored-response
//! version when one of them needs it.
//!
//! # Why the claim goes through `ReplayGuard`
//!
//! Because it is the same question the port already answers atomically, in the
//! same database, with the same "two concurrent requests must see exactly one
//! first use" guarantee — and because a per-process map would make the limit
//! "at most once per replica", which is not at most once. The port is
//! namespaced by [`asterius_domain::ReplayPurpose::AdminIdempotency`] and by
//! the caller, so one administrator cannot burn another's keys, and no admin
//! key can collide with a DPoP `jti`.

use asterius_domain::{ReplayCheck, ReplayGuard, ReplayPurpose, TenantId};
use time::{Duration, OffsetDateTime};

use crate::error::AdminError;

/// The header a key travels in.
pub const HEADER: &str = "idempotency-key";

/// How long a key is remembered.
///
/// Long enough to cover a retry by a person who saw a timeout and tried again
/// after lunch; short enough that the row is not a permanent record of every
/// administrative action's key. Past this the key stops meaning anything and
/// retention may sweep it with the rest of `jti_replay`.
pub const RETENTION: Duration = Duration::hours(24);

/// The shortest key accepted.
///
/// Short keys collide, and a collision here means one administrator's creation
/// is refused because another used `1`. The floor makes a caller choose
/// something with entropy in it.
pub const MIN_LEN: usize = 8;

/// The longest key accepted, matching RFC 9110's advice that a server bound
/// anything it stores from a request.
pub const MAX_LEN: usize = 255;

/// A validated `Idempotency-Key`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdempotencyKey(String);

impl IdempotencyKey {
    /// Validates a key a caller sent.
    ///
    /// Printable ASCII only. The value ends up in a database key and in log
    /// lines, and a key carrying a newline or a control character is a log
    /// injection with extra steps.
    ///
    /// # Errors
    ///
    /// [`AdminError::IdempotencyKeyInvalid`] naming the rule that was broken.
    // fuzz-target: admin_idempotency_key
    pub fn parse(raw: &str) -> Result<Self, AdminError> {
        if raw.len() < MIN_LEN {
            return Err(AdminError::IdempotencyKeyInvalid("too short"));
        }
        if raw.len() > MAX_LEN {
            return Err(AdminError::IdempotencyKeyInvalid("too long"));
        }
        if !raw
            .bytes()
            .all(|byte| byte.is_ascii_graphic() || byte == b' ')
        {
            return Err(AdminError::IdempotencyKeyInvalid("must be printable ASCII"));
        }
        Ok(Self(raw.to_owned()))
    }

    /// The key as presented.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for IdempotencyKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Claims `key` for `actor`, so that a repeat is refused rather than executed.
///
/// `actor` namespaces the key: RFC 7523's argument for scoping a `jti` to its
/// issuer applies here for the same reason, and without it one administrator
/// could deny another the use of `create-tenant-1`.
///
/// # Errors
///
/// [`AdminError::IdempotencyReplay`] when the key has been used, and
/// [`AdminError::Unavailable`] when the store could not be reached — never
/// success, because an unreachable store is not permission to run a creation
/// twice.
pub async fn claim(
    guard: &dyn ReplayGuard,
    tenant: &TenantId,
    actor: &str,
    key: &IdempotencyKey,
    now: OffsetDateTime,
) -> Result<(), AdminError> {
    match guard
        .claim(
            tenant,
            ReplayPurpose::AdminIdempotency,
            actor,
            key.as_str(),
            now + RETENTION,
        )
        .await
    {
        Ok(ReplayCheck::FirstUse) => Ok(()),
        Ok(ReplayCheck::Replay) => Err(AdminError::IdempotencyReplay),
        Err(error) => Err(AdminError::from_storage("idempotency.claim", &error)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Debug, Default)]
    struct SeenOnce(Mutex<std::collections::BTreeSet<String>>);

    #[async_trait::async_trait]
    impl ReplayGuard for SeenOnce {
        async fn claim(
            &self,
            tenant: &TenantId,
            purpose: ReplayPurpose,
            subject: &str,
            jti: &str,
            _expires_at: OffsetDateTime,
        ) -> Result<ReplayCheck, asterius_domain::DomainError> {
            let mut seen = self.0.lock().expect("an uncontended lock");
            let composite = format!("{tenant}|{}|{subject}|{jti}", purpose.as_str());
            Ok(if seen.insert(composite) {
                ReplayCheck::FirstUse
            } else {
                ReplayCheck::Replay
            })
        }
    }

    #[derive(Debug)]
    struct Broken;

    #[async_trait::async_trait]
    impl ReplayGuard for Broken {
        async fn claim(
            &self,
            _tenant: &TenantId,
            _purpose: ReplayPurpose,
            _subject: &str,
            _jti: &str,
            _expires_at: OffsetDateTime,
        ) -> Result<ReplayCheck, asterius_domain::DomainError> {
            Err(asterius_domain::DomainError::Storage("no database".into()))
        }
    }

    fn tenant() -> TenantId {
        TenantId::parse("acme").expect("a valid tenant id")
    }

    fn key(raw: &str) -> IdempotencyKey {
        IdempotencyKey::parse(raw).expect("a valid key")
    }

    #[test]
    fn a_key_below_the_floor_is_refused() {
        assert!(matches!(
            IdempotencyKey::parse("short"),
            Err(AdminError::IdempotencyKeyInvalid("too short"))
        ));
    }

    #[test]
    fn a_key_above_the_ceiling_is_refused() {
        assert!(matches!(
            IdempotencyKey::parse(&"k".repeat(MAX_LEN + 1)),
            Err(AdminError::IdempotencyKeyInvalid("too long"))
        ));
    }

    /// A key reaches a log line, so a control character in it is a log
    /// injection.
    #[test]
    fn a_key_carrying_a_control_character_is_refused() {
        for bad in ["key\nwith-newline", "key\0with-nul", "clé-non-ascii-ici"] {
            assert!(
                matches!(
                    IdempotencyKey::parse(bad),
                    Err(AdminError::IdempotencyKeyInvalid(_))
                ),
                "accepted {bad:?}"
            );
        }
    }

    #[test]
    fn an_ordinary_uuid_shaped_key_is_accepted() {
        assert!(IdempotencyKey::parse("6a1c9d3e-0f2b-4c5d-8e7f-a0b1c2d3e4f5").is_ok());
    }

    #[tokio::test]
    async fn the_first_use_of_a_key_is_admitted() {
        // Arrange
        let guard = SeenOnce::default();

        // Act
        let outcome = claim(
            &guard,
            &tenant(),
            "admin-1",
            &key("first-use-key"),
            OffsetDateTime::UNIX_EPOCH,
        )
        .await;

        // Assert
        assert!(outcome.is_ok());
    }

    #[tokio::test]
    async fn a_repeat_of_the_same_key_is_refused_rather_than_executed() {
        // Arrange
        let guard = SeenOnce::default();
        let reused = key("a-repeated-key");
        claim(
            &guard,
            &tenant(),
            "admin-1",
            &reused,
            OffsetDateTime::UNIX_EPOCH,
        )
        .await
        .expect("the first use");

        // Act
        let second = claim(
            &guard,
            &tenant(),
            "admin-1",
            &reused,
            OffsetDateTime::UNIX_EPOCH,
        )
        .await;

        // Assert
        assert!(matches!(second, Err(AdminError::IdempotencyReplay)));
    }

    /// One administrator must not be able to burn another's keys.
    #[tokio::test]
    async fn two_administrators_may_use_the_same_key_text() {
        // Arrange
        let guard = SeenOnce::default();
        let shared = key("create-the-tenant");
        claim(
            &guard,
            &tenant(),
            "admin-1",
            &shared,
            OffsetDateTime::UNIX_EPOCH,
        )
        .await
        .expect("the first administrator");

        // Act
        let other = claim(
            &guard,
            &tenant(),
            "admin-2",
            &shared,
            OffsetDateTime::UNIX_EPOCH,
        )
        .await;

        // Assert
        assert!(other.is_ok());
    }

    /// An unreachable store is not permission to run a creation twice.
    #[tokio::test]
    async fn an_unreachable_store_refuses_rather_than_admits() {
        // Act
        let outcome = claim(
            &Broken,
            &tenant(),
            "admin-1",
            &key("some-valid-key"),
            OffsetDateTime::UNIX_EPOCH,
        )
        .await;

        // Assert
        assert!(matches!(outcome, Err(AdminError::Unavailable)));
    }
}
