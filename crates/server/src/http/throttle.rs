//! The login limiter, as the sign-in handlers use it.
//!
//! The counting rules and the bucket keys are
//! [`asterius_domain::rate_limit`]; what is here is the orchestration around
//! them — read the counters before a credential is checked, count a failure
//! after one is refused, and say the same thing to everybody when a limit is
//! full.
//!
//! # Failures, not attempts
//!
//! The window counts refusals. A successful sign-in costs nothing, so a person
//! who signs in and out all day is never limited, and an attacker's budget is
//! exactly the number of wrong guesses an operator agreed to.
//!
//! # A proof empties the account bucket
//!
//! A fixed window forgets on its own only when it rolls over, which for the
//! default quarter hour means somebody who mistypes nine times and then signs
//! in correctly spends the rest of that window one attempt from a lockout —
//! having just proved they are the person the counter is about
//! (`ast-b3u`). [`LoginThrottle::record_success`] empties the account bucket
//! instead, so the number means "wrong guesses since the last proof".
//!
//! Only the *account* bucket, and only after a credential actually verified.
//! The address bucket is left alone because one account an attacker owns is
//! exactly what they would sign into to buy a fresh sweep budget, and proving
//! one identity says nothing about the thousand identifiers tried alongside
//! it. And the reset is unreachable without a proof, so it is not an
//! enumeration oracle: "no such identifier" and "wrong password" both take
//! the refusal path, where nothing is cleared, and remain the same observable.
//!
//! # What the two limits are for
//!
//! Per account, against somebody stuffing one known identifier. Per address,
//! against somebody sweeping a thousand identifiers once each — which the
//! per-account limit never sees, because no single account is tried twice.
//! Either alone leaves one of the two attacks unbounded.
//!
//! # Why a locked identifier looks like an unknown one
//!
//! The account bucket is keyed by the *typed* identifier, hashed, and it is
//! created on the first failure whether or not any such account exists. So an
//! attacker who exhausts the limit against `nobody@example.test` gets exactly
//! what they get against a real user: the same page, the same words, the same
//! hint. There is no "this account is locked" state to observe, because the
//! limiter never asks the directory anything.
//!
//! What is *not* equalised is the shape of the work: a throttled request skips
//! Argon2id and therefore answers faster than a request that was allowed
//! through. That distinguishes "throttled" from "not throttled" — which the
//! response says out loud anyway, since the whole point is to tell the person
//! to come back later — and it still does not distinguish a real account from
//! an invented one, because both reach the same state after the same number of
//! failures.

use asterius_domain::audit::{Actor, AuditEvent, AuditSink, Detail, EventType, Outcome};
use asterius_domain::rate_limit::{Bucket, LoginLimits, RateLimitStore, Scope};
use asterius_domain::{DomainError, TenantId, account_bucket, ip_bucket};
use std::net::IpAddr;
use time::{Duration, OffsetDateTime};

/// The buckets one sign-in attempt is counted against.
///
/// Either may be absent: an address is missing when the peer could not be
/// resolved, and an identifier is missing from a discoverable-credential
/// assertion, which names nobody by design.
#[derive(Debug, Default, Clone)]
pub struct Attempt {
    /// Where the attempt came from.
    address: Option<Bucket>,
    /// Which identifier it was made against.
    account: Option<Bucket>,
}

impl Attempt {
    /// An attempt from `address`, if one was resolved.
    #[must_use]
    pub fn from(address: Option<IpAddr>) -> Self {
        Self {
            address: address.map(ip_bucket),
            account: None,
        }
    }

    /// The same attempt, made against a typed identifier.
    #[must_use]
    pub fn against(mut self, username: &str) -> Self {
        self.account = Some(account_bucket(username));
        self
    }
}

/// The limiter, bound to one deployment's limits and one client address.
///
/// Carried in the handler contexts rather than assembled per call site, so
/// that a sign-in path cannot be written that forgets to consult it: the thing
/// the handler is handed already knows where the request came from.
#[derive(Debug, Clone, Copy)]
pub struct LoginThrottle<'a> {
    store: &'a dyn RateLimitStore,
    limits: LoginLimits,
    address: Option<IpAddr>,
}

/// Why an attempt was refused, and for how long.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refused {
    /// Which limit was full.
    pub scope: Scope,
    /// How long until it is not.
    pub retry_after: Duration,
}

impl Refused {
    /// The `Retry-After` value, in whole seconds, rounded up.
    ///
    /// Rounded up rather than truncated: a client that retries at the moment a
    /// truncated hint names is still inside the window and is refused again,
    /// which reads as a limiter that lies.
    #[must_use]
    pub fn retry_after_seconds(self) -> u64 {
        let millis =
            u64::try_from(self.retry_after.whole_milliseconds().max(0)).unwrap_or(u64::MAX);
        millis.div_ceil(1000).max(1)
    }

    /// The hint shown on the page.
    ///
    /// Minutes once past a minute, because "try again in 847 seconds" is a
    /// number a person has to do arithmetic on.
    #[must_use]
    pub fn hint(self) -> String {
        let seconds = self.retry_after_seconds();
        if seconds < 60 {
            format!("Too many attempts. Try again in {seconds} seconds.")
        } else {
            let minutes = seconds.div_ceil(60);
            format!("Too many attempts. Try again in {minutes} minutes.")
        }
    }
}

impl<'a> LoginThrottle<'a> {
    /// Builds a limiter over a store, for a request from `address`.
    #[must_use]
    pub const fn new(
        store: &'a dyn RateLimitStore,
        limits: LoginLimits,
        address: Option<IpAddr>,
    ) -> Self {
        Self {
            store,
            limits,
            address,
        }
    }

    /// The attempt this request is: its address, and the identifier it names.
    ///
    /// `None` for a ceremony that names nobody — a discoverable-credential
    /// assertion — which is then limited by address alone, because there is no
    /// identifier to count against and asking the credential who it belongs to
    /// before verifying it would be the enumeration this design avoids.
    #[must_use]
    pub fn attempt(&self, username: Option<&str>) -> Attempt {
        let attempt = Attempt::from(self.address);
        match username {
            Some(username) => attempt.against(username),
            None => attempt,
        }
    }

    /// Whether this attempt may reach the credential check.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if a counter cannot be read. The caller must
    /// not treat that as permission: a limiter that fails open is one an
    /// attacker can switch off by loading the database.
    pub async fn check(
        &self,
        tenant: &TenantId,
        attempt: &Attempt,
        now: OffsetDateTime,
    ) -> Result<Option<Refused>, DomainError> {
        for (scope, bucket, limit) in [
            (Scope::Address, &attempt.address, self.limits.per_address),
            (Scope::Account, &attempt.account, self.limits.per_account),
        ] {
            let Some(bucket) = bucket.as_ref() else {
                continue;
            };
            let counted = self
                .store
                .count(tenant, bucket, limit.window_start(now))
                .await?;
            if !limit.admits(counted) {
                return Ok(Some(Refused {
                    scope,
                    retry_after: limit.retry_after(now),
                }));
            }
        }
        Ok(None)
    }

    /// Forgets the failures counted against the identifier that just signed in.
    ///
    /// Called only where a credential verified — a password the verifier
    /// accepted, or an assertion that satisfied WebAuthn §7.2. Reaching it from
    /// any refusal, including the one that means "no such identifier", would
    /// make the reset observable and reopen the enumeration channel the account
    /// bucket exists to close.
    ///
    /// The account bucket only. Emptying the address one would let an attacker
    /// sweeping a thousand identifiers refill their budget by signing into the
    /// single account they own, which is the attack that limit is for. An
    /// attempt that names nobody — a discoverable-credential assertion — has no
    /// account bucket and so clears nothing.
    ///
    /// A delete that fails is logged and swallowed: the sign-in succeeded, and
    /// refusing it now because a counter could not be forgotten would punish
    /// the person for a write this server could not do. The window still
    /// expires on its own.
    pub async fn record_success(&self, tenant: &TenantId, attempt: &Attempt) {
        let Some(bucket) = attempt.account.as_ref() else {
            return;
        };
        if let Err(error) = self.store.clear(tenant, bucket).await {
            tracing::error!(%error, tenant = %tenant, "a successful sign-in did not clear its limit");
        }
    }

    /// Counts one refused sign-in against both of the attempt's buckets.
    ///
    /// Both, always. Counting only the bucket nearest its limit would leave
    /// the other unreachable, and the two bound different attacks.
    ///
    /// A write that fails is logged and swallowed: the sign-in has already
    /// been refused, and turning a limiter outage into a failed *refusal*
    /// would be the wrong way round. It is visible in the logs and, at volume,
    /// in the absence of the throttle metric.
    pub async fn record_failure(&self, tenant: &TenantId, attempt: &Attempt, now: OffsetDateTime) {
        for (bucket, limit) in [
            (&attempt.address, self.limits.per_address),
            (&attempt.account, self.limits.per_account),
        ] {
            let Some(bucket) = bucket.as_ref() else {
                continue;
            };
            if let Err(error) = self
                .store
                .record(
                    tenant,
                    bucket,
                    limit.window_start(now),
                    limit.window_end(now),
                )
                .await
            {
                tracing::error!(%error, tenant = %tenant, "a failed sign-in was not counted");
            }
        }
    }
}

/// The trail record for a refused-before-checked attempt.
///
/// Separate from [`record_throttled`] so its shape can be asserted without a
/// sink. It names the tenant and the limit that was full, and nothing else:
/// the identifier that was typed is not in the record, because a trail of the
/// usernames an attacker guessed is a list of accounts worth attacking that
/// anybody with read access to the trail inherits. The actor is
/// [`Actor::System`] for the same reason it is not a user — nobody has been
/// identified, and inventing a subject from a form field would put an
/// attacker's text in the subject column.
#[must_use]
pub fn throttled_event(tenant: &TenantId, refused: Refused, now: OffsetDateTime) -> AuditEvent {
    AuditEvent::new(
        tenant.clone(),
        EventType::AUTH_THROTTLED,
        Outcome::Failure,
        Actor::System,
        now,
    )
    .detail(Detail::new().label("limit", refused.scope.as_str()).number(
        "retry_after_seconds",
        i64::try_from(refused.retry_after_seconds()).unwrap_or(i64::MAX),
    ))
}

/// Appends that record, and counts the refusal.
///
/// A failure to write is logged and does not propagate: the attempt is
/// refused either way, and an audit outage must not become an authentication
/// bypass or a 500.
pub async fn record_throttled(
    audit: &dyn AuditSink,
    tenant: &TenantId,
    refused: Refused,
    now: OffsetDateTime,
) {
    crate::observability::metrics::login_throttled(refused.scope.as_str());
    if let Err(failure) = audit.record(throttled_event(tenant, refused, now)).await {
        tracing::error!(
            %failure,
            tenant = %tenant,
            "a throttled sign-in was not written to the audit trail"
        );
    }
}

/// The trail record for a credential that was checked and did not match.
///
/// Names no identifier, for the reason [`throttled_event`] names none: the
/// string came from an unauthenticated form, and a trail of the identifiers
/// people guessed is a target list. What it does carry is the method, so that
/// "someone is guessing passwords" and "someone is replaying assertions" are
/// separable in the trail even though both are `auth.failed`.
#[must_use]
pub fn failed_password_event(tenant: &TenantId, now: OffsetDateTime) -> AuditEvent {
    AuditEvent::new(
        tenant.clone(),
        EventType::AUTH_FAILED,
        Outcome::Failure,
        Actor::System,
        now,
    )
    .detail(Detail::new().label("method", "password"))
}

/// Appends that record. A failure to write is logged and does not propagate:
/// the sign-in is refused either way.
pub async fn record_failed_password(audit: &dyn AuditSink, tenant: &TenantId, now: OffsetDateTime) {
    if let Err(failure) = audit.record(failed_password_event(tenant, now)).await {
        tracing::error!(
            %failure,
            tenant = %tenant,
            "a failed sign-in was not written to the audit trail"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asterius_domain::RateLimit;
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    /// Counters in memory. Enough to assert what the limiter decides; it is
    /// deliberately not what the server runs, because a per-process counter
    /// limits nothing across replicas.
    #[derive(Debug, Default)]
    struct Counters(Mutex<BTreeMap<(String, i64), u32>>);

    #[async_trait::async_trait]
    impl RateLimitStore for Counters {
        async fn count(
            &self,
            _tenant: &TenantId,
            bucket: &Bucket,
            window_start: OffsetDateTime,
        ) -> Result<u32, DomainError> {
            let counters = self.0.lock().expect("the test store is not poisoned");
            Ok(*counters
                .get(&(bucket.as_str().to_owned(), window_start.unix_timestamp()))
                .unwrap_or(&0))
        }

        async fn record(
            &self,
            _tenant: &TenantId,
            bucket: &Bucket,
            window_start: OffsetDateTime,
            _expires_at: OffsetDateTime,
        ) -> Result<u32, DomainError> {
            let mut counters = self.0.lock().expect("the test store is not poisoned");
            let entry = counters
                .entry((bucket.as_str().to_owned(), window_start.unix_timestamp()))
                .or_default();
            *entry += 1;
            Ok(*entry)
        }

        async fn clear(&self, _tenant: &TenantId, bucket: &Bucket) -> Result<(), DomainError> {
            let mut counters = self.0.lock().expect("the test store is not poisoned");
            counters.retain(|(key, _), _| key != bucket.as_str());
            Ok(())
        }
    }

    fn limits() -> LoginLimits {
        LoginLimits {
            per_address: RateLimit {
                max: 5,
                window: Duration::minutes(15),
            },
            per_account: RateLimit {
                max: 2,
                window: Duration::minutes(15),
            },
        }
    }

    fn tenant() -> TenantId {
        TenantId::parse("demo").expect("`demo` is a valid tenant id")
    }

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("a valid timestamp")
    }

    fn address() -> IpAddr {
        "198.51.100.7".parse().expect("a literal address")
    }

    #[tokio::test]
    async fn a_first_attempt_is_allowed() {
        let store = Counters::default();
        let throttle = LoginThrottle::new(&store, limits(), Some(address()));

        let refused = throttle
            .check(&tenant(), &throttle.attempt(Some("alice")), now())
            .await
            .expect("the test store counts");

        assert_eq!(refused, None);
    }

    #[tokio::test]
    async fn repeated_failures_against_one_identifier_throttle_it() {
        let store = Counters::default();
        let throttle = LoginThrottle::new(&store, limits(), Some(address()));
        let attempt = throttle.attempt(Some("alice"));

        for _ in 0..2 {
            throttle.record_failure(&tenant(), &attempt, now()).await;
        }

        let refused = throttle
            .check(&tenant(), &attempt, now())
            .await
            .expect("the test store counts");
        assert_eq!(refused.map(|r| r.scope), Some(Scope::Account));
    }

    /// The sweep the per-account limit cannot see: one attempt each against
    /// many identifiers, all from one address.
    #[tokio::test]
    async fn a_sweep_across_many_identifiers_throttles_the_address() {
        let store = Counters::default();
        let throttle = LoginThrottle::new(&store, limits(), Some(address()));
        for who in ["a", "b", "c", "d", "e"] {
            throttle
                .record_failure(&tenant(), &throttle.attempt(Some(who)), now())
                .await;
        }

        let refused = throttle
            .check(&tenant(), &throttle.attempt(Some("f")), now())
            .await
            .expect("the test store counts");

        assert_eq!(refused.map(|r| r.scope), Some(Scope::Address));
    }

    /// The property this ticket turns on: an identifier nobody owns reaches
    /// the same throttled state, in the same number of attempts, as one
    /// somebody does — so "locked" and "no such account" are not tellable
    /// apart.
    #[tokio::test]
    async fn an_unknown_identifier_throttles_exactly_like_a_real_one() {
        let store = Counters::default();
        let throttle = LoginThrottle::new(&store, limits(), Some(address()));
        let real = Attempt::from(None).against("alice");
        let invented = Attempt::from(None).against("nobody@example.test");

        for _ in 0..2 {
            throttle.record_failure(&tenant(), &real, now()).await;
            throttle.record_failure(&tenant(), &invented, now()).await;
        }

        let against_real = throttle
            .check(&tenant(), &real, now())
            .await
            .expect("the test store counts");
        let against_invented = throttle
            .check(&tenant(), &invented, now())
            .await
            .expect("the test store counts");
        assert_eq!(against_real, against_invented);
    }

    #[tokio::test]
    async fn a_successful_sign_in_costs_nothing_because_only_failures_are_counted() {
        let store = Counters::default();
        let throttle = LoginThrottle::new(&store, limits(), Some(address()));
        let attempt = throttle.attempt(Some("alice"));

        for _ in 0..50 {
            let refused = throttle
                .check(&tenant(), &attempt, now())
                .await
                .expect("the test store counts");
            assert_eq!(refused, None);
        }
    }

    #[tokio::test]
    async fn the_limit_lifts_when_the_window_rolls_over() {
        let store = Counters::default();
        let throttle = LoginThrottle::new(&store, limits(), Some(address()));
        let attempt = throttle.attempt(Some("alice"));
        for _ in 0..2 {
            throttle.record_failure(&tenant(), &attempt, now()).await;
        }

        let later = now() + Duration::minutes(16);

        let refused = throttle
            .check(&tenant(), &attempt, later)
            .await
            .expect("the test store counts");
        assert_eq!(refused, None);
    }

    #[test]
    fn a_hint_is_a_whole_number_of_seconds_and_never_zero() {
        let refused = Refused {
            scope: Scope::Account,
            retry_after: Duration::milliseconds(1),
        };

        assert_eq!(refused.retry_after_seconds(), 1);
    }

    #[test]
    fn a_long_wait_is_offered_in_minutes() {
        let refused = Refused {
            scope: Scope::Account,
            retry_after: Duration::seconds(847),
        };

        assert!(refused.hint().contains("15 minutes"));
    }

    #[test]
    fn a_refused_password_is_recorded_without_the_identifier_that_was_typed() {
        let event = failed_password_event(&tenant(), now());

        assert_eq!(event.event_type, EventType::AUTH_FAILED);
        assert_eq!(event.outcome, Outcome::Failure);
        assert_eq!(event.subject, None);
        assert!(format!("{:?}", event.detail).contains("password"));
    }

    /// A trail of the identifiers an attacker guessed would be a list of
    /// accounts worth attacking, handed to whoever can read the trail.
    #[test]
    fn the_trail_record_names_the_limit_and_not_the_identifier() {
        let refused = Refused {
            scope: Scope::Account,
            retry_after: Duration::seconds(60),
        };

        let event = throttled_event(&tenant(), refused, now());

        let rendered = format!("{:?}", event.detail);
        assert!(rendered.contains("account"));
        assert!(!rendered.contains("alice"));
        assert_eq!(event.event_type, EventType::AUTH_THROTTLED);
    }

    /// The point of `ast-b3u`: nine wrong guesses and then the right password
    /// leaves a full quota, not one attempt's worth. The person just proved who
    /// they are; making them wait out the window is a lockout aimed at the
    /// wrong party.
    #[tokio::test]
    async fn a_successful_sign_in_empties_the_account_bucket() {
        // Arrange: at the limit, so the next attempt would be refused.
        let store = Counters::default();
        let throttle = LoginThrottle::new(&store, limits(), Some(address()));
        let attempt = throttle.attempt(Some("alice"));
        for _ in 0..2 {
            throttle.record_failure(&tenant(), &attempt, now()).await;
        }

        // Act
        throttle.record_success(&tenant(), &attempt).await;

        // Assert
        let refused = throttle
            .check(&tenant(), &attempt, now())
            .await
            .expect("the test store counts");
        assert_eq!(refused, None);
    }

    /// The window boundary is aligned to the epoch, so a proof made just before
    /// a rollover must not leave a counter for the next window to inherit.
    #[tokio::test]
    async fn a_successful_sign_in_empties_every_window_of_the_bucket() {
        // Arrange: failures in two different windows.
        let store = Counters::default();
        let throttle = LoginThrottle::new(&store, limits(), Some(address()));
        let attempt = throttle.attempt(Some("alice"));
        throttle.record_failure(&tenant(), &attempt, now()).await;
        let later = now() + Duration::minutes(16);
        for _ in 0..2 {
            throttle.record_failure(&tenant(), &attempt, later).await;
        }

        // Act
        throttle.record_success(&tenant(), &attempt).await;

        // Assert
        assert_eq!(
            throttle
                .check(&tenant(), &attempt, later)
                .await
                .expect("the test store counts"),
            None
        );
    }

    /// The address bucket bounds a sweep across many identifiers, and one
    /// account the attacker owns is exactly what they would sign into to buy
    /// themselves a fresh budget. Proving one identity says nothing about the
    /// other identifiers tried from that address.
    #[tokio::test]
    async fn a_successful_sign_in_leaves_the_address_bucket_alone() {
        // Arrange: a sweep that filled the address bucket.
        let store = Counters::default();
        let throttle = LoginThrottle::new(&store, limits(), Some(address()));
        for who in ["a", "b", "c", "d", "e"] {
            throttle
                .record_failure(&tenant(), &throttle.attempt(Some(who)), now())
                .await;
        }

        // Act
        throttle
            .record_success(&tenant(), &throttle.attempt(Some("mine")))
            .await;

        // Assert
        let refused = throttle
            .check(&tenant(), &throttle.attempt(Some("mine")), now())
            .await
            .expect("the test store counts");
        assert_eq!(refused.map(|r| r.scope), Some(Scope::Address));
    }

    /// An attempt that named nobody — a discoverable-credential assertion —
    /// has no account bucket to empty, and must not reach for the address one
    /// instead.
    #[tokio::test]
    async fn a_success_that_names_nobody_empties_nothing() {
        // Arrange
        let store = Counters::default();
        let throttle = LoginThrottle::new(&store, limits(), Some(address()));
        for who in ["a", "b", "c", "d", "e"] {
            throttle
                .record_failure(&tenant(), &throttle.attempt(Some(who)), now())
                .await;
        }

        // Act
        throttle
            .record_success(&tenant(), &throttle.attempt(None))
            .await;

        // Assert
        let refused = throttle
            .check(&tenant(), &throttle.attempt(Some("f")), now())
            .await
            .expect("the test store counts");
        assert_eq!(refused.map(|r| r.scope), Some(Scope::Address));
    }
}
