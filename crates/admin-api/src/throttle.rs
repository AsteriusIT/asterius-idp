//! Rate limits on `/admin/api`, built out of the counters `ast-2vk.9` already
//! ships.
//!
//! Nothing new is invented here. [`asterius_domain::rate_limit`] owns the
//! fixed-window arithmetic and the [`RateLimitStore`] port, `PgRateLimitStore`
//! owns the row, and the argument for why the state is in the database rather
//! than in process memory — a counter per replica is the configured limit
//! multiplied by the replica count — is made there and applies unchanged. What
//! is here is the one decision this API has to make for itself: what a bucket
//! is.
//!
//! # Every request, not every failure
//!
//! The login limiter counts *failures*, because a successful sign-in costs
//! nothing and a person signing in and out all day should never be limited.
//! The admin API counts *requests*, because the thing being bounded is
//! different: an authenticated administrator — or something holding their
//! session — enumerating a tenant's users at a thousand a second is the
//! abuse, and every one of those requests succeeds.
//!
//! # Why the bucket is the address and not the administrator
//!
//! The limit has to bite *before* the credential is resolved, or an
//! unauthenticated flood still costs one session lookup and one role query
//! per request — which is the denial of service the limit exists to stop. The
//! address is the only thing known that early. It is the address resolved
//! from the socket peer and the trusted proxy set (`ast-2vk.9`'s
//! `ClientAddr`), never a header taken at face value: a caller who can choose
//! the address can choose their own bucket.

use asterius_domain::{Bucket, RateLimit, RateLimitStore, TenantId, admin_api_bucket};
use std::net::IpAddr;
use time::{Duration, OffsetDateTime};

use crate::error::AdminError;

/// Requests one address may make per window, unless a deployment says
/// otherwise.
///
/// Generous, because a console screen is several calls and an operator paging
/// through an audit trail is many: this is a ceiling on abuse, not a pacing
/// mechanism.
pub const DEFAULT_LIMIT: RateLimit = RateLimit {
    max: 600,
    window: Duration::minutes(1),
};

/// Counts one request against `address` and says whether it may proceed.
///
/// An address of `None` — a peer that could not be resolved — is admitted.
/// The alternative is refusing every request from a deployment whose proxy
/// configuration is wrong, which turns a misconfiguration into an outage of
/// the surface an operator would use to fix it.
///
/// # Errors
///
/// [`AdminError::Throttled`] carrying the window's remaining time, and
/// [`AdminError::Unavailable`] if the counters could not be reached — never
/// success, because an unreachable limiter is not permission to be unlimited.
pub async fn admit(
    store: &dyn RateLimitStore,
    limit: RateLimit,
    tenant: &TenantId,
    address: Option<IpAddr>,
    now: OffsetDateTime,
) -> Result<(), AdminError> {
    let Some(address) = address else {
        return Ok(());
    };
    let bucket: Bucket = admin_api_bucket(address);
    let window_start = limit.window_start(now);

    // Counted first, then compared: this limiter counts every request, so the
    // increment is unconditional and the decision is made on the new total.
    // Reading first and writing later would admit a burst that arrives inside
    // one round trip.
    let counted = store
        .record(tenant, &bucket, window_start, limit.window_end(now))
        .await
        .map_err(|error| AdminError::from_storage("admin.rate_limit", &error))?;

    if limit.admits(counted.saturating_sub(1)) {
        Ok(())
    } else {
        Err(AdminError::Throttled {
            retry_after_seconds: retry_after_seconds(limit.retry_after(now)),
        })
    }
}

/// Whole seconds, rounded up and never zero.
///
/// Rounded up because a caller that retries at a truncated hint is still
/// inside the window and is refused again, which reads as a limiter that lies.
fn retry_after_seconds(remaining: Duration) -> u64 {
    let millis = u64::try_from(remaining.whole_milliseconds().max(0)).unwrap_or(u64::MAX);
    millis.div_ceil(1000).max(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use asterius_domain::DomainError;
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    #[derive(Debug, Default)]
    struct Counters(Mutex<BTreeMap<String, u32>>);

    #[async_trait::async_trait]
    impl RateLimitStore for Counters {
        async fn count(
            &self,
            _tenant: &TenantId,
            bucket: &Bucket,
            _window_start: OffsetDateTime,
        ) -> Result<u32, DomainError> {
            Ok(*self
                .0
                .lock()
                .expect("an uncontended lock")
                .get(bucket.as_str())
                .unwrap_or(&0))
        }

        async fn record(
            &self,
            _tenant: &TenantId,
            bucket: &Bucket,
            _window_start: OffsetDateTime,
            _expires_at: OffsetDateTime,
        ) -> Result<u32, DomainError> {
            let mut counts = self.0.lock().expect("an uncontended lock");
            let counted = counts.entry(bucket.as_str().to_owned()).or_insert(0);
            *counted += 1;
            Ok(*counted)
        }

        async fn clear(&self, _tenant: &TenantId, bucket: &Bucket) -> Result<(), DomainError> {
            self.0
                .lock()
                .expect("an uncontended lock")
                .remove(bucket.as_str());
            Ok(())
        }
    }

    #[derive(Debug)]
    struct Unreachable;

    #[async_trait::async_trait]
    impl RateLimitStore for Unreachable {
        async fn count(
            &self,
            _tenant: &TenantId,
            _bucket: &Bucket,
            _window_start: OffsetDateTime,
        ) -> Result<u32, DomainError> {
            Err(DomainError::Storage("no database".into()))
        }

        async fn record(
            &self,
            _tenant: &TenantId,
            _bucket: &Bucket,
            _window_start: OffsetDateTime,
            _expires_at: OffsetDateTime,
        ) -> Result<u32, DomainError> {
            Err(DomainError::Storage("no database".into()))
        }

        async fn clear(&self, _tenant: &TenantId, _bucket: &Bucket) -> Result<(), DomainError> {
            Err(DomainError::Storage("no database".into()))
        }
    }

    fn tenant() -> TenantId {
        TenantId::parse("acme").expect("a valid tenant id")
    }

    fn address() -> IpAddr {
        "198.51.100.7".parse().expect("a literal address")
    }

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("a valid timestamp")
    }

    const TWO_PER_WINDOW: RateLimit = RateLimit {
        max: 2,
        window: Duration::minutes(1),
    };

    #[tokio::test]
    async fn requests_inside_the_limit_are_admitted() {
        // Arrange
        let store = Counters::default();

        // Act / Assert
        for attempt in 1..=2 {
            assert!(
                admit(&store, TWO_PER_WINDOW, &tenant(), Some(address()), now())
                    .await
                    .is_ok(),
                "request {attempt} was refused"
            );
        }
    }

    #[tokio::test]
    async fn the_request_past_the_limit_is_refused_with_a_hint() {
        // Arrange
        let store = Counters::default();
        for _ in 0..2 {
            admit(&store, TWO_PER_WINDOW, &tenant(), Some(address()), now())
                .await
                .expect("inside the limit");
        }

        // Act
        let refused = admit(&store, TWO_PER_WINDOW, &tenant(), Some(address()), now()).await;

        // Assert
        let Err(AdminError::Throttled {
            retry_after_seconds,
        }) = refused
        else {
            panic!("expected a throttle, got {refused:?}");
        };
        assert!(retry_after_seconds >= 1);
    }

    /// Two addresses do not share a budget: one operator must not be able to
    /// lock another out.
    #[tokio::test]
    async fn two_addresses_are_counted_separately() {
        // Arrange
        let store = Counters::default();
        let other: IpAddr = "203.0.113.9".parse().expect("a literal address");
        for _ in 0..2 {
            admit(&store, TWO_PER_WINDOW, &tenant(), Some(address()), now())
                .await
                .expect("inside the limit");
        }

        // Act / Assert
        assert!(
            admit(&store, TWO_PER_WINDOW, &tenant(), Some(other), now())
                .await
                .is_ok()
        );
    }

    /// A misconfigured proxy must not take the admin API off the air.
    #[tokio::test]
    async fn an_unresolved_address_is_admitted() {
        // Arrange
        let store = Counters::default();

        // Act / Assert
        assert!(
            admit(&store, TWO_PER_WINDOW, &tenant(), None, now())
                .await
                .is_ok()
        );
    }

    /// An unreachable limiter is not permission to be unlimited.
    #[tokio::test]
    async fn an_unreachable_store_refuses_rather_than_admits() {
        // Act
        let outcome = admit(
            &Unreachable,
            TWO_PER_WINDOW,
            &tenant(),
            Some(address()),
            now(),
        )
        .await;

        // Assert
        assert!(matches!(outcome, Err(AdminError::Unavailable)));
    }

    #[test]
    fn a_hint_is_never_the_misleading_zero() {
        assert_eq!(retry_after_seconds(Duration::milliseconds(1)), 1);
        assert_eq!(retry_after_seconds(Duration::ZERO), 1);
        assert_eq!(retry_after_seconds(Duration::seconds(30)), 30);
    }
}
