//! The task that makes key rotation happen.
//!
//! `PgKeyRepository::apply_schedule` is the whole of the rotation mechanism:
//! it stages a key when one is due, promotes a `pending` key that has been
//! published for its propagation period, and retires a `retiring` key whose
//! grace has expired. Until this existed, the only caller in the binary was
//! `main`, once, at boot.
//!
//! That made "rotation" a thing that happened when somebody restarted the
//! server. A key staged on Monday stayed `pending` — published, unusable, and
//! not signing anything — until the next deploy. A key whose grace expired
//! stayed in the JWKS indefinitely. And a tenant created through the admin API
//! held no keys at all, so every token request for it failed with
//! `NoSigningKey` until a restart it had no way to ask for. None of that
//! announced itself: the tokens that *were* issued verified fine, because the
//! key still signing them was still published (`ast-mxc.9`).
//!
//! # How long a rotation takes to take effect
//!
//! Two delays in series. This task notices that a key is due within one
//! sweep interval, and [`crate::signing::CachedSigner`] notices
//! the promoted key within one of its own TTLs. So a promotion reaches the
//! signer in at most the sum of the two — about two minutes at the defaults.
//!
//! What that has to stay below is the *grace period*, because the failure this
//! avoids is signing under a key that has been retired out of the JWKS. Grace
//! is measured in hours or days (a week by default) and must already exceed
//! the lifetime of the longest-lived token signed under the key. Two minutes
//! against a week is three orders of magnitude of headroom, which is the
//! margin that makes a polling design correct here rather than merely
//! convenient.
//!
//! # Why polling rather than notifying
//!
//! The schedule is a row, and the thing that makes a key due is the clock
//! passing a timestamp in it — not an event anybody emits. There is nothing to
//! be notified *of*. A rotation performed by an operator on one replica is
//! likewise a row change, which the next sweep on every other replica sees.
//!
//! Several replicas sweeping at once is safe rather than merely tolerable:
//! `apply_schedule` does its work in one transaction and is idempotent, so two
//! replicas racing produce one staged key, not two. It is wasteful — *n*
//! replicas do *n* times the work — but the work is a handful of statements
//! per tenant per minute, and an advisory lock to avoid it would buy less than
//! it costs to reason about.

use asterius_domain::DomainError;
use asterius_domain::ports::{Clock, TenantRepository};
use asterius_store_pg::TenantKeyStore;
use std::future::Future;
use std::sync::Arc;
use time::Duration;

/// Walks every tenant and applies its key schedule.
pub struct RotationSweep {
    keys: TenantKeyStore,
    tenants: Arc<dyn TenantRepository>,
    clock: Arc<dyn Clock>,
    interval: Duration,
}

impl std::fmt::Debug for RotationSweep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RotationSweep")
            .field("interval", &self.interval)
            .finish_non_exhaustive()
    }
}

/// What one pass did, for the caller that wants to assert on it.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SweepOutcome {
    /// Tenants whose schedule was applied without error.
    pub swept: usize,
    /// Tenants whose schedule could not be applied.
    ///
    /// Counted rather than returned: one tenant's failure must not become
    /// every other tenant's, and the detail an operator needs is in the log
    /// beside the tenant it belongs to.
    pub failed: usize,
}

impl RotationSweep {
    /// How often the schedule is applied.
    ///
    /// Sixty seconds. The propagation period is the shortest thing a sweep has
    /// to keep up with, and the schema's floor for it is one second — but a
    /// key that becomes active a minute later than it strictly could costs
    /// nothing, because the key it replaces is still active and still
    /// published for its whole grace period. Sweeping faster would buy a
    /// promptness nothing needs and multiply the query load by the same
    /// factor.
    pub const DEFAULT_INTERVAL: Duration = Duration::seconds(60);

    /// Builds a sweep over every tenant in `tenants`.
    #[must_use]
    pub fn new(
        keys: TenantKeyStore,
        tenants: Arc<dyn TenantRepository>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self::with_interval(keys, tenants, clock, Self::DEFAULT_INTERVAL)
    }

    /// Builds a sweep with a chosen period, for tests and for a deployment
    /// that wants a different point on the promptness/load trade-off.
    #[must_use]
    pub fn with_interval(
        keys: TenantKeyStore,
        tenants: Arc<dyn TenantRepository>,
        clock: Arc<dyn Clock>,
        interval: Duration,
    ) -> Self {
        Self {
            keys,
            tenants,
            clock,
            interval,
        }
    }

    /// Applies every tenant's schedule once.
    ///
    /// Public and separate from [`RotationSweep::run`] so that a test can drive
    /// a promotion through the real task without waiting for a timer, and so
    /// that `main` can do a first pass synchronously at boot and fail there if
    /// the key-encryption key is wrong.
    ///
    /// One tenant's failure does not stop the others. A tenant whose key
    /// material cannot be unwrapped is a serious fault, but it is *that
    /// tenant's* fault, and letting it abort the pass would stop every other
    /// tenant's keys from rotating too — turning one broken tenant into a
    /// deployment-wide outage some weeks later, when the last good key aged
    /// out of the JWKS.
    ///
    /// # Errors
    ///
    /// [`DomainError`] only if the tenant list itself could not be read, which
    /// is the one failure that is not about a particular tenant.
    pub async fn sweep_once(&self) -> Result<SweepOutcome, DomainError> {
        let now = self.clock.now();
        let tenants = self.tenants.list().await?;
        let mut outcome = SweepOutcome::default();

        for tenant in tenants {
            match self.keys.apply_schedule(&tenant.id, now).await {
                Ok(()) => outcome.swept += 1,
                Err(error) => {
                    outcome.failed += 1;
                    // Error, not warning: nothing else reports this, and a
                    // tenant that stops rotating is on a clock that ends with
                    // its last key leaving the JWKS.
                    tracing::error!(
                        %error,
                        tenant = %tenant.id,
                        "could not apply the key rotation schedule"
                    );
                }
            }
        }
        Ok(outcome)
    }

    /// Sweeps every interval until `shutdown` resolves.
    ///
    /// Sweeps once immediately, before the first wait. A process that has just
    /// started is exactly the process most likely to be a *new* replica, or to
    /// have been down while a key came due.
    ///
    /// Never returns an error. A failure to read the tenant list is logged and
    /// the next pass tries again: the database being briefly unreachable is
    /// not a reason to stop rotating keys for the life of the process, and
    /// there is nobody above this to handle it.
    pub async fn run(self, shutdown: impl Future<Output = ()> + Send) {
        let period = std::time::Duration::try_from(self.interval)
            .unwrap_or_else(|_| std::time::Duration::from_secs(60));
        let mut shutdown = std::pin::pin!(shutdown);

        loop {
            match self.sweep_once().await {
                Ok(outcome) if outcome.failed > 0 => {
                    tracing::warn!(
                        swept = outcome.swept,
                        failed = outcome.failed,
                        "key rotation swept with failures"
                    );
                }
                Ok(outcome) => {
                    tracing::debug!(swept = outcome.swept, "key rotation swept");
                }
                Err(error) => {
                    tracing::error!(%error, "could not list tenants to rotate their keys");
                }
            }

            tokio::select! {
                () = tokio::time::sleep(period) => {}
                () = &mut shutdown => break,
            }
        }
        tracing::info!("key rotation sweep stopped");
    }
}
