//! The task that makes retention happen.
//!
//! [`asterius_store_pg::PgRetention`] holds the policy — which table is swept,
//! which is kept, and why. This is what runs it: every tenant, every interval,
//! for the life of the process.
//!
//! It is the same shape as [`crate::rotation::RotationSweep`] and for the same
//! reason: what makes a row deletable is the clock passing a timestamp in it,
//! not an event anybody emits, so there is nothing to be notified of and
//! polling is the design rather than a shortcut.
//!
//! Where the two differ is in what they do about other replicas. Rotation lets
//! them race, because the work is a handful of statements per tenant and the
//! transaction makes a race harmless. Retention takes a per-tenant advisory
//! lock and skips a tenant another replica is already sweeping: the work here
//! is unbounded — a busy tenant's `jti_replay` can be millions of rows — and
//! two replicas deleting the same rows would contend on every one of them.
//! Skipping is not a fallback, it is the point: the rows are still there next
//! interval, and by then the replica that took the lock has removed them.

use asterius_domain::DomainError;
use asterius_domain::ports::{Clock, TenantRepository};
use asterius_store_pg::{PgRetention, SweepOutcome};
use std::future::Future;
use std::sync::Arc;
use time::Duration;

/// Walks every tenant and applies the retention policy.
pub struct RetentionSweep {
    retention: PgRetention,
    tenants: Arc<dyn TenantRepository>,
    clock: Arc<dyn Clock>,
    interval: Duration,
}

impl std::fmt::Debug for RetentionSweep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RetentionSweep")
            .field("interval", &self.interval)
            .finish_non_exhaustive()
    }
}

/// What one pass did, for the caller that wants to assert on it.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SweepReport {
    /// Tenants this replica swept.
    pub swept: usize,
    /// Tenants another replica was already sweeping.
    pub busy: usize,
    /// Tenants whose sweep failed. Counted rather than returned, so that one
    /// tenant's broken sweep is not every tenant's.
    pub failed: usize,
    /// Rows deleted across every tenant and table.
    pub deleted: u64,
    /// Whether any table hit its batch ceiling and still had rows to give, so
    /// an operator can tell "nothing to do" from "still catching up".
    pub more_to_do: bool,
}

impl RetentionSweep {
    /// How often the policy is applied.
    ///
    /// Five minutes. Nothing here is urgent — every swept row is already
    /// expired, and every code path that reads one checks the clock rather
    /// than trusting the row's existence — so the interval is chosen against
    /// store growth and not against correctness. More often would multiply
    /// lock acquisitions for no benefit; much less often lets a busy tenant
    /// build a backlog large enough to need several passes.
    pub const DEFAULT_INTERVAL: Duration = Duration::minutes(5);

    /// Builds a sweep over every tenant in `tenants`.
    #[must_use]
    pub fn new(
        retention: PgRetention,
        tenants: Arc<dyn TenantRepository>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self::with_interval(retention, tenants, clock, Self::DEFAULT_INTERVAL)
    }

    /// Builds a sweep with a chosen period, for tests and for a deployment that
    /// wants a different point on the promptness/load trade-off.
    #[must_use]
    pub fn with_interval(
        retention: PgRetention,
        tenants: Arc<dyn TenantRepository>,
        clock: Arc<dyn Clock>,
        interval: Duration,
    ) -> Self {
        Self {
            retention,
            tenants,
            clock,
            interval,
        }
    }

    /// Applies the policy to every tenant, once.
    ///
    /// # Errors
    ///
    /// [`DomainError`] only if the tenant list itself could not be read, which
    /// is the one failure that is not about a particular tenant.
    pub async fn sweep_once(&self) -> Result<SweepReport, DomainError> {
        let now = self.clock.now();
        let tenants = self.tenants.list().await?;
        let mut report = SweepReport::default();

        for tenant in tenants {
            match self.retention.sweep_tenant(&tenant.id, now).await {
                Ok(SweepOutcome::Swept(sweep)) => {
                    report.swept += 1;
                    report.deleted += sweep.total();
                    report.more_to_do |= sweep.more_to_do;
                    if !sweep.deleted.is_empty() {
                        // Table names and counts, and nothing else. A worker
                        // log line is written once and read during an
                        // incident, so what it must not contain is anything
                        // about *whose* rows these were; see the worker case
                        // in `tests/log_redaction.rs`.
                        tracing::debug!(
                            tenant = %tenant.id,
                            deleted = sweep.total(),
                            tables = %summarise(&sweep.deleted),
                            "retention swept a tenant"
                        );
                    }
                }
                Ok(SweepOutcome::Busy) => report.busy += 1,
                Err(error) => {
                    report.failed += 1;
                    // Error, not warning: a tenant that stops being swept
                    // accumulates expired credentials indefinitely, and
                    // nothing else reports it.
                    tracing::error!(
                        %error,
                        tenant = %tenant.id,
                        "could not apply the retention policy"
                    );
                }
            }
        }
        Ok(report)
    }

    /// Sweeps every interval until `shutdown` resolves.
    ///
    /// Sweeps once immediately: a process that has just started may have been
    /// down for a while, and the backlog is the first thing to clear.
    ///
    /// Never returns an error, for the same reason [`crate::rotation`] does not
    /// — there is nobody above this to handle one, and a database that is
    /// briefly unreachable is not a reason to stop sweeping for the life of the
    /// process.
    pub async fn run(self, shutdown: impl Future<Output = ()> + Send) {
        let period = std::time::Duration::try_from(self.interval)
            .unwrap_or_else(|_| std::time::Duration::from_secs(300));
        let mut shutdown = std::pin::pin!(shutdown);

        loop {
            match self.sweep_once().await {
                Ok(report) if report.failed > 0 => {
                    tracing::warn!(
                        swept = report.swept,
                        busy = report.busy,
                        failed = report.failed,
                        deleted = report.deleted,
                        "retention swept with failures"
                    );
                }
                Ok(report) => {
                    tracing::debug!(
                        swept = report.swept,
                        busy = report.busy,
                        deleted = report.deleted,
                        more_to_do = report.more_to_do,
                        "retention swept"
                    );
                }
                Err(error) => {
                    tracing::error!(%error, "could not list tenants to sweep them");
                }
            }

            tokio::select! {
                () = tokio::time::sleep(period) => {}
                () = &mut shutdown => break,
            }
        }
        tracing::info!("retention sweep stopped");
    }
}

/// Renders `table=count` pairs for one log line.
///
/// The table names are compile-time constants from the policy and the counts
/// are numbers, so there is nothing here that a request could have influenced.
fn summarise(deleted: &[(&'static str, u64)]) -> String {
    deleted
        .iter()
        .map(|(table, count)| format!("{table}={count}"))
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_summary_names_each_table_and_its_count() {
        assert_eq!(
            summarise(&[("jti_replay", 12), ("sessions", 3)]),
            "jti_replay=12,sessions=3"
        );
        assert_eq!(summarise(&[]), "");
    }

    /// The interval is a trade-off rather than an arbitrary number: often
    /// enough that no backlog builds between passes, rare enough not to be a
    /// load of its own.
    #[test]
    fn the_default_interval_is_minutes_rather_than_seconds_or_hours() {
        assert!(RetentionSweep::DEFAULT_INTERVAL >= Duration::minutes(1));
        assert!(RetentionSweep::DEFAULT_INTERVAL <= Duration::hours(1));
    }
}
