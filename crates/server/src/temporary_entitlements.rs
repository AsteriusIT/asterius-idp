//! Bounded expiry reconciliation. Authority checks the database clock at use;
//! this worker only records each immutable deadline's expiry once for audit.
use asterius_domain::ports::TenantRepository;
use asterius_domain::temporary_entitlements::TemporaryEntitlements;
use std::future::Future;
use std::sync::Arc;

pub struct TemporaryEntitlementSweep {
    entitlements: Arc<dyn TemporaryEntitlements>,
    tenants: Arc<dyn TenantRepository>,
}
impl std::fmt::Debug for TemporaryEntitlementSweep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TemporaryEntitlementSweep")
            .finish_non_exhaustive()
    }
}
impl TemporaryEntitlementSweep {
    #[must_use]
    pub fn new(
        entitlements: Arc<dyn TemporaryEntitlements>,
        tenants: Arc<dyn TenantRepository>,
    ) -> Self {
        Self {
            entitlements,
            tenants,
        }
    }
    /// Each tenant gets one bounded batch. Replica races are serialized by the
    /// same tenant fence as publication and the transactional expiry marker.
    pub async fn sweep_once(&self) -> Result<u64, asterius_domain::DomainError> {
        let mut recorded = 0;
        for tenant in self.tenants.list().await? {
            if !tenant.is_active() {
                continue;
            }
            match self.entitlements.reconcile_expired(&tenant.id, 100).await {
                Ok(count) => recorded += count,
                Err(_) => {
                    // Deliberately omit database errors and any lifecycle identity.
                    tracing::error!(tenant = %tenant.id, "temporary entitlement expiry reconciliation failed");
                }
            }
        }
        Ok(recorded)
    }
    /// Immediately catches up after startup, then repeats once per minute.
    /// Shutdown never requires the clock or the expiry store to be available.
    pub async fn run(self, shutdown: impl Future<Output = ()> + Send) {
        let mut shutdown = std::pin::pin!(shutdown);
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                () = &mut shutdown => break,
                _ = interval.tick() => {
                    if self.sweep_once().await.is_err() {
                        tracing::error!("temporary entitlement tenant enumeration failed");
                    }
                }
            }
        }
    }
}
