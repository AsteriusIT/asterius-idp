//! The per-tenant settings a request is served under, and the cache in front
//! of them.
//!
//! # Why there is a cache, and why it is invalidated rather than expired
//!
//! Every discovery request would otherwise read a row: the document is public,
//! unauthenticated and fetched by every client that starts up. So the settings
//! are held in process behind a short TTL, exactly like
//! [`crate::tenancy::TenantDirectory`]'s snapshot and for the same reasons —
//! tens of tenants, changing rarely, and there is no Redis (ADR-0001).
//!
//! The TTL is the safety net, not the mechanism. `ast-f7m.4`'s acceptance
//! criterion is that switching a feature flag off changes the discovery
//! document *immediately*, so the admin API drops this cache when it writes
//! (`AdminBackend::tenant_directory_changed`), and the TTL is what catches the
//! case where the write happened in another replica, which has no way to tell
//! this one.
//!
//! # A read that fails is not "the defaults"
//!
//! [`SettingsDirectory::for_tenant`] returns the repository's error rather
//! than falling back. A tenant whose settings cannot be read is a tenant whose
//! *disabled* features would otherwise reappear in the document, which is the
//! one direction that must never happen by accident: the caller answers 503,
//! and a client retries a moment later, instead of being told this server does
//! something the operator switched off.

use asterius_domain::ports::TenantSettingsRepository;
use asterius_domain::{DomainError, TenantId, TenantSettings};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// How long a cached settings document is served before it is re-read.
///
/// The same thirty seconds [`crate::tenancy`] uses, for the same reason.
const CACHE_TTL: Duration = Duration::from_secs(30);

/// A settings repository plus an in-process cache.
#[derive(Clone)]
pub struct SettingsDirectory {
    repository: Arc<dyn TenantSettingsRepository>,
    cached: Arc<RwLock<HashMap<String, (TenantSettings, Instant)>>>,
}

impl std::fmt::Debug for SettingsDirectory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let held = self.cached.read().ok().map(|guard| guard.len());
        f.debug_struct("SettingsDirectory")
            .field("cached", &held)
            .finish_non_exhaustive()
    }
}

impl SettingsDirectory {
    /// Wraps a repository.
    #[must_use]
    pub fn new(repository: Arc<dyn TenantSettingsRepository>) -> Self {
        Self {
            repository,
            cached: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Drops everything cached, so the next read reloads.
    ///
    /// Everything and not one tenant: the admin API's hook says "something
    /// about the tenants changed", and a cache that had to be told *which*
    /// tenant would be one more thing a caller can get wrong. Reloading a
    /// handful of rows costs nothing next to serving a flag an operator
    /// believes they turned off.
    pub fn invalidate(&self) {
        if let Ok(mut guard) = self.cached.write() {
            guard.clear();
        }
    }

    /// This tenant's settings, from the cache or from the repository.
    ///
    /// # Errors
    ///
    /// Whatever the repository returns, including a stored document this build
    /// refuses to read.
    pub async fn for_tenant(&self, tenant: &TenantId) -> Result<TenantSettings, DomainError> {
        if let Ok(guard) = self.cached.read()
            && let Some((settings, loaded_at)) = guard.get(tenant.as_str())
            && loaded_at.elapsed() < CACHE_TTL
        {
            return Ok(settings.clone());
        }

        // Loaded outside the lock, which this lock type requires anyway. Two
        // requests racing here both read and one wins the write, which costs a
        // duplicate query on a cold cache.
        let settings = self.repository.settings(tenant).await?;
        if let Ok(mut guard) = self.cached.write() {
            guard.insert(
                tenant.as_str().to_owned(),
                (settings.clone(), Instant::now()),
            );
        }
        Ok(settings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asterius_domain::Feature;
    use std::collections::BTreeSet;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Debug)]
    struct Counted {
        reads: AtomicUsize,
        settings: RwLock<TenantSettings>,
    }

    #[async_trait::async_trait]
    impl TenantSettingsRepository for Counted {
        async fn settings(&self, _tenant: &TenantId) -> Result<TenantSettings, DomainError> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            Ok(self.settings.read().expect("an uncontended lock").clone())
        }

        async fn save(
            &self,
            _tenant: &TenantId,
            settings: &TenantSettings,
        ) -> Result<(), DomainError> {
            *self.settings.write().expect("an uncontended lock") = settings.clone();
            Ok(())
        }
    }

    fn disabling(feature: Feature) -> TenantSettings {
        TenantSettings::validated(
            BTreeSet::from([feature]),
            asterius_domain::entities::tenant_settings::DEFAULT_AUTHORIZATION_CODE_LIFETIME,
            asterius_domain::entities::tenant_settings::DEFAULT_ACCESS_TOKEN_LIFETIME,
        )
        .expect("within the caps")
    }

    fn tenant() -> TenantId {
        TenantId::parse("demo").expect("a valid tenant id")
    }

    #[tokio::test]
    async fn repeated_reads_are_served_from_the_cache() {
        // Arrange
        let repository = Arc::new(Counted {
            reads: AtomicUsize::new(0),
            settings: RwLock::new(TenantSettings::default()),
        });
        let directory = SettingsDirectory::new(Arc::clone(&repository) as _);

        // Act
        for _ in 0..3 {
            directory.for_tenant(&tenant()).await.expect("settings");
        }

        // Assert
        assert_eq!(repository.reads.load(Ordering::SeqCst), 1);
    }

    /// `ast-f7m.4`: a flag written through the admin API must be visible to the
    /// next request, not to the one thirty seconds later.
    #[tokio::test]
    async fn an_invalidated_cache_serves_the_new_settings_at_once() {
        // Arrange
        let repository = Arc::new(Counted {
            reads: AtomicUsize::new(0),
            settings: RwLock::new(TenantSettings::default()),
        });
        let directory = SettingsDirectory::new(Arc::clone(&repository) as _);
        directory.for_tenant(&tenant()).await.expect("settings");

        // Act
        repository
            .save(&tenant(), &disabling(Feature::DpopNonce))
            .await
            .expect("a write");
        directory.invalidate();
        let served = directory.for_tenant(&tenant()).await.expect("settings");

        // Assert
        assert!(served.disabled_features().contains(&Feature::DpopNonce));
    }

    /// The other half: without the invalidation the old document is still
    /// served, which is what makes the invalidation the thing under test
    /// rather than an accident of timing.
    #[tokio::test]
    async fn without_invalidation_the_cached_settings_are_still_served() {
        // Arrange
        let repository = Arc::new(Counted {
            reads: AtomicUsize::new(0),
            settings: RwLock::new(TenantSettings::default()),
        });
        let directory = SettingsDirectory::new(Arc::clone(&repository) as _);
        directory.for_tenant(&tenant()).await.expect("settings");

        // Act
        repository
            .save(&tenant(), &disabling(Feature::DpopNonce))
            .await
            .expect("a write");
        let served = directory.for_tenant(&tenant()).await.expect("settings");

        // Assert
        assert!(
            served.disabled_features().is_empty(),
            "the cache did not hold"
        );
    }
}
