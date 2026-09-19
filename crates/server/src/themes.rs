//! Tenant themes cached for browser rendering.

use asterius_domain::ports::ThemeRepository;
use asterius_domain::{DomainError, TenantId, Theme};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

const CACHE_TTL: Duration = Duration::from_secs(30);

#[derive(Debug)]
struct Cached {
    theme: Arc<Theme>,
    loaded_at: Instant,
}

/// A tenant-aware, bounded-staleness theme cache shared by runtime pages and
/// the administrative write path.
#[derive(Clone)]
pub struct ThemeDirectory {
    repository: Arc<dyn ThemeRepository>,
    entries: Arc<RwLock<HashMap<TenantId, Cached>>>,
}

impl std::fmt::Debug for ThemeDirectory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ThemeDirectory").finish_non_exhaustive()
    }
}

impl ThemeDirectory {
    #[must_use]
    pub fn new(repository: Arc<dyn ThemeRepository>) -> Self {
        Self {
            repository,
            entries: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Returns the validated theme, using the default returned by the
    /// repository when the tenant has never saved one.
    pub async fn for_tenant(&self, tenant: &TenantId) -> Result<Arc<Theme>, DomainError> {
        if let Ok(entries) = self.entries.read()
            && let Some(cached) = entries.get(tenant)
            && cached.loaded_at.elapsed() < CACHE_TTL
        {
            return Ok(Arc::clone(&cached.theme));
        }
        let theme = Arc::new(self.repository.theme(tenant).await?);
        if let Ok(mut entries) = self.entries.write() {
            entries.insert(
                tenant.clone(),
                Cached {
                    theme: Arc::clone(&theme),
                    loaded_at: Instant::now(),
                },
            );
        }
        Ok(theme)
    }

    /// Invalidates one tenant immediately after an administrative update.
    pub fn invalidate(&self, tenant: &TenantId) {
        if let Ok(mut entries) = self.entries.write() {
            entries.remove(tenant);
        }
    }

    #[must_use]
    pub fn repository(&self) -> Arc<dyn ThemeRepository> {
        Arc::clone(&self.repository)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asterius_domain::ports::StoredAsset;
    use std::sync::Mutex;

    #[derive(Debug, Default)]
    struct Fake {
        theme: Mutex<Theme>,
        reads: std::sync::atomic::AtomicUsize,
    }

    #[async_trait::async_trait]
    impl ThemeRepository for Fake {
        async fn theme(&self, _tenant: &TenantId) -> Result<Theme, DomainError> {
            self.reads
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(self.theme.lock().expect("an uncontended lock").clone())
        }

        async fn save_theme(&self, _tenant: &TenantId, theme: &Theme) -> Result<(), DomainError> {
            *self.theme.lock().expect("an uncontended lock") = theme.clone();
            Ok(())
        }

        async fn store_asset(
            &self,
            _tenant: &TenantId,
            _asset: &StoredAsset,
        ) -> Result<(), DomainError> {
            Ok(())
        }

        async fn asset(
            &self,
            _tenant: &TenantId,
            _digest: &str,
        ) -> Result<Option<StoredAsset>, DomainError> {
            Ok(None)
        }
    }

    #[tokio::test]
    async fn invalidation_publishes_a_saved_theme_without_cross_tenant_eviction() {
        let repository = Arc::new(Fake::default());
        let directory = ThemeDirectory::new(repository.clone());
        let alpha = TenantId::parse("alpha").expect("tenant id");
        let beta = TenantId::parse("beta").expect("tenant id");

        directory.for_tenant(&alpha).await.expect("first read");
        directory
            .for_tenant(&beta)
            .await
            .expect("second tenant read");
        directory.for_tenant(&alpha).await.expect("cached read");
        assert_eq!(
            repository.reads.load(std::sync::atomic::Ordering::Relaxed),
            2
        );

        directory.invalidate(&alpha);
        directory.for_tenant(&alpha).await.expect("reloaded read");
        directory
            .for_tenant(&beta)
            .await
            .expect("other tenant stayed cached");
        assert_eq!(
            repository.reads.load(std::sync::atomic::Ordering::Relaxed),
            3
        );
    }
}
