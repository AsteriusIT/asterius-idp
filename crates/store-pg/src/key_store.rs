//! Making the PostgreSQL key repository serve every tenant.
//!
//! [`PgKeyRepository`] is scoped to one tenant and refuses a call for any
//! other — which is the right shape for a repository, and the wrong shape for
//! the [`KeyStore`] the router holds, since that one object answers for every
//! tenant the server serves.
//!
//! This lives beside the other PostgreSQL adapters rather than in the server
//! crate, because it holds a `PgPool`, and `asterius-server` deliberately has
//! no `sqlx` dependency: SQL belongs to the adapter (ADR-0001).
//!
//! This is the adapter between them. It holds what a repository needs and
//! builds one per call, which is cheap: a pool handle and two `Arc`s. The
//! alternative — making the repository tenant-agnostic — would delete the
//! check that currently makes a cross-tenant call impossible, and that check is
//! worth more than an allocation.

use crate::keys::PgKeyRepository;
use asterius_domain::audit::AuditSink;
use asterius_domain::{DomainError, KeyStore, Kid, PublicKeyRecord, SigningAlgorithm, TenantId};
use asterius_jose::kek::Kek;
use sqlx::postgres::PgPool;
use std::sync::Arc;
use time::OffsetDateTime;

/// A [`KeyStore`] over PostgreSQL that answers for any tenant.
#[derive(Clone)]
pub struct TenantKeyStore {
    pool: PgPool,
    kek: Arc<dyn Kek>,
    audit: Arc<dyn AuditSink>,
}

impl std::fmt::Debug for TenantKeyStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The KEK's id is safe to print — it is derived from the material and
        // reveals nothing about it — and it is the one field an operator
        // debugging "cannot decrypt" actually wants.
        f.debug_struct("TenantKeyStore")
            .field("kek", &self.kek.id())
            .finish_non_exhaustive()
    }
}

impl TenantKeyStore {
    /// Wraps a pool, a key-encryption key and an audit sink.
    #[must_use]
    pub const fn new(pool: PgPool, kek: Arc<dyn Kek>, audit: Arc<dyn AuditSink>) -> Self {
        Self { pool, kek, audit }
    }

    /// The repository for one tenant.
    #[must_use]
    pub fn for_tenant(&self, tenant: &TenantId) -> PgKeyRepository {
        PgKeyRepository::new(
            self.pool.clone(),
            tenant.clone(),
            Arc::clone(&self.kek),
            Arc::clone(&self.audit),
        )
    }

    /// Brings a tenant's keys up to date with its schedule.
    ///
    /// The same call does two jobs, which is why it is the one the server
    /// makes: on a tenant with no keys it creates the first active key, and on
    /// a tenant that already has them it promotes, retires and stages only what
    /// the schedule is due. Running it at startup means a fresh deployment does
    /// not serve an empty JWKS — the first person to notice that would be a
    /// client whose signature check failed.
    ///
    /// # One key per algorithm, not one key
    ///
    /// Every algorithm in [`SigningAlgorithm::ALL`], because the discovery
    /// document advertises all of them: `id_token_signing_alg_values_supported`
    /// is the same closed list (ADR-0003), and OpenID Connect Dynamic Client
    /// Registration 1.0 §2 makes `id_token_signed_response_alg` "REQUIRED for
    /// signing the ID Token issued to this Client" — an obligation on the
    /// server, per client, settled at registration. A tenant that advertises
    /// `PS256` and holds no `PS256` key accepts a registration it can never
    /// honour, and the failure surfaces as a client that cannot log anybody in.
    ///
    /// Three key pairs per tenant rather than one is the cost. It is the right
    /// side of the trade: the alternative is a configuration knob that has to
    /// be kept in step with what the metadata says, and a mismatch there is
    /// exactly the failure this avoids.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the keys cannot be read or created.
    pub async fn apply_schedule(
        &self,
        tenant: &TenantId,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        let repository = self.for_tenant(tenant);
        for algorithm in SigningAlgorithm::ALL {
            repository.apply_schedule(algorithm, now).await?;

            // Then actually open the active key. `apply_schedule` is a no-op on
            // a tenant that already has one, so on its own it never touches the
            // ciphertext — and a server started with the wrong key-encryption
            // key would come up clean and fail on the first token instead.
            // Decrypting once at startup is what makes that a boot failure
            // someone is watching.
            repository
                .active_signing_key(algorithm)
                .await?
                .ok_or_else(|| {
                    DomainError::invalid(
                        "signing_keys",
                        format!("no active {algorithm} signing key after applying the schedule"),
                    )
                })?;
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl KeyStore for TenantKeyStore {
    async fn published_keys(&self, tenant: &TenantId) -> Result<Vec<PublicKeyRecord>, DomainError> {
        self.for_tenant(tenant).published_keys(tenant).await
    }

    async fn public_key(
        &self,
        tenant: &TenantId,
        kid: &Kid,
    ) -> Result<Option<PublicKeyRecord>, DomainError> {
        self.for_tenant(tenant).public_key(tenant, kid).await
    }
}
