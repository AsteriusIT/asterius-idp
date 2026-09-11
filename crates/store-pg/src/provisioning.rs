//! Making "a tenant exists" and "a tenant has signing keys" the same event.
//!
//! # The bug this exists for
//!
//! Signing keys used to be provisioned in exactly one place: a loop in `main`
//! over the tenants named in the configuration file, run once at startup
//! (`ast-mxc.9`). Every other way of creating a tenant produced one with no
//! keys at all — and since `ast-a05.13` a tenant with no keys refuses *every*
//! dynamic client registration with `invalid_client_metadata`, not only the
//! ones naming a non-default algorithm, because the endpoint checks that the
//! tenant holds an active key for the `id_token_signed_response_alg` being
//! registered. The tenant is inert until somebody restarts the server, which
//! is not something the tenant can ask for.
//!
//! [`crate::PgAdminSeed`] is one such path, and the admin API (`ast-f7m.3`)
//! will be another. Adding [`TenantKeyStore::apply_schedule`] to each caller
//! fixes the callers that exist and leaves the bug waiting for the next one.
//! This type makes the pairing a property of the repository a caller holds
//! instead: [`upsert`] does not return until the tenant can sign.
//!
//! [`upsert`]: TenantRepository::upsert
//!
//! # Why a decorator and not [`PgTenantRepository::upsert`] itself
//!
//! Folding the provisioning into the adapter would be stronger — no wrapper to
//! forget — and it was tried first. It is not usable here, for one blunt
//! reason: `PgTenantRepository` is also the only way to create a tenant in the
//! tests of `asterius-server`, which has no `sqlx` dependency by ADR-0001 and
//! therefore cannot write a `tenants` row by hand. A repository that always
//! provisions makes a tenant holding *no* keys, or holding one algorithm's
//! key and not another's, impossible to construct — and those two states are
//! exactly what the signer's refusal tests (`signing.rs`) and the rotation
//! sweep's tests (`rotation.rs`) are about. The guarantee would have been paid
//! for by deleting the tests that prove the degraded case is handled.
//!
//! So the adapter keeps writing exactly the row it is asked for, and the
//! guarantee lives one layer up, at the port every consumer holds. That is the
//! layer the admin API will see: it takes `dyn TenantRepository` from the
//! composition root and has no way to reach the bare adapter.
//!
//! # Concurrency and repetition
//!
//! Both are already handled by what this calls, which is why it calls it
//! rather than writing keys itself. `PgKeyRepository`'s pass runs in one
//! transaction holding `pg_advisory_xact_lock(hashtext(tenant),
//! hashtext('key-rotation'))` — the same two-key lock space
//! [`crate::retention`] and [`crate::rewrap`] use with their own second key —
//! so two replicas creating the same tenant at the same moment produce one set
//! of keys, not two. It is idempotent: a tenant that already has an active key
//! per algorithm and nothing due gets no writes and no audit records, so
//! re-asserting the configuration on every boot is free.
//!
//! The keys are not written in the transaction that writes the tenant. They
//! cannot be: `signing_keys` has a foreign key to `tenants`, and the lock above
//! belongs to the key repository's own transaction. A crash in between leaves a
//! tenant with no keys, which is the state that already existed for every
//! tenant before this module and which the rotation sweep repairs within one
//! interval.
//!
//! # Why the window is still open (`ast-zq9`)
//!
//! `ast-zq9` closed the other non-atomic admin write — a client registration
//! and its `client.registered` record now commit together — and looked at this
//! one with the same intent. It is not the same shape of problem, and the
//! difference is not the foreign key: a transaction *can* insert the tenant and
//! its keys in that order. It is that "write the keys" is
//! `TenantKeyStore::apply_schedule`, which is three passes of
//! `PgKeyRepository::run` — one per algorithm in `SigningAlgorithm::ALL` — each
//! of which opens its own transaction, takes
//! `pg_advisory_xact_lock(hashtext(tenant), hashtext('key-rotation'))` for the
//! length of it, and records `key.rotated` after committing it. Sharing one
//! transaction with the tenant row means every one of those passes accepting a
//! caller's connection instead of the pool, which changes where the rotation
//! lock is released, when the key-encryption key is exercised, and when the
//! rotation records are written — for *every* caller of the sweep, not just
//! this one. That is a refactor of the rotation path, and the rotation path is
//! the one thing here with a working repair loop: the sweep already turns a
//! keyless tenant into a signing one within a minute, and the audit trail
//! records the keys when it does.
//!
//! So the gap this module documents stands, deliberately, with its cost
//! restated: a tenant created by a process that dies in the window cannot sign
//! until the next sweep, and no client registration succeeds against it in the
//! meantime. Nothing is lost and nothing is unrecorded, which is what made the
//! registration case worth a schema-free fix and this one worth leaving.

use crate::key_store::TenantKeyStore;
use crate::tenants::PgTenantRepository;
use asterius_domain::ports::{Clock, TenantRepository};
use asterius_domain::{DomainError, Issuer, Tenant, TenantId};
use std::sync::Arc;

/// A [`TenantRepository`] whose writes leave a tenant able to sign.
///
/// Reads are the wrapped repository's, unchanged. Only [`upsert`] does more
/// than delegate.
///
/// [`upsert`]: TenantRepository::upsert
#[derive(Debug, Clone)]
pub struct ProvisionedTenants {
    inner: PgTenantRepository,
    keys: TenantKeyStore,
    clock: Arc<dyn Clock>,
}

impl ProvisionedTenants {
    /// Pairs a tenant repository with the key store that provisions what it
    /// writes.
    #[must_use]
    pub fn new(inner: PgTenantRepository, keys: TenantKeyStore, clock: Arc<dyn Clock>) -> Self {
        Self { inner, keys, clock }
    }
}

#[async_trait::async_trait]
impl TenantRepository for ProvisionedTenants {
    async fn find_by_id(&self, id: &TenantId) -> Result<Option<Tenant>, DomainError> {
        self.inner.find_by_id(id).await
    }

    async fn find_by_issuer(&self, issuer: &Issuer) -> Result<Option<Tenant>, DomainError> {
        self.inner.find_by_issuer(issuer).await
    }

    async fn find_by_host(&self, host: &str) -> Result<Option<Tenant>, DomainError> {
        self.inner.find_by_host(host).await
    }

    async fn list(&self) -> Result<Vec<Tenant>, DomainError> {
        self.inner.list().await
    }

    /// Writes the tenant, then brings its signing keys up to date.
    ///
    /// The order is forced by the foreign key. The consequence worth stating is
    /// that an error from the second half is returned after the first half has
    /// committed: the tenant exists and may hold no keys. That is reported
    /// rather than swallowed, because a caller creating a tenant is entitled to
    /// know it got half of one.
    ///
    /// Run on update as well as on insert. It costs nothing when there is
    /// nothing due, and it means a tenant whose row predates this rule is
    /// repaired the next time anything writes it rather than staying broken
    /// because of when it was created.
    ///
    /// # Errors
    ///
    /// Whatever the wrapped repository returns, or a [`DomainError`] from the
    /// key pass — including the [`DomainError::Invalid`] that a key which
    /// cannot be decrypted under the configured key-encryption key produces.
    async fn upsert(&self, tenant: &Tenant) -> Result<(), DomainError> {
        self.inner.upsert(tenant).await?;
        self.keys.apply_schedule(&tenant.id, self.clock.now()).await
    }

    async fn delete(&self, id: &TenantId) -> Result<(), DomainError> {
        self.inner.delete(id).await
    }
}
