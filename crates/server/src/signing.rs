//! The one thing in this process that holds a private key in memory.
//!
//! `asterius_store_pg::PgKeyRepository` deliberately does not implement
//! [`Signer`]: signing through it would unwrap the private key on every token,
//! which for a cloud KEK is a network round trip per token issued. Its module
//! documentation says the composition root loads the active key once and signs
//! from memory. This is that.
//!
//! # Why it is a cache and not a load
//!
//! A key does not stay active. `PgKeyRepository::apply_schedule` promotes a
//! `pending` key and moves the incumbent to `retiring`, and it may run on any
//! replica — an operator's rotation on one process, the background sweep on
//! another. A signer that read the key once at startup would keep signing with
//! the superseded key until somebody restarted it, and nothing would look
//! wrong: the tokens verify, because a `retiring` key is still published.
//! Rotation would silently not happen, which is the failure mode rotation
//! exists to avoid.
//!
//! So each entry has an age and is reloaded past [`CachedSigner::DEFAULT_TTL`]. That
//! bounds staleness rather than eliminating it, and the bound is safe for a
//! specific reason: a displaced key becomes `retiring`, not `retired`, and
//! stays in the JWKS for the tenant's grace period — which is measured in
//! hours or days and must already exceed the lifetime of the longest-lived
//! token it signed. A minute of signing under a key that is still published
//! and still verifiable costs nothing. A minute of signing under a *retired*
//! key would be an outage, and the TTL is three orders of magnitude short of
//! reaching one.
//!
//! Invalidating on rotation instead would be exact within one process and
//! useless across replicas, which is the deployment this has to work in.
//!
//! # Why misses are cached too
//!
//! A tenant may hold no key of some algorithm. Discovery advertises all three
//! (ADR-0003), and a client may register any of them as
//! `id_token_signed_response_alg`, so "no key for PS256" is a question a
//! misconfigured deployment asks on every single token. Caching the negative
//! answer keeps that a lookup rather than a query, at the cost of a key created
//! during the TTL taking up to the TTL to be noticed — the same bound as the
//! positive case, and the same argument.

use asterius_domain::keys::{CompactJws, Signer, SigningAlgorithm};
use asterius_domain::ports::Clock;
use asterius_domain::{DomainError, Kid, TenantId};
use asterius_jose::{SigningKey, jws};
use asterius_store_pg::TenantKeyStore;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use time::{Duration, OffsetDateTime};

/// A [`Signer`] over the PostgreSQL key repository, with the unwrapped keys
/// held in memory.
pub struct CachedSigner {
    keys: TenantKeyStore,
    clock: Arc<dyn Clock>,
    ttl: Duration,
    /// `None` in the value records "this tenant has no active key of this
    /// algorithm" — see the module documentation on caching misses.
    entries: RwLock<HashMap<(TenantId, SigningAlgorithm), Entry>>,
}

/// One cached answer, positive or negative, with the instant it was read.
struct Entry {
    key: Option<Arc<(Kid, SigningKey)>>,
    loaded_at: OffsetDateTime,
}

/// What the cache holds for one tenant and algorithm.
///
/// Three states, so a type rather than a nested [`Option`]: "this tenant has
/// no key of this algorithm" is something the cache *knows*, not something it
/// failed to know, and the two must not read alike at the call site.
enum Cached {
    /// An entry younger than the TTL. `None` inside is the cached miss.
    Fresh(Option<Arc<(Kid, SigningKey)>>),
    /// No entry at all, or one too old to trust.
    Expired,
}

impl std::fmt::Debug for CachedSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the keys, and not even how many: the count of cached entries
        // is a function of which tenants have been active, which is not
        // something a debug line should be carrying around.
        f.debug_struct("CachedSigner")
            .field("ttl", &self.ttl)
            .finish_non_exhaustive()
    }
}

impl CachedSigner {
    /// How long a loaded key is trusted before it is read again.
    ///
    /// Sixty seconds. Long enough that signing is a map lookup rather than a
    /// query plus a KEK operation; short enough that a rotation on another
    /// replica reaches this one inside a minute, against a grace period
    /// measured in hours.
    pub const DEFAULT_TTL: Duration = Duration::seconds(60);

    /// Builds a signer over `keys`.
    #[must_use]
    pub fn new(keys: TenantKeyStore, clock: Arc<dyn Clock>) -> Self {
        Self::with_ttl(keys, clock, Self::DEFAULT_TTL)
    }

    /// Builds a signer with a chosen cache lifetime.
    ///
    /// For tests that need to observe a reload without waiting a minute, and
    /// for a deployment that wants a different point on the staleness/latency
    /// trade-off. A zero or negative TTL means every signature reloads, which
    /// is correct but slow.
    #[must_use]
    pub fn with_ttl(keys: TenantKeyStore, clock: Arc<dyn Clock>, ttl: Duration) -> Self {
        Self {
            keys,
            clock,
            ttl,
            entries: RwLock::new(HashMap::new()),
        }
    }

    /// The active key for one algorithm, from the cache or the store.
    ///
    /// Returns `None` when the tenant holds no active key of that algorithm.
    /// That is a state, not an error: a tenant created a moment ago, or one
    /// whose keys were destroyed after a compromise.
    async fn resolve(
        &self,
        tenant: &TenantId,
        algorithm: SigningAlgorithm,
    ) -> Result<Option<Arc<(Kid, SigningKey)>>, DomainError> {
        let now = self.clock.now();
        let key = (tenant.clone(), algorithm);

        if let Cached::Fresh(fresh) = self.cached(&key, now) {
            return Ok(fresh);
        }

        // Loaded without the lock held. Two requests that miss together both
        // load, which wastes a KEK operation and cannot produce a wrong
        // answer: the read is idempotent and whichever writes last writes the
        // same thing.
        let loaded = self
            .keys
            .for_tenant(tenant)
            .active_signing_key(algorithm)
            .await?
            .map(Arc::new);

        if let Ok(mut entries) = self.entries.write() {
            entries.insert(
                key,
                Entry {
                    key: loaded.clone(),
                    loaded_at: now,
                },
            );
        }
        Ok(loaded)
    }

    /// The cached answer, if there is one and it is still young enough.
    fn cached(&self, key: &(TenantId, SigningAlgorithm), now: OffsetDateTime) -> Cached {
        // A poisoned lock means a panic while holding it. Treating that as a
        // miss reloads from the store, which is the safe reading — the
        // alternative is refusing to sign anything for the life of the
        // process.
        let Ok(entries) = self.entries.read() else {
            return Cached::Expired;
        };
        match entries.get(key) {
            Some(entry) if now - entry.loaded_at < self.ttl => Cached::Fresh(entry.key.clone()),
            _ => Cached::Expired,
        }
    }

    /// Any active key, preferring the default algorithm.
    ///
    /// For claims that commit to no algorithm at all — an access token says
    /// nothing about how it was signed, and its verifier resolves the key from
    /// the published JWKS by `kid`. The default is tried first so a tenant
    /// holding several keys has one answer rather than whichever sorted first.
    async fn resolve_any(
        &self,
        tenant: &TenantId,
    ) -> Result<Option<Arc<(Kid, SigningKey)>>, DomainError> {
        for algorithm in std::iter::once(SigningAlgorithm::DEFAULT).chain(SigningAlgorithm::ALL) {
            if let Some(key) = self.resolve(tenant, algorithm).await? {
                return Ok(Some(key));
            }
        }
        Ok(None)
    }
}

#[async_trait::async_trait]
impl Signer for CachedSigner {
    async fn sign(
        &self,
        tenant: &TenantId,
        algorithm: Option<SigningAlgorithm>,
        typ: &'static str,
        claims: &Value,
    ) -> Result<CompactJws, DomainError> {
        // A constraint the claims carry means exactly that algorithm, and no
        // second attempt under another: OIDC Core §3.1.3.6 makes `at_hash`
        // depend on the `alg` in the header, so a claims set built for ES256
        // and signed with EdDSA carries a value the client computes
        // differently and is entitled to reject. `ast-a05.12` is that bug,
        // found and fixed; this is the shape that keeps it fixed.
        let key = if let Some(required) = algorithm {
            self.resolve(tenant, required).await?
        } else {
            self.resolve_any(tenant).await?
        }
        .ok_or(DomainError::NoSigningKey { algorithm })?;

        let (kid, signing) = key.as_ref();
        jws::sign(signing, kid, typ, claims).map_err(|e| DomainError::invalid("jws", e.to_string()))
    }
}
