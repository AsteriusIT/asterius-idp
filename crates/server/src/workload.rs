//! External workload validation and bounded JWKS refresh, independent of exchange issuance.
use asterius_domain::ports::ClientUrlFetcher;
use asterius_domain::workload::{Config, Keys, Registry, Summary, Trust, Verified, Verifier};
use asterius_domain::{
    Actor, AuditEvent, AuditSink, ClientId, Detail, DomainError, EventType, Outcome, TenantId,
};
use asterius_jose::workload::{KeySet, Parsed};
use sha2::{Digest as _, Sha256};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use time::{Duration, OffsetDateTime};

fn invalid() -> DomainError {
    DomainError::invalid(
        "subject_token",
        "the workload assertion cannot be exchanged",
    )
}
type CacheKey = (TenantId, String, i64);
#[derive(Default)]
struct Snapshot {
    keys: Option<Arc<KeySet>>,
    expires_at: Option<OffsetDateTime>,
    last_attempt: Option<OffsetDateTime>,
}

pub struct ExternalWorkloads {
    registry: Arc<dyn Registry>,
    fetcher: Arc<dyn ClientUrlFetcher>,
    audit: Arc<dyn AuditSink>,
    cache: Mutex<HashMap<CacheKey, Arc<tokio::sync::Mutex<Snapshot>>>>,
}
impl std::fmt::Debug for ExternalWorkloads {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExternalWorkloads").finish_non_exhaustive()
    }
}
impl ExternalWorkloads {
    #[must_use]
    pub fn new(
        registry: Arc<dyn Registry>,
        fetcher: Arc<dyn ClientUrlFetcher>,
        audit: Arc<dyn AuditSink>,
    ) -> Self {
        Self {
            registry,
            fetcher,
            audit,
            cache: Mutex::new(HashMap::new()),
        }
    }
    async fn keys(
        &self,
        trust: &Trust,
        kid: &str,
        now: OffsetDateTime,
    ) -> Result<Arc<KeySet>, DomainError> {
        match &trust.config.keys {
            Keys::Inline { jwks } => {
                let encoded = serde_json::to_vec(jwks).map_err(|_| invalid())?;
                return KeySet::parse(&encoded, &trust.config.algorithms)
                    .map(Arc::new)
                    .map_err(|_| invalid());
            }
            Keys::Remote { uri } => {
                crate::outbound::ssrf::check_url(uri).map_err(|_| invalid())?;
            }
        }
        let key = (trust.tenant.clone(), trust.id.clone(), trust.version);
        let entry = {
            let mut cache = self.cache.lock().map_err(|_| invalid())?;
            // Versioned eviction cannot authorize through an older registry row.
            if cache.len() >= 256 && !cache.contains_key(&key) {
                // Never evict an in-flight fetch or a cooldown: otherwise
                // churn could bypass both singleflight and refresh limits.
                cache.retain(|_, entry| {
                    Arc::strong_count(entry) > 1
                        || entry.try_lock().map_or(true, |state| {
                            state
                                .last_attempt
                                .is_some_and(|last| last + Duration::seconds(60) > now)
                        })
                });
                if cache.len() >= 256 {
                    return Err(invalid());
                }
            }
            Arc::clone(
                cache
                    .entry(key)
                    .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(Snapshot::default()))),
            )
        };
        // One fetch for concurrent callers of the same version; no global lock
        // is held during DNS/TLS/network work.
        let mut state = entry.lock().await;
        if state.expires_at.is_some_and(|expiry| expiry > now)
            && let Some(keys) = state.keys.as_ref().filter(|keys| keys.contains(kid))
        {
            return Ok(Arc::clone(keys));
        }
        if state
            .last_attempt
            .is_some_and(|last| last + Duration::seconds(30) > now)
        {
            return Err(invalid());
        }
        state.last_attempt = Some(now);
        if state.expires_at.is_none_or(|expiry| expiry <= now) {
            state.keys = None;
            state.expires_at = None;
        }
        let Keys::Remote { uri } = &trust.config.keys else {
            return Err(invalid());
        };
        let bytes =
            tokio::time::timeout(std::time::Duration::from_secs(5), self.fetcher.fetch(uri))
                .await
                .map_err(|_| invalid())??;
        let keys =
            Arc::new(KeySet::parse(&bytes, &trust.config.algorithms).map_err(|_| invalid())?);
        state.expires_at = Some(now + Duration::seconds(60));
        state.keys = Some(Arc::clone(&keys));
        if !keys.contains(kid) {
            return Err(invalid());
        }
        Ok(keys)
    }
    async fn validate(
        &self,
        tenant: &TenantId,
        client: &ClientId,
        token: &str,
        now: OffsetDateTime,
    ) -> Result<Verified, DomainError> {
        let parsed = Parsed::parse(token).map_err(|_| invalid())?;
        let trusts = self.registry.candidates(tenant, parsed.issuer()).await?;
        let mut selected = None;
        for trust in trusts {
            if trust.tenant != *tenant
                || !trust.config.enabled
                || !trust.config.clients.contains(client.as_str())
                || !trust.config.algorithms.contains(&parsed.algorithm())
                || !parsed.matches_audience(&trust.config.audience)
            {
                continue;
            }
            trust.config.validate(tenant, &trust.id)?;
            let Ok(keys) = self.keys(&trust, parsed.kid(), now).await else {
                continue;
            };
            let Ok(expires_at) = parsed.verify(&trust.config, &keys, now) else {
                continue;
            };
            if selected.is_some() {
                return Err(invalid());
            }
            selected = Some(Verified {
                client: client.clone(),
                provider: trust.config.provider,
                tenant: tenant.clone(),
                trust_id: trust.id,
                trust_version: trust.version,
                principal: trust.config.principal,
                expires_at,
                digest: Sha256::digest(token.as_bytes()).into(),
                scopes: trust.config.scopes,
                resources: trust.config.resources,
                actions: trust.config.actions,
            });
        }
        selected.ok_or_else(invalid)
    }
}
#[async_trait::async_trait]
impl Verifier for ExternalWorkloads {
    async fn verify(
        &self,
        tenant: &TenantId,
        client: &ClientId,
        token: &str,
        now: OffsetDateTime,
    ) -> Result<Verified, DomainError> {
        let result = self.validate(tenant, client, token, now).await;
        let (event_type, outcome) = if result.is_ok() {
            (EventType::WORKLOAD_VERIFIED, Outcome::Success)
        } else {
            (EventType::WORKLOAD_REJECTED, Outcome::Failure)
        };
        let detail = match &result {
            Ok(verified) => Detail::new()
                .text("trust_id", &verified.trust_id)
                .number("version", verified.trust_version),
            Err(_) => Detail::new(),
        };
        self.audit
            .record(
                AuditEvent::new(
                    tenant.clone(),
                    event_type,
                    outcome,
                    Actor::Client(client.clone()),
                    now,
                )
                .detail(detail),
            )
            .await?;
        // Uniform protocol errors never expose an issuer or key-fetch oracle.
        result.map_err(|_| invalid())
    }
}

/// Administration preserves guarded fetching; the raw PostgreSQL port remains
/// internal composition, not an HTTP route or an enrollment mechanism.
#[derive(Debug, Clone)]
pub struct Administration {
    registry: asterius_store_pg::PgWorkloadTrusts,
    fetcher: Arc<dyn ClientUrlFetcher>,
}
impl Administration {
    #[must_use]
    pub fn new(
        registry: asterius_store_pg::PgWorkloadTrusts,
        fetcher: Arc<dyn ClientUrlFetcher>,
    ) -> Self {
        Self { registry, fetcher }
    }
}
#[async_trait::async_trait]
impl Registry for Administration {
    async fn candidates(&self, tenant: &TenantId, issuer: &str) -> Result<Vec<Trust>, DomainError> {
        self.registry.candidates(tenant, issuer).await
    }
    async fn list(&self, tenant: &TenantId) -> Result<Vec<Summary>, DomainError> {
        self.registry.list(tenant).await
    }
    async fn find(&self, tenant: &TenantId, id: &str) -> Result<Option<Summary>, DomainError> {
        self.registry.find(tenant, id).await
    }
    async fn put(
        &self,
        tenant: &TenantId,
        id: &str,
        config: &Config,
        expected: Option<i64>,
        actor: Actor,
        now: OffsetDateTime,
    ) -> Result<Summary, DomainError> {
        config.validate(tenant, id)?;
        if let Keys::Remote { uri } = &config.keys {
            crate::outbound::ssrf::check_url(uri).map_err(|_| invalid())?;
            if config.enabled {
                let bytes = tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    self.fetcher.fetch(uri),
                )
                .await
                .map_err(|_| invalid())??;
                KeySet::parse(&bytes, &config.algorithms).map_err(|_| invalid())?;
            }
        }
        self.registry
            .put(tenant, id, config, expected, actor, now)
            .await
    }
    async fn delete(
        &self,
        tenant: &TenantId,
        id: &str,
        expected: i64,
        actor: Actor,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        self.registry.delete(tenant, id, expected, actor, now).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asterius_domain::workload::{Algorithm, Provider};
    use asterius_domain::{Kid, SigningAlgorithm};
    use asterius_jose::{SigningKey, jws};
    use serde_json::{Value, json};
    use std::sync::{
        RwLock,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };
    const NOW: i64 = 1_760_000_000;
    #[derive(Debug)]
    struct TestRegistry(RwLock<Vec<Trust>>);
    #[async_trait::async_trait]
    impl Registry for TestRegistry {
        async fn candidates(
            &self,
            _tenant: &TenantId,
            issuer: &str,
        ) -> Result<Vec<Trust>, DomainError> {
            Ok(self
                .0
                .read()
                .expect("registry")
                .iter()
                .filter(|trust| trust.config.issuer == issuer)
                .cloned()
                .collect())
        }
        async fn list(&self, _: &TenantId) -> Result<Vec<Summary>, DomainError> {
            Err(DomainError::NotFound)
        }
        async fn find(&self, _: &TenantId, _: &str) -> Result<Option<Summary>, DomainError> {
            Err(DomainError::NotFound)
        }
        async fn put(
            &self,
            _: &TenantId,
            _: &str,
            _: &Config,
            _: Option<i64>,
            _: Actor,
            _: OffsetDateTime,
        ) -> Result<Summary, DomainError> {
            Err(DomainError::NotFound)
        }
        async fn delete(
            &self,
            _: &TenantId,
            _: &str,
            _: i64,
            _: Actor,
            _: OffsetDateTime,
        ) -> Result<(), DomainError> {
            Err(DomainError::NotFound)
        }
    }
    #[derive(Debug)]
    struct Fetch {
        document: RwLock<Vec<u8>>,
        calls: AtomicUsize,
        down: AtomicBool,
    }
    #[async_trait::async_trait]
    impl ClientUrlFetcher for Fetch {
        async fn fetch(&self, _: &str) -> Result<Vec<u8>, DomainError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            tokio::task::yield_now().await;
            if self.down.load(Ordering::SeqCst) {
                return Err(invalid());
            }
            Ok(self.document.read().expect("document").clone())
        }
    }
    #[derive(Debug, Default)]
    struct Trail(Mutex<Vec<AuditEvent>>);
    #[async_trait::async_trait]
    impl AuditSink for Trail {
        async fn record(&self, event: AuditEvent) -> Result<(), DomainError> {
            self.0.lock().expect("trail").push(event);
            Ok(())
        }
    }
    fn at(seconds: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(NOW + seconds).expect("time")
    }
    fn signed(kid: &str) -> (String, Value) {
        let key = SigningKey::generate(SigningAlgorithm::EdDsa).expect("key");
        let mut public = key.public_jwk().expect("public");
        public["kid"] = json!(kid);
        let claims = json!({"iss":"https://cluster.example","aud":"urn:asterius:workload:acme:inventory","sub":"system:serviceaccount:apps:inventory","iat":NOW,"exp":NOW+300,"kubernetes.io":{"namespace":"apps","serviceaccount":{"name":"inventory","uid":"sa-uid"},"pod":{"uid":"pod-uid"}}});
        (
            jws::sign(&key, &Kid::new(kid), "JWT", &claims)
                .expect("JWT")
                .as_str()
                .to_owned(),
            json!({"keys":[public]}),
        )
    }
    fn trust(keys: Keys) -> Trust {
        Trust {
            tenant: TenantId::new("acme"),
            id: "inventory".to_owned(),
            version: 1,
            config: Config {
                issuer: "https://cluster.example".to_owned(),
                audience: "urn:asterius:workload:acme:inventory".to_owned(),
                subject: "system:serviceaccount:apps:inventory".to_owned(),
                provider: Provider::Kubernetes,
                principal: "workload:inventory".to_owned(),
                clients: ["client-one".to_owned()].into(),
                scopes: ["inventory:read".to_owned()].into(),
                resources: ["https://api.example/".to_owned()].into(),
                actions: ["read".to_owned()].into(),
                required_claims: [
                    ("/kubernetes.io/namespace".to_owned(), "apps".to_owned()),
                    (
                        "/kubernetes.io/serviceaccount/name".to_owned(),
                        "inventory".to_owned(),
                    ),
                    (
                        "/kubernetes.io/serviceaccount/uid".to_owned(),
                        "sa-uid".to_owned(),
                    ),
                ]
                .into(),
                algorithms: [Algorithm::EdDSA].into(),
                keys,
                enabled: true,
            },
        }
    }
    fn verifier(
        trust: Trust,
        jwks: &Value,
    ) -> (ExternalWorkloads, Arc<TestRegistry>, Arc<Fetch>, Arc<Trail>) {
        let registry = Arc::new(TestRegistry(RwLock::new(vec![trust])));
        let fetch = Arc::new(Fetch {
            document: RwLock::new(serde_json::to_vec(jwks).expect("JWKS")),
            calls: AtomicUsize::new(0),
            down: AtomicBool::new(false),
        });
        let trail = Arc::new(Trail::default());
        (
            ExternalWorkloads::new(registry.clone(), fetch.clone(), trail.clone()),
            registry,
            fetch,
            trail,
        )
    }
    #[tokio::test]
    async fn issuer_client_tenant_and_disable_fail_without_key_cache_authority() {
        let (token, jwks) = signed("one");
        let (verifier, registry, fetch, trail) =
            verifier(trust(Keys::Inline { jwks: jwks.clone() }), &jwks);
        let tenant = TenantId::new("acme");
        let client = ClientId::new("client-one");
        assert!(
            verifier
                .verify(&tenant, &client, &token, at(0))
                .await
                .is_ok()
        );
        assert!(
            verifier
                .verify(&TenantId::new("other"), &client, &token, at(0))
                .await
                .is_err()
        );
        assert!(
            verifier
                .verify(&tenant, &ClientId::new("other-client"), &token, at(0))
                .await
                .is_err()
        );
        registry.0.write().expect("registry")[0].config.enabled = false;
        assert!(
            verifier
                .verify(&tenant, &client, &token, at(0))
                .await
                .is_err()
        );
        registry.0.write().expect("registry").clear();
        assert!(
            verifier
                .verify(&tenant, &client, &token, at(0))
                .await
                .is_err()
        );
        assert_eq!(fetch.calls.load(Ordering::SeqCst), 0);
        assert_eq!(trail.0.lock().expect("trail").len(), 5);
    }
    #[tokio::test]
    async fn remote_rotation_unknown_kid_backoff_and_expiry_fail_closed() {
        let (token, jwks) = signed("one");
        let (verifier, _registry, fetch, _) = verifier(
            trust(Keys::Remote {
                uri: "https://keys.example/jwks".to_owned(),
            }),
            &jwks,
        );
        let tenant = TenantId::new("acme");
        let client = ClientId::new("client-one");
        let (first, second) = tokio::join!(
            verifier.verify(&tenant, &client, &token, at(0)),
            verifier.verify(&tenant, &client, &token, at(0))
        );
        assert!(first.is_ok() && second.is_ok());
        assert_eq!(fetch.calls.load(Ordering::SeqCst), 1);
        let (rotated, jwks) = signed("two");
        *fetch.document.write().expect("document") = serde_json::to_vec(&jwks).expect("JWKS");
        assert!(
            verifier
                .verify(&tenant, &client, &rotated, at(29))
                .await
                .is_err()
        );
        assert_eq!(fetch.calls.load(Ordering::SeqCst), 1);
        assert!(
            verifier
                .verify(&tenant, &client, &rotated, at(30))
                .await
                .is_ok()
        );
        assert_eq!(fetch.calls.load(Ordering::SeqCst), 2);
        fetch.down.store(true, Ordering::SeqCst);
        assert!(
            verifier
                .verify(&tenant, &client, &rotated, at(89))
                .await
                .is_ok()
        );
        assert!(
            verifier
                .verify(&tenant, &client, &rotated, at(90))
                .await
                .is_err()
        );
        assert_eq!(fetch.calls.load(Ordering::SeqCst), 3);
        assert!(
            verifier
                .verify(&tenant, &client, &rotated, at(91))
                .await
                .is_err()
        );
        assert_eq!(fetch.calls.load(Ordering::SeqCst), 3);
    }
    #[tokio::test]
    async fn cache_capacity_cannot_evict_live_refresh_cooldowns() {
        let (token, jwks) = signed("one");
        let (verifier, _, fetch, _) = verifier(
            trust(Keys::Remote {
                uri: "https://keys.example/jwks".to_owned(),
            }),
            &jwks,
        );
        {
            let mut cache = verifier.cache.lock().expect("cache");
            for index in 0..256 {
                cache.insert(
                    (TenantId::new("acme"), format!("old-{index}"), 1),
                    Arc::new(tokio::sync::Mutex::new(Snapshot {
                        keys: None,
                        expires_at: Some(at(60)),
                        last_attempt: Some(at(0)),
                    })),
                );
            }
        }
        let tenant = TenantId::new("acme");
        let client = ClientId::new("client-one");
        assert!(
            verifier
                .verify(&tenant, &client, &token, at(0))
                .await
                .is_err()
        );
        assert_eq!(fetch.calls.load(Ordering::SeqCst), 0);
        assert!(
            verifier
                .verify(&tenant, &client, &token, at(60))
                .await
                .is_ok()
        );
        assert_eq!(fetch.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn version_change_and_inline_rotation_cannot_reuse_old_keys() {
        let (token, jwks) = signed("one");
        let (verifier, registry, _, _) =
            verifier(trust(Keys::Inline { jwks: jwks.clone() }), &jwks);
        let tenant = TenantId::new("acme");
        let client = ClientId::new("client-one");
        assert!(
            verifier
                .verify(&tenant, &client, &token, at(0))
                .await
                .is_ok()
        );
        let (rotated, jwks) = signed("two");
        {
            let mut registry = registry.0.write().expect("registry");
            registry[0].version += 1;
            registry[0].config.keys = Keys::Inline { jwks };
        }
        assert!(
            verifier
                .verify(&tenant, &client, &token, at(0))
                .await
                .is_err()
        );
        assert!(
            verifier
                .verify(&tenant, &client, &rotated, at(0))
                .await
                .is_ok()
        );
    }
    #[tokio::test]
    async fn ambiguous_valid_mapping_and_private_address_fail_closed() {
        let (token, jwks) = signed("one");
        let (verifier, registry, fetch, _) =
            verifier(trust(Keys::Inline { jwks: jwks.clone() }), &jwks);
        let tenant = TenantId::new("acme");
        let client = ClientId::new("client-one");
        // A second row with the same exact audience is corrupt operator state;
        // config validation refuses its mismatched trust-specific audience.
        {
            let mut rows = registry.0.write().expect("registry");
            let duplicate = rows[0].clone();
            rows.push(duplicate);
        }
        assert!(
            verifier
                .verify(&tenant, &client, &token, at(0))
                .await
                .is_err()
        );
        {
            let mut rows = registry.0.write().expect("registry");
            rows.truncate(1);
            rows[0].config.keys = Keys::Remote {
                uri: "https://127.0.0.1/jwks".to_owned(),
            };
        }
        assert!(
            verifier
                .verify(&tenant, &client, &token, at(0))
                .await
                .is_err()
        );
        assert_eq!(fetch.calls.load(Ordering::SeqCst), 0);
    }
}
