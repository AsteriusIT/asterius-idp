//! A tenant created away from the boot path is usable at once (`ast-qa3`).
//!
//! The bug: signing keys were provisioned by a loop in `main`, run once at
//! startup. A tenant created any other way — the deployment-admin seed, the
//! admin API of `ast-f7m.3`, anything later — held no keys, and since
//! `ast-a05.13` a tenant with no keys refuses *every* dynamic client
//! registration with `invalid_client_metadata`, not only the ones naming a
//! non-default algorithm. The deployment looked healthy and the tenant was
//! inert until somebody restarted the server.
//!
//! So the assertion here is not "rows appeared in `signing_keys`" — that is
//! `database.rs`'s job. It is the user-visible consequence: a tenant created a
//! moment ago accepts a registration naming each algorithm the discovery
//! document advertises, through the real endpoint, with no restart and no
//! rotation sweep in between.
//!
//! Needs `DATABASE_URL`, like the other store-backed tests here, and creates a
//! tenant of its own so a parallel run of the suite cannot collide with it.

use asterius_domain::audit::{AuditEvent, AuditSink};
use asterius_domain::keys::SigningAlgorithm;
use asterius_domain::ports::{Clock, JwksFetcher, SystemClock, TenantRepository as _};
use asterius_domain::{
    Capabilities, Client, ClientRegistry, DomainError, Issuer, Tenant, TenantId, TenantStatus,
};
use asterius_jose::{Kek, LocalKek};
use asterius_server::http::register::{
    InitialAccessTokens, RegisterContext, RegistrationPolicy, register,
};
use asterius_store_pg::{
    PgAuditSink, PgTenantRepository, ProvisionedTenants, Store, TenantKeyStore,
};
use axum::body::Bytes;
use axum::http::{HeaderMap, StatusCode, header};
use serde_json::json;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

/// The initial access token the registration policy below admits.
const TOKEN: &str = "vJ8qN2mXbL5-tRw0KePzUA";

/// Distinguishes the tenants of concurrent runs, as the other store-backed
/// suites here do.
static COUNTER: AtomicU32 = AtomicU32::new(0);

/// Accepts every write and remembers nothing: this suite asserts on the
/// response, and a real registry would need a schema this test does not care
/// about.
#[derive(Debug, Default)]
struct AcceptingRegistry;

#[async_trait::async_trait]
impl ClientRegistry for AcceptingRegistry {
    async fn register(
        &self,
        client: &Client,
        _registration_access_token: &[u8; 32],
    ) -> Result<Client, DomainError> {
        Ok(client.clone())
    }
}

/// Discards the audit trail. What is recorded is `register.rs`'s subject.
#[derive(Debug, Default)]
struct DiscardedAudit;

#[async_trait::async_trait]
impl AuditSink for DiscardedAudit {
    async fn record(&self, _event: AuditEvent) -> Result<(), DomainError> {
        Ok(())
    }
}

/// Refuses every fetch, which nothing here should need: no registration below
/// names a `sector_identifier_uri`, and a fetcher that could succeed would hide
/// an accidental outbound call rather than fail it.
#[derive(Debug, Default)]
struct NoOutbound;

#[async_trait::async_trait]
impl JwksFetcher for NoOutbound {
    async fn fetch(&self, _url: &str) -> Result<Vec<u8>, DomainError> {
        Err(DomainError::Storage(
            "no outbound calls in this test".into(),
        ))
    }
}

fn json_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        "application/json".parse().expect("header"),
    );
    headers.insert(
        header::AUTHORIZATION,
        format!("Bearer {TOKEN}").parse().expect("header"),
    );
    headers
}

/// The whole of the fixture: a database, a tenant created through the ordinary
/// repository, and the key store the endpoint consults.
struct Fixture {
    store: Store,
    keys: TenantKeyStore,
    tenant: Tenant,
    kek: Arc<dyn Kek>,
}

impl Fixture {
    /// `None` without `DATABASE_URL`, so a run with no database stays fast.
    async fn new() -> Option<Self> {
        let url = std::env::var("DATABASE_URL").ok()?;
        let store = Store::connect(&url, 4)
            .await
            .expect("DATABASE_URL is set but unreachable; is `docker compose up -d db` running?");
        store.migrate().await.expect("migrate");

        let kek: Arc<dyn Kek> = Arc::new(LocalKek::from_bytes(&[3_u8; 32]).expect("a 32-byte KEK"));
        let keys = TenantKeyStore::new(
            store.pool().clone(),
            Arc::clone(&kek),
            Arc::new(PgAuditSink::new(store.pool().clone())),
        );

        let id = format!(
            "prov-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let tenant_id = TenantId::parse(&id).expect("a generated tenant id");
        let clock = SystemClock;
        let tenant = Tenant {
            id: tenant_id,
            issuer: Issuer::parse(&format!("https://as.example/t/{id}")).expect("issuer"),
            custom_host: None,
            display_name: "Provisioning".to_owned(),
            default_resource: "https://api.example/".to_owned(),
            status: TenantStatus::Active,
            created_at: clock.now(),
            updated_at: clock.now(),
        };

        // The creation path under test: the repository the composition root
        // hands to everything that is not `main`, used here with no boot loop
        // and no rotation sweep anywhere near it.
        ProvisionedTenants::new(
            PgTenantRepository::new(store.pool().clone(), Arc::clone(&kek)),
            keys.clone(),
            Arc::new(SystemClock),
        )
        .upsert(&tenant)
        .await
        .expect("create the tenant");

        Some(Self {
            store,
            keys,
            tenant,
            kek,
        })
    }

    async fn tear_down(self) {
        PgTenantRepository::new(self.store.pool().clone(), self.kek)
            .delete(&self.tenant.id)
            .await
            .expect("delete tenant");
    }
}

#[tokio::test]
async fn a_tenant_created_off_the_boot_path_registers_every_advertised_algorithm() {
    let Some(fixture) = Fixture::new().await else {
        eprintln!("skipping: DATABASE_URL is not set");
        return;
    };

    for algorithm in SigningAlgorithm::ALL {
        let body = serde_json::to_vec(&json!({
            "client_name": "Billing",
            "redirect_uris": ["https://rp.example/cb"],
            "grant_types": ["authorization_code"],
            "scope": "openid",
            "jwks": {"keys": [{"kty": "OKP", "crv": "Ed25519", "x": "abc"}]},
            "id_token_signed_response_alg": algorithm.as_str(),
        }))
        .expect("serialise");

        let response = register(
            RegisterContext {
                tenant: &fixture.tenant,
                clients: &AcceptingRegistry,
                keys: &fixture.keys,
                capabilities: Capabilities::default(),
                policy: &RegistrationPolicy::Gated(InitialAccessTokens::from_tokens([TOKEN])),
                audit: &DiscardedAudit,
                outbound: &NoOutbound,
                request_id: Some("req-provisioning"),
            },
            &json_headers(),
            &Bytes::from(body),
            SystemClock.now(),
        )
        .await;

        assert_eq!(
            response.status(),
            StatusCode::CREATED,
            "a tenant created a moment ago refused {algorithm}: it holds no active key for it, \
             which is the whole of `ast-qa3`"
        );
    }

    fixture.tear_down().await;
}
