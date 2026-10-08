//! Database round trip for encrypted upstream OIDC credentials and tenant isolation.

use asterius_domain::TenantId;
use asterius_jose::{Kek, LocalKek};
use asterius_store_pg::{MIGRATOR, OidcProvider, Store};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use std::{str::FromStr as _, sync::Arc};
use time::OffsetDateTime;
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires DATABASE_URL; CI runs ignored store tests"]
// One isolated schema covers creation, rotation, tenant fencing and AAD tampering.
#[allow(clippy::too_many_lines)]
async fn credentials_are_encrypted_and_tenant_bound() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL for ignored store test");
    let schema = format!("oidc_providers_{}", Uuid::new_v4().simple());
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .expect("database");
    sqlx::query(&format!("create schema {schema}"))
        .execute(&admin)
        .await
        .expect("schema");
    admin.close().await;
    let options = PgConnectOptions::from_str(&url)
        .expect("database URL")
        .options([("search_path", schema.as_str())]);
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect_with(options)
        .await
        .expect("schema connection");
    MIGRATOR.run(&pool).await.expect("migrations");
    for tenant in ["one", "two"] {
        sqlx::query("insert into tenants (tenant_id, issuer, display_name, default_resource) values ($1, $2, $1, 'https://api.example/')")
            .bind(tenant).bind(format!("https://id.example/{tenant}"))
            .execute(&pool).await.expect("tenant");
    }
    let store = Store::from_pool(pool.clone());
    let kek: Arc<dyn Kek> = Arc::new(LocalKek::from_bytes(&[0x71; 32]).expect("32-byte KEK"));
    let one = store
        .scope(TenantId::new("one"))
        .oidc_providers(Arc::clone(&kek));
    let two = store
        .scope(TenantId::new("two"))
        .oidc_providers(Arc::clone(&kek));
    let provider = OidcProvider {
        id: "corporate".to_owned(),
        name: "Corporate".to_owned(),
        issuer: "https://login.example".to_owned(),
        authorization_endpoint: "https://login.example/authorize".to_owned(),
        token_endpoint: "https://login.example/token".to_owned(),
        jwks_uri: "https://login.example/keys".to_owned(),
        client_id: "client".to_owned(),
        username_claim: None,
        enabled: true,
        allow_registration: false,
        created_at: OffsetDateTime::UNIX_EPOCH,
        revision: String::new(),
    };
    one.put(&provider, Some(b"secret-first"))
        .await
        .expect("create");
    assert!(two.list().await.expect("other tenant list").is_empty());
    assert!(
        two.find("corporate")
            .await
            .expect("other tenant find")
            .is_none()
    );
    let ciphertext: Vec<u8> = sqlx::query_scalar(
        "select client_secret_ciphertext from oidc_identity_providers where tenant_id = 'one'",
    )
    .fetch_one(&pool)
    .await
    .expect("ciphertext");
    assert!(
        !ciphertext
            .windows(b"secret-first".len())
            .any(|part| part == b"secret-first")
    );
    let credential = one
        .find("corporate")
        .await
        .expect("find")
        .expect("provider");
    assert_eq!(credential.client_secret.as_slice(), b"secret-first");
    assert_eq!(credential.provider.username_claim, None);
    let mut mapped = provider.clone();
    mapped.username_claim = Some("preferred_username".to_owned());
    one.put(&mapped, None)
        .await
        .expect("configure username mapping");
    assert_eq!(
        one.list().await.expect("mapped list")[0]
            .username_claim
            .as_deref(),
        Some("preferred_username")
    );
    let mapped_credential = one
        .find("corporate")
        .await
        .expect("mapped read")
        .expect("provider");
    assert_eq!(
        mapped_credential.provider.username_claim.as_deref(),
        Some("preferred_username")
    );
    assert_eq!(mapped_credential.client_secret.as_slice(), b"secret-first");
    one.put(&provider, None)
        .await
        .expect("preserve secret on update");
    assert_eq!(
        one.find("corporate")
            .await
            .expect("find")
            .expect("provider")
            .client_secret
            .as_slice(),
        b"secret-first"
    );
    one.put(&provider, Some(b"secret-second"))
        .await
        .expect("rotate secret");
    assert_eq!(
        one.find("corporate")
            .await
            .expect("find")
            .expect("provider")
            .client_secret
            .as_slice(),
        b"secret-second"
    );
    exercise_flow_provider_contract(&pool, &one, &provider).await;
    assert!(!two.delete("corporate").await.expect("other tenant delete"));
    sqlx::query("update oidc_identity_providers set tenant_id = 'two' where tenant_id = 'one' and provider_id = 'corporate'")
        .execute(&pool).await.expect("simulate cross-tenant row copy");
    assert!(
        two.find("corporate").await.is_err(),
        "tenant-bound AAD must reject a moved envelope"
    );
    assert!(two.delete("corporate").await.expect("remove moved row"));
    pool.close().await;
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .expect("database");
    sqlx::query(&format!("drop schema {schema} cascade"))
        .execute(&admin)
        .await
        .expect("drop schema");
    admin.close().await;
}

// One isolated schema checks atomic receipt commit, lost-response recovery,
// lease/tenant fencing and credential-only drift against the actual repository.
#[allow(clippy::too_many_lines)]
async fn exercise_flow_provider_contract(
    pool: &sqlx::PgPool,
    providers: &asterius_store_pg::PgOidcProviders,
    template: &OidcProvider,
) {
    use asterius_store_pg::{FlowApplyStep, FlowLinkIntent, OidcFlowWrite, PgArchitectureFlows};
    let tenant = TenantId::new("one");
    let flows = PgArchitectureFlows::new(pool.clone());
    let flow = Uuid::new_v4();
    let node = "provider-node";
    let now = OffsetDateTime::now_utc();
    flows
        .create(
            &tenant,
            flow,
            "Provider architecture",
            serde_json::json!({"schema_version":1,"nodes":[],"edges":[]}),
            now,
        )
        .await
        .expect("flow");
    let token = flows
        .begin_apply(&tenant, flow, 1, now)
        .await
        .expect("lease");
    let mut requested = template.clone();
    requested.id = "flow-provider".into();
    // Tenant issuer uniqueness is part of the actual provider contract.
    requested.issuer = "https://flow-login.example".into();
    requested.authorization_endpoint = "https://flow-login.example/authorize".into();
    requested.token_endpoint = "https://flow-login.example/token".into();
    requested.jwks_uri = "https://flow-login.example/keys".into();
    flows
        .reserve(
            &tenant,
            flow,
            token,
            1,
            &FlowLinkIntent {
                node,
                kind: "identity_provider",
                resource: &requested.id,
                relation: "managed",
            },
            now,
        )
        .await
        .expect("reservation");
    let step = FlowApplyStep {
        flow,
        token,
        revision: 1,
        node,
        now,
    };
    let write = OidcFlowWrite {
        step,
        expected: None,
    };
    assert!(
        providers.put_flow(&requested, None, &write).await.is_err(),
        "missing initial secret rolls back the provider"
    );
    assert!(providers.find(&requested.id).await.expect("read").is_none());
    assert_eq!(
        flows.links(&tenant, flow).await.expect("links")[0]["state"],
        "pending"
    );
    providers
        .put_flow(&requested, Some(b"apply-only-secret"), &write)
        .await
        .expect("atomic create");
    let stored = providers
        .list()
        .await
        .expect("inventory")
        .into_iter()
        .find(|row| row.id == requested.id)
        .expect("provider");
    let links = flows.links(&tenant, flow).await.expect("links");
    assert_eq!(links[0]["state"], "applied");
    assert_eq!(links[0]["resource_revision"], stored.revision);
    assert!(
        !serde_json::to_string(&links)
            .expect("public receipts")
            .contains("apply-only-secret")
    );
    // Lost HTTP response cannot turn the same reserved create into an overwrite.
    assert!(
        providers
            .put_flow(&requested, Some(b"must-not-replace"), &write)
            .await
            .is_err()
    );
    assert_eq!(
        providers
            .find(&requested.id)
            .await
            .expect("read")
            .expect("provider")
            .client_secret
            .as_slice(),
        b"apply-only-secret"
    );
    let expected = stored.snapshot();
    providers
        .put(&requested, Some(b"external-rotation"))
        .await
        .expect("outside edit");
    let write = OidcFlowWrite {
        step: FlowApplyStep {
            flow,
            token,
            revision: 1,
            node,
            now,
        },
        expected: Some(&expected),
    };
    requested.name = "New name".into();
    assert!(
        providers
            .put_flow(&requested, Some(b"must-not-replace"), &write)
            .await
            .is_err(),
        "secret-only revision drift refuses a stale plan"
    );
    assert_eq!(
        providers
            .find(&requested.id)
            .await
            .expect("read")
            .expect("provider")
            .client_secret
            .as_slice(),
        b"external-rotation"
    );
    assert_ne!(
        providers
            .find(&requested.id)
            .await
            .expect("read")
            .expect("provider")
            .provider
            .name,
        "New name"
    );
    let current = providers
        .list()
        .await
        .expect("inventory")
        .into_iter()
        .find(|row| row.id == requested.id)
        .expect("provider")
        .snapshot();
    let stale = OidcFlowWrite {
        step: FlowApplyStep {
            flow,
            token: Uuid::new_v4(),
            revision: 1,
            node,
            now,
        },
        expected: Some(&current),
    };
    assert!(
        providers.put_flow(&requested, None, &stale).await.is_err(),
        "wrong lease token cannot mutate a provider"
    );
    // Ordinary credential rotation remains supported; only its public opaque
    // revision is placed in the plan/provenance, never an envelope or hash.
    assert!(!current.to_string().contains("external-rotation"));
}
