//! Conditional policy publication cannot silently remove guards or race signing.
use asterius_domain::policy::RuleSet;
use asterius_domain::policy::conditional::{ConditionalSettings as _, Sensitivity};
use asterius_domain::ports::PolicyStore as _;
use asterius_domain::{ClientId, TenantId};
use asterius_store_pg::{MIGRATOR, PgConditionalSettings, PgPolicies};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use std::str::FromStr as _;
use time::OffsetDateTime;
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires PostgreSQL; CI runs ignored conditional store regressions"]
#[expect(clippy::too_many_lines, reason = "CAS, classification ABA and publication/signing race share one isolated migrated fixture")]
async fn conditional_publication_cas_sources_and_signing_fence() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL");
    let schema = format!("conditional_access_{}", Uuid::new_v4().simple());
    let admin = PgPoolOptions::new().max_connections(1).connect(&url).await.expect("database");
    sqlx::query(&format!("create schema {schema}")).execute(&admin).await.expect("schema");
    let options = PgConnectOptions::from_str(&url).expect("URL").options([("search_path", schema.as_str())]);
    let pool = PgPoolOptions::new().max_connections(2).connect_with(options).await.expect("pool");
    MIGRATOR.run(&pool).await.expect("migrations");
    for name in ["one", "two"] {
        sqlx::query("insert into tenants(tenant_id,issuer,display_name,default_resource) values($1,$2,$1,'https://api.example/')")
            .bind(name).bind(format!("https://id.example/{name}")).execute(&pool).await.expect("tenant");
        sqlx::query("insert into clients(tenant_id,client_id,client_name,token_endpoint_auth_method,jwks) values($1,'app','Application','private_key_jwt','{\"keys\":[]}'::jsonb)").bind(name).execute(&pool).await.expect("client");
    }
    sqlx::query("insert into clients(tenant_id,client_id,client_name,token_endpoint_auth_method,jwks) values('two','foreign','Foreign application','private_key_jwt','{\"keys\":[]}'::jsonb)").execute(&pool).await.expect("foreign client");
    let tenant = TenantId::new("one");
    let client = ClientId::new("app");
    let policies = PgPolicies::new(pool.clone());
    let legacy = RuleSet::from_json(&serde_json::json!({"version":1,"rules":[{"id":"baseline","effect":"permit"}]})).expect("policy");
    let guarded = RuleSet::from_json(&serde_json::json!({"version":1,"rules":[{"id":"baseline","effect":"permit"}],"conditional_scopes":[{"id":"classified","mode":"active","clients":["app"],"actions":["client_credentials"],"rules":[{"id":"critical","effect":"permit","when":{"application_sensitivity":"critical"}}]}]})).expect("conditional policy");
    let now = OffsetDateTime::now_utc();
    policies.replace(&tenant, &legacy, now).await.expect("legacy compatible");
    let old = asterius_domain::policy::explanation::revision(&legacy);
    assert!(policies.replace_if_revision(&tenant, &guarded, None, now).await.is_err());
    policies.replace_if_revision(&tenant, &guarded, Some(&old), now).await.expect("conditional CAS");
    assert!(policies.replace_if_revision(&tenant, &legacy, Some(&old), now).await.is_err());
    assert!(policies.replace(&tenant, &legacy, now).await.is_err());
    assert!(policies.clear(&tenant).await.is_err());
    assert_eq!(policies.load(&tenant).await.expect("read").expect("published").rules, guarded);

    let settings = PgConditionalSettings::new(pool.clone());
    let initial = settings.replace(&tenant, &client, Some(Sensitivity::Critical), None).await.expect("first classification");
    assert!(settings.replace(&tenant, &client, None, None).await.is_err());
    let changed = settings.replace(&tenant, &client, None, Some(initial.revision)).await.expect("classification CAS");
    assert_ne!(initial.revision, changed.revision);
    assert!(settings.replace(&tenant, &client, Some(Sensitivity::Critical), Some(initial.revision)).await.is_err());

    // A signing reader holds the same tenant SHARE fence. Direct SQL is a
    // distinct publication path, proving the trigger rather than only a port.
    let mut signing = pool.begin().await.expect("signing transaction");
    sqlx::query("select tenant_id from tenants where tenant_id='one' for share").execute(&mut *signing).await.expect("signing fence");
    let mut publisher = pool.begin().await.expect("publication transaction");
    sqlx::query("set local lock_timeout='50ms'").execute(&mut *publisher).await.expect("bounded wait");
    let blocked = sqlx::query("delete from tenant_policies where tenant_id='one'").execute(&mut *publisher).await.expect_err("publication blocks behind signature");
    assert_eq!(blocked.as_database_error().and_then(sqlx::error::DatabaseError::code).as_deref(), Some("55P03"));
    publisher.rollback().await.expect("rollback blocked mutation");
    signing.commit().await.expect("signature completed");
    sqlx::query("delete from tenant_policies where tenant_id='one'").execute(&pool).await.expect("publication after signature");
    assert!(policies.load(&tenant).await.expect("read cleared").is_none());

    let default_remedy = RuleSet::from_json(&serde_json::json!({"version":1,"rules":[],"conditional_scopes":[{"id":"fresh-auth","mode":"active","clients":["app"],"actions":["authorize"],"assurance_remedy":"phr","rules":[{"id":"strong","effect":"permit","when":{"acr_at_least":"phr"}}]}]})).expect("default remedy");
    policies.replace_if_revision(&tenant, &default_remedy, None, now).await.expect("missing settings use default ACR ladder");
    sqlx::query("delete from tenant_policies where tenant_id='one'").execute(&pool).await.expect("clear controlled fixture");

    // Cross-tenant/unknown client and unsupported remedies are refused even
    // for a direct writer using valid SQL and no Rust policy port.
    for document in [
        serde_json::json!({"version":1,"rules":[],"conditional_scopes":[{"clients":["foreign"],"assurance_remedy":null}]}),
        serde_json::json!({"version":1,"rules":[],"conditional_scopes":[{"clients":["app"],"assurance_remedy":"unsupported"}]}),
    ] {
        assert!(sqlx::query("insert into tenant_policies(tenant_id,document,updated_at) values('one',$1,now())").bind(document).execute(&pool).await.is_err());
    }
    pool.close().await;
    sqlx::query(&format!("drop schema {schema} cascade")).execute(&admin).await.expect("cleanup own schema");
    admin.close().await;
}
