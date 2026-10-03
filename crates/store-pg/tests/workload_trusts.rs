//! Tenant isolation and the transaction fence used by future external exchange.
use asterius_domain::workload::{Config, Registry, Verified};
use asterius_domain::{Actor, TenantId};
use asterius_store_pg::{MIGRATOR, PgWorkloadTrusts};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use std::str::FromStr as _;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires DATABASE_URL; CI runs ignored store tests"]
// The single schema test checks rollback, replay and authoritative version fences together.
#[allow(clippy::too_many_lines)]
async fn revisions_replay_and_audit_are_tenant_bound() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL");
    let schema = format!("workload_trusts_{}", Uuid::new_v4().simple());
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .expect("database");
    sqlx::query(&format!("create schema {schema}"))
        .execute(&admin)
        .await
        .expect("schema");
    let options = PgConnectOptions::from_str(&url)
        .expect("URL")
        .options([("search_path", schema.as_str())]);
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect_with(options)
        .await
        .expect("pool");
    MIGRATOR.run(&pool).await.expect("migrations");
    for name in ["one", "two"] {
        sqlx::query("insert into tenants(tenant_id,issuer,display_name,default_resource) values($1,$2,$1,'https://api.example/')")
            .bind(name).bind(format!("https://id.example/{name}")).execute(&pool).await.expect("tenant");
    }
    let one = TenantId::new("one");
    let two = TenantId::new("two");
    let registry = PgWorkloadTrusts::new(pool.clone());
    let now = OffsetDateTime::now_utc();
    let mut config: Config = serde_json::from_value(serde_json::json!({
        "issuer":"https://cluster.example", "audience":"urn:asterius:workload:one:inventory",
        "subject":"system:serviceaccount:apps:inventory", "provider":"kubernetes",
        "principal":"workload:inventory", "clients":["client"], "scopes":["read"],
        "resources":["https://api.example/"], "actions":["read"],
        "required_claims":{"/kubernetes.io/namespace":"apps","/kubernetes.io/serviceaccount/name":"inventory","/kubernetes.io/serviceaccount/uid":"uid"},
        "algorithms":["EdDSA"], "keys":{"kind":"remote","uri":"https://cluster.example/keys"}
    })).expect("config");
    let created = registry
        .put(&one, "inventory", &config, None, Actor::System, now)
        .await
        .expect("create");
    assert!(!created.enabled);
    assert!(
        registry
            .find(&two, "inventory")
            .await
            .expect("other tenant")
            .is_none()
    );
    assert!(
        registry
            .put(&one, "inventory", &config, None, Actor::System, now)
            .await
            .is_err()
    );
    let metadata = serde_json::to_value(&created).expect("metadata");
    assert!(metadata.get("keys").is_none());
    config.enabled = true;
    let enabled = registry
        .put(
            &one,
            "inventory",
            &config,
            Some(created.version),
            Actor::System,
            now,
        )
        .await
        .expect("enable");
    let verified = Verified {
        client: asterius_domain::ClientId::new("client"),
        provider: asterius_domain::workload::Provider::Kubernetes,
        tenant: one.clone(),
        trust_id: "inventory".into(),
        trust_version: enabled.version,
        principal: config.principal.clone(),
        expires_at: now + Duration::seconds(300),
        digest: [17; 32],
        scopes: config.scopes.clone(),
        resources: config.resources.clone(),
        actions: config.actions.clone(),
    };
    let mut tx = pool.begin().await.expect("begin");
    asterius_store_pg::workload::consume_on_connection(&mut tx, &verified, now)
        .await
        .expect("first");
    tx.rollback().await.expect("rollback child issuance");
    let mut tx = pool.begin().await.expect("begin");
    asterius_store_pg::workload::consume_on_connection(&mut tx, &verified, now)
        .await
        .expect("rollback retained no mark");
    tx.commit().await.expect("commit issuance");
    let mut tx = pool.begin().await.expect("begin");
    assert!(
        asterius_store_pg::workload::consume_on_connection(&mut tx, &verified, now)
            .await
            .is_err()
    );
    tx.rollback().await.expect("rollback");
    config.enabled = false;
    let disabled = registry
        .put(
            &one,
            "inventory",
            &config,
            Some(enabled.version),
            Actor::System,
            now,
        )
        .await
        .expect("disable");
    let mut tx = pool.begin().await.expect("begin");
    assert!(
        asterius_store_pg::workload::consume_on_connection(&mut tx, &verified, now)
            .await
            .is_err()
    );
    tx.rollback().await.expect("rollback");
    registry
        .delete(&one, "inventory", disabled.version, Actor::System, now)
        .await
        .expect("delete");
    config.enabled = true;
    let recreated = registry
        .put(&one, "inventory", &config, None, Actor::System, now)
        .await
        .expect("recreate");
    assert!(recreated.version > disabled.version);
    let mut verified = verified;
    verified.trust_version = recreated.version;
    let mut tx = pool.begin().await.expect("begin");
    assert!(
        asterius_store_pg::workload::consume_on_connection(&mut tx, &verified, now)
            .await
            .is_err()
    );
    tx.rollback().await.expect("rollback");
    let count: i64 = sqlx::query_scalar("select count(*) from audit_events where tenant_id='one'")
        .fetch_one(&pool)
        .await
        .expect("audit");
    assert_eq!(count, 5);
    pool.close().await;
    sqlx::query(&format!("drop schema {schema} cascade"))
        .execute(&admin)
        .await
        .expect("cleanup");
    admin.close().await;
}
