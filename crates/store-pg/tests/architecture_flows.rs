//! Tenant isolation and optimistic writes for saved architecture drafts.

use std::str::FromStr as _;

use asterius_domain::{DomainError, TenantId};
use asterius_store_pg::{MIGRATOR, PgArchitectureFlows};
use serde_json::json;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use time::OffsetDateTime;
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires DATABASE_URL; CI runs ignored store tests"]
async fn drafts_are_tenant_bound_and_stale_writes_conflict() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL for ignored store test");
    let schema = format!("architecture_{}", Uuid::new_v4().simple());
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
    let repository = PgArchitectureFlows::new(pool.clone());
    let one = TenantId::new("one");
    let two = TenantId::new("two");
    let id = Uuid::new_v4();
    let now = OffsetDateTime::UNIX_EPOCH;
    let graph = json!({"schema_version": 1, "nodes": [], "edges": []});
    let created = repository
        .create(&one, id, "Example", graph.clone(), now)
        .await
        .expect("create");
    assert_eq!(created["revision"], 1);
    assert!(repository.list(&two).await.expect("other list").is_empty());
    assert!(matches!(
        repository.read(&two, id).await,
        Err(DomainError::NotFound)
    ));
    let updated = repository
        .update(&one, id, 1, "Changed", graph.clone(), now)
        .await
        .expect("update");
    assert_eq!(updated["revision"], 2);
    assert!(matches!(
        repository.update(&one, id, 1, "Stale", graph, now).await,
        Err(DomainError::Conflict(_))
    ));
    assert_eq!(
        repository.read(&one, id).await.expect("current")["name"],
        "Changed"
    );
    sqlx::query(&format!("drop schema {schema} cascade"))
        .execute(&pool)
        .await
        .expect("cleanup");
    pool.close().await;
}
