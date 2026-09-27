//! Tenant isolation and optimistic writes for saved architecture drafts.

use std::collections::BTreeSet;
use std::str::FromStr as _;

use asterius_domain::{
    ApplicationRole, ClientId, DomainError, ResourceIdentifier, ResourceServer, RoleOwner, TenantId,
};
use asterius_store_pg::{FlowApplyStep, FlowLinkIntent, MIGRATOR, PgArchitectureFlows};
use serde_json::json;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use time::OffsetDateTime;
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires DATABASE_URL; CI runs ignored store tests"]
// One isolated schema covers both the draft CAS and its apply lease; splitting
// them would double migration cost and lose the same-flow state transition.
#[allow(clippy::too_many_lines)]
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
    let token = repository
        .begin_apply(&one, id, 2, now)
        .await
        .expect("claim apply");
    assert!(matches!(
        repository.begin_apply(&one, id, 2, now).await,
        Err(DomainError::Conflict(_))
    ));
    let intent = FlowLinkIntent {
        node: "api-node",
        kind: "api",
        resource: "https://api.example/accounts",
        relation: "managed",
    };
    let pending = repository
        .reserve(&one, id, token, 2, &intent, now)
        .await
        .expect("reserve link");
    assert_eq!(pending["state"], "pending");
    assert!(
        repository
            .links(&two, id)
            .await
            .expect("other links")
            .is_empty()
    );
    repository
        .complete(&one, id, token, 2, "api-node", now)
        .await
        .expect("complete link");
    let digest = "a".repeat(64);
    repository
        .finish_apply(&one, id, token, 2, &digest, None)
        .await
        .expect("finish apply");
    let applied = repository.read(&one, id).await.expect("applied flow");
    assert_eq!(applied["applied_revision"], 2);
    assert_eq!(applied["applied_digest"], digest);
    assert_eq!(
        repository.links(&one, id).await.expect("links")[0]["state"],
        "applied"
    );
    let group_id = Uuid::new_v4();
    repository
        .create_group(&one, group_id, "engineering", "Engineering", now)
        .await
        .expect("group");
    repository
        .create_group(&one, group_id, "engineering", "Engineering", now)
        .await
        .expect("idempotent group");
    assert!(matches!(
        repository
            .create_group(&one, Uuid::new_v4(), "engineering", "Other", now)
            .await,
        Err(DomainError::Conflict(_))
    ));
    let api = ResourceServer {
        identifier: ResourceIdentifier::parse("https://api.example/accounts").expect("API ID"),
        scopes: None,
        default_token_lifetime: None,
        introspection_clients: BTreeSet::default(),
    };
    repository.create_api(&one, &api).await.expect("API");
    assert!(matches!(
        repository.create_api(&one, &api).await,
        Err(DomainError::Conflict(_))
    ));
    sqlx::query("insert into clients (tenant_id, client_id, client_name, token_endpoint_auth_method, jwks) values ('one', 'flow-client', 'Flow app', 'private_key_jwt', '{}'::jsonb)")
        .execute(&pool).await.expect("client for role");
    let token = repository
        .begin_apply(&one, id, 2, now)
        .await
        .expect("second apply");
    let role_id = json!(["flow-client", "reader"]).to_string();
    let role_link = FlowLinkIntent {
        node: "role-node",
        kind: "role",
        resource: &role_id,
        relation: "managed",
    };
    repository
        .reserve(&one, id, token, 2, &role_link, now)
        .await
        .expect("reserve role");
    let role = ApplicationRole::new(
        one.clone(),
        RoleOwner::Client(ClientId::new("flow-client")),
        "reader",
        Some("Read"),
        now,
    )
    .expect("role");
    repository
        .create_role_and_complete(id, token, 2, "role-node", &role, now)
        .await
        .expect("atomic role");
    let count: i64 = sqlx::query_scalar("select count(*) from client_roles where tenant_id = 'one' and client_id = 'flow-client' and name = 'reader'")
        .fetch_one(&pool).await.expect("role count");
    assert_eq!(count, 1);
    assert_eq!(
        repository
            .links(&one, id)
            .await
            .expect("role link")
            .iter()
            .find(|link| link["node_id"] == "role-node")
            .expect("role link")["state"],
        "applied"
    );
    repository
        .finish_apply(&one, id, token, 2, &digest, None)
        .await
        .expect("finish second apply");
    let token = repository
        .begin_apply(&one, id, 2, now)
        .await
        .expect("third apply");
    let new_api = ResourceServer {
        identifier: ResourceIdentifier::parse("https://api.example/new").expect("new API ID"),
        scopes: Some(BTreeSet::from(["read".to_owned()])),
        default_token_lifetime: None,
        introspection_clients: BTreeSet::default(),
    };
    let intent = FlowLinkIntent {
        node: "new-api",
        kind: "api",
        resource: new_api.identifier.as_str(),
        relation: "managed",
    };
    repository
        .reserve(&one, id, token, 2, &intent, now)
        .await
        .expect("reserve API");
    repository
        .create_api_and_complete(
            &one,
            &FlowApplyStep {
                flow: id,
                token,
                revision: 2,
                node: "new-api",
                now,
            },
            &new_api,
        )
        .await
        .expect("atomic API");
    assert_eq!(
        repository
            .links(&one, id)
            .await
            .expect("API link")
            .iter()
            .find(|link| link["node_id"] == "new-api")
            .expect("API link")["state"],
        "applied"
    );
    repository
        .finish_apply(&one, id, token, 2, &digest, None)
        .await
        .expect("finish third apply");
    sqlx::query(&format!("drop schema {schema} cascade"))
        .execute(&pool)
        .await
        .expect("cleanup");
    pool.close().await;
}
