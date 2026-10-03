//! CI regression for amendment winning before the exact final signing fence.
use asterius_domain::{ClientId, Grant, Issuer, TenantId};
use asterius_store_pg::{MIGRATOR, PgGrantRepository, PgPolicies};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use std::str::FromStr as _;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires PostgreSQL; CI runs ignored final issuance revision regressions"]
async fn grant_amend_issuance_fence_refuses_stale_revision_but_preserves_claim_and_narrowing() {
    let url = std::env::var("DATABASE_URL").expect("CI PostgreSQL URL");
    let schema = format!("grant_revision_{}", Uuid::new_v4().simple());
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .expect("admin");
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
    let tenant = TenantId::new("revision");
    let issuer = Issuer::parse("https://as.example/revision").expect("issuer");
    sqlx::query("insert into tenants(tenant_id,issuer,display_name,default_resource) values('revision','https://as.example/revision','Revision','https://api.example/')").execute(&pool).await.expect("tenant");
    sqlx::query("insert into clients(tenant_id,client_id,client_name,token_endpoint_auth_method,jwks) values('revision','client','Client','private_key_jwt','{\"keys\":[]}'::jsonb)").execute(&pool).await.expect("client");
    let now = OffsetDateTime::now_utc();
    let mut original = Grant::new(tenant.clone(), ClientId::new("client"), now);
    original.scopes = ["openid".to_owned(), "device.read".to_owned()].into();
    original.resources = ["https://api.example/".to_owned()].into();
    let repository = PgGrantRepository::new(pool.clone(), tenant.clone());
    repository
        .create(&original)
        .await
        .expect("create exact grant");
    repository
        .claim(&original.id, now)
        .await
        .expect("claim stamps authority without changing revision");
    let mut narrowed = original.clone();
    narrowed.scopes = ["openid".to_owned()].into();
    let mut signing = PgPolicies::new(pool.clone())
        .signing_fence(&tenant, &issuer)
        .await
        .expect("publication");
    assert!(
        PgGrantRepository::lock_issuance_authority_on(signing.connection(), &tenant, &narrowed)
            .await
            .is_ok(),
        "normal first claim and target narrowing retain exact permission revision"
    );
    signing
        .commit()
        .await
        .expect("release original signing fence");

    let mut amended = repository
        .find(&original.id)
        .await
        .expect("load")
        .expect("grant");
    amended.scopes = ["device.read".to_owned()].into();
    repository
        .amend(&amended, now + Duration::seconds(1))
        .await
        .expect("real amendment removes openid authority");
    let mut signing = PgPolicies::new(pool.clone())
        .signing_fence(&tenant, &issuer)
        .await
        .expect("publication after amend");
    assert!(
        PgGrantRepository::lock_issuance_authority_on(signing.connection(), &tenant, &narrowed)
            .await
            .is_err(),
        "unchanged identity tuple cannot authorize stale openid/authentication facts after amendment"
    );
    signing
        .commit()
        .await
        .expect("no signature or receipt from refused authority");
    let current = repository
        .find(&original.id)
        .await
        .expect("reload")
        .expect("current grant");
    let mut signing = PgPolicies::new(pool.clone())
        .signing_fence(&tenant, &issuer)
        .await
        .expect("fresh publication");
    assert!(
        PgGrantRepository::lock_issuance_authority_on(signing.connection(), &tenant, &current)
            .await
            .is_ok(),
        "freshly loaded current revision remains usable"
    );
    signing.commit().await.expect("release fresh signing fence");
    pool.close().await;
    sqlx::query(&format!("drop schema {schema} cascade"))
        .execute(&admin)
        .await
        .expect("cleanup");
    admin.close().await;
}
