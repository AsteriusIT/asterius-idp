//! CI PostgreSQL regressions for the final exact-grant signing authority fence.
//! These exercise real row locks and withdrawal, not cryptographic signatures.
use asterius_domain::{ClientId, Grant, RevocationReason, TenantId};
use asterius_store_pg::{MIGRATOR, PgGrantRepository, PgPolicies};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use std::str::FromStr as _;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

struct Fixture {
    admin: sqlx::PgPool,
    pool: sqlx::PgPool,
    schema: String,
    tenant: TenantId,
    grant: Grant,
}
impl Fixture {
    async fn new() -> Self {
        let url = std::env::var("DATABASE_URL").expect("CI PostgreSQL URL");
        let schema = format!("grant_issuance_{}", Uuid::new_v4().simple());
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .expect("admin");
        sqlx::query(&format!("create schema {schema}"))
            .execute(&admin)
            .await
            .expect("schema");
        let options = PgConnectOptions::from_str(&url).expect("URL").options([
            ("search_path", schema.as_str()),
            ("application_name", schema.as_str()),
        ]);
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect_with(options)
            .await
            .expect("pool");
        MIGRATOR.run(&pool).await.expect("migrations");
        let tenant = TenantId::new("issuance");
        sqlx::query("insert into tenants(tenant_id,issuer,display_name,default_resource) values('issuance','https://as.example/issuance','Issuance','https://api.example/')").execute(&pool).await.expect("tenant");
        sqlx::query("insert into clients(tenant_id,client_id,client_name,token_endpoint_auth_method,jwks) values('issuance','human','Human','private_key_jwt','{\"keys\":[]}'::jsonb)").execute(&pool).await.expect("client");
        let now = OffsetDateTime::now_utc();
        let mut grant = Grant::new(tenant.clone(), ClientId::new("human"), now);
        grant.claimed_at = Some(now);
        grant.expires_at = Some(now + Duration::hours(1));
        PgGrantRepository::new(pool.clone(), tenant.clone())
            .create(&grant)
            .await
            .expect("grant");
        Self {
            admin,
            pool,
            schema,
            tenant,
            grant,
        }
    }
    async fn cleanup(self) {
        self.pool.close().await;
        sqlx::query(&format!("drop schema {} cascade", self.schema))
            .execute(&self.admin)
            .await
            .expect("cleanup");
        self.admin.close().await;
    }
}

async fn wait_for_lock(pool: &sqlx::PgPool, pid: i32) {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let blocked: bool = sqlx::query_scalar("select exists(select 1 from pg_stat_activity where pid=$1 and wait_event_type='Lock')")
                .bind(pid).fetch_one(pool).await.expect("lock observation");
            if blocked { break; }
            tokio::task::yield_now().await;
        }
    }).await.expect("operation must reach the database row lock");
}

#[tokio::test]
#[ignore = "requires PostgreSQL; CI runs ignored signing authority regressions"]
async fn grant_issuance_fence_signer_wins_blocks_real_withdrawal() {
    let f = Fixture::new().await;
    let mut signing = PgPolicies::new(f.pool.clone())
        .signing_fence(&f.tenant)
        .await
        .expect("publication");
    let authority =
        PgGrantRepository::lock_issuance_authority_on(signing.connection(), &f.tenant, &f.grant)
            .await
            .expect("authority");
    assert!(authority.active_at(OffsetDateTime::now_utc()));
    let repository = PgGrantRepository::new(f.pool.clone(), f.tenant.clone());
    let grant_id = f.grant.id.clone();
    let waiter = tokio::spawn(async move {
        repository
            .revoke(
                &grant_id,
                RevocationReason::UserRevoked,
                &[],
                OffsetDateTime::now_utc(),
            )
            .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let blocked: bool = sqlx::query_scalar("select exists(select 1 from pg_stat_activity where application_name=$1 and wait_event_type='Lock')")
                .bind(&f.schema).fetch_one(&f.pool).await.expect("withdrawal lock observation");
            if blocked { break; }
            tokio::task::yield_now().await;
        }
    }).await.expect("real withdrawal waits on held signing authority");
    assert!(!waiter.is_finished());
    signing
        .commit()
        .await
        .expect("signature transaction commits before withdrawal");
    waiter
        .await
        .expect("withdrawal task")
        .expect("real repository withdrawal resumes");
    let mut late = PgPolicies::new(f.pool.clone())
        .signing_fence(&f.tenant)
        .await
        .expect("late publication");
    assert!(
        PgGrantRepository::lock_issuance_authority_on(late.connection(), &f.tenant, &f.grant)
            .await
            .is_err()
    );
    late.commit()
        .await
        .expect("refused transition commits no signature or binding");
    let receipts: i64 = sqlx::query_scalar(
        "select count(*) from kubernetes_online_tokens where tenant_id='issuance'",
    )
    .fetch_one(&f.pool)
    .await
    .expect("receipts");
    assert_eq!(receipts, 0);
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL; CI runs ignored signing authority regressions"]
async fn grant_issuance_fence_waiter_rechecks_database_clock_and_ancestry() {
    let f = Fixture::new().await;
    let mut writer = f.pool.begin().await.expect("writer");
    let id = Uuid::parse_str(f.grant.id.as_str()).expect("UUID");
    sqlx::query(
        "select grant_id from grants where tenant_id='issuance' and grant_id=$1 for update",
    )
    .bind(id)
    .fetch_one(&mut *writer)
    .await
    .expect("writer wins");
    let mut signing = PgPolicies::new(f.pool.clone())
        .signing_fence(&f.tenant)
        .await
        .expect("publication");
    let pid: i32 = sqlx::query_scalar("select pg_backend_pid()")
        .fetch_one(signing.connection())
        .await
        .expect("pid");
    let tenant = f.tenant.clone();
    let grant = f.grant.clone();
    let waiter = tokio::spawn(async move {
        let result =
            PgGrantRepository::lock_issuance_authority_on(signing.connection(), &tenant, &grant)
                .await;
        signing
            .commit()
            .await
            .expect("refused issuance transaction");
        result
    });
    wait_for_lock(&f.pool, pid).await;
    // Expiry changes AFTER the signer began waiting. Frozen process time or a
    // pre-wait query snapshot must not authorize signing after this commit.
    sqlx::query("update grants set expires_at=clock_timestamp()-interval '1 second' where tenant_id='issuance' and grant_id=$1").bind(id).execute(&mut *writer).await.expect("expire during wait");
    writer.commit().await.expect("expiry wins");
    assert!(waiter.await.expect("waiter").is_err());
    sqlx::query("update grants set expires_at=clock_timestamp()+interval '1 hour',parent_grant_id=grant_id where tenant_id='issuance' and grant_id=$1").bind(id).execute(&f.pool).await.expect("cycle fixture");
    let mut signing = PgPolicies::new(f.pool.clone())
        .signing_fence(&f.tenant)
        .await
        .expect("publication");
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            PgGrantRepository::lock_issuance_authority_on(
                signing.connection(),
                &f.tenant,
                &f.grant
            )
        )
        .await
        .expect("bounded cycle refusal")
        .is_err()
    );
    signing.commit().await.expect("no signing side effects");
    f.cleanup().await;
}
