//! PostgreSQL CI regression for tenant-before-user lifecycle serialization.
use super::*;
use crate::policies::PgPolicies;
use asterius_domain::Issuer;
use std::str::FromStr as _;
use std::time::Duration;

async fn fixture() -> (PgPool, PgUserRepository, UserId, Issuer) {
    let url = std::env::var("DATABASE_URL").expect("CI database URL");
    let tenant =
        TenantId::parse(&format!("lifecycle-{}", Uuid::new_v4().simple())).expect("fixture tenant");
    let options = sqlx::postgres::PgConnectOptions::from_str(&url)
        .expect("CI URL")
        .options([("application_name", tenant.as_str())]);
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .connect_with(options)
        .await
        .expect("test database");
    crate::MIGRATOR.run(&pool).await.expect("migrated fixture");

    let issuer = Issuer::parse(&format!("https://id.example/t/{}", tenant.as_str()))
        .expect("fixture issuer");
    sqlx::query("insert into tenants(tenant_id,issuer,display_name,default_resource) values($1,$2,'Lifecycle fixture','https://api.example/')")
        .bind(tenant.as_str()).bind(issuer.as_str()).execute(&pool).await.expect("fixture tenant");
    let user = UserId::generate();
    sqlx::query(
        "insert into users(tenant_id,user_id,username,status) values($1,$2,'owner','active')",
    )
    .bind(tenant.as_str())
    .bind(user.as_uuid())
    .execute(&pool)
    .await
    .expect("fixture user");
    let repository = PgUserRepository {
        pool: pool.clone(),
        tenant,
        kek: Arc::new(asterius_jose::LocalKek::from_bytes(&[0x59; 32]).expect("fixture KEK")),
    };
    (pool, repository, user, issuer)
}

async fn wait_for_tenant_lock(pool: &PgPool, query_fragment: &str) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let waiting: bool = sqlx::query_scalar(
                "select exists(select 1 from pg_stat_activity where datname=current_database() and application_name=current_setting('application_name') and pid<>pg_backend_pid() and wait_event_type='Lock' and query like $1)",
            )
            .bind(format!("%{query_fragment}%"))
            .fetch_one(pool)
            .await
            .expect("observe actual lock wait");
            if waiting {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("lifecycle must wait on tenant before acquiring user");
}

#[tokio::test]
#[ignore = "slow PostgreSQL lifecycle issuance ordering regression; CI only"]
async fn lifecycle_writer_waits_before_user_lock_and_disable_is_visible_after_commit() {
    let (pool, repository, user, issuer) = fixture().await;
    let policies = PgPolicies::new(pool.clone());
    let signer = policies
        .signing_fence(&repository.tenant, &issuer)
        .await
        .expect("signer wins tenant fence");
    let writer_repository = repository.clone();
    let writer =
        tokio::spawn(async move { writer_repository.disable_with_provider_commands(user).await });
    wait_for_tenant_lock(&pool, "for no key update").await;
    // A writer waiting on the tenant must not already own the user row.
    let mut probe = pool.begin().await.expect("probe transaction");
    sqlx::query("select user_id from users where tenant_id=$1 and user_id=$2 for share nowait")
        .bind(repository.tenant.as_str())
        .bind(user.as_uuid())
        .fetch_one(&mut *probe)
        .await
        .expect("user remains available to signer");
    probe.rollback().await.expect("release probe");
    signer
        .commit()
        .await
        .expect("signer commits before disable");
    writer
        .await
        .expect("writer task")
        .expect("disable succeeds");
    assert!(
        !repository
            .find(user)
            .await
            .expect("read disabled")
            .expect("user")
            .can_authenticate()
    );

    // Reverse the order: the issuance fence cannot pass a pending lifecycle write.
    sqlx::query("update users set status='active' where tenant_id=$1 and user_id=$2")
        .bind(repository.tenant.as_str())
        .bind(user.as_uuid())
        .execute(&pool)
        .await
        .expect("reset fixture outside concurrent issuance");
    let mut lifecycle = pool.begin().await.expect("lifecycle transaction");
    PgUserRepository::lifecycle_fence_on(&mut lifecycle, &repository.tenant)
        .await
        .expect("writer wins tenant fence");
    sqlx::query("update users set status='disabled' where tenant_id=$1 and user_id=$2")
        .bind(repository.tenant.as_str())
        .bind(user.as_uuid())
        .execute(&mut *lifecycle)
        .await
        .expect("same transaction status update");
    let reader_tenant = repository.tenant.clone();
    let reader = tokio::spawn(async move { policies.signing_fence(&reader_tenant, &issuer).await });
    wait_for_tenant_lock(&pool, "status='active' for share").await;
    lifecycle.commit().await.expect("commit lifecycle");
    let mut reader = reader.await.expect("reader task").expect("reader fence");
    let status: String =
        sqlx::query_scalar("select status from users where tenant_id=$1 and user_id=$2 for share")
            .bind(repository.tenant.as_str())
            .bind(user.as_uuid())
            .fetch_one(reader.connection())
            .await
            .expect("current status under fence");
    assert_eq!(status, "disabled");
    reader.commit().await.expect("release reader");
    sqlx::query("delete from tenants where tenant_id=$1")
        .bind(repository.tenant.as_str())
        .execute(&pool)
        .await
        .expect("cleanup fixture");
}
