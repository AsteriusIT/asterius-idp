//! CI PostgreSQL regressions for private parent authority generations.
use asterius_domain::{ClientId, Grant, Issuer, ParentDerivation, TenantId};
use asterius_store_pg::{MIGRATOR, PgGrantRepository, PgPolicies};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use std::str::FromStr as _;
use time::OffsetDateTime;
use uuid::Uuid;

struct Fixture {
    admin: sqlx::PgPool,
    pool: sqlx::PgPool,
    schema: String,
    tenant: TenantId,
    issuer: Issuer,
    parent: Grant,
}
impl Fixture {
    async fn new() -> Self {
        let url = std::env::var("DATABASE_URL").expect("CI PostgreSQL URL");
        let schema = format!("parent_revision_{}", Uuid::new_v4().simple());
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
        let tenant = TenantId::new("parent");
        let issuer = Issuer::parse("https://as.example/parent").expect("issuer");
        sqlx::query("insert into tenants(tenant_id,issuer,display_name,default_resource) values('parent','https://as.example/parent','Parent','https://api.example/')").execute(&pool).await.expect("tenant");
        sqlx::query("insert into clients(tenant_id,client_id,client_name,token_endpoint_auth_method,jwks) values('parent','client','Client','private_key_jwt','{\"keys\":[]}'::jsonb)").execute(&pool).await.expect("client");
        let mut parent = Grant::new(
            tenant.clone(),
            ClientId::new("client"),
            OffsetDateTime::now_utc(),
        );
        parent.scopes = ["openid".to_owned(), "device.read".to_owned()].into();
        parent.resources = ["https://api.example/".to_owned()].into();
        parent.claimed_at = Some(parent.created_at);
        PgGrantRepository::new(pool.clone(), tenant.clone())
            .create(&parent)
            .await
            .expect("parent");
        Self {
            admin,
            pool,
            schema,
            tenant,
            issuer,
            parent,
        }
    }
    fn child(&self, receipt: bool) -> Grant {
        let mut child = Grant::new(
            self.tenant.clone(),
            self.parent.client.clone(),
            OffsetDateTime::now_utc(),
        );
        child.parent = Some(self.parent.id.clone());
        child.parent_derivation = receipt.then(|| ParentDerivation::from_grant(&self.parent));
        child.scopes = ["openid".to_owned()].into();
        child.resources.clone_from(&self.parent.resources);
        child.claimed_at = Some(child.created_at);
        child
    }
    async fn allowed(&self, grant: &Grant) -> bool {
        let mut signing = PgPolicies::new(self.pool.clone())
            .signing_fence(&self.tenant, &self.issuer)
            .await
            .expect("publication");
        let allowed = PgGrantRepository::lock_issuance_authority_on(
            signing.connection(),
            &self.tenant,
            grant,
        )
        .await
        .is_ok();
        signing
            .commit()
            .await
            .expect("release authority without signature");
        allowed
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

#[tokio::test]
#[ignore = "requires PostgreSQL; CI runs private derivation generation regressions"]
async fn grant_parent_derivation_amendment_before_child_publication_refuses_old_ceiling() {
    let f = Fixture::new().await;
    let child = f.child(true);
    let repository = PgGrantRepository::new(f.pool.clone(), f.tenant.clone());
    repository
        .create(&child)
        .await
        .expect("derived child and immutable receipt inserted atomically");
    assert!(
        f.allowed(&child).await,
        "unchanged captured authority permits legitimate narrowed child"
    );
    let mut amended = f.parent.clone();
    amended.scopes = ["device.read".to_owned()].into();
    repository
        .amend(&amended, amended.created_at)
        .await
        .expect("real amendment wins before child signature");
    assert!(
        !f.allowed(&child).await,
        "fresh child identity tuple cannot hide stale parent ceiling"
    );
    let reloaded = repository
        .find(&child.id)
        .await
        .expect("load child")
        .expect("child");
    assert_eq!(
        reloaded.parent_derivation, child.parent_derivation,
        "loading preserves original receipt instead of synthesizing new authority"
    );
    assert!(!f.allowed(&reloaded).await);
    let changed=sqlx::query("update grants set parent_authority_revision=(select authority_revision from grants where tenant_id='parent' and grant_id=$1) where tenant_id='parent' and grant_id=$2")
        .bind(Uuid::parse_str(f.parent.id.as_str()).expect("UUID"))
        .bind(Uuid::parse_str(child.id.as_str()).expect("UUID"))
        .execute(&f.pool).await;
    assert!(
        changed.is_err(),
        "existing historical receipt cannot be backfilled from amended parent"
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL; CI runs private derivation generation regressions"]
async fn grant_parent_derivation_same_transaction_clock_changes_generation_and_legacy_is_absent() {
    let f = Fixture::new().await;
    let legacy = f.child(false);
    PgGrantRepository::new(f.pool.clone(), f.tenant.clone())
        .create(&legacy)
        .await
        .expect("legacy child");
    assert!(
        !f.allowed(&legacy).await,
        "missing historical derivation does not acquire current authority"
    );
    let mut transaction = f.pool.begin().await.expect("same-clock transaction");
    let id = Uuid::parse_str(f.parent.id.as_str()).expect("UUID");
    let first:(Uuid,OffsetDateTime)=sqlx::query_as("update grants set scopes=array['openid'] where tenant_id='parent' and grant_id=$1 returning authority_revision,updated_at")
        .bind(id).fetch_one(&mut *transaction).await.expect("first authority change");
    let second:(Uuid,OffsetDateTime)=sqlx::query_as("update grants set scopes=array['device.read'] where tenant_id='parent' and grant_id=$1 returning authority_revision,updated_at")
        .bind(id).fetch_one(&mut *transaction).await.expect("second authority change");
    assert_eq!(
        first.1, second.1,
        "baseline bookkeeping timestamp is fixed within this transaction"
    );
    assert_ne!(
        first.0, second.0,
        "every actual authority change gets a distinct generation"
    );
    transaction.commit().await.expect("commit changes");
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL; CI runs exact ancestor principal closure"]
async fn grant_parent_derivation_source_client_disable_blocks_different_sector_child() {
    let f = Fixture::new().await;
    sqlx::query("insert into clients(tenant_id,client_id,client_name,token_endpoint_auth_method,jwks) values('parent','recipient','Recipient','private_key_jwt','{\"keys\":[]}'::jsonb)").execute(&f.pool).await.expect("recipient client");
    let mut child = f.child(true);
    child.client = ClientId::new("recipient");
    // Native SSO may legitimately derive a different target-sector subject;
    // the exact persisted leaf tuple is checked, never global ancestor equality.
    child.subject = Some(asterius_domain::SubjectId::new("target-sector-subject"));
    PgGrantRepository::new(f.pool.clone(), f.tenant.clone())
        .create(&child)
        .await
        .expect("exact derived recipient");
    assert!(
        f.allowed(&child).await,
        "different client/sector remains valid with unchanged receipt"
    );
    sqlx::query(
        "update clients set status='disabled' where tenant_id='parent' and client_id='client'",
    )
    .execute(&f.pool)
    .await
    .expect("source disable wins");
    assert!(
        !f.allowed(&child).await,
        "active recipient cannot hide disabled exact source client"
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL; CI runs exact human lifecycle closure"]
async fn grant_parent_derivation_current_disabled_human_blocks_publication() {
    let f = Fixture::new().await;
    let user = Uuid::new_v4();
    sqlx::query("insert into users(tenant_id,user_id,username) values('parent',$1,'owner')")
        .bind(user)
        .execute(&f.pool)
        .await
        .expect("owner");
    let mut child = Grant::new(
        f.tenant.clone(),
        f.parent.client.clone(),
        OffsetDateTime::now_utc(),
    );
    child.user = Some(asterius_domain::UserId::new(user));
    child.subject = Some(asterius_domain::SubjectId::new("owner-subject"));
    child.claimed_at = Some(child.created_at);
    PgGrantRepository::new(f.pool.clone(), f.tenant.clone())
        .create(&child)
        .await
        .expect("human grant");
    assert!(f.allowed(&child).await);
    sqlx::query("update users set status='disabled' where tenant_id='parent' and user_id=$1")
        .bind(user)
        .execute(&f.pool)
        .await
        .expect("disable wins before fence");
    assert!(
        !f.allowed(&child).await,
        "unchanged grant generation cannot substitute current human authority"
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL; CI runs frozen session authority compatibility"]
async fn grant_parent_derivation_attested_lookup_rotation_preserves_generation() {
    let f = Fixture::new().await;
    sqlx::query("insert into users(tenant_id,user_id,username) values('parent','00000000-0000-4000-8000-000000000001','session-owner')").execute(&f.pool).await.expect("owner");
    sqlx::query("insert into sessions(tenant_id,session_id,public_sid,user_id,authenticated_at,expires_at,idle_expires_at,acr,amr) values ('parent','old','original','00000000-0000-4000-8000-000000000001',now(),now()+interval '1 hour',now()+interval '1 hour','phr',array['pop','user']),('parent','other','unrelated','00000000-0000-4000-8000-000000000001',now(),now()+interval '1 hour',now()+interval '1 hour','phr',array['pop','user'])").execute(&f.pool).await.expect("sessions");
    sqlx::query("insert into session_assurance_proofs(tenant_id,session_id,acr,assurance_authenticated_at,assurance_policy_revision,assurance_methods) select tenant_id,session_id,acr,authenticated_at,repeat('a',64),amr from sessions").execute(&f.pool).await.expect("original proofs");
    let id = Uuid::new_v4();
    sqlx::query("insert into grants(tenant_id,grant_id,client_id,user_id,subject,session_id,authenticated_at,acr,amr) select 'parent',$1,'client',user_id,'session-owner',session_id,authenticated_at,acr,amr from sessions where session_id='old'").bind(id).execute(&f.pool).await.expect("frozen grant");
    let revision: Uuid =
        sqlx::query_scalar("select authority_revision from grants where grant_id=$1")
            .bind(id)
            .fetch_one(&f.pool)
            .await
            .expect("original generation");
    let mut transaction = f.pool.begin().await.expect("lookup rotation");
    sqlx::query("update sessions set session_id='new',authenticated_at=authenticated_at+interval '30 seconds' where tenant_id='parent' and session_id='old'").execute(&mut *transaction).await.expect("stable public session lookup move");
    sqlx::query("update grants set session_id='new' where tenant_id='parent' and grant_id=$1")
        .bind(id)
        .execute(&mut *transaction)
        .await
        .expect("attested exact grant lookup move");
    transaction.commit().await.expect("commit lookup rotation");
    let after: Uuid = sqlx::query_scalar("select authority_revision from grants where grant_id=$1")
        .bind(id)
        .fetch_one(&f.pool)
        .await
        .expect("same authority");
    assert_eq!(
        revision, after,
        "attested same-public-session lookup move does not invalidate descendants"
    );
    sqlx::query("update grants set session_id='other' where tenant_id='parent' and grant_id=$1")
        .bind(id)
        .execute(&f.pool)
        .await
        .expect("arbitrary same-user reassignment");
    let reassigned: Uuid =
        sqlx::query_scalar("select authority_revision from grants where grant_id=$1")
            .bind(id)
            .fetch_one(&f.pool)
            .await
            .expect("new authority generation");
    assert_ne!(
        revision, reassigned,
        "unrelated session cannot retain frozen authority generation"
    );
    f.cleanup().await;
}
