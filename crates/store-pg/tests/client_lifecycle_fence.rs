//! CI-only client/publication lock ordering; no cryptographic issuance is claimed.
use asterius_domain::{Capabilities, Client, ClientId, ClientRegistration, ClientStatus, TenantId};
use asterius_store_pg::{MIGRATOR, PgClientRepository, PgPolicies};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use std::str::FromStr as _;
use time::OffsetDateTime;
use uuid::Uuid;

struct Fixture {
    admin: sqlx::PgPool,
    pool: sqlx::PgPool,
    schema: String,
    tenant: TenantId,
    client: Client,
}
impl Fixture {
    async fn new() -> Self {
        let url = std::env::var("DATABASE_URL").expect("CI PostgreSQL URL");
        let schema = format!("client_lifecycle_{}", Uuid::new_v4().simple());
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
        let tenant = TenantId::new("lifecycle");
        sqlx::query("insert into tenants(tenant_id,issuer,display_name,default_resource) values('lifecycle','https://as.example/lifecycle','Lifecycle','https://api.example/')")
            .execute(&pool).await.expect("tenant");
        let document = serde_json::json!({"client_name":"Controller","redirect_uris":["https://rp.example/cb"],"jwks_uri":"https://keys.example/jwks"});
        let client = Client {
            tenant: tenant.clone(),
            id: ClientId::new("controller"),
            registration: ClientRegistration::from_json(
                &serde_json::to_vec(&document).expect("JSON"),
                Capabilities::default(),
            )
            .expect("registration"),
            status: ClientStatus::Active,
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
        };
        PgClientRepository::new(pool.clone(), tenant.clone(), Capabilities::default())
            .upsert(&client)
            .await
            .expect("client");
        sqlx::query("insert into clients(tenant_id,client_id,client_name,token_endpoint_auth_method,jwks) values('lifecycle','reviewer','Reviewer','private_key_jwt','{\"keys\":[]}'::jsonb)")
            .execute(&pool).await.expect("reviewer");
        sqlx::query("insert into kubernetes_profiles(tenant_id,client_id,cluster_id,namespace,group_ids,revision) values('lifecycle','controller','owned','owned','{}',1)")
            .execute(&pool).await.expect("cluster profile");
        sqlx::query("insert into kubernetes_online_profiles(tenant_id,client_id,reviewer_client_id,enabled) values('lifecycle','controller','reviewer',true)")
            .execute(&pool).await.expect("online publication state");
        Self {
            admin,
            pool,
            schema,
            tenant,
            client,
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

#[tokio::test]
#[ignore = "requires PostgreSQL; CI runs client publication ordering regression"]
async fn client_lifecycle_writer_waits_before_client_row_and_preserves_invalidation() {
    let f = Fixture::new().await;
    let issuer = asterius_domain::Issuer::parse("https://as.example/lifecycle").expect("issuer");
    let mut signing = PgPolicies::new(f.pool.clone())
        .signing_fence(&f.tenant, &issuer)
        .await
        .expect("publication read admission");
    let repository =
        PgClientRepository::new(f.pool.clone(), f.tenant.clone(), Capabilities::default());
    let mut client = f.client.clone();
    client.status = ClientStatus::Disabled;
    let writer = tokio::spawn(async move { repository.upsert(&client).await });
    tokio::time::timeout(std::time::Duration::from_secs(5),async {
        loop {
            let blocked: bool = sqlx::query_scalar("select exists(select 1 from pg_stat_activity where application_name=$1 and wait_event_type='Lock')")
                .bind(&f.schema).fetch_one(&f.pool).await.expect("observe writer admission");
            if blocked { break; }
            tokio::task::yield_now().await;
        }
    }).await.expect("writer waits on held tenant publication admission");
    let status: String = tokio::time::timeout(std::time::Duration::from_secs(1),sqlx::query_scalar("select status from clients where tenant_id='lifecycle' and client_id='controller' for share").fetch_one(signing.connection()))
        .await.expect("writer must not hold client while waiting for tenant").expect("current client");
    assert_eq!(status, "active");
    assert!(!writer.is_finished());
    signing.commit().await.expect("publication commit");
    writer.await.expect("writer joined").expect("client update");
    let state: (String,bool) = sqlx::query_as("select c.status,p.enabled from clients c join kubernetes_online_profiles p using(tenant_id,client_id) where c.tenant_id='lifecycle' and c.client_id='controller'")
        .fetch_one(&f.pool).await.expect("committed lifecycle state");
    assert_eq!(state, ("disabled".to_owned(), false));
    f.cleanup().await;
}
