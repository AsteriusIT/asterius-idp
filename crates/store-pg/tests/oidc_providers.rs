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
        enabled: true,
        allow_registration: false,
        created_at: OffsetDateTime::UNIX_EPOCH,
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
