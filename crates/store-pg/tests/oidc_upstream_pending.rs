//! Single-use, encrypted upstream browser transaction persistence.

use asterius_domain::{TenantId, sha256_hex};
use asterius_jose::{Kek, LocalKek};
use asterius_store_pg::{MIGRATOR, NewOidcPending, Store};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use std::{str::FromStr as _, sync::Arc};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires DATABASE_URL; CI runs ignored store tests"]
// The single-use lifecycle shares one isolated schema and must run in order.
#[allow(clippy::too_many_lines)]
async fn state_is_encrypted_browser_bound_and_single_use() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL for ignored store test");
    let schema = format!("oidc_pending_{}", Uuid::new_v4().simple());
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
    let kek: Arc<dyn Kek> = Arc::new(LocalKek::from_bytes(&[0x29; 32]).expect("32-byte KEK"));
    let one = store
        .scope(TenantId::new("one"))
        .oidc_upstream_pending(Arc::clone(&kek));
    let two = store
        .scope(TenantId::new("two"))
        .oidc_upstream_pending(Arc::clone(&kek));
    let state = sha256_hex(b"state");
    let interaction = sha256_hex(b"interaction");
    let other_interaction = sha256_hex(b"other interaction");
    let nonce = sha256_hex(b"nonce");
    let now = OffsetDateTime::now_utc();
    one.begin(
        &NewOidcPending {
            state_digest: &state,
            interaction_digest: &interaction,
            provider_id: "corporate",
            issuer: "https://login.example",
            client_id: "client",
            token_endpoint: "https://login.example/token",
            jwks_uri: "https://login.example/keys",
            nonce_digest: &nonce,
            code_verifier: "secret-verifier",
        },
        now,
    )
    .await
    .expect("begin");
    let ciphertext: Vec<u8> = sqlx::query_scalar(
        "select verifier_ciphertext from oidc_upstream_pending where tenant_id = 'one'",
    )
    .fetch_one(&pool)
    .await
    .expect("ciphertext");
    assert!(
        !ciphertext
            .windows(b"secret-verifier".len())
            .any(|chunk| chunk == b"secret-verifier")
    );
    assert!(
        two.consume(&state, &interaction, "corporate", now)
            .await
            .expect("other tenant")
            .is_none()
    );
    assert!(
        one.consume(&state, &other_interaction, "corporate", now)
            .await
            .expect("wrong browser")
            .is_none()
    );
    assert!(
        one.consume(&state, &interaction, "other-provider", now)
            .await
            .expect("wrong provider")
            .is_none()
    );
    let consumed = one
        .consume(&state, &interaction, "corporate", now)
        .await
        .expect("consume")
        .expect("present");
    assert_eq!(consumed.code_verifier.as_slice(), b"secret-verifier");
    assert!(
        one.consume(&state, &interaction, "corporate", now)
            .await
            .expect("replay")
            .is_none()
    );
    one.begin(
        &NewOidcPending {
            state_digest: &state,
            interaction_digest: &interaction,
            provider_id: "corporate",
            issuer: "https://login.example",
            client_id: "client",
            token_endpoint: "https://login.example/token",
            jwks_uri: "https://login.example/keys",
            nonce_digest: &nonce,
            code_verifier: "second-verifier",
        },
        now,
    )
    .await
    .expect("begin again");
    assert!(
        one.consume(
            &state,
            &interaction,
            "corporate",
            now + Duration::minutes(6)
        )
        .await
        .expect("expired")
        .is_none()
    );
    pool.close().await;
}
