//! Exact-subject broker resolution and explicit account binding.

use asterius_domain::audit::Actor;
use asterius_domain::{TenantId, UserId};
use asterius_store_pg::{MIGRATOR, OidcRefusal, OidcResolution, Store};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use std::str::FromStr as _;
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires DATABASE_URL; CI runs ignored store tests"]
// One isolated schema exercises the full binding lifecycle without shared fixtures.
#[allow(clippy::too_many_lines)]
async fn bindings_are_exact_and_registration_never_takes_over_email() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL for ignored store test");
    let schema = format!("oidc_bindings_{}", Uuid::new_v4().simple());
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
        .expect("schema pool");
    MIGRATOR.run(&pool).await.expect("migrations");
    for tenant in ["one", "two"] {
        sqlx::query("insert into tenants (tenant_id, issuer, display_name, default_resource) values ($1,$2,$1,'https://api.example/')")
            .bind(tenant).bind(format!("https://id.example/{tenant}"))
            .execute(&pool).await.expect("tenant");
        sqlx::query("insert into oidc_identity_providers (tenant_id,provider_id,display_name,issuer,authorization_endpoint,token_endpoint,jwks_uri,client_id,client_secret_ciphertext,client_secret_nonce,kek_id,enabled,allow_registration) values ($1,'corp','Corp','https://login.example','https://login.example/auth','https://login.example/token','https://login.example/keys','client',$2,$3,'kek',true,false)")
            .bind(tenant).bind(vec![0_u8; 17]).bind(vec![if tenant == "one" { 1_u8 } else { 2_u8 }; 12])
            .execute(&pool).await.expect("provider");
    }
    let store = Store::from_pool(pool.clone());
    let one = store.scope(TenantId::new("one")).oidc_bindings();
    let two = store.scope(TenantId::new("two")).oidc_bindings();
    let victim = Uuid::new_v4();
    sqlx::query("insert into users (tenant_id,user_id,username,email) values ('one',$1,'existing','person@example.test')")
        .bind(victim).execute(&pool).await.expect("existing user");
    assert_eq!(
        one.resolve_or_create("corp", "https://login.example", "subject", None, None)
            .await
            .expect("resolve"),
        OidcResolution::Refused(OidcRefusal::Unlinked)
    );
    assert_eq!(
        one.resolve_or_create("corp", "https://login.example/", "subject", None, None)
            .await
            .expect("exact issuer"),
        OidcResolution::Refused(OidcRefusal::ProviderUnavailable)
    );
    one.link(
        "corp",
        "https://login.example",
        "subject",
        UserId::new(victim),
        Actor::Admin("operator".into()),
    )
    .await
    .expect("explicit link");
    let page_ids = [UserId::new(victim), UserId::generate()];
    assert_eq!(
        one.provider_names_for_users(&page_ids).await.expect("provider names"),
        vec![(UserId::new(victim), "Corp".to_owned())]
    );
    assert!(two.provider_names_for_users(&page_ids).await.expect("tenant fence").is_empty());
    assert!(one.provider_names_for_users(&[]).await.expect("empty page").is_empty());
    assert!(one.provider_names_for_users(&[page_ids[1]]).await.expect("unlinked page").is_empty());
    assert!(
        one.link(
            "corp",
            "https://login.example",
            "subject",
            UserId::new(victim),
            Actor::Admin("operator".into())
        )
        .await
        .is_err(),
        "subject cannot be linked twice"
    );
    assert!(
        one.link(
            "corp",
            "https://login.example",
            "second-subject",
            UserId::new(victim),
            Actor::Admin("operator".into())
        )
        .await
        .is_err(),
        "one provider cannot assign two subjects to one user"
    );
    assert_eq!(
        one.resolve_or_create("corp", "https://login.example", "subject", None, None)
            .await
            .expect("linked"),
        OidcResolution::User(UserId::new(victim))
    );
    assert_eq!(
        two.resolve_or_create("corp", "https://login.example", "subject", None, None)
            .await
            .expect("tenant fence"),
        OidcResolution::Refused(OidcRefusal::Unlinked)
    );
    sqlx::query("update users set status = 'disabled' where tenant_id = 'one' and user_id = $1")
        .bind(victim)
        .execute(&pool)
        .await
        .expect("disable user");
    assert_eq!(
        one.resolve_or_create("corp", "https://login.example", "subject", None, None)
            .await
            .expect("disabled"),
        OidcResolution::Refused(OidcRefusal::DisabledUser)
    );
    sqlx::query("update oidc_identity_providers set enabled = false where tenant_id = 'one'")
        .execute(&pool)
        .await
        .expect("disable provider");
    assert_eq!(
        one.resolve_or_create("corp", "https://login.example", "subject", None, None)
            .await
            .expect("provider disabled"),
        OidcResolution::Refused(OidcRefusal::ProviderUnavailable)
    );
    assert!(
        sqlx::query("delete from oidc_identity_providers where tenant_id = 'one'")
            .execute(&pool)
            .await
            .is_err(),
        "linked provider cannot be removed silently"
    );
    assert!(sqlx::query("update oidc_identity_providers set issuer = 'https://other.example' where tenant_id = 'one'")
        .execute(&pool).await.is_err(), "issuer replacement cannot strand a binding");
    assert!(
        one.unlink(
            "corp",
            "https://login.example",
            "subject",
            UserId::new(victim),
            Actor::Admin("operator".into())
        )
        .await
        .expect("unlink disabled binding")
    );
    sqlx::query("update oidc_identity_providers set enabled = true, allow_registration = true where tenant_id = 'one'")
        .execute(&pool).await.expect("enable registration");
    let result = one
        .resolve_or_create("corp", "https://login.example", "new-subject", None, None)
        .await
        .expect("create");
    let OidcResolution::User(created) = result else {
        panic!("expected user")
    };
    assert_ne!(created, UserId::new(victim));
    let email: Option<String> =
        sqlx::query_scalar("select email from users where tenant_id = 'one' and user_id = $1")
            .bind(created.as_uuid())
            .fetch_one(&pool)
            .await
            .expect("new account");
    assert_eq!(email, None);
    sqlx::query("update oidc_identity_providers set username_claim = 'preferred_username' where tenant_id = 'one'")
        .execute(&pool).await.expect("configure claim");
    assert_eq!(
        one.resolve_or_create("corp", "https://login.example", "new-subject", Some("preferred_username"), None)
            .await.expect("existing binding without username"),
        OidcResolution::Refused(OidcRefusal::UsernameUnavailable)
    );
    for name in [Some(""), Some(" hidden"), Some("existing")] {
        assert_eq!(
            one.resolve_or_create("corp", "https://login.example", "new-subject", Some("preferred_username"), name)
                .await.expect("refuse unsafe rename"),
            OidcResolution::Refused(OidcRefusal::UsernameUnavailable)
        );
    }
    let unchanged: String = sqlx::query_scalar(
        "select username from users where tenant_id = 'one' and user_id = $1"
    ).bind(created.as_uuid()).fetch_one(&pool).await.expect("unchanged username");
    assert!(unchanged.starts_with("oidc-"));
    assert_eq!(
        one.resolve_or_create("corp", "https://login.example", "new-subject", Some("preferred_username"), Some("mapped-name"))
            .await.expect("rename bound account"),
        OidcResolution::User(created)
    );
    let renamed: String = sqlx::query_scalar(
        "select username from users where tenant_id = 'one' and user_id = $1"
    ).bind(created.as_uuid()).fetch_one(&pool).await.expect("renamed username");
    assert_eq!(renamed, "mapped-name");
    sqlx::query("update oidc_identity_providers set username_claim = 'alternate_name' where tenant_id = 'one'")
        .execute(&pool).await.expect("change claim mapping");
    assert_eq!(
        one.resolve_or_create(
            "corp", "https://login.example", "new-subject",
            Some("preferred_username"), Some("stale-value")
        ).await.expect("stale mapping refused"),
        OidcResolution::Refused(OidcRefusal::ProviderUnavailable)
    );
    let still_renamed: String = sqlx::query_scalar(
        "select username from users where tenant_id = 'one' and user_id = $1"
    ).bind(created.as_uuid()).fetch_one(&pool).await.expect("unchanged after stale mapping");
    assert_eq!(still_renamed, "mapped-name");
    sqlx::query("update oidc_identity_providers set username_claim = 'preferred_username' where tenant_id = 'one'")
        .execute(&pool).await.expect("restore claim mapping");
    let victim_name: String = sqlx::query_scalar(
        "select username from users where tenant_id = 'one' and user_id = $1"
    ).bind(victim).fetch_one(&pool).await.expect("victim username");
    assert_eq!(victim_name, "existing");
    for name in [None, Some(""), Some(" hidden"), Some("existing")] {
        assert_eq!(
            one.resolve_or_create("corp", "https://login.example", "another-subject", Some("preferred_username"), name)
                .await.expect("refuse unavailable username"),
            OidcResolution::Refused(OidcRefusal::UsernameUnavailable)
        );
    }
    let named = one.resolve_or_create(
        "corp", "https://login.example", "another-subject", Some("preferred_username"), Some("upstream-alice")
    ).await.expect("create with verified username");
    let OidcResolution::User(named_id) = named else { panic!("expected named user") };
    let username: String = sqlx::query_scalar(
        "select username from users where tenant_id = 'one' and user_id = $1"
    ).bind(named_id.as_uuid()).fetch_one(&pool).await.expect("named account");
    assert_eq!(username, "upstream-alice");
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
