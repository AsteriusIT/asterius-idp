//! Managed-group invariants requiring PostgreSQL. CI runs these ignored tests.

use std::{borrow::Cow, str::FromStr as _};

use asterius_domain::{DomainError, Group, GroupDirectory, GroupMetadata, TenantId, UserId};
use asterius_store_pg::{MIGRATOR, PgGroups};
use serde_json::json;
use sqlx::{
    PgPool,
    migrate::Migrator,
    postgres::{PgConnectOptions, PgPoolOptions},
};
use time::OffsetDateTime;
use uuid::Uuid;

struct TestDb {
    pool: PgPool,
    schema: String,
    groups: PgGroups,
    tenant: TenantId,
    other: TenantId,
    user: UserId,
    foreign_user: UserId,
}

impl TestDb {
    async fn setup() -> Self {
        let url = std::env::var("DATABASE_URL").expect("ignored groups tests require DATABASE_URL");
        let schema = format!("groups_{}", Uuid::new_v4().simple());
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .unwrap();
        sqlx::query(&format!("create schema {schema}"))
            .execute(&admin)
            .await
            .unwrap();
        admin.close().await;
        let options = PgConnectOptions::from_str(&url)
            .unwrap()
            .options([("search_path", schema.as_str())]);
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .connect_with(options)
            .await
            .unwrap();
        // Seed legacy claims before the new migration, proving the migration
        // itself is additive rather than merely testing post-migration writes.
        let previous = Migrator {
            migrations: Cow::Owned(
                MIGRATOR
                    .iter()
                    .filter(|migration| migration.version < 90)
                    .cloned()
                    .collect(),
            ),
            ..Migrator::DEFAULT
        };
        previous.run(&pool).await.unwrap();
        for tenant in ["demo", "other"] {
            sqlx::query(
                "insert into tenants (tenant_id, issuer, display_name, default_resource)
                values ($1, $2, $1, 'https://api.example/')",
            )
            .bind(tenant)
            .bind(format!("https://id.example/{tenant}"))
            .execute(&pool)
            .await
            .unwrap();
        }
        let user = UserId::generate();
        let foreign_user = UserId::generate();
        for (tenant, id) in [("demo", user), ("other", foreign_user)] {
            sqlx::query("insert into users (tenant_id, user_id, username, claims) values ($1, $2, 'alice', $3)")
                .bind(tenant).bind(id.as_uuid()).bind(legacy_claims()).execute(&pool).await.unwrap();
        }
        MIGRATOR.run(&pool).await.unwrap();
        Self {
            groups: PgGroups::new(pool.clone()),
            pool,
            schema,
            tenant: TenantId::new("demo"),
            other: TenantId::new("other"),
            user,
            foreign_user,
        }
    }

    async fn group(&self, name: &str) -> Group {
        self.groups
            .create(&self.tenant, &metadata(name), now())
            .await
            .unwrap()
    }

    async fn cleanup(self) {
        sqlx::query(&format!("drop schema {} cascade", self.schema))
            .execute(&self.pool)
            .await
            .unwrap();
        self.pool.close().await;
    }
}

fn now() -> OffsetDateTime {
    OffsetDateTime::UNIX_EPOCH
}
fn metadata(name: &str) -> GroupMetadata {
    GroupMetadata::parse(name, "Engineering").unwrap()
}
fn legacy_claims() -> serde_json::Value {
    json!({"groups": {"value": ["Legacy Admins", "legacy", 7, "legacy"], "source": "admin", "verified_at": null}})
}

fn kubernetes_client(tenant: &TenantId) -> asterius_domain::Client {
    use asterius_domain::{
        Capabilities, Client, ClientComplianceProfile, ClientId, ClientRegistration, ClientStatus,
    };
    let registration = ClientRegistration::from_json_with_profile(
        json!({
            "client_name": "Cluster broker", "redirect_uris": ["https://broker.example/callback"],
            "grant_types": ["authorization_code", "refresh_token"], "scope": "openid",
            "jwks_uri": "https://broker.example/jwks", "id_token_signed_response_alg": "ES256",
            "managed_groups_claim": true
        })
        .to_string()
        .as_bytes(),
        Capabilities::default(),
        ClientComplianceProfile::Oidc,
    )
    .unwrap();
    Client {
        tenant: tenant.clone(),
        id: ClientId::new("cluster-a"),
        registration,
        status: ClientStatus::Active,
        created_at: now(),
        updated_at: now(),
    }
}

#[tokio::test]
#[ignore = "slow: requires PostgreSQL"]
async fn kubernetes_profiles_isolate_tenant_groups_and_reject_stale_or_rebound_audiences() {
    use asterius_domain::Capabilities;
    use asterius_domain::kubernetes::KubernetesProfile;
    let db = TestDb::setup().await;
    let selected = db.group("selected").await;
    let hidden = db.group("hidden").await;
    db.groups
        .add_member(&db.tenant, selected.id, db.user, now())
        .await
        .unwrap();
    db.groups
        .add_member(&db.tenant, hidden.id, db.user, now())
        .await
        .unwrap();
    let foreign = db
        .groups
        .create(&db.other, &metadata("foreign"), now())
        .await
        .unwrap();
    let client = kubernetes_client(&db.tenant);
    let clients = asterius_store_pg::PgClientRepository::new(
        db.pool.clone(),
        db.tenant.clone(),
        Capabilities::default(),
    );
    clients.upsert(&client).await.unwrap();
    let invalid = KubernetesProfile::parse("a", "default", vec![foreign.id.as_uuid()], 0).unwrap();
    assert!(matches!(
        db.groups
            .replace_kubernetes_profile(&db.tenant, &client.id, &invalid)
            .await,
        Err(DomainError::Invalid { .. })
    ));
    let profile = KubernetesProfile::parse("a", "default", vec![selected.id.as_uuid()], 0).unwrap();
    let saved = db
        .groups
        .replace_kubernetes_profile(&db.tenant, &client.id, &profile)
        .await
        .unwrap();
    assert_eq!(saved.revision(), 1);
    assert_eq!(
        db.groups
            .released_group_ids(&client, db.user)
            .await
            .unwrap(),
        vec![selected.id.to_string()]
    );
    assert!(
        db.groups
            .kubernetes_profile(&db.other, &client.id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(matches!(
        db.groups
            .replace_kubernetes_profile(&db.tenant, &client.id, &profile)
            .await,
        Err(DomainError::Conflict(_))
    ));
    let rebound = KubernetesProfile::parse("b", "default", vec![], saved.revision()).unwrap();
    assert!(matches!(
        db.groups
            .replace_kubernetes_profile(&db.tenant, &client.id, &rebound)
            .await,
        Err(DomainError::Conflict(_))
    ));
    let clear = KubernetesProfile::parse("a", "default", vec![], saved.revision()).unwrap();
    db.groups
        .replace_kubernetes_profile(&db.tenant, &client.id, &clear)
        .await
        .unwrap();
    assert!(
        db.groups
            .released_group_ids(&client, db.user)
            .await
            .unwrap()
            .is_empty()
    );
    db.cleanup().await;
}

#[tokio::test]
#[ignore = "slow: requires PostgreSQL"]
async fn groups_migration_and_managed_writes_preserve_legacy_claim_authority() {
    let db = TestDb::setup().await;
    assert!(
        db.groups
            .groups_for_user(&db.tenant, db.user, None, 20)
            .await
            .unwrap()
            .is_empty()
    );
    let group = db.group("legacy").await;
    db.groups
        .add_member(&db.tenant, group.id, db.user, now())
        .await
        .unwrap();
    let updated = db
        .groups
        .update(&db.tenant, group.id, 2, &metadata("renamed"), now())
        .await
        .unwrap();
    db.groups
        .delete(&db.tenant, group.id, updated.revision)
        .await
        .unwrap();
    let claims: serde_json::Value =
        sqlx::query_scalar("select claims from users where tenant_id = $1 and user_id = $2")
            .bind(db.tenant.as_str())
            .bind(db.user.as_uuid())
            .fetch_one(&db.pool)
            .await
            .unwrap();
    assert_eq!(claims, legacy_claims());
    MIGRATOR.run(&db.pool).await.unwrap();
    db.cleanup().await;
}

#[tokio::test]
#[ignore = "slow: requires PostgreSQL"]
async fn groups_names_are_unique_per_tenant_and_renames_keep_identity() {
    let db = TestDb::setup().await;
    let group = db.group("engineering").await;
    assert!(matches!(
        db.groups
            .create(&db.tenant, &metadata("engineering"), now())
            .await,
        Err(DomainError::Conflict(_))
    ));
    db.groups
        .create(&db.other, &metadata("engineering"), now())
        .await
        .unwrap();
    let updated = db
        .groups
        .update(
            &db.tenant,
            group.id,
            group.revision,
            &metadata("platform"),
            now(),
        )
        .await
        .unwrap();
    assert_eq!(updated.id, group.id);
    assert_eq!(updated.created_at, group.created_at);
    assert_eq!(updated.metadata.name().as_str(), "platform");
    assert_eq!(updated.revision, 2);
    db.cleanup().await;
}

#[tokio::test]
#[ignore = "slow: requires PostgreSQL"]
async fn groups_reject_cross_tenant_membership_and_hide_other_tenant_objects() {
    let db = TestDb::setup().await;
    let group = db.group("engineering").await;
    assert!(db.groups.get(&db.other, group.id).await.unwrap().is_none());
    assert!(matches!(
        db.groups
            .add_member(&db.tenant, group.id, db.foreign_user, now())
            .await,
        Err(DomainError::Conflict(_))
    ));
    assert!(matches!(
        db.groups
            .add_member(&db.other, group.id, db.foreign_user, now())
            .await,
        Err(DomainError::NotFound)
    ));
    assert!(matches!(
        db.groups
            .update(&db.other, group.id, 1, &metadata("changed"), now())
            .await,
        Err(DomainError::NotFound)
    ));
    assert!(matches!(
        db.groups.delete(&db.other, group.id, 1).await,
        Err(DomainError::NotFound)
    ));
    assert!(
        db.groups
            .members(&db.other, group.id, None, 20)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        db.groups
            .groups_for_user(&db.other, db.user, None, 20)
            .await
            .unwrap()
            .is_empty()
    );
    let direct = sqlx::query("insert into group_memberships (tenant_id, group_id, user_id, created_at) values ($1, $2, $3, $4)")
        .bind(db.other.as_str()).bind(group.id.as_uuid()).bind(db.foreign_user.as_uuid()).bind(now())
        .execute(&db.pool).await.unwrap_err();
    assert!(
        direct
            .as_database_error()
            .unwrap()
            .is_foreign_key_violation()
    );
    assert_eq!(
        db.groups
            .get(&db.tenant, group.id)
            .await
            .unwrap()
            .unwrap()
            .revision,
        1
    );
    db.cleanup().await;
}

#[tokio::test]
#[ignore = "slow: requires PostgreSQL"]
async fn groups_membership_is_idempotent_and_conflicts_with_stale_deletion() {
    let db = TestDb::setup().await;
    let group = db.group("engineering").await;
    let (first, second) = tokio::join!(
        db.groups.add_member(&db.tenant, group.id, db.user, now()),
        db.groups.add_member(&db.tenant, group.id, db.user, now()),
    );
    assert_ne!(first.unwrap(), second.unwrap());
    assert_eq!(
        db.groups
            .members(&db.tenant, group.id, None, 20)
            .await
            .unwrap(),
        vec![db.user]
    );
    assert_eq!(
        db.groups
            .get(&db.tenant, group.id)
            .await
            .unwrap()
            .unwrap()
            .revision,
        2
    );
    assert!(matches!(
        db.groups.delete(&db.tenant, group.id, 1).await,
        Err(DomainError::Conflict(_))
    ));
    assert!(
        db.groups
            .remove_member(&db.tenant, group.id, db.user, now())
            .await
            .unwrap()
    );
    assert!(
        !db.groups
            .remove_member(&db.tenant, group.id, db.user, now())
            .await
            .unwrap()
    );
    assert_eq!(
        db.groups
            .get(&db.tenant, group.id)
            .await
            .unwrap()
            .unwrap()
            .revision,
        3
    );
    db.cleanup().await;
}

#[tokio::test]
#[ignore = "slow: requires PostgreSQL"]
async fn groups_concurrent_metadata_edits_have_one_winner_and_failed_rename_rolls_back() {
    let db = TestDb::setup().await;
    let group = db.group("engineering").await;
    db.group("taken").await;
    assert!(matches!(
        db.groups
            .update(&db.tenant, group.id, 1, &metadata("taken"), now())
            .await,
        Err(DomainError::Conflict(_))
    ));
    assert_eq!(
        db.groups.get(&db.tenant, group.id).await.unwrap().unwrap(),
        group
    );
    let left = metadata("left");
    let right = metadata("right");
    let (first, second) = tokio::join!(
        db.groups.update(&db.tenant, group.id, 1, &left, now()),
        db.groups.update(&db.tenant, group.id, 1, &right, now()),
    );
    assert_ne!(first.is_ok(), second.is_ok());
    let failed = if first.is_err() { first } else { second };
    assert!(matches!(failed, Err(DomainError::Conflict(_))));
    assert_eq!(
        db.groups
            .get(&db.tenant, group.id)
            .await
            .unwrap()
            .unwrap()
            .revision,
        2
    );
    db.cleanup().await;
}

#[tokio::test]
#[ignore = "slow: requires PostgreSQL"]
async fn groups_deletion_cascades_memberships_and_user_deletion_preserves_catalogue() {
    let db = TestDb::setup().await;
    let first = db.group("first").await;
    let second = db.group("second").await;
    for group in [&first, &second] {
        db.groups
            .add_member(&db.tenant, group.id, db.user, now())
            .await
            .unwrap();
    }
    db.groups.delete(&db.tenant, first.id, 2).await.unwrap();
    assert!(
        db.groups
            .members(&db.tenant, first.id, None, 20)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(db.groups.get(&db.tenant, first.id).await.unwrap().is_none());
    sqlx::query("delete from users where tenant_id = $1 and user_id = $2")
        .bind(db.tenant.as_str())
        .bind(db.user.as_uuid())
        .execute(&db.pool)
        .await
        .unwrap();
    assert!(
        db.groups
            .members(&db.tenant, second.id, None, 20)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        db.groups
            .get(&db.tenant, second.id)
            .await
            .unwrap()
            .is_some()
    );
    db.cleanup().await;
}

#[tokio::test]
#[ignore = "slow: requires PostgreSQL"]
async fn groups_concurrent_add_and_delete_never_leave_orphan_memberships() {
    let db = TestDb::setup().await;
    let group = db.group("engineering").await;
    let (added, deleted) = tokio::join!(
        db.groups.add_member(&db.tenant, group.id, db.user, now()),
        db.groups.delete(&db.tenant, group.id, 1),
    );
    match (added, deleted) {
        (Ok(true), Err(DomainError::Conflict(_))) => {
            assert_eq!(
                db.groups
                    .members(&db.tenant, group.id, None, 20)
                    .await
                    .unwrap(),
                vec![db.user]
            );
            db.groups.delete(&db.tenant, group.id, 2).await.unwrap();
        }
        (Err(DomainError::NotFound), Ok(())) => {}
        results => panic!("unexpected concurrent outcomes: {results:?}"),
    }
    assert!(db.groups.get(&db.tenant, group.id).await.unwrap().is_none());
    assert!(
        db.groups
            .members(&db.tenant, group.id, None, 20)
            .await
            .unwrap()
            .is_empty()
    );
    db.cleanup().await;
}

#[tokio::test]
#[ignore = "slow: requires PostgreSQL"]
async fn groups_pages_are_bounded_ordered_and_do_not_repeat_cursor_items() {
    let db = TestDb::setup().await;
    for name in ["first", "second", "third"] {
        let group = db.group(name).await;
        db.groups
            .add_member(&db.tenant, group.id, db.user, now())
            .await
            .unwrap();
    }
    let page = db.groups.list(&db.tenant, None, 2).await.unwrap();
    assert_eq!(page.len(), 2);
    assert!(page[0].id < page[1].id);
    let remaining = db
        .groups
        .list(&db.tenant, Some(page[1].id), 2)
        .await
        .unwrap();
    assert_eq!(remaining.len(), 1);
    assert!(remaining[0].id > page[1].id);
    assert_eq!(
        db.groups
            .groups_for_user(&db.tenant, db.user, Some(page[1].id), 2)
            .await
            .unwrap(),
        remaining
    );
    assert!(
        db.groups
            .members(&db.tenant, page[0].id, Some(db.user), 2)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(matches!(
        db.groups.list(&db.tenant, None, 0).await,
        Err(DomainError::Invalid { .. })
    ));
    assert!(matches!(
        db.groups.members(&db.tenant, page[0].id, None, 201).await,
        Err(DomainError::Invalid { .. })
    ));
    db.cleanup().await;
}

#[tokio::test]
#[ignore = "slow: requires PostgreSQL"]
async fn groups_database_enforces_parser_bounds_for_direct_writers() {
    let db = TestDb::setup().await;
    let group = db.group("engineering").await;
    for bad in [
        "",
        "Uppercase",
        "name with spaces",
        "-start",
        &"a".repeat(65),
    ] {
        let error = sqlx::query(
            "update managed_groups set name = $3 where tenant_id = $1 and group_id = $2",
        )
        .bind(db.tenant.as_str())
        .bind(group.id.as_uuid())
        .bind(bad)
        .execute(&db.pool)
        .await
        .unwrap_err();
        assert_eq!(
            error.as_database_error().unwrap().code().as_deref(),
            Some("23514")
        );
    }
    for bad in [
        "",
        " leading",
        "trailing\u{3000}",
        "\u{00a0}leading",
        "a\u{0085}b",
        "a\u{202e}b",
        "a\u{200f}b",
        &"é".repeat(101),
    ] {
        let error = sqlx::query(
            "update managed_groups set display_name = $3 where tenant_id = $1 and group_id = $2",
        )
        .bind(db.tenant.as_str())
        .bind(group.id.as_uuid())
        .bind(bad)
        .execute(&db.pool)
        .await
        .unwrap_err();
        assert_eq!(
            error.as_database_error().unwrap().code().as_deref(),
            Some("23514"),
            "{bad:?}"
        );
    }
    let display = "é".repeat(100);
    let accepted = GroupMetadata::parse("engineering", &display).unwrap();
    db.groups
        .update(&db.tenant, group.id, 1, &accepted, now())
        .await
        .unwrap();
    db.cleanup().await;
}
