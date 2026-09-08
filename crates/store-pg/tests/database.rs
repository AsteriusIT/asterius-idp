//! Database-backed tests: schema invariants and tenant isolation.
//!
//! These run only when `DATABASE_URL` is set, so the default `cargo test`
//! stays sub-second and a contributor without Docker is not blocked:
//!
//! ```sh
//! docker compose up -d db
//! DATABASE_URL=postgres://asterius:asterius@127.0.0.1:5433/asterius cargo test
//! ```
//!
//! Each test gets its own PostgreSQL schema, migrated from scratch. That costs
//! roughly 40 ms per test and buys full parallelism with no shared fixtures —
//! which matters here more than usual, since half of what these tests check is
//! that data does not leak between scopes.

use asterius_domain::ports::{TenantRepository, TenantScoped};
use asterius_domain::{Issuer, Tenant, TenantId, TenantStatus};
use asterius_store_pg::{MIGRATOR, PgTenantRepository, Store};
use sqlx::Row;
use sqlx::postgres::{PgConnectOptions, PgPool, PgPoolOptions};
use std::str::FromStr;
use std::sync::atomic::{AtomicU32, Ordering};
use time::OffsetDateTime;

static COUNTER: AtomicU32 = AtomicU32::new(0);

struct TestDb {
    pool: PgPool,
    schema: String,
}

/// Sets up an isolated, migrated schema, or returns `None` without a database.
async fn setup() -> Option<TestDb> {
    let url = std::env::var("DATABASE_URL").ok()?;
    let schema = format!(
        "test_{}_{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    );

    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .expect("DATABASE_URL is set but unreachable; is `docker compose up -d db` running?");
    sqlx::query(&format!("create schema \"{schema}\""))
        .execute(&admin)
        .await
        .expect("create schema");
    admin.close().await;

    // Pinning `search_path` on the connection is what makes the isolation
    // real: the migrations use unqualified names, so they build the whole
    // schema inside this test's namespace without knowing about it.
    let options = PgConnectOptions::from_str(&url)
        .expect("DATABASE_URL is not a valid PostgreSQL URL")
        .options([("search_path", schema.as_str())]);
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect_with(options)
        .await
        .expect("connect");

    MIGRATOR.run(&pool).await.expect("run migrations");
    Some(TestDb { pool, schema })
}

macro_rules! db_test {
    ($(#[$meta:meta])* async fn $name:ident($db:ident) $body:block) => {
        $(#[$meta])*
        #[tokio::test]
        async fn $name() {
            let Some($db) = setup().await else {
                eprintln!("skipping {}: DATABASE_URL is not set", stringify!($name));
                return;
            };
            $body
        }
    };
}

fn tenant(id: &str, issuer: &str) -> Tenant {
    Tenant {
        id: TenantId::new(id),
        issuer: Issuer::parse(issuer).expect("test issuer"),
        custom_host: None,
        display_name: format!("Tenant {id}"),
        status: TenantStatus::Active,
        created_at: OffsetDateTime::UNIX_EPOCH,
        updated_at: OffsetDateTime::UNIX_EPOCH,
    }
}

// ---------------------------------------------------------------------------
// Migrations
// ---------------------------------------------------------------------------

db_test! {
    /// Running the migrator twice must be a no-op, because that is what every
    /// rolling deployment does.
    async fn migrations_are_idempotent(db) {
        MIGRATOR.run(&db.pool).await.expect("second run should be a no-op");
        let applied: i64 = sqlx::query_scalar("select count(*) from _sqlx_migrations")
            .fetch_one(&db.pool)
            .await
            .expect("count migrations");
        assert_eq!(applied, i64::try_from(MIGRATOR.iter().count()).expect("migration count"));
    }
}

// ---------------------------------------------------------------------------
// Schema invariants
// ---------------------------------------------------------------------------

/// Column names that look like they hold a credential but do not.
///
/// Every entry is an assertion a reviewer has to agree with, which is the
/// point: adding one is a deliberate act, and adding a genuine plaintext
/// credential means writing a lie here first.
const NOT_A_STORED_SECRET: &[(&str, &str, &str)] = &[
    (
        "clients",
        "token_endpoint_auth_method",
        "client metadata name, e.g. private_key_jwt",
    ),
    (
        "clients",
        "id_token_signed_response_alg",
        "an algorithm name from ADR-0003's allow-list, not a token",
    ),
    (
        "credentials",
        "credential_id",
        "a row identifier, not the credential",
    ),
    (
        "credentials",
        "passkey_credential_id",
        "the WebAuthn credential id is handed to the browser on every authentication",
    ),
    (
        "authorization_codes",
        "code_challenge",
        "PKCE challenge is public by design (RFC 7636 §4.2); the verifier never reaches storage",
    ),
    (
        "authorization_codes",
        "code_challenge_method",
        "the literal S256",
    ),
    (
        "signing_keys",
        "private_key_nonce",
        "the AEAD nonce for private_key_ciphertext; public by construction",
    ),
];

/// Substrings that mark a column as credential-bearing.
const SECRET_MARKERS: &[&str] = &[
    "secret",
    "password",
    "passwd",
    "token",
    "credential",
    "private_key",
    "verifier",
    "assertion",
];

db_test! {
    /// FAPI 2.0 SP §5.4.1 and RFC 6749 §10.3: opaque credentials are stored
    /// hashed. The convention is mechanical — `*_hash` for a digest,
    /// `*_ciphertext` for encrypted material — so that this test can enforce
    /// it, and so a future migration cannot add a plaintext token column
    /// without tripping over it.
    async fn no_column_stores_a_credential_in_plain_text(db) {
        let rows = sqlx::query(
            "select table_name, column_name
             from information_schema.columns
             where table_schema = $1 and table_name <> '_sqlx_migrations'
             order by table_name, column_name",
        )
        .bind(db.schema())
        .fetch_all(&db.pool)
        .await
        .expect("read information_schema");
        assert!(!rows.is_empty(), "the schema should not be empty");

        let mut offenders = Vec::new();
        for row in &rows {
            let table: String = row.get("table_name");
            let column: String = row.get("column_name");
            let looks_secret = SECRET_MARKERS.iter().any(|m| column.contains(m));
            let is_protected = column.ends_with("_hash") || column.ends_with("_ciphertext");
            let is_excused = NOT_A_STORED_SECRET
                .iter()
                .any(|(t, c, _)| *t == table && *c == column);
            if looks_secret && !is_protected && !is_excused {
                offenders.push(format!("{table}.{column}"));
            }
        }
        assert!(
            offenders.is_empty(),
            "these columns look like credentials but are neither hashed, encrypted, nor \
             justified in NOT_A_STORED_SECRET: {offenders:?}"
        );
    }
}

db_test! {
    /// The exemption list must not outlive the columns it excuses, or it turns
    /// into a place where a real plaintext column can hide behind a stale name.
    async fn every_exemption_still_names_a_real_column(db) {
        for (table, column, reason) in NOT_A_STORED_SECRET {
            let exists: bool = sqlx::query_scalar(
                "select exists (select 1 from information_schema.columns
                 where table_schema = $1 and table_name = $2 and column_name = $3)",
            )
            .bind(db.schema())
            .bind(table)
            .bind(column)
            .fetch_one(&db.pool)
            .await
            .expect("query information_schema");
            assert!(exists, "stale exemption {table}.{column} ({reason})");
        }
    }
}

db_test! {
    /// Every tenant-scoped table leads its primary key with `tenant_id`. This
    /// is both the isolation story and the index story: the tenant predicate is
    /// the cheapest thing any query can do, so there is no performance excuse
    /// for leaving it out.
    async fn every_table_leads_its_primary_key_with_tenant_id(db) {
        let rows = sqlx::query(
            "select c.table_name,
                    bool_or(col.column_name = 'tenant_id') as has_tenant_id,
                    min(case when k.ordinal_position = 1 then k.column_name end) as first_pk_column
             from information_schema.tables c
             join information_schema.columns col
               on col.table_schema = c.table_schema and col.table_name = c.table_name
             left join information_schema.table_constraints tc
               on tc.table_schema = c.table_schema and tc.table_name = c.table_name
              and tc.constraint_type = 'PRIMARY KEY'
             left join information_schema.key_column_usage k
               on k.constraint_name = tc.constraint_name and k.table_schema = tc.table_schema
             where c.table_schema = $1 and c.table_name <> '_sqlx_migrations'
             group by c.table_name
             order by c.table_name",
        )
        .bind(db.schema())
        .fetch_all(&db.pool)
        .await
        .expect("read information_schema");

        assert!(rows.len() >= 15, "expected the full baseline schema, found {} tables", rows.len());

        for row in &rows {
            let table: String = row.get("table_name");
            let has_tenant_id: bool = row.get("has_tenant_id");
            let first_pk: Option<String> = row.get("first_pk_column");
            assert!(has_tenant_id, "{table} has no tenant_id column");
            assert_eq!(
                first_pk.as_deref(),
                Some("tenant_id"),
                "{table} does not lead its primary key with tenant_id"
            );
        }
    }
}

db_test! {
    /// An audit trail the application can rewrite is not evidence, so the
    /// prohibition lives in the database rather than in a code review habit.
    async fn audit_events_reject_update_and_delete(db) {
        sqlx::query(
            "insert into tenants (tenant_id, issuer, display_name) values ('a', 'https://a.example', 'A')",
        )
        .execute(&db.pool)
        .await
        .expect("seed tenant");
        sqlx::query(
            "insert into audit_events (tenant_id, event_type, outcome, actor)
             values ('a', 'test', 'success', '{\"type\":\"system\"}'::jsonb)",
        )
        .execute(&db.pool)
        .await
        .expect("append an event");

        let update = sqlx::query("update audit_events set outcome = 'failure'")
            .execute(&db.pool)
            .await;
        assert!(update.is_err(), "audit_events accepted an UPDATE");

        let delete = sqlx::query("delete from audit_events").execute(&db.pool).await;
        assert!(delete.is_err(), "audit_events accepted a DELETE");
    }
}

db_test! {
    /// FAPI 2.0 SP §5.4.1 caps authorization codes at 60 seconds. Code enforces
    /// it; the schema refuses to hold a row that breaks it, so a bug in the
    /// issuing path cannot quietly persist a long-lived code.
    async fn the_schema_refuses_an_authorization_code_that_outlives_sixty_seconds(db) {
        sqlx::query(
            "insert into tenants (tenant_id, issuer, display_name) values ('a', 'https://a.example', 'A')",
        )
        .execute(&db.pool)
        .await
        .expect("seed tenant");
        sqlx::query(
            "insert into clients (tenant_id, client_id, client_name, token_endpoint_auth_method, jwks)
             values ('a', 'c', 'C', 'private_key_jwt', '{}'::jsonb)",
        )
        .execute(&db.pool)
        .await
        .expect("seed client");
        sqlx::query(
            "insert into grants (tenant_id, grant_id, client_id)
             values ('a', '00000000-0000-0000-0000-000000000001', 'c')",
        )
        .execute(&db.pool)
        .await
        .expect("seed grant");

        let too_long = sqlx::query(
            "insert into authorization_codes
                 (tenant_id, code_hash, client_id, grant_id, code_challenge, redirect_uri,
                  issued_at, expires_at)
             values ('a', '\\x00', 'c', '00000000-0000-0000-0000-000000000001', 'ch',
                     'https://rp.example/cb', now(), now() + interval '61 seconds')",
        )
        .execute(&db.pool)
        .await;
        assert!(too_long.is_err(), "the schema accepted a 61-second authorization code");

        sqlx::query(
            "insert into authorization_codes
                 (tenant_id, code_hash, client_id, grant_id, code_challenge, redirect_uri,
                  issued_at, expires_at)
             values ('a', '\\x01', 'c', '00000000-0000-0000-0000-000000000001', 'ch',
                     'https://rp.example/cb', now(), now() + interval '60 seconds')",
        )
        .execute(&db.pool)
        .await
        .expect("60 seconds is allowed");
    }
}

// ---------------------------------------------------------------------------
// Tenant isolation
// ---------------------------------------------------------------------------

db_test! {
    async fn the_tenant_repository_round_trips(db) {
        let repo = PgTenantRepository::new(db.pool.clone());
        let demo = tenant("demo", "https://as.example/t/demo");
        repo.upsert(&demo).await.expect("insert");

        let found = repo.find_by_id(&demo.id).await.expect("find").expect("present");
        assert_eq!(found.issuer, demo.issuer);
        assert_eq!(found.display_name, demo.display_name);
        assert!(found.is_active());
        // Timestamps come from the database, not from the entity we passed in.
        assert!(found.created_at > OffsetDateTime::UNIX_EPOCH);

        let by_issuer = repo.find_by_issuer(&demo.issuer).await.expect("find").expect("present");
        assert_eq!(by_issuer.id, demo.id);

        assert!(repo.find_by_id(&TenantId::new("absent")).await.expect("find").is_none());
        repo.delete(&demo.id).await.expect("delete");
        assert!(repo.find_by_id(&demo.id).await.expect("find").is_none());
    }
}

db_test! {
    /// Two tenants, two issuers, no crossing over. The lookups a request goes
    /// through — by id and by issuer — must each land on exactly one tenant.
    async fn a_tenant_lookup_never_returns_another_tenants_row(db) {
        let repo = PgTenantRepository::new(db.pool.clone());
        let a = tenant("alpha", "https://as.example/t/alpha");
        let b = tenant("beta", "https://as.example/t/beta");
        repo.upsert(&a).await.expect("insert alpha");
        repo.upsert(&b).await.expect("insert beta");

        assert_eq!(repo.find_by_id(&a.id).await.expect("find").expect("present").issuer, a.issuer);
        assert_eq!(repo.find_by_id(&b.id).await.expect("find").expect("present").issuer, b.issuer);
        assert_eq!(
            repo.find_by_issuer(&a.issuer).await.expect("find").expect("present").id,
            a.id
        );
        assert_eq!(repo.list().await.expect("list").len(), 2);
    }
}

db_test! {
    /// The issuer is unique across the deployment, so a second tenant cannot
    /// claim it — an ambiguous `iss` would break every client's audience check.
    async fn two_tenants_cannot_share_an_issuer(db) {
        let repo = PgTenantRepository::new(db.pool.clone());
        repo.upsert(&tenant("alpha", "https://as.example")).await.expect("insert alpha");
        let clash = repo.upsert(&tenant("beta", "https://as.example")).await;
        assert!(
            matches!(clash, Err(asterius_domain::DomainError::Conflict(_))),
            "expected a conflict, got {clash:?}"
        );
    }
}

db_test! {
    /// Deleting a tenant takes its data with it, and leaves every other
    /// tenant's data alone. Rows that survive a tenant are rows nobody owns.
    async fn deleting_a_tenant_cascades_only_over_its_own_data(db) {
        let repo = PgTenantRepository::new(db.pool.clone());
        repo.upsert(&tenant("alpha", "https://as.example/t/alpha")).await.expect("alpha");
        repo.upsert(&tenant("beta", "https://as.example/t/beta")).await.expect("beta");
        for id in ["alpha", "beta"] {
            sqlx::query(
                "insert into clients (tenant_id, client_id, client_name,
                                      token_endpoint_auth_method, jwks)
                 values ($1, 'shared-client-id', 'C', 'private_key_jwt', '{}'::jsonb)",
            )
            .bind(id)
            .execute(&db.pool)
            .await
            .expect("seed client");
        }

        repo.delete(&TenantId::new("alpha")).await.expect("delete alpha");

        let remaining: Vec<String> = sqlx::query_scalar("select tenant_id from clients")
            .fetch_all(&db.pool)
            .await
            .expect("read clients");
        assert_eq!(remaining, ["beta"], "the cascade crossed a tenant boundary");
    }
}

db_test! {
    /// Two tenants may reuse a `client_id`; the primary key is the pair. This
    /// is what stops one tenant's registration from constraining another's.
    async fn a_client_id_is_only_unique_within_its_tenant(db) {
        let repo = PgTenantRepository::new(db.pool.clone());
        repo.upsert(&tenant("alpha", "https://as.example/t/alpha")).await.expect("alpha");
        repo.upsert(&tenant("beta", "https://as.example/t/beta")).await.expect("beta");
        let store = Store::from_pool(db.pool.clone());

        for id in ["alpha", "beta"] {
            let scope = store.scope(TenantId::new(id));
            assert_eq!(scope.tenant().as_str(), id);
            sqlx::query(
                "insert into clients (tenant_id, client_id, client_name,
                                      token_endpoint_auth_method, jwks)
                 values ($1, 'billing', 'Billing', 'private_key_jwt', '{}'::jsonb)",
            )
            .bind(scope.tenant().as_str())
            .execute(&db.pool)
            .await
            .expect("both tenants may register the same client_id");
        }

        let count: i64 = sqlx::query_scalar("select count(*) from clients where client_id = 'billing'")
            .fetch_one(&db.pool)
            .await
            .expect("count");
        assert_eq!(count, 2);
    }
}

impl TestDb {
    fn schema(&self) -> &str {
        &self.schema
    }
}
