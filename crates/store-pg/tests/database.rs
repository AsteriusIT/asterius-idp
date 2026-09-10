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
use asterius_domain::rate_limit::RateLimitStore as _;
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
        default_resource: "https://api.example/".to_owned(),
        custom_host: None,
        display_name: format!("Tenant {id}"),
        status: TenantStatus::Active,
        refresh: asterius_domain::RefreshPolicy::default(),
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
        "clients",
        "dpop_bound_access_tokens",
        "a boolean saying whether tokens are DPoP-bound (RFC 9449 §5.2), not a token",
    ),
    (
        "clients",
        "tls_client_certificate_bound_access_tokens",
        "a boolean saying whether tokens are certificate-bound (RFC 8705 §3.4), not a token",
    ),
    (
        "clients",
        "previous_registration_access_token_expires_at",
        "when the outgoing registration access token stops being accepted — a deadline beside \
         the digest in previous_registration_access_token_hash, not a token",
    ),
    (
        "credentials",
        "credential_id",
        "a row identifier, not the credential",
    ),
    (
        "resource_servers",
        "token_lifetime_seconds",
        "how long a token for this resource server lives, in seconds — a number an \
         operator configures, not a token",
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
    (
        "tenant_pairwise_salts",
        "salt_nonce",
        "the AEAD nonce for salt_ciphertext; public by construction",
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
    // A pairwise salt is the only thing making a `sub` irreversible (OIDC Core
    // §8.1), so a plaintext column holding one is exactly as bad as a plaintext
    // private key.
    "salt",
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
            "insert into tenants (tenant_id, issuer, display_name, default_resource)
             values ('a', 'https://a.example', 'A', 'https://api.example/')",
        )
        .execute(&db.pool)
        .await
        .expect("seed tenant");
        sqlx::query(
            "insert into audit_events
                 (tenant_id, event_type, outcome, actor, previous_hash, event_hash)
             values ('a', 'auth.login', 'success', '{\"type\":\"system\"}'::jsonb,
                     repeat('\\000', 32)::bytea, repeat('\\001', 32)::bytea)",
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
    /// FAPI 2.0 SP §5.3.2.1 item 11 caps authorization codes at 60 seconds. Code
    /// enforces
    /// it; the schema refuses to hold a row that breaks it, so a bug in the
    /// issuing path cannot quietly persist a long-lived code.
    async fn the_schema_refuses_an_authorization_code_that_outlives_sixty_seconds(db) {
        sqlx::query(
            "insert into tenants (tenant_id, issuer, display_name, default_resource)
             values ('a', 'https://a.example', 'A', 'https://api.example/')",
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
        let repo = PgTenantRepository::new(db.pool.clone(), kek());
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
        let repo = PgTenantRepository::new(db.pool.clone(), kek());
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
        let repo = PgTenantRepository::new(db.pool.clone(), kek());
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
        let repo = PgTenantRepository::new(db.pool.clone(), kek());
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
        let repo = PgTenantRepository::new(db.pool.clone(), kek());
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

// ---------------------------------------------------------------------------
// Audit trail
// ---------------------------------------------------------------------------

use asterius_domain::audit::chain::EventHash;
use asterius_domain::audit::{
    Actor, AuditEvent, AuditRecord, AuditSink, Detail, EventType, Outcome,
};
use asterius_store_pg::PgAuditSink;

/// The credential shapes an audit write is most likely to be handed by mistake.
const A_CODE: &str = "Zx9Kq2mNpR7vT4wY1bC8dF3gH6jL0aS5uV-eW_iO2nQ";
const A_JWT: &str = "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCJ9.eyJzdWIiOiJhbGljZSJ9.c2ln";

async fn seed_tenant(pool: &PgPool, id: &str) {
    sqlx::query(
        "insert into tenants (tenant_id, issuer, display_name, default_resource)
         values ($1, $2, $1, $3) on conflict do nothing",
    )
    .bind(id)
    .bind(format!("https://as.example/t/{id}"))
    .bind("https://api.example/")
    .execute(pool)
    .await
    .expect("seed tenant");
}

fn audit_event(tenant: &str, event_type: EventType) -> AuditEvent {
    AuditEvent::new(
        TenantId::new(tenant),
        event_type,
        Outcome::Success,
        Actor::Client(asterius_domain::ClientId::new("billing")),
        OffsetDateTime::now_utc(),
    )
    .subject("alice")
    .request_id("req-1")
}

db_test! {
    /// The sequence one authorization code flow should leave behind. The flows
    /// themselves land with their own stories (`ast-gxh.*`, `ast-a05.*`); what
    /// is asserted here is that the trail records them in order, under one
    /// request id, with a chain that verifies.
    async fn a_code_flow_leaves_an_ordered_verifiable_trail(db) {
        seed_tenant(&db.pool, "demo").await;
        let sink = PgAuditSink::new(db.pool.clone());

        let flow = [
            EventType::PAR_ACCEPTED,
            EventType::AUTH_LOGIN,
            EventType::CONSENT_GRANTED,
            EventType::CODE_ISSUED,
            EventType::TOKEN_ISSUED,
        ];
        for event_type in flow {
            sink.record(audit_event("demo", event_type).detail(Detail::new().credential("code", A_CODE)))
                .await
                .expect("record");
        }

        let recorded: Vec<String> = sqlx::query_scalar(
            "select event_type from audit_events where tenant_id = 'demo' order by event_id",
        )
        .fetch_all(&db.pool)
        .await
        .expect("read the trail");
        assert_eq!(
            recorded,
            flow.iter().map(|e| e.as_str().to_owned()).collect::<Vec<_>>()
        );

        let request_ids: Vec<Option<String>> = sqlx::query_scalar(
            "select request_id from audit_events where tenant_id = 'demo'",
        )
        .fetch_all(&db.pool)
        .await
        .expect("read request ids");
        assert!(request_ids.iter().all(|id| id.as_deref() == Some("req-1")));

        let verified = sink.verify_chain(&TenantId::new("demo")).await.expect("verify");
        assert_eq!(verified.records, 5);
        assert_eq!(verified.start, EventHash::GENESIS);
    }
}

db_test! {
    /// The trail is kept for a long time and read during incidents, so a live
    /// credential in it is worse than in a log. Nothing recorded here may
    /// contain one — including the value passed as ordinary text, which is how
    /// it would happen in practice.
    async fn no_credential_reaches_the_stored_payload(db) {
        seed_tenant(&db.pool, "demo").await;
        let sink = PgAuditSink::new(db.pool.clone());

        sink.record(
            audit_event("demo", EventType::TOKEN_ISSUED).detail(
                Detail::new()
                    .credential("code", A_CODE)
                    .text("pasted_by_mistake", A_JWT)
                    .text("authorization", format!("Bearer {A_JWT}"))
                    .text("scope", "openid profile")
                    .number("expires_in", 300),
            ),
        )
        .await
        .expect("record");

        // Read the whole row as text: no column may contain either credential.
        let dumped: String = sqlx::query_scalar(
            "select coalesce(string_agg(t::text, ' '), '') from audit_events t
             where tenant_id = 'demo'",
        )
        .fetch_one(&db.pool)
        .await
        .expect("dump the row");

        assert!(!dumped.contains(A_CODE), "an authorization code reached storage");
        assert!(!dumped.contains(A_JWT), "a JWT reached storage");
        assert!(dumped.contains("redacted:"), "redaction left no marker: {dumped}");
        assert!(dumped.contains("sha256:"), "the correlatable digest was lost");
        assert!(dumped.contains("openid profile"), "an ordinary field was over-redacted");
    }
}

db_test! {
    /// A trail the application can rewrite is not evidence.
    async fn the_trail_refuses_update_and_delete(db) {
        seed_tenant(&db.pool, "demo").await;
        let sink = PgAuditSink::new(db.pool.clone());
        sink.record(audit_event("demo", EventType::AUTH_LOGIN)).await.expect("record");

        assert!(
            sqlx::query("update audit_events set subject = 'mallory'")
                .execute(&db.pool)
                .await
                .is_err(),
            "an UPDATE was accepted"
        );
        assert!(
            sqlx::query("delete from audit_events").execute(&db.pool).await.is_err(),
            "a DELETE was accepted outside the retention job"
        );
    }
}

db_test! {
    /// The property the hash chain exists for: a row edited directly in the
    /// database — around the trigger, as someone with SQL access would — is
    /// detected.
    async fn a_row_mutated_in_the_database_fails_verification(db) {
        seed_tenant(&db.pool, "demo").await;
        let sink = PgAuditSink::new(db.pool.clone());
        for event_type in [EventType::CODE_ISSUED, EventType::TOKEN_ISSUED, EventType::GRANT_REVOKED] {
            sink.record(audit_event("demo", event_type)).await.expect("record");
        }
        sink.verify_chain(&TenantId::new("demo")).await.expect("clean chain verifies");

        // Disable the guard the way an attacker with database access would,
        // and quietly change who a token was issued to.
        sqlx::query("alter table audit_events disable trigger audit_events_no_update")
            .execute(&db.pool)
            .await
            .expect("disable the trigger");
        sqlx::query(
            "update audit_events set subject = 'mallory'
             where tenant_id = 'demo' and event_type = 'token.issued'",
        )
        .execute(&db.pool)
        .await
        .expect("tamper");
        sqlx::query("alter table audit_events enable trigger audit_events_no_update")
            .execute(&db.pool)
            .await
            .expect("re-enable the trigger");

        let error = sink
            .verify_chain(&TenantId::new("demo"))
            .await
            .expect_err("a mutated row must not verify");
        let message = error.to_string();
        assert!(message.contains("was altered"), "{message}");
        assert!(message.contains("record 1"), "the wrong record was blamed: {message}");
    }
}

db_test! {
    /// Retention is the one path allowed to delete, it removes only what the
    /// cutoff covers, and running it again removes nothing.
    async fn retention_deletes_only_old_records_and_is_idempotent(db) {
        seed_tenant(&db.pool, "demo").await;
        let sink = PgAuditSink::new(db.pool.clone());

        let old = OffsetDateTime::now_utc() - time::Duration::days(400);
        let recent = OffsetDateTime::now_utc() - time::Duration::days(2);
        for (when, event_type) in [
            (old, EventType::AUTH_LOGIN),
            (old, EventType::CODE_ISSUED),
            (recent, EventType::TOKEN_ISSUED),
        ] {
            let mut event = audit_event("demo", event_type);
            event.occurred_at = when;
            sink.record(event).await.expect("record");
        }

        let cutoff = OffsetDateTime::now_utc() - time::Duration::days(365);
        let tenant = TenantId::new("demo");

        assert_eq!(sink.purge_older_than(&tenant, cutoff).await.expect("purge"), 2);
        assert_eq!(
            sink.purge_older_than(&tenant, cutoff).await.expect("purge again"),
            0,
            "retention is not idempotent"
        );

        let remaining: Vec<String> = sqlx::query_scalar(
            "select event_type from audit_events where tenant_id = 'demo'",
        )
        .fetch_all(&db.pool)
        .await
        .expect("read the trail");
        assert_eq!(remaining, ["token.issued"]);

        // The front of the chain is gone, so verification starts from what the
        // oldest surviving record claims — and the rest still verifies.
        let verified = sink.verify_chain(&tenant).await.expect("trimmed chain verifies");
        assert_eq!(verified.records, 1);
        assert_ne!(verified.start, EventHash::GENESIS, "the chain was not trimmed");
    }
}

db_test! {
    /// The escape hatch must close when the retention transaction commits, or
    /// any later query on that pooled connection could delete.
    async fn the_retention_escape_hatch_does_not_outlive_its_transaction(db) {
        seed_tenant(&db.pool, "demo").await;
        let sink = PgAuditSink::new(db.pool.clone());
        sink.record(audit_event("demo", EventType::AUTH_LOGIN)).await.expect("record");

        let tenant = TenantId::new("demo");
        sink.purge_older_than(&tenant, OffsetDateTime::UNIX_EPOCH).await.expect("purge nothing");

        // Same pool, and very likely the same connection, immediately after.
        assert!(
            sqlx::query("delete from audit_events").execute(&db.pool).await.is_err(),
            "the retention flag survived its transaction"
        );
    }
}

db_test! {
    /// Chains are per tenant: one tenant's writes must not appear in another's
    /// chain, or a busy tenant would make a quiet one's trail unverifiable.
    async fn each_tenant_has_its_own_independent_chain(db) {
        seed_tenant(&db.pool, "alpha").await;
        seed_tenant(&db.pool, "beta").await;
        let sink = PgAuditSink::new(db.pool.clone());

        sink.record(audit_event("alpha", EventType::AUTH_LOGIN)).await.expect("alpha 1");
        sink.record(audit_event("beta", EventType::AUTH_LOGIN)).await.expect("beta 1");
        sink.record(audit_event("alpha", EventType::TOKEN_ISSUED)).await.expect("alpha 2");

        let alpha = sink.verify_chain(&TenantId::new("alpha")).await.expect("alpha verifies");
        let beta = sink.verify_chain(&TenantId::new("beta")).await.expect("beta verifies");
        assert_eq!(alpha.records, 2);
        assert_eq!(beta.records, 1);
        assert_eq!(alpha.start, EventHash::GENESIS);
        assert_eq!(beta.start, EventHash::GENESIS);
        assert_ne!(alpha.tip, beta.tip);
    }
}

db_test! {
    /// An agent's action must be attributable to the human it acts for, and the
    /// delegation chain must survive the round trip through storage — otherwise
    /// the recomputed hash would not match and every trail with an agent in it
    /// would look tampered with.
    async fn a_delegation_chain_round_trips_and_still_verifies(db) {
        seed_tenant(&db.pool, "demo").await;
        let sink = PgAuditSink::new(db.pool.clone());

        let event = audit_event("demo", EventType::TOKEN_EXCHANGED).actor_chain(vec![
            Actor::User("alice".to_owned()),
            Actor::Agent {
                client: asterius_domain::ClientId::new("scheduler-bot"),
                on_behalf_of: "alice".to_owned(),
            },
        ]);
        sink.record(event).await.expect("record");

        let stored: serde_json::Value = sqlx::query_scalar(
            "select actor_chain from audit_events where tenant_id = 'demo'",
        )
        .fetch_one(&db.pool)
        .await
        .expect("read the chain");
        assert_eq!(stored.as_array().expect("array").len(), 2);
        assert_eq!(stored[1]["type"], "agent");
        assert_eq!(stored[1]["on_behalf_of"], "alice");

        sink.verify_chain(&TenantId::new("demo")).await.expect("should still verify");
    }
}

/// Seeds a record whose `detail` this build cannot read, linked to `previous`,
/// and returns the hash it was stored with.
///
/// Raw SQL because the binary refuses to write one: `scripts/check-json-sentinels.sh`
/// and the guard in `asterius_domain::json_sentinel` exist so that no code path
/// produces a member named after a `serde_json` sentinel. A row like this can
/// only have arrived from an import, a restored dump, or a build made before
/// the guard — and once it is there the database refuses `UPDATE`, so it stays
/// (`ast-1p1`).
///
/// The document is unreadable on two counts, deliberately: its first member is
/// the sentinel, which is what stops `serde_json` parsing the document at all
/// in a binary where `raw_value` or `arbitrary_precision` is unified in — as
/// this one is, through `sqlx` — and its value is a nested object, which no
/// detail value ever is. Either alone would do; both together mean the test
/// still describes an unreadable row on the day a `cargo update` changes which
/// of the two applies.
async fn seed_unreadable_record(db: &TestDb, tenant: &str, previous: &[u8]) -> Vec<u8> {
    let hash: Vec<u8> = sqlx::query_scalar(
        "insert into audit_events
             (tenant_id, occurred_at, event_type, outcome, actor, actor_chain, detail,
              previous_hash, event_hash)
         values ($1, now(), 'auth.login', 'success',
                 '{\"type\": \"client\", \"id\": \"billing\"}'::jsonb, '[]'::jsonb,
                 '{\"$serde_json::private::RawValue\": {\"value\": \"{}\"}}'::jsonb,
                 $2, sha256($3))
         returning event_hash",
    )
    .bind(tenant)
    .bind(previous)
    .bind(format!("opaque-{tenant}").into_bytes())
    .fetch_one(&db.pool)
    .await
    .expect("seed unreadable record");
    hash
}

/// The hash of `tenant`'s newest record.
async fn chain_tip(db: &TestDb, tenant: &str) -> Vec<u8> {
    sqlx::query_scalar(
        "select event_hash from audit_events where tenant_id = $1 order by event_id desc limit 1",
    )
    .bind(tenant)
    .fetch_one(&db.pool)
    .await
    .expect("read the tip")
}

db_test! {
    /// A record nobody can deserialise is authentic, not tampered: it is
    /// reported as opaque with its hash and its position, the records around it
    /// are read normally, and the chain through it still verifies.
    async fn an_unreadable_record_is_opaque_and_the_trail_around_it_survives(db) {
        seed_tenant(&db.pool, "demo").await;
        let sink = PgAuditSink::new(db.pool.clone());
        let tenant = TenantId::new("demo");

        sink.record(audit_event("demo", EventType::CODE_ISSUED)).await.expect("first");
        let tip = chain_tip(&db, "demo").await;
        let opaque_hash = seed_unreadable_record(&db, "demo", &tip).await;
        // Written through the sink, so it chains onto the unreadable record the
        // way any later record would.
        sink.record(audit_event("demo", EventType::TOKEN_ISSUED)).await.expect("third");

        let trail = sink
            .read_trail(&tenant)
            .await
            .expect("an unreadable row must not fail the read");

        assert_eq!(trail.len(), 3);
        assert_eq!(
            trail[0].event().expect("the record before it stays readable").event_type,
            EventType::CODE_ISSUED
        );
        assert_eq!(
            trail[2].event().expect("the record after it stays readable").event_type,
            EventType::TOKEN_ISSUED
        );
        match &trail[1] {
            AuditRecord::Opaque { hash, position, reason } => {
                assert_eq!(hash.as_bytes().as_slice(), opaque_hash.as_slice());
                assert_eq!(*position, 1);
                // The column, not the variant: whether such a document fails
                // to parse or merely fails to be a shape the trail defines
                // depends on which `serde_json` features the binary unifies,
                // and neither answer changes what an operator is told.
                assert_eq!(reason.column(), asterius_domain::audit::record::DETAIL);
            }
            AuditRecord::Event(event) => panic!("the seeded record read back as {event:?}"),
        }

        let verified = sink.verify_chain(&tenant).await.expect("the chain must verify through it");
        assert_eq!(verified.records, 3);
        assert_eq!(verified.opaque, 1);
        assert_eq!(verified.start, EventHash::GENESIS);
    }
}

db_test! {
    /// Unreadable is not forged. The same unreadable record, inserted where its
    /// predecessor hash does not follow the record before it — an insertion, or
    /// a record moved — is still a chain error, and the reader must not launder
    /// it into an opaque record that verifies.
    async fn an_unreadable_record_in_the_wrong_place_is_still_a_chain_error(db) {
        seed_tenant(&db.pool, "demo").await;
        let sink = PgAuditSink::new(db.pool.clone());
        let tenant = TenantId::new("demo");

        sink.record(audit_event("demo", EventType::CODE_ISSUED)).await.expect("first");
        seed_unreadable_record(&db, "demo", &[0u8; 32]).await;

        // It is read without failing...
        let trail = sink.read_trail(&tenant).await.expect("read");
        assert!(trail[1].is_opaque());

        // ...and it still does not verify.
        let error = sink
            .verify_chain(&tenant)
            .await
            .expect_err("a record that does not follow its predecessor must not verify");
        let message = error.to_string();
        assert!(message.contains("record 1"), "{message}");
    }
}

// ---------------------------------------------------------------------------
// Clients
// ---------------------------------------------------------------------------

use asterius_domain::{
    Capabilities, Client, ClientId, ClientRegistration, ClientStatus, TokenBinding,
};
use serde_json::json;

/// A registration document that says only what it must.
fn registration_document() -> serde_json::Value {
    json!({
        "client_name": "Billing",
        "redirect_uris": ["https://rp.example/cb"],
        // OIDC RP-Initiated Logout 1.0 §3.1. In the shared document on purpose:
        // it then rides through the round trip, the RFC 7592 update and the
        // "another tenant" tests without any of them having to remember it.
        "post_logout_redirect_uris": ["https://rp.example/after-logout"],
        "grant_types": ["authorization_code", "refresh_token"],
        "scope": "openid payments",
        "jwks": {"keys": [{"kty": "OKP", "crv": "Ed25519", "x": "abc"}]},
    })
}

fn client(tenant: &str, id: &str, document: &serde_json::Value) -> Client {
    client_with(tenant, id, document, Capabilities::default())
}

fn client_with(
    tenant: &str,
    id: &str,
    document: &serde_json::Value,
    capabilities: Capabilities,
) -> Client {
    Client {
        tenant: TenantId::new(tenant),
        id: ClientId::new(id),
        registration: ClientRegistration::from_json(
            &serde_json::to_vec(document).expect("serialise"),
            capabilities,
        )
        .expect("the document should be a valid registration"),
        status: ClientStatus::Active,
        created_at: OffsetDateTime::UNIX_EPOCH,
        updated_at: OffsetDateTime::UNIX_EPOCH,
    }
}

db_test! {
    /// Everything the schema can hold comes back exactly as it went in. The
    /// redirect URIs in particular: matching is byte-exact (RFC 9700 §4.1), so
    /// a round trip that changes one byte breaks every authorization request
    /// the client makes.
    async fn a_registration_survives_the_round_trip_through_storage(db) {
        seed_tenant(&db.pool, "demo").await;
        let store = Store::from_pool(db.pool.clone());
        let repo = store.scope(TenantId::new("demo")).clients(Capabilities::default());

        let registered = client("demo", "billing", &registration_document());
        repo.upsert(&registered).await.expect("insert");

        let found = repo
            .find(&ClientId::new("billing"))
            .await
            .expect("find")
            .expect("present");
        assert_eq!(found.registration, registered.registration);
        assert_eq!(found.id, registered.id);
        assert!(found.is_active());
        // Timestamps come from the database, not from the entity we passed in.
        assert!(found.created_at > OffsetDateTime::UNIX_EPOCH);

        assert_eq!(repo.list().await.expect("list").len(), 1);
        assert!(repo.find(&ClientId::new("absent")).await.expect("find").is_none());
        repo.delete(&ClientId::new("billing"), OffsetDateTime::now_utc())
            .await
            .expect("delete");
        assert!(repo.find(&ClientId::new("billing")).await.expect("find").is_none());
        assert!(
            matches!(
                repo.delete(&ClientId::new("billing"), OffsetDateTime::now_utc()).await,
                Err(asterius_domain::DomainError::NotFound)
            ),
            "deleting twice should report the second as missing"
        );
    }
}

db_test! {
    /// Two tenants, one `client_id`, no crossing over. A repository scoped to
    /// one tenant must not see the other's row even when the identifier is the
    /// same — which is exactly the case a missing `tenant_id` predicate breaks.
    async fn a_scoped_lookup_never_returns_another_tenants_client(db) {
        seed_tenant(&db.pool, "alpha").await;
        seed_tenant(&db.pool, "beta").await;
        let store = Store::from_pool(db.pool.clone());

        let mut beta_document = registration_document();
        beta_document
            .as_object_mut()
            .expect("object")
            .insert("redirect_uris".to_owned(), json!(["https://beta.example/cb"]));

        store
            .scope(TenantId::new("alpha"))
            .clients(Capabilities::default())
            .upsert(&client("alpha", "billing", &registration_document()))
            .await
            .expect("alpha");
        store
            .scope(TenantId::new("beta"))
            .clients(Capabilities::default())
            .upsert(&client("beta", "billing", &beta_document))
            .await
            .expect("beta");

        let alpha = store.scope(TenantId::new("alpha")).clients(Capabilities::default());
        let found = alpha.find(&ClientId::new("billing")).await.expect("find").expect("present");
        assert_eq!(found.tenant, TenantId::new("alpha"));
        assert_eq!(
            found.registration.redirect_uris[0].as_str(),
            "https://rp.example/cb",
            "the lookup returned the other tenant's row"
        );
        assert_eq!(alpha.list().await.expect("list").len(), 1);

        // And an entity belonging to another tenant cannot be written through
        // this scope at all.
        let wrong = alpha.upsert(&client("beta", "billing", &beta_document)).await;
        assert!(
            matches!(
                wrong,
                Err(asterius_domain::DomainError::Invalid { field: "tenant_id", .. })
            ),
            "a foreign entity was written into this tenant: {wrong:?}"
        );
    }
}

db_test! {
    /// Rows get edited by hand during incidents. A row that no longer describes
    /// a client this profile would accept must fail to load rather than quietly
    /// become one — here a redirect URI changed to plain http, which is not
    /// something the schema can express a check for.
    async fn a_row_edited_into_a_weaker_client_refuses_to_load(db) {
        seed_tenant(&db.pool, "demo").await;
        let store = Store::from_pool(db.pool.clone());
        let repo = store.scope(TenantId::new("demo")).clients(Capabilities::default());
        repo.upsert(&client("demo", "billing", &registration_document())).await.expect("insert");

        sqlx::query(
            "update clients set redirect_uris = '{http://rp.example/cb}'
             where tenant_id = 'demo' and client_id = 'billing'",
        )
        .execute(&db.pool)
        .await
        .expect("tamper");

        let error = repo
            .find(&ClientId::new("billing"))
            .await
            .expect_err("an http redirect URI must not load");
        assert!(error.to_string().contains("redirect_uris"), "{error}");
        assert!(repo.list().await.is_err(), "list accepted what find refused");
    }
}

db_test! {
    /// ADR-0002's "no ambiguity" rule, in the schema: exactly one key source.
    /// A client with both is a client whose keys depend on which code path
    /// looked; a client with neither cannot authenticate at all.
    async fn the_schema_refuses_a_client_with_two_key_sources_or_none(db) {
        seed_tenant(&db.pool, "demo").await;
        for (id, jwks, jwks_uri) in [
            ("both", "'{}'::jsonb", "'https://rp.example/jwks'"),
            ("neither", "null", "null"),
        ] {
            let statement = format!(
                "insert into clients (tenant_id, client_id, client_name,
                                      token_endpoint_auth_method, jwks, jwks_uri)
                 values ('demo', '{id}', 'C', 'private_key_jwt', {jwks}, {jwks_uri})"
            );
            assert!(
                sqlx::query(&statement).execute(&db.pool).await.is_err(),
                "clients_exactly_one_key_source did not fire for {id}"
            );
        }
    }
}

db_test! {
    /// A client the parser accepts is a client the repository can store. The
    /// schema originally had no column for the token binding, the subject type
    /// or the application type, and `upsert` refused rather than writing a row
    /// that said something else; the columns exist now, so what is asserted is
    /// the round trip — including that a certificate-bound client does not come
    /// back on DPoP, which is the downgrade the refusal existed to prevent.
    async fn a_client_using_every_registrable_field_round_trips(db) {
        seed_tenant(&db.pool, "demo").await;
        let store = Store::from_pool(db.pool.clone());
        let capabilities = Capabilities { mtls: true, ..Capabilities::default() };
        let repo = store.scope(TenantId::new("demo")).clients(capabilities);

        let mut document = registration_document();
        let object = document.as_object_mut().expect("object");
        object.insert("dpop_bound_access_tokens".to_owned(), json!(false));
        object.insert("tls_client_certificate_bound_access_tokens".to_owned(), json!(true));
        object.insert("application_type".to_owned(), json!("web"));
        object.insert("subject_type".to_owned(), json!("pairwise"));
        object.insert(
            "sector_identifier_uri".to_owned(),
            json!("https://rp.example/sector.json"),
        );
        object.insert("request_object_signing_alg".to_owned(), json!("ES256"));
        object.insert("authorization_details_types".to_owned(), json!(["payment_initiation"]));
        object.insert("use_mtls_endpoint_aliases".to_owned(), json!(true));

        let original = client_with("demo", "billing", &document, capabilities);
        assert_eq!(original.registration.token_binding, TokenBinding::Certificate);
        repo.upsert(&original).await.expect("a valid client must be storable");

        let reloaded = repo
            .find(&asterius_domain::ClientId::new("billing"))
            .await
            .expect("read")
            .expect("present");

        // The binding above all: coming back as DPoP would be the silent
        // downgrade this test exists to catch.
        assert_eq!(reloaded.registration.token_binding, TokenBinding::Certificate);
        assert_eq!(reloaded.registration, original.registration);
    }
}

db_test! {
    /// FAPI 2.0 SP §5.3.2.1: access tokens are always sender-constrained. The
    /// validator refuses a client bound to neither; so does the table, because
    /// a row is reachable by paths the validator is not on.
    async fn the_schema_refuses_a_client_bound_to_neither_dpop_nor_a_certificate(db) {
        seed_tenant(&db.pool, "demo").await;
        let unbound = sqlx::query(
            "insert into clients (tenant_id, client_id, client_name,
                                  token_endpoint_auth_method, jwks,
                                  dpop_bound_access_tokens,
                                  tls_client_certificate_bound_access_tokens)
             values ('demo', 'bearer', 'Bearer', 'private_key_jwt', '{}'::jsonb, false, false)",
        )
        .execute(&db.pool)
        .await;
        assert!(unbound.is_err(), "the schema accepted a bearer-token client");

        // OIDC Core §8.1: a sector identifier means nothing without a pairwise
        // subject, so the pair cannot be stored either.
        let stray_sector = sqlx::query(
            "insert into clients (tenant_id, client_id, client_name,
                                  token_endpoint_auth_method, jwks,
                                  subject_type, sector_identifier_uri)
             values ('demo', 'public-sector', 'S', 'private_key_jwt', '{}'::jsonb,
                     'public', 'https://rp.example/sector.json')",
        )
        .execute(&db.pool)
        .await;
        assert!(stray_sector.is_err(), "a sector identifier was stored on a public client");
    }
}

db_test! {
    /// The same row carries state other stories own — the agent profile
    /// (`ast-lh3.1`) and the registration access token (`ast-m9c.4`). Updating
    /// the metadata must not erase it, or re-registering a client would silently
    /// revoke its management credential.
    async fn updating_a_registration_leaves_columns_other_stories_own_alone(db) {
        seed_tenant(&db.pool, "demo").await;
        let store = Store::from_pool(db.pool.clone());
        let repo = store.scope(TenantId::new("demo")).clients(Capabilities::default());
        repo.upsert(&client("demo", "agent", &registration_document())).await.expect("insert");

        sqlx::query(
            "update clients
             set is_agent = true,
                 agent_owner_sub = 'alice',
                 registration_access_token_hash = repeat('\\001', 32)::bytea
             where tenant_id = 'demo' and client_id = 'agent'",
        )
        .execute(&db.pool)
        .await
        .expect("set the columns other stories own");

        let mut renamed = client("demo", "agent", &registration_document());
        renamed.registration.client_name = "Renamed".to_owned();
        repo.upsert(&renamed).await.expect("update");

        let row = sqlx::query(
            "select client_name, is_agent, agent_owner_sub, registration_access_token_hash
             from clients where tenant_id = 'demo' and client_id = 'agent'",
        )
        .fetch_one(&db.pool)
        .await
        .expect("read back");
        assert_eq!(row.get::<String, _>("client_name"), "Renamed");
        assert!(row.get::<bool, _>("is_agent"), "the agent flag was erased");
        assert_eq!(row.get::<Option<String>, _>("agent_owner_sub").as_deref(), Some("alice"));
        assert_eq!(
            row.get::<Option<Vec<u8>>, _>("registration_access_token_hash"),
            Some(vec![1_u8; 32]),
            "the registration access token was erased by a metadata update"
        );
    }
}

db_test! {
    /// A client registered for an mTLS method on a deployment that has since
    /// turned the flag off cannot authenticate any more, so it must not load as
    /// though it could.
    async fn a_client_needing_a_disabled_feature_refuses_to_load(db) {
        seed_tenant(&db.pool, "demo").await;
        let store = Store::from_pool(db.pool.clone());
        let mtls_on = Capabilities { mtls: true, ..Capabilities::default() };

        let mut document = registration_document();
        let members = document.as_object_mut().expect("object");
        members.insert("token_endpoint_auth_method".to_owned(), json!("tls_client_auth"));
        members.insert("tls_client_auth_subject_dn".to_owned(), json!("CN=billing,O=Demo"));

        store
            .scope(TenantId::new("demo"))
            .clients(mtls_on)
            .upsert(&client_with("demo", "billing", &document, mtls_on))
            .await
            .expect("insert");

        assert!(
            store
                .scope(TenantId::new("demo"))
                .clients(mtls_on)
                .find(&ClientId::new("billing"))
                .await
                .expect("find")
                .is_some()
        );
        let error = store
            .scope(TenantId::new("demo"))
            .clients(Capabilities::default())
            .find(&ClientId::new("billing"))
            .await
            .expect_err("mtls is off now");
        assert!(error.to_string().contains("mtls"), "{error}");
    }
}

db_test! {
    /// Only the key-authenticated shapes reach storage. The schema's check is
    /// the last line of the rule the validator enforces first, so that a row
    /// inserted by a seed script or by hand cannot create a secret-based client
    /// the validator would have refused.
    async fn the_schema_refuses_a_secret_based_authentication_method(db) {
        seed_tenant(&db.pool, "demo").await;
        for method in ["client_secret_basic", "client_secret_post", "client_secret_jwt", "none"] {
            let inserted = sqlx::query(
                "insert into clients (tenant_id, client_id, client_name,
                                      token_endpoint_auth_method, jwks)
                 values ('demo', $1, 'C', $1, '{}'::jsonb)",
            )
            .bind(method)
            .execute(&db.pool)
            .await;
            assert!(inserted.is_err(), "the schema accepted {method}");
        }
    }
}

// ---------------------------------------------------------------------------
// Dynamic client registration (`ast-m9c.4`)
// ---------------------------------------------------------------------------

db_test! {
    /// The registration round trip, against the row rather than the entity.
    ///
    /// Two things are asserted that no in-memory test can reach. The client
    /// that `register` hands back is the one the database holds — RFC 7591
    /// §3.2.1 makes the response "all registered metadata about this client",
    /// and the endpoint renders it from this value, so a row the database
    /// altered on the way in must show up here. And the registration access
    /// token is in the row only as a digest: the column is `bytea`, it is
    /// exactly the 32 bytes of SHA-256, and the token itself appears nowhere.
    async fn registering_a_client_stores_only_the_digest_of_its_access_token(db) {
        seed_tenant(&db.pool, "demo").await;
        let store = Store::from_pool(db.pool.clone());
        let repo = store.scope(TenantId::new("demo")).clients(Capabilities::default());

        let token = asterius_domain::OpaqueToken::generate();
        let digest = asterius_domain::sha256(token.expose().as_bytes());
        let registered = client("demo", "c.abc", &registration_document());

        let stored = repo.register(&registered, &digest).await.expect("register");
        assert_eq!(stored.registration, registered.registration);
        assert_eq!(stored.id, registered.id);
        assert!(stored.is_active());
        // The timestamps come from the column defaults, not from the entity, so
        // `client_id_issued_at` is a value the database will always agree with.
        assert!(stored.created_at > OffsetDateTime::UNIX_EPOCH);

        // The same client comes back through the ordinary read path.
        let found = repo.find(&ClientId::new("c.abc")).await.expect("find").expect("present");
        assert_eq!(found.registration, stored.registration);

        let column: Option<Vec<u8>> = sqlx::query_scalar(
            "select registration_access_token_hash from clients
             where tenant_id = 'demo' and client_id = 'c.abc'",
        )
        .fetch_one(&db.pool)
        .await
        .expect("read the digest");
        let column = column.expect("a registration access token was stored");
        assert_eq!(column, digest.to_vec());
        assert_eq!(column.len(), 32, "SHA-256 is 32 bytes");

        // Nothing in the row is the token. Checked across every text column,
        // because the point is not that one column is clean but that the
        // credential is not recoverable from the row at all.
        let row: Vec<String> = sqlx::query_scalar(
            "select coalesce(t.value::text, '') from clients c,
                    lateral jsonb_each(to_jsonb(c)) as t(key, value)
             where c.tenant_id = 'demo' and c.client_id = 'c.abc'",
        )
        .fetch_all(&db.pool)
        .await
        .expect("read the row");
        assert!(
            !row.iter().any(|value| value.contains(token.expose())),
            "the registration access token survived into the row"
        );
    }
}

db_test! {
    /// `register` creates; it never replaces.
    ///
    /// A `client_id` collision at 128 bits is not an update anybody asked for,
    /// and treating it as one would let the improbable case retire a live
    /// client's keys, redirect URIs and registration access token — through the
    /// one endpoint reachable without a client credential. The second call must
    /// fail and the first client must be untouched.
    async fn registering_over_an_existing_client_is_refused_not_merged(db) {
        seed_tenant(&db.pool, "demo").await;
        let store = Store::from_pool(db.pool.clone());
        let repo = store.scope(TenantId::new("demo")).clients(Capabilities::default());

        let first_digest = [1_u8; 32];
        repo.register(&client("demo", "c.abc", &registration_document()), &first_digest)
            .await
            .expect("the first registration");

        let mut second = registration_document();
        second
            .as_object_mut()
            .expect("object")
            .insert("redirect_uris".to_owned(), json!(["https://attacker.example/cb"]));
        let conflict = repo
            .register(&client("demo", "c.abc", &second), &[2_u8; 32])
            .await;
        assert!(
            matches!(conflict, Err(asterius_domain::DomainError::Conflict(_))),
            "a second registration under the same id was not refused: {conflict:?}"
        );

        let found = repo.find(&ClientId::new("c.abc")).await.expect("find").expect("present");
        assert_eq!(
            found.registration.redirect_uris[0].as_str(),
            "https://rp.example/cb",
            "the second registration overwrote the first client's redirect URI"
        );
        let digest: Option<Vec<u8>> = sqlx::query_scalar(
            "select registration_access_token_hash from clients
             where tenant_id = 'demo' and client_id = 'c.abc'",
        )
        .fetch_one(&db.pool)
        .await
        .expect("read the digest");
        assert_eq!(
            digest,
            Some(first_digest.to_vec()),
            "the second registration replaced the first client's access token"
        );
    }
}

db_test! {
    /// A client registered in one tenant does not exist in another, even when
    /// both tenants used the same `client_id`. This is the case a missing
    /// `tenant_id` predicate breaks, and dynamic registration is the path that
    /// creates clients fastest, so it is the path where a leak would be widest.
    async fn a_client_registered_in_one_tenant_is_invisible_in_another(db) {
        seed_tenant(&db.pool, "alpha").await;
        seed_tenant(&db.pool, "beta").await;
        let store = Store::from_pool(db.pool.clone());
        let alpha = store.scope(TenantId::new("alpha")).clients(Capabilities::default());
        let beta = store.scope(TenantId::new("beta")).clients(Capabilities::default());

        alpha
            .register(&client("alpha", "c.abc", &registration_document()), &[3_u8; 32])
            .await
            .expect("alpha registers");

        assert!(
            beta.find(&ClientId::new("c.abc")).await.expect("find").is_none(),
            "the other tenant's client was visible"
        );
        assert!(beta.list().await.expect("list").is_empty());
        assert_eq!(alpha.list().await.expect("list").len(), 1);

        // Both tenants may hold the same identifier without either seeing the
        // other's row, and the registration access tokens stay distinct.
        beta.register(&client("beta", "c.abc", &registration_document()), &[4_u8; 32])
            .await
            .expect("beta registers the same id");
        let digests: Vec<(String, Vec<u8>)> = sqlx::query_as(
            "select tenant_id, registration_access_token_hash from clients
             where client_id = 'c.abc' order by tenant_id",
        )
        .fetch_all(&db.pool)
        .await
        .expect("read the digests");
        assert_eq!(digests.len(), 2);
        assert_eq!(digests[0], ("alpha".to_owned(), vec![3_u8; 32]));
        assert_eq!(digests[1], ("beta".to_owned(), vec![4_u8; 32]));

        // And an entity belonging to another tenant cannot be registered
        // through this scope at all.
        let wrong = alpha
            .register(&client("beta", "c.def", &registration_document()), &[5_u8; 32])
            .await;
        assert!(
            matches!(
                wrong,
                Err(asterius_domain::DomainError::Invalid { field: "tenant_id", .. })
            ),
            "a foreign entity was registered into this tenant: {wrong:?}"
        );
    }
}

db_test! {
    /// RFC 7592 §2.1/§2.2/§2.3: a registration access token presented for a
    /// client it does not manage is revoked, wherever in the tenant it lives.
    ///
    /// The statement is keyed on the credential, not on a `client_id`, so this
    /// is the one place in the schema where a digest finds its own row. What
    /// the test pins is the blast radius: the digest column of the holder is
    /// nulled and nothing else in the row moves, so the client keeps serving
    /// its users and only loses the ability to manage its registration.
    async fn revoking_a_digest_clears_it_from_whichever_client_holds_it(db) {
        seed_tenant(&db.pool, "demo").await;
        let store = Store::from_pool(db.pool.clone());
        let repo = store.scope(TenantId::new("demo")).clients(Capabilities::default());

        let digest = [7_u8; 32];
        repo.register(&client("demo", "c.alpha", &registration_document()), &digest)
            .await
            .expect("alpha registers");
        repo.register(&client("demo", "c.beta", &registration_document()), &[8_u8; 32])
            .await
            .expect("beta registers");

        repo.revoke_registration_access_token(&digest).await.expect("revoke");

        let rows: Vec<(String, Option<Vec<u8>>)> = sqlx::query_as(
            "select client_id, registration_access_token_hash from clients
             where tenant_id = 'demo' order by client_id",
        )
        .fetch_all(&db.pool)
        .await
        .expect("read the digests");
        assert_eq!(rows[0], ("c.alpha".to_owned(), None), "the holder kept its credential");
        assert_eq!(
            rows[1],
            ("c.beta".to_owned(), Some(vec![8_u8; 32])),
            "a bystander lost its credential"
        );

        // The client is still a client. Only the credential went.
        let alpha = repo.find(&ClientId::new("c.alpha")).await.expect("find").expect("present");
        assert_eq!(alpha.registration.client_name, "Billing");
        assert!(alpha.is_active());
    }
}

db_test! {
    /// A digest no client holds writes nothing.
    ///
    /// This is the case an anonymous caller can reach at will, so it has to be
    /// free: no row version, no `updated_at`, no error. `updated_at` is the
    /// observable here because the row's trigger moves it on any write, so an
    /// unchanged timestamp is proof that the statement matched nothing rather
    /// than that it wrote the same bytes back.
    async fn revoking_a_digest_nobody_holds_writes_nothing(db) {
        seed_tenant(&db.pool, "demo").await;
        let store = Store::from_pool(db.pool.clone());
        let repo = store.scope(TenantId::new("demo")).clients(Capabilities::default());
        repo.register(&client("demo", "c.alpha", &registration_document()), &[9_u8; 32])
            .await
            .expect("alpha registers");

        let before: OffsetDateTime = sqlx::query_scalar(
            "select updated_at from clients where tenant_id = 'demo' and client_id = 'c.alpha'",
        )
        .fetch_one(&db.pool)
        .await
        .expect("read updated_at");

        repo.revoke_registration_access_token(&[0_u8; 32]).await.expect("revoke nothing");
        repo.revoke_registration_access_token(&[255_u8; 32]).await.expect("revoke nothing");

        let (after, digest): (OffsetDateTime, Option<Vec<u8>>) = sqlx::query_as(
            "select updated_at, registration_access_token_hash from clients
             where tenant_id = 'demo' and client_id = 'c.alpha'",
        )
        .fetch_one(&db.pool)
        .await
        .expect("read the row");
        assert_eq!(after, before, "a digest nobody holds touched a row");
        assert_eq!(digest, Some(vec![9_u8; 32]));
    }
}

db_test! {
    /// A digest presented at one tenant cannot revoke another tenant's
    /// credential, even when both tenants hold the same bytes.
    ///
    /// Two tenants holding one digest is a CSPRNG failure rather than something
    /// to expect, but the predicate has to be right for the reason every other
    /// statement here is tenant-scoped: this one runs on a request that has not
    /// authenticated, so a missing `tenant_id` would let anybody who can reach
    /// one tenant's endpoint burn a credential in another.
    async fn a_revocation_stops_at_the_tenant_boundary(db) {
        seed_tenant(&db.pool, "alpha").await;
        seed_tenant(&db.pool, "beta").await;
        let store = Store::from_pool(db.pool.clone());
        let alpha = store.scope(TenantId::new("alpha")).clients(Capabilities::default());
        let beta = store.scope(TenantId::new("beta")).clients(Capabilities::default());

        let shared = [11_u8; 32];
        alpha.register(&client("alpha", "c.abc", &registration_document()), &shared)
            .await
            .expect("alpha registers");
        beta.register(&client("beta", "c.abc", &registration_document()), &shared)
            .await
            .expect("beta registers");

        alpha.revoke_registration_access_token(&shared).await.expect("revoke");

        let rows: Vec<(String, Option<Vec<u8>>)> = sqlx::query_as(
            "select tenant_id, registration_access_token_hash from clients
             where client_id = 'c.abc' order by tenant_id",
        )
        .fetch_all(&db.pool)
        .await
        .expect("read the digests");
        assert_eq!(rows[0], ("alpha".to_owned(), None));
        assert_eq!(
            rows[1],
            ("beta".to_owned(), Some(shared.to_vec())),
            "one tenant's revocation reached into another"
        );
    }
}

db_test! {
    /// The revocation resolves through `clients_by_registration_access_token`
    /// and is never a sequential scan.
    ///
    /// The reason the statement is allowed to exist at all: it runs on an
    /// unauthenticated request, so a scan of `clients` per attempt would make
    /// honouring RFC 7592's SHOULD a denial-of-service primitive.
    ///
    /// The plan is read back rather than assumed, because the failure this
    /// guards against is silent: the statement keeps working, slowly, for ever.
    /// Two ways to get it wrong, and the plan catches both — a predicate that
    /// does not imply the partial index's own `where ... is not null` leaves
    /// the index unusable, and a predicate that merely narrows by `tenant_id`
    /// gets served by `clients_pkey` with the digest as a filter, which is a
    /// scan of the tenant wearing an index's name.
    ///
    /// The table is filled first and `analyze`d, because a planner with no
    /// statistics has no reason to prefer anything: the question is what
    /// happens at the size a deployment actually has, not at three rows. The
    /// row count is small enough to insert in one statement and large enough
    /// that a scan is the wrong answer.
    async fn the_revocation_is_planned_as_an_index_lookup(db) {
        seed_tenant(&db.pool, "demo").await;
        let store = Store::from_pool(db.pool.clone());
        let repo = store.scope(TenantId::new("demo")).clients(Capabilities::default());
        repo.register(&client("demo", "c.alpha", &registration_document()), &[13_u8; 32])
            .await
            .expect("alpha registers");

        // A tenant with a realistic number of clients, each holding its own
        // digest. Written straight to the table: what is under test is the
        // planner, and 5000 registrations through the repository would only
        // make the test slow.
        sqlx::query(
            "insert into clients (tenant_id, client_id, client_name,
                                  token_endpoint_auth_method, jwks,
                                  registration_access_token_hash)
             select 'demo', 'c.bulk.' || g, 'Bulk', 'private_key_jwt',
                    '{\"keys\": []}'::jsonb, sha256(g::text::bytea)
             from generate_series(1, 5000) g",
        )
        .execute(&db.pool)
        .await
        .expect("fill the tenant");
        sqlx::query("analyze clients").execute(&db.pool).await.expect("analyze");

        // The statement `revoke_registration_access_token` runs, verbatim, and
        // with the planner left entirely alone.
        let plan: Vec<String> = sqlx::query_scalar(
            "explain (costs off)
             update clients set registration_access_token_hash = null
             where tenant_id = $1
               and registration_access_token_hash = $2
               and registration_access_token_hash is not null",
        )
        .bind("demo")
        .bind([13_u8; 32].as_slice())
        .fetch_all(&db.pool)
        .await
        .expect("explain the revocation");
        let plan = plan.join("\n");

        assert!(
            plan.contains("clients_by_registration_access_token"),
            "the revocation did not use its index:\n{plan}"
        );
        assert!(
            !plan.contains("Seq Scan"),
            "the revocation fell back to a scan:\n{plan}"
        );
        assert!(
            !plan.contains("clients_pkey"),
            "the revocation scanned the tenant through the primary key:\n{plan}"
        );
    }
}

db_test! {
    /// The index is partial, so a client with no registration access token is
    /// not in it.
    ///
    /// Admin-created clients have no such token and are the majority in a
    /// mature deployment; indexing their nulls would pay for the whole table to
    /// serve a lookup that can never match them.
    async fn the_token_index_covers_only_clients_that_have_one(db) {
        let predicate: Option<String> = sqlx::query_scalar(
            "select pg_get_expr(i.indpred, i.indrelid)
             from pg_index i join pg_class c on c.oid = i.indexrelid
             where c.relname = 'clients_by_registration_access_token'",
        )
        .fetch_one(&db.pool)
        .await
        .expect("the index exists");
        let predicate = predicate.expect("the index is partial");
        assert!(
            predicate.contains("registration_access_token_hash IS NOT NULL"),
            "the index is not restricted to clients that hold a token: {predicate}"
        );
    }
}

db_test! {
    /// Registering into a tenant that does not exist is a conflict, not a
    /// storage failure and not a row. The foreign key is what makes it so, and
    /// this asserts the mapping rather than the constraint: a caller that got
    /// `Storage` back would retry, and a caller that got `Conflict` knows not
    /// to.
    async fn registering_into_an_unknown_tenant_creates_nothing(db) {
        let store = Store::from_pool(db.pool.clone());
        let repo = store.scope(TenantId::new("ghost")).clients(Capabilities::default());
        let failed = repo
            .register(&client("ghost", "c.abc", &registration_document()), &[7_u8; 32])
            .await;
        assert!(
            matches!(failed, Err(asterius_domain::DomainError::Conflict(_))),
            "{failed:?}"
        );
        let count: i64 = sqlx::query_scalar("select count(*) from clients")
            .fetch_one(&db.pool)
            .await
            .expect("count");
        assert_eq!(count, 0);
    }
}

// ---------------------------------------------------------------------------
// Signing keys: lifecycle, rotation and encryption at rest
// ---------------------------------------------------------------------------

use asterius_domain::keys::{KeyPurpose, KeyState, KeyStore, Kid, PurgeReason, SigningAlgorithm};
use asterius_jose::{LocalKek, SigningKey, VerifyingKey, jws};
use asterius_store_pg::{PgKeyRepository, RotationSchedule};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use std::sync::Arc;
use time::Duration;

/// A fixed key-encryption key. Constant on purpose: every assertion about what
/// is in the table has to be made against a KEK the test still holds.
const A_KEK: [u8; 32] = [0x5a; 32];

fn kek() -> Arc<LocalKek> {
    Arc::new(LocalKek::from_bytes(&A_KEK).expect("a 32-byte KEK"))
}

fn keys(pool: &PgPool, tenant: &str) -> PgKeyRepository {
    PgKeyRepository::new(
        pool.clone(),
        TenantId::new(tenant),
        kek(),
        Arc::new(PgAuditSink::new(pool.clone())),
    )
}

/// An epoch the tests do arithmetic from, so that "before rotation" and "after
/// the grace period" are exact rather than a sleep.
fn epoch() -> OffsetDateTime {
    OffsetDateTime::UNIX_EPOCH + time::Duration::days(20_000)
}

fn operator() -> Actor {
    Actor::Admin("ops@example".to_owned())
}

/// Rebuilds a verifying key from a published JWK, the way a relying party
/// would: the only thing it is given is the JWK Set.
fn verifying_key_from_jwk(jwk: &serde_json::Value) -> VerifyingKey {
    assert_eq!(jwk["kty"], "OKP", "this helper only knows Ed25519");
    assert_eq!(jwk["crv"], "Ed25519");
    let x = B64
        .decode(jwk["x"].as_str().expect("x is a string"))
        .expect("x is base64url");
    VerifyingKey::new(SigningAlgorithm::EdDsa, x)
}

async fn published(repo: &PgKeyRepository, tenant: &str) -> Vec<(Kid, KeyState)> {
    repo.published_keys(&TenantId::new(tenant))
        .await
        .expect("published keys")
        .into_iter()
        .map(|key| (key.kid, key.state))
        .collect()
}

db_test! {
    /// OIDC Core §10.1.1, the whole procedure in one test. Keys are rolled over
    /// by "adding new keys to the JWK Set"; the signer "can begin using a new
    /// key at its discretion and signals the change to the verifier using the
    /// kid value"; and the JWK Set "SHOULD retain recently decommissioned
    /// signing keys for a reasonable period of time to facilitate a smooth
    /// transition".
    ///
    /// So a token signed before a rotation must still verify against the
    /// published JWKS for the whole grace period, new tokens must carry the new
    /// `kid`, and once the grace period ends the old key must be gone from what
    /// is published.
    async fn a_token_signed_before_rotation_verifies_until_the_grace_period_ends(db) {
        seed_tenant(&db.pool, "demo").await;
        let repo = keys(&db.pool, "demo");
        let t0 = epoch();
        let schedule = repo.schedule(SigningAlgorithm::DEFAULT).await.expect("default schedule");

        // First key: active immediately, because no verifier can have cached a
        // JWK Set this tenant has never published.
        let first = repo.rotate(SigningAlgorithm::EdDsa, operator(), t0).await.expect("rotate");
        let old_kid = first.created.clone().expect("a key was created");
        assert_eq!(first.activated, None);
        assert_eq!(published(&repo, "demo").await, [(old_kid.clone(), KeyState::Active)]);

        let (signing_kid, old_key) = repo
            .active_signing_key(SigningAlgorithm::EdDsa)
            .await
            .expect("read")
            .expect("an active key");
        assert_eq!(signing_kid, old_kid);
        let old_token = jws::sign(&old_key, &old_kid, "at+jwt", &json!({"sub": "alice"}))
            .expect("sign");

        // Trigger a rotation. The new key is published and does not sign yet.
        let second = repo.rotate(SigningAlgorithm::EdDsa, operator(), t0).await.expect("rotate");
        let new_kid = second.created.clone().expect("a key was created");
        assert_ne!(new_kid, old_kid);
        assert_eq!(
            published(&repo, "demo").await,
            [(old_kid.clone(), KeyState::Active), (new_kid.clone(), KeyState::Pending)],
            "the new key must be published before it signs"
        );
        assert_eq!(
            repo.active_signing_key(SigningAlgorithm::EdDsa).await.expect("read").expect("key").0,
            old_kid,
            "a pending key must not sign"
        );

        // After the propagation period the signer begins using the new key.
        let promoted = t0 + schedule.propagation_period;
        let pass = repo.apply_schedule(SigningAlgorithm::EdDsa, promoted).await.expect("advance");
        assert_eq!(pass.activated.as_ref(), Some(&new_kid));
        assert_eq!(pass.superseded.as_ref(), Some(&old_kid));
        assert_eq!(pass.created, None, "nothing is due yet");

        let (kid, new_key) = repo
            .active_signing_key(SigningAlgorithm::EdDsa)
            .await
            .expect("read")
            .expect("an active key");
        assert_eq!(kid, new_kid, "new tokens must use the new kid");
        let new_token = jws::sign(&new_key, &new_kid, "at+jwt", &json!({"sub": "alice"}))
            .expect("sign");
        assert_eq!(jws::parse(new_token.as_str()).expect("parse").kid(), Some(new_kid.clone()));

        // The old token still verifies, using only what the JWKS publishes.
        let jwks = repo.published_keys(&TenantId::new("demo")).await.expect("jwks");
        let old_published = jwks
            .iter()
            .find(|key| key.kid == old_kid)
            .expect("the decommissioned key is still published");
        assert_eq!(old_published.state, KeyState::Retiring);
        jws::parse(old_token.as_str())
            .expect("parse")
            .verify(&verifying_key_from_jwk(&old_published.public_jwk))
            .expect("a token signed before the rotation must still verify");

        // Once the grace period is over the old key leaves the JWK Set.
        let expired = promoted + schedule.grace_period;
        let pass = repo.apply_schedule(SigningAlgorithm::EdDsa, expired).await.expect("advance");
        assert_eq!(pass.retired.as_slice(), std::slice::from_ref(&old_kid));
        assert_eq!(published(&repo, "demo").await, [(new_kid.clone(), KeyState::Active)]);

        // The row survives so the kid is never reused, but nothing publishes it.
        let retired = repo
            .public_key(&TenantId::new("demo"), &old_kid)
            .await
            .expect("read")
            .expect("the row is kept");
        assert_eq!(retired.state, KeyState::Retired);
        assert!(!retired.state.is_published());
    }
}

db_test! {
    /// The property `private_key_ciphertext` exists for: what is written down
    /// is not a key. Read the bytes straight out of the row and check that they
    /// are neither a JWK nor a PKCS#8 encoding of anything.
    async fn the_stored_private_key_is_ciphertext_and_not_a_key(db) {
        seed_tenant(&db.pool, "demo").await;
        let repo = keys(&db.pool, "demo");
        repo.rotate(SigningAlgorithm::EdDsa, operator(), epoch()).await.expect("rotate");

        let row = sqlx::query(
            "select private_key_ciphertext, private_key_nonce, kek_id
             from signing_keys where tenant_id = 'demo'",
        )
        .fetch_one(&db.pool)
        .await
        .expect("read the row");
        let ciphertext: Vec<u8> = row.get("private_key_ciphertext");

        assert!(
            serde_json::from_slice::<serde_json::Value>(&ciphertext).is_err(),
            "the stored private key parses as JSON, so it may be a JWK"
        );
        for algorithm in SigningAlgorithm::ALL {
            assert!(
                SigningKey::from_pkcs8(algorithm, &ciphertext).is_err(),
                "the stored private key parses as {algorithm} PKCS#8"
            );
        }

        // And it is not the key with a header bolted on, either.
        let (_, key) = repo
            .active_signing_key(SigningAlgorithm::EdDsa)
            .await
            .expect("read")
            .expect("an active key");
        for window in key.pkcs8().windows(16) {
            assert!(
                !ciphertext.windows(16).any(|candidate| candidate == window),
                "a 16-byte run of the private key is stored verbatim"
            );
        }

        // The nonce is the 96 bits AES-GCM is used with here, and the KEK is
        // named so that a rotated KEK leaves a trail.
        assert_eq!(row.get::<Vec<u8>, _>("private_key_nonce").len(), 12);
        assert!(row.get::<String, _>("kek_id").starts_with("local:"));

        // The round trip still produces the key that was stored: encrypting it
        // is only worth anything if it comes back.
        let signature = key.sign(b"payload").expect("sign");
        key.verifying_key().expect("public").verify(b"payload", &signature).expect("verify");
    }
}

db_test! {
    /// The ciphertext is bound to the row it belongs in, so a private key
    /// copied into another tenant's row is not a private key any more. Without
    /// the binding, an attacker with an `UPDATE` could install one tenant's
    /// signing key as another tenant's and mint tokens for it.
    async fn a_private_key_moved_to_another_tenant_stops_decrypting(db) {
        seed_tenant(&db.pool, "alpha").await;
        seed_tenant(&db.pool, "beta").await;
        let alpha = keys(&db.pool, "alpha");
        alpha.rotate(SigningAlgorithm::EdDsa, operator(), epoch()).await.expect("rotate");
        assert!(alpha.active_signing_key(SigningAlgorithm::EdDsa).await.expect("read").is_some());

        sqlx::query("update signing_keys set tenant_id = 'beta' where tenant_id = 'alpha'")
            .execute(&db.pool)
            .await
            .expect("move the row");

        let error = keys(&db.pool, "beta")
            .active_signing_key(SigningAlgorithm::EdDsa)
            .await
            .expect_err("a moved private key must not decrypt");
        assert!(
            matches!(error, asterius_domain::DomainError::Storage(_)),
            "expected a storage failure, got {error:?}"
        );
    }
}

db_test! {
    /// A rotation waits for any other rotation of the same tenant. Two at once
    /// — an operator triggering one while the background sweep runs, or two
    /// replicas sweeping together — would otherwise interleave into two new
    /// keys, or into a promotion racing an insert.
    ///
    /// Asserted by taking the repository's own lock from another transaction
    /// and watching a rotation fail to make progress until it is released.
    /// Nothing about wall-clock timing decides the outcome: while the lock is
    /// held the rotation cannot finish at all.
    async fn a_rotation_waits_for_another_rotation_of_the_same_tenant(db) {
        seed_tenant(&db.pool, "demo").await;
        let repo = keys(&db.pool, "demo");
        let t0 = epoch();
        repo.rotate(SigningAlgorithm::EdDsa, operator(), t0).await.expect("first key");

        // The same lock the repository takes, held by somebody else.
        let mut holder = db.pool.begin().await.expect("begin");
        sqlx::query("select pg_advisory_xact_lock(hashtext($1), hashtext('key-rotation'))")
            .bind("demo")
            .execute(&mut *holder)
            .await
            .expect("take the rotation lock");

        let blocked = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            repo.rotate(SigningAlgorithm::EdDsa, operator(), t0),
        )
        .await;
        assert!(
            blocked.is_err(),
            "a rotation ran while another transaction held the tenant's rotation lock"
        );

        // Nothing was written by the attempt that could not finish.
        let count: i64 = sqlx::query_scalar("select count(*) from signing_keys")
            .fetch_one(&db.pool)
            .await
            .expect("count");
        assert_eq!(count, 1, "a rotation that never got the lock still wrote a key");

        holder.rollback().await.expect("release the lock");
        repo.rotate(SigningAlgorithm::EdDsa, operator(), t0)
            .await
            .expect("a rotation must proceed once the lock is free");
    }
}

db_test! {
    /// Rotating twice before the first new key has been published long enough
    /// must not stack up keys nobody has started using. An operator being
    /// careful is not a request for four signing keys.
    async fn rotating_again_before_the_propagation_period_reports_the_staged_key(db) {
        seed_tenant(&db.pool, "demo").await;
        let repo = keys(&db.pool, "demo");
        let t0 = epoch();
        repo.rotate(SigningAlgorithm::EdDsa, operator(), t0).await.expect("first key");

        let (left, right) = tokio::join!(
            repo.rotate(SigningAlgorithm::EdDsa, operator(), t0),
            repo.rotate(SigningAlgorithm::EdDsa, operator(), t0),
        );
        let left = left.expect("rotate").created.expect("created");
        let right = right.expect("rotate").created.expect("created");
        assert_eq!(left, right, "two rotations produced two different keys");

        let count: i64 = sqlx::query_scalar("select count(*) from signing_keys")
            .fetch_one(&db.pool)
            .await
            .expect("count");
        assert_eq!(count, 2, "a queue of unused keys was left behind");
        assert_eq!(
            published(&repo, "demo").await.into_iter().map(|(_, state)| state).collect::<Vec<_>>(),
            [KeyState::Active, KeyState::Pending]
        );
    }
}

db_test! {
    /// FAPI 2.0 SP §6.8 item 4 asks that linked credentials be recorded so they
    /// can be revoked together; a rotation with no trail leaves nobody able to
    /// say when a compromised key stopped signing.
    async fn a_rotation_is_recorded_in_the_audit_trail(db) {
        seed_tenant(&db.pool, "demo").await;
        let repo = keys(&db.pool, "demo");
        let sink = PgAuditSink::new(db.pool.clone());
        let t0 = epoch();

        repo.rotate(SigningAlgorithm::EdDsa, operator(), t0).await.expect("first");
        repo.rotate(SigningAlgorithm::EdDsa, operator(), t0).await.expect("second");

        let recorded: Vec<String> = sqlx::query_scalar(
            "select event_type from audit_events where tenant_id = 'demo' order by event_id",
        )
        .fetch_all(&db.pool)
        .await
        .expect("read the trail");
        assert_eq!(recorded, ["key.rotated", "key.rotated"]);

        let row = sqlx::query(
            "select actor, detail from audit_events where tenant_id = 'demo' order by event_id limit 1",
        )
        .fetch_one(&db.pool)
        .await
        .expect("read the first record");
        assert_eq!(row.get::<serde_json::Value, _>("actor")["type"], "admin");
        let detail: serde_json::Value = row.get("detail");
        assert_eq!(detail["alg"], "EdDSA");
        assert_eq!(detail["purpose"], "sig");
        // The kid is public but is a long high-entropy string, so it is
        // recorded as a correlatable digest rather than as free text the
        // scanner would redact into a marker.
        assert!(
            detail["created_kid"].as_str().expect("created_kid").starts_with("sha256:"),
            "{detail}"
        );

        sink.verify_chain(&TenantId::new("demo")).await.expect("the chain still verifies");

        // A sweep that changed nothing writes nothing: a trail with one "no
        // change" record per minute is a trail nobody reads.
        repo.apply_schedule(SigningAlgorithm::EdDsa, t0).await.expect("sweep");
        let count: i64 = sqlx::query_scalar("select count(*) from audit_events where tenant_id = 'demo'")
            .fetch_one(&db.pool)
            .await
            .expect("count");
        assert_eq!(count, 2);
    }
}

db_test! {
    /// FAPI 2.0 SP §6.8 item 2: "single purpose keys are recommended. For
    /// example, it is not recomended to use the same key for signing and
    /// encryption." A P-256 or RSA key pair is usable for both operations, so
    /// nothing about the key type prevents the reuse — the schema has to.
    async fn one_key_cannot_be_stored_for_both_signing_and_encryption(db) {
        seed_tenant(&db.pool, "demo").await;
        let repo = keys(&db.pool, "demo");
        repo.rotate(SigningAlgorithm::EdDsa, operator(), epoch()).await.expect("rotate");

        let row = sqlx::query("select kid, public_jwk from signing_keys where tenant_id = 'demo'")
            .fetch_one(&db.pool)
            .await
            .expect("read the key");
        let kid: String = row.get("kid");
        let mut jwk: serde_json::Value = row.get("public_jwk");
        jwk["use"] = json!("enc");

        // Same key, same kid, second purpose: the primary key refuses it,
        // because the kid is the thumbprint of the material.
        let same_kid = sqlx::query(
            "insert into signing_keys (tenant_id, kid, alg, purpose, public_jwk,
                                       private_key_ciphertext, private_key_nonce, kek_id, state)
             values ('demo', $1, 'EdDSA', 'enc', $2, repeat('\\001', 64)::bytea,
                     repeat('\\002', 12)::bytea, 'local:x', 'pending')",
        )
        .bind(&kid)
        .bind(&jwk)
        .execute(&db.pool)
        .await;
        assert!(same_kid.is_err(), "the same key was stored twice, once per purpose");

        // Same key material under a fresh kid: the material index refuses it,
        // which is what catches a kid that was not computed honestly.
        let new_kid = sqlx::query(
            "insert into signing_keys (tenant_id, kid, alg, purpose, public_jwk,
                                       private_key_ciphertext, private_key_nonce, kek_id, state)
             values ('demo', 'a-kid-of-my-own-choosing', 'EdDSA', 'enc', $1,
                     repeat('\\001', 64)::bytea, repeat('\\003', 12)::bytea, 'local:x', 'pending')",
        )
        .bind(&jwk)
        .execute(&db.pool)
        .await;
        assert!(new_kid.is_err(), "the same key material was stored under two kids");

        // And a row may not advertise a purpose other than the one it is
        // stored under, or the JWKS would say `enc` while the signer used it.
        let lying = sqlx::query(
            "insert into signing_keys (tenant_id, kid, alg, purpose, public_jwk,
                                       private_key_ciphertext, private_key_nonce, kek_id, state)
             values ('demo', 'another-kid', 'EdDSA', 'sig',
                     '{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"unique-material\",\"use\":\"enc\"}'::jsonb,
                     repeat('\\001', 64)::bytea, repeat('\\004', 12)::bytea, 'local:x', 'pending')",
        )
        .execute(&db.pool)
        .await;
        assert!(lying.is_err(), "a signing key was published as an encryption key");
    }
}

db_test! {
    /// An encryption key must never be reachable through the signing path, even
    /// when one exists for the same algorithm. `purpose` is in the `where`
    /// clause of every query here, not applied by the caller.
    async fn the_signing_path_never_selects_an_encryption_key(db) {
        seed_tenant(&db.pool, "demo").await;
        let repo = keys(&db.pool, "demo");
        let signing = repo
            .rotate(SigningAlgorithm::EdDsa, operator(), epoch())
            .await
            .expect("rotate")
            .created
            .expect("created");

        // A hand-written encryption key of the same algorithm, also active.
        sqlx::query(
            "insert into signing_keys (tenant_id, kid, alg, purpose, public_jwk,
                                       private_key_ciphertext, private_key_nonce, kek_id,
                                       state, activated_at)
             values ('demo', 'an-encryption-key', 'EdDSA', 'enc',
                     '{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"enc-material\",\"use\":\"enc\"}'::jsonb,
                     repeat('\\001', 64)::bytea, repeat('\\005', 12)::bytea, 'local:x',
                     'active', now())",
        )
        .execute(&db.pool)
        .await
        .expect("an encryption key may exist alongside a signing key");

        let (kid, _) = repo
            .active_signing_key(SigningAlgorithm::EdDsa)
            .await
            .expect("read")
            .expect("an active signing key");
        assert_eq!(kid, signing, "the signing path picked up an encryption key");

        // It is published — a JWKS carries both — but as what it is.
        let purposes: Vec<KeyPurpose> = repo
            .published_keys(&TenantId::new("demo"))
            .await
            .expect("published")
            .into_iter()
            .map(|key| key.purpose)
            .collect();
        assert!(purposes.contains(&KeyPurpose::Signing));
        assert!(purposes.contains(&KeyPurpose::Encryption));
    }
}

db_test! {
    /// **The acceptance criterion of `ast-f7m.7`, against the real schema.**
    ///
    /// An operator pressing "rotate and sign immediately" must end with a new
    /// `kid` signing *and* the one it replaced still in the JWK Set. OIDC Core
    /// §10.1.1 asks for the second half in as many words — the set "SHOULD
    /// retain recently decommissioned signing keys for a reasonable period of
    /// time to facilitate a smooth transition" — and without it every token
    /// issued a minute before the rotation stops verifying.
    async fn an_immediate_rotation_activates_a_new_kid_and_keeps_the_previous_published(db) {
        seed_tenant(&db.pool, "demo").await;
        let repo = keys(&db.pool, "demo");
        let t0 = epoch();

        // Arrange: a tenant already signing, as every live tenant is.
        let incumbent = repo
            .rotate(SigningAlgorithm::EdDsa, operator(), t0)
            .await
            .expect("first key")
            .created
            .expect("a first key is created active");

        // Act: stage a successor and promote it in the same breath, well
        // inside the propagation period.
        let staged = repo
            .rotate(SigningAlgorithm::EdDsa, operator(), t0)
            .await
            .expect("rotate")
            .created
            .expect("a successor was staged");
        let promoted = repo.activate(&staged, operator(), t0).await.expect("activate");

        // Assert
        assert_eq!(promoted.activated.as_ref(), Some(&staged));
        assert_eq!(
            promoted.superseded.as_ref(),
            Some(&incumbent),
            "the rotation did not report which key it displaced"
        );

        let published = published(&repo, "demo").await;
        assert_eq!(
            published.iter().find(|(kid, _)| kid == &staged).map(|(_, state)| *state),
            Some(KeyState::Active),
            "the new key is not signing: {published:?}"
        );
        assert_eq!(
            published.iter().find(|(kid, _)| kid == &incumbent).map(|(_, state)| *state),
            Some(KeyState::Retiring),
            "the superseded key left the JWK Set, so tokens it signed stop \
             verifying: {published:?}"
        );

        // And exactly one key signs: the partial unique index is what makes
        // "which key signs this" have one answer.
        let active: i64 = sqlx::query_scalar(
            "select count(*) from signing_keys
             where tenant_id = 'demo' and alg = 'EdDSA' and purpose = 'sig' and state = 'active'",
        )
        .fetch_one(&db.pool)
        .await
        .expect("count");
        assert_eq!(active, 1);
    }
}

db_test! {
    /// Retiring the key an algorithm signs with would leave the tenant unable
    /// to issue a token of that algorithm — a denial of service one click deep,
    /// reachable by a mis-click and reached for deliberately by anybody who has
    /// got into the console. Rotation is the operation that replaces an active
    /// key, and it puts the successor in place first.
    async fn the_active_key_is_not_retirable(db) {
        seed_tenant(&db.pool, "demo").await;
        let repo = keys(&db.pool, "demo");
        let t0 = epoch();
        let active = repo
            .rotate(SigningAlgorithm::EdDsa, operator(), t0)
            .await
            .expect("first key")
            .created
            .expect("created");

        let refused = repo.retire(&active, operator(), t0).await;

        assert!(
            matches!(refused, Err(DomainError::Conflict(_))),
            "the active key was retirable: {refused:?}"
        );
        assert_eq!(
            published(&repo, "demo").await,
            [(active, KeyState::Active)],
            "a refused retirement changed the key set"
        );
    }
}

db_test! {
    /// A staged key an operator no longer wants never signed anything, so
    /// dropping it costs nothing — and the schema anticipates it: a key retired
    /// straight out of `pending` needs only the final stamp.
    async fn a_staged_key_can_be_retired_before_it_ever_signs(db) {
        seed_tenant(&db.pool, "demo").await;
        let repo = keys(&db.pool, "demo");
        let t0 = epoch();
        let active = repo
            .rotate(SigningAlgorithm::EdDsa, operator(), t0)
            .await
            .expect("first key")
            .created
            .expect("created");
        let staged = repo
            .rotate(SigningAlgorithm::EdDsa, operator(), t0)
            .await
            .expect("rotate")
            .created
            .expect("staged");

        let retired = repo.retire(&staged, operator(), t0).await.expect("retire");

        assert_eq!(retired.retired, vec![staged.clone()]);
        assert_eq!(
            published(&repo, "demo").await,
            [(active, KeyState::Active)],
            "a retired key is still published"
        );
        // The row stays, so the kid is never reused and an incident review can
        // still see the key existed.
        let inventory: Vec<(Kid, KeyState)> = repo
            .inventory()
            .await
            .expect("inventory")
            .into_iter()
            .map(|key| (key.kid, key.state))
            .collect();
        assert!(
            inventory.contains(&(staged, KeyState::Retired)),
            "the retired key left the inventory: {inventory:?}"
        );
    }
}

db_test! {
    /// The whole compromise path, end to end, and the property that makes a
    /// purge different from a retirement: the private half stops existing.
    ///
    /// FAPI 2.0 SP §6.8 is about shrinking "the time window in which a
    /// compromised key can be used". Retiring shuts the window on this
    /// deployment; only destroying the material shuts it on a backup taken
    /// afterwards. So the operator's sequence is: rotate with immediate
    /// activation, which installs a successor and pushes the suspect key into
    /// `retiring` — and then purge it.
    async fn the_compromise_path_destroys_the_key_it_replaces(db) {
        // Arrange: a tenant signing with a key that is about to be believed
        // compromised, and a token it signed.
        seed_tenant(&db.pool, "demo").await;
        let repo = keys(&db.pool, "demo");
        let t0 = epoch();
        let leaked = repo
            .rotate(SigningAlgorithm::EdDsa, operator(), t0)
            .await
            .expect("first key")
            .created
            .expect("created");
        let (_, key) = repo
            .active_signing_key(SigningAlgorithm::EdDsa)
            .await
            .expect("read")
            .expect("an active key");
        let token = jws::sign(&key, &leaked, "at+jwt", &json!({"sub": "alice"})).expect("sign");

        // Act: a successor signs from now on, then the leaked key is destroyed.
        let successor = repo
            .rotate(SigningAlgorithm::EdDsa, operator(), t0)
            .await
            .expect("rotate")
            .created
            .expect("staged");
        repo.activate(&successor, operator(), t0).await.expect("promote the successor");
        let reason = PurgeReason::parse("private key found in a public bucket, INC-42")
            .expect("a reason");
        let purge = repo.purge(&leaked, &reason, operator(), t0).await.expect("purge");

        // Assert: the call says what it did.
        assert_eq!(purge.kid, leaked);
        assert_eq!(purge.previous_state, KeyState::Retiring);
        assert!(purge.destroyed, "the purge reported destroying nothing");

        // The material is gone from the row — and the row is not.
        let row = sqlx::query(
            "select private_key_ciphertext, private_key_nonce, kek_id, state, purged_at
             from signing_keys where tenant_id = 'demo' and kid = $1",
        )
        .bind(leaked.as_str())
        .fetch_one(&db.pool)
        .await
        .expect("the row survives so the kid is never reused");
        assert_eq!(row.get::<Option<Vec<u8>>, _>("private_key_ciphertext"), None);
        assert_eq!(row.get::<Option<Vec<u8>>, _>("private_key_nonce"), None);
        assert_eq!(row.get::<Option<String>, _>("kek_id"), None);
        assert_eq!(row.get::<String, _>("state"), "purged");
        assert!(row.get::<Option<OffsetDateTime>, _>("purged_at").is_some());

        // Nothing publishes it, and nothing resolves it: a signature it made is
        // no longer checkable against anything this server will hand out. That
        // is the point of a purge rather than a side effect of it — the tokens
        // an attacker minted with the leaked key are exactly what must stop
        // being accepted.
        let published = published(&repo, "demo").await;
        assert!(
            !published.iter().any(|(kid, _)| kid == &leaked),
            "a purged key is still published: {published:?}"
        );
        assert_eq!(
            repo.public_key(&TenantId::new("demo"), &leaked).await.expect("read"),
            None,
            "the key store still resolves a purged kid, so its signatures still verify"
        );
        assert_eq!(
            jws::parse(token.as_str()).expect("parse").kid().as_ref(),
            Some(&leaked),
            "the token under test was signed by some other key"
        );

        // The successor is untouched: the tenant can still issue tokens.
        assert_eq!(
            repo.active_signing_key(SigningAlgorithm::EdDsa)
                .await
                .expect("read")
                .expect("an active key")
                .0,
            successor
        );

        // And the inventory still shows the purged key, because an incident
        // review asks about exactly the keys nothing publishes any more.
        let inventory: Vec<(Kid, KeyState)> = repo
            .inventory()
            .await
            .expect("inventory")
            .into_iter()
            .map(|key| (key.kid, key.state))
            .collect();
        assert!(
            inventory.contains(&(leaked, KeyState::Purged)),
            "the purged key left the inventory: {inventory:?}"
        );
    }
}

db_test! {
    /// Destroying the key a tenant signs with leaves it unable to issue a
    /// token — the same denial of service `retire` refuses, and worse, because
    /// this one is not reversible even by an operator with `psql`. The
    /// compromise path installs a successor first.
    async fn the_active_key_is_not_purgeable(db) {
        // Arrange
        seed_tenant(&db.pool, "demo").await;
        let repo = keys(&db.pool, "demo");
        let t0 = epoch();
        let active = repo
            .rotate(SigningAlgorithm::EdDsa, operator(), t0)
            .await
            .expect("first key")
            .created
            .expect("created");
        let reason = PurgeReason::parse("suspected compromise").expect("a reason");

        // Act
        let refused = repo.purge(&active, &reason, operator(), t0).await;

        // Assert
        assert!(
            matches!(refused, Err(DomainError::Conflict(_))),
            "the active key was purgeable: {refused:?}"
        );
        assert_eq!(
            published(&repo, "demo").await,
            [(active.clone(), KeyState::Active)],
            "a refused purge changed the key set"
        );
        let ciphertext: Option<Vec<u8>> = sqlx::query_scalar(
            "select private_key_ciphertext from signing_keys where tenant_id = 'demo' and kid = $1",
        )
        .bind(active.as_str())
        .fetch_one(&db.pool)
        .await
        .expect("read");
        assert!(ciphertext.is_some(), "a refused purge destroyed the material anyway");
    }
}

db_test! {
    /// A purge is the event an incident review starts from, and a record of it
    /// that does not say why is one nobody can review. The reason is required
    /// by the type, and it reaches the trail.
    async fn a_purge_is_recorded_with_its_reason(db) {
        // Arrange
        seed_tenant(&db.pool, "demo").await;
        let repo = keys(&db.pool, "demo");
        let sink = PgAuditSink::new(db.pool.clone());
        let t0 = epoch();
        repo.rotate(SigningAlgorithm::EdDsa, operator(), t0).await.expect("first key");
        let staged = repo
            .rotate(SigningAlgorithm::EdDsa, operator(), t0)
            .await
            .expect("rotate")
            .created
            .expect("staged");
        let reason = PurgeReason::parse("laptop with the KEK backup stolen, INC-7")
            .expect("a reason");

        // Act
        repo.purge(&staged, &reason, operator(), t0).await.expect("purge");

        // Assert
        let recorded: Vec<String> = sqlx::query_scalar(
            "select event_type from audit_events where tenant_id = 'demo' order by event_id",
        )
        .fetch_all(&db.pool)
        .await
        .expect("read the trail");
        assert_eq!(
            recorded,
            ["key.rotated", "key.rotated", "key.purged"],
            "a purge is not a rotation and must not be filed as one"
        );

        let row = sqlx::query(
            "select actor, detail from audit_events
             where tenant_id = 'demo' and event_type = 'key.purged'",
        )
        .fetch_one(&db.pool)
        .await
        .expect("read the purge record");
        assert_eq!(row.get::<serde_json::Value, _>("actor")["type"], "admin");
        let detail: serde_json::Value = row.get("detail");
        assert_eq!(detail["reason"], "laptop with the KEK backup stolen, INC-7");
        assert_eq!(detail["alg"], "EdDSA");
        assert_eq!(detail["previous_state"], "pending");
        // The kid is recorded the way every other key event records it: a
        // correlatable digest rather than free text the scanner would redact.
        assert!(
            detail["kid"].as_str().expect("kid").starts_with("sha256:"),
            "{detail}"
        );

        sink.verify_chain(&TenantId::new("demo")).await.expect("the chain still verifies");
    }
}

db_test! {
    /// Purging a key somebody already purged is what a retried request looks
    /// like, not a failure — but it is also not a second destruction, and the
    /// answer says which of the two happened.
    async fn purging_a_purged_key_destroys_nothing_and_is_not_an_error(db) {
        // Arrange
        seed_tenant(&db.pool, "demo").await;
        let repo = keys(&db.pool, "demo");
        let t0 = epoch();
        repo.rotate(SigningAlgorithm::EdDsa, operator(), t0).await.expect("first key");
        let staged = repo
            .rotate(SigningAlgorithm::EdDsa, operator(), t0)
            .await
            .expect("rotate")
            .created
            .expect("staged");
        let reason = PurgeReason::parse("INC-7").expect("a reason");
        repo.purge(&staged, &reason, operator(), t0).await.expect("purge");

        // Act
        let again = repo.purge(&staged, &reason, operator(), t0).await.expect("purge again");

        // Assert
        assert!(!again.destroyed, "a repeat purge claimed to destroy material twice");
        assert_eq!(again.previous_state, KeyState::Purged);
        let purges: i64 = sqlx::query_scalar(
            "select count(*) from audit_events
             where tenant_id = 'demo' and event_type = 'key.purged'",
        )
        .fetch_one(&db.pool)
        .await
        .expect("count");
        assert_eq!(purges, 1, "a purge that destroyed nothing was recorded as an incident");
    }
}

db_test! {
    /// A `kid` this tenant does not hold is not a key it can destroy, whichever
    /// tenant does hold it. Every statement binds the repository's tenant, so a
    /// `kid` copied from a sibling's console finds nothing.
    async fn a_kid_from_another_tenant_is_not_purgeable(db) {
        // Arrange
        seed_tenant(&db.pool, "alpha").await;
        seed_tenant(&db.pool, "beta").await;
        let t0 = epoch();
        let alphas = keys(&db.pool, "alpha")
            .rotate(SigningAlgorithm::EdDsa, operator(), t0)
            .await
            .expect("rotate")
            .created
            .expect("created");
        let reason = PurgeReason::parse("INC-7").expect("a reason");

        // Act
        let refused = keys(&db.pool, "beta").purge(&alphas, &reason, operator(), t0).await;

        // Assert
        assert!(
            matches!(refused, Err(DomainError::NotFound)),
            "one tenant destroyed another's key: {refused:?}"
        );
    }
}

db_test! {
    /// A `kid` this tenant does not hold is not a key it can retire, whichever
    /// tenant does hold it. The repository is scoped to one tenant and every
    /// statement binds it, so a `kid` copied from a sibling's console finds
    /// nothing.
    async fn a_kid_from_another_tenant_is_not_found(db) {
        seed_tenant(&db.pool, "alpha").await;
        seed_tenant(&db.pool, "beta").await;
        let t0 = epoch();
        let alphas = keys(&db.pool, "alpha")
            .rotate(SigningAlgorithm::EdDsa, operator(), t0)
            .await
            .expect("rotate")
            .created
            .expect("created");

        let refused = keys(&db.pool, "beta").retire(&alphas, operator(), t0).await;

        assert!(
            matches!(refused, Err(DomainError::NotFound)),
            "one tenant retired another's key: {refused:?}"
        );
    }
}

db_test! {
    /// A key that has stopped signing is never brought back. The reason it
    /// stopped may have been a compromise, and "reactivate" is the one button
    /// that would undo an incident response.
    async fn a_key_that_stopped_signing_is_not_reactivated(db) {
        seed_tenant(&db.pool, "demo").await;
        let repo = keys(&db.pool, "demo");
        let t0 = epoch();
        let first = repo
            .rotate(SigningAlgorithm::EdDsa, operator(), t0)
            .await
            .expect("first key")
            .created
            .expect("created");
        let second = repo
            .rotate(SigningAlgorithm::EdDsa, operator(), t0)
            .await
            .expect("rotate")
            .created
            .expect("staged");
        repo.activate(&second, operator(), t0).await.expect("promote the successor");

        let refused = repo.activate(&first, operator(), t0).await;

        assert!(
            matches!(refused, Err(DomainError::Conflict(_))),
            "a retiring key was made to sign again: {refused:?}"
        );
    }
}

db_test! {
    /// The console's inventory is wider than the JWK Set on purpose: a retired
    /// key must not be published, and an operator asking "what happened to that
    /// kid?" is asking about exactly the keys the JWK Set no longer names.
    async fn the_inventory_shows_keys_the_jwk_set_no_longer_does(db) {
        seed_tenant(&db.pool, "demo").await;
        let repo = keys(&db.pool, "demo");
        let t0 = epoch();
        repo.rotate(SigningAlgorithm::EdDsa, operator(), t0).await.expect("first key");
        let staged = repo
            .rotate(SigningAlgorithm::EdDsa, operator(), t0)
            .await
            .expect("rotate")
            .created
            .expect("staged");
        repo.retire(&staged, operator(), t0).await.expect("retire");

        let inventory = repo.inventory().await.expect("inventory");

        assert_eq!(inventory.len(), 2, "the inventory dropped a row");
        assert_eq!(
            published(&repo, "demo").await.len(),
            1,
            "a retired key is still published"
        );
        // Never any private material: the record type carries a public JWK and
        // no other key bytes, so this is a property of the port rather than of
        // a query listing columns carefully.
        for key in inventory {
            assert!(
                key.public_jwk.get("d").is_none(),
                "a private member reached a public key record: {}",
                key.public_jwk
            );
        }
    }
}

/// Inserts a `signing_keys` row by hand, the way a seed script or somebody in
/// a `psql` session during an incident would. The point of every test that uses
/// it is that the schema refuses on its own, without the repository's help.
async fn insert_key_row(
    pool: &PgPool,
    tenant: &str,
    kid: &str,
    state: &str,
    material: &str,
    nonce_seed: &str,
    kek_id: &str,
) -> Result<(), sqlx::Error> {
    let activated = if state == "pending" { "null" } else { "now()" };
    let statement = format!(
        "insert into signing_keys (tenant_id, kid, alg, purpose, public_jwk,
                                   private_key_ciphertext, private_key_nonce, kek_id,
                                   state, activated_at)
         values ('{tenant}', '{kid}', 'EdDSA', 'sig',
                 jsonb_build_object('kty', 'OKP', 'crv', 'Ed25519',
                                    'x', '{material}', 'use', 'sig'),
                 repeat('\\001', 64)::bytea,
                 substring(decode(md5('{nonce_seed}'), 'hex') from 1 for 12),
                 '{kek_id}', '{state}', {activated})"
    );
    sqlx::query(&statement).execute(pool).await.map(|_| ())
}

db_test! {
    /// AES-GCM loses confidentiality *and* authenticity if one nonce is used
    /// twice under one key (NIST SP 800-38D §8). The provider draws the nonce,
    /// so this is the belt to that braces: the table refuses to hold a repeat.
    async fn a_nonce_cannot_repeat_under_one_key_encryption_key(db) {
        seed_tenant(&db.pool, "alpha").await;
        seed_tenant(&db.pool, "beta").await;

        insert_key_row(&db.pool, "alpha", "k1", "pending", "m1", "n1", "local:one")
            .await
            .expect("the first key");

        // A different tenant and a different key, but the same nonce under the
        // same key-encryption key: still a total break, so still refused.
        let repeat =
            insert_key_row(&db.pool, "beta", "k2", "pending", "m2", "n1", "local:one").await;
        assert!(repeat.is_err(), "a nonce was reused under one key-encryption key");

        // The same nonce under a *different* KEK is not a reuse at all.
        insert_key_row(&db.pool, "beta", "k3", "pending", "m3", "n1", "local:two")
            .await
            .expect("a different KEK");
        insert_key_row(&db.pool, "alpha", "k4", "active", "m4", "n2", "local:one")
            .await
            .expect("a fresh nonce");
    }
}

db_test! {
    /// "Which key signs this" must have exactly one answer. Two active keys for
    /// one algorithm would make the choice depend on row order.
    async fn the_schema_refuses_two_active_keys_for_one_algorithm(db) {
        seed_tenant(&db.pool, "demo").await;
        let insert = async |kid: &str, material: &str, state: &str| {
            insert_key_row(&db.pool, "demo", kid, state, material, kid, "local:one").await
        };

        insert("k1", "m1", "active").await.expect("the first active key");
        assert!(
            insert("k2", "m2", "active").await.is_err(),
            "two active keys were accepted"
        );
        insert("k3", "m3", "pending").await.expect("the first pending key");
        assert!(
            insert("k4", "m4", "pending").await.is_err(),
            "two pending keys were accepted"
        );

        // A state that does not match its timestamps is a row nobody can read
        // afterwards, so it cannot be written.
        let inconsistent = sqlx::query(
            "insert into signing_keys (tenant_id, kid, alg, purpose, public_jwk,
                                       private_key_ciphertext, private_key_nonce, kek_id,
                                       state, activated_at)
             values ('demo', 'k5', 'ES256', 'sig',
                     '{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"m5\",\"y\":\"m5\",\"use\":\"sig\"}'::jsonb,
                     repeat('\\001', 64)::bytea,
                     substring(decode(md5('k5'), 'hex') from 1 for 12), 'local:one',
                     'active', null)",
        )
        .execute(&db.pool)
        .await;
        assert!(inconsistent.is_err(), "an active key with no activated_at was accepted");
    }
}

db_test! {
    /// The rotation policy is per tenant and exists from the first use, because
    /// a policy that only applies once somebody sets it is a policy most
    /// deployments never get (FAPI 2.0 SP §6.8 item 1).
    async fn a_rotation_schedule_defaults_on_first_use_and_can_be_replaced(db) {
        seed_tenant(&db.pool, "demo").await;
        let repo = keys(&db.pool, "demo");

        let default = repo.schedule(SigningAlgorithm::DEFAULT).await.expect("schedule");
        assert_eq!(default.rotation_period, Duration::days(90));
        assert_eq!(default.propagation_period, Duration::minutes(15));
        assert_eq!(default.grace_period, Duration::days(7));
        assert_eq!(default.last_rotated_at, None);
        assert!(default.is_due(epoch()), "a tenant with no key must always be due");

        repo.set_schedule(SigningAlgorithm::DEFAULT, RotationSchedule {
            rotation_period: Duration::days(1),
            propagation_period: Duration::minutes(5),
            grace_period: Duration::hours(6),
            last_rotated_at: None,
        })
        .await
        .expect("replace the schedule");

        let updated = repo.schedule(SigningAlgorithm::DEFAULT).await.expect("schedule");
        assert_eq!(updated.rotation_period, Duration::days(1));
        assert_eq!(updated.propagation_period, Duration::minutes(5));
        assert_eq!(updated.grace_period, Duration::hours(6));

        // A rotation records when it happened, and the sweep stages a new key
        // only once the period has passed.
        let t0 = epoch();
        repo.rotate(SigningAlgorithm::EdDsa, operator(), t0).await.expect("rotate");
        assert_eq!(repo.schedule(SigningAlgorithm::DEFAULT).await.expect("schedule").last_rotated_at, Some(t0));

        let too_soon = repo
            .apply_schedule(SigningAlgorithm::EdDsa, t0 + Duration::hours(23))
            .await
            .expect("sweep");
        assert_eq!(too_soon.created, None, "the sweep rotated before the period elapsed");

        let due = repo
            .apply_schedule(SigningAlgorithm::EdDsa, t0 + Duration::days(1))
            .await
            .expect("sweep");
        assert!(due.created.is_some(), "the sweep did not rotate when the period elapsed");
    }
}

db_test! {
    /// A schedule the schema will not hold must be refused rather than
    /// truncated: a propagation period of zero means signing with a key no
    /// verifier has had the chance to fetch.
    async fn a_schedule_that_defeats_the_procedure_is_refused(db) {
        seed_tenant(&db.pool, "demo").await;
        let repo = keys(&db.pool, "demo");

        for (label, schedule) in [
            (
                "zero propagation",
                RotationSchedule {
                    rotation_period: Duration::days(90),
                    propagation_period: Duration::ZERO,
                    grace_period: Duration::days(7),
                    last_rotated_at: None,
                },
            ),
            (
                "a rotation period of a minute",
                RotationSchedule {
                    rotation_period: Duration::minutes(1),
                    propagation_period: Duration::seconds(1),
                    grace_period: Duration::days(7),
                    last_rotated_at: None,
                },
            ),
            (
                "zero grace",
                RotationSchedule {
                    rotation_period: Duration::days(90),
                    propagation_period: Duration::minutes(15),
                    grace_period: Duration::ZERO,
                    last_rotated_at: None,
                },
            ),
            (
                "propagation longer than the rotation period",
                RotationSchedule {
                    rotation_period: Duration::hours(2),
                    propagation_period: Duration::hours(3),
                    grace_period: Duration::days(7),
                    last_rotated_at: None,
                },
            ),
        ] {
            assert!(
                repo.set_schedule(SigningAlgorithm::DEFAULT, schedule).await.is_err(),
                "the schema accepted {label}"
            );
        }
    }
}

db_test! {
    /// A repository is scoped to one tenant, and the scope is the tenant. A key
    /// belonging to another one must not be reachable through this handle even
    /// when the caller names it.
    async fn a_scoped_key_lookup_never_answers_for_another_tenant(db) {
        seed_tenant(&db.pool, "alpha").await;
        seed_tenant(&db.pool, "beta").await;
        let alpha = keys(&db.pool, "alpha");
        let beta = keys(&db.pool, "beta");
        let t0 = epoch();

        let alpha_kid = alpha
            .rotate(SigningAlgorithm::EdDsa, operator(), t0)
            .await
            .expect("rotate")
            .created
            .expect("created");
        beta.rotate(SigningAlgorithm::EdDsa, operator(), t0).await.expect("rotate");

        assert!(
            beta.public_key(&TenantId::new("beta"), &alpha_kid).await.expect("read").is_none(),
            "one tenant's kid resolved in another tenant"
        );
        assert_eq!(published(&beta, "beta").await.len(), 1);

        // Asking a scoped repository about a different tenant is a bug in the
        // caller, not a query to run.
        assert!(beta.published_keys(&TenantId::new("alpha")).await.is_err());
        assert!(beta.public_key(&TenantId::new("alpha"), &alpha_kid).await.is_err());
    }
}

db_test! {
    /// Rows get edited during incidents. A row that no longer describes a key
    /// this profile would publish must fail to load rather than reach a JWKS.
    async fn a_key_row_edited_into_something_unpublishable_refuses_to_load(db) {
        seed_tenant(&db.pool, "demo").await;
        let repo = keys(&db.pool, "demo");
        repo.rotate(SigningAlgorithm::EdDsa, operator(), epoch()).await.expect("rotate");

        // Disable the constraints the way someone with SQL access would, then
        // make the published `use` disagree with the stored purpose.
        sqlx::query("alter table signing_keys drop constraint signing_keys_jwk_use_matches_purpose")
            .execute(&db.pool)
            .await
            .expect("drop the constraint");
        sqlx::query("update signing_keys set public_jwk = jsonb_set(public_jwk, '{use}', '\"enc\"')")
            .execute(&db.pool)
            .await
            .expect("tamper");

        let error = repo
            .published_keys(&TenantId::new("demo"))
            .await
            .expect_err("a key whose use disagrees with its purpose must not publish");
        assert!(error.to_string().contains("public_jwk"), "{error}");
    }
}

// ---------------------------------------------------------------------------
// Users, claims and subject identifiers
// ---------------------------------------------------------------------------

use asterius_domain::{
    Claim, ClaimName, ClaimSet, ClaimSource, PairwiseSalt, SectorIdentifier, SubjectId, User,
    UserId, UserStatus,
};
use asterius_jose::{KeyBinding, TenantSecret};
use asterius_store_pg::PgUserRepository;

fn users(pool: &PgPool, tenant: &str) -> PgUserRepository {
    PgUserRepository::new(pool.clone(), TenantId::new(tenant), kek())
}

/// A fixed salt. Constant on purpose: an assertion about which `sub` a sector
/// sees can only be made against a salt the test still holds. Written into the
/// tenant's row by [`seed_salt`], so the repository reads back exactly this.
fn salt() -> PairwiseSalt {
    PairwiseSalt::from_bytes([0x5c; PairwiseSalt::LEN])
}

/// Gives a raw-SQL-seeded tenant the salt [`salt`] returns, sealed the way the
/// adapter seals it.
///
/// `seed_tenant` writes a bare `tenants` row, which is what an operator's
/// `INSERT` looks like and what most tests here want. A tenant that mints
/// subjects needs the salt as well, and needs it to be a *known* one, or no
/// test could assert which `sub` a sector sees.
async fn seed_salt(pool: &PgPool, tenant: &str) {
    let id = TenantId::new(tenant);
    let sealed = kek()
        .seal(
            KeyBinding::tenant_secret(&id, TenantSecret::PairwiseSalt),
            salt().expose(),
        )
        .expect("seal the salt");
    sqlx::query(
        "insert into tenant_pairwise_salts (tenant_id, salt_ciphertext, salt_nonce, kek_id)
         values ($1, $2, $3, $4)",
    )
    .bind(tenant)
    .bind(sealed.ciphertext())
    .bind(sealed.nonce())
    .bind(sealed.kek_id())
    .execute(pool)
    .await
    .expect("seed the pairwise salt");
}

fn sector(host: &str) -> SectorIdentifier {
    SectorIdentifier::stored(host).expect("a storable sector")
}

fn claim_name(raw: &str) -> ClaimName {
    ClaimName::parse(raw).expect("a claim name")
}

/// A user carrying one claim of each shape the model can hold: a plain value, a
/// language-tagged one that another party verified, and a nested object another
/// issuer asserted.
fn a_user(tenant: &str, id: UserId, username: &str) -> User {
    let mut claims = ClaimSet::new();
    claims.insert(
        claim_name("name"),
        Claim::new(serde_json::json!("Alice Example"), ClaimSource::Local).expect("a claim"),
    );
    claims.insert(
        claim_name("family_name#ja-Kana-JP"),
        Claim::new(serde_json::json!("クドウ"), ClaimSource::Admin)
            .expect("a claim")
            .verified(OffsetDateTime::UNIX_EPOCH),
    );
    claims.insert(
        claim_name("address"),
        Claim::new(
            serde_json::json!({ "country": "FR", "locality": "Lyon" }),
            ClaimSource::Issuer(
                asterius_domain::Issuer::parse("https://op.example").expect("an issuer"),
            ),
        )
        .expect("a claim"),
    );
    User {
        tenant: TenantId::new(tenant),
        id,
        username: username.to_owned(),
        email: Some(format!("{username}@example.test")),
        email_verified: true,
        status: UserStatus::Active,
        claims,
        created_at: OffsetDateTime::UNIX_EPOCH,
        updated_at: OffsetDateTime::UNIX_EPOCH,
    }
}

db_test! {
    /// The claim bag is JSONB, so nothing but this round trip says that what
    /// was stored is what comes back — including a language-tagged name, a
    /// nested object and a claim another issuer asserted.
    async fn a_user_round_trips_with_every_shape_of_claim_intact(db) {
        seed_tenant(&db.pool, "demo").await;
        let repo = users(&db.pool, "demo");
        let alice = a_user("demo", UserId::generate(), "alice");
        repo.upsert(&alice).await.expect("insert");

        let found = repo.find(alice.id).await.expect("find").expect("present");
        assert_eq!(found.claims, alice.claims);
        assert_eq!(found.username, "alice");
        assert_eq!(found.email.as_deref(), Some("alice@example.test"));
        assert!(found.email_verified);
        assert!(found.can_authenticate());
        // Timestamps come from the database, not from the entity passed in.
        assert!(found.created_at > OffsetDateTime::UNIX_EPOCH);

        assert_eq!(
            repo.find_by_username("alice").await.expect("find").expect("present").id,
            alice.id
        );
        assert!(repo.find_by_username("absent").await.expect("find").is_none());
        assert!(repo.find(UserId::generate()).await.expect("find").is_none());
    }
}

db_test! {
    /// Rows get edited by hand during incidents, and JSONB will hold anything.
    /// A bag that has grown a `sub` claim is an impersonation primitive the
    /// moment the claims service projects it, so the row must fail to load.
    async fn a_claim_bag_edited_into_something_the_model_refuses_fails_to_load(db) {
        seed_tenant(&db.pool, "demo").await;
        let repo = users(&db.pool, "demo");
        let alice = a_user("demo", UserId::generate(), "alice");
        repo.upsert(&alice).await.expect("insert");

        for hostile in [
            r#"{"sub": {"value": "victim", "source": "admin"}}"#,
            r#"{"email": {"value": "victim@example.test", "source": "admin"}}"#,
            r#"{"name": {"value": null, "source": "admin"}}"#,
            r#"{"name": {"value": "x", "source": "whoever"}}"#,
        ] {
            sqlx::query("update users set claims = $1::jsonb where tenant_id = 'demo'")
                .bind(hostile)
                .execute(&db.pool)
                .await
                .expect("tamper");
            let error = repo
                .find(alice.id)
                .await
                .expect_err("a bag the model refuses must not load");
            assert!(error.to_string().contains("claims"), "{hostile}: {error}");
        }
    }
}

db_test! {
    /// OIDC Core §8.1: the calculation is deterministic and the identifier is
    /// stable, so a relying party's account for a person does not move.
    async fn one_user_in_one_sector_always_sees_the_same_subject(db) {
        seed_tenant(&db.pool, "demo").await;
        seed_salt(&db.pool, "demo").await;
        let repo = users(&db.pool, "demo");
        let alice = a_user("demo", UserId::generate(), "alice");
        repo.upsert(&alice).await.expect("insert");

        let first = repo.subject(alice.id, &sector("rp.example")).await.expect("mint");
        let again = repo.subject(alice.id, &sector("rp.example")).await.expect("read");
        assert_eq!(first, again);
        // And it is the derivation, not something the database invented.
        assert_eq!(first, salt().derive_subject(&sector("rp.example"), alice.id));

        // One row, not two: minting twice must not accumulate identities.
        let rows: i64 = sqlx::query_scalar(
            "select count(*) from subject_identifiers where tenant_id = 'demo'",
        )
        .fetch_one(&db.pool)
        .await
        .expect("count");
        assert_eq!(rows, 1);
    }
}

db_test! {
    /// The whole privacy claim of a pairwise subject (OIDC Core §8): two
    /// relying parties comparing notes must not be able to tell that they are
    /// talking about one person.
    async fn two_sectors_never_see_one_user_under_the_same_subject(db) {
        seed_tenant(&db.pool, "demo").await;
        seed_salt(&db.pool, "demo").await;
        let repo = users(&db.pool, "demo");
        let alice = a_user("demo", UserId::generate(), "alice");
        repo.upsert(&alice).await.expect("insert");

        let here = repo.subject(alice.id, &sector("rp.example")).await.expect("mint");
        let there = repo.subject(alice.id, &sector("other.example")).await.expect("mint");
        let public = repo
            .subject(alice.id, &SectorIdentifier::public())
            .await
            .expect("mint");
        assert_ne!(here, there);
        assert_ne!(here, public);
        assert_ne!(there, public);

        // Every one of them resolves back to the same person, which is the
        // property UserInfo depends on.
        for subject in [&here, &there, &public] {
            assert_eq!(
                repo.find_by_subject(subject).await.expect("find").expect("present").id,
                alice.id
            );
        }

        // A public subject lives under the sentinel sector the schema is built
        // around, so both subject types are one row shape.
        let sectors: Vec<String> = sqlx::query_scalar(
            "select sector_identifier from subject_identifiers
             where tenant_id = 'demo' order by sector_identifier",
        )
        .fetch_all(&db.pool)
        .await
        .expect("read sectors");
        assert_eq!(sectors, ["", "other.example", "rp.example"]);

        let listed = repo.subjects(alice.id).await.expect("list");
        assert_eq!(listed.len(), 3);
        assert!(listed[0].0.is_public());
    }
}

db_test! {
    /// A subject is a relying party's primary key for a person. Two people
    /// sharing one is the outcome this table exists to make impossible, so the
    /// database refuses the write rather than the application noticing later.
    async fn two_users_cannot_be_given_the_same_subject(db) {
        seed_tenant(&db.pool, "demo").await;
        seed_salt(&db.pool, "demo").await;
        let repo = users(&db.pool, "demo");
        let alice = a_user("demo", UserId::generate(), "alice");
        let bob = a_user("demo", UserId::generate(), "bob");
        repo.upsert(&alice).await.expect("insert alice");
        repo.upsert(&bob).await.expect("insert bob");

        let alices = repo.subject(alice.id, &sector("rp.example")).await.expect("mint");

        // The derivation cannot produce a collision, so provoke one the way a
        // botched import would: write Alice's `sub` against Bob.
        let clash = sqlx::query(
            "insert into subject_identifiers (tenant_id, user_id, sector_identifier, subject)
             values ('demo', $1, 'other.example', $2)",
        )
        .bind(bob.id.as_uuid())
        .bind(alices.as_str())
        .execute(&db.pool)
        .await;
        assert!(clash.is_err(), "two users were given one subject");
    }
}

db_test! {
    /// A repository is scoped to one tenant, and the scope is the tenant. A
    /// user, a username and a `sub` belonging to another tenant must all be
    /// unreachable through this handle.
    async fn a_user_lookup_never_answers_for_another_tenant(db) {
        seed_tenant(&db.pool, "alpha").await;
        seed_tenant(&db.pool, "beta").await;
        seed_salt(&db.pool, "alpha").await;
        seed_salt(&db.pool, "beta").await;
        let store = Store::from_pool(db.pool.clone());
        let alpha_scope = store.scope(TenantId::new("alpha"));
        let beta_scope = store.scope(TenantId::new("beta"));
        let alpha = alpha_scope.users(kek());
        let beta = beta_scope.users(kek());
        assert_eq!(alpha.tenant().as_str(), "alpha");

        // The same username in both tenants: the unique index is per tenant, so
        // one tenant's accounts do not constrain another's.
        let here = a_user("alpha", UserId::generate(), "alice");
        let there = a_user("beta", UserId::generate(), "alice");
        alpha.upsert(&here).await.expect("insert into alpha");
        beta.upsert(&there).await.expect("insert into beta");

        assert!(beta.find(here.id).await.expect("find").is_none());
        assert_eq!(
            beta.find_by_username("alice").await.expect("find").expect("present").id,
            there.id
        );

        let subject = alpha.subject(here.id, &sector("rp.example")).await.expect("mint");
        assert!(
            beta.find_by_subject(&subject).await.expect("find").is_none(),
            "one tenant's subject resolved in another"
        );
        // Two tenants derive different subjects for one sector even when they
        // share a salt, because the local account ids differ.
        let theirs = beta.subject(there.id, &sector("rp.example")).await.expect("mint");
        assert_ne!(subject, theirs);

        // Writing an entity from another tenant through this handle is a bug in
        // the caller, not a query to run.
        assert!(beta.upsert(&here).await.is_err());
    }
}

db_test! {
    /// Deleting a user takes every identity they were known by with it. A row
    /// that survives its user is a row nobody owns — and, for a `sub`, a
    /// relying party's account with nothing behind it.
    async fn deleting_a_user_takes_every_subject_identifier_with_it(db) {
        seed_tenant(&db.pool, "demo").await;
        seed_salt(&db.pool, "demo").await;
        let repo = users(&db.pool, "demo");
        let alice = a_user("demo", UserId::generate(), "alice");
        let bob = a_user("demo", UserId::generate(), "bob");
        repo.upsert(&alice).await.expect("insert alice");
        repo.upsert(&bob).await.expect("insert bob");
        repo.subject(alice.id, &sector("rp.example")).await.expect("mint");
        repo.subject(bob.id, &sector("rp.example")).await.expect("mint");

        repo.delete(alice.id).await.expect("delete");
        assert!(repo.find(alice.id).await.expect("find").is_none());
        assert!(matches!(
            repo.delete(alice.id).await,
            Err(asterius_domain::DomainError::NotFound)
        ));

        let remaining: Vec<uuid::Uuid> = sqlx::query_scalar(
            "select user_id from subject_identifiers where tenant_id = 'demo'",
        )
        .fetch_all(&db.pool)
        .await
        .expect("read subjects");
        assert_eq!(remaining, [*bob.id.as_uuid()], "the cascade left an orphan sub");
    }
}

db_test! {
    /// `ast-2vk.12`. OIDC Core §8 makes a Subject Identifier "never
    /// reassigned", and the cascade above deletes the row that reserved it —
    /// so without a tombstone the value is free again the moment an account is
    /// deleted. Nothing reissues one in practice, because the local account id
    /// is a random UUID nobody reuses, but "never in practice" is not the
    /// guarantee a relying party that keyed its own records on `sub` was given.
    ///
    /// The restored user carries the *same* local account id, which is the only
    /// way a deterministic derivation can be made to produce the old value: an
    /// operator restoring an account from a backup, or an import that preserves
    /// ids, gets there without trying.
    async fn a_deleted_users_subject_is_never_reissued(db) {
        seed_tenant(&db.pool, "demo").await;
        seed_salt(&db.pool, "demo").await;
        let repo = users(&db.pool, "demo");
        let alice = a_user("demo", UserId::generate(), "alice");
        repo.upsert(&alice).await.expect("insert alice");
        let public = repo
            .subject(alice.id, &SectorIdentifier::public())
            .await
            .expect("mint");
        let pairwise = repo.subject(alice.id, &sector("rp.example")).await.expect("mint");

        repo.delete(alice.id).await.expect("delete");

        let tombstoned: Vec<String> = sqlx::query_scalar(
            "select subject from retired_subject_identifiers
              where tenant_id = 'demo' order by subject",
        )
        .fetch_all(&db.pool)
        .await
        .expect("read tombstones");
        let mut expected = vec![public.as_str().to_owned(), pairwise.as_str().to_owned()];
        expected.sort();
        assert_eq!(tombstoned, expected, "a deleted sub left no tombstone behind");

        // The same person, restored under the same local account id. The
        // derivation is deterministic, so it produces the retired value — and
        // must refuse rather than hand it out a second time.
        let restored = a_user("demo", alice.id, "alice");
        repo.upsert(&restored).await.expect("restore alice");
        let refused = repo.subject(restored.id, &sector("rp.example")).await;
        assert!(
            matches!(refused, Err(asterius_domain::DomainError::Conflict(_))),
            "a retired subject was reissued: {refused:?}"
        );
        assert!(
            repo.find_by_subject(&pairwise).await.expect("resolve").is_none(),
            "a retired sub resolves to the account that took its place"
        );
    }
}

db_test! {
    /// The collision the refusal is written for, forced by hand: a tombstone
    /// holding exactly what the derivation is about to produce. It should never
    /// happen — the inputs are a per-tenant secret salt and a random UUID — but
    /// "should never" is what the refusal is for, and the alternative reading
    /// (derive something else and hand that over) is the reassignment OIDC Core
    /// §8 rules out.
    async fn a_derivation_that_lands_on_a_tombstone_is_refused(db) {
        seed_tenant(&db.pool, "demo").await;
        seed_salt(&db.pool, "demo").await;
        let repo = users(&db.pool, "demo");
        let carol = a_user("demo", UserId::generate(), "carol");
        repo.upsert(&carol).await.expect("insert carol");
        // What the derivation produces for this user and sector, learned the
        // only way a test can: by asking for it once.
        let minted = repo.subject(carol.id, &sector("rp.example")).await.expect("mint");
        sqlx::query("delete from subject_identifiers where tenant_id = 'demo'")
            .execute(&db.pool)
            .await
            .expect("drop the reservation");
        sqlx::query(
            "insert into retired_subject_identifiers (tenant_id, subject, sector_identifier)
             values ('demo', $1, 'rp.example') on conflict do nothing",
        )
        .bind(minted.as_str())
        .execute(&db.pool)
        .await
        .expect("tombstone the value");

        let refused = repo.subject(carol.id, &sector("rp.example")).await;

        assert!(
            matches!(refused, Err(asterius_domain::DomainError::Conflict(_))),
            "the derivation reissued a tombstoned value: {refused:?}"
        );
        let reserved: i64 = sqlx::query_scalar(
            "select count(*) from subject_identifiers where tenant_id = 'demo'",
        )
        .fetch_one(&db.pool)
        .await
        .expect("count reservations");
        assert_eq!(reserved, 0, "the refused derivation still wrote a reservation");
    }
}

db_test! {
    /// The refusal is recorded, because a collision that nobody sees is a
    /// collision nobody investigates — and this one says either that a SHA-256
    /// preimage turned up or that a local account id was reused.
    async fn a_refused_derivation_is_audited(db) {
        seed_tenant(&db.pool, "demo").await;
        seed_salt(&db.pool, "demo").await;
        let repo = users(&db.pool, "demo");
        let carol = a_user("demo", UserId::generate(), "carol");
        repo.upsert(&carol).await.expect("insert carol");
        let minted = repo.subject(carol.id, &sector("rp.example")).await.expect("mint");
        sqlx::query("delete from subject_identifiers where tenant_id = 'demo'")
            .execute(&db.pool)
            .await
            .expect("drop the reservation");

        assert!(repo.subject(carol.id, &sector("rp.example")).await.is_err());

        let recorded: Vec<String> = sqlx::query_scalar(
            "select event_type from audit_events where tenant_id = 'demo' and subject = $1",
        )
        .bind(minted.as_str())
        .fetch_all(&db.pool)
        .await
        .expect("read the trail");
        assert_eq!(
            recorded,
            ["subject.collision"],
            "a refused derivation left no record"
        );
    }
}

db_test! {
    /// The guarantee is in the schema and not only on the path above: a
    /// tombstoned value cannot be reserved by any statement that reaches the
    /// database, including one this crate does not own.
    async fn the_database_refuses_to_reserve_a_tombstoned_subject(db) {
        seed_tenant(&db.pool, "demo").await;
        let user = UserId::generate();
        sqlx::query("insert into users (tenant_id, user_id, username) values ('demo', $1, 'dave')")
            .bind(user.as_uuid())
            .execute(&db.pool)
            .await
            .expect("seed user");
        sqlx::query(
            "insert into retired_subject_identifiers (tenant_id, subject)
             values ('demo', 'retired')",
        )
        .execute(&db.pool)
        .await
        .expect("tombstone");

        let refused = sqlx::query(
            "insert into subject_identifiers (tenant_id, user_id, sector_identifier, subject)
             values ('demo', $1, 'rp.example', 'retired')",
        )
        .bind(user.as_uuid())
        .execute(&db.pool)
        .await;

        assert!(refused.is_err(), "the database reserved a retired subject");
    }
}

db_test! {
    /// A tombstone that can be deleted is not a tombstone. Refused in the
    /// database for the same reason `audit_events` is append-only: the row
    /// exists to outlive the code that wrote it.
    async fn a_tombstone_cannot_be_deleted_or_updated(db) {
        seed_tenant(&db.pool, "demo").await;
        sqlx::query(
            "insert into retired_subject_identifiers (tenant_id, subject) values ('demo', 'gone')",
        )
        .execute(&db.pool)
        .await
        .expect("tombstone");

        assert!(
            sqlx::query("delete from retired_subject_identifiers where tenant_id = 'demo'")
                .execute(&db.pool)
                .await
                .is_err(),
            "a tombstone was deleted"
        );
        assert!(
            sqlx::query(
                "update retired_subject_identifiers set subject = 'other'
                  where tenant_id = 'demo'",
            )
            .execute(&db.pool)
            .await
            .is_err(),
            "a tombstone was rewritten"
        );
    }
}

db_test! {
    /// The tombstone outlives the tenant too. Deleting a tenant cascades over
    /// `users` and therefore over every reservation; if the tombstones went
    /// with them, recreating a tenant under the same id — the same issuer, as
    /// far as a relying party can tell — would free every `sub` in it.
    async fn a_tombstone_outlives_the_tenant(db) {
        let tenants = PgTenantRepository::new(db.pool.clone(), kek());
        tenants.upsert(&tenant("demo", "https://as.example/t/demo")).await.expect("insert");
        let repo = users(&db.pool, "demo");
        let alice = a_user("demo", UserId::generate(), "alice");
        repo.upsert(&alice).await.expect("insert alice");
        let subject = repo.subject(alice.id, &sector("rp.example")).await.expect("mint");

        tenants.delete(&TenantId::new("demo")).await.expect("delete the tenant");

        let tombstoned: Vec<String> =
            sqlx::query_scalar("select subject from retired_subject_identifiers")
                .fetch_all(&db.pool)
                .await
                .expect("read tombstones");
        assert_eq!(tombstoned, [subject.as_str().to_owned()]);
    }
}

db_test! {
    /// The reason the column is JSONB (`ast-s36.5`, `ast-s36.6`): a claim the
    /// schema has never heard of is a write, not a migration.
    async fn a_claim_the_schema_has_never_heard_of_needs_no_migration(db) {
        seed_tenant(&db.pool, "demo").await;
        let repo = users(&db.pool, "demo");
        let mut alice = a_user("demo", UserId::generate(), "alice");
        repo.upsert(&alice).await.expect("insert");

        alice.claims.insert(
            claim_name("https://claims.example/employee_number"),
            Claim::new(serde_json::json!(42), ClaimSource::Import).expect("a claim"),
        );
        alice.claims.insert(
            claim_name("zoneinfo"),
            Claim::new(serde_json::json!("Europe/Paris"), ClaimSource::Local).expect("a claim"),
        );
        repo.upsert(&alice).await.expect("update");

        let found = repo.find(alice.id).await.expect("find").expect("present");
        assert_eq!(found.claims, alice.claims);
        assert_eq!(found.claims.len(), 5);
        assert_eq!(
            found.claims.get(&claim_name("zoneinfo")).map(Claim::value),
            Some(&serde_json::json!("Europe/Paris"))
        );
    }
}

db_test! {
    /// A user record is not the place to say who somebody is, and a derived
    /// subject is something the rest of the server can carry: OIDC Core §8 caps
    /// a `sub` at 255 ASCII characters and it travels in a URL and a JWT.
    async fn a_user_record_cannot_be_given_a_claim_the_server_issues(db) {
        seed_tenant(&db.pool, "demo").await;
        for reserved in ["sub", "iss", "aud", "acr", "cnf", "email", "updated_at"] {
            assert!(
                ClaimName::parse(reserved).is_err(),
                "{reserved} was accepted as a user claim"
            );
        }
        let derived = salt().derive_subject(&sector("rp.example"), UserId::generate());
        assert_eq!(derived.as_str().len(), 43);
        assert!(SubjectId::new(derived.as_str().to_owned()).as_str().len() <= 255);
    }
}

db_test! {
    /// The property `salt_ciphertext` exists for: what is written down is not
    /// the salt. Read the bytes straight out of the row — an encryption claim
    /// proved against the API that wrote it proves only that the API is
    /// self-consistent.
    ///
    /// A leaked salt lets anybody holding a dump re-derive, or confirm, every
    /// pairwise `sub` in the tenant, which is the entire property pairwise
    /// subjects exist to provide (OIDC Core §8.1: "MUST NOT be reversible by
    /// any party other than the OpenID Provider").
    async fn the_stored_pairwise_salt_is_ciphertext_and_not_a_salt(db) {
        let repo = PgTenantRepository::new(db.pool.clone(), kek());
        repo.upsert(&tenant("demo", "https://demo.example")).await.expect("create");

        let row = sqlx::query(
            "select salt_ciphertext, salt_nonce, kek_id
             from tenant_pairwise_salts where tenant_id = 'demo'",
        )
        .fetch_one(&db.pool)
        .await
        .expect("the tenant should have a salt");
        let ciphertext: Vec<u8> = row.get("salt_ciphertext");

        // The plaintext is whatever `generate` drew, so recover it the only way
        // there is — through the KEK — and then look for it in the column.
        let sealed = asterius_jose::WrappedKey::from_parts(
            row.get::<String, _>("kek_id"),
            row.get::<Vec<u8>, _>("salt_nonce"),
            ciphertext.clone(),
        )
        .expect("a well-formed row");
        let plaintext = kek()
            .open(
                KeyBinding::tenant_secret(&TenantId::new("demo"), TenantSecret::PairwiseSalt),
                &sealed,
            )
            .expect("the row must open under the KEK that sealed it");
        assert_eq!(plaintext.len(), PairwiseSalt::LEN);

        assert_ne!(ciphertext.as_slice(), plaintext.as_slice(), "the column is the salt");
        // Not even a window of it. Eight bytes is already enough to halve the
        // search space for the rest.
        for window in plaintext.windows(8) {
            assert!(
                !ciphertext.windows(8).any(|candidate| candidate == window),
                "an 8-byte run of the salt is stored verbatim"
            );
        }
        // Ciphertext plus the GCM tag, and a 96-bit nonce beside it.
        assert_eq!(ciphertext.len(), PairwiseSalt::LEN + 16);
        assert_eq!(row.get::<Vec<u8>, _>("salt_nonce").len(), 12);
        assert!(row.get::<String, _>("kek_id").starts_with("local:"));

        // And the salt is not sitting in `tenants` in some other form either.
        let elsewhere: Vec<String> = sqlx::query_scalar(
            "select column_name from information_schema.columns
             where table_schema = $1 and table_name = 'tenants'",
        )
        .bind(db.schema())
        .fetch_all(&db.pool)
        .await
        .expect("read information_schema");
        assert!(
            !elsewhere.iter().any(|column| column.contains("salt")),
            "the tenants table grew a salt column: {elsewhere:?}"
        );
    }
}

db_test! {
    /// A tenant gets its salt when it is created, and never gets another one.
    /// "Generated once" is the property the whole design rests on: a second
    /// salt would make the same user in the same sector derive differently, and
    /// OIDC Core §8 says a Subject Identifier is never reassigned.
    async fn a_tenant_is_created_with_a_salt_and_never_given_a_second_one(db) {
        let repo = PgTenantRepository::new(db.pool.clone(), kek());
        let mut demo = tenant("demo", "https://demo.example");
        repo.upsert(&demo).await.expect("create");

        let first: Vec<u8> = sqlx::query_scalar(
            "select salt_ciphertext from tenant_pairwise_salts where tenant_id = 'demo'",
        )
        .fetch_one(&db.pool)
        .await
        .expect("a salt");

        // Updating the tenant must not disturb it, however many times.
        demo.display_name = "Renamed".to_owned();
        repo.upsert(&demo).await.expect("update");
        repo.upsert(&demo).await.expect("update again");

        let after: Vec<u8> = sqlx::query_scalar(
            "select salt_ciphertext from tenant_pairwise_salts where tenant_id = 'demo'",
        )
        .fetch_one(&db.pool)
        .await
        .expect("still one salt");
        assert_eq!(first, after, "a tenant update replaced the pairwise salt");

        let rows: i64 = sqlx::query_scalar("select count(*) from tenant_pairwise_salts")
            .fetch_one(&db.pool)
            .await
            .expect("count");
        assert_eq!(rows, 1);

        // Two tenants do not share one, or their subjects would correlate.
        repo.upsert(&tenant("other", "https://other.example")).await.expect("create");
        let salts: Vec<Vec<u8>> = sqlx::query_scalar(
            "select salt_ciphertext from tenant_pairwise_salts order by tenant_id",
        )
        .fetch_all(&db.pool)
        .await
        .expect("read salts");
        assert_eq!(salts.len(), 2);
        assert_ne!(salts[0], salts[1]);
    }
}

db_test! {
    /// Rotation is refused by the database, not merely unimplemented above it.
    /// Every `sub` already derived under this salt has been handed to a relying
    /// party and stored; replacing the salt would reassign identifiers OIDC
    /// Core §8 says are never reassigned.
    async fn a_pairwise_salt_cannot_be_rotated(db) {
        seed_tenant(&db.pool, "demo").await;
        seed_salt(&db.pool, "demo").await;

        for statement in [
            "update tenant_pairwise_salts set salt_ciphertext = salt_ciphertext",
            "update tenant_pairwise_salts set kek_id = 'local:elsewhere'",
            "update tenant_pairwise_salts set tenant_id = 'demo'",
        ] {
            let refused = sqlx::query(statement).execute(&db.pool).await;
            assert!(refused.is_err(), "the schema accepted: {statement}");
        }

        // The salt still opens, so the refusal did not corrupt anything.
        let repo = users(&db.pool, "demo");
        let alice = a_user("demo", UserId::generate(), "alice");
        repo.upsert(&alice).await.expect("insert");
        assert_eq!(
            repo.subject(alice.id, &sector("rp.example")).await.expect("mint"),
            salt().derive_subject(&sector("rp.example"), alice.id)
        );
    }
}

db_test! {
    /// A tenant with no salt must refuse to mint rather than fall back to a
    /// default or empty one. An empty salt would leave the derivation with no
    /// secret in it at all, so every `sub` in the deployment would be derivable
    /// by anyone who knows the algorithm — and, because the first derivation is
    /// the one stored and given to a relying party, it could never be withdrawn.
    async fn a_tenant_without_a_salt_refuses_to_mint_a_subject(db) {
        // Seeded with raw SQL and no salt row, which is what an operator's
        // `INSERT` — or a botched import — produces.
        seed_tenant(&db.pool, "demo").await;
        let repo = users(&db.pool, "demo");
        let alice = a_user("demo", UserId::generate(), "alice");
        repo.upsert(&alice).await.expect("insert");

        let error = repo
            .subject(alice.id, &sector("rp.example"))
            .await
            .expect_err("a tenant with no salt must not mint a subject");
        assert!(
            error.to_string().contains("pairwise_salt"),
            "the refusal should name the missing salt: {error}"
        );

        // And nothing was written, so a later mint under the real salt is still
        // the first one.
        let rows: i64 = sqlx::query_scalar("select count(*) from subject_identifiers")
            .fetch_one(&db.pool)
            .await
            .expect("count");
        assert_eq!(rows, 0, "a subject was minted without a salt");

        seed_salt(&db.pool, "demo").await;
        assert_eq!(
            repo.subject(alice.id, &sector("rp.example")).await.expect("mint"),
            salt().derive_subject(&sector("rp.example"), alice.id)
        );
    }
}

db_test! {
    /// The identifier a relying party holds must survive a restart. Two
    /// repositories built separately — different handles, nothing shared but
    /// the database and the KEK — must derive the same `sub` for the same user
    /// in the same sector, and different ones across sectors.
    ///
    /// This is the property that broke when the salt was an argument: two call
    /// sites could disagree and both look correct.
    async fn two_separate_repositories_agree_on_a_users_subject(db) {
        seed_tenant(&db.pool, "demo").await;
        seed_salt(&db.pool, "demo").await;
        let alice = a_user("demo", UserId::generate(), "alice");
        users(&db.pool, "demo").upsert(&alice).await.expect("insert");

        let here = users(&db.pool, "demo");
        let there = users(&db.pool, "demo");
        assert_eq!(
            here.subject(alice.id, &sector("rp.example")).await.expect("mint"),
            there.subject(alice.id, &sector("rp.example")).await.expect("read"),
            "two repositories disagreed about a user's subject"
        );

        // Different sectors, different subjects — from either handle.
        let rp = here.subject(alice.id, &sector("rp.example")).await.expect("mint");
        let other = there.subject(alice.id, &sector("other.example")).await.expect("mint");
        let public = there.subject(alice.id, &SectorIdentifier::public()).await.expect("mint");
        assert_ne!(rp, other);
        assert_ne!(rp, public);
        assert_ne!(other, public);

        // A repository holding a different KEK cannot open the salt at all,
        // which is what makes the ciphertext worth writing.
        let wrong = PgUserRepository::new(
            db.pool.clone(),
            TenantId::new("demo"),
            Arc::new(LocalKek::from_bytes(&[0x11; 32]).expect("a 32-byte KEK")),
        );
        assert!(
            wrong.subject(alice.id, &sector("rp.example")).await.is_err(),
            "the salt opened under a key-encryption key that did not seal it"
        );
    }
}

db_test! {
    /// The ciphertext is bound to its tenant, so a salt copied into another
    /// tenant's row is not a salt any more. Without the binding, an attacker
    /// with an `UPDATE` could give two tenants one salt — and two tenants
    /// sharing a salt are two tenants whose `sub` values correlate for any user
    /// whose local account id is known.
    async fn a_pairwise_salt_moved_to_another_tenant_stops_decrypting(db) {
        seed_tenant(&db.pool, "alpha").await;
        seed_tenant(&db.pool, "beta").await;
        seed_salt(&db.pool, "alpha").await;

        let alice = a_user("beta", UserId::generate(), "alice");
        users(&db.pool, "beta").upsert(&alice).await.expect("insert");

        // Copying the row wholesale is refused before the cryptography is even
        // consulted: the nonce index means one nonce may exist once per KEK.
        let row = sqlx::query(
            "select salt_ciphertext, salt_nonce, kek_id
             from tenant_pairwise_salts where tenant_id = 'alpha'",
        )
        .fetch_one(&db.pool)
        .await
        .expect("alpha's salt");
        let plant = |tenant: &'static str| {
            sqlx::query(
                "insert into tenant_pairwise_salts (tenant_id, salt_ciphertext, salt_nonce, kek_id)
                 values ($1, $2, $3, $4)",
            )
            .bind(tenant)
            .bind(row.get::<Vec<u8>, _>("salt_ciphertext"))
            .bind(row.get::<Vec<u8>, _>("salt_nonce"))
            .bind(row.get::<String, _>("kek_id"))
            .execute(&db.pool)
        };
        assert!(
            plant("beta").await.is_err(),
            "one nonce was accepted twice under one key-encryption key"
        );

        // So move it the way a restore from another tenant's backup would: the
        // original is gone, and the bytes arrive under a new owner. Now only
        // the binding is left to refuse it.
        sqlx::query("delete from tenant_pairwise_salts where tenant_id = 'alpha'")
            .execute(&db.pool)
            .await
            .expect("remove the original");
        plant("beta").await.expect("plant the row");

        let error = users(&db.pool, "beta")
            .subject(alice.id, &sector("rp.example"))
            .await
            .expect_err("a moved salt must not decrypt");
        assert!(
            matches!(error, asterius_domain::DomainError::Storage(_)),
            "expected a storage failure, got {error:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Single-use `jti` enforcement (ast-m9c.2)

mod replay {
    use super::*;
    use asterius_domain::keys::SigningAlgorithm;
    use asterius_domain::{ReplayCheck, ReplayGuard, ReplayPurpose};
    use asterius_store_pg::PgReplayGuard;
    use serde_json::json;
    use time::Duration;

    fn later() -> OffsetDateTime {
        OffsetDateTime::now_utc() + time::Duration::minutes(5)
    }

    db_test! {
        /// RFC 7523 §3 item 7. The whole defence in one assertion: a captured
        /// assertion is a bearer credential, and this is what stops it being
        /// spent twice.
        async fn a_jti_can_be_claimed_once(db) {
            seed_tenant(&db.pool, "demo").await;
            let guard = PgReplayGuard::new(db.pool.clone());
            let tenant = TenantId::new("demo");

            assert_eq!(
                guard.claim(&tenant, ReplayPurpose::ClientAssertion, "billing", "jti-1", later())
                    .await
                    .expect("first claim"),
                ReplayCheck::FirstUse
            );
            assert_eq!(
                guard.claim(&tenant, ReplayPurpose::ClientAssertion, "billing", "jti-1", later())
                    .await
                    .expect("second claim"),
                ReplayCheck::Replay
            );
        }
    }

    db_test! {
        /// The namespace is per client, not per tenant.
        ///
        /// A shared namespace would let any registered client burn likely
        /// `jti` values — "1", a guessable UUID — and deny service to every
        /// other client in the tenant. RFC 7523 §3 item 7 scopes uniqueness to
        /// the issuer of the assertion, which is the client.
        async fn two_clients_may_choose_the_same_jti(db) {
            seed_tenant(&db.pool, "demo").await;
            let guard = PgReplayGuard::new(db.pool.clone());
            let tenant = TenantId::new("demo");

            for client in ["billing", "reporting"] {
                assert_eq!(
                    guard.claim(&tenant, ReplayPurpose::ClientAssertion, client, "1", later())
                        .await
                        .expect("claim"),
                    ReplayCheck::FirstUse,
                    "{client} was denied a jti another client had used"
                );
            }
        }
    }

    db_test! {
        /// Two tenants, and two purposes, are likewise separate namespaces.
        async fn tenants_and_purposes_do_not_share_a_namespace(db) {
            seed_tenant(&db.pool, "demo").await;
            seed_tenant(&db.pool, "other").await;
            let guard = PgReplayGuard::new(db.pool.clone());

            for tenant in ["demo", "other"] {
                for purpose in [ReplayPurpose::ClientAssertion, ReplayPurpose::DpopProof] {
                    assert_eq!(
                        guard.claim(&TenantId::new(tenant), purpose, "billing", "shared", later())
                            .await
                            .expect("claim"),
                        ReplayCheck::FirstUse,
                        "{tenant}/{} collided with another namespace", purpose.as_str()
                    );
                }
            }
        }
    }

    db_test! {
        /// The property the whole design rests on: the check and the record are
        /// one statement, so concurrent replays cannot both win.
        ///
        /// A read followed by a write would pass every test above and fail this
        /// one — which is exactly the race an attacker replaying a captured
        /// assertion is trying to hit.
        async fn concurrent_claims_of_one_jti_yield_exactly_one_first_use(db) {
            seed_tenant(&db.pool, "demo").await;
            let guard = std::sync::Arc::new(PgReplayGuard::new(db.pool.clone()));
            let expires = later();

            let attempts: Vec<_> = (0..16)
                .map(|_| {
                    let guard = guard.clone();
                    tokio::spawn(async move {
                        guard
                            .claim(
                                &TenantId::new("demo"),
                                ReplayPurpose::ClientAssertion,
                                "billing",
                                "contested",
                                expires,
                            )
                            .await
                            .expect("claim")
                    })
                })
                .collect();

            let mut first_uses = 0;
            for attempt in attempts {
                if attempt.await.expect("task") == ReplayCheck::FirstUse {
                    first_uses += 1;
                }
            }
            assert_eq!(
                first_uses, 1,
                "16 concurrent claims of one jti produced {first_uses} first uses"
            );
        }
    }

    db_test! {
        /// Retention drops what has expired, and only for the tenant asked.
        async fn purging_removes_expired_rows_of_one_tenant_only(db) {
            seed_tenant(&db.pool, "demo").await;
            seed_tenant(&db.pool, "other").await;
            let guard = PgReplayGuard::new(db.pool.clone());
            let now = OffsetDateTime::now_utc();
            let past = now - time::Duration::minutes(1);

            for tenant in ["demo", "other"] {
                let t = TenantId::new(tenant);
                // Seeding: the verdict is not the point here, the row is.
                let _ = guard
                    .claim(&t, ReplayPurpose::ClientAssertion, "billing", "stale", past)
                    .await
                    .expect("stale");
                let _ = guard
                    .claim(&t, ReplayPurpose::ClientAssertion, "billing", "live", later())
                    .await
                    .expect("live");
            }

            let removed = guard
                .purge_expired(&TenantId::new("demo"), now)
                .await
                .expect("purge");
            assert_eq!(removed, 1, "purged something other than the one stale row");

            // The purged value is claimable again; the live one is not.
            assert_eq!(
                guard.claim(&TenantId::new("demo"), ReplayPurpose::ClientAssertion, "billing", "stale", later())
                    .await
                    .expect("claim"),
                ReplayCheck::FirstUse
            );
            assert_eq!(
                guard.claim(&TenantId::new("demo"), ReplayPurpose::ClientAssertion, "billing", "live", later())
                    .await
                    .expect("claim"),
                ReplayCheck::Replay
            );
            // The other tenant was not touched.
            assert_eq!(
                guard.claim(&TenantId::new("other"), ReplayPurpose::ClientAssertion, "billing", "stale", later())
                    .await
                    .expect("claim"),
                ReplayCheck::Replay,
                "purging one tenant removed another tenant's rows"
            );
        }
    }

    db_test! {
        /// The client-chosen `jti` is stored as a digest, not as itself.
        async fn the_stored_identifier_is_a_digest_not_the_clients_string(db) {
            seed_tenant(&db.pool, "demo").await;
            let guard = PgReplayGuard::new(db.pool.clone());
            let jti = "a-very-recognisable-value";
            let _ = guard
                .claim(&TenantId::new("demo"), ReplayPurpose::ClientAssertion, "billing", jti, later())
                .await
                .expect("claim");

            let stored: Vec<u8> = sqlx::query_scalar(
                "select jti_hash from jti_replay where tenant_id = $1 and subject = $2",
            )
            .bind("demo")
            .bind("billing")
            .fetch_one(&db.pool)
            .await
            .expect("read back");

            assert_eq!(stored.len(), 32, "not a SHA-256 digest");
            assert_eq!(stored, asterius_domain::sha256(jti.as_bytes()));
            assert!(
                !String::from_utf8_lossy(&stored).contains(jti),
                "the client's own string reached the column"
            );
        }
    }

    // -----------------------------------------------------------------------
    // DPoP proofs (ast-a05.6)

    /// A real DPoP proof, signed with a real key.
    ///
    /// The point of building it here rather than hand-writing a `jti` is that
    /// the values reaching the store are the ones the checker actually
    /// produces: the subject is the RFC 7638 thumbprint of the proof's key and
    /// the expiry is the end of the proof's own acceptance window. A test that
    /// invented them would keep passing if either changed.
    fn a_dpop_proof(key: &asterius_jose::SigningKey, jti: &str) -> asterius_jose::dpop::Proof {
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;

        let mut jwk = key.public_jwk().expect("jwk");
        if let Some(object) = jwk.as_object_mut() {
            object.remove("use");
        }
        let now = OffsetDateTime::now_utc();
        let header = json!({ "typ": "dpop+jwt", "alg": key.algorithm().as_str(), "jwk": jwk });
        let claims = json!({
            "jti": jti,
            "htm": "POST",
            "htu": "https://as.example/t/demo/token",
            "iat": now.unix_timestamp(),
        });
        let signing_input = format!(
            "{}.{}",
            B64.encode(serde_json::to_vec(&header).expect("header")),
            B64.encode(serde_json::to_vec(&claims).expect("claims"))
        );
        let signature = key.sign(signing_input.as_bytes()).expect("sign");
        let token = format!("{signing_input}.{}", B64.encode(signature));

        let uri = asterius_jose::dpop::NormalisedUri::parse("https://as.example/t/demo/token")
            .expect("endpoint");
        asterius_jose::dpop::check(
            &token,
            &asterius_jose::dpop::Expectation::new("POST", &uri),
            now,
        )
        .expect("a proof this test just signed")
    }

    db_test! {
        /// RFC 9449 §11.1: a captured proof is replayable at the endpoint it
        /// was made for until its `iat` window closes, and the `jti` is what
        /// closes the gap. This is that defence over the real store.
        ///
        /// The `subject` is the key's thumbprint, which is what
        /// `ReplayGuard::claim`'s documentation specifies for a DPoP proof —
        /// and it is the only value available: a proof is presented before the
        /// client is known, and often by a client that has no identity at this
        /// endpoint at all.
        async fn a_dpop_proofs_jti_can_be_claimed_once(db) {
            seed_tenant(&db.pool, "demo").await;
            let guard = PgReplayGuard::new(db.pool.clone());
            let tenant = TenantId::new("demo");
            let key = asterius_jose::SigningKey::generate(SigningAlgorithm::EdDsa)
                .expect("generate");
            let proof = a_dpop_proof(&key, "dpop-jti-1");

            assert_eq!(
                guard.claim(
                    &tenant,
                    ReplayPurpose::DpopProof,
                    proof.jkt.as_str(),
                    &proof.jti,
                    proof.replay_expires_at,
                ).await.expect("first claim"),
                ReplayCheck::FirstUse
            );
            assert_eq!(
                guard.claim(
                    &tenant,
                    ReplayPurpose::DpopProof,
                    proof.jkt.as_str(),
                    &proof.jti,
                    proof.replay_expires_at,
                ).await.expect("second claim"),
                ReplayCheck::Replay,
                "a captured DPoP proof was accepted twice"
            );
        }
    }

    db_test! {
        /// The namespace is the key, not the tenant and not the client.
        ///
        /// Two keys choosing the same `jti` is not a replay — it is two
        /// unrelated clients that both used a UUID library, or one client that
        /// rotated its DPoP key. A shared namespace would let whoever gets
        /// there first deny service to the other, and a DPoP key needs no
        /// registration, so "whoever gets there first" is anybody at all.
        async fn two_dpop_keys_may_choose_the_same_jti(db) {
            seed_tenant(&db.pool, "demo").await;
            let guard = PgReplayGuard::new(db.pool.clone());
            let tenant = TenantId::new("demo");

            let mut thumbprints = std::collections::HashSet::new();
            for _ in 0..2 {
                let key = asterius_jose::SigningKey::generate(SigningAlgorithm::EdDsa)
                    .expect("generate");
                let proof = a_dpop_proof(&key, "contested");
                assert!(
                    thumbprints.insert(proof.jkt.as_str().to_owned()),
                    "two generated keys share a thumbprint"
                );
                assert_eq!(
                    guard.claim(
                        &tenant,
                        ReplayPurpose::DpopProof,
                        proof.jkt.as_str(),
                        &proof.jti,
                        proof.replay_expires_at,
                    ).await.expect("claim"),
                    ReplayCheck::FirstUse,
                    "a key was denied a jti another key had used"
                );
            }
        }
    }

    db_test! {
        /// A DPoP proof and a client assertion that happen to choose the same
        /// `jti` are unrelated events, even from the same party.
        ///
        /// Worth its own case because the two share a table: a client
        /// authenticating with `private_key_jwt` and presenting a DPoP proof in
        /// the same request could plausibly reuse one identifier, and being
        /// told its proof was a replay would be a failure with no cause.
        async fn a_dpop_proof_and_a_client_assertion_do_not_share_a_namespace(db) {
            seed_tenant(&db.pool, "demo").await;
            let guard = PgReplayGuard::new(db.pool.clone());
            let tenant = TenantId::new("demo");
            let key = asterius_jose::SigningKey::generate(SigningAlgorithm::EdDsa)
                .expect("generate");
            let proof = a_dpop_proof(&key, "shared-identifier");

            for purpose in [ReplayPurpose::ClientAssertion, ReplayPurpose::DpopProof] {
                assert_eq!(
                    guard.claim(
                        &tenant,
                        purpose,
                        proof.jkt.as_str(),
                        &proof.jti,
                        proof.replay_expires_at,
                    ).await.expect("claim"),
                    ReplayCheck::FirstUse,
                    "{} collided with the other purpose", purpose.as_str()
                );
            }
        }
    }

    db_test! {
        /// The row lives exactly as long as the proof would be accepted, and
        /// the sweep collects it when it stops.
        ///
        /// This is what keeps the table proportional to traffic rather than to
        /// policy: a DPoP proof is good for five minutes, so a row is dead
        /// weight after five minutes, whatever any retention setting says.
        async fn a_dpop_replay_row_is_collected_once_its_proof_has_aged_out(db) {
            seed_tenant(&db.pool, "demo").await;
            let guard = PgReplayGuard::new(db.pool.clone());
            let tenant = TenantId::new("demo");
            let key = asterius_jose::SigningKey::generate(SigningAlgorithm::EdDsa)
                .expect("generate");
            let proof = a_dpop_proof(&key, "expiring");

            let _ = guard.claim(
                &tenant,
                ReplayPurpose::DpopProof,
                proof.jkt.as_str(),
                &proof.jti,
                proof.replay_expires_at,
            ).await.expect("claim");

            // While the proof would still be accepted, the row must stay: a
            // sweep that ran early would reopen the replay window it closed.
            assert_eq!(
                guard.purge_expired(&tenant, proof.replay_expires_at - Duration::seconds(1))
                    .await
                    .expect("purge"),
                0
            );
            assert_eq!(
                guard.claim(
                    &tenant,
                    ReplayPurpose::DpopProof,
                    proof.jkt.as_str(),
                    &proof.jti,
                    proof.replay_expires_at,
                ).await.expect("claim"),
                ReplayCheck::Replay
            );

            // Once it has aged out, the row protects nothing and goes.
            assert_eq!(
                guard.purge_expired(&tenant, proof.replay_expires_at)
                    .await
                    .expect("purge"),
                1
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Pushed authorization requests (ast-gxh.1)

mod auth_requests {
    use super::*;
    use asterius_domain::{AuthRequestRepository, ClientId, Consumed, PushedRequest};
    use asterius_store_pg::PgAuthRequestRepository;

    pub(super) fn digest(seed: &str) -> String {
        hex::encode(asterius_domain::sha256(seed.as_bytes()))
    }

    pub(super) fn request(tenant: &str, seed: &str, expires_at: OffsetDateTime) -> PushedRequest {
        PushedRequest {
            tenant: TenantId::new(tenant),
            request_uri_digest: digest(seed),
            client: ClientId::new("billing"),
            parameters: serde_json::json!({
                "redirect_uri": "https://rp.example/cb",
                "scopes": ["openid"],
            }),
            pushed_at: OffsetDateTime::now_utc(),
            expires_at,
        }
    }

    /// The FK needs a client to point at.
    pub(super) async fn seed_client(pool: &PgPool, tenant: &str) {
        seed_tenant(pool, tenant).await;
        let store = Store::from_pool(pool.clone());
        store
            .scope(TenantId::new(tenant))
            .clients(Capabilities::default())
            .upsert(&client(tenant, "billing", &registration_document()))
            .await
            .expect("seed client");
    }

    fn later() -> OffsetDateTime {
        OffsetDateTime::now_utc() + time::Duration::minutes(5)
    }

    db_test! {
        /// A reference round-trips and comes back with what was pushed.
        async fn a_pushed_request_can_be_consumed_once(db) {
            seed_client(&db.pool, "demo").await;
            let repo = PgAuthRequestRepository::new(db.pool.clone(), TenantId::new("demo"));
            let pushed = request("demo", "one", later());
            repo.push(&pushed).await.expect("push");

            let consumed = repo
                .consume(&pushed.request_uri_digest, OffsetDateTime::now_utc())
                .await
                .expect("consume");
            let Consumed::Request(found) = consumed else {
                panic!("a live reference did not resolve: {consumed:?}");
            };
            assert_eq!(found.client.as_str(), "billing");
            assert_eq!(found.parameters, pushed.parameters);

            // Spent.
            assert_eq!(
                repo.consume(&pushed.request_uri_digest, OffsetDateTime::now_utc())
                    .await
                    .expect("second consume"),
                Consumed::AlreadyUsed
            );
        }
    }

    db_test! {
        /// FAPI 2.0 SP §5.3.2.2 Note 3: one-time use is enforced at the
        /// *completion* of authorization, not at page load.
        ///
        /// So reading the request to render a consent screen must not spend it
        /// — a user who reloads the page twice before consenting is doing
        /// nothing wrong, and must not be told their request has expired.
        async fn peeking_does_not_spend_the_reference(db) {
            seed_client(&db.pool, "demo").await;
            let repo = PgAuthRequestRepository::new(db.pool.clone(), TenantId::new("demo"));
            let pushed = request("demo", "peek", later());
            repo.push(&pushed).await.expect("push");

            for _ in 0..3 {
                assert!(
                    repo.peek(&pushed.request_uri_digest, OffsetDateTime::now_utc())
                        .await
                        .expect("peek")
                        .is_some(),
                    "a reload spent the request"
                );
            }

            assert!(matches!(
                repo.consume(&pushed.request_uri_digest, OffsetDateTime::now_utc())
                    .await
                    .expect("consume"),
                Consumed::Request(_)
            ));
        }
    }

    db_test! {
        /// The property the one-time-use rule rests on: two submissions of the
        /// same consent screen, and exactly one wins.
        ///
        /// A read followed by a write would pass every other test here and fail
        /// this one — and letting both win is an authorization code issued
        /// twice for one user decision.
        async fn concurrent_consumption_yields_exactly_one_winner(db) {
            seed_client(&db.pool, "demo").await;
            let repo = std::sync::Arc::new(PgAuthRequestRepository::new(
                db.pool.clone(),
                TenantId::new("demo"),
            ));
            let pushed = request("demo", "contested", later());
            repo.push(&pushed).await.expect("push");

            let attempts: Vec<_> = (0..16)
                .map(|_| {
                    let repo = repo.clone();
                    let digest = pushed.request_uri_digest.clone();
                    tokio::spawn(async move {
                        repo.consume(&digest, OffsetDateTime::now_utc())
                            .await
                            .expect("consume")
                    })
                })
                .collect();

            let mut winners = 0;
            for attempt in attempts {
                if matches!(attempt.await.expect("task"), Consumed::Request(_)) {
                    winners += 1;
                }
            }
            assert_eq!(winners, 1, "{winners} concurrent consumers each got the request");
        }
    }

    db_test! {
        /// An expired reference is refused, and is not consumable afterwards.
        async fn an_expired_reference_is_refused(db) {
            seed_client(&db.pool, "demo").await;
            let repo = PgAuthRequestRepository::new(db.pool.clone(), TenantId::new("demo"));
            let pushed = request(
                "demo",
                "stale",
                OffsetDateTime::now_utc() - time::Duration::seconds(1),
            );
            repo.push(&pushed).await.expect("push");

            assert_eq!(
                repo.consume(&pushed.request_uri_digest, OffsetDateTime::now_utc())
                    .await
                    .expect("consume"),
                Consumed::Expired
            );
            assert!(
                repo.peek(&pushed.request_uri_digest, OffsetDateTime::now_utc())
                    .await
                    .expect("peek")
                    .is_none()
            );
        }
    }

    db_test! {
        /// A reference issued by one tenant is nothing at another.
        async fn a_reference_does_not_cross_tenants(db) {
            seed_client(&db.pool, "demo").await;
            seed_client(&db.pool, "other").await;
            let demo = PgAuthRequestRepository::new(db.pool.clone(), TenantId::new("demo"));
            let other = PgAuthRequestRepository::new(db.pool.clone(), TenantId::new("other"));

            let pushed = request("demo", "cross", later());
            demo.push(&pushed).await.expect("push");

            assert_eq!(
                other
                    .consume(&pushed.request_uri_digest, OffsetDateTime::now_utc())
                    .await
                    .expect("consume"),
                Consumed::NotFound,
                "a reference resolved at the wrong tenant"
            );
            // Still live where it belongs.
            assert!(matches!(
                demo.consume(&pushed.request_uri_digest, OffsetDateTime::now_utc())
                    .await
                    .expect("consume"),
                Consumed::Request(_)
            ));
        }
    }

    db_test! {
        /// An unknown reference is `NotFound` rather than an error, and a
        /// malformed one never reaches the database.
        async fn an_unknown_reference_resolves_to_nothing(db) {
            seed_client(&db.pool, "demo").await;
            let repo = PgAuthRequestRepository::new(db.pool.clone(), TenantId::new("demo"));
            assert_eq!(
                repo.consume(&digest("never-pushed"), OffsetDateTime::now_utc())
                    .await
                    .expect("consume"),
                Consumed::NotFound
            );
            assert!(
                repo.consume("not-hex", OffsetDateTime::now_utc()).await.is_err(),
                "a malformed digest was sent to the database"
            );
        }
    }

    db_test! {
        /// The stored row holds a digest. A leaked database must not yield a
        /// usable `request_uri`.
        async fn the_stored_row_holds_a_digest(db) {
            seed_client(&db.pool, "demo").await;
            let repo = PgAuthRequestRepository::new(db.pool.clone(), TenantId::new("demo"));
            let pushed = request("demo", "opaque", later());
            repo.push(&pushed).await.expect("push");

            let stored: Vec<u8> = sqlx::query_scalar(
                "select request_uri_hash from auth_requests where tenant_id = $1",
            )
            .bind("demo")
            .fetch_one(&db.pool)
            .await
            .expect("read back");

            assert_eq!(stored.len(), 32, "not a SHA-256 digest");
            assert_eq!(hex::encode(&stored), pushed.request_uri_digest);
        }
    }

    db_test! {
        /// Retention drops expired rows for the named tenant only.
        async fn purging_removes_expired_rows_of_one_tenant(db) {
            seed_client(&db.pool, "demo").await;
            seed_client(&db.pool, "other").await;
            let demo = PgAuthRequestRepository::new(db.pool.clone(), TenantId::new("demo"));
            let other = PgAuthRequestRepository::new(db.pool.clone(), TenantId::new("other"));
            let past = OffsetDateTime::now_utc() - time::Duration::minutes(1);

            demo.push(&request("demo", "gone", past)).await.expect("push");
            demo.push(&request("demo", "live", later())).await.expect("push");
            other.push(&request("other", "gone", past)).await.expect("push");

            let removed = demo
                .purge_expired(OffsetDateTime::now_utc())
                .await
                .expect("purge");
            assert_eq!(removed, 1);

            // The other tenant's expired row survives its neighbour's purge.
            let remaining: i64 = sqlx::query_scalar(
                "select count(*) from auth_requests where tenant_id = $1",
            )
            .bind("other")
            .fetch_one(&db.pool)
            .await
            .expect("count");
            assert_eq!(remaining, 1, "purging one tenant removed another's rows");
        }
    }
}

// ---------------------------------------------------------------------------
// Grants and the revocation cascade (ast-uwv.2)
// ---------------------------------------------------------------------------

mod interactions {
    use super::*;
    use asterius_domain::{
        AuthRequestRepository, Consumed, DomainError, InteractionRecord, InteractionRepository,
    };
    use asterius_store_pg::PgAuthRequestRepository;

    use super::auth_requests::{digest, request, seed_client};

    fn later() -> OffsetDateTime {
        OffsetDateTime::now_utc() + time::Duration::minutes(5)
    }

    db_test! {
        /// One row, two credentials. The client holds the `request_uri`; the
        /// browser holds the interaction id; neither can be derived from the
        /// other, and the row answers to both.
        async fn a_request_can_be_reached_by_either_credential(db) {
            seed_client(&db.pool, "demo").await;
            let repo = PgAuthRequestRepository::new(db.pool.clone(), TenantId::new("demo"));
            let pushed = request("demo", "both", later());
            repo.push(&pushed).await.expect("push");

            let ix = digest("browser-handle");
            repo.begin_interaction(&pushed.request_uri_digest, &ix, OffsetDateTime::now_utc())
                .await
                .expect("begin");

            let found: InteractionRecord = repo
                .by_interaction(&ix, OffsetDateTime::now_utc())
                .await
                .expect("read")
                .expect("the interaction must resolve");
            let request = found
                .client_request()
                .expect("an authorization names its client");
            assert_eq!(request.client.as_str(), "billing");
            assert_eq!(request.parameters, pushed.parameters);

            // The client's credential still works on the same row.
            assert!(
                repo.peek(&pushed.request_uri_digest, OffsetDateTime::now_utc())
                    .await
                    .expect("peek")
                    .is_some()
            );
        }
    }

    db_test! {
        /// The other kind of interaction (ADR-0009, `ast-wr4`): no client, no
        /// `request_uri`, and a destination that is a variant. One repository
        /// answers for both kinds, so the login pages reach this row through
        /// exactly the statements they reach an authorization through.
        async fn a_first_party_interaction_round_trips_without_a_client(db) {
            let repo = PgAuthRequestRepository::new(db.pool.clone(), TenantId::new("demo"));
            let now = OffsetDateTime::now_utc();
            let ix = digest("a-console-visitor");

            repo.begin_first_party_interaction(
                &ix,
                asterius_domain::FirstPartyDestination::AdminConsole,
                now + time::Duration::minutes(10),
                now,
            )
            .await
            .expect("begin");

            let found: InteractionRecord = repo
                .by_interaction(&ix, now)
                .await
                .expect("read")
                .expect("the interaction must resolve");
            assert!(
                found.client_request().is_none(),
                "a first-party interaction named a client"
            );
            assert_eq!(
                found.continuation.first_party(),
                Some(asterius_domain::FirstPartyDestination::AdminConsole)
            );

            // Progress and the session digest are written by the same call the
            // authorization path makes.
            repo.save_interaction_state(
                &ix,
                &serde_json::json!({"stage": "login"}),
                Some("a-session-digest"),
                now,
            )
            .await
            .expect("save");
            let found = repo
                .by_interaction(&ix, now)
                .await
                .expect("read")
                .expect("still live")
                ;
            assert_eq!(found.session.as_deref(), Some("a-session-digest"));

            // Spent once. A second completion must not open a second session.
            repo.complete_interaction(&ix, now).await.expect("complete");
            assert!(repo.complete_interaction(&ix, now).await.is_err());
            assert!(
                repo.by_interaction(&ix, now).await.expect("read").is_none(),
                "a spent interaction still resolves"
            );
        }
    }

    db_test! {
        /// A browser mismatch destroys the interaction whichever table it is
        /// in (FAPI 2.0 SP §6.5): the destroy does not first have to work out
        /// which kind it was, because the case where that guess is wrong is
        /// exactly the case somebody is being deceived in.
        async fn destroying_reaches_a_first_party_interaction_too(db) {
            let repo = PgAuthRequestRepository::new(db.pool.clone(), TenantId::new("demo"));
            let now = OffsetDateTime::now_utc();
            let ix = digest("a-mismatched-visitor");
            repo.begin_first_party_interaction(
                &ix,
                asterius_domain::FirstPartyDestination::AdminConsole,
                now + time::Duration::minutes(10),
                now,
            )
            .await
            .expect("begin");

            repo.destroy_interaction(&ix).await.expect("destroy");

            assert!(repo.by_interaction(&ix, now).await.expect("read").is_none());
        }
    }

    db_test! {
        /// A second `/authorize` on one `request_uri` is a replay, not a retry.
        ///
        /// Re-keying the row would hand the second browser the first one's
        /// flow, and the first would be left holding a cookie for a request
        /// somebody else now owns.
        async fn a_request_accepts_only_one_interaction(db) {
            seed_client(&db.pool, "demo").await;
            let repo = PgAuthRequestRepository::new(db.pool.clone(), TenantId::new("demo"));
            let pushed = request("demo", "once", later());
            repo.push(&pushed).await.expect("push");

            let first = digest("first-browser");
            repo.begin_interaction(&pushed.request_uri_digest, &first, OffsetDateTime::now_utc())
                .await
                .expect("first");

            let second = digest("second-browser");
            let error = repo
                .begin_interaction(&pushed.request_uri_digest, &second, OffsetDateTime::now_utc())
                .await
                .expect_err("a second interaction must be refused");
            assert!(matches!(error, DomainError::Conflict(_)), "{error:?}");

            // The first browser still owns it, and the second's id resolves
            // to nothing.
            assert!(
                repo.by_interaction(&first, OffsetDateTime::now_utc())
                    .await
                    .expect("read")
                    .is_some()
            );
            assert!(
                repo.by_interaction(&second, OffsetDateTime::now_utc())
                    .await
                    .expect("read")
                    .is_none()
            );
        }
    }

    db_test! {
        /// Progress is recorded, and cannot resurrect a closed request.
        async fn state_is_saved_and_an_expired_interaction_refuses_progress(db) {
            seed_client(&db.pool, "demo").await;
            let repo = PgAuthRequestRepository::new(db.pool.clone(), TenantId::new("demo"));

            let live = request("demo", "live", later());
            repo.push(&live).await.expect("push");
            let ix = digest("live-browser");
            repo.begin_interaction(&live.request_uri_digest, &ix, OffsetDateTime::now_utc())
                .await
                .expect("begin");

            let progress = serde_json::json!({"stage": "consent"});
            repo.save_interaction_state(&ix, &progress, Some("sess-1"), OffsetDateTime::now_utc())
                .await
                .expect("save");

            let found = repo
                .by_interaction(&ix, OffsetDateTime::now_utc())
                .await
                .expect("read")
                .expect("present");
            assert_eq!(found.state, progress);
            assert_eq!(found.session.as_deref(), Some("sess-1"));

            // An expired one refuses progress rather than accepting it.
            let stale = request(
                "demo",
                "stale",
                OffsetDateTime::now_utc() - time::Duration::seconds(1),
            );
            repo.push(&stale).await.expect("push");
            let stale_ix = digest("stale-browser");
            assert!(
                repo.begin_interaction(
                    &stale.request_uri_digest,
                    &stale_ix,
                    OffsetDateTime::now_utc()
                )
                .await
                .is_err(),
                "an expired request accepted an interaction"
            );
        }
    }

    db_test! {
        /// A browser mismatch destroys the request, not just the interaction.
        ///
        /// Leaving the `request_uri` alive would let the client retry into a
        /// flow whose browser half has been tampered with.
        async fn destroying_an_interaction_takes_the_request_with_it(db) {
            seed_client(&db.pool, "demo").await;
            let repo = PgAuthRequestRepository::new(db.pool.clone(), TenantId::new("demo"));
            let pushed = request("demo", "doomed", later());
            repo.push(&pushed).await.expect("push");
            let ix = digest("doomed-browser");
            repo.begin_interaction(&pushed.request_uri_digest, &ix, OffsetDateTime::now_utc())
                .await
                .expect("begin");

            repo.destroy_interaction(&ix).await.expect("destroy");

            assert!(
                repo.by_interaction(&ix, OffsetDateTime::now_utc())
                    .await
                    .expect("read")
                    .is_none()
            );
            assert_eq!(
                repo.consume(&pushed.request_uri_digest, OffsetDateTime::now_utc())
                    .await
                    .expect("consume"),
                Consumed::NotFound,
                "the client's half of a destroyed request survived"
            );

            // Destroying something already gone is success, not an error.
            repo.destroy_interaction(&ix).await.expect("idempotent");
        }
    }

    db_test! {
        /// An interaction id issued by one tenant is nothing at another.
        async fn an_interaction_does_not_cross_tenants(db) {
            seed_client(&db.pool, "demo").await;
            seed_client(&db.pool, "other").await;
            let demo = PgAuthRequestRepository::new(db.pool.clone(), TenantId::new("demo"));
            let other = PgAuthRequestRepository::new(db.pool.clone(), TenantId::new("other"));

            let pushed = request("demo", "crossing", later());
            demo.push(&pushed).await.expect("push");
            let ix = digest("crossing-browser");
            demo.begin_interaction(&pushed.request_uri_digest, &ix, OffsetDateTime::now_utc())
                .await
                .expect("begin");

            assert!(
                other
                    .by_interaction(&ix, OffsetDateTime::now_utc())
                    .await
                    .expect("read")
                    .is_none(),
                "an interaction resolved at the wrong tenant"
            );
            // And the wrong tenant cannot destroy it either.
            other.destroy_interaction(&ix).await.expect("no-op");
            assert!(
                demo.by_interaction(&ix, OffsetDateTime::now_utc())
                    .await
                    .expect("read")
                    .is_some(),
                "another tenant destroyed this one's interaction"
            );
        }
    }

    db_test! {
        /// The stored id is a digest. A leaked row must not yield a usable
        /// interaction id, exactly as for the `request_uri`.
        async fn the_stored_interaction_id_is_a_digest(db) {
            seed_client(&db.pool, "demo").await;
            let repo = PgAuthRequestRepository::new(db.pool.clone(), TenantId::new("demo"));
            let pushed = request("demo", "opaque-ix", later());
            repo.push(&pushed).await.expect("push");
            let ix = digest("secret-browser-handle");
            repo.begin_interaction(&pushed.request_uri_digest, &ix, OffsetDateTime::now_utc())
                .await
                .expect("begin");

            let stored: Vec<u8> = sqlx::query_scalar(
                "select interaction_id_hash from auth_requests where tenant_id = $1",
            )
            .bind("demo")
            .fetch_one(&db.pool)
            .await
            .expect("read back");

            assert_eq!(stored.len(), 32, "not a SHA-256 digest");
            assert_eq!(hex::encode(&stored), ix);
            assert!(!hex::encode(&stored).contains("secret-browser-handle"));
        }
    }
    db_test! {
        /// FAPI 2.0 SP §5.3.2.2 Note 3: one-time use at the *completion* of
        /// authorization. Two tabs both submitting consent must produce one
        /// authorization response, and the statement is what decides which.
        async fn a_request_can_be_completed_exactly_once(db) {
            seed_client(&db.pool, "demo").await;
            let repo = PgAuthRequestRepository::new(db.pool.clone(), TenantId::new("demo"));
            let pushed = request("demo", "completes-once", later());
            repo.push(&pushed).await.expect("push");
            let ix = digest("one-browser");
            repo.begin_interaction(&pushed.request_uri_digest, &ix, OffsetDateTime::now_utc())
                .await
                .expect("begin");

            repo.complete_interaction(&ix, OffsetDateTime::now_utc())
                .await
                .expect("the first completion must win");

            let error = repo
                .complete_interaction(&ix, OffsetDateTime::now_utc())
                .await
                .expect_err("a second completion must lose");
            assert!(matches!(error, DomainError::NotFound), "{error:?}");

            // And the row is spent for both callers: the browser cannot come
            // back to the page, and the client cannot consume the reference.
            assert!(
                repo.by_interaction(&ix, OffsetDateTime::now_utc())
                    .await
                    .expect("read")
                    .is_none()
            );
            assert_eq!(
                repo.consume(&pushed.request_uri_digest, OffsetDateTime::now_utc())
                    .await
                    .expect("consume"),
                Consumed::AlreadyUsed
            );
        }
    }

    db_test! {
        /// Completion does not resurrect a request whose window has closed.
        async fn an_expired_request_cannot_be_completed(db) {
            seed_client(&db.pool, "demo").await;
            let repo = PgAuthRequestRepository::new(db.pool.clone(), TenantId::new("demo"));
            let pushed = request("demo", "too-late", OffsetDateTime::now_utc() - time::Duration::seconds(1));
            repo.push(&pushed).await.expect("push");
            // `begin_interaction` refuses an expired request, so the handle is
            // written while the request is live and the clock is moved on
            // instead.
            let ix = digest("late-browser");
            sqlx::query("update auth_requests set interaction_id_hash = $2 where tenant_id = $1")
                .bind("demo")
                .bind(hex::decode(&ix).expect("hex"))
                .execute(&db.pool)
                .await
                .expect("attach a handle");

            let error = repo
                .complete_interaction(&ix, OffsetDateTime::now_utc())
                .await
                .expect_err("an expired request must not complete");
            assert!(matches!(error, DomainError::NotFound), "{error:?}");
        }
    }
}

mod grants {
    use super::*;
    use asterius_domain::{
        AuthenticationMethod, ClientId, DomainError, Grant, GrantAuthentication, GrantId,
        GrantStatus, LiveAccessToken, RevocationReason, SessionId, SubjectId,
    };
    use asterius_store_pg::PgGrantRepository;

    fn repo(pool: &PgPool, tenant: &str) -> PgGrantRepository {
        PgGrantRepository::new(pool.clone(), TenantId::new(tenant))
    }

    /// A tenant and one client for its grants to hang off. `grants` has a
    /// foreign key to `clients`, which is the schema saying that a grant with
    /// no client is not a thing.
    pub(super) async fn seed_client(pool: &PgPool, tenant: &str, client_id: &str) {
        seed_tenant(pool, tenant).await;
        Store::from_pool(pool.clone())
            .scope(TenantId::new(tenant))
            .clients(Capabilities::default())
            .upsert(&client(tenant, client_id, &registration_document()))
            .await
            .expect("seed client");
    }

    /// A grant carrying one value of every shape the row can hold, so that a
    /// round trip proves something.
    fn a_grant(tenant: &str, client_id: &str, subject: &str) -> Grant {
        let mut grant = Grant::new(TenantId::new(tenant), ClientId::new(client_id), epoch());
        grant.subject = Some(SubjectId::new(subject));
        grant.user = Some(UserId::generate());
        grant.scopes = ["openid", "payments"]
            .into_iter()
            .map(str::to_owned)
            .collect();
        grant.resources = ["https://api.example/".to_owned()].into_iter().collect();
        grant.claims = json!({"id_token": {"acr": {"essential": true}}});
        // OIDC Core §5.2, ordered by preference — an array and not a set, so a
        // round trip that reordered it would be caught.
        grant.claims_locales = vec!["ja-Kana-JP".to_owned(), "en".to_owned()];
        grant.authorization_details = vec![json!({"type": "payment_initiation"})];
        grant.session = Some(SessionId::new("sess-1"));
        // OIDC Core §2's three, copied off the session at the authorization
        // (`ast-dlk`). They are what a refresh reads once that session row is
        // gone, so a round trip that lost or reordered them would be a grant
        // that could no longer say when its person authenticated.
        grant.authentication = Some(GrantAuthentication {
            authenticated_at: epoch(),
            acr: Some("urn:asterius:acr:passkey-uv".to_owned()),
            amr: vec![
                AuthenticationMethod::Password,
                AuthenticationMethod::Passkey,
            ],
        });
        grant
    }

    /// A refresh token pointing at a grant. Written by hand because the token
    /// story (`ast-a05.5`) owns the repository that will write it; what these
    /// tests need is the row a revocation has to reach.
    pub(super) async fn insert_refresh_token(
        pool: &PgPool,
        tenant: &str,
        grant: &GrantId,
        label: &str,
    ) {
        sqlx::query(
            "insert into refresh_tokens (tenant_id, token_hash, grant_id, client_id, dpop_jkt,
                                         absolute_expires_at)
             values ($1, $2, $3::uuid, 'billing', 'a-thumbprint', now() + interval '30 days')",
        )
        .bind(tenant)
        .bind(asterius_domain::sha256(label.as_bytes()).to_vec())
        .bind(grant.as_str())
        .execute(pool)
        .await
        .expect("insert refresh token");
    }

    /// An authorization code pointing at a grant, redeemed or not. Written by
    /// hand for the same reason as the refresh token above: the repository that
    /// will write it belongs to another story, and what these tests need is the
    /// row the sweep used to reason about.
    async fn insert_authorization_code(
        pool: &PgPool,
        tenant: &str,
        grant: &GrantId,
        label: &str,
        consumed: bool,
    ) {
        sqlx::query(
            "insert into authorization_codes
                 (tenant_id, code_hash, client_id, grant_id, code_challenge, redirect_uri,
                  issued_at, expires_at, consumed_at)
             values ($1, $2, 'billing', $3::uuid, 'a-challenge', 'https://client.example/cb',
                     $4, $4 + interval '60 seconds', case when $5 then $4 end)",
        )
        .bind(tenant)
        .bind(asterius_domain::sha256(label.as_bytes()).to_vec())
        .bind(grant.as_str())
        .bind(epoch())
        .bind(consumed)
        .execute(pool)
        .await
        .expect("insert authorization code");
    }

    /// What a 60-second expiry sweep does a minute after the login.
    async fn delete_authorization_codes(pool: &PgPool, tenant: &str) {
        sqlx::query("delete from authorization_codes where tenant_id = $1")
            .bind(tenant)
            .execute(pool)
            .await
            .expect("purge authorization codes");
    }

    async fn authorization_codes(pool: &PgPool, tenant: &str) -> i64 {
        sqlx::query_scalar("select count(*) from authorization_codes where tenant_id = $1")
            .bind(tenant)
            .fetch_one(pool)
            .await
            .expect("count authorization codes")
    }

    async fn refresh_tokens(pool: &PgPool, tenant: &str) -> i64 {
        sqlx::query_scalar("select count(*) from refresh_tokens where tenant_id = $1")
            .bind(tenant)
            .fetch_one(pool)
            .await
            .expect("count refresh tokens")
    }

    async fn revoked_refresh_tokens(pool: &PgPool, tenant: &str) -> i64 {
        sqlx::query_scalar(
            "select count(*) from refresh_tokens
             where tenant_id = $1 and revoked_at is not null",
        )
        .bind(tenant)
        .fetch_one(pool)
        .await
        .expect("count revoked refresh tokens")
    }

    async fn denylisted(pool: &PgPool, tenant: &str) -> Vec<String> {
        sqlx::query_scalar(
            "select jti from access_token_denylist where tenant_id = $1 order by jti",
        )
        .bind(tenant)
        .fetch_all(pool)
        .await
        .expect("read the denylist")
    }

    fn access_token(jti: &str, expires_at: OffsetDateTime) -> LiveAccessToken {
        LiveAccessToken::new(jti, expires_at).expect("a well-formed jti")
    }

    db_test! {
        /// Everything the schema can hold comes back exactly as it went in, and
        /// comes back through the same validation the values passed on the way
        /// in.
        async fn a_grant_survives_the_round_trip_through_storage(db) {
            seed_client(&db.pool, "demo", "billing").await;
            let repo = repo(&db.pool, "demo");
            let stored = a_grant("demo", "billing", "sub-1");
            repo.create(&stored).await.expect("create");

            let found = repo.find(&stored.id).await.expect("find").expect("present");
            assert_eq!(found, stored);
            assert_eq!(found.status(epoch()), GrantStatus::Pending);

            assert_eq!(
                repo.list_for_subject(&SubjectId::new("sub-1")).await.expect("list"),
                vec![found]
            );
            assert!(
                repo.list_for_subject(&SubjectId::new("sub-2")).await.expect("list").is_empty()
            );
            assert!(
                repo.find(&GrantId::new("00000000-0000-4000-8000-000000000000"))
                    .await
                    .expect("find")
                    .is_none()
            );

            // A grant id is minted, never chosen: a second insert under the
            // same id is a collision, not an update of the permissions.
            assert!(
                matches!(repo.create(&stored).await, Err(DomainError::Conflict(_))),
                "a grant id was reused as an upsert key"
            );
        }
    }

    db_test! {
        /// A grant with no person behind it stores no authentication, and the
        /// fallback has nothing to read (`ast-dlk`, `ast-a05.8`).
        ///
        /// RFC 6749 §4.4 is a client acting for itself: no session, no
        /// `auth_time`, no `acr` and no `amr`. The three columns are null, and
        /// they come back as `None` rather than as an empty authentication —
        /// which is what stops `issuance::session_facts` from asserting a
        /// sign-in nobody performed.
        async fn a_client_only_grant_stores_no_authentication(db) {
            seed_client(&db.pool, "demo", "billing").await;
            let repo = repo(&db.pool, "demo");
            let mut grant = Grant::new(TenantId::new("demo"), ClientId::new("billing"), epoch());
            grant.scopes = ["payments"].into_iter().map(str::to_owned).collect();
            grant.claimed_at = Some(epoch());
            repo.create(&grant).await.expect("create");

            let found = repo.find(&grant.id).await.expect("find").expect("present");
            assert_eq!(found.authentication, None);

            let columns: (Option<OffsetDateTime>, Option<String>, Vec<String>) = sqlx::query_as(
                "select authenticated_at, acr, amr from grants
                 where tenant_id = $1 and grant_id = $2::uuid"
            )
            .bind("demo")
            .bind(grant.id.as_str())
            .fetch_one(&db.pool)
            .await
            .expect("read the row");
            assert_eq!(columns.0, None, "authenticated_at was written");
            assert_eq!(columns.1, None, "acr was written");
            assert!(columns.2.is_empty(), "amr was written: {:?}", columns.2);
        }
    }

    db_test! {
        /// Grant Management ID1 §5.6: "a grant should be considered active when
        /// associated tokens have been successfully claimed by the client."
        ///
        /// `claim` is what moves the grant, because `claim` is the only way to
        /// obtain the authority to mint a credential. The stamp therefore
        /// cannot be forgotten by an issuance path: the path cannot issue
        /// anything without asking for it.
        async fn a_grant_becomes_active_when_a_credential_is_claimed_from_it(db) {
            seed_client(&db.pool, "demo", "billing").await;
            let repo = repo(&db.pool, "demo");
            let grant = a_grant("demo", "billing", "sub-1");
            repo.create(&grant).await.expect("create");

            assert_eq!(
                repo.find(&grant.id).await.expect("find").expect("present").status(epoch()),
                GrantStatus::Pending
            );

            let _ = repo.claim(&grant.id, epoch()).await.expect("claim");

            let found = repo.find(&grant.id).await.expect("find").expect("present");
            assert_eq!(found.status(epoch()), GrantStatus::Active);
            assert_eq!(found.claimed_at, Some(epoch()));

            // Grant Management ID1 §5.6 asks when the *first* credential was
            // taken, and a refresh cycle would otherwise keep pushing the stamp
            // forward until a grant claimed months ago looked minutes old.
            let _ = repo
                .claim(&grant.id, epoch() + Duration::hours(1))
                .await
                .expect("second claim");
            assert_eq!(
                repo.find(&grant.id).await.expect("find").expect("present").claimed_at,
                Some(epoch()),
                "a later claim rewrote the instant the grant became active"
            );
        }
    }

    db_test! {
        /// A `client_credentials` grant is minted at the token endpoint at the
        /// moment its access token is. Nothing will ever reference it — no
        /// code, no refresh token — so the stamp `claim` writes is the only
        /// thing standing between it and the sweep.
        ///
        /// Two halves, and the first is the one that changed with
        /// `grants.claimed_at`: a grant that was created and never claimed from
        /// *is* collectable, whatever shape it has. The old derivation read
        /// `subject is null` as "claimed the moment it exists" and kept such a
        /// row forever, which spared an abandoned authorization on the strength
        /// of its shape rather than of anything that happened to it.
        async fn a_client_credentials_grant_is_claimed_by_the_claim_and_not_by_its_shape(db) {
            seed_client(&db.pool, "demo", "billing").await;
            let repo = repo(&db.pool, "demo");
            let machine = Grant::new(TenantId::new("demo"), ClientId::new("billing"), epoch());
            repo.create(&machine).await.expect("create");

            let found = repo.find(&machine.id).await.expect("find").expect("present");
            assert_eq!(
                found.status(epoch()),
                GrantStatus::Pending,
                "a grant nothing was ever taken from reported active"
            );

            let claimed = repo.claim(&machine.id, epoch()).await.expect("claim");
            assert_eq!(claimed.id(), &machine.id);
            assert_eq!(claimed.subject(), None, "a client_credentials grant has no sub");

            let found = repo.find(&machine.id).await.expect("find").expect("present");
            assert_eq!(found.status(epoch()), GrantStatus::Active);
            assert_eq!(found.claimed_at, Some(epoch()));
            assert_eq!(
                repo.purge_unclaimed(epoch() + Duration::days(1)).await.expect("purge"),
                0,
                "a claimed client_credentials grant was collected as unclaimed"
            );
        }
    }

    db_test! {
        /// The shape `ast-uwv.7` exists for, and the one the old derivation
        /// could not see.
        ///
        /// A code flow that issues no refresh token leaves a grant with exactly
        /// one live credential: a bare access token. That token is a stateless
        /// JWT (RFC 9068) and no table records it; the authorization code it
        /// was exchanged for lives at most 60 seconds (FAPI 2.0 SP §5.3.2.1
        /// item 11) and
        /// is then purged. So a minute after a perfectly ordinary login there
        /// is nothing in the database pointing at the grant at all — and the
        /// sweep used to delete it, taking with it the only row that could have
        /// revoked the token still in the client's hands.
        ///
        /// The assertions before the purge are the point: every piece of
        /// evidence the old derivation looked for is absent, and the grant
        /// survives anyway.
        async fn a_claimed_grant_survives_after_its_authorization_code_is_purged(db) {
            seed_client(&db.pool, "demo", "billing").await;
            let repo = repo(&db.pool, "demo");
            let grant = a_grant("demo", "billing", "sub-1");
            repo.create(&grant).await.expect("create");

            // The code flow: a code is written, redeemed, and the grant claimed
            // as the access token is minted. No refresh token is issued.
            insert_authorization_code(&db.pool, "demo", &grant.id, "code-1", true).await;
            let _ = repo.claim(&grant.id, epoch()).await.expect("claim");

            // ...and 60 seconds later the code row is gone.
            delete_authorization_codes(&db.pool, "demo").await;

            assert_eq!(
                authorization_codes(&db.pool, "demo").await,
                0,
                "the fixture left a code row for the derivation to find"
            );
            assert_eq!(
                refresh_tokens(&db.pool, "demo").await,
                0,
                "the fixture left a refresh token for the derivation to find"
            );
            let found = repo.find(&grant.id).await.expect("find").expect("present");
            assert!(found.subject.is_some(), "this is a code flow, not client_credentials");
            assert!(found.parent.is_none(), "this is a code flow, not a token exchange");
            assert_eq!(found.status(epoch()), GrantStatus::Active);

            assert_eq!(
                repo.purge_unclaimed(epoch() + Duration::days(1)).await.expect("purge"),
                0,
                "a grant with a live access token was collected as unclaimed"
            );
            assert!(
                repo.find(&grant.id).await.expect("find").is_some(),
                "the only row that could revoke a live access token was deleted"
            );
        }
    }

    db_test! {
        /// The acceptance criterion, read back from both tables: revoking a
        /// grant marks its refresh tokens revoked *and* puts its live access
        /// tokens on the denylist until their own `exp`.
        ///
        /// FAPI 2.0 SP §6.8 item 4: credentials issued under one authorization
        /// are linked so that they can be revoked together.
        async fn revoking_a_grant_revokes_its_refresh_tokens_and_denylists_its_access_tokens(db) {
            seed_client(&db.pool, "demo", "billing").await;
            let repo = repo(&db.pool, "demo");
            let grant = a_grant("demo", "billing", "sub-1");
            repo.create(&grant).await.expect("create");
            insert_refresh_token(&db.pool, "demo", &grant.id, "rt-1").await;
            insert_refresh_token(&db.pool, "demo", &grant.id, "rt-2").await;

            let now = epoch();
            let live = [
                access_token("at-1", now + Duration::minutes(5)),
                access_token("at-2", now + Duration::minutes(5)),
                // Already past its own `exp`: a denylist row for it would
                // protect nothing, because the token fails on `exp` first.
                access_token("at-expired", now - Duration::seconds(1)),
            ];

            let outcome = repo
                .revoke(&grant.id, RevocationReason::UserRevoked, &live, now)
                .await
                .expect("revoke");
            assert_eq!(outcome.refresh_tokens_revoked, 2);
            assert_eq!(outcome.access_tokens_denylisted, 2);
            assert_eq!(outcome.revoked_at, now);

            assert_eq!(revoked_refresh_tokens(&db.pool, "demo").await, 2);
            assert_eq!(denylisted(&db.pool, "demo").await, ["at-1", "at-2"]);

            let found = repo.find(&grant.id).await.expect("find").expect("present");
            assert_eq!(found.status(now), GrantStatus::Revoked);
            assert_eq!(found.revocation_reason, Some(RevocationReason::UserRevoked));

            // Revoking again is not a second cascade, and does not say whether
            // the grant was ever real (Grant Management ID1 §6.6).
            assert!(matches!(
                repo.revoke(&grant.id, RevocationReason::UserRevoked, &[], now).await,
                Err(DomainError::NotFound)
            ));
        }
    }

    db_test! {
        /// Revoking a grant writes its access-token cutoff, so the tokens the
        /// caller could not name go too.
        ///
        /// Grant Management ID1 §6.5: `DELETE` "MUST revoke the respective
        /// grant and all refresh tokens issued based on that grant […] It
        /// SHOULD also revoke all access tokens". Those cannot be listed —
        /// they are stateless JWTs (RFC 9068) and nothing wrote their `jti`
        /// down — and the denylist above only ever reaches the ones somebody
        /// presented. The cutoff is what withdraws the rest (`ast-m9c.13`),
        /// and it is the mark the resource path reads whether or not the token
        /// carries a `grant_id` claim.
        async fn revoking_a_grant_withdraws_the_access_tokens_nobody_can_name(db) {
            // Arrange
            seed_client(&db.pool, "demo", "billing").await;
            let repo = repo(&db.pool, "demo");
            let grant = a_grant("demo", "billing", "sub-1");
            repo.create(&grant).await.expect("create");
            let now = epoch();

            // Act: no live token named at all, which is what the Grant
            // Management endpoint passes — it holds its own token and not the
            // grant's.
            let outcome = repo
                .revoke(&grant.id, RevocationReason::UserRevoked, &[], now)
                .await
                .expect("revoke");
            assert_eq!(outcome.access_tokens_denylisted, 0, "nothing was named");

            // Assert
            assert_eq!(
                repo.revoked_before(&ClientId::new("billing"), Some(&grant.id))
                    .await
                    .expect("read the cutoff"),
                Some(now),
                "a revoked grant left its access tokens verifying"
            );
            assert_eq!(
                repo.revoked_before(&ClientId::new("billing"), None)
                    .await
                    .expect("read the cutoff"),
                None,
                "revoking one grant withdrew the whole client's tokens"
            );
        }
    }

    db_test! {
        /// The failure mode a revocation exists to prevent: the refresh token
        /// revoked, the access token still live, and the caller told it worked.
        ///
        /// A trigger makes the denylist insert fail after the refresh tokens
        /// have already been updated. All three tables must read back exactly
        /// as they did before the call.
        async fn a_revocation_that_fails_part_way_revokes_nothing(db) {
            seed_client(&db.pool, "demo", "billing").await;
            let repo = repo(&db.pool, "demo");
            let grant = a_grant("demo", "billing", "sub-1");
            repo.create(&grant).await.expect("create");
            // A live refresh token exists, so the grant was claimed: this is
            // what makes `active` below the reading a failed revocation must
            // leave untouched.
            let _ = repo.claim(&grant.id, epoch()).await.expect("claim");
            insert_refresh_token(&db.pool, "demo", &grant.id, "rt-1").await;

            sqlx::query(
                "create function refuse_the_denylist() returns trigger language plpgsql as $$
                 begin raise exception 'injected failure'; end; $$",
            )
            .execute(&db.pool)
            .await
            .expect("create the failure");
            sqlx::query(
                "create trigger denylist_refuses before insert on access_token_denylist
                 for each row execute function refuse_the_denylist()",
            )
            .execute(&db.pool)
            .await
            .expect("arm the failure");

            let now = epoch();
            let outcome = repo
                .revoke(
                    &grant.id,
                    RevocationReason::UserRevoked,
                    &[access_token("at-1", now + Duration::minutes(5))],
                    now,
                )
                .await;
            assert!(
                matches!(outcome, Err(DomainError::Storage(_))),
                "a revocation that could not denylist reported success"
            );

            assert_eq!(
                revoked_refresh_tokens(&db.pool, "demo").await,
                0,
                "a refresh token was revoked by a revocation that failed"
            );
            assert!(denylisted(&db.pool, "demo").await.is_empty());
            let found = repo.find(&grant.id).await.expect("find").expect("present");
            assert_eq!(
                found.status(now),
                GrantStatus::Active,
                "the grant was stamped by a revocation that failed"
            );

            // And with the failure disarmed, the same call does the whole
            // cascade — so the rollback left the grant revocable, not stuck.
            sqlx::query("drop trigger denylist_refuses on access_token_denylist")
                .execute(&db.pool)
                .await
                .expect("disarm");
            let retried = repo
                .revoke(
                    &grant.id,
                    RevocationReason::UserRevoked,
                    &[access_token("at-1", now + Duration::minutes(5))],
                    now,
                )
                .await
                .expect("revoke");
            assert_eq!(retried.refresh_tokens_revoked, 1);
            assert_eq!(retried.access_tokens_denylisted, 1);
            assert_eq!(revoked_refresh_tokens(&db.pool, "demo").await, 1);
            assert_eq!(denylisted(&db.pool, "demo").await, ["at-1"]);
        }
    }

    db_test! {
        /// `revoked -> active` is the transition the lifecycle refuses, and this
        /// is where refusing it means something: no `ClaimedGrant` means no
        /// token, and there is no other way to make one.
        async fn a_revoked_grant_refuses_to_issue_another_credential(db) {
            seed_client(&db.pool, "demo", "billing").await;
            let repo = repo(&db.pool, "demo");
            let grant = a_grant("demo", "billing", "sub-1");
            repo.create(&grant).await.expect("create");

            let now = epoch();
            let claimed = repo.claim(&grant.id, now).await.expect("a live grant is claimable");
            assert_eq!(claimed.id(), &grant.id);
            assert_eq!(claimed.subject(), Some(&SubjectId::new("sub-1")));

            let cascade = repo
                .revoke(&grant.id, RevocationReason::CodeReplayed, &[], now)
                .await
                .expect("revoke");
            assert_eq!(cascade.refresh_tokens_revoked, 0);

            let refused = repo.claim(&grant.id, now).await;
            assert!(
                matches!(refused, Err(DomainError::Invalid { field: "grant_id", .. })),
                "a revoked grant issued a credential: {refused:?}"
            );
            assert_eq!(
                repo.find(&grant.id).await.expect("find").expect("present").status(now),
                GrantStatus::Revoked,
                "a refused claim changed the grant"
            );

            // An expired grant is refused by the same guard, without a row
            // having been written at the instant it lapsed.
            let mut lapsing = a_grant("demo", "billing", "sub-2");
            lapsing.expires_at = Some(now + Duration::minutes(1));
            repo.create(&lapsing).await.expect("create");
            assert!(repo.claim(&lapsing.id, now).await.is_ok());
            assert!(
                repo.claim(&lapsing.id, now + Duration::minutes(1)).await.is_err(),
                "an expired grant issued a credential"
            );
        }
    }

    db_test! {
        /// Two tenants, one subject spelling, no crossing over — through every
        /// statement this repository has, including the two that write and the
        /// one that deletes. A missing `tenant_id` predicate in any of them
        /// would revoke or collect another customer's authorizations.
        async fn a_grant_of_one_tenant_is_invisible_to_another(db) {
            seed_client(&db.pool, "alpha", "billing").await;
            seed_client(&db.pool, "beta", "billing").await;
            let alpha = repo(&db.pool, "alpha");
            let beta = repo(&db.pool, "beta");

            let theirs = a_grant("alpha", "billing", "sub-1");
            alpha.create(&theirs).await.expect("create");
            insert_refresh_token(&db.pool, "alpha", &theirs.id, "rt-1").await;

            // Reads.
            assert!(beta.find(&theirs.id).await.expect("find").is_none());
            assert!(beta.list_for_subject(&SubjectId::new("sub-1")).await.expect("list").is_empty());
            assert!(matches!(beta.claim(&theirs.id, epoch()).await, Err(DomainError::NotFound)));

            // Revocation.
            assert!(matches!(
                beta.revoke(
                    &theirs.id,
                    RevocationReason::AdminRevoked,
                    &[access_token("at-1", epoch() + Duration::minutes(5))],
                    epoch(),
                ).await,
                Err(DomainError::NotFound)
            ));
            assert_eq!(revoked_refresh_tokens(&db.pool, "alpha").await, 0);
            assert!(denylisted(&db.pool, "alpha").await.is_empty());
            assert!(denylisted(&db.pool, "beta").await.is_empty());

            // Garbage collection.
            let unclaimed = a_grant("alpha", "billing", "sub-2");
            alpha.create(&unclaimed).await.expect("create");
            assert_eq!(
                beta.purge_unclaimed(epoch() + Duration::days(1)).await.expect("purge"),
                0,
                "one tenant's purge collected another tenant's grant"
            );
            assert!(alpha.find(&unclaimed.id).await.expect("find").is_some());

            // A grant cannot be written into another tenant either.
            assert!(matches!(
                beta.create(&theirs).await,
                Err(DomainError::Invalid { field: "tenant_id", .. })
            ));
        }
    }

    db_test! {
        /// Grant Management ID1 §5.6: "If the tokens haven't been claimed the
        /// grant should be deleted by the AS after a reasonable timeout."
        ///
        /// And the other half, which matters more: a grant somebody *did* claim
        /// from is never collected, because collecting it would delete the only
        /// row that can revoke the tokens minted from it.
        async fn an_unclaimed_grant_is_collected_after_the_timeout_and_a_claimed_one_is_not(db) {
            seed_client(&db.pool, "demo", "billing").await;
            let repo = repo(&db.pool, "demo");

            let abandoned = a_grant("demo", "billing", "sub-1");
            repo.create(&abandoned).await.expect("create");
            let claimed = a_grant("demo", "billing", "sub-2");
            repo.create(&claimed).await.expect("create");
            let _ = repo.claim(&claimed.id, epoch()).await.expect("claim");
            insert_refresh_token(&db.pool, "demo", &claimed.id, "rt-1").await;

            // Before the timeout, nothing is collected: an authorization a
            // client is still on its way to redeem is not abandoned.
            assert_eq!(
                repo.purge_unclaimed(epoch() - Duration::seconds(1)).await.expect("purge"),
                0
            );
            assert!(repo.find(&abandoned.id).await.expect("find").is_some());

            assert_eq!(
                repo.purge_unclaimed(epoch() + Duration::minutes(10)).await.expect("purge"),
                1
            );
            assert!(repo.find(&abandoned.id).await.expect("find").is_none());
            assert!(
                repo.find(&claimed.id).await.expect("find").is_some(),
                "a grant with a live refresh token was collected as unclaimed"
            );

            // A revoked grant that was never claimed from is kept too. It is
            // the one exception to "unclaimed grants are worthless": the record
            // of a withdrawal is the evidence that the withdrawal happened.

            // A revoked grant is not collected either: the record of a
            // withdrawal is the evidence that it happened.
            let withdrawn = a_grant("demo", "billing", "sub-3");
            repo.create(&withdrawn).await.expect("create");
            let withdrawal = repo
                .revoke(&withdrawn.id, RevocationReason::UserRevoked, &[], epoch())
                .await
                .expect("revoke");
            assert_eq!(withdrawal.access_tokens_denylisted, 0);
            assert_eq!(
                repo.purge_unclaimed(epoch() + Duration::minutes(10)).await.expect("purge"),
                0
            );
            assert!(repo.find(&withdrawn.id).await.expect("find").is_some());
        }
    }
}

// ---------------------------------------------------------------------------
// Sessions (ast-2vk.2)

mod codes {
    use super::*;
    use asterius_domain::{
        CodeBinding, DomainError, Grant, GrantId, GrantStatus, RevocationReason,
    };
    use asterius_store_pg::{PgCodeRepository, PgGrantRepository, Redemption};

    use super::grants::{insert_refresh_token, seed_client};

    fn repo(pool: &PgPool, tenant: &str) -> PgCodeRepository {
        PgCodeRepository::new(pool.clone(), TenantId::new(tenant))
    }

    /// The digest of a label, which is what the repository stores. Real codes
    /// come from `MintedCode::generate`; a test needs a value it can name
    /// twice.
    fn digest(label: &str) -> String {
        asterius_domain::sha256_hex(label.as_bytes())
    }

    /// A grant for codes to draw on, written first because the schema says a
    /// code with no grant is not a thing.
    async fn a_grant(pool: &PgPool, tenant: &str) -> GrantId {
        seed_client(pool, tenant, "billing").await;
        let mut grant = Grant::new(TenantId::new(tenant), ClientId::new("billing"), epoch());
        grant.user = Some(UserId::generate());
        grant.subject = Some(asterius_domain::SubjectId::new("sub-1"));
        grant.scopes = ["openid"].into_iter().map(str::to_owned).collect();
        PgGrantRepository::new(pool.clone(), TenantId::new(tenant))
            .create(&grant)
            .await
            .expect("create grant");
        grant.id
    }

    /// `timestamptz` holds microseconds, so a value with nanoseconds in it
    /// does not survive the round trip. Truncating here keeps the assertion
    /// about the repository rather than about Postgres's resolution.
    fn micros(at: OffsetDateTime) -> OffsetDateTime {
        at.replace_nanosecond(at.nanosecond() / 1_000 * 1_000)
            .expect("a truncated nanosecond is in range")
    }

    fn binding(grant: &GrantId, now: OffsetDateTime) -> CodeBinding {
        CodeBinding {
            client_id: "billing".to_owned(),
            grant_id: grant.clone(),
            code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_owned(),
            redirect_uri: "https://client.example/cb".to_owned(),
            nonce: Some("n-0S6_WzA2Mj".to_owned()),
            dpop_jkt: Some("a-thumbprint".to_owned()),
            // Grant Management ID1 §5.5: the fact the token response needs,
            // and the only field here that is not compared at redemption — so
            // the round-trip test is the only thing that would notice it being
            // dropped.
            grant_management_action: Some("merge".to_owned()),
            expires_at: micros(now + time::Duration::seconds(60)),
        }
    }

    db_test! {
        /// Every binding survives the round trip. They are what makes a leaked
        /// code worthless, and a binding that is written but not read back is
        /// a binding nothing will ever compare.
        async fn a_code_round_trips_every_binding(db) {
            let now = OffsetDateTime::now_utc();
            let grant = a_grant(&db.pool, "demo").await;
            let repo = repo(&db.pool, "demo");
            let expected = binding(&grant, now);

            repo.issue(&digest("code-1"), &expected, now).await.expect("issue");
            let Redemption::Redeemed(found) = repo
                .redeem(&digest("code-1"), now)
                .await
                .expect("redeem")
            else {
                panic!("a live code did not redeem");
            };
            assert_eq!(*found, expected);
        }
    }

    db_test! {
        /// RFC 6749 §4.1.2: a code "MUST NOT be used more than once".
        ///
        /// The check and the spend are one statement, so the second attempt
        /// matches no row rather than reading a flag somebody else is about to
        /// set.
        async fn a_code_is_redeemable_exactly_once(db) {
            let now = OffsetDateTime::now_utc();
            let grant = a_grant(&db.pool, "demo").await;
            let repo = repo(&db.pool, "demo");
            repo.issue(&digest("once"), &binding(&grant, now), now).await.expect("issue");

            assert!(matches!(
                repo.redeem(&digest("once"), now).await.expect("first"),
                Redemption::Redeemed(_)
            ));
            assert_eq!(
                repo.redeem(&digest("once"), now).await.expect("second"),
                Redemption::Replayed
            );
        }
    }

    db_test! {
        /// RFC 6749 §10.5: on reuse, revoke everything issued from that code.
        ///
        /// A replay and a theft look identical from here, so the safe reading
        /// is applied to both — and it happens inside `redeem`, where a caller
        /// cannot forget it.
        async fn a_replay_revokes_the_grant_and_its_refresh_tokens(db) {
            let now = OffsetDateTime::now_utc();
            let grant = a_grant(&db.pool, "demo").await;
            let repo = repo(&db.pool, "demo");
            insert_refresh_token(&db.pool, "demo", &grant, "rt-1").await;
            repo.issue(&digest("stolen"), &binding(&grant, now), now).await.expect("issue");

            assert!(matches!(
                repo.redeem(&digest("stolen"), now).await.expect("first"),
                Redemption::Redeemed(_)
            ));
            // Still `Pending`: spending a code is not claiming a credential.
            // Grant Management ID1 §5.6 makes a grant `active` when tokens
            // "have been successfully claimed by the client", which is the
            // token endpoint's `claim` a statement later. What matters here is
            // that a legitimate redemption did not *revoke* anything.
            let grants = PgGrantRepository::new(db.pool.clone(), TenantId::new("demo"));
            let after_first = grants.find(&grant).await.expect("find").expect("present");
            assert_eq!(after_first.status(now), GrantStatus::Pending);
            assert!(
                after_first.revoked_at.is_none(),
                "a legitimate redemption revoked the grant"
            );

            assert_eq!(
                repo.redeem(&digest("stolen"), now).await.expect("second"),
                Redemption::Replayed
            );

            let revoked = grants.find(&grant).await.expect("find").expect("present");
            assert_eq!(revoked.status(now), GrantStatus::Revoked);
            assert_eq!(revoked.revocation_reason, Some(RevocationReason::CodeReplayed));

            let live: i64 = sqlx::query_scalar(
                "select count(*) from refresh_tokens
                  where tenant_id = $1 and grant_id = $2::uuid and revoked_at is null",
            )
            .bind("demo")
            .bind(grant.as_str())
            .fetch_one(&db.pool)
            .await
            .expect("count");
            assert_eq!(live, 0, "a refresh token survived a code replay");
        }
    }

    db_test! {
        /// A third presentation must not rewrite the first revocation's reason
        /// or time. The `coalesce` is what makes this idempotent.
        async fn repeated_replays_keep_the_first_revocation(db) {
            let now = OffsetDateTime::now_utc();
            let grant = a_grant(&db.pool, "demo").await;
            let repo = repo(&db.pool, "demo");
            repo.issue(&digest("thrice"), &binding(&grant, now), now).await.expect("issue");

            assert!(matches!(
                repo.redeem(&digest("thrice"), now).await.expect("first"),
                Redemption::Redeemed(_)
            ));
            assert_eq!(
                repo.redeem(&digest("thrice"), now).await.expect("second"),
                Redemption::Replayed
            );
            let grants = PgGrantRepository::new(db.pool.clone(), TenantId::new("demo"));
            let first = grants.find(&grant).await.expect("find").expect("present");

            let later = now + time::Duration::minutes(5);
            assert_eq!(
                repo.redeem(&digest("thrice"), later).await.expect("third"),
                Redemption::Replayed
            );
            let again = grants.find(&grant).await.expect("find").expect("present");
            assert_eq!(again.revoked_at, first.revoked_at, "the revocation moved");
            assert_eq!(again.revocation_reason, first.revocation_reason);
        }
    }

    db_test! {
        /// Expired and unknown are one answer, and neither is a replay: there
        /// is nothing to revoke, and treating a guess as an incident would let
        /// anyone revoke a grant by presenting rubbish.
        async fn an_expired_or_unknown_code_is_not_found(db) {
            let now = OffsetDateTime::now_utc();
            let grant = a_grant(&db.pool, "demo").await;
            let repo = repo(&db.pool, "demo");
            let mut expiring = binding(&grant, now);
            expiring.expires_at = now + time::Duration::seconds(1);
            repo.issue(&digest("expiring"), &expiring, now).await.expect("issue");

            let later = now + time::Duration::seconds(2);
            assert_eq!(
                repo.redeem(&digest("expiring"), later).await.expect("expired"),
                Redemption::NotFound
            );
            assert_eq!(
                repo.redeem(&digest("never-issued"), now).await.expect("unknown"),
                Redemption::NotFound
            );

            // Neither touched the grant.
            let grants = PgGrantRepository::new(db.pool.clone(), TenantId::new("demo"));
            assert!(
                grants.find(&grant).await.expect("find").expect("present").revoked_at.is_none()
            );
        }
    }

    db_test! {
        /// FAPI 2.0 SP §5.3.2.1 item 11, as a `CHECK` constraint. The rule is
        /// enforced in code; this proves a row that broke it could not be
        /// written even if the code were wrong.
        async fn the_schema_refuses_a_code_that_would_outlive_the_cap(db) {
            let now = OffsetDateTime::now_utc();
            let grant = a_grant(&db.pool, "demo").await;
            let repo = repo(&db.pool, "demo");
            let mut too_long = binding(&grant, now);
            too_long.expires_at = now + time::Duration::seconds(61);

            let error = repo
                .issue(&digest("too-long"), &too_long, now)
                .await
                .expect_err("the database must refuse it");
            assert!(matches!(error, DomainError::Storage(_)), "{error:?}");
        }
    }

    db_test! {
        /// A code belongs to its tenant. Another tenant presenting the same
        /// digest finds nothing.
        async fn a_code_does_not_cross_a_tenant(db) {
            let now = OffsetDateTime::now_utc();
            let grant = a_grant(&db.pool, "demo").await;
            repo(&db.pool, "demo")
                .issue(&digest("theirs"), &binding(&grant, now), now)
                .await
                .expect("issue");

            seed_client(&db.pool, "other", "billing").await;
            assert_eq!(
                repo(&db.pool, "other").redeem(&digest("theirs"), now).await.expect("redeem"),
                Redemption::NotFound
            );
        }
    }

    db_test! {
        /// The sweep drops what is spent or past its expiry, and leaves a live
        /// code alone.
        async fn purging_drops_expired_codes_only(db) {
            let now = OffsetDateTime::now_utc();
            let grant = a_grant(&db.pool, "demo").await;
            let repo = repo(&db.pool, "demo");
            let mut stale = binding(&grant, now);
            stale.expires_at = now + time::Duration::seconds(1);
            repo.issue(&digest("stale"), &stale, now).await.expect("issue");
            repo.issue(&digest("fresh"), &binding(&grant, now), now).await.expect("issue");

            let later = now + time::Duration::seconds(2);
            assert_eq!(repo.purge_expired(later).await.expect("purge"), 1);
            assert!(matches!(
                repo.redeem(&digest("fresh"), later).await.expect("redeem"),
                Redemption::Redeemed(_)
            ));
        }
    }
}

mod sessions {
    use super::*;
    use asterius_domain::entities::session::SessionId;
    use asterius_domain::{
        AuthenticationMethod, ClientId, Lifetimes, Session, SessionRepository, SessionRevocation,
        SessionStatus,
    };
    use asterius_store_pg::PgSessionRepository;

    async fn seed_user(pool: &PgPool, tenant: &str, user: uuid::Uuid) {
        seed_tenant(pool, tenant).await;
        sqlx::query(
            "insert into users (tenant_id, user_id, username, status)
             values ($1, $2, $3, 'active')",
        )
        .bind(tenant)
        .bind(user)
        .bind(user.to_string())
        .execute(pool)
        .await
        .expect("seed user");
    }

    fn repo(pool: &PgPool, tenant: &str) -> PgSessionRepository {
        PgSessionRepository::new(pool.clone(), TenantId::new(tenant))
    }

    fn session_for(tenant: &str, id: &SessionId, user: uuid::Uuid) -> Session {
        Session::begin(
            TenantId::new(tenant),
            id,
            user,
            vec![AuthenticationMethod::Password],
            OffsetDateTime::now_utc(),
            Lifetimes::default(),
        )
    }

    db_test! {
        /// A session round-trips, and is active.
        async fn a_session_survives_the_round_trip(db) {
            let user = uuid::Uuid::new_v4();
            seed_user(&db.pool, "demo", user).await;
            let repo = repo(&db.pool, "demo");
            let id = SessionId::generate();
            repo.begin(&session_for("demo", &id, user)).await.expect("begin");

            let found = repo.find(&id.digest()).await.expect("find").expect("present");
            assert_eq!(found.user, user);
            assert_eq!(found.amr, vec![AuthenticationMethod::Password]);
            assert_eq!(found.status(OffsetDateTime::now_utc()), SessionStatus::Active);
        }
    }

    db_test! {
        /// The session-fixation defence: rotation is atomic, and the old id
        /// stops working the moment it returns.
        ///
        /// An attacker who planted an id in the victim's browser before they
        /// signed in holds a value that is now worth nothing.
        async fn rotating_invalidates_the_old_id_immediately(db) {
            let user = uuid::Uuid::new_v4();
            seed_user(&db.pool, "demo", user).await;
            let repo = repo(&db.pool, "demo");

            let planted = SessionId::generate();
            repo.begin(&session_for("demo", &planted, user)).await.expect("begin");

            let fresh = SessionId::generate();
            repo.rotate(
                &planted.digest(),
                &fresh.digest(),
                &[AuthenticationMethod::Password],
                None,
                OffsetDateTime::now_utc(),
            )
            .await
            .expect("rotate");

            assert!(
                repo.find(&planted.digest()).await.expect("find").is_none(),
                "the pre-login id still resolves after rotation"
            );
            let found = repo.find(&fresh.digest()).await.expect("find").expect("present");
            assert_eq!(found.user, user, "rotation lost the user");
        }
    }

    db_test! {
        /// Rotation moves `auth_time`, `amr` and `acr` together, because the
        /// reason to rotate is always that the user has just proved something.
        /// `max_age` is measured from `auth_time` (OIDC Core §3.1.2.1) and the
        /// step-up this server performs (`ast-2vk.7`) is exactly this write:
        /// a fresh id, a later authentication, the methods that have now been
        /// used, and the class they reached.
        async fn rotation_moves_the_authentication_time(db) {
            let user = uuid::Uuid::new_v4();
            seed_user(&db.pool, "demo", user).await;
            let repo = repo(&db.pool, "demo");

            let first = SessionId::generate();
            let mut original = session_for("demo", &first, user);
            original.authenticated_at = OffsetDateTime::now_utc() - time::Duration::hours(2);
            original.created_at = original.authenticated_at;
            repo.begin(&original).await.expect("begin");

            let stepped_up = SessionId::generate();
            let at = OffsetDateTime::now_utc();
            repo.rotate(
                &first.digest(),
                &stepped_up.digest(),
                &[AuthenticationMethod::Password, AuthenticationMethod::Passkey],
                Some(asterius_domain::acr::PASSKEY),
                at,
            )
            .await
            .expect("rotate");

            let found = repo.find(&stepped_up.digest()).await.expect("find").expect("present");
            assert!(
                found.authenticated_at > original.authenticated_at,
                "auth_time did not move"
            );
            assert!(
                !found.needs_reauthentication(Some(60), OffsetDateTime::now_utc()),
                "a just-stepped-up session should satisfy max_age=60"
            );
            assert_eq!(
                found.amr,
                vec![AuthenticationMethod::Password, AuthenticationMethod::Passkey]
            );
            assert_eq!(
                found.acr.as_deref(),
                Some(asterius_domain::acr::PASSKEY),
                "the class the step-up reached was not recorded"
            );
        }
    }

    db_test! {
        /// A rotation is not a way to revive a revoked or expired session.
        async fn a_revoked_session_cannot_be_rotated(db) {
            let user = uuid::Uuid::new_v4();
            seed_user(&db.pool, "demo", user).await;
            let repo = repo(&db.pool, "demo");

            let id = SessionId::generate();
            repo.begin(&session_for("demo", &id, user)).await.expect("begin");
            repo.revoke(&id.digest(), SessionRevocation::UserLogout, OffsetDateTime::now_utc())
                .await
                .expect("revoke");

            let fresh = SessionId::generate();
            assert!(
                repo.rotate(
                    &id.digest(),
                    &fresh.digest(),
                    &[AuthenticationMethod::Password],
                    None,
                    OffsetDateTime::now_utc(),
                )
                .await
                .is_err(),
                "a revoked session was rotated back into use"
            );
            assert!(repo.find(&fresh.digest()).await.expect("find").is_none());
        }
    }

    db_test! {
        /// The first reason survives. The first answer to "why was I signed
        /// out" is the true one.
        async fn revoking_twice_keeps_the_first_reason(db) {
            let user = uuid::Uuid::new_v4();
            seed_user(&db.pool, "demo", user).await;
            let repo = repo(&db.pool, "demo");
            let id = SessionId::generate();
            repo.begin(&session_for("demo", &id, user)).await.expect("begin");

            repo.revoke(&id.digest(), SessionRevocation::Suspicious, OffsetDateTime::now_utc())
                .await
                .expect("first");
            repo.revoke(&id.digest(), SessionRevocation::UserLogout, OffsetDateTime::now_utc())
                .await
                .expect("second");

            let found = repo.find(&id.digest()).await.expect("find").expect("present");
            assert_eq!(
                found.status(OffsetDateTime::now_utc()),
                SessionStatus::Revoked(SessionRevocation::Suspicious),
                "the later reason overwrote the first"
            );
        }
    }

    db_test! {
        /// A credential change ends every session the user has.
        async fn revoking_by_user_ends_all_their_sessions(db) {
            let user = uuid::Uuid::new_v4();
            let other = uuid::Uuid::new_v4();
            seed_user(&db.pool, "demo", user).await;
            seed_user(&db.pool, "demo", other).await;
            let repo = repo(&db.pool, "demo");

            let ids: Vec<SessionId> = (0..3).map(|_| SessionId::generate()).collect();
            for id in &ids {
                repo.begin(&session_for("demo", id, user)).await.expect("begin");
            }
            let untouched = SessionId::generate();
            repo.begin(&session_for("demo", &untouched, other)).await.expect("begin");

            let ended = repo
                .revoke_all_for_user(user, SessionRevocation::CredentialChange, OffsetDateTime::now_utc())
                .await
                .expect("revoke all");
            assert_eq!(ended, 3);

            for id in &ids {
                let found = repo.find(&id.digest()).await.expect("find").expect("present");
                assert!(!found.status(OffsetDateTime::now_utc()).is_usable());
            }
            let survivor = repo.find(&untouched.digest()).await.expect("find").expect("present");
            assert!(
                survivor.status(OffsetDateTime::now_utc()).is_usable(),
                "another user's session was revoked"
            );
        }
    }

    db_test! {
        /// Touching moves the idle deadline; it cannot revive a dead session.
        async fn touching_extends_an_active_session_only(db) {
            let user = uuid::Uuid::new_v4();
            seed_user(&db.pool, "demo", user).await;
            let repo = repo(&db.pool, "demo");
            let id = SessionId::generate();
            repo.begin(&session_for("demo", &id, user)).await.expect("begin");

            let before = repo.find(&id.digest()).await.expect("find").expect("present");
            repo.touch(&id.digest(), OffsetDateTime::now_utc(), time::Duration::hours(2))
                .await
                .expect("touch");
            let after = repo.find(&id.digest()).await.expect("find").expect("present");
            assert!(after.idle_expires_at > before.idle_expires_at);

            repo.revoke(&id.digest(), SessionRevocation::UserLogout, OffsetDateTime::now_utc())
                .await
                .expect("revoke");
            assert!(
                repo.touch(&id.digest(), OffsetDateTime::now_utc(), time::Duration::hours(2))
                    .await
                    .is_err(),
                "a revoked session was touched back to life"
            );
        }
    }

    db_test! {
        /// Back-channel logout needs the participant list.
        async fn participants_are_recorded_once_and_updated(db) {
            let user = uuid::Uuid::new_v4();
            seed_user(&db.pool, "demo", user).await;
            let store = Store::from_pool(db.pool.clone());
            store
                .scope(TenantId::new("demo"))
                .clients(Capabilities::default())
                .upsert(&client("demo", "billing", &registration_document()))
                .await
                .expect("seed client");

            let repo = repo(&db.pool, "demo");
            let id = SessionId::generate();
            repo.begin(&session_for("demo", &id, user)).await.expect("begin");

            let client_id = ClientId::new("billing");
            repo.record_participant(&id.digest(), &client_id, OffsetDateTime::now_utc())
                .await
                .expect("first");
            let later = OffsetDateTime::now_utc() + time::Duration::minutes(5);
            repo.record_participant(&id.digest(), &client_id, later)
                .await
                .expect("second");

            let participants = repo.participants(&id.digest()).await.expect("read");
            assert_eq!(participants.len(), 1, "a client was recorded twice");
            assert!(
                participants[0].last_seen_at > participants[0].first_seen_at,
                "the second visit did not update last_seen_at"
            );
        }
    }

    db_test! {
        /// A session id issued by one tenant is nothing at another.
        async fn a_session_does_not_cross_tenants(db) {
            let user = uuid::Uuid::new_v4();
            seed_user(&db.pool, "demo", user).await;
            seed_tenant(&db.pool, "other").await;
            let demo = repo(&db.pool, "demo");
            let other = repo(&db.pool, "other");

            let id = SessionId::generate();
            demo.begin(&session_for("demo", &id, user)).await.expect("begin");

            assert!(other.find(&id.digest()).await.expect("find").is_none());
            // And the wrong tenant cannot revoke it.
            other
                .revoke(&id.digest(), SessionRevocation::Administrative, OffsetDateTime::now_utc())
                .await
                .expect("no-op");
            let survivor = demo.find(&id.digest()).await.expect("find").expect("present");
            assert!(survivor.status(OffsetDateTime::now_utc()).is_usable());
        }
    }

    db_test! {
        /// The stored id is a digest: a leaked row must not yield a usable
        /// session cookie.
        async fn the_stored_session_id_is_a_digest(db) {
            let user = uuid::Uuid::new_v4();
            seed_user(&db.pool, "demo", user).await;
            let repo = repo(&db.pool, "demo");
            let id = SessionId::generate();
            repo.begin(&session_for("demo", &id, user)).await.expect("begin");

            let stored: String =
                sqlx::query_scalar("select session_id from sessions where tenant_id = $1")
                    .bind("demo")
                    .fetch_one(&db.pool)
                    .await
                    .expect("read back");
            assert_eq!(stored, id.digest());
            assert_ne!(stored, id.expose());
            assert!(!stored.contains(id.expose()));
        }
    }
}

// ---------------------------------------------------------------------------
// Password verification (ast-2vk.5)

mod passwords {
    use super::*;
    use asterius_domain::{Argon2Parameters, CredentialVerifier, Secret};
    use asterius_store_pg::PgPasswordVerifier;

    /// The floor, so tests cost what a real login costs rather than being fast
    /// for the wrong reason.
    fn parameters() -> Argon2Parameters {
        Argon2Parameters::default()
    }

    fn verifier(pool: &PgPool, tenant: &str) -> PgPasswordVerifier {
        PgPasswordVerifier::new(pool.clone(), TenantId::new(tenant), parameters())
            .expect("build verifier")
    }

    async fn seed_password_user(
        pool: &PgPool,
        tenant: &str,
        username: &str,
        password: &str,
        hash_with: &PgPasswordVerifier,
    ) -> uuid::Uuid {
        seed_tenant(pool, tenant).await;
        let user = uuid::Uuid::new_v4();
        sqlx::query(
            "insert into users (tenant_id, user_id, username, status)
             values ($1, $2, $3, 'active')",
        )
        .bind(tenant)
        .bind(user)
        .bind(username)
        .execute(pool)
        .await
        .expect("seed user");

        sqlx::query(
            "insert into credentials (tenant_id, credential_id, user_id, kind, password_hash)
             values ($1, $2, $3, 'password', $4)",
        )
        .bind(tenant)
        .bind(uuid::Uuid::new_v4())
        .bind(user)
        .bind(hash_with.hash_for_storage(password).expect("hash"))
        .execute(pool)
        .await
        .expect("seed credential");
        user
    }

    db_test! {
        /// The right password authenticates; a wrong one does not.
        async fn a_correct_password_verifies(db) {
            let verifier = verifier(&db.pool, "demo");
            let user =
                seed_password_user(&db.pool, "demo", "ada", "correct horse battery", &verifier)
                    .await;

            assert_eq!(
                verifier
                    .verify("ada", Secret::new("correct horse battery".to_owned()))
                    .await
                    .expect("verify"),
                Some(user)
            );
            assert_eq!(
                verifier
                    .verify("ada", Secret::new("wrong horse battery".to_owned()))
                    .await
                    .expect("verify"),
                None
            );
        }
    }

    db_test! {
        /// The unknown-user path runs a real Argon2id verification, so it
        /// costs what a real one costs.
        ///
        /// Timing is measured rather than asserted exactly: the point is that
        /// the two paths are the same order of magnitude, not that they are
        /// identical to the nanosecond. A verifier that returned early for an
        /// unknown user would be tens of times faster and fail this by a mile.
        async fn an_unknown_user_costs_the_same_as_a_known_one(db) {
            let verifier = verifier(&db.pool, "demo");
            seed_password_user(&db.pool, "demo", "ada", "correct horse battery", &verifier).await;

            let time_it = |username: &'static str| {
                let verifier = &verifier;
                async move {
                    let start = std::time::Instant::now();
                    let _ = verifier
                        .verify(username, Secret::new("some guess entirely".to_owned()))
                        .await
                        .expect("verify");
                    start.elapsed()
                }
            };

            // Warm caches first: the very first Argon2id call in a process
            // allocates its memory pool and is not representative.
            let _ = time_it("ada").await;

            let known = time_it("ada").await;
            let unknown = time_it("nobody-at-all").await;

            let ratio = known.as_secs_f64() / unknown.as_secs_f64().max(f64::MIN_POSITIVE);
            assert!(
                (0.25..=4.0).contains(&ratio),
                "known-user and unknown-user paths differ by {ratio:.1}x \
                 (known {known:?}, unknown {unknown:?}); the unknown path is \
                 not doing the work"
            );
        }
    }

    db_test! {
        /// A disabled account fails like a wrong password, and the check
        /// happens *after* verification so it costs the same.
        async fn a_disabled_account_does_not_authenticate(db) {
            let verifier = verifier(&db.pool, "demo");
            let user =
                seed_password_user(&db.pool, "demo", "ada", "correct horse battery", &verifier)
                    .await;

            sqlx::query("update users set status = 'disabled' where tenant_id = $1 and user_id = $2")
                .bind("demo")
                .bind(user)
                .execute(&db.pool)
                .await
                .expect("disable");

            assert_eq!(
                verifier
                    .verify("ada", Secret::new("correct horse battery".to_owned()))
                    .await
                    .expect("verify"),
                None,
                "a disabled account authenticated"
            );
        }
    }

    db_test! {
        /// Raising the parameters marks old hashes for rehashing, and the
        /// rehash replaces them.
        async fn a_weaker_hash_is_rehashed_on_the_next_login(db) {
            let weak = verifier(&db.pool, "demo");
            let user = seed_password_user(&db.pool, "demo", "ada", "correct horse", &weak).await;

            let stronger = PgPasswordVerifier::new(
                db.pool.clone(),
                TenantId::new("demo"),
                Argon2Parameters::new(32 * 1024, 3, 1).expect("valid"),
            )
            .expect("build");

            let stored: String = sqlx::query_scalar(
                "select password_hash from credentials where tenant_id = $1 and user_id = $2",
            )
            .bind("demo")
            .bind(user)
            .fetch_one(&db.pool)
            .await
            .expect("read");

            assert!(
                stronger.should_rehash(&stored),
                "a hash below the new parameters was not marked for rehashing"
            );
            assert!(
                !weak.should_rehash(&stored),
                "a hash at the current parameters was marked for rehashing"
            );

            stronger.rehash(user, "correct horse").await.expect("rehash");

            let after: String = sqlx::query_scalar(
                "select password_hash from credentials where tenant_id = $1 and user_id = $2",
            )
            .bind("demo")
            .bind(user)
            .fetch_one(&db.pool)
            .await
            .expect("read");
            assert_ne!(after, stored, "the hash was not replaced");
            assert!(!stronger.should_rehash(&after));
            // And it still verifies.
            assert_eq!(
                stronger
                    .verify("ada", Secret::new("correct horse".to_owned()))
                    .await
                    .expect("verify"),
                Some(user)
            );
        }
    }

    db_test! {
        /// The stored value is an Argon2id PHC string, never the password.
        async fn the_stored_credential_is_a_hash(db) {
            let verifier = verifier(&db.pool, "demo");
            let password = "correct horse battery staple";
            let user = seed_password_user(&db.pool, "demo", "ada", password, &verifier).await;

            let stored: String = sqlx::query_scalar(
                "select password_hash from credentials where tenant_id = $1 and user_id = $2",
            )
            .bind("demo")
            .bind(user)
            .fetch_one(&db.pool)
            .await
            .expect("read");

            assert!(stored.starts_with("$argon2id$"), "{stored}");
            assert!(!stored.contains(password), "the password reached the column");
            assert!(stored.contains("m=19456"), "not the configured cost: {stored}");
        }
    }

    db_test! {
        /// Two accounts with the same password have different hashes.
        ///
        /// Otherwise a leaked database tells an attacker which accounts share
        /// a password, which is a target list.
        async fn identical_passwords_hash_differently(db) {
            let verifier = verifier(&db.pool, "demo");
            let password = "correct horse battery";
            seed_password_user(&db.pool, "demo", "ada", password, &verifier).await;
            seed_password_user(&db.pool, "demo", "grace", password, &verifier).await;

            let hashes: Vec<String> = sqlx::query_scalar(
                "select password_hash from credentials where tenant_id = $1 order by user_id",
            )
            .bind("demo")
            .fetch_all(&db.pool)
            .await
            .expect("read");

            assert_eq!(hashes.len(), 2);
            assert_ne!(hashes[0], hashes[1], "the salt is not per credential");
        }
    }

    db_test! {
        /// A username in one tenant does not authenticate in another.
        async fn passwords_do_not_cross_tenants(db) {
            let demo = verifier(&db.pool, "demo");
            seed_password_user(&db.pool, "demo", "ada", "correct horse battery", &demo).await;
            seed_tenant(&db.pool, "other").await;
            let other = verifier(&db.pool, "other");

            assert_eq!(
                other
                    .verify("ada", Secret::new("correct horse battery".to_owned()))
                    .await
                    .expect("verify"),
                None,
                "a password authenticated at the wrong tenant"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// The client configuration endpoint (`ast-m9c.5`, RFC 7592)
// ---------------------------------------------------------------------------

/// What `GET`, `PUT` and `DELETE /register/{client_id}` do to the row.
///
/// The endpoint's own rules are unit-tested where they are decided; what only a
/// database can answer is what a management request does to the table — which
/// columns an update moves, which it must not, and what a delete takes with it
/// through the schema's cascades.
mod client_configuration {
    use super::*;
    use asterius_domain::entities::tenant_settings::MAX_ACCESS_TOKEN_LIFETIME;
    use asterius_domain::{ClientConfiguration, DomainError, ManagedClient, sha256};
    use asterius_store_pg::PgGrantRepository;

    /// Registers a client with a known registration access token and returns
    /// the digest that was stored, so a test can assert against the value the
    /// column holds rather than against one it recomputed.
    async fn register(pool: &PgPool, tenant: &str, id: &str, token: &str) -> [u8; 32] {
        let digest = sha256(token.as_bytes());
        Store::from_pool(pool.clone())
            .scope(TenantId::new(tenant))
            .clients(Capabilities::default())
            .register(&client(tenant, id, &registration_document()), &digest)
            .await
            .expect("register");
        digest
    }

    fn repo(pool: &PgPool, tenant: &str) -> asterius_store_pg::PgClientRepository {
        Store::from_pool(pool.clone())
            .scope(TenantId::new(tenant))
            .clients(Capabilities::default())
    }

    db_test! {
        /// The two columns a management request is authorised against come back
        /// from the row, and each client's digest answers only for that client.
        ///
        /// OIDC Registration §4.1: the client a configuration URL names "MUST be
        /// matched against the Client to which the Registration Access Token was
        /// issued". The store's part of that is simply that there is no lookup
        /// by token at all — `managed` is keyed by `client_id`, so the only
        /// digest the endpoint can ever compare against is the one belonging to
        /// the client in the path. This asserts it against the table.
        async fn a_registration_access_token_is_reachable_only_through_its_own_client(db) {
            seed_tenant(&db.pool, "demo").await;
            let alpha = register(&db.pool, "demo", "c.alpha", "alpha-token").await;
            let beta = register(&db.pool, "demo", "c.beta", "beta-token").await;
            assert_ne!(alpha, beta);

            let repo = repo(&db.pool, "demo");
            let managed = repo
                .managed(&ClientId::new("c.alpha"))
                .await
                .expect("read")
                .expect("present");
            assert_eq!(
                managed,
                ManagedClient {
                    registration_access_token: Some(alpha),
                    // A freshly registered client has never rotated
                    // (`ast-m9c.12`), so there is no second credential.
                    previous_registration_access_token: None,
                    status: ClientStatus::Active,
                }
            );
            assert_ne!(
                managed.registration_access_token,
                Some(beta),
                "one client's URL served another client's credential"
            );

            // A client that does not exist is `None`, not an error and not a
            // guess. The endpoint turns that into the same 401 a wrong token
            // gets (OIDC Registration §4.4).
            assert!(
                repo.managed(&ClientId::new("c.nobody")).await.expect("read").is_none()
            );

            // A client created by any path other than registration has no
            // configuration endpoint at all — OIDC Registration §3.2's "both or
            // neither" — so the column is null and nothing authenticates.
            repo.upsert(&client("demo", "c.admin", &registration_document()))
                .await
                .expect("upsert");
            let admin = repo
                .managed(&ClientId::new("c.admin"))
                .await
                .expect("read")
                .expect("present");
            assert_eq!(admin.registration_access_token, None);
        }
    }

    db_test! {
        /// A client in one tenant is invisible through another tenant's
        /// configuration endpoint — read, replace and delete alike.
        ///
        /// Each tenant is a separate authorization server with its own issuer,
        /// so a `client_id` means nothing outside its own. Both tenants hold the
        /// *same* identifier here, which is the case a missing `tenant_id`
        /// predicate turns into one tenant managing another's client.
        async fn a_client_is_invisible_through_another_tenants_configuration_endpoint(db) {
            seed_tenant(&db.pool, "alpha").await;
            seed_tenant(&db.pool, "beta").await;
            let alpha_digest = register(&db.pool, "alpha", "c.shared", "alpha-token").await;
            let beta_digest = register(&db.pool, "beta", "c.shared", "beta-token").await;

            let alpha = repo(&db.pool, "alpha");
            let beta = repo(&db.pool, "beta");

            // Each tenant sees only its own token for the identifier they share.
            assert_eq!(
                alpha.managed(&ClientId::new("c.shared")).await.expect("read")
                    .expect("present").registration_access_token,
                Some(alpha_digest)
            );
            assert_eq!(
                beta.managed(&ClientId::new("c.shared")).await.expect("read")
                    .expect("present").registration_access_token,
                Some(beta_digest)
            );

            // An identifier only the other tenant has does not exist here.
            register(&db.pool, "beta", "c.beta-only", "beta-only-token").await;
            assert!(
                alpha.managed(&ClientId::new("c.beta-only")).await.expect("read").is_none(),
                "another tenant's client was visible"
            );

            // A replace aimed at the other tenant's client changes nothing and
            // creates nothing: it is `NotFound`, never an insert.
            let mut renamed = client("alpha", "c.beta-only", &registration_document());
            renamed.registration.client_name = "Taken over".to_owned();
            assert!(
                matches!(alpha.replace(&renamed).await, Err(DomainError::NotFound)),
                "a replace reached across tenants"
            );
            assert!(alpha.managed(&ClientId::new("c.beta-only")).await.expect("read").is_none());
            assert_eq!(
                beta.find(&ClientId::new("c.beta-only")).await.expect("find")
                    .expect("present").registration.client_name,
                "Billing",
                "the other tenant's client was renamed"
            );

            // And an entity belonging to another tenant cannot be replaced
            // through this scope even under an identifier this scope holds.
            let foreign = client("beta", "c.shared", &registration_document());
            assert!(
                matches!(
                    alpha.replace(&foreign).await,
                    Err(DomainError::Invalid { field: "tenant_id", .. })
                ),
                "a foreign entity was written into this tenant"
            );

            // A delete is scoped the same way.
            assert!(
                matches!(
                    alpha.deprovision(&ClientId::new("c.beta-only"), OffsetDateTime::now_utc()).await,
                    Err(DomainError::NotFound)
                )
            );
            let survivors: Vec<(String, String)> = sqlx::query_as(
                "select tenant_id, client_id from clients order by tenant_id, client_id",
            )
            .fetch_all(&db.pool)
            .await
            .expect("list");
            assert_eq!(
                survivors,
                vec![
                    ("alpha".to_owned(), "c.shared".to_owned()),
                    ("beta".to_owned(), "c.beta-only".to_owned()),
                    ("beta".to_owned(), "c.shared".to_owned()),
                ]
            );
        }
    }

    db_test! {
        /// RFC 7592 §2.2, against the row: an update replaces the document and
        /// leaves everything that is not in it alone.
        ///
        /// Two halves, and both are only observable here.
        ///
        /// **Omitted fields reset.** "Valid values of client metadata fields in
        /// this request MUST replace, not augment, the values previously
        /// associated with this client. Omitted fields MUST be treated as null
        /// or empty values by the server". The row must not keep a redirect URI
        /// the client dropped — a preserved one is a live callback its owner
        /// believes is gone.
        ///
        /// **What is not registration metadata survives.** The registration
        /// access token that authorised the call, the per-client resource
        /// allow-list (`ast-m9c.6`), the agent profile (`ast-lh3.1`), the
        /// software statement, the status and the creation time are all in the
        /// same row and none of them is the client's to set. The `set` list of
        /// the statement is what makes that true; this is what would notice a
        /// column being added to it.
        async fn replacing_a_registration_resets_the_document_and_keeps_the_rest(db) {
            seed_tenant(&db.pool, "demo").await;
            let repo = repo(&db.pool, "demo");
            let digest = register(&db.pool, "demo", "c.abc", "the-token").await;

            // A rich registration, then the state other stories own written on
            // top of it the way their own code paths will.
            let mut rich = registration_document();
            let object = rich.as_object_mut().expect("object");
            object.insert("id_token_signed_response_alg".to_owned(), json!("PS256"));
            object.insert("application_type".to_owned(), json!("native"));
            object.insert("redirect_uris".to_owned(), json!([
                "https://rp.example/cb",
                "https://rp.example/second-cb",
            ]));
            object.insert("authorization_details_types".to_owned(), json!(["payment_initiation"]));
            object.insert("request_object_signing_alg".to_owned(), json!("ES256"));
            object.insert("userinfo_signed_response_alg".to_owned(), json!("ES256"));
            repo.replace(&client("demo", "c.abc", &rich)).await.expect("the first update");

            sqlx::query(
                "update clients
                 set resources = array['https://api.example/accounts'],
                     is_agent = true,
                     agent_owner_sub = 'alice',
                     software_statement = '{\"iss\": \"softwarehouse\"}'::jsonb
                 where tenant_id = 'demo' and client_id = 'c.abc'",
            )
            .execute(&db.pool)
            .await
            .expect("set the columns other stories own");

            let before = repo.find(&ClientId::new("c.abc")).await.expect("find").expect("present");
            assert_eq!(before.registration.redirect_uris.len(), 2);
            // The column is the only place `userinfo_signed_response_alg` can
            // live between two requests, so a registration that survives a
            // write and a read is the whole of it being registrable (`ast-e89`).
            assert_eq!(
                before.registration.userinfo_signed_response_alg,
                Some(asterius_domain::keys::SigningAlgorithm::Es256),
                "the registered UserInfo algorithm did not survive the round trip"
            );

            // A client renaming itself, and saying nothing about anything else.
            let minimal = json!({
                "client_name": "Billing, renamed",
                "redirect_uris": ["https://rp.example/only-cb"],
                "grant_types": ["authorization_code"],
                "jwks": {"keys": [{"kty": "OKP", "crv": "Ed25519", "x": "abc"}]},
            });
            let stored = repo
                .replace(&client("demo", "c.abc", &minimal))
                .await
                .expect("the replacement");

            // The value handed back is the committed row, so the assertions can
            // be made against it — and against a fresh read, which is what a
            // later request would see.
            for after in [stored, repo.find(&ClientId::new("c.abc")).await.expect("find").expect("present")] {
                assert_eq!(after.registration.client_name, "Billing, renamed");
                assert_eq!(
                    after.registration.redirect_uris.iter()
                        .map(asterius_domain::RedirectUri::as_str).collect::<Vec<_>>(),
                    vec!["https://rp.example/only-cb"],
                    "a redirect URI the update did not mention survived"
                );
                assert_eq!(
                    after.registration.id_token_signed_response_alg.as_str(),
                    "EdDSA",
                    "an omitted algorithm kept its old value"
                );
                assert!(
                    after.registration.post_logout_redirect_uris.is_empty(),
                    "a post-logout redirect URI the update did not mention survived"
                );
                assert!(after.registration.authorization_details_types.is_empty());
                assert!(after.registration.request_object_signing_alg.is_none());
                assert!(
                    after.registration.userinfo_signed_response_alg.is_none(),
                    "RFC 7592 §2.2: an omitted member is null, so the client is \
                     back to the JSON UserInfo response it did not ask to leave"
                );
                assert!(after.registration.scopes.is_empty());
                assert_eq!(after.registration.application_type.as_str(), "web");

                // Not the client's to set, and still there.
                assert_eq!(
                    after.registration.resources.iter().map(String::as_str).collect::<Vec<_>>(),
                    vec!["https://api.example/accounts"],
                    "an update erased the per-client resource allow-list"
                );
                assert_eq!(after.status, ClientStatus::Active);
                assert_eq!(after.created_at, before.created_at, "an update moved created_at");
                assert!(after.updated_at >= before.updated_at);
            }

            let row = sqlx::query(
                "select registration_access_token_hash, is_agent, agent_owner_sub,
                        software_statement, client_type
                 from clients where tenant_id = 'demo' and client_id = 'c.abc'",
            )
            .fetch_one(&db.pool)
            .await
            .expect("read the row");
            assert_eq!(
                row.get::<Option<Vec<u8>>, _>("registration_access_token_hash"),
                Some(digest.to_vec()),
                "an update rotated or erased the registration access token"
            );
            assert!(row.get::<bool, _>("is_agent"), "an update erased the agent flag");
            assert_eq!(
                row.get::<Option<String>, _>("agent_owner_sub").as_deref(),
                Some("alice")
            );
            assert!(row.get::<Option<serde_json::Value>, _>("software_statement").is_some());
            assert_eq!(row.get::<String, _>("client_type"), "confidential");
        }
    }

    db_test! {
        /// `replace` updates; it never creates.
        ///
        /// The endpoint authenticates against the row before it writes, so a
        /// missing row here means the client was deleted in between — by its own
        /// concurrent `DELETE`, most likely. Inserting would bring it back from
        /// the dead, with no registration access token and no audit of a
        /// registration that never happened.
        async fn replacing_a_client_that_is_not_there_creates_nothing(db) {
            seed_tenant(&db.pool, "demo").await;
            let repo = repo(&db.pool, "demo");
            let missing = repo.replace(&client("demo", "c.ghost", &registration_document())).await;
            assert!(matches!(missing, Err(DomainError::NotFound)), "{missing:?}");

            let count: i64 = sqlx::query_scalar("select count(*) from clients")
                .fetch_one(&db.pool)
                .await
                .expect("count");
            assert_eq!(count, 0);
        }
    }

    db_test! {
        /// RFC 7592 §2.3 and §5, against the schema's cascades.
        ///
        /// §2.3: a successful delete "will invalidate the `client_id`,
        /// `client_secret`, and `registration_access_token` for this client,
        /// thereby preventing the `client_id` from being used at either the
        /// authorization endpoint or token endpoint", and "If possible, the
        /// authorization
        /// server SHOULD immediately invalidate all existing authorization
        /// grants and currently active access tokens, all refresh tokens, and
        /// all other tokens associated with this client."
        ///
        /// Nothing in the delete path lists those tables, which is the point:
        /// the foreign keys do it, so a table added later with the same cascade
        /// is covered without anybody remembering to extend a statement. What
        /// this test does is name every dependent that exists today and check
        /// the row count, including the two that cascade at one remove through
        /// `grants`.
        ///
        /// And one thing that must *not* go: `audit_events` has no foreign key
        /// to `clients`, so deprovisioning a client does not erase the record of
        /// what it did.
        async fn deprovisioning_a_client_takes_its_grants_and_tokens_with_it(db) {
            seed_tenant(&db.pool, "demo").await;
            let repo = repo(&db.pool, "demo");
            register(&db.pool, "demo", "c.abc", "the-token").await;
            // A second client, so that "everything is gone" can be told apart
            // from "everything of this client is gone".
            register(&db.pool, "demo", "c.other", "another-token").await;

            let grant = "11111111-1111-1111-1111-111111111111";
            for client_id in ["c.abc", "c.other"] {
                sqlx::query(
                    "insert into client_keys (tenant_id, client_id, kid, jwk, expires_at)
                     values ('demo', $1, 'k1', '{}'::jsonb, now() + interval '1 day')",
                )
                .bind(client_id)
                .execute(&db.pool)
                .await
                .expect("seed a client key");
                sqlx::query(
                    "insert into auth_requests
                         (tenant_id, request_uri_hash, client_id, parameters, expires_at)
                     values ('demo', sha256($1::bytea), $2, '{}'::jsonb,
                             now() + interval '60 seconds')",
                )
                .bind(client_id.as_bytes())
                .bind(client_id)
                .execute(&db.pool)
                .await
                .expect("seed a pushed request");
            }
            sqlx::query(
                "insert into grants (tenant_id, grant_id, client_id)
                 values ('demo', $1::uuid, 'c.abc')",
            )
            .bind(grant)
            .execute(&db.pool)
            .await
            .expect("seed a grant");
            sqlx::query(
                "insert into refresh_tokens
                     (tenant_id, token_hash, grant_id, client_id, dpop_jkt,
                      absolute_expires_at)
                 values ('demo', sha256('rt'::bytea), $1::uuid, 'c.abc', 'a-thumbprint',
                         now() + interval '30 days')",
            )
            .bind(grant)
            .execute(&db.pool)
            .await
            .expect("seed a refresh token");
            sqlx::query(
                "insert into authorization_codes
                     (tenant_id, code_hash, client_id, grant_id, code_challenge, redirect_uri,
                      issued_at, expires_at)
                 values ('demo', sha256('code'::bytea), 'c.abc', $1::uuid, 'ch',
                         'https://rp.example/cb', now(), now() + interval '60 seconds')",
            )
            .bind(grant)
            .execute(&db.pool)
            .await
            .expect("seed an authorization code");

            let audit = PgAuditSink::new(db.pool.clone());
            audit
                .record(
                    AuditEvent::new(
                        TenantId::new("demo"),
                        EventType::CLIENT_REGISTERED,
                        Outcome::Success,
                        Actor::Client(ClientId::new("c.abc")),
                        OffsetDateTime::now_utc(),
                    )
                    .client(ClientId::new("c.abc")),
                )
                .await
                .expect("record");

            repo.deprovision(&ClientId::new("c.abc"), OffsetDateTime::now_utc())
                .await
                .expect("deprovision");

            // The client, and with it the only copy of its registration access
            // token: RFC 7592 §5's MUST, satisfied by the row being gone.
            assert!(repo.managed(&ClientId::new("c.abc")).await.expect("read").is_none());

            for (table, column) in [
                ("client_keys", "client_id"),
                ("auth_requests", "client_id"),
                ("grants", "client_id"),
                ("authorization_codes", "client_id"),
                ("refresh_tokens", "client_id"),
            ] {
                let left: i64 = sqlx::query_scalar(&format!(
                    "select count(*) from {table} where tenant_id = 'demo' and {column} = 'c.abc'"
                ))
                .fetch_one(&db.pool)
                .await
                .expect("count");
                assert_eq!(left, 0, "{table} kept a row for a deprovisioned client");
            }

            // The other client kept everything.
            let others: i64 = sqlx::query_scalar(
                "select (select count(*) from clients where client_id = 'c.other')
                      + (select count(*) from client_keys where client_id = 'c.other')
                      + (select count(*) from auth_requests where client_id = 'c.other')",
            )
            .fetch_one(&db.pool)
            .await
            .expect("count");
            assert_eq!(others, 3, "deleting one client took another's rows with it");

            // The trail survives. It is the only record left that the client
            // ever existed, which is exactly why it has no foreign key here.
            let recorded: i64 = sqlx::query_scalar(
                "select count(*) from audit_events where tenant_id = 'demo' and client_id = 'c.abc'",
            )
            .fetch_one(&db.pool)
            .await
            .expect("count");
            assert_eq!(recorded, 1, "the audit trail was cascaded away with the client");

            // A second delete is `NotFound`, not a silent success: two racing
            // DELETEs must not both report having done it.
            assert!(matches!(
                repo.deprovision(&ClientId::new("c.abc"), OffsetDateTime::now_utc()).await,
                Err(DomainError::NotFound)
            ));
        }
    }

    db_test! {
        /// A client whose stored row no longer validates can still authenticate,
        /// update itself and delete itself.
        ///
        /// This is why `managed` reads two scalar columns instead of loading the
        /// client. An operator turning mTLS off leaves every `tls_client_auth`
        /// client unable to load — `find` refuses it, correctly, because it can
        /// no longer authenticate at the token endpoint. If the *management*
        /// endpoint went through the same read, the client's owner could neither
        /// fix the registration nor remove it, and the record would be stranded
        /// with nobody able to reach it.
        async fn a_client_whose_row_no_longer_validates_can_still_be_fixed_or_removed(db) {
            seed_tenant(&db.pool, "demo").await;
            let mtls_on = Capabilities { mtls: true, ..Capabilities::default() };
            let digest = sha256(b"the-token");

            let mut document = registration_document();
            let members = document.as_object_mut().expect("object");
            members.insert("token_endpoint_auth_method".to_owned(), json!("tls_client_auth"));
            members.insert("tls_client_auth_subject_dn".to_owned(), json!("CN=c.abc,O=Demo"));
            Store::from_pool(db.pool.clone())
                .scope(TenantId::new("demo"))
                .clients(mtls_on)
                .register(&client_with("demo", "c.abc", &document, mtls_on), &digest)
                .await
                .expect("register while mtls is on");

            // mTLS is off now. The ordinary read refuses the row.
            let off = repo(&db.pool, "demo");
            assert!(off.find(&ClientId::new("c.abc")).await.is_err());

            // The management read does not, so the endpoint can still
            // authenticate the client that owns it.
            let managed = off
                .managed(&ClientId::new("c.abc"))
                .await
                .expect("the management read must not validate the document")
                .expect("present");
            assert_eq!(managed.registration_access_token, Some(digest));
            assert_eq!(managed.status, ClientStatus::Active);

            // And it can replace the offending document with one this
            // deployment does accept.
            let fixed = off
                .replace(&client("demo", "c.abc", &registration_document()))
                .await
                .expect("the client must be able to fix its own registration");
            assert_eq!(fixed.registration.token_endpoint_auth_method.as_str(), "private_key_jwt");
            assert!(off.find(&ClientId::new("c.abc")).await.expect("find").is_some());

            // Or, had it chosen to, remove it.
            off.deprovision(&ClientId::new("c.abc"), OffsetDateTime::now_utc())
                .await
                .expect("deprovision");
            assert!(off.managed(&ClientId::new("c.abc")).await.expect("read").is_none());
        }
    }

    db_test! {
        /// A suspended client is readable through `managed` and refused by the
        /// endpoint (RFC 7592 §2.1's 403), which needs the status to survive the
        /// read — and to survive an update, since a client must not be able to
        /// lift its own suspension by replacing its registration.
        async fn a_suspended_client_keeps_its_status_through_an_update(db) {
            seed_tenant(&db.pool, "demo").await;
            let repo = repo(&db.pool, "demo");
            register(&db.pool, "demo", "c.abc", "the-token").await;
            sqlx::query(
                "update clients set status = 'disabled'
                 where tenant_id = 'demo' and client_id = 'c.abc'",
            )
            .execute(&db.pool)
            .await
            .expect("suspend");

            assert_eq!(
                repo.managed(&ClientId::new("c.abc")).await.expect("read").expect("present").status,
                ClientStatus::Disabled
            );

            // `Client::status` on the entity is `Active` here, and the statement
            // does not write the column, so the suspension stands.
            let mut lifted = client("demo", "c.abc", &registration_document());
            lifted.status = ClientStatus::Active;
            let stored = repo.replace(&lifted).await.expect("replace");
            assert_eq!(
                stored.status,
                ClientStatus::Disabled,
                "a client lifted its own suspension by updating itself"
            );
            assert_eq!(
                repo.managed(&ClientId::new("c.abc")).await.expect("read").expect("present").status,
                ClientStatus::Disabled
            );
        }
    }

    db_test! {
        /// A rotation demotes the current digest and issues a new one, in one
        /// statement (`ast-m9c.12`, RFC 7592 §5).
        ///
        /// The property that needs a real database is the column dependency:
        /// `previous_registration_access_token_hash` takes the value
        /// `registration_access_token_hash` had *before* the assignment, which
        /// is Postgres' rule about `update` and not something a fake can prove.
        /// Get it wrong and the predecessor is the token being issued, so the
        /// old one dies immediately and the lost-response case is back.
        async fn a_rotation_demotes_the_current_token_and_dates_its_grace(db) {
            seed_tenant(&db.pool, "demo").await;
            let repo = repo(&db.pool, "demo");
            let original = register(&db.pool, "demo", "c.abc", "the-token").await;
            let fresh = sha256(b"the-next-token");
            let expires_at = OffsetDateTime::now_utc() + time::Duration::minutes(5);

            repo.rotate_registration_access_token(&ClientId::new("c.abc"), &fresh, expires_at)
                .await
                .expect("rotate");

            let managed = repo
                .managed(&ClientId::new("c.abc"))
                .await
                .expect("read")
                .expect("present");
            assert_eq!(managed.registration_access_token, Some(fresh));
            let previous = managed
                .previous_registration_access_token
                .expect("the rotated-out token must survive its grace window");
            assert_eq!(previous.digest, original);
            // Round-tripped through `timestamptz`, so equality is to the
            // microsecond Postgres keeps.
            assert_eq!(
                previous.grace_expires_at.unix_timestamp(),
                expires_at.unix_timestamp()
            );
            assert!(previous.is_within_grace(OffsetDateTime::now_utc()));
            assert!(!previous.is_within_grace(expires_at));

            // A second rotation overwrites the predecessor rather than keeping
            // a third generation alive.
            let newest = sha256(b"the-third-token");
            repo.rotate_registration_access_token(&ClientId::new("c.abc"), &newest, expires_at)
                .await
                .expect("rotate again");
            let managed = repo
                .managed(&ClientId::new("c.abc"))
                .await
                .expect("read")
                .expect("present");
            assert_eq!(managed.registration_access_token, Some(newest));
            assert_eq!(
                managed.previous_registration_access_token.expect("present").digest,
                fresh,
                "a rotation kept a generation older than the one it replaced"
            );
        }
    }

    db_test! {
        /// Retiring clears both columns, is idempotent, and never mints one.
        ///
        /// The `is not null` in the statement is what keeps the ordinary case —
        /// an authenticated request from a client that has never rotated —
        /// writing nothing at all, and the row's `updated_at` is how that shows
        /// from outside.
        async fn retiring_a_predecessor_clears_both_columns_and_is_idempotent(db) {
            seed_tenant(&db.pool, "demo").await;
            let repo = repo(&db.pool, "demo");
            register(&db.pool, "demo", "c.abc", "the-token").await;

            // Nothing to retire is not a failure, and it is not a write.
            let before: OffsetDateTime = sqlx::query_scalar(
                "select updated_at from clients where tenant_id = 'demo' and client_id = 'c.abc'",
            )
            .fetch_one(&db.pool)
            .await
            .expect("updated_at");
            repo.retire_previous_registration_access_token(&ClientId::new("c.abc"))
                .await
                .expect("retire nothing");
            let after: OffsetDateTime = sqlx::query_scalar(
                "select updated_at from clients where tenant_id = 'demo' and client_id = 'c.abc'",
            )
            .fetch_one(&db.pool)
            .await
            .expect("updated_at");
            assert_eq!(before, after, "retiring nothing touched the row");

            repo.rotate_registration_access_token(
                &ClientId::new("c.abc"),
                &sha256(b"the-next-token"),
                OffsetDateTime::now_utc() + time::Duration::minutes(5),
            )
            .await
            .expect("rotate");

            repo.retire_previous_registration_access_token(&ClientId::new("c.abc"))
                .await
                .expect("retire");

            let managed = repo
                .managed(&ClientId::new("c.abc"))
                .await
                .expect("read")
                .expect("present");
            assert!(managed.previous_registration_access_token.is_none());
            // Both columns, so the check constraint is satisfied and no half-row
            // is left for the reader to interpret.
            let expiry: Option<OffsetDateTime> = sqlx::query_scalar(
                "select previous_registration_access_token_expires_at from clients
                 where tenant_id = 'demo' and client_id = 'c.abc'",
            )
            .fetch_one(&db.pool)
            .await
            .expect("expiry");
            assert!(expiry.is_none(), "a predecessor's expiry outlived its digest");
            assert!(
                managed.registration_access_token.is_some(),
                "retiring the predecessor took the current credential with it"
            );

            // Idempotent.
            repo.retire_previous_registration_access_token(&ClientId::new("c.abc"))
                .await
                .expect("retire twice");
        }
    }

    db_test! {
        /// RFC 7592 §2.3: a deprovisioning "SHOULD immediately invalidate all
        /// existing authorization grants and currently active access tokens".
        /// The cascade covers everything with a row; an access token already
        /// issued has none — it is a signed JWT this server does not hold, and
        /// this schema has never inventoried the `jti` values it signed.
        ///
        /// So the delete leaves a cutoff behind, keyed by `client_id` and not
        /// by token, and the resource path refuses anything issued before it
        /// (`ast-m9c.13`). The mark cannot be a column on `clients`: this is a
        /// real delete, so it would be erased by the act it records.
        async fn deprovisioning_a_client_withdraws_the_access_tokens_it_had_issued(db) {
            // Arrange: two clients, so "everything is withdrawn" can be told
            // apart from "everything of this client is withdrawn".
            seed_tenant(&db.pool, "demo").await;
            register(&db.pool, "demo", "c.abc", "the-token").await;
            register(&db.pool, "demo", "c.other", "another-token").await;
            let deprovisioned_at =
                OffsetDateTime::from_unix_timestamp(1_760_000_000).expect("a fixed instant");

            // Act
            repo(&db.pool, "demo")
                .deprovision(&ClientId::new("c.abc"), deprovisioned_at)
                .await
                .expect("deprovision");

            // Assert
            let grants = PgGrantRepository::new(db.pool.clone(), TenantId::new("demo"));
            assert_eq!(
                grants.revoked_before(&ClientId::new("c.abc"), None).await.expect("read"),
                Some(deprovisioned_at),
                "a deprovisioned client left no cutoff, so its access tokens still verify"
            );
            assert_eq!(
                grants.revoked_before(&ClientId::new("c.other"), None).await.expect("read"),
                None,
                "deprovisioning one client withdrew another's access tokens"
            );
        }
    }

    db_test! {
        /// A client that was never issued a registration access token is not
        /// given one by a rotation, and a rotation aimed at another tenant's
        /// client writes nothing.
        ///
        /// OIDC Registration §3.2 — "both or neither" — has to survive every
        /// statement that touches the column, not just the one that registers.
        async fn a_rotation_cannot_mint_a_credential_for_a_client_that_has_none(db) {
            seed_tenant(&db.pool, "demo").await;
            seed_tenant(&db.pool, "other").await;
            let other = repo(&db.pool, "other");
            let repo = repo(&db.pool, "demo");
            let expires_at = OffsetDateTime::now_utc() + time::Duration::minutes(5);

            // Created by the admin path: no configuration endpoint at all.
            repo.upsert(&client("demo", "c.admin", &registration_document()))
                .await
                .expect("upsert");
            assert!(matches!(
                repo.rotate_registration_access_token(
                    &ClientId::new("c.admin"),
                    &sha256(b"unearned"),
                    expires_at,
                )
                .await,
                Err(DomainError::NotFound)
            ));
            assert_eq!(
                repo.managed(&ClientId::new("c.admin")).await.expect("read")
                    .expect("present").registration_access_token,
                None,
                "a rotation handed a credential to a client that was given none"
            );

            // No such client at all.
            assert!(matches!(
                repo.rotate_registration_access_token(
                    &ClientId::new("c.nobody"),
                    &sha256(b"unearned"),
                    expires_at,
                )
                .await,
                Err(DomainError::NotFound)
            ));

            // Another tenant's client, under an identifier this scope does not
            // hold: scoped like every other statement on this port.
            let theirs = register(&db.pool, "other", "c.theirs", "their-token").await;
            assert!(matches!(
                repo.rotate_registration_access_token(
                    &ClientId::new("c.theirs"),
                    &sha256(b"unearned"),
                    expires_at,
                )
                .await,
                Err(DomainError::NotFound)
            ));
            assert_eq!(
                other.managed(&ClientId::new("c.theirs")).await.expect("read")
                    .expect("present").registration_access_token,
                Some(theirs),
                "a rotation crossed a tenant boundary"
            );
        }
    }

    db_test! {
        /// The mark stops existing when the last token it could refuse has
        /// expired on its own `exp`. An access token's lifetime is capped at
        /// fifteen minutes whatever a tenant asks for
        /// (`MAX_ACCESS_TOKEN_LIFETIME`), so that is how long past the cutoff a
        /// row can still be refusing something — and after it, retention takes
        /// it. Without the bound the table would grow with every
        /// deprovisioning, forever, which is what an inventory of every issued
        /// `jti` was rejected for.
        async fn a_client_cutoff_expires_with_the_last_token_it_could_refuse(db) {
            // Arrange
            seed_tenant(&db.pool, "demo").await;
            register(&db.pool, "demo", "c.abc", "the-token").await;
            let deprovisioned_at =
                OffsetDateTime::from_unix_timestamp(1_760_000_000).expect("a fixed instant");

            // Act
            repo(&db.pool, "demo")
                .deprovision(&ClientId::new("c.abc"), deprovisioned_at)
                .await
                .expect("deprovision");

            // Assert
            let expires_at: OffsetDateTime = sqlx::query_scalar(
                "select expires_at from access_token_cutoffs
                  where tenant_id = 'demo' and principal_kind = 'client'
                    and principal_id = 'c.abc'",
            )
            .fetch_one(&db.pool)
            .await
            .expect("the cutoff row");
            assert_eq!(
                expires_at,
                deprovisioned_at + MAX_ACCESS_TOKEN_LIFETIME,
                "a cutoff outliving the tokens it refuses is a table that grows forever"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Retention (`ast-p2l.4`)
// ---------------------------------------------------------------------------

mod retention {
    use super::*;
    use asterius_domain::ClientId;
    use asterius_domain::ports::ClientUsageRecorder as _;
    use asterius_store_pg::{POLICY, PgClientUsage, PgRetention, Rule, SweepOutcome};
    use time::Duration;

    fn sweeper(pool: &PgPool) -> PgRetention {
        PgRetention::new(pool.clone())
    }

    fn now() -> OffsetDateTime {
        // A round instant rather than the wall clock, so a failure is
        // reproducible and the seeded offsets are readable.
        OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("a valid instant")
    }

    /// Every table the policy sweeps, in policy order.
    fn swept_tables() -> Vec<&'static str> {
        POLICY
            .iter()
            .filter(|entry| matches!(entry.rule, Rule::Sweep { .. }))
            .map(|entry| entry.table)
            .collect()
    }

    async fn count(pool: &PgPool, table: &str, tenant: &str) -> i64 {
        // The table name is a compile-time constant from `POLICY`, never input.
        sqlx::query_scalar(&format!(
            "select count(*) from {table} where tenant_id = $1"
        ))
        .bind(tenant)
        .fetch_one(pool)
        .await
        .unwrap_or_else(|e| panic!("count {table}: {e}"))
    }

    /// Puts one expired row and one live row in every swept table.
    ///
    /// "Expired" is two days behind `now`, which is past the longest grace in
    /// the policy bar the outbox's; the outbox rows are seeded separately at
    /// eight days. Written as raw SQL because most of these tables belong to
    /// stories that have not landed yet, and what this test needs is the row,
    /// not the repository that will eventually write it.
    async fn seed(pool: &PgPool, tenant: &str) {
        let user = uuid::Uuid::from_u128(0x5e_ed);
        let grant = uuid::Uuid::from_u128(0x9_2a_47);

        seed_owners(pool, tenant, user, grant).await;
        // One grant with no resource owner, expired long enough ago to be past
        // the policy's window: `grants` is a swept table since `ast-wgx`, and
        // the table-by-table criterion above needs a row it is allowed to take.
        seed_client_only_grant(
            pool,
            tenant,
            client_only_grant("stale"),
            now() - Duration::days(30),
        )
        .await;
        for (label, expires) in [
            ("stale", now() - Duration::days(2)),
            ("fresh", now() + Duration::hours(1)),
        ] {
            seed_expiring_rows(pool, tenant, user, grant, label, expires).await;
            // Called here rather than from `seed_expiring_rows`, which is at
            // clippy's line ceiling: this row belongs to the same stale/fresh
            // pair and to no other fixture.
            seed_initial_access_token(pool, tenant, label, expires).await;
            seed_recovery_token(pool, tenant, user, label, expires).await;
        }
        seed_outbox(pool, tenant).await;
    }

    /// The rows everything else hangs off: the tenant, one client, one user and
    /// one grant. Only the idle client below is swept.
    async fn seed_owners(pool: &PgPool, tenant: &str, user: uuid::Uuid, grant: uuid::Uuid) {
        seed_tenant(pool, tenant).await;
        // The tenant asked for idle clients to be swept (`ast-cu3`). Without
        // this the `clients` rule matches nothing at all, which is the default
        // and which would leave the table-by-table criterion below asserting
        // over a rule no tenant has switched on.
        seed_unused_client_expiry(pool, tenant, Duration::days(30)).await;

        sqlx::query(
            "insert into clients (tenant_id, client_id, client_name,
                                  token_endpoint_auth_method, jwks, last_used_at)
             values ($1, 'billing', 'Billing', 'private_key_jwt', '{\"keys\":[]}'::jsonb, $2)",
        )
        .bind(tenant)
        .bind(now())
        .execute(pool)
        .await
        .expect("seed client");

        // The one row the `clients` rule is allowed to take: a client nobody
        // has authenticated as since well before the tenant's window. It owns
        // nothing else, so its deletion cascades over no other seeded row and
        // the per-table counts stay readable.
        seed_idle_client(pool, tenant, "abandoned", now() - Duration::days(90)).await;

        sqlx::query("insert into users (tenant_id, user_id, username) values ($1, $2, 'alice')")
            .bind(tenant)
            .bind(user)
            .execute(pool)
            .await
            .expect("seed user");

        // The tenant's registered API (RFC 8707). Configuration, like the
        // client beside it: the sweep must leave it alone, or every token
        // request naming it would answer `invalid_target` the next morning.
        sqlx::query(
            "insert into resource_servers (tenant_id, identifier)
             values ($1, 'https://api.example/')
             on conflict do nothing",
        )
        .bind(tenant)
        .execute(pool)
        .await
        .expect("seed resource server");

        // A registered authorization details type (RFC 9396). Configuration
        // too: an unregistered type is refused, so a sweep that took this row
        // would turn every `authorization_details` request into
        // `invalid_authorization_details` overnight.
        sqlx::query(
            "insert into authorization_details_types (tenant_id, type_name, consent_template)
             values ($1, 'payment_initiation', 'Initiate a payment on your behalf')
             on conflict do nothing",
        )
        .bind(tenant)
        .execute(pool)
        .await
        .expect("seed authorization details type");

        sqlx::query(
            "insert into grants (tenant_id, grant_id, client_id, user_id)
             values ($1, $2, 'billing', $3)",
        )
        .bind(tenant)
        .bind(grant)
        .bind(user)
        .execute(pool)
        .await
        .expect("seed grant");

        // A tenant-scoped role on that user. Kept by the policy, and here so
        // that "the sweep does not touch a kept table" is asserted about
        // `user_roles` with a real row rather than by an exemption.
        sqlx::query(
            "insert into user_roles (tenant_id, user_id, role, tenant_is_reserved)
             select $1, $2, 'tenant_admin', t.is_reserved from tenants t
              where t.tenant_id = $1",
        )
        .bind(tenant)
        .bind(user)
        .execute(pool)
        .await
        .expect("seed role");

        // A retired `sub` (`ast-2vk.12`). Kept by the policy and never swept —
        // a tombstone with an expiry is a `sub` that comes back — so the
        // kept-table test needs a row here to be able to say anything.
        sqlx::query(
            "insert into retired_subject_identifiers (tenant_id, subject, sector_identifier)
             values ($1, 'a-sub-nobody-gets-again', 'rp.example')
             on conflict do nothing",
        )
        .bind(tenant)
        .execute(pool)
        .await
        .expect("seed retired subject");

        seed_theme(pool, tenant).await;
    }

    /// The tenant's theme and one image it could name (`ast-ndk.1`).
    ///
    /// Both tables are kept by the policy — a palette an administrator chose
    /// is configuration, not an artefact of one authorization — so the
    /// kept-table criterion needs a row in each before it can say anything
    /// about them. The document is the default one so that it is a document
    /// this build accepts: a fixture the theme repository would refuse to read
    /// is a fixture that lies about what is stored.
    async fn seed_theme(pool: &PgPool, tenant: &str) {
        sqlx::query(
            "insert into tenant_themes (tenant_id, document) values ($1, $2)
             on conflict do nothing",
        )
        .bind(tenant)
        .bind(asterius_domain::Theme::default().to_json())
        .execute(pool)
        .await
        .expect("seed theme");

        // Content addressed, so the digest is computed rather than invented:
        // the column is what a URL path segment is built from, and a fixture
        // whose digest does not match its bytes is one nothing else can check.
        let bytes = b"not really a png, but it is what was stored".to_vec();
        let digest = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&bytes));
        sqlx::query(
            "insert into tenant_theme_assets (tenant_id, digest, content_type, bytes)
             values ($1, $2, 'image/png', $3)
             on conflict do nothing",
        )
        .bind(tenant)
        .bind(digest)
        .bind(bytes)
        .execute(pool)
        .await
        .expect("seed theme asset");
    }

    /// One row per swept expiry-driven table, expiring at `expires`.
    async fn seed_expiring_rows(
        pool: &PgPool,
        tenant: &str,
        user: uuid::Uuid,
        grant: uuid::Uuid,
        label: &str,
        expires: OffsetDateTime,
    ) {
        let old = now() - Duration::days(2);
        {
            sqlx::query(
                "insert into client_keys (tenant_id, client_id, kid, jwk, expires_at)
                 values ($1, 'billing', $2, '{}'::jsonb, $3)",
            )
            .bind(tenant)
            .bind(label)
            .bind(expires)
            .execute(pool)
            .await
            .expect("seed client key");

            seed_client_key_fetch(pool, tenant, label, old, expires).await;

            sqlx::query(
                "insert into sessions (tenant_id, session_id, public_sid, user_id,
                                       authenticated_at, expires_at, idle_expires_at)
                 values ($1, $2, $2, $3, $4, $5, $5)",
            )
            .bind(tenant)
            .bind(label)
            .bind(user)
            .bind(old)
            .bind(expires)
            .execute(pool)
            .await
            .expect("seed session");

            seed_passkey_enrolment(pool, tenant, label, expires).await;
            seed_first_party_interaction(pool, tenant, label, expires).await;

            sqlx::query(
                "insert into auth_requests (tenant_id, request_uri_hash, client_id,
                                            parameters, expires_at)
                 values ($1, $2, 'billing', '{}'::jsonb, $3)",
            )
            .bind(tenant)
            .bind(asterius_domain::sha256(label.as_bytes()).to_vec())
            .bind(expires)
            .execute(pool)
            .await
            .expect("seed auth request");

            // A code's lifetime is capped at 60 seconds by the schema, so the
            // stale one is old by virtue of when it was issued.
            sqlx::query(
                "insert into authorization_codes
                     (tenant_id, code_hash, client_id, grant_id, code_challenge,
                      redirect_uri, issued_at, expires_at)
                 values ($1, $2, 'billing', $3, 'a-challenge',
                         'https://client.example/cb', $4, $4 + interval '60 seconds')",
            )
            .bind(tenant)
            .bind(asterius_domain::sha256(label.as_bytes()).to_vec())
            .bind(grant)
            .bind(if label == "stale" { old } else { now() })
            .execute(pool)
            .await
            .expect("seed authorization code");

            sqlx::query(
                "insert into refresh_tokens (tenant_id, token_hash, grant_id, client_id,
                                             dpop_jkt, absolute_expires_at)
                 values ($1, $2, $3, 'billing', 'a-thumbprint', $4)",
            )
            .bind(tenant)
            .bind(asterius_domain::sha256(label.as_bytes()).to_vec())
            .bind(grant)
            .bind(expires)
            .execute(pool)
            .await
            .expect("seed refresh token");

            seed_denylist_entry(pool, tenant, label, grant, expires).await;

            seed_access_token_cutoff(pool, tenant, label, expires).await;

            sqlx::query(
                "insert into jti_replay (tenant_id, purpose, subject, jti_hash, expires_at)
                 values ($1, 'client_assertion', 'billing', $2, $3)",
            )
            .bind(tenant)
            .bind(asterius_domain::sha256(label.as_bytes()).to_vec())
            .bind(expires)
            .execute(pool)
            .await
            .expect("seed replay marker");

            sqlx::query(
                "insert into rate_limits (tenant_id, bucket, window_start, expires_at)
                 values ($1, $2, $3, $4)",
            )
            .bind(tenant)
            .bind(label)
            .bind(old)
            .bind(expires)
            .execute(pool)
            .await
            .expect("seed rate limit");
        }
    }

    /// One negative cache entry per seeded label (`ast-mxc.8`).
    ///
    /// Expired once `next_attempt_at` has passed: from that instant the row
    /// suppresses no fetch, so keeping it would only accumulate a row per URL
    /// a client ever mistyped.
    async fn seed_client_key_fetch(
        pool: &PgPool,
        tenant: &str,
        label: &str,
        attempted: OffsetDateTime,
        next_attempt: OffsetDateTime,
    ) {
        sqlx::query(
            "insert into client_key_fetches (tenant_id, client_id, jwks_uri_hash,
                                             last_attempt_at, last_error, next_attempt_at)
             values ($1, 'billing', $2, $3, 'cannot connect to client.example', $4)",
        )
        .bind(tenant)
        .bind(asterius_domain::sha256(label.as_bytes()).to_vec())
        .bind(attempted)
        .bind(next_attempt)
        .execute(pool)
        .await
        .expect("seed client key fetch");
    }

    /// One enrolment per seeded session, expiring with it.
    ///
    /// `ast-2vk.15` added the table and its `POLICY` rule; without a row here
    /// the sweep has nothing to delete and the criterion above cannot see
    /// whether the rule works. It is swept before `sessions` — see `POLICY` —
    /// so the expired row is reported by its own rule rather than vanishing
    /// under the session's cascade.
    async fn seed_passkey_enrolment(
        pool: &PgPool,
        tenant: &str,
        session: &str,
        expires: OffsetDateTime,
    ) {
        sqlx::query(
            "insert into passkey_enrolments (tenant_id, session_id, csrf_digest,
                                             challenge, expires_at)
             values ($1, $2, $3, $4, $5)",
        )
        .bind(tenant)
        .bind(session)
        .bind(asterius_domain::sha256_hex(session.as_bytes()))
        .bind(vec![7_u8; 32])
        .bind(expires)
        .execute(pool)
        .await
        .expect("seed passkey enrolment");
    }

    /// The console's login (`ast-wr4`), in the table that holds the
    /// interactions with no client behind them. Without a row here the sweep
    /// has nothing to delete and the criterion above cannot see whether the
    /// rule works.
    async fn seed_first_party_interaction(
        pool: &PgPool,
        tenant: &str,
        label: &str,
        expires: OffsetDateTime,
    ) {
        sqlx::query(
            "insert into first_party_interactions (tenant_id, interaction_id_hash,
                                                   destination, expires_at)
             values ($1, $2, 'admin_console', $3)",
        )
        .bind(tenant)
        // The tenant is part of the digest because the column is unique across
        // the table, as an interaction id is across a deployment: two tenants
        // seeded in one database must not collide where two browsers never
        // would.
        .bind(asterius_domain::sha256(format!("console-{tenant}-{label}").as_bytes()).to_vec())
        .bind(expires)
        .execute(pool)
        .await
        .expect("seed first-party interaction");
    }

    /// A stable grant id per label, so a test can seed one and then look for it.
    fn client_only_grant(label: &str) -> uuid::Uuid {
        uuid::Uuid::from_slice(&asterius_domain::sha256(label.as_bytes())[..16])
            .expect("sixteen bytes are a uuid")
    }

    /// The row every `client_credentials` request leaves behind (`ast-a05.8`):
    /// no user, no subject, no session, claimed at once, expiring with the
    /// access token it was minted for.
    async fn seed_client_only_grant(
        pool: &PgPool,
        tenant: &str,
        grant: uuid::Uuid,
        expires: OffsetDateTime,
    ) {
        sqlx::query(
            "insert into grants (tenant_id, grant_id, client_id, scopes,
                                 created_at, claimed_at, expires_at)
             values ($1, $2, 'billing', '{invoices.read}', $3, $3, $3)",
        )
        .bind(tenant)
        .bind(grant)
        .bind(expires)
        .execute(pool)
        .await
        .expect("seed client-only grant");
    }

    /// A grant with a person behind it, expired as long ago as the client-only
    /// one, so that "expired" cannot be the only thing the rule looks at.
    async fn seed_user_grant(
        pool: &PgPool,
        tenant: &str,
        user: uuid::Uuid,
        grant: uuid::Uuid,
        expires: OffsetDateTime,
    ) {
        sqlx::query(
            "insert into grants (tenant_id, grant_id, client_id, user_id, subject,
                                 scopes, created_at, claimed_at, expires_at)
             values ($1, $2, 'billing', $3, 'alice', '{openid,offline_access}', $4, $4, $4)",
        )
        .bind(tenant)
        .bind(grant)
        .bind(user)
        .bind(expires)
        .execute(pool)
        .await
        .expect("seed user grant");
    }

    /// Whether that grant is still stored.
    async fn grant_exists(pool: &PgPool, tenant: &str, grant: uuid::Uuid) -> bool {
        let count: i64 = sqlx::query_scalar(
            "select count(*) from grants where tenant_id = $1 and grant_id = $2",
        )
        .bind(tenant)
        .bind(grant)
        .fetch_one(pool)
        .await
        .expect("count grants");
        count > 0
    }

    /// One initial access token of `tenant`, expiring at `expires` (`ast-cu3`).
    ///
    /// The expiry is the whole rule: past it the row is only a digest and a
    /// spent counter, and keeping the digest of every token a tenant ever
    /// issued turns a database dump into a list of guesses worth trying
    /// against every other deployment the operator runs.
    ///
    /// The digest is derived from the tenant *and* the label, because
    /// `token_hash` is unique across the deployment and not merely within a
    /// tenant: the tests that sweep two tenants in one schema would otherwise
    /// collide on it. It is computed in SQL rather than in Rust because what
    /// this fixture needs is thirty-two bytes that satisfy the column's check,
    /// not a credential anybody presents.
    async fn seed_initial_access_token(
        pool: &PgPool,
        tenant: &str,
        label: &str,
        expires: OffsetDateTime,
    ) {
        sqlx::query(
            "insert into initial_access_tokens (id, tenant_id, label, token_hash,
                                                max_uses, expires_at, created_by)
             values ($1, $2, $3, sha256(convert_to($2 || ':' || $3, 'UTF8')), 5, $4, 'seed')",
        )
        .bind(uuid::Uuid::new_v4())
        .bind(tenant)
        .bind(label)
        .bind(expires)
        .execute(pool)
        .await
        .expect("seed initial access token");
    }

    /// Stores `unused_client_expiry_seconds` on the tenant's settings.
    ///
    /// Written where the settings repository writes it —
    /// `settings -> 'options' -> 'registration_policy'` — because the sweep
    /// reads that path in SQL, and a fixture that put the number anywhere else
    /// would make the rule look broken.
    async fn seed_unused_client_expiry(pool: &PgPool, tenant: &str, expiry: Duration) {
        sqlx::query(
            "update tenants
                set settings = coalesce(settings, '{}'::jsonb)
                               || jsonb_build_object('options', jsonb_build_object(
                                      'registration_policy', jsonb_build_object(
                                          'unused_client_expiry_seconds', $2::bigint)))
              where tenant_id = $1",
        )
        .bind(tenant)
        .bind(expiry.whole_seconds())
        .execute(pool)
        .await
        .expect("seed the tenant's registration policy");
    }

    /// A client last used at `last_used_at`, owning nothing else.
    async fn seed_idle_client(pool: &PgPool, tenant: &str, id: &str, last_used_at: OffsetDateTime) {
        sqlx::query(
            "insert into clients (tenant_id, client_id, client_name,
                                  token_endpoint_auth_method, jwks, last_used_at)
             values ($1, $2, 'Abandoned', 'private_key_jwt', '{\"keys\":[]}'::jsonb, $3)",
        )
        .bind(tenant)
        .bind(id)
        .bind(last_used_at)
        .execute(pool)
        .await
        .expect("seed idle client");
    }

    /// One access token withdrawn by its own `jti`, until its own `exp`.
    async fn seed_denylist_entry(
        pool: &PgPool,
        tenant: &str,
        label: &str,
        grant: uuid::Uuid,
        expires: OffsetDateTime,
    ) {
        sqlx::query(
            "insert into access_token_denylist (tenant_id, jti, grant_id, expires_at)
             values ($1, $2, $3, $4)",
        )
        .bind(tenant)
        .bind(label)
        .bind(grant)
        .bind(expires)
        .execute(pool)
        .await
        .expect("seed denylist entry");
    }

    /// The bulk withdrawal a deprovisioning or a refresh-token revocation
    /// leaves behind (`ast-m9c.13`).
    ///
    /// Its `expires_at` is the cutoff plus the cap on an access token's
    /// lifetime, which is how the writer computes it — so the row seeded here
    /// is shaped like the ones the repositories write.
    async fn seed_access_token_cutoff(
        pool: &PgPool,
        tenant: &str,
        label: &str,
        expires: OffsetDateTime,
    ) {
        sqlx::query(
            "insert into access_token_cutoffs
                 (tenant_id, principal_kind, principal_id, revoked_before, expires_at)
             values ($1, 'client', $2, $3, $4)",
        )
        .bind(tenant)
        .bind(label)
        .bind(expires - Duration::minutes(15))
        .bind(expires)
        .execute(pool)
        .await
        .expect("seed access token cutoff");
    }

    /// A reset link, live or spent (`ast-2vk.10`).
    ///
    /// `issued_at` is placed before `expires_at` rather than at `now()`,
    /// because the table refuses a row whose link expired before it was drawn
    /// and the stale fixture is dated in the past.
    async fn seed_recovery_token(
        pool: &PgPool,
        tenant: &str,
        user: uuid::Uuid,
        label: &str,
        expires: OffsetDateTime,
    ) {
        sqlx::query(
            "insert into recovery_tokens
                 (tenant_id, token_hash, user_id, issued_at, expires_at)
             values ($1, $2, $3, $4, $5)",
        )
        .bind(tenant)
        .bind(format!("digest-of-a-{label}-recovery-link"))
        .bind(user)
        .bind(expires - Duration::minutes(15))
        .bind(expires)
        .execute(pool)
        .await
        .expect("seed recovery token");
    }

    /// The outbox is aged rather than expiring, and only a terminal row is ever
    /// swept: `pending` is work still owed, however old it looks.
    async fn seed_outbox(pool: &PgPool, tenant: &str) {
        sqlx::query(
            "insert into outbox (tenant_id, kind, destination, payload, status,
                                 created_at, delivered_at)
             values ($1, 'logout_token', 'https://rp.example/bc', '{}'::jsonb,
                     'delivered', $2, $2),
                    ($1, 'logout_token', 'https://rp.example/bc', '{}'::jsonb,
                     'delivered', $3, $3),
                    ($1, 'logout_token', 'https://rp.example/bc', '{}'::jsonb,
                     'pending', $2, null)",
        )
        .bind(tenant)
        .bind(now() - Duration::days(8))
        .bind(now())
        .execute(pool)
        .await
        .expect("seed outbox");

        // One attempt, so the `Kept` rule for `outbox_attempts` has something
        // to be checked against (`ast-0ju.9`). It is kept rather than swept
        // because it cascades from `outbox`: the trail of a delivery
        // disappears exactly when the row it describes does, and a second
        // cutoff here would either outlive the row or predecease it.
        //
        // Against the *pending* row, and that is the whole point: an attempt
        // hung off the delivered row eight days old is deleted by the cascade
        // when the sweep takes its parent, and "a kept table the sweep did not
        // empty" then reads as emptied. A delivery still owed, whose first
        // attempt was refused, is what the rule is about anyway.
        sqlx::query(
            "insert into outbox_attempts
                 (tenant_id, outbox_id, attempt, attempted_at, outcome, detail)
             select $1, outbox_id, 1, $2, 'retry', 'the relying party answered 503'
               from outbox
              where tenant_id = $1 and status = 'pending'",
        )
        .bind(tenant)
        .bind(now() - Duration::days(8))
        .execute(pool)
        .await
        .expect("seed an outbox attempt");
    }

    db_test! {
        /// The first acceptance criterion, table by table: seed an expired row
        /// and a live one everywhere, sweep, and require that exactly the
        /// expired one is gone. Driven off `POLICY` rather than a hand-written
        /// list, so a rule added without a seeded row fails here rather than
        /// being untested.
        async fn a_sweep_removes_the_expired_row_from_every_swept_table(db) {
            seed(&db.pool, "demo").await;

            let outcome = sweeper(&db.pool)
                .sweep_tenant(&TenantId::new("demo"), now())
                .await
                .expect("sweep");
            let SweepOutcome::Swept(sweep) = outcome else {
                panic!("an uncontended sweep must do the work");
            };

            for table in swept_tables() {
                let remaining = count(&db.pool, table, "demo").await;
                let expected = if table == "outbox" { 2 } else { 1 };
                assert_eq!(
                    remaining, expected,
                    "{table} has {remaining} rows after the sweep, expected {expected}; \
                     swept {:?}",
                    sweep.deleted
                );
                assert!(
                    sweep.deleted.iter().any(|(swept, count)| *swept == table && *count > 0),
                    "{table} lost rows but the sweep did not report them: {:?}",
                    sweep.deleted
                );
            }
            assert!(!sweep.more_to_do, "one row per table is not a backlog");
        }
    }

    db_test! {
        /// The live rows are the other half of the criterion: a sweep that
        /// deleted everything would pass the test above and sign every user out.
        async fn a_sweep_leaves_the_live_row_alone(db) {
            seed(&db.pool, "demo").await;
            sweeper(&db.pool)
                .sweep_tenant(&TenantId::new("demo"), now())
                .await
                .expect("sweep");

            let live: i64 = sqlx::query_scalar(
                "select count(*) from sessions where tenant_id = $1 and session_id = 'fresh'",
            )
            .bind("demo")
            .fetch_one(&db.pool)
            .await
            .expect("count live sessions");
            assert_eq!(live, 1, "a live session was swept");

            let pending: i64 = sqlx::query_scalar(
                "select count(*) from outbox where tenant_id = $1 and status = 'pending'",
            )
            .bind("demo")
            .fetch_one(&db.pool)
            .await
            .expect("count pending outbox rows");
            assert_eq!(pending, 1, "an undelivered notification was swept");
        }
    }

    db_test! {
        /// A kept table stays kept. `grants` is the one that matters: deleting
        /// a grant deletes the only row that could revoke the tokens minted
        /// from it, and the cascade would take the codes and refresh tokens
        /// with it.
        async fn a_sweep_does_not_touch_a_table_the_policy_keeps(db) {
            seed(&db.pool, "demo").await;

            let kept: Vec<&'static str> = POLICY
                .iter()
                .filter(|entry| matches!(entry.rule, Rule::Kept(_)))
                .map(|entry| entry.table)
                .filter(|table| !matches!(*table, "session_clients" | "audit_events"
                                                | "subject_identifiers" | "credentials"
                                                | "signing_keys" | "key_rotation_schedules"
                                                | "tenant_pairwise_salts"))
                .collect();

            // Counted *before* the sweep, or the assertion below cannot tell
            // "the sweep took the row" from "the seed never wrote one": a table
            // empty at both ends reads as emptied, which is how `ast-hy0` spent
            // its afternoon looking at the sweep instead of at the seed. A new
            // kept table arriving with a migration and no seed now says so.
            for table in &kept {
                assert!(
                    count(&db.pool, table, "demo").await > 0,
                    "seed missing for {table}: the policy keeps it, so `seed` must \
                     write a row there for this test to be able to say anything"
                );
            }

            sweeper(&db.pool)
                .sweep_tenant(&TenantId::new("demo"), now())
                .await
                .expect("sweep");

            for table in &kept {
                assert!(
                    count(&db.pool, table, "demo").await > 0,
                    "{table} is kept by the policy but the sweep emptied it"
                );
            }
        }
    }

    db_test! {
        /// **`ast-cu3`'s second acceptance criterion.** A client nobody has
        /// authenticated as since the tenant's `unused_client_expiry_seconds`
        /// is swept.
        ///
        /// The setting has been stored and validated since `ast-m9c.6` and
        /// read by nothing, which is the worst state for a security control:
        /// an operator who typed it believed idle registrations were being
        /// retired and they were not.
        async fn an_unused_client_is_swept_once_the_tenants_window_has_passed(db) {
            seed(&db.pool, "demo").await;

            sweeper(&db.pool)
                .sweep_tenant(&TenantId::new("demo"), now())
                .await
                .expect("sweep");

            let remaining: i64 = sqlx::query_scalar(
                "select count(*) from clients where tenant_id = $1 and client_id = 'abandoned'",
            )
            .bind("demo")
            .fetch_one(&db.pool)
            .await
            .expect("count the abandoned client");
            assert_eq!(remaining, 0, "a client idle for ninety days was kept");
        }
    }

    db_test! {
        /// The other half, and the one that matters: a client used this
        /// morning is not swept. Deleting a live client takes its keys, its
        /// redirect URIs and every grant made through it, and there is no
        /// undo.
        async fn a_recently_used_client_is_not_swept(db) {
            seed(&db.pool, "demo").await;

            sweeper(&db.pool)
                .sweep_tenant(&TenantId::new("demo"), now())
                .await
                .expect("sweep");

            let remaining: i64 = sqlx::query_scalar(
                "select count(*) from clients where tenant_id = $1 and client_id = 'billing'",
            )
            .bind("demo")
            .fetch_one(&db.pool)
            .await
            .expect("count the live client");
            assert_eq!(remaining, 1, "a client used today was swept");
        }
    }

    db_test! {
        /// A tenant that never asked keeps every client, however old.
        ///
        /// This is the default and it is the one that must not regress: the
        /// rule is opt-in per tenant, and a bug that made it unconditional
        /// would delete registrations across a whole deployment on the next
        /// sweep.
        async fn a_tenant_with_no_expiry_policy_keeps_an_idle_client(db) {
            seed_tenant(&db.pool, "quiet").await;
            seed_idle_client(&db.pool, "quiet", "ancient", now() - Duration::days(3650)).await;

            sweeper(&db.pool)
                .sweep_tenant(&TenantId::new("quiet"), now())
                .await
                .expect("sweep");

            let remaining: i64 = sqlx::query_scalar(
                "select count(*) from clients where tenant_id = $1 and client_id = 'ancient'",
            )
            .bind("quiet")
            .fetch_one(&db.pool)
            .await
            .expect("count the ancient client");
            assert_eq!(
                remaining, 1,
                "a tenant that set no expiry had a client deleted by the timer"
            );
        }
    }

    db_test! {
        /// A client that has never authenticated is as idle as its
        /// registration is old: 0010 did not backfill `last_used_at`, so
        /// `null` has to be read as `created_at` rather than as "used now".
        async fn a_client_that_has_never_authenticated_is_dated_by_its_registration(db) {
            seed_tenant(&db.pool, "fresh").await;
            seed_unused_client_expiry(&db.pool, "fresh", Duration::days(30)).await;
            sqlx::query(
                "insert into clients (tenant_id, client_id, client_name,
                                      token_endpoint_auth_method, jwks, created_at, last_used_at)
                 values ($1, 'never-used', 'Never used', 'private_key_jwt',
                         '{\"keys\":[]}'::jsonb, $2, null)",
            )
            .bind("fresh")
            .bind(now() - Duration::days(90))
            .execute(&db.pool)
            .await
            .expect("seed a client that has never authenticated");

            sweeper(&db.pool)
                .sweep_tenant(&TenantId::new("fresh"), now())
                .await
                .expect("sweep");

            let remaining: i64 = sqlx::query_scalar(
                "select count(*) from clients where tenant_id = $1 and client_id = 'never-used'",
            )
            .bind("fresh")
            .fetch_one(&db.pool)
            .await
            .expect("count the never-used client");
            assert_eq!(remaining, 0, "a client registered ninety days ago and never used was kept");
        }
    }

    db_test! {
        /// Recording a use is what makes the rule safe, and it has to move the
        /// instant forward on a client whose column is still null (`ast-cu3`).
        async fn recording_a_use_dates_a_client_that_had_never_been_used(db) {
            seed_tenant(&db.pool, "demo").await;
            seed_idle_client(&db.pool, "demo", "quiet", now() - Duration::days(90)).await;

            PgClientUsage::new(db.pool.clone())
                .record_use(&TenantId::new("demo"), &ClientId::new("quiet"), now())
                .await
                .expect("record a use");

            let recorded: Option<OffsetDateTime> = sqlx::query_scalar(
                "select last_used_at from clients where tenant_id = $1 and client_id = 'quiet'",
            )
            .bind("demo")
            .fetch_one(&db.pool)
            .await
            .expect("read last_used_at");
            assert_eq!(recorded, Some(now()), "a use was not recorded");
        }
    }

    db_test! {
        /// The second use inside the granularity window writes nothing, which
        /// is what keeps this off the token endpoint's hot path.
        async fn a_second_use_inside_the_window_does_not_write(db) {
            seed_tenant(&db.pool, "demo").await;
            seed_idle_client(&db.pool, "demo", "busy", now() - Duration::days(90)).await;
            let usage = PgClientUsage::new(db.pool.clone());
            usage
                .record_use(&TenantId::new("demo"), &ClientId::new("busy"), now())
                .await
                .expect("record a use");

            usage
                .record_use(
                    &TenantId::new("demo"),
                    &ClientId::new("busy"),
                    now() + Duration::minutes(1),
                )
                .await
                .expect("record a second use");

            let recorded: Option<OffsetDateTime> = sqlx::query_scalar(
                "select last_used_at from clients where tenant_id = $1 and client_id = 'busy'",
            )
            .bind("demo")
            .fetch_one(&db.pool)
            .await
            .expect("read last_used_at");
            assert_eq!(
                recorded,
                Some(now()),
                "a use inside the granularity window rewrote the row"
            );
        }
    }

    db_test! {
        /// `ast-wgx`: one `client_credentials` request per minute is 1 440
        /// grant rows a day, each expiring with a token that lived fifteen
        /// minutes. Past the policy's window the row answers no question the
        /// audit trail cannot.
        async fn an_expired_client_only_grant_is_swept_once_the_window_has_passed(db) {
            seed(&db.pool, "demo").await;
            let grant = client_only_grant("machine");
            seed_client_only_grant(&db.pool, "demo", grant, now() - Duration::days(30)).await;

            sweeper(&db.pool)
                .sweep_tenant(&TenantId::new("demo"), now())
                .await
                .expect("sweep");

            assert!(
                !grant_exists(&db.pool, "demo", grant).await,
                "a client-only grant expired thirty days ago is still stored"
            );
        }
    }

    db_test! {
        /// The window is what makes the rule safe to run: inside it the row is
        /// still there to be read by an operator asking what a machine client
        /// was authorized to do this morning.
        async fn a_client_only_grant_inside_the_window_is_kept(db) {
            seed(&db.pool, "demo").await;
            let grant = client_only_grant("this-morning");
            seed_client_only_grant(&db.pool, "demo", grant, now() - Duration::hours(1)).await;

            sweeper(&db.pool)
                .sweep_tenant(&TenantId::new("demo"), now())
                .await
                .expect("sweep");

            assert!(
                grant_exists(&db.pool, "demo", grant).await,
                "a grant that expired an hour ago was swept inside the window"
            );
        }
    }

    db_test! {
        /// A grant with a person behind it is the consent record and the
        /// revocable unit of authority, and no clock deletes one — however
        /// long ago its `expires_at` passed.
        async fn a_user_grant_is_not_swept_however_long_it_has_been_expired(db) {
            seed(&db.pool, "demo").await;
            let grant = client_only_grant("alice-offline");
            seed_user_grant(
                &db.pool,
                "demo",
                uuid::Uuid::from_u128(0x5e_ed),
                grant,
                now() - Duration::days(400),
            )
            .await;

            sweeper(&db.pool)
                .sweep_tenant(&TenantId::new("demo"), now())
                .await
                .expect("sweep");

            assert!(
                grant_exists(&db.pool, "demo", grant).await,
                "a user's grant was deleted by the retention sweep"
            );
        }
    }

    db_test! {
        /// The durable trace is the trail, not the row: the event naming the
        /// swept grant is still readable and the chain still verifies.
        async fn the_trail_of_a_swept_client_only_grant_survives_intact(db) {
            seed(&db.pool, "demo").await;
            let grant = client_only_grant("machine");
            seed_client_only_grant(&db.pool, "demo", grant, now() - Duration::days(30)).await;
            let sink = PgAuditSink::new(db.pool.clone());
            sink.record(
                audit_event("demo", EventType::TOKEN_ISSUED)
                    .grant(asterius_domain::GrantId::new(grant.to_string())),
            )
            .await
            .expect("record the issuance");

            sweeper(&db.pool)
                .sweep_tenant(&TenantId::new("demo"), now())
                .await
                .expect("sweep");

            let recorded: i64 = sqlx::query_scalar(
                "select count(*) from audit_events where tenant_id = 'demo' and grant_id = $1",
            )
            .bind(grant)
            .fetch_one(&db.pool)
            .await
            .expect("read the trail");
            assert_eq!(recorded, 1, "the trail lost the swept grant's event");
            let verified = sink
                .verify_chain(&TenantId::new("demo"))
                .await
                .expect("the chain still verifies");
            assert_eq!(verified.records, 1);
        }
    }

    db_test! {
        /// Nothing left to do is not an error, and a second sweep must not
        /// report work it did not do.
        async fn a_second_sweep_finds_nothing(db) {
            seed(&db.pool, "demo").await;
            let tenant = TenantId::new("demo");
            sweeper(&db.pool).sweep_tenant(&tenant, now()).await.expect("first");

            let SweepOutcome::Swept(again) = sweeper(&db.pool)
                .sweep_tenant(&tenant, now())
                .await
                .expect("second")
            else {
                panic!("the lock was not released by the first sweep");
            };
            assert_eq!(again.total(), 0, "a second sweep deleted {:?}", again.deleted);
        }
    }

    db_test! {
        /// "Safe to run concurrently", deterministically: hold the tenant's
        /// advisory lock the way another replica would, and require the sweep
        /// to decline rather than to wait or to work anyway.
        ///
        /// A lock the sweep merely *takes* would pass a race-based test by
        /// luck. This one cannot: the lock is already held when the sweep
        /// starts, so a sweep that ignored it would delete the seeded rows and
        /// a sweep that waited for it would never return.
        async fn a_tenant_another_replica_is_sweeping_is_left_alone(db) {
            seed(&db.pool, "demo").await;
            let tenant = TenantId::new("demo");

            // The other replica: its own connection, its own session lock.
            let mut replica = db.pool.acquire().await.expect("a second connection");
            let held: bool = sqlx::query_scalar(
                "select pg_try_advisory_lock(hashtext($1), hashtext('retention'))",
            )
            .bind(tenant.as_str())
            .fetch_one(&mut *replica)
            .await
            .expect("take the lock");
            assert!(held, "the lock was not free to begin with");

            let before = count(&db.pool, "jti_replay", "demo").await;
            let outcome = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                sweeper(&db.pool).sweep_tenant(&tenant, now()),
            )
            .await
            .expect("a contended sweep must return rather than wait")
            .expect("sweep");

            assert_eq!(outcome, SweepOutcome::Busy);
            assert_eq!(
                count(&db.pool, "jti_replay", "demo").await,
                before,
                "a sweep that could not take the lock deleted rows anyway"
            );

            // And once the other replica is done, the next sweep proceeds.
            sqlx::query("select pg_advisory_unlock(hashtext($1), hashtext('retention'))")
                .bind(tenant.as_str())
                .execute(&mut *replica)
                .await
                .expect("release");
            drop(replica);

            let SweepOutcome::Swept(sweep) = sweeper(&db.pool)
                .sweep_tenant(&tenant, now())
                .await
                .expect("sweep")
            else {
                panic!("the released lock was not available");
            };
            assert!(sweep.total() > 0, "the deferred work was never done");
        }
    }

    db_test! {
        /// The lock is per tenant, so one busy tenant does not stop the others.
        /// Getting this wrong turns a large tenant's backlog into every
        /// tenant's outage, which is the failure a global lock would cause.
        async fn one_tenant_being_swept_does_not_block_another(db) {
            seed(&db.pool, "demo").await;
            seed(&db.pool, "other").await;

            let mut replica = db.pool.acquire().await.expect("a second connection");
            sqlx::query("select pg_try_advisory_lock(hashtext($1), hashtext('retention'))")
                .bind("demo")
                .execute(&mut *replica)
                .await
                .expect("take demo's lock");

            let SweepOutcome::Swept(sweep) = sweeper(&db.pool)
                .sweep_tenant(&TenantId::new("other"), now())
                .await
                .expect("sweep other")
            else {
                panic!("another tenant's lock blocked this one");
            };
            assert!(sweep.total() > 0);
        }
    }

    db_test! {
        /// The race itself, run for real: four sweeps of one tenant at once.
        /// Whichever wins, the expired rows are gone exactly once and nobody
        /// errors — the property a production deployment of two replicas needs.
        async fn concurrent_sweeps_of_one_tenant_do_the_work_once(db) {
            seed(&db.pool, "demo").await;
            let tenant = TenantId::new("demo");
            let expired_replay_rows = 1;

            let one = sweeper(&db.pool);
            let two = sweeper(&db.pool);
            let three = sweeper(&db.pool);
            let four = sweeper(&db.pool);
            // `join!` polls all four on one task, so they interleave at every
            // await point inside the sweep — which is where the lock is taken.
            let outcomes = tokio::join!(
                one.sweep_tenant(&tenant, now()),
                two.sweep_tenant(&tenant, now()),
                three.sweep_tenant(&tenant, now()),
                four.sweep_tenant(&tenant, now()),
            );
            let outcomes = [outcomes.0, outcomes.1, outcomes.2, outcomes.3];

            let mut deleted = 0_u64;
            let mut swept = 0;
            for outcome in outcomes {
                match outcome.expect("no sweep may fail") {
                    SweepOutcome::Swept(sweep) => {
                        swept += 1;
                        deleted += sweep
                            .deleted
                            .iter()
                            .filter(|(table, _)| *table == "jti_replay")
                            .map(|(_, count)| count)
                            .sum::<u64>();
                    }
                    SweepOutcome::Busy => {}
                }
            }

            assert!(swept >= 1, "every replica declined; nothing was ever swept");
            assert_eq!(
                deleted, expired_replay_rows,
                "the expired replay marker was deleted {deleted} times across {swept} sweeps"
            );
            assert_eq!(count(&db.pool, "jti_replay", "demo").await, 1, "the live marker went too");
        }
    }

    db_test! {
        /// The failure mode this module exists to prevent: a migration adds an
        /// ephemeral table, nobody thinks about retention, and it accumulates
        /// silently for a year. The policy is compared with the live schema, so
        /// the omission is a failing test rather than a discovery.
        async fn the_policy_names_every_table_in_the_schema(db) {
            let tables: Vec<String> = sqlx::query_scalar(
                "select table_name from information_schema.tables
                  where table_schema = $1 and table_type = 'BASE TABLE'
                    and table_name <> '_sqlx_migrations'
                  order by table_name",
            )
            .bind(db.schema())
            .fetch_all(&db.pool)
            .await
            .expect("read information_schema");
            assert!(tables.len() > 10, "the schema looks empty: {tables:?}");

            let policy: std::collections::BTreeSet<&str> =
                POLICY.iter().map(|entry| entry.table).collect();

            let unruled: Vec<&String> = tables
                .iter()
                .filter(|table| !policy.contains(table.as_str()))
                .collect();
            assert!(
                unruled.is_empty(),
                "these tables have no retention rule: {unruled:?}\n\
                 Add each to asterius_store_pg::retention::POLICY, as a Sweep if its \
                 rows expire or as a Kept with the reason they do not."
            );

            let stale: Vec<&&str> = policy
                .iter()
                .filter(|table| !tables.iter().any(|existing| existing == *table))
                .collect();
            assert!(
                stale.is_empty(),
                "these rules name tables that no longer exist: {stale:?}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Rotating the key-encryption key
// ---------------------------------------------------------------------------

use asterius_store_pg::{PgKekRewrap, RewrapOutcome};

/// The KEK a rotation moves to. Different material from [`A_KEK`], so the two
/// derive different ids and neither can open the other's rows.
const B_KEK: [u8; 32] = [0xb7; 32];

fn next_kek() -> Arc<LocalKek> {
    Arc::new(LocalKek::from_bytes(&B_KEK).expect("a 32-byte KEK"))
}

/// Seals the fixed [`salt`] under an arbitrary KEK and writes it as the
/// tenant's salt row.
///
/// [`seed_salt`] always uses [`kek`]; a re-wrap test also needs to stage a
/// tenant that is *already* on the new key, which is what an interrupted pass
/// leaves behind.
async fn seed_salt_under(pool: &PgPool, tenant: &str, sealing: &LocalKek) {
    let id = TenantId::new(tenant);
    let sealed = sealing
        .seal(
            KeyBinding::tenant_secret(&id, TenantSecret::PairwiseSalt),
            salt().expose(),
        )
        .expect("seal the salt");
    sqlx::query(
        "insert into tenant_pairwise_salts (tenant_id, salt_ciphertext, salt_nonce, kek_id)
         values ($1, $2, $3, $4)",
    )
    .bind(tenant)
    .bind(sealed.ciphertext())
    .bind(sealed.nonce())
    .bind(sealed.kek_id())
    .execute(pool)
    .await
    .expect("seed the pairwise salt");
}

/// The tenant's salt row as it is stored: `(kek_id, nonce, ciphertext)`.
async fn stored_salt(pool: &PgPool, tenant: &str) -> (String, Vec<u8>, Vec<u8>) {
    sqlx::query_as(
        "select kek_id, salt_nonce, salt_ciphertext from tenant_pairwise_salts
         where tenant_id = $1",
    )
    .bind(tenant)
    .fetch_one(pool)
    .await
    .expect("read the salt row")
}

fn rewrap(pool: &PgPool) -> PgKekRewrap {
    PgKekRewrap::new(pool.clone())
}

/// Unwraps a [`RewrapOutcome`] that must not have been contended.
fn pass(outcome: RewrapOutcome) -> asterius_store_pg::Rewrap {
    match outcome {
        RewrapOutcome::Rewrapped(moved) => moved,
        RewrapOutcome::Busy => panic!("nothing else holds this tenant's lock"),
    }
}

db_test! {
    /// The test this whole feature exists for. OIDC Core §8 calls a Subject
    /// Identifier "a locally unique and never reassigned identifier within the
    /// Issuer for the End-User", and every `sub` here is derived from the
    /// tenant's pairwise salt — so a KEK rotation that changed the salt would
    /// silently reassign every identifier in the tenant.
    ///
    /// Both halves are asserted: the identifier already issued and stored, and
    /// a *fresh* derivation in a sector this tenant has never seen. The second
    /// is the one that would catch a changed salt, because the first is read
    /// back from `subject_identifiers` and would survive anything.
    async fn a_pairwise_subject_is_unchanged_after_the_key_encryption_key_is_rotated(db) {
        seed_tenant(&db.pool, "demo").await;
        seed_salt(&db.pool, "demo").await;
        let before = users(&db.pool, "demo");
        let alice = a_user("demo", UserId::generate(), "alice");
        before.upsert(&alice).await.expect("insert");
        let issued = before.subject(alice.id, &sector("rp.example")).await.expect("mint");
        let (old_kek_id, old_nonce, old_ciphertext) = stored_salt(&db.pool, "demo").await;

        let moved = pass(
            rewrap(&db.pool)
                .rewrap_tenant(&TenantId::new("demo"), kek().as_ref(), next_kek().as_ref())
                .await
                .expect("re-wrap"),
        );

        assert!(moved.pairwise_salt, "the salt was not re-wrapped: {moved:?}");
        assert!(moved.is_complete(), "{moved:?}");

        // The envelope changed, all of it: a new key, and a new nonce, because
        // `tenant_pairwise_salts_nonce_never_repeats` is only per KEK and
        // reusing a nonce under a different key is the failure AES-GCM does not
        // survive.
        let (new_kek_id, new_nonce, new_ciphertext) = stored_salt(&db.pool, "demo").await;
        assert_eq!(new_kek_id, next_kek().id());
        assert_ne!(new_kek_id, old_kek_id);
        assert_ne!(new_nonce, old_nonce);
        assert_ne!(new_ciphertext, old_ciphertext);

        // And the plaintext did not. Read through the repository, under the new
        // KEK, exactly as a replica would once the operator swapped the key.
        let after = PgUserRepository::new(db.pool.clone(), TenantId::new("demo"), next_kek());
        assert_eq!(
            after.subject(alice.id, &sector("rp.example")).await.expect("read"),
            issued,
            "the identifier already handed to a relying party moved"
        );
        assert_eq!(
            after.subject(alice.id, &sector("later.example")).await.expect("mint"),
            salt().derive_subject(&sector("later.example"), alice.id),
            "a subject minted after the rotation derives from a different salt"
        );
    }
}

db_test! {
    /// The other half of what the KEK seals. A signing key is re-wrapped in
    /// place — `signing_keys` takes an `UPDATE` — and the `kid` is a thumbprint
    /// of the public half, so nothing a relying party has cached moves.
    async fn a_signing_key_still_opens_after_the_key_encryption_key_is_rotated(db) {
        seed_tenant(&db.pool, "demo").await;
        let before = keys(&db.pool, "demo");
        before.rotate(SigningAlgorithm::EdDsa, operator(), epoch()).await.expect("first key");
        let (kid, _) = before
            .active_signing_key(SigningAlgorithm::EdDsa)
            .await
            .expect("read")
            .expect("an active key");

        let moved = pass(
            rewrap(&db.pool)
                .rewrap_tenant(&TenantId::new("demo"), kek().as_ref(), next_kek().as_ref())
                .await
                .expect("re-wrap"),
        );

        assert_eq!(moved.signing_keys, 1, "{moved:?}");
        let after = PgKeyRepository::new(
            db.pool.clone(),
            TenantId::new("demo"),
            next_kek(),
            Arc::new(PgAuditSink::new(db.pool.clone())),
        );
        let (same_kid, key) = after
            .active_signing_key(SigningAlgorithm::EdDsa)
            .await
            .expect("read under the new KEK")
            .expect("an active key");
        assert_eq!(same_kid, kid, "the kid moved, so every cached JWKS is stale");
        // It is a key, not merely bytes that decrypted: it still signs.
        jws::sign(&key, &kid, "at+jwt", &json!({"sub": "alice"})).expect("sign");

        // And the old KEK no longer opens it, which is the point of rotating.
        assert!(
            before.active_signing_key(SigningAlgorithm::EdDsa).await.is_err(),
            "the row still opens under the key that was rotated away from"
        );
    }
}

db_test! {
    /// A pass that died between the signing keys and the salt is resumed by
    /// running it again: every statement selects on the *old* `kek_id`, so what
    /// already moved is not touched twice and what did not is picked up.
    async fn a_pass_interrupted_half_way_is_finished_by_running_it_again(db) {
        seed_tenant(&db.pool, "demo").await;
        // The state an interrupted pass leaves: the salt already on the new
        // key, a signing key still on the old one.
        seed_salt_under(&db.pool, "demo", next_kek().as_ref()).await;
        keys(&db.pool, "demo")
            .rotate(SigningAlgorithm::EdDsa, operator(), epoch())
            .await
            .expect("a key under the old KEK");

        let resumed = pass(
            rewrap(&db.pool)
                .rewrap_tenant(&TenantId::new("demo"), kek().as_ref(), next_kek().as_ref())
                .await
                .expect("re-wrap"),
        );

        assert_eq!(resumed.signing_keys, 1, "{resumed:?}");
        assert!(!resumed.pairwise_salt, "a salt already on the new key was rewritten");
        assert!(resumed.is_complete(), "{resumed:?}");

        let after = PgUserRepository::new(db.pool.clone(), TenantId::new("demo"), next_kek());
        let alice = a_user("demo", UserId::generate(), "alice");
        after.upsert(&alice).await.expect("insert");
        assert_eq!(
            after.subject(alice.id, &sector("rp.example")).await.expect("mint"),
            salt().derive_subject(&sector("rp.example"), alice.id),
        );
    }
}

db_test! {
    /// Running the tool twice is not a mistake, it is the documented procedure:
    /// the second pass catches rows a replica wrote while it was still on the
    /// old key. So a second pass over a finished tenant must be a no-op rather
    /// than a re-seal, and must leave the row byte for byte as it was.
    async fn a_second_pass_over_a_finished_tenant_moves_nothing(db) {
        seed_tenant(&db.pool, "demo").await;
        seed_salt(&db.pool, "demo").await;
        let tenant = TenantId::new("demo");
        pass(
            rewrap(&db.pool)
                .rewrap_tenant(&tenant, kek().as_ref(), next_kek().as_ref())
                .await
                .expect("first pass"),
        );
        let settled = stored_salt(&db.pool, "demo").await;

        let again = pass(
            rewrap(&db.pool)
                .rewrap_tenant(&tenant, kek().as_ref(), next_kek().as_ref())
                .await
                .expect("second pass"),
        );

        assert!(again.is_empty(), "{again:?}");
        assert!(again.is_complete(), "{again:?}");
        assert_eq!(
            stored_salt(&db.pool, "demo").await,
            settled,
            "a no-op pass rewrote the row"
        );
    }
}

db_test! {
    /// Two operators, or two replicas, must not re-wrap one tenant at once: the
    /// salt is deleted and re-inserted, and a second writer racing that is the
    /// one way this could lose it. The lock is taken with `pg_try_advisory_...`,
    /// so the loser is told to move on rather than queued behind work that is
    /// about to make its own pass redundant.
    async fn a_tenant_somebody_else_is_re_wrapping_is_left_alone(db) {
        seed_tenant(&db.pool, "demo").await;
        seed_salt(&db.pool, "demo").await;
        let before = stored_salt(&db.pool, "demo").await;
        // Somebody else's session, holding exactly the lock a pass takes.
        let mut held = db.pool.acquire().await.expect("a second connection");
        sqlx::query("select pg_advisory_lock(hashtext('demo'), hashtext('kek-rewrap'))")
            .execute(&mut *held)
            .await
            .expect("hold the lock");

        let outcome = rewrap(&db.pool)
            .rewrap_tenant(&TenantId::new("demo"), kek().as_ref(), next_kek().as_ref())
            .await
            .expect("re-wrap");

        assert_eq!(outcome, RewrapOutcome::Busy);
        assert_eq!(
            stored_salt(&db.pool, "demo").await,
            before,
            "a contended pass wrote to the row anyway"
        );

        sqlx::query("select pg_advisory_unlock(hashtext('demo'), hashtext('kek-rewrap'))")
            .execute(&mut *held)
            .await
            .expect("release");
    }
}

db_test! {
    /// The re-wrap path exists; the invariant it was carved out of does not
    /// move. `tenant_pairwise_salts` still refuses `UPDATE`, so nothing — not
    /// this tool, not a migration, not an operator with `psql` — can change a
    /// salt's value in place and reassign every `sub` in the tenant.
    async fn the_salt_table_still_refuses_an_update(db) {
        seed_tenant(&db.pool, "demo").await;
        seed_salt(&db.pool, "demo").await;

        let refused = sqlx::query(
            "update tenant_pairwise_salts set kek_id = 'local:whatever' where tenant_id = 'demo'",
        )
        .execute(&db.pool)
        .await;

        let error = refused.expect_err("the immutability trigger is gone").to_string();
        assert!(error.contains("never updated"), "{error}");
    }
}

db_test! {
    /// A row sealed under a third key is the residue of an abandoned rotation.
    /// The pass cannot open it, and reports it rather than skipping it: an
    /// operator told "complete" while a row still needs a key they are about to
    /// destroy has been told the one thing that must not be wrong.
    async fn a_row_under_an_unrelated_key_is_reported_rather_than_skipped(db) {
        seed_tenant(&db.pool, "demo").await;
        let stray = LocalKek::from_bytes(&[0x33; 32]).expect("a 32-byte KEK");
        seed_salt_under(&db.pool, "demo", &stray).await;

        let moved = pass(
            rewrap(&db.pool)
                .rewrap_tenant(&TenantId::new("demo"), kek().as_ref(), next_kek().as_ref())
                .await
                .expect("re-wrap"),
        );

        assert_eq!(moved.stranded, 1, "{moved:?}");
        assert!(!moved.is_complete(), "{moved:?}");
    }
}

// ---------------------------------------------------------------------------
// Deployment admins: the reserved tenant and deployment-scoped roles
// (ADR-0010, `ast-1cj`)
// ---------------------------------------------------------------------------

use asterius_domain::{Argon2Parameters, DomainError, Role, Secret};
use asterius_store_pg::{DeploymentAdmin, PgAdminSeed, PgRoleRepository};

/// The password the seeding tests configure. Long enough to pass the policy
/// every other password in the deployment goes through.
const AN_ADMIN_PASSWORD: &str = "correct horse battery staple";

fn admin_seed(pool: &PgPool) -> PgAdminSeed {
    PgAdminSeed::new(pool.clone(), kek(), Argon2Parameters::default())
}

fn deployment_admin(tenant: &str) -> DeploymentAdmin {
    DeploymentAdmin {
        tenant: TenantId::new(tenant),
        issuer: Issuer::parse(&format!("https://as.example/t/{tenant}")).expect("issuer"),
        username: "admin".to_owned(),
        password: Secret::new(AN_ADMIN_PASSWORD.to_owned()),
    }
}

/// Inserts a user directly, for the tests that need one without a seed.
async fn seed_user(pool: &PgPool, tenant: &str, username: &str) -> UserId {
    let id = UserId::generate();
    sqlx::query("insert into users (tenant_id, user_id, username) values ($1, $2, $3)")
        .bind(tenant)
        .bind(id.as_uuid())
        .bind(username)
        .execute(pool)
        .await
        .expect("seed user");
    id
}

db_test! {
    /// Seeding writes the four things ADR-0010 names — the reserved tenant, a
    /// user in it, a password and a deployment-scoped role — and proves the
    /// last one by authenticating with the configured password.
    async fn seeding_produces_an_admin_that_can_authenticate(db) {
        let seeded = admin_seed(&db.pool)
            .ensure(&deployment_admin("admin"))
            .await
            .expect("seed");

        assert!(seeded.created, "the first pass should create the account");
        assert!(seeded.can_authenticate, "the seeded password does not authenticate");

        let reserved: bool = sqlx::query_scalar(
            "select is_reserved from tenants where tenant_id = 'admin'",
        )
        .fetch_one(&db.pool)
        .await
        .expect("read tenant");
        assert!(reserved, "the tenant was created but not reserved");

        let roles = PgRoleRepository::new(db.pool.clone(), TenantId::new("admin"))
            .roles_of(seeded.user)
            .await
            .expect("roles");
        assert_eq!(roles.len(), 1);
        assert_eq!(roles[0].role, Role::DeploymentAdmin);
    }
}

db_test! {
    /// Every boot runs the seed, so it has to be idempotent — and it must not
    /// rewrite the password hash it already agrees with, which would put a new
    /// salt in the row on every restart.
    async fn seeding_twice_changes_nothing(db) {
        let seed = admin_seed(&db.pool);
        let first = seed.ensure(&deployment_admin("admin")).await.expect("first");
        let hash_before: String = sqlx::query_scalar(
            "select password_hash from credentials where tenant_id = 'admin'",
        )
        .fetch_one(&db.pool)
        .await
        .expect("read credential");

        let second = seed.ensure(&deployment_admin("admin")).await.expect("second");

        assert_eq!(second.user, first.user, "the second pass made a second account");
        assert!(!second.created);
        assert!(second.can_authenticate);

        let hash_after: String = sqlx::query_scalar(
            "select password_hash from credentials where tenant_id = 'admin'",
        )
        .fetch_one(&db.pool)
        .await
        .expect("read credential");
        assert_eq!(hash_before, hash_after, "the hash was rewritten for nothing");
    }
}

db_test! {
    /// A password changed in the configuration is applied at the next boot:
    /// the file or the variable is the source of truth for the seeded account.
    async fn a_changed_configuration_password_replaces_the_stored_one(db) {
        let seed = admin_seed(&db.pool);
        seed.ensure(&deployment_admin("admin")).await.expect("first");

        let mut rotated = deployment_admin("admin");
        rotated.password = Secret::new("a quite different passphrase".to_owned());
        let again = seed.ensure(&rotated).await.expect("second");

        assert!(again.can_authenticate, "the new password does not authenticate");
    }
}

db_test! {
    /// A password the login form would refuse must not become the credential
    /// that administers the deployment.
    async fn a_password_below_policy_is_refused_before_anything_is_written(db) {
        let mut weak = deployment_admin("admin");
        weak.password = Secret::new("short".to_owned());

        let refused = admin_seed(&db.pool).ensure(&weak).await;

        assert!(matches!(refused, Err(DomainError::Invalid { .. })), "{refused:?}");
        let tenants: i64 = sqlx::query_scalar("select count(*) from tenants")
            .fetch_one(&db.pool)
            .await
            .expect("count tenants");
        assert_eq!(tenants, 0, "a refused password still created the reserved tenant");
    }
}

db_test! {
    /// Protection 1 of ADR-0010. `users` cascades from `tenants`, so a delete
    /// here would remove every deployment admin in one statement — which is
    /// exactly why the database refuses it rather than trusting the code above.
    async fn the_reserved_tenant_cannot_be_deleted(db) {
        let seeded = admin_seed(&db.pool)
            .ensure(&deployment_admin("admin"))
            .await
            .expect("seed");

        let refused = PgTenantRepository::new(db.pool.clone(), kek())
            .delete(&TenantId::new("admin"))
            .await;

        assert!(refused.is_err(), "the reserved tenant was deleted");
        let admins: i64 = sqlx::query_scalar(
            "select count(*) from users where tenant_id = 'admin' and user_id = $1",
        )
        .bind(seeded.user.as_uuid())
        .fetch_one(&db.pool)
        .await
        .expect("count users");
        assert_eq!(admins, 1, "the admin went with the tenant");
    }
}

db_test! {
    /// An ordinary tenant is still deletable. The protection is about the
    /// reserved row, not about making `tenants` immutable.
    async fn an_ordinary_tenant_is_still_deletable(db) {
        let repo = PgTenantRepository::new(db.pool.clone(), kek());
        repo.upsert(&tenant("demo", "https://as.example/t/demo")).await.expect("insert");
        admin_seed(&db.pool).ensure(&deployment_admin("admin")).await.expect("seed");

        repo.delete(&TenantId::new("demo")).await.expect("an ordinary tenant deletes");
    }
}

db_test! {
    /// Protection 2 of ADR-0010, and the reason it is a constraint rather than
    /// a check in the adapter: an ordinary tenant that could hold a
    /// deployment-scoped role would be implicitly privileged, and nothing in
    /// the data would say so.
    async fn a_deployment_role_is_refused_outside_the_reserved_tenant(db) {
        seed_tenant(&db.pool, "demo").await;
        let user = seed_user(&db.pool, "demo", "mallory").await;
        let roles = PgRoleRepository::new(db.pool.clone(), TenantId::new("demo"));

        let refused = roles.grant(user, Role::DeploymentAdmin).await;

        assert!(matches!(refused, Err(DomainError::Conflict(_))), "{refused:?}");
        assert!(!roles.holds(user, Role::DeploymentAdmin).await.expect("holds"));
        // A tenant-scoped role in the same tenant is fine: the rule is about
        // reach, not about that tenant having no administrators at all.
        roles.grant(user, Role::TenantAdmin).await.expect("a tenant admin is allowed");
    }
}

db_test! {
    /// The flag cannot be taken off the reserved tenant while a
    /// deployment-scoped role still hangs off it — the update cascades into
    /// `user_roles`, where the check refuses it. Without this, protection 2
    /// would be one `UPDATE` away from being untrue of rows already written.
    async fn a_tenant_holding_a_deployment_role_cannot_stop_being_reserved(db) {
        admin_seed(&db.pool).ensure(&deployment_admin("admin")).await.expect("seed");

        let refused = sqlx::query("update tenants set is_reserved = false where tenant_id = 'admin'")
            .execute(&db.pool)
            .await;

        assert!(refused.is_err(), "the reservation was cleared under a deployment admin");
    }
}

db_test! {
    /// Two reserved tenants would make "where does deployment authority live"
    /// a question with two answers.
    async fn a_deployment_has_at_most_one_reserved_tenant(db) {
        admin_seed(&db.pool).ensure(&deployment_admin("admin")).await.expect("seed");

        let refused = admin_seed(&db.pool).ensure(&deployment_admin("second")).await;

        assert!(matches!(refused, Err(DomainError::Conflict(_))), "{refused:?}");
    }
}

db_test! {
    /// A role is authority over an account, so it lives exactly as long as the
    /// account does.
    async fn deleting_a_user_takes_their_roles_with_them(db) {
        seed_tenant(&db.pool, "demo").await;
        let user = seed_user(&db.pool, "demo", "operator").await;
        let roles = PgRoleRepository::new(db.pool.clone(), TenantId::new("demo"));
        roles.grant(user, Role::TenantAdmin).await.expect("grant");

        sqlx::query("delete from users where tenant_id = 'demo' and user_id = $1")
            .bind(user.as_uuid())
            .execute(&db.pool)
            .await
            .expect("delete user");

        assert!(!roles.holds(user, Role::TenantAdmin).await.expect("holds"));
    }
}

db_test! {
    /// Granting the same role twice is not an error, because a seed that runs
    /// on every boot would otherwise fail on the second one.
    async fn granting_a_role_twice_is_idempotent_and_revoking_is_not(db) {
        seed_tenant(&db.pool, "demo").await;
        let user = seed_user(&db.pool, "demo", "operator").await;
        let roles = PgRoleRepository::new(db.pool.clone(), TenantId::new("demo"));

        roles.grant(user, Role::TenantAdmin).await.expect("first grant");
        roles.grant(user, Role::TenantAdmin).await.expect("second grant");
        assert_eq!(roles.holders_of(Role::TenantAdmin).await.expect("holders"), vec![user]);

        roles.revoke(user, Role::TenantAdmin).await.expect("revoke");
        assert!(matches!(roles.revoke(user, Role::TenantAdmin).await, Err(DomainError::NotFound)));
    }
}

db_test! {
    /// A role granted in one tenant is invisible in another, like every other
    /// tenant-scoped read in this store.
    async fn a_role_lookup_never_answers_for_another_tenant(db) {
        seed_tenant(&db.pool, "alpha").await;
        seed_tenant(&db.pool, "beta").await;
        let user = seed_user(&db.pool, "alpha", "operator").await;
        PgRoleRepository::new(db.pool.clone(), TenantId::new("alpha"))
            .grant(user, Role::TenantAdmin)
            .await
            .expect("grant");

        let elsewhere = PgRoleRepository::new(db.pool.clone(), TenantId::new("beta"));

        assert!(!elsewhere.holds(user, Role::TenantAdmin).await.expect("holds"));
        assert!(elsewhere.roles_of(user).await.expect("roles").is_empty());
    }
}

// ---------------------------------------------------------------------------
// Passkeys
// ---------------------------------------------------------------------------

mod passkeys {
    use super::*;
    use asterius_domain::entities::session::SessionId;
    use asterius_domain::{
        AuthenticationMethod, DomainError, ENROLMENT_TTL, Lifetimes, NewPasskey, PasskeyRepository,
        Session, SessionRepository, UserId,
    };
    use asterius_domain::{FirstPartyDestination, InteractionRepository};
    use asterius_store_pg::{PgAuthRequestRepository, PgPasskeyRepository, PgSessionRepository};
    use time::Duration;

    fn repo(pool: &PgPool, tenant: &str) -> PgPasskeyRepository {
        PgPasskeyRepository::new(pool.clone(), TenantId::new(tenant))
    }

    /// A tenant, a user and a live session, which is what an enrolment hangs
    /// off. Returns the session's lookup digest.
    async fn seed_session(pool: &PgPool, tenant: &str, user: uuid::Uuid) -> String {
        seed_tenant(pool, tenant).await;
        sqlx::query(
            "insert into users (tenant_id, user_id, username, status)
             values ($1, $2, $3, 'active') on conflict do nothing",
        )
        .bind(tenant)
        .bind(user)
        .bind(user.to_string())
        .execute(pool)
        .await
        .expect("seed user");

        let id = SessionId::generate();
        PgSessionRepository::new(pool.clone(), TenantId::new(tenant))
            .begin(&Session::begin(
                TenantId::new(tenant),
                &id,
                user,
                vec![AuthenticationMethod::Password],
                OffsetDateTime::now_utc(),
                Lifetimes::default(),
            ))
            .await
            .expect("begin a session");
        id.digest()
    }

    fn a_passkey(user: UserId, credential_id: &[u8]) -> NewPasskey {
        NewPasskey {
            user,
            credential_id: credential_id.to_vec(),
            public_key: b"a COSE key".to_vec(),
            sign_count: 0,
            aaguid: None,
            backup_eligible: true,
            backup_state: false,
            user_verified: true,
            rp_id: "as.example".to_owned(),
            label: None,
        }
    }

    db_test! {
        /// The property the whole table exists for: a challenge is spendable
        /// once. A second finish racing the first gets nothing, which is what
        /// stops a captured ceremony being replayed.
        async fn a_challenge_can_be_spent_exactly_once(db) {
            // Arrange
            let now = OffsetDateTime::now_utc();
            let session = seed_session(&db.pool, "demo", uuid::Uuid::new_v4()).await;
            let repo = repo(&db.pool, "demo");
            repo.open_enrolment(&session, "a-digest", now + ENROLMENT_TTL).await.expect("open");
            repo.issue_challenge(&session, &[7u8; 32], now + ENROLMENT_TTL, now)
                .await
                .expect("issue");

            // Act
            let first = repo.spend_challenge(&session, now).await.expect("spend");
            let second = repo.spend_challenge(&session, now).await.expect("spend again");

            // Assert
            assert_eq!(first.as_deref(), Some([7u8; 32].as_slice()));
            assert_eq!(second, None, "a spent challenge must not come back");
        }
    }

    db_test! {
        /// Past its five minutes, a challenge is not there to be spent — even
        /// though the session it hangs off is still perfectly alive.
        async fn an_expired_challenge_is_not_spendable(db) {
            // Arrange
            let now = OffsetDateTime::now_utc();
            let session = seed_session(&db.pool, "demo", uuid::Uuid::new_v4()).await;
            let repo = repo(&db.pool, "demo");
            repo.open_enrolment(&session, "a-digest", now + ENROLMENT_TTL).await.expect("open");
            repo.issue_challenge(&session, &[7u8; 32], now + ENROLMENT_TTL, now)
                .await
                .expect("issue");

            // Act
            let spent = repo
                .spend_challenge(&session, now + ENROLMENT_TTL + Duration::seconds(1))
                .await
                .expect("spend");

            // Assert
            assert_eq!(spent, None);
        }
    }

    db_test! {
        /// Rendering the page again starts over: the token that was outstanding
        /// stops working, and so does the challenge it went with.
        async fn reopening_an_enrolment_drops_the_outstanding_challenge(db) {
            // Arrange
            let now = OffsetDateTime::now_utc();
            let session = seed_session(&db.pool, "demo", uuid::Uuid::new_v4()).await;
            let repo = repo(&db.pool, "demo");
            repo.open_enrolment(&session, "first", now + ENROLMENT_TTL).await.expect("open");
            repo.issue_challenge(&session, &[7u8; 32], now + ENROLMENT_TTL, now)
                .await
                .expect("issue");

            // Act
            repo.open_enrolment(&session, "second", now + ENROLMENT_TTL).await.expect("reopen");

            // Assert
            let enrolment = repo.enrolment(&session, now).await.expect("read").expect("present");
            assert_eq!(enrolment.csrf_digest, "second");
            assert_eq!(enrolment.challenge, None);
            assert_eq!(repo.spend_challenge(&session, now).await.expect("spend"), None);
        }
    }

    db_test! {
        /// A challenge cannot be attached to an enrolment that has run out,
        /// which is what stops a page left open all afternoon from starting a
        /// ceremony on an old token.
        async fn an_expired_enrolment_takes_no_new_challenge(db) {
            // Arrange
            let now = OffsetDateTime::now_utc();
            let session = seed_session(&db.pool, "demo", uuid::Uuid::new_v4()).await;
            let repo = repo(&db.pool, "demo");
            repo.open_enrolment(&session, "a-digest", now + ENROLMENT_TTL).await.expect("open");

            // Act
            let issued = repo
                .issue_challenge(
                    &session,
                    &[7u8; 32],
                    now + ENROLMENT_TTL,
                    now + ENROLMENT_TTL + Duration::seconds(1),
                )
                .await
                .expect("issue");

            // Assert
            assert!(!issued);
        }
    }

    db_test! {
        /// Signing out takes the outstanding ceremony with it. The binding is a
        /// foreign key, so this is the database's answer and not a sweep's.
        async fn deleting_the_session_deletes_its_enrolment(db) {
            // Arrange
            let now = OffsetDateTime::now_utc();
            let session = seed_session(&db.pool, "demo", uuid::Uuid::new_v4()).await;
            let repo = repo(&db.pool, "demo");
            repo.open_enrolment(&session, "a-digest", now + ENROLMENT_TTL).await.expect("open");

            // Act
            sqlx::query("delete from sessions where tenant_id = $1 and session_id = $2")
                .bind("demo")
                .bind(&session)
                .execute(&db.pool)
                .await
                .expect("delete the session");

            // Assert
            assert_eq!(repo.enrolment(&session, now).await.expect("read"), None);
        }
    }

    db_test! {
        /// §7.1 step 22, enforced by the unique index rather than by a check
        /// with a race in it: one credential id, once, per tenant.
        async fn a_credential_id_is_unique_across_the_tenant(db) {
            // Arrange
            let first = uuid::Uuid::new_v4();
            let second = uuid::Uuid::new_v4();
            seed_session(&db.pool, "demo", first).await;
            seed_session(&db.pool, "demo", second).await;
            let repo = repo(&db.pool, "demo");
            repo.register(&a_passkey(UserId::new(first), b"the-credential-id"))
                .await
                .expect("register");

            // Act: a *different* user in the same tenant claims the same id.
            let again = repo
                .register(&a_passkey(UserId::new(second), b"the-credential-id"))
                .await;

            // Assert
            assert!(
                matches!(again, Err(DomainError::Conflict(_))),
                "expected a conflict, got {again:?}"
            );
        }
    }

    db_test! {
        /// ...and the scope of that rule is the tenant. Two tenants are two
        /// directories, and an id in one says nothing about the other.
        async fn the_same_credential_id_may_exist_in_another_tenant(db) {
            // Arrange
            let here = uuid::Uuid::new_v4();
            let there = uuid::Uuid::new_v4();
            seed_session(&db.pool, "demo", here).await;
            seed_session(&db.pool, "other", there).await;
            repo(&db.pool, "demo")
                .register(&a_passkey(UserId::new(here), b"the-credential-id"))
                .await
                .expect("register here");

            // Act
            let elsewhere = repo(&db.pool, "other")
                .register(&a_passkey(UserId::new(there), b"the-credential-id"))
                .await;

            // Assert
            assert!(elsewhere.is_ok(), "{elsewhere:?}");
        }
    }

    db_test! {
        /// Both backup flags and the sign counter reach the row. A recovery
        /// policy reads `eligible`; a cloned-authenticator check reads the
        /// counter; neither can read what was never written.
        async fn the_flags_and_the_counter_are_stored(db) {
            // Arrange
            let user = uuid::Uuid::new_v4();
            seed_session(&db.pool, "demo", user).await;
            let mut passkey = a_passkey(UserId::new(user), b"the-credential-id");
            passkey.sign_count = 42;
            passkey.backup_eligible = true;
            passkey.backup_state = true;

            // Act
            let stored = repo(&db.pool, "demo").register(&passkey).await.expect("register");

            // Assert
            let row = sqlx::query(
                "select passkey_backup_eligible, passkey_backup_state, passkey_sign_count,
                        passkey_rp_id, passkey_user_verified
                   from credentials where tenant_id = $1 and credential_id = $2",
            )
            .bind("demo")
            .bind(stored)
            .fetch_one(&db.pool)
            .await
            .expect("read the credential back");
            assert_eq!(row.get::<Option<bool>, _>("passkey_backup_eligible"), Some(true));
            assert_eq!(row.get::<Option<bool>, _>("passkey_backup_state"), Some(true));
            assert_eq!(row.get::<i64, _>("passkey_sign_count"), 42);
            assert_eq!(row.get::<Option<String>, _>("passkey_rp_id").as_deref(), Some("as.example"));
            assert_eq!(row.get::<Option<bool>, _>("passkey_user_verified"), Some(true));
        }
    }

    db_test! {
        /// `excludeCredentials` is built from this, and it is scoped to one
        /// user: offering somebody else's credential ids to an authenticator
        /// would answer a question nobody asked.
        async fn credential_ids_are_listed_for_one_user_only(db) {
            // Arrange
            let mine = uuid::Uuid::new_v4();
            let theirs = uuid::Uuid::new_v4();
            seed_session(&db.pool, "demo", mine).await;
            seed_session(&db.pool, "demo", theirs).await;
            let repo = repo(&db.pool, "demo");
            repo.register(&a_passkey(UserId::new(mine), b"mine")).await.expect("register");
            repo.register(&a_passkey(UserId::new(theirs), b"theirs")).await.expect("register");

            // Act
            let listed = repo.credential_ids(&UserId::new(mine)).await.expect("list");

            // Assert
            assert_eq!(listed, vec![b"mine".to_vec()]);
        }
    }

    // -----------------------------------------------------------------------
    // Authentication against a first-party interaction (`ast-akl`)
    // -----------------------------------------------------------------------

    /// The other kind of interaction, begun the way `/t/{tenant}/admin/` does.
    ///
    /// Returns the digest the browser's credential is looked up by, which is
    /// the same handle the authorization path passes to these statements.
    async fn seed_first_party(pool: &PgPool, tenant: &str, seed: &str) -> String {
        seed_tenant(pool, tenant).await;
        let now = OffsetDateTime::now_utc();
        let ix = super::auth_requests::digest(seed);
        PgAuthRequestRepository::new(pool.clone(), TenantId::new(tenant))
            .begin_first_party_interaction(
                &ix,
                FirstPartyDestination::AdminConsole,
                now + Duration::minutes(10),
                now,
            )
            .await
            .expect("begin a first-party interaction");
        ix
    }

    db_test! {
        /// `ast-akl`. An administrator arriving at `/t/{tenant}/admin/` gets a
        /// login page with a passkey button on it, and that button posts to
        /// the same two routes an authorization's login page posts to. So the
        /// challenge those routes store has to reach whichever table holds the
        /// interaction: one that can only attach to an `auth_requests` row
        /// leaves the page offering an option that cannot work, which is worse
        /// than offering none.
        async fn a_challenge_attaches_to_a_first_party_interaction(db) {
            // Arrange
            let now = OffsetDateTime::now_utc();
            let ix = seed_first_party(&db.pool, "demo", "an-admin-at-the-console").await;
            let repo = repo(&db.pool, "demo");

            // Act
            let issued = repo
                .issue_assertion_challenge(&ix, &[9u8; 32], now + Duration::minutes(5), now)
                .await
                .expect("issue");

            // Assert
            assert!(issued, "a first-party interaction took no challenge");
            assert_eq!(
                repo.spend_assertion_challenge(&ix, now).await.expect("spend").as_deref(),
                Some([9u8; 32].as_slice()),
            );
        }
    }

    db_test! {
        /// `ast-akl`. Single use, on the first-party table too: two finishes
        /// racing one ceremony must not both come away with bytes, or a
        /// captured assertion replays into a second administrator session.
        async fn a_first_party_challenge_can_be_spent_exactly_once(db) {
            // Arrange
            let now = OffsetDateTime::now_utc();
            let ix = seed_first_party(&db.pool, "demo", "a-replayed-console-ceremony").await;
            let repo = repo(&db.pool, "demo");
            repo.issue_assertion_challenge(&ix, &[9u8; 32], now + Duration::minutes(5), now)
                .await
                .expect("issue");

            // Act
            let first = repo.spend_assertion_challenge(&ix, now).await.expect("spend");
            let second = repo.spend_assertion_challenge(&ix, now).await.expect("spend again");

            // Assert
            assert_eq!(first.as_deref(), Some([9u8; 32].as_slice()));
            assert_eq!(second, None, "a spent first-party challenge came back");
        }
    }

    db_test! {
        /// `ast-akl`. The challenge carries its own deadline, shorter than the
        /// interaction's: a page left open all afternoon must not still be
        /// able to finish the ceremony it started (§13.4.3).
        async fn an_expired_first_party_challenge_is_not_spendable(db) {
            // Arrange
            let now = OffsetDateTime::now_utc();
            let ix = seed_first_party(&db.pool, "demo", "a-console-page-left-open").await;
            let repo = repo(&db.pool, "demo");
            repo.issue_assertion_challenge(&ix, &[9u8; 32], now + Duration::minutes(5), now)
                .await
                .expect("issue");

            // Act
            let spent = repo
                .spend_assertion_challenge(&ix, now + Duration::minutes(5) + Duration::seconds(1))
                .await
                .expect("spend");

            // Assert
            assert_eq!(spent, None);
        }
    }

    db_test! {
        /// `ast-akl`. A consumed interaction is a finished one, and the
        /// predicate that makes it unresumable holds for the passkey route as
        /// well as for the password form.
        async fn a_consumed_first_party_interaction_takes_no_challenge(db) {
            // Arrange
            let now = OffsetDateTime::now_utc();
            let ix = seed_first_party(&db.pool, "demo", "a-finished-console-visit").await;
            PgAuthRequestRepository::new(db.pool.clone(), TenantId::new("demo"))
                .complete_interaction(&ix, now)
                .await
                .expect("complete");

            // Act
            let issued = repo(&db.pool, "demo")
                .issue_assertion_challenge(&ix, &[9u8; 32], now + Duration::minutes(5), now)
                .await
                .expect("issue");

            // Assert
            assert!(!issued, "a spent interaction accepted a new challenge");
        }
    }

    db_test! {
        /// `ast-akl`. Tenancy, on a statement reached before any account is
        /// known: a challenge issued for one tenant's interaction is not
        /// spendable through another tenant's repository.
        async fn a_first_party_challenge_stops_at_the_tenant_boundary(db) {
            // Arrange
            let now = OffsetDateTime::now_utc();
            let ix = seed_first_party(&db.pool, "demo", "a-shared-handle").await;
            seed_tenant(&db.pool, "other").await;
            repo(&db.pool, "demo")
                .issue_assertion_challenge(&ix, &[9u8; 32], now + Duration::minutes(5), now)
                .await
                .expect("issue");

            // Act
            let stolen = repo(&db.pool, "other")
                .spend_assertion_challenge(&ix, now)
                .await
                .expect("spend");

            // Assert
            assert_eq!(stolen, None, "another tenant spent this challenge");
        }
    }
}

// ---------------------------------------------------------------------------
// Tenant creation provisions signing keys (`ast-qa3`)
// ---------------------------------------------------------------------------

use asterius_domain::ports::SystemClock;
use asterius_store_pg::{ProvisionedTenants, TenantKeyStore};

/// The tenant repository the composition root hands to everything else.
fn provisioned_tenants(pool: &PgPool) -> ProvisionedTenants {
    ProvisionedTenants::new(
        PgTenantRepository::new(pool.clone(), kek()),
        TenantKeyStore::new(
            pool.clone(),
            kek(),
            Arc::new(PgAuditSink::new(pool.clone())),
        ),
        Arc::new(SystemClock),
    )
}

/// One active key per advertised algorithm is what a provisioned tenant holds.
///
/// Written as a length so that adding a fourth algorithm to
/// `SigningAlgorithm::ALL` fails the assertions below rather than quietly
/// leaving one algorithm unprovisioned.
fn algorithms() -> i64 {
    i64::try_from(SigningAlgorithm::ALL.len()).expect("three algorithms fit in an i64")
}

/// How many keys in `state` the tenant holds, whatever the algorithm.
async fn key_count(pool: &PgPool, tenant: &str, state: &str) -> i64 {
    sqlx::query_scalar(
        "select count(*) from signing_keys where tenant_id = $1 and purpose = 'sig' and state = $2",
    )
    .bind(tenant)
    .bind(state)
    .fetch_one(pool)
    .await
    .expect("count keys")
}

db_test! {
    /// `ast-qa3`. Provisioning used to happen only in a loop in `main`, so a
    /// tenant created any other way held no keys and — since `ast-a05.13` —
    /// refused every client registration until the next restart. Creating one
    /// now leaves it able to sign every algorithm the discovery document
    /// advertises, with no boot involved.
    async fn creating_a_tenant_provisions_a_key_for_every_advertised_algorithm(db) {
        // Arrange
        let tenants = provisioned_tenants(&db.pool);

        // Act
        tenants
            .upsert(&tenant("provisioned", "https://as.example/t/provisioned"))
            .await
            .expect("create the tenant");

        // Assert
        let store = TenantKeyStore::new(
            db.pool.clone(),
            kek(),
            Arc::new(PgAuditSink::new(db.pool.clone())),
        );
        let repository = store.for_tenant(&TenantId::new("provisioned"));
        for algorithm in SigningAlgorithm::ALL {
            assert!(
                repository
                    .active_signing_key(algorithm)
                    .await
                    .expect("read the active key")
                    .is_some(),
                "a tenant created off the boot path holds no active {algorithm} key"
            );
        }
    }
}

db_test! {
    /// Two replicas starting at the same moment assert the same configuration
    /// at the same moment. The pass runs under
    /// `pg_advisory_xact_lock(hashtext(tenant), hashtext('key-rotation'))`, so
    /// the loser waits and then finds nothing due: one set of keys, not two.
    /// A second `upsert` — the ordinary case of re-asserting a tenant on every
    /// boot — must be equally free of new keys.
    async fn provisioning_a_tenant_twice_at_once_leaves_one_key_per_algorithm(db) {
        // Arrange
        let subject = tenant("racing", "https://as.example/t/racing");
        let one = provisioned_tenants(&db.pool);
        let two = provisioned_tenants(&db.pool);

        // Act
        let (first, second) = tokio::join!(one.upsert(&subject), two.upsert(&subject));

        // Assert
        first.expect("the first writer");
        second.expect("the second writer");
        assert_eq!(
            key_count(&db.pool, "racing", "active").await,
            algorithms(),
            "the race produced a key set per writer"
        );
        assert_eq!(
            key_count(&db.pool, "racing", "pending").await,
            0,
            "a first provisioning staged a key nobody is waiting to publish"
        );

        one.upsert(&subject).await.expect("re-assert the tenant");
        assert_eq!(
            key_count(&db.pool, "racing", "active").await,
            algorithms(),
            "re-asserting a tenant created a second set of keys"
        );
    }
}

db_test! {
    /// `ast-1gj`. The two writers above are not enough to hold the window
    /// open, and CI found what they miss: `Conflict("tenants_issuer_key")`.
    ///
    /// `on conflict (tenant_id) do update` names one arbiter, and Postgres
    /// only routes a conflict on *that* index to the update. `tenants.issuer`
    /// and `tenants.custom_host` are unique too, and a duplicate found there
    /// is a plain `23505`. Between one writer's arbiter check and its index
    /// insertion another can insert the same row, and the loser then meets the
    /// concurrent tuple on the issuer index rather than on the primary key —
    /// so a second replica asserting the configuration at boot fails outright
    /// instead of updating.
    ///
    /// Real threads and repeated rounds, because the window is a few
    /// microseconds inside one statement's execution: `tokio::join!` on one
    /// thread sends the statements in an order that keeps missing it — which
    /// is exactly why the two-writer test above passed here for months and
    /// then failed on a CI runner.
    async fn asserting_one_tenant_from_many_writers_at_once_never_conflicts(db) {
        // Arrange
        let repository = PgTenantRepository::new(db.pool.clone(), kek());
        let subject = tenant("stampede", "https://as.example/t/stampede");

        for round in 0..10 {
            if round > 0 {
                // Every round starts from no row, because it is the *insert*
                // that races; an update of an existing row does not.
                repository
                    .delete(&TenantId::new("stampede"))
                    .await
                    .expect("clear the tenant between rounds");
            }

            // Act: every writer waits at the barrier and then asserts the same
            // configuration, which is what a deployment's replicas do at boot.
            let barrier = Arc::new(std::sync::Barrier::new(8));
            let racing: Vec<_> = (0..8)
                .map(|_| {
                    let schema = db.schema.clone();
                    let subject = subject.clone();
                    let barrier = Arc::clone(&barrier);
                    std::thread::spawn(move || {
                        let runtime = tokio::runtime::Builder::new_current_thread()
                            .enable_all()
                            .build()
                            .expect("a runtime per writer");
                        runtime.block_on(async move {
                            // Its own pool, not the test's: a sqlx connection
                            // belongs to the runtime that opened it, and this
                            // thread's runtime is not the one driving that
                            // one. Sharing it deadlocks on the acquire.
                            let repository =
                                PgTenantRepository::new(connect_to_schema(&schema).await, kek());
                            barrier.wait();
                            repository.upsert(&subject).await
                        })
                    })
                })
                .collect();

            // Assert
            for (index, writer) in racing.into_iter().enumerate() {
                writer
                    .join()
                    .expect("a writer thread")
                    .unwrap_or_else(|error| panic!("round {round}, writer {index}: {error}"));
            }
        }

        assert_eq!(
            tenant_count(&db.pool, "stampede").await,
            1,
            "the stampede left more than one row for one tenant"
        );
    }
}

/// A pool of one connection pinned to an already-migrated schema.
///
/// `setup`'s connection options without its schema creation and migrations:
/// the writers above each need a pool their own runtime opened, and they are
/// all racing inside a schema that already exists.
async fn connect_to_schema(schema: &str) -> PgPool {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL is set: setup read it");
    let options = PgConnectOptions::from_str(&url)
        .expect("DATABASE_URL is not a valid PostgreSQL URL")
        .options([("search_path", schema)]);
    PgPoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .expect("connect")
}

/// How many rows one tenant id holds. One, or the upsert is not an upsert.
async fn tenant_count(pool: &PgPool, tenant: &str) -> i64 {
    sqlx::query_scalar("select count(*) from tenants where tenant_id = $1")
        .bind(tenant)
        .fetch_one(pool)
        .await
        .expect("count tenants")
}

db_test! {
    /// The reserved tenant of `ast-1cj`. It used to get its keys only because
    /// `main` named it in the startup loop one step after seeding it — a
    /// guarantee that held by the order of two calls in the composition root.
    /// The seed provisions it itself now, so the deployment admin's login page
    /// can mint a session however the seed was reached.
    async fn the_seeded_reserved_tenant_can_sign_without_the_boot_loop(db) {
        // Arrange / Act
        let seeded = admin_seed(&db.pool)
            .ensure(&deployment_admin("admin"))
            .await
            .expect("seed");

        // Assert
        let store = TenantKeyStore::new(
            db.pool.clone(),
            kek(),
            Arc::new(PgAuditSink::new(db.pool.clone())),
        );
        let repository = store.for_tenant(&seeded.tenant);
        for algorithm in SigningAlgorithm::ALL {
            assert!(
                repository
                    .active_signing_key(algorithm)
                    .await
                    .expect("read the active key")
                    .is_some(),
                "the reserved tenant holds no active {algorithm} key"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Rate limits (ast-2vk.9)
// ---------------------------------------------------------------------------

db_test! {
    /// The property the whole design rests on: the counter is in the database,
    /// so two callers — two replicas, in production — that increment the same
    /// bucket at the same time produce two, not one. A counter per process
    /// would multiply every configured limit by the replica count.
    async fn concurrent_increments_of_one_bucket_are_not_lost(db) {
        // Arrange
        seed_tenant(&db.pool, "demo").await;
        let store = asterius_store_pg::PgRateLimitStore::new(db.pool.clone());
        let tenant = TenantId::new("demo");
        let bucket = asterius_domain::account_bucket("ada");
        let window = OffsetDateTime::UNIX_EPOCH;
        let expiry = window + time::Duration::minutes(15);

        // Act
        let one = store.record(&tenant, &bucket, window, expiry);
        let two = store.record(&tenant, &bucket, window, expiry);
        let (first, second) = tokio::join!(one, two);

        // Assert
        let mut counts = [
            first.expect("the first increment"),
            second.expect("the second increment"),
        ];
        counts.sort_unstable();
        assert_eq!(counts, [1, 2], "an increment was lost");
        assert_eq!(
            store
                .count(&tenant, &bucket, window)
                .await
                .expect("read the counter"),
            2
        );
    }
}

db_test! {
    /// A counter is a per-tenant fact. One tenant's failed sign-ins must not
    /// lock a user of another tenant out.
    async fn one_tenants_counter_is_not_another_tenants(db) {
        // Arrange
        seed_tenant(&db.pool, "alpha").await;
        seed_tenant(&db.pool, "beta").await;
        let store = asterius_store_pg::PgRateLimitStore::new(db.pool.clone());
        let bucket = asterius_domain::account_bucket("ada");
        let window = OffsetDateTime::UNIX_EPOCH;

        // Act
        store
            .record(
                &TenantId::new("alpha"),
                &bucket,
                window,
                window + time::Duration::minutes(15),
            )
            .await
            .expect("count a failure for alpha");

        // Assert
        assert_eq!(
            store
                .count(&TenantId::new("beta"), &bucket, window)
                .await
                .expect("read beta's counter"),
            0
        );
    }
}

db_test! {
    /// Windows are separate rows, so the limit lifts when one rolls over
    /// rather than when somebody remembers to reset it.
    async fn a_later_window_starts_from_zero(db) {
        // Arrange
        seed_tenant(&db.pool, "demo").await;
        let store = asterius_store_pg::PgRateLimitStore::new(db.pool.clone());
        let tenant = TenantId::new("demo");
        let bucket = asterius_domain::account_bucket("ada");
        let first = OffsetDateTime::UNIX_EPOCH;
        let next = first + time::Duration::minutes(15);

        // Act
        store
            .record(&tenant, &bucket, first, next)
            .await
            .expect("count a failure");

        // Assert
        assert_eq!(
            store
                .count(&tenant, &bucket, next)
                .await
                .expect("read the next window"),
            0
        );
    }
}

db_test! {
    /// What a successful sign-in asks for (`ast-b3u`): every window of the
    /// bucket forgotten, not just the current one. The boundary is aligned to
    /// the epoch, so a proof made a second before a rollover would otherwise
    /// hand the next window a counter it never earned. One tenant's reset must
    /// also leave another tenant's counter for the same bucket alone.
    async fn clearing_a_bucket_forgets_every_window_of_it(db) {
        // Arrange
        seed_tenant(&db.pool, "demo").await;
        seed_tenant(&db.pool, "other").await;
        let store = asterius_store_pg::PgRateLimitStore::new(db.pool.clone());
        let tenant = TenantId::new("demo");
        let bucket = asterius_domain::account_bucket("ada");
        let first = OffsetDateTime::UNIX_EPOCH;
        let next = first + time::Duration::minutes(15);
        for (owner, window) in [(&tenant, first), (&tenant, next), (&TenantId::new("other"), first)] {
            store
                .record(owner, &bucket, window, window + time::Duration::minutes(15))
                .await
                .expect("count a failure");
        }

        // Act
        store.clear(&tenant, &bucket).await.expect("clear the bucket");

        // Assert
        for window in [first, next] {
            assert_eq!(
                store
                    .count(&tenant, &bucket, window)
                    .await
                    .expect("read the counter"),
                0,
                "a window survived the reset"
            );
        }
        assert_eq!(
            store
                .count(&TenantId::new("other"), &bucket, first)
                .await
                .expect("read the other tenant's counter"),
            1,
            "another tenant's counter was cleared"
        );
    }
}

// ---------------------------------------------------------------------------
// Refresh tokens (`ast-a05.5`)
// ---------------------------------------------------------------------------

/// The repository behind the `refresh_token` grant.
///
/// The grant's own behaviour is `crates/server/tests/refresh_token.rs`. What
/// is here is the part only the database can answer: that the two expiry
/// columns behave differently, that supersession is atomic, and that the
/// redemption is an index lookup rather than a scan of the tenant's tokens.
mod refresh_tokens {
    use super::*;
    use asterius_domain::{Grant, GrantId};
    use asterius_store_pg::{
        NewRefreshToken, PgGrantRepository, PgRefreshTokenRepository, Presentation, RefreshBinding,
    };
    use std::collections::BTreeSet;
    use time::Duration;

    /// A tenant, a client and a grant for the tokens to hang off.
    async fn seed(pool: &PgPool) -> GrantId {
        seed_tenant(pool, "demo").await;
        Store::from_pool(pool.clone())
            .scope(TenantId::new("demo"))
            .clients(Capabilities::default())
            .upsert(&client("demo", "billing", &registration_document()))
            .await
            .expect("seed client");

        let grants = PgGrantRepository::new(pool.clone(), TenantId::new("demo"));
        let mut grant = Grant::new(
            TenantId::new("demo"),
            ClientId::new("billing"),
            OffsetDateTime::now_utc(),
        );
        grant.subject = Some(SubjectId::new("alice"));
        grant.user = Some(UserId::generate());
        grant.scopes = ["openid", "offline_access"]
            .into_iter()
            .map(str::to_owned)
            .collect();
        grants.create(&grant).await.expect("seed grant");
        grant.id
    }

    /// A whole-second instant.
    ///
    /// `timestamptz` stores microseconds and `OffsetDateTime::now_utc()`
    /// carries nanoseconds, so a deadline written and read back is not the
    /// value that went in. These tests compare stored deadlines exactly —
    /// which is the point of them — so the instant they are built from has to
    /// be one the column can hold.
    fn fixed_instant() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_760_000_000).expect("a fixed instant")
    }

    fn scopes() -> BTreeSet<String> {
        ["openid".to_owned(), "offline_access".to_owned()].into()
    }

    fn token(
        grant: &GrantId,
        absolute: OffsetDateTime,
        idle: Option<OffsetDateTime>,
    ) -> NewRefreshToken {
        NewRefreshToken {
            grant: grant.clone(),
            client: ClientId::new("billing"),
            scopes: scopes(),
            binding: RefreshBinding::Dpop("a-thumbprint".to_owned()),
            absolute_expires_at: absolute,
            idle_expires_at: idle,
        }
    }

    db_test! {
        /// The two clocks, and the difference between them. Using a token
        /// pushes the idle deadline out and leaves the absolute one exactly
        /// where it was — which is the whole reason they are two columns.
        async fn using_a_token_moves_the_idle_deadline_and_not_the_absolute_one(db) {
            // Arrange
            let grant = seed(&db.pool).await;
            let repo = PgRefreshTokenRepository::new(db.pool.clone(), TenantId::new("demo"));
            let now = fixed_instant();
            let absolute = now + Duration::days(30);
            repo.issue("aa".repeat(32).as_str(), &token(&grant, absolute, Some(now + Duration::hours(1))), now)
                .await
                .expect("issue");

            // Act
            let accepted = repo
                .redeem(
                    "aa".repeat(32).as_str(),
                    now,
                    Duration::ZERO,
                    Some(now + Duration::days(14)),
                )
                .await
                .expect("redeem");

            // Assert
            let Presentation::Accepted(record) = accepted else {
                panic!("a live token was refused");
            };
            assert_eq!(record.absolute_expires_at, absolute);
            let (idle, stored_absolute): (Option<OffsetDateTime>, OffsetDateTime) = sqlx::query_as(
                "select idle_expires_at, absolute_expires_at from refresh_tokens
                  where tenant_id = 'demo' and token_hash = $1",
            )
            .bind(hex::decode("aa".repeat(32)).expect("hex"))
            .fetch_one(&db.pool)
            .await
            .expect("read the row back");
            assert_eq!(
                stored_absolute, absolute,
                "the absolute deadline moved when the token was used"
            );
            assert!(
                idle.expect("an idle deadline") > now + Duration::days(13),
                "the idle deadline was not pushed out"
            );
        }
    }

    db_test! {
        /// The idle deadline is capped at the absolute one in the statement
        /// that writes it, not only by the `CHECK` that would abort the
        /// transaction. A tenant whose idle window is longer than what is left
        /// of the absolute lifetime must still be able to refresh.
        async fn a_pushed_idle_deadline_never_passes_the_absolute_one(db) {
            // Arrange
            let grant = seed(&db.pool).await;
            let repo = PgRefreshTokenRepository::new(db.pool.clone(), TenantId::new("demo"));
            let now = fixed_instant();
            let absolute = now + Duration::hours(1);
            repo.issue("bb".repeat(32).as_str(), &token(&grant, absolute, Some(now + Duration::minutes(5))), now)
                .await
                .expect("issue");

            // Act
            let accepted = repo
                .redeem(
                    "bb".repeat(32).as_str(),
                    now,
                    Duration::ZERO,
                    Some(now + Duration::days(14)),
                )
                .await
                .expect("redeem");

            // Assert
            assert!(matches!(accepted, Presentation::Accepted(_)));
            let idle: Option<OffsetDateTime> = sqlx::query_scalar(
                "select idle_expires_at from refresh_tokens
                  where tenant_id = 'demo' and token_hash = $1",
            )
            .bind(hex::decode("bb".repeat(32)).expect("hex"))
            .fetch_one(&db.pool)
            .await
            .expect("read the row back");
            assert_eq!(idle, Some(absolute));
        }
    }

    db_test! {
        /// Supersession writes both rows or neither. A replacement whose
        /// digest already exists must not leave the old token stamped: the
        /// client would then hold nothing this server accepts.
        async fn a_failed_supersession_leaves_the_old_token_live(db) {
            // Arrange
            let grant = seed(&db.pool).await;
            let repo = PgRefreshTokenRepository::new(db.pool.clone(), TenantId::new("demo"));
            let now = fixed_instant();
            let absolute = now + Duration::days(30);
            repo.issue("cc".repeat(32).as_str(), &token(&grant, absolute, None), now)
                .await
                .expect("issue the old token");
            // The replacement's digest is already taken, so the insert fails.
            repo.issue("dd".repeat(32).as_str(), &token(&grant, absolute, None), now)
                .await
                .expect("issue the collider");

            // Act
            let failed = repo
                .supersede(
                    "cc".repeat(32).as_str(),
                    "dd".repeat(32).as_str(),
                    &token(&grant, absolute, None),
                    now,
                )
                .await;

            // Assert
            assert!(failed.is_err(), "a colliding replacement was accepted");
            let superseded: Option<OffsetDateTime> = sqlx::query_scalar(
                "select superseded_at from refresh_tokens
                  where tenant_id = 'demo' and token_hash = $1",
            )
            .bind(hex::decode("cc".repeat(32)).expect("hex"))
            .fetch_one(&db.pool)
            .await
            .expect("read the row back");
            assert_eq!(
                superseded, None,
                "the old token was stamped by a supersession that did not happen"
            );
        }
    }

    db_test! {
        /// A second refresh inside the grace window does not push the window
        /// out. `coalesce` keeps the first stamp, so the window is a window
        /// rather than a lease the holder of a stolen token can renew.
        async fn superseding_twice_keeps_the_first_stamp(db) {
            // Arrange
            let grant = seed(&db.pool).await;
            let repo = PgRefreshTokenRepository::new(db.pool.clone(), TenantId::new("demo"));
            let now = fixed_instant();
            let absolute = now + Duration::days(30);
            repo.issue("ee".repeat(32).as_str(), &token(&grant, absolute, None), now)
                .await
                .expect("issue");
            repo.supersede("ee".repeat(32).as_str(), &"ff".repeat(32), &token(&grant, absolute, None), now)
                .await
                .expect("first supersession");

            // Act
            repo.supersede(
                "ee".repeat(32).as_str(),
                &"ab".repeat(32),
                &token(&grant, absolute, None),
                now + Duration::minutes(30),
            )
            .await
            .expect("second supersession");

            // Assert
            let stamped: OffsetDateTime = sqlx::query_scalar(
                "select superseded_at from refresh_tokens
                  where tenant_id = 'demo' and token_hash = $1",
            )
            .bind(hex::decode("ee".repeat(32)).expect("hex"))
            .fetch_one(&db.pool)
            .await
            .expect("read the row back");
            assert!(
                stamped < now + Duration::minutes(1),
                "a retry pushed the grace window out"
            );
        }
    }

    db_test! {
        /// `ast-m9c.11`'s lesson, applied here: a predicate with no index is a
        /// scan of the tenant wearing a `where` clause. The redemption reads
        /// one row by the primary key, and a tenant with a realistic number of
        /// live tokens is where a planner would show otherwise.
        async fn the_redemption_is_planned_as_an_index_lookup(db) {
            // Arrange
            let grant = seed(&db.pool).await;
            sqlx::query(
                "insert into refresh_tokens (tenant_id, token_hash, grant_id, client_id,
                                             dpop_jkt, absolute_expires_at)
                 select 'demo', sha256(g::text::bytea), $1::uuid, 'billing', 'a-thumbprint',
                        now() + interval '30 days'
                 from generate_series(1, 5000) g",
            )
            .bind(grant.as_str())
            .execute(&db.pool)
            .await
            .expect("fill the tenant");
            sqlx::query("analyze refresh_tokens").execute(&db.pool).await.expect("analyze");

            // Act — `redeem`'s statement, verbatim, planner left alone.
            let plan: Vec<String> = sqlx::query_scalar(
                "explain (costs off)
                 update refresh_tokens
                    set last_used_at = $3,
                        idle_expires_at = $5
                  where tenant_id = $1
                    and token_hash = $2
                    and revoked_at is null
                    and absolute_expires_at > $3
                    and (idle_expires_at is null or idle_expires_at > $3)
                    and (superseded_at is null or superseded_at > $4)",
            )
            .bind("demo")
            .bind(asterius_domain::sha256(b"1").to_vec())
            .bind(OffsetDateTime::now_utc())
            .bind(OffsetDateTime::now_utc())
            .bind(Option::<OffsetDateTime>::None)
            .fetch_all(&db.pool)
            .await
            .expect("explain the redemption");
            let plan = plan.join("\n");

            // Assert
            assert!(
                plan.contains("refresh_tokens_pkey"),
                "the redemption did not use the primary key:\n{plan}"
            );
            assert!(
                !plan.contains("Seq Scan"),
                "the redemption fell back to a scan of the tenant:\n{plan}"
            );
        }
    }

    db_test! {
        /// RFC 7009 §2.1: revoking a refresh token SHOULD "also invalidate all
        /// access tokens based on the same authorization grant". Those tokens
        /// cannot be listed — they are stateless JWTs and nothing wrote their
        /// `jti` down — and the grant is deliberately left standing (Grant
        /// Management ID1 §6.5 Note), so its own `revoked_at` will not refuse
        /// them either. The cutoff on the grant is what does.
        async fn revoking_a_refresh_token_withdraws_the_access_tokens_of_its_grant(db) {
            // Arrange
            let grant = seed(&db.pool).await;
            let repo = PgRefreshTokenRepository::new(db.pool.clone(), TenantId::new("demo"));
            let digest = "aa".repeat(32);
            repo.issue(
                &digest,
                &token(&grant, fixed_instant() + Duration::days(30), None),
                fixed_instant(),
            )
            .await
            .expect("issue");

            // Act
            let revoked_at = fixed_instant() + Duration::hours(1);
            repo.revoke(&digest, &ClientId::new("billing"), revoked_at)
                .await
                .expect("revoke")
                .expect("the token was this client's");

            // Assert
            let grants = PgGrantRepository::new(db.pool.clone(), TenantId::new("demo"));
            assert_eq!(
                grants
                    .revoked_before(&ClientId::new("billing"), Some(&grant))
                    .await
                    .expect("read"),
                Some(revoked_at),
                "the access tokens the revoked refresh token paid for still verify"
            );
        }
    }

    db_test! {
        /// And it is §2.1's rule rather than a client-wide logout: another
        /// grant of the same client keeps its access tokens, because the
        /// authorization behind them was never withdrawn.
        async fn revoking_a_refresh_token_leaves_the_clients_other_grants_alone(db) {
            // Arrange
            let grant = seed(&db.pool).await;
            let repo = PgRefreshTokenRepository::new(db.pool.clone(), TenantId::new("demo"));
            let digest = "bb".repeat(32);
            repo.issue(
                &digest,
                &token(&grant, fixed_instant() + Duration::days(30), None),
                fixed_instant(),
            )
            .await
            .expect("issue");

            // Act
            repo.revoke(&digest, &ClientId::new("billing"), fixed_instant())
                .await
                .expect("revoke")
                .expect("the token was this client's");

            // Assert: the same client, no grant named — which is what a
            // `client_credentials` token looks like on the read path.
            let grants = PgGrantRepository::new(db.pool.clone(), TenantId::new("demo"));
            assert_eq!(
                grants.revoked_before(&ClientId::new("billing"), None).await.expect("read"),
                None,
                "revoking one grant's refresh token withdrew the whole client's tokens"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Resource servers (RFC 8707)
// ---------------------------------------------------------------------------

db_test! {
    /// RFC 8707 §3: the registry is what a `resource` is validated against, so
    /// what is written has to be what is read — including the difference
    /// between "no scope opinion" and "no scopes at all", which is what makes
    /// the column nullable rather than defaulted.
    async fn the_resource_server_registry_round_trips(db) {
        use asterius_domain::ports::ResourceServerRepository as _;
        use asterius_domain::{ResourceIdentifier, ResourceServer};
        use asterius_store_pg::PgResourceServers;

        let repo = PgTenantRepository::new(db.pool.clone(), kek());
        let demo = tenant("demo", "https://as.example/t/demo");
        repo.upsert(&demo).await.expect("insert the tenant");

        let registry = PgResourceServers::new(db.pool.clone(), demo.id.clone());

        // Creating a tenant registers its own default audience, or the first
        // token request after it would find no audience at all.
        let seeded = registry.list().await.expect("list");
        assert_eq!(seeded.len(), 1, "{seeded:?}");
        assert_eq!(seeded[0].identifier.as_str(), demo.default_resource);
        assert_eq!(seeded[0].scopes, None, "an unconfigured registry restricts nothing");

        let scoped = ResourceServer {
            identifier: ResourceIdentifier::parse("https://reports.example/").expect("an identifier"),
            scopes: Some(["read".to_owned()].into_iter().collect()),
            default_token_lifetime: Some(time::Duration::seconds(120)),
        };
        registry.register(&scoped).await.expect("register");

        let listed = registry.list().await.expect("list");
        assert_eq!(listed.len(), 2, "{listed:?}");
        let found = listed
            .iter()
            .find(|s| s.identifier.as_str() == "https://reports.example/")
            .expect("the registered resource server");
        assert_eq!(found.scopes, scoped.scopes);
        assert_eq!(found.default_token_lifetime, Some(time::Duration::seconds(120)));

        // A resource server that understands no scopes at all is a
        // configuration, not an absence.
        let none = ResourceServer { scopes: Some(std::collections::BTreeSet::new()), ..scoped };
        registry.register(&none).await.expect("re-register");
        let listed = registry.list().await.expect("list");
        assert_eq!(listed.len(), 2, "a re-registration inserted a second row: {listed:?}");
        assert_eq!(
            listed
                .iter()
                .find(|s| s.identifier.as_str() == "https://reports.example/")
                .expect("still registered")
                .scopes,
            Some(std::collections::BTreeSet::new())
        );

        assert!(registry.withdraw("https://reports.example/").await.expect("withdraw"));
        assert!(!registry.withdraw("https://reports.example/").await.expect("withdraw again"));
        assert_eq!(registry.list().await.expect("list").len(), 1);
    }
}

db_test! {
    /// A resource identifier is meaningful only inside the tenant that
    /// registered it: two tenants may front the same API, and neither may name
    /// the other's audiences.
    async fn a_registry_never_returns_another_tenants_resource_server(db) {
        use asterius_domain::ports::ResourceServerRepository as _;
        use asterius_domain::{ResourceIdentifier, ResourceServer};
        use asterius_store_pg::PgResourceServers;

        let repo = PgTenantRepository::new(db.pool.clone(), kek());
        let a = tenant("alpha", "https://as.example/t/alpha");
        let b = tenant("beta", "https://as.example/t/beta");
        repo.upsert(&a).await.expect("insert alpha");
        repo.upsert(&b).await.expect("insert beta");

        PgResourceServers::new(db.pool.clone(), a.id.clone())
            .register(&ResourceServer {
                identifier: ResourceIdentifier::parse("https://only-alpha.example/")
                    .expect("an identifier"),
                scopes: None,
                default_token_lifetime: None,
            })
            .await
            .expect("register");

        let beta = PgResourceServers::new(db.pool.clone(), b.id.clone())
            .list()
            .await
            .expect("list");
        assert!(
            beta.iter().all(|s| s.identifier.as_str() != "https://only-alpha.example/"),
            "a tenant saw another tenant's resource server: {beta:?}"
        );
    }
}

db_test! {
    /// The schema refuses an audience nothing could ever match, so a row
    /// inserted by hand during an incident cannot become an `aud` (RFC 8707 §2).
    async fn the_schema_refuses_a_resource_identifier_with_a_fragment(db) {
        let repo = PgTenantRepository::new(db.pool.clone(), kek());
        let demo = tenant("demo", "https://as.example/t/demo");
        repo.upsert(&demo).await.expect("insert the tenant");

        for wrong in ["https://api.example/v1#section", "/v1/accounts", "urn:example:api"] {
            let refused = sqlx::query(
                "insert into resource_servers (tenant_id, identifier) values ($1, $2)",
            )
            .bind(demo.id.as_str())
            .bind(wrong)
            .execute(&db.pool)
            .await;
            assert!(refused.is_err(), "the schema stored {wrong:?} as an audience");
        }
    }

}

// ---------------------------------------------------------------------------
// The shared client key fetch backoff (`ast-mxc.8`)
// ---------------------------------------------------------------------------

/// A negative cache one replica can read from another's failure.
///
/// The in-memory cache in `asterius-jose` is correct and per process; these
/// tests are about the half that has to survive a second replica and a
/// restart, so every one of them uses two adapters — or two caches — over one
/// database.
mod client_key_fetches {
    use super::*;
    use asterius_domain::ClientId;
    use asterius_domain::ports::{ClientKeyFetchBackoff, ClientUrlFetcher};
    use asterius_jose::ClientKeyCache;
    use asterius_store_pg::PgClientKeyFetches;
    use std::sync::atomic::AtomicU64;

    const URI: &str = "https://client.example/jwks?tenant=secret";

    fn at(offset: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_800_000_000 + offset).expect("a valid instant")
    }

    fn client() -> ClientId {
        ClientId::new("billing")
    }

    /// A tenant with one client, which the table's foreign key requires.
    async fn seed(pool: &PgPool) -> TenantId {
        seed_tenant(pool, "demo").await;
        sqlx::query(
            "insert into clients (tenant_id, client_id, client_name,
                                  token_endpoint_auth_method, jwks_uri)
             values ($1, 'billing', 'Billing', 'private_key_jwt', $2)",
        )
        .bind("demo")
        .bind(URI)
        .execute(pool)
        .await
        .expect("seed client");
        TenantId::new("demo")
    }

    db_test! {
        /// The whole point of the table: a failure one replica saw is a
        /// failure the next replica does not have to repeat.
        async fn a_failure_recorded_by_one_replica_is_read_by_another(db) {
            let tenant = seed(&db.pool).await;
            let first = PgClientKeyFetches::new(db.pool.clone());
            let second = PgClientKeyFetches::new(db.pool.clone());

            assert_eq!(
                second.next_attempt_at(&tenant, &client(), URI).await.expect("read"),
                None,
                "nothing has failed yet"
            );

            first
                .record_failure(
                    &tenant,
                    &client(),
                    URI,
                    "cannot connect to client.example",
                    at(0),
                    at(60),
                )
                .await
                .expect("record");

            assert_eq!(
                second.next_attempt_at(&tenant, &client(), URI).await.expect("read"),
                Some(at(60))
            );
        }
    }

    db_test! {
        /// The row describes the last attempt, and a successful attempt is not
        /// a reason to hold anybody back.
        async fn a_successful_fetch_clears_the_row_for_every_replica(db) {
            let tenant = seed(&db.pool).await;
            let store = PgClientKeyFetches::new(db.pool.clone());
            store
                .record_failure(&tenant, &client(), URI, "timed out", at(0), at(60))
                .await
                .expect("record");

            PgClientKeyFetches::new(db.pool.clone())
                .clear(&tenant, &client(), URI)
                .await
                .expect("clear");

            assert_eq!(
                store.next_attempt_at(&tenant, &client(), URI).await.expect("read"),
                None
            );
        }
    }

    db_test! {
        /// Keyed by URL, so a client that re-registers elsewhere does not
        /// inherit the old URL's outage — and a second URL is not held back by
        /// the first one's.
        async fn one_urls_failure_does_not_hold_back_another(db) {
            let tenant = seed(&db.pool).await;
            let store = PgClientKeyFetches::new(db.pool.clone());
            store
                .record_failure(&tenant, &client(), URI, "timed out", at(0), at(60))
                .await
                .expect("record");

            assert_eq!(
                store
                    .next_attempt_at(&tenant, &client(), "https://elsewhere.example/jwks")
                    .await
                    .expect("read"),
                None
            );
        }
    }

    db_test! {
        /// The row is a deadline every replica reads, so a report from an
        /// earlier attempt — a slow replica finishing after a later one — must
        /// not move it backwards and reopen the window.
        async fn a_late_report_of_an_earlier_attempt_does_not_shorten_the_window(db) {
            let tenant = seed(&db.pool).await;
            let store = PgClientKeyFetches::new(db.pool.clone());
            store
                .record_failure(&tenant, &client(), URI, "later attempt", at(30), at(90))
                .await
                .expect("record the later attempt");
            store
                .record_failure(&tenant, &client(), URI, "earlier attempt", at(0), at(60))
                .await
                .expect("record the earlier attempt");

            assert_eq!(
                store.next_attempt_at(&tenant, &client(), URI).await.expect("read"),
                Some(at(90))
            );
        }
    }

    db_test! {
        /// A `jwks_uri` may carry a query parameter the client considers a
        /// secret, so the URL itself never reaches a column — only a digest of
        /// it, and the reason, which is ours.
        async fn the_url_is_never_stored_in_the_clear(db) {
            let tenant = seed(&db.pool).await;
            PgClientKeyFetches::new(db.pool.clone())
                .record_failure(&tenant, &client(), URI, "timed out", at(0), at(60))
                .await
                .expect("record");

            let found: i64 = sqlx::query_scalar(
                "select count(*) from client_key_fetches
                  where tenant_id = $1 and last_error like '%client.example%'",
            )
            .bind("demo")
            .fetch_one(&db.pool)
            .await
            .expect("scan the table");
            assert_eq!(found, 0, "the URL reached a column");
        }
    }

    db_test! {
        /// A reason longer than the column allows must be cut, not refused: a
        /// fetch that failed and whose failure could not be recorded is the
        /// worst of both.
        async fn an_overlong_reason_is_stored_rather_than_refused(db) {
            let tenant = seed(&db.pool).await;
            PgClientKeyFetches::new(db.pool.clone())
                .record_failure(&tenant, &client(), URI, &"x".repeat(5_000), at(0), at(60))
                .await
                .expect("an overlong reason must not fail the write");

            let length: i32 = sqlx::query_scalar(
                "select length(last_error) from client_key_fetches where tenant_id = $1",
            )
            .bind("demo")
            .fetch_one(&db.pool)
            .await
            .expect("read the reason");
            assert!(length <= 200, "the reason was stored at {length} characters");
        }
    }

    /// A fetcher that always fails and counts how often it was asked.
    #[derive(Debug, Default)]
    struct CountingFetcher {
        calls: AtomicU64,
    }

    #[async_trait::async_trait]
    impl ClientUrlFetcher for CountingFetcher {
        async fn fetch(&self, _url: &str) -> Result<Vec<u8>, asterius_domain::DomainError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Err(asterius_domain::DomainError::Storage(
                "cannot connect to client.example".into(),
            ))
        }
    }

    db_test! {
        /// The criterion of `ast-mxc.8`, end to end and over a real database:
        /// three replicas and a restart cost the third party one fetch per
        /// backoff window between them, not one each.
        async fn replicas_and_a_restart_share_one_backoff_window(db) {
            let tenant = seed(&db.pool).await;
            let fetcher = Arc::new(CountingFetcher::default());
            let source = asterius_domain::JwksSource::Uri(URI.to_owned());
            let store = Arc::new(PgClientKeyFetches::new(db.pool.clone()));

            let replica = || {
                ClientKeyCache::new(fetcher.clone() as Arc<dyn ClientUrlFetcher>)
                    .sharing_backoff(store.clone() as Arc<dyn ClientKeyFetchBackoff>)
            };
            let replicas = [replica(), replica(), replica()];

            for second in 0..30 {
                for replica in &replicas {
                    let _ = replica
                        .resolve(&tenant, &client(), &source, None, at(second))
                        .await;
                }
            }
            // A restart: nothing in memory, the row still there.
            let _ = replica()
                .resolve(&tenant, &client(), &source, None, at(31))
                .await;
            assert_eq!(
                fetcher.calls.load(Ordering::Relaxed),
                1,
                "the third party was fetched once per replica, not once between them"
            );

            // And the window ends. `DEFAULT_NEGATIVE_TTL` is 60 seconds.
            let _ = replica()
                .resolve(&tenant, &client(), &source, None, at(60))
                .await;
            assert_eq!(
                fetcher.calls.load(Ordering::Relaxed),
                2,
                "the backoff outlived its window"
            );
        }
    }

    db_test! {
        /// Retention sweeps the table (`POLICY`), and the row it removes is the
        /// spent one: past `next_attempt_at` an entry suppresses nothing.
        async fn a_spent_entry_is_swept_and_a_live_one_is_not(db) {
            let tenant = seed(&db.pool).await;
            let store = PgClientKeyFetches::new(db.pool.clone());
            store
                .record_failure(&tenant, &client(), "https://spent.example/jwks",
                                "timed out", at(-600), at(-60))
                .await
                .expect("record the spent entry");
            store
                .record_failure(&tenant, &client(), "https://live.example/jwks",
                                "timed out", at(0), at(600))
                .await
                .expect("record the live entry");

            asterius_store_pg::PgRetention::new(db.pool.clone())
                .sweep_tenant(&tenant, at(0))
                .await
                .expect("sweep");

            let left: Vec<Vec<u8>> = sqlx::query_scalar(
                "select jwks_uri_hash from client_key_fetches where tenant_id = $1",
            )
            .bind("demo")
            .fetch_all(&db.pool)
            .await
            .expect("read what is left");
            assert_eq!(left.len(), 1, "the sweep took the wrong number of rows");
            assert_eq!(
                left[0],
                asterius_domain::sha256("https://live.example/jwks".as_bytes()).to_vec(),
                "the live entry was swept and the spent one kept"
            );
        }
    }

    db_test! {
        /// One tenant's clients never answer for another's: the key leads with
        /// the tenant, and a client id means nothing outside it.
        async fn a_failure_in_one_tenant_is_invisible_in_another(db) {
            let tenant = seed(&db.pool).await;
            seed_tenant(&db.pool, "other").await;
            sqlx::query(
                "insert into clients (tenant_id, client_id, client_name,
                                      token_endpoint_auth_method, jwks_uri)
                 values ('other', 'billing', 'Billing', 'private_key_jwt', $1)",
            )
            .bind(URI)
            .execute(&db.pool)
            .await
            .expect("seed the other tenant's client");

            let store = PgClientKeyFetches::new(db.pool.clone());
            store
                .record_failure(&tenant, &client(), URI, "timed out", at(0), at(60))
                .await
                .expect("record");

            assert_eq!(
                store
                    .next_attempt_at(&TenantId::new("other"), &client(), URI)
                    .await
                    .expect("read"),
                None
            );
        }
    }
}

// ---------------------------------------------------------------------------
// The previous key-encryption key, during a rotation
// ---------------------------------------------------------------------------

/// Steps 3 to 5 of the rotation runbook, from the database's side.
///
/// The rows move one tenant at a time while the replicas keep running, so
/// between the first re-wrapped row and the last restarted replica the
/// deployment holds rows under two keys. `CompositeKek` is what lets a process
/// on the new key open a row still on the old one — reads only. These tests use
/// a real repository against a real schema, because the failure they describe
/// is a `select` returning a row this process cannot open, and a unit test over
/// the KEK alone cannot show that.
mod previous_kek {
    use super::*;
    use asterius_domain::keys::SigningAlgorithm;
    use asterius_jose::CompositeKek;
    use asterius_jose::kek::Kek;
    use asterius_store_pg::{PgAuditSink, PgKeyRepository};
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A repository for one tenant under whichever KEK the test is holding.
    fn keys_under(pool: &PgPool, tenant: &str, kek: Arc<dyn Kek>) -> PgKeyRepository {
        PgKeyRepository::new(
            pool.clone(),
            TenantId::new(tenant),
            kek,
            Arc::new(PgAuditSink::new(pool.clone())),
        )
    }

    /// The current key with the old one behind it, as a booted replica holds it.
    fn composite(current: Arc<dyn Kek>, previous: Arc<dyn Kek>) -> Arc<dyn Kek> {
        Arc::new(CompositeKek::new(current, previous).expect("two distinct keys"))
    }

    /// A KEK that counts the unwraps it is asked for, over a real one.
    #[derive(Debug)]
    struct Spy {
        inner: Arc<LocalKek>,
        unwraps: AtomicUsize,
    }

    impl Spy {
        fn over(inner: Arc<LocalKek>) -> Arc<Self> {
            Arc::new(Self {
                inner,
                unwraps: AtomicUsize::new(0),
            })
        }

        fn unwraps(&self) -> usize {
            self.unwraps.load(Ordering::Relaxed)
        }
    }

    #[async_trait::async_trait]
    impl Kek for Spy {
        fn id(&self) -> &str {
            self.inner.id()
        }

        async fn wrap(
            &self,
            binding: asterius_jose::KeyBinding<'_>,
            plaintext: &[u8],
        ) -> Result<asterius_jose::WrappedKey, asterius_jose::JoseError> {
            self.inner.wrap(binding, plaintext).await
        }

        async fn unwrap(
            &self,
            binding: asterius_jose::KeyBinding<'_>,
            wrapped: &asterius_jose::WrappedKey,
        ) -> Result<zeroize::Zeroizing<Vec<u8>>, asterius_jose::JoseError> {
            self.unwraps.fetch_add(1, Ordering::Relaxed);
            self.inner.unwrap(binding, wrapped).await
        }
    }

    db_test! {
        /// A replica restarted on the new key opens a signing key the re-wrap
        /// has not reached yet. Without this, step 5 of the runbook is a window
        /// in which a restart cannot boot.
        async fn a_signing_key_under_the_previous_key_still_opens(db) {
            seed_tenant(&db.pool, "demo").await;
            let old = keys_under(&db.pool, "demo", kek());
            let created = old
                .rotate(SigningAlgorithm::EdDsa, operator(), epoch())
                .await
                .expect("rotate")
                .created
                .expect("a key was created");

            let replica = keys_under(&db.pool, "demo", composite(next_kek(), kek()));
            let (kid, _) = replica
                .active_signing_key(SigningAlgorithm::EdDsa)
                .await
                .expect("read")
                .expect("an active key");

            assert_eq!(kid, created);
        }

    }

    db_test! {
        /// The same row, on a replica holding only the new key: unreadable.
        /// This is the behaviour today, and the reason the ticket exists.
        async fn the_same_signing_key_does_not_open_without_the_previous_key(db) {
            seed_tenant(&db.pool, "demo").await;
            keys_under(&db.pool, "demo", kek())
                .rotate(SigningAlgorithm::EdDsa, operator(), epoch())
                .await
                .expect("rotate");

            let replica = keys_under(&db.pool, "demo", next_kek());
            let read = replica.active_signing_key(SigningAlgorithm::EdDsa).await;

            assert!(read.is_err(), "the new key alone opened the old row: {read:?}");
        }

    }

    db_test! {
        /// Once the re-wrap has moved a row, the previous key is not consulted
        /// for it. A retired key asked on every read is a key whose retirement
        /// has not happened.
        async fn a_re_wrapped_row_is_never_offered_to_the_previous_key(db) {
            seed_tenant(&db.pool, "demo").await;
            seed_salt(&db.pool, "demo").await;
            keys_under(&db.pool, "demo", kek())
                .rotate(SigningAlgorithm::EdDsa, operator(), epoch())
                .await
                .expect("rotate");
            pass(
                rewrap(&db.pool)
                    .rewrap_tenant(&TenantId::new("demo"), kek().as_ref(), next_kek().as_ref())
                    .await
                    .expect("re-wrap"),
            );
            let spy = Spy::over(kek());

            let replica = keys_under(
                &db.pool,
                "demo",
                composite(next_kek(), Arc::clone(&spy) as Arc<dyn Kek>),
            );
            replica
                .active_signing_key(SigningAlgorithm::EdDsa)
                .await
                .expect("read")
                .expect("an active key");

            assert_eq!(spy.unwraps(), 0, "the previous key was consulted");
        }

    }

    db_test! {
        /// Everything a replica writes during the rotation is written under the
        /// current key, so the re-wrap's second pass has less to do rather than
        /// more. `left_behind` counting zero is the assertion: it counts rows
        /// still on the old key after a pass.
        async fn a_key_staged_during_the_rotation_is_sealed_under_the_current_key(db) {
            seed_tenant(&db.pool, "demo").await;
            seed_salt(&db.pool, "demo").await;
            let replica = keys_under(&db.pool, "demo", composite(next_kek(), kek()));

            let staged = replica
                .rotate(SigningAlgorithm::EdDsa, operator(), epoch())
                .await
                .expect("rotate")
                .created
                .expect("a key was created");

            let sealed_under: String = sqlx::query_scalar(
                "select kek_id from signing_keys where tenant_id = $1 and kid = $2",
            )
            .bind("demo")
            .bind(staged.as_str())
            .fetch_one(&db.pool)
            .await
            .expect("read the row");
            assert_eq!(sealed_under, next_kek().id());
        }
    }
}

// ---------------------------------------------------------------------------
// Tenant settings
// ---------------------------------------------------------------------------

/// The `options` member of `tenants.settings`, over a real column.
///
/// What only a database can answer about this adapter is where the document
/// lands and what it displaces: the settings share one `jsonb` column with the
/// refresh policy `PgTenantRepository` writes, so "saved" has to mean "saved
/// beside", not "saved over". The rest of these assert the two halves of the
/// port agree about the member name — a reader and a writer that disagree
/// produce a tenant whose settings are written and never read, which from the
/// outside is indistinguishable from a cache that will not invalidate.
mod tenant_settings {
    use super::*;
    use asterius_domain::entities::tenant_settings::{
        MAX_ACCESS_TOKEN_LIFETIME, MAX_AUTHORIZATION_CODE_LIFETIME,
    };
    use asterius_domain::ports::TenantSettingsRepository as _;
    use asterius_domain::{DomainError, Feature, TenantSettings};
    use asterius_store_pg::PgTenantSettings;
    use std::collections::BTreeSet;
    use time::Duration;

    /// Settings a tenant could plausibly have chosen: not the defaults, so a
    /// read that quietly fell back to them fails the assertion.
    fn chosen() -> TenantSettings {
        let mut disabled = BTreeSet::new();
        disabled.insert(Feature::Mtls);
        disabled.insert(Feature::DeviceFlow);
        TenantSettings::validated(disabled, Duration::seconds(30), Duration::minutes(10))
            .expect("both lifetimes are under the profile's ceilings")
    }

    /// The raw `settings` document, as the column holds it.
    async fn document(pool: &PgPool, tenant: &str) -> serde_json::Value {
        sqlx::query_scalar("select settings from tenants where tenant_id = $1")
            .bind(tenant)
            .fetch_one(pool)
            .await
            .expect("read the settings column")
    }

    db_test! {
        /// What was saved is what comes back.
        async fn settings_survive_the_column(db) {
            seed_tenant(&db.pool, "demo").await;
            let repository = PgTenantSettings::new(db.pool.clone());

            repository
                .save(&TenantId::new("demo"), &chosen())
                .await
                .expect("save");

            let read = repository
                .settings(&TenantId::new("demo"))
                .await
                .expect("read back");
            assert_eq!(read, chosen());
        }
    }

    db_test! {
        /// A tenant that has never expressed an opinion reads the defaults.
        ///
        /// The absent member is the whole point: it is not the same as a
        /// stored document this build refuses, and a fresh tenant must not
        /// need a write before it can be read.
        async fn a_tenant_that_never_chose_reads_the_defaults(db) {
            seed_tenant(&db.pool, "demo").await;

            let read = PgTenantSettings::new(db.pool.clone())
                .settings(&TenantId::new("demo"))
                .await
                .expect("an unset tenant is readable");

            assert_eq!(read, TenantSettings::default());
        }
    }

    db_test! {
        /// A tenant that is not there is `NotFound`, not the defaults.
        ///
        /// Defaults for a row that does not exist would let a request for a
        /// deleted tenant answer as if it were live.
        async fn an_absent_tenant_is_not_found(db) {
            let outcome = PgTenantSettings::new(db.pool.clone())
                .settings(&TenantId::new("never-provisioned"))
                .await;

            assert!(matches!(outcome, Err(DomainError::NotFound)), "got {outcome:?}");
        }
    }

    db_test! {
        /// Saving for a tenant that is not there is `NotFound`, not a silent
        /// no-op: an update matching no row still "succeeds" in SQL, and an
        /// operator told "saved" about a tenant that does not exist would go
        /// looking for the setting anywhere but here.
        async fn saving_for_an_absent_tenant_is_not_found(db) {
            let outcome = PgTenantSettings::new(db.pool.clone())
                .save(&TenantId::new("never-provisioned"), &chosen())
                .await;

            assert!(matches!(outcome, Err(DomainError::NotFound)), "got {outcome:?}");
        }
    }

    db_test! {
        /// A save merges into the document rather than replacing it.
        ///
        /// `refresh` belongs to `PgTenantRepository`, and the two write the
        /// same column. A write of the whole document would revoke the tenant's
        /// refresh policy as a side effect of switching a feature off.
        async fn a_save_leaves_the_neighbouring_members_alone(db) {
            seed_tenant(&db.pool, "demo").await;
            sqlx::query(
                "update tenants
                    set settings = jsonb_build_object('refresh', $2::jsonb)
                  where tenant_id = $1",
            )
            .bind("demo")
            .bind(serde_json::json!({"rotation": "always"}))
            .execute(&db.pool)
            .await
            .expect("seed a refresh policy beside the options");

            PgTenantSettings::new(db.pool.clone())
                .save(&TenantId::new("demo"), &chosen())
                .await
                .expect("save");

            let document = document(&db.pool, "demo").await;
            assert_eq!(
                document.get("refresh"),
                Some(&serde_json::json!({"rotation": "always"})),
                "the refresh policy was displaced by an options write"
            );
            assert!(document.get("options").is_some(), "options were not written");
        }
    }

    db_test! {
        /// A second save replaces the `options` member whole.
        ///
        /// Merged members here would leave settings read half from one write
        /// and half from another — settings nobody chose. A feature switched
        /// back on has to actually come back on.
        async fn a_second_save_replaces_the_member_rather_than_merging_it(db) {
            seed_tenant(&db.pool, "demo").await;
            let repository = PgTenantSettings::new(db.pool.clone());
            repository
                .save(&TenantId::new("demo"), &chosen())
                .await
                .expect("first save");

            repository
                .save(&TenantId::new("demo"), &TenantSettings::default())
                .await
                .expect("second save");

            let read = repository
                .settings(&TenantId::new("demo"))
                .await
                .expect("read back");
            assert_eq!(read, TenantSettings::default());
            assert!(
                read.disabled_features().is_empty(),
                "a feature disabled by the first save survived the second"
            );
        }
    }

    db_test! {
        /// The adapter offers no route around the profile's ceilings.
        ///
        /// FAPI 2.0's ceilings are enforced by `TenantSettings::validated`, so
        /// the proof the store cannot bypass them is that there is nothing
        /// above the ceiling to hand it: `save` takes a `TenantSettings`, and
        /// the only way to build one refuses. This asserts the refusal so that
        /// a widened `save` signature — a `Value`, a lifetime pair — fails
        /// here rather than in production.
        async fn a_lifetime_past_the_fapi_ceiling_cannot_be_handed_to_the_store(db) {
            seed_tenant(&db.pool, "demo").await;

            let too_long = TenantSettings::validated(
                BTreeSet::new(),
                MAX_AUTHORIZATION_CODE_LIFETIME,
                MAX_ACCESS_TOKEN_LIFETIME + Duration::seconds(1),
            );

            assert!(too_long.is_err(), "the store would have been handed an over-long lifetime");
            let document = document(&db.pool, "demo").await;
            assert!(
                document.get("options").is_none(),
                "nothing should have reached the column"
            );
        }
    }

    db_test! {
        /// A hand-edited row above the ceiling fails the read.
        ///
        /// Rows get edited during incidents. A lifetime that quietly reverted
        /// to this build's default is a setting an operator believes is in
        /// force and is not, so the read refuses rather than falling back.
        async fn a_stored_lifetime_above_the_ceiling_is_refused_on_the_way_out(db) {
            seed_tenant(&db.pool, "demo").await;
            let mut smuggled = chosen().to_json();
            smuggled["access_token_lifetime_seconds"] =
                serde_json::json!(MAX_ACCESS_TOKEN_LIFETIME.whole_seconds() + 1);
            sqlx::query(
                "update tenants
                    set settings = coalesce(settings, '{}'::jsonb)
                                   || jsonb_build_object('options', $2::jsonb)
                  where tenant_id = $1",
            )
            .bind("demo")
            .bind(&smuggled)
            .execute(&db.pool)
            .await
            .expect("smuggle a row past the domain");

            let outcome = PgTenantSettings::new(db.pool.clone())
                .settings(&TenantId::new("demo"))
                .await;

            assert!(
                matches!(outcome, Err(DomainError::Invalid { field, .. }) if field == "settings.options"),
                "got {outcome:?}"
            );
        }
    }

    db_test! {
        /// The writer's member name is the one the reader looks under.
        ///
        /// `save` spells `'options'` inside a `query!` statement, which cannot
        /// take it from the module's constant; `settings` reads through that
        /// constant. This is what keeps the two from drifting apart.
        async fn the_written_member_is_the_one_read_back(db) {
            seed_tenant(&db.pool, "demo").await;
            PgTenantSettings::new(db.pool.clone())
                .save(&TenantId::new("demo"), &chosen())
                .await
                .expect("save");

            let document = document(&db.pool, "demo").await;
            let member = document
                .as_object()
                .expect("settings is an object")
                .keys()
                .find(|key| key.as_str() != "refresh")
                .expect("the save wrote a member")
                .clone();

            assert_eq!(member, "options");
            assert_eq!(
                TenantSettings::from_json(document.get(&member)).expect("parses"),
                chosen()
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Account recovery (ast-2vk.10)
// ---------------------------------------------------------------------------

/// The rules a clock decides, and the one an `update` decides.
///
/// These are here rather than in `asterius-server`'s `recovery.rs` because
/// both need `now` to be a parameter. Over HTTP it is not: the handler reads
/// the system clock, and a test that wanted an expired token would have to
/// either sleep for a quarter of an hour or reach past the adapter and rewrite
/// a row — which would be testing SQL written by the test rather than the SQL
/// that runs.
mod recovery {
    use super::*;
    use asterius_domain::ports::RecoveryTokenStore as _;
    use asterius_domain::{IssuedRecovery, RECOVERY_LIFETIME, RecoveryToken, UserId};
    use asterius_store_pg::PgRecoveryTokens;
    use time::Duration;

    async fn seed_account(pool: &PgPool, tenant: &str) -> UserId {
        seed_tenant(pool, tenant).await;
        let id = UserId::generate();
        sqlx::query(
            "insert into users (tenant_id, user_id, username, email, status)
             values ($1, $2, $3, $4, 'active')",
        )
        .bind(tenant)
        .bind(id.as_uuid())
        .bind(id.as_uuid().to_string())
        .bind(format!("{}@example.test", id.as_uuid()))
        .execute(pool)
        .await
        .expect("seed a user");
        id
    }

    fn tokens(pool: &PgPool, tenant: &str) -> PgRecoveryTokens {
        PgRecoveryTokens::new(pool.clone(), TenantId::new(tenant))
    }

    db_test! {
        /// The ordinary case: a token that was issued and has not expired is
        /// spent, and the account it names comes back.
        async fn a_live_token_is_spent_and_names_its_account(db) {
            // Arrange
            let user = seed_account(&db.pool, "rec-live").await;
            let store = tokens(&db.pool, "rec-live");
            let token = RecoveryToken::generate();
            let now = OffsetDateTime::now_utc();
            store
                .issue(&IssuedRecovery::new(user, &token, now))
                .await
                .expect("issue");

            // Act
            let spent = store.spend(&token.digest(), now).await.expect("spend");

            // Assert
            assert_eq!(spent, Some(user));
        }
    }

    db_test! {
        /// Single use. The second spend of one token finds nothing, and it is
        /// the `update`'s `consumed_at is null` predicate that decides — not a
        /// read the caller performed first.
        async fn a_token_is_spent_exactly_once(db) {
            // Arrange
            let user = seed_account(&db.pool, "rec-once").await;
            let store = tokens(&db.pool, "rec-once");
            let token = RecoveryToken::generate();
            let now = OffsetDateTime::now_utc();
            store
                .issue(&IssuedRecovery::new(user, &token, now))
                .await
                .expect("issue");
            store.spend(&token.digest(), now).await.expect("first spend");

            // Act
            let again = store.spend(&token.digest(), now).await.expect("second spend");

            // Assert
            assert_eq!(again, None);
        }
    }

    db_test! {
        /// **Fifteen minutes.** NIST SP 800-63B §6.1.2.3 asks for a short
        /// validity and OWASP's Forgot Password Cheat Sheet says the same; the
        /// number is `RECOVERY_LIFETIME`, and this is the only test that can
        /// state it against the predicate that actually runs.
        async fn a_token_past_its_lifetime_is_refused(db) {
            // Arrange
            let user = seed_account(&db.pool, "rec-expiry").await;
            let store = tokens(&db.pool, "rec-expiry");
            let token = RecoveryToken::generate();
            let issued_at = OffsetDateTime::now_utc();
            store
                .issue(&IssuedRecovery::new(user, &token, issued_at))
                .await
                .expect("issue");

            // Act
            let spent = store
                .spend(&token.digest(), issued_at + RECOVERY_LIFETIME + Duration::seconds(1))
                .await
                .expect("spend");

            // Assert
            assert_eq!(spent, None);
        }
    }

    db_test! {
        /// One second inside the window still works. Without this, the test
        /// above would pass against a token that never worked at all.
        async fn a_token_inside_its_lifetime_still_works(db) {
            // Arrange
            let user = seed_account(&db.pool, "rec-inside").await;
            let store = tokens(&db.pool, "rec-inside");
            let token = RecoveryToken::generate();
            let issued_at = OffsetDateTime::now_utc();
            store
                .issue(&IssuedRecovery::new(user, &token, issued_at))
                .await
                .expect("issue");

            // Act
            let spent = store
                .spend(&token.digest(), issued_at + RECOVERY_LIFETIME - Duration::seconds(1))
                .await
                .expect("spend");

            // Assert
            assert_eq!(spent, Some(user));
        }
    }

    db_test! {
        /// Issuing supersedes. Two live links in one mailbox is two account
        /// takeovers, and the one nobody used is the one nobody would notice
        /// being used.
        async fn issuing_a_token_kills_the_one_before_it(db) {
            // Arrange
            let user = seed_account(&db.pool, "rec-supersede").await;
            let store = tokens(&db.pool, "rec-supersede");
            let now = OffsetDateTime::now_utc();
            let first = RecoveryToken::generate();
            let second = RecoveryToken::generate();
            store.issue(&IssuedRecovery::new(user, &first, now)).await.expect("issue");
            store.issue(&IssuedRecovery::new(user, &second, now)).await.expect("issue");

            // Act
            let old = store.spend(&first.digest(), now).await.expect("spend");
            let new = store.spend(&second.digest(), now).await.expect("spend");

            // Assert
            assert_eq!(old, None);
            assert_eq!(new, Some(user));
        }
    }

    db_test! {
        /// **A credential change invalidates a token that was still valid.**
        /// A link quietly requested before the change must not survive it —
        /// otherwise changing a password after a compromise leaves the way
        /// back in that the attacker set up.
        async fn a_credential_change_invalidates_an_outstanding_token(db) {
            // Arrange
            let user = seed_account(&db.pool, "rec-change").await;
            let store = tokens(&db.pool, "rec-change");
            let now = OffsetDateTime::now_utc();
            let token = RecoveryToken::generate();
            store.issue(&IssuedRecovery::new(user, &token, now)).await.expect("issue");

            // Act
            let invalidated = store
                .invalidate_for_user(user, now)
                .await
                .expect("invalidate");
            let spent = store.spend(&token.digest(), now).await.expect("spend");

            // Assert
            assert_eq!(invalidated, 1);
            assert_eq!(spent, None);
        }
    }

    db_test! {
        /// The reason is recorded, so an operator can tell a completed reset
        /// from a link cancelled by a credential change — the distinction the
        /// handler deliberately refuses to show a browser.
        async fn an_invalidated_token_records_why(db) {
            // Arrange
            let user = seed_account(&db.pool, "rec-reason").await;
            let store = tokens(&db.pool, "rec-reason");
            let now = OffsetDateTime::now_utc();
            let token = RecoveryToken::generate();
            store.issue(&IssuedRecovery::new(user, &token, now)).await.expect("issue");
            store.invalidate_for_user(user, now).await.expect("invalidate");

            // Act
            let reason: Option<String> = sqlx::query_scalar(
                "select consumed_reason from recovery_tokens
                  where tenant_id = $1 and token_hash = $2",
            )
            .bind("rec-reason")
            .bind(token.digest())
            .fetch_one(&db.pool)
            .await
            .expect("read the row");

            // Assert
            assert_eq!(reason.as_deref(), Some("credential_change"));
        }
    }

    db_test! {
        /// **Hashed at rest.** No column anywhere holds the token, so a copy
        /// of this database is a pile of digests rather than a pile of live
        /// reset links (NIST SP 800-63B §5.1.1.2).
        async fn no_row_holds_the_token_itself(db) {
            // Arrange
            let user = seed_account(&db.pool, "rec-at-rest").await;
            let store = tokens(&db.pool, "rec-at-rest");
            let now = OffsetDateTime::now_utc();
            let token = RecoveryToken::generate();
            store.issue(&IssuedRecovery::new(user, &token, now)).await.expect("issue");

            // Act
            let row: String = sqlx::query_scalar(
                "select recovery_tokens::text from recovery_tokens where tenant_id = $1",
            )
            .bind("rec-at-rest")
            .fetch_one(&db.pool)
            .await
            .expect("read the row");

            // Assert
            assert!(!row.contains(token.expose()), "the row held the token: {row}");
            assert!(row.contains(&token.digest()));
        }
    }

    db_test! {
        /// A token nobody issued is refused rather than matched as a prefix.
        async fn a_token_nobody_issued_is_refused(db) {
            // Arrange
            seed_account(&db.pool, "rec-unknown").await;
            let store = tokens(&db.pool, "rec-unknown");

            // Act
            let spent = store
                .spend(&RecoveryToken::generate().digest(), OffsetDateTime::now_utc())
                .await
                .expect("spend");

            // Assert
            assert_eq!(spent, None);
        }
    }

    db_test! {
        /// A token belongs to the tenant that issued it. The predicate names
        /// `tenant_id`, so one tenant's link cannot reset another's account
        /// even if the digests somehow collided.
        async fn a_token_does_not_cross_tenants(db) {
            // Arrange
            let user = seed_account(&db.pool, "rec-mine").await;
            seed_account(&db.pool, "rec-theirs").await;
            let now = OffsetDateTime::now_utc();
            let token = RecoveryToken::generate();
            tokens(&db.pool, "rec-mine")
                .issue(&IssuedRecovery::new(user, &token, now))
                .await
                .expect("issue");

            // Act
            let elsewhere = tokens(&db.pool, "rec-theirs")
                .spend(&token.digest(), now)
                .await
                .expect("spend");

            // Assert
            assert_eq!(elsewhere, None);
        }
    }

    db_test! {
        /// `peek` reads without spending, so rendering the page a link leads
        /// to does not consume the link.
        async fn peeking_does_not_spend(db) {
            // Arrange
            let user = seed_account(&db.pool, "rec-peek").await;
            let store = tokens(&db.pool, "rec-peek");
            let now = OffsetDateTime::now_utc();
            let token = RecoveryToken::generate();
            store.issue(&IssuedRecovery::new(user, &token, now)).await.expect("issue");

            // Act
            let peeked = store.peek(&token.digest(), now).await.expect("peek");
            let spent = store.spend(&token.digest(), now).await.expect("spend");

            // Assert
            assert_eq!(peeked, Some(user));
            assert_eq!(spent, Some(user));
        }
    }

    db_test! {
        /// `peek` applies the same expiry predicate as `spend`, so a dead link
        /// produces an error page rather than a form that will fail after
        /// somebody has typed a password twice.
        async fn peeking_an_expired_token_finds_nothing(db) {
            // Arrange
            let user = seed_account(&db.pool, "rec-peek-dead").await;
            let store = tokens(&db.pool, "rec-peek-dead");
            let issued_at = OffsetDateTime::now_utc();
            let token = RecoveryToken::generate();
            store
                .issue(&IssuedRecovery::new(user, &token, issued_at))
                .await
                .expect("issue");

            // Act
            let peeked = store
                .peek(&token.digest(), issued_at + RECOVERY_LIFETIME + Duration::seconds(1))
                .await
                .expect("peek");

            // Assert
            assert_eq!(peeked, None);
        }
    }

    db_test! {
        /// The sweep drops what has expired. An expired row protects nothing —
        /// `spend` refuses it regardless — and only costs space.
        async fn expired_tokens_are_purged(db) {
            // Arrange
            let user = seed_account(&db.pool, "rec-purge").await;
            let store = tokens(&db.pool, "rec-purge");
            let issued_at = OffsetDateTime::now_utc();
            let token = RecoveryToken::generate();
            store
                .issue(&IssuedRecovery::new(user, &token, issued_at))
                .await
                .expect("issue");

            // Act
            let purged = store
                .purge_expired(issued_at + RECOVERY_LIFETIME + Duration::seconds(1))
                .await
                .expect("purge");

            // Assert
            assert_eq!(purged, 1);
        }
    }
}

/// A tenant's design tokens and the images they name (`ast-ndk.1`).
mod themes {
    use super::*;
    use asterius_domain::entities::theme::ImageFormat;
    use asterius_domain::ports::{StoredAsset, ThemeRepository as _};
    use asterius_domain::{DomainError, Theme};
    use asterius_store_pg::PgThemes;

    /// A theme a tenant could plausibly have chosen: not the defaults, so a
    /// read that quietly fell back to them fails the assertion.
    fn chosen() -> Theme {
        Theme::from_json(&serde_json::json!({
            "palette": {
                "background": "#fffdf7",
                "text": "#1a1a1a",
                "muted_text": "#4a4a4a",
                "accent": "#7b2d8e",
                "accent_text": "#ffffff",
                "danger": "#8b1a1a"
            },
            "font": "system-serif",
            "radius_px": 12,
            "spacing_px": 10,
            "product_name": "Acme Identity",
            "support": {"help_url": "https://help.example.com/"}
        }))
        .expect("the fixture clears WCAG AA on every pair")
    }

    /// Bytes standing in for a re-encoded logo. Their digest is computed the
    /// way the upload adapter computes it, over what is stored.
    fn asset(bytes: &[u8]) -> StoredAsset {
        use sha2::{Digest, Sha256};
        StoredAsset {
            digest: hex::encode(Sha256::digest(bytes)),
            format: ImageFormat::Png,
            bytes: bytes.to_vec(),
        }
    }

    db_test! {
        /// What was saved is what comes back, tokens and all.
        async fn a_theme_survives_the_round_trip(db) {
            seed_tenant(&db.pool, "demo").await;
            let repository = PgThemes::new(db.pool.clone());

            repository
                .save_theme(&TenantId::new("demo"), &chosen())
                .await
                .expect("save");

            let read = repository
                .theme(&TenantId::new("demo"))
                .await
                .expect("read back");
            assert_eq!(read, chosen());
        }
    }

    db_test! {
        /// A second save replaces the theme rather than adding a row: a tenant
        /// has one look, and two rows would make which one renders a matter of
        /// ordering.
        async fn saving_twice_replaces_the_theme(db) {
            seed_tenant(&db.pool, "demo").await;
            let repository = PgThemes::new(db.pool.clone());

            repository.save_theme(&TenantId::new("demo"), &Theme::default()).await.expect("first");
            repository.save_theme(&TenantId::new("demo"), &chosen()).await.expect("second");

            let rows: i64 = sqlx::query_scalar("select count(*) from tenant_themes where tenant_id = $1")
                .bind("demo")
                .fetch_one(&db.pool)
                .await
                .expect("count");
            assert_eq!(rows, 1);
            assert_eq!(
                repository.theme(&TenantId::new("demo")).await.expect("read"),
                chosen()
            );
        }
    }

    db_test! {
        /// A tenant that has never set a theme reads the shipped one, without
        /// needing a write first.
        async fn a_tenant_that_never_chose_reads_the_default_theme(db) {
            seed_tenant(&db.pool, "demo").await;

            let read = PgThemes::new(db.pool.clone())
                .theme(&TenantId::new("demo"))
                .await
                .expect("an unset tenant is readable");

            assert_eq!(read, Theme::default());
        }
    }

    db_test! {
        /// A theme saved for a tenant that does not exist is `NotFound`, not a
        /// storage error and not a silent success.
        async fn an_unknown_tenant_cannot_be_themed(db) {
            let error = PgThemes::new(db.pool.clone())
                .save_theme(&TenantId::new("ghost"), &chosen())
                .await
                .expect_err("no such tenant");

            assert!(matches!(error, DomainError::NotFound), "{error:?}");
        }
    }

    db_test! {
        /// A stored document this build refuses fails the read rather than
        /// falling back to the defaults: a palette that reverted on its own is
        /// a brand an administrator believes is in force and is not — and it
        /// is the one way an unvalidated palette could reach a page.
        async fn a_stored_document_that_fails_validation_fails_the_read(db) {
            seed_tenant(&db.pool, "demo").await;
            // Written past the repository, as a migration or a psql session
            // would: #999999 on white is 2.85:1, below WCAG AA.
            let mut document = chosen().to_json();
            document["palette"]["text"] = serde_json::json!("#999999");
            sqlx::query("insert into tenant_themes (tenant_id, document) values ($1, $2)")
                .bind("demo")
                .bind(&document)
                .execute(&db.pool)
                .await
                .expect("write behind the repository's back");

            let error = PgThemes::new(db.pool.clone())
                .theme(&TenantId::new("demo"))
                .await
                .expect_err("an unreadable palette is not served");

            assert!(matches!(error, DomainError::Invalid { .. }), "{error:?}");
        }
    }

    db_test! {
        /// An asset is stored under the digest of its bytes and read back
        /// whole.
        async fn an_asset_round_trips_under_its_digest(db) {
            seed_tenant(&db.pool, "demo").await;
            let repository = PgThemes::new(db.pool.clone());
            let logo = asset(b"not really a png, but it is what was stored");

            repository.store_asset(&TenantId::new("demo"), &logo).await.expect("store");

            let read = repository
                .asset(&TenantId::new("demo"), &logo.digest)
                .await
                .expect("read")
                .expect("the asset is there");
            assert_eq!(read, logo);
        }
    }

    db_test! {
        /// Storing the same bytes twice is one row and not an error: the
        /// digest is over the bytes, so the second write has nothing to change
        /// and a retried upload must not fail.
        async fn storing_the_same_asset_twice_is_idempotent(db) {
            seed_tenant(&db.pool, "demo").await;
            let repository = PgThemes::new(db.pool.clone());
            let logo = asset(b"the same logo, uploaded twice");

            repository.store_asset(&TenantId::new("demo"), &logo).await.expect("first");
            repository.store_asset(&TenantId::new("demo"), &logo).await.expect("second");

            let rows: i64 = sqlx::query_scalar(
                "select count(*) from tenant_theme_assets where tenant_id = $1",
            )
            .bind("demo")
            .fetch_one(&db.pool)
            .await
            .expect("count");
            assert_eq!(rows, 1);
        }
    }

    db_test! {
        /// One tenant cannot read another's asset by naming its digest.
        ///
        /// A digest is not a secret — anybody who has seen a logo can compute
        /// it — so the isolation has to come from the query, not from the
        /// difficulty of guessing.
        async fn an_asset_is_not_readable_across_tenants(db) {
            seed_tenant(&db.pool, "one").await;
            seed_tenant(&db.pool, "two").await;
            let repository = PgThemes::new(db.pool.clone());
            let logo = asset(b"tenant one's logo");
            repository.store_asset(&TenantId::new("one"), &logo).await.expect("store");

            let read = repository
                .asset(&TenantId::new("two"), &logo.digest)
                .await
                .expect("the read succeeds");

            assert!(read.is_none(), "tenant two read tenant one's asset");
        }
    }

    db_test! {
        /// A digest nothing stored is `None`, not an error: a theme naming an
        /// asset that is gone renders a page without a logo.
        async fn an_unknown_digest_is_not_an_error(db) {
            seed_tenant(&db.pool, "demo").await;

            let read = PgThemes::new(db.pool.clone())
                .asset(&TenantId::new("demo"), &"a".repeat(64))
                .await
                .expect("the read succeeds");

            assert!(read.is_none());
        }
    }

    db_test! {
        /// Deleting a tenant takes its theme and its assets with it. A blob
        /// that outlived the tenant it belonged to would be a logo nobody can
        /// reach and nobody can delete.
        async fn deleting_a_tenant_takes_its_theme_and_assets(db) {
            seed_tenant(&db.pool, "demo").await;
            let repository = PgThemes::new(db.pool.clone());
            repository.save_theme(&TenantId::new("demo"), &chosen()).await.expect("save");
            repository
                .store_asset(&TenantId::new("demo"), &asset(b"a logo"))
                .await
                .expect("store");

            sqlx::query("delete from tenants where tenant_id = $1")
                .bind("demo")
                .execute(&db.pool)
                .await
                .expect("delete the tenant");

            for table in ["tenant_themes", "tenant_theme_assets"] {
                let rows: i64 = sqlx::query_scalar(&format!("select count(*) from {table}"))
                    .fetch_one(&db.pool)
                    .await
                    .expect("count");
                assert_eq!(rows, 0, "{table} kept a row past its tenant");
            }
        }
    }

    db_test! {
        /// The check constraints are the last line: a row written past the
        /// repository still cannot name a media type this server will not
        /// serve, and cannot carry a digest that is not a safe path segment.
        async fn the_column_constraints_refuse_svg_and_a_traversable_digest(db) {
            seed_tenant(&db.pool, "demo").await;

            let svg = sqlx::query(
                "insert into tenant_theme_assets (tenant_id, digest, content_type, bytes)
                 values ($1, $2, 'image/svg+xml', $3)",
            )
            .bind("demo")
            .bind("a".repeat(64))
            .bind(b"<svg onload=alert(1)></svg>".to_vec())
            .execute(&db.pool)
            .await;
            assert!(svg.is_err(), "an SVG row was accepted");

            let traversal = sqlx::query(
                "insert into tenant_theme_assets (tenant_id, digest, content_type, bytes)
                 values ($1, $2, 'image/png', $3)",
            )
            .bind("demo")
            .bind("../../etc/passwd")
            .bind(b"bytes".to_vec())
            .execute(&db.pool)
            .await;
            assert!(traversal.is_err(), "a digest that is not hex was accepted");
        }
    }
}

// ---------------------------------------------------------------------------
// The transactional outbox and its worker (`ast-0ju.9`)
// ---------------------------------------------------------------------------

/// What the outbox promises, asserted against a real PostgreSQL.
///
/// Every one of these is a property that cannot be tested without the database:
/// `for update skip locked`, a claim that survives the process that took it,
/// and an ordering guarantee that is enforced by a `not exists` in the claim
/// statement rather than by anything in Rust.
mod outbox {
    use super::*;
    use asterius_domain::outbox::DeadLetterQuery as _;
    use asterius_store_pg::{Backoff, NewOutboxEntry, Outcome, PgOutbox, Verdict};
    use time::Duration;

    /// A schedule with a short lease and a short backoff, so that a test can
    /// step past both without sleeping.
    fn outbox(pool: &PgPool) -> PgOutbox {
        PgOutbox::with_schedule(
            pool.clone(),
            Backoff {
                base: Duration::seconds(10),
                cap: Duration::minutes(5),
            },
            Duration::seconds(30),
        )
    }

    /// Writes one row in its own transaction and commits, the way a caller
    /// that has nothing else to do in the transaction would.
    async fn queue(
        pool: &PgPool,
        tenant: &str,
        kind: &str,
        key: Option<&str>,
        now: OffsetDateTime,
    ) -> i64 {
        let mut transaction = pool.begin().await.expect("begin");
        let mut entry =
            NewOutboxEntry::new(kind, "https://rp.example/hook", serde_json::json!({"n": 1}));
        entry.ordering_key = key;
        let id = asterius_store_pg::enqueue(&mut transaction, &TenantId::new(tenant), &entry, now)
            .await
            .expect("enqueue");
        transaction.commit().await.expect("commit");
        id
    }

    async fn row_status(pool: &PgPool, id: i64) -> String {
        sqlx::query_scalar("select status from outbox where outbox_id = $1")
            .bind(id)
            .fetch_one(pool)
            .await
            .expect("read the row's status")
    }

    db_test! {
        /// The property the table exists for: the row and the change it
        /// describes commit together or not at all. A caller that rolls back
        /// must not leave a notification announcing something that never
        /// happened.
        async fn a_rolled_back_change_takes_its_outbox_row_with_it(db) {
            // Arrange
            seed_tenant(&db.pool, "ob-rollback").await;
            let now = OffsetDateTime::now_utc();
            let mut transaction = db.pool.begin().await.expect("begin");

            // Act
            let entry = NewOutboxEntry::new(
                "logout.backchannel",
                "https://rp.example/x",
                serde_json::json!({}),
            );
            asterius_store_pg::enqueue(
                &mut transaction,
                &TenantId::new("ob-rollback"),
                &entry,
                now,
            )
            .await
            .expect("enqueue");
            transaction.rollback().await.expect("rollback");

            // Assert
            let queued: i64 = sqlx::query_scalar("select count(*) from outbox where tenant_id = $1")
                .bind("ob-rollback")
                .fetch_one(&db.pool)
                .await
                .expect("count");
            assert_eq!(queued, 0, "a rolled-back transaction left an outbox row behind");
        }
    }

    db_test! {
        /// The other half of the same property: a committed change leaves its
        /// row claimable. Without this the test above would pass on an
        /// `enqueue` that wrote nothing at all.
        async fn a_committed_change_leaves_a_claimable_row(db) {
            // Arrange
            seed_tenant(&db.pool, "ob-commit").await;
            let now = OffsetDateTime::now_utc();
            let id = queue(&db.pool, "ob-commit", "logout.backchannel", None, now).await;

            // Act
            let claimed = outbox(&db.pool).claim("worker-a", 10, now).await.expect("claim");

            // Assert
            assert_eq!(claimed.iter().map(|event| event.id).collect::<Vec<_>>(), vec![id]);
            assert_eq!(claimed[0].attempt, 1);
        }
    }

    db_test! {
        /// A worker that dies after claiming and before acking must not lose
        /// the event. The lease lapses, the next worker takes the row again,
        /// and it comes back under the *same* id — which is what lets a
        /// receiver deduplicate an at-least-once delivery.
        async fn a_worker_that_dies_mid_delivery_loses_nothing(db) {
            // Arrange
            seed_tenant(&db.pool, "ob-crash").await;
            let now = OffsetDateTime::now_utc();
            let id = queue(&db.pool, "ob-crash", "logout.backchannel", None, now).await;
            let outbox = outbox(&db.pool);
            let taken = outbox.claim("worker-that-dies", 10, now).await.expect("claim");
            assert_eq!(taken.len(), 1, "the first claim should have taken the row");
            // No ack: this is the process being killed between the claim and
            // the delivery, which is the window the whole design is about.

            // Act
            let within_lease = outbox
                .claim("worker-b", 10, now + Duration::seconds(29))
                .await
                .expect("claim inside the lease");
            let after_lease = outbox
                .claim("worker-b", 10, now + Duration::seconds(31))
                .await
                .expect("claim after the lease");

            // Assert
            assert!(
                within_lease.is_empty(),
                "a live worker's claim was handed to a second worker"
            );
            assert_eq!(after_lease.iter().map(|event| event.id).collect::<Vec<_>>(), vec![id]);
            assert_eq!(after_lease[0].attempt, 2, "the reclaim must count as an attempt");
        }
    }

    db_test! {
        /// `for update skip locked` plus the claimed state: two workers polling
        /// the same backlog take disjoint sets and neither waits for the other.
        async fn two_workers_take_disjoint_sets(db) {
            // Arrange
            seed_tenant(&db.pool, "ob-disjoint").await;
            let now = OffsetDateTime::now_utc();
            let mut queued = Vec::new();
            for _ in 0..6 {
                queued.push(queue(&db.pool, "ob-disjoint", "logout.backchannel", None, now).await);
            }
            let outbox = outbox(&db.pool);

            // Act
            let first = outbox.claim("worker-a", 3, now).await.expect("claim a");
            let second = outbox.claim("worker-b", 10, now).await.expect("claim b");

            // Assert
            let a: Vec<_> = first.iter().map(|event| event.id).collect();
            let b: Vec<_> = second.iter().map(|event| event.id).collect();
            assert_eq!(a.len(), 3);
            assert_eq!(b.len(), 3);
            assert!(a.iter().all(|id| !b.contains(id)), "{a:?} and {b:?} overlap");
            let mut all: Vec<_> = a.into_iter().chain(b).collect();
            all.sort_unstable();
            assert_eq!(all, queued);
        }
    }

    db_test! {
        /// Per-key ordering. Two events about one `(client, session)` must
        /// reach the receiver oldest-first, so the second is not claimable
        /// while the first is still owed — whatever state "still owed" is in.
        async fn an_earlier_row_with_the_same_key_blocks_a_later_one(db) {
            // Arrange
            seed_tenant(&db.pool, "ob-order").await;
            let now = OffsetDateTime::now_utc();
            let first = queue(&db.pool, "ob-order", "logout.backchannel", Some("c1|s1"), now).await;
            let second = queue(&db.pool, "ob-order", "logout.backchannel", Some("c1|s1"), now).await;
            let outbox = outbox(&db.pool);

            // Act
            let head = outbox.claim("worker-a", 10, now).await.expect("claim the head");
            let blocked = outbox.claim("worker-b", 10, now).await.expect("claim behind it");

            // Assert
            assert_eq!(head.iter().map(|event| event.id).collect::<Vec<_>>(), vec![first]);
            assert!(
                blocked.is_empty(),
                "row {second} was claimed while {first} was still in flight"
            );
        }
    }

    db_test! {
        /// The tail becomes claimable once the head is done, and not before.
        /// A key that stayed blocked after its head was delivered would be a
        /// queue that stops forever on its first success.
        async fn the_next_row_in_a_key_follows_its_predecessor(db) {
            // Arrange
            seed_tenant(&db.pool, "ob-order-next").await;
            let now = OffsetDateTime::now_utc();
            let first = queue(&db.pool, "ob-order-next", "logout.backchannel", Some("k"), now).await;
            let second = queue(&db.pool, "ob-order-next", "logout.backchannel", Some("k"), now).await;
            let outbox = outbox(&db.pool);
            let head = outbox.claim("worker-a", 10, now).await.expect("claim");

            // Act
            outbox
                .ack(&head[0], &Outcome::delivered(now))
                .await
                .expect("ack the head");
            let tail = outbox.claim("worker-a", 10, now).await.expect("claim the tail");

            // Assert
            assert_eq!(head[0].id, first);
            assert_eq!(tail.iter().map(|event| event.id).collect::<Vec<_>>(), vec![second]);
        }
    }

    db_test! {
        /// A row with no ordering key is unordered by construction: two of them
        /// go out at once. Making every row ordered would serialise the whole
        /// outbox behind one slow receiver.
        async fn rows_without_a_key_are_not_serialised(db) {
            // Arrange
            seed_tenant(&db.pool, "ob-unordered").await;
            let now = OffsetDateTime::now_utc();
            queue(&db.pool, "ob-unordered", "notification.credential_changed", None, now).await;
            queue(&db.pool, "ob-unordered", "notification.credential_changed", None, now).await;

            // Act
            let claimed = outbox(&db.pool).claim("worker-a", 10, now).await.expect("claim");

            // Assert
            assert_eq!(claimed.len(), 2);
        }
    }

    db_test! {
        /// Order under real concurrency, which is the only way this can be
        /// asserted: eight workers polling one backlog of four keys, and every
        /// key's rows must be *delivered* in the order they were queued.
        ///
        /// Randomised over the interleaving rather than over an input — what
        /// varies here is which worker wins each race, and PostgreSQL and the
        /// runtime choose that, not the test.
        async fn concurrent_workers_keep_each_key_in_order(db) {
            // Arrange
            seed_tenant(&db.pool, "ob-concurrent").await;
            let now = OffsetDateTime::now_utc();
            let keys = ["a", "b", "c", "d"];
            let mut expected: std::collections::BTreeMap<&str, Vec<i64>> =
                std::collections::BTreeMap::new();
            for round in 0..12 {
                for key in keys {
                    let id = queue(
                        &db.pool,
                        "ob-concurrent",
                        "logout.backchannel",
                        Some(key),
                        now + Duration::milliseconds(round),
                    )
                    .await;
                    expected.entry(key).or_default().push(id);
                }
            }

            // Act
            let delivered = std::sync::Arc::new(tokio::sync::Mutex::new(Vec::<i64>::new()));
            let mut workers = Vec::new();
            for index in 0..8 {
                let outbox = outbox(&db.pool);
                let delivered = std::sync::Arc::clone(&delivered);
                workers.push(tokio::spawn(async move {
                    let name = format!("worker-{index}");
                    for _ in 0..200 {
                        let batch = outbox
                            .claim(&name, 2, OffsetDateTime::now_utc())
                            .await
                            .expect("claim");
                        if batch.is_empty() {
                            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
                            continue;
                        }
                        for event in batch {
                            delivered.lock().await.push(event.id);
                            outbox
                                .ack(&event, &Outcome::delivered(OffsetDateTime::now_utc()))
                                .await
                                .expect("ack");
                        }
                    }
                }));
            }
            for worker in workers {
                worker.await.expect("a worker panicked");
            }

            // Assert
            let order = delivered.lock().await.clone();
            assert_eq!(order.len(), 48, "not everything was delivered exactly once");
            for (key, ids) in expected {
                let seen: Vec<_> = order.iter().copied().filter(|id| ids.contains(id)).collect();
                assert_eq!(seen, ids, "key {key} was delivered out of order");
            }
        }
    }

    db_test! {
        /// A failure records what happened and pushes the row into the future
        /// by the configured backoff. A retry that came back immediately would
        /// turn one unreachable receiver into a hot loop.
        async fn a_failure_is_recorded_and_backed_off(db) {
            // Arrange
            seed_tenant(&db.pool, "ob-backoff").await;
            let now = OffsetDateTime::now_utc();
            queue(&db.pool, "ob-backoff", "logout.backchannel", None, now).await;
            let outbox = outbox(&db.pool);
            let claimed = outbox.claim("worker-a", 10, now).await.expect("claim");

            // Act
            outbox
                .ack(
                    &claimed[0],
                    &Outcome::failed(&claimed[0], now, "rp.example answered 503".to_owned()),
                )
                .await
                .expect("ack");
            let immediately = outbox.claim("worker-a", 10, now).await.expect("claim now");
            let later = outbox
                .claim("worker-a", 10, now + Duration::seconds(60))
                .await
                .expect("claim later");

            // Assert
            assert!(immediately.is_empty(), "a failed row was retried with no backoff");
            assert_eq!(later.len(), 1);
            assert_eq!(later[0].attempt, 2);
            let (outcome, detail): (String, Option<String>) = sqlx::query_as(
                "select outcome, detail from outbox_attempts where outbox_id = $1 and attempt = 1",
            )
            .bind(claimed[0].id)
            .fetch_one(&db.pool)
            .await
            .expect("read the attempt");
            assert_eq!(outcome, Verdict::Retry.as_str());
            assert_eq!(detail.as_deref(), Some("rp.example answered 503"));
        }
    }

    db_test! {
        /// A row that has spent its budget stops being retried and becomes
        /// visible to an operator instead — and what it shows carries no
        /// payload, no destination and no ordering key, because an abandoned
        /// recovery message's payload is a live reset link.
        async fn an_exhausted_row_is_dead_lettered_and_visible(db) {
            // Arrange
            seed_tenant(&db.pool, "ob-dead").await;
            let now = OffsetDateTime::now_utc();
            let mut transaction = db.pool.begin().await.expect("begin");
            let mut entry = NewOutboxEntry::new(
                "notification.account_recovery",
                "someone@example.test",
                serde_json::json!({"link": "https://as.example/recovery?token=secret"}),
            );
            entry.max_attempts = Some(2);
            let id = asterius_store_pg::enqueue(
                &mut transaction,
                &TenantId::new("ob-dead"),
                &entry,
                now,
            )
            .await
            .expect("enqueue");
            transaction.commit().await.expect("commit");
            let outbox = outbox(&db.pool);

            // Act
            let mut at = now;
            for _ in 0..2 {
                let claimed = outbox.claim("worker-a", 10, at).await.expect("claim");
                assert_eq!(claimed.len(), 1, "the row stopped being claimable too early");
                outbox
                    .ack(
                        &claimed[0],
                        &Outcome::failed(&claimed[0], at, "no mail sender is wired".to_owned()),
                    )
                    .await
                    .expect("ack");
                at += Duration::hours(1);
            }
            let after = outbox.claim("worker-a", 10, at).await.expect("claim again");
            let letters = outbox
                .dead_letters(&TenantId::new("ob-dead"), 10)
                .await
                .expect("dead letters");

            // Assert
            assert!(after.is_empty(), "an abandoned row was claimed again");
            assert_eq!(row_status(&db.pool, id).await, "abandoned");
            assert_eq!(letters.len(), 1);
            assert_eq!(letters[0].id, id);
            assert_eq!(letters[0].kind, "notification.account_recovery");
            assert_eq!(letters[0].attempts, 2);
            assert_eq!(letters[0].last_error.as_deref(), Some("no mail sender is wired"));
            let rendered = format!("{:?}", letters[0]);
            assert!(!rendered.contains("secret"), "a dead letter carried its payload");
            assert!(
                !rendered.contains("someone@example.test"),
                "a dead letter carried its destination"
            );
        }
    }

    db_test! {
        /// A journalled delivery is terminal but leaves `delivered_at` null,
        /// because nothing left the process. That is what keeps
        /// `PgOutboxMailSender::queued` — the operator's view of what *would*
        /// have been sent while no mail sender is wired — honest.
        async fn a_journalled_delivery_never_claims_to_have_been_sent(db) {
            // Arrange
            seed_tenant(&db.pool, "ob-journal").await;
            let now = OffsetDateTime::now_utc();
            let id = queue(
                &db.pool,
                "ob-journal",
                "notification.credential_changed",
                None,
                now,
            )
            .await;
            let outbox = outbox(&db.pool);
            let claimed = outbox.claim("worker-a", 10, now).await.expect("claim");

            // Act
            outbox
                .ack(&claimed[0], &Outcome::journalled(now))
                .await
                .expect("ack");

            // Assert
            assert_eq!(row_status(&db.pool, id).await, "delivered");
            let sent: Option<OffsetDateTime> =
                sqlx::query_scalar("select delivered_at from outbox where outbox_id = $1")
                    .bind(id)
                    .fetch_one(&db.pool)
                    .await
                    .expect("read delivered_at");
            assert_eq!(sent, None, "a journalled row claimed it had been sent");
        }
    }

    db_test! {
        /// Delivery throughput against a deliverer that does nothing, so what
        /// is measured is the claim, the ack and the round trips they cost —
        /// the part this ticket owns. Ignored by default: it is a measurement
        /// rather than an assertion, and it takes seconds.
        ///
        /// Run it with:
        /// `cargo nextest run -p asterius-store-pg outbox::throughput --run-ignored all --no-capture`
        #[ignore = "a measurement, not an assertion; needs a database and takes seconds"]
        async fn throughput_of_a_do_nothing_deliverer(db) {
            // Arrange
            seed_tenant(&db.pool, "ob-throughput").await;
            let now = OffsetDateTime::now_utc();
            let total = 2_000_u32;
            let mut transaction = db.pool.begin().await.expect("begin");
            for _ in 0..total {
                let entry = NewOutboxEntry::new(
                    "logout.backchannel",
                    "https://rp.example/x",
                    serde_json::json!({}),
                );
                asterius_store_pg::enqueue(
                    &mut transaction,
                    &TenantId::new("ob-throughput"),
                    &entry,
                    now,
                )
                .await
                .expect("enqueue");
            }
            transaction.commit().await.expect("commit");

            // Act
            let started = std::time::Instant::now();
            let mut workers = Vec::new();
            for index in 0..4 {
                let outbox = outbox(&db.pool);
                workers.push(tokio::spawn(async move {
                    let name = format!("worker-{index}");
                    let mut delivered = 0_u32;
                    loop {
                        let batch = outbox
                            .claim(&name, 64, OffsetDateTime::now_utc())
                            .await
                            .expect("claim");
                        if batch.is_empty() {
                            break;
                        }
                        for event in batch {
                            outbox
                                .ack(&event, &Outcome::delivered(OffsetDateTime::now_utc()))
                                .await
                                .expect("ack");
                            delivered += 1;
                        }
                    }
                    delivered
                }));
            }
            let mut delivered = 0_u32;
            for worker in workers {
                delivered += worker.await.expect("a worker panicked");
            }
            let elapsed = started.elapsed();

            // Assert
            assert_eq!(delivered, total);
            let rate = f64::from(delivered) / elapsed.as_secs_f64();
            println!("outbox throughput: {rate:.0} deliveries/s over {elapsed:?}");
        }
    }
}
