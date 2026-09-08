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

// ---------------------------------------------------------------------------
// Audit trail
// ---------------------------------------------------------------------------

use asterius_domain::audit::chain::EventHash;
use asterius_domain::audit::{Actor, AuditEvent, AuditSink, Detail, EventType, Outcome};
use asterius_store_pg::PgAuditSink;

/// The credential shapes an audit write is most likely to be handed by mistake.
const A_CODE: &str = "Zx9Kq2mNpR7vT4wY1bC8dF3gH6jL0aS5uV-eW_iO2nQ";
const A_JWT: &str = "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCJ9.eyJzdWIiOiJhbGljZSJ9.c2ln";

async fn seed_tenant(pool: &PgPool, id: &str) {
    sqlx::query(
        "insert into tenants (tenant_id, issuer, display_name)
         values ($1, $2, $1) on conflict do nothing",
    )
    .bind(id)
    .bind(format!("https://as.example/t/{id}"))
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
