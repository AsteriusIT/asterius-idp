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
    /// FAPI 2.0 SP §5.3.2.1 item 11 caps authorization codes at 60 seconds. Code
    /// enforces
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
        repo.delete(&ClientId::new("billing")).await.expect("delete");
        assert!(repo.find(&ClientId::new("billing")).await.expect("find").is_none());
        assert!(
            matches!(
                repo.delete(&ClientId::new("billing")).await,
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
        document
            .as_object_mut()
            .expect("object")
            .insert("token_endpoint_auth_method".to_owned(), json!("tls_client_auth"));

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

use asterius_domain::keys::{KeyPurpose, KeyState, KeyStore, Kid, SigningAlgorithm};
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
        let schedule = repo.schedule().await.expect("default schedule");

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

        let default = repo.schedule().await.expect("schedule");
        assert_eq!(default.rotation_period, Duration::days(90));
        assert_eq!(default.propagation_period, Duration::minutes(15));
        assert_eq!(default.grace_period, Duration::days(7));
        assert_eq!(default.last_rotated_at, None);
        assert!(default.is_due(epoch()), "a tenant with no key must always be due");

        repo.set_schedule(RotationSchedule {
            rotation_period: Duration::days(1),
            propagation_period: Duration::minutes(5),
            grace_period: Duration::hours(6),
            last_rotated_at: None,
        })
        .await
        .expect("replace the schedule");

        let updated = repo.schedule().await.expect("schedule");
        assert_eq!(updated.rotation_period, Duration::days(1));
        assert_eq!(updated.propagation_period, Duration::minutes(5));
        assert_eq!(updated.grace_period, Duration::hours(6));

        // A rotation records when it happened, and the sweep stages a new key
        // only once the period has passed.
        let t0 = epoch();
        repo.rotate(SigningAlgorithm::EdDsa, operator(), t0).await.expect("rotate");
        assert_eq!(repo.schedule().await.expect("schedule").last_rotated_at, Some(t0));

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
                repo.set_schedule(schedule).await.is_err(),
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
            dpop_jkt: None,
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
            assert_eq!(found.client.as_str(), "billing");
            assert_eq!(found.parameters, pushed.parameters);

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
}

mod grants {
    use super::*;
    use asterius_domain::{
        DomainError, Grant, GrantId, GrantStatus, LiveAccessToken, RevocationReason, SessionId,
        SubjectId,
    };
    use asterius_store_pg::PgGrantRepository;

    fn repo(pool: &PgPool, tenant: &str) -> PgGrantRepository {
        PgGrantRepository::new(pool.clone(), TenantId::new(tenant))
    }

    /// A tenant and one client for its grants to hang off. `grants` has a
    /// foreign key to `clients`, which is the schema saying that a grant with
    /// no client is not a thing.
    async fn seed_client(pool: &PgPool, tenant: &str, client_id: &str) {
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
        grant.authorization_details = vec![json!({"type": "payment_initiation"})];
        grant.session = Some(SessionId::new("sess-1"));
        grant
    }

    /// A refresh token pointing at a grant. Written by hand because the token
    /// story (`ast-a05.5`) owns the repository that will write it; what these
    /// tests need is the row a revocation has to reach.
    async fn insert_refresh_token(pool: &PgPool, tenant: &str, grant: &GrantId, label: &str) {
        sqlx::query(
            "insert into refresh_tokens (tenant_id, token_hash, grant_id, client_id, dpop_jkt)
             values ($1, $2, $3::uuid, 'billing', 'a-thumbprint')",
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
        /// Rotation moves `auth_time`, because the reason to rotate is always
        /// that the user has just proved something. `max_age` is measured from
        /// it (OIDC Core §3.1.2.1).
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
