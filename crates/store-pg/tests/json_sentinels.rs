//! The `serde_json` sentinel detection and repair scripts, run against a real
//! database with a deliberately corrupted row in it.
//!
//! `crates/domain/src/json_sentinel.rs` refuses these member names on the way
//! in. This file is about the rows written before it existed, and about why
//! they need SQL: such a row is one this binary will not load. The claims model
//! re-runs `ClaimName::parse` over every member as the row comes back, which is
//! where the refusal lands here; and where the document reaches anything typed
//! as a `RawValue`, `serde_json` refuses the parse outright. Either way a
//! repair tool written in Rust cannot load the row it exists to fix, so the
//! proof has to be this shape — seed in SQL, detect in SQL, repair in SQL, and
//! only then ask the binary to read the row.
//!
//! These run only when `DATABASE_URL` is set, like the rest of the
//! database-backed tests:
//!
//! ```sh
//! docker compose up -d db
//! DATABASE_URL=postgres://asterius:asterius@127.0.0.1:5433/asterius \
//!   cargo nextest run -p asterius-store-pg json_sentinels
//! ```

use serde_json::{Value, json};
use sqlx::pool::PoolConnection;
use sqlx::postgres::{PgConnectOptions, PgPool, PgPoolOptions, PgRow};
use sqlx::{Acquire as _, Row as _};
use sqlx::{Postgres, Transaction};
use std::str::FromStr;
use std::sync::atomic::{AtomicU32, Ordering};

use asterius_domain::ClaimSet;
use asterius_store_pg::MIGRATOR;

/// The detection script, read from the file an operator would run. Copying it
/// into the test would leave the test passing while the script rotted.
const DETECT: &str = include_str!("../../../scripts/sql/json-sentinels-detect.sql");

/// The repair script, likewise. Several statements, so it goes through
/// `raw_sql`, and all of them on one connection: the helper functions it
/// defines live in `pg_temp` and die with the session.
const REPAIR: &str = include_str!("../../../scripts/sql/json-sentinels-repair.sql");

static COUNTER: AtomicU32 = AtomicU32::new(0);

struct TestDb {
    pool: PgPool,
    tenant: String,
}

/// Sets up an isolated, migrated schema, or returns `None` without a database.
async fn setup() -> Option<TestDb> {
    let url = std::env::var("DATABASE_URL").ok()?;
    let schema = format!(
        "sentinels_{}_{}",
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

    // The scripts name tables without qualifying them and ask
    // `current_schema()` which schema they are in, exactly as they do in
    // production; pinning `search_path` is what points them at this test's
    // schema without either side knowing about the other.
    let options = PgConnectOptions::from_str(&url)
        .expect("DATABASE_URL is not a valid PostgreSQL URL")
        .options([("search_path", schema.as_str())]);
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect_with(options)
        .await
        .expect("connect");

    MIGRATOR.run(&pool).await.expect("run migrations");

    let tenant = "probe".to_owned();
    sqlx::query(
        "insert into tenants (tenant_id, issuer, display_name, default_resource)
         values ($1, 'https://probe.example/t/probe', 'probe', 'https://probe.example/api')",
    )
    .bind(&tenant)
    .execute(&pool)
    .await
    .expect("seed tenant");

    Some(TestDb { pool, tenant })
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

/// Writes a user whose claim bag carries a reserved member name.
///
/// Raw SQL because there is no other way: `PgUserRepository::upsert` refuses
/// this bag, which is the whole point of the guard. Only an admin path, an
/// import or a restored dump could have produced such a row, and this is the
/// closest thing to one of those that a test can be.
async fn seed_corrupt_user(db: &TestDb, username: &str, claims: &str) -> uuid::Uuid {
    let user_id = uuid::Uuid::new_v4();
    sqlx::query(&format!(
        "insert into users (tenant_id, user_id, username, status, claims)
         values ($1, $2, $3, 'active', '{claims}'::jsonb)"
    ))
    .bind(&db.tenant)
    .bind(user_id)
    .bind(username)
    .execute(&db.pool)
    .await
    .expect("seed corrupt user");
    user_id
}

/// The claim bag as the application reads it.
///
/// This is `PgUserRepository`'s own read path: the column comes back as a
/// `Value` and is then parsed into a [`ClaimSet`], which re-runs
/// `ClaimName::parse` over every member — the step that refuses a reserved
/// name, and so the step a corrupted row fails. Spelled out here rather than
/// called through the repository because the repository wants a KEK it has no
/// use for in this test; the conversion under test is the one in
/// `crate::users::Row::into_entity`.
async fn load_claims(db: &TestDb, user_id: uuid::Uuid) -> Result<ClaimSet, String> {
    serde_json::from_value::<ClaimSet>(read_claims(db, user_id).await)
        .map_err(|error| error.to_string())
}

/// The column as PostgreSQL hands it back, before the claims model judges it.
///
/// Used to assert what the repair did to the document, which is a question
/// about JSON and not about claims.
async fn read_claims(db: &TestDb, user_id: uuid::Uuid) -> Value {
    sqlx::query_scalar::<_, Value>("select claims from users where tenant_id = $1 and user_id = $2")
        .bind(&db.tenant)
        .bind(user_id)
        .fetch_one(&db.pool)
        .await
        .expect("the column decodes; it is the claims model that refuses the row")
}

/// Runs the detection script and returns its findings as
/// `(finding, table, column, sentinel_keys)`.
async fn detect(db: &TestDb) -> Vec<(String, String, String, Vec<String>)> {
    sqlx::query(DETECT)
        .fetch_all(&db.pool)
        .await
        .expect("detection script")
        .iter()
        .map(|row: &PgRow| {
            (
                row.get::<String, _>("finding"),
                row.get::<String, _>("table_name"),
                row.get::<String, _>("column_name"),
                row.get::<Option<Vec<String>>, _>("sentinel_keys")
                    .unwrap_or_default(),
            )
        })
        .collect()
}

/// Runs the repair script and returns its journal as `(action, table, column)`.
///
/// One connection and one transaction, which is how the shell wrapper runs it.
async fn repair(db: &TestDb) -> Vec<(String, String, String)> {
    let mut connection: PoolConnection<Postgres> = db.pool.acquire().await.expect("connection");
    let mut transaction: Transaction<'_, Postgres> =
        connection.begin().await.expect("begin repair");
    let rows = sqlx::raw_sql(REPAIR)
        .fetch_all(&mut *transaction)
        .await
        .expect("repair script");
    let journal = rows
        .iter()
        .map(|row: &PgRow| {
            (
                row.get::<String, _>("action"),
                row.get::<String, _>("table_name"),
                row.get::<String, _>("column_name"),
            )
        })
        .collect();
    transaction.commit().await.expect("commit repair");
    journal
}

db_test! {
    /// The whole point, end to end: a row this binary cannot read is found by
    /// SQL, fixed by SQL, and read by the binary afterwards.
    async fn a_corrupted_row_is_detected_repaired_and_readable_again(db) {
        // A bag in the shape the claims model stores, with one member named
        // after a type serde_json reserves -- and named first, which is the
        // position that decides whether the document parses at all.
        let user = seed_corrupt_user(
            &db,
            "corrupt",
            r#"{"$serde_json::private::RawValue": {"value": "{}", "source": "admin"},
                "given_name": {"value": "Ada", "source": "admin"}}"#,
        ).await;

        assert!(
            load_claims(&db, user).await.is_err(),
            "the seeded row loaded, so it is not the corruption this repairs"
        );

        let findings = detect(&db).await;
        assert_eq!(
            findings,
            vec![(
                "sentinel".to_owned(),
                "users".to_owned(),
                "claims".to_owned(),
                vec!["$serde_json::private::RawValue".to_owned()],
            )]
        );

        let journal = repair(&db).await;
        assert_eq!(
            journal,
            vec![("repaired".to_owned(), "users".to_owned(), "claims".to_owned())]
        );

        assert_eq!(
            read_claims(&db, user).await,
            json!({
                "quarantined_$serde_json::private::RawValue": {"value": "{}", "source": "admin"},
                "given_name": {"value": "Ada", "source": "admin"},
            }),
            "the repair renames the member and keeps everything else"
        );
        let loaded = load_claims(&db, user).await.expect("the repaired row must load");
        assert!(
            loaded.iter().any(|(name, _)| name.as_str() == "given_name"),
            "the untouched claim has to survive the repair as a claim"
        );

        assert!(detect(&db).await.is_empty(), "the repair must be complete");
    }
}

db_test! {
    /// What is looked for is the name, wherever it sits, and not the parse
    /// failure it causes when it happens to be first. A reserved name buried
    /// inside a member's value is the same corruption waiting for the rewrite
    /// that hoists it into first position.
    async fn a_sentinel_buried_in_a_value_is_detected(db) {
        seed_corrupt_user(
            &db,
            "buried",
            r#"{"address": {"source": "admin",
                            "value": {"street": "1 A St",
                                      "$serde_json::private::Number": "1"}}}"#,
        ).await;

        let findings = detect(&db).await;

        assert_eq!(
            findings,
            vec![(
                "sentinel".to_owned(),
                "users".to_owned(),
                "claims".to_owned(),
                vec!["$serde_json::private::Number".to_owned()],
            )]
        );
    }
}

db_test! {
    /// A sentinel inside an array inside an object is the same corruption and
    /// has to be found and renamed where it lies.
    async fn a_sentinel_nested_under_arrays_is_repaired_in_place(db) {
        let user = seed_corrupt_user(
            &db,
            "nested",
            r#"{"roles": {"source": "admin",
                          "value": [[{"$serde_json::private::Number": "1"}], "staff"]}}"#,
        ).await;

        repair(&db).await;

        assert_eq!(
            read_claims(&db, user).await,
            json!({"roles": {
                "source": "admin",
                "value": [[{"quarantined_$serde_json::private::Number": "1"}], "staff"],
            }}),
            "array order and every other member survive the rename"
        );
        load_claims(&db, user).await.expect("the repaired row must load");
    }
}

db_test! {
    /// The inventory in the detection script has to name every JSONB column in
    /// the schema; a migration that adds one is exactly how this scan would
    /// quietly stop covering the database. The script reports the gap itself,
    /// so a clean schema must produce no findings at all.
    async fn every_jsonb_column_in_the_schema_is_covered(db) {
        let findings = detect(&db).await;

        assert!(
            findings.is_empty(),
            "a freshly migrated schema reported {findings:?}; \
             'unreviewed_column' means scripts/sql/json-sentinels-detect.sql is stale"
        );
    }
}

db_test! {
    /// `audit_events` is append-only and hash-chained: rewriting a member would
    /// be refused by the trigger and would invalidate the chain if it were not.
    /// The repair must leave it alone and say so, rather than fail.
    async fn a_corrupted_audit_record_is_reported_and_not_rewritten(db) {
        sqlx::query(
            "insert into audit_events
                 (tenant_id, event_type, outcome, actor, detail, previous_hash, event_hash)
             values ($1, 'probe', 'success', '{\"type\": \"system\", \"id\": \"probe\"}'::jsonb,
                     '{\"$serde_json::private::RawValue\": \"{}\"}'::jsonb,
                     sha256('previous'), sha256('event'))",
        )
        .bind(&db.tenant)
        .execute(&db.pool)
        .await
        .expect("seed corrupt audit record");

        let journal = repair(&db).await;

        assert_eq!(
            journal,
            vec![(
                "left_for_a_human".to_owned(),
                "audit_events".to_owned(),
                "detail".to_owned(),
            )]
        );
        let still_there: bool = sqlx::query_scalar(
            "select jsonb_path_exists(detail, 'lax $.** ? (@.type() == \"object\").keyvalue()
                 ? (@.key == \"$serde_json::private::RawValue\")')
             from audit_events where tenant_id = $1",
        )
        .bind(&db.tenant)
        .fetch_one(&db.pool)
        .await
        .expect("read audit record");
        assert!(still_there, "the record must be untouched, not silently edited");
    }
}
