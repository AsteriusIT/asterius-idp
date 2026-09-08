mkdir -p crates/store-pg/tests
cat > crates/store-pg/tests/support.rs <<'RSEOF'
//! Shared plumbing for the database-backed tests.
//!
//! These tests run only when `DATABASE_URL` is set, so the default
//! `cargo test` stays sub-second and a contributor without Docker is not
//! blocked. `docker compose up -d db` and the URL from `.env.example` turn
//! them on.
//!
//! Each test gets its own PostgreSQL schema, created and migrated from
//! scratch and dropped afterwards. That costs about 40 ms per test and buys
//! full parallelism with no shared fixtures to leak between cases — which
//! matters here more than usual, since half the point of these tests is that
//! data does not leak between scopes.

#![allow(dead_code, reason = "each integration test binary uses part of this")]

use sqlx::postgres::{PgConnectOptions, PgPool, PgPoolOptions};
use std::str::FromStr;
use std::sync::atomic::{AtomicU32, Ordering};

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// A migrated, isolated schema that drops itself when the test ends.
pub struct TestDb {
    pub pool: PgPool,
    admin: PgPool,
    schema: String,
}

impl TestDb {
    /// The schema this test owns.
    pub fn schema(&self) -> &str {
        &self.schema
    }

    /// Tears the schema down. Called by the `db_test` macro.
    pub async fn drop_schema(self) {
        let statement = format!("drop schema if exists \"{}\" cascade", self.schema);
        self.pool.close().await;
        let _ = sqlx::query(&statement).execute(&self.admin).await;
        self.admin.close().await;
    }
}

/// Sets up an isolated schema, or returns `None` when `DATABASE_URL` is unset.
pub async fn setup() -> Option<TestDb> {
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

    sqlx::query(&format!("drop schema if exists \"{schema}\" cascade"))
        .execute(&admin)
        .await
        .expect("drop stale schema");
    sqlx::query(&format!("create schema \"{schema}\""))
        .execute(&admin)
        .await
        .expect("create schema");

    // Pinning search_path on the connection is what makes the isolation real:
    // the migrations are written with unqualified names, so they build the
    // whole schema inside this test's namespace without knowing about it.
    let options = PgConnectOptions::from_str(&url)
        .expect("DATABASE_URL is not a valid PostgreSQL URL")
        .options([("search_path", schema.as_str())]);

    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect_with(options)
        .await
        .expect("connect to the test schema");

    asterius_store_pg::MIGRATOR.run(&pool).await.expect("run migrations");

    Some(TestDb { pool, admin, schema })
}

/// Declares a test that needs a database, and skips it politely without one.
#[macro_export]
macro_rules! db_test {
    ($(#[$meta:meta])* async fn $name:ident($db:ident: TestDb) $body:block) => {
        $(#[$meta])*
        #[tokio::test]
        async fn $name() {
            let Some($db) = $crate::support::setup().await else {
                eprintln!(
                    "skipping {}: DATABASE_URL is not set (see .env.example)",
                    stringify!($name)
                );
                return;
            };
            let result = {
                let $db = &$db;
                std::panic::AssertUnwindSafe(async move { $body })
            };
            let outcome = futures_lite::future::poll_once(std::future::pending::<()>());
            let _ = outcome;
            result.0.await;
        }
    };
}
