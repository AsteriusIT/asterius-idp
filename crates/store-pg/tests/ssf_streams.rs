//! The SSF stream table, against a real database (SSF 1.0 §8.1.1,
//! `ast-0ju.3`).
//!
//! What is asserted here is what only a database can answer: the uniqueness
//! that makes §8.1.1.1's 409 a race-free answer, the receiver in every
//! `WHERE` clause that makes another receiver's stream a 404 rather than a
//! refusal, and §8.1.1.5's rule that a deleted stream delivers nothing more.
//! The §8.1.1 semantics themselves are unit-tested in `asterius_ssf::stream`,
//! where they need no rows.
//!
//! These run only when `DATABASE_URL` is set, like the rest of the
//! database-backed tests:
//!
//! ```sh
//! DATABASE_URL=postgres://asterius:asterius@127.0.0.1:5433/asterius \
//!   cargo nextest run -p asterius-store-pg ssf_streams
//! ```

use asterius_domain::{ClientId, DomainError, TenantId};
use asterius_ssf::stream::{Delivery, StreamConfiguration, StreamId};
use asterius_store_pg::{PgSsfStreams, SET_OUTBOX_KIND};
use sqlx::Row as _;
use sqlx::postgres::{PgConnectOptions, PgPool, PgPoolOptions};
use std::str::FromStr as _;
use std::sync::atomic::{AtomicU32, Ordering};

use asterius_store_pg::MIGRATOR;

static COUNTER: AtomicU32 = AtomicU32::new(0);

const RECEIVER: &str = "receiver";
const OTHER_RECEIVER: &str = "other-receiver";
const AUDIENCE: &str = "https://receiver.example/events";

struct TestDb {
    pool: PgPool,
    tenant: TenantId,
}

impl TestDb {
    fn streams(&self) -> PgSsfStreams {
        PgSsfStreams::new(self.pool.clone(), self.tenant.clone())
    }
}

/// Sets up an isolated, migrated schema with two receivers in it, or returns
/// `None` without a database.
async fn setup() -> Option<TestDb> {
    let url = std::env::var("DATABASE_URL").ok()?;
    let schema = format!(
        "ssf_streams_{}_{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    );

    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .expect("DATABASE_URL is set but unreachable; is the database running?");
    sqlx::query(&format!("create schema \"{schema}\""))
        .execute(&admin)
        .await
        .expect("create schema");
    admin.close().await;

    let options = PgConnectOptions::from_str(&url)
        .expect("DATABASE_URL is not a valid PostgreSQL URL")
        .options([("search_path", schema.as_str())]);
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect_with(options)
        .await
        .expect("connect");

    MIGRATOR.run(&pool).await.expect("run migrations");

    sqlx::query(
        "insert into tenants (tenant_id, issuer, display_name, default_resource)
         values ('demo', 'https://as.example/t/demo', 'demo', 'https://api.example/')",
    )
    .execute(&pool)
    .await
    .expect("seed tenant");

    for client in [RECEIVER, OTHER_RECEIVER] {
        sqlx::query(
            "insert into clients (tenant_id, client_id, client_name,
                                  token_endpoint_auth_method, jwks)
             values ('demo', $1, $1, 'private_key_jwt', '{}'::jsonb)",
        )
        .bind(client)
        .execute(&pool)
        .await
        .expect("seed receiver");
    }

    Some(TestDb {
        pool,
        tenant: TenantId::new("demo"),
    })
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

fn receiver() -> ClientId {
    ClientId::new(RECEIVER.to_owned())
}

fn other_receiver() -> ClientId {
    ClientId::new(OTHER_RECEIVER.to_owned())
}

/// A poll stream for `audience`, the shape a `POST` with an empty body makes.
fn stream(audience: &[&str]) -> StreamConfiguration {
    StreamConfiguration {
        stream_id: StreamId::generate(),
        audience: audience.iter().map(|entry| (*entry).to_owned()).collect(),
        events_requested: Vec::new(),
        delivery: Delivery::Poll,
        description: None,
        inactivity_timeout: None,
    }
}

/// Queues a SET for `stream`, the way the delivery stories will.
async fn queue_set(db: &TestDb, stream: &StreamId) -> i64 {
    sqlx::query(
        "insert into outbox (tenant_id, kind, destination, payload)
         values ('demo', $1, $2, '{}'::jsonb)
         returning outbox_id",
    )
    .bind(SET_OUTBOX_KIND)
    .bind(stream.as_str())
    .fetch_one(&db.pool)
    .await
    .expect("queue a SET")
    .get("outbox_id")
}

async fn outbox_status(db: &TestDb, id: i64) -> String {
    sqlx::query("select status from outbox where tenant_id = 'demo' and outbox_id = $1")
        .bind(id)
        .fetch_one(&db.pool)
        .await
        .expect("read the outbox row")
        .get("status")
}

db_test! {
    /// The round trip: what is stored is what comes back, including the
    /// members §8.1.1 makes optional.
    async fn a_stored_stream_reads_back_as_it_was_written(db) {
        // Arrange
        let streams = db.streams();
        let mut created = stream(&[AUDIENCE]);
        created.description = Some("production".to_owned());
        created.inactivity_timeout = Some(3600);
        created.events_requested = vec![
            "https://schemas.openid.net/secevent/caep/event-type/session-revoked".to_owned(),
        ];
        created.delivery = Delivery::Push {
            endpoint_url: "https://receiver.example/push".to_owned(),
        };

        // Act
        streams.create(&receiver(), &created).await.expect("create");
        let read = streams
            .find(&receiver(), &created.stream_id)
            .await
            .expect("read");

        // Assert
        assert_eq!(read, Some(created));
    }
}

db_test! {
    /// §8.1.1.1: one stream per receiver per audience. The second creation is
    /// a conflict raised by the schema, so two concurrent `POST`s cannot both
    /// believe they were first.
    async fn a_second_stream_for_the_same_audience_is_a_conflict(db) {
        // Arrange
        let streams = db.streams();
        streams.create(&receiver(), &stream(&[AUDIENCE])).await.expect("the first stream");

        // Act
        let refused = streams.create(&receiver(), &stream(&[AUDIENCE])).await;

        // Assert
        assert!(
            matches!(refused, Err(DomainError::Conflict(_))),
            "a second stream for the same audience was accepted: {refused:?}"
        );
    }
}

db_test! {
    /// The audience is a set: naming the same two audiences in the other
    /// order is the same stream, and the index has to see it that way.
    async fn the_order_of_the_audience_does_not_make_a_second_stream(db) {
        // Arrange
        let streams = db.streams();
        let other = "https://receiver.example/other";
        streams
            .create(&receiver(), &stream(&[AUDIENCE, other]))
            .await
            .expect("the first stream");

        // Act
        let refused = streams.create(&receiver(), &stream(&[other, AUDIENCE])).await;

        // Assert
        assert!(
            matches!(refused, Err(DomainError::Conflict(_))),
            "the same audience in another order made a second stream: {refused:?}"
        );
    }
}

db_test! {
    /// Two receivers configuring the same audience are two streams: the
    /// uniqueness is per receiver, which is what lets a receiver be told
    /// about a subject without knowing who else is.
    async fn another_receiver_may_hold_a_stream_for_the_same_audience(db) {
        // Arrange
        let streams = db.streams();
        streams.create(&receiver(), &stream(&[AUDIENCE])).await.expect("the first stream");

        // Act
        let second = streams.create(&other_receiver(), &stream(&[AUDIENCE])).await;

        // Assert
        assert!(second.is_ok(), "a second receiver was refused: {second:?}");
    }
}

db_test! {
    /// §8: a receiver reaches its own streams and no others. Another
    /// receiver's `stream_id` is not a row this repository returns, so the
    /// endpoint has nothing to refuse and answers 404.
    async fn another_receivers_stream_is_not_a_row_this_receiver_can_read(db) {
        // Arrange
        let streams = db.streams();
        let theirs = stream(&[AUDIENCE]);
        streams.create(&other_receiver(), &theirs).await.expect("their stream");

        // Act
        let read = streams.find(&receiver(), &theirs.stream_id).await.expect("read");
        let listed = streams.list(&receiver()).await.expect("list");

        // Assert
        assert_eq!(read, None);
        assert!(listed.is_empty(), "another receiver's stream was listed");
    }
}

db_test! {
    /// §8.1.1.2's `GET` with no `stream_id`: the caller's streams, and a
    /// receiver with none gets an empty list rather than an error.
    async fn a_receiver_lists_its_own_streams(db) {
        // Arrange
        let streams = db.streams();
        let first = stream(&[AUDIENCE]);
        let second = stream(&["https://receiver.example/other"]);
        streams.create(&receiver(), &first).await.expect("first");
        streams.create(&receiver(), &second).await.expect("second");

        // Act
        let listed = streams.list(&receiver()).await.expect("list");
        let none = streams.list(&other_receiver()).await.expect("list");

        // Assert
        assert_eq!(listed.len(), 2);
        assert!(none.is_empty());
    }
}

db_test! {
    /// An update writes the receiver-supplied members and nothing else.
    async fn an_update_writes_the_receiver_supplied_members(db) {
        // Arrange
        let streams = db.streams();
        let created = stream(&[AUDIENCE]);
        streams.create(&receiver(), &created).await.expect("create");
        let mut updated = created.clone();
        updated.description = Some("staging".to_owned());
        updated.delivery = Delivery::Push {
            endpoint_url: "https://receiver.example/push".to_owned(),
        };

        // Act
        let written = streams.save(&receiver(), &updated).await.expect("save");
        let read = streams.find(&receiver(), &created.stream_id).await.expect("read");

        // Assert
        assert!(written);
        assert_eq!(read, Some(updated));
    }
}

db_test! {
    /// An update aimed at another receiver's stream writes nothing, which is
    /// the same 404 a read gets.
    async fn an_update_cannot_reach_another_receivers_stream(db) {
        // Arrange
        let streams = db.streams();
        let theirs = stream(&[AUDIENCE]);
        streams.create(&other_receiver(), &theirs).await.expect("their stream");
        let mut attempt = theirs.clone();
        attempt.description = Some("mine now".to_owned());

        // Act
        let written = streams.save(&receiver(), &attempt).await.expect("save");
        let unchanged = streams.find(&other_receiver(), &theirs.stream_id).await.expect("read");

        // Assert
        assert!(!written);
        assert_eq!(unchanged, Some(theirs));
    }
}

db_test! {
    /// §8.1.1.5: the stream goes, and the events it still owed are abandoned
    /// in the same transaction.
    async fn deleting_a_stream_abandons_the_events_it_still_owed(db) {
        // Arrange
        let streams = db.streams();
        let mine = stream(&[AUDIENCE]);
        let theirs = stream(&[AUDIENCE]);
        streams.create(&receiver(), &mine).await.expect("my stream");
        streams.create(&other_receiver(), &theirs).await.expect("their stream");
        let owed = queue_set(&db, &mine.stream_id).await;
        let untouched = queue_set(&db, &theirs.stream_id).await;

        // Act
        let deleted = streams.delete(&receiver(), &mine.stream_id).await.expect("delete");

        // Assert
        assert!(deleted);
        assert_eq!(streams.find(&receiver(), &mine.stream_id).await.expect("read"), None);
        assert_eq!(outbox_status(&db, owed).await, "abandoned");
        assert_eq!(
            outbox_status(&db, untouched).await,
            "pending",
            "another stream's queued events were abandoned"
        );
    }
}

db_test! {
    /// A `DELETE` for a stream that is not this receiver's deletes nothing —
    /// and, just as importantly, abandons nothing.
    async fn deleting_another_receivers_stream_does_nothing_at_all(db) {
        // Arrange
        let streams = db.streams();
        let theirs = stream(&[AUDIENCE]);
        streams.create(&other_receiver(), &theirs).await.expect("their stream");
        let owed = queue_set(&db, &theirs.stream_id).await;

        // Act
        let deleted = streams.delete(&receiver(), &theirs.stream_id).await.expect("delete");

        // Assert
        assert!(!deleted);
        assert_eq!(
            streams.find(&other_receiver(), &theirs.stream_id).await.expect("read"),
            Some(theirs)
        );
        assert_eq!(outbox_status(&db, owed).await, "pending");
    }
}

db_test! {
    /// A second `DELETE` finds nothing, which is the 404 §8.1.1.5's caller
    /// answers rather than an error.
    async fn a_second_delete_finds_nothing(db) {
        // Arrange
        let streams = db.streams();
        let mine = stream(&[AUDIENCE]);
        streams.create(&receiver(), &mine).await.expect("create");
        assert!(streams.delete(&receiver(), &mine.stream_id).await.expect("delete"));

        // Act
        let again = streams.delete(&receiver(), &mine.stream_id).await.expect("delete");

        // Assert
        assert!(!again);
    }
}

db_test! {
    /// Deleting the receiver takes its streams with it: a stream is a
    /// standing arrangement with a client, and an orphan row would be a
    /// configuration nobody can reach and nothing removes.
    async fn removing_the_receiver_removes_its_streams(db) {
        // Arrange
        let streams = db.streams();
        let mine = stream(&[AUDIENCE]);
        streams.create(&receiver(), &mine).await.expect("create");

        // Act
        sqlx::query("delete from clients where tenant_id = 'demo' and client_id = $1")
            .bind(RECEIVER)
            .execute(&db.pool)
            .await
            .expect("delete the receiver");

        // Assert
        assert!(streams.list(&receiver()).await.expect("list").is_empty());
    }
}
