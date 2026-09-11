//! The poll queue, against a real database (RFC 8936 §2.3–§2.4,
//! `ast-0ju.7`).
//!
//! What is asserted here is what only a database can answer: that a delivered
//! SET is still there for the next poll until it is acknowledged, that
//! `moreAvailable` counts what is actually held, and that deleting a stream
//! takes its queued SETs with it (SSF 1.0 §8.1.1.5). The §2.1 and §2.3
//! document shapes are unit-tested in `asterius_ssf::poll`, and who may poll
//! which stream is `crates/server/tests/ssf_poll.rs`.
//!
//! These run only when `DATABASE_URL` is set, like the rest of the
//! database-backed tests:
//!
//! ```sh
//! DATABASE_URL=postgres://asterius:asterius@127.0.0.1:5433/asterius \
//!   cargo nextest run -p asterius-store-pg ssf_poll
//! ```

use asterius_domain::{ClientId, TenantId};
use asterius_ssf::stream::{Delivery, StreamConfiguration, StreamId};
use asterius_store_pg::{MIGRATOR, PgSsfPoll, PgSsfStreams};
use sqlx::Row as _;
use sqlx::postgres::{PgConnectOptions, PgPool, PgPoolOptions};
use std::str::FromStr as _;
use std::sync::atomic::{AtomicU32, Ordering};
use time::OffsetDateTime;

static COUNTER: AtomicU32 = AtomicU32::new(0);

const RECEIVER: &str = "receiver";
const AUDIENCE: &str = "https://receiver.example/events";

struct TestDb {
    pool: PgPool,
    tenant: TenantId,
}

impl TestDb {
    fn queue(&self) -> PgSsfPoll {
        PgSsfPoll::new(self.pool.clone(), self.tenant.clone())
    }

    fn streams(&self) -> PgSsfStreams {
        PgSsfStreams::new(self.pool.clone(), self.tenant.clone())
    }

    /// A poll stream this receiver owns, ready to be polled.
    async fn stream(&self) -> StreamId {
        let stream = StreamConfiguration {
            stream_id: StreamId::generate(),
            audience: vec![AUDIENCE.to_owned()],
            events_requested: Vec::new(),
            delivery: Delivery::Poll,
            description: None,
            inactivity_timeout: None,
        };
        self.streams()
            .create(&ClientId::new(RECEIVER), &stream)
            .await
            .expect("create a stream");
        stream.stream_id
    }

    /// Queues one SET, the way `ast-0ju.8`'s emitters will: inside a
    /// transaction of their own.
    async fn queue_set(&self, stream: &StreamId, jti: &str, at: OffsetDateTime) {
        let mut transaction = self.pool.begin().await.expect("begin");
        self.queue()
            .enqueue(&mut transaction, stream, jti, &format!("jws.of.{jti}"), at)
            .await
            .expect("queue a SET");
        transaction.commit().await.expect("commit");
    }
}

/// Sets up an isolated, migrated schema with a receiver in it, or returns
/// `None` without a database.
async fn setup() -> Option<TestDb> {
    let url = std::env::var("DATABASE_URL").ok()?;
    let schema = format!(
        "ssf_poll_{}_{}",
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
        .max_connections(4)
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

    sqlx::query(
        "insert into clients (tenant_id, client_id, client_name,
                              token_endpoint_auth_method, jwks)
         values ('demo', $1, $1, 'private_key_jwt', '{}'::jsonb)",
    )
    .bind(RECEIVER)
    .execute(&pool)
    .await
    .expect("seed receiver");

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

fn at(seconds: i64) -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_700_000_000 + seconds).expect("an instant")
}

db_test! {
    /// §2.4: "SETs that are not acknowledged are returned again in the
    /// response to the next poll request".
    async fn an_unacknowledged_set_is_delivered_again(db) {
        // Arrange
        let stream = db.stream().await;
        db.queue_set(&stream, "set-1", at(0)).await;
        let queue = db.queue();
        let first = queue.deliver(&stream, 10, at(1)).await.expect("first poll");

        // Act: the receiver polls again without acknowledging anything.
        let second = queue.deliver(&stream, 10, at(2)).await.expect("second poll");

        // Assert
        assert_eq!(first.sets.len(), 1);
        assert_eq!(second.sets, first.sets);
    }
}

db_test! {
    /// §2.4: an acknowledgement is what removes a SET, and it removes only
    /// the ones it names.
    async fn an_acknowledgement_removes_only_what_it_names(db) {
        // Arrange
        let stream = db.stream().await;
        db.queue_set(&stream, "set-1", at(0)).await;
        db.queue_set(&stream, "set-2", at(1)).await;
        let queue = db.queue();

        // Act
        let removed = queue
            .acknowledge(&stream, &["set-1".to_owned()])
            .await
            .expect("acknowledge");
        let left = queue.deliver(&stream, 10, at(2)).await.expect("poll");

        // Assert
        assert_eq!(removed, 1);
        assert_eq!(
            left.sets.iter().map(|set| set.jti.clone()).collect::<Vec<_>>(),
            vec!["set-2".to_owned()]
        );
    }
}

db_test! {
    /// §2.4 again: acknowledging something this stream never held is not an
    /// error, and takes nothing with it.
    async fn acknowledging_an_unknown_identifier_removes_nothing(db) {
        // Arrange
        let stream = db.stream().await;
        db.queue_set(&stream, "set-1", at(0)).await;
        let queue = db.queue();

        // Act
        let removed = queue
            .acknowledge(&stream, &["set-invented".to_owned()])
            .await
            .expect("acknowledge");

        // Assert
        assert_eq!(removed, 0);
        assert!(queue.has_pending(&stream).await.expect("read"));
    }
}

db_test! {
    /// This deployment's policy for §2.4's `setErrs`: a SET the receiver could
    /// not process is retired rather than handed over for ever.
    async fn a_reported_error_retires_the_set(db) {
        // Arrange
        let stream = db.stream().await;
        db.queue_set(&stream, "set-1", at(0)).await;
        let queue = db.queue();

        // Act
        let removed = queue
            .reject(&stream, &["set-1".to_owned()])
            .await
            .expect("reject");
        let left = queue.deliver(&stream, 10, at(1)).await.expect("poll");

        // Assert
        assert_eq!(removed, 1);
        assert!(left.sets.is_empty(), "a reported SET is not delivered again");
    }
}

db_test! {
    /// §2.3: `maxEvents` bounds the batch and `moreAvailable` says the rest
    /// are still there.
    async fn a_bounded_poll_says_more_is_available(db) {
        // Arrange
        let stream = db.stream().await;
        for index in 0..3 {
            db.queue_set(&stream, &format!("set-{index}"), at(index)).await;
        }

        // Act
        let batch = db.queue().deliver(&stream, 2, at(10)).await.expect("poll");

        // Assert
        assert_eq!(
            batch.sets.iter().map(|set| set.jti.clone()).collect::<Vec<_>>(),
            vec!["set-0".to_owned(), "set-1".to_owned()],
            "oldest first"
        );
        assert!(batch.more_available);
    }
}

db_test! {
    /// The other side of the same member: a poll that emptied the queue says
    /// there is nothing more, so a receiver does not poll again for nothing.
    async fn a_complete_poll_says_no_more_is_available(db) {
        // Arrange
        let stream = db.stream().await;
        db.queue_set(&stream, "set-1", at(0)).await;

        // Act
        let batch = db.queue().deliver(&stream, 10, at(1)).await.expect("poll");

        // Assert
        assert_eq!(batch.sets.len(), 1);
        assert!(!batch.more_available);
    }
}

db_test! {
    /// §2.1's acknowledge-only poll: `maxEvents: 0` returns nothing, and says
    /// so without hiding what is waiting.
    async fn a_poll_for_no_events_returns_none_and_still_reports_more(db) {
        // Arrange
        let stream = db.stream().await;
        db.queue_set(&stream, "set-1", at(0)).await;

        // Act
        let batch = db.queue().deliver(&stream, 0, at(1)).await.expect("poll");

        // Assert
        assert!(batch.sets.is_empty());
        assert!(batch.more_available);
    }
}

db_test! {
    /// One poll is one delivery, counted: an operator reading a SET that has
    /// been handed over forty times is reading a receiver that cannot process
    /// it.
    async fn every_delivery_of_a_set_is_counted(db) {
        // Arrange
        let stream = db.stream().await;
        db.queue_set(&stream, "set-1", at(0)).await;
        let queue = db.queue();

        // Act
        queue.deliver(&stream, 10, at(1)).await.expect("first poll");
        queue.deliver(&stream, 10, at(2)).await.expect("second poll");

        // Assert
        let row = sqlx::query(
            "select deliveries, delivered_at from ssf_poll_queue
              where tenant_id = 'demo' and stream_id = $1 and jti = 'set-1'",
        )
        .bind(stream.as_str())
        .fetch_one(&db.pool)
        .await
        .expect("read the row");
        assert_eq!(row.get::<i32, _>("deliveries"), 2);
        assert_eq!(row.get::<OffsetDateTime, _>("delivered_at"), at(2));
    }
}

db_test! {
    /// A SET queued twice under one `jti` is one row: §2.3 names each SET by
    /// its `jti`, so a duplicate is not something a receiver could tell apart.
    async fn one_identifier_is_one_queued_set(db) {
        // Arrange
        let stream = db.stream().await;

        // Act
        db.queue_set(&stream, "set-1", at(0)).await;
        db.queue_set(&stream, "set-1", at(1)).await;

        // Assert
        let batch = db.queue().deliver(&stream, 10, at(2)).await.expect("poll");
        assert_eq!(batch.sets.len(), 1);
    }
}

db_test! {
    /// SSF 1.0 §8.1.1.5: "the transmitter MUST NOT deliver any events for a
    /// deleted stream". The queue goes with the stream, in the delete itself.
    async fn deleting_a_stream_takes_its_queued_sets_with_it(db) {
        // Arrange
        let stream = db.stream().await;
        db.queue_set(&stream, "set-1", at(0)).await;

        // Act
        let deleted = db
            .streams()
            .delete(&ClientId::new(RECEIVER), &stream)
            .await
            .expect("delete");

        // Assert
        assert!(deleted);
        assert!(!db.queue().has_pending(&stream).await.expect("read"));
    }
}

db_test! {
    /// A queue belongs to a stream, and a stream that does not exist has no
    /// queue: a SET cannot be parked against an identifier nobody owns.
    async fn a_set_cannot_be_queued_for_a_stream_that_does_not_exist(db) {
        // Arrange
        let unknown = StreamId::generate();
        let mut transaction = db.pool.begin().await.expect("begin");

        // Act
        let refused = db
            .queue()
            .enqueue(&mut transaction, &unknown, "set-1", "jws.of.set-1", at(0))
            .await;

        // Assert
        assert!(refused.is_err(), "the foreign key must refuse this");
    }
}
