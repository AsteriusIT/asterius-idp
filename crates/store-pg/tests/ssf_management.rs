//! Stream status and subject membership, against a real database (SSF 1.0
//! §8.1.2, §8.1.3, `ast-0ju.4`).
//!
//! What is asserted here is what only a database can answer: that a paused
//! stream *holds* the events it does not deliver and hands them over in order
//! when it is enabled again, that a disabled one keeps nothing, that a
//! membership is one row however the receiver spells the subject, and that
//! deleting a stream takes its memberships with it (§8.1.1.5). The request and
//! response shapes are unit-tested in `asterius_ssf::management`, and who may
//! call which endpoint is `crates/server/tests/ssf_management.rs`.
//!
//! These run only when `DATABASE_URL` is set, like the rest of the
//! database-backed tests:
//!
//! ```sh
//! DATABASE_URL=postgres://asterius:asterius@127.0.0.1:5433/asterius \
//!   cargo nextest run -p asterius-store-pg ssf_management
//! ```

use asterius_domain::{ClientId, TenantId};
use asterius_ssf::stream::{Delivery, StreamConfiguration, StreamId, StreamStatus};
use asterius_ssf::subject::{ComplexSubject, SimpleSubject, Subject};
use asterius_store_pg::{
    Added, Discarded, Enqueued, MIGRATOR, PgSsfPoll, PgSsfStreams, PgSsfSubjects,
};
use serde_json::json;
use sqlx::postgres::{PgConnectOptions, PgPool, PgPoolOptions};
use std::str::FromStr as _;
use std::sync::atomic::{AtomicU32, Ordering};
use time::OffsetDateTime;

static COUNTER: AtomicU32 = AtomicU32::new(0);

const RECEIVER: &str = "receiver";
const OTHER_RECEIVER: &str = "other-receiver";
const AUDIENCE: &str = "https://receiver.example/events";

struct TestDb {
    pool: PgPool,
    tenant: TenantId,
}

impl TestDb {
    /// The stream repository, with the KEK that would seal a push
    /// credential (`ast-0ju.6`). Every stream here is a *poll* stream, which
    /// stores none, so the key is a fixed one: nothing in this file depends on
    /// what it is, only that the repository has one.
    fn streams(&self) -> PgSsfStreams {
        PgSsfStreams::new(
            self.pool.clone(),
            self.tenant.clone(),
            std::sync::Arc::new(
                asterius_jose::LocalKek::from_bytes(&[0x5a; 32]).expect("a 32-byte KEK"),
            ),
        )
    }

    fn subjects(&self) -> PgSsfSubjects {
        PgSsfSubjects::new(self.pool.clone(), self.tenant.clone())
    }

    fn queue(&self) -> PgSsfPoll {
        PgSsfPoll::new(self.pool.clone(), self.tenant.clone())
    }

    /// A poll stream `receiver` owns.
    async fn stream_of(&self, receiver: &str) -> StreamId {
        let stream = StreamConfiguration {
            stream_id: StreamId::generate(),
            audience: vec![format!("{AUDIENCE}/{receiver}")],
            events_requested: Vec::new(),
            delivery: Delivery::Poll,
            description: None,
            inactivity_timeout: None,
        };
        self.streams()
            .create(&ClientId::new(receiver), &stream)
            .await
            .expect("create a stream");
        stream.stream_id
    }

    async fn stream(&self) -> StreamId {
        self.stream_of(RECEIVER).await
    }

    /// Queues one SET the way `ast-0ju.8`'s emitters will.
    async fn queue_set(&self, stream: &StreamId, jti: &str, at: OffsetDateTime) -> Enqueued {
        let mut transaction = self.pool.begin().await.expect("begin");
        let outcome = self
            .queue()
            .enqueue(&mut transaction, stream, jti, &format!("jws.of.{jti}"), at)
            .await
            .expect("queue a SET");
        transaction.commit().await.expect("commit");
        outcome
    }

    async fn set_status(&self, stream: &StreamId, status: StreamStatus) {
        let changed = self
            .streams()
            .set_status_for(&ClientId::new(RECEIVER), stream, status, None, at(0))
            .await
            .expect("set the status");
        assert!(changed, "the fixture stream must exist");
    }
}

/// Sets up an isolated, migrated schema with two receivers in it.
async fn setup() -> Option<TestDb> {
    let url = std::env::var("DATABASE_URL").ok()?;
    let schema = format!(
        "ssf_mgmt_{}_{}",
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

fn at(seconds: i64) -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_700_000_000 + seconds).expect("an instant")
}

fn opaque(id: &str) -> Subject {
    Subject::from(SimpleSubject::opaque(id).expect("a subject"))
}

// ---------------------------------------------------------------------------
// §8.1.2 — status
// ---------------------------------------------------------------------------

db_test! {
    /// §8.1.1.1 creates a usable stream: one that was never told a status
    /// delivers.
    async fn a_new_stream_is_enabled(db) {
        // Arrange
        let stream = db.stream().await;

        // Act
        let status = db
            .streams()
            .status(&ClientId::new(RECEIVER), &stream)
            .await
            .expect("read the status");

        // Assert
        assert_eq!(status, Some((StreamStatus::Enabled, None)));
    }
}

db_test! {
    /// §8: the receiver is in every statement, so another receiver's stream is
    /// not one this one can read or change.
    async fn a_status_is_not_readable_or_writable_by_another_receiver(db) {
        // Arrange
        let theirs = db.stream_of(OTHER_RECEIVER).await;

        // Act
        let read = db
            .streams()
            .status(&ClientId::new(RECEIVER), &theirs)
            .await
            .expect("read the status");
        let written = db
            .streams()
            .set_status_for(
                &ClientId::new(RECEIVER),
                &theirs,
                StreamStatus::Disabled,
                None,
                at(0),
            )
            .await
            .expect("attempt the write");

        // Assert
        assert_eq!(read, None);
        assert!(!written, "one receiver disabled another receiver's stream");
        assert_eq!(
            db.streams()
                .status(&ClientId::new(OTHER_RECEIVER), &theirs)
                .await
                .expect("read the status"),
            Some((StreamStatus::Enabled, None)),
        );
    }
}

db_test! {
    /// §8.1.2.2's `reason` is kept and read back at §8.1.2.1: a paused stream
    /// nobody can explain is an incident nobody can close.
    async fn the_reason_a_stream_was_paused_is_read_back(db) {
        // Arrange
        let stream = db.stream().await;

        // Act
        db.streams()
            .set_status_for(
                &ClientId::new(RECEIVER),
                &stream,
                StreamStatus::Paused,
                Some("receiver asked"),
                at(0),
            )
            .await
            .expect("pause");

        // Assert
        assert_eq!(
            db.streams()
                .status(&ClientId::new(RECEIVER), &stream)
                .await
                .expect("read the status"),
            Some((StreamStatus::Paused, Some("receiver asked".to_owned()))),
        );
    }
}

// ---------------------------------------------------------------------------
// §8.1.2 — what each status does to the events
// ---------------------------------------------------------------------------

db_test! {
    /// > `paused`: the Transmitter MUST NOT transmit events over the stream.
    /// > The Transmitter SHOULD hold any events it would have transmitted
    /// > while paused, and transmit them when the stream becomes enabled.
    ///
    /// Both halves in one test, because either alone is a different bug: held
    /// and never released is a receiver that silently loses signals, released
    /// without being held is a receiver that never had them.
    async fn a_paused_stream_holds_its_events_and_releases_them_when_enabled(db) {
        // Arrange
        let stream = db.stream().await;
        db.set_status(&stream, StreamStatus::Paused).await;

        // Act
        let held = db.queue_set(&stream, "set-1", at(1)).await;
        let while_paused = db.queue().deliver(&stream, 10, at(2)).await.expect("poll");
        db.set_status(&stream, StreamStatus::Enabled).await;
        let after = db.queue().deliver(&stream, 10, at(3)).await.expect("poll");

        // Assert
        assert_eq!(held, Enqueued::Held);
        assert!(
            while_paused.sets.is_empty(),
            "a paused stream transmitted an event"
        );
        assert_eq!(
            after.sets.iter().map(|set| set.jti.as_str()).collect::<Vec<_>>(),
            vec!["set-1"],
            "enabling the stream did not release what it held",
        );
    }
}

db_test! {
    /// §8.1.2: events held while paused are transmitted "in the order in which
    /// they occurred, per subject". The queue is ordered by the instant an
    /// event was queued, which is an order per subject as well.
    async fn events_held_while_paused_are_released_in_the_order_they_happened(db) {
        // Arrange
        let stream = db.stream().await;
        db.set_status(&stream, StreamStatus::Paused).await;
        db.queue_set(&stream, "first", at(1)).await;
        db.queue_set(&stream, "second", at(2)).await;
        db.queue_set(&stream, "third", at(3)).await;

        // Act
        db.set_status(&stream, StreamStatus::Enabled).await;
        let released = db.queue().deliver(&stream, 10, at(4)).await.expect("poll");

        // Assert
        assert_eq!(
            released.sets.iter().map(|set| set.jti.as_str()).collect::<Vec<_>>(),
            vec!["first", "second", "third"],
        );
    }
}

db_test! {
    /// > `disabled`: the Transmitter MUST NOT transmit events over the stream,
    /// > and will not hold any events.
    async fn a_disabled_stream_holds_nothing(db) {
        // Arrange
        let stream = db.stream().await;
        db.set_status(&stream, StreamStatus::Disabled).await;

        // Act
        let dropped = db.queue_set(&stream, "set-1", at(1)).await;
        db.set_status(&stream, StreamStatus::Enabled).await;
        let after = db.queue().deliver(&stream, 10, at(2)).await.expect("poll");

        // Assert
        assert_eq!(dropped, Enqueued::Dropped(Discarded::StreamDisabled));
        assert!(
            after.sets.is_empty(),
            "an event queued while disabled came back when the stream was enabled",
        );
    }
}

db_test! {
    /// An enabled stream is the ordinary case, and the outcome says so: an
    /// emitter that cannot tell "queued" from "dropped" cannot report a
    /// signal that was never kept.
    async fn an_enabled_stream_queues_its_events(db) {
        // Arrange
        let stream = db.stream().await;

        // Act
        let queued = db.queue_set(&stream, "set-1", at(1)).await;

        // Assert
        assert_eq!(queued, Enqueued::Queued);
    }
}

db_test! {
    /// A long poll must not wake on a stream that may not transmit: §8.1.2
    /// makes `paused` a promise about delivery, not about the queue.
    async fn a_paused_stream_reports_nothing_pending(db) {
        // Arrange
        let stream = db.stream().await;
        db.queue_set(&stream, "set-1", at(1)).await;

        // Act
        let while_enabled = db.queue().has_pending(&stream).await.expect("read");
        db.set_status(&stream, StreamStatus::Paused).await;
        let while_paused = db.queue().has_pending(&stream).await.expect("read");

        // Assert
        assert!(while_enabled);
        assert!(!while_paused);
    }
}

// ---------------------------------------------------------------------------
// §8.1.3 — subject membership
// ---------------------------------------------------------------------------

db_test! {
    /// §8.1.3.2 then §8.1.3.1: the subject a receiver added is the subject its
    /// stream carries events about.
    async fn an_added_subject_is_one_this_stream_delivers_to(db) {
        // Arrange
        let stream = db.stream().await;
        let subject = opaque("u-1");

        // Act
        let added = db
            .subjects()
            .add(&ClientId::new(RECEIVER), &stream, &subject, Some(true), at(0))
            .await
            .expect("add");

        // Assert
        assert_eq!(added, Added::Member);
        assert!(
            db.subjects().delivers_to(&stream, &subject).await.expect("match"),
        );
        assert!(
            !db.subjects().delivers_to(&stream, &opaque("u-2")).await.expect("match"),
            "a stream delivered to a subject nobody added",
        );
    }
}

db_test! {
    /// `default_subjects: NONE` (§7.1): a stream nobody has added a subject to
    /// carries events about nobody.
    async fn a_stream_with_no_subjects_delivers_to_nobody(db) {
        // Arrange
        let stream = db.stream().await;

        // Act
        let delivers = db
            .subjects()
            .delivers_to(&stream, &opaque("u-1"))
            .await
            .expect("match");

        // Assert
        assert!(!delivers);
    }
}

db_test! {
    /// The canonical key is what makes an add and a remove name one row, even
    /// when the receiver spells the subject differently each time.
    async fn two_spellings_of_one_subject_are_one_membership(db) {
        // Arrange
        let stream = db.stream().await;
        let first = Subject::from_json(&json!({
            "device": {"format": "opaque", "id": "d-1"},
            "user": {"id": "u-1", "format": "opaque"},
        }))
        .expect("a subject");
        let second = Subject::from_json(&json!({
            "user": {"format": "opaque", "id": "u-1"},
            "device": {"format": "opaque", "id": "d-1"},
        }))
        .expect("a subject");

        // Act
        db.subjects()
            .add(&ClientId::new(RECEIVER), &stream, &first, None, at(0))
            .await
            .expect("add");
        db.subjects()
            .add(&ClientId::new(RECEIVER), &stream, &second, None, at(1))
            .await
            .expect("add again");

        // Assert
        assert_eq!(db.subjects().list(&stream).await.expect("list").len(), 1);
    }
}

db_test! {
    /// §8.1.3.3: after a remove, the stream no longer carries events about that
    /// subject.
    async fn a_removed_subject_is_no_longer_delivered_to(db) {
        // Arrange
        let stream = db.stream().await;
        let subject = opaque("u-1");
        db.subjects()
            .add(&ClientId::new(RECEIVER), &stream, &subject, None, at(0))
            .await
            .expect("add");

        // Act
        let removed = db
            .subjects()
            .remove(&ClientId::new(RECEIVER), &stream, &subject)
            .await
            .expect("remove");

        // Assert
        assert!(removed, "the stream exists, so the removal was answered for");
        assert!(!db.subjects().delivers_to(&stream, &subject).await.expect("match"));
    }
}

db_test! {
    /// §8: the receiver is in every statement a receiver can reach, so one
    /// receiver cannot subscribe another receiver's stream to anybody.
    async fn one_receiver_cannot_add_a_subject_to_another_receivers_stream(db) {
        // Arrange
        let theirs = db.stream_of(OTHER_RECEIVER).await;

        // Act
        let added = db
            .subjects()
            .add(&ClientId::new(RECEIVER), &theirs, &opaque("u-1"), None, at(0))
            .await
            .expect("attempt the add");

        // Assert
        assert_eq!(added, Added::NoSuchStream);
        assert!(db.subjects().list(&theirs).await.expect("list").is_empty());
    }
}

db_test! {
    /// §8.1.1.5: a deleted stream carries nothing, and its subject identifiers
    /// do not outlive the stream that described them.
    async fn deleting_a_stream_takes_its_memberships_with_it(db) {
        // Arrange
        let stream = db.stream().await;
        db.subjects()
            .add(&ClientId::new(RECEIVER), &stream, &opaque("u-1"), None, at(0))
            .await
            .expect("add");

        // Act
        let deleted = db
            .streams()
            .delete(&ClientId::new(RECEIVER), &stream)
            .await
            .expect("delete");

        // Assert
        assert!(deleted);
        assert!(db.subjects().list(&stream).await.expect("list").is_empty());
    }
}

db_test! {
    /// §8.1.3.1, against stored rows: a stream that named a user and a device
    /// hears about that user with no device named, and does not hear about the
    /// same user on another device.
    async fn matching_a_stored_complex_subject_follows_the_spec(db) {
        // Arrange
        let stream = db.stream().await;
        let member = Subject::from(
            ComplexSubject::of_user(SimpleSubject::opaque("u-1").expect("user"))
                .with_device(SimpleSubject::opaque("d-1").expect("device")),
        );
        db.subjects()
            .add(&ClientId::new(RECEIVER), &stream, &member, None, at(0))
            .await
            .expect("add");

        // Act
        let less_restrictive = Subject::from(ComplexSubject::of_user(
            SimpleSubject::opaque("u-1").expect("user"),
        ));
        let mismatch = Subject::from(
            ComplexSubject::of_user(SimpleSubject::opaque("u-1").expect("user"))
                .with_device(SimpleSubject::opaque("d-2").expect("device")),
        );

        // Assert
        assert!(
            db.subjects().delivers_to(&stream, &less_restrictive).await.expect("match"),
        );
        assert!(
            !db.subjects().delivers_to(&stream, &mismatch).await.expect("match"),
        );
    }
}
