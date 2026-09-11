//! Push delivery end to end (RFC 8935, `ast-0ju.6`).
//!
//! The unit tests in `asterius_server::outbox::ssf` assert what one delivery
//! decides. What only a database can answer is what this file is for:
//!
//! * a SET queued for a stream is claimed by the worker, posted to the
//!   receiver's endpoint with the credential the stream stored **sealed**, and
//!   acked — so the seal, the outbox claim, the deliverer and the ack agree
//!   about one row;
//! * two SETs about one subject arrive in the order they were generated **even
//!   when the first is retried** (§2.2 delivers one at a time, and the ordering
//!   key is what stops the second overtaking the first);
//! * a receiver that refuses with §2.3's object dead-letters the SET and pauses
//!   the stream (SSF 1.0 §8.1.2), so the next SET is not posted.
//!
//! The receiver is a fake at the transport port rather than a socket. It has to
//! be: `asterius_server::outbound::ssrf` refuses every address a test could
//! bind — loopback first among them — which is the behaviour that guard exists
//! for. What the real outbound path does with TLS, redirects and timeouts is
//! asserted where it lives, in `outbound::post`.
//!
//! Every application row is made through the repository the server itself
//! uses, so a test cannot set up a state the application could not reach — a
//! stream with a credential in the clear, say. The only SQL here is the
//! `create schema` that isolates one test from another: the delivery worker
//! claims across tenants by design (one worker, every tenant's backlog), so two
//! of these tests sharing a schema would each deliver the other's rows.
//!
//! ```sh
//! DATABASE_URL=postgres://asterius:asterius@127.0.0.1:5433/asterius \
//!   cargo nextest run -p asterius-server ssf_push
//! ```

use asterius_domain::audit::{AuditEvent, EventType};
use asterius_domain::entities::client::{Client, ClientRegistration, ClientStatus};
use asterius_domain::ports::{Clock, TenantRepository as _};
use asterius_domain::{
    Capabilities, ClientId, DomainError, Issuer, Tenant, TenantId, TenantStatus,
};
use asterius_jose::{Kek, LocalKek};
use asterius_server::outbound::{PostError, PostRequest};
use asterius_server::outbox::{
    OutboxWorker, PgPushStreams, SetPoster, SsfPushDeliverer, push_event,
};
use asterius_ssf::push::AuthorizationHeader;
use asterius_ssf::stream::{Delivery, StreamConfiguration, StreamId};
use asterius_store_pg::{Backoff, MIGRATOR, PgOutbox, PgTenantRepository, Store};
use serde_json::json;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use std::str::FromStr as _;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use time::{Duration, OffsetDateTime};

static COUNTER: AtomicU32 = AtomicU32::new(0);

const RECEIVER: &str = "receiver";
const CREDENTIAL: &str = "Bearer receiver-token";
const ENDPOINT: &str = "https://receiver.example/events";

/// What a receiver is told to answer: a status, or a status with a body.
type Answer = Result<u16, (u16, Vec<u8>)>;

/// A receiver that answers what a test tells it to and keeps what it was sent.
#[derive(Debug, Default)]
struct FakeReceiver {
    answers: Mutex<Vec<Answer>>,
    seen: Mutex<Vec<(Option<String>, String)>>,
}

impl FakeReceiver {
    fn answering(answers: Vec<Answer>) -> Arc<Self> {
        Arc::new(Self {
            answers: Mutex::new(answers),
            seen: Mutex::new(Vec::new()),
        })
    }

    fn bodies(&self) -> Vec<String> {
        self.seen
            .lock()
            .expect("not poisoned")
            .iter()
            .map(|(_, body)| body.clone())
            .collect()
    }

    fn credentials(&self) -> Vec<Option<String>> {
        self.seen
            .lock()
            .expect("not poisoned")
            .iter()
            .map(|(credential, _)| credential.clone())
            .collect()
    }
}

#[async_trait::async_trait]
impl SetPoster for FakeReceiver {
    async fn post(
        &self,
        _url: &str,
        request: PostRequest<'_>,
        body: &[u8],
    ) -> Result<u16, PostError> {
        self.seen.lock().expect("not poisoned").push((
            request.authorization.map(str::to_owned),
            String::from_utf8_lossy(body).into_owned(),
        ));
        let answer = {
            let mut answers = self.answers.lock().expect("not poisoned");
            if answers.is_empty() {
                Ok(202)
            } else {
                answers.remove(0)
            }
        };
        answer.map_err(|(status, body)| PostError::Refused {
            host: "receiver.example".to_owned(),
            status,
            body,
        })
    }
}

#[derive(Debug, Default)]
struct Trail(Mutex<Vec<AuditEvent>>);

#[async_trait::async_trait]
impl asterius_domain::audit::AuditSink for Trail {
    async fn record(&self, event: AuditEvent) -> Result<(), DomainError> {
        self.0.lock().expect("not poisoned").push(event);
        Ok(())
    }
}

impl Trail {
    fn types(&self) -> Vec<EventType> {
        self.0
            .lock()
            .expect("not poisoned")
            .iter()
            .map(|event| event.event_type)
            .collect()
    }
}

#[derive(Debug)]
struct Now;

impl Clock for Now {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

struct Fixture {
    store: Store,
    tenant: Tenant,
    kek: Arc<dyn Kek>,
    receiver: Arc<FakeReceiver>,
    trail: Arc<Trail>,
}

impl Fixture {
    /// `None` without `DATABASE_URL`, so the default suite stays fast.
    async fn new(answers: Vec<Answer>) -> Option<Self> {
        let url = std::env::var("DATABASE_URL").ok()?;
        let schema = format!(
            "ssf_push_{}_{}",
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

        let options = PgConnectOptions::from_str(&url)
            .expect("DATABASE_URL is not a valid PostgreSQL URL")
            .options([("search_path", schema.as_str())]);
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .connect_with(options)
            .await
            .expect("connect");
        MIGRATOR.run(&pool).await.expect("migrate");
        let store = Store::from_pool(pool);

        let kek: Arc<dyn Kek> = Arc::new(LocalKek::from_bytes(&[7_u8; 32]).expect("a 32-byte KEK"));
        let now = OffsetDateTime::now_utc();
        let id = "push-tenant".to_owned();
        let tenant = Tenant {
            id: TenantId::parse(&id).expect("a generated tenant id"),
            issuer: Issuer::parse(&format!("https://as.example/t/{id}")).expect("issuer"),
            custom_host: None,
            display_name: "Push".to_owned(),
            default_resource: "https://api.example/".to_owned(),
            status: TenantStatus::Active,
            refresh: asterius_domain::RefreshPolicy::default(),
            created_at: now,
            updated_at: now,
        };
        PgTenantRepository::new(store.pool().clone(), Arc::clone(&kek))
            .upsert(&tenant)
            .await
            .expect("create tenant");

        let receiver = Client {
            tenant: tenant.id.clone(),
            id: ClientId::new(RECEIVER),
            registration: ClientRegistration::from_json(
                &serde_json::to_vec(&json!({
                    "client_name": "Receiver",
                    "grant_types": ["client_credentials"],
                    "response_types": [],
                    "scope": "ssf.manage",
                    "token_endpoint_auth_method": "private_key_jwt",
                    "jwks": {"keys": [{"kty": "OKP", "crv": "Ed25519", "x": "abc"}]},
                }))
                .expect("serialise"),
                Capabilities::default(),
            )
            .expect("a valid registration"),
            status: ClientStatus::Active,
            created_at: now,
            updated_at: now,
        };
        store
            .scope(tenant.id.clone())
            .clients(Capabilities::default())
            .upsert(&receiver)
            .await
            .expect("register the receiver");

        Some(Self {
            store,
            tenant,
            kek,
            receiver: FakeReceiver::answering(answers),
            trail: Arc::new(Trail::default()),
        })
    }

    /// An outbox with a two-attempt budget and no backoff.
    ///
    /// Two attempts, so "the budget ran out" is the second delivery rather
    /// than the eleventh; no backoff, so a retry is due immediately rather
    /// than in five seconds. Both are about keeping this test to the thing it
    /// asserts — the order SETs reach a receiver in, and what a refusal does.
    /// How long the wait between attempts is, and that it grows, is
    /// `ast-0ju.9`'s schedule and is tested where it lives.
    fn outbox(&self) -> PgOutbox {
        PgOutbox::with_schedule(
            self.store.pool().clone(),
            Backoff {
                base: Duration::ZERO,
                cap: Duration::ZERO,
            },
            Duration::seconds(30),
        )
        .with_max_attempts(2)
    }

    fn streams(&self) -> asterius_store_pg::PgSsfStreams {
        self.store
            .scope(self.tenant.id.clone())
            .ssf_streams(Arc::clone(&self.kek))
    }

    /// A push stream with a credential, written the way the endpoint writes it.
    async fn push_stream(&self) -> StreamId {
        let stream = StreamConfiguration {
            stream_id: StreamId::generate(),
            audience: vec![ENDPOINT.to_owned()],
            events_requested: Vec::new(),
            delivery: Delivery::Push {
                endpoint_url: ENDPOINT.to_owned(),
                authorization_header: Some(
                    AuthorizationHeader::parse(CREDENTIAL).expect("a field value"),
                ),
            },
            description: None,
            inactivity_timeout: None,
        };
        self.streams()
            .create(&ClientId::new(RECEIVER), &stream)
            .await
            .expect("create the stream");
        stream.stream_id
    }

    async fn queue(&self, stream: &StreamId, subject: &str, jws: &str) {
        self.outbox()
            .queue_all(
                &self.tenant.id,
                &[push_event(stream, subject, jws)],
                OffsetDateTime::now_utc(),
            )
            .await
            .expect("queue a SET");
    }

    fn worker(&self) -> OutboxWorker {
        OutboxWorker::new(self.outbox(), Arc::new(Now), "test-worker".to_owned()).with(Arc::new(
            SsfPushDeliverer::new(
                Arc::new(PgPushStreams::new(
                    self.store.clone(),
                    Arc::clone(&self.kek),
                )),
                Arc::clone(&self.receiver) as Arc<dyn SetPoster>,
                Arc::clone(&self.trail) as Arc<dyn asterius_domain::audit::AuditSink>,
                Arc::new(Now),
            ),
        ))
    }

    async fn stats(&self, stream: &StreamId) -> asterius_store_pg::StreamStats {
        self.streams()
            .stats(&ClientId::new(RECEIVER), stream)
            .await
            .expect("read the stream")
            .expect("the stream exists")
    }
}

macro_rules! db_test {
    ($(#[$meta:meta])* async fn $name:ident($fixture:ident, $answers:expr) $body:block) => {
        $(#[$meta])*
        #[tokio::test]
        async fn $name() {
            let Some($fixture) = Fixture::new($answers).await else {
                eprintln!("skipping {}: DATABASE_URL is not set", stringify!($name));
                return;
            };
            $body
        }
    };
}

db_test! {
    /// One queued SET becomes one `POST` carrying the credential the stream
    /// stored sealed, and the row is delivered. This is the whole path — seal,
    /// claim, deliver, ack — and the credential coming back out of the database
    /// as the receiver registered it is the half no unit test can assert.
    async fn a_queued_set_is_pushed_with_the_stored_credential(fixture, vec![Ok(202)]) {
        // Arrange
        let stream = fixture.push_stream().await;
        fixture.queue(&stream, "u-1", "set-one").await;

        // Act
        let report = fixture.worker().deliver_once().await.expect("a pass");

        // Assert
        assert_eq!(report.delivered, 1, "{report:?}");
        assert_eq!(fixture.receiver.bodies(), vec!["set-one".to_owned()]);
        assert_eq!(
            fixture.receiver.credentials(),
            vec![Some(CREDENTIAL.to_owned())],
            "SSF 1.0 §6.1.1: the credential goes on every request"
        );
        let stats = fixture.stats(&stream).await;
        assert_eq!((stats.delivered, stats.failed, stats.queue_depth), (1, 0, 0));
        assert!(stats.status.delivers());
        assert!(fixture.trail.types().contains(&EventType::SSF_SET_PUSHED));
    }
}

db_test! {
    /// Two SETs about one subject, the first of which the receiver cannot take
    /// at the first attempt. The second must not overtake it: §2.2 transmits
    /// one at a time, and a "session revoked" arriving before the event it
    /// invalidates is the failure this ordering exists to prevent.
    async fn two_events_for_one_subject_arrive_in_order_despite_a_retry(
        fixture,
        vec![Err((503, Vec::new()))]
    ) {
        // Arrange
        let stream = fixture.push_stream().await;
        fixture.queue(&stream, "u-1", "first").await;
        fixture.queue(&stream, "u-1", "second").await;
        let worker = fixture.worker();

        // Act
        let first = worker.deliver_once().await.expect("a pass");
        let second = worker.deliver_once().await.expect("a pass");
        let third = worker.deliver_once().await.expect("a pass");

        // Assert
        assert_eq!(
            first.claimed, 1,
            "the second SET was claimed beside the one being retried"
        );
        assert_eq!(first.retrying, 1);
        assert_eq!((second.delivered, third.delivered), (1, 1));
        assert_eq!(
            fixture.receiver.bodies(),
            vec!["first".to_owned(), "first".to_owned(), "second".to_owned()],
            "the second SET overtook the one being retried"
        );
    }
}

db_test! {
    /// §2.3: a receiver that refuses dead-letters the SET rather than retrying
    /// it, and §8.1.2's pause is what stops the next one being attempted at all
    /// — the backlog stays queued instead of becoming dead letters too.
    async fn a_refusal_dead_letters_the_set_and_pauses_the_stream(
        fixture,
        vec![Err((400, br#"{"err":"invalid_audience","description":"not mine"}"#.to_vec()))]
    ) {
        // Arrange. The second SET is queued *after* the first pass on purpose:
        // deliveries within one batch run concurrently — the claim query has
        // already made them ordering-disjoint — so two rows claimed together
        // would both be posted before either could pause anything. What is
        // asserted here is the next SET, which is the one a pause exists to
        // stop.
        let stream = fixture.push_stream().await;
        fixture.queue(&stream, "u-1", "first").await;
        let worker = fixture.worker();

        // Act
        let first = worker.deliver_once().await.expect("a pass");
        fixture.queue(&stream, "u-2", "second").await;
        let second = worker.deliver_once().await.expect("a pass");

        // Assert
        assert!(first.abandoned >= 1, "§2.4: a 4xx was retried: {first:?}");
        assert_eq!(second.retrying, 1, "the next SET was not held: {second:?}");
        let stats = fixture.stats(&stream).await;
        assert!(!stats.status.delivers(), "the stream kept delivering");
        assert!(
            stats.reason.as_deref().unwrap_or_default().contains("invalid_audience"),
            "the pause must record which refusal stopped the stream: {stats:?}"
        );
        assert!(fixture.trail.types().contains(&EventType::SSF_PUSH_REFUSED));
        assert!(fixture.trail.types().contains(&EventType::SSF_STREAM_PAUSED));
        assert_eq!(
            fixture.receiver.bodies(),
            vec!["first".to_owned()],
            "a paused stream was posted to again"
        );
    }
}
