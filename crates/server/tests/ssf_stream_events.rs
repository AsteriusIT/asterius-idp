//! A receiver's view of the two SETs that are about a *stream* (SSF 1.0
//! §8.1.4 and §8.1.5, `ast-0ju.5`).
//!
//! The unit tests beside the transmitter assert what it queues. This file
//! asserts what a *receiver* sees, doing what a receiver does and nothing the
//! transmitter can help it with: it takes the compact serialisation off the
//! queue, fetches the tenant's published JWKS, resolves the `kid`, verifies
//! the signature under a policy of its own, and then compares the claims with
//! the examples in §8.1.4 and §8.1.5 member by member.
//!
//! That order matters. A test that read the claims without verifying would
//! pass for a SET no receiver could accept — an unsigned one, one typed
//! `JWT`, one signed by a key the tenant does not publish — and those are
//! exactly the ways a transmitter breaks its receivers quietly.
//!
//! The two events are checked together because they are the same shape and
//! the same decision: `sub_id` is the *stream*, as an `opaque` identifier, so
//! neither SET names a person, and neither is filtered by `events_requested`
//! or by the stream's subject membership.

use asterius_domain::keys::KeyStore as _;
use asterius_domain::outbox::QueuedEvent;
use asterius_domain::{DomainError, Issuer, SectorIdentifier, TenantId, UserId};
use asterius_jose::verify::{Policy, TypRule, Verified};
use asterius_jose::{LocalKeyStore, client_keys};
use asterius_server::ssf::{PolledSet, SsfQueues, SsfTransmitter};
use asterius_ssf::stream::{StreamId, StreamStatus};
use asterius_ssf::{STREAM_UPDATED, VERIFICATION, VerificationState};
use asterius_store_pg::{DeliveryMethod, Subscription};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use time::OffsetDateTime;

const ISSUER: &str = "https://as.example/t/demo";
const AUDIENCE: &str = "https://receiver.example/events";
const RECEIVER: &str = "receiver";

fn tenant() -> TenantId {
    TenantId::new("demo")
}

fn issuer() -> Issuer {
    Issuer::parse(ISSUER).expect("an issuer")
}

fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("a fixed instant")
}

// ---------------------------------------------------------------------------
// The transmitter side: the real one, with an in-memory queue
// ---------------------------------------------------------------------------

/// The queue, holding whatever was put on it.
#[derive(Debug, Default)]
struct Queue {
    polled: Mutex<Vec<String>>,
    pushed: Mutex<Vec<QueuedEvent>>,
}

#[async_trait::async_trait]
impl SsfQueues for Queue {
    async fn subscribed(&self, _event: &str) -> Result<Vec<Subscription>, DomainError> {
        // Nothing subscribed to anything. Both events must still be queued:
        // §8.1.4 and §8.1.5 bypass `events_requested`.
        Ok(Vec::new())
    }

    async fn queue_poll(
        &self,
        sets: &[PolledSet<'_>],
        _now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        let mut polled = self.polled.lock().expect("not poisoned");
        for set in sets {
            polled.push(set.jws.to_owned());
        }
        Ok(())
    }

    async fn queue_push(
        &self,
        events: &[QueuedEvent],
        _now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        self.pushed
            .lock()
            .expect("not poisoned")
            .extend_from_slice(events);
        Ok(())
    }
}

/// The receivers, as the transmitter's port sees them. Neither event under
/// test consults this — that is the point — so it answers nothing.
#[derive(Debug)]
struct NoClients;

#[async_trait::async_trait]
impl asterius_domain::ClientRepository for NoClients {
    async fn find(
        &self,
        _client: &asterius_domain::ClientId,
    ) -> Result<Option<asterius_domain::Client>, DomainError> {
        Ok(None)
    }
}

/// The subject resolver. Same reason: a SET about a stream names no person.
#[derive(Debug)]
struct NoSubjects;

#[async_trait::async_trait]
impl asterius_domain::ports::SubjectResolver for NoSubjects {
    async fn subject(
        &self,
        _user: UserId,
        _sector: &SectorIdentifier,
    ) -> Result<asterius_domain::SubjectId, DomainError> {
        Err(DomainError::invalid(
            "subject",
            "a SET about a stream must not derive a subject",
        ))
    }
}

fn subscription(stream: &StreamId) -> Subscription {
    Subscription {
        stream_id: stream.clone(),
        receiver: asterius_domain::ClientId::new(RECEIVER),
        audience: vec![AUDIENCE.to_owned()],
        delivery: DeliveryMethod::Poll,
    }
}

// ---------------------------------------------------------------------------
// The receiver side: what an Event Receiver actually does with a SET
// ---------------------------------------------------------------------------

/// A receiver holding one transmitter's published keys.
struct Receiver {
    jwks: Value,
}

impl Receiver {
    /// Fetches the transmitter's JWKS, as §7.1's `jwks_uri` would serve it.
    async fn fetching(keys: &LocalKeyStore) -> Self {
        let published = keys
            .published_keys(&tenant())
            .await
            .expect("the tenant's published keys");
        let entries: Vec<Value> = published
            .into_iter()
            .map(|record| record.public_jwk)
            .collect();
        Self {
            jwks: json!({ "keys": entries }),
        }
    }

    /// Accepts a SET the way a receiver must: typing, algorithm, signature,
    /// issuer, audience — then the claims.
    ///
    /// RFC 8417 §2 gives a SET no `exp`, and SSF 1.0 §4.1.7 says this
    /// transmitter emits none, so the policy says so explicitly rather than
    /// letting the default reject every SET it is handed.
    fn accept(&self, jws: &str) -> Verified {
        let resolver = client_keys::keys_from_jwk_set(&self.jwks).expect("a readable JWKS");
        let policy = Policy::new(
            TypRule::Exactly("secevent+jwt"),
            vec![asterius_domain::SigningAlgorithm::EdDsa],
        )
        .issued_by(ISSUER)
        .for_audience(AUDIENCE)
        .without_expiry();
        asterius_jose::verify(jws, &policy, &resolver, now()).expect("a SET a receiver accepts")
    }

    /// The one event in the SET: its type URI and its payload (§4.2.1).
    fn single_event(verified: &Verified) -> (String, Value) {
        let events = verified
            .claims
            .get("events")
            .and_then(Value::as_object)
            .expect("an events claim");
        assert_eq!(events.len(), 1, "SSF 1.0 §4.2.1: exactly one event");
        let (uri, payload) = events.iter().next().expect("the one event");
        (uri.clone(), payload.clone())
    }

    /// The checks §4 makes of every SET, whichever event it carries.
    fn assert_envelope(verified: &Verified, stream: &StreamId) {
        let claims = &verified.claims;
        assert_eq!(claims["iss"], json!(ISSUER), "§4.1.6");
        assert_eq!(claims["aud"], json!(AUDIENCE), "§4.1.3");
        assert!(
            claims.get("jti").and_then(Value::as_str).is_some(),
            "§4.1.1"
        );
        assert_eq!(claims["iat"], json!(now().unix_timestamp()), "§4.1.5");
        // §4.1.2: a SET carries `sub_id`, never `sub`.
        assert!(claims.get("sub").is_none(), "§4.1.2");
        // §4.1.7: no `exp` on a SET.
        assert!(claims.get("exp").is_none(), "§4.1.7");
        // §8.1.4 and §8.1.5: the subject is the stream, opaquely.
        assert_eq!(
            claims["sub_id"],
            json!({"format": "opaque", "id": stream.as_str()}),
        );
    }
}

/// The transmitter, its queue and the key the receiver will verify against.
struct Fixture {
    keys: Arc<LocalKeyStore>,
    queue: Arc<Queue>,
}

impl Fixture {
    fn new() -> Self {
        let keys = Arc::new(LocalKeyStore::new());
        keys.generate(&tenant(), asterius_domain::SigningAlgorithm::EdDsa)
            .expect("a tenant signing key");
        Self {
            keys,
            queue: Arc::new(Queue::default()),
        }
    }

    /// The one SET on the poll queue.
    fn queued(&self) -> String {
        let polled = self.queue.polled.lock().expect("not poisoned");
        assert_eq!(polled.len(), 1, "exactly one SET was queued");
        polled[0].clone()
    }

    async fn verify(&self, stream: &StreamId, state: Option<&VerificationState>) {
        let clients = NoClients;
        let subjects = NoSubjects;
        let transmitter = SsfTransmitter {
            tenant: &tenant(),
            issuer: &issuer(),
            queues: self.queue.as_ref(),
            clients: &clients,
            subjects: &subjects,
            signer: self.keys.as_ref(),
        };
        transmitter
            .verify(&subscription(stream), state, now())
            .await
            .expect("the verification event was queued");
    }

    async fn announce(&self, stream: &StreamId, status: StreamStatus, reason: Option<&str>) {
        let clients = NoClients;
        let subjects = NoSubjects;
        let transmitter = SsfTransmitter {
            tenant: &tenant(),
            issuer: &issuer(),
            queues: self.queue.as_ref(),
            clients: &clients,
            subjects: &subjects,
            signer: self.keys.as_ref(),
        };
        transmitter
            .announce_status(&subscription(stream), status, reason, now())
            .await
            .expect("the stream-updated event was queued");
    }
}

// ---------------------------------------------------------------------------
// §8.1.4 — the verification event
// ---------------------------------------------------------------------------

/// §8.1.4's example, verified end to end: a receiver fetches the JWKS,
/// accepts the SET, and finds the `state` it sent, byte for byte.
#[tokio::test]
async fn a_receiver_accepts_the_verification_event_of_section_8_1_4() {
    // Arrange
    let fixture = Fixture::new();
    let receiver = Receiver::fetching(&fixture.keys).await;
    let stream = StreamId::generate();
    let state =
        VerificationState::parse("VGhpcyBpcyBhbiBleGFtcGxlIHN0YXRlIHZhbHVlLgo=").expect("a state");

    // Act
    fixture.verify(&stream, Some(&state)).await;
    let verified = receiver.accept(&fixture.queued());

    // Assert
    Receiver::assert_envelope(&verified, &stream);
    let (uri, payload) = Receiver::single_event(&verified);
    assert_eq!(uri, VERIFICATION);
    assert_eq!(
        payload,
        json!({"state": "VGhpcyBpcyBhbiBleGFtcGxlIHN0YXRlIHZhbHVlLgo="}),
    );
}

/// §8.1.4's `state` is OPTIONAL, and a receiver validating the event against
/// its schema must not meet a `state: null` it did not ask for.
#[tokio::test]
async fn a_verification_event_without_a_state_carries_an_empty_payload() {
    // Arrange
    let fixture = Fixture::new();
    let receiver = Receiver::fetching(&fixture.keys).await;
    let stream = StreamId::generate();

    // Act
    fixture.verify(&stream, None).await;
    let verified = receiver.accept(&fixture.queued());

    // Assert
    let (uri, payload) = Receiver::single_event(&verified);
    assert_eq!(uri, VERIFICATION);
    assert_eq!(payload, json!({}));
}

// ---------------------------------------------------------------------------
// §8.1.5 — the stream-updated event
// ---------------------------------------------------------------------------

/// §8.1.5's example: `status` and `reason`, about the stream itself.
#[tokio::test]
async fn a_receiver_accepts_the_stream_updated_event_of_section_8_1_5() {
    // Arrange
    let fixture = Fixture::new();
    let receiver = Receiver::fetching(&fixture.keys).await;
    let stream = StreamId::generate();

    // Act
    fixture
        .announce(
            &stream,
            StreamStatus::Paused,
            Some("Disabled by administrator action."),
        )
        .await;
    let verified = receiver.accept(&fixture.queued());

    // Assert
    Receiver::assert_envelope(&verified, &stream);
    let (uri, payload) = Receiver::single_event(&verified);
    assert_eq!(uri, STREAM_UPDATED);
    assert_eq!(
        payload,
        json!({
            "status": "paused",
            "reason": "Disabled by administrator action.",
        }),
    );
}

/// The re-enable §8.1.5 also requires: the same event, the new status, and no
/// leftover reason from the pause it ends.
#[tokio::test]
async fn a_receiver_is_told_when_a_stream_is_enabled_again() {
    // Arrange
    let fixture = Fixture::new();
    let receiver = Receiver::fetching(&fixture.keys).await;
    let stream = StreamId::generate();

    // Act
    fixture.announce(&stream, StreamStatus::Enabled, None).await;
    let verified = receiver.accept(&fixture.queued());

    // Assert
    let (uri, payload) = Receiver::single_event(&verified);
    assert_eq!(uri, STREAM_UPDATED);
    assert_eq!(payload, json!({"status": "enabled"}));
}

/// A receiver is not offered a SET signed by a key the transmitter does not
/// publish — which is what makes the two tests above evidence rather than a
/// reading of a JSON blob.
#[tokio::test]
async fn a_set_signed_by_an_unpublished_key_is_refused_by_the_receiver() {
    // Arrange
    let fixture = Fixture::new();
    let stranger = LocalKeyStore::new();
    stranger
        .generate(&tenant(), asterius_domain::SigningAlgorithm::EdDsa)
        .expect("another key");
    let receiver = Receiver::fetching(&stranger).await;
    let stream = StreamId::generate();

    // Act
    fixture.verify(&stream, None).await;
    let jws = fixture.queued();
    let resolver = client_keys::keys_from_jwk_set(&receiver.jwks).expect("a readable JWKS");
    let policy = Policy::new(
        TypRule::Exactly("secevent+jwt"),
        vec![asterius_domain::SigningAlgorithm::EdDsa],
    )
    .issued_by(ISSUER)
    .for_audience(AUDIENCE)
    .without_expiry();

    // Assert
    assert!(
        asterius_jose::verify(&jws, &policy, &resolver, now()).is_err(),
        "a receiver accepted a SET signed by a key the transmitter never published"
    );
}
