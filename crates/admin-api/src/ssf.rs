//! The Shared Signals screen: streams, their state, and the two things an
//! operator may do to one (`ast-f7m.8`).
//!
//! Three routes. `GET /ssf/streams` lists every stream of the tenant with
//! SSF 1.0 §8.1.2's status, this server's reason for it, the delivery
//! counters and the queue depth; `PUT /ssf/streams/{stream_id}/status`
//! pauses or re-enables one; `POST /ssf/streams/{stream_id}/verification`
//! sends it §8.1.4's verification event. The dead-letter side — retry and
//! drop — is in [`crate::outbox`], because a dead letter is an outbox row
//! before it is an SSF one.
//!
//! # What an operator is and is not shown
//!
//! A stream is a receiver's standing arrangement to be told about this
//! tenant's users, and the operator of the tenant may see every one of them
//! — that is what `admin.ssf:read` means, and why the listing has no
//! `client_id` in its predicate where the management API has one in every
//! statement. What the listing does **not** carry is the receiver's push
//! endpoint or its credential: the endpoint may hold a token in its query
//! string, the credential is sealed for a reason, and neither is needed to
//! answer "is this receiver taking anything". See
//! [`StreamSummary`].
//!
//! # Why the status route is an operator's and not the receiver's
//!
//! §8.1.2 gives the receiver its own status endpoint; that is `ast-0ju.4`
//! and it is not in this build. This route exists because the *worker*
//! pauses a stream (`ast-0ju.6`) and until now nothing but an `UPDATE` in
//! SQL could re-enable it. It writes `enabled` and `paused` and nothing
//! else: `disabled` is a receiver's decision about its own stream, and an
//! operator who wants a stream gone deletes the receiver.
//!
//! # The verification event is the receiver's, sent early
//!
//! The SET this route queues is byte-for-byte the one §8.1.4 defines — see
//! [`asterius_ssf::verification`] — so a receiver that handles a
//! verification it asked for handles this one. What is different is who
//! asked. The `state` an operator types is placed in the token verbatim
//! and is therefore parsed as a value that will be signed: bounded, no
//! control characters, never echoed by a refusal, never written to the
//! trail.

use asterius_domain::{ClientId, DomainError, TenantId};
use asterius_ssf::stream::{StreamId, StreamStatus};
use asterius_ssf::verification::VerificationState;
use serde::Deserialize;
use serde_json::{Value, json};
use std::fmt::Debug;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::error::AdminError;

/// The longest reason an operator may attach to a pause, in characters.
///
/// The column is unbounded text and the worker's own reasons are under a
/// hundred characters. A reason is rendered on the screen beside the
/// stream and read back by the receiver the day `ast-0ju.4` lands, so it is
/// bounded like the other free text this API accepts.
pub const MAX_REASON_LEN: usize = 256;

/// The largest body either mutation reads, before the shared limit.
///
/// A status and a reason, or a `state`: a few hundred bytes. The bound is
/// what stops a caller sending a megabyte for the parser to reject.
pub const MAX_BODY_BYTES: usize = 4 * 1024;

/// What the admin API needs from the deployment's SSF side.
///
/// A port in this crate rather than a method on the streams repository,
/// because `scripts/check-layering.sh` will not let this crate reach the
/// adapter that holds it — and because the verification event has to be
/// *signed*, which is the composition root's transmitter and not a
/// repository call. The implementation is
/// `asterius_server::admin::Deployment`.
#[async_trait::async_trait]
pub trait SsfAdministration: Debug + Send + Sync {
    /// Every stream of the tenant, oldest first.
    ///
    /// # Errors
    ///
    /// [`DomainError`] if the streams cannot be read.
    async fn streams(&self, tenant: &TenantId) -> Result<Vec<StreamSummary>, DomainError>;

    /// Writes a stream's status and reason (§8.1.2). `false` is "no such
    /// stream".
    ///
    /// # Errors
    ///
    /// [`DomainError`] if the write fails.
    async fn set_status(
        &self,
        tenant: &TenantId,
        stream: &StreamId,
        status: StreamStatus,
        reason: Option<&str>,
        now: OffsetDateTime,
    ) -> Result<bool, DomainError>;

    /// Signs and queues §8.1.4's verification event on the stream's own
    /// queue. `false` is "no such stream".
    ///
    /// # Errors
    ///
    /// [`DomainError`] if the SET cannot be built, signed or queued.
    async fn verify(
        &self,
        tenant: &TenantId,
        stream: &StreamId,
        state: Option<&VerificationState>,
        now: OffsetDateTime,
    ) -> Result<bool, DomainError>;
}

/// One stream, as the console lists it.
///
/// No endpoint and no credential, by construction: there is no field for
/// either, so a renderer cannot leak what it was never handed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamSummary {
    /// The stream.
    pub stream_id: StreamId,
    /// The receiver it belongs to.
    pub receiver: ClientId,
    /// The delivery method URN: `urn:ietf:rfc:8935` (push) or
    /// `urn:ietf:rfc:8936` (poll).
    pub delivery_method: &'static str,
    /// §8.1.1's `events_requested`.
    pub events_requested: Vec<String>,
    /// §8.1.1's `description`.
    pub description: Option<String>,
    /// When the receiver created it.
    pub created_at: OffsetDateTime,
    /// §8.1.2's status.
    pub status: StreamStatus,
    /// Why it is not enabled, in this server's or an operator's words.
    pub reason: Option<String>,
    /// When the status last changed.
    pub status_changed_at: Option<OffsetDateTime>,
    /// SETs the receiver accepted, since creation.
    pub delivered: i64,
    /// Deliveries that failed, retries included.
    pub failed: i64,
    /// SETs still owed on the outbox.
    pub queue_depth: i64,
}

/// Renders one stream.
#[must_use]
pub fn document(stream: &StreamSummary) -> Value {
    json!({
        "stream_id": stream.stream_id.as_str(),
        "receiver": stream.receiver.as_str(),
        "delivery_method": stream.delivery_method,
        "events_requested": stream.events_requested,
        "description": stream.description,
        "created_at": timestamp(stream.created_at),
        "status": stream.status.as_str(),
        "reason": stream.reason,
        "status_changed_at": stream.status_changed_at.map(timestamp),
        "delivered": stream.delivered,
        "failed": stream.failed,
        "queue_depth": stream.queue_depth,
    })
}

/// RFC 3339, or the epoch if the value cannot be formatted — unreachable for
/// a `timestamptz`, and a screen that fails over one odd timestamp is worse
/// than one showing a wrong date beside a real stream.
fn timestamp(at: OffsetDateTime) -> String {
    at.format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned())
}

/// What `PUT /ssf/streams/{stream_id}/status` takes, as it arrives.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawStatusRequest {
    status: String,
    #[serde(default)]
    reason: Option<String>,
}

/// A status change an operator asked for, after validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusRequest {
    /// `enabled` or `paused`, and never `disabled`.
    pub status: StreamStatus,
    /// The operator's reason. Dropped for `enabled`, which has none.
    pub reason: Option<String>,
}

/// Reads a status request out of a body.
///
/// # Errors
///
/// [`AdminError::Invalid`] for a body that is not the document, a status
/// other than `enabled` or `paused`, or a reason that is empty, over
/// [`MAX_REASON_LEN`] characters or carries a control character. No message
/// echoes the body.
// fuzz-target: admin_stream_status
pub fn parse_status_request(body: &[u8]) -> Result<StatusRequest, AdminError> {
    let raw: RawStatusRequest = serde_json::from_slice(body).map_err(|error| {
        AdminError::Invalid(format!(
            "the request body is not a status document: {}",
            error.classify_for_operator()
        ))
    })?;
    let status = match StreamStatus::parse(&raw.status) {
        Some(status @ (StreamStatus::Enabled | StreamStatus::Paused)) => status,
        // `disabled` is a stream status (§8.1.2) and not one an operator
        // writes: see the module documentation.
        Some(StreamStatus::Disabled) | None => {
            return Err(AdminError::Invalid(
                "status must be enabled or paused".to_owned(),
            ));
        }
    };
    let reason = match (status, raw.reason) {
        (StreamStatus::Enabled, _) | (_, None) => None,
        (_, Some(reason)) => Some(accept_reason(&reason)?),
    };
    Ok(StatusRequest { status, reason })
}

fn accept_reason(reason: &str) -> Result<String, AdminError> {
    let reason = reason.trim();
    if reason.is_empty() {
        return Err(AdminError::Invalid(
            "reason must not be empty when given".to_owned(),
        ));
    }
    if reason.chars().count() > MAX_REASON_LEN {
        return Err(AdminError::Invalid(format!(
            "reason is longer than {MAX_REASON_LEN} characters"
        )));
    }
    if reason.chars().any(char::is_control) {
        return Err(AdminError::Invalid(
            "reason must not carry a control character".to_owned(),
        ));
    }
    Ok(reason.to_owned())
}

/// What `POST /ssf/streams/{stream_id}/verification` takes.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawVerificationRequest {
    #[serde(default)]
    state: Option<String>,
}

/// Reads the optional `state` out of a verification request body.
///
/// An empty body is a request with no `state`, because a button that sends
/// nothing is the common case and a 400 for it would be a screen that
/// cannot verify without typing something.
///
/// # Errors
///
/// [`AdminError::Invalid`] for a body that is not the document or a `state`
/// [`VerificationState::parse`] refuses. The message names the rule and
/// never the value.
pub fn parse_verification_request(body: &[u8]) -> Result<Option<VerificationState>, AdminError> {
    if body.iter().all(u8::is_ascii_whitespace) {
        return Ok(None);
    }
    let raw: RawVerificationRequest = serde_json::from_slice(body).map_err(|error| {
        AdminError::Invalid(format!(
            "the request body is not a verification document: {}",
            error.classify_for_operator()
        ))
    })?;
    raw.state
        .as_deref()
        .map(|state| {
            VerificationState::parse(state).map_err(|error| AdminError::Invalid(error.to_string()))
        })
        .transpose()
}

/// What a `serde_json` error may say to an operator.
///
/// The error's `Display` quotes the offending token for some failures, and
/// the body is text somebody typed; the category is enough to act on.
trait ClassifyForOperator {
    fn classify_for_operator(&self) -> &'static str;
}

impl ClassifyForOperator for serde_json::Error {
    fn classify_for_operator(&self) -> &'static str {
        match self.classify() {
            serde_json::error::Category::Io | serde_json::error::Category::Eof => {
                "the body ended early"
            }
            serde_json::error::Category::Syntax => "the body is not JSON",
            serde_json::error::Category::Data => {
                "the body carries a member the document does not have, or one of the wrong type"
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn summary() -> StreamSummary {
        StreamSummary {
            stream_id: StreamId::parse("stream-0000000000000000000000000000").expect("a stream id"),
            receiver: ClientId::new("billing"),
            delivery_method: asterius_ssf::stream::DELIVERY_PUSH,
            events_requested: vec![asterius_ssf::caep::SESSION_REVOKED.to_owned()],
            description: Some("billing's stream".to_owned()),
            created_at: OffsetDateTime::UNIX_EPOCH,
            status: StreamStatus::Paused,
            reason: Some("the receiver answered 400".to_owned()),
            status_changed_at: Some(OffsetDateTime::UNIX_EPOCH + time::Duration::hours(1)),
            delivered: 40,
            failed: 3,
            queue_depth: 2,
        }
    }

    /// What the screen is for: the state, the reason, and the three numbers.
    #[test]
    fn a_stream_document_carries_state_reason_and_counters() {
        // Arrange
        let stream = summary();

        // Act
        let rendered = document(&stream);

        // Assert
        assert_eq!(rendered["status"], "paused");
        assert_eq!(rendered["reason"], "the receiver answered 400");
        assert_eq!(rendered["delivered"], 40);
        assert_eq!(rendered["failed"], 3);
        assert_eq!(rendered["queue_depth"], 2);
        assert_eq!(rendered["receiver"], "billing");
        assert_eq!(rendered["status_changed_at"], "1970-01-01T01:00:00Z");
    }

    /// The type has no endpoint and no credential field, so this asserts on
    /// the serialized member set: one added later that carried either would
    /// fail here rather than reach a screen.
    #[test]
    fn a_stream_document_has_no_endpoint_and_no_credential() {
        // Arrange / Act
        let rendered = document(&summary());
        let members: Vec<_> = rendered
            .as_object()
            .expect("an object")
            .keys()
            .map(String::as_str)
            .collect();

        // Assert
        assert_eq!(
            members,
            vec![
                "created_at",
                "delivered",
                "delivery_method",
                "description",
                "events_requested",
                "failed",
                "queue_depth",
                "reason",
                "receiver",
                "status",
                "status_changed_at",
                "stream_id",
            ]
        );
    }

    #[test]
    fn a_pause_with_a_reason_is_accepted_trimmed() {
        // Arrange / Act
        let request = parse_status_request(br#"{"status":"paused","reason":"  maintenance  "}"#)
            .expect("accepted");

        // Assert
        assert_eq!(request.status, StreamStatus::Paused);
        assert_eq!(request.reason.as_deref(), Some("maintenance"));
    }

    /// An enabled stream has no reason: whatever was sent is dropped rather
    /// than stored beside a delivering stream.
    #[test]
    fn enabling_discards_the_reason() {
        // Arrange / Act
        let request =
            parse_status_request(br#"{"status":"enabled","reason":"fixed"}"#).expect("accepted");

        // Assert
        assert_eq!(request.status, StreamStatus::Enabled);
        assert_eq!(request.reason, None);
    }

    /// `disabled` is §8.1.2's third state and is the receiver's, not the
    /// operator's.
    #[test]
    fn disabled_and_unknown_statuses_are_refused() {
        for status in ["disabled", "stopped", ""] {
            let body = format!(r#"{{"status":"{status}"}}"#);
            let error = parse_status_request(body.as_bytes()).expect_err("refused");
            assert!(matches!(error, AdminError::Invalid(_)), "{status}");
        }
    }

    #[test]
    fn a_reason_that_is_empty_over_long_or_control_carrying_is_refused() {
        // Arrange
        let long = "r".repeat(MAX_REASON_LEN + 1);
        let bodies = [
            r#"{"status":"paused","reason":"   "}"#.to_owned(),
            format!(r#"{{"status":"paused","reason":"{long}"}}"#),
            r#"{"status":"paused","reason":"a b"}"#.to_owned(),
        ];

        // Act / Assert
        for body in bodies {
            assert!(parse_status_request(body.as_bytes()).is_err(), "{body}");
        }
    }

    /// An unknown member is a 400 and not a silent drop: `{"staus": …}`
    /// changing nothing while answering 200 would be the worse outcome.
    #[test]
    fn an_unknown_member_or_a_non_document_is_refused_without_echo() {
        for body in [
            br#"{"status":"paused","secret":"xyzzy"}"#.as_slice(),
            b"xyzzy".as_slice(),
            b"[]".as_slice(),
        ] {
            let error = parse_status_request(body).expect_err("refused");
            assert!(!error.to_string().contains("xyzzy"));
        }
    }

    #[test]
    fn a_verification_request_may_be_empty_or_carry_a_state() {
        // Arrange / Act
        let none = parse_verification_request(b"").expect("empty is fine");
        let object = parse_verification_request(b"{}").expect("an empty object is fine");
        let some = parse_verification_request(br#"{"state":"abc"}"#).expect("a state");

        // Assert
        assert_eq!(none, None);
        assert_eq!(object, None);
        assert_eq!(
            some.map(|state| state.as_str().to_owned()),
            Some("abc".to_owned())
        );
    }

    #[test]
    fn a_verification_state_the_profile_refuses_is_a_400_without_echo() {
        // Arrange / Act
        let error = parse_verification_request(br#"{"state":"xyzzy\n"}"#).expect_err("refused");

        // Assert
        assert!(matches!(error, AdminError::Invalid(_)));
        assert!(!error.to_string().contains("xyzzy"));
    }
}
