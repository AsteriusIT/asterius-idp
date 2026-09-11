//! Stream status and subject membership: SSF 1.0 §8.1.2 and §8.1.3.
//!
//! The two management endpoints that are not the stream configuration itself.
//! §8.1.2 is what a stream is *doing* — `enabled`, `paused` or `disabled` —
//! and §8.1.3 is *whose* events it carries. Like [`crate::stream`], this
//! module holds the protocol and nothing else: it parses a receiver's request
//! and renders the object it reads back, reaches no database, authenticates
//! nobody, and makes no HTTP decision.
//!
//! # The three statuses are three different promises (§8.1.2)
//!
//! > `enabled`: the Transmitter MUST transmit events over the stream […]
//! > `paused`: the Transmitter MUST NOT transmit events over the stream. The
//! > Transmitter SHOULD hold any events it would have transmitted while
//! > paused, and transmit them when the stream becomes enabled […]
//! > `disabled`: the Transmitter MUST NOT transmit events over the stream, and
//! > will not hold any events.
//!
//! [`StreamStatus::delivers`] and [`StreamStatus::holds`] are those three
//! sentences as two questions, so that the enqueue guard and the delivery read
//! cannot disagree about what `paused` means. The type itself lives in
//! [`crate::stream`], where push delivery already writes it: one enum, because
//! two spellings of three states would be two things a stored row could mean.
//!
//! A held queue is bounded — [`MAX_HELD_WHILE_PAUSED`] — because "SHOULD hold"
//! against an unbounded store is a receiver that pauses a stream and fills a
//! tenant's database. What the bound costs is written down there.
//!
//! # Ordering per subject
//!
//! §8.1.2 requires that events held while paused be transmitted "in the order
//! in which they occurred, per subject". This module does not order anything —
//! the queue does — but the rule is the reason the queue is read oldest-first
//! and never re-sorted per delivery: a global order by the instant an event
//! was queued is an order per subject as well, and it is the only one that
//! needs no per-subject bookkeeping to be right.
//!
//! # Why a subject request carries `verified` and this transmitter ignores it
//!
//! §8.1.3.2 lets a receiver assert that it has verified the subject it is
//! adding. The member is parsed — a receiver that sends it must not be
//! refused — and it grants nothing: what a receiver may hear about is decided
//! by the subject matching of §8.1.3.1 against this tenant's own events, never
//! by a boolean the caller set. See `docs/threat-model.md`.

use crate::stream::{StreamId, StreamStatus};
use crate::subject::{Subject, SubjectError};
use serde_json::{Map, Value};
use thiserror::Error;

/// The longest `reason` this transmitter stores or echoes (§8.1.2.2).
///
/// 256 characters, as [`crate::stream::MAX_DESCRIPTION_LEN`]: it is receiver
/// text kept beside a stream and read back by whoever can read the stream, and
/// the two have the same shape and the same risk.
pub const MAX_REASON_LEN: usize = 256;

/// How many events a paused stream holds before it stops holding more.
///
/// §8.1.2 says a paused transmitter SHOULD hold what it would have sent. It
/// does not say for how many, and an unbounded answer is a receiver that
/// pauses one stream and fills the tenant's database — with subject
/// identifiers, which is the one thing this crate's threat model says not to
/// keep longer than the signal is useful.
///
/// So: ten thousand, and then the *newest* event is dropped rather than the
/// oldest. Dropping the oldest would let a flood of new events silently evict
/// the signals a receiver most needs to rebuild its state — the revocation
/// that happened first — and would do it in the order that makes the queue
/// look healthy. Dropping the newest keeps the held prefix an ordered,
/// truthful record of what happened after the pause, and the drop is counted
/// and recorded rather than silent.
pub const MAX_HELD_WHILE_PAUSED: usize = 10_000;

/// Why a status or subject request was refused.
///
/// Every variant names a member and never echoes its value: a `reason` is
/// receiver text and a subject identifier is personal data, and these strings
/// reach both a log and a response body.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ManagementError {
    /// The body is not a JSON object.
    #[error("this request must be a JSON object")]
    NotAnObject,
    /// A member is present with the wrong JSON type.
    #[error("`{member}` is not of the type SSF 1.0 gives it")]
    WrongType {
        /// The member's name. A constant from this module, never a value.
        member: &'static str,
    },
    /// A member is present but too long.
    #[error("`{member}` is longer than this transmitter accepts")]
    TooLong {
        /// The member's name.
        member: &'static str,
    },
    /// `stream_id` is missing, which §8.1.2.2, §8.1.3.2 and §8.1.3.3 all make
    /// REQUIRED.
    #[error("`stream_id` is required on this request")]
    MissingStreamId,
    /// `status` is missing on a §8.1.2.2 request.
    #[error("`status` is required on a status change")]
    MissingStatus,
    /// `status` names a state §8.1.2 does not define.
    #[error("`status` must be one of enabled, paused or disabled")]
    UnknownStatus,
    /// `subject` is missing on a §8.1.3.2 or §8.1.3.3 request.
    #[error("`subject` is required on this request")]
    MissingSubject,
    /// `subject` is not a usable subject identifier.
    #[error("`subject` is not a subject identifier this transmitter reads: {0}")]
    Subject(#[from] SubjectError),
}

/// A §8.1.2.2 request: change this stream's status.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct StatusRequest {
    /// §8.1.2.2's `stream_id`. REQUIRED, read through
    /// [`StatusRequest::addressed_stream`].
    pub stream_id: Option<StreamId>,
    /// §8.1.2.2's `status`.
    pub status: StreamStatus,
    /// §8.1.2.2's `reason`: why the receiver asked. Kept and read back at
    /// §8.1.2.1, because a paused stream nobody can explain is an incident
    /// nobody can close.
    pub reason: Option<String>,
}

impl StatusRequest {
    /// Parses one status change body (§8.1.2.2).
    ///
    /// Unknown members are ignored, as §8.1.1's object is extensible and this
    /// one is no different. A *known* member of the wrong type is refused: a
    /// `status` that is not a string is a receiver meaning something this
    /// transmitter would get wrong, and getting it wrong here is either a
    /// stream that keeps delivering after a receiver stopped it or one that
    /// stops without being asked.
    ///
    /// # Errors
    ///
    /// [`ManagementError`] for anything §8.1.2.2 answers 400 to.
    // fuzz-target: ssf_stream_management
    pub fn parse(body: &Value) -> Result<Self, ManagementError> {
        let object = body.as_object().ok_or(ManagementError::NotAnObject)?;
        let status = object
            .get("status")
            .ok_or(ManagementError::MissingStatus)?
            .as_str()
            .ok_or(ManagementError::WrongType { member: "status" })?;
        let status = StreamStatus::parse(status).ok_or(ManagementError::UnknownStatus)?;
        Ok(Self {
            stream_id: addressed(object)?,
            status,
            reason: reason(object)?,
        })
    }

    /// The stream this request addresses.
    ///
    /// # Errors
    ///
    /// [`ManagementError::MissingStreamId`] — §8.1.2.2 makes the member
    /// REQUIRED, and a request without it addresses no stream at all.
    pub fn addressed_stream(&self) -> Result<&StreamId, ManagementError> {
        self.stream_id
            .as_ref()
            .ok_or(ManagementError::MissingStreamId)
    }
}

/// A §8.1.3.2 or §8.1.3.3 request: add or remove one subject.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SubjectRequest {
    /// The `stream_id` both sections make REQUIRED.
    pub stream_id: Option<StreamId>,
    /// The subject identifier (§8.1.3.1's object).
    pub subject: Subject,
    /// §8.1.3.2's `verified`, as the receiver sent it.
    ///
    /// Parsed and ignored. See the module documentation: an assertion by the
    /// caller cannot be what decides which events the caller receives.
    pub verified: Option<bool>,
}

impl SubjectRequest {
    /// Parses one add-subject or remove-subject body (§8.1.3.2, §8.1.3.3).
    ///
    /// # Errors
    ///
    /// [`ManagementError`] for a body that is not one of those requests.
    // fuzz-target: ssf_stream_management
    pub fn parse(body: &Value) -> Result<Self, ManagementError> {
        let object = body.as_object().ok_or(ManagementError::NotAnObject)?;
        let subject = object
            .get("subject")
            .ok_or(ManagementError::MissingSubject)?;
        let verified = match object.get("verified") {
            None | Some(Value::Null) => None,
            Some(value) => Some(
                value
                    .as_bool()
                    .ok_or(ManagementError::WrongType { member: "verified" })?,
            ),
        };
        Ok(Self {
            stream_id: addressed(object)?,
            subject: Subject::from_json(subject)?,
            verified,
        })
    }

    /// The stream this request addresses.
    ///
    /// # Errors
    ///
    /// [`ManagementError::MissingStreamId`] — §8.1.3.2 and §8.1.3.3 both make
    /// the member REQUIRED.
    pub fn addressed_stream(&self) -> Result<&StreamId, ManagementError> {
        self.stream_id
            .as_ref()
            .ok_or(ManagementError::MissingStreamId)
    }
}

/// §8.1.2.1's and §8.1.2.2's response object.
///
/// > `stream_id`: REQUIRED […] `status`: REQUIRED […] `reason`: OPTIONAL
///
/// `reason` is omitted rather than rendered as `null` when there is none: a
/// member that is absent is one a receiver's parser does not have to have an
/// opinion about.
#[must_use]
pub fn render_status(
    stream: &StreamId,
    status: StreamStatus,
    reason: Option<&str>,
) -> Map<String, Value> {
    let mut object = Map::new();
    object.insert("stream_id".to_owned(), Value::from(stream.as_str()));
    object.insert("status".to_owned(), Value::from(status.as_str()));
    if let Some(reason) = reason {
        object.insert("reason".to_owned(), Value::from(reason));
    }
    object
}

/// The `stream_id` a management request addresses, if it names one.
fn addressed(object: &Map<String, Value>) -> Result<Option<StreamId>, ManagementError> {
    let Some(value) = object.get("stream_id") else {
        return Ok(None);
    };
    let raw = value.as_str().ok_or(ManagementError::WrongType {
        member: "stream_id",
    })?;
    // A `stream_id` that is not one this server could have issued is refused
    // here rather than looked up: it names no row, and the shape check costs a
    // length comparison where a query costs a round trip.
    Ok(Some(StreamId::parse(raw).ok_or(
        ManagementError::TooLong {
            member: "stream_id",
        },
    )?))
}

/// §8.1.2.2's `reason`, bounded.
fn reason(object: &Map<String, Value>) -> Result<Option<String>, ManagementError> {
    let Some(value) = object.get("reason") else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let text = value
        .as_str()
        .ok_or(ManagementError::WrongType { member: "reason" })?;
    if text.chars().count() > MAX_REASON_LEN {
        return Err(ManagementError::TooLong { member: "reason" });
    }
    Ok(Some(text.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::subject::SimpleSubject;
    use serde_json::json;

    fn stream_id() -> StreamId {
        StreamId::generate()
    }

    #[test]
    fn a_status_change_names_a_stream_a_state_and_a_reason() {
        // Arrange
        let stream = stream_id();
        let body = json!({
            "stream_id": stream.as_str(),
            "status": "paused",
            "reason": "maintenance window",
        });

        // Act
        let request = StatusRequest::parse(&body).expect("a status request");

        // Assert
        assert_eq!(request.addressed_stream(), Ok(&stream));
        assert_eq!(request.status, StreamStatus::Paused);
        assert_eq!(request.reason.as_deref(), Some("maintenance window"));
    }

    #[test]
    fn a_status_change_without_a_status_is_refused() {
        assert_eq!(
            StatusRequest::parse(&json!({"stream_id": stream_id().as_str()})),
            Err(ManagementError::MissingStatus)
        );
    }

    #[test]
    fn a_status_the_spec_does_not_define_is_refused() {
        assert_eq!(
            StatusRequest::parse(&json!({"status": "sleeping"})),
            Err(ManagementError::UnknownStatus)
        );
    }

    #[test]
    fn a_status_change_without_a_stream_id_addresses_nothing() {
        // Arrange
        let request = StatusRequest::parse(&json!({"status": "enabled"})).expect("a request");

        // Act & Assert
        assert_eq!(
            request.addressed_stream(),
            Err(ManagementError::MissingStreamId)
        );
    }

    #[test]
    fn an_oversized_reason_is_refused() {
        // Arrange
        let long = "r".repeat(MAX_REASON_LEN + 1);
        let body = json!({"status": "paused", "reason": long});

        // Act & Assert
        assert_eq!(
            StatusRequest::parse(&body),
            Err(ManagementError::TooLong { member: "reason" })
        );
    }

    /// §8.1.2.1's response object, and §8.1.2.2's.
    #[test]
    fn a_rendered_status_names_the_stream_the_state_and_the_reason() {
        // Arrange
        let stream = stream_id();

        // Act
        let rendered = render_status(&stream, StreamStatus::Paused, Some("no receiver"));

        // Assert
        assert_eq!(
            Value::Object(rendered),
            json!({
                "stream_id": stream.as_str(),
                "status": "paused",
                "reason": "no receiver",
            })
        );
    }

    #[test]
    fn a_status_with_no_reason_omits_the_member() {
        // Arrange
        let stream = stream_id();

        // Act
        let rendered = render_status(&stream, StreamStatus::Enabled, None);

        // Assert
        assert!(!rendered.contains_key("reason"));
    }

    /// §8.1.3.2: a stream, a subject, and the receiver's assertion about it.
    #[test]
    fn an_add_subject_request_names_a_stream_and_a_subject() {
        // Arrange
        let stream = stream_id();
        let body = json!({
            "stream_id": stream.as_str(),
            "subject": {"format": "opaque", "id": "u-1"},
            "verified": true,
        });

        // Act
        let request = SubjectRequest::parse(&body).expect("a subject request");

        // Assert
        assert_eq!(request.addressed_stream(), Ok(&stream));
        assert_eq!(
            request.subject,
            Subject::from(SimpleSubject::opaque("u-1").expect("a subject"))
        );
        assert_eq!(request.verified, Some(true));
    }

    #[test]
    fn a_subject_request_without_a_subject_is_refused() {
        assert_eq!(
            SubjectRequest::parse(&json!({"stream_id": stream_id().as_str()})),
            Err(ManagementError::MissingSubject)
        );
    }

    /// The reason the model refuses rather than shrugs: a subject it cannot
    /// read is one it cannot match, and a membership nobody can match is a
    /// receiver waiting for events that never come.
    #[test]
    fn a_subject_this_transmitter_cannot_read_is_refused() {
        // Arrange
        let body = json!({"subject": {"format": "badge_number", "id": "42"}});

        // Act
        let refusal = SubjectRequest::parse(&body);

        // Assert
        assert_eq!(
            refusal,
            Err(ManagementError::Subject(SubjectError::UnknownFormat))
        );
    }

    #[test]
    fn a_verified_member_of_the_wrong_type_is_refused() {
        // Arrange
        let body = json!({
            "subject": {"format": "opaque", "id": "u-1"},
            "verified": "yes",
        });

        // Act & Assert
        assert_eq!(
            SubjectRequest::parse(&body),
            Err(ManagementError::WrongType { member: "verified" })
        );
    }

    /// A member this revision does not define must not refuse a receiver built
    /// against a later one.
    #[test]
    fn an_unknown_member_is_ignored() {
        // Arrange
        let body = json!({
            "status": "enabled",
            "something_later": {"nested": true},
        });

        // Act
        let request = StatusRequest::parse(&body).expect("a status request");

        // Assert
        assert_eq!(request.status, StreamStatus::Enabled);
    }
}
