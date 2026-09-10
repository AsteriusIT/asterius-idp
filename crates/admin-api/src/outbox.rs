//! The dead-letter screen: deliveries this deployment has given up on.
//!
//! One read. `GET /outbox/dead-letters` lists the rows that exhausted their
//! attempt budget, newest first, so that "our logout notifications stopped
//! arriving" is a question an operator can answer without a database client.
//!
//! # What is rendered, and what is deliberately not
//!
//! The id, the kind, the attempt count, when it was queued, when it was last
//! tried, and the deliverer's own description of the last failure.
//!
//! **Not the payload and not the destination.** An abandoned
//! `notification.account_recovery` row's payload contains a live
//! password-reset link and its destination is the address of the person it was
//! for; a `logout.backchannel` row's destination is a URL that may carry a
//! query parameter its owner treats as a secret. This screen is reached with a
//! read scope, granted so that somebody can see *that* delivery is failing —
//! not so they can read the messages. Whoever is entitled to those reads the
//! database, which is a deliberate act with a record.
//!
//! The same reasoning excludes the ordering key, which is built from a subject
//! id or a session id.
//!
//! # There is no retry button
//!
//! Re-queueing is a mutation that has to decide what happens to the ordering
//! key's other rows, and a button that quietly reorders a session's events is
//! worse than no button. `asterius_domain::outbox::DeadLetterQuery` is
//! read-only for that reason.

use asterius_domain::outbox::DeadLetter;
use serde::Serialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// How many rows one request lists.
///
/// A ceiling rather than a page: the dead-letter queue of a healthy deployment
/// is empty, and one that has thousands has a systemic failure whose shape is
/// visible in the first hundred. Paginating it would be a feature for a
/// situation nobody should be in.
pub const LIMIT: u32 = 100;

/// One abandoned delivery, as the API renders it.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct DeadLetterDocument {
    /// The row's identity within the tenant.
    pub id: i64,
    /// What kind of thing failed to be delivered, e.g.
    /// `notification.account_recovery`.
    pub kind: String,
    /// The dispatch family: everything before the first `.`.
    pub family: String,
    /// How many times it was tried.
    pub attempts: u32,
    /// When it was queued, RFC 3339.
    pub created_at: String,
    /// When it was last tried, RFC 3339, or absent if no attempt was recorded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_attempt_at: Option<String>,
    /// The deliverer's description of the last failure, if there was one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

/// Renders one dead letter.
#[must_use]
pub fn summarise(letter: &DeadLetter) -> DeadLetterDocument {
    DeadLetterDocument {
        id: letter.id,
        family: letter
            .kind
            .split_once('.')
            .map_or_else(|| letter.kind.clone(), |(head, _)| head.to_owned()),
        kind: letter.kind.clone(),
        attempts: letter.attempts,
        created_at: timestamp(letter.created_at),
        last_attempt_at: letter.last_attempt_at.map(timestamp),
        last_error: letter.last_error.clone(),
    }
}

/// RFC 3339, or the epoch if the value cannot be formatted.
///
/// Unformattable is unreachable for a value read out of a `timestamptz`, and
/// a screen that returns 500 because one row's timestamp is odd is worse than
/// one that shows a wrong date beside a real failure.
fn timestamp(at: OffsetDateTime) -> String {
    at.format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn letter() -> DeadLetter {
        DeadLetter {
            id: 42,
            kind: "notification.account_recovery".to_owned(),
            attempts: 10,
            created_at: OffsetDateTime::UNIX_EPOCH,
            last_attempt_at: Some(OffsetDateTime::UNIX_EPOCH + time::Duration::hours(2)),
            last_error: Some("mail.example answered 550".to_owned()),
        }
    }

    /// The whole point of the screen: which delivery, how hard it was tried,
    /// and what the receiver said.
    #[test]
    fn a_dead_letter_carries_what_an_operator_needs_to_act() {
        // Arrange
        let row = letter();

        // Act
        let rendered = summarise(&row);

        // Assert
        assert_eq!(rendered.id, 42);
        assert_eq!(rendered.kind, "notification.account_recovery");
        assert_eq!(rendered.family, "notification");
        assert_eq!(rendered.attempts, 10);
        assert_eq!(rendered.created_at, "1970-01-01T00:00:00Z");
        assert_eq!(
            rendered.last_error.as_deref(),
            Some("mail.example answered 550")
        );
    }

    /// The type has no payload and no destination field, so this asserts on
    /// the serialized document: a field added later that carried either would
    /// fail here rather than reach an operator's screen.
    #[test]
    fn a_rendered_dead_letter_has_no_payload_and_no_destination() {
        // Arrange
        let row = letter();

        // Act
        let json = serde_json::to_value(summarise(&row)).expect("a document serializes");
        let fields: Vec<_> = json
            .as_object()
            .expect("an object")
            .keys()
            .map(String::as_str)
            .collect();

        // Assert
        assert_eq!(
            fields,
            vec![
                "id",
                "kind",
                "family",
                "attempts",
                "created_at",
                "last_attempt_at",
                "last_error",
            ]
        );
    }

    /// A row abandoned before any attempt was recorded — an unregistered
    /// family is abandoned on the ack of its first claim — must render
    /// without inventing a timestamp.
    #[test]
    fn a_letter_with_no_recorded_attempt_omits_the_field() {
        // Arrange
        let mut row = letter();
        row.last_attempt_at = None;
        row.last_error = None;

        // Act
        let json = serde_json::to_value(summarise(&row)).expect("a document serializes");

        // Assert
        assert!(json.get("last_attempt_at").is_none());
        assert!(json.get("last_error").is_none());
    }

    /// A kind with no dot is its own family, so the column is never blank.
    #[test]
    fn a_kind_without_a_dot_is_its_own_family() {
        // Arrange
        let mut row = letter();
        row.kind = "heartbeat".to_owned();

        // Act
        let rendered = summarise(&row);

        // Assert
        assert_eq!(rendered.family, "heartbeat");
    }
}
