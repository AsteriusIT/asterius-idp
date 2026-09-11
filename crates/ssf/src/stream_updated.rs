//! The stream-updated event (SSF 1.0 §8.1.5, `ast-0ju.5`).
//!
//! > The Transmitter MUST send this event to the Receiver before the stream
//! > is paused or disabled, and upon the stream being re-enabled.
//!
//! §8.1.5's payload is two members — `status`, one of the three states §8.1.2
//! defines, and `reason`, OPTIONAL free text — and its `sub_id` is the stream
//! itself as an `opaque` identifier, exactly as §8.1.4's verification event.
//! That is what makes both of them events about *the stream* rather than
//! about a person: no subject is derived, no receiver sector is consulted,
//! and neither event is matched against the stream's `events_requested`
//! (§8.1.1's filter is a receiver's subscription to *security* events; a
//! receiver cannot usefully unsubscribe from being told that its own stream
//! stopped, and §8.1.5 makes the transmitter send it regardless).
//!
//! # `reason` is text, and it reaches a third party
//!
//! The reason on the row is either this server's own sentence — "the receiver
//! answered 400 four times" — or an operator's, already bounded by the
//! console. It is still rendered into a signed token handed to a receiver, so
//! it is tidied here, once, at the point it becomes a claim: stripped of the
//! control characters a receiver's log would render, bounded by
//! [`crate::management::MAX_REASON_LEN`], and omitted entirely when nothing is
//! left. A stream-updated event with no `reason` is a valid one; a stream
//! whose pause could not be announced because its reason was odd is not.

use crate::event::{EventUri, SecurityEvent};
use crate::management::MAX_REASON_LEN;
use crate::stream::StreamStatus;
use serde_json::Value;

/// The event type URI of §8.1.5.
pub const STREAM_UPDATED: &str =
    "https://schemas.openid.net/secevent/ssf/event-type/stream-updated";

/// §8.1.5's event: the stream's new status, and why it changed if known.
///
/// No `event_timestamp` and no `subject` member, for the reason
/// [`crate::verification::verification_event`] gives: the section defines the
/// payload as `status` and `reason`, and a receiver validating against the
/// schema is entitled to refuse members it did not ask for. The SET's own
/// `iat` says when, and its `sub_id` says which stream.
#[must_use]
pub fn stream_updated_event(status: StreamStatus, reason: Option<&str>) -> SecurityEvent {
    let uri = EventUri::parse(STREAM_UPDATED)
        .expect("the stream-updated event type is an absolute URI within the bound");
    let event = SecurityEvent::new(uri).with("status", Value::from(status.as_str()));
    match tidy(reason) {
        Some(reason) => event.with("reason", Value::from(reason)),
        None => event,
    }
}

/// The `reason` as it may appear in a signed token, or `None`.
fn tidy(reason: Option<&str>) -> Option<String> {
    let reason: String = reason?
        .chars()
        .filter(|character| !character.is_control())
        .take(MAX_REASON_LEN)
        .collect();
    let reason = reason.trim();
    (!reason.is_empty()).then(|| reason.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// §8.1.5's example payload: a status and the sentence beside it.
    #[test]
    fn a_stream_updated_event_carries_the_status_and_the_reason() {
        // Arrange / Act
        let event = stream_updated_event(
            StreamStatus::Paused,
            Some("Disabled by administrator action."),
        );
        let claim = event.to_events_claim();

        // Assert
        assert_eq!(event.uri().as_str(), STREAM_UPDATED);
        assert_eq!(
            claim[STREAM_UPDATED],
            serde_json::json!({
                "status": "paused",
                "reason": "Disabled by administrator action.",
            })
        );
    }

    /// `reason` is OPTIONAL: without one the payload is the status alone,
    /// rather than a `reason: null` a schema-validating receiver would refuse.
    #[test]
    fn a_stream_updated_event_without_a_reason_carries_the_status_alone() {
        // Arrange / Act
        let claim = stream_updated_event(StreamStatus::Enabled, None).to_events_claim();

        // Assert
        assert_eq!(
            claim[STREAM_UPDATED],
            serde_json::json!({"status": "enabled"})
        );
    }

    /// The three statuses of §8.1.2 are spelled the way §8.1.2 spells them,
    /// because a receiver dispatches on the string.
    #[test]
    fn the_status_is_spelled_as_the_status_endpoint_spells_it() {
        // Arrange / Act / Assert
        for status in [
            StreamStatus::Enabled,
            StreamStatus::Paused,
            StreamStatus::Disabled,
        ] {
            let claim = stream_updated_event(status, None).to_events_claim();
            assert_eq!(
                claim[STREAM_UPDATED]["status"],
                Value::from(status.as_str())
            );
        }
    }

    /// A reason with a control character reaches a receiver's log; it is
    /// stripped rather than allowed to stop the announcement.
    #[test]
    fn a_reason_is_stripped_of_control_characters_and_never_drops_the_event() {
        // Arrange / Act
        let claim =
            stream_updated_event(StreamStatus::Paused, Some("the receiver\r\nanswered 400"))
                .to_events_claim();

        // Assert
        assert_eq!(
            claim[STREAM_UPDATED]["reason"],
            Value::from("the receiveranswered 400")
        );
    }

    /// An over-long reason is bounded, not refused: the announcement matters
    /// more than the sentence.
    #[test]
    fn an_over_long_reason_is_bounded() {
        // Arrange
        let long = "r".repeat(MAX_REASON_LEN + 50);

        // Act
        let claim = stream_updated_event(StreamStatus::Disabled, Some(&long)).to_events_claim();

        // Assert
        let reason = claim[STREAM_UPDATED]["reason"]
            .as_str()
            .expect("a reason")
            .to_owned();
        assert_eq!(reason.chars().count(), MAX_REASON_LEN);
    }

    /// A reason that is only whitespace is no reason at all.
    #[test]
    fn a_blank_reason_is_omitted() {
        // Arrange / Act
        let claim = stream_updated_event(StreamStatus::Paused, Some("   ")).to_events_claim();

        // Assert
        assert_eq!(
            claim[STREAM_UPDATED],
            serde_json::json!({"status": "paused"})
        );
    }
}
