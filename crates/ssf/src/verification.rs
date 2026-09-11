//! The verification event (SSF 1.0 §8.1.4, `ast-f7m.8`).
//!
//! > The Event Transmitter MUST support a verification event ... to enable
//! > the Event Receiver to verify that the stream is operational. [...] The
//! > Event Receiver MAY include a `state` value in the request, and the
//! > Event Transmitter MUST include that value in the Verification Event.
//!
//! §8.1.4.2 gives the receiver a request endpoint for this, and `ast-0ju.5`
//! built it: a receiver posts `{stream_id, state}`
//! ([`crate::management::VerificationRequest`]) and gets 204, or 429 if it
//! asked again inside `min_verification_interval`. An *operator* can trigger
//! the same event from the console (`ast-f7m.8`). Both build it through
//! [`verification_event`], so the SET a receiver gets is the same one either
//! way — the same type URI, the same `sub_id` (the stream, as an `opaque`
//! identifier, which is what the section's example carries) and the same
//! optional `state` — and a receiver written to §8.1.4 handles it without
//! knowing who asked.
//!
//! # `state` is a correlation value, not free text
//!
//! The receiver compares it against what it sent, so it must reach the
//! receiver verbatim — and because it is placed by whoever asks, it is
//! bounded and refused on a control character here, once, before it can be
//! a member of a signed token. It is never echoed by an error and never
//! written to the audit trail: the trail records that a `state` was given,
//! not which.

use crate::event::{EventUri, SecurityEvent};
use serde_json::Value;

/// The event type URI of §8.1.4.
pub const VERIFICATION: &str = "https://schemas.openid.net/secevent/ssf/event-type/verification";

/// The longest `state` accepted, in characters.
///
/// §8.1.4 puts no bound on it. A receiver's correlation value is an
/// identifier of its own choosing — a UUID, a nonce — and the SET the value
/// ends up in is bounded as a whole ([`crate::set::MAX_SET_CLAIMS_BYTES`]);
/// this is the room that bound leaves once the rest of the claims are
/// counted, rounded down to a number a person can remember.
pub const MAX_STATE_LEN: usize = 256;

/// Why a `state` was refused.
#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum StateError {
    /// Given and empty. Absent is fine; empty is a value nothing can match.
    #[error("state must not be empty")]
    Empty,
    /// Over [`MAX_STATE_LEN`] characters.
    #[error("state is longer than {max} characters")]
    TooLong {
        /// The bound.
        max: usize,
    },
    /// Carries a control character, which a receiver's log would render.
    #[error("state must not carry a control character")]
    Control,
}

/// A validated `state` value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationState(String);

impl VerificationState {
    /// Accepts a `state` as a receiver, or an operator on its behalf, gave it.
    ///
    /// # Errors
    ///
    /// [`StateError`] for an empty, over-long or control-carrying value.
    // fuzz-target: ssf_verification_state
    pub fn parse(raw: &str) -> Result<Self, StateError> {
        if raw.is_empty() {
            return Err(StateError::Empty);
        }
        if raw.chars().count() > MAX_STATE_LEN {
            return Err(StateError::TooLong { max: MAX_STATE_LEN });
        }
        if raw.chars().any(char::is_control) {
            return Err(StateError::Control);
        }
        Ok(Self(raw.to_owned()))
    }

    /// The value, exactly as accepted.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The verification event, with `state` if one was given (§8.1.4).
///
/// No `event_timestamp` and no `subject` member: the section defines the
/// event's payload as `state` alone, and a receiver that validates against
/// the schema is entitled to refuse members it did not ask for.
#[must_use]
pub fn verification_event(state: Option<&VerificationState>) -> SecurityEvent {
    let uri = EventUri::parse(VERIFICATION)
        .expect("the verification event type is an absolute URI within the bound");
    let event = SecurityEvent::new(uri);
    match state {
        Some(state) => event.with("state", Value::from(state.as_str())),
        None => event,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// §8.1.4's example: the event type, and `state` echoed verbatim.
    #[test]
    fn a_verification_event_carries_the_state_it_was_given() {
        // Arrange
        let state = VerificationState::parse("VGhpcyBpcyBhbiBleGFtcGxlIHN0YXRlIHZhbHVlLgo=")
            .expect("a base64 state");

        // Act
        let event = verification_event(Some(&state));
        let claim = event.to_events_claim();

        // Assert
        assert_eq!(event.uri().as_str(), VERIFICATION);
        assert_eq!(
            claim[VERIFICATION]["state"],
            Value::from("VGhpcyBpcyBhbiBleGFtcGxlIHN0YXRlIHZhbHVlLgo=")
        );
    }

    /// `state` is OPTIONAL: without one the payload is an empty object, not
    /// a `state: null` a schema-validating receiver would refuse.
    #[test]
    fn a_verification_event_without_a_state_has_an_empty_payload() {
        // Arrange / Act
        let claim = verification_event(None).to_events_claim();

        // Assert
        assert_eq!(claim[VERIFICATION], serde_json::json!({}));
    }

    #[test]
    fn an_empty_state_is_refused() {
        // Arrange / Act / Assert
        assert_eq!(VerificationState::parse(""), Err(StateError::Empty));
    }

    #[test]
    fn a_state_over_the_bound_is_refused_and_one_at_it_is_kept() {
        // Arrange
        let at = "s".repeat(MAX_STATE_LEN);
        let over = "s".repeat(MAX_STATE_LEN + 1);

        // Act / Assert
        assert!(VerificationState::parse(&at).is_ok());
        assert_eq!(
            VerificationState::parse(&over),
            Err(StateError::TooLong { max: MAX_STATE_LEN })
        );
    }

    #[test]
    fn a_state_with_a_control_character_is_refused() {
        // Arrange / Act / Assert
        assert_eq!(
            VerificationState::parse("abc\r\ndef"),
            Err(StateError::Control)
        );
        assert_eq!(
            VerificationState::parse("abc\u{7f}"),
            Err(StateError::Control)
        );
    }

    /// The refusal names the rule and never the value: the message reaches
    /// an error body and a log.
    #[test]
    fn a_refusal_does_not_echo_the_state() {
        // Arrange
        let error = VerificationState::parse("secret-value\n").expect_err("refused");

        // Act
        let message = error.to_string();

        // Assert
        assert!(!message.contains("secret-value"));
    }
}
