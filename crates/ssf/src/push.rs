//! Push delivery: what the wire carries, and what an answer to it means
//! (RFC 8935).
//!
//! The transmitter `POST`s one SET to the receiver's endpoint (§2.1), one at a
//! time (§2.2), and reads the answer. Everything in this module is that answer
//! being turned into a decision: accepted, refused, or worth trying again.
//! There is no socket here, no stream and no store — [`crate::poll`] is the
//! same shape for RFC 8936, for the same reason: what the specification says
//! must be assertable without a database and without a receiver.
//!
//! # The one thing a receiver gets to say back
//!
//! §2.3's body is the only document in the push direction that this
//! transmitter *reads* rather than writes, and the party that writes it is a
//! third party whose URL another party configured. That makes
//! [`ReceiverError::parse`] a parser in the sense the definition of done means
//! it, and it is treated as one: it is total (every byte string is an answer,
//! because the status code has already said the delivery failed), the code is
//! mapped onto the closed set of §2.3 rather than kept as the receiver wrote
//! it, and the free-text `description` is stripped and bounded before it is
//! kept. All three exist because what comes out of here is written to
//! `outbox.last_error`, read back by the admin API and rendered on an
//! operator's screen. A receiver that could put a kilobyte of terminal escapes
//! or another tenant's identifier there would be writing in this deployment's
//! own logs.
//!
//! # Retry, and the two statuses §2.4 carves out
//!
//! §2.4: retry on 5xx and on timeouts, and do not retry a 4xx — except 429 and
//! 503, which are a receiver asking for a moment rather than refusing the
//! request. [`disposition`] is that rule and nothing else; how long the pause
//! is and how many are left belongs to the outbox's backoff, because that is
//! where the attempt counter lives.

use serde_json::Value;

/// The longest `authorization_header` this transmitter will keep.
///
/// A bearer token, a basic credential or a signed assertion all fit; anything
/// longer is either not a header value or an attempt to use a stream row as
/// storage. HTTP has no limit of its own, so somebody has to have one, and a
/// value this server cannot send is better refused at the endpoint than
/// discovered on the first delivery.
pub const MAX_AUTHORIZATION_HEADER_LEN: usize = 1024;

/// The credential a push receiver hands the transmitter (SSF 1.0 §6.1.1).
///
/// > If the transmitter is provided an `authorization_header` value, it MUST
/// > present it in every request it makes to the receiver's endpoint.
///
/// A type rather than a `String` for three reasons, all of which are about the
/// places a `String` would end up:
///
/// * it is **validated at the edge** — a value with a `\r`, a `\n` or a NUL in
///   it is a header-injection attempt against the receiver, and it is refused
///   where the receiver registers it rather than where the socket is written;
/// * it **does not render itself** in `Debug` or `Display`, so it cannot
///   arrive in a `tracing` field, a panic message or an error by accident;
/// * reading it back takes a named call, [`AuthorizationHeader::expose`], which
///   is a thing a reviewer can grep for.
#[derive(Clone, PartialEq, Eq)]
pub struct AuthorizationHeader(String);

/// Why an `authorization_header` was not accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AuthorizationHeaderError {
    /// Empty, or nothing but spaces.
    #[error("an `authorization_header` must not be empty")]
    Empty,
    /// Longer than [`MAX_AUTHORIZATION_HEADER_LEN`].
    #[error("an `authorization_header` is longer than this transmitter accepts")]
    TooLong,
    /// Holds a byte an HTTP field value may not carry.
    #[error("an `authorization_header` must be printable ASCII")]
    NotAFieldValue,
}

impl AuthorizationHeader {
    /// Reads a receiver's credential, or says why it is not one.
    ///
    /// RFC 9110 §5.5 makes a field value visible ASCII with optional spaces
    /// and horizontal tabs. This is stricter than that in one direction — no
    /// obs-text, no leading or trailing whitespace — because nothing legitimate
    /// needs either and both are how a value smuggles a second header.
    ///
    /// # Errors
    ///
    /// [`AuthorizationHeaderError`], naming the rule and never the value.
    pub fn parse(raw: &str) -> Result<Self, AuthorizationHeaderError> {
        let trimmed = raw.trim_matches(|c| c == ' ' || c == '\t');
        if trimmed.is_empty() {
            return Err(AuthorizationHeaderError::Empty);
        }
        if trimmed.len() > MAX_AUTHORIZATION_HEADER_LEN {
            return Err(AuthorizationHeaderError::TooLong);
        }
        if !trimmed
            .bytes()
            .all(|byte| (0x21..=0x7e).contains(&byte) || byte == b' ' || byte == b'\t')
        {
            return Err(AuthorizationHeaderError::NotAFieldValue);
        }
        Ok(Self(trimmed.to_owned()))
    }

    /// Reads it back from storage, where it has already been through
    /// [`Self::parse`] once.
    ///
    /// Checked again all the same: a row is a thing that can be edited, and
    /// the first delivery after such an edit is not where a `\r\n` should be
    /// noticed.
    ///
    /// # Errors
    ///
    /// [`AuthorizationHeaderError`], as [`Self::parse`].
    pub fn from_storage(raw: &str) -> Result<Self, AuthorizationHeaderError> {
        Self::parse(raw)
    }

    /// The value, for the one caller that puts it on the wire.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for AuthorizationHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuthorizationHeader(<redacted>)")
    }
}

/// The media type of a pushed SET (§2.1).
///
/// RFC 8417 §2.3's media type for a SET, and not `application/jwt`: a receiver
/// is entitled to route on it, and §2.1 spells it out.
pub const PUSH_CONTENT_TYPE: &str = "application/secevent+jwt";

/// What the transmitter will read back (§2.1).
///
/// §2.3's error object is JSON, and it is the only body this direction has.
pub const PUSH_ACCEPT: &str = "application/json";

/// The most bytes of a receiver's answer that are parsed.
///
/// The body is an error object of a few dozen bytes. Anything beyond this is
/// either a receiver's HTML error page or a receiver trying to make this
/// server hold something large, and neither becomes a better answer for being
/// read to the end.
pub const MAX_ERROR_BODY_BYTES: usize = 8 * 1024;

/// The most characters of §2.3's `description` that are kept.
///
/// Enough for a sentence an operator can act on, short enough that a receiver
/// cannot use `outbox.last_error` as free storage or push anything else out of
/// a log line.
pub const MAX_DESCRIPTION_CHARS: usize = 120;

/// One of §2.3's error codes, or the fact that it was not one of them.
///
/// A closed set rather than the receiver's string. This value is a metric
/// label, an audit member and a branch — `invalid_key` is acted on — and all
/// three are places where a value an outsider chose does not belong.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum ReceiverErrorCode {
    /// The request body was not a valid SET, or was not understood.
    InvalidRequest,
    /// The key that signed the SET was not one the receiver could use.
    InvalidKey,
    /// `iss` was not one the receiver accepts.
    InvalidIssuer,
    /// `aud` did not name the receiver.
    InvalidAudience,
    /// The `Authorization` header was refused.
    AuthenticationFailed,
    /// The transmitter is known and not allowed.
    AccessDenied,
    /// Anything else the receiver said, including nothing at all.
    Unrecognised,
}

impl ReceiverErrorCode {
    /// The six codes §2.3 defines, in the order it lists them.
    ///
    /// Public so that a test can be exhaustive over the specification's set
    /// rather than over this enum, which also holds [`Self::Unrecognised`].
    pub const DEFINED: [Self; 6] = [
        Self::InvalidRequest,
        Self::InvalidKey,
        Self::InvalidIssuer,
        Self::InvalidAudience,
        Self::AuthenticationFailed,
        Self::AccessDenied,
    ];

    /// The code as §2.3 spells it, or `unrecognised`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::InvalidKey => "invalid_key",
            Self::InvalidIssuer => "invalid_issuer",
            Self::InvalidAudience => "invalid_audience",
            Self::AuthenticationFailed => "authentication_failed",
            Self::AccessDenied => "access_denied",
            Self::Unrecognised => "unrecognised",
        }
    }

    /// The code `raw` names, or [`Self::Unrecognised`].
    ///
    /// Exact match, no case folding and no trimming: §2.3's values are
    /// lowercase tokens, and a receiver sending ` Invalid_Key ` has not sent
    /// one of them. Guessing would mean a stream paused, or a key refresh
    /// recorded, on the strength of a string this server invented a reading
    /// for.
    #[must_use]
    pub fn parse(raw: &str) -> Self {
        Self::DEFINED
            .into_iter()
            .find(|code| code.as_str() == raw)
            .unwrap_or(Self::Unrecognised)
    }

    /// Whether this code says the *transmitter's keys* are the problem.
    ///
    /// Only `invalid_key`. §2.3 describes it as the receiver being unable to
    /// use the key the SET was signed with, which is the one refusal that
    /// points at this server's JWKS rather than at the SET's contents — so it
    /// is the one that is worth telling an operator to look at the published
    /// key set for. Nothing here refreshes anything on its own: a receiver
    /// that could make a transmitter roll its keys by answering 400 would be a
    /// denial of service with extra steps.
    #[must_use]
    pub const fn suggests_key_refresh(self) -> bool {
        matches!(self, Self::InvalidKey)
    }
}

/// §2.3's error object, as this transmitter is willing to keep it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiverError {
    /// Which of §2.3's refusals it was.
    pub code: ReceiverErrorCode,
    /// The receiver's own words, stripped and bounded, if it sent any that
    /// survived.
    pub description: Option<String>,
}

impl ReceiverError {
    /// Reads a receiver's failure body (§2.3).
    ///
    /// Total: a body that is not JSON, is JSON but not an object, or is an
    /// object without `err`, is [`ReceiverErrorCode::Unrecognised`] with no
    /// description. The status code has already decided that the delivery
    /// failed, so there is nothing for a parse error to change — and a parser
    /// that could fail here would only mean a second way to describe the same
    /// failure.
    ///
    /// Only the first [`MAX_ERROR_BODY_BYTES`] are looked at.
    // fuzz-target: ssf_push_error
    #[must_use]
    pub fn parse(body: &[u8]) -> Self {
        let head = &body[..body.len().min(MAX_ERROR_BODY_BYTES)];
        let Ok(Value::Object(object)) = serde_json::from_slice::<Value>(head) else {
            return Self {
                code: ReceiverErrorCode::Unrecognised,
                description: None,
            };
        };
        let code = object
            .get("err")
            .and_then(Value::as_str)
            .map_or(ReceiverErrorCode::Unrecognised, ReceiverErrorCode::parse);
        let description = object
            .get("description")
            .and_then(Value::as_str)
            .and_then(sanitise);
        Self { code, description }
    }

    /// One line for `outbox.last_error` and for an operator's screen.
    ///
    /// The code, which is this server's own constant, and the description only
    /// only after the sanitiser below has been over it.
    #[must_use]
    pub fn detail(&self) -> String {
        self.description.as_ref().map_or_else(
            || format!("the receiver refused the SET: {}", self.code.as_str()),
            |description| {
                format!(
                    "the receiver refused the SET: {} ({description})",
                    self.code.as_str()
                )
            },
        )
    }
}

/// What to do about a receiver's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Disposition {
    /// The receiver took the SET (§2.2).
    Delivered,
    /// The receiver refused it, and another attempt would be refused too
    /// (§2.3, §2.4).
    Rejected(ReceiverError),
    /// The receiver could not take it *now* (§2.4).
    Retry {
        /// The status that said so, for the line an operator reads.
        status: u16,
    },
}

/// §2.4's rule, over a status code and whatever body came with it.
///
/// * 2xx — accepted. §2.2 names 202; a receiver answering 200 has taken the
///   SET all the same, and treating that as a failure would redeliver a signal
///   the receiver has already acted on.
/// * 429 and 503 — the two §2.4 carves out of "do not retry a 4xx". 503 is not
///   a 4xx at all, and is named here because §2.4 names it.
/// * anything else 4xx, and every 3xx — refused. A 3xx is a failure rather
///   than a hop: nothing in this server follows a redirect to an address that
///   has not been through the SSRF guard.
/// * 5xx — retried.
#[must_use]
pub fn disposition(status: u16, body: &[u8]) -> Disposition {
    match status {
        200..=299 => Disposition::Delivered,
        // 429 is the 4xx §2.4 carves out; 503, the other status it names, is
        // inside the 5xx range and needs no pattern of its own.
        429 | 500..=599 => Disposition::Retry { status },
        _ => Disposition::Rejected(ReceiverError::parse(body)),
    }
}

/// A receiver's free text, reduced to something safe to store and render.
///
/// Control characters are dropped rather than escaped — a newline, a `\r` and
/// an ANSI escape are the three ways a string ends up forging a second log
/// line or repainting a terminal — and the result is cut to
/// [`MAX_DESCRIPTION_CHARS`] *characters*, not bytes, so a multi-byte
/// character is never split into invalid UTF-8. Whitespace is collapsed for
/// the same reason: a description of four hundred spaces is not information.
///
/// `None` when nothing survives, which is the same answer as a body that
/// carried no description at all.
fn sanitise(raw: &str) -> Option<String> {
    let mut kept = String::new();
    let mut last_was_space = true;
    for character in raw.chars() {
        if kept.chars().count() >= MAX_DESCRIPTION_CHARS {
            break;
        }
        let character = if character.is_control() || character.is_whitespace() {
            ' '
        } else {
            character
        };
        if character == ' ' {
            if last_was_space {
                continue;
            }
            last_was_space = true;
        } else {
            last_was_space = false;
        }
        kept.push(character);
    }
    let trimmed = kept.trim_end();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// §2.1: the SET goes out as `application/secevent+jwt` and the
    /// transmitter says it will read JSON back, which is the media type §2.3's
    /// error object arrives in.
    #[test]
    fn a_push_names_the_media_types_of_section_2_1() {
        assert_eq!(PUSH_CONTENT_TYPE, "application/secevent+jwt");
        assert_eq!(PUSH_ACCEPT, "application/json");
    }

    /// §2.2: "the SET has been accepted" is a 202.
    #[test]
    fn an_accepted_set_is_delivered() {
        // Arrange / Act
        let outcome = disposition(202, b"");

        // Assert
        assert_eq!(outcome, Disposition::Delivered);
    }

    /// §2.3: a failure is a 400 carrying `err` and `description`, and the code
    /// is read out of it.
    #[test]
    fn a_four_hundred_carries_the_receivers_error_code() {
        // Arrange
        let body = br#"{"err":"invalid_issuer","description":"iss does not match"}"#;

        // Act
        let outcome = disposition(400, body);

        // Assert
        let Disposition::Rejected(error) = outcome else {
            panic!("§2.3's 400 must not be a retry");
        };
        assert_eq!(error.code, ReceiverErrorCode::InvalidIssuer);
        assert_eq!(error.description.as_deref(), Some("iss does not match"));
    }

    /// §2.3 names six codes and no seventh. One this build has not heard of is
    /// kept as unrecognised rather than becoming a label an outsider chose.
    #[test]
    fn an_unknown_error_code_is_not_kept_verbatim() {
        // Arrange / Act
        let error = ReceiverError::parse(br#"{"err":"teapot","description":"x"}"#);

        // Assert
        assert_eq!(error.code, ReceiverErrorCode::Unrecognised);
        assert_eq!(error.code.as_str(), "unrecognised");
    }

    /// A body that is not the object §2.3 describes still has to produce an
    /// answer: the status code already said the delivery failed.
    #[test]
    fn a_body_that_is_not_the_error_object_is_still_an_error() {
        // Arrange / Act
        let error = ReceiverError::parse(b"<html>go away</html>");

        // Assert
        assert_eq!(error.code, ReceiverErrorCode::Unrecognised);
        assert_eq!(error.description, None);
    }

    /// The description is written by the receiver and ends up on an operator's
    /// screen and in the audit trail, so it is stripped of control characters
    /// and bounded before it is kept.
    #[test]
    fn a_description_is_bounded_and_stripped_of_control_characters() {
        // Arrange
        let raw = format!("line\u{1b}[31m one\n{}", "x".repeat(500));
        let body = serde_json::json!({"err": "access_denied", "description": raw});

        // Act
        let error = ReceiverError::parse(&serde_json::to_vec(&body).expect("serialises"));

        // Assert
        let description = error.description.expect("a description was sent");
        assert!(description.chars().count() <= MAX_DESCRIPTION_CHARS);
        assert!(!description.chars().any(char::is_control));
    }

    /// §2.3's `invalid_key` is the one code that says something about *this*
    /// transmitter's keys rather than about the SET, so it is the one that
    /// asks for a key refresh to be recorded.
    #[test]
    fn only_invalid_key_asks_for_a_key_refresh() {
        // Arrange / Act / Assert
        for code in ReceiverErrorCode::DEFINED {
            assert_eq!(
                code.suggests_key_refresh(),
                code == ReceiverErrorCode::InvalidKey,
                "{} disagreed",
                code.as_str()
            );
        }
    }

    /// §2.4: 5xx is retried, and so are the two 4xx the section carves out.
    #[test]
    fn server_errors_and_the_two_carved_out_statuses_are_retried() {
        // Arrange / Act / Assert
        for status in [429, 500, 502, 503, 504] {
            assert!(
                matches!(disposition(status, b""), Disposition::Retry { .. }),
                "{status} was not retried"
            );
        }
    }

    /// §2.4: every other 4xx is the receiver saying the request is wrong, and
    /// nine more identical requests will be just as wrong.
    #[test]
    fn client_errors_other_than_the_carve_outs_are_not_retried() {
        // Arrange / Act / Assert
        for status in [400, 401, 403, 404, 405, 413, 422] {
            assert!(
                matches!(disposition(status, b""), Disposition::Rejected(_)),
                "{status} was retried"
            );
        }
    }

    /// A 3xx is neither: nothing follows a redirect here, so it is a failure
    /// the receiver has to fix rather than one a retry could clear.
    #[test]
    fn a_redirect_is_a_rejection_rather_than_a_retry() {
        // Arrange / Act
        let outcome = disposition(302, b"");

        // Assert
        assert!(matches!(outcome, Disposition::Rejected(_)));
    }

    /// A 2xx that is not 202 is still an acceptance: §2.2 names 202 and a
    /// receiver answering 200 has taken the SET all the same.
    #[test]
    fn any_success_status_is_an_acceptance() {
        // Arrange / Act / Assert
        assert_eq!(disposition(200, b""), Disposition::Delivered);
        assert_eq!(disposition(204, b""), Disposition::Delivered);
    }

    /// SSF 1.0 §6.1.1's credential is kept, and kept exactly: a receiver that
    /// registered `Bearer t` is presented `Bearer t`.
    #[test]
    fn an_authorization_header_is_kept_as_the_receiver_registered_it() {
        // Arrange / Act
        let header = AuthorizationHeader::parse("Bearer t-123").expect("a field value");

        // Assert
        assert_eq!(header.expose(), "Bearer t-123");
    }

    /// A value carrying a line break would let a receiver's registration write
    /// a second header into every request this server makes to it.
    #[test]
    fn a_header_value_with_a_line_break_is_refused() {
        // Arrange / Act / Assert
        for raw in ["Bearer t\r\nX-Admin: 1", "Bearer t\nX: 1", "Bearer\u{0}t"] {
            assert_eq!(
                AuthorizationHeader::parse(raw),
                Err(AuthorizationHeaderError::NotAFieldValue),
                "{raw:?} was accepted"
            );
        }
    }

    /// Empty and over-long are their own refusals: a stream holding either is
    /// a stream whose every delivery would fail at the socket.
    #[test]
    fn an_empty_or_over_long_header_is_refused() {
        // Arrange / Act / Assert
        assert_eq!(
            AuthorizationHeader::parse("   "),
            Err(AuthorizationHeaderError::Empty)
        );
        assert_eq!(
            AuthorizationHeader::parse(&"x".repeat(MAX_AUTHORIZATION_HEADER_LEN + 1)),
            Err(AuthorizationHeaderError::TooLong)
        );
    }

    /// The credential never renders itself. This value is in a stream, in a
    /// deliverer and in whatever `Debug` line the next person adds.
    #[test]
    fn a_credential_does_not_render_itself() {
        // Arrange
        let header = AuthorizationHeader::parse("Bearer secret-value").expect("a field value");

        // Act
        let rendered = format!("{header:?}");

        // Assert
        assert!(!rendered.contains("secret-value"), "{rendered}");
    }

    /// What goes in `outbox.last_error` names the code, so an operator reading
    /// a dead letter sees which of §2.3's refusals it was.
    #[test]
    fn a_rejection_describes_itself_by_its_code() {
        // Arrange
        let error = ReceiverError::parse(br#"{"err":"authentication_failed"}"#);

        // Act
        let detail = error.detail();

        // Assert
        assert!(detail.contains("authentication_failed"), "{detail}");
    }
}
