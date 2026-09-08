//! Redacting credentials out of log records.
//!
//! RFC 9700 §4.2 and §4.3 warn that credentials leak through logs. The usual
//! mitigation is a rule — "never log a token" — which fails for the obvious
//! reason: log lines are written by whoever is debugging at 2am, and the value
//! they reach for is exactly the one that was confusing them.
//!
//! So redaction happens at the formatter, not at the call site. Every field of
//! every event and span passes through
//! [`asterius_domain::audit::redaction`] — the same scanner the audit trail
//! uses, so the two cannot drift — and a value that looks like a credential is
//! replaced before it reaches an appender. `tracing::debug!(code = %code)`
//! written in a hurry produces a redacted line, not an incident.
//!
//! Two further rules, both about fields whose *name* says enough:
//!
//! * A field named like a secret is redacted regardless of its value, because
//!   a short password does not look like a credential to a scanner but is one.
//! * A field named `sub`, `username` or `email` is hashed rather than dropped,
//!   because correlating a user across log lines is the main reason to have
//!   logs at all, and doing it without writing the identity into them is
//!   strictly better.

use asterius_domain::audit::redaction;
use std::fmt;
use tracing::field::{Field, Visit};
use tracing_subscriber::field::{RecordFields, VisitOutput};
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::{FormatFields, FormattedFields};

/// Field names whose value is a secret whatever it looks like.
///
/// A password may be short and wordlike; a PIN is four digits. Neither trips a
/// shape-based scanner, and both are credentials.
const SECRET_BY_NAME: &[&str] = &[
    "password",
    "passphrase",
    "secret",
    "client_secret",
    "code_verifier",
    "private_key",
    "authorization",
    "cookie",
    "set_cookie",
    "dpop",
    "assertion",
    "client_assertion",
    "refresh_token",
    "access_token",
    "id_token",
    "client_notification_token",
    "registration_access_token",
    "device_code",
    "user_code",
];

/// Field names holding a user identity, which is pseudonymised rather than
/// removed so that lines can still be correlated.
const IDENTITY_BY_NAME: &[&str] = &["sub", "subject", "username", "email", "login_hint"];

/// Decides what a single field's rendered value should be.
#[must_use]
pub fn redact_field(name: &str, value: &str) -> String {
    let lowered = name.to_ascii_lowercase();

    if SECRET_BY_NAME
        .iter()
        .any(|secret| lowered == *secret || lowered.ends_with(secret))
    {
        return format!("[redacted:{}]", &redaction::fingerprint(value)[..16]);
    }

    if IDENTITY_BY_NAME.iter().any(|identity| lowered == *identity) {
        return format!("sha256:{}", &redaction::fingerprint(value)[..16]);
    }

    redaction::redact(value)
}

/// A `tracing` field formatter that redacts as it renders.
#[derive(Debug, Clone, Copy, Default)]
pub struct RedactingFields;

impl<'writer> FormatFields<'writer> for RedactingFields {
    fn format_fields<R: RecordFields>(&self, writer: Writer<'writer>, fields: R) -> fmt::Result {
        let mut visitor = RedactingVisitor {
            writer,
            first: true,
            result: Ok(()),
        };
        fields.record(&mut visitor);
        visitor.finish()
    }

    fn add_fields(
        &self,
        current: &'writer mut FormattedFields<Self>,
        fields: &tracing::span::Record<'_>,
    ) -> fmt::Result {
        let mut visitor = RedactingVisitor {
            writer: current.as_writer(),
            first: false,
            result: Ok(()),
        };
        fields.record(&mut visitor);
        visitor.finish()
    }
}

struct RedactingVisitor<'w> {
    writer: Writer<'w>,
    first: bool,
    result: fmt::Result,
}

impl RedactingVisitor<'_> {
    fn write(&mut self, name: &str, value: &str) {
        if self.result.is_err() {
            return;
        }
        let separator = if self.first { "" } else { " " };
        self.first = false;
        let redacted = redact_field(name, value);
        self.result = if name == "message" {
            write!(self.writer, "{separator}{redacted}")
        } else {
            write!(self.writer, "{separator}{name}={redacted}")
        };
    }
}

impl Visit for RedactingVisitor<'_> {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.write(field.name(), value);
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        // `%value` and `?value` both land here for most types, so this is the
        // path that matters; rendering first and redacting after is what makes
        // the scanner see what the log would have shown.
        self.write(field.name(), format!("{value:?}").trim_matches('"'));
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.write(field.name(), &value.to_string());
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.write(field.name(), &value.to_string());
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.write(field.name(), &value.to_string());
    }

    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        self.write(field.name(), &value.to_string());
    }
}

impl VisitOutput<fmt::Result> for RedactingVisitor<'_> {
    fn finish(self) -> fmt::Result {
        self.result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_field_named_like_a_secret_is_redacted_however_short_its_value() {
        for name in [
            "password",
            "client_secret",
            "code_verifier",
            "user_password",
        ] {
            let rendered = redact_field(name, "hunter2");
            assert!(!rendered.contains("hunter2"), "{name} leaked: {rendered}");
            assert!(rendered.starts_with("[redacted:"), "{rendered}");
        }
    }

    #[test]
    fn a_credential_shaped_value_is_redacted_whatever_the_field_is_called() {
        let jwt = "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCJ9.eyJzdWIiOiJhbGljZSJ9.c2ln";
        let rendered = redact_field("some_debug_field", jwt);
        assert!(!rendered.contains(jwt), "{rendered}");
    }

    /// Pseudonymised, not dropped: correlating one user's lines is most of why
    /// logs exist, and a digest does that without writing down who they are.
    #[test]
    fn an_identity_is_hashed_so_lines_can_still_be_correlated() {
        let first = redact_field("sub", "alice@example.com");
        let second = redact_field("sub", "alice@example.com");
        assert_eq!(first, second);
        assert!(!first.contains("alice"), "{first}");
        assert!(first.starts_with("sha256:"));
        assert_ne!(first, redact_field("sub", "bob@example.com"));
    }

    #[test]
    fn ordinary_fields_survive_intact() {
        for (name, value) in [
            ("grant_type", "authorization_code"),
            ("error", "invalid_grant"),
            ("tenant", "demo"),
            ("status", "404"),
            ("message", "starting"),
        ] {
            assert_eq!(redact_field(name, value), value, "{name} was over-redacted");
        }
    }
}
