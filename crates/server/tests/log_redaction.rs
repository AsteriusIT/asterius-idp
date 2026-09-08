//! RFC 9700 §4.2/§4.3: credentials must not leak through logs.
//!
//! The acceptance criterion for `ast-83p.5` is to run a code flow with logging
//! at TRACE and assert with regexes that nothing sensitive appears. The flow's
//! endpoints land with their own stories, so what is exercised here is every
//! shape those endpoints will log — deliberately written the careless way, with
//! the credential passed straight into a `tracing` field, because that is how
//! the leak actually happens.

use asterius_server::observability::redact::RedactingFields;
use std::sync::{Arc, Mutex};
use tracing::subscriber::with_default;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::{Registry, fmt};

/// The credentials a code flow handles, in the shapes they really take.
mod credentials {
    pub const AUTHORIZATION_CODE: &str = "Zx9Kq2mNpR7vT4wY1bC8dF3gH6jL0aS5uV-eW_iO2nQ";
    pub const ACCESS_TOKEN: &str =
        "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCJ9.eyJzdWIiOiJhbGljZSJ9.c2lnbmF0dXJl";
    pub const REFRESH_TOKEN: &str = "Rt7Yb2NmQp9vX4wZ1cD8eF3gH6jK0aL5uV-eW_iO2nQ";
    pub const CLIENT_ASSERTION: &str =
        "eyJhbGciOiJFUzI1NiIsInR5cCI6ImNsaWVudC1hdXRoZW50aWNhdGlvbitqd3QifQ.eyJpc3MiOiJjMSJ9.c2ln";
    pub const DPOP_PROOF: &str =
        "eyJhbGciOiJFUzI1NiIsInR5cCI6ImRwb3Arand0In0.eyJodG0iOiJQT1NUIn0.c2ln";
    pub const PASSWORD: &str = "correct horse battery staple";
    pub const CLIENT_NOTIFICATION_TOKEN: &str = "Nt3Wq8ZmKp2vY7xB1cF5gH9jL4aS6uV-eW_iO0nQ";
    pub const REQUEST_URI: &str =
        "urn:ietf:params:oauth:request_uri:Zx9Kq2mNpR7vT4wY1bC8dF3gH6jL0aS5";
    pub const CODE_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    pub const ALL: &[(&str, &str)] = &[
        ("authorization code", AUTHORIZATION_CODE),
        ("access token", ACCESS_TOKEN),
        ("refresh token", REFRESH_TOKEN),
        ("client assertion", CLIENT_ASSERTION),
        ("DPoP proof", DPOP_PROOF),
        ("password", PASSWORD),
        ("client_notification_token", CLIENT_NOTIFICATION_TOKEN),
        ("request_uri", REQUEST_URI),
        ("code_verifier", CODE_VERIFIER),
    ];
}

/// Collects everything written to the subscriber.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Captured {
    fn contents(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().expect("lock")).into_owned()
    }
}

impl std::io::Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("lock").extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Captured {
    type Writer = Self;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// Runs `body` with the real redacting subscriber at TRACE and returns the logs.
fn capture(body: impl FnOnce()) -> String {
    let captured = Captured::default();
    let subscriber = Registry::default().with(
        fmt::layer()
            .with_ansi(false)
            .with_writer(captured.clone())
            .fmt_fields(RedactingFields),
    );
    with_default(subscriber, body);
    captured.contents()
}

/// A token response, for the `Debug`-dump case below.
#[derive(Debug)]
#[allow(dead_code, reason = "the fields exist to be rendered by Debug")]
struct TokenResponse<'a> {
    access_token: &'a str,
    token_type: &'a str,
}

/// A full authorization code flow, logged the careless way at every step.
fn log_a_code_flow() {
    use credentials as c;

    tracing::trace!(request_uri = %c::REQUEST_URI, "par accepted");
    tracing::trace!(password = %c::PASSWORD, username = "alice", "authenticating");
    tracing::debug!(sub = "alice@example.com", "login succeeded");
    tracing::trace!(code = %c::AUTHORIZATION_CODE, "code issued");
    tracing::trace!(
        client_assertion = %c::CLIENT_ASSERTION,
        dpop = %c::DPOP_PROOF,
        "client authenticated"
    );
    tracing::trace!(code_verifier = %c::CODE_VERIFIER, "pkce verified");
    tracing::info!(
        access_token = %c::ACCESS_TOKEN,
        refresh_token = %c::REFRESH_TOKEN,
        grant_type = "authorization_code",
        "token issued"
    );
    tracing::trace!(
        client_notification_token = %c::CLIENT_NOTIFICATION_TOKEN,
        "ciba notification"
    );

    // The same values arriving through paths nobody thinks about: a Debug dump
    // of a struct, an error message, a bare positional message.
    tracing::debug!(
        response = ?TokenResponse { access_token: c::ACCESS_TOKEN, token_type: "DPoP" },
        "responding"
    );
    tracing::warn!("redeeming code {}", c::AUTHORIZATION_CODE);
    tracing::error!(error = %format!("grant failed for {}", c::REFRESH_TOKEN), "refused");
}

#[test]
fn no_credential_from_a_code_flow_appears_in_the_logs() {
    let logs = capture(log_a_code_flow);

    assert!(
        !logs.is_empty(),
        "nothing was captured; the test proves nothing"
    );
    for (what, secret) in credentials::ALL {
        assert!(
            !logs.contains(secret),
            "the {what} was written to the logs.\n--- logs ---\n{logs}"
        );
    }
}

/// A JWT leaks its payload even in fragments, so a partial match matters too.
#[test]
fn no_jwt_payload_survives_even_in_fragments() {
    let logs = capture(log_a_code_flow);
    for fragment in [
        "eyJhbGciOiJFZERTQSIs", // access token header
        "eyJzdWIiOiJhbGljZSJ9", // its payload
        "eyJodG0iOiJQT1NUIn0",  // the DPoP proof's payload
    ] {
        assert!(
            !logs.contains(fragment),
            "a JWT fragment survived: {fragment}\n{logs}"
        );
    }
}

/// Redaction must not empty the logs out: an unreadable log is one nobody
/// consults, and then the redaction has cost more than it saved.
#[test]
fn the_logs_remain_useful_after_redaction() {
    let logs = capture(log_a_code_flow);

    for expected in [
        "par accepted",
        "login succeeded",
        "code issued",
        "token issued",
        "grant_type=authorization_code",
        "pkce verified",
    ] {
        assert!(
            logs.contains(expected),
            "lost {expected:?} from the logs:\n{logs}"
        );
    }
    assert!(
        logs.contains("redacted:"),
        "no redaction marker to explain the gaps"
    );
}

/// The subject is pseudonymised rather than removed, so one user's lines can
/// still be followed — the same digest every time, and never the identity.
#[test]
fn a_subject_is_correlatable_without_being_identifiable() {
    let logs = capture(|| {
        tracing::info!(sub = "alice@example.com", "first");
        tracing::info!(sub = "alice@example.com", "second");
        tracing::info!(sub = "bob@example.com", "third");
    });

    assert!(!logs.contains("alice@example.com"), "{logs}");
    assert!(!logs.contains("bob@example.com"), "{logs}");

    let digests: Vec<&str> = logs
        .split_whitespace()
        .filter(|token| token.starts_with("sub=sha256:"))
        .collect();
    assert_eq!(digests.len(), 3, "{logs}");
    assert_eq!(
        digests[0], digests[1],
        "the same user got two different digests"
    );
    assert_ne!(digests[0], digests[2], "two users got the same digest");
}
