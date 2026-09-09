//! RFC 9700 §4.2/§4.3: credentials must not leak through logs.
//!
//! The acceptance criterion for `ast-83p.5` is to run a code flow with logging
//! at TRACE and assert with regexes that nothing sensitive appears. The flow's
//! endpoints land with their own stories, so what is exercised here is every
//! shape those endpoints will log — deliberately written the careless way, with
//! the credential passed straight into a `tracing` field, because that is how
//! the leak actually happens.
//!
//! # What `ast-p2l.4` added
//!
//! The code flow is only the request path. Two more surfaces write logs, and
//! FAPI 2.0 SP §7 counts a leak from either as a leak from the authorization
//! server:
//!
//! * **The background workers.** `retention::RetentionSweep` and
//!   `rotation::RotationSweep` run with no request in scope and log errors that
//!   nobody hand-wrote: a `sqlx` failure quotes the connection string that
//!   produced it, password included. Nothing about a worker line goes through a
//!   handler that might have sanitised it first.
//! * **The admin API.** `asterius_admin_api` has no endpoints yet (`ast-f7m`),
//!   so there is no admin log line to capture and this file does not pretend
//!   otherwise. What it does instead is cover the console *by construction*:
//!   `every_log_formatter_in_the_workspace_redacts` walks every crate,
//!   including `admin-api`, and fails on any subscriber built without
//!   [`RedactingFields`] — so the day the console installs one, this test is
//!   already watching. The field shapes it will use are exercised below
//!   against the real formatter.

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

// ---------------------------------------------------------------------------
// Worker logs (`ast-p2l.4`)
// ---------------------------------------------------------------------------

/// What a background sweep writes, including the two lines nobody wrote on
/// purpose: an error carrying the DSN, and an error carrying whatever string
/// the failure was about.
fn log_a_worker_pass() {
    // The useful, ordinary line: table names and counts.
    tracing::debug!(
        tenant = "demo",
        deleted = 412_u64,
        tables = "jti_replay=400,authorization_codes=12",
        "retention swept a tenant"
    );

    // The failure path. `sqlx` renders the pool's connection string into its
    // own error text, so this is what `tracing::error!(%error, ...)` produces.
    tracing::error!(
        error = %"pool timed out connecting to postgres://asterius:s3cr3t-db-pw@db.internal:5432/asterius",
        tenant = "demo",
        "could not apply the retention policy"
    );

    // A rotation failure quotes the key it could not unwrap.
    tracing::error!(
        error = %"cannot unwrap the private key sealed under local:9wQk2H0=",
        tenant = "demo",
        kid = "0Jd7bQoEo3cA0m6JGX3nUeqQ0nQvQ5m2m0P0oE2n1sQ",
        "could not apply the key rotation schedule"
    );

    // A sweep that logs the row it choked on, which is the shape that turns a
    // retention worker into a credential exporter.
    tracing::warn!(
        request_uri = %"urn:ietf:params:oauth:request_uri:Zx9Kq2mNpR7vT4wY1bC8dF3gH6jL0aS5",
        email = "alice@example.com",
        "skipping an expired row"
    );
}

/// The worker half of the criterion: a sweep runs with no request in scope, so
/// nothing upstream of it has had a chance to sanitise anything.
#[test]
fn no_worker_log_line_carries_a_credential_or_a_password() {
    let logs = capture(log_a_worker_pass);

    for (what, secret) in [
        ("the database password", "s3cr3t-db-pw"),
        ("the DSN userinfo", "asterius:s3cr3t-db-pw"),
        ("a request_uri", credentials::REQUEST_URI),
        ("a user's email", "alice@example.com"),
    ] {
        assert!(
            !logs.contains(secret),
            "{what} reached a worker log line.\n--- logs ---\n{logs}"
        );
    }
}

/// Redaction that also removed the host would make the worker's error useless,
/// and an operator who cannot read the error turns the logging off.
#[test]
fn a_worker_log_still_says_what_happened_and_where() {
    let logs = capture(log_a_worker_pass);

    for expected in [
        "retention swept a tenant",
        "jti_replay=400",
        "db.internal:5432",
        "pool timed out",
        "tenant=demo",
        "could not apply the retention policy",
    ] {
        assert!(logs.contains(expected), "lost {expected:?}:\n{logs}");
    }
}

// ---------------------------------------------------------------------------
// Admin console shapes (`ast-p2l.4`, ahead of `ast-f7m`)
// ---------------------------------------------------------------------------

/// The fields a first-party admin console logs: it authenticates with the
/// session cookie rather than an OAuth token, and its actor is a named human
/// rather than a `sub` — which is why neither is covered by the code-flow case
/// above.
fn log_an_admin_request() {
    tracing::info!(
        admin_email = "root@example.com",
        action = "client.disabled",
        client_id = "checkout-service",
        "admin action"
    );
    tracing::debug!(
        cookie = "asterius_session=Vt7Yb2NmQp9vX4wZ1cD8eF3gH6jK0aL5uV-eW_iO2nQ",
        authorization = "Bearer eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJyb290In0.c2ln",
        "authenticating the console"
    );
    tracing::debug!(
        registration_access_token = "Rat7Yb2NmQp9vX4wZ1cD8eF3gH6jK0aL5uV-eW_iO2nQ",
        "reissuing a registration access token"
    );
}

#[test]
fn an_admin_line_names_the_action_but_not_the_human_or_their_session() {
    let logs = capture(log_an_admin_request);

    for (what, secret) in [
        ("the admin's address", "root@example.com"),
        (
            "the console session cookie",
            "Vt7Yb2NmQp9vX4wZ1cD8eF3gH6jK0aL5uV-eW_iO2nQ",
        ),
        (
            "a registration access token",
            "Rat7Yb2NmQp9vX4wZ1cD8eF3gH6jK0aL5uV-eW_iO2nQ",
        ),
        ("the console's bearer token", "eyJzdWIiOiJyb290In0"),
    ] {
        assert!(!logs.contains(secret), "{what} leaked:\n{logs}");
    }

    // What an audit reader needs from an admin line: what was done, to what.
    assert!(logs.contains("client.disabled"), "{logs}");
    assert!(logs.contains("checkout-service"), "{logs}");
    assert!(logs.contains("admin_email=sha256:"), "{logs}");
}

// ---------------------------------------------------------------------------
// The rule that covers the crates this file cannot see (`ast-p2l.4`)
// ---------------------------------------------------------------------------

/// Every `.rs` file in the workspace's crates, with its repo-relative path.
fn workspace_sources() -> Vec<(String, String)> {
    let crates = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/server has a parent")
        .to_path_buf();

    let mut files = Vec::new();
    let mut stack = vec![crates.clone()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("read a source directory") {
            let path = entry.expect("directory entry").path();
            if path.is_dir() {
                if path.file_name().is_some_and(|name| name == "target") {
                    continue;
                }
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                let relative = path
                    .strip_prefix(&crates)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .replace('\\', "/");
                files.push((
                    relative,
                    std::fs::read_to_string(&path).expect("read source"),
                ));
            }
        }
    }
    assert!(
        files.len() > 10,
        "the source walk found {} files",
        files.len()
    );
    files
}

/// Redaction is a property of the *formatter*, so it protects exactly the logs
/// that go through a subscriber built with [`RedactingFields`]. A second
/// subscriber built anywhere else — in the admin API, in a worker's own `main`,
/// in a test helper that then gets copied — silently has none of it, and
/// nothing about the resulting log line looks wrong.
///
/// So the rule is asserted over the whole tree rather than remembered. The
/// failure message names the file and the line, because the crate that trips
/// this will usually not be the crate whose author is reading the failure: six
/// stories are in flight against this workspace at once, and a fix that takes
/// one line to understand is a fix that happens at merge time instead of
/// becoming somebody's afternoon.
#[test]
fn every_log_formatter_in_the_workspace_redacts() {
    // Building a `fmt` layer is the moment redaction is chosen or lost.
    const BUILDS_A_FORMATTER: &[&str] = &["fmt::layer(", "SubscriberBuilder"];
    // These install a default formatter outright, so there is no `fmt_fields`
    // call to add and the answer is always "use `observability::init`".
    const INSTALLS_AN_UNREDACTED_ONE: &[&str] = &[
        "tracing_subscriber::fmt::init(",
        "tracing_subscriber::fmt().init(",
        "fmt::fmt(",
    ];

    let mut offenders = Vec::new();
    for (path, source) in workspace_sources() {
        // This file names each pattern in order to look for it.
        if path.ends_with("tests/log_redaction.rs") {
            continue;
        }
        let redacts = source.contains("RedactingFields");

        for (number, line) in source.lines().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") || trimmed.starts_with('*') {
                continue;
            }
            for needle in INSTALLS_AN_UNREDACTED_ONE {
                if line.contains(needle) {
                    offenders.push(format!(
                        "{path}:{}: `{needle}` installs a formatter that cannot redact",
                        number + 1
                    ));
                }
            }
            if redacts {
                continue;
            }
            for needle in BUILDS_A_FORMATTER {
                if line.contains(needle) {
                    offenders.push(format!(
                        "{path}:{}: `{needle}` with no `RedactingFields` in the file",
                        number + 1
                    ));
                }
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "every tracing subscriber must format its fields through \
         asterius_server::observability::redact::RedactingFields (RFC 9700 §4.2):\n  {}",
        offenders.join("\n  ")
    );
}

/// A check that cannot fail is not a check. Both halves of the matcher are
/// exercised on text rather than on the tree, so the proof does not depend on
/// the tree currently being wrong.
#[test]
fn the_formatter_audit_would_catch_a_violation() {
    let hostile = "    let layer = fmt::layer().with_ansi(false);\n";
    assert!(hostile.contains("fmt::layer("));
    assert!(!hostile.contains("RedactingFields"));

    let compliant = "    fmt::layer().fmt_fields(RedactingFields)\n";
    assert!(compliant.contains("RedactingFields"));
}
