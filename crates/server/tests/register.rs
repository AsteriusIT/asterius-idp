//! The dynamic client registration endpoint, end to end (RFC 7591 §3).
//!
//! In-memory fakes for the registry and the audit sink, so the whole file runs
//! in milliseconds. What is *not* faked is the validation: these push real
//! registration documents through [`ClientRegistration::from_json`], because the
//! endpoint's only job is to turn that one decision into an HTTP response.
//!
//! The fake registry records every write, which is what makes the important
//! negative assertions possible: a rejected document must leave nothing behind,
//! and a refused caller must not reach the store at all.

use asterius_domain::audit::{AuditEvent, AuditSink, DetailValue, EventType, Outcome};
use asterius_domain::{
    Capabilities, Client, ClientRegistry, DomainError, Issuer, Tenant, TenantId, TenantStatus,
    sha256,
};
use asterius_server::http::register::{
    Denial, InitialAccessTokens, MAX_BODY_BYTES, RegisterContext, RegistrationPolicy, register,
};
use axum::body::Bytes;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::Response;
use serde_json::{Value, json};
use std::sync::Mutex;
use time::OffsetDateTime;

const ISSUER: &str = "https://as.example/t/demo";
const TOKEN: &str = "vJ8qN2mXbL5-tRw0KePzUA";

// ---- fakes ---------------------------------------------------------------

/// Every registration this run wrote, with the token digest it was given.
#[derive(Debug, Default)]
struct FakeRegistry {
    written: Mutex<Vec<(Client, [u8; 32])>>,
    broken: bool,
}

impl FakeRegistry {
    fn broken() -> Self {
        Self {
            broken: true,
            ..Self::default()
        }
    }

    fn written(&self) -> Vec<(Client, [u8; 32])> {
        self.written.lock().expect("lock").clone()
    }
}

#[async_trait::async_trait]
impl ClientRegistry for FakeRegistry {
    async fn register(
        &self,
        client: &Client,
        registration_access_token: &[u8; 32],
    ) -> Result<Client, DomainError> {
        if self.broken {
            return Err(DomainError::Storage("the database is gone".into()));
        }
        self.written
            .lock()
            .expect("lock")
            .push((client.clone(), *registration_access_token));
        // What the store returns is what the row holds, and the row's
        // timestamps come from the database rather than from the entity. The
        // fake reproduces that, because the response is rendered from this
        // value and a test that returned the input unchanged would not notice
        // the endpoint rendering from the input instead.
        Ok(Client {
            created_at: OffsetDateTime::from_unix_timestamp(1_760_000_000).expect("instant"),
            updated_at: OffsetDateTime::from_unix_timestamp(1_760_000_000).expect("instant"),
            ..client.clone()
        })
    }
}

#[derive(Debug, Default)]
struct FakeAudit(Mutex<Vec<AuditEvent>>);

#[async_trait::async_trait]
impl AuditSink for FakeAudit {
    async fn record(&self, event: AuditEvent) -> Result<(), DomainError> {
        self.0.lock().expect("lock").push(event);
        Ok(())
    }
}

impl FakeAudit {
    fn events(&self) -> Vec<AuditEvent> {
        self.0.lock().expect("lock").clone()
    }
}

// ---- fixtures ------------------------------------------------------------

fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_759_000_000).expect("fixed instant")
}

fn tenant() -> Tenant {
    Tenant {
        id: TenantId::new("demo"),
        issuer: Issuer::parse(ISSUER).expect("issuer"),
        custom_host: None,
        display_name: "demo".into(),
        status: TenantStatus::Active,
        created_at: OffsetDateTime::UNIX_EPOCH,
        updated_at: OffsetDateTime::UNIX_EPOCH,
    }
}

fn document() -> Value {
    json!({
        "client_name": "Billing",
        "redirect_uris": ["https://rp.example/cb"],
        "grant_types": ["authorization_code", "refresh_token"],
        "scope": "openid payments",
        "jwks": {"keys": [{"kty": "OKP", "crv": "Ed25519", "x": "abc"}]},
    })
}

fn json_headers(authorization: Option<&str>) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        "application/json".parse().expect("header"),
    );
    if let Some(value) = authorization {
        headers.insert(
            header::AUTHORIZATION,
            value.parse().expect("a valid header value"),
        );
    }
    headers
}

fn gated() -> RegistrationPolicy {
    RegistrationPolicy::Gated(InitialAccessTokens::from_tokens([TOKEN]))
}

/// Runs one request against a fresh registry and audit sink.
async fn post(
    policy: &RegistrationPolicy,
    registry: &FakeRegistry,
    audit: &FakeAudit,
    headers: &HeaderMap,
    body: &[u8],
) -> Response {
    register(
        RegisterContext {
            tenant: &tenant(),
            clients: registry,
            capabilities: Capabilities::default(),
            policy,
            audit,
            request_id: Some("req-1"),
        },
        headers,
        &Bytes::copy_from_slice(body),
        now(),
    )
    .await
}

async fn body_of(response: Response) -> Value {
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("read the body");
    serde_json::from_slice(&bytes).expect("the response body must be JSON")
}

// ---- tests ---------------------------------------------------------------

/// The success path, against every field RFC 7591 §3.2.1 and OIDC Registration
/// §3.2 name — and against the stored row rather than the request, which is the
/// property the whole endpoint exists to have.
#[tokio::test]
async fn a_valid_document_registers_a_client_and_echoes_what_was_stored() {
    let registry = FakeRegistry::default();
    let audit = FakeAudit::default();
    let body = serde_json::to_vec(&document()).expect("serialise");

    let response = post(
        &gated(),
        &registry,
        &audit,
        &json_headers(Some(&format!("Bearer {TOKEN}"))),
        &body,
    )
    .await;

    assert_eq!(response.status(), StatusCode::CREATED);
    // RFC 7591 §3.2.1's example, and the reason for it: the body carries a
    // credential that must be handed over exactly once.
    assert_eq!(
        response
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok()),
        Some("no-store")
    );

    let written = registry.written();
    assert_eq!(written.len(), 1, "exactly one row should have been written");
    let (stored, digest) = &written[0];

    let document = body_of(response).await;
    assert_eq!(document["client_id"], json!(stored.id.as_str()));
    assert_eq!(document["client_id_issued_at"], json!(1_760_000_000_i64));
    assert_eq!(
        document["registration_client_uri"],
        json!(format!("{ISSUER}/register/{}", stored.id.as_str()))
    );

    // The echoed metadata is the *stored* registration, including the two
    // fields the client never sent: the auth method it was defaulted to and the
    // PAR requirement this profile provisions (ADR-0002).
    assert_eq!(
        document["client_name"],
        json!(stored.registration.client_name)
    );
    assert_eq!(
        document["token_endpoint_auth_method"],
        json!("private_key_jwt")
    );
    assert_eq!(
        document["require_pushed_authorization_requests"],
        json!(true)
    );
    assert_eq!(document["response_types"], json!(["code"]));
    assert_eq!(document["redirect_uris"], json!(["https://rp.example/cb"]));

    // The registration access token is returned once and stored only as a
    // digest. Both halves matter: the digest must be of the token that was
    // handed over, and the token must not be recoverable from what was kept.
    let token = document["registration_access_token"]
        .as_str()
        .expect("a registration access token");
    assert_eq!(
        *digest,
        sha256(token.as_bytes()),
        "the stored digest is not the digest of the token the client was given"
    );
    assert_eq!(token.len(), 43, "256 bits is 43 base64url symbols");
    assert_ne!(
        hex::encode(digest),
        token,
        "the at-rest form must not be the credential"
    );

    // The policy decision is in the trail (`ast-m9c.4`'s definition of done).
    let events = audit.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_type, EventType::CLIENT_REGISTERED);
    assert_eq!(events[0].outcome, Outcome::Success);
    assert_eq!(events[0].client.as_ref(), Some(&stored.id));
    assert_eq!(events[0].request_id.as_deref(), Some("req-1"));
    assert_eq!(
        events[0].detail.iter().find(|(k, _)| *k == "policy"),
        Some((
            &"policy".to_owned(),
            &DetailValue::Text("initial_access_token".to_owned())
        ))
    );
}

/// RFC 7591 §3.2.2: a rejected document is a 400 naming the field, and the
/// error code distinguishes a redirect URI failure from every other one. No row
/// is written — a registration that failed validation must leave nothing to
/// clean up, and nothing an attacker can point a later request at.
#[tokio::test]
async fn a_rejected_document_is_a_400_naming_the_field_and_writes_nothing() {
    let cases: [(Value, &str, &str); 5] = [
        (
            json!({
                "redirect_uris": ["https://rp.example/cb"],
                "jwks": {"keys": [{"kty": "OKP", "crv": "Ed25519", "x": "abc"}]},
            }),
            "invalid_client_metadata",
            "client_name",
        ),
        (
            json!({
                "client_name": "Billing",
                "redirect_uris": ["http://rp.example/cb"],
                "jwks": {"keys": [{"kty": "OKP", "crv": "Ed25519", "x": "abc"}]},
            }),
            "invalid_redirect_uri",
            "redirect_uris",
        ),
        (
            json!({
                "client_name": "Billing",
                "redirect_uris": ["https://rp.example/cb"],
                "token_endpoint_auth_method": "client_secret_basic",
                "jwks": {"keys": [{"kty": "OKP", "crv": "Ed25519", "x": "abc"}]},
            }),
            "invalid_client_metadata",
            "token_endpoint_auth_method",
        ),
        (
            json!({
                "client_name": "Billing",
                "redirect_uris": ["https://rp.example/cb"],
                "jwks": {"keys": [{"kty": "OKP", "crv": "Ed25519", "x": "abc"}]},
                "jwks_uri": "https://rp.example/jwks",
            }),
            "invalid_client_metadata",
            "jwks",
        ),
        (
            json!({
                "client_name": "Billing",
                "redirect_uris": ["https://rp.example/cb"],
                "jwks": {"keys": [{"kty": "OKP", "crv": "Ed25519", "x": "abc"}]},
                "response_types": ["token"],
            }),
            "invalid_client_metadata",
            "response_types",
        ),
    ];

    for (document, code, field) in cases {
        let registry = FakeRegistry::default();
        let audit = FakeAudit::default();
        let body = serde_json::to_vec(&document).expect("serialise");
        let response = post(
            &gated(),
            &registry,
            &audit,
            &json_headers(Some(&format!("Bearer {TOKEN}"))),
            &body,
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{field}");
        let rendered = body_of(response).await;
        assert_eq!(rendered["error"], json!(code), "{field}");
        let description = rendered["error_description"]
            .as_str()
            .expect("a description");
        assert!(
            description.contains(field),
            "the description does not name the field that failed: {description}"
        );
        // RFC 7591 §3.2.2 calls `error_description` "human-readable ASCII text".
        assert!(description.is_ascii(), "{description}");

        assert!(
            registry.written().is_empty(),
            "a rejected registration wrote a row"
        );
        // Audited, because the caller held a credential — but as a failure, and
        // with no client id, since none was minted.
        let events = audit.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].outcome, Outcome::Failure);
        assert!(events[0].client.is_none());
    }
}

/// The description a rejected caller gets is written by this server. A
/// registration document is one of the few places a caller puts a credential by
/// mistake, and an endpoint reachable before client authentication must not
/// reflect its input.
#[tokio::test]
async fn an_error_never_quotes_the_document_back() {
    const MARKER: &str = "swordfish-please-do-not-echo-me";

    // One document per rejected field, so that each error path is exercised
    // rather than only the first rule that happens to fire. Every one of these
    // carries the marker in the value that fails.
    let documents = [
        json!({
            "client_name": MARKER,
            "redirect_uris": [format!("https://{MARKER}.example/cb")],
            "jwks": {"keys": [{"kty": "OKP", "crv": "Ed25519", "x": "abc"}]},
            "scope": format!("{MARKER} {}", "x".repeat(200)),
        }),
        json!({
            "client_name": "Billing",
            "redirect_uris": [format!("http://{MARKER}.example/cb")],
            "jwks": {"keys": [{"kty": "OKP", "crv": "Ed25519", "x": "abc"}]},
        }),
        json!({
            "client_name": "Billing",
            "redirect_uris": ["https://rp.example/cb"],
            "token_endpoint_auth_method": MARKER,
            "jwks": {"keys": [{"kty": "OKP", "crv": "Ed25519", "x": "abc"}]},
        }),
        json!({
            "client_name": "Billing",
            "redirect_uris": ["https://rp.example/cb"],
            "grant_types": [MARKER],
            "jwks": {"keys": [{"kty": "OKP", "crv": "Ed25519", "x": "abc"}]},
        }),
        json!({
            "client_name": "Billing",
            "redirect_uris": ["https://rp.example/cb"],
            "id_token_signed_response_alg": MARKER,
            "jwks": {"keys": [{"kty": "OKP", "crv": "Ed25519", "x": "abc"}]},
        }),
        json!({
            "client_name": "Billing",
            "redirect_uris": ["https://rp.example/cb"],
            "application_type": MARKER,
            "jwks": {"keys": [{"kty": "OKP", "crv": "Ed25519", "x": "abc"}]},
        }),
        // A syntax error, where `serde_json` renders the offending value into
        // its own message and the endpoint must drop it.
        json!(format!("{{\"client_name\": \"{MARKER}\"")),
    ];

    for document in documents {
        let registry = FakeRegistry::default();
        let audit = FakeAudit::default();
        let body = match document.as_str() {
            Some(raw) => raw.as_bytes().to_vec(),
            None => serde_json::to_vec(&document).expect("serialise"),
        };

        let response = post(
            &gated(),
            &registry,
            &audit,
            &json_headers(Some(&format!("Bearer {TOKEN}"))),
            &body,
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{document}");
        let rendered = body_of(response).await.to_string();
        assert!(
            !rendered.contains(MARKER),
            "the error echoed the request: {rendered}"
        );
    }
}

/// Malformed JSON is a metadata error like any other, and the position it
/// reports carries nothing out of the document.
#[tokio::test]
async fn a_body_that_is_not_json_is_a_metadata_error() {
    let registry = FakeRegistry::default();
    let audit = FakeAudit::default();
    let response = post(
        &gated(),
        &registry,
        &audit,
        &json_headers(Some(&format!("Bearer {TOKEN}"))),
        b"{\"client_name\": \"unterminated",
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let rendered = body_of(response).await;
    assert_eq!(rendered["error"], json!("invalid_client_metadata"));
    assert!(
        !rendered["error_description"]
            .as_str()
            .expect("a description")
            .contains("unterminated")
    );
    assert!(registry.written().is_empty());
}

/// The gate runs before anything else, so a refused caller cannot make this
/// process parse a document, mint an identifier or write an audit row. The last
/// one is the point: `audit_events` cannot be deleted from, so a row per
/// unauthenticated request would be an amplification primitive aimed at the one
/// table with no way back.
#[tokio::test]
async fn a_caller_the_policy_refuses_reaches_neither_the_parser_nor_the_store() {
    let cases = [
        (RegistrationPolicy::Closed, None, Denial::Closed),
        (gated(), None, Denial::Missing),
        (gated(), Some("Bearer not-the-token"), Denial::Invalid),
        (gated(), Some("Basic dXNlcjpwdw=="), Denial::Missing),
    ];

    for (policy, authorization, expected) in cases {
        let registry = FakeRegistry::default();
        let audit = FakeAudit::default();
        // A body that would be rejected by the validator anyway, so that a
        // status of 400 would prove the gate ran too late.
        let response = post(
            &policy,
            &registry,
            &audit,
            &json_headers(authorization),
            b"not json at all",
        )
        .await;

        assert_eq!(response.status(), expected.status(), "{authorization:?}");
        assert_eq!(
            response
                .headers()
                .get(header::WWW_AUTHENTICATE)
                .and_then(|v| v.to_str().ok()),
            expected.challenge(),
            "{authorization:?}"
        );
        let rendered = body_of(response).await;
        assert_eq!(rendered["error"], json!(expected.code()));

        assert!(registry.written().is_empty(), "{authorization:?}");
        assert!(
            audit.events().is_empty(),
            "a denial before the gate was written to the audit trail"
        );
    }
}

/// Open registration is the mode RFC 7591 §3 recommends and this deployment
/// does not default to. When an operator does choose it, no credential is
/// asked for — and the trail says which posture produced the client, so that
/// "how did this get here?" has an answer.
#[tokio::test]
async fn open_registration_needs_no_credential_and_says_so_in_the_trail() {
    let registry = FakeRegistry::default();
    let audit = FakeAudit::default();
    let body = serde_json::to_vec(&document()).expect("serialise");
    let response = post(
        &RegistrationPolicy::Open,
        &registry,
        &audit,
        &json_headers(None),
        &body,
    )
    .await;

    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(registry.written().len(), 1);
    let events = audit.events();
    assert_eq!(
        events[0].detail.iter().find(|(k, _)| *k == "policy"),
        Some((&"policy".to_owned(), &DetailValue::Text("open".to_owned())))
    );
    assert_eq!(
        events[0]
            .detail
            .iter()
            .find(|(k, _)| *k == "open_registration"),
        Some((&"open_registration".to_owned(), &DetailValue::Flag(true)))
    );
}

/// Two registrations never collide, and never share a credential. A `client_id`
/// reused across registrations would let one client speak for another; a reused
/// registration access token would let one manage another.
#[tokio::test]
async fn two_registrations_share_neither_an_identifier_nor_a_token() {
    let registry = FakeRegistry::default();
    let audit = FakeAudit::default();
    let body = serde_json::to_vec(&document()).expect("serialise");
    let headers = json_headers(Some(&format!("Bearer {TOKEN}")));

    let first = body_of(post(&gated(), &registry, &audit, &headers, &body).await).await;
    let second = body_of(post(&gated(), &registry, &audit, &headers, &body).await).await;

    assert_ne!(first["client_id"], second["client_id"]);
    assert_ne!(
        first["registration_access_token"],
        second["registration_access_token"]
    );
    let written = registry.written();
    assert_ne!(
        written[0].1, written[1].1,
        "two clients share a token digest"
    );
}

/// RFC 7591 §3: the endpoint reads `application/json`. Anything else is a 415
/// rather than a guess, because a second encoding would be a second parser with
/// a second chance to disagree about the same document.
#[tokio::test]
async fn a_body_that_is_not_json_encoded_is_refused_before_it_is_read() {
    let registry = FakeRegistry::default();
    let audit = FakeAudit::default();
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        "application/x-www-form-urlencoded".parse().expect("header"),
    );
    headers.insert(
        header::AUTHORIZATION,
        format!("Bearer {TOKEN}").parse().expect("header"),
    );
    let body = serde_json::to_vec(&document()).expect("serialise");

    let response = post(&gated(), &registry, &audit, &headers, &body).await;
    assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert!(registry.written().is_empty());
}

/// The bound on what an authorized caller can make this process buffer. Checked
/// before the content type, because the body has already been read by the time
/// either runs and the cheaper refusal should be the one that fires.
#[tokio::test]
async fn an_oversized_document_is_refused() {
    let registry = FakeRegistry::default();
    let audit = FakeAudit::default();
    let body = vec![b'x'; MAX_BODY_BYTES + 1];

    let response = post(
        &gated(),
        &registry,
        &audit,
        &json_headers(Some(&format!("Bearer {TOKEN}"))),
        &body,
    )
    .await;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert!(registry.written().is_empty());
}

/// A store that cannot write must not produce a 201. The caller is told the
/// registration did not happen, which is true — nothing was stored — and it is
/// told with a code that says "try again", not one that says "your document was
/// wrong".
#[tokio::test]
async fn a_store_that_refuses_the_write_is_not_reported_as_a_bad_document() {
    let registry = FakeRegistry::broken();
    let audit = FakeAudit::default();
    let body = serde_json::to_vec(&document()).expect("serialise");

    let response = post(
        &gated(),
        &registry,
        &audit,
        &json_headers(Some(&format!("Bearer {TOKEN}"))),
        &body,
    )
    .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let rendered = body_of(response).await;
    assert_eq!(rendered["error"], json!("temporarily_unavailable"));

    let events = audit.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].outcome, Outcome::Failure);
    assert_eq!(
        events[0].detail.iter().find(|(k, _)| *k == "reason"),
        Some((
            &"reason".to_owned(),
            // Recorded through `Detail::label`; `Detail::text` would have
            // classified this string as a credential and stored a digest.
            &DetailValue::Text("temporarily_unavailable".to_owned())
        ))
    );
}
