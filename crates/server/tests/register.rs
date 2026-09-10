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

use asterius_domain::RegistrationPolicy as TenantRegistrationPolicy;
use asterius_domain::audit::{AuditEvent, AuditSink, DetailValue, EventType, Outcome};
use asterius_domain::keys::{KeyPurpose, KeyState, SigningAlgorithm};
use asterius_domain::ports::{InitialAccessTokenStore, JwksFetcher};
use asterius_domain::{
    Capabilities, Client, ClientRegistry, DomainError, InitialAccessToken,
    InitialAccessTokenReservation, Issuer, KeyStore, Kid, NewInitialAccessToken, PublicKeyRecord,
    Tenant, TenantId, TenantStatus, sha256,
};
use asterius_jose::jws;
use asterius_jose::key::SigningKey;
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

/// The tenant's key set: one active key per algorithm named, and nothing else.
///
/// Registration refuses an `id_token_signed_response_alg` the tenant holds no
/// active key for, so what this holds is what the endpoint will accept.
#[derive(Debug)]
struct FakeKeys(Vec<SigningAlgorithm>);

impl FakeKeys {
    /// The tenant a boot-time `apply_schedule` leaves behind: every advertised
    /// algorithm signable.
    fn provisioned() -> Self {
        Self(SigningAlgorithm::ALL.to_vec())
    }

    fn holding(algorithms: &[SigningAlgorithm]) -> Self {
        Self(algorithms.to_vec())
    }
}

#[async_trait::async_trait]
impl KeyStore for FakeKeys {
    async fn published_keys(&self, tenant: &TenantId) -> Result<Vec<PublicKeyRecord>, DomainError> {
        Ok(self
            .0
            .iter()
            .map(|algorithm| PublicKeyRecord {
                tenant: tenant.clone(),
                kid: Kid::new(format!("k-{algorithm}")),
                algorithm: *algorithm,
                purpose: KeyPurpose::Signing,
                state: KeyState::Active,
                public_jwk: json!({}),
                created_at: OffsetDateTime::UNIX_EPOCH,
            })
            .collect())
    }

    async fn public_key(
        &self,
        _tenant: &TenantId,
        _kid: &Kid,
    ) -> Result<Option<PublicKeyRecord>, DomainError> {
        Ok(None)
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
        default_resource: "https://api.example/".to_owned(),
        custom_host: None,
        display_name: "demo".into(),
        status: TenantStatus::Active,
        refresh: asterius_domain::RefreshPolicy::default(),
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

/// The outbound path, answered from memory.
///
/// `None` is a fetch that fails, which is what every test that registers no
/// `sector_identifier_uri` should see: nothing must dereference anything for
/// those, and a fetcher that would succeed could not prove it.
#[derive(Debug, Default)]
struct FakeOutbound {
    document: Option<Vec<u8>>,
}

impl FakeOutbound {
    fn serving(document: &Value) -> Self {
        Self {
            document: Some(document.to_string().into_bytes()),
        }
    }
}

#[async_trait::async_trait]
impl JwksFetcher for FakeOutbound {
    async fn fetch(&self, _url: &str) -> Result<Vec<u8>, DomainError> {
        self.document
            .clone()
            .ok_or_else(|| DomainError::invalid("sector_identifier_uri", "unreachable"))
    }
}

/// Runs one request against a fresh registry and audit sink.
async fn post(
    policy: &RegistrationPolicy,
    registry: &FakeRegistry,
    audit: &FakeAudit,
    headers: &HeaderMap,
    body: &[u8],
) -> Response {
    post_to(
        &FakeKeys::provisioned(),
        &FakeOutbound::default(),
        policy,
        registry,
        audit,
        headers,
        body,
    )
    .await
}

/// [`post`], with the outbound path spelt out for the registrations that use
/// it.
async fn post_with(
    outbound: &dyn JwksFetcher,
    policy: &RegistrationPolicy,
    registry: &FakeRegistry,
    audit: &FakeAudit,
    headers: &HeaderMap,
    body: &[u8],
) -> Response {
    post_to(
        &FakeKeys::provisioned(),
        outbound,
        policy,
        registry,
        audit,
        headers,
        body,
    )
    .await
}

/// [`post`], against a tenant whose stored registration policy is `policy`
/// (`ast-m9c.6`).
async fn post_under(
    tenant_policy: &TenantRegistrationPolicy,
    outbound: &dyn JwksFetcher,
    policy: &RegistrationPolicy,
    registry: &FakeRegistry,
    audit: &FakeAudit,
    headers: &HeaderMap,
    body: &[u8],
) -> Response {
    register(
        RegisterContext {
            tenant_policy,
            tenant: &tenant(),
            clients: registry,
            keys: &FakeKeys::provisioned(),
            capabilities: Capabilities::default(),
            policy,
            initial_access_tokens: None,
            audit,
            outbound,
            request_id: Some("req-1"),
        },
        headers,
        &Bytes::copy_from_slice(body),
        now(),
    )
    .await
}

/// A tenant policy from a stored document.
fn tenant_policy(document: &Value) -> TenantRegistrationPolicy {
    TenantRegistrationPolicy::from_json(Some(document)).expect("the test policy is valid")
}

/// One tenant's initial access tokens, in memory (`ast-cu3`).
///
/// Reserving is the whole point of the fake, so it enforces the quota and the
/// expiry rather than answering `Reserved` to anything: a fake that always
/// admitted would make every test below pass against an endpoint that never
/// looked at the row.
#[derive(Debug, Default)]
struct FakeInitialAccessTokens {
    rows: Mutex<Vec<(TenantId, [u8; 32], InitialAccessToken)>>,
}

impl FakeInitialAccessTokens {
    /// Stores a token of `tenant` with the given quota and expiry.
    fn holding(
        tenant: &TenantId,
        token: &str,
        max_uses: Option<u32>,
        expires_at: Option<OffsetDateTime>,
    ) -> Self {
        let store = Self::default();
        store.rows.lock().expect("lock").push((
            tenant.clone(),
            sha256(token.as_bytes()),
            InitialAccessToken {
                id: uuid::Uuid::from_u128(0xa5),
                tenant: tenant.clone(),
                label: "onboarding".to_owned(),
                uses: 0,
                max_uses,
                expires_at,
                created_at: now(),
            },
        ));
        store
    }

    /// How many uses have been charged against the only token in the store.
    fn uses(&self) -> u32 {
        self.rows.lock().expect("lock")[0].2.uses
    }
}

#[async_trait::async_trait]
impl InitialAccessTokenStore for FakeInitialAccessTokens {
    async fn issue(
        &self,
        _token: &NewInitialAccessToken,
    ) -> Result<InitialAccessToken, DomainError> {
        unimplemented!("the registration endpoint never issues")
    }

    async fn reserve(
        &self,
        tenant: &TenantId,
        digest: &[u8; 32],
        now: OffsetDateTime,
    ) -> Result<InitialAccessTokenReservation, DomainError> {
        let mut rows = self.rows.lock().expect("lock");
        let Some((_, _, row)) = rows
            .iter_mut()
            .find(|(owner, stored, _)| owner == tenant && stored == digest)
        else {
            return Ok(InitialAccessTokenReservation::Unknown);
        };
        if row.expires_at.is_some_and(|at| at <= now) {
            return Ok(InitialAccessTokenReservation::Expired);
        }
        if row.remaining() == Some(0) {
            return Ok(InitialAccessTokenReservation::Exhausted);
        }
        row.uses += 1;
        Ok(InitialAccessTokenReservation::Reserved {
            id: row.id,
            remaining: row.remaining(),
        })
    }

    async fn release(&self, tenant: &TenantId, id: uuid::Uuid) -> Result<(), DomainError> {
        let mut rows = self.rows.lock().expect("lock");
        if let Some((_, _, row)) = rows
            .iter_mut()
            .find(|(owner, _, row)| owner == tenant && row.id == id)
        {
            row.uses = row.uses.saturating_sub(1);
        }
        Ok(())
    }

    async fn list(&self, _tenant: &TenantId) -> Result<Vec<InitialAccessToken>, DomainError> {
        unimplemented!("the registration endpoint never lists")
    }
}

/// [`post_under`], with this tenant's own initial access tokens wired.
#[allow(clippy::too_many_arguments, reason = "one argument per collaborator, \
    and the endpoint context genuinely has this many; wrapping them in a \
    struct here would only move the list")]
async fn post_gated_by(
    tokens: &dyn InitialAccessTokenStore,
    tenant_policy: &TenantRegistrationPolicy,
    policy: &RegistrationPolicy,
    registry: &FakeRegistry,
    audit: &FakeAudit,
    headers: &HeaderMap,
    body: &[u8],
) -> Response {
    register(
        RegisterContext {
            tenant_policy,
            tenant: &tenant(),
            clients: registry,
            keys: &FakeKeys::provisioned(),
            capabilities: Capabilities::default(),
            policy,
            initial_access_tokens: Some(tokens),
            audit,
            outbound: &FakeOutbound::default(),
            request_id: Some("req-1"),
        },
        headers,
        &Bytes::copy_from_slice(body),
        now(),
    )
    .await
}

/// The document a per-tenant gate test registers: [`document`], serialised.
fn gated_document() -> Vec<u8> {
    serde_json::to_vec(&document()).expect("serialise the document")
}

/// A tenant that gates itself on its own tokens, with a per-token quota.
fn tenant_gate(quota: u32) -> TenantRegistrationPolicy {
    tenant_policy(&json!({
        "mode": "initial_access_token",
        "max_clients_per_initial_access_token": quota,
    }))
}

/// The same request against a tenant holding a chosen set of signing keys.
async fn post_to(
    keys: &FakeKeys,
    outbound: &dyn JwksFetcher,
    policy: &RegistrationPolicy,
    registry: &FakeRegistry,
    audit: &FakeAudit,
    headers: &HeaderMap,
    body: &[u8],
) -> Response {
    register(
        RegisterContext {
            tenant_policy: &asterius_domain::RegistrationPolicy::default(),
            tenant: &tenant(),
            clients: registry,
            keys,
            capabilities: Capabilities::default(),
            policy,
            initial_access_tokens: None,
            audit,
            outbound,
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

// ---- sector identifiers (OIDC Registration §5) ----------------------------

/// A pairwise registration across two hosts, which must name a sector and
/// therefore owes the §5 fetch.
fn pairwise_document() -> Value {
    let mut document = document();
    let object = document.as_object_mut().expect("object");
    object.insert(
        "redirect_uris".to_owned(),
        json!(["https://a.rp.example/cb", "https://b.rp.example/cb"]),
    );
    object.insert("subject_type".to_owned(), json!("pairwise"));
    object.insert(
        "sector_identifier_uri".to_owned(),
        json!("https://rp.example/sector.json"),
    );
    document
}

/// The success path: the sector's owner lists both callbacks, so the client has
/// shown it belongs to the sector it named.
#[tokio::test]
async fn a_pairwise_client_whose_sector_lists_its_redirect_uris_is_registered() {
    let registry = FakeRegistry::default();
    let audit = FakeAudit::default();
    let outbound = FakeOutbound::serving(&json!([
        "https://a.rp.example/cb",
        "https://b.rp.example/cb"
    ]));

    let response = post_with(
        &outbound,
        &RegistrationPolicy::Open,
        &registry,
        &audit,
        &json_headers(None),
        pairwise_document().to_string().as_bytes(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::CREATED);
}

/// Naming a sector the client does not control must not register: it would be
/// handed the `sub` values of everyone else in that sector.
#[tokio::test]
async fn a_pairwise_client_missing_from_its_sector_document_is_refused() {
    let registry = FakeRegistry::default();
    let audit = FakeAudit::default();
    let outbound = FakeOutbound::serving(&json!(["https://a.rp.example/cb"]));

    let response = post_with(
        &outbound,
        &RegistrationPolicy::Open,
        &registry,
        &audit,
        &json_headers(None),
        pairwise_document().to_string().as_bytes(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        body_of(response).await["error"],
        json!("invalid_client_metadata")
    );
}

/// A sector that cannot be fetched — no answer, or an address the ADR-0006
/// guard refuses — fails closed rather than being taken on trust.
#[tokio::test]
async fn a_pairwise_client_whose_sector_cannot_be_fetched_is_refused() {
    let registry = FakeRegistry::default();
    let audit = FakeAudit::default();

    let response = post_with(
        &FakeOutbound::default(),
        &RegistrationPolicy::Open,
        &registry,
        &audit,
        &json_headers(None),
        pairwise_document().to_string().as_bytes(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        body_of(response).await["error"],
        json!("invalid_client_metadata")
    );
}

/// A `sector_identifier_uri` that is not https never reaches the fetcher: the
/// document is refused by validation, so no address is ever dereferenced.
#[tokio::test]
async fn a_sector_identifier_uri_that_is_not_https_is_refused_before_any_fetch() {
    let registry = FakeRegistry::default();
    let audit = FakeAudit::default();
    let mut document = pairwise_document();
    document.as_object_mut().expect("object").insert(
        "sector_identifier_uri".to_owned(),
        json!("http://rp.example/sector.json"),
    );

    let response = post_with(
        // Serving the document that would have satisfied §5: the refusal must
        // come from the scheme, not from the fetch failing.
        &FakeOutbound::serving(&json!([
            "https://a.rp.example/cb",
            "https://b.rp.example/cb"
        ])),
        &RegistrationPolicy::Open,
        &registry,
        &audit,
        &json_headers(None),
        document.to_string().as_bytes(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        body_of(response).await["error"],
        json!("invalid_client_metadata")
    );
}

/// The bug `ast-a05.13` is about: a document naming an `id_token_signed_response_alg`
/// its tenant holds no active key for used to be accepted, and the client only
/// found out at its first token request, as an opaque `NoSigningKey` failure.
/// RFC 7591 §3.2.2 has a code for exactly this, and now it is used.
#[tokio::test]
async fn an_algorithm_the_tenant_cannot_sign_with_is_refused_at_registration() {
    let registry = FakeRegistry::default();
    let audit = FakeAudit::default();
    let mut document = document();
    document["id_token_signed_response_alg"] = json!("ES256");
    let body = serde_json::to_vec(&document).expect("serialise");

    let response = post_to(
        // A tenant whose only signing key is the default one.
        &FakeKeys::holding(&[SigningAlgorithm::EdDsa]),
        &FakeOutbound::default(),
        &gated(),
        &registry,
        &audit,
        &json_headers(Some(&format!("Bearer {TOKEN}"))),
        &body,
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let rendered = body_of(response).await;
    assert_eq!(rendered["error"], json!("invalid_client_metadata"));
    assert!(
        rendered["error_description"]
            .as_str()
            .expect("a description")
            .contains("ES256"),
        "the description must name the field's value so it can be fixed: {rendered}"
    );
    // Nothing was written: a client that could never be issued an ID token must
    // not exist as a row, and must not consume a `client_id`.
    assert!(registry.written().is_empty());
    let events = audit.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].outcome, Outcome::Failure);
    assert_eq!(
        events[0].detail.iter().find(|(k, _)| *k == "reason"),
        Some((
            &"reason".to_owned(),
            &DetailValue::Text("invalid_client_metadata".to_owned())
        ))
    );
}

/// The other side of it: a tenant provisioned as `TenantKeyStore::apply_schedule`
/// leaves one accepts every algorithm the discovery document advertises.
#[tokio::test]
async fn every_advertised_algorithm_registers_against_a_provisioned_tenant() {
    for algorithm in SigningAlgorithm::ALL {
        let registry = FakeRegistry::default();
        let audit = FakeAudit::default();
        let mut document = document();
        document["id_token_signed_response_alg"] = json!(algorithm.as_str());
        let body = serde_json::to_vec(&document).expect("serialise");

        let response = post(
            &gated(),
            &registry,
            &audit,
            &json_headers(Some(&format!("Bearer {TOKEN}"))),
            &body,
        )
        .await;

        assert_eq!(
            response.status(),
            StatusCode::CREATED,
            "{algorithm} refused"
        );
        assert_eq!(registry.written().len(), 1);
    }
}

/// A native client whose only callbacks are on the loopback interface, asking
/// for pairwise subjects without naming a sector — `ast-m9c.10`.
fn loopback_pairwise_document() -> Value {
    json!({
        "client_name": "Desktop",
        "application_type": "native",
        "redirect_uris": ["http://127.0.0.1:51004/cb"],
        "grant_types": ["authorization_code"],
        "subject_type": "pairwise",
        "jwks": {"keys": [{"kty": "OKP", "crv": "Ed25519", "x": "abc"}]},
    })
}

/// OIDC Core §8.1 derives the sector from "the host component of the registered
/// `redirect_uri`", and RFC 8252 §7.3 gives *every* native client the same
/// loopback host. A pairwise client with nothing but loopback callbacks and no
/// `sector_identifier_uri` would therefore put every native client of the
/// deployment into one sector, and hand them all the same correlatable `sub`
/// under a registration that says `pairwise`.
///
/// The document is refused at registration, as RFC 7591 §3.2.2
/// `invalid_client_metadata` — not at the authorization request that would
/// otherwise fail later for a reason the client never sees.
#[tokio::test]
async fn a_pairwise_client_with_only_loopback_callbacks_is_refused_at_registration() {
    let registry = FakeRegistry::default();
    let audit = FakeAudit::default();

    let response = post(
        &RegistrationPolicy::Open,
        &registry,
        &audit,
        &json_headers(None),
        loopback_pairwise_document().to_string().as_bytes(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = body_of(response).await;
    assert_eq!(body["error"], json!("invalid_client_metadata"));
    assert!(
        body["error_description"]
            .as_str()
            .expect("a description")
            .contains("sector_identifier_uri"),
        "the client is not told what to register instead: {body}"
    );
    assert!(
        registry.written().is_empty(),
        "a refused document registered a client"
    );
}

/// The rule is that the sector is underivable, not that loopback is suspicious:
/// a pairwise client with a callback on a host of its own registers as before.
#[tokio::test]
async fn a_pairwise_client_with_a_host_of_its_own_still_registers() {
    let registry = FakeRegistry::default();
    let audit = FakeAudit::default();
    let mut document = loopback_pairwise_document();
    let object = document.as_object_mut().expect("object");
    object.insert("application_type".to_owned(), json!("web"));
    object.insert(
        "redirect_uris".to_owned(),
        json!(["https://desktop.rp.example/cb"]),
    );

    let response = post(
        &RegistrationPolicy::Open,
        &registry,
        &audit,
        &json_headers(None),
        document.to_string().as_bytes(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::CREATED);
}

// ---- the tenant's registration policy (`ast-m9c.6`) ----------------------

/// The issuer whose software statements the test tenant trusts.
const VOUCHER: &str = "https://vouch.example";
/// The `kid` the voucher publishes.
const VOUCHER_KID: &str = "vouch-1";

/// A policy naming one trusted software statement issuer.
fn trusting_the_voucher(required: bool) -> Value {
    json!({
        "software_statement": {
            "required": required,
            "issuers": [{
                "issuer": VOUCHER,
                "jwks_uri": "https://vouch.example/jwks"
            }]
        }
    })
}

/// The voucher's signing key and the JWK Set it publishes.
fn voucher_key() -> (SigningKey, Value) {
    let key = SigningKey::generate(SigningAlgorithm::EdDsa).expect("generate");
    let mut jwk = key.public_jwk().expect("jwk");
    jwk["kid"] = json!(VOUCHER_KID);
    (key, json!({ "keys": [jwk] }))
}

/// A software statement signed by the voucher, asserting `claims`.
fn statement(key: &SigningKey, claims: &Value) -> String {
    jws::sign(
        key,
        &Kid::new(VOUCHER_KID),
        "software-statement+jwt",
        claims,
    )
    .expect("sign")
    .as_str()
    .to_owned()
}

/// The detail a refusal recorded under `name`, if any.
fn detail(audit: &FakeAudit, name: &str) -> Option<String> {
    let events = audit.events();
    let event = events.first()?;
    event
        .detail
        .iter()
        .find(|(key, _)| key.as_str() == name)
        .and_then(|(_, value)| match value {
            DetailValue::Text(text) => Some(text.clone()),
            _ => None,
        })
}

/// A tenant may refuse a document the profile would have accepted, and the
/// refusal is RFC 7591 §3.2.2's `invalid_client_metadata` with the rule in the
/// trail and not in the response.
#[tokio::test]
async fn a_document_the_tenants_policy_refuses_is_not_registered() {
    // Arrange
    let registry = FakeRegistry::default();
    let audit = FakeAudit::default();
    let policy = tenant_policy(&json!({ "redirect_uri_hosts": ["trusted.example"] }));
    let body = serde_json::to_vec(&document()).expect("serialise");

    // Act
    let response = post_under(
        &policy,
        &FakeOutbound::default(),
        &gated(),
        &registry,
        &audit,
        &json_headers(Some(&format!("Bearer {TOKEN}"))),
        &body,
    )
    .await;

    // Assert
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let rendered = body_of(response).await;
    assert_eq!(rendered["error"], json!("invalid_client_metadata"));
    assert!(
        !rendered["error_description"]
            .as_str()
            .expect("a description")
            .contains("rp.example"),
        "the refusal must not echo a value from the document: {rendered}"
    );
    assert!(registry.written().is_empty());
    assert_eq!(
        detail(&audit, "rule").as_deref(),
        Some("redirect_host_not_allowed"),
        "the failing rule belongs in the audit trail"
    );
}

/// RFC 7591 §2.3: "Values of client metadata that are conveyed in the software
/// statement ... MUST take precedence over those conveyed using plain JSON
/// values."
#[tokio::test]
async fn a_software_statement_overrides_the_requested_metadata() {
    // Arrange
    let registry = FakeRegistry::default();
    let audit = FakeAudit::default();
    let (key, jwks) = voucher_key();
    let mut requested = document();
    requested["client_name"] = json!("Whatever the registrant typed");
    requested["software_statement"] = json!(statement(
        &key,
        &json!({ "iss": VOUCHER, "client_name": "Vouched by the fleet manager" })
    ));
    let body = serde_json::to_vec(&requested).expect("serialise");

    // Act
    let response = post_under(
        &tenant_policy(&trusting_the_voucher(false)),
        &FakeOutbound::serving(&jwks),
        &gated(),
        &registry,
        &audit,
        &json_headers(Some(&format!("Bearer {TOKEN}"))),
        &body,
    )
    .await;

    // Assert
    assert_eq!(response.status(), StatusCode::CREATED);
    let written = registry.written();
    assert_eq!(written.len(), 1);
    assert_eq!(
        written[0].0.registration.client_name,
        "Vouched by the fleet manager"
    );
}

/// RFC 7591 §3.2.2's `unapproved_software_statement`, and no fetch: a tenant
/// cannot be made to dereference anything by presenting a statement from
/// somebody it never trusted.
#[tokio::test]
async fn a_statement_from_an_unapproved_issuer_is_refused() {
    // Arrange
    let registry = FakeRegistry::default();
    let audit = FakeAudit::default();
    let (key, _) = voucher_key();
    let mut requested = document();
    requested["software_statement"] = json!(statement(
        &key,
        &json!({ "iss": "https://stranger.example", "client_name": "Trojan" })
    ));
    let body = serde_json::to_vec(&requested).expect("serialise");

    // Act
    let response = post_under(
        &tenant_policy(&trusting_the_voucher(false)),
        // A fetcher that fails, so a passing test proves nothing was fetched
        // rather than that the fetch succeeded.
        &FakeOutbound::default(),
        &gated(),
        &registry,
        &audit,
        &json_headers(Some(&format!("Bearer {TOKEN}"))),
        &body,
    )
    .await;

    // Assert
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        body_of(response).await["error"],
        json!("unapproved_software_statement")
    );
    assert!(registry.written().is_empty());
}

/// A statement signed by a key the issuer does not publish is
/// `invalid_software_statement` — the same answer as a malformed one, because
/// the difference is the bearer's business and not the client's.
#[tokio::test]
async fn a_statement_signed_by_an_unpublished_key_is_invalid() {
    // Arrange
    let registry = FakeRegistry::default();
    let audit = FakeAudit::default();
    let (impostor, _) = voucher_key();
    let (_, published) = voucher_key();
    let mut requested = document();
    requested["software_statement"] = json!(statement(
        &impostor,
        &json!({ "iss": VOUCHER, "client_name": "Trojan" })
    ));
    let body = serde_json::to_vec(&requested).expect("serialise");

    // Act
    let response = post_under(
        &tenant_policy(&trusting_the_voucher(false)),
        &FakeOutbound::serving(&published),
        &gated(),
        &registry,
        &audit,
        &json_headers(Some(&format!("Bearer {TOKEN}"))),
        &body,
    )
    .await;

    // Assert
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        body_of(response).await["error"],
        json!("invalid_software_statement")
    );
    assert!(registry.written().is_empty());
}

#[tokio::test]
async fn a_statement_that_is_not_a_jwt_is_invalid() {
    // Arrange
    let registry = FakeRegistry::default();
    let audit = FakeAudit::default();
    let mut requested = document();
    requested["software_statement"] = json!("not.a.jwt");
    let body = serde_json::to_vec(&requested).expect("serialise");

    // Act
    let response = post_under(
        &tenant_policy(&trusting_the_voucher(false)),
        &FakeOutbound::default(),
        &gated(),
        &registry,
        &audit,
        &json_headers(Some(&format!("Bearer {TOKEN}"))),
        &body,
    )
    .await;

    // Assert
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        body_of(response).await["error"],
        json!("invalid_software_statement")
    );
}

/// The `agent` onboarding rule (`E11_01`): this tenant registers nothing that
/// nobody vouched for.
#[tokio::test]
async fn a_tenant_that_requires_a_statement_refuses_a_document_without_one() {
    // Arrange
    let registry = FakeRegistry::default();
    let audit = FakeAudit::default();
    let body = serde_json::to_vec(&document()).expect("serialise");

    // Act
    let response = post_under(
        &tenant_policy(&trusting_the_voucher(true)),
        &FakeOutbound::default(),
        &gated(),
        &registry,
        &audit,
        &json_headers(Some(&format!("Bearer {TOKEN}"))),
        &body,
    )
    .await;

    // Assert
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        body_of(response).await["error"],
        json!("invalid_client_metadata")
    );
    assert_eq!(
        detail(&audit, "rule").as_deref(),
        Some("software_statement_required")
    );
    assert!(registry.written().is_empty());
}

/// Precedence decides *which* values are used, never *whether* they are
/// checked: a trusted issuer cannot assert a client this profile refuses.
#[tokio::test]
async fn a_statement_cannot_assert_a_client_the_profile_refuses() {
    // Arrange
    let registry = FakeRegistry::default();
    let audit = FakeAudit::default();
    let (key, jwks) = voucher_key();
    let mut requested = document();
    requested["software_statement"] = json!(statement(
        &key,
        &json!({
            "iss": VOUCHER,
            // FAPI 2.0 SP §5.3.2.1 item 3: not a method this server has.
            "token_endpoint_auth_method": "client_secret_basic"
        })
    ));
    let body = serde_json::to_vec(&requested).expect("serialise");

    // Act
    let response = post_under(
        &tenant_policy(&trusting_the_voucher(false)),
        &FakeOutbound::serving(&jwks),
        &gated(),
        &registry,
        &audit,
        &json_headers(Some(&format!("Bearer {TOKEN}"))),
        &body,
    )
    .await;

    // Assert
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        body_of(response).await["error"],
        json!("invalid_client_metadata")
    );
    assert!(registry.written().is_empty());
}

/// And the tenant's own rules apply to what the statement asserted, so a
/// vouching issuer is subject to the policy rather than an escape from it.
#[tokio::test]
async fn a_statement_is_still_subject_to_the_tenants_policy() {
    // Arrange
    let registry = FakeRegistry::default();
    let audit = FakeAudit::default();
    let (key, jwks) = voucher_key();
    let mut policy_document = trusting_the_voucher(false);
    policy_document["redirect_uri_hosts"] = json!(["trusted.example"]);
    let mut requested = document();
    requested["redirect_uris"] = json!(["https://trusted.example/cb"]);
    requested["software_statement"] = json!(statement(
        &key,
        &json!({ "iss": VOUCHER, "redirect_uris": ["https://elsewhere.example/cb"] })
    ));
    let body = serde_json::to_vec(&requested).expect("serialise");

    // Act
    let response = post_under(
        &tenant_policy(&policy_document),
        &FakeOutbound::serving(&jwks),
        &gated(),
        &registry,
        &audit,
        &json_headers(Some(&format!("Bearer {TOKEN}"))),
        &body,
    )
    .await;

    // Assert
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        detail(&audit, "rule").as_deref(),
        Some("redirect_host_not_allowed")
    );
    assert!(registry.written().is_empty());
}

/// `ast-0qv`: a tenant closes its own registration endpoint whatever the
/// deployment configured. The route is unmounted for it too — that half is
/// asserted in `tests/discovery.rs`, where the route/metadata parity lives.
#[tokio::test]
async fn a_tenant_that_closed_registration_refuses_a_valid_token() {
    // Arrange
    let registry = FakeRegistry::default();
    let audit = FakeAudit::default();
    let body = serde_json::to_vec(&document()).expect("serialise");

    // Act
    let response = post_under(
        &tenant_policy(&json!({ "mode": "closed" })),
        &FakeOutbound::default(),
        &gated(),
        &registry,
        &audit,
        &json_headers(Some(&format!("Bearer {TOKEN}"))),
        &body,
    )
    .await;

    // Assert
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(registry.written().is_empty());
}

/// And cannot open one the operator gated: a tenant asking for `open` against a
/// gated deployment still demands the token.
#[tokio::test]
async fn a_tenant_cannot_open_a_gated_deployment() {
    // Arrange
    let registry = FakeRegistry::default();
    let audit = FakeAudit::default();
    let body = serde_json::to_vec(&document()).expect("serialise");

    // Act
    let response = post_under(
        &tenant_policy(&json!({ "mode": "open" })),
        &FakeOutbound::default(),
        &gated(),
        &registry,
        &audit,
        &json_headers(None),
        &body,
    )
    .await;

    // Assert
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(registry.written().is_empty());
}

// ---- the per-tenant gate (`ast-cu3`) --------------------------------------

/// The acceptance criterion this ticket exists for: a tenant that has narrowed
/// itself to `initial_access_token` admits the token *it* was issued, and the
/// quota it configured is charged.
///
/// Before `ast-cu3` this combination refused everybody, because the only
/// credentials the endpoint could compare against were the deployment's, and a
/// tenant has none of those.
#[tokio::test]
async fn a_tenant_issued_token_registers_a_client_and_charges_the_quota() {
    // Arrange
    let tokens = FakeInitialAccessTokens::holding(&tenant().id, TOKEN, Some(2), None);
    let registry = FakeRegistry::default();
    let audit = FakeAudit::default();

    // Act
    let response = post_gated_by(
        &tokens,
        &tenant_gate(2),
        &RegistrationPolicy::Open,
        &registry,
        &audit,
        &json_headers(Some(&format!("Bearer {TOKEN}"))),
        &gated_document(),
    )
    .await;

    // Assert
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(registry.written().len(), 1);
    assert_eq!(tokens.uses(), 1, "the registration did not charge the token");
}

/// The quota is the point of the setting: past it, RFC 7591 §3.2.2 defers to
/// RFC 6750 §3.1 and the answer is a 401 `invalid_token`.
#[tokio::test]
async fn a_token_at_its_quota_is_refused() {
    // Arrange
    let tokens = FakeInitialAccessTokens::holding(&tenant().id, TOKEN, Some(1), None);
    let registry = FakeRegistry::default();
    let audit = FakeAudit::default();
    let spend = async || {
        post_gated_by(
            &tokens,
            &tenant_gate(1),
            &RegistrationPolicy::Open,
            &registry,
            &audit,
            &json_headers(Some(&format!("Bearer {TOKEN}"))),
            &gated_document(),
        )
        .await
    };
    assert_eq!(spend().await.status(), StatusCode::CREATED);

    // Act
    let refused = spend().await;

    // Assert
    assert_eq!(refused.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        refused
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .and_then(|value| value.to_str().ok()),
        Some(r#"Bearer error="invalid_token""#)
    );
    assert_eq!(body_of(refused).await["error"], json!("invalid_token"));
    assert_eq!(
        registry.written().len(),
        1,
        "a client was registered past the quota"
    );
}

/// An expiry a clock enforces, which is the other thing a configuration file
/// could not express.
#[tokio::test]
async fn an_expired_token_is_refused() {
    // Arrange
    let tokens = FakeInitialAccessTokens::holding(
        &tenant().id,
        TOKEN,
        Some(5),
        Some(now() - time::Duration::seconds(1)),
    );
    let registry = FakeRegistry::default();
    let audit = FakeAudit::default();

    // Act
    let response = post_gated_by(
        &tokens,
        &tenant_gate(5),
        &RegistrationPolicy::Open,
        &registry,
        &audit,
        &json_headers(Some(&format!("Bearer {TOKEN}"))),
        &gated_document(),
    )
    .await;

    // Assert
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(registry.written().is_empty());
}

/// The deployment's own credentials do not open a tenant that gates itself.
///
/// This is the direction that would otherwise be easy to get wrong: falling
/// back to the configured tokens when the table has no match would let an
/// operator's string register clients at a tenant that asked to control its own
/// registrations.
#[tokio::test]
async fn a_deployment_token_is_refused_at_a_tenant_that_gates_itself() {
    // Arrange: the store holds a *different* token; TOKEN is the deployment's.
    let tokens = FakeInitialAccessTokens::holding(&tenant().id, "a-token-of-this-tenant", None, None);
    let registry = FakeRegistry::default();
    let audit = FakeAudit::default();
    let deployment = RegistrationPolicy::Gated(InitialAccessTokens::from_tokens([TOKEN]));

    // Act
    let response = post_gated_by(
        &tokens,
        &tenant_gate(5),
        &deployment,
        &registry,
        &audit,
        &json_headers(Some(&format!("Bearer {TOKEN}"))),
        &gated_document(),
    )
    .await;

    // Assert
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(registry.written().is_empty());
}

/// The other half of the criterion: a tenant with no policy of its own is still
/// admitted by the deployment's tokens, exactly as before.
#[tokio::test]
async fn a_tenant_with_no_policy_still_uses_the_deployment_tokens() {
    // Arrange
    let tokens = FakeInitialAccessTokens::default();
    let registry = FakeRegistry::default();
    let audit = FakeAudit::default();
    let deployment = RegistrationPolicy::Gated(InitialAccessTokens::from_tokens([TOKEN]));

    // Act
    let response = post_gated_by(
        &tokens,
        &TenantRegistrationPolicy::default(),
        &deployment,
        &registry,
        &audit,
        &json_headers(Some(&format!("Bearer {TOKEN}"))),
        &gated_document(),
    )
    .await;

    // Assert
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(registry.written().len(), 1);
}

/// A refused document gives the quota back. The token bought a *client*, and a
/// registration that produced none must not have cost one.
#[tokio::test]
async fn a_refused_document_does_not_spend_the_quota() {
    // Arrange
    let tokens = FakeInitialAccessTokens::holding(&tenant().id, TOKEN, Some(1), None);
    let registry = FakeRegistry::default();
    let audit = FakeAudit::default();

    // Act
    let refused = post_gated_by(
        &tokens,
        &tenant_gate(1),
        &RegistrationPolicy::Open,
        &registry,
        &audit,
        &json_headers(Some(&format!("Bearer {TOKEN}"))),
        br#"{"redirect_uris": ["http://insecure.example/cb"]}"#,
    )
    .await;

    // Assert
    assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
    assert_eq!(tokens.uses(), 0, "a refused document spent a use");
}

/// A tenant that gates itself in a process with no store registers nobody,
/// rather than falling through to whatever the deployment configured.
#[tokio::test]
async fn a_tenant_gate_with_no_store_wired_refuses_everybody() {
    // Arrange
    let registry = FakeRegistry::default();
    let audit = FakeAudit::default();
    let deployment = RegistrationPolicy::Gated(InitialAccessTokens::from_tokens([TOKEN]));

    // Act
    let response = post_under(
        &tenant_gate(5),
        &FakeOutbound::default(),
        &deployment,
        &registry,
        &audit,
        &json_headers(Some(&format!("Bearer {TOKEN}"))),
        &gated_document(),
    )
    .await;

    // Assert
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(registry.written().is_empty());
}

/// A tenant that gates itself inside a *closed* deployment is still closed: the
/// tenant may only narrow what the deployment allows.
#[tokio::test]
async fn a_tenant_gate_cannot_open_a_closed_deployment() {
    // Arrange
    let tokens = FakeInitialAccessTokens::holding(&tenant().id, TOKEN, None, None);
    let registry = FakeRegistry::default();
    let audit = FakeAudit::default();

    // Act
    let response = post_gated_by(
        &tokens,
        &tenant_gate(5),
        &RegistrationPolicy::Closed,
        &registry,
        &audit,
        &json_headers(Some(&format!("Bearer {TOKEN}"))),
        &gated_document(),
    )
    .await;

    // Assert
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(registry.written().is_empty());
}
