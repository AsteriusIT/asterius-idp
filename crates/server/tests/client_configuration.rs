//! The RFC 7592 client configuration endpoint, end to end.
//!
//! One in-memory store standing in for `clients`, so the whole file runs in
//! milliseconds. What is *not* faked is anything that decides: the metadata
//! validator, the digest comparison, the immutability guard and the response
//! renderer are the real ones, and the fake does only what the table does —
//! hold rows, hand back what it holds, and refuse to write a row that is not
//! there.
//!
//! The fake is deliberately built with **two** clients in it. Almost every
//! question this endpoint has to answer is really a question about which of the
//! two a request may touch, and a fixture with one client cannot ask it.

use asterius_domain::audit::{AuditEvent, AuditSink, EventType, Outcome};
use asterius_domain::{
    Capabilities, Client, ClientConfiguration, ClientId, ClientRegistration, ClientRepository,
    ClientStatus, DomainError, Issuer, ManagedClient, OpaqueToken, Tenant, TenantId, TenantStatus,
    sha256,
};
use asterius_server::http::client_configuration::{ConfigurationContext, read, remove, update};
use axum::body::Bytes;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::Response;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::Mutex;
use time::OffsetDateTime;

const ISSUER: &str = "https://as.example/t/demo";

// ---- the fake store ------------------------------------------------------

/// One row of the fake `clients` table.
#[derive(Debug, Clone)]
struct Row {
    client: Client,
    /// The digest, exactly as the column holds it. `None` is a client that was
    /// never given a configuration endpoint — an admin-created one.
    registration_access_token: Option<[u8; 32]>,
    /// The per-client resource allow-list. Not part of the registration
    /// document (`ast-m9c.6` owns it), so an update must not touch it.
    resources: Vec<String>,
}

#[derive(Debug, Default)]
struct FakeClients {
    rows: Mutex<BTreeMap<String, Row>>,
    broken: bool,
}

impl FakeClients {
    fn broken() -> Self {
        Self {
            broken: true,
            ..Self::default()
        }
    }

    fn insert(&self, row: Row) {
        self.rows
            .lock()
            .expect("lock")
            .insert(row.client.id.as_str().to_owned(), row);
    }

    fn row(&self, id: &str) -> Option<Row> {
        self.rows.lock().expect("lock").get(id).cloned()
    }

    fn ids(&self) -> Vec<String> {
        self.rows.lock().expect("lock").keys().cloned().collect()
    }

    fn storage_failure() -> DomainError {
        DomainError::Storage("the database is gone".into())
    }
}

#[async_trait::async_trait]
impl ClientRepository for FakeClients {
    async fn find(&self, client_id: &ClientId) -> Result<Option<Client>, DomainError> {
        if self.broken {
            return Err(Self::storage_failure());
        }
        Ok(self.row(client_id.as_str()).map(|row| row.client))
    }
}

#[async_trait::async_trait]
impl ClientConfiguration for FakeClients {
    async fn managed(&self, client_id: &ClientId) -> Result<Option<ManagedClient>, DomainError> {
        if self.broken {
            return Err(Self::storage_failure());
        }
        Ok(self.row(client_id.as_str()).map(|row| ManagedClient {
            registration_access_token: row.registration_access_token,
            status: row.client.status,
        }))
    }

    async fn replace(&self, client: &Client) -> Result<Client, DomainError> {
        if self.broken {
            return Err(Self::storage_failure());
        }
        let mut rows = self.rows.lock().expect("lock");
        // An `update`, like the statement it stands for: no row, no write.
        let Some(row) = rows.get_mut(client.id.as_str()) else {
            return Err(DomainError::NotFound);
        };
        // The columns the statement's `set` list does not name survive: the
        // token, the status, the creation time and the resource allow-list.
        row.client.registration = client.registration.clone();
        row.client.updated_at = OffsetDateTime::from_unix_timestamp(1_760_000_500).expect("time");
        // The row's own `resources` column, restored on the way out the way
        // `PgClientRepository` restores it from the column.
        row.client.registration.resources = row.resources.iter().cloned().collect();
        Ok(row.client.clone())
    }

    async fn deprovision(&self, client_id: &ClientId) -> Result<(), DomainError> {
        if self.broken {
            return Err(Self::storage_failure());
        }
        self.rows
            .lock()
            .expect("lock")
            .remove(client_id.as_str())
            .map(|_| ())
            .ok_or(DomainError::NotFound)
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
        "id_token_signed_response_alg": "PS256",
        "authorization_details_types": ["payment_initiation"],
        "jwks": {"keys": [{"kty": "OKP", "crv": "Ed25519", "x": "abc"}]},
    })
}

fn client(id: &str, document: &Value) -> Client {
    Client {
        tenant: TenantId::new("demo"),
        id: ClientId::new(id),
        registration: ClientRegistration::from_json(
            &serde_json::to_vec(document).expect("serialise"),
            Capabilities::default(),
        )
        .expect("a valid registration"),
        status: ClientStatus::Active,
        created_at: OffsetDateTime::from_unix_timestamp(1_760_000_000).expect("instant"),
        updated_at: OffsetDateTime::from_unix_timestamp(1_760_000_000).expect("instant"),
    }
}

/// Two clients, each with its own registration access token.
///
/// The second exists for one reason: every "is this token allowed to do this"
/// question needs a token that is real and belongs to somebody else.
struct Fixture {
    tenant: Tenant,
    clients: FakeClients,
    audit: FakeAudit,
    alpha: OpaqueToken,
    beta: OpaqueToken,
}

impl Fixture {
    fn new() -> Self {
        let clients = FakeClients::default();
        let alpha = OpaqueToken::generate();
        let beta = OpaqueToken::generate();
        clients.insert(Row {
            client: client("c.alpha", &document()),
            registration_access_token: Some(sha256(alpha.expose().as_bytes())),
            resources: vec!["https://api.example/accounts".to_owned()],
        });
        clients.insert(Row {
            client: client("c.beta", &document()),
            registration_access_token: Some(sha256(beta.expose().as_bytes())),
            resources: Vec::new(),
        });
        Self {
            tenant: tenant(),
            clients,
            audit: FakeAudit::default(),
            alpha,
            beta,
        }
    }

    fn context(&self) -> ConfigurationContext<'_> {
        ConfigurationContext {
            tenant: &self.tenant,
            clients: &self.clients,
            configuration: &self.clients,
            capabilities: Capabilities::default(),
            audit: &self.audit,
            request_id: Some("req-1"),
        }
    }
}

fn headers(authorization: Option<&str>) -> HeaderMap {
    let mut map = HeaderMap::new();
    map.insert(
        header::CONTENT_TYPE,
        "application/json".parse().expect("header"),
    );
    if let Some(value) = authorization {
        map.insert(
            header::AUTHORIZATION,
            value.parse().expect("a valid header value"),
        );
    }
    map
}

fn bearer(token: &OpaqueToken) -> HeaderMap {
    headers(Some(&format!("Bearer {}", token.expose())))
}

async fn body_of(response: Response) -> Value {
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("read the body");
    serde_json::from_slice(&bytes).expect("the response body must be JSON")
}

/// The status, the `WWW-Authenticate` challenge and the whole body, which is
/// what "two refusals are indistinguishable" has to be checked over.
async fn refusal(response: Response) -> (StatusCode, Option<String>, Value) {
    let status = response.status();
    let challenge = response
        .headers()
        .get(header::WWW_AUTHENTICATE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    (status, challenge, body_of(response).await)
}

/// The document a client would send back to change one field, built from a read.
fn amended(read: &Value, change: impl FnOnce(&mut serde_json::Map<String, Value>)) -> Vec<u8> {
    let mut document = read.clone();
    change(document.as_object_mut().expect("object"));
    serde_json::to_vec(&document).expect("serialise")
}

// ---- authentication ------------------------------------------------------

/// OIDC Registration §4.1: the client a configuration URL names "MUST be
/// matched against the Client to which the Registration Access Token was
/// issued".
///
/// This is the assertion the endpoint exists to satisfy. A registration access
/// token is a bearer credential with read, replace and delete over one client;
/// if it worked at a second client's URL, any registered client could take over
/// any other. All three verbs are checked, because a guard on the read that was
/// forgotten on the delete is the same bug with a worse outcome.
#[tokio::test]
async fn a_token_for_one_client_does_nothing_at_another_clients_url() {
    let fixture = Fixture::new();
    let body = Bytes::from(serde_json::to_vec(&document()).expect("serialise"));

    // Alpha's token, entirely valid, presented at beta's URL.
    let got = read(&fixture.context(), "c.beta", &bearer(&fixture.alpha), now()).await;
    assert_eq!(got.status(), StatusCode::UNAUTHORIZED);

    let put = update(
        &fixture.context(),
        "c.beta",
        &bearer(&fixture.alpha),
        &body,
        now(),
    )
    .await;
    assert_eq!(put.status(), StatusCode::UNAUTHORIZED);

    let deleted = remove(&fixture.context(), "c.beta", &bearer(&fixture.alpha), now()).await;
    assert_eq!(deleted.status(), StatusCode::UNAUTHORIZED);

    // Nothing happened to beta: it is still there and still what it was.
    assert_eq!(fixture.clients.ids(), vec!["c.alpha", "c.beta"]);
    let beta = fixture.clients.row("c.beta").expect("beta survives");
    assert_eq!(beta.client.registration.client_name, "Billing");

    // And alpha's own token still works at alpha's URL, so the refusal above
    // was about the pairing and not about the token.
    let mine = read(
        &fixture.context(),
        "c.alpha",
        &bearer(&fixture.alpha),
        now(),
    )
    .await;
    assert_eq!(mine.status(), StatusCode::OK);
}

/// OIDC Registration §4.4: "for security reasons, to inhibit brute force
/// attacks, endpoints MUST NOT return the HTTP 404 Not Found status code",
/// and an unknown client, an invalid client and an invalid token all get the
/// same 401.
///
/// Checked over the whole response — status, challenge and body — because a
/// difference in any one of them is an oracle for which `client_id` values are
/// registered, which is exactly what the 404 would have been.
#[tokio::test]
async fn an_unknown_client_is_indistinguishable_from_a_wrong_token() {
    let fixture = Fixture::new();
    let stranger = OpaqueToken::generate();

    // A client that does not exist, with a plausible token.
    let unknown =
        refusal(read(&fixture.context(), "c.nobody", &bearer(&stranger), now()).await).await;
    // A client that does exist, with the wrong token.
    let wrong = refusal(read(&fixture.context(), "c.alpha", &bearer(&stranger), now()).await).await;
    // A client that does exist, with another client's real token.
    let others =
        refusal(read(&fixture.context(), "c.beta", &bearer(&fixture.alpha), now()).await).await;

    assert_eq!(unknown.0, StatusCode::UNAUTHORIZED);
    assert_eq!(unknown, wrong, "an unknown client answers differently");
    assert_eq!(unknown, others, "a foreign token answers differently");
    assert_eq!(
        unknown.1.as_deref(),
        Some(r#"Bearer error="invalid_token""#),
        "RFC 6750 §3: a rejected credential is told so"
    );
    assert_eq!(unknown.2["error"], json!("invalid_token"));

    // The same for the other two verbs, which have the same rule in RFC 7592
    // §2.2 and §2.3.
    let body = Bytes::from(serde_json::to_vec(&document()).expect("serialise"));
    for response in [
        update(
            &fixture.context(),
            "c.nobody",
            &bearer(&stranger),
            &body,
            now(),
        )
        .await,
        remove(&fixture.context(), "c.nobody", &bearer(&stranger), now()).await,
    ] {
        assert_eq!(refusal(response).await, unknown);
    }
}

/// RFC 6750 §3: a request with no credential gets a bare challenge, not one
/// that describes a token it did not send.
#[tokio::test]
async fn a_request_with_no_credential_is_told_to_authenticate() {
    let fixture = Fixture::new();
    let (status, challenge, body) =
        refusal(read(&fixture.context(), "c.alpha", &headers(None), now()).await).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(challenge.as_deref(), Some("Bearer"));
    assert_eq!(body["error"], json!("invalid_token"));

    // A credential in the wrong scheme is no credential: RFC 6750 §2.1 defines
    // one scheme, and RFC 9110 §11.1 makes only the scheme name case-insensitive.
    let basic = format!("Basic {}", fixture.alpha.expose());
    let (status, challenge, _) =
        refusal(read(&fixture.context(), "c.alpha", &headers(Some(&basic)), now()).await).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(challenge.as_deref(), Some("Bearer"));
}

/// A client the admin API created was never given a configuration endpoint.
///
/// OIDC Registration §3.2: an implementation "MUST either return both a Client
/// Configuration Endpoint and a Registration Access Token or neither of them".
/// Such a client has neither, so its row has no digest — and a null column must
/// refuse every token rather than accept any.
#[tokio::test]
async fn a_client_that_was_never_issued_a_token_cannot_be_managed() {
    let fixture = Fixture::new();
    fixture.clients.insert(Row {
        client: client("c.admin", &document()),
        registration_access_token: None,
        resources: Vec::new(),
    });

    for token in [&fixture.alpha, &fixture.beta, &OpaqueToken::generate()] {
        let response = read(&fixture.context(), "c.admin", &bearer(token), now()).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    // Including the empty credential, which is what a naive comparison against
    // an absent column would accept.
    let empty = read(
        &fixture.context(),
        "c.admin",
        &headers(Some("Bearer ")),
        now(),
    )
    .await;
    assert_eq!(empty.status(), StatusCode::UNAUTHORIZED);
    assert!(fixture.clients.row("c.admin").is_some());
}

/// RFC 7592 §2.1 and OIDC Registration §4.4: a client that holds a valid token
/// but "does not have permission to read its record" gets a 403, not a 401.
///
/// The 403 is reachable only after a credential is accepted, so it tells
/// nothing to anyone who did not already hold the client's own token. A
/// suspended client is refused all three verbs — including the delete, because
/// `status = 'disabled'` is an operator's decision about a client under
/// investigation and a self-delete would cascade away the evidence.
#[tokio::test]
async fn a_suspended_client_is_forbidden_rather_than_unauthorised() {
    let fixture = Fixture::new();
    let mut row = fixture.clients.row("c.alpha").expect("alpha");
    row.client.status = ClientStatus::Disabled;
    fixture.clients.insert(row);

    let body = Bytes::from(serde_json::to_vec(&document()).expect("serialise"));
    for response in [
        read(
            &fixture.context(),
            "c.alpha",
            &bearer(&fixture.alpha),
            now(),
        )
        .await,
        update(
            &fixture.context(),
            "c.alpha",
            &bearer(&fixture.alpha),
            &body,
            now(),
        )
        .await,
        remove(
            &fixture.context(),
            "c.alpha",
            &bearer(&fixture.alpha),
            now(),
        )
        .await,
    ] {
        let (status, challenge, body) = refusal(response).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["error"], json!("access_denied"));
        assert_eq!(
            challenge, None,
            "a 403 must not invite a credential that was already accepted"
        );
    }
    assert!(
        fixture.clients.row("c.alpha").is_some(),
        "a suspended client deleted itself"
    );

    // And the wrong token against a suspended client is still a 401: the 403
    // must not become a way to learn that a suspended client exists.
    let (status, ..) = refusal(
        read(
            &fixture.context(),
            "c.alpha",
            &bearer(&OpaqueToken::generate()),
            now(),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// ---- read ----------------------------------------------------------------

/// RFC 7592 §2.1 and §3, OIDC Registration §4.3: a read returns "all registered
/// metadata about this client", from the row.
///
/// And the document that comes back re-registers as the same client, which is
/// what makes RFC 7592 §2.2's read-modify-write loop safe: §2.2 requires an
/// update to "include all client metadata fields as returned to the client from
/// a previous registration, read, or update operation", so a read whose output
/// did not round-trip would silently change the client on every update.
#[tokio::test]
async fn a_read_returns_the_stored_registration_and_it_round_trips() {
    let fixture = Fixture::new();
    let response = read(
        &fixture.context(),
        "c.alpha",
        &bearer(&fixture.alpha),
        now(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );

    let document = body_of(response).await;
    assert_eq!(document["client_id"], json!("c.alpha"));
    assert_eq!(document["client_id_issued_at"], json!(1_760_000_000_i64));
    assert_eq!(
        document["registration_client_uri"],
        json!(format!("{ISSUER}/register/c.alpha"))
    );
    assert_eq!(document["id_token_signed_response_alg"], json!("PS256"));
    assert_eq!(
        document["authorization_details_types"],
        json!(["payment_initiation"])
    );

    // OIDC Registration §4.3: the server "need not include the
    // registration_access_token ... unless [it has] been updated". This one
    // holds only its digest, so it never can.
    assert!(document.get("registration_access_token").is_none());
    // The per-client resource allow-list is policy, not registration metadata.
    assert!(document.get("resources").is_none());

    let stored = fixture.clients.row("c.alpha").expect("alpha").client;
    let round_tripped = ClientRegistration::from_json(
        &serde_json::to_vec(&document).expect("serialise"),
        Capabilities::default(),
    )
    .expect("a read must itself be a valid registration document");
    assert_eq!(
        round_tripped.redirect_uris,
        stored.registration.redirect_uris
    );
    assert_eq!(round_tripped.scopes, stored.registration.scopes);
    assert_eq!(
        round_tripped.id_token_signed_response_alg,
        stored.registration.id_token_signed_response_alg
    );
}

// ---- update --------------------------------------------------------------

/// RFC 7592 §2.2's replacement rule, which is the security rule of this story:
///
/// > Valid values of client metadata fields in this request MUST replace, not
/// > augment, the values previously associated with this client. Omitted fields
/// > MUST be treated as null or empty values by the server, indicating the
/// > client's request to delete them from the client's registration.
///
/// The request under test is the one a partial-update reading gets wrong: a
/// client changing its name, and saying nothing about anything else. Every
/// field it left out must come back at its registration-time default, not at
/// the value the row used to hold. `redirect_uris` is the one that matters —
/// keeping an old callback the client asked to drop is a live redirect target
/// the client no longer controls — and it is asserted here as a *changed* set
/// rather than an empty one, because a client with no callbacks is not a
/// document this validator accepts.
#[tokio::test]
async fn an_update_replaces_the_document_and_does_not_merge_it() {
    let fixture = Fixture::new();
    let before = fixture.clients.row("c.alpha").expect("alpha").client;
    assert_eq!(
        before.registration.id_token_signed_response_alg.as_str(),
        "PS256"
    );
    assert!(!before.registration.authorization_details_types.is_empty());
    assert!(!before.registration.scopes.is_empty());

    let body = Bytes::from(
        serde_json::to_vec(&json!({
            "client_id": "c.alpha",
            "client_name": "Billing, renamed",
            "redirect_uris": ["https://rp.example/new-cb"],
            "grant_types": ["authorization_code"],
            "jwks": {"keys": [{"kty": "OKP", "crv": "Ed25519", "x": "abc"}]},
        }))
        .expect("serialise"),
    );

    let response = update(
        &fixture.context(),
        "c.alpha",
        &bearer(&fixture.alpha),
        &body,
        now(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    let after = fixture.clients.row("c.alpha").expect("alpha").client;
    assert_eq!(after.registration.client_name, "Billing, renamed");

    // Replaced, not merged.
    assert_eq!(
        after
            .registration
            .redirect_uris
            .iter()
            .map(asterius_domain::RedirectUri::as_str)
            .collect::<Vec<_>>(),
        vec!["https://rp.example/new-cb"],
        "the old redirect URI survived an update that did not mention it"
    );
    assert_eq!(
        after.registration.id_token_signed_response_alg.as_str(),
        "EdDSA",
        "an omitted algorithm kept its old value instead of resetting to the default"
    );
    assert!(
        after.registration.authorization_details_types.is_empty(),
        "an omitted RFC 9396 type list was preserved"
    );
    assert!(
        after.registration.scopes.is_empty(),
        "an omitted scope string was preserved"
    );
    assert!(
        !after
            .registration
            .allows(asterius_domain::GrantType::RefreshToken),
        "an omitted grant type was preserved"
    );

    // The response is the stored row, so a client reading it sees the resets.
    let document = body_of(response).await;
    assert_eq!(
        document["redirect_uris"],
        json!(["https://rp.example/new-cb"])
    );
    assert_eq!(document["id_token_signed_response_alg"], json!("EdDSA"));
    assert_eq!(document["scope"], json!(""));

    // And what the client does not own is untouched: the resource allow-list
    // (`ast-m9c.6`) and the token that authorised the call.
    let row = fixture.clients.row("c.alpha").expect("alpha");
    assert_eq!(
        row.resources,
        vec!["https://api.example/accounts".to_owned()],
        "an update erased the per-client resource allow-list"
    );
    assert_eq!(
        row.registration_access_token,
        Some(sha256(fixture.alpha.expose().as_bytes())),
        "an update rotated the registration access token"
    );
}

/// RFC 7592 §2.2: "The client MUST include its `client_id` field in the request,
/// and it MUST be the same as its currently issued client identifier."
///
/// A `client_id` that names another client is the interesting case: it is a
/// client with a valid token asking to be somebody else. The refusal must be a
/// 400 about the document, and — the part that matters — the *other* client
/// must be untouched.
#[tokio::test]
async fn an_update_cannot_rename_a_client_or_point_at_another_one() {
    let fixture = Fixture::new();
    let read_back = body_of(
        read(
            &fixture.context(),
            "c.alpha",
            &bearer(&fixture.alpha),
            now(),
        )
        .await,
    )
    .await;

    for wrong in [json!("c.beta"), json!("c.other"), json!(7), json!(null)] {
        let body = Bytes::from(amended(&read_back, |object| {
            object.insert("client_id".to_owned(), wrong.clone());
        }));
        let response = update(
            &fixture.context(),
            "c.alpha",
            &bearer(&fixture.alpha),
            &body,
            now(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{wrong}");
        let document = body_of(response).await;
        assert_eq!(document["error"], json!("invalid_client_metadata"));
        // The description names the field and never quotes the value.
        let description = document["error_description"].as_str().expect("a string");
        assert!(description.contains("client_id"));
        assert!(!description.contains("c.beta"));
    }

    // An update with no `client_id` at all is not "unchanged": §2.2 makes it
    // required.
    let body = Bytes::from(amended(&read_back, |object| {
        object.remove("client_id");
    }));
    let response = update(
        &fixture.context(),
        "c.alpha",
        &bearer(&fixture.alpha),
        &body,
        now(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // Neither client moved.
    assert_eq!(fixture.clients.ids(), vec!["c.alpha", "c.beta"]);
    for id in ["c.alpha", "c.beta"] {
        assert_eq!(
            fixture
                .clients
                .row(id)
                .expect(id)
                .client
                .registration
                .client_name,
            "Billing"
        );
    }
}

/// RFC 7592 §2.2 on `client_secret`: a client "MUST NOT be allowed to overwrite
/// its existing client secret with its own chosen value", and the update "MUST
/// NOT include the `registration_access_token` ... or `client_secret_expires_at`"
/// fields.
///
/// This server issues no secret at all (FAPI 2.0 SP §5.3.2.1), so there is
/// nothing for either secret field to match — and a client that asked to set or
/// rotate a credential and received a 200 would hold a false belief about its
/// own credentials, which is the one thing a silent "ignored" must not do here.
#[tokio::test]
async fn an_update_cannot_claim_a_credential_this_server_does_not_issue() {
    let fixture = Fixture::new();
    let read_back = body_of(
        read(
            &fixture.context(),
            "c.alpha",
            &bearer(&fixture.alpha),
            now(),
        )
        .await,
    )
    .await;
    let attacker = OpaqueToken::generate();

    for (field, value) in [
        ("client_secret", json!("a secret of my own choosing")),
        ("client_secret_expires_at", json!(0)),
        ("registration_access_token", json!(attacker.expose())),
    ] {
        let body = Bytes::from(amended(&read_back, |object| {
            object.insert(field.to_owned(), value.clone());
        }));
        let response = update(
            &fixture.context(),
            "c.alpha",
            &bearer(&fixture.alpha),
            &body,
            now(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{field}");
        let document = body_of(response).await;
        assert_eq!(document["error"], json!("invalid_client_metadata"));
        let description = document["error_description"].as_str().expect("a string");
        assert!(description.contains(field), "{description}");
        // The endpoint never echoes the value it refused.
        assert!(!description.contains(attacker.expose()));
        assert!(!description.contains("a secret of my own choosing"));
    }

    // The token the attacker tried to install is not the one that works.
    let response = read(&fixture.context(), "c.alpha", &bearer(&attacker), now()).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let response = read(
        &fixture.context(),
        "c.alpha",
        &bearer(&fixture.alpha),
        now(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
}

/// The read-modify-write loop RFC 7592 §2.2 describes, run for real.
///
/// A client reads its registration, changes one field in the document it was
/// given, and sends the whole thing back. That must work without the client
/// stripping anything: the two fields this server refuses —
/// `registration_access_token` and `client_secret_expires_at` — are exactly the
/// two a read never returns.
#[tokio::test]
async fn a_client_can_change_one_field_by_sending_back_what_a_read_gave_it() {
    let fixture = Fixture::new();
    let read_back = body_of(
        read(
            &fixture.context(),
            "c.alpha",
            &bearer(&fixture.alpha),
            now(),
        )
        .await,
    )
    .await;

    let body = Bytes::from(amended(&read_back, |object| {
        object.insert("client_name".to_owned(), json!("Billing (EU)"));
    }));
    let response = update(
        &fixture.context(),
        "c.alpha",
        &bearer(&fixture.alpha),
        &body,
        now(),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "a verbatim read document was refused as an update"
    );

    let after = body_of(response).await;
    assert_eq!(after["client_name"], json!("Billing (EU)"));
    // Everything else came back as it was, because the client sent it back.
    assert_eq!(after["redirect_uris"], read_back["redirect_uris"]);
    assert_eq!(after["scope"], read_back["scope"]);
    assert_eq!(
        after["id_token_signed_response_alg"],
        read_back["id_token_signed_response_alg"]
    );
    assert_eq!(
        after["authorization_details_types"],
        read_back["authorization_details_types"]
    );
    assert_eq!(after["client_id"], read_back["client_id"]);
    assert_eq!(
        after["registration_client_uri"],
        read_back["registration_client_uri"]
    );
}

/// RFC 7592 §2.2 sends the update through the same validator as a registration,
/// so a document that would not register does not update either — and the
/// stored row is left exactly as it was.
#[tokio::test]
async fn an_update_that_would_not_register_does_not_update() {
    let fixture = Fixture::new();
    let before = fixture.clients.row("c.alpha").expect("alpha").client;

    for bad in [
        // FAPI 2.0 SP §5.3.2.2: redirect URIs are https.
        json!({"client_id": "c.alpha", "client_name": "x",
               "redirect_uris": ["http://rp.example/cb"]}),
        // FAPI 2.0 SP §5.3.2.1 item 3: no shared-secret authentication.
        json!({"client_id": "c.alpha", "client_name": "x",
               "redirect_uris": ["https://rp.example/cb"],
               "token_endpoint_auth_method": "client_secret_basic"}),
        // ADR-0002: PAR is not optional.
        json!({"client_id": "c.alpha", "client_name": "x",
               "redirect_uris": ["https://rp.example/cb"],
               "require_pushed_authorization_requests": false}),
        // The consent screen has to be able to name somebody.
        json!({"client_id": "c.alpha", "redirect_uris": ["https://rp.example/cb"]}),
    ] {
        let body = Bytes::from(serde_json::to_vec(&bad).expect("serialise"));
        let response = update(
            &fixture.context(),
            "c.alpha",
            &bearer(&fixture.alpha),
            &body,
            now(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{bad}");
        let document = body_of(response).await;
        assert!(
            ["invalid_client_metadata", "invalid_redirect_uri"]
                .contains(&document["error"].as_str().expect("a code")),
            "RFC 7591 §3.2.2 has two codes and this is neither: {document}"
        );
    }

    assert_eq!(
        fixture
            .clients
            .row("c.alpha")
            .expect("alpha")
            .client
            .registration,
        before.registration,
        "a rejected update changed the row"
    );
}

/// The body caps and the media type, matching `POST /register`: an oversized
/// document is refused before it is parsed, and only `application/json` is read
/// (RFC 7592 §2.2 says the update carries "a content type of application/json").
#[tokio::test]
async fn an_update_is_bounded_and_json_only() {
    let fixture = Fixture::new();

    let huge = Bytes::from(vec![
        b'{';
        asterius_server::http::register::MAX_BODY_BYTES + 1
    ]);
    let response = update(
        &fixture.context(),
        "c.alpha",
        &bearer(&fixture.alpha),
        &huge,
        now(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);

    let body = Bytes::from(serde_json::to_vec(&document()).expect("serialise"));
    let mut form = HeaderMap::new();
    form.insert(
        header::CONTENT_TYPE,
        "application/x-www-form-urlencoded".parse().expect("header"),
    );
    form.insert(
        header::AUTHORIZATION,
        format!("Bearer {}", fixture.alpha.expose())
            .parse()
            .expect("header"),
    );
    let response = update(&fixture.context(), "c.alpha", &form, &body, now()).await;
    assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

// ---- delete --------------------------------------------------------------

/// RFC 7592 §2.3: "If a client has been successfully deprovisioned, the
/// authorization server MUST respond with an HTTP 204 No Content message."
///
/// And §5: "If a client is deprovisioned from a server, any outstanding
/// registration access token for that client MUST be invalidated at the same
/// time ... The authorization server MUST treat all such requests as if the
/// registration access token was invalid by returning an HTTP 401 Unauthorized
/// error." So the same token that worked a moment ago is a 401 afterwards, and
/// the answer is the one a stranger gets — not a 404, and not a 410.
#[tokio::test]
async fn a_delete_removes_the_client_and_its_token_stops_working() {
    let fixture = Fixture::new();
    let stranger = OpaqueToken::generate();

    let response = remove(
        &fixture.context(),
        "c.alpha",
        &bearer(&fixture.alpha),
        now(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        response
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    let body = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("read the body");
    assert!(body.is_empty(), "a 204 carried a body");

    assert_eq!(fixture.clients.ids(), vec!["c.beta"]);

    // The token is gone with the row. All three verbs, and each of them the
    // same answer a stranger would get.
    let document = Bytes::from(serde_json::to_vec(&document()).expect("serialise"));
    let after = refusal(
        read(
            &fixture.context(),
            "c.alpha",
            &bearer(&fixture.alpha),
            now(),
        )
        .await,
    )
    .await;
    assert_eq!(after.0, StatusCode::UNAUTHORIZED);
    assert_eq!(
        after,
        refusal(read(&fixture.context(), "c.alpha", &bearer(&stranger), now()).await).await,
        "a deleted client is distinguishable from one that never existed"
    );
    for response in [
        update(
            &fixture.context(),
            "c.alpha",
            &bearer(&fixture.alpha),
            &document,
            now(),
        )
        .await,
        remove(
            &fixture.context(),
            "c.alpha",
            &bearer(&fixture.alpha),
            now(),
        )
        .await,
    ] {
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    // The other client is untouched, which is the whole point of a per-client
    // credential.
    let response = read(&fixture.context(), "c.beta", &bearer(&fixture.beta), now()).await;
    assert_eq!(response.status(), StatusCode::OK);
}

// ---- storage failures ----------------------------------------------------

/// "The database is down" and "no such client" must not be the same answer: one
/// of them tells a client to stop retrying and the other does not.
#[tokio::test]
async fn a_store_that_cannot_be_reached_is_not_a_refusal() {
    let clients = FakeClients::broken();
    let audit = FakeAudit::default();
    let tenant = tenant();
    let context = ConfigurationContext {
        tenant: &tenant,
        clients: &clients,
        configuration: &clients,
        capabilities: Capabilities::default(),
        audit: &audit,
        request_id: Some("req-1"),
    };
    let token = OpaqueToken::generate();

    let response = read(&context, "c.alpha", &bearer(&token), now()).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let document = body_of(response).await;
    assert_eq!(document["error"], json!("temporarily_unavailable"));
    assert!(
        audit.events().is_empty(),
        "a request that never authenticated wrote an audit row"
    );
}

// ---- the audit trail -----------------------------------------------------

/// Every operation that got past the credential is recorded, and nothing that
/// did not.
///
/// The second half is the one worth having: this endpoint is reachable with
/// nothing but a path segment, so an audit row per unauthenticated request
/// would be an amplification primitive aimed at the one table nothing can
/// delete from.
#[tokio::test]
async fn what_reaches_the_audit_trail_is_what_got_past_the_credential() {
    let fixture = Fixture::new();
    let stranger = OpaqueToken::generate();
    let body = Bytes::from(
        serde_json::to_vec(&json!({
            "client_id": "c.alpha",
            "client_name": "Billing",
            "redirect_uris": ["https://rp.example/cb"],
            "grant_types": ["authorization_code"],
            "jwks": {"keys": [{"kty": "OKP", "crv": "Ed25519", "x": "abc"}]},
        }))
        .expect("serialise"),
    );

    // Four refusals, none of which got past the credential.
    let _ = read(&fixture.context(), "c.alpha", &headers(None), now()).await;
    let _ = read(&fixture.context(), "c.alpha", &bearer(&stranger), now()).await;
    let _ = read(&fixture.context(), "c.nobody", &bearer(&stranger), now()).await;
    let _ = read(&fixture.context(), "c.beta", &bearer(&fixture.alpha), now()).await;
    assert!(
        fixture.audit.events().is_empty(),
        "a refusal before authentication was audited: {:?}",
        fixture.audit.events()
    );

    // Three successes, one per verb, each under its own event type and naming
    // the client that acted.
    let _ = read(
        &fixture.context(),
        "c.alpha",
        &bearer(&fixture.alpha),
        now(),
    )
    .await;
    let _ = update(
        &fixture.context(),
        "c.alpha",
        &bearer(&fixture.alpha),
        &body,
        now(),
    )
    .await;
    let _ = remove(
        &fixture.context(),
        "c.alpha",
        &bearer(&fixture.alpha),
        now(),
    )
    .await;

    let events = fixture.audit.events();
    assert_eq!(
        events
            .iter()
            .map(|event| event.event_type.as_str())
            .collect::<Vec<_>>(),
        vec!["client.read", "client.updated", "client.deleted"]
    );
    for event in &events {
        assert_eq!(event.outcome, Outcome::Success);
        assert_eq!(event.client.as_ref().map(ClientId::as_str), Some("c.alpha"));
        assert_eq!(event.request_id.as_deref(), Some("req-1"));
        assert_ne!(event.event_type, EventType::CLIENT_REGISTERED);
    }

    // A refusal that *did* get past the credential is recorded, under the verb
    // that was attempted.
    let fixture = Fixture::new();
    let mut row = fixture.clients.row("c.alpha").expect("alpha");
    row.client.status = ClientStatus::Disabled;
    fixture.clients.insert(row);
    let _ = remove(
        &fixture.context(),
        "c.alpha",
        &bearer(&fixture.alpha),
        now(),
    )
    .await;
    let events = fixture.audit.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_type, EventType::CLIENT_DELETED);
    assert_eq!(events[0].outcome, Outcome::Failure);
}

// ---- wiring --------------------------------------------------------------

/// The wiring `protocol.rs` needs, checked by the compiler rather than by
/// reading it.
///
/// `Store::scope(..).clients(..)` hands back a `PgClientRepository`, and the
/// context holds two ports over it: the narrow read that renders the document a
/// `GET` returns, and the management port that authenticates, replaces and
/// deprovisions. They are separate on purpose — one re-validates a stored row
/// against today's profile and the other deliberately does not — and this is
/// what would fail if a later change made the real adapter stop satisfying
/// either.
#[test]
fn the_postgres_repository_satisfies_both_ports_this_endpoint_holds() {
    fn wire(repository: &asterius_store_pg::PgClientRepository, tenant: &Tenant) {
        let audit = FakeAudit::default();
        let _context = ConfigurationContext {
            tenant,
            clients: repository,
            configuration: repository,
            capabilities: Capabilities::default(),
            audit: &audit,
            request_id: Some("req-1"),
        };
    }
    // Never called: the assertion is that it compiles, and building a pool
    // would need a database this test does not want.
    let _ = wire;
}
