//! The SSF transmitter configuration document (`ast-0ju.1`).
//!
//! SSF 1.0 §7.2 puts one document per transmitter at
//! `/.well-known/ssf-configuration`, and §7.2.4 gives a receiver one check to
//! run on it: the `issuer` must be identical to the URL it fetched from. Both
//! well-known forms are served, for the reason `crates/oidc/src/tenancy.rs`
//! gives — OIDC Discovery §4 appends the prefix to the issuer path, RFC 8414
//! §3.1 inserts it, and clients in the wild use both.
//!
//! The parity assertion is the same one `discovery.rs` makes and the reason
//! `ast-o0t.3` exists: a document must not name a URL that answers 404. This
//! transmitter names none of SSF §7.1's five management endpoints, because
//! none of them is routed yet (`ast-0ju.3` through `ast-0ju.7`); the test
//! below asserts the *agreement*, not the emptiness, so it stays honest as
//! each of those stories turns one on.

use asterius_domain::ports::{TenantRepository, TenantSettingsRepository as _};
use asterius_domain::{
    Capabilities, DomainError, Issuer, KeyStore, SigningAlgorithm, Tenant, TenantId, TenantStatus,
};
use asterius_jose::LocalKeyStore;
use asterius_server::config::{Config, ServerConfig};
use asterius_server::http::protocol::{self, ProtocolState};
use asterius_server::http::server::{app, not_found};
use asterius_server::tenancy::{TenantDirectory, TenantState};
use asterius_server::tenant_settings::SettingsDirectory;
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use time::OffsetDateTime;
use tower::ServiceExt as _;

const CONFIG: &str = r#"
    [keys]
    kek_env = "ASTERIUS_TEST_KEK"

    [database]
    url = "postgres://asterius@localhost/asterius"
"#;

const ISSUER: &str = "https://as.example/t/demo";
const APPENDED: &str = "/t/demo/.well-known/ssf-configuration";
const INSERTED: &str = "/.well-known/ssf-configuration/t/demo";

fn ssf_on() -> Capabilities {
    Capabilities {
        ssf: true,
        ..Capabilities::default()
    }
}

#[derive(Debug)]
struct OneTenant(Tenant);

#[async_trait::async_trait]
impl TenantRepository for OneTenant {
    async fn find_by_id(&self, _: &TenantId) -> Result<Option<Tenant>, DomainError> {
        unimplemented!("the directory only uses list()")
    }
    async fn find_by_issuer(&self, _: &Issuer) -> Result<Option<Tenant>, DomainError> {
        unimplemented!("the directory only uses list()")
    }
    async fn find_by_host(&self, _: &str) -> Result<Option<Tenant>, DomainError> {
        unimplemented!("the directory only uses list()")
    }
    async fn list(&self) -> Result<Vec<Tenant>, DomainError> {
        Ok(vec![self.0.clone()])
    }
    async fn upsert(&self, _: &Tenant) -> Result<(), DomainError> {
        unimplemented!("read-only")
    }
    async fn delete(&self, _: &TenantId) -> Result<(), DomainError> {
        unimplemented!("read-only")
    }
}

/// A settings repository a test can write to under a running server, which is
/// what "a tenant switched the feature off" has to mean to be worth asserting.
#[derive(Debug, Default)]
struct EditableSettings(std::sync::RwLock<asterius_domain::TenantSettings>);

#[async_trait::async_trait]
impl asterius_domain::ports::TenantSettingsRepository for EditableSettings {
    async fn settings(
        &self,
        _tenant: &TenantId,
    ) -> Result<asterius_domain::TenantSettings, DomainError> {
        Ok(self.0.read().expect("an uncontended lock").clone())
    }

    async fn save(
        &self,
        _tenant: &TenantId,
        settings: &asterius_domain::TenantSettings,
    ) -> Result<(), DomainError> {
        *self.0.write().expect("an uncontended lock") = settings.clone();
        Ok(())
    }
}

fn server(capabilities: Capabilities) -> Router {
    server_with(capabilities, None)
}

fn server_with(capabilities: Capabilities, settings: Option<SettingsDirectory>) -> Router {
    let tenant = Tenant {
        id: TenantId::parse("demo").expect("tenant id"),
        issuer: Issuer::parse(ISSUER).expect("issuer"),
        default_resource: "https://api.example/".to_owned(),
        custom_host: None,
        display_name: "Demo".to_owned(),
        status: TenantStatus::Active,
        refresh: asterius_domain::RefreshPolicy::default(),
        created_at: OffsetDateTime::UNIX_EPOCH,
        updated_at: OffsetDateTime::UNIX_EPOCH,
    };

    let keys = Arc::new(LocalKeyStore::new());
    keys.generate(&tenant.id, SigningAlgorithm::DEFAULT)
        .expect("generate a key");

    let config: ServerConfig = Config::parse(CONFIG, Path::new("asterius.toml"), &BTreeMap::new())
        .expect("valid test config")
        .server;

    let directory = TenantDirectory::new(Arc::new(OneTenant(tenant)));
    let routes = protocol::routes(ProtocolState {
        keys: Arc::clone(&keys) as Arc<dyn KeyStore>,
        capabilities,
        tenant_settings: settings,
        // This document needs no database, which is what lets this suite run
        // without one.
        clients: None,
    })
    .fallback(not_found);

    app(routes, TenantState::new(directory, &config), None, &config)
}

async fn get(router: Router, path: &str) -> (StatusCode, axum::http::HeaderMap, String) {
    let response = router
        .oneshot(
            Request::builder()
                .uri(path)
                .header(header::HOST, "as.example")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("router is infallible");
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = axum::body::to_bytes(response.into_body(), 256 * 1024)
        .await
        .expect("body");
    (
        status,
        headers,
        String::from_utf8_lossy(&bytes).into_owned(),
    )
}

async fn document(capabilities: Capabilities) -> Value {
    let (status, _, body) = get(server(capabilities), APPENDED).await;
    assert_eq!(status, StatusCode::OK);
    serde_json::from_str(&body).expect("the transmitter configuration is JSON")
}

// ---------------------------------------------------------------------------
// The document — SSF 1.0 §7.1, §7.2.3
// ---------------------------------------------------------------------------

/// SSF 1.0 §7.2.3: 200 and `application/json`, and §7.1's members.
#[tokio::test]
async fn the_transmitter_advertises_what_it_can_do() {
    // Arrange, act
    let metadata = document(ssf_on()).await;

    // Assert
    assert_eq!(metadata["spec_version"], "1_0");
    assert_eq!(metadata["issuer"], ISSUER);
    assert_eq!(metadata["jwks_uri"], format!("{ISSUER}/jwks"));
    assert_eq!(
        metadata["authorization_schemes"][0]["spec_urn"],
        "urn:ietf:rfc:6749"
    );
    assert_eq!(metadata["default_subjects"], "NONE");
    assert!(metadata["critical_subject_members"].is_array());
}

#[tokio::test]
async fn the_document_is_served_as_json() {
    // Arrange, act
    let (status, headers, _) = get(server(ssf_on()), APPENDED).await;

    // Assert
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers.get(header::CONTENT_TYPE).expect("content type"),
        "application/json"
    );
}

/// SSF 1.0 §7.2 and RFC 8414 §3.1: the well-known segment is inserted between
/// the host and the issuer's path, and OIDC Discovery §4's appended spelling
/// names the same transmitter. Both must be the same bytes, because a
/// receiver that fetched one and validated against the other would be
/// comparing two documents.
#[tokio::test]
async fn both_well_known_forms_return_the_same_document() {
    // Arrange, act
    let (appended_status, _, appended) = get(server(ssf_on()), APPENDED).await;
    let (inserted_status, _, inserted) = get(server(ssf_on()), INSERTED).await;

    // Assert
    assert_eq!(appended_status, StatusCode::OK);
    assert_eq!(inserted_status, StatusCode::OK);
    assert_eq!(appended, inserted);
}

/// SSF 1.0 §7.2.4, which is the whole of a receiver's validation: the issuer
/// in the document is identical to the base of the URL the document came from.
#[tokio::test]
async fn the_issuer_matches_the_url_the_document_was_fetched_from() {
    for path in [APPENDED, INSERTED] {
        // Arrange
        let (status, _, body) = get(server(ssf_on()), path).await;
        assert_eq!(status, StatusCode::OK, "{path}");
        let metadata: Value = serde_json::from_str(&body).expect("JSON");

        // Act: reconstruct the issuer the fetch URL describes, both ways round.
        let issuer = metadata["issuer"].as_str().expect("an issuer");
        let fetched = format!("https://as.example{path}");

        // Assert
        assert!(
            fetched == format!("{issuer}/.well-known/ssf-configuration")
                || fetched
                    == format!(
                        "https://as.example/.well-known/ssf-configuration{}",
                        issuer.trim_start_matches("https://as.example")
                    ),
            "{issuer} is not the issuer {fetched} describes"
        );
    }
}

/// Every URL this document publishes is https (SSF 1.0 §7.1).
#[tokio::test]
async fn every_url_in_the_document_is_https() {
    // Arrange, act
    let metadata = document(ssf_on()).await;

    // Assert
    for (key, value) in metadata.as_object().expect("an object") {
        let Some(text) = value.as_str() else { continue };
        if text.starts_with("http") {
            assert!(text.starts_with("https://"), "{key} is not https: {text}");
        }
    }
}

// ---------------------------------------------------------------------------
// Parity — ast-o0t.3, extended per tenant by ast-edc
// ---------------------------------------------------------------------------

/// Every URL the transmitter configuration names resolves to a route.
///
/// Today it names one, `jwks_uri`, and none of SSF §7.1's five management
/// endpoints — they are `ast-0ju.3` through `ast-0ju.5` and are not built.
/// This test asserts the agreement rather than the absence, so it is the test
/// each of those stories has to keep green as it adds a member *and* a route.
#[tokio::test]
async fn every_url_the_transmitter_advertises_resolves_to_a_route() {
    // Arrange
    let metadata = document(ssf_on()).await;
    let object = metadata.as_object().expect("an object");
    let advertised: Vec<(&String, &str)> = object
        .iter()
        .filter(|(key, _)| key.ends_with("_endpoint") || *key == "jwks_uri")
        .filter_map(|(key, value)| value.as_str().map(|url| (key, url)))
        .collect();
    assert!(
        advertised.iter().any(|(key, _)| *key == "jwks_uri"),
        "the document names no key set at all: {advertised:?}"
    );

    // Act, assert
    for (key, url) in advertised {
        let path = url
            .strip_prefix("https://as.example")
            .expect("a URL under the issuer host");
        let (status, ..) = get(server(ssf_on()), path).await;
        assert_ne!(
            status,
            StatusCode::NOT_FOUND,
            "{key} advertises {url}, which is not routed"
        );
    }
}

/// The other half of parity, in the state SSF is in today: a member that names
/// a delivery method or a management endpoint would be describing behaviour
/// this build does not have.
#[tokio::test]
async fn nothing_unbuilt_is_advertised() {
    // Arrange, act
    let metadata = document(ssf_on()).await;
    let object = metadata.as_object().expect("an object");

    // Assert
    let endpoints: Vec<&String> = object
        .keys()
        .filter(|key| key.ends_with("_endpoint"))
        .collect();
    assert!(
        endpoints.is_empty(),
        "SSF management endpoints are advertised before they are routed: {endpoints:?}"
    );
    assert!(
        object.get("delivery_methods_supported").is_none(),
        "a delivery method is advertised before `ast-0ju.6` delivers one"
    );
}

/// The flag's off state, on the deployment: no document, and nothing about SSF
/// in the OP's own metadata either — the transmitter is discovered at its own
/// well-known URL, and a client that finds nothing there has found the truth.
#[tokio::test]
async fn a_deployment_without_the_feature_serves_no_transmitter() {
    // Arrange, act
    let (status, ..) = get(server(Capabilities::default()), APPENDED).await;
    let (inserted, ..) = get(server(Capabilities::default()), INSERTED).await;
    let (_, _, provider) = get(
        server(Capabilities::default()),
        "/t/demo/.well-known/openid-configuration",
    )
    .await;

    // Assert
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(inserted, StatusCode::NOT_FOUND);
    assert!(
        !provider.contains("ssf"),
        "the provider metadata mentions SSF while the feature is off"
    );
}

/// The same gate, per tenant (`ast-edc`): a tenant that switches `ssf` off
/// under a deployment that has it on stops having a transmitter, and the
/// change is visible to the next request.
#[tokio::test]
async fn a_tenant_that_switches_the_feature_off_serves_no_transmitter() {
    // Arrange
    let repository = Arc::new(EditableSettings::default());
    let directory = SettingsDirectory::new(Arc::clone(&repository) as _);
    let (before, ..) = get(server_with(ssf_on(), Some(directory.clone())), APPENDED).await;
    assert_eq!(
        before,
        StatusCode::OK,
        "the deployment does not serve the document this test switches off"
    );

    // Act
    repository
        .save(
            &TenantId::parse("demo").expect("tenant id"),
            &asterius_domain::TenantSettings::validated(
                std::collections::BTreeSet::from([asterius_domain::Feature::Ssf]),
                asterius_domain::entities::tenant_settings::DEFAULT_AUTHORIZATION_CODE_LIFETIME,
                asterius_domain::entities::tenant_settings::DEFAULT_ACCESS_TOKEN_LIFETIME,
            )
            .expect("within the caps"),
        )
        .await
        .expect("save");
    directory.invalidate();

    // Assert
    let (after, ..) = get(server_with(ssf_on(), Some(directory)), APPENDED).await;
    assert_eq!(after, StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// The golden document
// ---------------------------------------------------------------------------

/// The whole document for the reference tenant, pinned.
///
/// The same argument `discovery.rs` makes: every other test here asserts one
/// property, and this one is what makes an *accidental* change visible — a
/// member added by a refactor, a value flipped, an endpoint advertised before
/// its route exists.
///
/// Regenerate deliberately with `UPDATE_GOLDEN=1 cargo nextest run -p
/// asterius-server --test ssf_configuration`, and read the diff.
#[tokio::test]
async fn the_document_matches_the_golden_file() {
    let metadata = document(ssf_on()).await;
    let rendered = format!(
        "{}\n",
        serde_json::to_string_pretty(&metadata).expect("pretty")
    );

    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden/ssf-configuration.json");

    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        std::fs::write(&path, &rendered).expect("write the golden file");
        return;
    }

    let expected = std::fs::read_to_string(&path).unwrap_or_else(|_| {
        panic!(
            "no golden file at {}; create it with UPDATE_GOLDEN=1",
            path.display()
        )
    });

    assert_eq!(
        rendered, expected,
        "the transmitter configuration changed.\nIf that was deliberate, regenerate with \
         UPDATE_GOLDEN=1 and read the diff before committing."
    );
}
