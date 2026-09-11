//! The PDP metadata document (`ast-pj0.3`).
//!
//! Authorization API 1.0 §9.2 puts one document per PDP at
//! `/.well-known/authzen-configuration`, inserted between the host and the
//! path of the PDP identifier — §9.2's own multi-tenant example — and §9.2.3
//! gives a PEP one check to run on it: `policy_decision_point` must be
//! identical to the identifier the URL was derived from. Both well-known
//! spellings are served, for the reason `crates/oidc/src/tenancy.rs` gives.
//!
//! The parity assertions are `ast-o0t.3`'s, extended to the AuthZEN
//! endpoints: every URL the document names is routed, and every AuthZEN
//! endpoint the registry mounts is named. They are written against the
//! registry rather than against a list, so `ast-pj0.2`'s boxcar endpoint joins
//! both sides at once.

use asterius_domain::ports::{TenantRepository, TenantSettingsRepository as _};
use asterius_domain::{
    Capabilities, DomainError, Issuer, KeyStore, SigningAlgorithm, Tenant, TenantId, TenantStatus,
};
use asterius_jose::LocalKeyStore;
use asterius_jose::client_keys;
use asterius_jose::verify::{Policy, TypRule};
use asterius_oidc::authzen_configuration::SIGNED_METADATA_TYP;
use asterius_oidc::metadata::Endpoint;
use asterius_server::config::{Config, ServerConfig};
use asterius_server::http::protocol::{self, ProtocolState};
use asterius_server::http::server::{app, not_found};
use asterius_server::tenancy::{TenantDirectory, TenantState};
use asterius_server::tenant_settings::SettingsDirectory;
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use serde_json::{Value, json};
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
const APPENDED: &str = "/t/demo/.well-known/authzen-configuration";
const INSERTED: &str = "/.well-known/authzen-configuration/t/demo";

fn authzen_on() -> Capabilities {
    Capabilities {
        authzen: true,
        ..Capabilities::default()
    }
}

fn tenant() -> Tenant {
    Tenant {
        id: TenantId::parse("demo").expect("tenant id"),
        issuer: Issuer::parse(ISSUER).expect("issuer"),
        default_resource: "https://api.example/".to_owned(),
        custom_host: None,
        display_name: "Demo".to_owned(),
        status: TenantStatus::Active,
        refresh: asterius_domain::RefreshPolicy::default(),
        created_at: OffsetDateTime::UNIX_EPOCH,
        updated_at: OffsetDateTime::UNIX_EPOCH,
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

/// The keys this deployment signs and publishes with, held so that a test can
/// verify a signature against the very set `/jwks` serves.
fn keystore() -> Arc<LocalKeyStore> {
    let keys = Arc::new(LocalKeyStore::new());
    keys.generate(&tenant().id, SigningAlgorithm::DEFAULT)
        .expect("generate a key");
    keys
}

fn server(capabilities: Capabilities) -> Router {
    server_with(capabilities, None, None)
}

/// A deployment that signs its PDP metadata (`[authzen] signed_metadata`).
///
/// Signs *and publishes* from the key store it is handed, which is the point:
/// a PEP verifies the document against the set `jwks_uri` serves, so a fixture
/// that signed with one store and published another would prove nothing.
fn signing_server(keys: &Arc<LocalKeyStore>) -> Router {
    routes_over(
        keys,
        authzen_on(),
        None,
        Some(Arc::clone(keys) as Arc<dyn asterius_domain::keys::Signer>),
    )
}

fn server_with(
    capabilities: Capabilities,
    settings: Option<SettingsDirectory>,
    signed_metadata: Option<Arc<dyn asterius_domain::keys::Signer>>,
) -> Router {
    routes_over(&keystore(), capabilities, settings, signed_metadata)
}

fn routes_over(
    keys: &Arc<LocalKeyStore>,
    capabilities: Capabilities,
    settings: Option<SettingsDirectory>,
    signed_metadata: Option<Arc<dyn asterius_domain::keys::Signer>>,
) -> Router {
    let config: ServerConfig = Config::parse(CONFIG, Path::new("asterius.toml"), &BTreeMap::new())
        .expect("valid test config")
        .server;

    let directory = TenantDirectory::new(Arc::new(OneTenant(tenant())));
    let routes = protocol::routes(ProtocolState {
        keys: Arc::clone(keys) as Arc<dyn KeyStore>,
        capabilities,
        tenant_settings: settings,
        // This document needs no database, which is what lets this suite run
        // without one.
        clients: None,
        signed_metadata,
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

async fn document(router: Router, path: &str) -> Value {
    let (status, _, body) = get(router, path).await;
    assert_eq!(status, StatusCode::OK);
    serde_json::from_str(&body).expect("the PDP configuration is JSON")
}

// ---------------------------------------------------------------------------
// The document — §9.1.1, §9.2.2
// ---------------------------------------------------------------------------

/// §9.2.2: 200 and `application/json`, carrying §9.1.1's two required
/// parameters.
#[tokio::test]
async fn the_pdp_advertises_its_identifier_and_its_evaluation_endpoint() {
    // Arrange, act
    let (status, headers, body) = get(server(authzen_on()), APPENDED).await;

    // Assert
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers.get(header::CONTENT_TYPE).expect("content type"),
        "application/json"
    );
    let metadata: Value = serde_json::from_str(&body).expect("JSON");
    assert_eq!(metadata["policy_decision_point"], json!(ISSUER));
    assert_eq!(
        metadata["access_evaluation_endpoint"],
        json!(format!("{ISSUER}/access/v1/evaluation"))
    );
}

/// §9.2.3, which is the whole of a PEP's validation: the
/// `policy_decision_point` is identical to the identifier the fetched URL was
/// derived from — both ways round, since §9.2 inserts the well-known segment
/// and OIDC Discovery §4's spelling appends it.
#[tokio::test]
async fn the_identifier_matches_the_url_the_document_was_fetched_from() {
    for path in [APPENDED, INSERTED] {
        // Arrange
        let metadata = document(server(authzen_on()), path).await;

        // Act
        let pdp = metadata["policy_decision_point"]
            .as_str()
            .expect("an identifier");
        let fetched = format!("https://as.example{path}");

        // Assert
        assert!(
            fetched == format!("{pdp}/.well-known/authzen-configuration")
                || fetched
                    == format!(
                        "https://as.example/.well-known/authzen-configuration{}",
                        pdp.trim_start_matches("https://as.example")
                    ),
            "{pdp} is not the PDP {fetched} describes"
        );
    }
}

/// §9.2: both spellings name the same PDP, byte for byte. A PEP that fetched
/// one and validated against the other would be comparing two documents.
#[tokio::test]
async fn both_well_known_forms_return_the_same_document() {
    // Arrange, act
    let (appended_status, _, appended) = get(server(authzen_on()), APPENDED).await;
    let (inserted_status, _, inserted) = get(server(authzen_on()), INSERTED).await;

    // Assert
    assert_eq!(appended_status, StatusCode::OK);
    assert_eq!(inserted_status, StatusCode::OK);
    assert_eq!(appended, inserted);
}

/// §9.1.1: the identifier is https and carries no query and no fragment, and
/// so is every URL beside it.
#[tokio::test]
async fn every_url_in_the_document_is_https_and_bare() {
    // Arrange, act
    let metadata = document(server(authzen_on()), APPENDED).await;

    // Assert
    for (key, value) in metadata.as_object().expect("an object") {
        let Some(text) = value.as_str() else { continue };
        if !text.starts_with("http") {
            continue;
        }
        assert!(text.starts_with("https://"), "{key} is not https: {text}");
        assert!(
            !text.contains('?') && !text.contains('#'),
            "{key} carries a query or a fragment: {text}"
        );
    }
}

/// §9.2.2: a parameter this PDP has nothing to say about is omitted. Search
/// (`ast-pj0.6`) is not implemented, so no `search_*` member exists, and no
/// `capabilities` member either — an empty one is what §9.2.2 forbids.
#[tokio::test]
async fn nothing_unimplemented_is_advertised() {
    // Arrange, act
    let metadata = document(server(authzen_on()), APPENDED).await;
    let members = metadata.as_object().expect("an object");

    // Assert
    for absent in [
        "search_subject_endpoint",
        "search_resource_endpoint",
        "search_action_endpoint",
        "capabilities",
    ] {
        assert!(
            !members.contains_key(absent),
            "{absent} is advertised by a PDP that does not implement it"
        );
    }
}

// ---------------------------------------------------------------------------
// Parity — ast-o0t.3, extended to the AuthZEN endpoints
// ---------------------------------------------------------------------------

/// Every URL the PDP document names resolves to a route. A 404 would be the
/// server disowning a URL it just advertised.
#[tokio::test]
async fn every_url_the_pdp_advertises_resolves_to_a_route() {
    // Arrange
    let metadata = document(server(authzen_on()), APPENDED).await;
    let advertised: Vec<(String, String)> = metadata
        .as_object()
        .expect("an object")
        .iter()
        .filter(|(key, _)| key.ends_with("_endpoint"))
        .filter_map(|(key, value)| value.as_str().map(|url| (key.clone(), url.to_owned())))
        .collect();
    assert!(
        advertised
            .iter()
            .any(|(key, _)| key == "access_evaluation_endpoint"),
        "the document names no evaluation endpoint at all: {advertised:?}"
    );

    // Act, assert
    for (key, url) in advertised {
        let path = url
            .strip_prefix("https://as.example")
            .expect("a URL under the issuer host");
        let (status, ..) = get(server(authzen_on()), path).await;
        assert_ne!(
            status,
            StatusCode::NOT_FOUND,
            "{key} advertises {url}, which is not routed"
        );
    }
}

/// The other direction, and the acceptance criterion of `ast-pj0.3`: every
/// AuthZEN endpoint the registry mounts is named here, and nothing else is.
///
/// Read from [`Endpoint::in_pdp_metadata`] rather than from a list, so
/// `ast-pj0.2`'s `access_evaluations_endpoint` is required here the moment it
/// joins the registry, and forbidden until then.
#[tokio::test]
async fn the_document_names_exactly_the_authzen_endpoints_that_are_mounted() {
    // Arrange
    let capabilities = authzen_on();
    let metadata = document(server(capabilities), APPENDED).await;
    let members = metadata.as_object().expect("an object");

    // Act
    let named: Vec<&String> = members
        .keys()
        .filter(|key| key.ends_with("_endpoint"))
        .collect();
    let mounted: Vec<&str> = Endpoint::enabled(&capabilities)
        .filter(|endpoint| endpoint.in_pdp_metadata())
        .map(Endpoint::metadata_key)
        .collect();

    // Assert
    assert_eq!(
        named.iter().map(|key| key.as_str()).collect::<Vec<_>>(),
        mounted,
        "the PDP document and the endpoint registry disagree"
    );
}

/// The feature gate, on the deployment: no document at all, the same 404 the
/// SSF transmitter answers, and for the same reason — as far as this
/// deployment is concerned there is no PDP here.
#[tokio::test]
async fn a_deployment_without_the_feature_serves_no_pdp() {
    // Arrange, act
    let (appended, ..) = get(server(Capabilities::default()), APPENDED).await;
    let (inserted, ..) = get(server(Capabilities::default()), INSERTED).await;

    // Assert
    assert_eq!(appended, StatusCode::NOT_FOUND);
    assert_eq!(inserted, StatusCode::NOT_FOUND);
}

/// The same gate, per tenant (`ast-edc`): a tenant that switches `authzen` off
/// under a deployment that has it on stops having a PDP, and the change is
/// visible to the next request.
#[tokio::test]
async fn a_tenant_that_switches_the_feature_off_serves_no_pdp() {
    // Arrange
    let repository = Arc::new(EditableSettings::default());
    let directory = SettingsDirectory::new(Arc::clone(&repository) as _);
    let (before, ..) = get(
        server_with(authzen_on(), Some(directory.clone()), None),
        APPENDED,
    )
    .await;
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
                std::collections::BTreeSet::from([asterius_domain::Feature::Authzen]),
                asterius_domain::entities::tenant_settings::DEFAULT_AUTHORIZATION_CODE_LIFETIME,
                asterius_domain::entities::tenant_settings::DEFAULT_ACCESS_TOKEN_LIFETIME,
            )
            .expect("within the caps"),
        )
        .await
        .expect("save");
    directory.invalidate();

    // Assert
    let (after, ..) = get(server_with(authzen_on(), Some(directory), None), APPENDED).await;
    assert_eq!(after, StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// signed_metadata — §9.1.3
// ---------------------------------------------------------------------------

/// §9.1.3 is OPTIONAL, and off is the default: a deployment that was not asked
/// to sign its metadata publishes none.
#[tokio::test]
async fn the_document_is_unsigned_unless_the_deployment_asked_for_it() {
    // Arrange, act
    let metadata = document(server(authzen_on()), APPENDED).await;

    // Assert
    assert!(
        metadata.get("signed_metadata").is_none(),
        "a deployment that was not configured to sign its metadata signed it"
    );
}

/// §9.1.3 and RFC 8414 §2.1: the signature verifies against the keys the
/// tenant publishes at `jwks_uri`, and the claims repeat the document.
#[tokio::test]
async fn a_signed_document_verifies_against_the_published_keys() {
    // Arrange
    let keys = keystore();
    let metadata = document(signing_server(&keys), APPENDED).await;
    let signed = metadata["signed_metadata"]
        .as_str()
        .expect("a signed metadata JWT");

    // Act: a PEP fetches the key set the way `jwks_uri` serves it.
    let (status, _, body) = get(signing_server(&keys), "/t/demo/jwks").await;
    assert_eq!(status, StatusCode::OK);
    let jwks: Value = serde_json::from_str(&body).expect("a key set");
    let resolver = client_keys::keys_from_jwk_set(&jwks).expect("a readable JWKS");
    let policy = Policy::new(
        TypRule::Exactly(SIGNED_METADATA_TYP),
        SigningAlgorithm::ALL.to_vec(),
    )
    .issued_by(ISSUER)
    .without_expiry();
    let verified = asterius_jose::verify(signed, &policy, &resolver, OffsetDateTime::now_utc())
        .expect("a signature a PEP accepts");

    // Assert
    assert_eq!(verified.claims["iss"], json!(ISSUER));
    assert_eq!(verified.claims["policy_decision_point"], json!(ISSUER));
    assert_eq!(
        verified.claims["access_evaluation_endpoint"],
        metadata["access_evaluation_endpoint"]
    );
    assert!(
        verified.claims.get("signed_metadata").is_none(),
        "the signed document signs itself"
    );
}

// ---------------------------------------------------------------------------
// The golden document
// ---------------------------------------------------------------------------

/// The whole document for the reference tenant, pinned.
///
/// Every other test here asserts one property; this one is what makes an
/// *accidental* change visible — a member added by a refactor, a value
/// flipped, an endpoint advertised before its route exists.
///
/// Regenerate deliberately with `UPDATE_GOLDEN=1 cargo nextest run -p
/// asterius-server --test authzen_configuration`, and read the diff.
#[tokio::test]
async fn the_document_matches_the_golden_file() {
    let metadata = document(server(authzen_on()), APPENDED).await;
    let rendered = format!(
        "{}\n",
        serde_json::to_string_pretty(&metadata).expect("pretty")
    );

    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden/authzen-configuration.json");

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
        "the PDP configuration changed.\nIf that was deliberate, regenerate with \
         UPDATE_GOLDEN=1 and read the diff before committing."
    );
}
