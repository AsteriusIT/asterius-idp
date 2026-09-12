//! Discovery, JWKS, and the parity between what is advertised and what exists.
//!
//! The parity test is the reason `ast-o0t.3` exists. RFC 8414 §2 says metadata
//! must reflect actual behaviour, and the way that stops being true is never
//! dramatic: an endpoint is added and the document is not updated, or a flag is
//! turned off and its key stays. Both are silent. Asserting the two agree is
//! the only thing that keeps them agreeing.

use asterius_domain::ports::{TenantRepository, TenantSettingsRepository as _};
use asterius_domain::{
    Capabilities, DomainError, Issuer, KeyStore, SigningAlgorithm, Tenant, TenantId, TenantStatus,
};
use asterius_jose::LocalKeyStore;
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

fn server_config() -> ServerConfig {
    Config::parse(CONFIG, Path::new("asterius.toml"), &BTreeMap::new())
        .expect("valid test config")
        .server
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

/// A settings repository whose answer a test can change under a running
/// server, which is what "the change is visible immediately" needs to mean
/// something.
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

/// The whole server, for one tenant, with one signing key.
fn server(capabilities: Capabilities) -> Router {
    server_with(capabilities, None)
}

/// The same server, with a per-tenant settings cache the caller keeps a handle
/// on.
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

    let config = server_config();
    let directory = TenantDirectory::new(Arc::new(OneTenant(tenant)));
    let routes = protocol::routes(ProtocolState {
        keys: Arc::clone(&keys) as Arc<dyn KeyStore>,
        capabilities,
        tenant_settings: settings,
        // The discovery and JWKS handlers need no database; leaving this
        // `None` is what lets this suite run without one.
        clients: None,
        signed_metadata: None,
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
    let (status, _, body) = get(
        server(capabilities),
        "/t/demo/.well-known/openid-configuration",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    serde_json::from_str(&body).expect("metadata is JSON")
}

// ---------------------------------------------------------------------------
// Parity — ast-o0t.3
// ---------------------------------------------------------------------------

/// Every `*_endpoint` URL in the document resolves to a route. A 501 counts:
/// the endpoint exists and is not built. A 404 does not, because that is the
/// server saying it never heard of a URL it just advertised.
#[tokio::test]
async fn every_advertised_endpoint_resolves_to_a_route() {
    let capabilities = Capabilities {
        mtls: true,
        grant_management: true,
        ciba: true,
        device_flow: true,
        token_exchange: true,
        ssf: true,
        authzen: true,
        authzen_search: true,
        dpop_nonce: true,
        request_object: true,
        dynamic_client_registration: true,
        self_registration: true,
    };
    let metadata = document(capabilities).await;
    let object = metadata.as_object().expect("object");

    let advertised: Vec<(&String, &str)> = object
        .iter()
        .filter(|(key, _)| key.ends_with("_endpoint") || *key == "jwks_uri")
        .filter_map(|(key, value)| value.as_str().map(|url| (key, url)))
        .collect();
    assert!(
        advertised.len() >= 9,
        "expected the full endpoint set, got {advertised:?}"
    );

    for (key, url) in advertised {
        let path = url
            .strip_prefix("https://as.example")
            .expect("URL under the issuer host");
        let (status, ..) = get(server(capabilities), path).await;
        assert_ne!(
            status,
            StatusCode::NOT_FOUND,
            "{key} advertises {url}, which is not routed"
        );
    }
}

/// The other direction: a route that exists but is not advertised is a
/// surface nobody documented.
#[tokio::test]
async fn every_routed_protocol_endpoint_is_advertised() {
    let capabilities = Capabilities::default();
    let metadata = document(capabilities).await;
    let object = metadata.as_object().expect("object");

    for endpoint in Endpoint::ALL {
        let routed = {
            let path = format!("/t/demo{}", endpoint.path());
            let (status, ..) = get(server(capabilities), &path).await;
            status != StatusCode::NOT_FOUND
        };
        let advertised = object.contains_key(endpoint.metadata_key());
        assert_eq!(
            routed, advertised,
            "{endpoint:?}: routed={routed} advertised={advertised}"
        );
    }
}

/// Turning a flag on adds its endpoint to both the document and the router,
/// and turning it off removes it from both.
#[tokio::test]
async fn a_disabled_feature_is_neither_advertised_nor_routed() {
    let off = Capabilities::default();
    let on = Capabilities {
        device_flow: true,
        ..Capabilities::default()
    };
    let path = format!("/t/demo{}", Endpoint::DeviceAuthorization.path());

    let (status, ..) = get(server(off), &path).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a disabled endpoint is routed"
    );
    assert!(
        document(off)
            .await
            .get("device_authorization_endpoint")
            .is_none()
    );

    let (status, ..) = get(server(on), &path).await;
    assert_ne!(
        status,
        StatusCode::NOT_FOUND,
        "an enabled endpoint is not routed"
    );
    assert!(
        document(on)
            .await
            .get("device_authorization_endpoint")
            .is_some()
    );
}

/// CIBA Core 1.0 §4 and `ast-lh3.4`: with the flag on, the whole CIBA block
/// is advertised and the endpoint is routed; with it off, neither.
///
/// §4 is why it is the whole block rather than the URL alone:
/// `backchannel_token_delivery_modes_supported` is REQUIRED beside
/// `backchannel_authentication_endpoint`, so a document carrying one without
/// the other is not a smaller CIBA document but an invalid one. The metadata
/// side of the same statement is `asterius_oidc::metadata`.
/// `ast-pj0.3`: the parity rule, extended to the AuthZEN endpoints and to the
/// second document that names them.
///
/// An AuthZEN endpoint lives in two places — the OP's own metadata, where it
/// has been since `ast-pj0.1`, and the PDP's document at
/// `/.well-known/authzen-configuration` (Authorization API 1.0 §9.1.1) — and
/// the route, the OP member and the PDP member appear and disappear together.
/// Read from the registry rather than from a list, so `ast-pj0.2`'s boxcar
/// endpoint is covered here the moment it is registered.
#[tokio::test]
async fn the_authzen_endpoints_are_routed_and_named_in_both_documents_or_neither() {
    // Arrange
    let on = Capabilities {
        authzen: true,
        authzen_search: true,
        ..Capabilities::default()
    };
    let off = Capabilities::default();
    let authzen: Vec<Endpoint> = Endpoint::ALL
        .into_iter()
        .filter(|endpoint| endpoint.in_pdp_metadata())
        .collect();
    assert!(!authzen.is_empty(), "the registry mounts no PDP endpoint");

    for capabilities in [on, off] {
        let expected = capabilities.authzen;

        // Act
        let provider = document(capabilities).await;
        let (pdp_status, _, pdp_body) = get(
            server(capabilities),
            "/t/demo/.well-known/authzen-configuration",
        )
        .await;

        // Assert: the PDP document exists exactly with the feature (§9.2.2).
        assert_eq!(
            pdp_status == StatusCode::OK,
            expected,
            "the PDP document answered {pdp_status} with authzen={expected}"
        );

        for endpoint in &authzen {
            let path = format!("/t/demo{}", endpoint.path());
            let (routed, ..) = get(server(capabilities), &path).await;
            assert_eq!(
                routed != StatusCode::NOT_FOUND,
                expected,
                "{endpoint:?} is routed={} with authzen={expected}",
                routed != StatusCode::NOT_FOUND
            );
            assert_eq!(
                provider.get(endpoint.metadata_key()).is_some(),
                expected,
                "{endpoint:?} in the OP metadata with authzen={expected}"
            );
            if expected {
                let pdp: Value = serde_json::from_str(&pdp_body).expect("the PDP document is JSON");
                assert_eq!(
                    pdp.get(endpoint.metadata_key()).and_then(Value::as_str),
                    Some(format!("https://as.example/t/demo{}", endpoint.path()).as_str()),
                    "{endpoint:?} is missing from the PDP document"
                );
            }
        }
    }
}

/// Authorization API 1.0 §8 is OPTIONAL, and §9.2.2 says a parameter with
/// nothing to say is omitted: a deployment that decides but does not search
/// advertises no `search_*_endpoint` and answers 404 at the three paths
/// (`ast-pj0.6`).
///
/// The interesting case, because it is the one where the PDP exists: the
/// evaluation endpoint is routed and named, and the searches are neither.
#[tokio::test]
async fn the_search_endpoints_follow_their_own_flag() {
    // Arrange
    let deciding = Capabilities {
        authzen: true,
        ..Capabilities::default()
    };
    let searching = Capabilities {
        authzen: true,
        authzen_search: true,
        ..Capabilities::default()
    };
    let searches = [
        Endpoint::SearchSubject,
        Endpoint::SearchResource,
        Endpoint::SearchAction,
    ];

    for capabilities in [deciding, searching] {
        let expected = capabilities.authzen_search;

        // Act
        let provider = document(capabilities).await;
        let (_, _, pdp_body) = get(
            server(capabilities),
            "/t/demo/.well-known/authzen-configuration",
        )
        .await;
        let pdp: Value = serde_json::from_str(&pdp_body).expect("the PDP document is JSON");

        // Assert
        assert!(
            pdp.get("access_evaluation_endpoint").is_some(),
            "a PDP that decides stopped advertising its evaluation endpoint"
        );
        for endpoint in searches {
            let path = format!("/t/demo{}", endpoint.path());
            let (routed, ..) = get(server(capabilities), &path).await;
            assert_eq!(
                routed != StatusCode::NOT_FOUND,
                expected,
                "{endpoint:?} is routed={} with search={expected}",
                routed != StatusCode::NOT_FOUND
            );
            assert_eq!(
                pdp.get(endpoint.metadata_key()).is_some(),
                expected,
                "{endpoint:?} in the PDP document with search={expected}"
            );
            assert_eq!(
                provider.get(endpoint.metadata_key()).is_some(),
                expected,
                "{endpoint:?} in the OP metadata with search={expected}"
            );
        }
    }
}

#[tokio::test]
async fn ciba_is_advertised_and_routed_together_or_not_at_all() {
    // Arrange
    let on = Capabilities {
        ciba: true,
        ..Capabilities::default()
    };
    let off = Capabilities::default();
    let path = format!("/t/demo{}", Endpoint::BackchannelAuthentication.path());
    let grant = Value::String("urn:openid:params:grant-type:ciba".to_owned());
    let members = [
        "backchannel_authentication_endpoint",
        "backchannel_token_delivery_modes_supported",
        "backchannel_user_code_parameter_supported",
        "backchannel_authentication_request_signing_alg_values_supported",
    ];

    // Act
    let advertised = document(on).await;
    let (reached, ..) = get(server(on), &path).await;
    let silent = document(off).await;
    let (unreachable, ..) = get(server(off), &path).await;

    // Assert
    assert_ne!(
        reached,
        StatusCode::NOT_FOUND,
        "a backchannel authentication endpoint is advertised and not routed"
    );
    assert_eq!(
        unreachable,
        StatusCode::NOT_FOUND,
        "a route exists for a tenant whose document does not name it"
    );
    for member in members {
        assert!(
            advertised.get(member).is_some(),
            "{member} is missing from a document that offers CIBA: {advertised}"
        );
        assert!(
            silent.get(member).is_none(),
            "{member} is advertised with nothing routed: {silent}"
        );
    }
    assert_eq!(
        advertised["backchannel_authentication_endpoint"],
        Value::String("https://as.example/t/demo/bc-authorize".to_owned()),
        "{advertised}"
    );
    assert!(
        advertised["grant_types_supported"]
            .as_array()
            .expect("array")
            .contains(&grant),
        "the endpoint is advertised without the grant that reaches it"
    );
    assert!(
        !silent["grant_types_supported"]
            .as_array()
            .expect("array")
            .contains(&grant),
        "the CIBA grant is advertised with no endpoint to take it to"
    );
}

/// RFC 8628 §4: `device_authorization_endpoint` is the member a device client
/// reads, and §3.4's grant is how it finishes. Both appear together, both point
/// at something routed, and both vanish together — the same statement as the
/// CIBA test above, on a feature that *is* implemented.
#[tokio::test]
async fn the_device_endpoint_and_its_grant_are_advertised_and_routed_together() {
    // Arrange
    let on = Capabilities {
        device_flow: true,
        ..Capabilities::default()
    };
    let path = format!("/t/demo{}", Endpoint::DeviceAuthorization.path());
    let grant = Value::String("urn:ietf:params:oauth:grant-type:device_code".to_owned());

    // Act
    let advertised = document(on).await;
    let (reached, ..) = get(server(on), &path).await;
    let silent = document(Capabilities::default()).await;
    let (unreachable, ..) = get(server(Capabilities::default()), &path).await;

    // Assert
    assert_ne!(reached, StatusCode::NOT_FOUND);
    assert_eq!(
        advertised["device_authorization_endpoint"],
        Value::String("https://as.example/t/demo/device_authorization".to_owned()),
        "{advertised}"
    );
    assert!(
        advertised["grant_types_supported"]
            .as_array()
            .expect("array")
            .contains(&grant),
        "the endpoint is advertised without the grant that finishes it"
    );
    assert_eq!(unreachable, StatusCode::NOT_FOUND);
    assert!(silent.get("device_authorization_endpoint").is_none());
    assert!(
        !silent["grant_types_supported"]
            .as_array()
            .expect("array")
            .contains(&grant),
        "the device grant is advertised with the flag off: {silent}"
    );
}

// ---------------------------------------------------------------------------
// Discovery — ast-o0t.1, ast-o0t.2
// ---------------------------------------------------------------------------

/// RFC 8414 §3.1 and OIDC Discovery §4, and the acceptance criterion for
/// `ast-o0t.2`: the two locations and the two document names must produce the
/// same bytes. MCP clients try both.
#[tokio::test]
async fn all_four_discovery_urls_return_the_same_document() {
    let paths = [
        "/t/demo/.well-known/openid-configuration",
        "/.well-known/openid-configuration/t/demo",
        "/t/demo/.well-known/oauth-authorization-server",
        "/.well-known/oauth-authorization-server/t/demo",
    ];

    let mut bodies = Vec::new();
    for path in paths {
        let (status, headers, body) = get(server(Capabilities::default()), path).await;
        assert_eq!(status, StatusCode::OK, "{path}");
        assert_eq!(
            headers.get(header::CONTENT_TYPE).expect("content type"),
            "application/json",
            "{path}"
        );
        bodies.push(body);
    }

    for (path, body) in paths.iter().zip(&bodies) {
        assert_eq!(body, &bodies[0], "{path} returned a different document");
    }
}

/// OIDC Discovery §4.3: a client checks that `issuer` is identical to the URL
/// it used. A document that says something else is one a conforming client
/// rejects.
#[tokio::test]
async fn the_issuer_matches_the_url_the_document_was_fetched_from() {
    let metadata = document(Capabilities::default()).await;
    assert_eq!(metadata["issuer"], ISSUER);
}

#[tokio::test]
async fn the_document_is_cacheable_and_revalidatable() {
    let (_, headers, _) = get(
        server(Capabilities::default()),
        "/t/demo/.well-known/openid-configuration",
    )
    .await;
    assert_eq!(
        headers.get(header::CACHE_CONTROL).expect("cache-control"),
        "public, max-age=300"
    );
    let etag = headers
        .get(header::ETAG)
        .expect("etag")
        .to_str()
        .expect("ascii");
    assert!(
        etag.starts_with('"') && etag.ends_with('"'),
        "not a quoted etag: {etag}"
    );
}

#[tokio::test]
async fn an_unknown_tenant_is_a_404_and_says_nothing_else() {
    let (status, _, body) = get(
        server(Capabilities::default()),
        "/t/absent/.well-known/openid-configuration",
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(
        !body.contains("absent"),
        "the response echoed the tenant: {body}"
    );
    assert!(!body.contains("issuer"), "{body}");
}

// ---------------------------------------------------------------------------
// JWKS — ast-mxc.2
// ---------------------------------------------------------------------------

/// The property the whole endpoint exists to not violate.
#[tokio::test]
async fn the_key_set_never_contains_private_material() {
    let (status, _, body) = get(server(Capabilities::default()), "/t/demo/jwks").await;
    assert_eq!(status, StatusCode::OK);

    // RFC 7518 §6.2.2 and §6.3.2: the private members, by name.
    for private in [
        "\"d\"", "\"p\"", "\"q\"", "\"dp\"", "\"dq\"", "\"qi\"", "\"k\"",
    ] {
        assert!(
            !body.contains(private),
            "the key set contains {private}: {body}"
        );
    }

    let document: Value = serde_json::from_str(&body).expect("JSON");
    let keys = document["keys"].as_array().expect("keys array");
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0]["kty"], "OKP");
    assert_eq!(keys[0]["use"], "sig");
    assert!(
        keys[0]["kid"].is_string(),
        "a key without a kid cannot be selected"
    );
}

/// FAPI 2.0 SP §5.4.2: a provider should not serve two keys with the same
/// `kid`, because a verifier then has to guess which one to use.
#[tokio::test]
async fn no_two_published_keys_share_a_kid() {
    let keys = Arc::new(LocalKeyStore::new());
    let tenant = TenantId::parse("demo").expect("tenant id");
    for algorithm in SigningAlgorithm::ALL {
        keys.generate(&tenant, algorithm).expect("generate");
    }
    // Rotate one, so the set holds an active and a retiring key too.
    keys.generate(&tenant, SigningAlgorithm::EdDsa)
        .expect("rotate");

    let published = keys.published_keys(&tenant).await.expect("published");
    assert!(published.len() >= 4, "expected several published keys");

    let mut seen = std::collections::BTreeSet::new();
    for key in &published {
        assert!(seen.insert(key.kid.clone()), "duplicate kid {}", key.kid);
    }
}

/// FAPI 2.0 SP §5.4.2 also says not to use `x5u` or `jku`. We never emit them,
/// and this is what notices if that changes.
#[tokio::test]
async fn the_key_set_never_offers_a_url_to_fetch_a_key_from() {
    let (_, _, body) = get(server(Capabilities::default()), "/t/demo/jwks").await;
    for header in ["x5u", "jku", "x5c"] {
        assert!(
            !body.contains(header),
            "the key set contains {header}: {body}"
        );
    }
}

#[tokio::test]
async fn the_key_set_is_cacheable() {
    let (_, headers, _) = get(server(Capabilities::default()), "/t/demo/jwks").await;
    assert_eq!(
        headers.get(header::CACHE_CONTROL).expect("cache-control"),
        "public, max-age=300"
    );
    assert!(headers.contains_key(header::ETAG));
}

/// The advertised `jwks_uri` must be the URL that actually serves the keys —
/// the one thing a client cannot work around if it is wrong.
#[tokio::test]
async fn the_advertised_jwks_uri_is_the_one_that_serves_the_keys() {
    let metadata = document(Capabilities::default()).await;
    let url = metadata["jwks_uri"].as_str().expect("jwks_uri");
    assert_eq!(url, format!("{ISSUER}/jwks"));

    let path = url
        .strip_prefix("https://as.example")
        .expect("under the issuer host");
    let (status, _, body) = get(server(Capabilities::default()), path).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("\"keys\""));
}

// ---------------------------------------------------------------------------
// The 501 contract
// ---------------------------------------------------------------------------

/// An advertised but unbuilt endpoint answers 501, not 404. The distinction
/// matters to a client: 404 says "wrong URL", 501 says "right URL, not yet".
#[tokio::test]
async fn an_unimplemented_endpoint_answers_501_with_an_oauth_error() {
    let (status, headers, body) = get(server(Capabilities::default()), "/t/demo/token").await;
    assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
    assert_eq!(
        headers.get(header::CONTENT_TYPE).expect("content type"),
        "application/json"
    );
    let error: Value = serde_json::from_str(&body).expect("JSON");
    assert!(
        error["error"].is_string(),
        "not an OAuth error shape: {body}"
    );
}

/// Even a 501 is a response, so it carries the security headers everything
/// else does.
#[tokio::test]
async fn an_unimplemented_endpoint_is_still_a_hardened_response() {
    let (_, headers, _) = get(server(Capabilities::default()), "/t/demo/authorize").await;
    assert!(headers.contains_key(header::STRICT_TRANSPORT_SECURITY));
    assert!(headers.contains_key("x-request-id"));
    assert!(
        !headers
            .keys()
            .any(|k| k.as_str().starts_with("access-control-")),
        "an endpoint leaked CORS headers"
    );
}

// ---------------------------------------------------------------------------
// The golden document
// ---------------------------------------------------------------------------

/// The whole document for the reference tenant, pinned.
///
/// Every other test here asserts one property; this one asserts the shape as a
/// whole, which is the only way an *accidental* change shows up — a member
/// added by a refactor, a list quietly reordered, a value flipped. A diff here
/// is not necessarily a bug, but it is always something a human should have
/// meant to do.
///
/// Regenerate deliberately with `UPDATE_GOLDEN=1 cargo test -p asterius-server
/// --test discovery`, and read the diff before committing it.
#[tokio::test]
async fn the_document_matches_the_golden_file() {
    let metadata = document(Capabilities::default()).await;
    let rendered = format!(
        "{}\n",
        serde_json::to_string_pretty(&metadata).expect("pretty")
    );

    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden/openid-configuration.json");

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
        "the discovery document changed.\nIf that was deliberate, regenerate with \
         UPDATE_GOLDEN=1 and read the diff before committing."
    );
}

// ---- per-tenant feature flags (`ast-f7m.4`) --------------------------------

/// A tenant that switches a deployment feature off stops advertising it, and
/// the change is visible to the *next* request rather than when a cache
/// expires — which is `ast-f7m.4`'s second acceptance criterion. The
/// invalidation is the one the admin API performs after a write
/// (`AdminBackend::tenant_directory_changed`).
#[tokio::test]
async fn a_flag_switched_off_leaves_the_discovery_document_at_once() {
    // Arrange
    let repository = Arc::new(EditableSettings::default());
    let directory = SettingsDirectory::new(Arc::clone(&repository) as _);
    let capabilities = Capabilities {
        device_flow: true,
        ..Capabilities::default()
    };
    let path = "/t/demo/.well-known/openid-configuration";

    let (_, _, before) = get(server_with(capabilities, Some(directory.clone())), path).await;
    let before: Value = serde_json::from_str(&before).expect("a JSON document");
    assert!(
        before.get("device_authorization_endpoint").is_some(),
        "the deployment does not advertise the feature this test switches off"
    );

    // Act
    repository
        .save(
            &TenantId::parse("demo").expect("tenant id"),
            &asterius_domain::TenantSettings::validated(
                std::collections::BTreeSet::from([asterius_domain::Feature::DeviceFlow]),
                asterius_domain::entities::tenant_settings::DEFAULT_AUTHORIZATION_CODE_LIFETIME,
                asterius_domain::entities::tenant_settings::DEFAULT_ACCESS_TOKEN_LIFETIME,
            )
            .expect("within the caps"),
        )
        .await
        .expect("a write");
    directory.invalidate();

    let (status, _, after) = get(server_with(capabilities, Some(directory)), path).await;

    // Assert
    assert_eq!(status, StatusCode::OK);
    let after: Value = serde_json::from_str(&after).expect("a JSON document");
    assert!(
        after.get("device_authorization_endpoint").is_none(),
        "the document still advertises a feature this tenant switched off: {after}"
    );
}

/// The subtraction rule at the edge: a tenant cannot advertise a feature the
/// deployment does not run, whatever its settings say.
#[tokio::test]
async fn a_tenant_cannot_advertise_a_feature_the_deployment_lacks() {
    // Arrange
    let repository = Arc::new(EditableSettings::default());
    let directory = SettingsDirectory::new(Arc::clone(&repository) as _);

    // Act
    let (status, _, body) = get(
        server_with(Capabilities::default(), Some(directory)),
        "/t/demo/.well-known/openid-configuration",
    )
    .await;

    // Assert
    assert_eq!(status, StatusCode::OK);
    let document: Value = serde_json::from_str(&body).expect("a JSON document");
    assert!(document.get("device_authorization_endpoint").is_none());
}

// ---- prompt=create (`ast-2vk.8`) ------------------------------------------

/// OpenID Connect Prompt Create 1.0 §4: `prompt_values_supported` names
/// `create` exactly when the OP supports it.
///
/// The deployment default is off, and off is what the golden document above
/// pins. This is the other half: switching
/// `Feature::SelfRegistration` on is what puts the value in the document, and
/// nothing else does.
#[tokio::test]
async fn prompt_create_is_advertised_only_where_self_registration_is_on() {
    // Arrange
    let path = "/t/demo/.well-known/openid-configuration";
    let on = Capabilities {
        self_registration: true,
        ..Capabilities::default()
    };

    // Act
    let (_, _, without) = get(server_with(Capabilities::default(), None), path).await;
    let (status, _, with) = get(server_with(on, None), path).await;

    // Assert
    assert_eq!(status, StatusCode::OK);
    let without: Value = serde_json::from_str(&without).expect("a JSON document");
    let with: Value = serde_json::from_str(&with).expect("a JSON document");
    assert_eq!(
        without["prompt_values_supported"],
        json!(["none", "login", "consent", "select_account"]),
        "a deployment that registers nobody advertised `create`: {without}"
    );
    assert_eq!(
        with["prompt_values_supported"],
        json!(["none", "login", "consent", "select_account", "create"]),
        "a deployment that registers people did not advertise `create`: {with}"
    );
}

/// The per-tenant half, which is what `tenant_feature_guard` gives every other
/// optional feature: a tenant may switch self-registration off, and then its
/// own document stops offering `create` even though the deployment runs it.
///
/// The value is not merely cosmetic. `protocol::authorization_policy` builds
/// the pushed-request validator from the same capabilities this document is
/// rendered from, so a tenant whose document has stopped naming `create` is a
/// tenant whose pushed request carrying it is refused.
#[tokio::test]
async fn a_tenant_can_switch_prompt_create_off() {
    // Arrange
    let repository = Arc::new(EditableSettings::default());
    let directory = SettingsDirectory::new(Arc::clone(&repository) as _);
    let capabilities = Capabilities {
        self_registration: true,
        ..Capabilities::default()
    };
    let path = "/t/demo/.well-known/openid-configuration";

    // Act
    repository
        .save(
            &TenantId::parse("demo").expect("tenant id"),
            &asterius_domain::TenantSettings::validated(
                std::collections::BTreeSet::from([asterius_domain::Feature::SelfRegistration]),
                asterius_domain::entities::tenant_settings::DEFAULT_AUTHORIZATION_CODE_LIFETIME,
                asterius_domain::entities::tenant_settings::DEFAULT_ACCESS_TOKEN_LIFETIME,
            )
            .expect("within the caps"),
        )
        .await
        .expect("a write");
    directory.invalidate();
    let (status, _, body) = get(server_with(capabilities, Some(directory)), path).await;

    // Assert
    assert_eq!(status, StatusCode::OK);
    let document: Value = serde_json::from_str(&body).expect("a JSON document");
    let prompts = document["prompt_values_supported"]
        .as_array()
        .expect("an array");
    assert!(
        !prompts.contains(&json!("create")),
        "a tenant that switched registration off still advertises it: {document}"
    );
}

/// `ast-pew`: `preferred_username` is advertised again, because something
/// writes it now (the sign-up page of `ast-2vk.8`). It is advertised for every
/// tenant — the claim is a property of the build, not of a feature flag: an
/// account can carry a display name however it was created.
#[tokio::test]
async fn preferred_username_is_advertised() {
    // Arrange
    let path = "/t/demo/.well-known/openid-configuration";

    // Act
    let (status, _, body) = get(server_with(Capabilities::default(), None), path).await;

    // Assert
    assert_eq!(status, StatusCode::OK);
    let document: Value = serde_json::from_str(&body).expect("a JSON document");
    let claims = document["claims_supported"].as_array().expect("an array");
    assert!(
        claims.contains(&json!("preferred_username")),
        "the document does not advertise the claim the sign-up page writes: {document}"
    );
}

// ---- per-tenant parity (`ast-edc`) ----------------------------------------

/// A tenant repository serving two tenants under the same host, so a test can
/// assert that one tenant's settings do not reach the other.
#[derive(Debug)]
struct TwoTenants(Vec<Tenant>);

#[async_trait::async_trait]
impl TenantRepository for TwoTenants {
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
        Ok(self.0.clone())
    }
    async fn upsert(&self, _: &Tenant) -> Result<(), DomainError> {
        unimplemented!("read-only")
    }
    async fn delete(&self, _: &TenantId) -> Result<(), DomainError> {
        unimplemented!("read-only")
    }
}

/// Settings that differ per tenant, which is what makes "the other tenant is
/// unaffected" a statement about the code rather than about the fixture.
#[derive(Debug, Default)]
struct PerTenantSettings(BTreeMap<String, asterius_domain::TenantSettings>);

#[async_trait::async_trait]
impl asterius_domain::ports::TenantSettingsRepository for PerTenantSettings {
    async fn settings(
        &self,
        tenant: &TenantId,
    ) -> Result<asterius_domain::TenantSettings, DomainError> {
        Ok(self.0.get(tenant.as_str()).cloned().unwrap_or_default())
    }

    async fn save(
        &self,
        _tenant: &TenantId,
        _settings: &asterius_domain::TenantSettings,
    ) -> Result<(), DomainError> {
        unimplemented!("read-only")
    }
}

fn tenant_named(id: &str) -> Tenant {
    Tenant {
        id: TenantId::parse(id).expect("tenant id"),
        issuer: Issuer::parse(&format!("https://as.example/t/{id}")).expect("issuer"),
        default_resource: "https://api.example/".to_owned(),
        custom_host: None,
        display_name: id.to_owned(),
        status: TenantStatus::Active,
        refresh: asterius_domain::RefreshPolicy::default(),
        created_at: OffsetDateTime::UNIX_EPOCH,
        updated_at: OffsetDateTime::UNIX_EPOCH,
    }
}

/// Every capability, on at the deployment level, so a tenant's settings are the
/// only thing that can take one away.
const ALL_ON: Capabilities = Capabilities {
    mtls: true,
    grant_management: true,
    ciba: true,
    device_flow: true,
    token_exchange: true,
    ssf: true,
    authzen: true,
    authzen_search: true,
    dpop_nonce: true,
    request_object: true,
    dynamic_client_registration: true,
    self_registration: true,
};

fn disabling(feature: asterius_domain::Feature) -> asterius_domain::TenantSettings {
    asterius_domain::TenantSettings::validated(
        std::collections::BTreeSet::from([feature]),
        asterius_domain::entities::tenant_settings::DEFAULT_AUTHORIZATION_CODE_LIFETIME,
        asterius_domain::entities::tenant_settings::DEFAULT_ACCESS_TOKEN_LIFETIME,
    )
    .expect("within the caps")
}

/// A server for two tenants, `demo` and `other`, with `demo`'s settings taken
/// from the argument and `other`'s left at the defaults.
fn two_tenant_server(demo: asterius_domain::TenantSettings) -> Router {
    let tenants = vec![tenant_named("demo"), tenant_named("other")];
    let keys = Arc::new(LocalKeyStore::new());
    for tenant in &tenants {
        keys.generate(&tenant.id, SigningAlgorithm::DEFAULT)
            .expect("generate a key");
    }

    let repository = Arc::new(PerTenantSettings(BTreeMap::from([(
        "demo".to_owned(),
        demo,
    )])));
    let config = server_config();
    let directory = TenantDirectory::new(Arc::new(TwoTenants(tenants)));
    let routes = protocol::routes(ProtocolState {
        keys: Arc::clone(&keys) as Arc<dyn KeyStore>,
        capabilities: ALL_ON,
        tenant_settings: Some(SettingsDirectory::new(repository as _)),
        clients: None,
        signed_metadata: None,
    })
    .fallback(not_found);

    app(routes, TenantState::new(directory, &config), None, &config)
}

/// The parity invariant of `ast-o0t.3`, per tenant: for every endpoint a tenant
/// can switch off, the document and the router agree — the key is gone and the
/// URL answers 404, exactly as it does when the deployment lacks the feature.
#[tokio::test]
async fn a_feature_a_tenant_switched_off_is_neither_advertised_nor_reachable() {
    for endpoint in Endpoint::ALL {
        let Some(feature) = endpoint.required_feature() else {
            continue;
        };

        // Arrange
        let router = two_tenant_server(disabling(feature));

        // Act
        let (status, _, body) =
            get(router.clone(), "/t/demo/.well-known/openid-configuration").await;
        let document: Value = serde_json::from_str(&body).expect("a JSON document");
        let (reached, ..) = get(router, &format!("/t/demo{}", endpoint.path())).await;

        // Assert
        assert_eq!(status, StatusCode::OK);
        assert!(
            document.get(endpoint.metadata_key()).is_none(),
            "{endpoint:?} is still advertised to a tenant that switched {feature} off"
        );
        assert_eq!(
            reached,
            StatusCode::NOT_FOUND,
            "{endpoint:?} is still reachable by a tenant that switched {feature} off"
        );
    }
}

/// The blast radius: one tenant's setting is one tenant's setting.
#[tokio::test]
async fn another_tenant_keeps_the_feature_the_first_switched_off() {
    // Arrange
    let router = two_tenant_server(disabling(asterius_domain::Feature::DeviceFlow));
    let path = format!("/t/other{}", Endpoint::DeviceAuthorization.path());

    // Act
    let (_, _, body) = get(router.clone(), "/t/other/.well-known/openid-configuration").await;
    let (reached, ..) = get(router, &path).await;

    // Assert
    let document: Value = serde_json::from_str(&body).expect("a JSON document");
    assert!(
        document.get("device_authorization_endpoint").is_some(),
        "another tenant's setting removed this tenant's endpoint: {document}"
    );
    assert_ne!(
        reached,
        StatusCode::NOT_FOUND,
        "another tenant's setting unmounted this tenant's route"
    );
}

/// A settings read that fails must not open a route the tenant may have closed.
/// The discovery handler already answers 503 rather than guessing; the guard
/// holds the same line.
#[tokio::test]
async fn a_settings_read_that_fails_closes_the_route() {
    // Arrange
    #[derive(Debug)]
    struct Broken;

    #[async_trait::async_trait]
    impl asterius_domain::ports::TenantSettingsRepository for Broken {
        async fn settings(
            &self,
            _tenant: &TenantId,
        ) -> Result<asterius_domain::TenantSettings, DomainError> {
            Err(DomainError::Storage("no database".into()))
        }
        async fn save(
            &self,
            _tenant: &TenantId,
            _settings: &asterius_domain::TenantSettings,
        ) -> Result<(), DomainError> {
            unimplemented!("read-only")
        }
    }

    let router = server_with(ALL_ON, Some(SettingsDirectory::new(Arc::new(Broken) as _)));

    // Act
    let (status, ..) = get(
        router,
        &format!("/t/demo{}", Endpoint::DeviceAuthorization.path()),
    )
    .await;

    // Assert
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}

/// `ast-0qv`, the tenant half: a stored registration policy of `closed` takes
/// the endpoint away from that tenant, through the same subtraction every other
/// feature goes through — advertised nowhere, mounted nowhere.
#[tokio::test]
async fn a_tenant_whose_policy_is_closed_has_no_registration_endpoint() {
    // Arrange
    let settings = asterius_domain::TenantSettings::from_json(Some(&serde_json::json!({
        "registration_policy": { "mode": "closed" }
    })))
    .expect("a valid settings document");
    let router = two_tenant_server(settings);

    // Act
    let (status, _, body) = get(router.clone(), "/t/demo/.well-known/openid-configuration").await;
    let (reached, ..) = get(router, &format!("/t/demo{}", Endpoint::Registration.path())).await;

    // Assert
    assert_eq!(status, StatusCode::OK);
    let document: Value = serde_json::from_str(&body).expect("a JSON document");
    assert!(
        document.get("registration_endpoint").is_none(),
        "a tenant that registers nobody still advertises the endpoint: {document}"
    );
    assert_eq!(reached, StatusCode::NOT_FOUND);
}

/// The deployment half of the same rule, and the defect `ast-m9c.6` names: a
/// deployment with `[registration] mode = "closed"` used to advertise a
/// `registration_endpoint` that answered 403 to everybody.
#[tokio::test]
async fn a_closed_deployment_advertises_no_registration_endpoint() {
    // Arrange
    let router = server_with(Capabilities::default(), None);

    // Act
    let (status, _, body) = get(router, "/t/demo/.well-known/openid-configuration").await;

    // Assert
    assert_eq!(status, StatusCode::OK);
    let document: Value = serde_json::from_str(&body).expect("a JSON document");
    assert!(
        document.get("registration_endpoint").is_none(),
        "what gates the announcement must gate the route: {document}"
    );
}
