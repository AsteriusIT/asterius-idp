//! Discovery, JWKS, and the parity between what is advertised and what exists.
//!
//! The parity test is the reason `ast-o0t.3` exists. RFC 8414 §2 says metadata
//! must reflect actual behaviour, and the way that stops being true is never
//! dramatic: an endpoint is added and the document is not updated, or a flag is
//! turned off and its key stays. Both are silent. Asserting the two agree is
//! the only thing that keeps them agreeing.

use asterius_domain::ports::TenantRepository;
use asterius_domain::{
    Capabilities, DomainError, Issuer, KeyStore, SigningAlgorithm, Tenant, TenantId, TenantStatus,
};
use asterius_jose::LocalKeyStore;
use asterius_oidc::metadata::Endpoint;
use asterius_server::config::{Config, ServerConfig};
use asterius_server::http::protocol::{self, ProtocolState};
use asterius_server::http::server::{app, not_found};
use asterius_server::tenancy::{TenantDirectory, TenantState};
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

/// The whole server, for one tenant, with one signing key.
fn server(capabilities: Capabilities) -> Router {
    let tenant = Tenant {
        id: TenantId::parse("demo").expect("tenant id"),
        issuer: Issuer::parse(ISSUER).expect("issuer"),
        custom_host: None,
        display_name: "Demo".to_owned(),
        status: TenantStatus::Active,
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
        dpop_nonce: true,
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
