//! Tenant resolution through the fully assembled application.
//!
//! `tenancy::resolve` is unit-tested in place; this drives the real router, so
//! it also covers the parts that only exist once everything is wired: that the
//! rewritten path is what routing sees, that a rejection still carries the
//! security headers, and that a handler receives the tenant without ever
//! asking for one.
//!
//! Two seeded tenants, distinct issuers — the acceptance shape for
//! `ast-83p.10`.

use asterius_domain::ports::TenantRepository;
use asterius_domain::{DomainError, Issuer, Tenant, TenantId, TenantStatus};
use asterius_server::config::{Config, ServerConfig};
use asterius_server::http::server::{app, not_found};
use asterius_server::tenancy::{TenantDirectory, TenantState};
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use axum::routing::get;
use axum::{Extension, Router};
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

fn server_config() -> ServerConfig {
    Config::parse(CONFIG, Path::new("asterius.toml"), &BTreeMap::new())
        .expect("valid test config")
        .server
}

/// A fixed two-tenant directory, in memory.
#[derive(Debug)]
struct Seeded(Vec<Tenant>);

#[async_trait::async_trait]
impl TenantRepository for Seeded {
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

fn tenant(id: &str, issuer: &str, custom_host: Option<&str>, status: TenantStatus) -> Tenant {
    Tenant {
        id: TenantId::parse(id).expect("tenant id"),
        issuer: Issuer::parse(issuer).expect("issuer"),
        default_resource: "https://api.example/".to_owned(),
        custom_host: custom_host.map(str::to_owned),
        display_name: id.to_owned(),
        status,
        created_at: OffsetDateTime::UNIX_EPOCH,
        updated_at: OffsetDateTime::UNIX_EPOCH,
    }
}

/// Two tenants on one host, a third on its own hostname, and one disabled.
fn seeded() -> Router {
    let tenants = vec![
        tenant(
            "alpha",
            "https://as.example/t/alpha",
            None,
            TenantStatus::Active,
        ),
        tenant(
            "beta",
            "https://as.example/t/beta",
            None,
            TenantStatus::Active,
        ),
        tenant(
            "acme",
            "https://login.acme.test",
            Some("login.acme.test"),
            TenantStatus::Active,
        ),
        tenant(
            "closed",
            "https://as.example/t/closed",
            None,
            TenantStatus::Disabled,
        ),
    ];
    let directory = TenantDirectory::new(Arc::new(Seeded(tenants)));
    let config = server_config();
    let state = TenantState::new(directory, &config);

    // Handlers are mounted at bare paths. That is the point: they cannot see
    // tenancy in the URL, so they cannot get it wrong.
    let routes = Router::new()
        .route(
            "/authorize",
            get(|Extension(tenant): Extension<Arc<Tenant>>| async move {
                format!("{}|{}", tenant.id, tenant.issuer)
            }),
        )
        .route(
            "/.well-known/openid-configuration",
            get(|Extension(tenant): Extension<Arc<Tenant>>| async move {
                format!("{}|{}", tenant.id, tenant.issuer)
            }),
        )
        .fallback(not_found);

    app(routes, state, None, &config)
}

async fn request(host: &str, path: &str) -> (StatusCode, String, axum::http::HeaderMap) {
    let response = seeded()
        .oneshot(
            Request::builder()
                .uri(path)
                .header(header::HOST, host)
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("router is infallible");
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("body");
    (
        status,
        String::from_utf8_lossy(&bytes).into_owned(),
        headers,
    )
}

// ---------------------------------------------------------------------------
// Resolution
// ---------------------------------------------------------------------------

#[tokio::test]
async fn each_tenant_is_served_under_its_own_path_with_its_own_issuer() {
    let (status, body, _) = request("as.example", "/t/alpha/authorize").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "alpha|https://as.example/t/alpha");

    let (status, body, _) = request("as.example", "/t/beta/authorize").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "beta|https://as.example/t/beta");
}

/// RFC 8414 §3.1 and OIDC Discovery §4 describe different URLs for the same
/// document, and MCP Authorization tells clients to try both. Both must work,
/// and both must reach the same handler.
#[tokio::test]
async fn both_well_known_forms_reach_the_same_document() {
    let appended = request("as.example", "/t/alpha/.well-known/openid-configuration").await;
    let inserted = request("as.example", "/.well-known/openid-configuration/t/alpha").await;

    assert_eq!(appended.0, StatusCode::OK);
    assert_eq!(inserted.0, StatusCode::OK);
    assert_eq!(appended.1, "alpha|https://as.example/t/alpha");
    assert_eq!(appended.1, inserted.1);
}

#[tokio::test]
async fn a_vanity_host_needs_no_tenant_in_the_path() {
    let (status, body, _) = request("login.acme.test", "/authorize").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "acme|https://login.acme.test");

    let (status, body, _) = request("login.acme.test", "/.well-known/openid-configuration").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "acme|https://login.acme.test");
}

#[tokio::test]
async fn the_query_string_survives_the_rewrite() {
    let (status, ..) = request(
        "as.example",
        "/t/alpha/authorize?client_id=a&request_uri=urn:x",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

// ---------------------------------------------------------------------------
// Isolation
// ---------------------------------------------------------------------------

/// The check that makes the issuer claim honest: a tenant is only served on a
/// host it owns. Otherwise `https://anything/t/alpha/token` would mint tokens
/// asserting `iss: https://as.example/t/alpha`, and a client verifying `iss`
/// would be satisfied by a server it never spoke to.
#[tokio::test]
async fn a_tenant_is_not_reachable_through_a_host_it_does_not_own() {
    for host in [
        "attacker.example",
        "login.acme.test",
        "as.example.attacker.test",
    ] {
        let (status, ..) = request(host, "/t/alpha/authorize").await;
        assert_eq!(status, StatusCode::NOT_FOUND, "alpha was served on {host}");
    }
}

/// The mirror: a vanity-host tenant is not reachable by path on the shared
/// host, because its issuer says otherwise.
#[tokio::test]
async fn a_vanity_host_tenant_is_not_reachable_by_path_elsewhere() {
    let (status, ..) = request("as.example", "/t/acme/authorize").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// Disabled, absent and wrong-host all answer identically. Anything else lets
/// an unauthenticated caller enumerate tenants and spot suspensions.
#[tokio::test]
async fn absent_disabled_and_wrong_host_are_indistinguishable() {
    let absent = request("as.example", "/t/nosuchtenant/authorize").await;
    let disabled = request("as.example", "/t/closed/authorize").await;
    let wrong_host = request("attacker.example", "/t/alpha/authorize").await;

    assert_eq!(absent.0, StatusCode::NOT_FOUND);
    assert_eq!(disabled.0, disabled.0);
    assert_eq!(absent.0, disabled.0);
    assert_eq!(absent.0, wrong_host.0);
    assert_eq!(absent.1, disabled.1);
    assert_eq!(absent.1, wrong_host.1);
}

#[tokio::test]
async fn a_path_that_names_no_tenant_on_a_shared_host_is_not_served() {
    for path in ["/authorize", "/", "/t/", "/token"] {
        let (status, ..) = request("as.example", path).await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "{path} was served without a tenant"
        );
    }
}

/// A tenant id is a path segment under attacker control that selects signing
/// keys. Traversal, encoding tricks and case games are refused.
#[tokio::test]
async fn a_malformed_tenant_path_is_refused() {
    for path in [
        "/t/../authorize",
        "/t/Alpha/authorize",
        "/t/alpha%2f../authorize",
        "/.well-known/openid-configuration/t/alpha/extra",
        "/.well-known/openid-configuration/not-a-tenant",
    ] {
        let (status, ..) = request("as.example", path).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path} was not refused");
    }
}

// ---------------------------------------------------------------------------
// The middleware stack still applies
// ---------------------------------------------------------------------------

/// A tenant rejection is produced inside the shared middleware, so it must
/// still carry everything an ordinary response carries.
#[tokio::test]
async fn a_tenant_rejection_is_still_a_hardened_response() {
    let (status, _, headers) = request("attacker.example", "/t/alpha/authorize").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(
        headers
            .get(header::STRICT_TRANSPORT_SECURITY)
            .expect("HSTS"),
        "max-age=31536000; includeSubDomains; preload"
    );
    assert!(headers.contains_key("x-request-id"));
    assert_eq!(
        headers.get(header::X_FRAME_OPTIONS).expect("frame options"),
        "DENY"
    );
    assert!(
        !headers
            .keys()
            .any(|k| k.as_str().starts_with("access-control-")),
        "a tenant rejection leaked CORS headers"
    );
}
