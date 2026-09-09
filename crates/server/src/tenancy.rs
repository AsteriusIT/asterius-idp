//! Resolving the tenant, before any protocol handler runs.
//!
//! A tenant is an issuer, so "which tenant is this?" is the first question of
//! every request and the answer decides whose keys sign the result. Getting it
//! wrong is not a routing bug, it is a cross-tenant compromise.
//!
//! The middleware here does three things and then gets out of the way:
//!
//! 1. **Resolves.** [`asterius_oidc::tenancy::route`] turns the path into a
//!    tenant id and a handler path, accepting both well-known forms; failing
//!    that, the host is matched against a tenant's vanity hostname.
//! 2. **Verifies the host.** A resolved tenant is only served if the request's
//!    host is the one in its issuer, or its configured `custom_host`. Without
//!    this, `https://anything/t/demo/token` would mint tokens claiming
//!    `iss: https://as.example/t/demo`.
//! 3. **Rewrites the path.** Handlers are mounted at `/authorize` and `/token`
//!    and never learn that tenants exist, which means a handler cannot forget
//!    to scope itself — it has no tenant parameter to forget.
//!
//! Lookups are cached in-process as an immutable snapshot swapped under a
//! lock. There is no Redis (ADR-0001), and there does not need to be: tenants
//! number in the tens, change rarely, and a snapshot read is a lock acquire and
//! a hash lookup.

use asterius_domain::ports::TenantRepository;
use asterius_domain::{Tenant, TenantId};
use asterius_oidc::tenancy::{self, Route, RouteError};
use axum::extract::{Request, State};
use axum::http::{StatusCode, Uri, header, uri};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use crate::config::ServerConfig;
use crate::http::forwarded;

/// How long a cached snapshot is served before it is reloaded.
///
/// Invalidation on admin change is the fast path; this is the safety net for
/// the case the admin change happened in *another* replica, which has no way to
/// tell this one. Short enough that an operator disabling a tenant sees it take
/// effect while they are still watching, long enough that the database is not
/// answering the same question on every request.
const SNAPSHOT_TTL: Duration = Duration::from_secs(30);

/// An immutable view of every tenant, indexed the two ways requests arrive.
#[derive(Debug)]
struct Snapshot {
    by_id: HashMap<String, Arc<Tenant>>,
    by_host: HashMap<String, Arc<Tenant>>,
    loaded_at: Instant,
}

impl Snapshot {
    fn build(tenants: Vec<Tenant>) -> Self {
        let mut by_id = HashMap::with_capacity(tenants.len());
        let mut by_host = HashMap::new();
        for tenant in tenants {
            let tenant = Arc::new(tenant);
            if let Some(host) = &tenant.custom_host {
                by_host.insert(host.to_ascii_lowercase(), Arc::clone(&tenant));
            }
            by_id.insert(tenant.id.as_str().to_owned(), tenant);
        }
        Self {
            by_id,
            by_host,
            loaded_at: Instant::now(),
        }
    }

    fn is_fresh(&self) -> bool {
        self.loaded_at.elapsed() < SNAPSHOT_TTL
    }
}

/// The tenant directory: a repository plus an in-process cache.
#[derive(Clone)]
pub struct TenantDirectory {
    repository: Arc<dyn TenantRepository>,
    snapshot: Arc<RwLock<Option<Arc<Snapshot>>>>,
}

impl std::fmt::Debug for TenantDirectory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let cached = self
            .snapshot
            .read()
            .ok()
            .and_then(|guard| guard.as_ref().map(|snapshot| snapshot.by_id.len()));
        f.debug_struct("TenantDirectory")
            .field("repository", &"<dyn TenantRepository>")
            .field(
                "snapshot",
                &cached.map_or("empty".to_owned(), |n| format!("{n} tenants")),
            )
            .finish()
    }
}

impl TenantDirectory {
    /// Wraps a repository.
    #[must_use]
    pub fn new(repository: Arc<dyn TenantRepository>) -> Self {
        Self {
            repository,
            snapshot: Arc::new(RwLock::new(None)),
        }
    }

    /// Drops the cached snapshot so the next lookup reloads.
    ///
    /// The admin API calls this after any change to a tenant (`ast-f7m.4`).
    /// Dropping rather than updating is deliberate: a partial update is a way
    /// to serve a tenant that was just disabled.
    pub fn invalidate(&self) {
        if let Ok(mut guard) = self.snapshot.write() {
            *guard = None;
        }
    }

    /// The current snapshot, reloading if it is missing or stale.
    async fn snapshot(&self) -> Result<Arc<Snapshot>, asterius_domain::DomainError> {
        if let Ok(guard) = self.snapshot.read()
            && let Some(snapshot) = guard.as_ref()
            && snapshot.is_fresh()
        {
            return Ok(Arc::clone(snapshot));
        }

        // Reload outside the lock. Two requests racing here both load and one
        // wins the write; that costs a duplicate query on a cold cache and
        // avoids holding a lock across an await, which this lock type cannot
        // do anyway.
        let loaded = Arc::new(Snapshot::build(self.repository.list().await?));
        if let Ok(mut guard) = self.snapshot.write() {
            *guard = Some(Arc::clone(&loaded));
        }
        Ok(loaded)
    }

    /// Looks a tenant up by its identifier.
    ///
    /// # Errors
    ///
    /// Returns the repository's error if the tenant list cannot be loaded.
    pub async fn by_id(
        &self,
        id: &TenantId,
    ) -> Result<Option<Arc<Tenant>>, asterius_domain::DomainError> {
        Ok(self
            .snapshot()
            .await?
            .by_id
            .get(id.as_str())
            .map(Arc::clone))
    }

    /// Looks a tenant up by its vanity hostname.
    ///
    /// # Errors
    ///
    /// Returns the repository's error if the tenant list cannot be loaded.
    pub async fn by_host(
        &self,
        host: &str,
    ) -> Result<Option<Arc<Tenant>>, asterius_domain::DomainError> {
        Ok(self
            .snapshot()
            .await?
            .by_host
            .get(&host.to_ascii_lowercase())
            .map(Arc::clone))
    }
}

/// Everything the tenant middleware needs.
#[derive(Clone, Debug)]
pub struct TenantState {
    /// Where tenants come from.
    pub directory: TenantDirectory,
    /// Peers whose forwarding headers are believed.
    pub trusted_proxies: Arc<Vec<ipnet::IpNet>>,
}

impl TenantState {
    /// Builds the middleware state from the server configuration.
    #[must_use]
    pub fn new(directory: TenantDirectory, config: &ServerConfig) -> Self {
        Self {
            directory,
            trusted_proxies: Arc::new(config.trusted_proxies.clone()),
        }
    }
}

/// Why a request could not be attributed to a tenant.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Rejection {
    /// The path named a tenant that cannot exist.
    Malformed(String),
    /// No tenant matched, or the one that matched is disabled or on another host.
    NoSuchTenant,
    /// The tenant list could not be loaded.
    Unavailable,
}

impl IntoResponse for Rejection {
    fn into_response(self) -> Response {
        // A disabled tenant, a tenant on another host and a tenant that has
        // never existed all answer 404 with the same body. Anything else lets
        // an unauthenticated caller enumerate which tenants exist and which
        // have been suspended.
        let (status, body) = match self {
            Self::Malformed(_) | Self::NoSuchTenant => (StatusCode::NOT_FOUND, "not found\n"),
            Self::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, "service unavailable\n"),
        };
        (
            status,
            [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            body,
        )
            .into_response()
    }
}

/// Resolves the tenant, verifies the host, and rewrites the path.
///
/// On success the request carries `Arc<Tenant>` in its extensions and a path
/// with tenancy removed.
pub async fn layer(State(state): State<TenantState>, mut request: Request, next: Next) -> Response {
    let peer = request
        .extensions()
        .get::<axum::extract::ConnectInfo<SocketAddr>>()
        .map_or_else(|| IpAddr::from([0, 0, 0, 0]), |info| info.0.ip());

    let authority = request
        .uri()
        .authority()
        .map(uri::Authority::as_str)
        .map(str::to_owned);
    let host = forwarded::resolve_host(
        peer,
        request.headers(),
        &state.trusted_proxies,
        authority.as_deref(),
    )
    .map(str::to_owned);

    let path = request.uri().path().to_owned();
    let resolved = match resolve(&state, &path, host.as_deref()).await {
        Ok(resolved) => resolved,
        Err(rejection) => {
            if let Rejection::Malformed(reason) = &rejection {
                tracing::debug!(%path, %reason, "rejected a malformed tenant path");
            }
            return rejection.into_response();
        }
    };

    rewrite_path(request.uri_mut(), &resolved.path);
    // The client address, resolved once here rather than in each handler that
    // wants one. This layer already holds both halves of the question — the
    // socket peer and the trusted-proxy set — and a handler that resolved it
    // itself would be a second place for the spoofing rule to be got wrong.
    // `ast-2vk.9`'s login limiter is the first reader; `ast-p2l.3` and the
    // audit trail are the next.
    let client = forwarded::resolve(peer, request.headers(), &state.trusted_proxies);
    request.extensions_mut().insert(client);
    request
        .extensions_mut()
        .insert(Arc::clone(&resolved.tenant));
    next.run(request).await
}

/// A resolved request: which tenant, and what path the handler should see.
struct Resolved {
    tenant: Arc<Tenant>,
    path: String,
}

async fn resolve(
    state: &TenantState,
    path: &str,
    host: Option<&str>,
) -> Result<Resolved, Rejection> {
    // Every routing failure is a malformed request rather than a missing
    // tenant: the path is wrong whichever tenants happen to exist.
    let route: Route =
        tenancy::route(path).map_err(|e: RouteError| Rejection::Malformed(e.to_string()))?;

    let unavailable = |error: asterius_domain::DomainError| {
        tracing::error!(%error, "cannot load the tenant directory");
        Rejection::Unavailable
    };

    // A tenant named in the path wins; otherwise the host has to name one.
    let tenant = if let Some(id) = &route.tenant {
        state.directory.by_id(id).await.map_err(unavailable)?
    } else {
        let host = host.ok_or(Rejection::NoSuchTenant)?;
        state.directory.by_host(host).await.map_err(unavailable)?
    }
    .ok_or(Rejection::NoSuchTenant)?;

    if !tenant.is_active() {
        return Err(Rejection::NoSuchTenant);
    }

    // The host must be one this tenant answers to. Without this check,
    // `https://anything/t/demo/token` would be served and would mint tokens
    // claiming `iss: https://as.example/t/demo` — an issuer the request never
    // reached. A client checking `iss` would be satisfied by a server it never
    // spoke to.
    if !serves_host(&tenant, host) {
        tracing::debug!(
            tenant = %tenant.id,
            requested = host.unwrap_or("<none>"),
            issuer = %tenant.issuer,
            "host does not belong to the resolved tenant"
        );
        return Err(Rejection::NoSuchTenant);
    }

    Ok(Resolved {
        tenant,
        path: route.path,
    })
}

/// Whether `host` is a hostname this tenant answers to.
fn serves_host(tenant: &Tenant, host: Option<&str>) -> bool {
    let Some(host) = host else { return false };
    let host = host.trim().to_ascii_lowercase();
    if host == tenant.issuer.authority().to_ascii_lowercase() {
        return true;
    }
    tenant
        .custom_host
        .as_ref()
        .is_some_and(|custom| custom.eq_ignore_ascii_case(&host))
}

/// Replaces the path of `uri` in place, keeping the query.
fn rewrite_path(uri: &mut Uri, path: &str) {
    let mut parts = uri.clone().into_parts();
    let path_and_query = match parts
        .path_and_query
        .as_ref()
        .and_then(uri::PathAndQuery::query)
    {
        Some(query) => format!("{path}?{query}"),
        None => path.to_owned(),
    };
    // The path comes from `tenancy::route`, which only ever returns a prefix of
    // the original path or a literal, so this cannot fail — but a panic in a
    // middleware is worse than leaving the URI alone.
    if let Ok(parsed) = path_and_query.parse::<uri::PathAndQuery>() {
        parts.path_and_query = Some(parsed);
        if let Ok(rebuilt) = Uri::from_parts(parts) {
            *uri = rebuilt;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asterius_domain::{DomainError, Issuer, TenantStatus};
    use time::OffsetDateTime;

    /// An in-memory `TenantRepository` that counts how often it is read, so
    /// the caching tests can assert on the thing that matters.
    #[derive(Debug, Default)]
    struct FakeRepository {
        tenants: std::sync::Mutex<Vec<Tenant>>,
        reads: std::sync::atomic::AtomicUsize,
    }

    impl FakeRepository {
        fn with(tenants: Vec<Tenant>) -> Arc<Self> {
            Arc::new(Self {
                tenants: std::sync::Mutex::new(tenants),
                reads: 0.into(),
            })
        }

        fn reads(&self) -> usize {
            self.reads.load(std::sync::atomic::Ordering::Relaxed)
        }

        fn replace(&self, tenants: Vec<Tenant>) {
            *self.tenants.lock().expect("lock") = tenants;
        }
    }

    #[async_trait::async_trait]
    impl TenantRepository for FakeRepository {
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
            self.reads
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(self.tenants.lock().expect("lock").clone())
        }
        async fn upsert(&self, _: &Tenant) -> Result<(), DomainError> {
            unimplemented!("read-only in tests")
        }
        async fn delete(&self, _: &TenantId) -> Result<(), DomainError> {
            unimplemented!("read-only in tests")
        }
    }

    fn tenant(id: &str, issuer: &str, custom_host: Option<&str>) -> Tenant {
        Tenant {
            id: TenantId::parse(id).expect("test tenant id"),
            issuer: Issuer::parse(issuer).expect("test issuer"),
            default_resource: "https://api.example/".to_owned(),
            custom_host: custom_host.map(str::to_owned),
            display_name: id.to_owned(),
            status: TenantStatus::Active,
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    fn state(repository: Arc<FakeRepository>) -> TenantState {
        TenantState {
            directory: TenantDirectory::new(repository),
            trusted_proxies: Arc::new(Vec::new()),
        }
    }

    // ---- host verification ----------------------------------------------

    #[test]
    fn a_tenant_serves_its_issuer_authority_and_its_vanity_host() {
        let t = tenant("demo", "https://as.example/t/demo", Some("login.acme.test"));
        assert!(serves_host(&t, Some("as.example")));
        assert!(serves_host(&t, Some("AS.Example")));
        assert!(serves_host(&t, Some("login.acme.test")));
        assert!(!serves_host(&t, Some("attacker.example")));
        assert!(!serves_host(&t, None));
    }

    #[test]
    fn a_port_in_the_issuer_must_be_present_in_the_host() {
        let t = tenant("demo", "https://as.example:8443/t/demo", None);
        assert!(serves_host(&t, Some("as.example:8443")));
        assert!(
            !serves_host(&t, Some("as.example")),
            "port must not be optional"
        );
    }

    // ---- resolution ------------------------------------------------------

    #[tokio::test]
    async fn a_path_tenant_resolves_and_the_path_is_rewritten() {
        let state = state(FakeRepository::with(vec![tenant(
            "demo",
            "https://as.example/t/demo",
            None,
        )]));
        let resolved = resolve(&state, "/t/demo/authorize", Some("as.example"))
            .await
            .expect("should resolve");
        assert_eq!(resolved.tenant.id.as_str(), "demo");
        assert_eq!(resolved.path, "/authorize");
    }

    #[tokio::test]
    async fn both_well_known_forms_resolve_to_one_tenant_and_one_path() {
        let state = state(FakeRepository::with(vec![tenant(
            "demo",
            "https://as.example/t/demo",
            None,
        )]));
        for path in [
            "/t/demo/.well-known/openid-configuration",
            "/.well-known/openid-configuration/t/demo",
        ] {
            let resolved = resolve(&state, path, Some("as.example"))
                .await
                .expect("should resolve");
            assert_eq!(resolved.tenant.id.as_str(), "demo");
            assert_eq!(resolved.path, "/.well-known/openid-configuration");
        }
    }

    #[tokio::test]
    async fn a_vanity_host_resolves_without_a_tenant_path() {
        let state = state(FakeRepository::with(vec![tenant(
            "acme",
            "https://login.acme.test",
            Some("login.acme.test"),
        )]));
        let resolved = resolve(&state, "/authorize", Some("login.acme.test"))
            .await
            .expect("should resolve");
        assert_eq!(resolved.tenant.id.as_str(), "acme");
        assert_eq!(resolved.path, "/authorize");
    }

    /// The check that stops `https://anything/t/demo/token` from minting tokens
    /// that claim an issuer the request never reached.
    #[tokio::test]
    async fn a_tenant_is_not_served_on_a_host_that_is_not_its_own() {
        let state = state(FakeRepository::with(vec![tenant(
            "demo",
            "https://as.example/t/demo",
            None,
        )]));
        let rejected = resolve(&state, "/t/demo/token", Some("attacker.example")).await;
        assert_eq!(rejected.err(), Some(Rejection::NoSuchTenant));
    }

    #[tokio::test]
    async fn an_unknown_or_disabled_tenant_is_indistinguishable_from_a_missing_one() {
        let mut disabled = tenant("off", "https://as.example/t/off", None);
        disabled.status = TenantStatus::Disabled;
        let state = state(FakeRepository::with(vec![
            tenant("demo", "https://as.example/t/demo", None),
            disabled,
        ]));

        for path in ["/t/off/authorize", "/t/absent/authorize"] {
            let rejected = resolve(&state, path, Some("as.example")).await;
            assert_eq!(rejected.err(), Some(Rejection::NoSuchTenant), "{path}");
        }
    }

    #[tokio::test]
    async fn a_malformed_tenant_path_never_reaches_the_directory() {
        let repository = FakeRepository::with(vec![]);
        let state = state(Arc::clone(&repository));
        let rejected = resolve(&state, "/t/../authorize", Some("as.example")).await;
        assert!(matches!(rejected.err(), Some(Rejection::Malformed(_))));
        assert_eq!(
            repository.reads(),
            0,
            "a malformed path should not hit the store"
        );
    }

    #[tokio::test]
    async fn a_request_with_no_host_at_all_is_refused() {
        let state = state(FakeRepository::with(vec![tenant(
            "demo",
            "https://as.example/t/demo",
            None,
        )]));
        assert_eq!(
            resolve(&state, "/t/demo/authorize", None).await.err(),
            Some(Rejection::NoSuchTenant)
        );
    }

    // ---- caching ---------------------------------------------------------

    #[tokio::test]
    async fn repeated_lookups_are_served_from_one_snapshot() {
        let repository =
            FakeRepository::with(vec![tenant("demo", "https://as.example/t/demo", None)]);
        let directory = TenantDirectory::new(Arc::clone(&repository) as Arc<dyn TenantRepository>);
        let id = TenantId::parse("demo").expect("id");

        for _ in 0..25 {
            assert!(directory.by_id(&id).await.expect("lookup").is_some());
        }
        assert_eq!(repository.reads(), 1, "the cache did not hold");
    }

    #[tokio::test]
    async fn invalidation_makes_the_next_lookup_see_the_change() {
        let repository =
            FakeRepository::with(vec![tenant("demo", "https://as.example/t/demo", None)]);
        let directory = TenantDirectory::new(Arc::clone(&repository) as Arc<dyn TenantRepository>);
        let id = TenantId::parse("demo").expect("id");
        let added = TenantId::parse("second").expect("id");

        assert!(directory.by_id(&id).await.expect("lookup").is_some());
        assert!(directory.by_id(&added).await.expect("lookup").is_none());

        repository.replace(vec![
            tenant("demo", "https://as.example/t/demo", None),
            tenant("second", "https://as.example/t/second", None),
        ]);
        // Still the old snapshot: that is the point of a cache.
        assert!(directory.by_id(&added).await.expect("lookup").is_none());

        directory.invalidate();
        assert!(directory.by_id(&added).await.expect("lookup").is_some());
        assert_eq!(repository.reads(), 2);
    }

    #[tokio::test]
    async fn a_vanity_host_is_matched_case_insensitively() {
        let repository = FakeRepository::with(vec![tenant(
            "acme",
            "https://login.acme.test",
            Some("Login.Acme.Test"),
        )]);
        let directory = TenantDirectory::new(repository as Arc<dyn TenantRepository>);
        assert!(
            directory
                .by_host("login.acme.test")
                .await
                .expect("lookup")
                .is_some()
        );
        assert!(
            directory
                .by_host("LOGIN.ACME.TEST")
                .await
                .expect("lookup")
                .is_some()
        );
    }

    // ---- path rewriting --------------------------------------------------

    #[test]
    fn rewriting_keeps_the_query_string() {
        let mut uri: Uri = "/t/demo/authorize?client_id=a&request_uri=b"
            .parse()
            .expect("uri");
        rewrite_path(&mut uri, "/authorize");
        assert_eq!(uri.path(), "/authorize");
        assert_eq!(uri.query(), Some("client_id=a&request_uri=b"));
    }

    #[test]
    fn rewriting_a_path_without_a_query_leaves_no_stray_question_mark() {
        let mut uri: Uri = "/t/demo/token".parse().expect("uri");
        rewrite_path(&mut uri, "/token");
        assert_eq!(uri.to_string(), "/token");
    }
}
