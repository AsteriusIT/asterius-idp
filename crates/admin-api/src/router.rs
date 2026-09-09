//! The axum router, mounted from the registry and from nothing else.
//!
//! # The router and the list of routes are one object
//!
//! [`AdminApi`] owns both the `Router` and the [`Operation`] slice it was built
//! from, and the only way to obtain one is [`AdminApi::new`], which walks
//! [`crate::registry`] and mounts each entry. So
//! [`AdminApi::operations`] *is* an enumeration of the router's routes rather
//! than a list written beside it — which is the property the table-driven
//! authorization test needs. A hand-maintained list would go stale the first
//! time somebody added a route and forgot the list, which is exactly how four
//! fuzz targets sat uncompiled in `ast-k2o`.
//!
//! # One gate, before every handler
//!
//! [`dispatch`] runs the same sequence for every operation, in order of cost:
//! rate limit, credential, CSRF, authority, idempotency. A handler is reached
//! only with a [`crate::auth::Principal`] that has already satisfied the
//! authority its own [`Operation`] declares, so there is no per-handler
//! authorization to forget.

use asterius_domain::{
    Actor, AuditEvent, Detail, EventType, Outcome, RefreshPolicy, Tenant, TenantId, TenantStatus,
};
use axum::Router;
use axum::extract::Request;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use std::net::IpAddr;
use std::sync::Arc;
use time::OffsetDateTime;

use crate::auth::{Credentials, Principal, authenticate};
use crate::backend::{AdminBackend, AdminTokens};
use crate::error::AdminError;
use crate::idempotency::{self, IdempotencyKey};
use crate::operations::{Effect, Method, Operation};
use crate::pagination::{Page, PageRequest};
use crate::{csrf, openapi, throttle};

/// The client address, as this crate sees it.
///
/// A type of this crate's own rather than `asterius_server`'s `ClientAddr`,
/// because `scripts/check-layering.sh` will not let the admin API depend on
/// the server crate and because the direction of the dependency is the other
/// way round. The composition root copies one into the other; the *resolution*
/// — socket peer plus trusted proxy set, never a header at face value — stays
/// where it was.
#[derive(Debug, Clone, Copy)]
pub struct ClientAddress(pub Option<IpAddr>);

/// Everything the admin API needs, assembled once at startup.
#[derive(Clone)]
pub struct AdminState {
    /// Where the API reaches the deployment.
    pub backend: Arc<dyn AdminBackend>,
    /// How a DPoP-bound access token is resolved, when the deployment can mint
    /// one. `None` until `ast-a05.8` lands, which makes the automation mode
    /// answer 401 rather than accept something nothing verified.
    pub tokens: Option<Arc<dyn AdminTokens>>,
    /// Requests one address may make per window.
    pub rate_limit: asterius_domain::RateLimit,
}

impl std::fmt::Debug for AdminState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminState")
            .field("tokens", &self.tokens.is_some())
            .field("rate_limit", &self.rate_limit)
            .finish_non_exhaustive()
    }
}

/// The mounted admin API, and the routes it mounted.
pub struct AdminApi {
    router: Router,
    operations: &'static [Operation],
}

impl std::fmt::Debug for AdminApi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminApi")
            .field("operations", &self.operations.len())
            .finish_non_exhaustive()
    }
}

impl AdminApi {
    /// Mounts every declared operation.
    ///
    /// The `match` on the verb is where the structural refusal of `GET` lands
    /// in the router: an [`Operation`] can only carry `Method::Get` if it was
    /// built by [`Operation::read`], because [`crate::operations::Mutating`]
    /// has no `Get` variant to pass to the other constructor.
    #[must_use]
    pub fn new(state: &AdminState) -> Self {
        let operations = crate::registry();
        let mut router = Router::new();

        for operation in operations {
            let operation = *operation;
            let state = state.clone();
            let handler = move |request: Request| dispatch(operation, state, request);
            let method_router = match operation.method() {
                Method::Get => axum::routing::get(handler),
                Method::Post => axum::routing::post(handler),
                Method::Put => axum::routing::put(handler),
                Method::Patch => axum::routing::patch(handler),
                Method::Delete => axum::routing::delete(handler),
            };
            router = router.route(operation.path(), method_router);
        }

        Self {
            router: Router::new().nest(crate::BASE_PATH, router),
            operations,
        }
    }

    /// The routes this router serves.
    ///
    /// Not a list kept beside the router: the same slice the router was built
    /// from, so a route that exists is a route this returns.
    #[must_use]
    pub const fn operations(&self) -> &'static [Operation] {
        self.operations
    }

    /// The router, for merging into the deployment's.
    pub fn into_router(self) -> Router {
        self.router
    }
}

/// The gate every request passes through, and then the handler.
async fn dispatch(operation: Operation, state: AdminState, request: Request) -> Response {
    match handle(operation, &state, request).await {
        Ok(response) => response,
        Err(refusal) => refusal.into_response(),
    }
}

async fn handle(
    operation: Operation,
    state: &AdminState,
    request: Request,
) -> Result<Response, AdminError> {
    let (parts, body) = request.into_parts();
    let headers = parts.headers.clone();

    let tenant = parts
        .extensions
        .get::<Arc<Tenant>>()
        .cloned()
        // Unreachable in the assembled application: the tenancy middleware
        // resolves a tenant before routing, so a handler cannot run without
        // one. Refused rather than unwrapped, because "cannot happen" is a
        // claim about code somebody else may change.
        .ok_or(AdminError::Unavailable)?;
    let address = parts
        .extensions
        .get::<ClientAddress>()
        .copied()
        .unwrap_or(ClientAddress(None));

    let now = OffsetDateTime::now_utc();
    let backend = state.backend.as_ref();

    // 1. The limit, before anything reads the database on an anonymous
    //    caller's behalf.
    throttle::admit(
        backend.rate_limits().as_ref(),
        state.rate_limit,
        &tenant.id,
        address.0,
        now,
    )
    .await?;

    // 2. Who is this?
    let origin = origin_of(&tenant);
    let url = format!("{origin}{}", parts.uri.path());
    let principal = authenticate(
        backend,
        state.tokens.as_deref(),
        &tenant,
        &headers,
        Credentials {
            cookies: &cookies(&headers),
            method: parts.method.as_str(),
            url: &url,
        },
    )
    .await?;

    // 3. CSRF, for the console and for state changes only. A read cannot be
    //    the target of a forgery worth mounting, and a token call carries no
    //    ambient credential to forge with.
    if operation.effect() == Effect::Mutates
        && let Principal::Console { session_id, .. } = &principal
    {
        csrf::check(&headers, session_id, &origin)?;
    }

    // 4. The authority the operation declares, against the tenant the request
    //    was routed to.
    if !principal
        .held()
        .satisfies(operation.authority(), &tenant.id)
    {
        return Err(AdminError::Forbidden);
    }

    // 5. At most once per key, for creations.
    if operation.needs_idempotency_key() {
        let key = headers
            .get(idempotency::HEADER)
            .and_then(|value| value.to_str().ok())
            .ok_or(AdminError::IdempotencyKeyMissing)?;
        let key = IdempotencyKey::parse(key)?;
        idempotency::claim(
            backend.replay().as_ref(),
            &tenant.id,
            &principal.audit_actor(),
            &key,
            now,
        )
        .await?;
    }

    let context = Handling {
        state,
        tenant: &tenant,
        principal: &principal,
        headers: &headers,
        query: parts.uri.query().unwrap_or_default().to_owned(),
        path: parts.uri.path().to_owned(),
        now,
    };

    // The dispatch table. A `match` on the operation id rather than a closure
    // per route, so that a registry entry with no handler is a non-exhaustive
    // match the compiler refuses.
    match operation.id() {
        crate::SESSION_READ_ID => context.session_document(),
        crate::OPENAPI_READ_ID => Ok(openapi_response()),
        crate::TENANTS_LIST_ID => context.list_tenants().await,
        crate::TENANT_READ_ID => context.read_tenant().await,
        crate::TENANT_CREATE_ID => context.create_tenant(body).await,
        // Unreachable while `every_registered_operation_has_a_handler` passes,
        // which is why that test exists rather than a comment here.
        other => {
            tracing::error!(
                operation = other,
                "an admin route is mounted with no handler"
            );
            Err(AdminError::Unavailable)
        }
    }
}

/// Everything a handler is given, once the gate has passed it.
struct Handling<'a> {
    state: &'a AdminState,
    tenant: &'a Tenant,
    principal: &'a Principal,
    headers: &'a HeaderMap,
    query: String,
    path: String,
    now: OffsetDateTime,
}

impl Handling<'_> {
    /// `GET /session` — who the console is, and the token it must send back.
    ///
    /// This is where a console obtains its synchroniser token. It is a `GET`,
    /// so a cross-site page could cause the request — and would not be able to
    /// *read* the response, because there is no CORS layer anywhere in this
    /// server (`no_cors_layer_is_used_anywhere` asserts it), so the browser
    /// refuses the reader the body.
    fn session_document(&self) -> Result<Response, AdminError> {
        let Principal::Console {
            tenant,
            user,
            session_id,
            held,
        } = self.principal
        else {
            // An automation caller has no session and therefore no CSRF token
            // to be given. Refused rather than answered with a null: a token
            // client asking for one has misunderstood the mode it is in.
            return Err(AdminError::Forbidden);
        };

        let roles = match held {
            crate::rbac::Held::Roles { roles, .. } => {
                roles.iter().map(|role| role.as_str()).collect::<Vec<_>>()
            }
            crate::rbac::Held::Scopes { .. } => Vec::new(),
        };

        Ok(json_no_store(
            StatusCode::OK,
            &serde_json::json!({
                "tenant": tenant.as_str(),
                "user": user.as_uuid().to_string(),
                "roles": roles,
                "csrf_token": csrf::token(session_id),
            }),
        ))
    }

    /// `GET /tenants` — the deployment's tenants, one cursor page at a time.
    async fn list_tenants(&self) -> Result<Response, AdminError> {
        let request = PageRequest::parse(
            query_value(&self.query, "cursor").as_deref(),
            query_value(&self.query, "limit").as_deref(),
        )?;

        let tenants = self
            .state
            .backend
            .tenants()
            .list()
            .await
            .map_err(|error| AdminError::from_storage("tenants.list", &error))?;

        // `TenantRepository::list` is ordered by id and returns every row:
        // tenants number in the tens (see `crate::tenancy`'s snapshot), so the
        // page is cut here rather than in SQL. That is a deliberate and stated
        // limit — if a deployment ever holds thousands, the port grows a
        // ranged `list_after`, and the cursor's opacity is what lets that
        // happen without breaking a console.
        let rows: Vec<serde_json::Value> = tenants
            .iter()
            .skip_while(|tenant| {
                request
                    .after
                    .as_ref()
                    .is_some_and(|cursor| tenant.id.as_str() <= cursor.key())
            })
            .take(request.limit + 1)
            .map(summarise)
            .collect();

        let page = Page::from_overfetched(rows, request.limit, |row| {
            row["tenant_id"].as_str().unwrap_or_default().to_owned()
        });

        Ok(json_no_store(
            StatusCode::OK,
            &serde_json::to_value(&page).unwrap_or_else(|_| serde_json::json!({})),
        ))
    }

    /// `GET /tenants/{tenant_id}` — one tenant.
    ///
    /// The second authority check lives here and has to: the gate checked the
    /// caller against the tenant the request was *routed* to, and this
    /// operation names a different one in its path. Without this, a tenant
    /// admin of `acme` reaching their own console could read `other` — the
    /// cross-tenant read the whole model exists to prevent.
    async fn read_tenant(&self) -> Result<Response, AdminError> {
        let named = self
            .path
            .rsplit('/')
            .next()
            .filter(|segment| !segment.is_empty())
            .ok_or(AdminError::NotFound)?;
        let named = TenantId::parse(named).map_err(|_| AdminError::NotFound)?;

        if !self
            .principal
            .held()
            .satisfies(crate::TENANT_READ.authority(), &named)
        {
            return Err(AdminError::Forbidden);
        }

        let found = self
            .state
            .backend
            .tenants()
            .find_by_id(&named)
            .await
            .map_err(|error| AdminError::from_storage("tenants.get", &error))?
            .ok_or(AdminError::NotFound)?;

        Ok(json_no_store(StatusCode::OK, &summarise(&found)))
    }

    /// `POST /tenants` — creates a tenant, with its signing keys.
    ///
    /// Through `dyn TenantRepository`, which the composition root fills with
    /// `ProvisionedTenants`: writing a tenant and giving it keys are one step
    /// (`ast-qa3`). Reaching for the bare adapter here would create a tenant
    /// with no active key, which then refuses every client registration — a
    /// failure that surfaces days later at somebody else's endpoint.
    async fn create_tenant(&self, body: axum::body::Body) -> Result<Response, AdminError> {
        let bytes = axum::body::to_bytes(body, MAX_BODY_BYTES)
            .await
            .map_err(|_| AdminError::Invalid("the request body is too large".to_owned()))?;
        let requested: NewTenant = serde_json::from_slice(&bytes).map_err(|error| {
            AdminError::Invalid(format!("the request body is not valid: {error}"))
        })?;

        let id = TenantId::parse(&requested.tenant_id)
            .map_err(|error| AdminError::Invalid(format!("tenant_id: {error}")))?;
        let issuer = asterius_domain::Issuer::parse(&requested.issuer)
            .map_err(|error| AdminError::Invalid(format!("issuer: {error}")))?;

        if self
            .state
            .backend
            .tenants()
            .find_by_id(&id)
            .await
            .map_err(|error| AdminError::from_storage("tenants.create", &error))?
            .is_some()
        {
            return Err(AdminError::Conflict(format!("tenant {id} already exists")));
        }

        let tenant = Tenant {
            id: id.clone(),
            default_resource: requested
                .default_resource
                .unwrap_or_else(|| issuer.as_str().to_owned()),
            display_name: requested
                .display_name
                .unwrap_or_else(|| requested.tenant_id.clone()),
            issuer,
            custom_host: requested.custom_host,
            status: TenantStatus::Active,
            refresh: RefreshPolicy::default(),
            created_at: self.now,
            updated_at: self.now,
        };

        self.state
            .backend
            .tenants()
            .upsert(&tenant)
            .await
            .map_err(|error| AdminError::from_storage("tenants.create", &error))?;

        // The routing snapshot is up to thirty seconds stale otherwise, and an
        // operator who has just created a tenant will try it immediately.
        self.state.backend.tenant_directory_changed();

        // Recorded against the tenant the *administrator* is in, not the one
        // just created: that is where the trail of who did what to this
        // deployment lives, and a new tenant's empty trail is not where anyone
        // would look for the record of its creation.
        self.record(
            EventType::ADMIN_CHANGED,
            Detail::new()
                .label("operation", crate::TENANT_CREATE_ID)
                .text("tenant_created", tenant.id.as_str()),
        )
        .await;

        Ok(json_no_store(StatusCode::CREATED, &summarise(&tenant)))
    }

    /// Writes one record, naming the administrator behind it.
    ///
    /// ADR-0009: the string [`Actor::Admin`] carries is a *user* identifier.
    ///
    /// A failed write is logged and does not fail the operation, and that is a
    /// deliberate choice rather than an omission: the tenant already exists by
    /// the time this runs, so refusing the request would report a failure that
    /// did not happen and invite a retry that creates a second one. The record
    /// that matters for evidence is the one the database refuses to let
    /// anybody rewrite, and losing an append is loud in the logs.
    async fn record(&self, event_type: EventType, detail: Detail) {
        let event = AuditEvent::new(
            self.tenant.id.clone(),
            event_type,
            Outcome::Success,
            Actor::Admin(self.principal.audit_actor()),
            self.now,
        )
        .detail(detail);

        let request_id = self
            .headers
            .get("x-request-id")
            .and_then(|value| value.to_str().ok())
            .map(ToOwned::to_owned);
        let event = match request_id {
            Some(id) => event.request_id(id),
            None => event,
        };

        if let Err(error) = self.state.backend.audit().record(event).await {
            tracing::error!(%error, "an administrative change was not recorded in the audit trail");
        }
    }
}

/// The largest creation body accepted, before the shared body limit.
const MAX_BODY_BYTES: usize = 64 * 1024;

/// What `POST /tenants` takes.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct NewTenant {
    tenant_id: String,
    issuer: String,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    default_resource: Option<String>,
    #[serde(default)]
    custom_host: Option<String>,
}

/// A tenant as this API renders it.
///
/// Deliberately not `serde`-derived on [`Tenant`]: the entity is an internal
/// type whose fields change, and deriving would publish every future addition
/// to an admin console the moment it was added.
fn summarise(tenant: &Tenant) -> serde_json::Value {
    serde_json::json!({
        "tenant_id": tenant.id.as_str(),
        "issuer": tenant.issuer.as_str(),
        "display_name": tenant.display_name,
        "default_resource": tenant.default_resource,
        "custom_host": tenant.custom_host,
        "status": tenant.status.as_str(),
    })
}

/// The API's own origin, from the tenant's issuer.
///
/// From the issuer and never from a `Host` header: a caller who can choose the
/// host can choose the origin the CSRF check compares against, and the check
/// then passes for everybody.
fn origin_of(tenant: &Tenant) -> String {
    format!("https://{}", tenant.issuer.authority())
}

/// Every `Cookie` field, joined.
///
/// RFC 9113 §8.2.3 permits a user agent to split the list across several
/// fields and requires a server to join them before parsing; Chromium does
/// split it. Reading only the first field is `ast-bze`, where the session
/// cookie is silently missed whenever two `__Host-` cookies are in flight.
fn cookies(headers: &HeaderMap) -> String {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect::<Vec<_>>()
        .join("; ")
}

/// One query parameter, percent-decoding nothing this API's parameters need.
fn query_value(query: &str, name: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        (key == name).then(|| value.to_owned())
    })
}

fn json_no_store(status: StatusCode, body: &serde_json::Value) -> Response {
    let mut response = (status, axum::Json(body)).into_response();
    // An admin API answer describes a deployment's configuration and its
    // people. Nothing about it belongs in a shared cache, and `no-store` is
    // what `crates/web/src/document.rs` applies to documents for the same
    // reason.
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    response
}

fn openapi_response() -> Response {
    let mut response = (StatusCode::OK, openapi::document()).into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/json"),
    );
    headers.insert(
        header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    response
}

/// Marks the extension the composition root must insert, so that a deployment
/// which forgets is a deployment whose limiter counts nothing.
///
/// Used by `asterius-server`'s wiring test.
pub const CLIENT_ADDRESS_EXTENSION: &str = "asterius_admin_api::ClientAddress";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operations::Method as OperationMethod;
    use crate::rbac::Reach;
    use asterius_domain::entities::session::SessionId;
    use asterius_domain::ports::TenantRepository;
    use asterius_domain::{
        AuditSink, AuthenticationMethod, DomainError, Issuer, Lifetimes, RateLimit, RateLimitStore,
        ReplayCheck, ReplayGuard, ReplayPurpose, Role, Session, UserId,
    };
    use axum::body::Body;
    use axum::http::Request as HttpRequest;
    use std::collections::BTreeMap;
    use std::sync::Mutex;
    use tower::ServiceExt as _;

    const ORIGIN: &str = "https://as.example";

    // ---- the fake deployment ----------------------------------------------

    #[derive(Debug, Default)]
    struct Fake {
        tenants: Mutex<Vec<Tenant>>,
        sessions: Mutex<BTreeMap<String, Session>>,
        roles: Mutex<BTreeMap<String, Vec<Role>>>,
        events: Mutex<Vec<AuditEvent>>,
        counters: Mutex<BTreeMap<String, u32>>,
        claimed: Mutex<std::collections::BTreeSet<String>>,
        invalidations: Mutex<usize>,
    }

    #[derive(Debug, Clone)]
    struct Handle(Arc<Fake>);

    #[async_trait::async_trait]
    impl TenantRepository for Handle {
        async fn find_by_id(&self, id: &TenantId) -> Result<Option<Tenant>, DomainError> {
            Ok(self
                .0
                .tenants
                .lock()
                .expect("an uncontended lock")
                .iter()
                .find(|tenant| &tenant.id == id)
                .cloned())
        }

        async fn find_by_issuer(&self, _issuer: &Issuer) -> Result<Option<Tenant>, DomainError> {
            Ok(None)
        }

        async fn find_by_host(&self, _host: &str) -> Result<Option<Tenant>, DomainError> {
            Ok(None)
        }

        async fn list(&self) -> Result<Vec<Tenant>, DomainError> {
            let mut tenants = self.0.tenants.lock().expect("an uncontended lock").clone();
            tenants.sort_by(|a, b| a.id.as_str().cmp(b.id.as_str()));
            Ok(tenants)
        }

        async fn upsert(&self, tenant: &Tenant) -> Result<(), DomainError> {
            let mut tenants = self.0.tenants.lock().expect("an uncontended lock");
            tenants.retain(|held| held.id != tenant.id);
            tenants.push(tenant.clone());
            Ok(())
        }

        async fn delete(&self, _id: &TenantId) -> Result<(), DomainError> {
            Ok(())
        }
    }

    #[async_trait::async_trait]
    impl AuditSink for Handle {
        async fn record(&self, event: AuditEvent) -> Result<(), DomainError> {
            self.0
                .events
                .lock()
                .expect("an uncontended lock")
                .push(event);
            Ok(())
        }
    }

    #[async_trait::async_trait]
    impl RateLimitStore for Handle {
        async fn count(
            &self,
            _tenant: &TenantId,
            bucket: &asterius_domain::Bucket,
            _window_start: OffsetDateTime,
        ) -> Result<u32, DomainError> {
            Ok(*self
                .0
                .counters
                .lock()
                .expect("an uncontended lock")
                .get(bucket.as_str())
                .unwrap_or(&0))
        }

        async fn record(
            &self,
            _tenant: &TenantId,
            bucket: &asterius_domain::Bucket,
            _window_start: OffsetDateTime,
            _expires_at: OffsetDateTime,
        ) -> Result<u32, DomainError> {
            let mut counters = self.0.counters.lock().expect("an uncontended lock");
            let counted = counters.entry(bucket.as_str().to_owned()).or_insert(0);
            *counted += 1;
            Ok(*counted)
        }
    }

    #[async_trait::async_trait]
    impl ReplayGuard for Handle {
        async fn claim(
            &self,
            _tenant: &TenantId,
            purpose: ReplayPurpose,
            subject: &str,
            jti: &str,
            _expires_at: OffsetDateTime,
        ) -> Result<ReplayCheck, DomainError> {
            let mut claimed = self.0.claimed.lock().expect("an uncontended lock");
            Ok(
                if claimed.insert(format!("{}|{subject}|{jti}", purpose.as_str())) {
                    ReplayCheck::FirstUse
                } else {
                    ReplayCheck::Replay
                },
            )
        }
    }

    #[async_trait::async_trait]
    impl AdminBackend for Handle {
        async fn session(
            &self,
            tenant: &TenantId,
            id_digest: &str,
        ) -> Result<Option<Session>, DomainError> {
            Ok(self
                .0
                .sessions
                .lock()
                .expect("an uncontended lock")
                .get(id_digest)
                .filter(|session| &session.tenant == tenant)
                .cloned())
        }

        async fn roles(&self, tenant: &TenantId, user: UserId) -> Result<Vec<Role>, DomainError> {
            Ok(self
                .0
                .roles
                .lock()
                .expect("an uncontended lock")
                .get(&format!("{tenant}|{}", user.as_uuid()))
                .cloned()
                .unwrap_or_default())
        }

        fn tenants(&self) -> Arc<dyn TenantRepository> {
            Arc::new(self.clone())
        }

        fn audit(&self) -> Arc<dyn AuditSink> {
            Arc::new(self.clone())
        }

        fn rate_limits(&self) -> Arc<dyn RateLimitStore> {
            Arc::new(self.clone())
        }

        fn replay(&self) -> Arc<dyn ReplayGuard> {
            Arc::new(self.clone())
        }

        fn tenant_directory_changed(&self) {
            *self.0.invalidations.lock().expect("an uncontended lock") += 1;
        }
    }

    // ---- fixtures ----------------------------------------------------------

    fn tenant_named(id: &str) -> Tenant {
        Tenant {
            id: TenantId::parse(id).expect("a valid tenant id"),
            issuer: Issuer::parse(&format!("{ORIGIN}/t/{id}")).expect("a valid issuer"),
            default_resource: format!("{ORIGIN}/t/{id}"),
            custom_host: None,
            display_name: id.to_owned(),
            status: TenantStatus::Active,
            refresh: RefreshPolicy::default(),
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    /// A deployment holding two tenants, with a signed-in user in each whose
    /// roles the caller chooses.
    struct World {
        handle: Handle,
        api_tenant: Arc<Tenant>,
    }

    impl World {
        fn new() -> Self {
            let handle = Handle(Arc::new(Fake::default()));
            for id in ["acme", "asterius-admin", "other"] {
                handle
                    .0
                    .tenants
                    .lock()
                    .expect("an uncontended lock")
                    .push(tenant_named(id));
            }
            Self {
                api_tenant: Arc::new(tenant_named("acme")),
                handle,
            }
        }

        /// Routes subsequent requests to `id` instead of `acme`.
        fn routed_at(mut self, id: &str) -> Self {
            self.api_tenant = Arc::new(tenant_named(id));
            self
        }

        /// Mints a usable session in `tenant` for a user holding `roles`, and
        /// returns the cookie value.
        fn sign_in(&self, tenant: &str, roles: &[Role]) -> String {
            let id = SessionId::generate();
            let tenant = TenantId::parse(tenant).expect("a valid tenant id");
            let user = UserId::generate();
            let session = Session::begin(
                tenant.clone(),
                &id,
                *user.as_uuid(),
                vec![AuthenticationMethod::Passkey],
                OffsetDateTime::now_utc(),
                Lifetimes::default(),
            );
            self.handle
                .0
                .sessions
                .lock()
                .expect("an uncontended lock")
                .insert(id.digest(), session);
            self.handle
                .0
                .roles
                .lock()
                .expect("an uncontended lock")
                .insert(format!("{tenant}|{}", user.as_uuid()), roles.to_vec());
            id.expose().to_owned()
        }

        fn api(&self) -> AdminApi {
            AdminApi::new(&AdminState {
                backend: Arc::new(self.handle.clone()),
                tokens: None,
                rate_limit: RateLimit {
                    max: 10_000,
                    window: time::Duration::minutes(1),
                },
            })
        }

        async fn send(&self, request: HttpRequest<Body>) -> Response {
            let mut request = request;
            request
                .extensions_mut()
                .insert(Arc::clone(&self.api_tenant));
            request.extensions_mut().insert(ClientAddress(Some(
                "198.51.100.7".parse().expect("literal"),
            )));
            self.api()
                .into_router()
                .oneshot(request)
                .await
                .expect("the router answers")
        }
    }

    /// A request for `operation`, with whatever credentials the caller adds.
    fn request_for(operation: &Operation) -> axum::http::request::Builder {
        // A concrete value for every `{placeholder}`, so that the table-driven
        // test exercises the route rather than the 404 of an unmatched path.
        let path = operation.full_path().replace("{tenant_id}", "acme");
        HttpRequest::builder()
            .method(operation.method().as_str())
            .uri(path)
            .header("origin", ORIGIN)
    }

    fn body_for(operation: &Operation) -> Body {
        if operation.method() == OperationMethod::Post {
            Body::from(
                serde_json::json!({
                    "tenant_id": "brand-new",
                    "issuer": format!("{ORIGIN}/t/brand-new"),
                })
                .to_string(),
            )
        } else {
            Body::empty()
        }
    }

    async fn body_of(response: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .expect("a readable body");
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    }

    // ---- the table-driven authorization test ------------------------------

    /// **The piece this bead turns on.**
    ///
    /// The routes come from [`AdminApi::operations`] — the same slice the
    /// router was built from — so a route added without a declared authority
    /// cannot be added at all, and a route added *with* one is checked here
    /// the moment it exists. A hand-written list would have to be remembered,
    /// and `ast-k2o` is what happens when one is not.
    #[tokio::test]
    async fn every_route_refuses_a_request_carrying_no_credential() {
        // Arrange
        let world = World::new();
        let operations = world.api().operations();
        assert!(!operations.is_empty(), "the registry is empty");

        for operation in operations {
            // Act
            let response = world
                .send(
                    request_for(operation)
                        .body(body_for(operation))
                        .expect("a request"),
                )
                .await;

            // Assert
            assert_eq!(
                response.status(),
                StatusCode::UNAUTHORIZED,
                "{} answered a credential-less request with something other than 401",
                operation.id()
            );
        }
    }

    /// The other half: authenticated, and without the authority the route
    /// declares. A signed-in user holding no role at all is the weakest
    /// credential there is, and every route must refuse it with 403 — never
    /// 200, and never 401, which would tell them to sign in again forever.
    #[tokio::test]
    async fn every_route_refuses_an_authenticated_caller_holding_no_role() {
        // Arrange
        let world = World::new();
        let cookie = world.sign_in("acme", &[]);
        let operations = world.api().operations();

        for operation in operations {
            // Act
            let response = world
                .send(
                    request_for(operation)
                        .header(
                            "cookie",
                            format!(
                                "{}={cookie}",
                                asterius_domain::entities::session::COOKIE_NAME
                            ),
                        )
                        .header(csrf::HEADER, csrf::token(&cookie))
                        .header(idempotency::HEADER, "a-first-use-key")
                        .body(body_for(operation))
                        .expect("a request"),
                )
                .await;

            // Assert
            assert_eq!(
                response.status(),
                StatusCode::FORBIDDEN,
                "{} admitted a caller holding no role",
                operation.id()
            );
        }
    }

    /// A tenant admin holds tenant-scoped authority and nothing more: every
    /// deployment-scoped route must refuse them, and no tenant-scoped one may.
    #[tokio::test]
    async fn a_tenant_admin_is_refused_exactly_the_deployment_scoped_routes() {
        // Arrange
        let world = World::new();
        let cookie = world.sign_in("acme", &[Role::TenantAdmin]);

        for operation in world.api().operations() {
            // Act
            let response = world
                .send(
                    request_for(operation)
                        .header(
                            "cookie",
                            format!(
                                "{}={cookie}",
                                asterius_domain::entities::session::COOKIE_NAME
                            ),
                        )
                        .header(csrf::HEADER, csrf::token(&cookie))
                        .header(idempotency::HEADER, "another-first-use-key")
                        .body(body_for(operation))
                        .expect("a request"),
                )
                .await;

            // Assert
            let refused = response.status() == StatusCode::FORBIDDEN;
            assert_eq!(
                refused,
                operation.authority().reach() == Reach::Deployment,
                "{} answered {} for a tenant admin",
                operation.id(),
                response.status()
            );
        }
    }

    /// Every mounted route has a handler. Without this the `match` in
    /// [`handle`] would answer 503 for a route somebody registered and forgot
    /// to wire, which looks like an outage rather than a mistake.
    #[tokio::test]
    async fn every_registered_operation_has_a_handler() {
        // Arrange
        let world = World::new().routed_at("asterius-admin");
        let cookie = world.sign_in("asterius-admin", &[Role::DeploymentAdmin]);

        for operation in world.api().operations() {
            // Act
            let response = world
                .send(
                    request_for(operation)
                        .header(
                            "cookie",
                            format!(
                                "{}={cookie}",
                                asterius_domain::entities::session::COOKIE_NAME
                            ),
                        )
                        .header(csrf::HEADER, csrf::token(&cookie))
                        .header(idempotency::HEADER, format!("key-for-{}", operation.id()))
                        .body(body_for(operation))
                        .expect("a request"),
                )
                .await;

            // Assert
            assert_ne!(
                response.status(),
                StatusCode::SERVICE_UNAVAILABLE,
                "{} is mounted with no handler",
                operation.id()
            );
            assert!(
                response.status().is_success(),
                "{} answered {} for a deployment admin",
                operation.id(),
                response.status()
            );
        }
    }

    // ---- CSRF --------------------------------------------------------------

    #[tokio::test]
    async fn a_mutation_without_the_csrf_token_is_refused() {
        // Arrange
        let world = World::new().routed_at("asterius-admin");
        let cookie = world.sign_in("asterius-admin", &[Role::DeploymentAdmin]);

        // Act
        let response = world
            .send(
                request_for(&crate::TENANT_CREATE)
                    .header(
                        "cookie",
                        format!(
                            "{}={cookie}",
                            asterius_domain::entities::session::COOKIE_NAME
                        ),
                    )
                    .header(idempotency::HEADER, "a-key-that-is-long-enough")
                    .body(body_for(&crate::TENANT_CREATE))
                    .expect("a request"),
            )
            .await;

        // Assert
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(body_of(response).await["error"]["code"], "csrf_failed");
    }

    #[tokio::test]
    async fn a_mutation_from_another_origin_is_refused() {
        // Arrange
        let world = World::new().routed_at("asterius-admin");
        let cookie = world.sign_in("asterius-admin", &[Role::DeploymentAdmin]);

        // Act
        let response = world
            .send(
                HttpRequest::builder()
                    .method("POST")
                    .uri(crate::TENANT_CREATE.full_path())
                    .header("origin", "https://evil.example")
                    .header(
                        "cookie",
                        format!(
                            "{}={cookie}",
                            asterius_domain::entities::session::COOKIE_NAME
                        ),
                    )
                    .header(csrf::HEADER, csrf::token(&cookie))
                    .header(idempotency::HEADER, "a-key-that-is-long-enough")
                    .body(body_for(&crate::TENANT_CREATE))
                    .expect("a request"),
            )
            .await;

        // Assert
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    /// A read is not subject to the check: the console has to be able to fetch
    /// its own token, and a `GET` is not a state change worth forging.
    #[tokio::test]
    async fn a_read_needs_no_csrf_token() {
        // Arrange
        let world = World::new();
        let cookie = world.sign_in("acme", &[Role::TenantAdmin]);

        // Act
        let response = world
            .send(
                request_for(&crate::SESSION_READ)
                    .header(
                        "cookie",
                        format!(
                            "{}={cookie}",
                            asterius_domain::entities::session::COOKIE_NAME
                        ),
                    )
                    .body(Body::empty())
                    .expect("a request"),
            )
            .await;

        // Assert
        assert_eq!(response.status(), StatusCode::OK);
    }

    /// The console's whole CSRF story: the token it must send back is the one
    /// this route hands it, and it is the one the mutation accepts.
    #[tokio::test]
    async fn the_session_route_hands_back_the_token_the_mutation_accepts() {
        // Arrange
        let world = World::new();
        let cookie = world.sign_in("acme", &[Role::TenantAdmin]);

        // Act
        let response = world
            .send(
                request_for(&crate::SESSION_READ)
                    .header(
                        "cookie",
                        format!(
                            "{}={cookie}",
                            asterius_domain::entities::session::COOKIE_NAME
                        ),
                    )
                    .body(Body::empty())
                    .expect("a request"),
            )
            .await;

        // Assert
        let document = body_of(response).await;
        assert_eq!(
            document["csrf_token"],
            serde_json::Value::String(csrf::token(&cookie))
        );
        assert_eq!(document["roles"], serde_json::json!(["tenant_admin"]));
    }

    // ---- cross-tenant ------------------------------------------------------

    /// The check the multi-tenant model rests on, at the route that names a
    /// tenant in its path rather than in its routing.
    #[tokio::test]
    async fn a_tenant_admin_cannot_read_another_tenant_by_naming_it_in_the_path() {
        // Arrange
        let world = World::new();
        let cookie = world.sign_in("acme", &[Role::TenantAdmin]);

        // Act
        let response = world
            .send(
                HttpRequest::builder()
                    .method("GET")
                    .uri(
                        crate::TENANT_READ
                            .full_path()
                            .replace("{tenant_id}", "other"),
                    )
                    .header(
                        "cookie",
                        format!(
                            "{}={cookie}",
                            asterius_domain::entities::session::COOKIE_NAME
                        ),
                    )
                    .body(Body::empty())
                    .expect("a request"),
            )
            .await;

        // Assert
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn a_deployment_admin_reads_any_tenant() {
        // Arrange
        let world = World::new().routed_at("asterius-admin");
        let cookie = world.sign_in("asterius-admin", &[Role::DeploymentAdmin]);

        // Act
        let response = world
            .send(
                HttpRequest::builder()
                    .method("GET")
                    .uri(
                        crate::TENANT_READ
                            .full_path()
                            .replace("{tenant_id}", "other"),
                    )
                    .header(
                        "cookie",
                        format!(
                            "{}={cookie}",
                            asterius_domain::entities::session::COOKIE_NAME
                        ),
                    )
                    .body(Body::empty())
                    .expect("a request"),
            )
            .await;

        // Assert
        assert_eq!(response.status(), StatusCode::OK);
    }

    // ---- idempotency, pagination, audit ------------------------------------

    #[tokio::test]
    async fn a_creation_without_an_idempotency_key_is_refused() {
        // Arrange
        let world = World::new().routed_at("asterius-admin");
        let cookie = world.sign_in("asterius-admin", &[Role::DeploymentAdmin]);

        // Act
        let response = world
            .send(
                request_for(&crate::TENANT_CREATE)
                    .header(
                        "cookie",
                        format!(
                            "{}={cookie}",
                            asterius_domain::entities::session::COOKIE_NAME
                        ),
                    )
                    .header(csrf::HEADER, csrf::token(&cookie))
                    .body(body_for(&crate::TENANT_CREATE))
                    .expect("a request"),
            )
            .await;

        // Assert
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(body_of(response).await["error"]["code"], "idempotency_key");
    }

    /// The property the key exists for: the retry does not create a second
    /// tenant.
    #[tokio::test]
    async fn a_repeated_creation_runs_once() {
        // Arrange
        let world = World::new().routed_at("asterius-admin");
        let cookie = world.sign_in("asterius-admin", &[Role::DeploymentAdmin]);
        let send = async || {
            world
                .send(
                    request_for(&crate::TENANT_CREATE)
                        .header(
                            "cookie",
                            format!(
                                "{}={cookie}",
                                asterius_domain::entities::session::COOKIE_NAME
                            ),
                        )
                        .header(csrf::HEADER, csrf::token(&cookie))
                        .header(idempotency::HEADER, "the-same-key-twice")
                        .body(body_for(&crate::TENANT_CREATE))
                        .expect("a request"),
                )
                .await
        };

        // Act
        let first = send().await.status();
        let second = send().await.status();

        // Assert
        assert_eq!(first, StatusCode::CREATED);
        assert_eq!(second, StatusCode::CONFLICT);
        let created = world
            .handle
            .0
            .tenants
            .lock()
            .expect("an uncontended lock")
            .iter()
            .filter(|tenant| tenant.id.as_str() == "brand-new")
            .count();
        assert_eq!(created, 1);
    }

    /// ADR-0009 and ADR-0010: the actor is a user identifier, and it is
    /// recorded for every mutation.
    #[tokio::test]
    async fn a_creation_is_audited_with_the_administrator_behind_it() {
        // Arrange
        let world = World::new().routed_at("asterius-admin");
        let cookie = world.sign_in("asterius-admin", &[Role::DeploymentAdmin]);

        // Act
        world
            .send(
                request_for(&crate::TENANT_CREATE)
                    .header(
                        "cookie",
                        format!(
                            "{}={cookie}",
                            asterius_domain::entities::session::COOKIE_NAME
                        ),
                    )
                    .header(csrf::HEADER, csrf::token(&cookie))
                    .header(idempotency::HEADER, "an-audited-creation")
                    .body(body_for(&crate::TENANT_CREATE))
                    .expect("a request"),
            )
            .await;

        // Assert
        let events = world.handle.0.events.lock().expect("an uncontended lock");
        let recorded = events.first().expect("one record");
        assert_eq!(recorded.event_type, EventType::ADMIN_CHANGED);
        let Actor::Admin(who) = &recorded.actor else {
            panic!("the actor is not an administrator: {:?}", recorded.actor);
        };
        assert!(
            uuid::Uuid::parse_str(who).is_ok(),
            "the actor is not a user identifier: {who}"
        );
    }

    /// The routing snapshot is up to thirty seconds stale otherwise, and an
    /// operator who has just created a tenant will try it immediately.
    #[tokio::test]
    async fn a_creation_invalidates_the_tenant_directory() {
        // Arrange
        let world = World::new().routed_at("asterius-admin");
        let cookie = world.sign_in("asterius-admin", &[Role::DeploymentAdmin]);

        // Act
        world
            .send(
                request_for(&crate::TENANT_CREATE)
                    .header(
                        "cookie",
                        format!(
                            "{}={cookie}",
                            asterius_domain::entities::session::COOKIE_NAME
                        ),
                    )
                    .header(csrf::HEADER, csrf::token(&cookie))
                    .header(idempotency::HEADER, "an-invalidating-creation")
                    .body(body_for(&crate::TENANT_CREATE))
                    .expect("a request"),
            )
            .await;

        // Assert
        assert_eq!(
            *world
                .handle
                .0
                .invalidations
                .lock()
                .expect("an uncontended lock"),
            1
        );
    }

    #[tokio::test]
    async fn a_listing_pages_with_a_cursor() {
        // Arrange
        let world = World::new().routed_at("asterius-admin");
        let cookie = world.sign_in("asterius-admin", &[Role::DeploymentAdmin]);
        let cookie_header = format!(
            "{}={cookie}",
            asterius_domain::entities::session::COOKIE_NAME
        );

        // Act
        let first = world
            .send(
                HttpRequest::builder()
                    .method("GET")
                    .uri(format!("{}?limit=1", crate::TENANTS_LIST.full_path()))
                    .header("cookie", &cookie_header)
                    .body(Body::empty())
                    .expect("a request"),
            )
            .await;
        let first = body_of(first).await;
        let cursor = first["next_cursor"].as_str().expect("a cursor").to_owned();
        let second = world
            .send(
                HttpRequest::builder()
                    .method("GET")
                    .uri(format!(
                        "{}?limit=1&cursor={cursor}",
                        crate::TENANTS_LIST.full_path()
                    ))
                    .header("cookie", &cookie_header)
                    .body(Body::empty())
                    .expect("a request"),
            )
            .await;

        // Assert
        let second = body_of(second).await;
        assert_eq!(first["items"][0]["tenant_id"], "acme");
        assert_eq!(second["items"][0]["tenant_id"], "asterius-admin");
    }

    #[tokio::test]
    async fn a_cursor_this_server_did_not_issue_is_a_400_rather_than_an_empty_page() {
        // Arrange
        let world = World::new().routed_at("asterius-admin");
        let cookie = world.sign_in("asterius-admin", &[Role::DeploymentAdmin]);

        // Act
        let response = world
            .send(
                HttpRequest::builder()
                    .method("GET")
                    .uri(format!(
                        "{}?cursor=not-a-cursor",
                        crate::TENANTS_LIST.full_path()
                    ))
                    .header(
                        "cookie",
                        format!(
                            "{}={cookie}",
                            asterius_domain::entities::session::COOKIE_NAME
                        ),
                    )
                    .body(Body::empty())
                    .expect("a request"),
            )
            .await;

        // Assert
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(body_of(response).await["error"]["code"], "invalid_cursor");
    }

    // ---- the document ------------------------------------------------------

    /// The contract test runs against the document the server serves, not
    /// against a copy of it.
    #[tokio::test]
    async fn the_served_document_is_the_generated_one() {
        // Arrange
        let world = World::new();
        let cookie = world.sign_in("acme", &[Role::TenantAdmin]);

        // Act
        let response = world
            .send(
                request_for(&crate::OPENAPI_READ)
                    .header(
                        "cookie",
                        format!(
                            "{}={cookie}",
                            asterius_domain::entities::session::COOKIE_NAME
                        ),
                    )
                    .body(Body::empty())
                    .expect("a request"),
            )
            .await;

        // Assert
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .expect("a readable body");
        assert_eq!(String::from_utf8_lossy(&bytes), openapi::document());
    }

    /// ADR-0009's reason for existing: the surface's own description is not
    /// readable by an anonymous caller.
    #[tokio::test]
    async fn the_document_is_not_served_to_an_anonymous_caller() {
        // Arrange
        let world = World::new();

        // Act
        let response = world
            .send(
                request_for(&crate::OPENAPI_READ)
                    .body(Body::empty())
                    .expect("a request"),
            )
            .await;

        // Assert
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    // ---- the sessions the API refuses --------------------------------------

    #[tokio::test]
    async fn a_session_from_another_tenant_does_not_resolve() {
        // Arrange
        let world = World::new();
        let cookie = world.sign_in("other", &[Role::TenantAdmin]);

        // Act
        let response = world
            .send(
                request_for(&crate::SESSION_READ)
                    .header(
                        "cookie",
                        format!(
                            "{}={cookie}",
                            asterius_domain::entities::session::COOKIE_NAME
                        ),
                    )
                    .body(Body::empty())
                    .expect("a request"),
            )
            .await;

        // Assert
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// The automation mode is implemented and not yet buildable: refusing is
    /// the honest answer until `ast-a05.8` can mint a token to resolve.
    #[tokio::test]
    async fn a_token_call_is_refused_while_no_verifier_is_wired() {
        // Arrange
        let world = World::new();

        // Act
        let response = world
            .send(
                request_for(&crate::SESSION_READ)
                    .header("authorization", "DPoP an-access-token")
                    .header("dpop", "a.b.c")
                    .body(Body::empty())
                    .expect("a request"),
            )
            .await;

        // Assert
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response
                .headers()
                .get("www-authenticate")
                .and_then(|value| value.to_str().ok()),
            Some(r#"DPoP error="invalid_token""#)
        );
    }

    // ---- rate limiting -----------------------------------------------------

    #[tokio::test]
    async fn a_flood_from_one_address_is_throttled() {
        // Arrange
        let world = World::new();
        let api = AdminApi::new(&AdminState {
            backend: Arc::new(world.handle.clone()),
            tokens: None,
            rate_limit: RateLimit {
                max: 1,
                window: time::Duration::minutes(1),
            },
        });
        let send = async || {
            let mut request = request_for(&crate::SESSION_READ)
                .body(Body::empty())
                .expect("a request");
            request
                .extensions_mut()
                .insert(Arc::clone(&world.api_tenant));
            request.extensions_mut().insert(ClientAddress(Some(
                "198.51.100.7".parse().expect("literal"),
            )));
            AdminApi::new(&AdminState {
                backend: Arc::new(world.handle.clone()),
                tokens: None,
                rate_limit: RateLimit {
                    max: 1,
                    window: time::Duration::minutes(1),
                },
            })
            .into_router()
            .oneshot(request)
            .await
            .expect("the router answers")
        };
        drop(api);

        // Act
        let first = send().await.status();
        let second = send().await.status();

        // Assert
        assert_eq!(first, StatusCode::UNAUTHORIZED);
        assert_eq!(second, StatusCode::TOO_MANY_REQUESTS);
    }

    // ---- the structural guarantee, at the router ---------------------------

    /// ADR-0009's structural refusal, asserted at the router by its effect
    /// rather than by a status code.
    ///
    /// A mutating operation's path may also carry a *read* — `/tenants` is
    /// both the listing and the creation — so a `GET` there is answered, and
    /// answered `200` by the listing. Asserting `405` would therefore assert
    /// nothing about the mutation. What must hold is the property the ADR
    /// actually asks for: **a `GET` never has a state-changing effect**, since
    /// `SameSite=Lax` leaves a top-level `GET` unprotected and no CSRF header
    /// travels on one.
    ///
    /// So the test sends a `GET` carrying everything the mutation would need —
    /// the same path, the same body, an administrator's cookie — and requires
    /// that nothing changed and that no audit record was written. The
    /// registry-level guarantee is [`crate::operations`]'s, and the type-level
    /// one is that `Mutating` has no `Get` variant at all.
    #[tokio::test]
    async fn a_get_never_has_the_effect_of_a_mutation() {
        // Arrange
        let world = World::new().routed_at("asterius-admin");
        let cookie = world.sign_in("asterius-admin", &[Role::DeploymentAdmin]);
        let operations = world.api().operations();
        let before = world.handle.0.tenants.lock().expect("a lock").len();
        let mut mutations = 0;

        for operation in operations {
            if operation.effect() != Effect::Mutates {
                continue;
            }
            mutations += 1;

            // Act
            world
                .send(
                    HttpRequest::builder()
                        .method("GET")
                        .uri(operation.full_path().replace("{tenant_id}", "acme"))
                        .header(
                            "cookie",
                            format!(
                                "{}={cookie}",
                                asterius_domain::entities::session::COOKIE_NAME
                            ),
                        )
                        .header(csrf::HEADER, csrf::token(&cookie))
                        .header(idempotency::HEADER, "a-key-that-is-long-enough")
                        .body(body_for(operation))
                        .expect("a request"),
                )
                .await;
        }

        // Assert
        assert!(mutations > 0, "the registry declares no mutation to check");
        assert_eq!(
            world.handle.0.tenants.lock().expect("a lock").len(),
            before,
            "a GET changed state"
        );
        assert!(
            world.handle.0.events.lock().expect("a lock").is_empty(),
            "a GET produced an administrative audit record"
        );
    }

    #[test]
    fn the_client_address_extension_is_named_for_the_composition_root() {
        assert!(CLIENT_ADDRESS_EXTENSION.ends_with("ClientAddress"));
    }

    #[test]
    fn one_query_parameter_is_read_without_disturbing_the_others() {
        assert_eq!(
            query_value("a=1&limit=25&z=9", "limit"),
            Some("25".to_owned())
        );
        assert_eq!(query_value("a=1", "limit"), None);
        assert_eq!(query_value("", "limit"), None);
    }

    /// From the issuer, never from a `Host` header a caller chose.
    #[test]
    fn the_origin_comes_from_the_issuer() {
        assert_eq!(origin_of(&tenant_named("acme")), ORIGIN);
    }
}
