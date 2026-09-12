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
//! `dispatch` runs the same sequence for every operation, in order of cost:
//! rate limit, credential, CSRF, authority, idempotency. A handler is reached
//! only with a [`crate::auth::Principal`] that has already satisfied the
//! authority its own [`Operation`] declares, so there is no per-handler
//! authorization to forget.

use asterius_domain::entities::session::{SessionId, SessionRevocation};
use asterius_domain::{
    Activation, Actor, AuditEvent, Client, ClientRegistration, ClientStatus, Detail, DomainError,
    EventType, Kid, NewInitialAccessToken, OpaqueToken, Outcome, RefreshPolicy, RoleOwner, Tenant,
    TenantId, TenantSettings, TenantStatus,
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
use crate::operations::{Method, Operation};
use crate::pagination::{Cursor, Page, PageRequest};
use crate::{
    audit, clients, csrf, initial_access_tokens, keys, openapi, outbox, policies, ssf, throttle,
    users,
};

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
    /// The reserved tenant a deployment admin's session lives in (ADR-0010),
    /// when the deployment configures one.
    ///
    /// Named here rather than discovered per request, because "which tenant may
    /// hold deployment authority" is a deployment's decision — the `[admin]`
    /// table — and looking it up by scanning tenants would make an
    /// unauthenticated caller's bad cookie cost a table read. `None` is a
    /// deployment with no admin account, where a session resolves in its own
    /// tenant and nowhere else.
    pub reserved_tenant: Option<TenantId>,
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
        state.reserved_tenant.as_ref(),
        &headers,
        Credentials {
            cookies: &cookies(&headers),
            method: parts.method.as_str(),
            url: &url,
        },
    )
    .await?;

    // 3. CSRF, for the console and for everything that is not a plain read. A
    //    `GET` cannot be the target of a forgery worth mounting, and a token
    //    call carries no ambient credential to forge with. A probe
    //    (`Effect::Probes`) writes nothing and is still checked: it is mounted
    //    on a verb a cross-site form can emit, and the header is what says the
    //    request came from this console.
    if operation.effect().needs_csrf_token()
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

    route(operation.id(), &context, body).await
}

/// The dispatch table. A `match` on the operation id rather than a closure per
/// route, so that a registry entry with no handler is a non-exhaustive match the
/// compiler refuses.
///
/// Its own function rather than the tail of [`handle`], because the gate above
/// is a sequence of five checks that has to be read in order and the table is a
/// list that grows by one line per route; keeping them in one body meant the
/// nineteenth route made the function too long to read.
async fn route(
    id: &str,
    context: &Handling<'_>,
    body: axum::body::Body,
) -> Result<Response, AdminError> {
    match id {
        crate::SESSION_READ_ID => context.session_document(),
        crate::SESSION_END_ID => context.end_session().await,
        crate::OPENAPI_READ_ID => Ok(openapi_response()),
        crate::TENANTS_LIST_ID => context.list_tenants().await,
        crate::TENANT_READ_ID => context.read_tenant().await,
        crate::TENANT_CREATE_ID => context.create_tenant(body).await,
        crate::TENANT_SETTINGS_READ_ID => context.read_settings().await,
        crate::TENANT_SETTINGS_UPDATE_ID => context.update_settings(body).await,
        crate::CLIENTS_LIST_ID => context.list_clients().await,
        crate::CLIENT_READ_ID => context.read_client().await,
        crate::CLIENT_CREATE_ID => context.create_client(body).await,
        crate::CLIENT_UPDATE_ID => context.update_client(body).await,
        crate::REGISTRATION_READ_ID => Ok(context.read_registration_gate()),
        crate::INITIAL_ACCESS_TOKENS_LIST_ID => context.list_initial_access_tokens().await,
        crate::INITIAL_ACCESS_TOKEN_CREATE_ID => context.issue_initial_access_token(body).await,
        crate::KEYS_LIST_ID => context.list_keys().await,
        crate::KEYS_JWKS_ID => context.preview_jwks().await,
        crate::KEYS_ROTATE_ID => context.rotate_key(body).await,
        crate::KEYS_RETIRE_ID => context.retire_key().await,
        crate::KEYS_PURGE_ID => context.purge_key(body).await,
        crate::KEYS_SCHEDULE_ID => context.set_key_schedule(body).await,
        crate::KEYS_SCHEDULE_APPLY_ID => context.apply_key_schedule().await,
        crate::OUTBOX_DEAD_LETTERS_ID => context.list_dead_letters().await,
        crate::OUTBOX_DEAD_LETTER_RETRY_ID => context.retry_dead_letter().await,
        crate::OUTBOX_DEAD_LETTER_DROP_ID => context.drop_dead_letter().await,
        crate::POLICY_READ_ID => context.read_policy().await,
        crate::POLICY_UPDATE_ID => context.update_policy(body).await,
        crate::POLICY_DELETE_ID => context.delete_policy().await,
        crate::POLICY_TRY_ID => context.try_policy(body).await,
        crate::SSF_STREAMS_LIST_ID => context.list_streams().await,
        crate::SSF_STREAM_STATUS_UPDATE_ID => context.update_stream_status(body).await,
        crate::SSF_STREAM_VERIFY_ID => context.verify_stream(body).await,
        crate::AUDIT_EVENTS_LIST_ID => context.list_audit_events().await,
        crate::AUDIT_EVENTS_EXPORT_ID => context.export_audit_events(),
        crate::USERS_LIST_ID => context.list_users().await,
        crate::USER_READ_ID => context.read_user().await,
        crate::USER_CREATE_ID => context.create_user(body).await,
        crate::USER_CLAIMS_UPDATE_ID => context.update_claims(body).await,
        crate::USER_STATUS_UPDATE_ID => context.update_status(body).await,
        crate::USER_CREDENTIALS_READ_ID => context.read_credentials().await,
        crate::USER_PASSKEY_REMOVE_ID => context.remove_passkey().await,
        crate::USER_PASSWORD_RESET_ID => context.reset_password().await,
        crate::USER_SESSIONS_LIST_ID => context.list_sessions().await,
        crate::USER_SESSION_REVOKE_ID => context.revoke_session().await,
        crate::USER_GRANTS_LIST_ID => context.list_grants().await,
        crate::USER_GRANT_REVOKE_ID => context.revoke_grant().await,
        crate::USER_ROLES_READ_ID => context.read_roles().await,
        crate::USER_ROLES_UPDATE_ID => context.update_roles(body).await,
        crate::APP_ROLES_LIST_ID => context.list_roles(RoleOwner::Tenant).await,
        crate::APP_ROLE_CREATE_ID => context.create_role(RoleOwner::Tenant, body).await,
        crate::APP_ROLE_DELETE_ID => context.delete_role(RoleOwner::Tenant).await,
        crate::CLIENT_APP_ROLES_LIST_ID => {
            let owner = context.client_owner_in_path()?;
            context.list_roles(owner).await
        }
        crate::CLIENT_APP_ROLE_CREATE_ID => {
            let owner = context.client_owner_in_path()?;
            context.create_role(owner, body).await
        }
        crate::CLIENT_APP_ROLE_DELETE_ID => {
            let owner = context.client_owner_in_path()?;
            context.delete_role(owner).await
        }
        crate::USER_APP_ROLES_LIST_ID => context.list_held_roles().await,
        crate::USER_APP_ROLE_ASSIGN_ID => context.assign_role(body).await,
        crate::USER_APP_ROLE_WITHDRAW_ID => context.withdraw_role(RoleOwner::Tenant).await,
        crate::USER_CLIENT_APP_ROLE_WITHDRAW_ID => {
            let owner = context.client_owner_in_path()?;
            context.withdraw_role(owner).await
        }
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

        // What this caller may actually do, so a console can hide a link
        // rather than offer a 403. Derived by asking the *same* `satisfies`
        // every request goes through, over the *same* registry the router was
        // built from: a console cannot be told a role means something the
        // server disagrees with, because nothing here re-states the mapping.
        //
        // Two lists rather than one, because a scope string does not say how
        // far it reaches: `admin.tenants:read` is held by a tenant admin over
        // its own tenant and by a deployment admin over every tenant, and a
        // console that could not tell them apart would offer the tenant list
        // to somebody who is about to be refused it.
        let (scopes, deployment_scopes) = Self::held_scopes(held, tenant);

        Ok(json_no_store(
            StatusCode::OK,
            &serde_json::json!({
                "tenant": tenant.as_str(),
                "user": user.as_uuid().to_string(),
                "roles": roles,
                "scopes": scopes,
                "deployment_scopes": deployment_scopes,
                "csrf_token": csrf::token(session_id),
            }),
        ))
    }

    /// The registry's scopes this caller holds, in this tenant and across the
    /// deployment.
    ///
    /// Sorted and deduplicated: the document is read by a person as often as
    /// by a program, and a set is what it means.
    fn held_scopes(held: &crate::rbac::Held, tenant: &TenantId) -> (Vec<String>, Vec<String>) {
        let mut here = std::collections::BTreeSet::new();
        let mut everywhere = std::collections::BTreeSet::new();

        for operation in crate::registry() {
            let scope = operation.authority().scope();
            let reach = operation.authority().reach();
            if held.satisfies(crate::rbac::Authority::new(reach, scope), tenant) {
                match reach {
                    crate::rbac::Reach::Deployment => everywhere.insert(scope.to_owned()),
                    crate::rbac::Reach::Tenant | crate::rbac::Reach::Authenticated => {
                        here.insert(scope.to_owned())
                    }
                };
            }
        }

        (here.into_iter().collect(), everywhere.into_iter().collect())
    }

    /// `DELETE /session` — ends the session this request was made with.
    ///
    /// Two things have to happen and neither one is enough alone. The row is
    /// revoked, so the id stops resolving for anybody holding a copy of the
    /// cookie; and the browser is sent the clearing `Set-Cookie`, so the next
    /// navigation to `/admin/` meets the door `ast-wr4` put there rather than
    /// carrying a dead id around. A console cannot do either itself: the
    /// cookie is `HttpOnly`, which is the point.
    ///
    /// The session ended is the one that authenticated the request and no
    /// other. There is no identifier anywhere in this route, so "sign out"
    /// cannot be aimed.
    async fn end_session(&self) -> Result<Response, AdminError> {
        let Principal::Console {
            tenant, session_id, ..
        } = self.principal
        else {
            // A token caller has no session to end. Refused rather than
            // answered with "done": a client that believes it signed something
            // out would stop looking for the credential that is still live.
            return Err(AdminError::Forbidden);
        };

        let digest = SessionId::from_presented(session_id.clone()).digest();

        self.state
            .backend
            .end_session(tenant, &digest, SessionRevocation::UserLogout, self.now)
            .await
            .map_err(|error| AdminError::from_storage(crate::SESSION_END_ID, &error))?;

        // `session.revoked` and not `admin.changed`: this is a session ending,
        // which is what somebody asking "why was I signed out" filters on, and
        // nothing about the deployment's configuration changed.
        self.record(
            EventType::SESSION_REVOKED,
            Detail::new()
                .label("operation", crate::SESSION_END_ID)
                .label("reason", SessionRevocation::UserLogout.as_str()),
        )
        .await;

        let mut response = json_no_store(StatusCode::OK, &serde_json::json!({"ended": true}));
        response.headers_mut().insert(
            header::SET_COOKIE,
            axum::http::HeaderValue::from_str(&asterius_web::session::clear_cookie())
                .map_err(|_| AdminError::Unavailable)?,
        );
        Ok(response)
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

    /// `GET /tenants/{tenant_id}/settings` — the flags and lifetimes in force.
    async fn read_settings(&self) -> Result<Response, AdminError> {
        let named = self.settings_subject(crate::TENANT_SETTINGS_READ.authority())?;

        let settings = self
            .state
            .backend
            .tenant_settings()
            .settings(&named)
            .await
            .map_err(|error| AdminError::from_storage("tenants.settings.read", &error))?;

        Ok(json_no_store(
            StatusCode::OK,
            &render_settings(&named, &settings),
        ))
    }

    /// `PUT /tenants/{tenant_id}/settings` — replaces them.
    ///
    /// The ceilings are applied here, in the server, and not in the console:
    /// the console's own bounds checking is a courtesy to whoever is typing,
    /// and an administrator holding a session and a CSRF token can send this
    /// request with `curl`. A body asking for a code lifetime past FAPI 2.0
    /// SP's sixty seconds is refused with the clause named, which is
    /// `ast-f7m.4`'s acceptance criterion.
    async fn update_settings(&self, body: axum::body::Body) -> Result<Response, AdminError> {
        let named = self.settings_subject(crate::TENANT_SETTINGS_UPDATE.authority())?;

        let bytes = axum::body::to_bytes(body, MAX_BODY_BYTES)
            .await
            .map_err(|_| AdminError::Invalid("the request body is too large".to_owned()))?;
        let requested: RequestedSettings = serde_json::from_slice(&bytes).map_err(|error| {
            AdminError::Invalid(format!("the request body is not valid: {error}"))
        })?;

        let mut disabled = std::collections::BTreeSet::new();
        for name in &requested.disabled_features {
            let feature = asterius_domain::Feature::from_key(name).ok_or_else(|| {
                AdminError::Invalid(format!("{name} is not a feature this server knows"))
            })?;
            disabled.insert(feature);
        }

        let repository = self.state.backend.tenant_settings();
        let previous = repository
            .settings(&named)
            .await
            .map_err(|error| AdminError::from_storage("tenants.settings.read", &error))?;

        // Read before the new settings are assembled, because an absent
        // `registration_policy` means "keep the stored one": `TenantSettings`
        // is replaced wholesale here, so anything not carried over is deleted.
        let registration = match &requested.registration_policy {
            None => previous.registration().clone(),
            Some(document) => asterius_domain::RegistrationPolicy::from_json(Some(document))
                .map_err(|refusal| AdminError::Invalid(refusal.to_string()))?,
        };

        // Read before assembly, like the registration policy: these settings
        // are replaced wholesale, so a form that does not carry a tenant's
        // language and its overridden wording would delete both.
        let default_locale = match &requested.default_locale {
            None => previous.default_locale(),
            Some(tag) => asterius_domain::Locale::matching(tag).ok_or_else(|| {
                AdminError::Invalid(format!(
                    "'{tag}' is not a language this server renders; the supported tags are the \
                     members of `ui_locales_supported`"
                ))
            })?,
        };

        // Two validators, and both of them run here rather than at render time.
        // `MessageOverrides` decides what a *string* may be — text, bounded, no
        // `<` and no `>`, no non-printing characters — and
        // `asterius_web::validate_overrides` decides what a *key* may be,
        // because the catalogue lives with the pages. An administrator who
        // mistypes a key is told which one; the sign-in page that reads the row
        // later cannot fail, and ignores what it does not know.
        let messages = match &requested.messages {
            None => previous.messages().clone(),
            Some(document) => {
                let parsed = asterius_domain::MessageOverrides::from_json(Some(document))
                    .map_err(|refusal| AdminError::Invalid(refusal.to_string()))?;
                asterius_web::validate_overrides(&parsed)
                    .map_err(|refusal| AdminError::Invalid(refusal.to_string()))?;
                parsed
            }
        };

        // The one line this whole operation exists for. `TenantSettings` has
        // private fields and one constructor, so there is no way past it.
        let settings = TenantSettings::validated(
            disabled,
            time::Duration::seconds(requested.authorization_code_lifetime_seconds),
            time::Duration::seconds(requested.access_token_lifetime_seconds),
        )
        .map_err(|refusal| AdminError::Invalid(refusal.to_string()))?
        .with_registration(registration)
        .with_default_locale(default_locale)
        .with_messages(messages);

        repository
            .save(&named, &settings)
            .await
            .map_err(|error| AdminError::from_storage("tenants.settings.update", &error))?;

        // A flag is published in the discovery document, so a change that is
        // not visible there is a change an administrator cannot verify. The
        // deployment's snapshot is dropped here rather than left to expire.
        self.state.backend.tenant_directory_changed();

        self.record(
            EventType::ADMIN_CHANGED,
            settings_diff(&named, &previous, &settings),
        )
        .await;

        Ok(json_no_store(
            StatusCode::OK,
            &render_settings(&named, &settings),
        ))
    }

    /// The tenant a settings route names, once the caller has been re-checked
    /// against it.
    ///
    /// The same second check [`Self::read_tenant`] makes and for the same
    /// reason: the gate checked the caller against the tenant the request was
    /// *routed* to, and these operations name a different one in their path.
    fn settings_subject(&self, authority: crate::Authority) -> Result<TenantId, AdminError> {
        let named = self
            .path
            .strip_suffix("/settings")
            .and_then(|prefix| prefix.rsplit('/').next())
            .filter(|segment| !segment.is_empty())
            .ok_or(AdminError::NotFound)?;
        let named = TenantId::parse(named).map_err(|_| AdminError::NotFound)?;

        if !self.principal.held().satisfies(authority, &named) {
            return Err(AdminError::Forbidden);
        }
        Ok(named)
    }

    /// `GET /clients` — this tenant's clients, one cursor page at a time.
    ///
    /// The `q` parameter filters *before* the page is cut, which is the only
    /// order that makes a filtered page mean anything: filtering after the cut
    /// would give an operator a page of three rows and a cursor promising more.
    async fn list_clients(&self) -> Result<Response, AdminError> {
        let request = PageRequest::parse(
            query_value(&self.query, "cursor").as_deref(),
            query_value(&self.query, "limit").as_deref(),
        )?;
        // Decoded, unlike the cursor and the limit beside it: a search box
        // holds prose, and a browser sends prose percent-encoded. See
        // [`clients::search_term`].
        let query = clients::search_term(&query_value(&self.query, "q").unwrap_or_default());

        let clients = self
            .state
            .backend
            .clients()
            .list(&self.tenant.id)
            .await
            .map_err(|error| AdminError::from_storage(crate::CLIENTS_LIST_ID, &error))?;

        // Ordered by `client_id` below the port, and the cursor is that id, so
        // the page is cut here for the reason `list_tenants` states: a tenant
        // holds clients in the tens or hundreds, and a ranged `list_after` on
        // the port is what a deployment with more would grow. The cursor is
        // opaque so that it can grow without breaking a console.
        let rows: Vec<serde_json::Value> = clients
            .iter()
            .filter(|client| clients::matches(client, &query))
            .skip_while(|client| {
                request
                    .after
                    .as_ref()
                    .is_some_and(|cursor| client.id.as_str() <= cursor.key())
            })
            .take(request.limit + 1)
            .map(clients::summarise)
            .collect();

        let page = Page::from_overfetched(rows, request.limit, |row| {
            row["client_id"].as_str().unwrap_or_default().to_owned()
        });

        Ok(json_no_store(
            StatusCode::OK,
            &serde_json::to_value(&page).unwrap_or_else(|_| serde_json::json!({})),
        ))
    }

    /// `GET /clients/{client_id}` — one client's registration.
    ///
    /// The client is looked up in the tenant the request was routed to, so a
    /// `client_id` belonging to another tenant is a 404 here rather than
    /// somebody else's configuration.
    async fn read_client(&self) -> Result<Response, AdminError> {
        let id = self.client_in_path("")?;
        let client = self.load_client(&id, crate::CLIENT_READ_ID).await?;

        Ok(json_no_store(StatusCode::OK, &clients::document(&client)))
    }

    /// `POST /clients` — registers a client from the console.
    ///
    /// **The whole of the validation is `ClientRegistration::from_json`**, the
    /// call `POST /register` makes, on the bytes as they arrived. Nothing here
    /// decides what an acceptable client is; see [`crate::clients`]. The two
    /// checks that follow are the two a document cannot answer: whether this
    /// tenant can sign the ID tokens the client asked for, and whether a
    /// pairwise client's sector is backed (OIDC Registration §5).
    ///
    /// No registration access token is minted, so none is shown once and none
    /// is stored: a client created here is managed from the console, and OIDC
    /// Registration §3.2 requires "both a Client Configuration Endpoint and a
    /// Registration Access Token or neither of them".
    async fn create_client(&self, body: axum::body::Body) -> Result<Response, AdminError> {
        let bytes = self.body_bytes(body).await?;
        let status = clients::requested_status(&bytes)?.unwrap_or(ClientStatus::Active);
        let registration = ClientRegistration::from_json(&bytes, self.state.backend.capabilities())
            .map_err(|failure| clients::refusal(&failure))?;

        self.check_client_is_serviceable(&registration, crate::CLIENT_CREATE_ID)
            .await?;

        let client = Client {
            tenant: self.tenant.id.clone(),
            // Minted here and never taken from the body: FAPI 2.0 SP §6.7 says
            // a client must not influence its own identifier, and an
            // administrator is not an exception — the console has no more
            // business choosing a `client_id` than a registering client does.
            id: asterius_domain::ClientId::mint(),
            registration,
            status,
            // Placeholders the store overwrites. The response is rendered from
            // what comes back, so these never reach a screen.
            created_at: self.now,
            updated_at: self.now,
        };

        let stored =
            self.state
                .backend
                .clients()
                .create(&client)
                .await
                .map_err(|error| match error {
                    DomainError::Conflict(message) => AdminError::Conflict(message),
                    other => AdminError::from_storage(crate::CLIENT_CREATE_ID, &other),
                })?;

        self.record(
            EventType::ADMIN_CHANGED,
            Detail::new()
                .label("operation", crate::CLIENT_CREATE_ID)
                .text("client_id", stored.id.as_str())
                .text("status", stored.status.as_str()),
        )
        .await;

        Ok(json_no_store(
            StatusCode::CREATED,
            &clients::document(&stored),
        ))
    }

    /// `PUT /clients/{client_id}` — replaces one client's registration.
    ///
    /// A replacement and not a merge (RFC 7592 §2.2), through the same
    /// validator as a creation: an edit that could pass a document a fresh
    /// registration would refuse would make the shared validator a formality.
    ///
    /// The `client_id`, the creation time and everything the document does not
    /// carry — the registration access token, the per-client resource
    /// allow-list, the agent profile — survive untouched, because the entity
    /// written is the stored one with a new registration on it rather than one
    /// assembled from the request.
    async fn update_client(&self, body: axum::body::Body) -> Result<Response, AdminError> {
        let id = self.client_in_path("")?;
        let existing = self.load_client(&id, crate::CLIENT_UPDATE_ID).await?;

        let bytes = self.body_bytes(body).await?;
        // Absent means unchanged, which is what stops a console built against
        // an older server from reactivating a client somebody suspended.
        let status = clients::requested_status(&bytes)?.unwrap_or(existing.status);
        let registration = ClientRegistration::from_json(&bytes, self.state.backend.capabilities())
            .map_err(|failure| clients::refusal(&failure))?;

        self.check_client_is_serviceable(&registration, crate::CLIENT_UPDATE_ID)
            .await?;

        let updated = Client {
            registration,
            status,
            updated_at: self.now,
            ..existing.clone()
        };

        let stored = self
            .state
            .backend
            .clients()
            .replace(&updated)
            .await
            .map_err(|error| match error {
                DomainError::NotFound => AdminError::NotFound,
                other => AdminError::from_storage(crate::CLIENT_UPDATE_ID, &other),
            })?;

        self.record(
            EventType::ADMIN_CHANGED,
            Detail::new()
                .label("operation", crate::CLIENT_UPDATE_ID)
                .text("client_id", stored.id.as_str())
                .text("status_before", existing.status.as_str())
                .text("status_after", stored.status.as_str()),
        )
        .await;

        Ok(json_no_store(StatusCode::OK, &clients::document(&stored)))
    }

    /// `GET /registration` — the dynamic registration gate, as configured.
    ///
    /// A read of configuration, so there is nothing to await. See
    /// [`crate::clients::RegistrationGate`] for why this reports the gate
    /// rather than offering to mint an initial access token.
    fn read_registration_gate(&self) -> Response {
        json_no_store(
            StatusCode::OK,
            &clients::registration_document(self.state.backend.registration_gate()),
        )
    }

    /// `GET /initial-access-tokens` — this tenant's own registration
    /// credentials (`ast-cu3`).
    ///
    /// A quota, an expiry and a label per row. No digest and no plaintext: see
    /// [`crate::initial_access_tokens`].
    async fn list_initial_access_tokens(&self) -> Result<Response, AdminError> {
        let tokens = self
            .state
            .backend
            .initial_access_tokens()
            .list(&self.tenant.id)
            .await
            .map_err(|error| {
                AdminError::from_storage(crate::INITIAL_ACCESS_TOKENS_LIST_ID, &error)
            })?;

        let rendered: Vec<_> = tokens
            .iter()
            .map(|token| initial_access_tokens::summarise(token, self.now))
            .collect();
        Ok(json_no_store(
            StatusCode::OK,
            &serde_json::json!({ "items": rendered }),
        ))
    }

    /// `GET /outbox/dead-letters` — deliveries given up on (`ast-0ju.9`).
    ///
    /// Newest first, capped at [`outbox::LIMIT`]. No payload and no
    /// destination is rendered: see [`crate::outbox`] for why that is the
    /// design of the document rather than an omission.
    async fn list_dead_letters(&self) -> Result<Response, AdminError> {
        let letters = self
            .state
            .backend
            .outbox()
            .dead_letters(&self.tenant.id, outbox::LIMIT)
            .await
            .map_err(|error| AdminError::from_storage(crate::OUTBOX_DEAD_LETTERS_ID, &error))?;

        let rendered: Vec<_> = letters.iter().map(outbox::summarise).collect();
        Ok(json_no_store(
            StatusCode::OK,
            &serde_json::json!({ "items": rendered }),
        ))
    }

    /// The `{outbox_id}` in this request's path: the segment after
    /// `dead-letters`.
    ///
    /// Read by position rather than by `trim_end_matches`, for the reason
    /// [`Self::user_in_path`] gives: the retry route has a tail and the drop
    /// route has none, and one rule that holds for both beats two literals.
    /// A segment that is not an integer names nothing this server holds and
    /// is the same answer as a row of another tenant: 404.
    fn outbox_id_in_path(&self) -> Result<i64, AdminError> {
        let mut segments = self.path.split('/');
        segments
            .find(|segment| *segment == "dead-letters")
            .and_then(|_| segments.next())
            .and_then(|segment| segment.parse::<i64>().ok())
            .ok_or(AdminError::NotFound)
    }

    /// One abandoned row of this tenant that the buttons apply to, or the
    /// refusal that says why not.
    ///
    /// A row of another kind is a 409 and not a 404: it exists, the caller
    /// can see it on the screen, and "no such resource" would send them
    /// looking for a typo. See [`crate::outbox`] for the rule.
    async fn retryable_dead_letter(
        &self,
        operation: &'static str,
    ) -> Result<asterius_domain::outbox::DeadLetter, AdminError> {
        let id = self.outbox_id_in_path()?;
        let letter = self
            .state
            .backend
            .outbox()
            .dead_letter(&self.tenant.id, id)
            .await
            .map_err(|error| AdminError::from_storage(operation, &error))?
            .ok_or(AdminError::NotFound)?;
        if !outbox::is_retryable(&letter) {
            return Err(AdminError::Conflict(format!(
                "only {} deliveries can be retried or dropped from the console; this row is {}",
                outbox::RETRYABLE_FAMILY,
                letter.kind
            )));
        }
        Ok(letter)
    }

    /// What the two dead-letter mutations record: the row, its kind, how
    /// hard it was tried and what the receiver last said. Never the payload,
    /// which the port does not carry.
    fn dead_letter_detail(letter: &asterius_domain::outbox::DeadLetter) -> Detail {
        let detail = Detail::new()
            .number("outbox_id", letter.id)
            .text("kind", &letter.kind)
            .number("attempts", i64::from(letter.attempts));
        match &letter.last_error {
            Some(error) => detail.text("last_error", error),
            None => detail,
        }
    }

    /// `POST /outbox/dead-letters/{outbox_id}/retry` — back on the schedule
    /// (`ast-f7m.8`).
    ///
    /// The row is read first and the mutation is predicated on its status,
    /// so a row swept by retention between the two answers 404 rather than
    /// recording a retry that requeued nothing.
    async fn retry_dead_letter(&self) -> Result<Response, AdminError> {
        let letter = self
            .retryable_dead_letter(crate::OUTBOX_DEAD_LETTER_RETRY_ID)
            .await?;
        let requeued = self
            .state
            .backend
            .dead_letter_operations()
            .requeue(&self.tenant.id, letter.id, self.now)
            .await
            .map_err(|error| {
                AdminError::from_storage(crate::OUTBOX_DEAD_LETTER_RETRY_ID, &error)
            })?;
        if !requeued {
            return Err(AdminError::NotFound);
        }
        self.record(
            EventType::OUTBOX_RETRIED,
            Self::dead_letter_detail(&letter)
                .label("operation", crate::OUTBOX_DEAD_LETTER_RETRY_ID),
        )
        .await;
        Ok(json_no_store(
            StatusCode::OK,
            &serde_json::json!({ "id": letter.id, "kind": letter.kind, "requeued": true }),
        ))
    }

    /// `DELETE /outbox/dead-letters/{outbox_id}` — gone, and recorded
    /// (`ast-f7m.8`).
    ///
    /// The record is written *after* the delete and carries everything the
    /// row said about itself, because once the row is gone this record is
    /// the only place an investigator finds it.
    async fn drop_dead_letter(&self) -> Result<Response, AdminError> {
        let letter = self
            .retryable_dead_letter(crate::OUTBOX_DEAD_LETTER_DROP_ID)
            .await?;
        let dropped = self
            .state
            .backend
            .dead_letter_operations()
            .drop_letter(&self.tenant.id, letter.id)
            .await
            .map_err(|error| AdminError::from_storage(crate::OUTBOX_DEAD_LETTER_DROP_ID, &error))?;
        if !dropped {
            return Err(AdminError::NotFound);
        }
        self.record(
            EventType::OUTBOX_DROPPED,
            Self::dead_letter_detail(&letter).label("operation", crate::OUTBOX_DEAD_LETTER_DROP_ID),
        )
        .await;
        Ok(StatusCode::NO_CONTENT.into_response())
    }

    /// `GET /policies` — the tenant's authorization policy (`ast-pj0.4`).
    ///
    /// A tenant that has never written one is a 200 carrying the empty
    /// document rather than a 404: the editor has to open on something, and
    /// "no policy" is a state of the tenant rather than a missing resource.
    async fn read_policy(&self) -> Result<Response, AdminError> {
        let stored = self
            .state
            .backend
            .policies()
            .load(&self.tenant.id)
            .await
            .map_err(|error| AdminError::from_storage(crate::POLICY_READ_ID, &error))?;

        Ok(json_no_store(
            StatusCode::OK,
            &policies::document(stored.as_ref()),
        ))
    }

    /// `PUT /policies` — replaces the policy after parsing it (`ast-pj0.4`).
    ///
    /// Parsed before it is stored, and stored only as a
    /// `asterius_domain::policy::RuleSet`: the port has no method that takes a
    /// `Value`, so a document this build cannot read cannot reach the column
    /// the evaluator reads back.
    ///
    /// The record carries the rule count and not the rules. A policy is the
    /// list of attributes, groups and roles a tenant reasons about, and the
    /// audit trail is the one table this deployment keeps forever; the
    /// document itself is readable by anybody holding `admin.policies:read`,
    /// which is where it belongs.
    async fn update_policy(&self, body: axum::body::Body) -> Result<Response, AdminError> {
        let bytes = axum::body::to_bytes(body, policies::MAX_BODY_BYTES)
            .await
            .map_err(|_| AdminError::Invalid("the request body is too large".to_owned()))?;
        let rules = policies::parse_document(&bytes)?;

        self.state
            .backend
            .policies()
            .replace(&self.tenant.id, &rules, self.now)
            .await
            .map_err(|error| AdminError::from_storage(crate::POLICY_UPDATE_ID, &error))?;

        self.record(
            EventType::POLICY_UPDATED,
            Detail::new()
                .label("operation", crate::POLICY_UPDATE_ID)
                .number(
                    "rules",
                    i64::try_from(rules.rules().len()).unwrap_or(i64::MAX),
                )
                .flag("cleared", false),
        )
        .await;

        Ok(json_no_store(
            StatusCode::OK,
            &serde_json::json!({
                "document": rules.to_json(),
                "rule_count": rules.rules().len(),
            }),
        ))
    }

    /// `DELETE /policies` — the tenant goes back to denying everything.
    ///
    /// 204 whether or not there was a document: the tenant ends in the state
    /// the caller asked for, and a 404 for "there was nothing to delete" would
    /// make a retried click an error. The record says it was a clearing.
    async fn delete_policy(&self) -> Result<Response, AdminError> {
        let removed = self
            .state
            .backend
            .policies()
            .clear(&self.tenant.id)
            .await
            .map_err(|error| AdminError::from_storage(crate::POLICY_DELETE_ID, &error))?;

        if removed {
            self.record(
                EventType::POLICY_UPDATED,
                Detail::new()
                    .label("operation", crate::POLICY_DELETE_ID)
                    .number("rules", 0)
                    .flag("cleared", true),
            )
            .await;
        }

        Ok(StatusCode::NO_CONTENT.into_response())
    }

    /// `POST /policies/try` — what the stored policy decides about one
    /// request, without enforcing it (`ast-f7m.9`).
    ///
    /// The console's test bench. It answers §6.2's Decision, so an
    /// administrator reads what a relying party would be handed rather than a
    /// rendering invented for this screen.
    ///
    /// # No record
    ///
    /// Deliberately unaudited, and not because a trial is unimportant. The
    /// trail records what *happened to a tenant's people and configuration*: a
    /// decision this endpoint takes enforces nothing, changes nothing, and
    /// tells its caller a function of a document they may already `GET` in
    /// full over facts they may already read. There is nothing here that a
    /// later investigator could not recompute from the policy and the trail of
    /// the edits to it, which `policy.updated` already carries — while a
    /// record per keystroke of a bench would be the highest-volume row in the
    /// one table this deployment keeps forever. The threat-model row says the
    /// same thing: the bench is a policy oracle for somebody who already holds
    /// the policy.
    ///
    /// # Not the PDP's budget
    ///
    /// This is an admin route, so it passes the admin rate limiter like every
    /// other one and cannot reach `LimitedEndpoint::AccessEvaluation` at all —
    /// this crate has no handle on it. A bench left open in a tab therefore
    /// cannot spend the budget a PEP's traffic depends on.
    async fn try_policy(&self, body: axum::body::Body) -> Result<Response, AdminError> {
        let bytes = axum::body::to_bytes(body, asterius_oidc::authzen::MAX_REQUEST_BYTES)
            .await
            .map_err(|_| AdminError::Invalid("the request body is too large".to_owned()))?;
        let request = policies::parse_trial(&bytes)?;

        // A failure is a refusal and not a deny. The PDP endpoint answers a
        // PEP `decision: false` when it cannot read the store, because an
        // enforcement point has to do *something* safe; a person asked
        // "what does my policy say?" must not be told "deny" by an outage
        // they would then go and edit a rule about.
        let decision = self
            .state
            .backend
            .policy_trial()
            .decide(&self.tenant.id, &request)
            .await
            .map_err(|error| AdminError::from_storage(crate::POLICY_TRY_ID, &error))?;

        Ok(json_no_store(
            StatusCode::OK,
            &policies::trial_response(&decision),
        ))
    }

    /// The `{stream_id}` in this request's path: the segment after
    /// `streams`, which must be an identifier this server issues.
    ///
    /// One that is not is a 404 and not a 400: it names nothing, and the
    /// refusal must not distinguish "malformed" from "another tenant's".
    fn stream_in_path(&self) -> Result<asterius_ssf::stream::StreamId, AdminError> {
        let mut segments = self.path.split('/');
        segments
            .find(|segment| *segment == "streams")
            .and_then(|_| segments.next())
            .and_then(asterius_ssf::stream::StreamId::parse)
            .ok_or(AdminError::NotFound)
    }

    /// `GET /ssf/streams` — every stream of the tenant, with its figures
    /// (`ast-f7m.8`).
    async fn list_streams(&self) -> Result<Response, AdminError> {
        let streams = self
            .state
            .backend
            .ssf()
            .streams(&self.tenant.id)
            .await
            .map_err(|error| AdminError::from_storage(crate::SSF_STREAMS_LIST_ID, &error))?;
        let items: Vec<_> = streams.iter().map(ssf::document).collect();
        Ok(json_no_store(
            StatusCode::OK,
            &serde_json::json!({ "items": items }),
        ))
    }

    /// `PUT /ssf/streams/{stream_id}/status` — pause or re-enable (SSF 1.0
    /// §8.1.2, `ast-f7m.8`).
    ///
    /// Recorded as `ssf.stream_updated` — the type the receiver's own edits
    /// leave — with the operator as the actor and the stream fingerprinted,
    /// exactly as the management endpoint records it. A reader of the trail
    /// filtering on the type sees every change to the arrangement, whoever
    /// made it, and tells the two apart by the actor.
    async fn update_stream_status(&self, body: axum::body::Body) -> Result<Response, AdminError> {
        let stream = self.stream_in_path()?;
        let bytes = axum::body::to_bytes(body, ssf::MAX_BODY_BYTES)
            .await
            .map_err(|_| AdminError::Invalid("the request body is too large".to_owned()))?;
        let requested = ssf::parse_status_request(&bytes)?;

        let written = self
            .state
            .backend
            .ssf()
            .set_status(
                &self.tenant.id,
                &stream,
                requested.status,
                requested.reason.as_deref(),
                self.now,
            )
            .await
            .map_err(|error| {
                AdminError::from_storage(crate::SSF_STREAM_STATUS_UPDATE_ID, &error)
            })?;
        if !written {
            return Err(AdminError::NotFound);
        }

        let detail = Detail::new()
            .label("operation", crate::SSF_STREAM_STATUS_UPDATE_ID)
            .credential("stream_id", stream.as_str())
            .label("status", requested.status.as_str());
        let detail = match &requested.reason {
            Some(reason) => detail.text("reason", reason),
            None => detail,
        };
        self.record(EventType::SSF_STREAM_UPDATED, detail).await;

        Ok(json_no_store(
            StatusCode::OK,
            &serde_json::json!({
                "stream_id": stream.as_str(),
                "status": requested.status.as_str(),
                "reason": requested.reason,
            }),
        ))
    }

    /// `POST /ssf/streams/{stream_id}/verification` — §8.1.4's event, on
    /// the stream's own queue (`ast-f7m.8`).
    ///
    /// The record says a `state` was given and not which: it is a value the
    /// receiver will compare against, and the trail is read more widely than
    /// the receiver.
    async fn verify_stream(&self, body: axum::body::Body) -> Result<Response, AdminError> {
        let stream = self.stream_in_path()?;
        let bytes = axum::body::to_bytes(body, ssf::MAX_BODY_BYTES)
            .await
            .map_err(|_| AdminError::Invalid("the request body is too large".to_owned()))?;
        let state = ssf::parse_verification_request(&bytes)?;

        let queued = self
            .state
            .backend
            .ssf()
            .verify(&self.tenant.id, &stream, state.as_ref(), self.now)
            .await
            .map_err(|error| AdminError::from_storage(crate::SSF_STREAM_VERIFY_ID, &error))?;
        if !queued {
            return Err(AdminError::NotFound);
        }

        self.record(
            EventType::SSF_VERIFICATION_REQUESTED,
            Detail::new()
                .label("operation", crate::SSF_STREAM_VERIFY_ID)
                .credential("stream_id", stream.as_str())
                .flag("with_state", state.is_some()),
        )
        .await;

        Ok(json_no_store(
            StatusCode::ACCEPTED,
            &serde_json::json!({ "stream_id": stream.as_str(), "queued": true }),
        ))
    }

    /// `GET /audit/events` — the trail, filtered, one page at a time
    /// (`ast-lh3.9`).
    ///
    /// The filter is parsed before the cursor is read, so a caller with a
    /// bad filter and a bad cursor is told about the filter: the cursor was
    /// minted for a different query and would be wrong anyway.
    async fn list_audit_events(&self) -> Result<Response, AdminError> {
        let filter = audit::parse_filter(&self.query)?;
        let request = PageRequest::parse(
            query_value(&self.query, "cursor").as_deref(),
            query_value(&self.query, "limit").as_deref(),
        )?;
        // The cursor key is the id of the last record shown; anything else
        // is a cursor this server did not mint for this listing.
        let before = request
            .after
            .as_ref()
            .map(|cursor| {
                cursor
                    .key()
                    .parse::<i64>()
                    .map_err(|_| AdminError::CursorInvalid)
            })
            .transpose()?;
        let limit = u32::try_from(request.limit + 1).unwrap_or(u32::MAX);

        let entries = self
            .state
            .backend
            .audit_trail()
            .query(&self.tenant.id, &filter, before, limit)
            .await
            .map_err(|error| AdminError::from_storage(crate::AUDIT_EVENTS_LIST_ID, &error))?;

        let items: Vec<serde_json::Value> = entries.iter().map(audit::render).collect();
        let page = Page::from_overfetched(items, request.limit, |row| row["id"].to_string());

        Ok(json_no_store(
            StatusCode::OK,
            &serde_json::to_value(&page).unwrap_or_else(|_| serde_json::json!({})),
        ))
    }

    /// `GET /audit/events/export` — the same records as NDJSON, streamed.
    ///
    /// Not `async`: nothing is read before the response starts. The first
    /// page is fetched when the body is first polled, so a storage failure
    /// surfaces as a body that does not complete — see
    /// [`crate::audit::Export`] for why that is the honest shape.
    fn export_audit_events(&self) -> Result<Response, AdminError> {
        let filter = audit::parse_filter(&self.query)?;
        let export = audit::Export::new(
            self.state.backend.audit_trail(),
            self.tenant.id.clone(),
            filter,
        );

        let mut response = (StatusCode::OK, axum::body::Body::from_stream(export)).into_response();
        let headers = response.headers_mut();
        headers.insert(
            header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static(audit::NDJSON),
        );
        headers.insert(
            header::CACHE_CONTROL,
            axum::http::HeaderValue::from_static("no-store"),
        );
        // A download and not a page: a browser handed NDJSON with no
        // disposition renders it, and a rendered export is one a person
        // screenshots.
        headers.insert(
            header::CONTENT_DISPOSITION,
            axum::http::HeaderValue::from_static("attachment; filename=\"audit-events.ndjson\""),
        );
        Ok(response)
    }

    /// `POST /initial-access-tokens` — mints one, shown once (`ast-cu3`).
    ///
    /// The quota comes from the tenant's stored registration policy and never
    /// from the body. That is the whole point of the ticket this is part of:
    /// `max_clients_per_initial_access_token` was a setting that stored,
    /// reloaded and evaluated and bound nothing, and the way it binds is by
    /// being stamped onto the credential at the moment it is created.
    ///
    /// A tenant whose settings cannot be read is refused rather than issued an
    /// unlimited token, for the reason `PgTenantSettings::settings` gives about
    /// a policy that quietly reverted to a default.
    async fn issue_initial_access_token(
        &self,
        body: axum::body::Body,
    ) -> Result<Response, AdminError> {
        let bytes = self.body_bytes(body).await?;
        let requested = initial_access_tokens::requested(&bytes)?;

        let settings = self
            .state
            .backend
            .tenant_settings()
            .settings(&self.tenant.id)
            .await
            .map_err(|error| {
                AdminError::from_storage(crate::INITIAL_ACCESS_TOKEN_CREATE_ID, &error)
            })?;
        let quota = settings
            .registration()
            .max_clients_per_initial_access_token();

        // 256 bits, like every other opaque credential this server issues, and
        // held for exactly as long as it takes to hash it and render it once.
        let token = OpaqueToken::generate();
        let expires_at = requested.lifetime_seconds.and_then(|seconds| {
            i64::try_from(seconds)
                .ok()
                .map(|seconds| self.now + time::Duration::seconds(seconds))
        });

        let minted = NewInitialAccessToken::new(
            self.tenant.id.clone(),
            requested.label,
            asterius_domain::sha256(token.expose().as_bytes()),
            quota,
            expires_at,
            self.principal.audit_actor(),
            self.now,
        )
        .map_err(|error| match error {
            DomainError::Invalid { field, reason } => {
                AdminError::Invalid(format!("{field}: {reason}"))
            }
            other => AdminError::from_storage(crate::INITIAL_ACCESS_TOKEN_CREATE_ID, &other),
        })?;

        let stored = self
            .state
            .backend
            .initial_access_tokens()
            .issue(&minted)
            .await
            .map_err(|error| match error {
                DomainError::Conflict(message) => AdminError::Conflict(message),
                other => AdminError::from_storage(crate::INITIAL_ACCESS_TOKEN_CREATE_ID, &other),
            })?;

        // The label, the quota and the expiry — never the credential. An audit
        // trail that carried the token would be a place to read one back out of,
        // and this trail is append-only and cannot be deleted from.
        self.record(
            EventType::ADMIN_CHANGED,
            Detail::new()
                .label("operation", crate::INITIAL_ACCESS_TOKEN_CREATE_ID)
                .text("initial_access_token_id", stored.id.to_string())
                .text("label", &stored.label)
                .text(
                    "max_clients",
                    stored
                        .max_uses
                        .map_or_else(|| "unlimited".to_owned(), |max| max.to_string()),
                ),
        )
        .await;

        Ok(json_no_store(
            StatusCode::CREATED,
            &initial_access_tokens::issued(&stored, token.expose(), self.now),
        ))
    }

    /// The two things about a client that a registration document cannot say.
    ///
    /// Both are asked before anything is written, and in this order: the key
    /// check is a local read and refusing on it spares an unreachable client an
    /// outbound request, which is the same order `POST /register` uses.
    async fn check_client_is_serviceable(
        &self,
        registration: &ClientRegistration,
        operation: &'static str,
    ) -> Result<(), AdminError> {
        let records = self
            .state
            .backend
            .keys()
            .inventory(&self.tenant.id)
            .await
            .map_err(|error| AdminError::from_storage(operation, &error))?;
        clients::check_signable(&records, registration)?;

        // The tenant's registration policy, applied to the console exactly as
        // it is to `POST /register` (`ast-m9c.6`). An administrator is not an
        // exception: a rule that says this tenant registers no callbacks on
        // other people's hosts is a statement about the tenant, and a second
        // door that ignored it would be the way around it.
        let settings = self
            .state
            .backend
            .tenant_settings()
            .settings(&self.tenant.id)
            .await
            .map_err(|error| AdminError::from_storage(operation, &error))?;
        settings
            .registration()
            .evaluate(registration)
            .map_err(|violation| clients::refusal(&violation.to_metadata_error()))?;

        self.state
            .backend
            .clients()
            .verify_sector(registration)
            .await
            .map_err(|failure| clients::refusal(&failure))
    }

    /// The `client_id` named in the path.
    ///
    /// Taken as it arrived, with no decoding step, for the reason
    /// [`Self::retire_key`] gives about a `kid`: a `client_id` this server
    /// mints is `c.` and 22 `base64url` symbols, none of which a URL encodes,
    /// and a segment carrying anything else names no client here and gets a 404
    /// from the lookup. A decoder would be a parser added to the attack surface
    /// in order to accept identifiers this server never issues.
    fn client_in_path(&self, suffix: &str) -> Result<asterius_domain::ClientId, AdminError> {
        let segment = self
            .path
            .trim_end_matches(suffix)
            .rsplit('/')
            .next()
            .filter(|segment| !segment.is_empty())
            .ok_or(AdminError::NotFound)?;
        Ok(asterius_domain::ClientId::new(segment))
    }

    /// One client of the tenant this request was routed to, or a 404.
    async fn load_client(
        &self,
        id: &asterius_domain::ClientId,
        operation: &'static str,
    ) -> Result<Client, AdminError> {
        self.state
            .backend
            .clients()
            .find(&self.tenant.id, id)
            .await
            .map_err(|error| AdminError::from_storage(operation, &error))?
            .ok_or(AdminError::NotFound)
    }

    // ---- accounts (`ast-f7m.6`) -------------------------------------------

    /// `GET /users` — this tenant's accounts, one cursor page at a time.
    ///
    /// The filtering and the cut are done **below the port**, unlike
    /// [`Self::list_clients`] beside it: a tenant holds clients in the tens
    /// and accounts in the millions, so a listing that read them all and
    /// filtered in memory would be a way to make this server allocate a
    /// directory on request. The cursor is the username, which is unique
    /// within a tenant and is the order the port lists in.
    async fn list_users(&self) -> Result<Response, AdminError> {
        let request = PageRequest::parse(
            query_value(&self.query, "cursor").as_deref(),
            query_value(&self.query, "limit").as_deref(),
        )?;
        // Decoded, unlike the cursor and the limit beside it: a search box
        // holds prose, and a browser sends prose percent-encoded.
        let term = clients::search_term(&query_value(&self.query, "q").unwrap_or_default());

        let rows = self
            .state
            .backend
            .users()
            .search(
                &self.tenant.id,
                &term,
                request.after.as_ref().map(Cursor::key),
                // One more than asked for, which is how the page knows whether
                // to mint a cursor without a second `COUNT`.
                request.limit + 1,
            )
            .await
            .map_err(|error| AdminError::from_storage(crate::USERS_LIST_ID, &error))?;

        let items: Vec<serde_json::Value> = rows.iter().map(users::summarise).collect();
        let page = Page::from_overfetched(items, request.limit, |row| {
            row["username"].as_str().unwrap_or_default().to_owned()
        });

        Ok(json_no_store(
            StatusCode::OK,
            &serde_json::to_value(&page).unwrap_or_else(|_| serde_json::json!({})),
        ))
    }

    /// `GET /users/{user_id}` — one account and its claims.
    async fn read_user(&self) -> Result<Response, AdminError> {
        let id = self.user_in_path()?;
        let user = self.load_user(id, crate::USER_READ_ID).await?;

        Ok(json_no_store(StatusCode::OK, &users::document(&user)))
    }

    /// `POST /users` — creates an account.
    ///
    /// Everything the body says is checked before anything is written, by
    /// [`users::accept_account`]: the password against the deployment's own
    /// policy (`ast-895`), the claim names against
    /// [`asterius_domain::ClaimName`], the sizes against the module's bounds.
    async fn create_user(&self, body: axum::body::Body) -> Result<Response, AdminError> {
        let requested: users::RequestedAccount = self.parse_body(body).await?;
        let account = users::accept_account(&requested, &self.tenant.id, self.now)?;

        // Read off the account before it is moved into the port: the response
        // is rendered from what came back, and this is only for the record.
        let created_with_a_password = account.password.is_some();

        let stored =
            self.state
                .backend
                .users()
                .create(account)
                .await
                .map_err(|error| match error {
                    DomainError::Conflict(message) => AdminError::Conflict(message),
                    other => AdminError::from_storage(crate::USER_CREATE_ID, &other),
                })?;

        // The username is a person's login identifier, so it goes in through
        // `subject_of` rather than `text`: a trail kept for years and read by
        // whoever is on call has no business being a directory of addresses.
        self.record_about(
            EventType::USER_CREATED,
            &stored.id,
            Detail::new()
                .label("operation", crate::USER_CREATE_ID)
                .flag("password", created_with_a_password)
                .flag("email_verified", stored.email_verified),
        )
        .await;

        Ok(json_no_store(
            StatusCode::CREATED,
            &users::document(&stored),
        ))
    }

    /// `PUT /users/{user_id}/claims` — replaces the claims and the flags.
    ///
    /// OIDC Core §5.1. A replacement rather than a merge, and the address and
    /// its `email_verified` are one document: see [`users::RequestedClaims`].
    async fn update_claims(&self, body: axum::body::Body) -> Result<Response, AdminError> {
        let id = self.user_in_path()?;
        let held = self.load_user(id, crate::USER_CLAIMS_UPDATE_ID).await?;
        let requested: users::RequestedClaims = self.parse_body(body).await?;

        let edited = users::apply_claims(&held, &requested, self.now)?;
        let saved = self
            .state
            .backend
            .users()
            .save(&edited)
            .await
            .map_err(|error| AdminError::from_storage(crate::USER_CLAIMS_UPDATE_ID, &error))?;

        // How many claims and whether the address is asserted verified, never
        // the values: a claim is personal data by definition.
        self.record_about(
            EventType::USER_CLAIMS_CHANGED,
            &saved.id,
            Detail::new()
                .label("operation", crate::USER_CLAIMS_UPDATE_ID)
                .number(
                    "claims_before",
                    i64::try_from(held.claims.len()).unwrap_or(-1),
                )
                .number(
                    "claims_after",
                    i64::try_from(saved.claims.len()).unwrap_or(-1),
                )
                .flag("email_verified", saved.email_verified)
                .flag("email_changed", held.email != saved.email),
        )
        .await;

        Ok(json_no_store(StatusCode::OK, &users::document(&saved)))
    }

    /// `PUT /users/{user_id}/status` — switches an account on or off.
    ///
    /// Disabling is three effects in one call, and the order is the point:
    /// the account is marked first, then its sessions are revoked, then the
    /// relying parties that took part are told (OIDC Back-Channel Logout 1.0
    /// §2.5). A relying party told that a session ended while the account
    /// could still sign in would be told something this server cannot stand
    /// behind — which is why the ordering lives below the port, in one
    /// implementation, rather than in three statements here.
    async fn update_status(&self, body: axum::body::Body) -> Result<Response, AdminError> {
        let id = self.user_in_path()?;
        let held = self.load_user(id, crate::USER_STATUS_UPDATE_ID).await?;
        let requested: users::RequestedStatus = self.parse_body(body).await?;

        let status = if requested.enabled {
            asterius_domain::UserStatus::Active
        } else {
            asterius_domain::UserStatus::Disabled
        };

        let terminated = self
            .state
            .backend
            .users()
            .set_status(&self.tenant.id, held.id, status, self.now)
            .await
            .map_err(|error| match error {
                DomainError::NotFound => AdminError::NotFound,
                other => AdminError::from_storage(crate::USER_STATUS_UPDATE_ID, &other),
            })?;

        // The trail half of the RISC `account-disabled` signal; see
        // [`EventType::ACCOUNT_DISABLED`] for where the transmitter will go.
        let event = if requested.enabled {
            EventType::ACCOUNT_ENABLED
        } else {
            EventType::ACCOUNT_DISABLED
        };
        self.record_about(
            event,
            &held.id,
            Detail::new()
                .label("operation", crate::USER_STATUS_UPDATE_ID)
                .label("status", status.as_str())
                .number(
                    "sessions_revoked",
                    i64::try_from(terminated.sessions_revoked).unwrap_or(-1),
                )
                .number(
                    "logout_tokens_queued",
                    i64::try_from(terminated.logout_tokens_queued).unwrap_or(-1),
                ),
        )
        .await;

        let reread = self
            .load_user(held.id, crate::USER_STATUS_UPDATE_ID)
            .await?;
        let mut document = users::document(&reread);
        if let Some(object) = document.as_object_mut() {
            object.insert(
                "terminated".to_owned(),
                users::termination_document(terminated),
            );
        }
        Ok(json_no_store(StatusCode::OK, &document))
    }

    /// `GET /users/{user_id}/roles` — who administers, and what they hold.
    async fn read_roles(&self) -> Result<Response, AdminError> {
        let id = self.user_in_path()?;
        let held = self.load_user(id, crate::USER_ROLES_READ_ID).await?;
        let roles = self
            .state
            .backend
            .roles(&self.tenant.id, held.id)
            .await
            .map_err(|error| AdminError::from_storage(crate::USER_ROLES_READ_ID, &error))?;

        Ok(json_no_store(
            StatusCode::OK,
            &users::roles_document(&roles, self.grantable()),
        ))
    }

    /// `PUT /users/{user_id}/roles` — replaces what an account administers.
    ///
    /// Three refusals, and each one closes a way of ending up with authority
    /// nobody granted.
    ///
    /// * **A role this build does not know is a 400**, never a silent drop: a
    ///   console sending `admin` must not be answered "done" and left showing
    ///   a role the account does not hold.
    /// * **Nobody edits their own roles.** Otherwise the weakest way in — a
    ///   session of somebody who may appoint administrators — is also a way to
    ///   appoint *themselves* more, and the trail would show an account that
    ///   granted itself its own authority. An administrator who needs their
    ///   own roles changed asks another one, which is what makes the record
    ///   evidence of a decision rather than of a click.
    /// * **A deployment-scoped role may only be granted by somebody who
    ///   already reaches the deployment.** The schema refuses it outside the
    ///   reserved tenant, but inside the reserved tenant a tenant admin would
    ///   otherwise be able to hand out authority over every tenant there is.
    ///
    /// Every added and every removed role is recorded separately
    /// ([`EventType::ROLE_GRANTED`], [`EventType::ROLE_REVOKED`]), because the
    /// question asked afterwards is "who was made an administrator, and by
    /// whom", and one record saying "the set changed" does not answer it.
    async fn update_roles(&self, body: axum::body::Body) -> Result<Response, AdminError> {
        let id = self.user_in_path()?;
        let held_by = self.load_user(id, crate::USER_ROLES_UPDATE_ID).await?;
        let requested: users::RequestedRoles = self.parse_body(body).await?;
        let wanted = requested.parse()?;

        if self.is_the_caller(held_by.id) {
            return Err(AdminError::Forbidden);
        }

        let before = self
            .state
            .backend
            .roles(&self.tenant.id, held_by.id)
            .await
            .map_err(|error| AdminError::from_storage(crate::USER_ROLES_UPDATE_ID, &error))?;

        let granting: Vec<asterius_domain::Role> = wanted
            .iter()
            .filter(|role| !before.contains(role))
            .copied()
            .collect();
        let revoking: Vec<asterius_domain::Role> = before
            .iter()
            .filter(|role| !wanted.contains(role))
            .copied()
            .collect();

        // Either direction on a deployment-scoped role is a change to who
        // administers every tenant, so both are gated on reaching the
        // deployment — taking one away is as much a decision as giving it.
        if granting
            .iter()
            .chain(revoking.iter())
            .any(|role| role.needs_the_reserved_tenant())
            && !self.grantable()
        {
            return Err(AdminError::Forbidden);
        }

        for role in &granting {
            self.state
                .backend
                .grant_role(&self.tenant.id, held_by.id, *role)
                .await
                .map_err(|error| match error {
                    DomainError::Conflict(message) => AdminError::Conflict(message),
                    other => AdminError::from_storage(crate::USER_ROLES_UPDATE_ID, &other),
                })?;
            self.record_about(
                EventType::ROLE_GRANTED,
                &held_by.id,
                Detail::new()
                    .label("operation", crate::USER_ROLES_UPDATE_ID)
                    .label("role", role.as_str()),
            )
            .await;
        }

        for role in &revoking {
            self.state
                .backend
                .revoke_role(&self.tenant.id, held_by.id, *role)
                .await
                .map_err(|error| match error {
                    // Somebody else took it away between the read and the
                    // write. The end state is the one that was asked for, so
                    // this is not a failure to report — but it is not recorded
                    // either, because this request did not revoke anything.
                    DomainError::NotFound => AdminError::NotFound,
                    other => AdminError::from_storage(crate::USER_ROLES_UPDATE_ID, &other),
                })?;
            self.record_about(
                EventType::ROLE_REVOKED,
                &held_by.id,
                Detail::new()
                    .label("operation", crate::USER_ROLES_UPDATE_ID)
                    .label("role", role.as_str()),
            )
            .await;
        }

        let after = self
            .state
            .backend
            .roles(&self.tenant.id, held_by.id)
            .await
            .map_err(|error| AdminError::from_storage(crate::USER_ROLES_UPDATE_ID, &error))?;

        Ok(json_no_store(
            StatusCode::OK,
            &users::roles_document(&after, self.grantable()),
        ))
    }

    /// Whether the caller may hand out authority over the whole deployment.
    ///
    /// Asked through `satisfies` rather than by looking for a role name, so
    /// that it is the same question `Reach::Deployment` routes ask.
    fn grantable(&self) -> bool {
        self.principal.held().satisfies(
            crate::rbac::Authority::new(crate::rbac::Reach::Deployment, "admin.roles:write"),
            &self.tenant.id,
        )
    }

    /// Whether this account is the one making the request.
    fn is_the_caller(&self, subject: asterius_domain::UserId) -> bool {
        matches!(
            self.principal,
            Principal::Console { user, .. } if *user == subject
        )
    }

    /// `GET /users/{user_id}/credentials` — what this account can sign in
    /// with.
    async fn read_credentials(&self) -> Result<Response, AdminError> {
        let id = self.user_in_path()?;
        let user = self.load_user(id, crate::USER_CREDENTIALS_READ_ID).await?;

        let credentials = self
            .state
            .backend
            .users()
            .credentials(&self.tenant.id, user.id)
            .await
            .map_err(|error| AdminError::from_storage(crate::USER_CREDENTIALS_READ_ID, &error))?;

        Ok(json_no_store(
            StatusCode::OK,
            &users::credentials_document(&credentials),
        ))
    }

    /// `DELETE /users/{user_id}/credentials/passkeys/{credential_id}` — blocks
    /// one passkey.
    async fn remove_passkey(&self) -> Result<Response, AdminError> {
        let credential = self
            .path
            .rsplit('/')
            .next()
            .and_then(|segment| uuid::Uuid::parse_str(segment).ok())
            .ok_or(AdminError::NotFound)?;
        let id = self.user_in_path()?;
        let user = self.load_user(id, crate::USER_PASSKEY_REMOVE_ID).await?;

        let removed = self
            .state
            .backend
            .users()
            .remove_passkey(&self.tenant.id, user.id, credential, self.now)
            .await
            .map_err(|error| AdminError::from_storage(crate::USER_PASSKEY_REMOVE_ID, &error))?;

        if !removed {
            // A credential this tenant does not hold, or one already blocked.
            // 404 either way: telling a caller which of the two it was would
            // answer "does this uuid name a credential" for anybody with the
            // authority to ask about one account.
            return Err(AdminError::NotFound);
        }

        self.record_about(
            EventType::CREDENTIAL_CHANGED,
            &user.id,
            Detail::new()
                .label("operation", crate::USER_PASSKEY_REMOVE_ID)
                .label("credential_kind", "passkey")
                .text("credential_id", credential.to_string()),
        )
        .await;

        Ok(json_no_store(
            StatusCode::OK,
            &serde_json::json!({"removed": true}),
        ))
    }

    /// `POST /users/{user_id}/credentials/password/reset` — forces a reset.
    ///
    /// Invalidates the password, ends the sessions and mails a recovery link
    /// (`ast-2vk.10`). It does not set a password an administrator chose; see
    /// [`asterius_domain::UserAdministration::force_password_reset`].
    async fn reset_password(&self) -> Result<Response, AdminError> {
        let id = self.user_in_path()?;
        let user = self.load_user(id, crate::USER_PASSWORD_RESET_ID).await?;

        let reset = self
            .state
            .backend
            .users()
            .force_password_reset(&self.tenant.id, user.id, self.now)
            .await
            .map_err(|error| match error {
                DomainError::NotFound => AdminError::NotFound,
                other => AdminError::from_storage(crate::USER_PASSWORD_RESET_ID, &other),
            })?;

        self.record_about(
            EventType::CREDENTIAL_CHANGED,
            &user.id,
            Detail::new()
                .label("operation", crate::USER_PASSWORD_RESET_ID)
                .label("credential_kind", "password")
                .flag("password_invalidated", reset.password_invalidated)
                .flag("recovery_sent", reset.recovery_sent)
                .number(
                    "sessions_revoked",
                    i64::try_from(reset.terminated.sessions_revoked).unwrap_or(-1),
                ),
        )
        .await;

        Ok(json_no_store(StatusCode::OK, &users::reset_document(reset)))
    }

    /// `GET /users/{user_id}/sessions` — this account's browser sessions.
    async fn list_sessions(&self) -> Result<Response, AdminError> {
        let id = self.user_in_path()?;
        let user = self.load_user(id, crate::USER_SESSIONS_LIST_ID).await?;

        let sessions = self
            .state
            .backend
            .users()
            .sessions(&self.tenant.id, user.id)
            .await
            .map_err(|error| AdminError::from_storage(crate::USER_SESSIONS_LIST_ID, &error))?;

        let items: Vec<serde_json::Value> = sessions
            .iter()
            .map(|session| users::session_document(session, self.now))
            .collect();

        Ok(json_no_store(
            StatusCode::OK,
            &serde_json::json!({"items": items}),
        ))
    }

    /// `DELETE /users/{user_id}/sessions/{sid}` — ends one session.
    ///
    /// The `sid` names the session and the account in the path is checked
    /// against it below the port, so a `sid` belonging to somebody else is a
    /// 404 rather than a revocation attributed to the wrong person.
    async fn revoke_session(&self) -> Result<Response, AdminError> {
        let sid = self
            .path
            .rsplit('/')
            .next()
            .filter(|segment| !segment.is_empty())
            .ok_or(AdminError::NotFound)?
            .to_owned();
        let id = self.user_in_path()?;
        let user = self.load_user(id, crate::USER_SESSION_REVOKE_ID).await?;

        let terminated = self
            .state
            .backend
            .users()
            .revoke_session(&self.tenant.id, &sid, self.now)
            .await
            .map_err(|error| match error {
                DomainError::NotFound => AdminError::NotFound,
                other => AdminError::from_storage(crate::USER_SESSION_REVOKE_ID, &other),
            })?;

        // The `sid` is published to every relying party that took part in the
        // session, so it is not a credential — but it is an identifier for a
        // person's browser, and `credential` is how the trail names *which*
        // one without recording it.
        self.record_about(
            EventType::SESSION_REVOKED,
            &user.id,
            Detail::new()
                .label("operation", crate::USER_SESSION_REVOKE_ID)
                .credential("sid", &sid)
                .number(
                    "logout_tokens_queued",
                    i64::try_from(terminated.logout_tokens_queued).unwrap_or(-1),
                ),
        )
        .await;

        Ok(json_no_store(
            StatusCode::OK,
            &users::termination_document(terminated),
        ))
    }

    /// `GET /users/{user_id}/grants` — the authorizations this account gave.
    async fn list_grants(&self) -> Result<Response, AdminError> {
        let id = self.user_in_path()?;
        let user = self.load_user(id, crate::USER_GRANTS_LIST_ID).await?;

        let grants = self
            .state
            .backend
            .users()
            .grants(&self.tenant.id, user.id)
            .await
            .map_err(|error| AdminError::from_storage(crate::USER_GRANTS_LIST_ID, &error))?;

        let items: Vec<serde_json::Value> = grants.iter().map(users::grant_document).collect();

        Ok(json_no_store(
            StatusCode::OK,
            &serde_json::json!({"items": items}),
        ))
    }

    /// `DELETE /users/{user_id}/grants/{grant_id}` — withdraws one
    /// authorization.
    ///
    /// Grant Management ID1 §6.5's semantics, through the same transaction the
    /// client-facing endpoint uses.
    async fn revoke_grant(&self) -> Result<Response, AdminError> {
        let named = self
            .path
            .rsplit('/')
            .next()
            .filter(|segment| !segment.is_empty())
            .ok_or(AdminError::NotFound)?
            .to_owned();
        // A grant id is a v4 UUID this server minted (`Grant::new`), so a
        // segment that is not one names nothing and is a 404 rather than a
        // query with a caller's string in it.
        if uuid::Uuid::parse_str(&named).is_err() {
            return Err(AdminError::NotFound);
        }
        let grant = asterius_domain::GrantId::new(named.clone());
        let id = self.user_in_path()?;
        let user = self.load_user(id, crate::USER_GRANT_REVOKE_ID).await?;

        let revoked = self
            .state
            .backend
            .users()
            .revoke_grant(&self.tenant.id, &grant, self.now)
            .await
            .map_err(|error| AdminError::from_storage(crate::USER_GRANT_REVOKE_ID, &error))?;

        if !revoked {
            // §6.6's 404, which is also what a second `DELETE` gets: a grant
            // that was live a moment ago and is not now.
            return Err(AdminError::NotFound);
        }

        self.record_about(
            EventType::GRANT_REVOKED,
            &user.id,
            Detail::new()
                .label("operation", crate::USER_GRANT_REVOKE_ID)
                .text("grant_id", grant.as_str()),
        )
        .await;

        Ok(json_no_store(
            StatusCode::OK,
            &serde_json::json!({"revoked": true}),
        ))
    }

    // -- application roles (`ast-095`) ----------------------------------

    /// The `{client_id}` in this request's path, as the catalogue it names.
    ///
    /// Read as *the segment after `clients`*, for the reason
    /// [`Handling::user_in_path`] gives: the routes under `/clients/…` have
    /// several tails and a rule that holds for all of them beats one
    /// `trim_end_matches` per route.
    fn client_owner_in_path(&self) -> Result<RoleOwner, AdminError> {
        let mut segments = self.path.split('/');
        segments
            .find(|segment| *segment == "clients")
            .and_then(|_| segments.next())
            .filter(|segment| !segment.is_empty())
            .map(|segment| RoleOwner::Client(asterius_domain::ClientId::new(segment.to_owned())))
            .ok_or(AdminError::NotFound)
    }

    /// The `{role_name}` in this request's path: the last segment.
    ///
    /// Every route carrying one ends with it, and a name outside the alphabet
    /// is a bad request rather than a 404 — see [`crate::roles::accept_name`].
    fn role_in_path(&self) -> Result<asterius_domain::RoleName, AdminError> {
        let last = self
            .path
            .rsplit('/')
            .next()
            .filter(|segment| !segment.is_empty())
            .ok_or(AdminError::NotFound)?;
        crate::roles::accept_name(last)
    }

    /// `GET /roles` and `GET /clients/{client_id}/roles` — one catalogue.
    async fn list_roles(&self, owner: RoleOwner) -> Result<Response, AdminError> {
        let operation = match owner {
            RoleOwner::Tenant => crate::APP_ROLES_LIST_ID,
            RoleOwner::Client(_) => crate::CLIENT_APP_ROLES_LIST_ID,
        };
        let catalogue = self
            .state
            .backend
            .application_roles()
            .catalogue(&self.tenant.id, &owner)
            .await
            .map_err(|error| AdminError::from_storage(operation, &error))?;

        Ok(json_no_store(
            StatusCode::OK,
            &serde_json::json!({
                "roles": catalogue
                    .iter()
                    .map(crate::roles::document)
                    .collect::<Vec<_>>(),
            }),
        ))
    }

    /// `POST /roles` and `POST /clients/{client_id}/roles` — defines a role.
    ///
    /// A name already in the catalogue answers 200 rather than 201 and does
    /// not overwrite the description: the catalogue ends in the state the
    /// caller asked for, and a repeated create must not quietly rewrite what
    /// somebody documented.
    async fn create_role(
        &self,
        owner: RoleOwner,
        body: axum::body::Body,
    ) -> Result<Response, AdminError> {
        let operation = match owner {
            RoleOwner::Tenant => crate::APP_ROLE_CREATE_ID,
            RoleOwner::Client(_) => crate::CLIENT_APP_ROLE_CREATE_ID,
        };
        let requested: crate::roles::RequestedRole = self.parse_body(body).await?;
        let role = crate::roles::accept_role(&requested, &self.tenant.id, owner, self.now)?;

        let created = self
            .state
            .backend
            .application_roles()
            .define(&role)
            .await
            .map_err(|error| match error {
                // A client that does not exist. Reported as a conflict rather
                // than a 404 because the thing addressed — the catalogue — is
                // exactly what is missing.
                DomainError::Conflict(message) => AdminError::Conflict(message),
                other => AdminError::from_storage(operation, &other),
            })?;

        if created {
            self.record(
                EventType::APP_ROLE_DEFINED,
                Detail::new()
                    .label("operation", operation)
                    .text("role", role.name.as_str())
                    .text(
                        "client_id",
                        role.owner
                            .client()
                            .map_or("", asterius_domain::ClientId::as_str),
                    ),
            )
            .await;
        }

        Ok(json_no_store(
            if created {
                StatusCode::CREATED
            } else {
                StatusCode::OK
            },
            &crate::roles::document(&role),
        ))
    }

    /// `DELETE /roles/{role_name}` and its per-client twin.
    ///
    /// 409 while any account still holds it. The refusal comes from the
    /// schema's `on delete restrict`, not from a read followed by a write:
    /// the case that matters is an assignment made while the deletion was
    /// being considered, and a check here would race with it.
    async fn delete_role(&self, owner: RoleOwner) -> Result<Response, AdminError> {
        let operation = match owner {
            RoleOwner::Tenant => crate::APP_ROLE_DELETE_ID,
            RoleOwner::Client(_) => crate::CLIENT_APP_ROLE_DELETE_ID,
        };
        let name = self.role_in_path()?;

        let removed = self
            .state
            .backend
            .application_roles()
            .remove(&self.tenant.id, &owner, &name)
            .await
            .map_err(|error| match error {
                DomainError::Conflict(_) => AdminError::Conflict(
                    "this role is still held by at least one account; withdraw it \
                     from them before deleting it"
                        .to_owned(),
                ),
                other => AdminError::from_storage(operation, &other),
            })?;

        if !removed {
            return Err(AdminError::NotFound);
        }

        self.record(
            EventType::APP_ROLE_REMOVED,
            Detail::new()
                .label("operation", operation)
                .text("role", name.as_str())
                .text(
                    "client_id",
                    owner.client().map_or("", asterius_domain::ClientId::as_str),
                ),
        )
        .await;

        Ok(json_no_store(
            StatusCode::OK,
            &serde_json::json!({"deleted": true}),
        ))
    }

    /// `GET /users/{user_id}/roles` — what one account holds.
    async fn list_held_roles(&self) -> Result<Response, AdminError> {
        let id = self.user_in_path()?;
        // Through the user lookup first, so that an account of another tenant
        // is a 404 here for the same reason it is everywhere else.
        let user = self.load_user(id, crate::USER_APP_ROLES_LIST_ID).await?;

        let held = self
            .state
            .backend
            .application_roles()
            .held_by(&self.tenant.id, user.id)
            .await
            .map_err(|error| AdminError::from_storage(crate::USER_APP_ROLES_LIST_ID, &error))?;

        Ok(json_no_store(
            StatusCode::OK,
            &crate::roles::held_document(&held),
        ))
    }

    /// `POST /users/{user_id}/roles` — gives an account a role.
    async fn assign_role(&self, body: axum::body::Body) -> Result<Response, AdminError> {
        let id = self.user_in_path()?;
        let user = self.load_user(id, crate::USER_APP_ROLE_ASSIGN_ID).await?;
        let requested: crate::roles::RequestedAssignment = self.parse_body(body).await?;
        let name = crate::roles::accept_name(&requested.name)?;
        let owner = crate::roles::accept_owner(requested.client_id.as_deref())?;

        let assigned = self
            .state
            .backend
            .application_roles()
            .assign(&self.tenant.id, user.id, &owner, &name, self.now)
            .await
            .map_err(|error| match error {
                // The role is not in the catalogue, or the client is not this
                // tenant's. Never a silent creation: assignment must not be a
                // way to invent a name that ends up in a token.
                DomainError::Conflict(_) => AdminError::Conflict(
                    "no such role in that catalogue; create it before assigning it".to_owned(),
                ),
                other => AdminError::from_storage(crate::USER_APP_ROLE_ASSIGN_ID, &other),
            })?;

        if assigned {
            self.record_about(
                EventType::APP_ROLE_ASSIGNED,
                &user.id,
                Detail::new()
                    .label("operation", crate::USER_APP_ROLE_ASSIGN_ID)
                    .text("role", name.as_str())
                    .text(
                        "client_id",
                        owner.client().map_or("", asterius_domain::ClientId::as_str),
                    ),
            )
            .await;
        }

        Ok(json_no_store(
            if assigned {
                StatusCode::CREATED
            } else {
                StatusCode::OK
            },
            &serde_json::json!({"assigned": true}),
        ))
    }

    /// `DELETE /users/{user_id}/roles/{role_name}` and its per-client twin.
    async fn withdraw_role(&self, owner: RoleOwner) -> Result<Response, AdminError> {
        let operation = match owner {
            RoleOwner::Tenant => crate::USER_APP_ROLE_WITHDRAW_ID,
            RoleOwner::Client(_) => crate::USER_CLIENT_APP_ROLE_WITHDRAW_ID,
        };
        let id = self.user_in_path()?;
        let user = self.load_user(id, operation).await?;
        let name = self.role_in_path()?;

        let withdrawn = self
            .state
            .backend
            .application_roles()
            .withdraw(&self.tenant.id, user.id, &owner, &name)
            .await
            .map_err(|error| AdminError::from_storage(operation, &error))?;

        if !withdrawn {
            return Err(AdminError::NotFound);
        }

        self.record_about(
            EventType::APP_ROLE_WITHDRAWN,
            &user.id,
            Detail::new()
                .label("operation", operation)
                .text("role", name.as_str())
                .text(
                    "client_id",
                    owner.client().map_or("", asterius_domain::ClientId::as_str),
                ),
        )
        .await;

        Ok(json_no_store(
            StatusCode::OK,
            &serde_json::json!({"withdrawn": true}),
        ))
    }

    /// The `{user_id}` in this request's path, whatever follows it.
    ///
    /// Read as *the segment after `users`* rather than by trimming a known
    /// tail, because the routes under `/users/{user_id}` have five different
    /// tails and two of them end in another identifier. One rule that holds
    /// for all of them beats five `trim_end_matches` calls, one of which would
    /// eventually be given the wrong literal and would silently read a
    /// credential id as an account id.
    fn user_in_path(&self) -> Result<asterius_domain::UserId, AdminError> {
        let mut segments = self.path.split('/');
        segments
            .find(|segment| *segment == "users")
            .and_then(|_| segments.next())
            .and_then(|segment| uuid::Uuid::parse_str(segment).ok())
            .map(asterius_domain::UserId::new)
            // A `user_id` that is not a UUID names nothing this server holds,
            // so it is the same answer as one that names an account of another
            // tenant: 404, and no hint about which it was.
            .ok_or(AdminError::NotFound)
    }

    /// One account of the tenant this request was routed to, or a 404.
    ///
    /// The tenant is a predicate on the query below the port, which is what
    /// makes "an administrator of A cannot reach an account of B by naming its
    /// uuid" a fact about the lookup rather than a check somebody remembered.
    async fn load_user(
        &self,
        id: asterius_domain::UserId,
        operation: &'static str,
    ) -> Result<asterius_domain::User, AdminError> {
        self.state
            .backend
            .users()
            .find(&self.tenant.id, id)
            .await
            .map_err(|error| AdminError::from_storage(operation, &error))?
            .ok_or(AdminError::NotFound)
    }

    /// The request body, under the shared size limit.
    async fn body_bytes(&self, body: axum::body::Body) -> Result<Vec<u8>, AdminError> {
        axum::body::to_bytes(body, MAX_BODY_BYTES)
            .await
            .map(|bytes| bytes.to_vec())
            .map_err(|_| AdminError::Invalid("the request body is too large".to_owned()))
    }

    /// `GET /keys` — this tenant's keys and its rotation policies.
    ///
    /// The tenant is the one the request was routed to and is not a parameter:
    /// the gate has already checked the caller against it, so there is no
    /// second authority check here and no path segment a caller could aim
    /// somewhere else. That is the difference between this and
    /// [`Self::read_tenant`], which names a tenant in its path and has to
    /// re-check for exactly that reason.
    async fn list_keys(&self) -> Result<Response, AdminError> {
        let backend = self.state.backend.keys();
        let records = backend
            .inventory(&self.tenant.id)
            .await
            .map_err(|error| AdminError::from_storage(crate::KEYS_LIST_ID, &error))?;
        let schedules = backend
            .schedules(&self.tenant.id)
            .await
            .map_err(|error| AdminError::from_storage(crate::KEYS_LIST_ID, &error))?;

        Ok(json_no_store(
            StatusCode::OK,
            &keys::inventory_document(&records, &schedules),
        ))
    }

    /// `GET /keys/jwks` — the JWK Set as it stands.
    ///
    /// Reads the inventory and filters, rather than asking for the published
    /// set: one port method feeds both screens, and `keys::jwks_document`
    /// applies the same `is_published` rule the JWKS endpoint applies. Two
    /// reads that could answer differently would make the preview a claim
    /// rather than a copy.
    async fn preview_jwks(&self) -> Result<Response, AdminError> {
        let records = self
            .state
            .backend
            .keys()
            .inventory(&self.tenant.id)
            .await
            .map_err(|error| AdminError::from_storage(crate::KEYS_JWKS_ID, &error))?;

        Ok(json_no_store(
            StatusCode::OK,
            &keys::jwks_document(&records),
        ))
    }

    /// `POST /keys/rotate` — stages a key, and promotes it if asked to.
    async fn rotate_key(&self, body: axum::body::Body) -> Result<Response, AdminError> {
        let request: keys::RotationRequest = self.parse_body(body).await?;
        let algorithm = request.algorithm()?;
        let activation = request.activation();

        let rotation = self
            .state
            .backend
            .keys()
            .rotate(
                &self.tenant.id,
                algorithm,
                activation,
                Actor::Admin(self.principal.audit_actor()),
                self.now,
            )
            .await
            .map_err(|error| AdminError::from_storage(crate::KEYS_ROTATE_ID, &error))?;

        // The rotation itself is already in the audit trail: the repository
        // records `key.rotated` with the `kid` values, under the actor passed
        // above, because a rotation that reached storage must be recorded
        // whether it came from this endpoint or from the sweep. What is added
        // here is the administrative fact — that a person pressed the button
        // and which activation they chose — which the key rows do not carry.
        self.record(
            EventType::ADMIN_CHANGED,
            Detail::new()
                .label("operation", crate::KEYS_ROTATE_ID)
                .text("alg", algorithm.as_str())
                .text(
                    "activation",
                    if activation == Activation::Immediate {
                        "immediate"
                    } else {
                        "on_schedule"
                    },
                ),
        )
        .await;

        Ok(json_no_store(
            StatusCode::OK,
            &keys::rotation_document(&rotation),
        ))
    }

    /// `POST /keys/{kid}/retire` — takes one key out of the published set.
    ///
    /// The `kid` comes out of the path and is used only to look a row up in
    /// this tenant's keys: [`KeyAdministration::retire`] is given the tenant
    /// the request was routed to, so a `kid` belonging to another tenant is a
    /// 404 here rather than a key somebody else loses.
    async fn retire_key(&self) -> Result<Response, AdminError> {
        let kid = self.key_in_path("/retire")?;

        let rotation = self
            .state
            .backend
            .keys()
            .retire(
                &self.tenant.id,
                &kid,
                Actor::Admin(self.principal.audit_actor()),
                self.now,
            )
            .await
            .map_err(|error| match error {
                // A key the tenant does not hold, and the active key, are both
                // answers the console has to show a person — not storage
                // failures. `from_storage` would flatten them into a 500.
                DomainError::NotFound => AdminError::NotFound,
                DomainError::Conflict(message) => AdminError::Conflict(message),
                other => AdminError::from_storage(crate::KEYS_RETIRE_ID, &other),
            })?;

        self.record(
            EventType::ADMIN_CHANGED,
            Detail::new()
                .label("operation", crate::KEYS_RETIRE_ID)
                .credential("kid", kid.as_str()),
        )
        .await;

        Ok(json_no_store(
            StatusCode::OK,
            &keys::rotation_document(&rotation),
        ))
    }

    /// The `kid` an action's path names, for `/keys/{kid}/{action}`.
    ///
    /// Taken as it arrived, with no decoding step. A `kid` this server issues
    /// is an RFC 7638 thumbprint — base64url, so `[A-Za-z0-9_-]`, none of which
    /// a URL encodes — and a segment carrying anything else names no key here
    /// and gets a 404 from the lookup. Adding a decoder would add a parser to
    /// the attack surface in order to accept identifiers this server never
    /// mints.
    ///
    /// One reader for both actions, so that a `kid` cannot mean one thing to
    /// retire and another to purge.
    fn key_in_path(&self, action: &str) -> Result<Kid, AdminError> {
        self.path
            .trim_end_matches(action)
            .rsplit('/')
            .next()
            .filter(|segment| !segment.is_empty())
            .map(Kid::new)
            .ok_or(AdminError::NotFound)
    }

    /// `POST /keys/{kid}/purge` — destroys one key's private material.
    ///
    /// The endpoint an operator reaches for when a key is believed to have
    /// leaked. What it guarantees, and what it cannot, is in the module
    /// documentation of `asterius_domain::keys` and in `docs/threat-model.md`;
    /// the short version is that this server stops signing with the key, stops
    /// publishing it, stops accepting its signatures and destroys the material,
    /// and that a token some resource server already accepted is beyond its
    /// reach.
    ///
    /// The reason is required — see [`keys::PurgeRequest`] — and the audit
    /// record the repository writes carries it.
    async fn purge_key(&self, body: axum::body::Body) -> Result<Response, AdminError> {
        let kid = self.key_in_path("/purge")?;
        let request: keys::PurgeRequest = self.parse_body(body).await?;
        let reason = request.reason()?;

        let purge = self
            .state
            .backend
            .keys()
            .purge(
                &self.tenant.id,
                &kid,
                &reason,
                Actor::Admin(self.principal.audit_actor()),
                self.now,
            )
            .await
            .map_err(|error| match error {
                // A key the tenant does not hold, and the active key, are both
                // answers the console has to show a person — not storage
                // failures. `from_storage` would flatten them into a 500.
                DomainError::NotFound => AdminError::NotFound,
                DomainError::Conflict(message) => AdminError::Conflict(message),
                other => AdminError::from_storage(crate::KEYS_PURGE_ID, &other),
            })?;

        // The destruction itself is already in the trail as `key.purged`, with
        // the reason, written by the repository — because a purge that reached
        // storage must be recorded whatever called it. What is added here is
        // the administrative fact: which console operation a person invoked.
        self.record(
            EventType::ADMIN_CHANGED,
            Detail::new()
                .label("operation", crate::KEYS_PURGE_ID)
                .credential("kid", kid.as_str()),
        )
        .await;

        Ok(json_no_store(StatusCode::OK, &keys::purge_document(&purge)))
    }

    /// `PUT /keys/schedule` — replaces one algorithm's rotation policy.
    async fn set_key_schedule(&self, body: axum::body::Body) -> Result<Response, AdminError> {
        let request: keys::ScheduleRequest = self.parse_body(body).await?;
        let algorithm = request.algorithm()?;
        let schedule = request.schedule()?;

        self.state
            .backend
            .keys()
            .set_schedule(&self.tenant.id, algorithm, schedule)
            .await
            .map_err(|error| match error {
                DomainError::Invalid { field, reason } => {
                    AdminError::Invalid(format!("{field}: {reason}"))
                }
                other => AdminError::from_storage(crate::KEYS_SCHEDULE_ID, &other),
            })?;

        self.record(
            EventType::ADMIN_CHANGED,
            Detail::new()
                .label("operation", crate::KEYS_SCHEDULE_ID)
                .text("alg", algorithm.as_str())
                .number(
                    "rotation_period_seconds",
                    schedule.rotation_period.whole_seconds(),
                )
                .number(
                    "propagation_period_seconds",
                    schedule.propagation_period.whole_seconds(),
                )
                .number(
                    "grace_period_seconds",
                    schedule.grace_period.whole_seconds(),
                ),
        )
        .await;

        Ok(json_no_store(
            StatusCode::OK,
            &keys::schedule_document(schedule),
        ))
    }

    /// `POST /keys/schedule/apply` — runs the rotation sweep now.
    ///
    /// Takes no body. There is nothing to choose: the pass is the tenant's
    /// whole schedule, every advertised algorithm, by the rules already stored.
    /// An `alg` here would be a different operation — one that rotates what a
    /// caller names — and that operation exists, it is `POST /keys/rotate`.
    ///
    /// Idempotent because the pass is: a second call finds nothing due and
    /// changes nothing, and says so in `changed`. The `Idempotency-Key` the
    /// console sends on every `POST` still applies, and covers the narrower
    /// case the header is for — the same request arriving twice because a
    /// connection dropped.
    async fn apply_key_schedule(&self) -> Result<Response, AdminError> {
        let passes = self
            .state
            .backend
            .keys()
            .apply_schedule_now(
                &self.tenant.id,
                Actor::Admin(self.principal.audit_actor()),
                self.now,
            )
            .await
            .map_err(|error| AdminError::from_storage(crate::KEYS_SCHEDULE_APPLY_ID, &error))?;

        // Whatever the pass moved is already in the trail as `key.rotated`,
        // written by the repository under the actor passed above. This record
        // is the other fact, and the one those cannot carry: that a person ran
        // the sweep by hand at this moment — including when it turned out
        // nothing was due, which is precisely the case that leaves no
        // `key.rotated` behind and precisely the case an incident review asks
        // about.
        let changed = passes.iter().any(|(_, pass)| !pass.is_empty());
        self.record(
            EventType::KEY_SCHEDULE_APPLIED,
            Detail::new()
                .label("operation", crate::KEYS_SCHEDULE_APPLY_ID)
                .label("changed", if changed { "yes" } else { "no" }),
        )
        .await;

        Ok(json_no_store(
            StatusCode::OK,
            &keys::schedule_applied_document(&passes),
        ))
    }

    /// Reads a JSON body, under the shared size limit.
    async fn parse_body<T: serde::de::DeserializeOwned>(
        &self,
        body: axum::body::Body,
    ) -> Result<T, AdminError> {
        let bytes = axum::body::to_bytes(body, MAX_BODY_BYTES)
            .await
            .map_err(|_| AdminError::Invalid("the request body is too large".to_owned()))?;
        serde_json::from_slice(&bytes)
            .map_err(|error| AdminError::Invalid(format!("the request body is not valid: {error}")))
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
    /// Writes one record about an *account*, naming the administrator behind
    /// it and the account it was done to.
    ///
    /// A second helper rather than an argument on [`Self::record`], because
    /// the two carry different things: an administrative change to a tenant
    /// has no subject, and an account event that lost its subject would be a
    /// record of something having happened to somebody.
    ///
    /// The subject is the account's uuid, which is the identifier ADR-0009
    /// says a trail records — never the username or the address, which are a
    /// person's and are fingerprinted when they appear at all.
    async fn record_about(
        &self,
        event_type: EventType,
        subject: &asterius_domain::UserId,
        detail: Detail,
    ) {
        let event = AuditEvent::new(
            self.tenant.id.clone(),
            event_type,
            Outcome::Success,
            Actor::Admin(self.principal.audit_actor()),
            self.now,
        )
        .subject(subject.as_uuid().to_string())
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

/// What `PUT /tenants/{tenant_id}/settings` takes.
///
/// `deny_unknown_fields`, so a console built against a newer server is told it
/// is sending something this one does not understand rather than having half
/// its form silently ignored.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestedSettings {
    #[serde(default)]
    disabled_features: Vec<String>,
    authorization_code_lifetime_seconds: i64,
    access_token_lifetime_seconds: i64,
    /// This tenant's registration policy (`ast-m9c.6`), as a document.
    ///
    /// Absent means "leave it as it is", not "clear it": the console's settings
    /// form and the registration policy are two screens, and a save from the
    /// first one must not silently reopen an endpoint the second one closed.
    #[serde(default)]
    registration_policy: Option<serde_json::Value>,
    /// The language this tenant's pages fall back to (`ast-ndk.5`), as a BCP 47
    /// tag from `ui_locales_supported`.
    ///
    /// Absent means "leave it as it is", like the registration policy and for
    /// the same reason.
    #[serde(default)]
    default_locale: Option<String>,
    /// The wording this tenant substitutes, as an object of message key to
    /// text.
    ///
    /// Absent means "leave it as it is". An empty object means "use the
    /// built-in wording for everything", which is a different instruction and
    /// one an administrator has to be able to give.
    #[serde(default)]
    messages: Option<serde_json::Value>,
}

/// A settings document as this API renders it.
///
/// The ceilings travel with it: a form that wants to grey out an impossible
/// value should not have to hard-code a number that lives in
/// [`asterius_domain::entities::tenant_settings`], and a console pinned to an
/// older release then shows the server's limits rather than its own.
fn render_settings(tenant: &TenantId, settings: &TenantSettings) -> serde_json::Value {
    use asterius_domain::entities::tenant_settings::{
        MAX_ACCESS_TOKEN_LIFETIME, MAX_AUTHORIZATION_CODE_LIFETIME,
    };

    serde_json::json!({
        "tenant_id": tenant.as_str(),
        "disabled_features": settings
            .disabled_features()
            .iter()
            .map(|feature| feature.as_str())
            .collect::<Vec<_>>(),
        "authorization_code_lifetime_seconds":
            settings.lifetimes().authorization_code().whole_seconds(),
        "access_token_lifetime_seconds": settings.lifetimes().access_token().whole_seconds(),
        // Rendered from the stored policy rather than echoed from a request,
        // so a console shows the rules that are in force — including the ones
        // a preset expanded into.
        "registration_policy": settings.registration().to_json(),
        // OIDC Core §3.1.2.1's last layer, and the wording this tenant has
        // substituted. Rendered from the stored settings rather than echoed
        // from a request, like the policy above.
        "default_locale": settings.default_locale().as_tag(),
        "messages": settings.messages().to_json(),
        "supported_locales": asterius_domain::Locale::SUPPORTED_TAGS,
        "limits": {
            "max_authorization_code_lifetime_seconds":
                MAX_AUTHORIZATION_CODE_LIFETIME.whole_seconds(),
            "max_access_token_lifetime_seconds": MAX_ACCESS_TOKEN_LIFETIME.whole_seconds(),
        },
    })
}

/// The before-and-after of a settings change, as the audit trail records it.
///
/// Only what changed, and nothing that is not a number or a flag name this
/// server owns: a settings document holds no secret today, and building the
/// record out of a closed vocabulary is what keeps that true when it holds
/// something else tomorrow. The unchanged members are left out on purpose —
/// a diff that repeats the whole document is one nobody reads.
fn settings_diff(tenant: &TenantId, before: &TenantSettings, after: &TenantSettings) -> Detail {
    let mut detail = Detail::new()
        .label("operation", crate::TENANT_SETTINGS_UPDATE_ID)
        .text("tenant", tenant.as_str());

    if before.disabled_features() != after.disabled_features() {
        detail = detail
            .text("disabled_features.before", feature_list(before))
            .text("disabled_features.after", feature_list(after));
    }
    if before.lifetimes().authorization_code() != after.lifetimes().authorization_code() {
        detail = detail
            .number(
                "authorization_code_lifetime_seconds.before",
                before.lifetimes().authorization_code().whole_seconds(),
            )
            .number(
                "authorization_code_lifetime_seconds.after",
                after.lifetimes().authorization_code().whole_seconds(),
            );
    }
    if before.lifetimes().access_token() != after.lifetimes().access_token() {
        detail = detail
            .number(
                "access_token_lifetime_seconds.before",
                before.lifetimes().access_token().whole_seconds(),
            )
            .number(
                "access_token_lifetime_seconds.after",
                after.lifetimes().access_token().whole_seconds(),
            );
    }
    detail
}

/// The disabled flags as one readable string; `none` rather than an empty
/// string, which in a trail is indistinguishable from a member that failed to
/// be written.
fn feature_list(settings: &TenantSettings) -> String {
    if settings.disabled_features().is_empty() {
        return "none".to_owned();
    }
    settings
        .disabled_features()
        .iter()
        .map(|feature| feature.as_str())
        .collect::<Vec<_>>()
        .join(",")
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
    // The gate reads an operation's effect through
    // `Effect::needs_csrf_token`, so the enum itself is only named by the
    // table-driven tests below.
    use crate::operations::Effect;
    use crate::rbac::Reach;
    use asterius_domain::entities::session::SessionId;
    use asterius_domain::keys::{
        KeyAdministration, KeyPurge, KeyPurpose, KeyRotation, KeyState, PublicKeyRecord,
        PurgeReason, RotationSchedule, SigningAlgorithm,
    };
    use asterius_domain::ports::TenantRepository;
    use asterius_domain::{
        AuditSink, AuthenticationMethod, DomainError, Feature, Issuer, Lifetimes, RateLimit,
        RateLimitStore, ReplayCheck, ReplayGuard, ReplayPurpose, Role, Session, TenantSettings,
        UserId,
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
        /// The users this fake says hold an enabled passkey, keyed
        /// `tenant|uuid` as `roles` is. Empty by default, which is a fresh
        /// deployment: the seeded admin has a password and nothing else
        /// (`ast-895`).
        passkeys: Mutex<std::collections::BTreeSet<String>>,
        events: Mutex<Vec<AuditEvent>>,
        counters: Mutex<BTreeMap<String, u32>>,
        claimed: Mutex<std::collections::BTreeSet<String>>,
        invalidations: Mutex<usize>,
        settings: Mutex<BTreeMap<String, TenantSettings>>,
        keys: Mutex<Vec<PublicKeyRecord>>,
        key_schedules: Mutex<BTreeMap<String, RotationSchedule>>,
        minted: Mutex<u32>,
        clients: Mutex<Vec<Client>>,
        capabilities: Mutex<asterius_domain::Capabilities>,
        /// Sectors this fake will confirm. A registration naming anything else
        /// is refused, which is how a test reaches OIDC Registration §5's
        /// refusal without a socket.
        confirmed_sectors: Mutex<Vec<String>>,
        /// The initial access tokens this fake has been asked to issue
        /// (`ast-cu3`), with the digest each was stored under.
        initial_access_tokens: Mutex<Vec<([u8; 32], asterius_domain::InitialAccessToken)>>,
        /// Deliveries this fake outbox has abandoned (`ast-0ju.9`), newest
        /// last. `World::new` seeds two `ssf.set` rows per tenant so that the
        /// retry and drop routes name something (`ast-f7m.8`).
        dead_letters: Mutex<Vec<asterius_domain::outbox::DeadLetter>>,
        /// The tenants' authorization policies (`ast-pj0.4`), keyed by
        /// tenant id. Absent is a tenant that has never written one, which is
        /// the state every tenant starts in.
        policies: Mutex<BTreeMap<String, asterius_domain::policy::StoredPolicy>>,
        /// The rows an operator put back on the schedule (`ast-f7m.8`).
        requeued: Mutex<Vec<i64>>,
        /// The rows an operator dropped.
        dropped: Mutex<Vec<i64>>,
        /// This deployment's SSF streams, as the console lists them
        /// (`ast-f7m.8`), keyed by nothing: a handful of rows.
        streams: Mutex<Vec<(TenantId, ssf::StreamSummary)>>,
        /// The verification events this fake transmitter queued: the stream
        /// and the `state`, if one was given.
        verifications: Mutex<Vec<(String, Option<String>)>>,
        /// This deployment's accounts (`ast-f7m.6`).
        accounts: Mutex<Vec<asterius_domain::User>>,
        /// The accounts holding a usable password, by local id.
        account_passwords: Mutex<std::collections::BTreeSet<uuid::Uuid>>,
        /// Every account's browser sessions, with how many relying parties
        /// took part in each.
        account_sessions: Mutex<Vec<SeededSession>>,
        /// Every account's passkeys.
        account_passkeys: Mutex<Vec<SeededPasskey>>,
        /// Every account's authorizations.
        account_grants: Mutex<Vec<asterius_domain::Grant>>,
        /// The accounts a recovery message was handed to the sender for.
        recovery_sent: Mutex<Vec<UserId>>,
        /// How many back-channel logout tokens this deployment has queued.
        ///
        /// The number the acceptance criterion is about: disabling an account
        /// must queue one per participating relying party, and a test can read
        /// it here without opening a socket — `outbound::post` refuses the
        /// loopback on purpose (`ast-o4u.2`).
        logout_tokens: Mutex<usize>,
        /// The subject of every evaluation the console's test bench asked
        /// about (`ast-f7m.9`), oldest first. What a test reads to assert that
        /// a request reached the PDP — and, by its emptiness, that one did
        /// not.
        trials: Mutex<Vec<String>>,
        /// Whether the bench's store is down, so that a test can assert a
        /// refusal is a refusal rather than a deny.
        trials_fail: Mutex<bool>,
        /// The application-role catalogues (`ast-095`).
        role_catalogue: Mutex<Vec<asterius_domain::ApplicationRole>>,
        /// Who holds what: the assignment rows, keyed by nothing — the tests
        /// that read them are about a handful of rows and a scan is clearer
        /// than an index that could be wrong.
        role_assignments: Mutex<Vec<SeededAssignment>>,
    }

    /// One application-role assignment held by the fake.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct SeededAssignment {
        tenant: TenantId,
        user: UserId,
        owner: RoleOwner,
        name: asterius_domain::RoleName,
    }

    /// One seeded session, and how many relying parties took part in it.
    #[derive(Debug, Clone)]
    struct SeededSession {
        tenant: TenantId,
        user: UserId,
        summary: asterius_domain::SessionSummary,
        /// How many participants registered a `backchannel_logout_uri`, which
        /// is how many logout tokens ending this session queues (§2.2: a
        /// client that registered none is not a participant).
        participants: usize,
    }

    /// One seeded passkey.
    #[derive(Debug, Clone)]
    struct SeededPasskey {
        tenant: TenantId,
        user: UserId,
        passkey: asterius_domain::PasskeySummary,
    }

    /// The subject this fake deployment holds in the group `admins`
    /// (`ast-f7m.9`).
    ///
    /// A fact of the fake tenant and not of any request: the bench's tests
    /// send bodies that do and do not name it, and none of them can make a
    /// subject a member by saying so.
    const GROUPED_SUBJECT: &str = "subject-in-admins";

    #[derive(Debug, Clone)]
    struct Handle(Arc<Fake>);

    #[async_trait::async_trait]
    impl asterius_domain::ports::PolicyStore for Handle {
        async fn load(
            &self,
            tenant: &TenantId,
        ) -> Result<Option<asterius_domain::policy::StoredPolicy>, DomainError> {
            Ok(self
                .0
                .policies
                .lock()
                .expect("an uncontended lock")
                .get(tenant.as_str())
                .cloned())
        }

        async fn replace(
            &self,
            tenant: &TenantId,
            rules: &asterius_domain::policy::RuleSet,
            now: OffsetDateTime,
        ) -> Result<(), DomainError> {
            self.0.policies.lock().expect("an uncontended lock").insert(
                tenant.as_str().to_owned(),
                asterius_domain::policy::StoredPolicy {
                    rules: rules.clone(),
                    updated_at: now,
                },
            );
            Ok(())
        }

        async fn clear(&self, tenant: &TenantId) -> Result<bool, DomainError> {
            Ok(self
                .0
                .policies
                .lock()
                .expect("an uncontended lock")
                .remove(tenant.as_str())
                .is_some())
        }
    }

    /// The PDP behind the console's test bench (`ast-f7m.9`), over the same
    /// document the admin routes write.
    ///
    /// A real [`asterius_domain::policy::DeclarativeEngine`] and not a canned
    /// answer: the test that matters is "what the bench says is what the
    /// stored rules say", and a fake that returned `permit` would assert
    /// nothing about the rules.
    ///
    /// The facts are attached here, as the composition root attaches them: a
    /// subject this fake tenant holds is in the group `admins`, and a request
    /// body can neither state that nor take it away.
    #[async_trait::async_trait]
    impl crate::backend::PolicyTrial for Handle {
        async fn decide(
            &self,
            tenant: &TenantId,
            request: &asterius_domain::policy::EvaluationRequest,
        ) -> Result<asterius_domain::policy::Decision, DomainError> {
            self.0
                .trials
                .lock()
                .expect("an uncontended lock")
                .push(request.subject.id().to_owned());
            if *self.0.trials_fail.lock().expect("an uncontended lock") {
                return Err(DomainError::Storage(Box::new(std::io::Error::other(
                    "the policy store is unreachable",
                ))));
            }

            let groups: Vec<String> = if request.subject.id() == GROUPED_SUBJECT {
                vec!["admins".to_owned()]
            } else {
                Vec::new()
            };
            let subject = request.subject.clone().with_groups(groups);
            let resolved = asterius_domain::policy::EvaluationRequest::new(
                subject,
                request.action.clone(),
                request.resource.clone(),
                request.context.clone(),
            );

            asterius_domain::ports::PolicyEngine::evaluate(
                &asterius_domain::policy::DeclarativeEngine::new(Arc::new(self.clone())),
                tenant,
                &resolved,
            )
            .await
        }
    }

    #[async_trait::async_trait]
    impl asterius_domain::outbox::DeadLetterQuery for Handle {
        async fn dead_letters(
            &self,
            _tenant: &TenantId,
            limit: u32,
        ) -> Result<Vec<asterius_domain::outbox::DeadLetter>, DomainError> {
            let letters = self.0.dead_letters.lock().expect("an uncontended lock");
            Ok(letters.iter().rev().take(limit as usize).cloned().collect())
        }

        async fn dead_letter(
            &self,
            _tenant: &TenantId,
            id: i64,
        ) -> Result<Option<asterius_domain::outbox::DeadLetter>, DomainError> {
            let letters = self.0.dead_letters.lock().expect("an uncontended lock");
            Ok(letters.iter().find(|letter| letter.id == id).cloned())
        }
    }

    #[async_trait::async_trait]
    impl asterius_domain::outbox::DeadLetterOperations for Handle {
        async fn requeue(
            &self,
            _tenant: &TenantId,
            id: i64,
            _now: OffsetDateTime,
        ) -> Result<bool, DomainError> {
            let mut letters = self.0.dead_letters.lock().expect("an uncontended lock");
            let before = letters.len();
            letters.retain(|letter| letter.id != id);
            let removed = letters.len() < before;
            if removed {
                self.0
                    .requeued
                    .lock()
                    .expect("an uncontended lock")
                    .push(id);
            }
            Ok(removed)
        }

        async fn drop_letter(&self, _tenant: &TenantId, id: i64) -> Result<bool, DomainError> {
            let mut letters = self.0.dead_letters.lock().expect("an uncontended lock");
            let before = letters.len();
            letters.retain(|letter| letter.id != id);
            let removed = letters.len() < before;
            if removed {
                self.0.dropped.lock().expect("an uncontended lock").push(id);
            }
            Ok(removed)
        }
    }

    #[async_trait::async_trait]
    impl ssf::SsfAdministration for Handle {
        async fn streams(&self, tenant: &TenantId) -> Result<Vec<ssf::StreamSummary>, DomainError> {
            let streams = self.0.streams.lock().expect("an uncontended lock");
            Ok(streams
                .iter()
                .filter(|(owner, _)| owner == tenant)
                .map(|(_, stream)| stream.clone())
                .collect())
        }

        async fn set_status(
            &self,
            tenant: &TenantId,
            stream: &asterius_ssf::stream::StreamId,
            status: asterius_ssf::stream::StreamStatus,
            reason: Option<&str>,
            now: OffsetDateTime,
        ) -> Result<bool, DomainError> {
            let mut streams = self.0.streams.lock().expect("an uncontended lock");
            let Some((_, held)) = streams
                .iter_mut()
                .find(|(owner, held)| owner == tenant && held.stream_id == *stream)
            else {
                return Ok(false);
            };
            held.status = status;
            held.reason = reason.map(ToOwned::to_owned);
            held.status_changed_at = Some(now);
            Ok(true)
        }

        async fn verify(
            &self,
            tenant: &TenantId,
            stream: &asterius_ssf::stream::StreamId,
            state: Option<&asterius_ssf::VerificationState>,
            _now: OffsetDateTime,
        ) -> Result<bool, DomainError> {
            let known = self
                .0
                .streams
                .lock()
                .expect("an uncontended lock")
                .iter()
                .any(|(owner, held)| owner == tenant && held.stream_id == *stream);
            if !known {
                return Ok(false);
            }
            self.0
                .verifications
                .lock()
                .expect("an uncontended lock")
                .push((
                    stream.as_str().to_owned(),
                    state.map(|state| state.as_str().to_owned()),
                ));
            Ok(true)
        }
    }

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
    impl asterius_domain::ports::TenantSettingsRepository for Handle {
        async fn settings(&self, tenant: &TenantId) -> Result<TenantSettings, DomainError> {
            Ok(self
                .0
                .settings
                .lock()
                .expect("an uncontended lock")
                .get(tenant.as_str())
                .cloned()
                .unwrap_or_default())
        }

        async fn save(
            &self,
            tenant: &TenantId,
            settings: &TenantSettings,
        ) -> Result<(), DomainError> {
            self.0
                .settings
                .lock()
                .expect("an uncontended lock")
                .insert(tenant.as_str().to_owned(), settings.clone());
            Ok(())
        }
    }

    /// The trail read back: the recorded events, newest first, through the
    /// reference semantics of the filter, with ids that are their position
    /// in the recording order — which is what the database's ids are.
    #[async_trait::async_trait]
    impl asterius_domain::audit::AuditQuery for Handle {
        async fn query(
            &self,
            tenant: &TenantId,
            filter: &asterius_domain::audit::AuditFilter,
            before: Option<i64>,
            limit: u32,
        ) -> Result<Vec<asterius_domain::audit::TrailEntry>, DomainError> {
            use asterius_domain::audit::chain::{EventHash, hash};
            Ok(self
                .0
                .events
                .lock()
                .expect("an uncontended lock")
                .iter()
                .enumerate()
                .rev()
                .filter(|(_, event)| event.tenant == *tenant)
                .map(|(index, event)| asterius_domain::audit::TrailEntry {
                    id: i64::try_from(index).expect("a small index") + 1,
                    hash: hash(EventHash::GENESIS, event),
                    record: asterius_domain::audit::AuditRecord::Event(Box::new(event.clone())),
                })
                .filter(|entry| before.is_none_or(|before| entry.id < before))
                .filter(|entry| {
                    entry
                        .record
                        .event()
                        .is_some_and(|event| filter.matches(event))
                })
                .take(limit.min(asterius_domain::audit::query::MAX_PAGE) as usize)
                .collect())
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

        async fn clear(
            &self,
            _tenant: &TenantId,
            bucket: &asterius_domain::Bucket,
        ) -> Result<(), DomainError> {
            self.0
                .counters
                .lock()
                .expect("an uncontended lock")
                .remove(bucket.as_str());
            Ok(())
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

    /// The key lifecycle, as the *port* promises it.
    ///
    /// A fake and not the PostgreSQL repository, so what the tests below prove
    /// is the API's half of the contract: which call the handler makes, what it
    /// renders, and what it refuses. That the adapter honours the same contract
    /// against a real schema — the advisory lock, the partial unique index, the
    /// grace period — is proved in `crates/store-pg/tests/database.rs`, which
    /// needs a database and runs in CI.
    ///
    /// The state transitions here are the ones
    /// [`KeyAdministration`] documents, and no others: staging publishes a
    /// `pending` key, immediate activation promotes it and pushes the incumbent
    /// to `retiring` — where it stays published — and the first key of an
    /// algorithm is born active because there is no cached JWK Set to protect.
    #[async_trait::async_trait]
    impl KeyAdministration for Handle {
        async fn inventory(&self, tenant: &TenantId) -> Result<Vec<PublicKeyRecord>, DomainError> {
            Ok(self
                .0
                .keys
                .lock()
                .expect("an uncontended lock")
                .iter()
                .filter(|record| &record.tenant == tenant)
                .cloned()
                .collect())
        }

        async fn schedules(
            &self,
            _tenant: &TenantId,
        ) -> Result<Vec<(SigningAlgorithm, RotationSchedule)>, DomainError> {
            let held = self.0.key_schedules.lock().expect("an uncontended lock");
            Ok(SigningAlgorithm::ALL
                .into_iter()
                .map(|algorithm| {
                    let schedule = held
                        .get(algorithm.as_str())
                        .copied()
                        .unwrap_or(default_schedule());
                    (algorithm, schedule)
                })
                .collect())
        }

        async fn set_schedule(
            &self,
            _tenant: &TenantId,
            algorithm: SigningAlgorithm,
            schedule: RotationSchedule,
        ) -> Result<(), DomainError> {
            self.0
                .key_schedules
                .lock()
                .expect("an uncontended lock")
                .insert(algorithm.as_str().to_owned(), schedule);
            Ok(())
        }

        async fn rotate(
            &self,
            tenant: &TenantId,
            algorithm: SigningAlgorithm,
            activation: Activation,
            _actor: Actor,
            _now: OffsetDateTime,
        ) -> Result<KeyRotation, DomainError> {
            let mut records = self.0.keys.lock().expect("an uncontended lock");
            let mut minted = self.0.minted.lock().expect("an uncontended lock");
            *minted += 1;
            let kid = Kid::new(format!("kid-{minted}"));

            // Scoped to the tenant, like the store is: a sibling's active key
            // must not decide whether *this* tenant's staged key is promoted.
            // The fake was tenant-blind here until `ast-f7m.5` seeded a key in
            // one tenant and watched a rotation in another change behaviour.
            let holds_active = records.iter().any(|record| {
                &record.tenant == tenant
                    && record.algorithm == algorithm
                    && record.state == KeyState::Active
            });

            // A tenant with no active key has published no JWK Set anyone could
            // have cached, so there is nothing for the propagation period to
            // protect.
            let promote = activation == Activation::Immediate || !holds_active;

            let mut superseded = None;
            if promote {
                for record in records.iter_mut() {
                    if record.algorithm == algorithm && record.state == KeyState::Active {
                        record.state = KeyState::Retiring;
                        superseded = Some(record.kid.clone());
                    }
                }
            }

            records.push(PublicKeyRecord {
                tenant: tenant.clone(),
                kid: kid.clone(),
                algorithm,
                purpose: KeyPurpose::Signing,
                state: if promote {
                    KeyState::Active
                } else {
                    KeyState::Pending
                },
                public_jwk: serde_json::json!({
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "use": "sig",
                    "kid": kid.as_str(),
                    "x": format!("public-{kid}"),
                    // A row carrying private material, because a `jsonb` column
                    // is something an incident can put anything into. Nothing
                    // this API renders may contain it.
                    "d": "PRIVATE-KEY-MATERIAL",
                }),
                created_at: OffsetDateTime::UNIX_EPOCH,
            });

            Ok(KeyRotation {
                created: Some(kid.clone()),
                activated: promote.then_some(kid),
                superseded,
                retired: Vec::new(),
            })
        }

        /// One pass per algorithm, by the one rule the store's pass turns on:
        /// a schedule stages a key when it is due, and does nothing when it is
        /// not. That is enough to model what the tests read — a due schedule
        /// rotates, a schedule just rotated does not — and modelling the
        /// propagation and grace periods too would be a second implementation
        /// of the lifecycle in a test double.
        async fn apply_schedule_now(
            &self,
            tenant: &TenantId,
            actor: Actor,
            now: OffsetDateTime,
        ) -> Result<Vec<(SigningAlgorithm, KeyRotation)>, DomainError> {
            let mut passes = Vec::with_capacity(SigningAlgorithm::ALL.len());
            for algorithm in SigningAlgorithm::ALL {
                let schedule = {
                    let held = self.0.key_schedules.lock().expect("an uncontended lock");
                    held.get(algorithm.as_str())
                        .copied()
                        .unwrap_or(default_schedule())
                };

                if !schedule.is_due(now) {
                    passes.push((algorithm, KeyRotation::default()));
                    continue;
                }

                let pass = self
                    .rotate(
                        tenant,
                        algorithm,
                        Activation::OnSchedule,
                        actor.clone(),
                        now,
                    )
                    .await?;
                self.0
                    .key_schedules
                    .lock()
                    .expect("an uncontended lock")
                    .insert(
                        algorithm.as_str().to_owned(),
                        RotationSchedule {
                            last_rotated_at: Some(now),
                            ..schedule
                        },
                    );
                passes.push((algorithm, pass));
            }
            Ok(passes)
        }

        async fn retire(
            &self,
            tenant: &TenantId,
            kid: &Kid,
            _actor: Actor,
            _now: OffsetDateTime,
        ) -> Result<KeyRotation, DomainError> {
            let mut records = self.0.keys.lock().expect("an uncontended lock");
            // Scoped to the tenant the request was routed to, so a `kid` copied
            // from a sibling tenant's console is a 404 and not a key somebody
            // else loses.
            let record = records
                .iter_mut()
                .find(|record| &record.kid == kid && &record.tenant == tenant)
                .ok_or(DomainError::NotFound)?;

            match record.state {
                KeyState::Retired | KeyState::Purged => Ok(KeyRotation::default()),
                KeyState::Active => Err(DomainError::Conflict(format!(
                    "key {kid} is the active {} key",
                    record.algorithm
                ))),
                KeyState::Pending | KeyState::Retiring => {
                    record.state = KeyState::Retired;
                    Ok(KeyRotation {
                        retired: vec![kid.clone()],
                        ..KeyRotation::default()
                    })
                }
            }
        }

        /// Destroys the private material — which this fake models the only way
        /// it can: the record it holds carries a `public_jwk` with a `d` member
        /// in it, standing in for the sealed column, and a purge takes that
        /// member out. The property the tests read is the state.
        async fn purge(
            &self,
            tenant: &TenantId,
            kid: &Kid,
            _reason: &PurgeReason,
            _actor: Actor,
            _now: OffsetDateTime,
        ) -> Result<KeyPurge, DomainError> {
            let mut records = self.0.keys.lock().expect("an uncontended lock");
            let record = records
                .iter_mut()
                .find(|record| &record.kid == kid && &record.tenant == tenant)
                .ok_or(DomainError::NotFound)?;

            let previous_state = record.state;
            match previous_state {
                KeyState::Active => Err(DomainError::Conflict(format!(
                    "key {kid} is the active {} key",
                    record.algorithm
                ))),
                KeyState::Purged => Ok(KeyPurge {
                    kid: kid.clone(),
                    previous_state,
                    destroyed: false,
                }),
                KeyState::Pending | KeyState::Retiring | KeyState::Retired => {
                    record.state = KeyState::Purged;
                    if let Some(object) = record.public_jwk.as_object_mut() {
                        object.remove("d");
                    }
                    Ok(KeyPurge {
                        kid: kid.clone(),
                        previous_state,
                        destroyed: true,
                    })
                }
            }
        }
    }

    /// The client store, and the sector check, as the composition root would
    /// provide them.
    ///
    /// `create` refuses a `client_id` that is taken and `replace` refuses one
    /// that is absent, because PostgreSQL does, and a fake that was gentler
    /// than the store would let a handler's error mapping go untested.
    #[async_trait::async_trait]
    impl asterius_domain::ports::ClientAdministration for Handle {
        async fn list(&self, tenant: &TenantId) -> Result<Vec<Client>, DomainError> {
            let mut clients: Vec<Client> = self
                .0
                .clients
                .lock()
                .expect("an uncontended lock")
                .iter()
                .filter(|client| &client.tenant == tenant)
                .cloned()
                .collect();
            clients.sort_by(|a, b| a.id.as_str().cmp(b.id.as_str()));
            Ok(clients)
        }

        async fn find(
            &self,
            tenant: &TenantId,
            client_id: &asterius_domain::ClientId,
        ) -> Result<Option<Client>, DomainError> {
            Ok(self
                .0
                .clients
                .lock()
                .expect("an uncontended lock")
                .iter()
                .find(|client| &client.tenant == tenant && &client.id == client_id)
                .cloned())
        }

        async fn create(&self, client: &Client) -> Result<Client, DomainError> {
            let mut clients = self.0.clients.lock().expect("an uncontended lock");
            if clients
                .iter()
                .any(|held| held.tenant == client.tenant && held.id == client.id)
            {
                return Err(DomainError::Conflict("client_id is taken".to_owned()));
            }
            clients.push(client.clone());
            Ok(client.clone())
        }

        async fn replace(&self, client: &Client) -> Result<Client, DomainError> {
            let mut clients = self.0.clients.lock().expect("an uncontended lock");
            let Some(held) = clients
                .iter_mut()
                .find(|held| held.tenant == client.tenant && held.id == client.id)
            else {
                return Err(DomainError::NotFound);
            };
            *held = client.clone();
            Ok(held.clone())
        }

        async fn verify_sector(
            &self,
            registration: &ClientRegistration,
        ) -> Result<(), asterius_domain::ClientMetadataError> {
            let Some(uri) = registration.sector_identifier_uri_to_verify() else {
                return Ok(());
            };
            if self
                .0
                .confirmed_sectors
                .lock()
                .expect("an uncontended lock")
                .iter()
                .any(|confirmed| confirmed == uri)
            {
                return Ok(());
            }
            Err(asterius_domain::ClientMetadataError::unreachable(
                "sector_identifier_uri",
            ))
        }
    }

    /// The fake's initial access token store (`ast-cu3`).
    ///
    /// Only what the admin API exercises is implemented. `reserve` and
    /// `release` belong to `POST /register`, which is a different crate's
    /// endpoint and has its own fake in `crates/server/tests/register.rs`;
    /// stubbing them here with something permissive would be a second,
    /// gentler definition of the quota rule.
    #[async_trait::async_trait]
    impl asterius_domain::ports::InitialAccessTokenStore for Handle {
        async fn issue(
            &self,
            token: &asterius_domain::NewInitialAccessToken,
        ) -> Result<asterius_domain::InitialAccessToken, DomainError> {
            let stored = asterius_domain::InitialAccessToken {
                id: uuid::Uuid::new_v4(),
                tenant: token.tenant.clone(),
                label: token.label.clone(),
                uses: 0,
                max_uses: token.max_uses,
                expires_at: token.expires_at,
                created_at: OffsetDateTime::from_unix_timestamp(1_700_000_000)
                    .expect("a fixed instant"),
            };
            self.0
                .initial_access_tokens
                .lock()
                .expect("an uncontended lock")
                .push((token.digest, stored.clone()));
            Ok(stored)
        }

        async fn reserve(
            &self,
            _tenant: &TenantId,
            _digest: &[u8; 32],
            _now: OffsetDateTime,
        ) -> Result<asterius_domain::InitialAccessTokenReservation, DomainError> {
            unimplemented!("the admin API never spends a token")
        }

        async fn release(&self, _tenant: &TenantId, _id: uuid::Uuid) -> Result<(), DomainError> {
            unimplemented!("the admin API never spends a token")
        }

        async fn list(
            &self,
            tenant: &TenantId,
        ) -> Result<Vec<asterius_domain::InitialAccessToken>, DomainError> {
            Ok(self
                .0
                .initial_access_tokens
                .lock()
                .expect("an uncontended lock")
                .iter()
                .filter(|(_, token)| &token.tenant == tenant)
                .map(|(_, token)| token.clone())
                .collect())
        }
    }

    /// The fake's account directory (`ast-f7m.6`).
    ///
    /// It implements the *effects* the port promises and not only the writes,
    /// because those effects are what the routes are asserted on: disabling an
    /// account revokes its sessions here too, and revoking a session counts one
    /// queued logout token per participating relying party. A fake that only
    /// stored a status would let every ordering test pass while the real
    /// adapter forgot to notify anybody.
    ///
    /// What it is *not* is a second implementation of back-channel logout: the
    /// token itself, its claims and its signature are
    /// `asterius_server::backchannel`'s, tested there against a fake outbox.
    /// What is counted here is the promise the port makes to this crate.
    #[async_trait::async_trait]
    impl asterius_domain::UserAdministration for Handle {
        async fn search(
            &self,
            tenant: &TenantId,
            term: &str,
            after: Option<&str>,
            limit: usize,
        ) -> Result<Vec<asterius_domain::User>, DomainError> {
            let accounts = self.0.accounts.lock().expect("an uncontended lock");
            let mut matched: Vec<asterius_domain::User> = accounts
                .iter()
                .filter(|user| &user.tenant == tenant)
                .filter(|user| crate::users::matches(user, term))
                .filter(|user| after.is_none_or(|cursor| user.username.as_str() > cursor))
                .cloned()
                .collect();
            matched.sort_by(|a, b| a.username.cmp(&b.username));
            matched.truncate(limit);
            Ok(matched)
        }

        async fn find(
            &self,
            tenant: &TenantId,
            id: UserId,
        ) -> Result<Option<asterius_domain::User>, DomainError> {
            Ok(self
                .0
                .accounts
                .lock()
                .expect("an uncontended lock")
                .iter()
                .find(|user| &user.tenant == tenant && user.id == id)
                .cloned())
        }

        async fn create(
            &self,
            account: asterius_domain::NewAccount,
        ) -> Result<asterius_domain::User, DomainError> {
            let mut accounts = self.0.accounts.lock().expect("an uncontended lock");
            if accounts.iter().any(|held| {
                held.tenant == account.user.tenant && held.username == account.user.username
            }) {
                return Err(DomainError::Conflict("username is taken".to_owned()));
            }
            if account.password.is_some() {
                self.0
                    .account_passwords
                    .lock()
                    .expect("an uncontended lock")
                    .insert(*account.user.id.as_uuid());
            }
            accounts.push(account.user.clone());
            Ok(account.user)
        }

        async fn set_status(
            &self,
            tenant: &TenantId,
            id: UserId,
            status: asterius_domain::UserStatus,
            now: OffsetDateTime,
        ) -> Result<asterius_domain::Terminated, DomainError> {
            {
                let mut accounts = self.0.accounts.lock().expect("an uncontended lock");
                let held = accounts
                    .iter_mut()
                    .find(|user| &user.tenant == tenant && user.id == id)
                    .ok_or(DomainError::NotFound)?;
                held.status = status;
                held.updated_at = now;
            }
            if status == asterius_domain::UserStatus::Disabled {
                return Ok(self.terminate(tenant, id, "account_closed", now));
            }
            Ok(asterius_domain::Terminated::default())
        }

        async fn save(
            &self,
            user: &asterius_domain::User,
        ) -> Result<asterius_domain::User, DomainError> {
            let mut accounts = self.0.accounts.lock().expect("an uncontended lock");
            let held = accounts
                .iter_mut()
                .find(|held| held.tenant == user.tenant && held.id == user.id)
                .ok_or(DomainError::NotFound)?;
            *held = user.clone();
            Ok(held.clone())
        }

        async fn sessions(
            &self,
            tenant: &TenantId,
            user: UserId,
        ) -> Result<Vec<asterius_domain::SessionSummary>, DomainError> {
            Ok(self
                .0
                .account_sessions
                .lock()
                .expect("an uncontended lock")
                .iter()
                .filter(|row| &row.tenant == tenant && row.user == user)
                .map(|row| row.summary.clone())
                .collect())
        }

        async fn revoke_session(
            &self,
            tenant: &TenantId,
            public_sid: &str,
            now: OffsetDateTime,
        ) -> Result<asterius_domain::Terminated, DomainError> {
            let mut sessions = self.0.account_sessions.lock().expect("an uncontended lock");
            let row = sessions
                .iter_mut()
                .find(|row| &row.tenant == tenant && row.summary.public_sid == public_sid)
                .ok_or(DomainError::NotFound)?;
            if row.summary.revoked.is_some() {
                return Ok(asterius_domain::Terminated::default());
            }
            row.summary.revoked = Some((now, "administrative"));
            let queued = row.participants;
            *self.0.logout_tokens.lock().expect("an uncontended lock") += queued;
            Ok(asterius_domain::Terminated {
                sessions_revoked: 1,
                logout_tokens_queued: queued,
            })
        }

        async fn grants(
            &self,
            tenant: &TenantId,
            user: UserId,
        ) -> Result<Vec<asterius_domain::Grant>, DomainError> {
            Ok(self
                .0
                .account_grants
                .lock()
                .expect("an uncontended lock")
                .iter()
                .filter(|grant| &grant.tenant == tenant && grant.user == Some(user))
                .cloned()
                .collect())
        }

        async fn revoke_grant(
            &self,
            tenant: &TenantId,
            grant: &asterius_domain::GrantId,
            now: OffsetDateTime,
        ) -> Result<bool, DomainError> {
            let mut grants = self.0.account_grants.lock().expect("an uncontended lock");
            let Some(held) = grants
                .iter_mut()
                .find(|held| &held.tenant == tenant && &held.id == grant)
            else {
                return Ok(false);
            };
            if held.revoked_at.is_some() {
                return Ok(false);
            }
            held.revoked_at = Some(now);
            Ok(true)
        }

        async fn credentials(
            &self,
            tenant: &TenantId,
            user: UserId,
        ) -> Result<asterius_domain::CredentialSummary, DomainError> {
            let passkeys = self
                .0
                .account_passkeys
                .lock()
                .expect("an uncontended lock")
                .iter()
                .filter(|row| &row.tenant == tenant && row.user == user)
                .map(|row| row.passkey.clone())
                .collect();
            Ok(asterius_domain::CredentialSummary {
                password: self
                    .0
                    .account_passwords
                    .lock()
                    .expect("an uncontended lock")
                    .contains(user.as_uuid()),
                passkeys,
            })
        }

        async fn remove_passkey(
            &self,
            tenant: &TenantId,
            user: UserId,
            credential: uuid::Uuid,
            now: OffsetDateTime,
        ) -> Result<bool, DomainError> {
            let mut passkeys = self.0.account_passkeys.lock().expect("an uncontended lock");
            let Some(row) = passkeys.iter_mut().find(|row| {
                &row.tenant == tenant && row.user == user && row.passkey.id == credential
            }) else {
                return Ok(false);
            };
            if row.passkey.disabled_at.is_some() {
                return Ok(false);
            }
            row.passkey.disabled_at = Some(now);
            Ok(true)
        }

        async fn force_password_reset(
            &self,
            tenant: &TenantId,
            user: UserId,
            now: OffsetDateTime,
        ) -> Result<asterius_domain::PasswordReset, DomainError> {
            let held = self
                .0
                .accounts
                .lock()
                .expect("an uncontended lock")
                .iter()
                .find(|held| &held.tenant == tenant && held.id == user)
                .cloned()
                .ok_or(DomainError::NotFound)?;

            let invalidated = self
                .0
                .account_passwords
                .lock()
                .expect("an uncontended lock")
                .remove(user.as_uuid());
            let recovery_sent = held.email.is_some();
            if recovery_sent {
                self.0
                    .recovery_sent
                    .lock()
                    .expect("an uncontended lock")
                    .push(user);
            }
            Ok(asterius_domain::PasswordReset {
                password_invalidated: invalidated,
                recovery_sent,
                terminated: self.terminate(tenant, user, "credential_change", now),
            })
        }
    }

    impl Handle {
        /// Revokes every live session of `user`, counting the logout tokens
        /// each participating relying party would be queued.
        fn terminate(
            &self,
            tenant: &TenantId,
            user: UserId,
            reason: &'static str,
            now: OffsetDateTime,
        ) -> asterius_domain::Terminated {
            let mut sessions = self.0.account_sessions.lock().expect("an uncontended lock");
            let mut terminated = asterius_domain::Terminated::default();
            for row in sessions
                .iter_mut()
                .filter(|row| &row.tenant == tenant && row.user == user)
                .filter(|row| row.summary.revoked.is_none())
            {
                row.summary.revoked = Some((now, reason));
                terminated.sessions_revoked += 1;
                terminated.logout_tokens_queued += row.participants;
            }
            *self.0.logout_tokens.lock().expect("an uncontended lock") +=
                terminated.logout_tokens_queued;
            terminated
        }
    }

    fn default_schedule() -> RotationSchedule {
        RotationSchedule {
            rotation_period: time::Duration::days(90),
            propagation_period: time::Duration::minutes(15),
            grace_period: time::Duration::days(7),
            last_rotated_at: None,
        }
    }

    /// The catalogues and assignments, in memory.
    ///
    /// It reproduces the two refusals the schema is responsible for, because
    /// they are the two the handlers translate: assigning a role that is not
    /// in the catalogue, and deleting one that somebody still holds. A fake
    /// that quietly allowed either would let a handler test pass while the
    /// real adapter answered 409.
    #[async_trait::async_trait]
    impl asterius_domain::ApplicationRoleDirectory for Handle {
        async fn define(
            &self,
            role: &asterius_domain::ApplicationRole,
        ) -> Result<bool, DomainError> {
            let mut catalogue = self.0.role_catalogue.lock().expect("an uncontended lock");
            if catalogue.iter().any(|held| {
                held.tenant == role.tenant && held.owner == role.owner && held.name == role.name
            }) {
                return Ok(false);
            }
            catalogue.push(role.clone());
            Ok(true)
        }

        async fn catalogue(
            &self,
            tenant: &TenantId,
            owner: &RoleOwner,
        ) -> Result<Vec<asterius_domain::ApplicationRole>, DomainError> {
            let catalogue = self.0.role_catalogue.lock().expect("an uncontended lock");
            let mut rows: Vec<asterius_domain::ApplicationRole> = catalogue
                .iter()
                .filter(|held| &held.tenant == tenant && &held.owner == owner)
                .cloned()
                .collect();
            rows.sort_by(|a, b| a.name.cmp(&b.name));
            Ok(rows)
        }

        async fn remove(
            &self,
            tenant: &TenantId,
            owner: &RoleOwner,
            name: &asterius_domain::RoleName,
        ) -> Result<bool, DomainError> {
            let held = self
                .0
                .role_assignments
                .lock()
                .expect("an uncontended lock")
                .iter()
                .any(|row| &row.tenant == tenant && &row.owner == owner && &row.name == name);
            if held {
                // What `on delete restrict` produces.
                return Err(DomainError::Conflict("user_tenant_roles".to_owned()));
            }
            let mut catalogue = self.0.role_catalogue.lock().expect("an uncontended lock");
            let before = catalogue.len();
            catalogue.retain(|role| {
                !(&role.tenant == tenant && &role.owner == owner && &role.name == name)
            });
            Ok(catalogue.len() < before)
        }

        async fn assign(
            &self,
            tenant: &TenantId,
            user: UserId,
            owner: &RoleOwner,
            name: &asterius_domain::RoleName,
            _now: OffsetDateTime,
        ) -> Result<bool, DomainError> {
            let defined = self
                .0
                .role_catalogue
                .lock()
                .expect("an uncontended lock")
                .iter()
                .any(|role| &role.tenant == tenant && &role.owner == owner && &role.name == name);
            if !defined {
                // What the foreign key produces.
                return Err(DomainError::Conflict("user_tenant_roles".to_owned()));
            }
            let row = SeededAssignment {
                tenant: tenant.clone(),
                user,
                owner: owner.clone(),
                name: name.clone(),
            };
            let mut assignments = self.0.role_assignments.lock().expect("an uncontended lock");
            if assignments.contains(&row) {
                return Ok(false);
            }
            assignments.push(row);
            Ok(true)
        }

        async fn withdraw(
            &self,
            tenant: &TenantId,
            user: UserId,
            owner: &RoleOwner,
            name: &asterius_domain::RoleName,
        ) -> Result<bool, DomainError> {
            let mut assignments = self.0.role_assignments.lock().expect("an uncontended lock");
            let before = assignments.len();
            assignments.retain(|row| {
                !(&row.tenant == tenant
                    && row.user == user
                    && &row.owner == owner
                    && &row.name == name)
            });
            Ok(assignments.len() < before)
        }

        async fn held_by(
            &self,
            tenant: &TenantId,
            user: UserId,
        ) -> Result<asterius_domain::HeldRoles, DomainError> {
            let mut held = asterius_domain::HeldRoles::default();
            for row in self
                .0
                .role_assignments
                .lock()
                .expect("an uncontended lock")
                .iter()
                .filter(|row| &row.tenant == tenant && row.user == user)
            {
                match &row.owner {
                    RoleOwner::Tenant => {
                        held.tenant.insert(row.name.clone());
                    }
                    RoleOwner::Client(client) => {
                        held.clients
                            .entry(client.clone())
                            .or_default()
                            .insert(row.name.clone());
                    }
                }
            }
            Ok(held)
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

        async fn end_session(
            &self,
            tenant: &TenantId,
            id_digest: &str,
            reason: SessionRevocation,
            now: OffsetDateTime,
        ) -> Result<(), DomainError> {
            // The store's own rule, kept here so the fake cannot be gentler
            // than PostgreSQL: the first reason for a revocation stands.
            if let Some(session) = self
                .0
                .sessions
                .lock()
                .expect("an uncontended lock")
                .get_mut(id_digest)
                .filter(|session| &session.tenant == tenant)
                && session.revoked.is_none()
            {
                session.revoked = Some((now, reason));
            }
            Ok(())
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

        async fn grant_role(
            &self,
            tenant: &TenantId,
            user: UserId,
            role: Role,
        ) -> Result<(), DomainError> {
            // The schema's rule, kept here so the fake cannot be gentler than
            // PostgreSQL: a deployment-scoped role only inside the reserved
            // tenant.
            if role.needs_the_reserved_tenant() && tenant.as_str() != "asterius-admin" {
                return Err(DomainError::Conflict(format!(
                    "{role} cannot be held in {tenant}"
                )));
            }
            let mut held = self.0.roles.lock().expect("an uncontended lock");
            let entry = held
                .entry(format!("{tenant}|{}", user.as_uuid()))
                .or_default();
            if !entry.contains(&role) {
                entry.push(role);
            }
            Ok(())
        }

        async fn revoke_role(
            &self,
            tenant: &TenantId,
            user: UserId,
            role: Role,
        ) -> Result<(), DomainError> {
            let mut held = self.0.roles.lock().expect("an uncontended lock");
            let Some(entry) = held.get_mut(&format!("{tenant}|{}", user.as_uuid())) else {
                return Err(DomainError::NotFound);
            };
            let before = entry.len();
            entry.retain(|candidate| *candidate != role);
            if entry.len() == before {
                return Err(DomainError::NotFound);
            }
            Ok(())
        }

        async fn passkey_enrolment(
            &self,
            tenant: &TenantId,
            user: UserId,
        ) -> Result<asterius_domain::PasskeyEnrolment, DomainError> {
            Ok(
                if self
                    .0
                    .passkeys
                    .lock()
                    .expect("an uncontended lock")
                    .contains(&format!("{tenant}|{}", user.as_uuid()))
                {
                    asterius_domain::PasskeyEnrolment::Enrolled
                } else {
                    asterius_domain::PasskeyEnrolment::None
                },
            )
        }

        fn tenants(&self) -> Arc<dyn TenantRepository> {
            Arc::new(self.clone())
        }

        fn tenant_settings(&self) -> Arc<dyn asterius_domain::ports::TenantSettingsRepository> {
            Arc::new(self.clone())
        }

        fn keys(&self) -> Arc<dyn KeyAdministration> {
            Arc::new(self.clone())
        }

        fn users(&self) -> Arc<dyn asterius_domain::UserAdministration> {
            Arc::new(self.clone())
        }

        fn outbox(&self) -> Arc<dyn asterius_domain::outbox::DeadLetterQuery> {
            Arc::new(self.clone())
        }

        fn dead_letter_operations(&self) -> Arc<dyn asterius_domain::outbox::DeadLetterOperations> {
            Arc::new(self.clone())
        }

        fn policies(&self) -> Arc<dyn asterius_domain::ports::PolicyStore> {
            Arc::new(self.clone())
        }

        fn policy_trial(&self) -> Arc<dyn crate::backend::PolicyTrial> {
            Arc::new(self.clone())
        }

        fn ssf(&self) -> Arc<dyn ssf::SsfAdministration> {
            Arc::new(self.clone())
        }

        fn audit_trail(&self) -> Arc<dyn asterius_domain::audit::AuditQuery> {
            Arc::new(self.clone())
        }

        fn initial_access_tokens(
            &self,
        ) -> Arc<dyn asterius_domain::ports::InitialAccessTokenStore> {
            Arc::new(self.clone())
        }

        fn clients(&self) -> Arc<dyn asterius_domain::ports::ClientAdministration> {
            Arc::new(self.clone())
        }

        fn application_roles(&self) -> Arc<dyn asterius_domain::ApplicationRoleDirectory> {
            Arc::new(self.clone())
        }

        fn capabilities(&self) -> asterius_domain::Capabilities {
            *self.0.capabilities.lock().expect("an uncontended lock")
        }

        fn registration_gate(&self) -> clients::RegistrationGate {
            clients::RegistrationGate {
                mode: "initial_access_token",
                configured_tokens: 2,
            }
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

    /// The `kid` every tenant in the fixture holds a staged key under, and the
    /// value `{kid}` is replaced with when a test walks the registry.
    const SEEDED_KID: &str = "seeded-pending-key";

    /// The `client_id` the fixture's tenants hold a client under, and the value
    /// `{client_id}` is replaced with when a test walks the registry.
    ///
    /// Shaped like one this server mints (`c.` and 22 `base64url` symbols) so
    /// that the routes are exercised with the identifiers they will really see.
    const SEEDED_CLIENT_ID: &str = "c.SeededClientSeededClien";

    /// The account every tenant in the fixture holds, and the value
    /// `{user_id}` is replaced with when a test walks the registry.
    const SEEDED_USER_ID: &str = "3f1d5c2a-0000-4000-8000-000000000001";

    /// An application role in both catalogues that nobody holds, so the two
    /// delete routes have something they are allowed to remove (`ast-095`).
    /// The stream every tenant of the world holds, so that `{stream_id}`
    /// names something for the tests that walk the registry (`ast-f7m.8`).
    const SEEDED_STREAM_ID: &str = "stream-seeded-000000000000000000000";
    /// The abandoned `ssf.set` row the retry route is walked against, and
    /// the one the drop route is: two, because the first press of each
    /// removes its row from the list and a walk that used one id would
    /// assert a 404 for the second (`ast-095`'s `{role_name}` argument).
    const RETRY_LETTER_ID: i64 = 7001;
    const DROP_LETTER_ID: i64 = 7002;

    /// One abandoned SSF delivery.
    fn seeded_letter(id: i64) -> asterius_domain::outbox::DeadLetter {
        asterius_domain::outbox::DeadLetter {
            id,
            kind: "ssf.set".to_owned(),
            attempts: 10,
            created_at: OffsetDateTime::UNIX_EPOCH,
            last_attempt_at: Some(OffsetDateTime::UNIX_EPOCH),
            last_error: Some("the receiver answered 503; the SET is still owed".to_owned()),
        }
    }

    /// One paused stream and two abandoned SETs for `tenant`, so that every
    /// `{stream_id}` and `{outbox_id}` in the registry names something for
    /// the tests that walk it (`ast-f7m.8`).
    fn seed_shared_signals(handle: &Handle, tenant: &str) {
        handle
            .0
            .streams
            .lock()
            .expect("an uncontended lock")
            .push((TenantId::new(tenant), seeded_stream()));
        for letter in [RETRY_LETTER_ID, DROP_LETTER_ID] {
            handle
                .0
                .dead_letters
                .lock()
                .expect("an uncontended lock")
                .push(seeded_letter(letter));
        }
    }

    /// One stream, as the console lists it.
    fn seeded_stream() -> ssf::StreamSummary {
        ssf::StreamSummary {
            stream_id: asterius_ssf::stream::StreamId::parse(SEEDED_STREAM_ID)
                .expect("a fixed stream id"),
            receiver: asterius_domain::ClientId::new(SEEDED_CLIENT_ID),
            delivery_method: asterius_ssf::stream::DELIVERY_PUSH,
            events_requested: vec![asterius_ssf::caep::SESSION_REVOKED.to_owned()],
            description: None,
            created_at: OffsetDateTime::UNIX_EPOCH,
            status: asterius_ssf::stream::StreamStatus::Paused,
            reason: Some("the receiver answered 400".to_owned()),
            status_changed_at: Some(OffsetDateTime::UNIX_EPOCH),
            delivered: 12,
            failed: 4,
            queue_depth: 3,
        }
    }

    const SPARE_ROLE: &str = "spare";
    /// An application role in both catalogues that the seeded account *does*
    /// hold, so the two withdraw routes have something to withdraw — and so
    /// that deleting it is the 409 the schema produces.
    const HELD_ROLE: &str = "held";

    /// The `sid` of that account's seeded session, and the value `{sid}` is
    /// replaced with. Shaped like the opaque identifier `Session::begin`
    /// publishes rather than like a digest, because the digest is the thing
    /// this API is not allowed to know (`ast-o4u.5`).
    const SEEDED_SID: &str = "sid-of-the-seeded-session";

    /// The passkey row that account holds, and the value `{credential_id}` is
    /// replaced with.
    const SEEDED_CREDENTIAL_ID: &str = "3f1d5c2a-0000-4000-8000-000000000002";

    /// The authorization that account granted, and the value `{grant_id}` is
    /// replaced with.
    const SEEDED_GRANT_ID: &str = "3f1d5c2a-0000-4000-8000-000000000003";

    /// How many relying parties took part in the seeded session.
    ///
    /// Two, and not one: "one logout token per participant" and "one logout
    /// token per session" agree at one and disagree at two, so a fixture of
    /// one would let the wrong rule pass.
    const SEEDED_PARTICIPANTS: usize = 2;

    fn seeded_user_id() -> UserId {
        UserId::new(uuid::Uuid::parse_str(SEEDED_USER_ID).expect("a fixed uuid"))
    }

    /// One account of `tenant`, with an address and no claims.
    fn seeded_user(tenant: &str) -> asterius_domain::User {
        asterius_domain::User {
            tenant: TenantId::parse(tenant).expect("a valid tenant id"),
            id: seeded_user_id(),
            username: "ada@example.test".to_owned(),
            email: Some("ada@example.test".to_owned()),
            email_verified: true,
            status: asterius_domain::UserStatus::Active,
            claims: asterius_domain::ClaimSet::new(),
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    /// That account's live session, with two participating relying parties.
    fn seeded_session(tenant: &str) -> SeededSession {
        SeededSession {
            tenant: TenantId::parse(tenant).expect("a valid tenant id"),
            user: seeded_user_id(),
            summary: asterius_domain::SessionSummary {
                public_sid: SEEDED_SID.to_owned(),
                created_at: OffsetDateTime::UNIX_EPOCH,
                authenticated_at: OffsetDateTime::UNIX_EPOCH,
                last_seen_at: OffsetDateTime::UNIX_EPOCH,
                // Far enough ahead that `is_live` does not depend on when the
                // suite runs.
                expires_at: OffsetDateTime::UNIX_EPOCH + time::Duration::days(365 * 100),
                amr: vec![AuthenticationMethod::Password],
                acr: None,
                revoked: None,
            },
            participants: SEEDED_PARTICIPANTS,
        }
    }

    /// That account's passkey.
    fn seeded_passkey(tenant: &str) -> SeededPasskey {
        SeededPasskey {
            tenant: TenantId::parse(tenant).expect("a valid tenant id"),
            user: seeded_user_id(),
            passkey: asterius_domain::PasskeySummary {
                id: uuid::Uuid::parse_str(SEEDED_CREDENTIAL_ID).expect("a fixed uuid"),
                label: Some("a laptop".to_owned()),
                rp_id: "as.example".to_owned(),
                created_at: OffsetDateTime::UNIX_EPOCH,
                last_used_at: None,
                disabled_at: None,
            },
        }
    }

    /// That account's authorization to the seeded client.
    fn seeded_grant(tenant: &str) -> asterius_domain::Grant {
        let mut grant = asterius_domain::Grant::new(
            TenantId::parse(tenant).expect("a valid tenant id"),
            asterius_domain::ClientId::new(SEEDED_CLIENT_ID),
            OffsetDateTime::UNIX_EPOCH,
        );
        grant.id = asterius_domain::GrantId::new(SEEDED_GRANT_ID);
        grant.user = Some(seeded_user_id());
        grant.scopes = ["openid".to_owned()].into_iter().collect();
        grant
    }

    /// A registration document this profile accepts, as a fixture.
    ///
    /// Deliberately minimal: every other member has a default this server
    /// provisions, and a fixture that set them all would stop noticing when a
    /// default changed.
    fn valid_registration() -> serde_json::Value {
        serde_json::json!({
            "client_name": "Seeded client",
            "redirect_uris": ["https://app.example.test/callback"],
            "grant_types": ["authorization_code"],
            "scope": "openid",
            "jwks_uri": "https://app.example.test/jwks.json",
        })
    }

    fn seeded_client(tenant: &str, id: &str) -> Client {
        Client {
            tenant: TenantId::parse(tenant).expect("a valid tenant id"),
            id: asterius_domain::ClientId::new(id),
            registration: ClientRegistration::from_json(
                valid_registration().to_string().as_bytes(),
                asterius_domain::Capabilities::default(),
            )
            .expect("the fixture is a valid registration document"),
            status: ClientStatus::Active,
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    /// One key, carrying a private member no response may ever contain.
    fn seeded_key(tenant: &str, kid: &str, state: KeyState) -> PublicKeyRecord {
        PublicKeyRecord {
            tenant: TenantId::parse(tenant).expect("a valid tenant id"),
            kid: Kid::new(kid),
            algorithm: SigningAlgorithm::EdDsa,
            purpose: KeyPurpose::Signing,
            state,
            public_jwk: serde_json::json!({
                "kty": "OKP",
                "crv": "Ed25519",
                "use": "sig",
                "kid": kid,
                "x": format!("public-{kid}"),
                "d": "PRIVATE-KEY-MATERIAL",
            }),
            created_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

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

    /// One catalogue entry for a tenant.
    fn seeded_role(tenant: &str, owner: RoleOwner, name: &str) -> asterius_domain::ApplicationRole {
        asterius_domain::ApplicationRole::new(
            TenantId::new(tenant),
            owner,
            name,
            None,
            OffsetDateTime::UNIX_EPOCH,
        )
        .expect("a fixed role")
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
                // One staged key per tenant, so that the `{kid}` in
                // `keys.retire` names something for every test that walks the
                // registry. `pending`, because that is the state the route
                // accepts — the active key is refused on purpose.
                handle
                    .0
                    .keys
                    .lock()
                    .expect("an uncontended lock")
                    .push(seeded_key(id, SEEDED_KID, KeyState::Pending));
                // One client per tenant, so that the `{client_id}` in the
                // client routes names something for every test that walks the
                // registry — and so that a cross-tenant read has a real row in
                // the other tenant to fail to find.
                handle
                    .0
                    .clients
                    .lock()
                    .expect("an uncontended lock")
                    .push(seeded_client(id, SEEDED_CLIENT_ID));
                // One account per tenant, with one live session, one passkey
                // and one authorization, so that every `{user_id}`, `{sid}`,
                // `{credential_id}` and `{grant_id}` in the registry names
                // something for the tests that walk it.
                handle
                    .0
                    .accounts
                    .lock()
                    .expect("an uncontended lock")
                    .push(seeded_user(id));
                handle
                    .0
                    .account_passwords
                    .lock()
                    .expect("an uncontended lock")
                    .insert(*seeded_user_id().as_uuid());
                handle
                    .0
                    .account_sessions
                    .lock()
                    .expect("an uncontended lock")
                    .push(seeded_session(id));
                handle
                    .0
                    .account_passkeys
                    .lock()
                    .expect("an uncontended lock")
                    .push(seeded_passkey(id));
                handle
                    .0
                    .account_grants
                    .lock()
                    .expect("an uncontended lock")
                    .push(seeded_grant(id));
                seed_shared_signals(&handle, id);
                // Two roles in each catalogue, one held and one not, so that
                // every `{role_name}` in the registry names something *and*
                // the delete routes have a role they are allowed to remove
                // while the withdraw routes have one to withdraw (`ast-095`).
                for name in [SPARE_ROLE, HELD_ROLE] {
                    for owner in [
                        RoleOwner::Tenant,
                        RoleOwner::Client(asterius_domain::ClientId::new(SEEDED_CLIENT_ID)),
                    ] {
                        handle
                            .0
                            .role_catalogue
                            .lock()
                            .expect("an uncontended lock")
                            .push(seeded_role(id, owner.clone(), name));
                        if name == HELD_ROLE {
                            handle
                                .0
                                .role_assignments
                                .lock()
                                .expect("an uncontended lock")
                                .push(SeededAssignment {
                                    tenant: TenantId::new(id),
                                    user: seeded_user_id(),
                                    owner,
                                    name: asterius_domain::RoleName::parse(name)
                                        .expect("a fixed role name"),
                                });
                        }
                    }
                }
            }
            // An *active* key, in the tenant the registry walk runs against
            // only. Registering a client is refused when the tenant cannot sign
            // the ID tokens it asks for (`clients::check_signable`), so the
            // table-driven tests need one — and the key-rotation tests, which
            // run in `acme`, need a tenant that has none, because their
            // premise is a tenant whose first key is born signing.
            handle
                .0
                .keys
                .lock()
                .expect("an uncontended lock")
                .push(seeded_key(
                    "asterius-admin",
                    "seeded-active-key",
                    KeyState::Active,
                ));
            Self {
                api_tenant: Arc::new(tenant_named("acme")),
                handle,
            }
        }

        /// Empties the dead-letter queue the world seeds (`ast-f7m.8`), for
        /// the tests whose premise is a healthy deployment.
        fn forget_dead_letters(&self) {
            self.handle
                .0
                .dead_letters
                .lock()
                .expect("an uncontended lock")
                .clear();
        }

        /// Routes subsequent requests to `id` instead of `acme`.
        fn routed_at(mut self, id: &str) -> Self {
            self.api_tenant = Arc::new(tenant_named(id));
            self
        }

        /// Mints a usable session in `tenant` for a user holding `roles`, and
        /// returns the cookie value.
        ///
        /// The session records a **user-verified passkey**, which is what a
        /// console login has to be for a deployment-scoped role (`ast-895`).
        /// A test about the rule itself uses [`World::sign_in_with`].
        fn sign_in(&self, tenant: &str, roles: &[Role]) -> String {
            self.sign_in_with(
                tenant,
                roles,
                &[
                    AuthenticationMethod::Passkey,
                    AuthenticationMethod::UserVerified,
                ],
                asterius_domain::PasskeyEnrolment::Enrolled,
            )
        }

        /// [`World::sign_in`], with the two things `ast-895` decides on: how
        /// the user authenticated, and whether the account has a passkey that
        /// could have been asked for.
        /// [`World::sign_in`] for a *named* account, so that a test can make
        /// the caller and the account it acts on the same person — which is
        /// the one thing the roles route refuses.
        fn sign_in_as(&self, tenant: &str, user: UserId, roles: &[Role]) -> String {
            self.sign_in_as_with(
                tenant,
                user,
                roles,
                &[
                    AuthenticationMethod::Passkey,
                    AuthenticationMethod::UserVerified,
                ],
                asterius_domain::PasskeyEnrolment::Enrolled,
            )
        }

        fn sign_in_with(
            &self,
            tenant: &str,
            roles: &[Role],
            amr: &[AuthenticationMethod],
            enrolment: asterius_domain::PasskeyEnrolment,
        ) -> String {
            self.sign_in_as_with(tenant, UserId::generate(), roles, amr, enrolment)
        }

        fn sign_in_as_with(
            &self,
            tenant: &str,
            user: UserId,
            roles: &[Role],
            amr: &[AuthenticationMethod],
            enrolment: asterius_domain::PasskeyEnrolment,
        ) -> String {
            let id = SessionId::generate();
            let tenant = TenantId::parse(tenant).expect("a valid tenant id");
            let session = Session::begin(
                tenant.clone(),
                &id,
                *user.as_uuid(),
                amr.to_vec(),
                OffsetDateTime::now_utc(),
                Lifetimes::default(),
            );
            self.handle
                .0
                .sessions
                .lock()
                .expect("an uncontended lock")
                .insert(id.digest(), session);
            let key = format!("{tenant}|{}", user.as_uuid());
            self.handle
                .0
                .roles
                .lock()
                .expect("an uncontended lock")
                .insert(key.clone(), roles.to_vec());
            if enrolment == asterius_domain::PasskeyEnrolment::Enrolled {
                self.handle
                    .0
                    .passkeys
                    .lock()
                    .expect("an uncontended lock")
                    .insert(key);
            }
            id.expose().to_owned()
        }

        /// A `GET` of `operation` carrying `cookie`, which is every request
        /// the `ast-895` tests make.
        async fn get(&self, operation: &Operation, cookie: &str) -> Response {
            self.send(
                request_for(operation)
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
            .await
        }

        /// A `GET` of `operation` with a query string, carrying `cookie`.
        async fn get_with_query(
            &self,
            operation: &Operation,
            query: &str,
            cookie: &str,
        ) -> Response {
            let uri = format!("{}?{query}", operation.full_path());
            self.send(
                axum::http::Request::builder()
                    .method("GET")
                    .uri(uri)
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
            .await
        }

        /// Calls `operation` in `acme` as a freshly signed-in holder of
        /// `role`, with everything a mutation needs to get past CSRF and
        /// idempotency — so that a 403 in the assertion is about authority and
        /// not about a missing header.
        ///
        /// A session per call, because `session.end` is a route: a shared
        /// cookie would make every later call a 401 that says nothing about
        /// what the role holds.
        async fn as_role(&self, operation: &Operation, role: Role) -> Response {
            let cookie = self.sign_in("acme", &[role]);
            self.send(
                request_for(operation)
                    .header(
                        "cookie",
                        format!(
                            "{}={cookie}",
                            asterius_domain::entities::session::COOKIE_NAME
                        ),
                    )
                    .header(csrf::HEADER, csrf::token(&cookie))
                    .header(idempotency::HEADER, "a-restricted-role-key")
                    .body(body_for(operation))
                    .expect("a request"),
            )
            .await
        }

        fn api(&self) -> AdminApi {
            AdminApi::new(&AdminState {
                backend: Arc::new(self.handle.clone()),
                tokens: None,
                rate_limit: RateLimit {
                    max: 10_000,
                    window: time::Duration::minutes(1),
                },
                reserved_tenant: Some(
                    TenantId::parse("asterius-admin").expect("a valid tenant id"),
                ),
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
        let path = operation
            .full_path()
            .replace("{tenant_id}", "acme")
            .replace("{kid}", SEEDED_KID)
            .replace("{client_id}", SEEDED_CLIENT_ID)
            .replace("{user_id}", SEEDED_USER_ID)
            .replace("{sid}", SEEDED_SID)
            .replace("{credential_id}", SEEDED_CREDENTIAL_ID)
            .replace("{grant_id}", SEEDED_GRANT_ID)
            .replace("{stream_id}", SEEDED_STREAM_ID)
            .replace(
                "{outbox_id}",
                &match operation.id() {
                    crate::OUTBOX_DEAD_LETTER_DROP_ID => DROP_LETTER_ID,
                    _ => RETRY_LETTER_ID,
                }
                .to_string(),
            )
            // A delete must name a role nobody holds and a withdrawal must
            // name one somebody does; one literal could not be both, and a
            // table walk that used one would assert a 409 for the first or a
            // 404 for the second (`ast-095`).
            .replace(
                "{role_name}",
                match operation.id() {
                    crate::USER_APP_ROLE_WITHDRAW_ID | crate::USER_CLIENT_APP_ROLE_WITHDRAW_ID => {
                        HELD_ROLE
                    }
                    _ => SPARE_ROLE,
                },
            );
        HttpRequest::builder()
            .method(operation.method().as_str())
            .uri(path)
            .header("origin", ORIGIN)
    }

    /// A body each mutating route will accept.
    ///
    /// Keyed on the `operationId` rather than on the verb, because the table
    /// tests assert that every registered route *succeeds* for a caller holding
    /// the authority it declares — so a route reached with a body it rejects
    /// would fail those tests for the wrong reason and hide a real refusal.
    fn body_for(operation: &Operation) -> Body {
        let document = match operation.id() {
            crate::TENANT_CREATE_ID => serde_json::json!({
                "tenant_id": "brand-new",
                "issuer": format!("{ORIGIN}/t/brand-new"),
            }),
            // A whole-document PUT: the table-driven tests send it to every
            // route, so this one has to be a body the handler accepts rather
            // than the empty one, or "every route answers a deployment admin"
            // would be asserting a 400.
            crate::TENANT_SETTINGS_UPDATE_ID => settings_body(60, 300),
            // A registration document, because that is what these two take:
            // the same document `POST /register` takes, validated by the same
            // call.
            crate::CLIENT_CREATE_ID | crate::CLIENT_UPDATE_ID => valid_registration(),
            // A label is the one thing an issuance requires: the quota is the
            // tenant's and the expiry is optional (`ast-cu3`).
            crate::INITIAL_ACCESS_TOKEN_CREATE_ID => serde_json::json!({"label": "onboarding"}),
            // A username is the one thing an account requires: the password
            // is optional (a tenant may enrol a passkey instead) and every
            // claim is.
            crate::USER_CREATE_ID => serde_json::json!({"username": "new@example.test"}),
            // A name and nothing else: the description is optional, and a
            // role cannot be created already assigned to somebody (`ast-095`).
            crate::APP_ROLE_CREATE_ID | crate::CLIENT_APP_ROLE_CREATE_ID => {
                serde_json::json!({"name": "auditor"})
            }
            // The role the table walk has just created, in the tenant's own
            // catalogue: assignment is a foreign key onto it, so a name that
            // was never created is a 409 rather than a silent creation.
            crate::USER_APP_ROLE_ASSIGN_ID => serde_json::json!({"name": "auditor"}),
            // A whole policy document: the route refuses `{}` because a
            // document with no version is not one this build reads
            // (`ast-pj0.4`).
            crate::POLICY_UPDATE_ID => serde_json::json!({
                "version": 1,
                "rules": [{"id": "walked", "effect": "deny"}],
            }),
            // One Authorization API §6.1 request: the bench refuses a body
            // that does not name a subject, an action and a resource, so the
            // table walk has to send one that does (`ast-f7m.9`).
            crate::POLICY_TRY_ID => serde_json::json!({
                "subject": {"type": "user", "id": "walked"},
                "action": {"name": "read"},
                "resource": {"type": "document", "id": "walked"},
            }),
            crate::KEYS_ROTATE_ID => serde_json::json!({"alg": "EdDSA"}),
            // A whole status document: the route refuses `{}` because a
            // status it did not name is not a status (`ast-f7m.8`).
            crate::SSF_STREAM_STATUS_UPDATE_ID => {
                serde_json::json!({"status": "paused", "reason": "walked"})
            }
            crate::KEYS_SCHEDULE_ID => serde_json::json!({
                "alg": "EdDSA",
                "rotation_period_seconds": 7_776_000,
                "propagation_period_seconds": 900,
                "grace_period_seconds": 604_800,
            }),
            // Destroying key material is recorded, and the record has to say
            // why — so this route is one of the two that will not accept `{}`.
            crate::KEYS_PURGE_ID => serde_json::json!({"reason": "leaked in INC-1"}),
            // `keys.retire` names its subject in the path and takes no body.
            _ if operation.effect() == Effect::Mutates => serde_json::json!({}),
            _ => return Body::empty(),
        };
        Body::from(document.to_string())
    }

    async fn body_of(response: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .expect("a readable body");
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    }

    // ---- the policy screen (`ast-pj0.4`) ----------------------------------

    /// A `PUT` or `DELETE` of the policy, with the CSRF token a first-party
    /// mutation needs. No `Idempotency-Key`: both verbs are idempotent by
    /// their own definition (RFC 9110 §9.2.2) and the registry asks for a key
    /// on `POST` only.
    async fn edit_policy(
        world: &World,
        operation: &Operation,
        cookie: &str,
        body: serde_json::Value,
    ) -> Response {
        let body = if body.is_null() {
            Body::empty()
        } else {
            Body::from(body.to_string())
        };
        world
            .send(
                request_for(operation)
                    .header(
                        "cookie",
                        format!(
                            "{}={cookie}",
                            asterius_domain::entities::session::COOKIE_NAME
                        ),
                    )
                    .header(csrf::HEADER, csrf::token(cookie))
                    .body(body)
                    .expect("a request"),
            )
            .await
    }

    /// A tenant that has never written a policy still gets a document to open
    /// the editor on: "no policy" is a state of the tenant, not a missing
    /// resource.
    #[tokio::test]
    async fn a_tenant_with_no_policy_reads_an_empty_document() {
        // Arrange
        let world = World::new();
        let cookie = world.sign_in("acme", &[Role::TenantAdmin]);

        // Act
        let response = world.get(&crate::POLICY_READ, &cookie).await;

        // Assert
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_of(response).await;
        assert_eq!(body["rule_count"], serde_json::json!(0));
        assert_eq!(body["updated_at"], serde_json::Value::Null);
    }

    /// The round trip the console editor makes: put a document, get it back
    /// unchanged.
    #[tokio::test]
    async fn a_policy_survives_the_round_trip_through_the_api() {
        // Arrange
        let world = World::new();
        let cookie = world.sign_in("acme", &[Role::TenantAdmin]);
        let document = serde_json::json!({
            "version": 1,
            "rules": [{
                "id": "deny-contractors",
                "effect": "deny",
                "when": {"group": "contractors"},
                "reason_admin": "contractors do not reach this",
            }],
        });

        // Act
        let written = edit_policy(&world, &crate::POLICY_UPDATE, &cookie, document.clone()).await;
        let read = world.get(&crate::POLICY_READ, &cookie).await;

        // Assert
        assert_eq!(written.status(), StatusCode::OK);
        let body = body_of(read).await;
        assert_eq!(body["document"], document);
        assert_eq!(body["rule_count"], serde_json::json!(1));
    }

    /// A tenant cannot supply code: a condition this build does not know is a
    /// 400 naming the path, never a document stored for a later build to
    /// interpret.
    #[tokio::test]
    async fn a_document_this_build_does_not_understand_is_refused() {
        // Arrange
        let world = World::new();
        let cookie = world.sign_in("acme", &[Role::TenantAdmin]);
        let document = serde_json::json!({
            "version": 1,
            "rules": [{"id": "r", "effect": "permit", "when": {"eval": "1 + 1"}}],
        });

        // Act
        let response = edit_policy(&world, &crate::POLICY_UPDATE, &cookie, document).await;

        // Assert
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(
            world
                .handle
                .0
                .policies
                .lock()
                .expect("an uncontended lock")
                .is_empty()
        );
    }

    /// Both edits leave one type in the trail, told apart by a flag: a reader
    /// filtering on `policy.updated` sees every change to the tenant's
    /// authorization, whichever direction it went.
    #[tokio::test]
    async fn writing_and_clearing_a_policy_are_both_recorded() {
        // Arrange
        let world = World::new();
        let cookie = world.sign_in("acme", &[Role::TenantAdmin]);
        let document = serde_json::json!({
            "version": 1,
            "rules": [{"id": "r", "effect": "deny"}],
        });

        // Act
        edit_policy(&world, &crate::POLICY_UPDATE, &cookie, document).await;
        let cleared = edit_policy(
            &world,
            &crate::POLICY_DELETE,
            &cookie,
            serde_json::Value::Null,
        )
        .await;

        // Assert
        assert_eq!(cleared.status(), StatusCode::NO_CONTENT);
        assert!(
            world
                .handle
                .0
                .policies
                .lock()
                .expect("an uncontended lock")
                .is_empty()
        );
        let events = world.handle.0.events.lock().expect("an uncontended lock");
        let recorded = events
            .iter()
            .filter(|event| event.event_type == EventType::POLICY_UPDATED)
            .count();
        assert_eq!(recorded, 2);
    }

    /// The scope is its own: reading the tenant's lifetimes is not reading the
    /// authorization model. An auditor holds the read by definition and no
    /// write at all.
    #[tokio::test]
    async fn an_auditor_reads_the_policy_and_does_not_write_it() {
        // Arrange
        let world = World::new();
        let cookie = world.sign_in("acme", &[Role::SecurityAuditor]);

        // Act
        let read = world.get(&crate::POLICY_READ, &cookie).await;
        let written = edit_policy(
            &world,
            &crate::POLICY_UPDATE,
            &cookie,
            serde_json::json!({"version": 1, "rules": []}),
        )
        .await;

        // Assert
        assert_eq!(read.status(), StatusCode::OK);
        assert_eq!(written.status(), StatusCode::FORBIDDEN);
    }

    // ---- the policy test bench (`ast-f7m.9`) ------------------------------

    /// A `POST /policies/try`, as the console makes it: the session cookie,
    /// the synchroniser token, and no `Idempotency-Key` — the bench stores
    /// nothing, so there is nothing for a key to make happen at most once.
    async fn try_policy(world: &World, cookie: &str, body: serde_json::Value) -> Response {
        world
            .send(
                request_for(&crate::POLICY_TRY)
                    .header(
                        "cookie",
                        format!(
                            "{}={cookie}",
                            asterius_domain::entities::session::COOKIE_NAME
                        ),
                    )
                    .header(csrf::HEADER, csrf::token(cookie))
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .expect("a request"),
            )
            .await
    }

    fn a_trial_for(subject: &str) -> serde_json::Value {
        serde_json::json!({
            "subject": {"type": "user", "id": subject},
            "action": {"name": "read"},
            "resource": {"type": "document", "id": "42"},
        })
    }

    /// What the screen is for: an administrator writes a rule and asks what it
    /// decides, and the answer is §6.2's Decision over the document that was
    /// just stored.
    #[tokio::test]
    async fn the_bench_decides_by_the_document_the_editor_stored() {
        // Arrange
        let world = World::new();
        let cookie = world.sign_in("acme", &[Role::TenantAdmin]);
        let document = serde_json::json!({
            "version": 1,
            "rules": [{
                "id": "admins-read",
                "effect": "permit",
                "actions": ["read"],
                "when": {"group": "admins"},
                "reason_admin": "the admins group reads every document",
            }],
        });
        edit_policy(&world, &crate::POLICY_UPDATE, &cookie, document).await;

        // Act
        let permitted = try_policy(&world, &cookie, a_trial_for(GROUPED_SUBJECT)).await;

        // Assert
        assert_eq!(permitted.status(), StatusCode::OK);
        let body = body_of(permitted).await;
        assert_eq!(body["decision"], serde_json::json!(true));
        assert_eq!(
            body["context"]["reason_admin"],
            serde_json::json!({"en": "the admins group reads every document"})
        );
    }

    /// The facts are this server's. The same rule, a subject this tenant does
    /// not hold in the group, and a body that says it does anyway: still a
    /// deny, because nothing a caller writes reaches `subject.groups`.
    #[tokio::test]
    async fn a_bench_request_cannot_grant_itself_the_facts_a_rule_reads() {
        // Arrange
        let world = World::new();
        let cookie = world.sign_in("acme", &[Role::TenantAdmin]);
        let document = serde_json::json!({
            "version": 1,
            "rules": [{
                "id": "admins-read",
                "effect": "permit",
                "actions": ["read"],
                "when": {"group": "admins"},
            }],
        });
        edit_policy(&world, &crate::POLICY_UPDATE, &cookie, document).await;
        let claiming = serde_json::json!({
            "subject": {"type": "user", "id": "nobody", "groups": ["admins"],
                        "properties": {"groups": ["admins"]}},
            "action": {"name": "read"},
            "resource": {"type": "document", "id": "42"},
        });

        // Act
        let response = try_policy(&world, &cookie, claiming).await;

        // Assert
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            body_of(response).await["decision"],
            serde_json::json!(false)
        );
    }

    /// The bench enforces nothing, so it records nothing: the trail carries
    /// the edits (`policy.updated`) and the decisions a PEP acted on
    /// (`access.evaluated`), and a trial is neither.
    #[tokio::test]
    async fn a_trial_is_not_written_to_the_trail() {
        // Arrange
        let world = World::new();
        let cookie = world.sign_in("acme", &[Role::TenantAdmin]);
        world.handle.0.events.lock().expect("a lock").clear();

        // Act
        let response = try_policy(&world, &cookie, a_trial_for("anybody")).await;

        // Assert
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            world
                .handle
                .0
                .events
                .lock()
                .expect("an uncontended lock")
                .is_empty(),
            "the test bench wrote a record"
        );
    }

    /// The bench is on the admin API's limiter, which is the one this crate
    /// can reach at all: a console left open cannot spend the budget the
    /// PDP's enforcement points depend on.
    #[tokio::test]
    async fn the_bench_spends_the_admin_limiter_and_not_the_pdps() {
        // Arrange
        let world = World::new();
        let cookie = world.sign_in("acme", &[Role::TenantAdmin]);
        let send = async || {
            let mut request = request_for(&crate::POLICY_TRY)
                .header(
                    "cookie",
                    format!(
                        "{}={cookie}",
                        asterius_domain::entities::session::COOKIE_NAME
                    ),
                )
                .header(csrf::HEADER, csrf::token(&cookie))
                .body(Body::from(a_trial_for("anybody").to_string()))
                .expect("a request");
            request
                .extensions_mut()
                .insert(Arc::clone(&world.api_tenant));
            request.extensions_mut().insert(ClientAddress(Some(
                "198.51.100.9".parse().expect("literal"),
            )));
            AdminApi::new(&AdminState {
                backend: Arc::new(world.handle.clone()),
                tokens: None,
                rate_limit: RateLimit {
                    max: 1,
                    window: time::Duration::minutes(1),
                },
                reserved_tenant: None,
            })
            .into_router()
            .oneshot(request)
            .await
            .expect("the router answers")
        };

        // Act
        let first = send().await.status();
        let second = send().await.status();

        // Assert
        assert_eq!(first, StatusCode::OK);
        assert_eq!(second, StatusCode::TOO_MANY_REQUESTS);
    }

    /// The bench is reachable with an administrator's session and with
    /// nothing else: no cookie is a 401, and no request reaches the PDP.
    #[tokio::test]
    async fn the_bench_needs_the_admin_session() {
        // Arrange
        let world = World::new();

        // Act
        let response = world
            .send(
                request_for(&crate::POLICY_TRY)
                    .body(Body::from(a_trial_for("anybody").to_string()))
                    .expect("a request"),
            )
            .await;

        // Assert
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(
            world
                .handle
                .0
                .trials
                .lock()
                .expect("an uncontended lock")
                .is_empty(),
            "an unauthenticated request reached the PDP"
        );
    }

    /// The cookie is ambient, so a `POST` a cross-site form could emit is
    /// refused without this session's synchroniser token — even though it
    /// changes nothing, and even though the browser would not let the forging
    /// page read the answer.
    #[tokio::test]
    async fn a_trial_without_the_synchroniser_token_is_refused() {
        // Arrange
        let world = World::new();
        let cookie = world.sign_in("acme", &[Role::TenantAdmin]);

        // Act
        let response = world
            .send(
                request_for(&crate::POLICY_TRY)
                    .header(
                        "cookie",
                        format!(
                            "{}={cookie}",
                            asterius_domain::entities::session::COOKIE_NAME
                        ),
                    )
                    .body(Body::from(a_trial_for("anybody").to_string()))
                    .expect("a request"),
            )
            .await;

        // Assert
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(
            world
                .handle
                .0
                .trials
                .lock()
                .expect("an uncontended lock")
                .is_empty()
        );
    }

    /// An auditor may ask what the catalogue they may read decides: the bench
    /// declares `admin.policies:read`, and a caller holding no policy scope at
    /// all is refused.
    #[tokio::test]
    async fn the_bench_takes_the_read_scope_of_the_policy_it_is_about() {
        // Arrange
        let world = World::new();
        let auditor = world.sign_in("acme", &[Role::SecurityAuditor]);
        let agent = world.sign_in("acme", &[Role::UserSupport]);

        // Act
        let audited = try_policy(&world, &auditor, a_trial_for("anybody")).await;
        let refused = try_policy(&world, &agent, a_trial_for("anybody")).await;

        // Assert
        assert_eq!(audited.status(), StatusCode::OK);
        assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    }

    /// §6.1 makes the three entities REQUIRED. A body missing one is a 400
    /// naming the member, and not a deny: an administrator told "denied" by a
    /// typo would go and edit a rule that was never consulted.
    #[tokio::test]
    async fn a_malformed_trial_is_a_refusal_and_not_a_deny() {
        // Arrange
        let world = World::new();
        let cookie = world.sign_in("acme", &[Role::TenantAdmin]);
        let body = serde_json::json!({"subject": {"type": "user", "id": "alice"}});

        // Act
        let response = try_policy(&world, &cookie, body).await;

        // Assert
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    /// A store this server could not read is a refusal for the bench, where
    /// the PDP endpoint answers a PEP `decision: false`. The difference is the
    /// reader: an enforcement point has to do something safe, and a person
    /// asking what their policy says must not be told "deny" by an outage.
    #[tokio::test]
    async fn an_unreadable_store_refuses_the_trial_rather_than_denying_it() {
        // Arrange
        let world = World::new();
        let cookie = world.sign_in("acme", &[Role::TenantAdmin]);
        *world.handle.0.trials_fail.lock().expect("a lock") = true;

        // Act
        let response = try_policy(&world, &cookie, a_trial_for("anybody")).await;

        // Assert
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    // ---- the dead-letter screen (`ast-0ju.9`) -----------------------------

    /// The screen exists so that "our logout notifications stopped arriving"
    /// is answerable without a database client: which delivery, how many times
    /// it was tried, and what the receiver said.
    #[tokio::test]
    async fn a_tenant_admin_reads_the_deliveries_the_outbox_gave_up_on() {
        // Arrange
        let world = World::new();
        world.forget_dead_letters();
        world
            .handle
            .0
            .dead_letters
            .lock()
            .expect("an uncontended lock")
            .push(asterius_domain::outbox::DeadLetter {
                id: 91,
                kind: "logout.backchannel".to_owned(),
                attempts: 10,
                created_at: OffsetDateTime::UNIX_EPOCH,
                last_attempt_at: Some(OffsetDateTime::UNIX_EPOCH),
                last_error: Some("rp.example answered 503".to_owned()),
            });
        let cookie = world.sign_in("acme", &[Role::TenantAdmin]);

        // Act
        let response = world.get(&crate::OUTBOX_DEAD_LETTERS, &cookie).await;

        // Assert
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_of(response).await;
        let items = body["items"].as_array().expect("an items array");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["id"], 91);
        assert_eq!(items[0]["family"], "logout");
        assert_eq!(items[0]["attempts"], 10);
        assert_eq!(items[0]["last_error"], "rp.example answered 503");
    }

    /// A healthy deployment has none, and the screen must say so rather than
    /// 404 — an operator checking whether delivery is failing needs "no" to be
    /// an answer.
    #[tokio::test]
    async fn an_outbox_with_nothing_abandoned_renders_an_empty_list() {
        // Arrange
        let world = World::new();
        world.forget_dead_letters();
        let cookie = world.sign_in("acme", &[Role::TenantAdmin]);

        // Act
        let response = world.get(&crate::OUTBOX_DEAD_LETTERS, &cookie).await;

        // Assert
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_of(response).await;
        assert_eq!(body["items"].as_array().map(Vec::len), Some(0));
    }

    // ---- the shared-signals screen (`ast-f7m.8`) ---------------------------

    /// One detail value by key, for the assertions about what a record says.
    fn detail_value<'a>(
        detail: &'a asterius_domain::audit::Detail,
        key: &str,
    ) -> Option<&'a asterius_domain::audit::DetailValue> {
        detail
            .iter()
            .find(|(name, _)| *name == key)
            .map(|(_, value)| value)
    }

    /// The list is the screen: state, reason and the three numbers, and
    /// nothing a receiver registered as a secret.
    #[tokio::test]
    async fn a_tenant_admin_reads_every_stream_with_its_state_and_figures() {
        // Arrange
        let world = World::new();
        let cookie = world.sign_in("acme", &[Role::TenantAdmin]);

        // Act
        let response = world.get(&crate::SSF_STREAMS_LIST, &cookie).await;

        // Assert
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_of(response).await;
        let items = body["items"].as_array().expect("an items array");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["stream_id"], SEEDED_STREAM_ID);
        assert_eq!(items[0]["status"], "paused");
        assert_eq!(items[0]["reason"], "the receiver answered 400");
        assert_eq!(items[0]["delivered"], 12);
        assert_eq!(items[0]["failed"], 4);
        assert_eq!(items[0]["queue_depth"], 3);
        assert!(items[0].get("endpoint_url").is_none());
        assert!(items[0].get("authorization_header").is_none());
    }

    /// **The first acceptance criterion of `ast-f7m.8`.** Re-enabling a
    /// stream the worker paused writes `enabled`, clears the reason, and is
    /// recorded as `ssf.stream_updated` with the administrator as the
    /// actor — the same type the receiver's own edits leave.
    #[tokio::test]
    async fn an_operator_re_enables_a_paused_stream_and_it_is_audited() {
        // Arrange
        let world = World::new();
        let cookie = world.sign_in("acme", &[Role::TenantAdmin]);

        // Act
        let response = world
            .send(
                as_console(&crate::SSF_STREAM_STATUS_UPDATE, &cookie)
                    .body(Body::from(
                        serde_json::json!({"status": "enabled"}).to_string(),
                    ))
                    .expect("a request"),
            )
            .await;

        // Assert
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_of(response).await;
        assert_eq!(body["status"], "enabled");
        assert_eq!(body["reason"], serde_json::Value::Null);
        let streams = world.handle.0.streams.lock().expect("a lock");
        let (_, stream) = streams
            .iter()
            .find(|(tenant, _)| tenant.as_str() == "acme")
            .expect("acme's stream");
        assert_eq!(stream.status, asterius_ssf::stream::StreamStatus::Enabled);
        assert_eq!(stream.reason, None);
        drop(streams);

        let events = world.handle.0.events.lock().expect("a lock");
        let recorded = events
            .iter()
            .find(|event| event.event_type == EventType::SSF_STREAM_UPDATED)
            .expect("the change was not recorded");
        assert!(matches!(recorded.actor, Actor::Admin(_)));
        assert_eq!(
            rendered(detail_value(&recorded.detail, "status").expect("a status")).as_deref(),
            Some("enabled")
        );
        // The stream is fingerprinted, as the management endpoint records it.
        assert!(matches!(
            detail_value(&recorded.detail, "stream_id"),
            Some(asterius_domain::audit::DetailValue::Fingerprint(_))
        ));
    }

    /// Pausing by hand carries the hand's reason to the row and the trail.
    #[tokio::test]
    async fn an_operator_pauses_a_stream_with_a_reason() {
        // Arrange
        let world = World::new();
        let cookie = world.sign_in("acme", &[Role::TenantAdmin]);
        world
            .handle
            .0
            .streams
            .lock()
            .expect("a lock")
            .iter_mut()
            .for_each(|(_, stream)| {
                stream.status = asterius_ssf::stream::StreamStatus::Enabled;
                stream.reason = None;
            });

        // Act
        let response = world
            .send(
                as_console(&crate::SSF_STREAM_STATUS_UPDATE, &cookie)
                    .body(Body::from(
                        serde_json::json!({"status": "paused", "reason": "receiver migration"})
                            .to_string(),
                    ))
                    .expect("a request"),
            )
            .await;

        // Assert
        assert_eq!(response.status(), StatusCode::OK);
        let streams = world.handle.0.streams.lock().expect("a lock");
        let (_, stream) = streams
            .iter()
            .find(|(tenant, _)| tenant.as_str() == "acme")
            .expect("acme's stream");
        assert_eq!(stream.status, asterius_ssf::stream::StreamStatus::Paused);
        assert_eq!(stream.reason.as_deref(), Some("receiver migration"));
        drop(streams);
        let events = world.handle.0.events.lock().expect("a lock");
        let recorded = events
            .iter()
            .find(|event| event.event_type == EventType::SSF_STREAM_UPDATED)
            .expect("the change was not recorded");
        assert_eq!(
            rendered(detail_value(&recorded.detail, "reason").expect("a reason")).as_deref(),
            Some("receiver migration")
        );
    }

    /// `disabled` is the receiver's state (§8.1.2), and a status that is
    /// not a status is a 400 that changes nothing and records nothing.
    #[tokio::test]
    async fn a_status_the_operator_may_not_write_is_refused_and_not_recorded() {
        // Arrange
        let world = World::new();
        let cookie = world.sign_in("acme", &[Role::TenantAdmin]);

        // Act
        let response = world
            .send(
                as_console(&crate::SSF_STREAM_STATUS_UPDATE, &cookie)
                    .body(Body::from(
                        serde_json::json!({"status": "disabled"}).to_string(),
                    ))
                    .expect("a request"),
            )
            .await;

        // Assert
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let streams = world.handle.0.streams.lock().expect("a lock");
        assert!(
            streams
                .iter()
                .all(|(_, stream)| stream.status == asterius_ssf::stream::StreamStatus::Paused)
        );
        drop(streams);
        let events = world.handle.0.events.lock().expect("a lock");
        assert!(
            !events
                .iter()
                .any(|event| event.event_type == EventType::SSF_STREAM_UPDATED)
        );
    }

    /// A stream of another tenant, or one that does not exist, is a 404 —
    /// the streams port is asked with the request's tenant, not the path's.
    #[tokio::test]
    async fn a_stream_the_tenant_does_not_hold_is_not_found() {
        // Arrange
        let world = World::new();
        world
            .handle
            .0
            .streams
            .lock()
            .expect("a lock")
            .retain(|(tenant, _)| tenant.as_str() != "acme");
        let cookie = world.sign_in("acme", &[Role::TenantAdmin]);

        // Act
        let status = world
            .send(
                as_console(&crate::SSF_STREAM_STATUS_UPDATE, &cookie)
                    .body(Body::from(
                        serde_json::json!({"status": "enabled"}).to_string(),
                    ))
                    .expect("a request"),
            )
            .await;
        let verify = world
            .send(
                as_console(&crate::SSF_STREAM_VERIFY, &cookie)
                    .body(Body::empty())
                    .expect("a request"),
            )
            .await;

        // Assert
        assert_eq!(status.status(), StatusCode::NOT_FOUND);
        assert_eq!(verify.status(), StatusCode::NOT_FOUND);
    }

    /// **"Trigger verification".** The event is queued with the `state`
    /// verbatim (§8.1.4), and the trail says that a state was given — not
    /// what it was.
    #[tokio::test]
    async fn an_operator_triggers_a_verification_event_with_a_state() {
        // Arrange
        let world = World::new();
        let cookie = world.sign_in("acme", &[Role::TenantAdmin]);

        // Act
        let response = world
            .send(
                as_console(&crate::SSF_STREAM_VERIFY, &cookie)
                    .body(Body::from(
                        serde_json::json!({"state": "corr-0042"}).to_string(),
                    ))
                    .expect("a request"),
            )
            .await;

        // Assert
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let queued = world.handle.0.verifications.lock().expect("a lock");
        assert_eq!(
            queued.as_slice(),
            &[(SEEDED_STREAM_ID.to_owned(), Some("corr-0042".to_owned()))]
        );
        drop(queued);
        let events = world.handle.0.events.lock().expect("a lock");
        let recorded = events
            .iter()
            .find(|event| event.event_type == EventType::SSF_VERIFICATION_REQUESTED)
            .expect("the verification was not recorded");
        assert!(matches!(recorded.actor, Actor::Admin(_)));
        assert_eq!(
            detail_value(&recorded.detail, "with_state"),
            Some(&asterius_domain::audit::DetailValue::Flag(true))
        );
        let serialised = format!("{:?}", recorded.detail);
        assert!(
            !serialised.contains("corr-0042"),
            "the state reached the trail"
        );
    }

    /// A `state` the profile refuses is a 400 and queues nothing.
    #[tokio::test]
    async fn a_verification_with_a_refused_state_queues_nothing() {
        // Arrange
        let world = World::new();
        let cookie = world.sign_in("acme", &[Role::TenantAdmin]);

        // Act
        let response = world
            .send(
                as_console(&crate::SSF_STREAM_VERIFY, &cookie)
                    .body(Body::from(
                        serde_json::json!({"state": "line\nbreak"}).to_string(),
                    ))
                    .expect("a request"),
            )
            .await;

        // Assert
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(
            world
                .handle
                .0
                .verifications
                .lock()
                .expect("a lock")
                .is_empty()
        );
    }

    /// **The dead-letter half of the first criterion.** A retry takes the
    /// row off the screen, puts it back on the schedule, and is recorded
    /// with the row's kind and attempt count under the operator's name.
    #[tokio::test]
    async fn an_operator_requeues_an_abandoned_set_and_it_is_audited() {
        // Arrange
        let world = World::new();
        let cookie = world.sign_in("acme", &[Role::TenantAdmin]);

        // Act
        let response = world
            .send(
                as_console(&crate::OUTBOX_DEAD_LETTER_RETRY, &cookie)
                    .body(Body::empty())
                    .expect("a request"),
            )
            .await;

        // Assert
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_of(response).await["requeued"], true);
        assert_eq!(
            world.handle.0.requeued.lock().expect("a lock").as_slice(),
            &[RETRY_LETTER_ID]
        );
        let letters = world.handle.0.dead_letters.lock().expect("a lock");
        assert!(!letters.iter().any(|letter| letter.id == RETRY_LETTER_ID));
        drop(letters);
        let events = world.handle.0.events.lock().expect("a lock");
        let recorded = events
            .iter()
            .find(|event| event.event_type == EventType::OUTBOX_RETRIED)
            .expect("the retry was not recorded");
        assert!(matches!(recorded.actor, Actor::Admin(_)));
        assert_eq!(
            detail_value(&recorded.detail, "outbox_id"),
            Some(&asterius_domain::audit::DetailValue::Number(
                RETRY_LETTER_ID
            ))
        );
        assert_eq!(
            rendered(detail_value(&recorded.detail, "kind").expect("a kind")).as_deref(),
            Some("ssf.set")
        );
        assert_eq!(
            detail_value(&recorded.detail, "attempts"),
            Some(&asterius_domain::audit::DetailValue::Number(10))
        );
    }

    /// A drop removes the row and leaves the record that is now the only
    /// trace of it: kind, attempts and the receiver's last word.
    #[tokio::test]
    async fn an_operator_drops_an_abandoned_set_and_the_record_outlives_it() {
        // Arrange
        let world = World::new();
        let cookie = world.sign_in("acme", &[Role::TenantAdmin]);

        // Act
        let response = world
            .send(
                as_console(&crate::OUTBOX_DEAD_LETTER_DROP, &cookie)
                    .body(Body::empty())
                    .expect("a request"),
            )
            .await;

        // Assert
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            world.handle.0.dropped.lock().expect("a lock").as_slice(),
            &[DROP_LETTER_ID]
        );
        let events = world.handle.0.events.lock().expect("a lock");
        let recorded = events
            .iter()
            .find(|event| event.event_type == EventType::OUTBOX_DROPPED)
            .expect("the drop was not recorded");
        assert_eq!(
            rendered(detail_value(&recorded.detail, "last_error").expect("the last error"))
                .as_deref(),
            Some("the receiver answered 503; the SET is still owed")
        );
    }

    /// The rule of `crate::outbox`: a row of another family is refused with
    /// a 409 that names the rule, and nothing is requeued or dropped.
    #[tokio::test]
    async fn a_dead_letter_of_another_family_is_neither_retried_nor_dropped() {
        // Arrange
        let world = World::new();
        {
            let mut letters = world.handle.0.dead_letters.lock().expect("a lock");
            for letter in letters.iter_mut() {
                letter.kind = "notification.account_recovery".to_owned();
            }
        }
        let cookie = world.sign_in("acme", &[Role::TenantAdmin]);

        // Act
        let retry = world
            .send(
                as_console(&crate::OUTBOX_DEAD_LETTER_RETRY, &cookie)
                    .body(Body::empty())
                    .expect("a request"),
            )
            .await;
        let drop = world
            .send(
                as_console(&crate::OUTBOX_DEAD_LETTER_DROP, &cookie)
                    .body(Body::empty())
                    .expect("a request"),
            )
            .await;

        // Assert
        assert_eq!(retry.status(), StatusCode::CONFLICT);
        assert_eq!(drop.status(), StatusCode::CONFLICT);
        assert!(world.handle.0.requeued.lock().expect("a lock").is_empty());
        assert!(world.handle.0.dropped.lock().expect("a lock").is_empty());
        assert_eq!(world.handle.0.dead_letters.lock().expect("a lock").len(), 6);
    }

    /// A row that is not abandoned — or is somebody else's — is a 404.
    #[tokio::test]
    async fn a_dead_letter_that_does_not_exist_is_not_found() {
        // Arrange
        let world = World::new();
        world.forget_dead_letters();
        let cookie = world.sign_in("acme", &[Role::TenantAdmin]);

        // Act
        let response = world
            .send(
                as_console(&crate::OUTBOX_DEAD_LETTER_RETRY, &cookie)
                    .body(Body::empty())
                    .expect("a request"),
            )
            .await;

        // Assert
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    /// **The export's RBAC, as the criterion states it.** A support agent
    /// holds `admin.users:read` and `admin.sessions:write` and does not hold
    /// `admin.audit:read`: the export is a 403 and the body is the error
    /// envelope, never a line of the trail.
    #[tokio::test]
    async fn the_export_is_refused_to_a_caller_without_the_audit_scope() {
        // Arrange
        let world = World::new();
        let cookie = world.sign_in("acme", &[Role::UserSupport]);

        // Act
        let response = world.get(&crate::AUDIT_EVENTS_EXPORT, &cookie).await;

        // Assert
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_ne!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some(audit::NDJSON)
        );
    }

    // ---- the audit query API (`ast-lh3.9`) --------------------------------

    fn agent_actor(id: &str, owner: &str) -> asterius_domain::audit::Actor {
        asterius_domain::audit::Actor::Agent {
            client: asterius_domain::ClientId::new(id),
            on_behalf_of: owner.to_owned(),
        }
    }

    /// The chain user alice → agent A → agent B in `acme`, as the token
    /// endpoints write it, plus noise: carol's agent and a record in another
    /// tenant.
    fn seed_delegation_chain(world: &World) {
        use asterius_domain::audit::{Actor, Detail, EventType, Outcome};
        let at = |seconds: i64| OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(seconds);
        let mut events = world.handle.0.events.lock().expect("an uncontended lock");
        events.push(
            AuditEvent::new(
                TenantId::new("acme"),
                EventType::TOKEN_ISSUED,
                Outcome::Success,
                agent_actor("c.a", "alice"),
                at(10),
            )
            .client(asterius_domain::ClientId::new("c.a"))
            .grant(asterius_domain::GrantId::new(
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            ))
            .detail(
                Detail::new()
                    .label("grant_type", "client_credentials")
                    .pii("ip", "203.0.113.5")
                    .pii("user_agent", "Mozilla/5.0 (agent-runner)"),
            ),
        );
        events.push(
            AuditEvent::new(
                TenantId::new("acme"),
                EventType::TOKEN_EXCHANGED,
                Outcome::Success,
                agent_actor("c.b", "bob"),
                at(20),
            )
            .client(asterius_domain::ClientId::new("c.b"))
            .subject("alice")
            .grant(asterius_domain::GrantId::new(
                "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            ))
            .actor_chain(vec![Actor::Client(asterius_domain::ClientId::new("c.a"))]),
        );
        events.push(
            AuditEvent::new(
                TenantId::new("acme"),
                EventType::TOKEN_ISSUED,
                Outcome::Success,
                agent_actor("c.c", "carol"),
                at(30),
            )
            .client(asterius_domain::ClientId::new("c.c")),
        );
        events.push(
            AuditEvent::new(
                TenantId::new("other"),
                EventType::TOKEN_ISSUED,
                Outcome::Success,
                agent_actor("c.a", "alice"),
                at(40),
            )
            .client(asterius_domain::ClientId::new("c.a")),
        );
    }

    /// The acceptance criterion: "everything done under alice" is the
    /// issuance to A and the exchange by B, newest first, with B's chain
    /// intact — and nothing of carol's, and nothing from another tenant.
    #[tokio::test]
    async fn everything_done_under_a_user_lists_the_whole_delegation_chain() {
        // Arrange
        let world = World::new();
        seed_delegation_chain(&world);
        let cookie = world.sign_in("acme", &[Role::SecurityAuditor]);

        // Act
        let response = world
            .get_with_query(&crate::AUDIT_EVENTS_LIST, "user=alice", &cookie)
            .await;

        // Assert
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_of(response).await;
        let items = body["items"].as_array().expect("an items array");
        assert_eq!(items.len(), 2, "{body}");
        assert_eq!(items[0]["type"], "token.exchanged");
        assert_eq!(items[0]["agent_id"], "c.b");
        assert_eq!(items[0]["agent_owner"], "bob");
        assert_eq!(items[0]["subject"], "alice");
        assert_eq!(items[0]["actor_chain"][0]["id"], "c.a");
        assert_eq!(items[0]["grant_id"], "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb");
        assert_eq!(items[1]["type"], "token.issued");
        assert_eq!(items[1]["agent_id"], "c.a");
        assert_eq!(items[1]["agent_owner"], "alice");
        assert!(
            items[1]["hash"]
                .as_str()
                .is_some_and(|hash| hash.len() == 64)
        );
        assert_eq!(body["next_cursor"], serde_json::Value::Null);
    }

    /// RFC 8693 §4.1: A is a link in B's exchange, so a filter on A finds it.
    #[tokio::test]
    async fn an_agent_filter_finds_the_exchanges_it_was_a_link_in() {
        // Arrange
        let world = World::new();
        seed_delegation_chain(&world);
        let cookie = world.sign_in("acme", &[Role::TenantAdmin]);

        // Act
        let response = world
            .get_with_query(
                &crate::AUDIT_EVENTS_LIST,
                "agent=c.a&type=token.exchanged",
                &cookie,
            )
            .await;

        // Assert
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_of(response).await;
        let items = body["items"].as_array().expect("an items array");
        assert_eq!(items.len(), 1, "{body}");
        assert_eq!(items[0]["agent_id"], "c.b");
    }

    /// Keyset paging through the listing: a page of one, a cursor, the next
    /// page, and a `null` cursor at the end.
    #[tokio::test]
    async fn the_listing_pages_by_cursor() {
        // Arrange
        let world = World::new();
        seed_delegation_chain(&world);
        let cookie = world.sign_in("acme", &[Role::TenantAdmin]);

        // Act
        let first = body_of(
            world
                .get_with_query(&crate::AUDIT_EVENTS_LIST, "limit=2", &cookie)
                .await,
        )
        .await;
        let cursor = first["next_cursor"].as_str().expect("a cursor").to_owned();
        let second = body_of(
            world
                .get_with_query(
                    &crate::AUDIT_EVENTS_LIST,
                    &format!("limit=2&cursor={cursor}"),
                    &cookie,
                )
                .await,
        )
        .await;

        // Assert
        assert_eq!(first["items"].as_array().map(Vec::len), Some(2));
        assert_eq!(second["items"].as_array().map(Vec::len), Some(1));
        assert_eq!(second["items"][0]["type"], "token.issued");
        assert_eq!(second["items"][0]["agent_id"], "c.a");
        assert_eq!(second["next_cursor"], serde_json::Value::Null);
    }

    /// A misspelled filter is a 400, not the whole trail.
    #[tokio::test]
    async fn an_unknown_filter_parameter_is_refused() {
        // Arrange
        let world = World::new();
        seed_delegation_chain(&world);
        let cookie = world.sign_in("acme", &[Role::TenantAdmin]);

        // Act
        let response = world
            .get_with_query(&crate::AUDIT_EVENTS_LIST, "agnet=c.a", &cookie)
            .await;

        // Assert
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    /// The export: NDJSON, one line per record, newest first, the same filter
    /// semantics as the listing — and PII minimised on every line, because
    /// what was fingerprinted on the way in is a digest on the way out.
    #[tokio::test]
    async fn the_export_streams_ndjson_with_hashed_personal_data() {
        // Arrange
        let world = World::new();
        seed_delegation_chain(&world);
        let cookie = world.sign_in("acme", &[Role::SecurityAuditor]);

        // Act
        let response = world
            .get_with_query(&crate::AUDIT_EVENTS_EXPORT, "user=alice", &cookie)
            .await;

        // Assert
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some(audit::NDJSON)
        );
        assert_eq!(
            response
                .headers()
                .get(header::CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
            Some("no-store")
        );
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .expect("a readable body");
        let text = std::str::from_utf8(&bytes).expect("utf-8");
        let lines: Vec<serde_json::Value> = text
            .lines()
            .map(|line| serde_json::from_str(line).expect("one JSON text per line"))
            .collect();
        assert_eq!(lines.len(), 2, "{text}");
        assert_eq!(lines[0]["type"], "token.exchanged");
        assert_eq!(lines[1]["type"], "token.issued");
        assert!(
            !text.contains("203.0.113.5"),
            "an address reached the export: {text}"
        );
        assert!(
            !text.contains("Mozilla"),
            "a user agent reached the export: {text}"
        );
        assert!(text.contains("\"ip\":\"sha256:"), "{text}");
    }

    /// The scope is `admin.audit:read`: the auditor and the administrator
    /// hold it by definition, and support — who may look up an account —
    /// does not thereby get to read everything everyone did.
    #[tokio::test]
    async fn the_trail_is_read_by_auditors_and_not_by_support() {
        // Arrange
        let world = World::new();

        // Act / Assert
        for operation in [&crate::AUDIT_EVENTS_LIST, &crate::AUDIT_EVENTS_EXPORT] {
            assert_eq!(
                world
                    .as_role(operation, Role::SecurityAuditor)
                    .await
                    .status(),
                StatusCode::OK,
                "{}",
                operation.id()
            );
            assert_eq!(
                world.as_role(operation, Role::TenantAdmin).await.status(),
                StatusCode::OK,
                "{}",
                operation.id()
            );
            assert_eq!(
                world.as_role(operation, Role::UserSupport).await.status(),
                StatusCode::FORBIDDEN,
                "{}",
                operation.id()
            );
        }
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

        for operation in world.api().operations() {
            // One session per route, because `session.end` is a route: reusing
            // a cookie across the loop would have every operation after it
            // answer 401 for a reason that has nothing to do with authority.
            let cookie = world.sign_in("acme", &[Role::TenantAdmin]);
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

    /// Walks the registry for one restricted role and asserts that a route is
    /// refused exactly when the role's authority map says it should be.
    ///
    /// Written once and called twice, because the interesting part is the
    /// predicate — reach *and* scope, from [`Role::grants`] — and not the
    /// request plumbing around it. A per-route expected list would be a second
    /// copy of the mapping, and the copy is what goes stale when a route is
    /// added.
    async fn each_route_agrees_with_the_authority_map(role: Role) {
        // Arrange
        let world = World::new();

        for operation in world.api().operations() {
            // Act
            let response = world.as_role(operation, role).await;

            // Assert
            let authority = operation.authority();
            let allowed = authority.reach() != Reach::Deployment && role.grants(authority.scope());
            assert_eq!(
                response.status() == StatusCode::FORBIDDEN,
                !allowed,
                "{} answered {} for a {role}, which {} `{}`",
                operation.id(),
                response.status(),
                if allowed { "holds" } else { "does not hold" },
                authority.scope()
            );
        }
    }

    /// The distinction `user_support` exists for, asserted over every route
    /// there is: it may end a session (`admin.sessions:write`) and may not
    /// edit the claims that describe somebody (`admin.users:write`).
    #[tokio::test]
    async fn a_support_agent_is_refused_exactly_what_it_does_not_hold() {
        each_route_agrees_with_the_authority_map(Role::UserSupport).await;
    }

    /// And the auditor's one property: it is refused every mutation on the
    /// admin surface, including the ones a support agent is allowed.
    #[tokio::test]
    async fn a_security_auditor_is_refused_exactly_what_it_does_not_hold() {
        each_route_agrees_with_the_authority_map(Role::SecurityAuditor).await;
    }

    /// The two refusals spelled out on the routes the bead names, so that a
    /// reader who does not want to unfold the predicate above can still see
    /// what a support agent may and may not do.
    #[tokio::test]
    async fn a_support_agent_ends_a_session_and_cannot_edit_the_claims() {
        // Arrange
        let world = World::new();

        // Act
        let editing = world
            .as_role(&crate::USER_CLAIMS_UPDATE, Role::UserSupport)
            .await;
        let revoking = world
            .as_role(&crate::USER_SESSION_REVOKE, Role::UserSupport)
            .await;

        // Assert
        assert_eq!(editing.status(), StatusCode::FORBIDDEN);
        assert_ne!(revoking.status(), StatusCode::FORBIDDEN);
    }

    /// Every mounted route has a handler. Without this the `match` in
    /// [`handle`] would answer 503 for a route somebody registered and forgot
    /// to wire, which looks like an outage rather than a mistake.
    #[tokio::test]
    async fn every_registered_operation_has_a_handler() {
        // Arrange
        let world = World::new().routed_at("asterius-admin");

        for operation in world.api().operations() {
            // A fresh session per route: `session.end` ends the one it is
            // called with, and a shared cookie would turn every later route
            // into a 401 that says nothing about whether it has a handler.
            let cookie = world.sign_in("asterius-admin", &[Role::DeploymentAdmin]);
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

    // ---- the authenticator a deployment admin must have used (`ast-895`) ---

    /// The rule. A deployment admin holding a passkey does not administer the
    /// deployment on a password, whatever the password is: NIST SP 800-63B
    /// §5.2.5 wants verifier impersonation resistance on the account that
    /// reaches every tenant.
    #[tokio::test]
    async fn a_deployment_admin_on_a_password_is_sent_to_a_passkey_step_up() {
        // Arrange
        let world = World::new().routed_at("asterius-admin");
        let cookie = world.sign_in_with(
            "asterius-admin",
            &[Role::DeploymentAdmin],
            &[AuthenticationMethod::Password],
            asterius_domain::PasskeyEnrolment::Enrolled,
        );

        // Act
        let response = world.get(&crate::TENANTS_LIST, &cookie).await;

        // Assert
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            body_of(response).await["error"]["code"],
            "step_up_required",
            "the console cannot tell this from an expired session"
        );
    }

    /// The same session, with the passkey presented.
    #[tokio::test]
    async fn a_deployment_admin_who_used_a_user_verified_passkey_is_admitted() {
        // Arrange
        let world = World::new().routed_at("asterius-admin");
        let cookie = world.sign_in_with(
            "asterius-admin",
            &[Role::DeploymentAdmin],
            &[
                AuthenticationMethod::Password,
                AuthenticationMethod::Passkey,
                AuthenticationMethod::UserVerified,
            ],
            asterius_domain::PasskeyEnrolment::Enrolled,
        );

        // Act
        let response = world.get(&crate::TENANTS_LIST, &cookie).await;

        // Assert
        assert!(response.status().is_success(), "{}", response.status());
    }

    /// A passkey with no UV proved possession and nothing about who was
    /// holding the authenticator.
    #[tokio::test]
    async fn a_passkey_without_user_verification_does_not_open_the_admin_surface() {
        // Arrange
        let world = World::new().routed_at("asterius-admin");
        let cookie = world.sign_in_with(
            "asterius-admin",
            &[Role::DeploymentAdmin],
            &[AuthenticationMethod::Passkey],
            asterius_domain::PasskeyEnrolment::Enrolled,
        );

        // Act
        let response = world.get(&crate::TENANTS_LIST, &cookie).await;

        // Assert
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(body_of(response).await["error"]["code"], "step_up_required");
    }

    /// The bootstrap window, written down: the seeded admin has a password and
    /// no passkey, and it is the account that would have to enrol one. See
    /// `asterius_domain::admin_access_policy` and `docs/threat-model.md`.
    #[tokio::test]
    async fn the_seeded_admin_may_still_sign_in_before_it_has_enrolled_a_passkey() {
        // Arrange
        let world = World::new().routed_at("asterius-admin");
        let cookie = world.sign_in_with(
            "asterius-admin",
            &[Role::DeploymentAdmin],
            &[AuthenticationMethod::Password],
            asterius_domain::PasskeyEnrolment::None,
        );

        // Act
        let response = world.get(&crate::TENANTS_LIST, &cookie).await;

        // Assert
        assert!(
            response.status().is_success(),
            "a fresh deployment would have nobody able to enrol a passkey: {}",
            response.status()
        );
    }

    /// The rule is about deployment scope. A tenant admin's assurance is the
    /// tenant's own `acr` policy, decided elsewhere.
    #[tokio::test]
    async fn a_tenant_admin_on_a_password_is_not_touched_by_this_rule() {
        // Arrange
        let world = World::new();
        let cookie = world.sign_in_with(
            "acme",
            &[Role::TenantAdmin],
            &[AuthenticationMethod::Password],
            asterius_domain::PasskeyEnrolment::Enrolled,
        );

        // Act
        let response = world.get(&crate::CLIENTS_LIST, &cookie).await;

        // Assert
        assert!(response.status().is_success(), "{}", response.status());
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

    /// The console navigates by what the caller may *do*, so the session
    /// document reports it — computed from the same registry and the same
    /// `satisfies` every request goes through (`ast-3t8`).
    #[tokio::test]
    async fn the_session_document_reports_the_scopes_the_caller_holds() {
        // Arrange
        let world = World::new();
        let support = world.sign_in("acme", &[Role::UserSupport]);
        let admin = world.sign_in("acme", &[Role::TenantAdmin]);

        // Act
        let held = body_of(world.get(&crate::SESSION_READ, &support).await).await;
        let everything = body_of(world.get(&crate::SESSION_READ, &admin).await).await;

        // Assert
        let scopes = held["scopes"].as_array().expect("a list").clone();
        assert!(scopes.contains(&serde_json::json!("admin.sessions:write")));
        assert!(scopes.contains(&serde_json::json!("admin.users:read")));
        assert!(!scopes.contains(&serde_json::json!("admin.users:write")));
        // Tenant-scoped either way, so the deployment list is empty for both.
        assert_eq!(held["deployment_scopes"], serde_json::json!([]));
        assert_eq!(everything["deployment_scopes"], serde_json::json!([]));
        assert!(
            everything["scopes"]
                .as_array()
                .expect("a list")
                .contains(&serde_json::json!("admin.users:write"))
        );
    }

    /// A deployment admin's two lists differ, which is what lets the console
    /// tell "may read this tenant" from "may read every tenant" without
    /// knowing a role name.
    #[tokio::test]
    async fn a_deployment_admin_holds_scopes_in_both_lists() {
        // Arrange
        let world = World::new().routed_at("asterius-admin");
        let cookie = world.sign_in("asterius-admin", &[Role::DeploymentAdmin]);

        // Act
        let document = body_of(world.get(&crate::SESSION_READ, &cookie).await).await;

        // Assert
        assert!(
            document["deployment_scopes"]
                .as_array()
                .expect("a list")
                .contains(&serde_json::json!("admin.tenants:read"))
        );
        assert!(
            document["scopes"]
                .as_array()
                .expect("a list")
                .contains(&serde_json::json!("admin.tenants:read"))
        );
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

    // ---- application roles (`ast-095`) ------------------------------------

    /// Deleting a role somebody still holds is refused, not cascaded.
    ///
    /// The decision `ast-095` asked to be made: a cascade would be one request
    /// that withdraws authority from an unbounded number of people, recorded
    /// as one audit event naming none of them. The refusal is the schema's
    /// `on delete restrict`; what is asserted here is that the API renders it
    /// as a 409 and that the role is still there afterwards.
    #[tokio::test]
    async fn deleting_a_role_somebody_holds_is_refused_with_409() {
        // Arrange
        let world = World::new().routed_at("asterius-admin");
        let cookie = world.sign_in("asterius-admin", &[Role::DeploymentAdmin]);

        // Act
        let response = world
            .send(
                HttpRequest::builder()
                    .method("DELETE")
                    .uri(format!("{}/app-roles/{HELD_ROLE}", crate::BASE_PATH))
                    .header("origin", ORIGIN)
                    .header(
                        "cookie",
                        format!(
                            "{}={cookie}",
                            asterius_domain::entities::session::COOKIE_NAME
                        ),
                    )
                    .header(csrf::HEADER, csrf::token(&cookie))
                    .body(Body::empty())
                    .expect("a request"),
            )
            .await;

        // Assert
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let still_there = world
            .handle
            .0
            .role_catalogue
            .lock()
            .expect("an uncontended lock")
            .iter()
            .any(|role| role.name.as_str() == HELD_ROLE);
        assert!(still_there, "a held role was deleted anyway");
    }

    /// Assigning a role that is in no catalogue is a conflict, never a silent
    /// creation: assignment must not be a way to invent a name that ends up in
    /// a token.
    #[tokio::test]
    async fn assigning_a_role_that_was_never_created_is_refused() {
        // Arrange
        let world = World::new().routed_at("asterius-admin");
        let cookie = world.sign_in("asterius-admin", &[Role::DeploymentAdmin]);

        // Act
        let response = world
            .send(
                HttpRequest::builder()
                    .method("POST")
                    .uri(format!(
                        "{}/users/{SEEDED_USER_ID}/app-roles",
                        crate::BASE_PATH
                    ))
                    .header("origin", ORIGIN)
                    .header(
                        "cookie",
                        format!(
                            "{}={cookie}",
                            asterius_domain::entities::session::COOKIE_NAME
                        ),
                    )
                    .header(csrf::HEADER, csrf::token(&cookie))
                    .header(idempotency::HEADER, "an-invented-role")
                    .body(Body::from(
                        serde_json::json!({"name": "invented"}).to_string(),
                    ))
                    .expect("a request"),
            )
            .await;

        // Assert
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    /// A name outside the alphabet is a 400 and not a 409 or a 404: it is a
    /// statement about the request, and a caller told 404 would retry a
    /// spelling that can never exist.
    #[tokio::test]
    async fn a_role_name_outside_the_alphabet_is_a_bad_request() {
        // Arrange
        let world = World::new().routed_at("asterius-admin");
        let cookie = world.sign_in("asterius-admin", &[Role::DeploymentAdmin]);

        // Act
        let response = world
            .send(
                HttpRequest::builder()
                    .method("POST")
                    .uri(format!("{}/app-roles", crate::BASE_PATH))
                    .header("origin", ORIGIN)
                    .header(
                        "cookie",
                        format!(
                            "{}={cookie}",
                            asterius_domain::entities::session::COOKIE_NAME
                        ),
                    )
                    .header(csrf::HEADER, csrf::token(&cookie))
                    .header(idempotency::HEADER, "a-name-with-a-space")
                    .body(Body::from(
                        serde_json::json!({"name": "read write"}).to_string(),
                    ))
                    .expect("a request"),
            )
            .await;

        // Assert
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    /// The account screen reports both catalogues in the shape a token uses,
    /// so an administrator and a developer are reading one structure.
    #[tokio::test]
    async fn the_account_screen_reports_both_kinds_of_role() {
        // Arrange
        let world = World::new().routed_at("asterius-admin");
        let cookie = world.sign_in("asterius-admin", &[Role::DeploymentAdmin]);

        // Act
        let response = world
            .send(
                HttpRequest::builder()
                    .method("GET")
                    .uri(format!(
                        "{}/users/{SEEDED_USER_ID}/app-roles",
                        crate::BASE_PATH
                    ))
                    .header("origin", ORIGIN)
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
        let body = body_of(response).await;
        assert_eq!(body["roles"], serde_json::json!([HELD_ROLE]));
        assert_eq!(
            body["resource_access"][SEEDED_CLIENT_ID]["roles"],
            serde_json::json!([HELD_ROLE])
        );
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

    /// **`ast-8gm`.** A deployment admin's session lives in the reserved
    /// tenant and can live nowhere else (ADR-0010), so administering another
    /// tenant means presenting that session at that tenant's prefix — there is
    /// no other address for `Reach::Tenant` routes, which name no tenant in
    /// their path on purpose. Looking the cookie up only in the tenant the
    /// request was routed to made every one of those routes answer 401 "the
    /// session presented is not usable" to the only administrator a deployment
    /// seeds, and left `Held::roles_satisfy`'s deployment-wide branch
    /// unreachable for the console.
    #[tokio::test]
    async fn a_deployment_admin_administers_another_tenant_with_the_session_it_has() {
        // Arrange
        let world = World::new().routed_at("acme");
        let cookie = world.sign_in("asterius-admin", &[Role::DeploymentAdmin]);

        // Act
        let response = world.get(&crate::CLIENTS_LIST, &cookie).await;

        // Assert
        assert_eq!(response.status(), StatusCode::OK);
    }

    /// The other half of the same rule: resolving a reserved-tenant session
    /// elsewhere is not admitting it. A user of the reserved tenant holding a
    /// *tenant*-scoped role has authority over that tenant and over no other,
    /// so the answer is 403 — "not you" — rather than the 401 that would tell
    /// a console to sign in again for a session that is perfectly good.
    #[tokio::test]
    async fn a_reserved_tenant_user_without_deployment_scope_is_refused_elsewhere() {
        // Arrange
        let world = World::new().routed_at("acme");
        let cookie = world.sign_in("asterius-admin", &[Role::TenantAdmin]);

        // Act
        let response = world.get(&crate::CLIENTS_LIST, &cookie).await;

        // Assert
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
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
            reserved_tenant: None,
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
                reserved_tenant: None,
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

    // ---- signing keys (`ast-f7m.7`) ---------------------------------------

    /// A signed-in tenant administrator, and the console's way of calling a
    /// route: session cookie, synchroniser token, idempotency key.
    fn as_console(operation: &Operation, cookie: &str) -> axum::http::request::Builder {
        request_for(operation)
            .header(
                "cookie",
                format!(
                    "{}={cookie}",
                    asterius_domain::entities::session::COOKIE_NAME
                ),
            )
            .header(csrf::HEADER, csrf::token(cookie))
            .header(idempotency::HEADER, format!("key-{}", uuid::Uuid::new_v4()))
    }

    // ---- clients (`ast-f7m.5`) ---------------------------------------------

    /// A console signed in to the tenant the registry walk seeds with an active
    /// signing key, which is what a tenant needs before it can register a
    /// client at all.
    fn console_in_a_signing_tenant() -> (World, String) {
        let world = World::new().routed_at("asterius-admin");
        let cookie = world.sign_in("asterius-admin", &[Role::TenantAdmin]);
        (world, cookie)
    }

    async fn post_client(world: &World, cookie: &str, document: &serde_json::Value) -> Response {
        world
            .send(
                as_console(&crate::CLIENT_CREATE, cookie)
                    .body(Body::from(document.to_string()))
                    .expect("a request"),
            )
            .await
    }

    /// **The acceptance criterion of `ast-m9c.6` for this crate.** The tenant's
    /// registration policy is not a property of the `POST /register` endpoint;
    /// it is a property of the tenant, so the console is bound by it too. A
    /// second door that ignored the policy would be the way around it.
    #[tokio::test]
    async fn the_console_cannot_register_a_client_the_tenants_policy_refuses() {
        // Arrange
        let (world, cookie) = console_in_a_signing_tenant();
        let policy = asterius_domain::RegistrationPolicy::from_json(Some(&serde_json::json!({
            "redirect_uri_hosts": ["trusted.example.test"]
        })))
        .expect("a valid policy");
        world.handle.0.settings.lock().expect("lock").insert(
            "asterius-admin".to_owned(),
            TenantSettings::default().with_registration(policy),
        );

        // Act
        let response = post_client(&world, &cookie, &valid_registration()).await;

        // Assert
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "the console registered a callback host the tenant's policy excludes"
        );
        let body = body_of(response).await;
        assert!(
            body["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains("client_metadata")),
            "the refusal does not carry the RFC 7591 §3.2.2 code: {body}"
        );
    }

    /// **The acceptance criterion of `ast-f7m.5`.** The console must not be
    /// able to create a client dynamic client registration would refuse.
    ///
    /// Each document below is refused by `ClientMetadata::validate` for a
    /// reason the specifications give, and the console reaches that validator
    /// through the same call `POST /register` makes — so this test is really
    /// asserting that no second, laxer definition of a valid client was written
    /// for the admin API. The `client_name` on each one is what would be stored
    /// if any of them were accepted, and the inventory is checked afterwards.
    #[tokio::test]
    async fn the_console_cannot_register_a_client_dynamic_registration_would_refuse() {
        // Arrange
        let (world, cookie) = console_in_a_signing_tenant();
        let refused = [
            // ADR-0005 / OAuth Security BCP §2.1: a web client's callback is
            // https.
            (
                "plaintext callback",
                serde_json::json!({
                    "client_name": "Refused",
                    "redirect_uris": ["http://app.example.test/callback"],
                    "jwks_uri": "https://app.example.test/jwks.json",
                }),
            ),
            // RFC 7591 §2: `jwks` and `jwks_uri` are mutually exclusive.
            (
                "both key sources",
                serde_json::json!({
                    "client_name": "Refused",
                    "redirect_uris": ["https://app.example.test/callback"],
                    "jwks_uri": "https://app.example.test/jwks.json",
                    "jwks": {"keys": []},
                }),
            ),
            // RFC 8725 §3.1 and ADR-0003: the algorithm list is closed.
            (
                "an algorithm off the list",
                serde_json::json!({
                    "client_name": "Refused",
                    "redirect_uris": ["https://app.example.test/callback"],
                    "jwks_uri": "https://app.example.test/jwks.json",
                    "id_token_signed_response_alg": "RS256",
                }),
            ),
            // FAPI 2.0 SP §5.3.2.1: no shared secret authentication.
            (
                "a shared secret",
                serde_json::json!({
                    "client_name": "Refused",
                    "redirect_uris": ["https://app.example.test/callback"],
                    "jwks_uri": "https://app.example.test/jwks.json",
                    "token_endpoint_auth_method": "client_secret_basic",
                }),
            ),
            // ADR-0002: the implicit and hybrid flows do not exist here.
            (
                "an implicit response type",
                serde_json::json!({
                    "client_name": "Refused",
                    "redirect_uris": ["https://app.example.test/callback"],
                    "jwks_uri": "https://app.example.test/jwks.json",
                    "response_types": ["token"],
                }),
            ),
            // RFC 7591 §2: a client needs keys this server can verify with.
            (
                "no key source at all",
                serde_json::json!({
                    "client_name": "Refused",
                    "redirect_uris": ["https://app.example.test/callback"],
                }),
            ),
        ];

        for (what, document) in refused {
            // Act
            let response = post_client(&world, &cookie, &document).await;

            // Assert
            assert_eq!(
                response.status(),
                StatusCode::BAD_REQUEST,
                "the console accepted {what}"
            );
            let body = body_of(response).await;
            assert_eq!(body["error"]["code"], serde_json::json!("invalid_request"));
            assert!(
                body["error"]["message"]
                    .as_str()
                    .is_some_and(|message| message.contains("client_metadata")
                        || message.contains("redirect_uri")),
                "{what} was refused without the RFC 7591 §3.2.2 code: {body}"
            );
        }

        // And nothing was written: a refusal that stored a row would be worse
        // than an acceptance, because the console would not show it either.
        let listed = body_of(
            world
                .send(
                    as_console(&crate::CLIENTS_LIST, &cookie)
                        .body(Body::empty())
                        .expect("a request"),
                )
                .await,
        )
        .await;
        let names: Vec<&str> = listed["items"]
            .as_array()
            .expect("a page of clients")
            .iter()
            .filter_map(|row| row["client_name"].as_str())
            .collect();
        assert!(!names.contains(&"Refused"), "{listed}");
    }

    /// The client an administrator gets back is the one that was stored, and it
    /// is a document the edit form can save again unchanged.
    ///
    /// The second half is the one that rots silently: a rendering that dropped
    /// or renamed a member would leave every visit to the edit screen one
    /// "Save" away from rewriting the client.
    #[tokio::test]
    async fn a_client_created_from_the_console_reads_back_and_saves_unchanged() {
        // Arrange
        let (world, cookie) = console_in_a_signing_tenant();

        // Act
        let created = post_client(&world, &cookie, &valid_registration()).await;
        assert_eq!(created.status(), StatusCode::CREATED);
        let created = body_of(created).await;
        let id = created["client_id"]
            .as_str()
            .expect("a client_id")
            .to_owned();

        let read = body_of(
            world
                .send(
                    as_console(&crate::CLIENT_READ, &cookie)
                        .uri(crate::CLIENT_READ.full_path().replace("{client_id}", &id))
                        .body(Body::empty())
                        .expect("a request"),
                )
                .await,
        )
        .await;

        let saved = world
            .send(
                as_console(&crate::CLIENT_UPDATE, &cookie)
                    .uri(crate::CLIENT_UPDATE.full_path().replace("{client_id}", &id))
                    .body(Body::from(read.to_string()))
                    .expect("a request"),
            )
            .await;

        // Assert
        assert_eq!(created, read, "the created client is not the one read back");
        assert_eq!(
            saved.status(),
            StatusCode::OK,
            "an unedited client could not be saved"
        );
        let saved = body_of(saved).await;
        for member in [
            "client_id",
            "redirect_uris",
            "grant_types",
            "scope",
            "jwks_uri",
            "token_endpoint_auth_method",
            "id_token_signed_response_alg",
            "status",
        ] {
            assert_eq!(
                saved[member], read[member],
                "saving changed {member}: {saved}"
            );
        }
    }

    /// FAPI 2.0 SP §5.3.2.1 and OIDC Registration §3.2: this server issues no
    /// `client_secret`, and a client created from the console has no
    /// registration access token either — it is managed from the console, so it
    /// gets neither a configuration endpoint nor a token for one.
    ///
    /// Asserted over the whole serialised response rather than member by
    /// member, because the failure this guards against is a *new* member.
    #[tokio::test]
    async fn a_client_created_from_the_console_is_handed_no_credential() {
        // Arrange
        let (world, cookie) = console_in_a_signing_tenant();

        // Act
        let created = body_of(post_client(&world, &cookie, &valid_registration()).await).await;

        // Assert
        let rendered = created.to_string();
        for credential in [
            "client_secret",
            "registration_access_token",
            "registration_client_uri",
        ] {
            assert!(
                !rendered.contains(credential),
                "the console handed out a {credential}: {rendered}"
            );
        }
    }

    /// OIDC Registration §5: a pairwise client's `sector_identifier_uri` is a
    /// claim it has to back. The console cannot skip the fetch — it goes
    /// through the same port, whose one implementation calls the same function
    /// `POST /register` calls.
    #[tokio::test]
    async fn a_pairwise_client_whose_sector_is_not_backed_is_refused() {
        // Arrange
        let (world, cookie) = console_in_a_signing_tenant();
        let document = serde_json::json!({
            "client_name": "Pairwise",
            "redirect_uris": [
                "https://one.example.test/callback",
                "https://two.example.test/callback",
            ],
            "jwks_uri": "https://one.example.test/jwks.json",
            "subject_type": "pairwise",
            "sector_identifier_uri": "https://sector.example.test/uris.json",
        });

        // Act
        let response = post_client(&world, &cookie, &document).await;

        // Assert
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = body_of(response).await;
        assert!(
            body["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains("sector_identifier_uri")),
            "{body}"
        );

        // And it is accepted once the sector is backed, so the refusal above is
        // the check rather than the document being wrong in some other way.
        world
            .handle
            .0
            .confirmed_sectors
            .lock()
            .expect("an uncontended lock")
            .push("https://sector.example.test/uris.json".to_owned());
        let accepted = post_client(&world, &cookie, &document).await;
        assert_eq!(accepted.status(), StatusCode::CREATED);
    }

    /// A client whose ID tokens this tenant could not sign is refused at the
    /// form rather than at the token endpoint weeks later. `acme` holds a
    /// staged key and no active one, which is exactly that situation.
    #[tokio::test]
    async fn a_client_this_tenant_cannot_sign_for_is_refused() {
        // Arrange
        let world = World::new();
        let cookie = world.sign_in("acme", &[Role::TenantAdmin]);

        // Act
        let response = post_client(&world, &cookie, &valid_registration()).await;

        // Assert
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = body_of(response).await;
        assert!(
            body["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains("id_token_signed_response_alg")),
            "{body}"
        );
    }

    /// A body that says nothing about the status must not reactivate a client
    /// somebody suspended — an edit made during an incident by a console built
    /// against an older server would otherwise put it back in service.
    #[tokio::test]
    async fn an_edit_that_says_nothing_about_status_leaves_a_suspension_alone() {
        // Arrange
        let (world, cookie) = console_in_a_signing_tenant();
        let created = body_of(post_client(&world, &cookie, &valid_registration()).await).await;
        let id = created["client_id"]
            .as_str()
            .expect("a client_id")
            .to_owned();
        let path = crate::CLIENT_UPDATE.full_path().replace("{client_id}", &id);

        let mut suspending = valid_registration();
        suspending["status"] = serde_json::json!("disabled");
        let suspended = world
            .send(
                as_console(&crate::CLIENT_UPDATE, &cookie)
                    .uri(path.clone())
                    .body(Body::from(suspending.to_string()))
                    .expect("a request"),
            )
            .await;
        assert_eq!(
            body_of(suspended).await["status"],
            serde_json::json!("disabled")
        );

        // Act: an edit of the metadata that says nothing about the status.
        let mut edited = valid_registration();
        edited["client_name"] = serde_json::json!("Renamed while suspended");
        let response = world
            .send(
                as_console(&crate::CLIENT_UPDATE, &cookie)
                    .uri(path)
                    .body(Body::from(edited.to_string()))
                    .expect("a request"),
            )
            .await;

        // Assert
        let body = body_of(response).await;
        assert_eq!(
            body["client_name"],
            serde_json::json!("Renamed while suspended")
        );
        assert_eq!(
            body["status"],
            serde_json::json!("disabled"),
            "an edit put a suspended client back in service: {body}"
        );
    }

    /// The search narrows the inventory, and it matches what an operator has to
    /// hand — here the name they gave the client.
    #[tokio::test]
    async fn the_client_list_can_be_searched() {
        // Arrange
        let (world, cookie) = console_in_a_signing_tenant();
        let mut payments = valid_registration();
        payments["client_name"] = serde_json::json!("Payments");
        post_client(&world, &cookie, &payments).await;

        // Act
        let page = body_of(
            world
                .send(
                    as_console(&crate::CLIENTS_LIST, &cookie)
                        .uri(format!("{}?q=payments", crate::CLIENTS_LIST.full_path()))
                        .body(Body::empty())
                        .expect("a request"),
                )
                .await,
        )
        .await;

        // Assert
        let names: Vec<&str> = page["items"]
            .as_array()
            .expect("a page of clients")
            .iter()
            .filter_map(|row| row["client_name"].as_str())
            .collect();
        assert_eq!(names, ["Payments"], "{page}");
    }

    /// A `client_id` belonging to another tenant is a 404 here, not somebody
    /// else's configuration: the lookup is scoped to the tenant the request was
    /// routed to.
    #[tokio::test]
    async fn a_client_of_another_tenant_is_not_found() {
        // Arrange: `other` holds a client under an id `acme` also holds one
        // under, so only the scoping can tell them apart.
        let world = World::new();
        let cookie = world.sign_in("acme", &[Role::TenantAdmin]);
        world
            .handle
            .0
            .clients
            .lock()
            .expect("an uncontended lock")
            .push(seeded_client("other", "c.OnlyInTheOtherTenant1"));

        // Act
        let response = world
            .send(
                as_console(&crate::CLIENT_READ, &cookie)
                    .uri(
                        crate::CLIENT_READ
                            .full_path()
                            .replace("{client_id}", "c.OnlyInTheOtherTenant1"),
                    )
                    .body(Body::empty())
                    .expect("a request"),
            )
            .await;

        // Assert
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    /// The registration gate is reported as a mode and a count, and the console
    /// is told plainly that it cannot mint an initial access token — because
    /// nothing below it can (`ast-m9c.6`).
    #[tokio::test]
    async fn the_registration_gate_is_reported_without_naming_a_token() {
        // Arrange
        let world = World::new().routed_at("asterius-admin");
        let cookie = world.sign_in("asterius-admin", &[Role::DeploymentAdmin]);

        // Act
        let response = world
            .send(
                as_console(&crate::REGISTRATION_READ, &cookie)
                    .body(Body::empty())
                    .expect("a request"),
            )
            .await;

        // Assert
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_of(response).await;
        assert_eq!(body["mode"], serde_json::json!("initial_access_token"));
        assert_eq!(body["configured_tokens"], serde_json::json!(2));
        assert_eq!(body["console_issuance"], serde_json::json!(true));
    }

    /// **The first acceptance criterion of `ast-f7m.7`.**
    ///
    /// OIDC Core §10.1.1 describes rotation as adding a key to the JWK Set and
    /// retaining "recently decommissioned signing keys for a reasonable period
    /// of time to facilitate a smooth transition". So a rotation an operator
    /// asks for from the console must do *both*: the new `kid` signs, and the
    /// one it replaced is still in the published set — or every token issued a
    /// minute ago stops verifying.
    #[tokio::test]
    async fn rotating_from_the_console_activates_a_new_kid_and_keeps_the_previous_one_published() {
        // Arrange: a tenant already signing with a key, as every live tenant
        // is.
        let world = World::new();
        let cookie = world.sign_in("acme", &[Role::TenantAdmin]);
        let first = world
            .send(
                as_console(&crate::KEYS_ROTATE, &cookie)
                    .body(Body::from(serde_json::json!({"alg": "EdDSA"}).to_string()))
                    .expect("a request"),
            )
            .await;
        let first = body_of(first).await;
        let incumbent = first["activated_kid"]
            .as_str()
            .expect("the tenant's first key is born signing")
            .to_owned();

        // Act: rotate again, asking for the new key to sign at once.
        let response = world
            .send(
                as_console(&crate::KEYS_ROTATE, &cookie)
                    .body(Body::from(
                        serde_json::json!({"alg": "EdDSA", "activate_immediately": true})
                            .to_string(),
                    ))
                    .expect("a request"),
            )
            .await;

        // Assert
        assert_eq!(response.status(), StatusCode::OK);
        let rotation = body_of(response).await;
        let successor = rotation["activated_kid"]
            .as_str()
            .expect("an immediate rotation activates the key it staged")
            .to_owned();
        assert_ne!(successor, incumbent, "the rotation reused the same kid");
        assert_eq!(
            rotation["superseded_kid"].as_str(),
            Some(incumbent.as_str()),
            "the rotation did not report which key it displaced: {rotation}"
        );

        let jwks = body_of(
            world
                .send(
                    as_console(&crate::KEYS_JWKS, &cookie)
                        .body(Body::empty())
                        .expect("a request"),
                )
                .await,
        )
        .await;
        let published: Vec<&str> = jwks["keys"]
            .as_array()
            .expect("a JWK Set")
            .iter()
            .filter_map(|key| key["kid"].as_str())
            .collect();
        assert!(
            published.contains(&successor.as_str()),
            "the new key is not published: {jwks}"
        );
        assert!(
            published.contains(&incumbent.as_str()),
            "the superseded key left the JWK Set, so tokens it signed stop \
             verifying: {jwks}"
        );

        // And the inventory says which of the two signs now.
        let inventory = body_of(
            world
                .send(
                    as_console(&crate::KEYS_LIST, &cookie)
                        .body(Body::empty())
                        .expect("a request"),
                )
                .await,
        )
        .await;
        let eddsa = inventory["algorithms"]
            .as_array()
            .expect("groups")
            .iter()
            .find(|group| group["alg"] == serde_json::json!("EdDSA"))
            .expect("an EdDSA group")
            .clone();
        let active: Vec<&str> = eddsa["keys"]
            .as_array()
            .expect("keys")
            .iter()
            .filter(|key| key["state"] == serde_json::json!("active"))
            .filter_map(|key| key["kid"].as_str())
            .collect();
        assert_eq!(
            active,
            [successor.as_str()],
            "exactly one key signs, and it is the new one: {eddsa}"
        );
    }

    /// **The second acceptance criterion of `ast-f7m.7`.**
    ///
    /// Every response the key screen can produce, checked for the private JWK
    /// members RFC 7518 §6 defines. The fixture's rows *carry* a `d` member —
    /// a `jsonb` column is something an incident can put anything into — so
    /// this fails if the rendering ever stops being an allow-list.
    #[tokio::test]
    async fn no_key_route_ever_renders_private_material() {
        // Arrange
        let world = World::new();
        let cookie = world.sign_in("acme", &[Role::TenantAdmin]);
        world
            .send(
                as_console(&crate::KEYS_ROTATE, &cookie)
                    .body(Body::from(serde_json::json!({"alg": "EdDSA"}).to_string()))
                    .expect("a request"),
            )
            .await;

        for operation in [&crate::KEYS_LIST, &crate::KEYS_JWKS] {
            // Act
            let response = world
                .send(
                    as_console(operation, &cookie)
                        .body(Body::empty())
                        .expect("a request"),
                )
                .await;
            let document = body_of(response).await;
            let rendered = document.to_string();

            // Assert
            assert!(
                !rendered.contains("PRIVATE-KEY-MATERIAL"),
                "{} rendered private key material: {rendered}",
                operation.id()
            );
            for member in [
                "\"d\"", "\"p\"", "\"q\"", "\"dp\"", "\"dq\"", "\"qi\"", "\"k\"",
            ] {
                assert!(
                    !rendered.contains(member),
                    "{} rendered the {member} member: {rendered}",
                    operation.id()
                );
            }
            assert!(
                rendered.contains("public-"),
                "{} rendered no public key at all: {rendered}",
                operation.id()
            );
        }
    }

    /// The one key an algorithm signs with is not retirable, because a console
    /// button that takes an issuer offline in one click is a button somebody
    /// eventually presses. Rotation is how an active key is replaced, and it
    /// puts a successor in place first.
    #[tokio::test]
    async fn the_active_key_cannot_be_retired_from_the_console() {
        // Arrange
        let world = World::new();
        let cookie = world.sign_in("acme", &[Role::TenantAdmin]);
        let rotation = body_of(
            world
                .send(
                    as_console(&crate::KEYS_ROTATE, &cookie)
                        .body(Body::from(serde_json::json!({"alg": "EdDSA"}).to_string()))
                        .expect("a request"),
                )
                .await,
        )
        .await;
        let active = rotation["activated_kid"].as_str().expect("an active kid");

        // Act
        let response = world
            .send(
                as_console(&crate::KEYS_RETIRE, &cookie)
                    .uri(format!("{}/keys/{active}/retire", crate::BASE_PATH))
                    .body(Body::empty())
                    .expect("a request"),
            )
            .await;

        // Assert
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let jwks = body_of(
            world
                .send(
                    as_console(&crate::KEYS_JWKS, &cookie)
                        .body(Body::empty())
                        .expect("a request"),
                )
                .await,
        )
        .await;
        assert!(
            jwks["keys"]
                .as_array()
                .expect("a JWK Set")
                .iter()
                .any(|key| key["kid"] == serde_json::json!(active)),
            "the refused retirement removed the key anyway: {jwks}"
        );
    }

    /// A retired key has left the JWK Set, which is the whole point of
    /// retiring one.
    #[tokio::test]
    async fn a_retired_key_leaves_the_published_set() {
        // Arrange
        let world = World::new();
        let cookie = world.sign_in("acme", &[Role::TenantAdmin]);

        // Act
        let response = world
            .send(
                as_console(&crate::KEYS_RETIRE, &cookie)
                    .body(Body::empty())
                    .expect("a request"),
            )
            .await;

        // Assert
        assert_eq!(response.status(), StatusCode::OK);
        let jwks = body_of(
            world
                .send(
                    as_console(&crate::KEYS_JWKS, &cookie)
                        .body(Body::empty())
                        .expect("a request"),
                )
                .await,
        )
        .await;
        assert!(
            !jwks["keys"]
                .as_array()
                .expect("a JWK Set")
                .iter()
                .any(|key| key["kid"] == serde_json::json!(SEEDED_KID)),
            "a retired key is still published: {jwks}"
        );
    }

    /// The console's answer to a compromise: the key leaves the published set
    /// and its private half stops existing. The response says which of the two
    /// outcomes happened, because an operator retrying after a timeout has to
    /// be able to tell "I destroyed it" from "it was already gone".
    #[tokio::test]
    async fn a_purged_key_leaves_the_published_set_and_reports_the_destruction() {
        // Arrange
        let world = World::new();
        let cookie = world.sign_in("acme", &[Role::TenantAdmin]);

        // Act
        let response = world
            .send(
                as_console(&crate::KEYS_PURGE, &cookie)
                    .body(Body::from(
                        serde_json::json!({"reason": "leaked in INC-42"}).to_string(),
                    ))
                    .expect("a request"),
            )
            .await;

        // Assert
        assert_eq!(response.status(), StatusCode::OK);
        let document = body_of(response).await;
        assert_eq!(document["kid"], serde_json::json!(SEEDED_KID));
        assert_eq!(document["state"], serde_json::json!("purged"));
        assert_eq!(document["destroyed"], serde_json::json!(true));

        let jwks = body_of(
            world
                .send(
                    as_console(&crate::KEYS_JWKS, &cookie)
                        .body(Body::empty())
                        .expect("a request"),
                )
                .await,
        )
        .await;
        assert!(
            !jwks["keys"]
                .as_array()
                .expect("a JWK Set")
                .iter()
                .any(|key| key["kid"] == serde_json::json!(SEEDED_KID)),
            "a purged key is still published: {jwks}"
        );
    }

    /// A purge with no reason is not a purge. The record of a destruction is
    /// where an incident review starts, and one that does not say why the key
    /// was destroyed is a hole exactly there — so the body is refused before
    /// the key store is reached.
    #[tokio::test]
    async fn a_purge_without_a_reason_destroys_nothing() {
        // Arrange
        let world = World::new();
        let cookie = world.sign_in("acme", &[Role::TenantAdmin]);

        for body in [
            serde_json::json!({}),
            serde_json::json!({"reason": "   "}),
            serde_json::json!({"reason": ""}),
        ] {
            // Act
            let response = world
                .send(
                    as_console(&crate::KEYS_PURGE, &cookie)
                        .body(Body::from(body.to_string()))
                        .expect("a request"),
                )
                .await;

            // Assert
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{body}");
        }

        let states: Vec<KeyState> = world
            .handle
            .0
            .keys
            .lock()
            .expect("a lock")
            .iter()
            .map(|record| record.state)
            .collect();
        assert!(
            !states.contains(&KeyState::Purged),
            "a body with no reason destroyed a key anyway: {states:?}"
        );
    }

    /// Destroying the key a tenant signs with would leave it unable to issue a
    /// token, irreversibly. The compromise path is a rotation with immediate
    /// activation first — which is the sequence this test walks — and only then
    /// a purge.
    #[tokio::test]
    async fn the_active_key_cannot_be_purged_and_the_compromise_path_can() {
        // Arrange: a tenant whose active key is believed compromised.
        let world = World::new();
        let cookie = world.sign_in("acme", &[Role::TenantAdmin]);
        let rotation = body_of(
            world
                .send(
                    as_console(&crate::KEYS_ROTATE, &cookie)
                        .body(Body::from(serde_json::json!({"alg": "EdDSA"}).to_string()))
                        .expect("a request"),
                )
                .await,
        )
        .await;
        let leaked = rotation["activated_kid"]
            .as_str()
            .expect("an active kid")
            .to_owned();

        // Act / Assert: the active key is refused.
        let refused = world
            .send(
                as_console(&crate::KEYS_PURGE, &cookie)
                    .uri(format!("{}/keys/{leaked}/purge", crate::BASE_PATH))
                    .body(Body::from(
                        serde_json::json!({"reason": "leaked in INC-42"}).to_string(),
                    ))
                    .expect("a request"),
            )
            .await;
        assert_eq!(refused.status(), StatusCode::CONFLICT);

        // Act: rotate with immediate activation, which installs a successor and
        // pushes the suspect key out of `active` in one call...
        let promoted = body_of(
            world
                .send(
                    as_console(&crate::KEYS_ROTATE, &cookie)
                        .body(Body::from(
                            serde_json::json!({"alg": "EdDSA", "activate_immediately": true})
                                .to_string(),
                        ))
                        .expect("a request"),
                )
                .await,
        )
        .await;
        assert_eq!(promoted["superseded_kid"], serde_json::json!(leaked));

        // ...and only then destroy it.
        let purged = world
            .send(
                as_console(&crate::KEYS_PURGE, &cookie)
                    .uri(format!("{}/keys/{leaked}/purge", crate::BASE_PATH))
                    .body(Body::from(
                        serde_json::json!({"reason": "leaked in INC-42"}).to_string(),
                    ))
                    .expect("a request"),
            )
            .await;

        // Assert
        assert_eq!(purged.status(), StatusCode::OK);
        let jwks = body_of(
            world
                .send(
                    as_console(&crate::KEYS_JWKS, &cookie)
                        .body(Body::empty())
                        .expect("a request"),
                )
                .await,
        )
        .await;
        let keys = jwks["keys"].as_array().expect("a JWK Set");
        assert!(
            !keys
                .iter()
                .any(|key| key["kid"] == serde_json::json!(leaked)),
            "the compromised key is still published: {jwks}"
        );
        assert!(
            !keys.is_empty(),
            "the tenant was left with nothing to verify against: {jwks}"
        );
    }

    /// A `kid` belonging to another tenant is not a key this console may
    /// destroy either. A 404 and not a 403, for the reason retirement gives.
    #[tokio::test]
    async fn a_kid_this_tenant_does_not_hold_cannot_be_purged() {
        // Arrange
        let world = World::new();
        let cookie = world.sign_in("acme", &[Role::TenantAdmin]);

        // Act
        let response = world
            .send(
                as_console(&crate::KEYS_PURGE, &cookie)
                    .uri(format!(
                        "{}/keys/a-kid-nobody-holds/purge",
                        crate::BASE_PATH
                    ))
                    .body(Body::from(
                        serde_json::json!({"reason": "leaked in INC-42"}).to_string(),
                    ))
                    .expect("a request"),
            )
            .await;

        // Assert
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    /// A `kid` belonging to another tenant is not a key this console may
    /// retire. It is a 404 and not a 403, because telling a caller that a `kid`
    /// exists somewhere else is telling them something about a tenant they may
    /// not read.
    #[tokio::test]
    async fn a_kid_this_tenant_does_not_hold_is_not_found() {
        // Arrange
        let world = World::new();
        let cookie = world.sign_in("acme", &[Role::TenantAdmin]);

        // Act
        let response = world
            .send(
                as_console(&crate::KEYS_RETIRE, &cookie)
                    .uri(format!(
                        "{}/keys/a-kid-nobody-holds/retire",
                        crate::BASE_PATH
                    ))
                    .body(Body::empty())
                    .expect("a request"),
            )
            .await;

        // Assert
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    /// RFC 8725 §3.1 fixes the permitted algorithms in advance. The console is
    /// not an exception, and a request naming `none` must not reach the key
    /// store at all.
    #[tokio::test]
    async fn the_console_cannot_rotate_an_algorithm_this_server_refuses() {
        // Arrange
        let world = World::new();
        let cookie = world.sign_in("acme", &[Role::TenantAdmin]);
        let before = world.handle.0.keys.lock().expect("a lock").len();

        // Act
        let response = world
            .send(
                as_console(&crate::KEYS_ROTATE, &cookie)
                    .body(Body::from(serde_json::json!({"alg": "none"}).to_string()))
                    .expect("a request"),
            )
            .await;

        // Assert
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            world.handle.0.keys.lock().expect("a lock").len(),
            before,
            "a refused algorithm still minted a key"
        );
    }

    /// A rotation is an administrative change and is recorded as one, naming
    /// the person who asked for it (ADR-0009).
    #[tokio::test]
    async fn a_rotation_from_the_console_is_audited_with_the_administrator_behind_it() {
        // Arrange
        let world = World::new();
        let cookie = world.sign_in("acme", &[Role::TenantAdmin]);

        // Act
        world
            .send(
                as_console(&crate::KEYS_ROTATE, &cookie)
                    .body(Body::from(
                        serde_json::json!({"alg": "ES256", "activate_immediately": true})
                            .to_string(),
                    ))
                    .expect("a request"),
            )
            .await;

        // Assert
        let events = world.handle.0.events.lock().expect("a lock");
        let recorded = events
            .iter()
            .find(|event| event.event_type == EventType::ADMIN_CHANGED)
            .expect("a rotation was not recorded");
        assert!(
            matches!(recorded.actor, Actor::Admin(_)),
            "the rotation was not attributed to an administrator: {:?}",
            recorded.actor
        );
    }

    /// A schedule whose next rotation is already overdue: pressing "apply now"
    /// runs the pass, and the report names the key it staged.
    ///
    /// The acceptance criterion of `ast-sep`, and the reason the route exists:
    /// an operator who has just shortened a rotation period should not have to
    /// wait for the background sweep to see the policy take effect.
    #[tokio::test]
    async fn applying_a_schedule_that_is_overdue_rotates_now() {
        // Arrange
        let world = World::new();
        let cookie = world.sign_in("acme", &[Role::TenantAdmin]);
        world.handle.0.key_schedules.lock().expect("a lock").insert(
            "EdDSA".to_owned(),
            RotationSchedule {
                // Rotated a year ago on a ninety-day period: due, and overdue.
                last_rotated_at: Some(OffsetDateTime::UNIX_EPOCH),
                ..default_schedule()
            },
        );

        // Act
        let response = world
            .send(
                as_console(&crate::KEYS_SCHEDULE_APPLY, &cookie)
                    .body(Body::empty())
                    .expect("a request"),
            )
            .await;

        // Assert
        assert_eq!(response.status(), StatusCode::OK);
        let document = body_of(response).await;
        assert_eq!(document["changed"], serde_json::json!(true), "{document}");
        let eddsa = document["algorithms"]
            .as_array()
            .expect("algorithms")
            .iter()
            .find(|group| group["alg"] == serde_json::json!("EdDSA"))
            .expect("an EdDSA pass")
            .clone();
        assert_eq!(eddsa["changed"], serde_json::json!(true), "{eddsa}");
        assert!(
            eddsa["created_kid"].is_string(),
            "the overdue schedule staged no key: {eddsa}"
        );
    }

    /// The second press: nothing is due any more, nothing happens, and the
    /// response says so. An operator who cannot tell "nothing to do" from "the
    /// request was lost" presses the button again.
    #[tokio::test]
    async fn applying_a_schedule_twice_changes_nothing_the_second_time() {
        // Arrange
        let world = World::new();
        let cookie = world.sign_in("acme", &[Role::TenantAdmin]);

        let first = world
            .send(
                as_console(&crate::KEYS_SCHEDULE_APPLY, &cookie)
                    .body(Body::empty())
                    .expect("a request"),
            )
            .await;
        assert_eq!(first.status(), StatusCode::OK);
        assert_eq!(body_of(first).await["changed"], serde_json::json!(true));
        let after_one = world.handle.0.keys.lock().expect("a lock").len();

        // Act
        let second = world
            .send(
                as_console(&crate::KEYS_SCHEDULE_APPLY, &cookie)
                    .body(Body::empty())
                    .expect("a request"),
            )
            .await;

        // Assert
        assert_eq!(second.status(), StatusCode::OK);
        let document = body_of(second).await;
        assert_eq!(document["changed"], serde_json::json!(false), "{document}");
        for group in document["algorithms"].as_array().expect("algorithms") {
            assert_eq!(group["changed"], serde_json::json!(false), "{group}");
            assert_eq!(group["created_kid"], serde_json::Value::Null, "{group}");
        }
        assert_eq!(
            world.handle.0.keys.lock().expect("a lock").len(),
            after_one,
            "a second apply minted a key"
        );
    }

    /// Recorded whether or not anything moved, and attributed to the person who
    /// pressed it: "somebody forced the sweep and nothing was due" is a fact no
    /// `key.rotated` record can carry, because none is written.
    #[tokio::test]
    async fn applying_a_schedule_that_did_nothing_is_still_recorded() {
        // Arrange
        let world = World::new();
        let cookie = world.sign_in("acme", &[Role::TenantAdmin]);
        for algorithm in SigningAlgorithm::ALL {
            world.handle.0.key_schedules.lock().expect("a lock").insert(
                algorithm.as_str().to_owned(),
                RotationSchedule {
                    last_rotated_at: Some(OffsetDateTime::now_utc()),
                    ..default_schedule()
                },
            );
        }

        // Act
        let response = world
            .send(
                as_console(&crate::KEYS_SCHEDULE_APPLY, &cookie)
                    .body(Body::empty())
                    .expect("a request"),
            )
            .await;

        // Assert
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_of(response).await["changed"], serde_json::json!(false));
        let events = world.handle.0.events.lock().expect("a lock");
        let recorded = events
            .iter()
            .find(|event| event.event_type == EventType::KEY_SCHEDULE_APPLIED)
            .expect("the sweep was not recorded");
        assert!(
            matches!(recorded.actor, Actor::Admin(_)),
            "the sweep was not attributed to an administrator: {:?}",
            recorded.actor
        );
    }

    /// Setting a schedule is a `PUT`, so it carries no idempotency key and must
    /// still be refused without the synchroniser token: it changes what the
    /// tenant does for the next ninety days.
    #[tokio::test]
    async fn a_schedule_a_console_did_not_send_is_refused() {
        // Arrange
        let world = World::new();
        let cookie = world.sign_in("acme", &[Role::TenantAdmin]);

        // Act
        let response = world
            .send(
                request_for(&crate::KEYS_SCHEDULE)
                    .header(
                        "cookie",
                        format!(
                            "{}={cookie}",
                            asterius_domain::entities::session::COOKIE_NAME
                        ),
                    )
                    .body(body_for(&crate::KEYS_SCHEDULE))
                    .expect("a request"),
            )
            .await;

        // Assert
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
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

    // ---- tenant settings (`ast-f7m.4`) -------------------------------------

    /// Signs a tenant admin in and sends `body` to `acme`'s settings.
    async fn put_settings(world: &World, body: serde_json::Value) -> Response {
        let cookie = world.sign_in("acme", &[Role::TenantAdmin]);
        world
            .send(
                HttpRequest::builder()
                    .method("PUT")
                    .uri(
                        crate::TENANT_SETTINGS_UPDATE
                            .full_path()
                            .replace("{tenant_id}", "acme"),
                    )
                    .header("origin", ORIGIN)
                    .header(
                        "cookie",
                        format!(
                            "{}={cookie}",
                            asterius_domain::entities::session::COOKIE_NAME
                        ),
                    )
                    .header(csrf::HEADER, csrf::token(&cookie))
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .expect("a request"),
            )
            .await
    }

    /// One audit detail value as a string, for the assertions that only care
    /// whether a value is present.
    fn rendered(value: &asterius_domain::audit::DetailValue) -> Option<String> {
        match value {
            asterius_domain::audit::DetailValue::Text(text) => Some(text.clone()),
            asterius_domain::audit::DetailValue::Number(_)
            | asterius_domain::audit::DetailValue::Flag(_)
            | asterius_domain::audit::DetailValue::Fingerprint(_) => None,
        }
    }

    /// A settings document that also stores a registration policy
    /// (`ast-m9c.6`), which is where the token quota comes from.
    fn settings_body_with_policy(policy: &serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "disabled_features": [],
            "authorization_code_lifetime_seconds": 60,
            "access_token_lifetime_seconds": 300,
            "registration_policy": policy,
        })
    }

    /// Stores a per-tenant registration policy through the API that owns it,
    /// so the fixture cannot store one the API would refuse.
    async fn store_policy(world: &World, cookie: &str, policy: &serde_json::Value) {
        let response = world
            .send(
                as_console(&crate::TENANT_SETTINGS_UPDATE, cookie)
                    .body(Body::from(settings_body_with_policy(policy).to_string()))
                    .expect("a request"),
            )
            .await;
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "the policy was not stored"
        );
    }

    /// **`ast-cu3`'s first acceptance criterion, admin side.** The token is
    /// shown once, and the quota on it is the tenant's — not the caller's.
    #[tokio::test]
    async fn issuing_an_initial_access_token_shows_it_once_with_the_tenants_quota() {
        // Arrange
        let world = World::new();
        let cookie = world.sign_in("acme", &[Role::TenantAdmin]);
        store_policy(
            &world,
            &cookie,
            &serde_json::json!({
                "mode": "initial_access_token",
                "max_clients_per_initial_access_token": 3,
            }),
        )
        .await;

        // Act: the body names a quota of its own, which must be ignored.
        let response = world
            .send(
                as_console(&crate::INITIAL_ACCESS_TOKEN_CREATE, &cookie)
                    .body(Body::from(
                        serde_json::json!({ "label": "onboarding", "max_uses": 9999 }).to_string(),
                    ))
                    .expect("a request"),
            )
            .await;

        // Assert
        assert_eq!(response.status(), StatusCode::CREATED);
        let body = body_of(response).await;
        assert_eq!(body["max_uses"], serde_json::json!(3));
        assert_eq!(body["remaining"], serde_json::json!(3));
        assert_eq!(body["shown_once"], serde_json::json!(true));
        assert!(
            body["initial_access_token"]
                .as_str()
                .is_some_and(|token| token.len() >= 22),
            "the response did not carry a credential worth issuing"
        );
    }

    /// The credential exists in one response and nowhere else: a later `GET`
    /// renders the quota and the expiry and cannot render the token.
    #[tokio::test]
    async fn listing_initial_access_tokens_renders_no_credential() {
        // Arrange
        let world = World::new();
        let cookie = world.sign_in("acme", &[Role::TenantAdmin]);
        store_policy(
            &world,
            &cookie,
            &serde_json::json!({ "mode": "initial_access_token" }),
        )
        .await;
        let created = world
            .send(
                as_console(&crate::INITIAL_ACCESS_TOKEN_CREATE, &cookie)
                    .body(Body::from(
                        serde_json::json!({ "label": "onboarding" }).to_string(),
                    ))
                    .expect("a request"),
            )
            .await;
        assert_eq!(created.status(), StatusCode::CREATED);

        // Act
        let response = world
            .send(
                as_console(&crate::INITIAL_ACCESS_TOKENS_LIST, &cookie)
                    .body(Body::empty())
                    .expect("a request"),
            )
            .await;

        // Assert
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_of(response).await;
        let items = body["items"].as_array().expect("a list of tokens");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["label"], serde_json::json!("onboarding"));
        assert_eq!(items[0]["usable"], serde_json::json!(true));
        assert!(
            items[0].get("initial_access_token").is_none(),
            "the list rendered a credential"
        );
    }

    /// The issuance is on the trail with its actor and without its token: an
    /// administrator who mints a credential and uses it elsewhere is still
    /// named at the moment they minted it.
    #[tokio::test]
    async fn issuing_an_initial_access_token_is_audited_without_the_token() {
        // Arrange
        let world = World::new();
        let cookie = world.sign_in("acme", &[Role::TenantAdmin]);
        store_policy(
            &world,
            &cookie,
            &serde_json::json!({ "mode": "initial_access_token" }),
        )
        .await;

        // Act
        let response = world
            .send(
                as_console(&crate::INITIAL_ACCESS_TOKEN_CREATE, &cookie)
                    .body(Body::from(
                        serde_json::json!({ "label": "onboarding" }).to_string(),
                    ))
                    .expect("a request"),
            )
            .await;
        assert_eq!(response.status(), StatusCode::CREATED);
        let issued = body_of(response).await;
        let token = issued["initial_access_token"]
            .as_str()
            .expect("a credential")
            .to_owned();

        // Assert
        let events = world.handle.0.events.lock().expect("an uncontended lock");
        let recorded = events
            .iter()
            .find(|event| {
                event.detail.iter().any(|(key, value)| {
                    key == "operation"
                        && rendered(value).as_deref() == Some(crate::INITIAL_ACCESS_TOKEN_CREATE_ID)
                })
            })
            .expect("the issuance was not recorded");

        let values: Vec<String> = recorded
            .detail
            .iter()
            .filter_map(|(_, value)| rendered(value))
            .collect();
        assert!(
            values.iter().any(|value| value == "onboarding"),
            "the trail does not say which token was issued"
        );
        assert!(
            !values.iter().any(|value| value == &token),
            "the audit trail carries the credential"
        );
    }

    fn settings_body(code_seconds: i64, access_token_seconds: i64) -> serde_json::Value {
        serde_json::json!({
            "disabled_features": [],
            "authorization_code_lifetime_seconds": code_seconds,
            "access_token_lifetime_seconds": access_token_seconds,
        })
    }

    /// The acceptance criterion of `ast-ndk.5`, at the door an administrator
    /// actually knocks on: an override naming a key no page has is refused,
    /// and the refusal says which key.
    #[tokio::test]
    async fn the_api_refuses_a_message_override_for_a_key_no_page_has() {
        // Arrange
        let world = World::new();
        let mut body = settings_body(60, 300);
        body["messages"] = serde_json::json!({ "consent.allowed": "Continuer" });

        // Act
        let response = put_settings(&world, body).await;

        // Assert
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let refused = body_of(response).await;
        let message = refused["error"]["message"].as_str().unwrap_or_default();
        assert!(
            message.contains("consent.allowed"),
            "the refusal does not name the key: {message}"
        );
    }

    /// The other half, and the one that is a security control rather than a
    /// usability one: a tenant supplies no markup.
    #[tokio::test]
    async fn the_api_refuses_a_message_override_that_carries_markup() {
        // Arrange
        let world = World::new();
        let mut body = settings_body(60, 300);
        body["messages"] = serde_json::json!({ "consent.allow": "<script>alert(1)</script>" });

        // Act
        let response = put_settings(&world, body).await;

        // Assert
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let refused = body_of(response).await;
        let message = refused["error"]["message"].as_str().unwrap_or_default();
        assert!(
            message.contains("consent.allow"),
            "the refusal does not name the key: {message}"
        );
    }

    /// A tenant's language and wording are stored, rendered back, and — the
    /// part a wholesale replacement gets wrong — survive the next settings save
    /// that does not mention them.
    #[tokio::test]
    async fn a_tenants_language_and_wording_are_stored_and_survive_the_next_save() {
        // Arrange
        let world = World::new();
        let mut body = settings_body(60, 300);
        body["default_locale"] = serde_json::json!("fr");
        body["messages"] = serde_json::json!({ "consent.allow": "Continuer" });

        // Act
        let stored = body_of(put_settings(&world, body).await).await;
        let unrelated = body_of(put_settings(&world, settings_body(45, 300)).await).await;

        // Assert
        assert_eq!(stored["default_locale"], "fr", "{stored}");
        assert_eq!(stored["messages"]["consent.allow"], "Continuer", "{stored}");
        assert_eq!(
            unrelated["default_locale"], "fr",
            "a save that did not mention the language deleted it: {unrelated}"
        );
        assert_eq!(
            unrelated["messages"]["consent.allow"], "Continuer",
            "a save that did not mention the wording deleted it: {unrelated}"
        );
    }

    #[tokio::test]
    async fn the_api_refuses_a_default_locale_this_build_cannot_render() {
        // Arrange
        let world = World::new();
        let mut body = settings_body(60, 300);
        body["default_locale"] = serde_json::json!("de");

        // Act
        let response = put_settings(&world, body).await;

        // Assert
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let refused = body_of(response).await;
        let message = refused["error"]["message"].as_str().unwrap_or_default();
        assert!(
            message.contains("ui_locales_supported"),
            "the refusal does not say where the supported tags are listed: {message}"
        );
    }

    /// `ast-f7m.4`'s first acceptance criterion. The refusal is the *API's*,
    /// reached with no form in the way, which is the whole point: the cap is a
    /// server-side rule.
    #[tokio::test]
    async fn the_api_refuses_a_code_lifetime_over_sixty_seconds() {
        // Arrange
        let world = World::new();

        // Act
        let response = put_settings(&world, settings_body(300, 300)).await;

        // Assert
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = body_of(response).await;
        let message = body["error"]["message"].as_str().unwrap_or_default();
        assert!(
            message.contains("FAPI 2.0 Security Profile §5.3.2.1 item 11"),
            "the refusal does not name the clause: {message}"
        );
    }

    #[tokio::test]
    async fn the_api_refuses_an_access_token_lifetime_over_the_cap() {
        // Arrange
        let world = World::new();

        // Act
        let response = put_settings(&world, settings_body(60, 3600)).await;

        // Assert
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = body_of(response).await;
        assert!(
            body["error"]["message"]
                .as_str()
                .unwrap_or_default()
                .contains("900 s"),
            "{body}"
        );
    }

    /// A refused change writes nothing: the stored settings are still the ones
    /// that were in force before the attempt.
    #[tokio::test]
    async fn a_refused_change_leaves_the_stored_settings_alone() {
        // Arrange
        let world = World::new();

        // Act
        let _ = put_settings(&world, settings_body(3600, 300)).await;

        // Assert
        assert!(
            world
                .handle
                .0
                .settings
                .lock()
                .expect("an uncontended lock")
                .is_empty(),
            "a refused change was written anyway"
        );
    }

    /// The second acceptance criterion, at this layer: a flag change drops the
    /// deployment's cached view, so the next discovery request is served from
    /// the new settings rather than from a snapshot up to thirty seconds old.
    #[tokio::test]
    async fn changing_a_flag_invalidates_the_deployments_cached_view() {
        // Arrange
        let world = World::new();
        let body = serde_json::json!({
            "disabled_features": ["dpop_nonce"],
            "authorization_code_lifetime_seconds": 60,
            "access_token_lifetime_seconds": 300,
        });

        // Act
        let response = put_settings(&world, body).await;

        // Assert
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            *world
                .handle
                .0
                .invalidations
                .lock()
                .expect("an uncontended lock"),
            1,
            "the settings change did not invalidate the cache"
        );
    }

    /// The third: a change is recorded with what it was and what it became.
    #[tokio::test]
    async fn a_settings_change_is_audited_with_a_before_and_after_diff() {
        // Arrange
        let world = World::new();

        // Act
        let response = put_settings(&world, settings_body(30, 300)).await;

        // Assert
        assert_eq!(response.status(), StatusCode::OK);
        let events = world.handle.0.events.lock().expect("an uncontended lock");
        let recorded = events.last().expect("a recorded change");
        let detail: BTreeMap<&String, &asterius_domain::audit::DetailValue> =
            recorded.detail.iter().collect();
        assert_eq!(
            detail.get(&"authorization_code_lifetime_seconds.before".to_owned()),
            Some(&&asterius_domain::audit::DetailValue::Number(60))
        );
        assert_eq!(
            detail.get(&"authorization_code_lifetime_seconds.after".to_owned()),
            Some(&&asterius_domain::audit::DetailValue::Number(30))
        );
        assert!(
            !detail.contains_key(&"access_token_lifetime_seconds.before".to_owned()),
            "an unchanged member is not part of the diff"
        );
    }

    #[tokio::test]
    async fn settings_that_were_saved_are_the_settings_read_back() {
        // Arrange
        let world = World::new();
        let body = serde_json::json!({
            "disabled_features": ["mtls"],
            "authorization_code_lifetime_seconds": 45,
            "access_token_lifetime_seconds": 120,
        });
        let _ = put_settings(&world, body).await;
        let cookie = world.sign_in("acme", &[Role::TenantAdmin]);

        // Act
        let response = world
            .send(
                HttpRequest::builder()
                    .method("GET")
                    .uri(
                        crate::TENANT_SETTINGS_READ
                            .full_path()
                            .replace("{tenant_id}", "acme"),
                    )
                    .header("origin", ORIGIN)
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
        let document = body_of(response).await;
        assert_eq!(document["authorization_code_lifetime_seconds"], 45);
        assert_eq!(document["disabled_features"][0], "mtls");
        assert_eq!(
            document["limits"]["max_authorization_code_lifetime_seconds"],
            60
        );
    }

    /// The cross-tenant read the second authority check exists to stop, on the
    /// settings path this time: `acme`'s admin naming `other` in the path.
    #[tokio::test]
    async fn a_tenant_admin_cannot_reach_a_siblings_settings() {
        // Arrange
        let world = World::new();
        let cookie = world.sign_in("acme", &[Role::TenantAdmin]);

        // Act
        let response = world
            .send(
                HttpRequest::builder()
                    .method("PUT")
                    .uri(
                        crate::TENANT_SETTINGS_UPDATE
                            .full_path()
                            .replace("{tenant_id}", "other"),
                    )
                    .header("origin", ORIGIN)
                    .header(
                        "cookie",
                        format!(
                            "{}={cookie}",
                            asterius_domain::entities::session::COOKIE_NAME
                        ),
                    )
                    .header(csrf::HEADER, csrf::token(&cookie))
                    .header("content-type", "application/json")
                    .body(Body::from(settings_body(60, 300).to_string()))
                    .expect("a request"),
            )
            .await;

        // Assert
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn a_feature_name_this_build_does_not_know_is_refused() {
        // Arrange
        let world = World::new();
        let body = serde_json::json!({
            "disabled_features": ["telepathy"],
            "authorization_code_lifetime_seconds": 60,
            "access_token_lifetime_seconds": 300,
        });

        // Act
        let response = put_settings(&world, body).await;

        // Assert
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(Feature::from_key("telepathy"), None);
    }

    // ---- signing out (`ast-bfn`) ------------------------------------------

    /// **The acceptance criterion of `ast-bfn`'s logout half.**
    ///
    /// An administrator who presses "Sign out" must end up with a session this
    /// server refuses, not merely with a console that has forgotten it. The
    /// cookie is `HttpOnly`, so script cannot remove it: the server has to
    /// send the clearing `Set-Cookie` *and* revoke the row, and the second is
    /// what makes a cookie already copied out of a browser worthless.
    #[tokio::test]
    async fn signing_out_revokes_the_session_and_clears_the_cookie() {
        // Arrange
        let world = World::new();
        let cookie = world.sign_in("acme", &[Role::TenantAdmin]);

        // Act
        let response = world
            .send(
                as_console(&crate::SESSION_END, &cookie)
                    .body(Body::empty())
                    .expect("a request"),
            )
            .await;

        // Assert: the browser is told to drop it, with the attributes it was
        // set with — a `Set-Cookie` whose attributes differ is one the browser
        // keeps (`asterius_web::session`).
        assert_eq!(response.status(), StatusCode::OK);
        let cleared = response
            .headers()
            .get(header::SET_COOKIE)
            .and_then(|value| value.to_str().ok())
            .expect("a clearing Set-Cookie")
            .to_owned();
        assert!(cleared.contains("Max-Age=0"), "{cleared}");
        assert!(
            cleared.starts_with(asterius_domain::entities::session::COOKIE_NAME),
            "{cleared}"
        );

        // And the id itself is dead: the same cookie no longer reads a
        // session.
        let after = world
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
        assert_eq!(after.status(), StatusCode::UNAUTHORIZED);
    }

    /// Ending a session is recorded, and as a session event rather than as a
    /// configuration change: "why was I signed out" is answered from this
    /// trail, and `admin.changed` is where somebody looks for a settings edit.
    #[tokio::test]
    async fn signing_out_is_recorded_in_the_audit_trail() {
        // Arrange
        let world = World::new();
        let cookie = world.sign_in("acme", &[Role::TenantAdmin]);

        // Act
        let response = world
            .send(
                as_console(&crate::SESSION_END, &cookie)
                    .body(Body::empty())
                    .expect("a request"),
            )
            .await;

        // Assert
        assert_eq!(response.status(), StatusCode::OK);
        let events = world.handle.0.events.lock().expect("a lock");
        assert!(
            events
                .iter()
                .any(|event| event.event_type == EventType::SESSION_REVOKED),
            "signing out left no record: {events:?}"
        );
    }

    /// Signing out twice with the same cookie is a 401, not a second logout:
    /// the first call revoked the row, so the credential is already gone by
    /// the time the gate looks at it.
    #[tokio::test]
    async fn a_second_sign_out_with_the_same_cookie_is_refused() {
        // Arrange
        let world = World::new();
        let cookie = world.sign_in("acme", &[Role::TenantAdmin]);
        let first = world
            .send(
                as_console(&crate::SESSION_END, &cookie)
                    .body(Body::empty())
                    .expect("a request"),
            )
            .await;
        assert_eq!(first.status(), StatusCode::OK);

        // Act
        let second = world
            .send(
                as_console(&crate::SESSION_END, &cookie)
                    .body(Body::empty())
                    .expect("a request"),
            )
            .await;

        // Assert
        assert_eq!(second.status(), StatusCode::UNAUTHORIZED);
    }

    // ---- accounts, credentials, sessions and grants (`ast-f7m.6`) ----------

    /// A console signed in to `acme`, which the fixture seeds with one
    /// account, one live session, one passkey and one grant.
    fn console_over_the_seeded_account() -> (World, String) {
        let world = World::new();
        let cookie = world.sign_in("acme", &[Role::TenantAdmin]);
        (world, cookie)
    }

    /// **The acceptance criterion of `ast-f7m.6`, and OIDC Back-Channel Logout
    /// 1.0 §2.5.**
    ///
    /// Switching an account off is not an edit to a column: the sessions it
    /// had are revoked, and every relying party that took part in one is
    /// queued a logout token. Two participants and not one in the fixture, so
    /// that "one token per participant" and "one token per session" are told
    /// apart.
    ///
    /// Asserted in process, on the queue. `outbound::post` refuses the
    /// loopback (`ast-o4u.2`), so a test that tried to receive the POST would
    /// be testing the anti-SSRF rule rather than the notification.
    #[tokio::test]
    async fn disabling_an_account_revokes_its_sessions_and_queues_a_token_for_each_participant() {
        // Arrange
        let (world, cookie) = console_over_the_seeded_account();

        // Act
        let response = world
            .send(
                as_console(&crate::USER_STATUS_UPDATE, &cookie)
                    .body(Body::from(
                        serde_json::json!({"enabled": false}).to_string(),
                    ))
                    .expect("a request"),
            )
            .await;

        // Assert
        assert_eq!(response.status(), StatusCode::OK);
        let document = body_of(response).await;
        assert_eq!(document["status"], serde_json::json!("disabled"));
        assert_eq!(
            document["terminated"]["sessions_revoked"],
            serde_json::json!(1)
        );
        assert_eq!(
            document["terminated"]["logout_tokens_queued"],
            serde_json::json!(SEEDED_PARTICIPANTS)
        );
        assert_eq!(
            *world
                .handle
                .0
                .logout_tokens
                .lock()
                .expect("an uncontended lock"),
            SEEDED_PARTICIPANTS,
            "the participating relying parties were not queued a logout token"
        );
    }

    // ---- roles (`ast-3t8`) -------------------------------------------------

    /// Sends a role set for the seeded account, as `cookie`'s holder.
    async fn put_roles(world: &World, cookie: &str, roles: &[&str]) -> Response {
        world
            .send(
                as_console(&crate::USER_ROLES_UPDATE, cookie)
                    .body(Body::from(serde_json::json!({"roles": roles}).to_string()))
                    .expect("a request"),
            )
            .await
    }

    /// Appointing somebody is a decision, and the trail has to name all three
    /// of it: who was appointed, to what, and by whom.
    #[tokio::test]
    async fn granting_a_role_is_recorded_against_the_account_and_the_administrator() {
        // Arrange
        let (world, cookie) = console_over_the_seeded_account();

        // Act
        let response = put_roles(&world, &cookie, &["user_support"]).await;

        // Assert
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_of(response).await;
        assert_eq!(body["roles"], serde_json::json!(["user_support"]));
        let events = world.handle.0.events.lock().expect("an uncontended lock");
        let recorded = events
            .iter()
            .find(|event| event.event_type == EventType::ROLE_GRANTED)
            .expect("a grant is recorded");
        assert_eq!(recorded.subject.as_deref(), Some(SEEDED_USER_ID));
        assert!(
            matches!(recorded.actor, Actor::Admin(_)),
            "the record does not name the administrator behind it"
        );
    }

    /// The other direction is its own record: "who stopped being an
    /// administrator, and when" is asked as often as the reverse.
    #[tokio::test]
    async fn revoking_a_role_is_recorded_separately_from_granting_one() {
        // Arrange
        let (world, cookie) = console_over_the_seeded_account();
        assert_eq!(
            put_roles(&world, &cookie, &["user_support"]).await.status(),
            StatusCode::OK
        );

        // Act
        let response = put_roles(&world, &cookie, &[]).await;

        // Assert
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_of(response).await;
        assert_eq!(body["roles"], serde_json::json!([]));
        let events = world.handle.0.events.lock().expect("an uncontended lock");
        assert!(
            events
                .iter()
                .any(|event| event.event_type == EventType::ROLE_REVOKED),
            "the revocation left no record"
        );
    }

    /// Otherwise the weakest way into an administrator's session is also a way
    /// to widen it, and the trail would show an account granting itself its
    /// own authority.
    #[tokio::test]
    async fn nobody_edits_their_own_roles() {
        // Arrange
        let world = World::new();
        let cookie = world.sign_in_as(
            "acme",
            asterius_domain::UserId::new(
                uuid::Uuid::parse_str(SEEDED_USER_ID).expect("a seeded uuid"),
            ),
            &[Role::TenantAdmin],
        );

        // Act
        let response = put_roles(&world, &cookie, &["user_support"]).await;

        // Assert
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    /// A tenant admin of the reserved tenant is still only a tenant admin: the
    /// schema would refuse the row elsewhere, and here — where it would not —
    /// the API refuses to let authority over every tenant be handed out by
    /// somebody who does not hold it.
    #[tokio::test]
    async fn a_tenant_admin_cannot_appoint_a_deployment_admin() {
        // Arrange
        let world = World::new().routed_at("asterius-admin");
        let cookie = world.sign_in("asterius-admin", &[Role::TenantAdmin]);

        // Act
        let response = put_roles(&world, &cookie, &["deployment_admin"]).await;

        // Assert
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    /// A role this build does not know is a 400 and never a silent drop: a
    /// console answered "done" would show a role that was never granted.
    #[tokio::test]
    async fn a_role_this_server_does_not_know_is_refused() {
        // Arrange
        let (world, cookie) = console_over_the_seeded_account();

        // Act
        let response = put_roles(&world, &cookie, &["superuser"]).await;

        // Assert
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    /// The console draws its checkboxes from `grantable`, so what it may
    /// offer is the server's answer: a tenant admin is not offered the
    /// deployment-wide role it could not grant.
    #[tokio::test]
    async fn a_tenant_admin_is_not_offered_the_deployment_wide_role() {
        // Arrange
        let (world, cookie) = console_over_the_seeded_account();

        // Act
        let response = world.get(&crate::USER_ROLES_READ, &cookie).await;

        // Assert
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_of(response).await;
        let grantable = body["grantable"].as_array().expect("a list").clone();
        assert!(!grantable.contains(&serde_json::json!("deployment_admin")));
        assert!(grantable.contains(&serde_json::json!("user_support")));
    }

    /// The trail half of the RISC `account-disabled` signal. The transmitter
    /// is `ast-0ju`; what exists today is this record and the named seam, on
    /// the precedent of `credential.changed`.
    #[tokio::test]
    async fn disabling_an_account_is_recorded_against_the_account_and_the_administrator() {
        // Arrange
        let (world, cookie) = console_over_the_seeded_account();

        // Act
        let response = world
            .send(
                as_console(&crate::USER_STATUS_UPDATE, &cookie)
                    .body(Body::from(
                        serde_json::json!({"enabled": false}).to_string(),
                    ))
                    .expect("a request"),
            )
            .await;

        // Assert
        assert_eq!(response.status(), StatusCode::OK);
        let events = world.handle.0.events.lock().expect("an uncontended lock");
        let recorded = events
            .iter()
            .find(|event| event.event_type == EventType::ACCOUNT_DISABLED)
            .expect("a disablement is recorded");
        assert_eq!(recorded.subject.as_deref(), Some(SEEDED_USER_ID));
        assert!(
            matches!(recorded.actor, Actor::Admin(_)),
            "the record does not name the administrator behind it"
        );
    }

    /// Enabling revokes nothing, so nobody is told anything: a relying party
    /// notified of a logout because an account came back would be told
    /// something that did not happen.
    #[tokio::test]
    async fn enabling_an_account_queues_no_logout_token() {
        // Arrange
        let (world, cookie) = console_over_the_seeded_account();

        // Act
        let response = world
            .send(
                as_console(&crate::USER_STATUS_UPDATE, &cookie)
                    .body(Body::from(serde_json::json!({"enabled": true}).to_string()))
                    .expect("a request"),
            )
            .await;

        // Assert
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            *world
                .handle
                .0
                .logout_tokens
                .lock()
                .expect("an uncontended lock"),
            0
        );
    }

    /// The check the multi-tenant model rests on, at the account routes: an
    /// administrator of one tenant naming another tenant's `user_id` finds
    /// nothing, because the tenant is a predicate on the lookup.
    #[tokio::test]
    async fn an_account_of_another_tenant_is_not_found() {
        // Arrange
        let world = World::new();
        let cookie = world.sign_in("acme", &[Role::TenantAdmin]);
        // The `other` tenant holds an account under the same uuid, so the 404
        // is about the tenant and not about the row being absent everywhere.
        assert!(
            world
                .handle
                .0
                .accounts
                .lock()
                .expect("an uncontended lock")
                .iter()
                .any(|user| user.tenant.as_str() == "other")
        );

        // Act
        let response = world
            .send(
                as_console(&crate::USER_READ, &cookie)
                    .body(Body::empty())
                    .expect("a request"),
            )
            .await;

        // Assert: `acme` holds one too, so this one is found — the negative is
        // the routed tenant below.
        assert_eq!(response.status(), StatusCode::OK);

        // Act again, routed at a tenant that holds no such account.
        let elsewhere = World::new().routed_at("empty-tenant");
        let cookie = elsewhere.sign_in("empty-tenant", &[Role::TenantAdmin]);
        let response = elsewhere
            .send(
                as_console(&crate::USER_READ, &cookie)
                    .body(Body::empty())
                    .expect("a request"),
            )
            .await;

        // Assert
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    /// A `user_id` that is not a UUID names nothing this server holds, and is
    /// answered the same way as one that names somebody else's account.
    #[tokio::test]
    async fn a_user_id_that_is_not_an_identifier_is_not_found() {
        // Arrange
        let (world, cookie) = console_over_the_seeded_account();

        // Act
        let response = world
            .send(
                request_for(&crate::USER_READ)
                    .uri("/admin/api/v1/users/not-a-uuid")
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
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    /// `ast-895`: the deny list is not optional, and the console is not a way
    /// around it. Asserted at the route and not only at
    /// [`crate::users::accept_password`], because the question is whether the
    /// handler calls it.
    #[tokio::test]
    async fn an_account_cannot_be_created_on_a_password_the_login_form_would_refuse() {
        // Arrange
        let (world, cookie) = console_over_the_seeded_account();

        // Act
        let response = world
            .send(
                as_console(&crate::USER_CREATE, &cookie)
                    .body(Body::from(
                        serde_json::json!({
                            "username": "grace@example.test",
                            "password": "password123",
                        })
                        .to_string(),
                    ))
                    .expect("a request"),
            )
            .await;

        // Assert
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            world
                .handle
                .0
                .accounts
                .lock()
                .expect("an uncontended lock")
                .iter()
                .filter(|user| user.username == "grace@example.test")
                .count(),
            0,
            "a refused creation wrote an account anyway"
        );
    }

    /// An account created with a password this deployment accepts.
    #[tokio::test]
    async fn an_account_created_from_the_console_reads_back() {
        // Arrange
        let (world, cookie) = console_over_the_seeded_account();

        // Act
        let response = world
            .send(
                as_console(&crate::USER_CREATE, &cookie)
                    .body(Body::from(
                        serde_json::json!({
                            "username": "grace@example.test",
                            "email": "grace@example.test",
                            "password": "a passphrase nobody has used before",
                        })
                        .to_string(),
                    ))
                    .expect("a request"),
            )
            .await;

        // Assert
        assert_eq!(response.status(), StatusCode::CREATED);
        let document = body_of(response).await;
        assert_eq!(
            document["username"],
            serde_json::json!("grace@example.test")
        );
        assert_eq!(document["status"], serde_json::json!("active"));
        // OIDC Core §5.1: the flag is asserted, never defaulted on.
        assert_eq!(document["email_verified"], serde_json::json!(false));
    }

    /// A creation is never a replacement: the second one is a 409 rather than
    /// an overwrite of somebody's account.
    #[tokio::test]
    async fn a_username_this_tenant_already_holds_is_refused() {
        // Arrange
        let (world, cookie) = console_over_the_seeded_account();

        // Act
        let response = world
            .send(
                as_console(&crate::USER_CREATE, &cookie)
                    .body(Body::from(
                        serde_json::json!({"username": "ada@example.test"}).to_string(),
                    ))
                    .expect("a request"),
            )
            .await;

        // Assert
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    /// The directory answers a search and pages with an opaque cursor, which
    /// is what `ast-cts` fixed for the other listings.
    #[tokio::test]
    async fn the_directory_searches_and_pages() {
        // Arrange
        let (world, cookie) = console_over_the_seeded_account();
        for name in ["bob@example.test", "carol@example.test"] {
            world
                .handle
                .0
                .accounts
                .lock()
                .expect("an uncontended lock")
                .push(asterius_domain::User {
                    id: UserId::generate(),
                    username: name.to_owned(),
                    email: Some(name.to_owned()),
                    ..seeded_user("acme")
                });
        }

        // Act: one row at a time, so a cursor has to be minted.
        let first = world
            .send(
                request_for(&crate::USERS_LIST)
                    .uri("/admin/api/v1/users?limit=1")
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
        assert_eq!(first.status(), StatusCode::OK);
        let page = body_of(first).await;
        assert_eq!(page["items"].as_array().map(Vec::len), Some(1));
        assert_eq!(
            page["items"][0]["username"],
            serde_json::json!("ada@example.test")
        );
        let cursor = page["next_cursor"].as_str().expect("a cursor").to_owned();
        // Opaque: the console must not be able to start parsing it.
        assert!(!cursor.contains("ada@example.test"), "{cursor}");

        // Act: the next page, and a search that narrows it.
        let searched = world
            .send(
                request_for(&crate::USERS_LIST)
                    .uri("/admin/api/v1/users?q=carol")
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
        let page = body_of(searched).await;
        assert_eq!(page["items"].as_array().map(Vec::len), Some(1));
        assert_eq!(
            page["items"][0]["username"],
            serde_json::json!("carol@example.test")
        );
    }

    /// OIDC Core §5.1, at the route: the claims and the verification flags are
    /// one document and one write.
    #[tokio::test]
    async fn claims_and_their_verification_flags_are_saved_together() {
        // Arrange
        let (world, cookie) = console_over_the_seeded_account();

        // Act
        let response = world
            .send(
                as_console(&crate::USER_CLAIMS_UPDATE, &cookie)
                    .body(Body::from(
                        serde_json::json!({
                            "email": "ada@newmail.test",
                            "email_verified": false,
                            "claims": {
                                "name": {"value": "Ada Lovelace", "verified": true},
                                "zoneinfo": {"value": "Europe/London"},
                            },
                        })
                        .to_string(),
                    ))
                    .expect("a request"),
            )
            .await;

        // Assert
        assert_eq!(response.status(), StatusCode::OK);
        let document = body_of(response).await;
        assert_eq!(document["email"], serde_json::json!("ada@newmail.test"));
        assert_eq!(document["email_verified"], serde_json::json!(false));
        assert_eq!(
            document["claims"]["name"]["value"],
            serde_json::json!("Ada Lovelace")
        );
        assert!(
            document["claims"]["name"]["verified_at"].is_number(),
            "a claim marked verified was not stamped"
        );
        assert_eq!(
            document["claims"]["zoneinfo"]["verified_at"],
            serde_json::Value::Null
        );
    }

    /// A bag able to hold a `sub` is a bag able to impersonate somebody, and
    /// the route refuses one rather than storing it under another name.
    #[tokio::test]
    async fn a_claim_the_authorization_server_mints_is_refused_by_the_route() {
        // Arrange
        let (world, cookie) = console_over_the_seeded_account();

        // Act
        let response = world
            .send(
                as_console(&crate::USER_CLAIMS_UPDATE, &cookie)
                    .body(Body::from(
                        serde_json::json!({"claims": {"sub": {"value": "somebody-else"}}})
                            .to_string(),
                    ))
                    .expect("a request"),
            )
            .await;

        // Assert
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    /// The sessions tab names a session by the `sid` the deployment already
    /// publishes to relying parties, and by nothing else: the lookup digest is
    /// not on this side of the port at all.
    #[tokio::test]
    async fn a_session_is_listed_by_the_identifier_relying_parties_already_hold() {
        // Arrange
        let (world, cookie) = console_over_the_seeded_account();

        // Act
        let response = world
            .send(
                as_console(&crate::USER_SESSIONS_LIST, &cookie)
                    .body(Body::empty())
                    .expect("a request"),
            )
            .await;

        // Assert
        assert_eq!(response.status(), StatusCode::OK);
        let document = body_of(response).await;
        assert_eq!(document["items"][0]["sid"], serde_json::json!(SEEDED_SID));
        assert_eq!(document["items"][0]["live"], serde_json::json!(true));
    }

    /// §2.5 again, for one session rather than a whole account: ending it from
    /// the console tells the same relying parties, through the same seam, as
    /// ending it from the browser.
    #[tokio::test]
    async fn revoking_one_session_queues_a_logout_token_for_each_participant() {
        // Arrange
        let (world, cookie) = console_over_the_seeded_account();

        // Act
        let response = world
            .send(
                as_console(&crate::USER_SESSION_REVOKE, &cookie)
                    .body(Body::empty())
                    .expect("a request"),
            )
            .await;

        // Assert
        assert_eq!(response.status(), StatusCode::OK);
        let document = body_of(response).await;
        assert_eq!(document["sessions_revoked"], serde_json::json!(1));
        assert_eq!(
            document["logout_tokens_queued"],
            serde_json::json!(SEEDED_PARTICIPANTS)
        );
        let events = world.handle.0.events.lock().expect("an uncontended lock");
        assert!(
            events
                .iter()
                .any(|event| event.event_type == EventType::SESSION_REVOKED),
            "ending a session from the console was not recorded"
        );
    }

    /// Grant Management ID1 §6.5 and §6.6: the first `DELETE` withdraws the
    /// authorization and the second finds nothing to withdraw.
    #[tokio::test]
    async fn withdrawing_an_authorization_twice_is_a_404_the_second_time() {
        // Arrange
        let (world, cookie) = console_over_the_seeded_account();

        // Act
        let first = world
            .send(
                as_console(&crate::USER_GRANT_REVOKE, &cookie)
                    .body(Body::empty())
                    .expect("a request"),
            )
            .await;
        let second = world
            .send(
                as_console(&crate::USER_GRANT_REVOKE, &cookie)
                    .body(Body::empty())
                    .expect("a request"),
            )
            .await;

        // Assert
        assert_eq!(first.status(), StatusCode::OK);
        assert_eq!(second.status(), StatusCode::NOT_FOUND);
    }

    /// The grants tab renders what an operator needs to decide and nothing
    /// that identifies the person to a relying party.
    #[tokio::test]
    async fn the_grants_tab_names_the_client_and_the_scopes_and_no_subject() {
        // Arrange
        let (world, cookie) = console_over_the_seeded_account();

        // Act
        let response = world
            .send(
                as_console(&crate::USER_GRANTS_LIST, &cookie)
                    .body(Body::empty())
                    .expect("a request"),
            )
            .await;

        // Assert
        assert_eq!(response.status(), StatusCode::OK);
        let document = body_of(response).await;
        assert_eq!(
            document["items"][0]["client_id"],
            serde_json::json!(SEEDED_CLIENT_ID)
        );
        assert_eq!(
            document["items"][0]["scopes"],
            serde_json::json!(["openid"])
        );
        assert!(
            !document.to_string().contains("the-sub-this-client-knows"),
            "the grants tab rendered a subject identifier"
        );
    }

    /// The credentials tab answers "what can this person sign in with", and
    /// answers it without material: the port carries none.
    #[tokio::test]
    async fn the_credentials_tab_lists_a_passkey_without_its_key() {
        // Arrange
        let (world, cookie) = console_over_the_seeded_account();

        // Act
        let response = world
            .send(
                as_console(&crate::USER_CREDENTIALS_READ, &cookie)
                    .body(Body::empty())
                    .expect("a request"),
            )
            .await;

        // Assert
        assert_eq!(response.status(), StatusCode::OK);
        let document = body_of(response).await;
        assert_eq!(document["password"], serde_json::json!(true));
        assert_eq!(
            document["passkeys"][0]["credential_id"],
            serde_json::json!(SEEDED_CREDENTIAL_ID)
        );
        let rendered = document.to_string();
        assert!(!rendered.contains("public_key"));
        assert!(!rendered.contains("sign_count"));
    }

    /// Blocking a passkey stamps the row rather than deleting it, so the
    /// second attempt finds nothing to block and the credential is still
    /// visible to an incident review.
    #[tokio::test]
    async fn blocking_a_passkey_twice_is_a_404_the_second_time() {
        // Arrange
        let (world, cookie) = console_over_the_seeded_account();

        // Act
        let first = world
            .send(
                as_console(&crate::USER_PASSKEY_REMOVE, &cookie)
                    .body(Body::empty())
                    .expect("a request"),
            )
            .await;
        let second = world
            .send(
                as_console(&crate::USER_PASSKEY_REMOVE, &cookie)
                    .body(Body::empty())
                    .expect("a request"),
            )
            .await;

        // Assert
        assert_eq!(first.status(), StatusCode::OK);
        assert_eq!(second.status(), StatusCode::NOT_FOUND);
        let events = world.handle.0.events.lock().expect("an uncontended lock");
        assert!(
            events
                .iter()
                .any(|event| event.event_type == EventType::CREDENTIAL_CHANGED),
            "blocking a credential was not recorded"
        );
    }

    /// `ast-2vk.10`: forcing a reset invalidates the password, ends the
    /// sessions and mails a link. It does not set a password an administrator
    /// chose — there is no field in the request that could carry one.
    #[tokio::test]
    async fn forcing_a_reset_invalidates_the_password_and_hands_off_a_link() {
        // Arrange
        let (world, cookie) = console_over_the_seeded_account();

        // Act
        let response = world
            .send(
                as_console(&crate::USER_PASSWORD_RESET, &cookie)
                    .body(Body::empty())
                    .expect("a request"),
            )
            .await;

        // Assert
        assert_eq!(response.status(), StatusCode::OK);
        let document = body_of(response).await;
        assert_eq!(document["password_invalidated"], serde_json::json!(true));
        assert_eq!(document["recovery_sent"], serde_json::json!(true));
        assert_eq!(document["sessions_revoked"], serde_json::json!(1));
        assert_eq!(
            world
                .handle
                .0
                .recovery_sent
                .lock()
                .expect("an uncontended lock")
                .len(),
            1
        );
    }
}
