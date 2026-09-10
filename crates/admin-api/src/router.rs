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
    EventType, Kid, NewInitialAccessToken, OpaqueToken, Outcome, RefreshPolicy, Tenant, TenantId,
    TenantSettings, TenantStatus,
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
use crate::{clients, csrf, initial_access_tokens, keys, openapi, outbox, throttle};

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
        /// last. Empty by default, which is a healthy deployment.
        dead_letters: Mutex<Vec<asterius_domain::outbox::DeadLetter>>,
    }

    #[derive(Debug, Clone)]
    struct Handle(Arc<Fake>);

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

    fn default_schedule() -> RotationSchedule {
        RotationSchedule {
            rotation_period: time::Duration::days(90),
            propagation_period: time::Duration::minutes(15),
            grace_period: time::Duration::days(7),
            last_rotated_at: None,
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

        fn outbox(&self) -> Arc<dyn asterius_domain::outbox::DeadLetterQuery> {
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
        fn sign_in_with(
            &self,
            tenant: &str,
            roles: &[Role],
            amr: &[AuthenticationMethod],
            enrolment: asterius_domain::PasskeyEnrolment,
        ) -> String {
            let id = SessionId::generate();
            let tenant = TenantId::parse(tenant).expect("a valid tenant id");
            let user = UserId::generate();
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
        let path = operation
            .full_path()
            .replace("{tenant_id}", "acme")
            .replace("{kid}", SEEDED_KID)
            .replace("{client_id}", SEEDED_CLIENT_ID);
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
            crate::KEYS_ROTATE_ID => serde_json::json!({"alg": "EdDSA"}),
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

    // ---- the dead-letter screen (`ast-0ju.9`) -----------------------------

    /// The screen exists so that "our logout notifications stopped arriving"
    /// is answerable without a database client: which delivery, how many times
    /// it was tried, and what the receiver said.
    #[tokio::test]
    async fn a_tenant_admin_reads_the_deliveries_the_outbox_gave_up_on() {
        // Arrange
        let world = World::new();
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
        let cookie = world.sign_in("acme", &[Role::TenantAdmin]);

        // Act
        let response = world.get(&crate::OUTBOX_DEAD_LETTERS, &cookie).await;

        // Assert
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_of(response).await;
        assert_eq!(body["items"].as_array().map(Vec::len), Some(0));
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
}
