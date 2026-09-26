//! User-approved Claims Provider OAuth code + PKCE connection and recollection.

use crate::claims_provider::ClaimsProviders;
use crate::http::account::{
    self, AccountContext, checked_csrf, csrf_for, error_page, fresh, no_store,
};
use crate::http::redirect::SeeOther;
use crate::outbound::{HttpsClientUrlFetcher, HttpsPoster, PostRequest};
use asterius_domain::{FirstPartyDestination, Session, UserId, sha256_hex};
use asterius_store_pg::{
    CpConnection, CpConnectionSummary, PgAggregatedClaims, PgCpOAuth, StoredClaimSource,
};
use asterius_web::Document;
use axum::body::Bytes;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeSet, HashMap};
use time::{Duration, OffsetDateTime};
use zeroize::{Zeroize, Zeroizing};

pub const PAGE_PATH: &str = "/account/claims-providers";
pub const CALLBACK_PATH: &str = "/account/claims-providers/callback";
const CSRF_SEPARATOR: &str = "account-claims-providers-csrf";

pub struct Context<'a> {
    pub account: AccountContext<'a>,
    pub providers: &'a ClaimsProviders,
    pub pending: &'a PgCpOAuth,
    pub sources: &'a PgAggregatedClaims,
}

impl std::fmt::Debug for Context<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("Context").finish_non_exhaustive()
    }
}

pub async fn page(context: &Context<'_>, headers: &HeaderMap, now: OffsetDateTime) -> Response {
    let Some(session) = account::admitted(&context.account, headers, now).await else {
        return account::begin(
            &context.account,
            FirstPartyDestination::AccountClaimsProviders,
            now,
        )
        .await;
    };
    render_current(context, &session, None, StatusCode::OK, now).await
}

pub async fn submit(
    context: &Context<'_>,
    headers: &HeaderMap,
    body: &Bytes,
    now: OffsetDateTime,
) -> Response {
    let Some(session) = account::admitted(&context.account, headers, now).await else {
        return account::begin(
            &context.account,
            FirstPartyDestination::AccountClaimsProviders,
            now,
        )
        .await;
    };
    let Some((csrf, action, issuer)) = parse_form(body) else {
        return render_current(
            context,
            &session,
            Some("Invalid form."),
            StatusCode::BAD_REQUEST,
            now,
        )
        .await;
    };
    if !checked_csrf(&session, CSRF_SEPARATOR, &csrf) {
        return render_current(
            context,
            &session,
            Some("Form expired. Reload and try again."),
            StatusCode::BAD_REQUEST,
            now,
        )
        .await;
    }
    if !fresh(&session, now) {
        return account::begin(
            &context.account,
            FirstPartyDestination::AccountClaimsProviders,
            now,
        )
        .await;
    }
    if action != "revoke"
        && context
            .providers
            .oauth_registration(context.account.tenant.id.as_str(), &issuer)
            .is_none()
    {
        return render_current(
            context,
            &session,
            Some("Provider is not configured."),
            StatusCode::BAD_REQUEST,
            now,
        )
        .await;
    }
    match action.as_str() {
        "connect" => connect(context, &session, &issuer).await,
        "refresh" => refresh(context, &session, &issuer, now).await,
        "revoke" => {
            let registration = context
                .providers
                .oauth_registration(context.account.tenant.id.as_str(), &issuer);
            let loaded = context
                .pending
                .load(UserId::new(session.user), &issuer, now)
                .await;
            match context
                .pending
                .revoke(UserId::new(session.user), &issuer, now)
                .await
            {
                Ok(_) => {
                    // Local erasure and the callback fence commit before any
                    // slow outbound revocation attempt.
                    let remote = match (registration, loaded) {
                        (Some(registration), Ok(Some(connection)))
                            if registration.revocation_endpoint.is_some() =>
                        {
                            Some(revoke_remote(&registration, &connection).await)
                        }
                        (_, Err(_)) => Some(false),
                        _ => None,
                    };
                    render_current(
                        context,
                        &session,
                        Some(if remote == Some(true) {
                            "Provider connection and claims removed; provider token revocation confirmed."
                        } else if remote == Some(false) {
                            "Local connection and claims removed. Provider token revocation could not be confirmed."
                        } else {
                            "Local connection and claims removed. No provider revocation endpoint is configured."
                        }),
                        StatusCode::OK,
                        now,
                    )
                    .await
                }
                Err(error) => {
                    tracing::error!(%error, tenant = %context.account.tenant.id, "cannot revoke Claims Provider connection");
                    error_page(&context.account, StatusCode::SERVICE_UNAVAILABLE)
                }
            }
        }
        _ => {
            render_current(
                context,
                &session,
                Some("Invalid form."),
                StatusCode::BAD_REQUEST,
                now,
            )
            .await
        }
    }
}

/// RFC 7009 revocation is best effort; local erasure still runs if the CP is
/// unavailable. Each POST uses the same HTTPS SSRF guard as token exchange.
async fn revoke_remote(
    registration: &crate::claims_provider::OAuthRegistration,
    connection: &CpConnection,
) -> bool {
    let Some(endpoint) = registration.revocation_endpoint.as_deref() else {
        return false;
    };
    let Ok(poster) = HttpsPoster::new() else {
        return false;
    };
    let mut confirmed = true;
    if let Some(refresh) = &connection.refresh_token {
        confirmed &= revoke_one(
            &poster,
            endpoint,
            &registration.client_id,
            refresh,
            "refresh_token",
        )
        .await;
    }
    if connection.access_expires_at > OffsetDateTime::now_utc() {
        confirmed &= revoke_one(
            &poster,
            endpoint,
            &registration.client_id,
            &connection.access_token,
            "access_token",
        )
        .await;
    }
    confirmed
}

async fn revoke_one(
    poster: &HttpsPoster,
    endpoint: &str,
    client_id: &str,
    token: &str,
    hint: &str,
) -> bool {
    let body = Zeroizing::new(
        url::form_urlencoded::Serializer::new(String::new())
            .append_pair("client_id", client_id)
            .append_pair("token", token)
            .append_pair("token_type_hint", hint)
            .finish(),
    );
    poster
        .post_with_response(
            endpoint,
            PostRequest::of("application/x-www-form-urlencoded"),
            body.as_bytes(),
        )
        .await
        .is_ok_and(|response| response.status == 200 && !response.truncated)
}

async fn connect(context: &Context<'_>, session: &Session, issuer: &str) -> Response {
    let Some(registration) = context
        .providers
        .oauth_registration(context.account.tenant.id.as_str(), issuer)
    else {
        return error_page(&context.account, StatusCode::BAD_REQUEST);
    };
    let (state, verifier, nonce) = match (random_value(), random_value(), random_value()) {
        (Ok(state), Ok(verifier), Ok(nonce)) => (state, Zeroizing::new(verifier), nonce),
        _ => return error_page(&context.account, StatusCode::SERVICE_UNAVAILABLE),
    };
    let state_hash = sha256_hex(state.as_bytes());
    if let Err(error) = context
        .pending
        .begin(
            &state_hash,
            session.user,
            &session.id_digest,
            issuer,
            &nonce,
            &verifier,
        )
        .await
    {
        tracing::error!(%error, tenant = %context.account.tenant.id, "cannot save Claims Provider setup");
        return error_page(&context.account, StatusCode::SERVICE_UNAVAILABLE);
    }
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let callback = callback_url(context.account.tenant.issuer.as_str());
    let Ok(mut url) = url::Url::parse(&registration.authorization_endpoint) else {
        return error_page(&context.account, StatusCode::SERVICE_UNAVAILABLE);
    };
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &registration.client_id)
        .append_pair("redirect_uri", &callback)
        .append_pair("scope", &registration.scope)
        .append_pair("state", &state)
        .append_pair("nonce", &nonce)
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256")
        .append_pair("prompt", "consent");
    match SeeOther::to(url.as_str()) {
        Ok(redirect) => {
            let mut response = redirect.into_response();
            response
                .headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            response.headers_mut().insert(
                header::REFERRER_POLICY,
                HeaderValue::from_static("no-referrer"),
            );
            response
        }
        Err(_) => error_page(&context.account, StatusCode::SERVICE_UNAVAILABLE),
    }
}

/// The callback only accepts the browser session that began this exact state.
pub async fn callback(
    context: &Context<'_>,
    headers: &HeaderMap,
    raw_query: Option<&str>,
    now: OffsetDateTime,
) -> Response {
    let Some(session) = account::admitted(&context.account, headers, now).await else {
        return error_page(&context.account, StatusCode::BAD_REQUEST);
    };
    let Some((state, code, response_issuer)) = raw_query.and_then(parse_callback) else {
        return render_current(
            context,
            &session,
            Some("Provider authorization was not completed."),
            StatusCode::BAD_REQUEST,
            now,
        )
        .await;
    };
    let code = Zeroizing::new(code);
    let pending = match context
        .pending
        .consume(&sha256_hex(state.as_bytes()), &session.id_digest)
        .await
    {
        Ok(Some(pending)) if pending.user_id == session.user => pending,
        Ok(_) => {
            return render_current(
                context,
                &session,
                Some("Provider setup expired. Start again."),
                StatusCode::BAD_REQUEST,
                now,
            )
            .await;
        }
        Err(error) => {
            tracing::error!(%error, tenant = %context.account.tenant.id, "cannot consume Claims Provider setup");
            return error_page(&context.account, StatusCode::SERVICE_UNAVAILABLE);
        }
    };
    let Some(registration) = context
        .providers
        .oauth_registration(context.account.tenant.id.as_str(), &pending.provider_issuer)
    else {
        return error_page(&context.account, StatusCode::BAD_REQUEST);
    };
    if response_issuer
        .as_deref()
        .is_some_and(|issuer| issuer != registration.issuer)
    {
        return render_current(
            context,
            &session,
            Some("Provider issuer did not match setup."),
            StatusCode::BAD_REQUEST,
            now,
        )
        .await;
    }
    let token = match exchange_code(
        &registration,
        &callback_url(context.account.tenant.issuer.as_str()),
        &code,
        &pending.code_verifier,
    )
    .await
    {
        Ok(token) => token,
        Err(()) => {
            return render_current(
                context,
                &session,
                Some("Provider token exchange failed. Start again."),
                StatusCode::BAD_GATEWAY,
                now,
            )
            .await;
        }
    };
    let subject = match context.providers.verify_id_token(
        context.account.tenant.id.as_str(),
        &registration.issuer,
        &token.id_token,
        &token.access_token,
        &pending.provider_nonce,
        now,
    ) {
        Ok(subject) => subject,
        Err(_) => {
            return render_current(
                context,
                &session,
                Some("Provider identity proof was rejected."),
                StatusCode::BAD_GATEWAY,
                now,
            )
            .await;
        }
    };
    let fetcher = match HttpsClientUrlFetcher::new() {
        Ok(fetcher) => fetcher,
        Err(_) => return error_page(&context.account, StatusCode::SERVICE_UNAVAILABLE),
    };
    let verified = match context
        .providers
        .collect(
            context.account.tenant,
            &registration.issuer,
            &subject,
            &registration.allowed_claims,
            &token.access_token,
            &fetcher,
            now,
        )
        .await
    {
        Ok(verified) => verified,
        Err(_) => {
            tracing::warn!(tenant = %context.account.tenant.id, "Claims Provider signed UserInfo rejected");
            return render_current(
                context,
                &session,
                Some("Provider claims could not be verified."),
                StatusCode::BAD_GATEWAY,
                now,
            )
            .await;
        }
    };
    let access_expires_at =
        now + Duration::seconds(token.expires_in.unwrap_or(300).min(3600) as i64);
    if token.expires_in == Some(0)
        || token
            .scope
            .as_deref()
            .is_some_and(|scope| scope != registration.scope)
    {
        return error_page(&context.account, StatusCode::BAD_GATEWAY);
    }
    let connection = CpConnection {
        provider_issuer: registration.issuer.clone(),
        provider_subject: subject,
        granted_scope: registration.scope.clone(),
        access_token: token.access_token.clone(),
        access_expires_at,
        refresh_token: token.refresh_token.clone(),
        refresh_expires_at: token
            .refresh_token
            .as_ref()
            .map(|_| now + Duration::days(30)),
        revision: 1,
    };
    // Persist the credential before the source. A crash here can leave an
    // account-visible credential without deliverable claims, which the user
    // can refresh or remove. The guarded source write serializes with revoke.
    let user = UserId::new(session.user);
    let revision = match context
        .pending
        .save(user, &connection, pending.created_at, now)
        .await
    {
        Ok(revision) => revision,
        Err(error) => {
            tracing::error!(%error, tenant = %context.account.tenant.id, "cannot save Claims Provider connection");
            return error_page(&context.account, StatusCode::SERVICE_UNAVAILABLE);
        }
    };
    match context
        .sources
        .replace_for_connection(user, &verified, revision, now)
        .await
    {
        Ok(()) => {
            render_current(
                context,
                &session,
                Some("Signed provider claims connected. You can refresh them from this page."),
                StatusCode::OK,
                now,
            )
            .await
        }
        Err(error) => {
            tracing::error!(%error, tenant = %context.account.tenant.id, "cannot save Claims Provider source");
            let _ = context
                .pending
                .discard_if_revision(user, &registration.issuer, revision)
                .await;
            error_page(&context.account, StatusCode::SERVICE_UNAVAILABLE)
        }
    }
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    id_token: String,
    refresh_token: Option<String>,
    expires_in: Option<u64>,
    scope: Option<String>,
}

impl Drop for TokenResponse {
    fn drop(&mut self) {
        self.access_token.zeroize();
        self.id_token.zeroize();
        if let Some(refresh) = &mut self.refresh_token {
            refresh.zeroize();
        }
    }
}

async fn exchange_code(
    registration: &crate::claims_provider::OAuthRegistration,
    redirect_uri: &str,
    code: &str,
    verifier: &str,
) -> Result<TokenResponse, ()> {
    let body = Zeroizing::new(
        url::form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "authorization_code")
            .append_pair("client_id", &registration.client_id)
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("code", code)
            .append_pair("code_verifier", verifier)
            .finish(),
    );
    let poster = HttpsPoster::new().map_err(|_| ())?;
    let response = poster
        .post_with_response(
            &registration.token_endpoint,
            PostRequest::of("application/x-www-form-urlencoded").accepting("application/json"),
            body.as_bytes(),
        )
        .await
        .map_err(|_| ())?;
    if response.status != 200
        || response.truncated
        || !response
            .content_type
            .as_deref()
            .and_then(|value| value.split(';').next())
            .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"))
    {
        return Err(());
    }
    let response_body = Zeroizing::new(response.body);
    let token: TokenResponse = serde_json::from_slice(&response_body).map_err(|_| ())?;
    if token.access_token.is_empty()
        || token.access_token.len() > 4096
        || token.id_token.is_empty()
        || token.id_token.len() > 8192
        || !token.token_type.eq_ignore_ascii_case("Bearer")
        || token
            .refresh_token
            .as_ref()
            .is_some_and(|value| value.is_empty() || value.len() > 4096)
        || token.scope.as_ref().is_some_and(|scope| scope.len() > 512)
    {
        return Err(());
    }
    Ok(token)
}

#[derive(Deserialize)]
struct RefreshResponse {
    access_token: String,
    token_type: String,
    expires_in: Option<u64>,
    refresh_token: Option<String>,
    scope: Option<String>,
    id_token: Option<String>,
}

impl Drop for RefreshResponse {
    fn drop(&mut self) {
        self.access_token.zeroize();
        if let Some(value) = &mut self.refresh_token {
            value.zeroize();
        }
        if let Some(value) = &mut self.id_token {
            value.zeroize();
        }
    }
}

async fn exchange_refresh(
    registration: &crate::claims_provider::OAuthRegistration,
    refresh_token: &str,
) -> Result<RefreshResponse, ()> {
    let body = Zeroizing::new(
        url::form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "refresh_token")
            .append_pair("client_id", &registration.client_id)
            .append_pair("refresh_token", refresh_token)
            .finish(),
    );
    let poster = HttpsPoster::new().map_err(|_| ())?;
    let response = poster
        .post_with_response(
            &registration.token_endpoint,
            PostRequest::of("application/x-www-form-urlencoded").accepting("application/json"),
            body.as_bytes(),
        )
        .await
        .map_err(|_| ())?;
    if response.status != 200
        || response.truncated
        || !response
            .content_type
            .as_deref()
            .and_then(|value| value.split(';').next())
            .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"))
    {
        return Err(());
    }
    let response_body = Zeroizing::new(response.body);
    let token: RefreshResponse = serde_json::from_slice(&response_body).map_err(|_| ())?;
    if token.access_token.is_empty()
        || token.access_token.len() > 4096
        || !token.token_type.eq_ignore_ascii_case("Bearer")
        || token.expires_in == Some(0)
        || token
            .refresh_token
            .as_ref()
            .is_some_and(|value| value.is_empty() || value.len() > 4096)
        || token
            .scope
            .as_ref()
            .is_some_and(|value| value.len() > 512 || value != &registration.scope)
        || token
            .id_token
            .as_ref()
            .is_some_and(|value| value.is_empty() || value.len() > 8192)
    {
        return Err(());
    }
    Ok(token)
}

async fn refresh(
    context: &Context<'_>,
    session: &Session,
    issuer: &str,
    now: OffsetDateTime,
) -> Response {
    let Some(registration) = context
        .providers
        .oauth_registration(context.account.tenant.id.as_str(), issuer)
    else {
        return error_page(&context.account, StatusCode::BAD_REQUEST);
    };
    let user = UserId::new(session.user);
    let mut connection = match context.pending.load(user, issuer, now).await {
        Ok(Some(value)) => value,
        Ok(None) => {
            return render_current(
                context,
                session,
                Some("Connection expired. Connect again."),
                StatusCode::BAD_REQUEST,
                now,
            )
            .await;
        }
        Err(error) => {
            tracing::error!(%error, tenant = %context.account.tenant.id, "cannot load Claims Provider connection");
            return error_page(&context.account, StatusCode::SERVICE_UNAVAILABLE);
        }
    };
    if connection.granted_scope != registration.scope {
        return render_current(
            context,
            session,
            Some("Provider scope changed. Remove this connection and connect again."),
            StatusCode::BAD_REQUEST,
            now,
        )
        .await;
    }
    if connection.access_expires_at <= now + Duration::seconds(30) {
        let Some(stored_refresh) = connection.refresh_token.as_deref() else {
            return render_current(
                context,
                session,
                Some("Connection expired. Connect again."),
                StatusCode::BAD_REQUEST,
                now,
            )
            .await;
        };
        if connection
            .refresh_expires_at
            .is_none_or(|expiry| expiry <= now)
        {
            return render_current(
                context,
                session,
                Some("Connection expired. Connect again."),
                StatusCode::BAD_REQUEST,
                now,
            )
            .await;
        }
        let renewed = match exchange_refresh(&registration, stored_refresh).await {
            Ok(value) => value,
            Err(()) => {
                return render_current(
                    context,
                    session,
                    Some("Provider renewal failed. Connect again."),
                    StatusCode::BAD_GATEWAY,
                    now,
                )
                .await;
            }
        };
        if let Some(id_token) = &renewed.id_token {
            match context.providers.verify_refreshed_id_token(
                context.account.tenant.id.as_str(),
                issuer,
                id_token,
                &renewed.access_token,
                now,
            ) {
                Ok(subject) if subject == connection.provider_subject => {}
                _ => {
                    return render_current(
                        context,
                        session,
                        Some(
                            "Provider identity changed. Remove this connection and connect again.",
                        ),
                        StatusCode::BAD_GATEWAY,
                        now,
                    )
                    .await;
                }
            }
        }
        connection.access_token.zeroize();
        connection.access_token = renewed.access_token.clone();
        connection.access_expires_at =
            now + Duration::seconds(renewed.expires_in.unwrap_or(300).min(3600) as i64);
        if let Some(new_refresh) = &renewed.refresh_token {
            if let Some(old) = &mut connection.refresh_token {
                old.zeroize();
            }
            connection.refresh_token = Some(new_refresh.clone());
            connection.refresh_expires_at = Some(now + Duration::days(30));
        }
        match context.pending.rotate(user, &connection, now).await {
            Ok(true) => {
                connection.revision += 1;
            }
            Ok(false) => {
                return render_current(
                    context,
                    session,
                    Some("Connection changed. Reload and try again."),
                    StatusCode::CONFLICT,
                    now,
                )
                .await;
            }
            Err(error) => {
                tracing::error!(%error, tenant = %context.account.tenant.id, "cannot rotate Claims Provider credential");
                return error_page(&context.account, StatusCode::SERVICE_UNAVAILABLE);
            }
        }
    }
    let fetcher = match HttpsClientUrlFetcher::new() {
        Ok(fetcher) => fetcher,
        Err(_) => return error_page(&context.account, StatusCode::SERVICE_UNAVAILABLE),
    };
    let verified = match context
        .providers
        .collect(
            context.account.tenant,
            issuer,
            &connection.provider_subject,
            &registration.allowed_claims,
            &connection.access_token,
            &fetcher,
            now,
        )
        .await
    {
        Ok(value) => value,
        Err(_) => {
            tracing::warn!(tenant = %context.account.tenant.id, "Claims Provider recollection rejected");
            return render_current(
                context,
                session,
                Some("Provider claims could not be verified."),
                StatusCode::BAD_GATEWAY,
                now,
            )
            .await;
        }
    };
    match context
        .sources
        .replace_for_connection(user, &verified, connection.revision, now)
        .await
    {
        Ok(()) => {
            render_current(
                context,
                session,
                Some("Signed provider claims refreshed."),
                StatusCode::OK,
                now,
            )
            .await
        }
        Err(error) => {
            tracing::error!(%error, tenant = %context.account.tenant.id, "cannot save refreshed Claims Provider source");
            error_page(&context.account, StatusCode::SERVICE_UNAVAILABLE)
        }
    }
}

async fn render_current(
    context: &Context<'_>,
    session: &Session,
    message: Option<&str>,
    status: StatusCode,
    now: OffsetDateTime,
) -> Response {
    let sources = match context
        .sources
        .by_user(UserId::new(session.user), now)
        .await
    {
        Ok(sources) => sources,
        Err(error) => {
            tracing::error!(%error, tenant = %context.account.tenant.id, "cannot read Claims Provider sources");
            return error_page(&context.account, StatusCode::SERVICE_UNAVAILABLE);
        }
    };
    let connections = match context
        .pending
        .by_user(UserId::new(session.user), now)
        .await
    {
        Ok(connections) => connections,
        Err(error) => {
            tracing::error!(%error, tenant = %context.account.tenant.id, "cannot read Claims Provider connections");
            return error_page(&context.account, StatusCode::SERVICE_UNAVAILABLE);
        }
    };
    let mut stored_values = HashMap::new();
    for source in &sources {
        match context
            .providers
            .stored_values(context.account.tenant, source, now)
        {
            Ok(Some(values)) => {
                stored_values.insert(source.provider_issuer.clone(), values);
            }
            Ok(None) => {}
            Err(_) => {
                tracing::warn!(tenant = %context.account.tenant.id, "stored Claims Provider values failed verification");
                return error_page(&context.account, StatusCode::SERVICE_UNAVAILABLE);
            }
        }
    }
    render(
        context,
        session,
        &sources,
        &connections,
        &stored_values,
        message,
        status,
    )
}

fn render(
    context: &Context<'_>,
    session: &Session,
    sources: &[StoredClaimSource],
    connections: &[CpConnectionSummary],
    stored_values: &HashMap<String, Vec<(String, Value)>>,
    message: Option<&str>,
    status: StatusCode,
) -> Response {
    let action = context.account.mount.absolute(PAGE_PATH);
    let account = context.account.mount.absolute(account::PAGE_PATH);
    let csrf = csrf_for(session, CSRF_SEPARATOR);
    let mut items = String::new();
    let mut rendered = BTreeSet::new();
    for registration in context
        .providers
        .oauth_registrations(context.account.tenant.id.as_str())
    {
        rendered.insert(registration.issuer.clone());
        let connected = sources
            .iter()
            .find(|source| source.provider_issuer == registration.issuer);
        let credential = connections
            .iter()
            .find(|entry| entry.provider_issuer == registration.issuer);
        let details = connected.map_or_else(
            || "No signed claims stored.".to_owned(),
            |source| {
                format!(
                    "Stored claim names: {}. Expires: {}.",
                    escape_html(&source.claim_names.join(", ")),
                    escape_html(&account::stamp(source.expires_at))
                )
            },
        );
        let values = stored_values
            .get(&registration.issuer)
            .map_or_else(String::new, |pairs| {
                let mut list = String::from("<dl aria-label=\"Verified stored claims\">");
                for (name, value) in pairs {
                    list.push_str(&format!(
                        "<dt>{}</dt><dd>{}</dd>",
                        escape_html(name),
                        escape_html(&value.to_string())
                    ));
                }
                list.push_str("</dl>");
                list
            });
        let buttons = if credential.is_some() {
            "<button name=\"action\" value=\"refresh\">Refresh signed claims</button> <button name=\"action\" value=\"revoke\">Remove local connection and claims</button>"
        } else if connected.is_some() {
            "<button name=\"action\" value=\"connect\">Reconnect provider</button> <button name=\"action\" value=\"revoke\">Remove provider claims</button>"
        } else {
            "<button name=\"action\" value=\"connect\">Connect and approve claims</button>"
        };
        let credential_details = credential.map_or_else(String::new, |entry| {
            format!(
                "<p>Connection available until {}.</p>",
                escape_html(&account::stamp(
                    entry.refresh_expires_at.unwrap_or(entry.access_expires_at)
                ))
            )
        });
        items.push_str(&format!(
            "<li><h2>{}</h2><p>{}</p><p><a href=\"{}\" rel=\"noreferrer\">Connection policy</a></p><p>{details}</p>{values}{credential_details}<form method=\"post\" action=\"{}\"><input type=\"hidden\" name=\"csrf\" value=\"{csrf}\"><input type=\"hidden\" name=\"issuer\" value=\"{}\">{buttons}</form></li>",
            escape_html(&registration.issuer), escape_html(&registration.allowed_claims.into_iter().collect::<Vec<_>>().join(", ")),
            escape_html(&registration.policy_url), escape_html(&action), escape_html(&registration.issuer),
        ));
    }
    // A provider removed from operator configuration still has locally held
    // material until expiry. Keep its removal control visible to the user.
    for issuer in connections
        .iter()
        .map(|entry| &entry.provider_issuer)
        .chain(sources.iter().map(|entry| &entry.provider_issuer))
    {
        if !rendered.insert(issuer.clone()) {
            continue;
        }
        items.push_str(&format!("<li data-provider=\"{}\"><h2>{}</h2><p>Provider is no longer configured.</p><form method=\"post\" action=\"{}\"><input type=\"hidden\" name=\"csrf\" value=\"{csrf}\"><input type=\"hidden\" name=\"issuer\" value=\"{}\"><button name=\"action\" value=\"revoke\">Remove local connection and claims</button></form></li>",
            escape_html(issuer), escape_html(issuer), escape_html(&action), escape_html(issuer)));
    }
    if items.is_empty() {
        items.push_str("<li>No Claims Providers are configured.</li>");
    }
    let notice = message.map_or_else(String::new, |message| {
        format!("<p role=\"status\">{}</p>", escape_html(message))
    });
    let document = Document::render(context.account.nonce, |_nonce| {
        format!(
            "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"referrer\" content=\"no-referrer\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>Claims Providers</title></head><body><main><h1>Claims Providers</h1><p>Connect a provider to collect signed claims. Recollect them when they expire. Each relying party needs your separate approval before receiving them. Removing a connection erases credentials here and contacts the provider revocation endpoint when configured.</p>{notice}<ul>{items}</ul><p><a href=\"{}\">Back to account</a></p></main></body></html>",
            escape_html(&account)
        )
    });
    let mut response = (status, no_store(), document).into_response();
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    response
}

fn callback_url(issuer: &str) -> String {
    format!("{}{CALLBACK_PATH}", issuer.trim_end_matches('/'))
}

fn random_value() -> Result<String, getrandom::Error> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn parse_form(body: &[u8]) -> Option<(String, String, String)> {
    if body.len() > account::MAX_BODY {
        return None;
    }
    let mut csrf = None;
    let mut action = None;
    let mut issuer = None;
    for (key, value) in url::form_urlencoded::parse(body) {
        let target = match key.as_ref() {
            "csrf" => &mut csrf,
            "action" => &mut action,
            "issuer" => &mut issuer,
            _ => return None,
        };
        if target.is_some() {
            return None;
        }
        *target = Some(value.into_owned());
    }
    let (csrf, action, issuer) = (csrf?, action?, issuer?);
    if csrf.len() > account::MAX_CSRF_CHARS || issuer.len() > 2048 {
        return None;
    }
    Some((csrf, action, issuer))
}

fn parse_callback(raw: &str) -> Option<(String, String, Option<String>)> {
    if raw.len() > 4096 {
        return None;
    }
    let mut state = None;
    let mut code = None;
    let mut issuer = None;
    for (key, value) in url::form_urlencoded::parse(raw.as_bytes()) {
        let target = match key.as_ref() {
            "state" => &mut state,
            "code" => &mut code,
            "iss" => &mut issuer,
            _ => return None,
        };
        if target.is_some() {
            return None;
        }
        *target = Some(value.into_owned());
    }
    let (state, code) = (state?, code?);
    if state.len() != 43
        || code.is_empty()
        || code.len() > 2048
        || !state
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        || !code.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
    {
        return None;
    }
    if issuer
        .as_ref()
        .is_some_and(|value: &String| value.len() > 2048 || !value.starts_with("https://"))
    {
        return None;
    }
    Some((state, code, issuer))
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
