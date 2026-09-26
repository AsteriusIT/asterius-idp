//! User-started, one-shot Claims Provider OAuth code + PKCE connection.
//! Access tokens are used once for signed UserInfo and discarded; renewal is
//! not offered until encrypted long-lived credential custody is implemented.

use crate::claims_provider::ClaimsProviders;
use crate::http::account::{
    self, AccountContext, checked_csrf, csrf_for, error_page, fresh, no_store,
};
use crate::http::redirect::SeeOther;
use crate::outbound::{HttpsClientUrlFetcher, HttpsPoster, PostRequest};
use asterius_domain::{FirstPartyDestination, Session, UserId, sha256_hex};
use asterius_store_pg::{PgAggregatedClaims, PgCpOAuth, StoredClaimSource};
use asterius_web::Document;
use axum::body::Bytes;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use time::{Duration, OffsetDateTime};
use zeroize::{Zeroize, Zeroizing};

pub const PAGE_PATH: &str = "/account/claims-providers";
pub const CALLBACK_PATH: &str = "/account/claims-providers/callback";
const CSRF_SEPARATOR: &str = "account-claims-providers-csrf";
const PENDING_LIFETIME: Duration = Duration::minutes(10);

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
    if context
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
        "connect" => connect(context, &session, &issuer, now).await,
        "revoke" => {
            match context
                .sources
                .revoke(UserId::new(session.user), &issuer, now)
                .await
            {
                Ok(_) => {
                    render_current(
                        context,
                        &session,
                        Some("Provider claims removed."),
                        StatusCode::OK,
                        now,
                    )
                    .await
                }
                Err(error) => {
                    tracing::error!(%error, tenant = %context.account.tenant.id, "cannot revoke Claims Provider source");
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

async fn connect(
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
            now + PENDING_LIFETIME,
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
        .consume(&sha256_hex(state.as_bytes()), &session.id_digest, now)
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
        Err(error) => {
            tracing::warn!(%error, tenant = %context.account.tenant.id, "Claims Provider signed UserInfo rejected");
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
    match context
        .sources
        .replace(UserId::new(session.user), &verified, now)
        .await
    {
        Ok(()) => {
            render_current(
                context,
                &session,
                Some("Signed provider claims connected until they expire."),
                StatusCode::OK,
                now,
            )
            .await
        }
        Err(error) => {
            tracing::error!(%error, tenant = %context.account.tenant.id, "cannot save Claims Provider source");
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
    {
        return Err(());
    }
    Ok(token)
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
    render(context, session, &sources, message, status)
}

fn render(
    context: &Context<'_>,
    session: &Session,
    sources: &[StoredClaimSource],
    message: Option<&str>,
    status: StatusCode,
) -> Response {
    let action = context.account.mount.absolute(PAGE_PATH);
    let account = context.account.mount.absolute(account::PAGE_PATH);
    let csrf = csrf_for(session, CSRF_SEPARATOR);
    let mut items = String::new();
    for registration in context
        .providers
        .oauth_registrations(context.account.tenant.id.as_str())
    {
        let connected = sources
            .iter()
            .find(|source| source.provider_issuer == registration.issuer);
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
        let verb = if connected.is_some() {
            "revoke"
        } else {
            "connect"
        };
        let label = if connected.is_some() {
            "Remove provider claims"
        } else {
            "Connect and approve claims"
        };
        items.push_str(&format!(
            "<li><h2>{}</h2><p>{}</p><p>{details}</p><form method=\"post\" action=\"{}\"><input type=\"hidden\" name=\"csrf\" value=\"{csrf}\"><input type=\"hidden\" name=\"issuer\" value=\"{}\"><button name=\"action\" value=\"{verb}\">{label}</button></form></li>",
            escape_html(&registration.issuer), escape_html(&registration.allowed_claims.into_iter().collect::<Vec<_>>().join(", ")),
            escape_html(&action), escape_html(&registration.issuer),
        ));
    }
    if items.is_empty() {
        items.push_str("<li>No Claims Providers are configured.</li>");
    }
    let notice = message.map_or_else(String::new, |message| {
        format!("<p role=\"status\">{}</p>", escape_html(message))
    });
    let document = Document::render(context.account.nonce, |_nonce| {
        format!(
            "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"referrer\" content=\"no-referrer\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>Claims Providers</title></head><body><main><h1>Claims Providers</h1><p>Connect a provider to collect its signed claims for up to one hour. Each relying party still needs your separate approval before receiving them.</p>{notice}<ul>{items}</ul><p><a href=\"{}\">Back to account</a></p></main></body></html>",
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
