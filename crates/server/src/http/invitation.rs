//! First login through a mailed, tenant-bound invitation.

use crate::tenancy::MountPrefix;
use asterius_domain::audit::{Actor, AuditEvent, AuditSink, Detail, EventType, Outcome};
use asterius_domain::{AcceptedPassword, OpaqueToken, Tenant};
use asterius_web::pages::{self, InvitationPage, nonce_attribute};
use asterius_web::{Document, csp::Nonce, recovery as csrf};
use axum::body::Bytes;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use time::OffsetDateTime;

pub const PAGE_PATH: &str = "/invite";
const MAX_FORM_BYTES: usize = 4096;
const MAX_QUERY_BYTES: usize = 256;
const MAX_TOKEN_BYTES: usize = 128;

#[derive(Debug)]
pub struct Context<'a> {
    pub tenant: &'a Tenant,
    pub theme: &'a asterius_domain::Theme,
    pub invitations: &'a asterius_store_pg::PgInvitations,
    pub passwords: Option<&'a asterius_store_pg::PgPasswordVerifier>,
    pub audit: &'a dyn AuditSink,
    pub throttle: crate::http::throttle::LoginThrottle<'a>,
    /// A password-only sign-in must reach at least one level in this tenant's ACR ladder.
    pub password_allowed: bool,
    pub nonce: &'a Nonce,
    pub mount: MountPrefix,
}

pub async fn show(context: &Context<'_>, query: Option<&str>, now: OffsetDateTime) -> Response {
    if query.is_some_and(|query| query.len() > MAX_QUERY_BYTES) {
        return page(context, "", "", "", false, false, None);
    }
    let token = query
        .and_then(|query| one_field(query.as_bytes(), "token"))
        .filter(|value| value.len() <= MAX_TOKEN_BYTES)
        .map(OpaqueToken::from_presented);
    let Some(token) = token else {
        return page(context, "", "", "", false, false, None);
    };
    let preview = match context.invitations.preview(&token, now).await {
        Ok(preview) => preview,
        Err(error) => {
            tracing::error!(%error, tenant = %context.tenant.id, "cannot inspect invitation");
            return page(context, "", "", "", false, false, None);
        }
    };
    let Some(preview) = preview else {
        return page(context, "", "", "", false, false, None);
    };
    if !context.password_allowed {
        return page(
            context,
            "",
            "",
            "",
            false,
            false,
            Some(
                "This tenant requires another sign-in method. Contact your administrator for onboarding help.",
            ),
        );
    }
    if context.passwords.is_none() {
        return page(context, "", "", "", false, false, None);
    }
    let (csrf_token, cookie) = csrf::issue();
    let mut response = page(
        context,
        &preview.username,
        token.expose(),
        csrf_token.expose(),
        true,
        false,
        None,
    );
    append_cookie(&mut response, &cookie);
    response
}

pub async fn submit(
    context: &Context<'_>,
    headers: &HeaderMap,
    body: &Bytes,
    now: OffsetDateTime,
) -> Response {
    if body.len() > MAX_FORM_BYTES {
        return page(context, "", "", "", false, false, None);
    }
    let Some(value) = one_field(body, "token") else {
        return page(context, "", "", "", false, false, None);
    };
    if value.len() > MAX_TOKEN_BYTES {
        return page(context, "", "", "", false, false, None);
    }
    let token = OpaqueToken::from_presented(value);
    let preview = match context.invitations.preview(&token, now).await {
        Ok(Some(preview)) => preview,
        Ok(None) => return page(context, "", "", "", false, false, None),
        Err(error) => {
            tracing::error!(%error, tenant = %context.tenant.id, "cannot inspect invitation");
            return page(context, "", "", "", false, false, None);
        }
    };
    let Some(passwords) = context.passwords else {
        return page(context, "", "", "", false, false, None);
    };
    if !context.password_allowed {
        return page(
            context,
            "",
            "",
            "",
            false,
            false,
            Some(
                "This tenant requires another sign-in method. Contact your administrator for onboarding help.",
            ),
        );
    }
    let attempt = context.throttle.attempt(None);
    match context
        .throttle
        .check(&context.tenant.id, &attempt, now)
        .await
    {
        Ok(Some(refused)) => return retry(context, &preview.username, &token, &refused.hint()),
        Err(error) => {
            tracing::error!(%error, tenant = %context.tenant.id, "cannot check invitation throttle");
            return page(context, "", "", "", false, false, None);
        }
        Ok(None) => {}
    }
    context
        .throttle
        .record_failure(&context.tenant.id, &attempt, now)
        .await;
    let cookies = headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect::<Vec<_>>()
        .join("; ");
    if csrf::check(&cookies, one_field(body, "csrf").as_deref()).is_err() {
        return retry(
            context,
            &preview.username,
            &token,
            "That form expired. Please try again.",
        );
    }
    let accepted = match accept_password(body) {
        Ok(accepted) => accepted,
        Err(message) => return retry(context, &preview.username, &token, message),
    };
    let hash = match passwords.hash_for_storage(accepted.expose()) {
        Ok(hash) => hash,
        Err(error) => {
            tracing::error!(%error, tenant = %context.tenant.id, "cannot hash invited password");
            return page(context, "", "", "", false, false, None);
        }
    };
    match context.invitations.activate(&token, &hash, now).await {
        Ok(Some(activated)) => {
            audit_activation(context, &activated, now).await;
            let mut response = page(context, "", "", "", false, true, None);
            append_cookie(&mut response, &csrf::clear_cookie());
            response
        }
        Ok(None) => page(context, "", "", "", false, false, None),
        Err(error) => {
            tracing::error!(%error, tenant = %context.tenant.id, "cannot activate invitation");
            page(context, "", "", "", false, false, None)
        }
    }
}

fn accept_password(body: &Bytes) -> Result<AcceptedPassword, &'static str> {
    let password = one_field(body, "password").ok_or("Enter a password.")?;
    if one_field(body, "password_confirmation").as_deref() != Some(password.as_str()) {
        return Err("The passwords did not match.");
    }
    AcceptedPassword::accept_locally(&password)
        .map_err(|_| "Choose a longer, less common password.")
}

async fn audit_activation(
    context: &Context<'_>,
    activated: &asterius_store_pg::ActivatedInvitation,
    now: OffsetDateTime,
) {
    let user = activated.user;
    let event = AuditEvent::new(
        context.tenant.id.clone(),
        EventType::INVITATION_ACTIVATED,
        Outcome::Success,
        Actor::User(user.as_uuid().to_string()),
        now,
    )
    .subject(user.as_uuid().to_string())
    .detail(Detail::new().text("invitation_id", activated.invitation_id.to_string()));
    if let Err(error) = context.audit.record(event).await {
        tracing::error!(%error, tenant = %context.tenant.id, "cannot audit invitation activation");
    }
    if let Some(role) = &activated.role {
        let event = AuditEvent::new(
            context.tenant.id.clone(),
            EventType::ROLE_GRANTED,
            Outcome::Success,
            Actor::Admin(activated.invited_by.clone()),
            now,
        )
        .subject(user.as_uuid().to_string())
        .detail(Detail::new().text("role", role));
        if let Err(error) = context.audit.record(event).await {
            tracing::error!(%error, tenant = %context.tenant.id, "cannot audit invited role assignment");
        }
    }
    for group in &activated.group_ids {
        let event = AuditEvent::new(
            context.tenant.id.clone(),
            EventType::INVITATION_ASSIGNMENTS_APPLIED,
            Outcome::Success,
            Actor::Admin(activated.invited_by.clone()),
            now,
        )
        .subject(user.as_uuid().to_string())
        .detail(Detail::new().text("group_id", group.to_string()));
        if let Err(error) = context.audit.record(event).await {
            tracing::error!(%error, tenant = %context.tenant.id, "cannot audit invited group assignment");
        }
    }
}

fn retry(context: &Context<'_>, username: &str, token: &OpaqueToken, message: &str) -> Response {
    let (csrf_token, cookie) = csrf::issue();
    let mut response = page(
        context,
        username,
        token.expose(),
        csrf_token.expose(),
        true,
        false,
        Some(message),
    );
    append_cookie(&mut response, &cookie);
    response
}

fn page(
    context: &Context<'_>,
    username: &str,
    token: &str,
    csrf_token: &str,
    available: bool,
    complete: bool,
    message: Option<&str>,
) -> Response {
    let font_url = crate::http::font_url(&context.mount);
    let presentation = crate::http::ThemeChrome::new(context.theme, &context.mount);
    let mut response = Document::render(context.nonce, |nonce| {
        pages::render(&InvitationPage {
            text: &crate::http::i18n::UNTRANSLATED,
            tenant_name: &context.tenant.display_name,
            username,
            action: &context.mount.absolute(PAGE_PATH),
            csrf: csrf_token,
            token,
            minimum_password_length: asterius_domain::entities::password::MIN_LENGTH,
            message,
            available,
            complete,
            nonce_attribute: nonce_attribute(nonce),
            theme_css: &presentation.css,
            brand: presentation.brand(&font_url),
        })
    })
    .into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        "no-store".parse().expect("static header"),
    );
    *response.status_mut() = StatusCode::OK;
    response
}

fn append_cookie(response: &mut Response, value: &str) {
    if let Ok(value) = value.parse() {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
}

fn one_field(data: &[u8], name: &str) -> Option<String> {
    let mut result = None;
    for (key, value) in url::form_urlencoded::parse(data) {
        if key == name {
            if result.is_some() {
                return None;
            }
            result = Some(value.into_owned());
        }
    }
    result
}
