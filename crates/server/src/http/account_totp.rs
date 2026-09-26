//! Self-service TOTP lifecycle. Provisioning material appears only in the
//! no-store response that creates the pending seed (`ast-s36.15.2`).

use asterius_domain::audit::{Actor, AuditEvent, AuditSink, Detail, EventType, Outcome};
use asterius_domain::{FirstPartyDestination, Session, totp::TotpSecret};
use asterius_store_pg::{PgTotpCredentials, TotpStatus};
use asterius_web::Document;
use axum::body::Bytes;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use time::OffsetDateTime;

use crate::http::account::{
    self, AccountContext, begin, checked_csrf, csrf_for, error_page, fresh, no_store,
};

/// Account page that starts or confirms authenticator enrollment.
pub const PAGE_PATH: &str = "/account/totp";
const CSRF_SEPARATOR: &str = "account-totp-csrf";

/// Dependencies for the signed-in account's enrollment page.
pub struct TotpContext<'a> {
    /// Shared account admission and presentation.
    pub account: AccountContext<'a>,
    /// Tenant-scoped encrypted credential store.
    pub credentials: &'a PgTotpCredentials,
    /// Account security trail.
    pub audit: &'a dyn AuditSink,
    /// Account- and address-scoped limit for an optional code proof.
    pub throttle: crate::http::throttle::LoginThrottle<'a>,
}

impl std::fmt::Debug for TotpContext<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TotpContext").finish_non_exhaustive()
    }
}

/// Reads state only; a pending seed is never decrypted for a GET.
pub async fn page(context: &TotpContext<'_>, headers: &HeaderMap, now: OffsetDateTime) -> Response {
    let Some(session) = account::admitted(&context.account, headers, now).await else {
        return begin(&context.account, FirstPartyDestination::AccountTotp, now).await;
    };
    match context.credentials.status(session.user, now).await {
        Ok(status) => render(context, &session, status, None, None, StatusCode::OK),
        Err(error) => {
            tracing::error!(%error, tenant = %context.account.tenant.id, "cannot read TOTP enrollment status");
            error_page(&context.account, StatusCode::SERVICE_UNAVAILABLE)
        }
    }
}

/// Starts a fresh pending enrollment or proves possession of its seed.
pub async fn submit(
    context: &TotpContext<'_>,
    headers: &HeaderMap,
    body: &Bytes,
    now: OffsetDateTime,
) -> Response {
    let Some(session) = account::admitted(&context.account, headers, now).await else {
        return begin(&context.account, FirstPartyDestination::AccountTotp, now).await;
    };
    let Some(form) = parse_form(body) else {
        return render(
            context,
            &session,
            TotpStatus::Unenrolled,
            Some("Form was invalid."),
            None,
            StatusCode::BAD_REQUEST,
        );
    };
    if !checked_csrf(&session, CSRF_SEPARATOR, &form.csrf) {
        return render(
            context,
            &session,
            TotpStatus::Unenrolled,
            Some("Form expired. Reload and try again."),
            None,
            StatusCode::BAD_REQUEST,
        );
    }
    if !fresh(&session, now) {
        return begin(&context.account, FirstPartyDestination::AccountTotp, now).await;
    }

    match form.action.as_str() {
        "start" => start(context, &session, now).await,
        "confirm" => confirm(context, &session, &form.code, now).await,
        "remove" => remove(context, &session, &form.code, now).await,
        _ => render(
            context,
            &session,
            TotpStatus::Unenrolled,
            Some("Form was invalid."),
            None,
            StatusCode::BAD_REQUEST,
        ),
    }
}

/// Removes an active factor only after fresh authentication that satisfies the
/// tenant's configured assurance policy. In deployments without an ACR policy,
/// the current TOTP code itself is the required second factor. This leaves
/// lost-device recovery to the deployment's existing approved account recovery
/// process instead of creating a weaker bypass here.
// Keep this protocol transition together so validation and issuance order stays auditable.
#[allow(clippy::too_many_lines)]
async fn remove(
    context: &TotpContext<'_>,
    session: &Session,
    code: &str,
    now: OffsetDateTime,
) -> Response {
    let status = match context.credentials.status(session.user, now).await {
        Ok(status) => status,
        Err(error) => {
            tracing::error!(%error, tenant = %context.account.tenant.id, "cannot read TOTP status before removal");
            return error_page(&context.account, StatusCode::SERVICE_UNAVAILABLE);
        }
    };
    if status != TotpStatus::Active {
        return render(
            context,
            session,
            status,
            Some("No active authenticator was removed."),
            None,
            StatusCode::CONFLICT,
        );
    }

    let assurance_satisfied = !context.account.acr.levels().is_empty()
        && context.account.acr.achieved(&session.amr).is_some();
    let step_up_satisfied = if code.is_empty() {
        assurance_satisfied
    } else {
        let account_name = session.user.to_string();
        let attempt = context.throttle.attempt(Some(&account_name));
        match context
            .throttle
            .check(&context.account.tenant.id, &attempt, now)
            .await
        {
            Ok(Some(refused)) => {
                crate::http::throttle::record_throttled(
                    context.audit,
                    &context.account.tenant.id,
                    refused,
                    now,
                )
                .await;
                return render(
                    context,
                    session,
                    TotpStatus::Active,
                    Some(&refused.hint()),
                    None,
                    StatusCode::TOO_MANY_REQUESTS,
                );
            }
            Err(error) => {
                tracing::error!(%error, tenant = %context.account.tenant.id, "cannot check TOTP removal throttle");
                return error_page(&context.account, StatusCode::SERVICE_UNAVAILABLE);
            }
            Ok(None) => {}
        }
        match context.credentials.verify(session.user, code, now).await {
            Ok(true) => {
                context
                    .throttle
                    .record_success(&context.account.tenant.id, &attempt)
                    .await;
                true
            }
            Ok(false) => {
                context
                    .throttle
                    .record_failure(&context.account.tenant.id, &attempt, now)
                    .await;
                false
            }
            Err(error) => {
                tracing::error!(%error, tenant = %context.account.tenant.id, "cannot verify TOTP removal step-up");
                return error_page(&context.account, StatusCode::SERVICE_UNAVAILABLE);
            }
        }
    };
    if !step_up_satisfied {
        record(
            context,
            session,
            "removal_step_up_failed",
            Outcome::Failure,
            now,
        )
        .await;
        return render(
            context,
            session,
            TotpStatus::Active,
            Some(
                "Removal needs a fresh sign-in that meets your security policy, or a current authenticator code.",
            ),
            None,
            StatusCode::FORBIDDEN,
        );
    }

    match context.credentials.remove(session.user).await {
        Ok(true) => {
            record(context, session, "removed", Outcome::Success, now).await;
            render(
                context,
                session,
                TotpStatus::Unenrolled,
                Some("Authenticator removed. Set it up again from this page when ready."),
                None,
                StatusCode::OK,
            )
        }
        Ok(false) => render(
            context,
            session,
            TotpStatus::Unenrolled,
            Some("No active authenticator was removed."),
            None,
            StatusCode::CONFLICT,
        ),
        Err(error) => {
            tracing::error!(%error, tenant = %context.account.tenant.id, "cannot remove TOTP authenticator");
            error_page(&context.account, StatusCode::SERVICE_UNAVAILABLE)
        }
    }
}

async fn start(context: &TotpContext<'_>, session: &Session, now: OffsetDateTime) -> Response {
    let secret = match TotpSecret::generate() {
        Ok(secret) => secret,
        Err(error) => {
            tracing::error!(%error, "cannot generate TOTP enrollment seed");
            return error_page(&context.account, StatusCode::SERVICE_UNAVAILABLE);
        }
    };
    match context.credentials.begin(session.user, &secret, now).await {
        Ok(()) => {
            record(
                context,
                session,
                "enrollment_started",
                Outcome::Success,
                now,
            )
            .await;
            let encoded = base32(secret.expose());
            let label = format!("{}:{}", context.account.tenant.display_name, session.user);
            let issuer = form_encode(&context.account.tenant.display_name);
            let label = path_encode(&label);
            let uri = format!(
                "otpauth://totp/{label}?secret={encoded}&issuer={issuer}&algorithm=SHA1&digits=6&period=30"
            );
            render(
                context,
                session,
                TotpStatus::Pending,
                None,
                Some((&encoded, &uri)),
                StatusCode::OK,
            )
        }
        Err(asterius_domain::DomainError::Conflict(_)) => render(
            context,
            session,
            TotpStatus::Active,
            Some("An authenticator is already active."),
            None,
            StatusCode::CONFLICT,
        ),
        Err(error) => {
            tracing::error!(%error, tenant = %context.account.tenant.id, "cannot start TOTP enrollment");
            error_page(&context.account, StatusCode::SERVICE_UNAVAILABLE)
        }
    }
}

async fn confirm(
    context: &TotpContext<'_>,
    session: &Session,
    code: &str,
    now: OffsetDateTime,
) -> Response {
    match context.credentials.confirm(session.user, code, now).await {
        Ok(true) => {
            record(
                context,
                session,
                "enrollment_confirmed",
                Outcome::Success,
                now,
            )
            .await;
            render(
                context,
                session,
                TotpStatus::Active,
                Some("Authenticator enabled. The setup key will not be shown again."),
                None,
                StatusCode::OK,
            )
        }
        Ok(false) => {
            record(
                context,
                session,
                "enrollment_confirmation_failed",
                Outcome::Failure,
                now,
            )
            .await;
            let status = match context.credentials.status(session.user, now).await {
                Ok(status) => status,
                Err(error) => {
                    tracing::error!(%error, tenant = %context.account.tenant.id, "cannot read TOTP enrollment status");
                    return error_page(&context.account, StatusCode::SERVICE_UNAVAILABLE);
                }
            };
            render(
                context,
                session,
                status,
                Some(
                    "That code could not confirm enrollment. Check the device clock or start a new enrollment.",
                ),
                None,
                StatusCode::BAD_REQUEST,
            )
        }
        Err(error) => {
            tracing::error!(%error, tenant = %context.account.tenant.id, "cannot confirm TOTP enrollment");
            error_page(&context.account, StatusCode::SERVICE_UNAVAILABLE)
        }
    }
}

async fn record(
    context: &TotpContext<'_>,
    session: &Session,
    action: &'static str,
    outcome: Outcome,
    now: OffsetDateTime,
) {
    let subject = session.user.to_string();
    let event = AuditEvent::new(
        context.account.tenant.id.clone(),
        EventType::CREDENTIAL_CHANGED,
        outcome,
        Actor::User(subject.clone()),
        now,
    )
    .session(asterius_domain::SessionId::new(session.id_digest.clone()))
    .subject(subject)
    .detail(
        Detail::new()
            .label("kind", "totp")
            .label("reason", "account_totp_lifecycle")
            .label("change", action),
    );
    if let Err(error) = context.audit.record(event).await {
        tracing::error!(%error, tenant = %context.account.tenant.id, "TOTP enrollment event was not written to the audit trail");
    }
}

fn render(
    context: &TotpContext<'_>,
    session: &Session,
    status: TotpStatus,
    message: Option<&str>,
    provisioning: Option<(&str, &str)>,
    http_status: StatusCode,
) -> Response {
    let csrf = csrf_for(session, CSRF_SEPARATOR);
    let action = context.account.mount.absolute(PAGE_PATH);
    let account = context.account.mount.absolute(account::PAGE_PATH);
    let notice = message.map_or_else(String::new, |message| {
        format!("<p role=\"status\">{}</p>", escape_html(message))
    });
    let body = match status {
        TotpStatus::Active => format!(
            "<p>Authenticator is active.</p><form method=\"post\" action=\"{}\"><input type=\"hidden\" name=\"csrf\" value=\"{}\"><label>Current six digit code, unless this session already meets your tenant's assurance policy <input name=\"code\" inputmode=\"numeric\" autocomplete=\"one-time-code\" pattern=\"[0-9]{{6}}\" maxlength=\"6\"></label><button name=\"action\" value=\"remove\">Remove authenticator</button></form><p>If you have lost access to your authenticator, use an existing approved sign-in or account recovery method. This page does not bypass your tenant's assurance policy.</p>",
            escape_html(&action),
            csrf
        ),
        TotpStatus::Pending => format!(
            "<p>Enrollment is pending. The setup key is shown only in the response that starts enrollment; if you did not save it, start again.</p><form method=\"post\" action=\"{}\"><input type=\"hidden\" name=\"csrf\" value=\"{}\"><button name=\"action\" value=\"start\">Start a new setup key</button></form>",
            escape_html(&action),
            csrf
        ),
        TotpStatus::Unenrolled => format!(
            "<form method=\"post\" action=\"{}\"><input type=\"hidden\" name=\"csrf\" value=\"{}\"><button name=\"action\" value=\"start\">Start authenticator setup</button></form>",
            escape_html(&action),
            csrf
        ),
    };
    let one_time = provisioning.map_or_else(String::new, |(secret, uri)| format!(
        "<section><h2>Save this setup key now</h2><p><code>{secret}</code></p><p>Authenticator URI:</p><pre>{}</pre><form method=\"post\" action=\"{}\"><input type=\"hidden\" name=\"csrf\" value=\"{}\"><label>Six digit code <input name=\"code\" inputmode=\"numeric\" autocomplete=\"one-time-code\" pattern=\"[0-9]{{6}}\" maxlength=\"6\" required></label><button name=\"action\" value=\"confirm\">Confirm setup</button></form></section>", escape_html(uri), escape_html(&action), csrf));
    let document = Document::render(context.account.nonce, |_nonce| {
        format!(
            "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"referrer\" content=\"no-referrer\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>Authenticator setup</title></head><body><main><h1>Authenticator setup</h1>{notice}{body}{one_time}<p><a href=\"{}\">Back to account</a></p></main></body></html>",
            escape_html(&account)
        )
    });
    let mut response = (http_status, no_store(), document).into_response();
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        axum::http::HeaderValue::from_static("no-referrer"),
    );
    response
}

struct Form {
    csrf: String,
    action: String,
    code: String,
}

fn parse_form(body: &[u8]) -> Option<Form> {
    if body.len() > account::MAX_BODY {
        return None;
    }
    let mut csrf = None;
    let mut action = None;
    let mut code = None;
    for (key, value) in url::form_urlencoded::parse(body) {
        let target = match key.as_ref() {
            "csrf" => &mut csrf,
            "action" => &mut action,
            "code" => &mut code,
            _ => continue,
        };
        if target.is_some() {
            return None;
        }
        *target = Some(value.into_owned());
    }
    let csrf = csrf?;
    let action = action?;
    let code = code.unwrap_or_default();
    if csrf.is_empty()
        || csrf.len() > account::MAX_CSRF_CHARS
        || !matches!(action.as_str(), "start" | "confirm" | "remove")
    {
        return None;
    }
    Some(Form { csrf, action, code })
}

fn base32(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut output = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let mut accumulator = 0_u32;
    let mut bits = 0_u8;
    for byte in bytes {
        accumulator = (accumulator << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            output.push(char::from(ALPHABET[((accumulator >> bits) & 31) as usize]));
        }
    }
    if bits > 0 {
        output.push(char::from(
            ALPHABET[((accumulator << (5 - bits)) & 31) as usize],
        ));
    }
    while !output.len().is_multiple_of(8) {
        output.push('=');
    }
    output
}

fn form_encode(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

fn path_encode(value: &str) -> String {
    value
        .bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b':') {
                char::from(byte).to_string()
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect()
}

fn escape_html(value: &str) -> String {
    value
        .chars()
        .map(|character| match character {
            '&' => "&amp;".to_owned(),
            '<' => "&lt;".to_owned(),
            '>' => "&gt;".to_owned(),
            '"' => "&quot;".to_owned(),
            '\'' => "&#39;".to_owned(),
            _ => character.to_string(),
        })
        .collect()
}
