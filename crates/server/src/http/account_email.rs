//! Self-service email change with a fresh session and a one-use mailbox proof.

use asterius_domain::audit::{Actor, AuditEvent, AuditSink, EventType, Outcome};
use asterius_domain::{
    EmailVerificationToken, FirstPartyDestination, MAX_REGISTRATION_EMAIL_LENGTH, MailSender,
    Notification, UserDirectory, UserId,
};
use asterius_store_pg::PgEmailChangeRequests;
use asterius_web::Document;
use asterius_web::pages::{self, AccountEmailPage, nonce_attribute};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use time::{Duration, OffsetDateTime};

use crate::http::account::{
    self, AccountContext, MAX_BODY, begin, checked_csrf, csrf_for, error_page, fresh, no_store,
};

/// The signed-in form.
pub const PAGE_PATH: &str = "/account/email";
/// A link that confirms the pending address, without signing anybody in.
pub const CONFIRM_PATH: &str = "/account/email/confirm";
/// Reauthenticate before asking for a change.
pub const SIGN_IN_PATH: &str = "/account/email/sign-in";
const CSRF_SEPARATOR: &str = "account-email-csrf";
const LIFETIME: Duration = Duration::minutes(15);

/// Handles needed for one tenant's email change flow.
pub struct EmailContext<'a> {
    /// Shared account admission and page presentation.
    pub account: AccountContext<'a>,
    /// Accounts, used only to show the current address.
    pub users: &'a dyn UserDirectory,
    /// Pending one-use requests.
    pub changes: &'a PgEmailChangeRequests,
    /// Queues the confirmation link.
    pub mail: &'a dyn MailSender,
    /// Security audit trail.
    pub audit: &'a dyn AuditSink,
}

impl std::fmt::Debug for EmailContext<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmailContext").finish_non_exhaustive()
    }
}

/// Show the current address and a new-address form.
pub async fn page(
    context: &EmailContext<'_>,
    headers: &HeaderMap,
    now: OffsetDateTime,
) -> Response {
    let Some(session) = account::admitted(&context.account, headers, now).await else {
        return begin(&context.account, FirstPartyDestination::AccountEmail, now).await;
    };
    let user = match context.users.by_id(UserId::new(session.user)).await {
        Ok(Some(user)) => user,
        Ok(None) => return error_page(&context.account, StatusCode::NOT_FOUND),
        Err(error) => {
            tracing::error!(%error, tenant = %context.account.tenant.id, "cannot read account email");
            return error_page(&context.account, StatusCode::SERVICE_UNAVAILABLE);
        }
    };
    render(
        context,
        user.email.as_deref().unwrap_or(""),
        true,
        "",
        &csrf_for(&session, CSRF_SEPARATOR),
        StatusCode::OK,
    )
}

/// Issue a short-lived confirmation link for the new address.
pub async fn submit(
    context: &EmailContext<'_>,
    headers: &HeaderMap,
    body: &[u8],
    now: OffsetDateTime,
) -> Response {
    let Some(session) = account::admitted(&context.account, headers, now).await else {
        return begin(&context.account, FirstPartyDestination::AccountEmail, now).await;
    };
    let Some((csrf, address)) = parse_form(body) else {
        return render(
            context,
            "",
            true,
            context.account.text.account_email_unusable(),
            &csrf_for(&session, CSRF_SEPARATOR),
            StatusCode::BAD_REQUEST,
        );
    };
    if !checked_csrf(&session, CSRF_SEPARATOR, &csrf) {
        return render(
            context,
            "",
            true,
            context.account.text.account_email_form_expired(),
            &csrf_for(&session, CSRF_SEPARATOR),
            StatusCode::BAD_REQUEST,
        );
    }
    if !fresh(&session, now) {
        return begin(&context.account, FirstPartyDestination::AccountEmail, now).await;
    }

    let token = EmailVerificationToken::generate();
    let user = UserId::new(session.user);
    let issued = match context
        .changes
        .issue(user, &address, &token.digest(), now, now + LIFETIME)
        .await
    {
        Ok(issued) => issued,
        Err(error) => {
            tracing::error!(%error, tenant = %context.account.tenant.id, "cannot record pending email change");
            return error_page(&context.account, StatusCode::SERVICE_UNAVAILABLE);
        }
    };
    if issued {
        let link = format!(
            "{}{CONFIRM_PATH}?token={}",
            context.account.tenant.issuer.as_str().trim_end_matches('/'),
            token.expose()
        );
        // .1's delivery worker sends this queued message. A queue success is
        // not represented as delivered on the page.
        let message =
            Notification::email_change_confirmation(address, link, LIFETIME.whole_minutes())
                .with_expires_at(now + LIFETIME);
        if let Err(error) = context.mail.send(&message).await {
            tracing::error!(%error, tenant = %context.account.tenant.id, "cannot queue email change confirmation");
            return error_page(&context.account, StatusCode::SERVICE_UNAVAILABLE);
        }
        record(
            context,
            EventType::EMAIL_CHANGE_REQUESTED,
            Outcome::Success,
            Some(user),
            now,
        )
        .await;
    }
    render(
        context,
        "",
        false,
        context.account.text.account_email_queued(),
        "",
        StatusCode::OK,
    )
}

/// Reauthenticate and return to the email form.
pub async fn sign_in(context: &EmailContext<'_>, now: OffsetDateTime) -> Response {
    begin(&context.account, FirstPartyDestination::AccountEmail, now).await
}

/// Consume a confirmation link. No session is created by mailbox proof.
pub async fn confirm(
    context: &EmailContext<'_>,
    query: Option<&str>,
    now: OffsetDateTime,
) -> Response {
    let token = query.and_then(query_token);
    let Some(token) = token else {
        record(
            context,
            EventType::EMAIL_CHANGE_REFUSED,
            Outcome::Failure,
            None,
            now,
        )
        .await;
        return render(
            context,
            "",
            false,
            context.account.text.account_email_invalid(),
            "",
            StatusCode::BAD_REQUEST,
        );
    };
    match context.changes.confirm(&token.digest(), now).await {
        Ok(Some(change)) => {
            record(
                context,
                EventType::EMAIL_CHANGED,
                Outcome::Success,
                Some(change.user),
                now,
            )
            .await;
            render(
                context,
                "",
                false,
                context.account.text.account_email_confirmed(),
                "",
                StatusCode::OK,
            )
        }
        Ok(None) => {
            record(
                context,
                EventType::EMAIL_CHANGE_REFUSED,
                Outcome::Failure,
                None,
                now,
            )
            .await;
            render(
                context,
                "",
                false,
                context.account.text.account_email_invalid(),
                "",
                StatusCode::BAD_REQUEST,
            )
        }
        Err(error) => {
            tracing::error!(%error, tenant = %context.account.tenant.id, "cannot confirm email change");
            error_page(&context.account, StatusCode::SERVICE_UNAVAILABLE)
        }
    }
}

fn parse_form(body: &[u8]) -> Option<(String, String)> {
    if body.len() > MAX_BODY {
        return None;
    }
    let raw = std::str::from_utf8(body).ok()?;
    let mut csrf = None;
    let mut email = None;
    for (key, value) in url::form_urlencoded::parse(raw.as_bytes()) {
        match key.as_ref() {
            "csrf" if csrf.is_none() => csrf = Some(value.into_owned()),
            "email" if email.is_none() => email = Some(value.into_owned()),
            "csrf" | "email" => return None,
            _ => {}
        }
    }
    let csrf: String = csrf?;
    if csrf.is_empty() || csrf.len() > 256 {
        return None;
    }
    let raw_email: String = email?;
    if raw_email.chars().any(char::is_control) {
        return None;
    }
    let email = raw_email.trim().to_owned();
    if email.is_empty()
        || email.len() > MAX_REGISTRATION_EMAIL_LENGTH
        || !email.contains('@')
        || email.starts_with('@')
        || email.ends_with('@')
        || email
            .chars()
            .any(|ch| ch.is_control() || ch.is_whitespace())
    {
        return None;
    }
    Some((csrf, email))
}

fn query_token(query: &str) -> Option<EmailVerificationToken> {
    if query.len() > 1024 {
        return None;
    }
    let mut token = None;
    for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
        if key == "token" {
            if token.is_some() {
                return None;
            }
            token = Some(EmailVerificationToken::parse(&value).ok()?);
        }
    }
    token
}

async fn record(
    context: &EmailContext<'_>,
    kind: EventType,
    outcome: Outcome,
    user: Option<UserId>,
    now: OffsetDateTime,
) {
    let actor = user.map_or(Actor::System, |id| Actor::User(id.as_uuid().to_string()));
    let mut event = AuditEvent::new(context.account.tenant.id.clone(), kind, outcome, actor, now);
    if let Some(user) = user {
        event = event.subject(user.as_uuid().to_string());
    }
    if let Err(error) = context.audit.record(event).await {
        tracing::error!(%error, tenant = %context.account.tenant.id, "cannot audit email change");
    }
}

fn render(
    context: &EmailContext<'_>,
    current: &str,
    show_form: bool,
    message: &str,
    csrf: &str,
    status: StatusCode,
) -> Response {
    let font_url = crate::http::font_url(&context.account.mount);
    let presentation = crate::http::ThemeChrome::new(context.account.theme, &context.account.mount);
    let action = context.account.mount.absolute(PAGE_PATH);
    let account_href = context.account.mount.absolute(account::PAGE_PATH);
    let document = Document::render(context.account.nonce, |nonce| {
        pages::render(&AccountEmailPage {
            text: context.account.text,
            tenant_name: &context.account.tenant.display_name,
            current_address: current,
            show_form,
            message,
            action: &action,
            csrf,
            account_href: &account_href,
            nonce_attribute: nonce_attribute(nonce),
            theme_css: &presentation.css,
            brand: presentation.brand(&font_url),
        })
    });
    (status, no_store(), document).into_response()
}

#[cfg(test)]
mod tests {
    use super::{parse_form, query_token};

    #[test]
    fn email_change_form_rejects_ambiguous_or_unusable_addresses() {
        assert!(parse_form(b"csrf=x&email=a%40example.test&email=b%40example.test").is_none());
        assert!(parse_form(b"csrf=x&email=%0d%0aevil%40example.test").is_none());
        assert_eq!(
            parse_form(b"csrf=x&email=ada%40example.test"),
            Some(("x".to_owned(), "ada@example.test".to_owned()))
        );
    }

    #[test]
    fn email_change_confirmation_rejects_duplicate_tokens() {
        let token = asterius_domain::EmailVerificationToken::generate();
        let query = format!("token={}&token={}", token.expose(), token.expose());
        assert!(query_token(&query).is_none());
    }
}
