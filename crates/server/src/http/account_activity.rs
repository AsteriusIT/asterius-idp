//! A bounded, redacted view of security changes for the signed-in account.
//!
//! The audit trail is an operator record. This page projects only known event
//! types onto fixed labels; actor, detail, identifiers and hashes never reach
//! the template. The query is scoped to the tenant and authenticated user.

use asterius_domain::audit::query::{AuditFilter, AuditQuery};
use asterius_domain::audit::{AuditEvent, DetailValue, EventType, Outcome};
use asterius_domain::{FirstPartyDestination, TenantId};
use asterius_web::Document;
use asterius_web::pages::{self, AccountActivityPage, ActivityLine, nonce_attribute};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use time::{Duration, OffsetDateTime};

use crate::http::account::{self, AccountContext, begin, error_page, no_store, stamp};

/// The account owner's recent activity.
pub const PAGE_PATH: &str = "/account/activity";
const WINDOW: Duration = Duration::days(90);
const QUERY_LIMIT: u32 = 100;
const DISPLAY_LIMIT: usize = 30;

/// Authenticated account page context.
pub struct ActivityContext<'a> {
    /// Session admission, tenant, text and page chrome.
    pub account: AccountContext<'a>,
    /// Read-only trail query.
    pub audit: &'a dyn AuditQuery,
}

impl std::fmt::Debug for ActivityContext<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ActivityContext").finish_non_exhaustive()
    }
}

/// `GET /account/activity`.
pub async fn page(
    context: &ActivityContext<'_>,
    headers: &HeaderMap,
    now: OffsetDateTime,
) -> Response {
    let Some(session) = account::admitted(&context.account, headers, now).await else {
        return begin(
            &context.account,
            FirstPartyDestination::AccountActivity,
            now,
        )
        .await;
    };

    let filter = AuditFilter {
        user: Some(session.user.to_string()),
        event_types: vec![
            EventType::AUTH_LOGIN,
            EventType::CREDENTIAL_CREATED,
            EventType::CREDENTIAL_CHANGED,
            EventType::RECOVERY_USED,
            EventType::EMAIL_VERIFIED,
            EventType::SESSION_REVOKED,
        ],
        from: Some(now - WINDOW),
        until: Some(now + Duration::seconds(1)),
        ..AuditFilter::default()
    };
    let entries = match context
        .audit
        .query(&context.account.tenant.id, &filter, None, QUERY_LIMIT)
        .await
    {
        Ok(entries) => entries,
        Err(error) => {
            tracing::error!(%error, tenant = %context.account.tenant.id, "cannot read account security activity");
            return error_page(&context.account, StatusCode::SERVICE_UNAVAILABLE);
        }
    };
    let subject = session.user.to_string();
    let events = entries
        .iter()
        .filter_map(|entry| entry.record.event())
        .filter_map(|event| {
            visible_line(
                event,
                &context.account.tenant.id,
                &subject,
                now,
                context.account.text,
            )
        })
        .take(DISPLAY_LIMIT)
        .collect();

    let font_url = crate::http::font_url(&context.account.mount);
    let presentation = crate::http::ThemeChrome::new(context.account.theme, &context.account.mount);
    let sessions_href = context
        .account
        .mount
        .absolute(crate::http::account_sessions::PAGE_PATH);
    let account_href = context.account.mount.absolute(account::PAGE_PATH);
    let document = Document::render(context.account.nonce, |nonce| {
        pages::render(&AccountActivityPage {
            text: context.account.text,
            tenant_name: &context.account.tenant.display_name,
            events,
            sessions_href: &sessions_href,
            account_href: &account_href,
            nonce_attribute: nonce_attribute(nonce),
            theme_css: &presentation.css,
            brand: presentation.brand(&font_url),
        })
    });
    (StatusCode::OK, no_store(), document).into_response()
}

fn visible_line(
    event: &AuditEvent,
    tenant: &TenantId,
    subject: &str,
    now: OffsetDateTime,
    text: &asterius_web::Catalog,
) -> Option<ActivityLine> {
    // Guard the projection even if an AuditQuery implementation has a faulty
    // filter. The page must never display another account's row.
    if &event.tenant != tenant
        || event.subject.as_deref() != Some(subject)
        || event.occurred_at < now - WINDOW
        || event.occurred_at > now
    {
        return None;
    }
    label(event, text).map(|action| ActivityLine {
        action: action.to_owned(),
        occurred_at: stamp(event.occurred_at.to_offset(time::UtcOffset::UTC)),
    })
}

fn detail_label<'a>(event: &'a AuditEvent, key: &str) -> Option<&'a str> {
    event.detail.iter().find_map(|(name, value)| {
        if name == key {
            match value {
                DetailValue::Text(text) => Some(text.as_str()),
                _ => None,
            }
        } else {
            None
        }
    })
}

/// Closed mapping: no audit detail or actor text can become page content.
fn label<'a>(event: &AuditEvent, text: &'a asterius_web::Catalog) -> Option<&'a str> {
    if event.outcome != Outcome::Success {
        return None;
    }
    match event.event_type {
        EventType::AUTH_LOGIN => Some(text.activity_sign_in()),
        EventType::CREDENTIAL_CREATED if detail_label(event, "kind") == Some("passkey") => {
            Some(text.activity_passkey_added())
        }
        EventType::CREDENTIAL_CHANGED
            if detail_label(event, "kind") == Some("passkey")
                && detail_label(event, "change") == Some("removed") =>
        {
            Some(text.activity_passkey_removed())
        }
        EventType::CREDENTIAL_CHANGED
            if detail_label(event, "kind") == Some("password")
                && detail_label(event, "reason") != Some("recovery") =>
        {
            Some(text.activity_password())
        }
        EventType::RECOVERY_USED => Some(text.activity_recovery()),
        EventType::EMAIL_VERIFIED => Some(text.activity_email()),
        EventType::SESSION_REVOKED => Some(text.activity_session_closed()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asterius_domain::TenantId;
    use asterius_domain::audit::{Actor, Detail};

    #[test]
    fn only_known_successful_changes_are_labeled() {
        let text = asterius_web::Catalog::default();
        let event = AuditEvent::new(
            TenantId::new("demo"),
            EventType::CREDENTIAL_CHANGED,
            Outcome::Success,
            Actor::User("user".to_owned()),
            OffsetDateTime::UNIX_EPOCH,
        )
        .subject("user")
        .detail(
            Detail::new()
                .label("kind", "passkey")
                .label("change", "removed")
                .text("untrusted", "private@example.com"),
        );
        assert_eq!(label(&event, &text), Some(text.activity_passkey_removed()));
        assert_eq!(
            label(
                &AuditEvent {
                    outcome: Outcome::Failure,
                    ..event
                },
                &text
            ),
            None
        );
    }

    #[test]
    fn activity_projection_rejects_other_tenants_and_accounts() {
        let text = asterius_web::Catalog::default();
        let now = OffsetDateTime::UNIX_EPOCH + Duration::days(1);
        let event = AuditEvent::new(
            TenantId::new("demo"),
            EventType::RECOVERY_USED,
            Outcome::Success,
            Actor::User("alice".to_owned()),
            now,
        )
        .subject("alice")
        .detail(Detail::new().text("secret", "private@example.com"));

        let line = visible_line(&event, &TenantId::new("demo"), "alice", now, &text)
            .expect("own event is visible");
        assert_eq!(line.action, text.activity_recovery());
        assert!(!line.action.contains("private@example.com"));
        assert!(visible_line(&event, &TenantId::new("other"), "alice", now, &text).is_none());
        assert!(visible_line(&event, &TenantId::new("demo"), "bob", now, &text).is_none());
        assert!(
            visible_line(
                &event,
                &TenantId::new("demo"),
                "alice",
                now + Duration::days(91),
                &text
            )
            .is_none()
        );
    }
}
