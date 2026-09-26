//! Account-owner approval and withdrawal for operator-pinned ID-JAG delegation.

use asterius_domain::{FirstPartyDestination, Session};
use asterius_store_pg::{IdJagConsent, MAX_CONSENT_LIFETIME, PgIdJagRedemption};
use asterius_web::Document;
use axum::body::Bytes;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use time::OffsetDateTime;

use crate::http::account::{
    self, AccountContext, begin, checked_csrf, csrf_for, error_page, fresh, no_store,
};
use crate::id_jag_trust::{IdJagConsentOption, IdJagTrusts};

pub const PAGE_PATH: &str = "/account/id-jag";
const CSRF_SEPARATOR: &str = "account-id-jag-consent";

pub struct ConsentContext<'a> {
    pub account: AccountContext<'a>,
    pub store: &'a PgIdJagRedemption,
    pub trusts: &'a IdJagTrusts,
}

impl std::fmt::Debug for ConsentContext<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConsentContext")
            .finish_non_exhaustive()
    }
}

pub async fn page(
    context: &ConsentContext<'_>,
    headers: &HeaderMap,
    now: OffsetDateTime,
) -> Response {
    let Some(session) = account::admitted(&context.account, headers, now).await else {
        return begin(
            &context.account,
            FirstPartyDestination::AccountIdJagConsent,
            now,
        )
        .await;
    };
    render_current(context, &session, now, None, StatusCode::OK).await
}

pub async fn submit(
    context: &ConsentContext<'_>,
    headers: &HeaderMap,
    body: &Bytes,
    now: OffsetDateTime,
) -> Response {
    let Some(session) = account::admitted(&context.account, headers, now).await else {
        return begin(
            &context.account,
            FirstPartyDestination::AccountIdJagConsent,
            now,
        )
        .await;
    };
    let Some(form) = parse_form(body) else {
        return render_current(
            context,
            &session,
            now,
            Some("Invalid form."),
            StatusCode::BAD_REQUEST,
        )
        .await;
    };
    if !checked_csrf(&session, CSRF_SEPARATOR, &form.csrf) {
        return render_current(
            context,
            &session,
            now,
            Some("Form expired. Reload and try again."),
            StatusCode::BAD_REQUEST,
        )
        .await;
    }
    if !fresh(&session, now) {
        return begin(
            &context.account,
            FirstPartyDestination::AccountIdJagConsent,
            now,
        )
        .await;
    }

    let result = match form.action.as_str() {
        "grant" => {
            let options = context
                .trusts
                .consent_options(context.account.tenant.id.as_str());
            let permitted = options.iter().any(|option| {
                option.issuer == form.issuer
                    && option.actor_client_id == form.actor_client_id
                    && option.client_id == form.client_id
                    && option.resources.contains(&form.resource)
                    && !form.scopes.is_empty()
                    && form
                        .scopes
                        .iter()
                        .all(|scope| option.scopes.contains(scope))
            });
            if !permitted {
                return render_current(
                    context,
                    &session,
                    now,
                    Some("Authorization is unavailable."),
                    StatusCode::BAD_REQUEST,
                )
                .await;
            }
            context
                .store
                .grant_consent(
                    session.user,
                    &session.id_digest,
                    &form.issuer,
                    &form.actor_client_id,
                    &form.client_id,
                    &form.resource,
                    &form.scopes,
                    now + MAX_CONSENT_LIFETIME,
                    now,
                )
                .await
        }
        "revoke" if form.scopes.is_empty() => {
            context
                .store
                .revoke_consent(
                    session.user,
                    &session.id_digest,
                    &form.issuer,
                    &form.actor_client_id,
                    &form.client_id,
                    &form.resource,
                    now,
                )
                .await
        }
        _ => {
            return render_current(
                context,
                &session,
                now,
                Some("Invalid form."),
                StatusCode::BAD_REQUEST,
            )
            .await;
        }
    };
    match result {
        Ok(true) => {
            render_current(
                context,
                &session,
                now,
                Some("Authorization updated."),
                StatusCode::OK,
            )
            .await
        }
        Ok(false) => {
            render_current(
                context,
                &session,
                now,
                Some("Authorization is unavailable."),
                StatusCode::CONFLICT,
            )
            .await
        }
        Err(error) => {
            tracing::error!(%error, tenant = %context.account.tenant.id, "cannot update ID-JAG consent");
            error_page(&context.account, StatusCode::SERVICE_UNAVAILABLE)
        }
    }
}

struct Form {
    csrf: String,
    action: String,
    issuer: String,
    actor_client_id: String,
    client_id: String,
    resource: String,
    scopes: Vec<String>,
}

fn parse_form(body: &[u8]) -> Option<Form> {
    if body.len() > account::MAX_BODY {
        return None;
    }
    let mut csrf = None;
    let mut action = None;
    let mut issuer = None;
    let mut actor_client_id = None;
    let mut client_id = None;
    let mut resource = None;
    let mut scopes = Vec::new();
    for (key, value) in url::form_urlencoded::parse(body) {
        if value.len() > 2048 {
            return None;
        }
        let target = match key.as_ref() {
            "csrf" => &mut csrf,
            "action" => &mut action,
            "issuer" => &mut issuer,
            "actor_client_id" => &mut actor_client_id,
            "client_id" => &mut client_id,
            "resource" => &mut resource,
            "scope" => {
                if value.is_empty()
                    || scopes.len() == 32
                    || scopes.iter().any(|scope| scope == &value)
                {
                    return None;
                }
                scopes.push(value.into_owned());
                continue;
            }
            _ => return None,
        };
        if target.replace(value.into_owned()).is_some() {
            return None;
        }
    }
    let csrf = csrf?;
    if csrf.is_empty() || csrf.len() > account::MAX_CSRF_CHARS {
        return None;
    }
    Some(Form {
        csrf,
        action: action?,
        issuer: issuer?,
        actor_client_id: actor_client_id?,
        client_id: client_id?,
        resource: resource?,
        scopes,
    })
}

async fn render_current(
    context: &ConsentContext<'_>,
    session: &Session,
    now: OffsetDateTime,
    message: Option<&str>,
    status: StatusCode,
) -> Response {
    let (bound, consents) = match tokio::try_join!(
        context.store.bound_issuers(session.user),
        context.store.consents_for_owner(session.user, now)
    ) {
        Ok(rows) => rows,
        Err(error) => {
            tracing::error!(%error, tenant = %context.account.tenant.id, "cannot read ID-JAG consent");
            return error_page(&context.account, StatusCode::SERVICE_UNAVAILABLE);
        }
    };
    let options = context
        .trusts
        .consent_options(context.account.tenant.id.as_str());
    render(
        context, session, &bound, &consents, &options, message, status,
    )
}

fn render(
    context: &ConsentContext<'_>,
    session: &Session,
    bound: &[String],
    consents: &[IdJagConsent],
    options: &[IdJagConsentOption],
    message: Option<&str>,
    status: StatusCode,
) -> Response {
    let csrf = csrf_for(session, CSRF_SEPARATOR);
    let action = escape_html(&context.account.mount.absolute(PAGE_PATH));
    let mut content = String::new();
    if let Some(message) = message {
        content.push_str(&format!("<p role=\"status\">{}</p>", escape_html(message)));
    }
    content.push_str("<h2>Current approvals</h2>");
    if consents.is_empty() {
        content.push_str("<p>No active approvals.</p>");
    }
    for consent in consents {
        content.push_str(&format!(
            "<section><p>Issuer: <code>{}</code><br>Actor: <code>{}</code><br>Client: <code>{}</code><br>Resource: <code>{}</code><br>Scopes: <code>{}</code><br>Expires: <time>{}</time></p><form method=\"post\" action=\"{action}\">{}<button name=\"action\" value=\"revoke\">Revoke</button></form></section>",
            escape_html(&consent.issuer), escape_html(&consent.actor_client_id),
            escape_html(&consent.client_id), escape_html(&consent.resource),
            escape_html(&consent.scopes.join(" ")), account::stamp(consent.expires_at),
            tuple_fields(&csrf, &consent.issuer, &consent.actor_client_id, &consent.client_id, &consent.resource),
        ));
    }
    content.push_str("<h2>New approval</h2><p>Approvals last at most 30 days. Only issuers linked to your account by an operator appear here.</p>");
    let mut offered = false;
    for option in options
        .iter()
        .filter(|option| bound.contains(&option.issuer))
    {
        for resource in &option.resources {
            offered = true;
            content.push_str(&format!(
                "<form method=\"post\" action=\"{action}\"><p>Issuer: <code>{}</code><br>Actor: <code>{}</code><br>Client: <code>{}</code><br>Resource: <code>{}</code></p>{}",
                escape_html(&option.issuer), escape_html(&option.actor_client_id),
                escape_html(&option.client_id), escape_html(resource),
                tuple_fields(&csrf, &option.issuer, &option.actor_client_id, &option.client_id, resource),
            ));
            for scope in &option.scopes {
                content.push_str(&format!(
                    "<label><input type=\"checkbox\" name=\"scope\" value=\"{}\">{}</label> ",
                    escape_html(scope),
                    escape_html(scope)
                ));
            }
            content.push_str(
                "<button name=\"action\" value=\"grant\">Approve selected scopes</button></form>",
            );
        }
    }
    if !offered {
        content.push_str("<p>No linked, configured issuer is available for approval.</p>");
    }
    let account = escape_html(&context.account.mount.absolute(account::PAGE_PATH));
    let document = Document::render(context.account.nonce, |_nonce| {
        format!(
            "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"referrer\" content=\"no-referrer\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>External identity approvals</title></head><body><main><h1>External identity approvals</h1>{content}<p><a href=\"{account}\">Back to account</a></p></main></body></html>"
        )
    });
    let mut response = (status, no_store(), document).into_response();
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    response
}

fn tuple_fields(csrf: &str, issuer: &str, actor: &str, client: &str, resource: &str) -> String {
    format!(
        "<input type=\"hidden\" name=\"csrf\" value=\"{}\"><input type=\"hidden\" name=\"issuer\" value=\"{}\"><input type=\"hidden\" name=\"actor_client_id\" value=\"{}\"><input type=\"hidden\" name=\"client_id\" value=\"{}\"><input type=\"hidden\" name=\"resource\" value=\"{}\">",
        escape_html(csrf),
        escape_html(issuer),
        escape_html(actor),
        escape_html(client),
        escape_html(resource),
    )
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
