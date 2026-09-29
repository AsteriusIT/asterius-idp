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

#[expect(
    clippy::too_many_lines,
    reason = "The consent handler keeps validation and grant or revocation responses together."
)]
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
    let action = context.account.mount.absolute(PAGE_PATH);
    let account = context.account.mount.absolute(account::PAGE_PATH);
    let consents = consents
        .iter()
        .map(|entry| asterius_web::pages::ExternalApprovalLine {
            issuer: entry.issuer.clone(),
            actor: entry.actor_client_id.clone(),
            client: entry.client_id.clone(),
            resource: entry.resource.clone(),
            scopes: entry.scopes.clone(),
            expires: account::stamp(entry.expires_at),
        })
        .collect();
    let options = options
        .iter()
        .filter(|entry| bound.contains(&entry.issuer))
        .flat_map(|entry| {
            entry
                .resources
                .iter()
                .map(|resource| asterius_web::pages::ExternalApprovalLine {
                    issuer: entry.issuer.clone(),
                    actor: entry.actor_client_id.clone(),
                    client: entry.client_id.clone(),
                    resource: resource.clone(),
                    scopes: entry.scopes.clone(),
                    expires: String::new(),
                })
        })
        .collect();
    let font_url = crate::http::font_url(&context.account.mount);
    let presentation = crate::http::ThemeChrome::new(context.account.theme, &context.account.mount);
    let document = Document::render(context.account.nonce, |nonce| {
        asterius_web::pages::render(&asterius_web::pages::AccountExternalApprovalsPage {
            text: context.account.text,
            tenant_name: &context.account.tenant.display_name,
            action: &action,
            account_href: &account,
            csrf: &csrf,
            message,
            consents,
            options,
            nonce_attribute: asterius_web::pages::nonce_attribute(nonce),
            theme_css: &presentation.css,
            brand: presentation.brand(&font_url),
        })
    });
    let mut response = (status, no_store(), document).into_response();
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    response
}
