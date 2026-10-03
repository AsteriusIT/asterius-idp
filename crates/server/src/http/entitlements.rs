//! Ordinary browser-session temporary privilege lifecycle; no API bearer authority.
use super::account::{self, AccountContext};
use asterius_domain::temporary_entitlements::{
    AccountEntitlements, ActivationStatus, CancelRequest, DecideRequest, RequestActivation,
    RequestStatus, RevokeActivation, SessionActor, TemporaryEntitlements,
};
use asterius_domain::{DomainError, FirstPartyDestination, RateLimit, RateLimitStore, UserId};
use asterius_web::{Document, pages};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;
pub const PAGE_PATH: &str = "/account/entitlements";
pub const SIGN_IN_PATH: &str = "/account/entitlements/sign-in";
const SEPARATOR: &str = "temporary-entitlement-account-csrf";
pub struct EntitlementsContext<'a> {
    pub account: AccountContext<'a>,
    pub store: &'a dyn TemporaryEntitlements,
    pub limits: &'a dyn RateLimitStore,
}
impl std::fmt::Debug for EntitlementsContext<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EntitlementsContext")
            .finish_non_exhaustive()
    }
}
#[derive(Debug)]
pub enum Command {
    Request(RequestActivation),
    Decide(DecideRequest),
    Cancel(CancelRequest),
    Revoke(RevokeActivation),
}
// fuzz-target: temporary_entitlement_command
#[must_use]
pub fn parse_command(action: &str, body: &[u8]) -> Option<(String, Command)> {
    if body.len() > account::MAX_BODY {
        return None;
    }
    let raw = std::str::from_utf8(body).ok()?;
    let mut object = serde_json::Map::new();
    for (key, value) in url::form_urlencoded::parse(raw.as_bytes()) {
        let value = if key == "duration_seconds" {
            serde_json::Value::Number(value.parse::<i32>().ok()?.into())
        } else {
            serde_json::Value::String(value.into_owned())
        };
        if object.insert(key.into_owned(), value).is_some() {
            return None;
        }
    }
    let csrf = object.remove("csrf")?.as_str()?.to_owned();
    if csrf.is_empty() || csrf.len() > account::MAX_CSRF_CHARS {
        return None;
    }
    let value = serde_json::Value::Object(object);
    let command = match action {
        "request" => Command::Request(serde_json::from_value(value).ok()?),
        "decide" => Command::Decide(serde_json::from_value(value).ok()?),
        "cancel" => Command::Cancel(serde_json::from_value(value).ok()?),
        "revoke" => Command::Revoke(serde_json::from_value(value).ok()?),
        _ => return None,
    };
    Some((csrf, command))
}
pub async fn page(
    context: &EntitlementsContext<'_>,
    headers: &HeaderMap,
    message: &str,
    now: OffsetDateTime,
) -> Response {
    let Some(session) = account::admitted(&context.account, headers, now).await else {
        return account::begin(
            &context.account,
            FirstPartyDestination::AccountEntitlements,
            now,
        )
        .await;
    };
    let actor = SessionActor {
        user: UserId::new(session.user),
        session_digest: session.id_digest.clone(),
    };
    let Ok(data) = context
        .store
        .account(&context.account.tenant.id, &actor)
        .await
    else {
        // Storage errors may contain user-controlled lifecycle values.
        tracing::error!("cannot read temporary entitlements");
        return account::error_page(&context.account, StatusCode::SERVICE_UNAVAILABLE);
    };
    render(context, &session, &data, message)
}
pub async fn sign_in(context: &EntitlementsContext<'_>, now: OffsetDateTime) -> Response {
    account::begin(
        &context.account,
        FirstPartyDestination::AccountEntitlements,
        now,
    )
    .await
}
pub async fn command(
    context: &EntitlementsContext<'_>,
    action: &str,
    headers: &HeaderMap,
    body: &[u8],
    now: OffsetDateTime,
) -> Response {
    let Some(session) = account::admitted(&context.account, headers, now).await else {
        return account::begin(
            &context.account,
            FirstPartyDestination::AccountEntitlements,
            now,
        )
        .await;
    };
    let Some((csrf, command)) = parse_command(action, body) else {
        return account::error_page(&context.account, StatusCode::BAD_REQUEST);
    };
    if !account::checked_csrf(&session, SEPARATOR, &csrf) {
        return account::error_page(&context.account, StatusCode::FORBIDDEN);
    }
    let limit = RateLimit {
        max: 20,
        window: Duration::minutes(10),
    };
    let bucket =
        asterius_domain::approval_decision_bucket(&format!("entitlement:{}", session.id_digest));
    let allowed = context
        .limits
        .record(
            &context.account.tenant.id,
            &bucket,
            limit.window_start(now),
            limit.window_end(now),
        )
        .await;
    if !allowed.is_ok_and(|count| limit.admits(count.saturating_sub(1))) {
        return account::error_page(&context.account, StatusCode::TOO_MANY_REQUESTS);
    }
    let actor = SessionActor {
        user: UserId::new(session.user),
        session_digest: session.id_digest.clone(),
    };
    let tenant = &context.account.tenant.id;
    let result = match command {
        Command::Request(c) => context.store.request(tenant, &actor, c).await.map(|_| ()),
        Command::Decide(c) => context.store.decide(tenant, &actor, c).await.map(|_| ()),
        Command::Cancel(c) => context.store.cancel(tenant, &actor, c).await.map(|_| ()),
        Command::Revoke(c) => context.store.revoke(tenant, &actor, c).await.map(|_| ()),
    };
    match result {
        Ok(())=>{
            let target=context.account.mount.absolute(PAGE_PATH);
            match super::redirect::SeeOther::to(&target){Ok(redirect)=>(account::no_store(),redirect).into_response(),Err(_)=>account::error_page(&context.account,StatusCode::INTERNAL_SERVER_ERROR)}
        },
        Err(DomainError::Invalid{field:"authentication",..})=>page(context,headers,if context.account.text.lang()=="fr"{"Authentifiez-vous à nouveau avec le niveau de preuve configuré, puis réessayez. Aucun accès n’a été accordé."}else{"Sign in again with the configured assurance, then retry. No access was granted."},now).await,
        Err(DomainError::NotFound|DomainError::Conflict(_))=>account::error_page(&context.account,StatusCode::NOT_FOUND),
        Err(DomainError::Invalid{..})=>account::error_page(&context.account,StatusCode::BAD_REQUEST),
        Err(_)=>{tracing::error!("temporary entitlement command refused");account::error_page(&context.account,StatusCode::SERVICE_UNAVAILABLE)},
    }
}
fn render(
    context: &EntitlementsContext<'_>,
    session: &asterius_domain::Session,
    data: &AccountEntitlements,
    message: &str,
) -> Response {
    let account = &context.account;
    let page_href = account.mount.absolute(PAGE_PATH);
    let account_href = account.mount.absolute(account::PAGE_PATH);
    let sign_in_href = account.mount.absolute(SIGN_IN_PATH);
    let csrf = account::csrf_for(session, SEPARATOR);
    let font_url = super::font_url(&account.mount);
    let chrome = super::ThemeChrome::new(account.theme, &account.mount);
    let french = account.text.lang() == "fr";
    let choose = |fr, en| if french { fr } else { en };
    let eligible = data
        .eligibilities
        .iter()
        .filter(|el| {
            el.user_id == session.user
                && el.revoked_at.is_none()
                && el.not_before <= data.observed_at
                && data.observed_at < el.expires_at
        })
        .filter_map(|el| {
            data.entitlements
                .iter()
                .find(|e| e.entitlement_id == el.entitlement_id && e.configuration.enabled)
                .map(|e| pages::TemporaryEligibilityLine {
                    entitlement: e.clone(),
                    expires_at: timestamp(el.expires_at),
                    idempotency_key: Uuid::new_v4().to_string(),
                })
        })
        .collect();
    let requests = data
        .requests
        .iter()
        .map(|r| pages::TemporaryRequestLine {
            request: r.clone(),
            deadline: timestamp(r.deadline),
            own: r.requester_user_id == session.user,
            pending: r.status == RequestStatus::Pending && data.observed_at < r.deadline,
            idempotency_key: Uuid::new_v4().to_string(),
        })
        .collect();
    let activations = data
        .activations
        .iter()
        .map(|a| pages::TemporaryActivationLine {
            activation: a.clone(),
            expires_at: timestamp(a.expires_at),
            status: if a.status == ActivationStatus::Revoked {
                choose("Révoqué", "Revoked")
            } else if a.status == ActivationStatus::Expired {
                choose("Expiré", "Expired")
            } else if a.status == ActivationStatus::Invalidated {
                choose("Périmètre invalidé", "Scope invalidated")
            } else {
                choose(
                    "Éligibilité vérifiée à chaque utilisation",
                    "Eligibility checked at every use",
                )
            },
            idempotency_key: Uuid::new_v4().to_string(),
        })
        .collect();
    let document = Document::render(account.nonce, |nonce| {
        pages::render(&pages::AccountEntitlementsPage {
            text: account.text,
            tenant_name: &account.tenant.display_name,
            account_href: &account_href,
            page_href: &page_href,
            sign_in_href: &sign_in_href,
            csrf: &csrf,
            title: choose("Accès temporaire", "Temporary access"),
            introduction: choose(
                "Une demande n’accorde aucun rôle. Une personne indépendante doit approuver le périmètre exact. L’expiration est définitive ; les jetons déjà émis restent valables jusqu’à leur expiration bornée.",
                "A request grants no role. An independent person must approve its exact scope. Expiry is final; existing tokens remain valid until their capped expiry.",
            ),
            message,
            request_label: choose("Demander une activation", "Request activation"),
            requests_label: choose("Demandes et décisions", "Requests and decisions"),
            activations_label: choose("Activations", "Activations"),
            reason_label: choose("Motif", "Reason"),
            duration_label: choose("Durée en secondes", "Duration in seconds"),
            requester_label: choose("Demandeur", "Requester"),
            deadline_label: choose("Décision avant", "Decide before"),
            approve_label: choose("Approuver", "Approve"),
            deny_label: choose("Refuser", "Deny"),
            cancel_label: choose("Annuler", "Cancel"),
            revoke_label: choose("Révoquer", "Revoke"),
            sign_in_label: choose("S’authentifier à nouveau", "Sign in again"),
            eligible,
            requests,
            activations,
            nonce_attribute: pages::nonce_attribute(nonce),
            theme_css: &chrome.css,
            brand: chrome.brand(&font_url),
        })
    });
    (account::no_store(), document).into_response()
}
fn timestamp(seconds: i64) -> String {
    OffsetDateTime::from_unix_timestamp(seconds)
        .map(account::stamp)
        .unwrap_or_default()
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_pollution_claims_and_unknown_decisions() {
        let key = Uuid::new_v4();
        let request = Uuid::new_v4();
        let form = format!("csrf=x&request_id={request}&idempotency_key={key}&decision=approve");
        assert!(parse_command("decide", form.as_bytes()).is_some());
        for extra in ["&decision=deny", "&acr=passkey", "&actor=other"] {
            assert!(parse_command("decide", format!("{form}{extra}").as_bytes()).is_none());
        }
        assert!(parse_command("decide", form.replace("approve", "maybe").as_bytes()).is_none());
        assert!(parse_command("revoke", form.as_bytes()).is_none());
    }
}
