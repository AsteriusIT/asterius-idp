//! OID4VP verifier transport with authenticated initiation and durable replay.

use crate::http::protocol::ClientEndpoints;
use asterius_domain::audit::{Actor, AuditEvent, Detail, EventType, Outcome};
use asterius_domain::{Client, ClientId, Tenant};
use asterius_oidc::client_auth::{AssertionRules, Attempt};
use asterius_oidc::form::Parameters;
use asterius_oidc::oid4vp::{PendingPresentation, extract_direct_post, prepare};
use axum::body::Bytes;
use axum::extract::{Extension, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde_json::{Value, json};
use std::sync::Arc;
use time::OffsetDateTime;

const MAX_FORM_BYTES: usize = 65_536;

/// Mounts OID4VP routes under the resolved tenant's path prefix.
pub fn routes(endpoints: Arc<ClientEndpoints>) -> Router {
    Router::new()
        .route("/oid4vp/request", post(request))
        .route("/oid4vp/response", post(response))
        .route("/oid4vp/result", post(result))
        .with_state(endpoints)
}

async fn request(
    State(endpoints): State<Arc<ClientEndpoints>>,
    Extension(tenant): Extension<Arc<Tenant>>,
    certificate: Option<Extension<Arc<crate::mtls::PresentedCertificate>>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Ok(form) = parse_form(&headers, &body) else {
        return refused(StatusCode::BAD_REQUEST);
    };
    let now = OffsetDateTime::now_utc();
    let certificate = certificate.as_deref().map(|presented| &presented.leaf);
    let Ok(client) = authenticate(&endpoints, &tenant, &headers, &form, certificate, now).await
    else {
        return refused(StatusCode::UNAUTHORIZED);
    };
    let Ok(Some(verifier_id)) = form.get("verifier_id") else {
        return refused(StatusCode::BAD_REQUEST);
    };
    let Some(verifier) = endpoints
        .oid4vp_verifiers
        .find(tenant.id.as_str(), verifier_id)
        .filter(|verifier| verifier.initiator_client_id == client.id.as_str())
    else {
        return refused(StatusCode::NOT_FOUND);
    };
    let Ok(prepared) = prepare(&verifier.query) else {
        tracing::error!(tenant = %tenant.id, verifier = verifier_id, "invalid configured OID4VP request");
        return refused(StatusCode::SERVICE_UNAVAILABLE);
    };
    let transactions = transactions(&endpoints, &tenant);
    if let Err(error) = transactions
        .save(
            &asterius_store_pg::NewOid4vpTransaction {
                state: &prepared.pending.state,
                nonce: &prepared.pending.nonce,
                client_id: &prepared.pending.client_id,
                initiator_client_id: client.id.as_str(),
                credential_id: &prepared.pending.credential_id,
                verifier_id,
            },
            now,
        )
        .await
    {
        tracing::error!(%error, tenant = %tenant.id, "cannot save OID4VP transaction");
        return refused(StatusCode::SERVICE_UNAVAILABLE);
    }
    let Some(uri) = authorization_uri(&prepared.parameters) else {
        return refused(StatusCode::SERVICE_UNAVAILABLE);
    };
    respond(
        StatusCode::OK,
        json!({
            "authorization_uri": uri,
            "state": prepared.pending.state,
            "expires_in": asterius_store_pg::OID4VP_TRANSACTION_LIFETIME.whole_seconds()
        }),
    )
}

async fn response(
    State(endpoints): State<Arc<ClientEndpoints>>,
    Extension(tenant): Extension<Arc<Tenant>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Ok(form) = parse_form(&headers, &body) else {
        return refused(StatusCode::BAD_REQUEST);
    };
    let Ok(Some(state)) = form.get("state") else {
        return refused(StatusCode::BAD_REQUEST);
    };
    let now = OffsetDateTime::now_utc();
    let transactions = transactions(&endpoints, &tenant);
    let transaction = match transactions.consume(state, now).await {
        Ok(Some(transaction)) => transaction,
        Ok(None) => return refused(StatusCode::BAD_REQUEST),
        Err(error) => {
            tracing::error!(%error, tenant = %tenant.id, "cannot consume OID4VP transaction");
            return refused(StatusCode::SERVICE_UNAVAILABLE);
        }
    };
    let Some(verifier) = endpoints
        .oid4vp_verifiers
        .find(tenant.id.as_str(), &transaction.verifier_id)
        .filter(|verifier| {
            verifier.initiator_client_id == transaction.initiator_client_id
                && verifier.query.client_id == transaction.client_id
                && verifier.query.credential_id == transaction.credential_id
        })
    else {
        return refused(StatusCode::BAD_REQUEST);
    };
    let pending = PendingPresentation {
        state: state.to_owned(),
        nonce: transaction.nonce.clone(),
        client_id: transaction.client_id,
        credential_id: transaction.credential_id,
    };
    let verified = extract_direct_post(&pending, &form).and_then(|offered| {
        asterius_jose::oid4vp::verify_jwt_vc_json(
            &offered.vp_jwt,
            &verifier.policy(transaction.nonce),
            now,
        )
        .map_err(|_| asterius_oidc::oid4vp::Oid4vpError::Response("presentation was refused"))
    });
    let outcome = if verified.is_ok() {
        Outcome::Success
    } else {
        Outcome::Failure
    };
    let mut event = AuditEvent::new(
        tenant.id.clone(),
        EventType::OID4VP_PRESENTED,
        outcome,
        Actor::Client(ClientId::new(transaction.initiator_client_id.clone())),
        now,
    )
    .detail(Detail::new().text("verifier_id", &transaction.verifier_id));
    if let Ok(presentation) = &verified {
        event = event.subject(presentation.holder.clone());
    }
    if let Err(error) = endpoints.audit.record(event).await {
        tracing::error!(%error, tenant = %tenant.id, "OID4VP audit write failed");
        return refused(StatusCode::SERVICE_UNAVAILABLE);
    }
    let Ok(verified) = verified else {
        return refused(StatusCode::BAD_REQUEST);
    };
    let claims = Value::Array(verified.disclosed_claims);
    match transactions
        .record_verified(
            state,
            &verified.holder,
            &verified.credential_issuer,
            &claims,
            now,
        )
        .await
    {
        Ok(true) => respond(StatusCode::OK, json!({})),
        Ok(false) => refused(StatusCode::BAD_REQUEST),
        Err(error) => {
            tracing::error!(%error, tenant = %tenant.id, "cannot store verified OID4VP result");
            refused(StatusCode::SERVICE_UNAVAILABLE)
        }
    }
}

async fn result(
    State(endpoints): State<Arc<ClientEndpoints>>,
    Extension(tenant): Extension<Arc<Tenant>>,
    certificate: Option<Extension<Arc<crate::mtls::PresentedCertificate>>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Ok(form) = parse_form(&headers, &body) else {
        return refused(StatusCode::BAD_REQUEST);
    };
    let now = OffsetDateTime::now_utc();
    let certificate = certificate.as_deref().map(|presented| &presented.leaf);
    let Ok(client) = authenticate(&endpoints, &tenant, &headers, &form, certificate, now).await
    else {
        return refused(StatusCode::UNAUTHORIZED);
    };
    let (Ok(Some(verifier_id)), Ok(Some(state))) = (form.get("verifier_id"), form.get("state"))
    else {
        return refused(StatusCode::BAD_REQUEST);
    };
    if endpoints
        .oid4vp_verifiers
        .find(tenant.id.as_str(), verifier_id)
        .is_none_or(|verifier| verifier.initiator_client_id != client.id.as_str())
    {
        return refused(StatusCode::NOT_FOUND);
    }
    match transactions(&endpoints, &tenant)
        .verified_result(state, client.id.as_str(), verifier_id, now)
        .await
    {
        Ok(Some(value)) => respond(StatusCode::OK, value),
        Ok(None) => respond(StatusCode::ACCEPTED, json!({"status": "pending"})),
        Err(error) => {
            tracing::error!(%error, tenant = %tenant.id, "cannot read OID4VP result");
            refused(StatusCode::SERVICE_UNAVAILABLE)
        }
    }
}

fn parse_form(headers: &HeaderMap, body: &[u8]) -> Result<Parameters, ()> {
    if body.len() > MAX_FORM_BYTES
        || headers
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_none_or(|value| !value.starts_with("application/x-www-form-urlencoded"))
    {
        return Err(());
    }
    Ok(Parameters::from_pairs(
        url::form_urlencoded::parse(body)
            .map(|(key, value)| (key.into_owned(), value.into_owned())),
    ))
}

async fn authenticate(
    endpoints: &ClientEndpoints,
    tenant: &Tenant,
    headers: &HeaderMap,
    form: &Parameters,
    certificate: Option<&asterius_oidc::mtls::ClientCertificate>,
    now: OffsetDateTime,
) -> Result<Client, ()> {
    let attempt = Attempt {
        assertion: form.get("client_assertion").map_err(|_| ())?,
        assertion_type: form.get("client_assertion_type").map_err(|_| ())?,
        client_id: form.get("client_id").map_err(|_| ())?,
        authorization_header: headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok()),
        certificate,
    };
    let scope = endpoints.store.scope(tenant.id.clone());
    let clients = scope.clients(endpoints.capabilities);
    endpoints
        .authenticator
        .authenticate(
            tenant,
            &clients,
            &attempt,
            &AssertionRules::for_issuer(tenant.issuer.as_str()),
            now,
        )
        .await
        .map_err(|_| ())
}

fn authorization_uri(parameters: &Value) -> Option<String> {
    let object = parameters.as_object()?;
    let mut uri = url::Url::parse("openid4vp:").ok()?;
    {
        let mut query = uri.query_pairs_mut();
        for (name, value) in object {
            let rendered = value
                .as_str()
                .map_or_else(|| value.to_string(), str::to_owned);
            query.append_pair(name, &rendered);
        }
    }
    Some(uri.to_string())
}

fn transactions(
    endpoints: &ClientEndpoints,
    tenant: &Tenant,
) -> asterius_store_pg::PgOid4vpTransactions {
    asterius_store_pg::PgOid4vpTransactions::new(endpoints.store.pool().clone(), tenant.id.clone())
}

fn refused(status: StatusCode) -> Response {
    respond(status, json!({"error": "invalid_request"}))
}

fn respond(status: StatusCode, value: Value) -> Response {
    (
        status,
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        Json(value),
    )
        .into_response()
}
