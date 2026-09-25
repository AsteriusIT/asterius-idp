//! Tenant-scoped OpenID4VCI 1.0 identity credential endpoints.
//!
//! OAuth authorization-code issuance remains the existing `/authorize` and
//! `/token` flow. A wallet must obtain a token scoped for the configured
//! credential and audienced at this tenant's `/credential` resource. Here the
//! token is checked again against the live grant and account before any VC is
//! signed. The wallet key proof and nonce are independent of the OAuth DPoP
//! key: the former binds the VC holder, the latter binds the access token.

use crate::http::{access_token, dpop};
use asterius_domain::audit::{Actor, AuditEvent, AuditSink, Detail, EventType, Outcome};
use asterius_domain::entities::grant::GrantStatus;
use asterius_domain::keys::{KeyStore, Signer, SigningAlgorithm};
use asterius_domain::{ClientId, CredentialConfiguration, DomainError, GrantId, Tenant};
use asterius_oidc::oid4vci::{self, CredentialRequest, CredentialRequestError};
use asterius_oidc::userinfo;
use asterius_store_pg::{PgGrantRepository, PgOid4vciNonces, PgUserRepository};
use axum::http::{HeaderMap, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::json;
use time::OffsetDateTime;

/// Paths mounted only for tenants that opted in to this identity credential.
pub const CREDENTIAL_PATH: &str = "/credential";
/// The public nonce endpoint from OpenID4VCI §7.
pub const NONCE_PATH: &str = "/nonce";
/// A hostable JSON Credential Offer for the authorization-code flow.
pub const OFFER_PATH: &str = "/credential-offer";
/// The well-known metadata path after tenant routing.
pub const METADATA_PATH: &str = "/.well-known/openid-credential-issuer";

/// The narrow set of live rows and cryptographic services issuance needs.
#[derive(Debug)]
pub struct IssueContext<'a> {
    pub tenant: &'a Tenant,
    pub configuration: &'a CredentialConfiguration,
    pub grants: &'a PgGrantRepository,
    pub users: &'a PgUserRepository,
    pub nonces: &'a PgOid4vciNonces,
    pub keys: &'a dyn KeyStore,
    pub signer: &'a dyn Signer,
    pub audit: &'a dyn AuditSink,
    pub dpop: &'a dpop::DpopEndpoint,
    pub certificate: Option<&'a asterius_oidc::mtls::ClientCertificate>,
    pub now: OffsetDateTime,
}

/// Returns metadata only for a tenant whose policy enables live issuance.
#[must_use]
pub fn metadata(tenant: &Tenant, configuration: &CredentialConfiguration) -> Response {
    (
        StatusCode::OK,
        axum::Json(oid4vci::issuer_metadata(&tenant.issuer, configuration)),
    )
        .into_response()
}

/// A direct offer contains no authorization code or personal data.
#[must_use]
pub fn offer(tenant: &Tenant, configuration: &CredentialConfiguration) -> Response {
    no_store(
        (
            StatusCode::OK,
            axum::Json(oid4vci::authorization_code_offer(
                &tenant.issuer,
                configuration,
            )),
        )
            .into_response(),
    )
}

/// Issues a public challenge, bounded by the caller's address at the router.
pub async fn nonce(nonces: &PgOid4vciNonces, now: OffsetDateTime) -> Response {
    match nonces.issue(now).await {
        Ok(nonce) => {
            no_store((StatusCode::OK, axum::Json(json!({"c_nonce": nonce}))).into_response())
        }
        Err(error) => {
            tracing::error!(%error, "cannot issue OID4VCI nonce");
            unavailable()
        }
    }
}

/// Validates token, live grant, account, request and one-time wallet proof;
/// then signs and audits one identity VC.
pub async fn credential(
    context: IssueContext<'_>,
    method: &Method,
    headers: &HeaderMap,
    query: Option<&str>,
    body: &[u8],
) -> Response {
    match issue(&context, method, headers, query, body).await {
        Ok(jwt) => no_store(
            (
                StatusCode::OK,
                axum::Json(json!({
                    "credentials": [{"credential": jwt}]
                })),
            )
                .into_response(),
        ),
        Err(Refused::Client(status, code)) => error(status, code),
        Err(Refused::Dpop(refusal)) => dpop_challenge(&refusal),
        Err(Refused::Server(error)) => {
            tracing::error!(%error, tenant = %context.tenant.id, "OID4VCI issuance unavailable");
            unavailable()
        }
    }
}

enum Refused {
    Client(StatusCode, &'static str),
    Dpop(dpop::Refusal),
    Server(DomainError),
}

impl From<DomainError> for Refused {
    fn from(error: DomainError) -> Self {
        Self::Server(error)
    }
}

fn invalid_token() -> Refused {
    Refused::Client(StatusCode::UNAUTHORIZED, "invalid_token")
}

fn carries_scope(verified: &asterius_jose::verify::Verified, wanted: &str) -> bool {
    verified
        .claim_str("scope")
        .unwrap_or_default()
        .split(' ')
        .any(|scope| scope == wanted)
}

struct AuthorizedSubject {
    client: ClientId,
    grant: GrantId,
    subject: asterius_domain::SubjectId,
    user: asterius_domain::User,
}

async fn authenticate(
    context: &IssueContext<'_>,
    method: &Method,
    headers: &HeaderMap,
    query: Option<&str>,
) -> Result<asterius_jose::verify::Verified, Refused> {
    let offered = headers.get_all(header::AUTHORIZATION).iter().count();
    let authorization = headers
        .get_all(header::AUTHORIZATION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect::<Vec<_>>();
    if offered != authorization.len() {
        return Err(invalid_token());
    }
    let presented = userinfo::present(&authorization, query).map_err(|_| invalid_token())?;
    let credential_url = format!("{}{}", context.tenant.issuer.as_str(), CREDENTIAL_PATH);
    let verified = access_token::verify_for_audience(
        context.tenant,
        context.keys,
        presented.token(),
        &credential_url,
        context.now,
    )
    .await
    .map_err(|failure| match failure {
        access_token::Rejected::Token(_) => invalid_token(),
        access_token::Rejected::Unavailable(error) => Refused::Server(error),
    })?;
    access_token::check_sender_constraint(
        &access_token::Presented {
            tenant: context.tenant,
            dpop: context.dpop,
            target: dpop::ProofTarget::at_path(CREDENTIAL_PATH),
            certificate: context.certificate,
            method,
            headers,
            presented,
            now: context.now,
        },
        &verified,
    )
    .await
    .map_err(|failure| match failure {
        access_token::NotBound::Refused => invalid_token(),
        access_token::NotBound::Dpop(refusal) => Refused::Dpop(refusal),
    })?;

    Ok(verified)
}

async fn authorized_subject(
    context: &IssueContext<'_>,
    verified: &asterius_jose::verify::Verified,
) -> Result<AuthorizedSubject, Refused> {
    let jti = verified.claim_str("jti").ok_or_else(invalid_token)?;
    if context.grants.is_denylisted(jti).await? {
        return Err(invalid_token());
    }
    let client = verified.claim_str("client_id").ok_or_else(invalid_token)?;
    let grant_id = verified.claim_str("grant_id").ok_or_else(invalid_token)?;
    let client_id = ClientId::new(client.to_owned());
    let grant_id = GrantId::new(grant_id.to_owned());
    let cutoff = context
        .grants
        .revoked_before(&client_id, Some(&grant_id))
        .await?;
    if access_token::withdrawn(&verified, cutoff) {
        return Err(invalid_token());
    }
    if !carries_scope(verified, context.configuration.scope())
        || (context.configuration.claims().contains("email") && !carries_scope(verified, "email"))
    {
        return Err(Refused::Client(StatusCode::FORBIDDEN, "insufficient_scope"));
    }
    let grant = context
        .grants
        .find(&grant_id)
        .await?
        .ok_or_else(invalid_token)?;
    if grant.client != client_id
        || !matches!(grant.status(context.now), GrantStatus::Active)
        || !grant.scopes.contains(context.configuration.scope())
        || grant
            .subject
            .as_ref()
            .map(asterius_domain::SubjectId::as_str)
            != verified.claim_str("sub")
    {
        return Err(invalid_token());
    }
    if context.configuration.claims().contains("email") && !grant.scopes.contains("email") {
        return Err(Refused::Client(StatusCode::FORBIDDEN, "insufficient_scope"));
    }
    let user_id = grant.user.ok_or_else(invalid_token)?;
    let user = context
        .users
        .find(user_id)
        .await?
        .ok_or_else(invalid_token)?;
    if user.tenant != context.tenant.id || !user.can_authenticate() {
        return Err(invalid_token());
    }
    let subject = grant.subject.ok_or_else(invalid_token)?;
    Ok(AuthorizedSubject {
        client: client_id,
        grant: grant_id,
        subject,
        user,
    })
}

async fn issue(
    context: &IssueContext<'_>,
    method: &Method,
    headers: &HeaderMap,
    query: Option<&str>,
    body: &[u8],
) -> Result<String, Refused> {
    let verified = authenticate(context, method, headers, query).await?;
    let authorized = authorized_subject(context, &verified).await?;
    let request =
        CredentialRequest::parse(body, context.configuration).map_err(|error| match error {
            CredentialRequestError::Invalid => {
                Refused::Client(StatusCode::BAD_REQUEST, "invalid_credential_request")
            }
            CredentialRequestError::UnsupportedConfiguration => {
                Refused::Client(StatusCode::BAD_REQUEST, "unknown_credential_configuration")
            }
        })?;
    let proof = asterius_jose::oid4vci_proof::verify(
        request.proof(),
        &context.tenant.issuer,
        authorized.client.as_str(),
        context.now,
    )
    .map_err(|_| Refused::Client(StatusCode::BAD_REQUEST, "invalid_proof"))?;
    let claims = oid4vci::credential_claims(
        &context.tenant.issuer,
        context.configuration,
        authorized.subject.as_str(),
        &authorized.user,
        &proof.public_jwk,
        context.now,
    )
    .map_err(|_| Refused::Client(StatusCode::BAD_REQUEST, "credential_request_denied"))?;
    if !context.nonces.consume(&proof.nonce, context.now).await? {
        return Err(Refused::Client(StatusCode::BAD_REQUEST, "invalid_nonce"));
    }
    let jwt = context
        .signer
        .sign(
            &context.tenant.id,
            Some(SigningAlgorithm::EdDsa),
            "JWT",
            &claims,
        )
        .await?;
    context
        .audit
        .record(
            AuditEvent::new(
                context.tenant.id.clone(),
                EventType::VC_ISSUED,
                Outcome::Success,
                Actor::Client(authorized.client.clone()),
                context.now,
            )
            .client(authorized.client)
            .subject(authorized.subject.as_str())
            .grant(authorized.grant)
            .detail(
                Detail::new()
                    .label("format", oid4vci::FORMAT)
                    .text("configuration", context.configuration.id()),
            ),
        )
        .await?;
    Ok(jwt.as_str().to_owned())
}

fn error(status: StatusCode, code: &'static str) -> Response {
    let mut response = (status, axum::Json(json!({"error": code}))).into_response();
    if matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) {
        let algs = SigningAlgorithm::ALL
            .iter()
            .copied()
            .map(SigningAlgorithm::as_str)
            .collect::<Vec<_>>()
            .join(" ");
        for challenge in [
            format!("DPoP algs=\"{algs}\" error=\"{code}\""),
            format!("Bearer error=\"{code}\""),
        ] {
            if let Ok(value) = axum::http::HeaderValue::from_str(&challenge) {
                response
                    .headers_mut()
                    .append(header::WWW_AUTHENTICATE, value);
            }
        }
    }
    no_store(response)
}

fn dpop_challenge(refusal: &dpop::Refusal) -> Response {
    if refusal.status().is_server_error() {
        return unavailable();
    }
    let mut response = StatusCode::UNAUTHORIZED.into_response();
    if let Ok(value) =
        axum::http::HeaderValue::from_str(&format!("DPoP error=\"{}\"", refusal.code()))
    {
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, value);
    }
    if refusal.code() == dpop::USE_NONCE
        && let Some(nonce) = refusal.nonce()
        && let Ok(value) = axum::http::HeaderValue::from_str(nonce)
    {
        response.headers_mut().insert(dpop::NONCE_HEADER, value);
    }
    no_store(response)
}

fn unavailable() -> Response {
    error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable")
}

fn no_store(mut response: Response) -> Response {
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    response.headers_mut().insert(
        header::PRAGMA,
        axum::http::HeaderValue::from_static("no-cache"),
    );
    response
}
