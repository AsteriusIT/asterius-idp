//! Browser-bound OIDC authorization-code transactions for external sign-in.

use crate::outbound::{HttpsPoster, PostRequest, ssrf};
use asterius_domain::ports::{ClientUrlFetcher, InteractionRepository};
use asterius_domain::{DomainError, OpaqueToken, TenantId, sha256_hex};
use asterius_store_pg::{NewOidcPending, PgOidcProviders, PgOidcUpstreamPending};
use asterius_web::interaction::{self, InteractionId, Stage, StoredState};
use axum::http::HeaderMap;
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use sha2::{Digest as _, Sha256};
use time::OffsetDateTime;
use url::Url;

/// Identity resolution is supplied by tenant-scoped account binding. The
/// verifier calls this port only with claims from a checked ID token.
#[async_trait::async_trait]
pub trait UpstreamIdentityResolver: std::fmt::Debug + Send + Sync {
    async fn resolve_or_create(
        &self,
        tenant: &TenantId,
        provider_id: &str,
        exact_issuer: &str,
        verified_subject: &str,
    ) -> Result<Option<uuid::Uuid>, DomainError>;
}

/// Resolves only verified upstream issuer and subject pairs against the
/// tenant's explicit bindings or its first-login creation policy.
#[derive(Debug, Clone)]
pub struct StoreUpstreamIdentityResolver {
    store: asterius_store_pg::Store,
}

impl StoreUpstreamIdentityResolver {
    #[must_use]
    pub const fn new(store: asterius_store_pg::Store) -> Self {
        Self { store }
    }
}

#[async_trait::async_trait]
impl UpstreamIdentityResolver for StoreUpstreamIdentityResolver {
    async fn resolve_or_create(
        &self,
        tenant: &TenantId,
        provider_id: &str,
        exact_issuer: &str,
        verified_subject: &str,
    ) -> Result<Option<uuid::Uuid>, DomainError> {
        match self
            .store
            .scope(tenant.clone())
            .oidc_bindings()
            .resolve_or_create(provider_id, exact_issuer, verified_subject)
            .await?
        {
            asterius_store_pg::OidcResolution::User(user) => Ok(Some(*user.as_uuid())),
            asterius_store_pg::OidcResolution::Refused(_) => Ok(None),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FlowError {
    #[error("upstream sign-in was refused")]
    Refused,
    #[error("upstream sign-in is temporarily unavailable")]
    Unavailable,
}

/// Returns the provider URL only after the browser and current interaction
/// stage are checked and the state/verifier pair is stored durably.
// The caller supplies each boundary explicitly: browser, tenant, stores and clock.
#[allow(clippy::too_many_arguments)]
pub async fn begin(
    provider_id: &str,
    interaction_id: &str,
    headers: &HeaderMap,
    tenant_issuer: &str,
    requests: &dyn InteractionRepository,
    providers: &PgOidcProviders,
    pending: &PgOidcUpstreamPending,
    now: OffsetDateTime,
) -> Result<String, FlowError> {
    let presented = InteractionId::from_presented(interaction_id.to_owned());
    let from_cookie = interaction::id_from_cookie_header(&crate::http::cookies(headers));
    asterius_web::Interaction::resume(&presented, from_cookie.as_ref())
        .map_err(|_| FlowError::Refused)?;
    let record = requests
        .by_interaction(&presented.digest(), now)
        .await
        .map_err(|_| FlowError::Unavailable)?
        .ok_or(FlowError::Refused)?;
    let interaction_stage = StoredState::from_stored(&record.state).stage;
    if !matches!(interaction_stage, Stage::Login | Stage::StepUp) {
        return Err(FlowError::Refused);
    }
    let credential = providers
        .find(provider_id)
        .await
        .map_err(|_| FlowError::Unavailable)?
        .ok_or(FlowError::Refused)?;
    let provider = &credential.provider;
    if !provider.enabled || ssrf::check_url(&provider.authorization_endpoint).is_err() {
        return Err(FlowError::Refused);
    }
    let state = OpaqueToken::generate_bits::<256>();
    let nonce = OpaqueToken::generate_bits::<256>();
    let verifier = OpaqueToken::generate_bits::<256>();
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.expose().as_bytes()));
    let redirect_uri = asterius_admin_api::oidc_providers::callback_url(tenant_issuer, provider_id);
    let mut url = Url::parse(&provider.authorization_endpoint).map_err(|_| FlowError::Refused)?;
    if url.query().is_some() {
        return Err(FlowError::Refused);
    }
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &provider.client_id)
        .append_pair("redirect_uri", &redirect_uri)
        .append_pair("scope", "openid")
        .append_pair("state", state.expose())
        .append_pair("nonce", nonce.expose())
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256");
    pending
        .begin(
            &NewOidcPending {
                state_digest: &sha256_hex(state.expose().as_bytes()),
                interaction_digest: &presented.digest(),
                provider_id,
                issuer: &provider.issuer,
                client_id: &provider.client_id,
                token_endpoint: &provider.token_endpoint,
                jwks_uri: &provider.jwks_uri,
                nonce_digest: &sha256_hex(nonce.expose().as_bytes()),
                code_verifier: verifier.expose(),
            },
            now,
        )
        .await
        .map_err(|_| FlowError::Unavailable)?;
    Ok(url.into())
}

/// Consumes state before any outbound request, verifies the provider's signed
/// ID token, then resolves only its issuer/subject pair.
#[expect(
    clippy::too_many_arguments,
    reason = "The browser and tenant bindings must be explicit at this security boundary"
)]
pub async fn callback(
    provider_id: &str,
    state: &str,
    code: &str,
    response_issuer: Option<&str>,
    headers: &HeaderMap,
    tenant: &TenantId,
    tenant_issuer: &str,
    requests: &dyn InteractionRepository,
    providers: &PgOidcProviders,
    pending: &PgOidcUpstreamPending,
    fetcher: &dyn ClientUrlFetcher,
    resolver: &dyn UpstreamIdentityResolver,
    now: OffsetDateTime,
) -> Result<uuid::Uuid, FlowError> {
    if state.len() > 512 || code.is_empty() || code.len() > 4096 {
        return Err(FlowError::Refused);
    }
    let from_cookie = interaction::id_from_cookie_header(&crate::http::cookies(headers))
        .ok_or(FlowError::Refused)?;
    let transaction = pending
        .consume(
            &sha256_hex(state.as_bytes()),
            &from_cookie.digest(),
            provider_id,
            now,
        )
        .await
        .map_err(|_| FlowError::Unavailable)?
        .ok_or(FlowError::Refused)?;
    let record = requests
        .by_interaction(&from_cookie.digest(), now)
        .await
        .map_err(|_| FlowError::Unavailable)?
        .ok_or(FlowError::Refused)?;
    if !matches!(
        StoredState::from_stored(&record.state).stage,
        Stage::Login | Stage::StepUp
    ) {
        return Err(FlowError::Refused);
    }
    if response_issuer.is_some_and(|issuer| issuer != transaction.issuer) {
        return Err(FlowError::Refused);
    }
    let credential = providers
        .find(provider_id)
        .await
        .map_err(|_| FlowError::Unavailable)?
        .ok_or(FlowError::Refused)?;
    let provider = &credential.provider;
    if !provider.enabled
        || provider.issuer != transaction.issuer
        || provider.client_id != transaction.client_id
        || provider.token_endpoint != transaction.token_endpoint
        || provider.jwks_uri != transaction.jwks_uri
    {
        return Err(FlowError::Refused);
    }
    let redirect_uri = asterius_admin_api::oidc_providers::callback_url(tenant_issuer, provider_id);
    let body = zeroize::Zeroizing::new(
        url::form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "authorization_code")
            .append_pair("code", code)
            .append_pair("redirect_uri", &redirect_uri)
            .append_pair(
                "code_verifier",
                std::str::from_utf8(&transaction.code_verifier).map_err(|_| FlowError::Refused)?,
            )
            .finish(),
    );
    let basic = client_secret_basic(
        &provider.client_id,
        std::str::from_utf8(&credential.client_secret).map_err(|_| FlowError::Refused)?,
    );
    let poster = HttpsPoster::new().map_err(|_| FlowError::Unavailable)?;
    let response = poster
        .post_with_response(
            &transaction.token_endpoint,
            PostRequest::of("application/x-www-form-urlencoded")
                .accepting("application/json")
                .authorized_by(Some(&basic)),
            body.as_bytes(),
        )
        .await
        .map_err(|_| FlowError::Unavailable)?;
    if response.truncated || response.status != 200 {
        return Err(FlowError::Refused);
    }
    let token: serde_json::Value =
        serde_json::from_slice(&response.body).map_err(|_| FlowError::Refused)?;
    let id_token = token
        .get("id_token")
        .and_then(serde_json::Value::as_str)
        .ok_or(FlowError::Refused)?;
    let jwks = fetcher
        .fetch(&transaction.jwks_uri)
        .await
        .map_err(|_| FlowError::Unavailable)?;
    let verified = asterius_jose::upstream_id_token::verify_upstream_id_token(
        id_token,
        &jwks,
        &transaction.issuer,
        &transaction.client_id,
        &transaction.nonce_digest,
        now,
    )
    .map_err(|_| FlowError::Refused)?;
    resolver
        .resolve_or_create(tenant, provider_id, &transaction.issuer, &verified.subject)
        .await
        .map_err(|_| FlowError::Unavailable)?
        .ok_or(FlowError::Refused)
}

/// RFC 6749 §2.3.1 form-encodes both components before Basic framing.
fn client_secret_basic(client_id: &str, client_secret: &str) -> zeroize::Zeroizing<String> {
    fn encode(value: &str) -> zeroize::Zeroizing<String> {
        let encoded = zeroize::Zeroizing::new(
            url::form_urlencoded::Serializer::new(String::new())
                .append_pair("", value)
                .finish(),
        );
        zeroize::Zeroizing::new(encoded[1..].to_owned())
    }
    let id = encode(client_id);
    let secret = encode(client_secret);
    let credential = zeroize::Zeroizing::new(format!("{}:{}", id.as_str(), secret.as_str()));
    zeroize::Zeroizing::new(format!("Basic {}", STANDARD.encode(credential.as_bytes())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_auth_encodes_credentials_before_framing() {
        let header = client_secret_basic("client:id", "s:ecret+&=");
        assert_eq!(&*header, "Basic Y2xpZW50JTNBaWQ6cyUzQWVjcmV0JTJCJTI2JTNE");
    }
}
