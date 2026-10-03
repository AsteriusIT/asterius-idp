//! Candidate primary-database online authentication service.
use std::sync::Arc;

use asterius_domain::kubernetes_online::{KubernetesOnline, OnlineProfile, ProfileChange,
    TokenReviewRequest, TokenReviewResponse};
use asterius_domain::{Actor, ClientId, DomainError, SigningAlgorithm, Tenant, TenantId};
use asterius_jose::verify::{Policy, TypRule};
use asterius_store_pg::kubernetes_online::PgKubernetesOnline;
use serde_json::json;
use time::OffsetDateTime;

#[derive(Debug)]
pub struct OnlineAuthentication {
    profiles: PgKubernetesOnline,
}

impl OnlineAuthentication {
    #[must_use]
    pub fn new(profiles: PgKubernetesOnline) -> Arc<Self> {
        Arc::new(Self {profiles})
    }

    async fn review_current(&self, tenant: &Tenant, reviewer: &ClientId,
        client: &ClientId, request: &TokenReviewRequest) -> Result<TokenReviewResponse,DomainError> {
        if request.require_route_audience(client.as_str()).is_err() {
            return Ok(TokenReviewResponse::denied());
        }
        let compact = request.credential().expose();
        let Ok(parsed) = asterius_jose::jws::parse(compact) else {
            return Ok(TokenReviewResponse::denied());
        };
        let Some(kid) = parsed.kid() else { return Ok(TokenReviewResponse::denied()); };
        let mut read = self.profiles.begin_review().await?;
        let Some(key) = read.public_key(&tenant.id,kid.as_str()).await? else {
            return Ok(TokenReviewResponse::denied());
        };
        let Ok(resolver) = asterius_jose::keys_from_jwk_set(&json!({"keys":[key]})) else {
            return Ok(TokenReviewResponse::denied());
        };
        let now = OffsetDateTime::now_utc();
        let policy = Policy::new(TypRule::Exactly("JWT"),vec![SigningAlgorithm::Es256])
            .issued_by(tenant.issuer.as_str()).for_audience(client.as_str());
        let Ok(verified) = asterius_jose::verify::verify(compact,&policy,&resolver,now) else {
            return Ok(TokenReviewResponse::denied());
        };
        let issued = verified.claims.get("iat").and_then(serde_json::Value::as_i64);
        let expiry = verified.claims.get("exp").and_then(serde_json::Value::as_i64);
        let (Some(issued),Some(expiry)) = (issued,expiry) else {
            return Ok(TokenReviewResponse::denied());
        };
        if expiry<=issued || expiry.saturating_sub(issued)>300 || issued>now.unix_timestamp().saturating_add(30)
            || expiry<=now.unix_timestamp() || now.unix_timestamp().saturating_sub(issued)>300 {
            return Ok(TokenReviewResponse::denied());
        }
        let identity = read.review(&tenant.id,reviewer,client,compact,&verified.claims).await?;
        read.commit().await?;
        let Some(identity) = identity else { return Ok(TokenReviewResponse::denied()); };
        TokenReviewResponse::released(request,client.as_str(),identity.username,identity.groups)
    }
}

#[async_trait::async_trait]
impl KubernetesOnline for OnlineAuthentication {
    async fn profile(&self, tenant: &TenantId, client: &ClientId)
        -> Result<Option<OnlineProfile>, DomainError> {
        self.profiles.profile(tenant,client).await
    }
    async fn replace_profile(&self, tenant: &TenantId, client: &ClientId,
        actor: &Actor, change: &ProfileChange) -> Result<OnlineProfile,DomainError> {
        self.profiles.replace_profile(tenant,client,actor,change).await
    }
    async fn review(&self, tenant: &Tenant, reviewer: &ClientId, client: &ClientId,
        request: &TokenReviewRequest) -> Result<TokenReviewResponse,DomainError> {
        // Database failures, timeout or unavailable key material never release
        // a cached positive result or fall back to the offline authenticator.
        match tokio::time::timeout(std::time::Duration::from_secs(3),
            self.review_current(tenant,reviewer,client,request)).await {
            Ok(Ok(response)) => Ok(response),
            _ => Ok(TokenReviewResponse::denied()),
        }
    }
}
