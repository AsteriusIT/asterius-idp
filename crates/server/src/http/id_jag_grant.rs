//! Pinned ID-JAG redemption for the RFC 7523 JWT bearer grant profile.
//!
//! The token endpoint does not dispatch this profile yet. A deployment-wide
//! grant advertisement needs a tenant-aware readiness gate and client
//! registration support before this method may be called. Keeping the issuer
//! below dispatch prevents an upstream assertion from acquiring authority by
//! merely selecting its own issuer or actor.

use std::collections::BTreeSet;

use asterius_domain::audit::trail::{self, keys};
use asterius_domain::audit::{Actor, AuditEvent, Detail, EventType, Outcome};
use asterius_domain::entities::agent::AgentLimits;
use asterius_domain::entities::client::{GrantType, SubjectType, TokenBinding};
use asterius_domain::keys::Signer;
use asterius_domain::{Client, DomainError, Grant, SectorIdentifier, Tenant, User};
use asterius_oidc::form::Parameters;
use asterius_oidc::tokens::JwtId;
use asterius_oidc::tokens::access::AccessToken;
use asterius_store_pg::{PgIdJagRedemption, PgUserRepository};
use axum::Json;
use axum::response::{IntoResponse, Response};
use serde_json::json;
use time::{Duration, OffsetDateTime};

use super::agent_issuance::AgentPolicy;
use super::issuance::{self, ImplicitResources, SenderConstraint};
use super::token::GrantHandler;
use super::token::{not_issued, refused};

const INVALID: &str = "the ID-JAG assertion cannot be redeemed";
const PROFILE: &str = "invalid JWT bearer redemption profile";

/// Dependencies resolved for this authenticated request and tenant.
pub struct IdJagGrant<'a> {
    pub trusts: &'a crate::id_jag_trust::IdJagTrusts,
    pub redemption: &'a PgIdJagRedemption,
    pub users: &'a PgUserRepository,
    pub resource_servers: &'a dyn asterius_domain::ResourceServerRepository,
    pub signer: &'a dyn Signer,
    pub agent_policy: AgentPolicy<'a>,
    pub constraint: SenderConstraint<'a>,
    pub lifetimes: asterius_domain::TokenLifetimes,
    pub grant_id_claim: bool,
    pub now: OffsetDateTime,
}

impl std::fmt::Debug for IdJagGrant<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("IdJagGrant").finish_non_exhaustive()
    }
}

impl IdJagGrant<'_> {
    /// Redeems a JWT bearer assertion already presented by an authenticated
    /// client. No response token escapes until the replay, consent, grant and
    /// audit transaction commits.
    pub async fn redeem(&self, tenant: &Tenant, client: &Client, params: &Parameters) -> Response {
        match self.issue(tenant, client, params).await {
            Ok(response) => response,
            Err(Failure::Client(code, description)) => refused(code, description),
            Err(Failure::Server(error)) => not_issued(tenant, client, &error),
        }
    }

    // Keep this protocol transition together so validation and issuance order stays auditable.
    #[allow(clippy::too_many_lines)]
    async fn issue(
        &self,
        tenant: &Tenant,
        client: &Client,
        params: &Parameters,
    ) -> Result<Response, Failure> {
        // This static profile allowlist belongs with the assertion validator.
        const ALLOWED: [&str; 7] = [
            "grant_type",
            "assertion",
            "scope",
            "resource",
            "client_id",
            "client_assertion_type",
            "client_assertion",
        ];
        if client.registration.token_binding != TokenBinding::Dpop
            || client.registration.subject_type != SubjectType::Pairwise
        {
            return Err(Failure::Client("unauthorized_client", PROFILE));
        }
        let proof = self.constraint.proof_key.ok_or(Failure::Client(
            "invalid_request",
            "a DPoP proof is required",
        ))?;
        let confirmation = self
            .constraint
            .confirmation(client)
            .map_err(|_| Failure::Client("invalid_request", PROFILE))?;
        let one = |name| {
            params
                .get(name)
                .map_err(|_| Failure::Client("invalid_request", PROFILE))
        };
        if params.names().any(|name| !ALLOWED.contains(&name))
            || ALLOWED.iter().any(|name| one(name).is_err())
            || one("grant_type")? != Some("urn:ietf:params:oauth:grant-type:jwt-bearer")
        {
            return Err(Failure::Client("invalid_request", PROFILE));
        }
        let assertion = one("assertion")?
            .filter(|value| !value.is_empty() && value.len() <= 8192)
            .ok_or(Failure::Client("invalid_request", PROFILE))?;
        let requested_scope = one("scope")?;
        let requested_resource = one("resource")?;

        let verified = self
            .trusts
            .verify(
                tenant.id.as_str(),
                client.id.as_str(),
                proof.as_str(),
                assertion,
                self.now,
            )
            .map_err(|_| Failure::Client("invalid_grant", INVALID))?;
        if requested_resource.is_some_and(|value| value != verified.resource)
            || requested_scope.is_some_and(|value| {
                value.split_whitespace().count() != verified.scopes.len()
                    || value.split_whitespace().collect::<BTreeSet<_>>()
                        != verified.scopes.iter().map(String::as_str).collect()
            })
            || !verified.scopes.is_subset(&client.registration.scopes)
            || limits_scopes_refused(client, &verified.scopes)
            || verified.scopes.contains("openid")
            || verified.scopes.contains("offline_access")
        {
            return Err(Failure::Client("invalid_scope", INVALID));
        }
        let limits = client
            .registration
            .agent
            .as_ref()
            .map_or_else(AgentLimits::default, |profile| profile.limits().clone());
        if client.registration.agent.is_some() && limits.max_delegation_depth() < 2 {
            return Err(Failure::Client("access_denied", INVALID));
        }
        if limits
            .audiences()
            .is_some_and(|allowed| !allowed.contains(&verified.resource))
            || client.registration.agent.as_ref().is_some_and(|profile| {
                profile
                    .scope_needing_human_approval(verified.scopes.iter().map(String::as_str))
                    .is_some()
            })
        {
            return Err(Failure::Client("access_denied", INVALID));
        }

        let mapped = self
            .redemption
            .resolve_subject(&verified.issuer, &verified.subject)
            .await?
            .ok_or(Failure::Client("invalid_grant", INVALID))?;
        let user_id = asterius_domain::UserId::new(mapped);
        let user = self
            .users
            .find(user_id)
            .await?
            .filter(User::can_authenticate)
            .ok_or(Failure::Client("invalid_grant", INVALID))?;
        let sector = SectorIdentifier::of_client(client)
            .map_err(|_| Failure::Client("unauthorized_client", PROFILE))?;
        let subject = self.users.subject(user.id, &sector).await?;
        let assertion_exp = OffsetDateTime::from_unix_timestamp(verified.expires_at)
            .map_err(|_| Failure::Client("invalid_grant", INVALID))?;
        let lifetime = client
            .registration
            .agent
            .as_ref()
            .map_or(self.lifetimes, |agent| agent.cap(self.lifetimes))
            .access_token()
            .min(assertion_exp - self.now);
        if lifetime < Duration::seconds(1) {
            return Err(Failure::Client("invalid_grant", INVALID));
        }

        let mut grant = Grant::new(tenant.id.clone(), client.id.clone(), self.now);
        grant.user = Some(user.id);
        grant.subject = Some(subject.clone());
        grant.scopes = verified.scopes.clone();
        grant.resources.insert(verified.resource.clone());
        grant.actor_chain = vec![
            json!({ "client_id": client.id.as_str() }),
            json!({ "iss": verified.issuer, "client_id": verified.actor_client_id }),
        ];
        grant.claimed_at = Some(self.now);
        grant.expires_at = Some(self.now + lifetime);
        let targets = BTreeSet::from([verified.resource.clone()]);
        let targeting = issuance::targeting(
            self.resource_servers,
            tenant,
            client,
            &grant,
            &targets,
            ImplicitResources {
                grant_management: false,
                ssf: false,
            },
        )
        .await
        .map_err(|error| match error {
            issuance::TargetingError::InvalidTarget => Failure::Client("invalid_target", INVALID),
            issuance::TargetingError::Storage(error) => Failure::Server(error),
        })?;
        if targeting.scopes != verified.scopes
            || targeting.audience.values().collect::<Vec<_>>() != [verified.resource.as_str()]
        {
            return Err(Failure::Client("invalid_scope", INVALID));
        }
        self.agent_policy
            .permits(
                tenant,
                client,
                &grant,
                &targets,
                GrantType::JwtBearer,
                self.now,
            )
            .await
            .map_err(|refusal| Failure::Client(refusal.code, refusal.description))?;
        let claimed = grant
            .claim(self.now)
            .map_err(|error| Failure::Server(DomainError::invalid("grant", error.to_string())))?;
        let access = AccessToken::new(
            &tenant.issuer,
            &grant,
            &claimed,
            targeting.audience,
            confirmation,
            JwtId::generate(),
            self.now,
        )
        .restricted_to_scopes(targeting.scopes)
        .with_grant_id_when(self.grant_id_claim)
        .for_lifetime(lifetime)
        .build()
        .map_err(|error| {
            Failure::Server(DomainError::invalid("access_token", error.to_string()))
        })?;
        let signed = self
            .signer
            .sign(
                &tenant.id,
                access.required_algorithm(),
                access.typ(),
                access.claims(),
            )
            .await?;

        let actor = client.registration.agent.as_ref().map_or_else(
            || Actor::Client(client.id.clone()),
            |profile| Actor::Agent {
                client: client.id.clone(),
                on_behalf_of: profile.owner().to_string(),
            },
        );
        let mut detail = Detail::new()
            .label("grant_type", "jwt_bearer")
            .text("id_jag_issuer", &verified.issuer)
            .text("id_jag_actor_client_id", &verified.actor_client_id);
        if let Some(resource) = trail::resource_summary(targets.iter().map(String::as_str)) {
            detail = detail.text(keys::RESOURCE, resource);
        }
        let event = AuditEvent::new(
            tenant.id.clone(),
            EventType::TOKEN_EXCHANGED,
            Outcome::Success,
            actor,
            self.now,
        )
        .client(client.id.clone())
        .subject(subject.as_str().to_owned())
        .grant(grant.id.clone())
        .detail(detail);
        let scopes: Vec<_> = verified.scopes.iter().cloned().collect();
        if !self
            .redemption
            .commit_issued(
                &verified.issuer,
                &verified.subject,
                &verified.actor_client_id,
                client.id.as_str(),
                &verified.resource,
                &scopes,
                &verified.jti,
                assertion_exp,
                self.now,
                &grant,
                event,
            )
            .await?
        {
            return Err(Failure::Client("invalid_grant", INVALID));
        }
        Ok((
            axum::http::StatusCode::OK,
            Json(json!({
                "access_token": signed.as_str(),
                "token_type": "DPoP",
                "expires_in": lifetime.whole_seconds(),
                "scope": scopes.join(" "),
            })),
        )
            .into_response())
    }
}

#[async_trait::async_trait]
impl GrantHandler for IdJagGrant<'_> {
    fn grant(&self) -> GrantType {
        GrantType::JwtBearer
    }

    async fn handle(&self, tenant: &Tenant, client: &Client, params: &Parameters) -> Response {
        self.redeem(tenant, client, params).await
    }
}

fn limits_scopes_refused(client: &Client, scopes: &BTreeSet<String>) -> bool {
    client.registration.agent.as_ref().is_some_and(|profile| {
        profile
            .limits()
            .scopes()
            .is_some_and(|allowed| !scopes.is_subset(allowed))
    })
}

enum Failure {
    Client(&'static str, &'static str),
    Server(DomainError),
}

impl From<DomainError> for Failure {
    fn from(error: DomainError) -> Self {
        Self::Server(error)
    }
}
