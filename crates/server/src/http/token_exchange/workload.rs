//! External workload subject profiles on the independently authenticated endpoint.
use super::{
    AccessToken, AgentLimits, BTreeSet, Ceiling, Client, DomainError, Duration, ExchangeRequest,
    Failure, Grant, INVALID_TARGET, Issued, JwtId, Parameters, SubjectId, TARGET_REFUSED, Tenant,
    TokenExchange, issuance, subject_refused, token_exchange,
};
use asterius_domain::entities::client::TokenEndpointAuthMethod;
use asterius_domain::workload::Verified;
use asterius_domain::{AuthorizationDetails, AuthorizationDetailsRegistry};
use asterius_oidc::tokens::access::Confirmation;

impl TokenExchange<'_> {
    pub(super) async fn issue_workload(
        &self,
        tenant: &Tenant,
        client: &Client,
        params: &Parameters,
        request: &ExchangeRequest<'_>,
        confirmation: Confirmation,
    ) -> Result<Issued, Failure> {
        let context = self.workloads.as_ref().ok_or_else(subject_refused)?;
        if !matches!(
            client.registration.token_endpoint_auth_method,
            TokenEndpointAuthMethod::PrivateKeyJwt
                | TokenEndpointAuthMethod::TlsClientAuth
                | TokenEndpointAuthMethod::SelfSignedTlsClientAuth
        ) {
            return Err(subject_refused());
        }
        let limits = client
            .registration
            .agent
            .as_ref()
            .map_or_else(AgentLimits::default, |profile| profile.limits().clone());
        if limits.impersonation() || request.targets.len() != 1 {
            return Err(Failure::Client(INVALID_TARGET, TARGET_REFUSED));
        }
        let verified = context
            .verifier
            .verify(&tenant.id, &client.id, request.subject_token, self.now)
            .await
            .map_err(|_| subject_refused())?;
        let (grant, targeting, lifetime) = self
            .workload_grant(tenant, client, params, request, &verified, &limits)
            .await?;
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
        .with_grant_id_when(true)
        .for_lifetime(lifetime)
        .build()
        .map_err(|error| {
            Failure::Server(DomainError::invalid("access_token", error.to_string()))
        })?;
        context
            .store
            .issue_with_audit(&verified, &grant, self.now, self.audit)
            .await
            .map_err(|error| match error {
                DomainError::Invalid { .. } => subject_refused(),
                other => Failure::Server(other),
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
        Ok(Issued {
            workload: true,
            response: Self::response(signed.as_str(), &grant.scopes, lifetime),
            chain: grant.actor_chain.clone(),
            subject: grant.subject.clone(),
            grant,
        })
    }
    async fn workload_grant(
        &self,
        tenant: &Tenant,
        client: &Client,
        params: &Parameters,
        request: &ExchangeRequest<'_>,
        verified: &Verified,
        limits: &AgentLimits,
    ) -> Result<(Grant, issuance::Targeting, Duration), Failure> {
        let context = self.workloads.as_ref().ok_or_else(subject_refused)?;
        let subject = Ceiling {
            subject: Some(SubjectId::new(&verified.principal)),
            user: None,
            parent: None,
            scopes: verified.scopes.clone(),
            resources: verified.resources.clone(),
            chain: Vec::new(),
            remaining: verified.expires_at - self.now,
        };
        let scopes = Self::scopes(client, limits, &subject, request.scope)?;
        let lifetime = self.lifetime(client, &subject)?.min(Duration::seconds(300));
        let mut grant = Grant::new(tenant.id.clone(), client.id.clone(), self.now);
        grant.subject = subject.subject.clone();
        grant.scopes = scopes;
        grant.resources = subject.resources.clone();
        grant.actor_chain =
            token_exchange::extend_chain(&[], client.id.as_str(), limits.max_delegation_depth())
                .map_err(|_| subject_refused())?;
        grant.claimed_at = Some(self.now);
        grant.expires_at = Some(self.now + lifetime);
        let targeting = self
            .targeting(tenant, client, &grant, request, limits)
            .await?;
        grant.resources = targeting.audience.values().map(str::to_owned).collect();
        grant.scopes = targeting.scopes.clone();
        let raw_details = params.get("authorization_details").map_err(|_| {
            Failure::Client("invalid_request", "a parameter was sent more than once")
        })?;
        grant.authorization_details = if let Some(raw) = raw_details {
            let details = AuthorizationDetails::parse(raw).map_err(|_| invalid_actions())?;
            narrow_actions(&details, verified, &grant.resources)?;
            let registry = AuthorizationDetailsRegistry::new(context.types.list().await?);
            registry
                .validate(
                    &details,
                    &client.registration.authorization_details_types,
                    &grant.resources,
                )
                .map_err(|_| invalid_actions())?;
            details.to_json()
        } else {
            Vec::new()
        };
        self.permitted(tenant, client, &grant).await?;
        Ok((grant, targeting, lifetime))
    }
}
fn invalid_actions() -> Failure {
    Failure::Client(
        "invalid_authorization_details",
        "the requested actions exceed workload authority",
    )
}
fn narrow_actions(
    details: &AuthorizationDetails,
    verified: &Verified,
    targets: &BTreeSet<String>,
) -> Result<(), Failure> {
    asterius_domain::workload::validate_actions(&details.to_json(), &verified.actions, targets)
        .map_err(|_| invalid_actions())
}
