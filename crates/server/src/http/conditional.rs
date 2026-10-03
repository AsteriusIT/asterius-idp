//! Conditional boundaries use only facts tied to this request and transaction.
use super::forwarded::ConditionalOrigin;
use std::collections::BTreeMap;
use std::sync::Arc;
use asterius_domain::audit::{Actor, AuditEvent, AuditSink, Detail, EventType, Outcome};
use asterius_domain::entities::agent::AgentOwner;
use asterius_domain::entities::client::GrantType;
use asterius_domain::policy::conditional::{Availability, ConditionalScope, ConditionalSettings, EnforcementMode, Fact, FactName, FactValue, TrustedAccessContext};
use asterius_domain::policy::{Action, ActiveGrant, Context, Decision, EvaluationRequest, Properties, Resource, StoredPolicy, Subject};
use asterius_domain::ports::{ApplicationRoleDirectory as _, GrantRepository as _, GroupDirectory as _, PolicyStore as _, TenantSettingsRepository as _, UserDirectory as _};
use asterius_domain::{Capabilities, Client, DomainError, Grant, GrantAuthentication, Tenant, UserId};
use asterius_store_pg::{PgConditionalSettings, PgGroups, PgPolicies, PgTenantSettings, Store};
use time::{Duration, OffsetDateTime};

tokio::task_local! {
    pub(crate) static ORIGIN: ConditionalOrigin;
}

#[must_use]
pub(crate) fn origin() -> ConditionalOrigin {
    ORIGIN.try_with(|origin| *origin).unwrap_or_else(|_| ConditionalOrigin::absent())
}

#[derive(Debug, Clone)]
pub(crate) struct ConditionalAccess {
    store: Store,
    capabilities: Capabilities,
    kek: Arc<dyn asterius_jose::Kek>,
    audit: Arc<dyn AuditSink>,
}

#[derive(Clone, Copy)]
struct Principal<'a> {
    user: Option<UserId>,
    subject: Option<&'a str>,
    authentication: Option<&'a GrantAuthentication>,
    grant: Option<&'a Grant>,
}

impl ConditionalAccess {
    pub(crate) fn new(store: Store, capabilities: Capabilities, kek: Arc<dyn asterius_jose::Kek>, audit: Arc<dyn AuditSink>) -> Self {
        Self { store, capabilities, kek, audit }
    }

    /// Necessary before grant side effects; the signing boundary rechecks it.
    pub(crate) async fn check_grant(&self, tenant: &Tenant, client: &Client, grant: &Grant, kind: GrantType, now: OffsetDateTime) -> Result<bool, DomainError> {
        if grant.tenant != tenant.id || client.tenant != tenant.id || grant.client != client.id {
            return Err(DomainError::invalid("conditional_access", "transaction binding mismatch"));
        }
        let owner = client.registration.agent.as_ref().map(|profile| match profile.owner() { AgentOwner::User(user) => *user });
        // Refresh never refreshes authentication age; a delegated agent cannot
        // borrow assurance from a human parent even if that grant carries it.
        let authentication = (client.registration.agent.is_none() && grant.actor_chain.is_empty()).then_some(grant.authentication.as_ref()).flatten();
        let input = Principal { user: owner.or(grant.user), subject: grant.subject.as_ref().map(|id| id.as_str()), authentication, grant: Some(grant) };
        self.check(tenant, client, action(kind), input, now).await
    }

    async fn check(&self, tenant: &Tenant, client: &Client, action: &str, input: Principal<'_>, now: OffsetDateTime) -> Result<bool, DomainError> {
        let policies = PgPolicies::new(self.store.pool().clone());
        // Rebuild once if publication races fact resolution. The final signing
        // fence is necessary in addition to this check before side effects.
        for _ in 0..2 {
            let Some(policy) = policies.load(&tenant.id).await? else { return Ok(true); };
            let Some(scope) = policy.rules.conditional_scopes().iter().find(|scope| scope.applies(&client.id, action)) else { return Ok(true); };
            let request = self.resolve(tenant, client, action, &policy, scope, input, now).await?;
            let revision = asterius_domain::policy::explanation::revision(&policy.rules);
            let current = policies.load(&tenant.id).await?;
            if current.as_ref().map(|policy| asterius_domain::policy::explanation::revision(&policy.rules)).as_ref() != Some(&revision) { continue; }
            let decision = scope.evaluate(&request);
            self.record(tenant, client, &policy, scope, &request, &decision, input.grant, now).await;
            return Ok(decision.permit() || scope.mode == EnforcementMode::ReportOnly);
        }
        Err(DomainError::invalid("conditional_access", "policy changed repeatedly during resolution"))
    }

    async fn resolve(&self, tenant: &Tenant, client: &Client, action: &str, policy: &StoredPolicy, scope: &ConditionalScope, input: Principal<'_>, now: OffsetDateTime) -> Result<EvaluationRequest, DomainError> {
        let tenant_scope = self.store.scope(tenant.id.clone());
        let current = tenant_scope.clients(self.capabilities).find(&client.id).await?.ok_or(DomainError::NotFound)?;
        if !current.is_active() { return Err(DomainError::invalid("conditional_access", "application unavailable")); }
        let settings = PgTenantSettings::new(self.store.pool().clone()).settings(&tenant.id).await?;
        let acr = settings.acr_policy();
        let classification = PgConditionalSettings::new(self.store.pool().clone()).read(&tenant.id, &client.id).await?;
        let mut facts = self.connection_facts(scope, now);
        if let Some(sensitivity) = classification.as_ref().and_then(|value| value.sensitivity) {
            facts.insert(FactName::ApplicationSensitivity, known(FactValue::Text(sensitivity.as_str().to_owned()), "administrative_client_settings", now));
        }
        let verified_acr = input.authentication.and_then(|authentication| authentication.acr.as_ref().filter(|value| acr.level(value).is_some_and(|level| level.is_met_by(&authentication.amr))));
        if let Some(authentication) = input.authentication {
            facts.insert(FactName::AuthenticationAge, known(FactValue::AuthenticationTime(authentication.authenticated_at), "exact_grant_authentication", now));
            if let Some(value) = verified_acr { facts.insert(FactName::Assurance, known(FactValue::Text(value.clone()), "exact_grant_authentication", now)); }
        }
        let trusted = TrustedAccessContext { tenant: tenant.id.clone(), subject: input.subject.map(str::to_owned), client: client.id.clone(), action: action.to_owned(), evaluated_at: now, policy_revision: asterius_domain::policy::explanation::revision(&policy.rules), acr_revision: asterius_domain::sha256_hex(acr.to_json().to_string().as_bytes()), client_revision: asterius_domain::sha256_hex(format!("{}:{:?}", current.updated_at.unix_timestamp_nanos(), classification.as_ref().map(|value| value.revision)).as_bytes()), facts };
        let subject = self.subject(tenant, client, input, now).await?;
        let mut trusted = trusted;
        if input.user.is_some() {
            for name in [FactName::Groups, FactName::Roles, FactName::Grants] { trusted.facts.insert(name, known(FactValue::Resolved, "current_tenant_directory", now)); }
        }
        let props = input.grant.map_or(Ok(Properties::empty()), |grant| Properties::new([("scopes", serde_json::json!(grant.scopes)), ("audience", serde_json::json!(grant.resources))])).map_err(invalid_request)?;
        Ok(EvaluationRequest::new(subject, Action::new(action, Properties::empty()).map_err(invalid_request)?, Resource::new("application", client.id.as_str(), props).map_err(invalid_request)?, Context::default().with_acr(verified_acr.cloned(), acr.levels().iter().map(|level| level.value().to_owned())).with_trusted(trusted)))
    }

    fn connection_facts(&self, scope: &ConditionalScope, now: OffsetDateTime) -> BTreeMap<FactName, Fact> {
        let mut facts = BTreeMap::new();
        let network = origin();
        if let Some(ip) = network.ip.filter(|_| network.availability == Availability::Known) {
            let zones = scope.network_zones.iter().filter(|(_, networks)| networks.iter().any(|net| net.contains(&ip))).map(|(name, _)| name.clone()).collect();
            facts.insert(FactName::NetworkZone, known(FactValue::Names(zones), "current_verified_connection", now));
        } else { facts.insert(FactName::NetworkZone, Fact::missing(network.availability, "current_verified_connection")); }
        facts.insert(FactName::DeviceCompliance, Fact::missing(Availability::Unavailable, "device_registry_adapter"));
        facts
    }

    async fn subject(&self, tenant: &Tenant, client: &Client, input: Principal<'_>, now: OffsetDateTime) -> Result<Subject, DomainError> {
        let kind = if client.registration.agent.is_some() { "agent" } else if input.user.is_some() { "user" } else { "client" };
        let id = input.subject.unwrap_or(client.id.as_str());
        let subject = Subject::new(kind, id, Properties::empty()).map_err(invalid_request)?;
        let Some(user) = input.user else { return Ok(subject); };
        let tenant_scope = self.store.scope(tenant.id.clone());
        let user = tenant_scope.users(Arc::clone(&self.kek)).by_id(user).await?.filter(|user| user.can_authenticate()).ok_or_else(|| DomainError::invalid("conditional_access", "principal unavailable"))?;
        let groups = PgGroups::new(self.store.pool().clone()).authorization_references_for_user(&tenant.id, user.id).await?;
        let roles = tenant_scope.application_roles().held_by(&tenant.id, user.id).await?;
        let grants = match input.subject { Some(subject) => tenant_scope.grants().for_subject(&asterius_domain::SubjectId::new(subject)).await?, None => Vec::new() };
        subject.with_groups(groups).with_roles(roles).with_grants(grants.iter().filter_map(|grant| ActiveGrant::of(grant, now))).map_err(invalid_request)
    }

    async fn record(&self, tenant: &Tenant, client: &Client, policy: &StoredPolicy, scope: &ConditionalScope, request: &EvaluationRequest, decision: &Decision, grant: Option<&Grant>, now: OffsetDateTime) {
        let nested = StoredPolicy { rules: scope.rules.clone(), updated_at: policy.updated_at };
        let mut explanation = asterius_domain::policy::explanation::explain(Some(&nested), request, "conditional_access");
        explanation.policy_revision = Some(asterius_domain::policy::explanation::revision(&policy.rules));
        let states: BTreeMap<_, _> = scope.required().into_iter().map(|name| (name, request.context.trusted().map_or(Availability::Absent, |context| context.availability(name)))).collect();
        let detail = Detail::new().label("enforcement", if scope.mode == EnforcementMode::Active { "active" } else { "report_only" }).text("action", request.context.trusted().map_or("unknown", |context| context.action.as_str())).text("scope", &scope.id).text("required_fact_states", serde_json::json!(states).to_string());
        let mut event = AuditEvent::new(tenant.id.clone(), EventType::ACCESS_EVALUATED, if decision.permit() { Outcome::Success } else { Outcome::Failure }, Actor::Client(client.id.clone()), now).client(client.id.clone()).detail(detail);
        if let Some(grant) = grant {
            event = event.grant(grant.id.clone());
            if let Some(session) = &grant.session { event = event.session(session.clone()); }
        }
        if let Err(error) = self.audit.record_with_diagnostics(event, &explanation).await { tracing::error!(%error, tenant = %tenant.id, "conditional decision audit unavailable"); }
    }
}

fn known(value: FactValue, source: &str, now: OffsetDateTime) -> Fact {
    Fact::known(value, source, now, now + Duration::seconds(30))
}

fn invalid_request(error: asterius_domain::policy::RequestError) -> DomainError {
    DomainError::invalid("conditional_access", error.to_string())
}

pub(crate) const fn action(kind: GrantType) -> &'static str {
    match kind {
        GrantType::AuthorizationCode => "authorization_code", GrantType::RefreshToken => "refresh_token", GrantType::ClientCredentials => "client_credentials", GrantType::TokenExchange => "token_exchange", GrantType::JwtBearer => "jwt_bearer", GrantType::DeviceCode => "device_code", GrantType::Ciba => "ciba",
    }
}

#[async_trait::async_trait]
impl super::agent_issuance::ConditionalGuard for ConditionalAccess {
    async fn permits(&self, tenant: &Tenant, client: &Client, grant: &Grant, kind: GrantType, now: OffsetDateTime) -> Result<bool, DomainError> {
        self.check_grant(tenant, client, grant, kind, now).await
    }
}
