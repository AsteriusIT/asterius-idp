//! Conditional boundaries use only facts tied to this request and transaction.
use super::forwarded::ConditionalOrigin;
use std::collections::BTreeMap;
use std::cell::RefCell;
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
    pub(crate) static PDP_AUTHORITY: RefCell<Option<PdpAuthority>>;
}

/// Populated only after signature, sender, audience, revocation and scope checks.
#[derive(Debug, Clone)]
pub(crate) struct PdpAuthority {
    pub tenant: asterius_domain::TenantId,
    pub client: asterius_domain::ClientId,
    pub grant: Option<asterius_domain::GrantId>,
    pub subject: Option<String>,
}
pub(crate) fn bind_pdp(authority: PdpAuthority) {
    // Unit adapters without tenancy middleware never receive trusted authority.
    let _ = PDP_AUTHORITY.try_with(|slot| *slot.borrow_mut() = Some(authority));
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
        let verified_acr = input.authentication.filter(|authentication| authentication.authenticated_at <= now).and_then(|authentication| authentication.acr.as_ref().filter(|value| acr.level(value).is_some_and(|level| level.is_met_by(&authentication.amr))));
        if let Some(authentication) = input.authentication {
            facts.insert(FactName::AuthenticationAge, known(FactValue::AuthenticationTime(authentication.authenticated_at), "exact_grant_authentication", now));
            if let Some(value) = verified_acr { facts.insert(FactName::Assurance, known(FactValue::Text(value.clone()), "exact_grant_authentication", now)); }
            else if authentication.authenticated_at > now { facts.insert(FactName::Assurance, Fact::missing(Availability::Invalid, "exact_grant_authentication")); }
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
        add_guard_trace(&mut explanation, scope, request);
        let states: BTreeMap<_, _> = scope.required_for(request).into_iter().map(|name| (name, request.context.trusted().map_or(Availability::Absent, |context| context.availability(name)))).collect();
        let mut detail = Detail::new().label("enforcement", if scope.mode == EnforcementMode::Active { "active" } else { "report_only" }).text("action", request.context.trusted().map_or("unknown", |context| context.action.as_str())).text("scope", &scope.id).text("required_fact_states", serde_json::json!(states).to_string());
        if let Some(trusted) = request.context.trusted() {
            let sources: BTreeMap<_, _> = trusted.facts.iter().map(|(name, fact)| (name, serde_json::json!({"source":fact.source,"observed_at":fact.observed_at.map(OffsetDateTime::unix_timestamp),"expires_at":fact.expires_at.map(OffsetDateTime::unix_timestamp)}))).collect();
            detail = detail.text("acr_revision", &trusted.acr_revision).text("client_revision", &trusted.client_revision).text("evaluated_at", trusted.evaluated_at.unix_timestamp().to_string()).text("fact_sources", serde_json::json!(sources).to_string());
        }
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

/// Uses one policy snapshot for both the base PDP and its application guard.
#[derive(Debug)]
pub(crate) struct ConditionalPolicyEngine {
    access: ConditionalAccess,
    tenant: Tenant,
    now: OffsetDateTime,
}
impl ConditionalPolicyEngine {
    pub(crate) fn new(access: ConditionalAccess, tenant: Tenant, now: OffsetDateTime) -> Self { Self { access, tenant, now } }
}
#[async_trait::async_trait]
impl asterius_domain::ports::PolicyEngine for ConditionalPolicyEngine {
    async fn evaluate(&self, tenant: &asterius_domain::TenantId, question: &EvaluationRequest) -> Result<Decision, DomainError> {
        if tenant != &self.tenant.id { return Err(DomainError::NotFound); }
        let authority = PDP_AUTHORITY.try_with(|slot| slot.borrow().clone()).ok().flatten();
        let policies = PgPolicies::new(self.access.store.pool().clone());
        for _ in 0..2 {
            let policy = policies.load(tenant).await?;
            let base = asterius_domain::policy::explanation::evaluate(policy.as_ref(), question, "access_evaluation");
            let Some(policy) = policy else { return Ok(base); };
            let guarded = policy.rules.conditional_scopes().iter().any(|scope| scope.actions.contains("access_evaluation"));
            if !guarded { return Ok(base); }
            let Some(authority) = authority.as_ref().filter(|authority| &authority.tenant == tenant) else {
                return Ok(Decision::default_deny("verified conditional application context unavailable"));
            };
            let Some(scope) = policy.rules.conditional_scopes().iter().find(|scope| scope.applies(&authority.client, "access_evaluation")) else { return Ok(base); };
            let repositories = self.access.store.scope(tenant.clone());
            let client = repositories.clients(self.access.capabilities).find(&authority.client).await?.ok_or(DomainError::NotFound)?;
            let user = repositories.users(Arc::clone(&self.access.kek)).find_by_subject(&asterius_domain::SubjectId::new(question.subject.id())).await?;
            let grant = match &authority.grant { Some(id) => repositories.grants().find(id).await?, None => None };
            let exact = grant.as_ref().filter(|grant| grant.tenant == *tenant && grant.client == authority.client && grant.subject.as_ref().is_some_and(|subject| subject.as_str() == question.subject.id()) && authority.subject.as_deref() == Some(question.subject.id()) && ActiveGrant::of(grant, self.now).is_some());
            let authentication = exact.filter(|grant| grant.actor_chain.is_empty() && client.registration.agent.is_none()).and_then(|grant| grant.authentication.as_ref());
            let input = Principal { user: user.as_ref().map(|user| user.id), subject: Some(question.subject.id()), authentication, grant: exact };
            let resolved = self.access.resolve(&self.tenant, &client, "access_evaluation", &policy, scope, input, self.now).await?;
            let mut request = question.clone();
            // Existing subject attributes remain PEP inputs; assurance and source
            // availability come exclusively from this verified transaction.
            request.subject = question.subject.clone().with_groups(resolved.subject.groups().iter().cloned()).with_roles(resolved.subject.roles().clone()).with_grants(resolved.subject.grants().iter().cloned()).map_err(invalid_request)?;
            request.context = Context::new(question.context.properties().clone()).with_acr(resolved.context.acr().map(str::to_owned), resolved.context.ladder().iter().cloned());
            if let Some(trusted) = resolved.context.trusted() { request.context = request.context.with_trusted(trusted.clone()); }
            let base = if scope.mode == EnforcementMode::Active {
                asterius_domain::policy::explanation::evaluate(Some(&policy), &request, "access_evaluation")
            } else { base };
            let current = policies.load(tenant).await?;
            if current.as_ref().map(|value| asterius_domain::policy::explanation::revision(&value.rules)) != Some(asterius_domain::policy::explanation::revision(&policy.rules)) { continue; }
            let conditional = scope.evaluate(&request);
            self.access.record(&self.tenant, &client, &policy, scope, &request, &conditional, exact, self.now).await;
            if base.permit() && !conditional.permit() && scope.mode == EnforcementMode::Active {
                let nested = StoredPolicy { rules: scope.rules.clone(), updated_at: policy.updated_at };
                let mut explanation = asterius_domain::policy::explanation::explain(Some(&nested), &request, "conditional_access");
                explanation.policy_revision = Some(asterius_domain::policy::explanation::revision(&policy.rules));
                add_guard_trace(&mut explanation, scope, &request);
                return Ok(conditional.with_explanation(explanation));
            }
            return Ok(base);
        }
        Ok(Decision::default_deny("conditional policy changed during evaluation"))
    }
}

fn add_guard_trace(explanation: &mut asterius_domain::policy::explanation::DecisionExplanation, scope: &ConditionalScope, request: &EvaluationRequest) {
    let available = request.context.trusted().is_some_and(|trusted| scope.required_for(request).into_iter().all(|name| trusted.availability(name) == Availability::Known));
    // The guard precedes boolean rules: NOT and ANY cannot negate absence.
    explanation.rules.insert(0, asterius_domain::policy::explanation::RuleExplanation {
        id: "conditional-required-facts".to_owned(), effect: "deny", applicable: true, matched: !available,
        conditions: vec![asterius_domain::policy::explanation::ConditionExplanation { path: "required_facts".to_owned(), kind: "trusted_fact_guard", matched: available, missing: !available }],
    });
    if explanation.rules.len() > 128 { explanation.rules.pop(); explanation.truncated = true; }
    let mut remaining = asterius_domain::policy::explanation::MAX_TRACE_NODES;
    for rule in &mut explanation.rules {
        if rule.conditions.len() > remaining { rule.conditions.truncate(remaining); explanation.truncated = true; }
        remaining -= rule.conditions.len();
    }
}

#[async_trait::async_trait]
impl super::authorize::ConditionalAuthorization for ConditionalAccess {
    async fn prepare(&self, tenant: &Tenant, client_id: &asterius_domain::ClientId, session: Option<&asterius_domain::Session>, now: OffsetDateTime) -> Result<Option<asterius_web::interaction::ConditionalBinding>, DomainError> {
        let Some(policy) = PgPolicies::new(self.store.pool().clone()).load(&tenant.id).await? else { return Ok(None); };
        let Some(scope) = policy.rules.conditional_scopes().iter().find(|scope| scope.applies(client_id, "authorize")) else { return Ok(None); };
        if scope.mode == EnforcementMode::ReportOnly { return Ok(None); }
        let repositories = self.store.scope(tenant.id.clone());
        let client = repositories.clients(self.capabilities).find(client_id).await?.ok_or(DomainError::NotFound)?;
        let settings = PgTenantSettings::new(self.store.pool().clone()).settings(&tenant.id).await?;
        let acr = settings.acr_policy();
        let revision = asterius_domain::policy::explanation::revision(&policy.rules);
        let mut binding = asterius_web::interaction::ConditionalBinding { client: client_id.as_str().to_owned(), action: "authorize".to_owned(), policy_revision: revision, acr: None, acceptable_acr: Vec::new(), max_age: None };
        if let Some(session) = session.filter(|session| session.status(now).is_usable()) {
            let sector = asterius_domain::SectorIdentifier::of_client(&client).map_err(|_| DomainError::invalid("conditional_access", "application sector unavailable"))?;
            let subject = repositories.users(Arc::clone(&self.kek)).subject(asterius_domain::UserId::new(session.user), &sector).await?;
            let authentication = GrantAuthentication { authenticated_at: session.authenticated_at, acr: session.acr.clone(), amr: session.amr.clone() };
            let input = Principal { user: Some(asterius_domain::UserId::new(session.user)), subject: Some(subject.as_str()), authentication: Some(&authentication), grant: None };
            let request = self.resolve(tenant, &client, "authorize", &policy, scope, input, now).await?;
            let decision = scope.evaluate(&request);
            self.record(tenant, &client, &policy, scope, &request, &decision, None, now).await;
            if decision.permit() { return Ok(Some(binding)); }
            binding.acr = Some(scope.remedy(&request, acr).ok_or_else(|| DomainError::invalid("conditional_access", "conditional denial cannot be repaired by authentication"))?);
            binding.max_age = Some(0);
        } else {
            // Resolve identity after login, while binding any configured remedy
            // to the original pushed client and enforcing it as essential.
            if let Some(target) = &scope.assurance_remedy {
                if !acr.can_produce(target) { return Err(DomainError::invalid("conditional_access", "conditional authentication requirement unavailable")); }
                binding.acr = Some(target.clone());
            }
        }
        if let Some(target) = &binding.acr {
            binding.acceptable_acr = acr.levels().iter().skip_while(|level| level.value() != target).map(|level| level.value().to_owned()).collect();
        }
        Ok(Some(binding))
    }
    async fn permits(&self, tenant: &Tenant, client: &Client, grant: &Grant, now: OffsetDateTime) -> Result<bool, DomainError> {
        let input = Principal { user: grant.user, subject: grant.subject.as_ref().map(|value| value.as_str()), authentication: grant.authentication.as_ref(), grant: Some(grant) };
        self.check(tenant, client, "authorize", input, now).await
    }
}
