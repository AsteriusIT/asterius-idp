//! Conditional boundaries use only facts tied to this request and transaction.
use super::forwarded::ConditionalOrigin;
use asterius_domain::audit::{Actor, AuditEvent, AuditSink, Detail, EventType, Outcome};
use asterius_domain::entities::agent::AgentOwner;
use asterius_domain::entities::client::GrantType;
use asterius_domain::policy::conditional::{
    Availability, ConditionalScope, ConditionalSettings, EnforcementMode, Fact, FactName,
    FactValue, TrustedAccessContext,
};
use asterius_domain::policy::{
    Action, ActiveGrant, Context, Decision, EvaluationRequest, Properties, Resource, StoredPolicy,
    Subject,
};
use asterius_domain::ports::{
    ApplicationRoleDirectory as _, GrantRepository as _, GroupDirectory as _, PolicyStore as _,
    TenantSettingsRepository as _, UserDirectory as _,
};
use asterius_domain::{
    Capabilities, Client, DomainError, Grant, GrantAuthentication, Tenant, UserId,
};
use asterius_store_pg::{PgConditionalSettings, PgGroups, PgPolicies, PgTenantSettings, Store};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::sync::Arc;
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
    pub scopes: std::collections::BTreeSet<String>,
    pub resources: std::collections::BTreeSet<String>,
    pub task: Option<PdpTaskAuthority>,
}
#[derive(Debug, Clone)]
pub(crate) struct PdpTaskAuthority {
    pub jti: String,
    pub id: uuid::Uuid,
    pub revision: i64,
}
pub(crate) fn bind_pdp(authority: PdpAuthority) {
    // Unit adapters without tenancy middleware never receive trusted authority.
    let _ = PDP_AUTHORITY.try_with(|slot| *slot.borrow_mut() = Some(authority));
}

#[must_use]
pub(crate) fn origin() -> ConditionalOrigin {
    ORIGIN
        .try_with(|origin| *origin)
        .unwrap_or_else(|_| ConditionalOrigin::absent())
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
    pub(crate) fn new(
        store: Store,
        capabilities: Capabilities,
        kek: Arc<dyn asterius_jose::Kek>,
        audit: Arc<dyn AuditSink>,
    ) -> Self {
        Self {
            store,
            capabilities,
            kek,
            audit,
        }
    }

    /// Necessary before grant side effects; the signing boundary rechecks it.
    pub(crate) async fn check_grant(
        &self,
        tenant: &Tenant,
        client: &Client,
        grant: &Grant,
        kind: GrantType,
        now: OffsetDateTime,
    ) -> Result<bool, DomainError> {
        if grant.tenant != tenant.id || client.tenant != tenant.id || grant.client != client.id {
            return Err(DomainError::invalid(
                "conditional_access",
                "transaction binding mismatch",
            ));
        }
        let owner = client
            .registration
            .agent
            .as_ref()
            .map(|profile| match profile.owner() {
                AgentOwner::User(user) => *user,
            });
        // Refresh never refreshes authentication age; a delegated agent cannot
        // borrow assurance from a human parent even if that grant carries it.
        let authentication = (client.registration.agent.is_none() && grant.actor_chain.is_empty())
            .then_some(grant.authentication.as_ref())
            .flatten();
        let input = Principal {
            user: owner.or(grant.user),
            subject: grant
                .subject
                .as_ref()
                .map(asterius_domain::SubjectId::as_str),
            authentication,
            grant: Some(grant),
        };
        self.check(tenant, client, action(kind), input, now).await
    }

    async fn check(
        &self,
        tenant: &Tenant,
        client: &Client,
        action: &str,
        input: Principal<'_>,
        now: OffsetDateTime,
    ) -> Result<bool, DomainError> {
        let policies = PgPolicies::new(self.store.pool().clone());
        // Rebuild once if publication races fact resolution. The final signing
        // fence is necessary in addition to this check before side effects.
        for _ in 0..2 {
            let Some(policy) = policies.load(&tenant.id).await? else {
                return Ok(true);
            };
            let Some(scope) = policy
                .rules
                .conditional_scopes()
                .iter()
                .find(|scope| scope.applies(&client.id, action))
            else {
                return Ok(true);
            };
            let mut request = self
                .resolve(tenant, client, action, &policy, scope, input, now)
                .await?;
            let revision = asterius_domain::policy::explanation::revision(&policy.rules);
            let current = policies.load(&tenant.id).await?;
            if current
                .as_ref()
                .map(|policy| asterius_domain::policy::explanation::revision(&policy.rules))
                .as_ref()
                != Some(&revision)
            {
                continue;
            }
            let decision = scope.evaluate(&request);
            self.record(
                tenant,
                client,
                &policy,
                scope,
                &request,
                &decision,
                input.grant,
                now,
            )
            .await;
            // Audit persistence may wait. Recheck source validity and original
            // authentication age using a fresh clock immediately before the
            // caller invokes the already-prepared local signer.
            let finished = OffsetDateTime::now_utc();
            advance_clock(&mut request, finished);
            let final_decision = scope.evaluate(&request);
            if decision.permit() && !final_decision.permit() {
                self.record(
                    tenant,
                    client,
                    &policy,
                    scope,
                    &request,
                    &final_decision,
                    input.grant,
                    finished,
                )
                .await;
            }
            return Ok((decision.permit() && final_decision.permit())
                || scope.mode == EnforcementMode::ReportOnly);
        }
        Err(DomainError::invalid(
            "conditional_access",
            "policy changed repeatedly during resolution",
        ))
    }

    #[expect(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "One exact tenant/client/policy scope resolves and binds the complete current-source snapshot"
    )]
    async fn resolve(
        &self,
        tenant: &Tenant,
        client: &Client,
        action: &str,
        policy: &StoredPolicy,
        scope: &ConditionalScope,
        input: Principal<'_>,
        now: OffsetDateTime,
    ) -> Result<EvaluationRequest, DomainError> {
        let tenant_scope = self.store.scope(tenant.id.clone());
        let current = tenant_scope
            .clients(self.capabilities)
            .find(&client.id)
            .await?
            .ok_or(DomainError::NotFound)?;
        if !current.is_active() {
            return Err(DomainError::invalid(
                "conditional_access",
                "application unavailable",
            ));
        }
        let settings = PgTenantSettings::new(self.store.pool().clone())
            .settings(&tenant.id)
            .await?;
        let acr = settings.acr_policy();
        let classification = PgConditionalSettings::new(self.store.pool().clone())
            .read(&tenant.id, &client.id)
            .await?;
        let mut facts = Self::connection_facts(scope, now);
        if let Some(sensitivity) = classification.as_ref().and_then(|value| value.sensitivity) {
            facts.insert(
                FactName::ApplicationSensitivity,
                known(
                    FactValue::Text(sensitivity.as_str().to_owned()),
                    "administrative_client_settings",
                    now,
                ),
            );
        }
        if let Some(authentication) = input.authentication {
            let revision = asterius_domain::sha256_hex(acr.to_json().to_string().as_bytes());
            let verified = authentication.assurance_authenticated_at.filter(|at| {
                *at <= authentication.authenticated_at
                    && authentication.authenticated_at <= now
                    && authentication.assurance_policy_revision.as_deref()
                        == Some(revision.as_str())
                    && !authentication.assurance_methods.is_empty()
                    && !authentication.assurance_methods.iter().any(|method| {
                        matches!(
                            method,
                            asterius_domain::AuthenticationMethod::FederatedOidc
                                | asterius_domain::AuthenticationMethod::ExistingSession
                        )
                    })
                    && authentication.acr.as_ref().is_none_or(|class| {
                        acr.level(class)
                            .is_some_and(|level| level.is_met_by(&authentication.assurance_methods))
                    })
            });
            if let Some(at) = verified {
                facts.insert(
                    FactName::AuthenticationAge,
                    known(
                        FactValue::AuthenticationTime(at),
                        "exact_grant_assurance_proof",
                        now,
                    ),
                );
                if let Some(class) = &authentication.acr {
                    facts.insert(
                        FactName::Assurance,
                        known(
                            FactValue::Text(class.clone()),
                            "exact_grant_assurance_proof",
                            now,
                        ),
                    );
                }
            } else {
                let availability = if authentication.authenticated_at > now
                    || authentication
                        .assurance_authenticated_at
                        .is_some_and(|at| at > authentication.authenticated_at)
                {
                    Availability::Invalid
                } else {
                    Availability::Unavailable
                };
                for name in [FactName::AuthenticationAge, FactName::Assurance] {
                    facts.insert(
                        name,
                        Fact::missing(availability, "exact_grant_assurance_proof"),
                    );
                }
            }
        }
        // Legacy unscoped ACR policy keeps its cumulative semantics. Scoped
        // freshness and assurance use only the provenance-backed facts above.
        let verified_acr = input
            .authentication
            .filter(|authentication| authentication.authenticated_at <= now)
            .and_then(|authentication| {
                authentication.acr.as_ref().filter(|class| {
                    acr.level(class)
                        .is_some_and(|level| level.is_met_by(&authentication.amr))
                })
            });
        let trusted = TrustedAccessContext {
            tenant: tenant.id.clone(),
            subject: input.subject.map(str::to_owned),
            client: client.id.clone(),
            action: action.to_owned(),
            evaluated_at: now,
            policy_revision: asterius_domain::policy::explanation::revision(&policy.rules),
            acr_revision: asterius_domain::sha256_hex(acr.to_json().to_string().as_bytes()),
            client_revision: asterius_domain::sha256_hex(
                format!(
                    "{}:{:?}",
                    current.updated_at.unix_timestamp_nanos(),
                    classification.as_ref().map(|value| value.revision)
                )
                .as_bytes(),
            ),
            facts,
        };
        let subject = self.subject(tenant, client, input, now).await?;
        let mut trusted = trusted;
        if input.user.is_some() {
            for name in [FactName::Groups, FactName::Roles] {
                trusted.facts.insert(
                    name,
                    known(FactValue::Resolved, "current_tenant_directory", now),
                );
            }
            if input.subject.is_some() {
                trusted.facts.insert(
                    FactName::Grants,
                    known(FactValue::Resolved, "current_tenant_directory", now),
                );
            }
        }
        let props = input
            .grant
            .map_or(Ok(Properties::empty()), |grant| {
                Properties::new([
                    ("scopes", serde_json::json!(grant.scopes)),
                    ("audience", serde_json::json!(grant.resources)),
                ])
            })
            .map_err(|error| invalid_request(&error))?;
        Ok(EvaluationRequest::new(
            subject,
            Action::new(action, Properties::empty()).map_err(|error| invalid_request(&error))?,
            Resource::new("application", client.id.as_str(), props)
                .map_err(|error| invalid_request(&error))?,
            Context::default()
                .with_acr(
                    verified_acr.cloned(),
                    acr.levels().iter().map(|level| level.value().to_owned()),
                )
                .with_trusted(trusted),
        ))
    }

    fn connection_facts(scope: &ConditionalScope, now: OffsetDateTime) -> BTreeMap<FactName, Fact> {
        let mut facts = BTreeMap::new();
        let network = origin();
        if let Some(ip) = network
            .ip
            .filter(|_| network.availability == Availability::Known)
        {
            let zones = scope
                .network_zones
                .iter()
                .filter(|(_, networks)| networks.iter().any(|net| net.contains(&ip)))
                .map(|(name, _)| name.clone())
                .collect();
            facts.insert(
                FactName::NetworkZone,
                known(FactValue::Names(zones), "current_verified_connection", now),
            );
        } else {
            facts.insert(
                FactName::NetworkZone,
                Fact::missing(network.availability, "current_verified_connection"),
            );
        }
        facts.insert(
            FactName::DeviceCompliance,
            Fact::missing(Availability::Unavailable, "device_registry_adapter"),
        );
        facts
    }

    async fn subject(
        &self,
        tenant: &Tenant,
        client: &Client,
        input: Principal<'_>,
        now: OffsetDateTime,
    ) -> Result<Subject, DomainError> {
        let kind = if client.registration.agent.is_some() {
            "agent"
        } else if input.user.is_some() {
            "user"
        } else {
            "client"
        };
        let id = input.subject.unwrap_or(client.id.as_str());
        let subject =
            Subject::new(kind, id, Properties::empty()).map_err(|error| invalid_request(&error))?;
        let Some(user) = input.user else {
            return Ok(subject);
        };
        let tenant_scope = self.store.scope(tenant.id.clone());
        let user = tenant_scope
            .users(Arc::clone(&self.kek))
            .by_id(user)
            .await?
            .filter(asterius_domain::User::can_authenticate)
            .ok_or_else(|| DomainError::invalid("conditional_access", "principal unavailable"))?;
        let groups = PgGroups::new(self.store.pool().clone())
            .authorization_references_for_user(&tenant.id, user.id)
            .await?;
        let roles = match input.grant {
            Some(grant) => {
                tenant_scope
                    .application_roles()
                    .held_by_grant(grant)
                    .await?
            }
            None => {
                tenant_scope
                    .application_roles()
                    .held_by(&tenant.id, user.id)
                    .await?
            }
        };
        let grants = match input.subject {
            Some(subject) => {
                tenant_scope
                    .grants()
                    .for_subject(&asterius_domain::SubjectId::new(subject))
                    .await?
            }
            None => Vec::new(),
        };
        subject
            .with_groups(groups)
            .with_roles(roles)
            .with_grants(
                grants
                    .iter()
                    .filter_map(|grant| ActiveGrant::of(grant, now)),
            )
            .map_err(|error| invalid_request(&error))
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "Audit provenance must preserve the exact tenant/client, policy scope, question, original grant and observation time"
    )]
    async fn record(
        &self,
        tenant: &Tenant,
        client: &Client,
        policy: &StoredPolicy,
        scope: &ConditionalScope,
        request: &EvaluationRequest,
        decision: &Decision,
        grant: Option<&Grant>,
        now: OffsetDateTime,
    ) {
        let nested = StoredPolicy {
            rules: scope.rules.clone(),
            updated_at: policy.updated_at,
        };
        let mut explanation = asterius_domain::policy::explanation::explain(
            Some(&nested),
            request,
            "conditional_access",
        );
        explanation.policy_revision = Some(asterius_domain::policy::explanation::revision(
            &policy.rules,
        ));
        add_guard_trace(&mut explanation, scope, request);
        let mut detail = Detail::new()
            .label(
                "enforcement",
                if scope.mode == EnforcementMode::Active {
                    "active"
                } else {
                    "report_only"
                },
            )
            .text(
                "action",
                request
                    .context
                    .trusted()
                    .map_or("unknown", |context| context.action.as_str()),
            )
            .text("scope", &scope.id);
        if let Some(trusted) = request.context.trusted() {
            detail = detail
                .credential("acr_revision", &trusted.acr_revision)
                .credential("client_revision", &trusted.client_revision)
                .number("evaluated_at", trusted.evaluated_at.unix_timestamp());
            for name in scope.required_for(request) {
                let state = match trusted.availability(name) {
                    Availability::Known => "known",
                    Availability::Absent => "absent",
                    Availability::Stale => "stale",
                    Availability::Unavailable => "unavailable",
                    Availability::Invalid => "invalid",
                };
                detail = detail.label(&format!("fact.{name:?}.state"), state);
                if let Some(fact) = trusted.facts.get(&name) {
                    let source = match fact.source.as_str() {
                        "administrative_client_settings" => "administrative_client_settings",
                        "exact_grant_authentication" => "exact_grant_authentication",
                        "current_verified_connection" => "current_verified_connection",
                        "device_registry_adapter" => "device_registry_adapter",
                        "current_tenant_directory" => "current_tenant_directory",
                        _ => "unrecognized_source",
                    };
                    detail = detail.label(&format!("fact.{name:?}.source"), source);
                    if let Some(observed) = fact.observed_at {
                        detail = detail.number(
                            &format!("fact.{name:?}.observed_at"),
                            observed.unix_timestamp(),
                        );
                    }
                    if let Some(expires) = fact.expires_at {
                        detail = detail.number(
                            &format!("fact.{name:?}.expires_at"),
                            expires.unix_timestamp(),
                        );
                    }
                }
            }
        }
        let mut event = AuditEvent::new(
            tenant.id.clone(),
            EventType::ACCESS_EVALUATED,
            if decision.permit() {
                Outcome::Success
            } else {
                Outcome::Failure
            },
            Actor::Client(client.id.clone()),
            now,
        )
        .client(client.id.clone())
        .detail(detail);
        if let Some(grant) = grant {
            event = event.grant(grant.id.clone());
            if let Some(session) = &grant.session {
                event = event.session(session.clone());
            }
        }
        if let Err(error) = self
            .audit
            .record_with_diagnostics(event, &explanation)
            .await
        {
            tracing::error!(%error, tenant = %tenant.id, "conditional decision audit unavailable");
        }
    }
}

fn known(value: FactValue, source: &str, now: OffsetDateTime) -> Fact {
    Fact::known(value, source, now, now + Duration::seconds(30))
}

fn invalid_request(error: &asterius_domain::policy::RequestError) -> DomainError {
    DomainError::invalid("conditional_access", error.to_string())
}

pub(crate) const fn action(kind: GrantType) -> &'static str {
    match kind {
        GrantType::AuthorizationCode => "authorization_code",
        GrantType::RefreshToken => "refresh_token",
        GrantType::ClientCredentials => "client_credentials",
        GrantType::TokenExchange => "token_exchange",
        GrantType::JwtBearer => "jwt_bearer",
        GrantType::DeviceCode => "device_code",
        GrantType::Ciba => "ciba",
    }
}

#[async_trait::async_trait]
impl super::agent_issuance::ConditionalGuard for ConditionalAccess {
    async fn permits(
        &self,
        tenant: &Tenant,
        client: &Client,
        grant: &Grant,
        kind: GrantType,
        now: OffsetDateTime,
    ) -> Result<bool, DomainError> {
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
    pub(crate) fn new(access: ConditionalAccess, tenant: Tenant, now: OffsetDateTime) -> Self {
        Self {
            access,
            tenant,
            now,
        }
    }
}
#[async_trait::async_trait]
impl asterius_domain::ports::PolicyEngine for ConditionalPolicyEngine {
    #[expect(
        clippy::too_many_lines,
        reason = "One stored snapshot must compose legacy and conditional decisions, exact verified authority, freshness and a matching audit explanation"
    )]
    async fn evaluate(
        &self,
        tenant: &asterius_domain::TenantId,
        question: &EvaluationRequest,
    ) -> Result<Decision, DomainError> {
        if tenant != &self.tenant.id {
            return Err(DomainError::NotFound);
        }
        let authority = PDP_AUTHORITY
            .try_with(|slot| slot.borrow().clone())
            .ok()
            .flatten();
        let policies = PgPolicies::new(self.access.store.pool().clone());
        for _ in 0..2 {
            let policy = policies.load(tenant).await?;
            let base = asterius_domain::policy::explanation::evaluate(
                policy.as_ref(),
                question,
                "access_evaluation",
            );
            let Some(policy) = policy else {
                return Ok(base);
            };
            let guarded = policy
                .rules
                .conditional_scopes()
                .iter()
                .any(|scope| scope.actions.contains("access_evaluation"));
            if !guarded {
                return Ok(base);
            }
            let Some(authority) = authority
                .as_ref()
                .filter(|authority| &authority.tenant == tenant)
            else {
                return Ok(Decision::default_deny(
                    "verified conditional application context unavailable",
                ));
            };
            let Some(scope) = policy
                .rules
                .conditional_scopes()
                .iter()
                .find(|scope| scope.applies(&authority.client, "access_evaluation"))
            else {
                return Ok(base);
            };
            let repositories = self.access.store.scope(tenant.clone());
            let client = repositories
                .clients(self.access.capabilities)
                .find(&authority.client)
                .await?
                .ok_or(DomainError::NotFound)?;
            let user = repositories
                .users(Arc::clone(&self.access.kek))
                .find_by_subject(&asterius_domain::SubjectId::new(question.subject.id()))
                .await?;
            let private = match authority.task.as_ref() {
                Some(task) => {
                    repositories
                        .grants()
                        .agent_tasks()
                        .token_grant(tenant, &task.jti, task.id, task.revision)
                        .await?
                }
                None => None,
            };
            let reference = if authority.task.is_some() {
                private.as_ref()
            } else {
                authority.grant.as_ref()
            };
            let grant = match reference {
                Some(id) => repositories.grants().find(id).await?,
                None => None,
            };
            // The verified PDP token can be narrower than the durable grant.
            let grant = grant.map(|mut grant| {
                grant.scopes.clone_from(&authority.scopes);
                grant.resources.clone_from(&authority.resources);
                grant
            });
            let exact = grant.as_ref().filter(|grant| {
                grant.tenant == *tenant
                    && grant.client == authority.client
                    && grant
                        .subject
                        .as_ref()
                        .is_some_and(|subject| subject.as_str() == question.subject.id())
                    && authority.subject.as_deref() == Some(question.subject.id())
                    && ActiveGrant::of(grant, self.now).is_some()
            });
            let authentication = exact
                .filter(|grant| grant.actor_chain.is_empty() && client.registration.agent.is_none())
                .and_then(|grant| grant.authentication.as_ref());
            let input = Principal {
                user: user.as_ref().map(|user| user.id),
                subject: Some(question.subject.id()),
                authentication,
                grant: exact,
            };
            let resolved = self
                .access
                .resolve(
                    &self.tenant,
                    &client,
                    "access_evaluation",
                    &policy,
                    scope,
                    input,
                    self.now,
                )
                .await?;
            let mut request = question.clone();
            // Existing subject attributes remain PEP inputs; assurance and source
            // availability come exclusively from this verified transaction.
            request.subject = question
                .subject
                .clone()
                .with_groups(resolved.subject.groups().iter().cloned())
                .with_roles(resolved.subject.roles().clone())
                .with_grants(resolved.subject.grants().iter().cloned())
                .map_err(|error| invalid_request(&error))?;
            request.context = Context::new(question.context.properties().clone()).with_acr(
                resolved.context.acr().map(str::to_owned),
                resolved.context.ladder().iter().cloned(),
            );
            if let Some(trusted) = resolved.context.trusted() {
                request.context = request.context.with_trusted(trusted.clone());
            }
            let base = if scope.mode == EnforcementMode::Active {
                asterius_domain::policy::explanation::evaluate(
                    Some(&policy),
                    &request,
                    "access_evaluation",
                )
            } else {
                base
            };
            let current = policies.load(tenant).await?;
            if current
                .as_ref()
                .map(|value| asterius_domain::policy::explanation::revision(&value.rules))
                != Some(asterius_domain::policy::explanation::revision(
                    &policy.rules,
                ))
            {
                continue;
            }
            let conditional = scope.evaluate(&request);
            self.access
                .record(
                    &self.tenant,
                    &client,
                    &policy,
                    scope,
                    &request,
                    &conditional,
                    exact,
                    self.now,
                )
                .await;
            advance_clock(&mut request, OffsetDateTime::now_utc());
            // The base policy can consume temporary roles too. Audit/storage
            // awaits must not preserve a permit from an expired snapshot.
            let base = if scope.mode == EnforcementMode::Active {
                asterius_domain::policy::explanation::evaluate(
                    Some(&policy),
                    &request,
                    "access_evaluation",
                )
            } else {
                base
            };
            let final_conditional = scope.evaluate(&request);
            if base.permit()
                && (!conditional.permit() || !final_conditional.permit())
                && scope.mode == EnforcementMode::Active
            {
                let conditional = if conditional.permit() {
                    final_conditional
                } else {
                    conditional
                };
                let nested = StoredPolicy {
                    rules: scope.rules.clone(),
                    updated_at: policy.updated_at,
                };
                let mut explanation = asterius_domain::policy::explanation::explain(
                    Some(&nested),
                    &request,
                    "conditional_access",
                );
                explanation.policy_revision = Some(asterius_domain::policy::explanation::revision(
                    &policy.rules,
                ));
                add_guard_trace(&mut explanation, scope, &request);
                return Ok(conditional.with_explanation(explanation));
            }
            return Ok(base);
        }
        Ok(Decision::default_deny(
            "conditional policy changed during evaluation",
        ))
    }
}

// Updating the clock never changes original authentication or source validity.
fn advance_clock(request: &mut EvaluationRequest, now: OffsetDateTime) {
    let mut roles = request.subject.roles().clone();
    roles.retain_current_temporary_roles(now);
    request.subject = request.subject.clone().with_roles(roles);
    if let Some(trusted) = request.context.trusted() {
        let mut trusted = trusted.clone();
        trusted.evaluated_at = now;
        request.context = request.context.clone().with_trusted(trusted);
    }
}

fn add_guard_trace(
    explanation: &mut asterius_domain::policy::explanation::DecisionExplanation,
    scope: &ConditionalScope,
    request: &EvaluationRequest,
) {
    let available = request.context.trusted().is_some_and(|trusted| {
        scope
            .required_for(request)
            .into_iter()
            .all(|name| trusted.availability(name) == Availability::Known)
    });
    // The guard precedes boolean rules: NOT and ANY cannot negate absence.
    explanation.rules.insert(
        0,
        asterius_domain::policy::explanation::RuleExplanation {
            id: "conditional-required-facts".to_owned(),
            effect: "deny",
            applicable: true,
            matched: !available,
            conditions: vec![asterius_domain::policy::explanation::ConditionExplanation {
                path: "required_facts".to_owned(),
                kind: "trusted_fact_guard",
                matched: available,
                missing: !available,
            }],
        },
    );
    if explanation.rules.len() > 128 {
        explanation.rules.pop();
        explanation.truncated = true;
    }
    let mut remaining = asterius_domain::policy::explanation::MAX_TRACE_NODES;
    for rule in &mut explanation.rules {
        if rule.conditions.len() > remaining {
            rule.conditions.truncate(remaining);
            explanation.truncated = true;
        }
        remaining -= rule.conditions.len();
    }
}

#[async_trait::async_trait]
impl super::authorize::ConditionalAuthorization for ConditionalAccess {
    async fn prepare(
        &self,
        tenant: &Tenant,
        client_id: &asterius_domain::ClientId,
        session: Option<&asterius_domain::Session>,
        now: OffsetDateTime,
    ) -> Result<Option<asterius_web::interaction::ConditionalBinding>, DomainError> {
        let Some(policy) = PgPolicies::new(self.store.pool().clone())
            .load(&tenant.id)
            .await?
        else {
            return Ok(None);
        };
        let Some(scope) = policy
            .rules
            .conditional_scopes()
            .iter()
            .find(|scope| scope.applies(client_id, "authorize"))
        else {
            return Ok(None);
        };
        if scope.mode == EnforcementMode::ReportOnly {
            return Ok(None);
        }
        let repositories = self.store.scope(tenant.id.clone());
        let client = repositories
            .clients(self.capabilities)
            .find(client_id)
            .await?
            .ok_or(DomainError::NotFound)?;
        let settings = PgTenantSettings::new(self.store.pool().clone())
            .settings(&tenant.id)
            .await?;
        let acr = settings.acr_policy();
        let revision = asterius_domain::policy::explanation::revision(&policy.rules);
        let mut binding = asterius_web::interaction::ConditionalBinding {
            client: client_id.as_str().to_owned(),
            action: "authorize".to_owned(),
            policy_revision: revision,
            acr: None,
            acceptable_acr: Vec::new(),
            max_age: None,
        };
        if let Some(session) = session.filter(|session| session.status(now).is_usable()) {
            let sector = asterius_domain::SectorIdentifier::of_client(&client).map_err(|_| {
                DomainError::invalid("conditional_access", "application sector unavailable")
            })?;
            let subject = repositories
                .users(Arc::clone(&self.kek))
                .subject(asterius_domain::UserId::new(session.user), &sector)
                .await?;
            let authentication = GrantAuthentication {
                assurance_authenticated_at: session.assurance_authenticated_at,
                assurance_policy_revision: session.assurance_policy_revision.clone(),
                assurance_methods: session.assurance_methods.clone(),
                authenticated_at: session.authenticated_at,
                acr: session.acr.clone(),
                amr: session.amr.clone(),
            };
            let input = Principal {
                user: Some(asterius_domain::UserId::new(session.user)),
                subject: Some(subject.as_str()),
                authentication: Some(&authentication),
                grant: None,
            };
            let request = self
                .resolve(tenant, &client, "authorize", &policy, scope, input, now)
                .await?;
            let decision = scope.evaluate(&request);
            self.record(
                tenant, &client, &policy, scope, &request, &decision, None, now,
            )
            .await;
            if decision.permit() {
                return Ok(Some(binding));
            }
            binding.acr = Some(scope.remedy(&request, acr).ok_or_else(|| {
                DomainError::invalid(
                    "conditional_access",
                    "conditional denial cannot be repaired by authentication",
                )
            })?);
            binding.max_age = Some(0);
        } else {
            // Resolve identity after login, while binding any configured remedy
            // to the original pushed client and enforcing it as essential.
            if let Some(target) = &scope.assurance_remedy {
                if !acr.can_produce(target) {
                    return Err(DomainError::invalid(
                        "conditional_access",
                        "conditional authentication requirement unavailable",
                    ));
                }
                binding.acr = Some(target.clone());
            }
        }
        if let Some(target) = &binding.acr {
            binding.acceptable_acr = acr
                .levels()
                .iter()
                .skip_while(|level| level.value() != target)
                .map(|level| level.value().to_owned())
                .collect();
        }
        Ok(Some(binding))
    }
    async fn permits(
        &self,
        tenant: &Tenant,
        client: &Client,
        grant: &Grant,
        now: OffsetDateTime,
    ) -> Result<bool, DomainError> {
        let input = Principal {
            user: grant.user,
            subject: grant
                .subject
                .as_ref()
                .map(asterius_domain::SubjectId::as_str),
            authentication: grant.authentication.as_ref(),
            grant: Some(grant),
        };
        self.check(tenant, client, "authorize", input, now).await
    }
}

/// Composes policy publication with the prepared task/lineage signing fence.
#[derive(Debug)]
pub(crate) struct ConditionalSigner<'a> {
    inner: ConditionalSignerInner<'a>,
    access: ConditionalAccess,
    tenant: Tenant,
    admission: Option<Arc<tokio::sync::OwnedSemaphorePermit>>,
}
#[derive(Debug)]
enum ConditionalSignerInner<'a> {
    Borrowed(&'a dyn asterius_domain::Signer),
    Prepared(Box<dyn asterius_domain::Signer + 'a>),
}
impl ConditionalSignerInner<'_> {
    fn get(&self) -> &dyn asterius_domain::Signer {
        match self {
            Self::Borrowed(inner) => *inner,
            Self::Prepared(inner) => inner.as_ref(),
        }
    }
}
// Generated role claims must still be present in the current exact-grant
// snapshot. No historical activation or unrelated principal supplies authority.
fn signed_roles_current(
    claims: &serde_json::Value,
    held: &asterius_domain::HeldRoles,
    client: &asterius_domain::ClientId,
    now: OffsetDateTime,
) -> bool {
    if let Some(roles) = claims.get("roles") {
        let Some(roles) = roles.as_array() else {
            return false;
        };
        if !roles.iter().all(|role| {
            role.as_str()
                .is_some_and(|name| held.tenant.iter().any(|current| current.as_str() == name))
        }) {
            return false;
        }
    }
    let Some(access) = claims.get("resource_access") else {
        return true;
    };
    let Some(access) = access.as_object() else {
        return false;
    };
    if access.len() != 1 {
        return false;
    }
    let Some(roles) = access
        .get(client.as_str())
        .and_then(|value| value.get("roles"))
        .and_then(serde_json::Value::as_array)
    else {
        return false;
    };
    let Some(current) = held.clients.get(client) else {
        return roles.is_empty();
    };
    for value in roles {
        let Some(name) = value.as_str() else {
            return false;
        };
        let Some(role) = current.iter().find(|role| role.as_str() == name) else {
            return false;
        };
        if let Some(deadline) = held
            .temporary_deadlines
            .get(client)
            .and_then(|deadlines| deadlines.get(role))
        {
            let Some(expiry) = claims.get("exp").and_then(serde_json::Value::as_i64) else {
                return false;
            };
            if !held.role_current_at(client, role, now)
                || expiry > deadline.unix_timestamp()
                || expiry <= now.unix_timestamp()
                || *deadline <= now
            {
                return false;
            }
        }
    }
    true
}

impl<'a> ConditionalSigner<'a> {
    pub(crate) fn new(
        inner: &'a dyn asterius_domain::Signer,
        access: ConditionalAccess,
        tenant: Tenant,
    ) -> Self {
        Self {
            inner: ConditionalSignerInner::Borrowed(inner),
            access,
            tenant,
            admission: None,
        }
    }
    async fn current_roles(
        &self,
        tenant: &asterius_domain::TenantId,
        grant: &Grant,
        claims: &serde_json::Value,
    ) -> Result<asterius_domain::HeldRoles, DomainError> {
        if claims.get("roles").is_none() && claims.get("resource_access").is_none() {
            return Ok(asterius_domain::HeldRoles::empty());
        }
        let held = self
            .access
            .store
            .scope(tenant.clone())
            .application_roles()
            .held_by_grant(grant)
            .await?;
        if !signed_roles_current(claims, &held, &grant.client, OffsetDateTime::now_utc()) {
            return Err(DomainError::invalid(
                "temporary_entitlement",
                "current role authority or exclusive expiry changed",
            ));
        }
        Ok(held)
    }

    async fn fence(
        &self,
        tenant: &asterius_domain::TenantId,
    ) -> Result<asterius_store_pg::PolicyPublicationFence, DomainError> {
        if tenant != &self.tenant.id {
            return Err(DomainError::NotFound);
        }
        PgPolicies::new(self.access.store.pool().clone())
            .signing_fence(tenant, &self.tenant.issuer)
            .await
    }
}
#[async_trait::async_trait]
impl asterius_domain::Signer for ConditionalSigner<'_> {
    async fn prepare(
        &self,
        tenant: &asterius_domain::TenantId,
        algorithm: Option<asterius_domain::SigningAlgorithm>,
    ) -> Result<Option<Box<dyn asterius_domain::Signer + '_>>, DomainError> {
        if self.admission.is_some() {
            return Ok(None);
        }
        if self.access.store.pool().options().get_max_connections() < 3 {
            return Err(DomainError::Storage(
                "composed signing requires database.max_connections >= 3".into(),
            ));
        }
        let admission = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            Arc::clone(self.access.store.signing_admission()).acquire_owned(),
        )
        .await
        .map_err(|_| DomainError::Storage("signing admission timed out".into()))?
        .map_err(|_| DomainError::Storage("signing admission unavailable".into()))?;
        let inner = match self.inner.get().prepare(tenant, algorithm).await? {
            Some(inner) => ConditionalSignerInner::Prepared(inner),
            None => ConditionalSignerInner::Borrowed(self.inner.get()),
        };
        Ok(Some(Box::new(ConditionalSigner {
            inner,
            access: self.access.clone(),
            tenant: self.tenant.clone(),
            admission: Some(Arc::new(admission)),
        })))
    }
    async fn sign(
        &self,
        tenant: &asterius_domain::TenantId,
        algorithm: Option<asterius_domain::SigningAlgorithm>,
        typ: &'static str,
        claims: &serde_json::Value,
    ) -> Result<asterius_domain::CompactJws, DomainError> {
        if !matches!(typ, "at+jwt" | "oauth-id-jag+jwt") {
            return self.inner.get().sign(tenant, algorithm, typ, claims).await;
        }
        // Resolve keys before holding even a publication lock. Prepared task
        // decorators retain all their checks when called through this port.
        if let Some(prepared) = self.prepare(tenant, algorithm).await? {
            return prepared.sign(tenant, algorithm, typ, claims).await;
        }
        let transaction = self.fence(tenant).await?;
        let client = if typ == "oauth-id-jag+jwt" {
            claims.get("act").and_then(|actor| actor.get("client_id"))
        } else {
            claims.get("client_id")
        };
        let client = client.and_then(serde_json::Value::as_str).ok_or_else(|| {
            DomainError::invalid("conditional_access", "signing application context absent")
        })?;
        let policy = PgPolicies::new(self.access.store.pool().clone())
            .load(tenant)
            .await?;
        if policy.as_ref().is_some_and(|policy| {
            policy.rules.conditional_scopes().iter().any(|scope| {
                scope.mode == EnforcementMode::Active
                    && scope
                        .clients
                        .contains(&asterius_domain::ClientId::new(client))
            })
        }) {
            return Err(DomainError::invalid(
                "conditional_access",
                "scoped issuance requires exact grant context",
            ));
        }
        let signed = self
            .inner
            .get()
            .sign(tenant, algorithm, typ, claims)
            .await?;
        transaction.commit().await?;
        Ok(signed)
    }
    async fn sign_identity(
        &self,
        tenant: &asterius_domain::TenantId,
        grant: &Grant,
        algorithm: Option<asterius_domain::SigningAlgorithm>,
        typ: &'static str,
        claims: &serde_json::Value,
    ) -> Result<asterius_domain::CompactJws, DomainError> {
        if claims.get("asterius_jit").is_some()
            || grant.tenant != *tenant
            || claims.get("iss").and_then(serde_json::Value::as_str)
                != Some(self.tenant.issuer.as_str())
            || !matches!(typ, "JWT" | "dpop+id_token")
            || claims.get("aud").and_then(serde_json::Value::as_str) != Some(grant.client.as_str())
            || grant.subject.as_ref().is_none_or(|subject| {
                claims.get("sub").and_then(serde_json::Value::as_str) != Some(subject.as_str())
            })
        {
            return Err(DomainError::invalid(
                "id_token",
                "exact identity grant required",
            ));
        }
        if let Some(prepared) = self.prepare(tenant, algorithm).await? {
            return prepared
                .sign_identity(tenant, grant, algorithm, typ, claims)
                .await;
        }
        let mut transaction = self.fence(tenant).await?;
        let held = self.current_roles(tenant, grant, claims).await?;
        let mut identity_claims = claims.clone();
        let identity = asterius_store_pg::PgTemporaryEntitlements::kubernetes_identity_for_grant_on(
            transaction.connection(), tenant, grant, &held,
        ).await?;
        if let Some(identity) = &identity {
            if algorithm != Some(asterius_domain::SigningAlgorithm::Es256) {
                return Err(DomainError::invalid("id_token", "temporary cluster identity requires ES256"));
            }
            let expiry = identity_claims.get("exp").and_then(serde_json::Value::as_i64)
                .ok_or_else(|| DomainError::invalid("id_token", "integer expiry required"))?;
            let issued_at = identity_claims.get("iat").and_then(serde_json::Value::as_i64)
                .ok_or_else(|| DomainError::invalid("id_token", "integer issue time required"))?;
            let capped = expiry.min(identity.expires_at).min(issued_at.saturating_add(300));
            if capped <= OffsetDateTime::now_utc().unix_timestamp() {
                return Err(DomainError::invalid("id_token", "temporary identity expired"));
            }
            identity_claims["exp"] = serde_json::json!(capped);
            identity_claims["asterius_jit"] = serde_json::to_value(identity)
                .map_err(|error| DomainError::Storage(error.to_string()))?;
        }
        let signed = self
            .inner
            .get()
            .sign_identity(tenant, grant, algorithm, typ, &identity_claims)
            .await?;
        if !signed_roles_current(&identity_claims, &held, &grant.client, OffsetDateTime::now_utc())
            || identity.as_ref().is_some_and(|identity| {
                let now = OffsetDateTime::now_utc();
                identity.expires_at <= now.unix_timestamp()
                    || asterius_domain::RoleName::parse(&identity.role)
                        .map_or(true, |role| !held.role_current_at(&grant.client, &role, now))
            }) {
            return Err(DomainError::invalid(
                "temporary_entitlement",
                "temporary authority expired during signing",
            ));
        }
        transaction.commit().await?;
        Ok(signed)
    }

    async fn sign_access(
        &self,
        tenant: &asterius_domain::TenantId,
        issuance: asterius_domain::keys::AccessIssuance<'_>,
        algorithm: Option<asterius_domain::SigningAlgorithm>,
        typ: &'static str,
        claims: &serde_json::Value,
    ) -> Result<asterius_domain::CompactJws, DomainError> {
        if let Some(prepared) = self.prepare(tenant, algorithm).await? {
            return prepared
                .sign_access(tenant, issuance, algorithm, typ, claims)
                .await;
        }
        let transaction = self.fence(tenant).await?;
        let client = self
            .access
            .store
            .scope(tenant.clone())
            .clients(self.access.capabilities)
            .find(&issuance.grant.client)
            .await?
            .ok_or(DomainError::NotFound)?;
        let claimed_client = if typ == "oauth-id-jag+jwt" {
            claims.get("act").and_then(|actor| actor.get("client_id"))
        } else {
            claims.get("client_id")
        };
        if claimed_client.and_then(serde_json::Value::as_str)
            != Some(issuance.grant.client.as_str())
            || claims.get("iss").and_then(serde_json::Value::as_str)
                != Some(self.tenant.issuer.as_str())
            || issuance.grant.subject.as_ref().is_some_and(|subject| {
                claims.get("sub").and_then(serde_json::Value::as_str) != Some(subject.as_str())
            })
        {
            return Err(DomainError::invalid(
                "conditional_access",
                "signed claim transaction mismatch",
            ));
        }
        // Evaluate the actual narrowed token, while passing the complete durable
        // grant/implicit-resource lineage unchanged to the task signing fence.
        let mut narrowed = issuance.grant.clone();
        narrowed.scopes = claims
            .get("scope")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| DomainError::invalid("conditional_access", "signed scope absent"))?
            .split_whitespace()
            .map(str::to_owned)
            .collect();
        narrowed.resources = if typ == "oauth-id-jag+jwt" {
            std::collections::BTreeSet::from([claims
                .get("resource")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| {
                    DomainError::invalid("conditional_access", "signed resource absent")
                })?
                .to_owned()])
        } else {
            match claims.get("aud") {
                Some(serde_json::Value::String(value)) => {
                    std::collections::BTreeSet::from([value.clone()])
                }
                Some(serde_json::Value::Array(values)) => values
                    .iter()
                    .map(|value| {
                        value.as_str().map(str::to_owned).ok_or_else(|| {
                            DomainError::invalid("conditional_access", "signed audience invalid")
                        })
                    })
                    .collect::<Result<_, _>>()?,
                _ => {
                    return Err(DomainError::invalid(
                        "conditional_access",
                        "signed audience absent",
                    ));
                }
            }
        };
        // This fresh clock follows any key/lock wait. Auth age is always from
        // the original transaction, never from an unrelated elevated session.
        if !self
            .access
            .check_grant(
                &self.tenant,
                &client,
                &narrowed,
                issuance.kind,
                OffsetDateTime::now_utc(),
            )
            .await?
        {
            return Err(DomainError::invalid(
                "conditional_access",
                "conditional issuance refused",
            ));
        }
        let held = self.current_roles(tenant, &narrowed, claims).await?;
        let signed = self
            .inner
            .get()
            .sign_access(tenant, issuance, algorithm, typ, claims)
            .await?;
        if !signed_roles_current(claims, &held, &narrowed.client, OffsetDateTime::now_utc()) {
            return Err(DomainError::invalid(
                "temporary_entitlement",
                "temporary authority expired during signing",
            ));
        }
        transaction.commit().await?;
        Ok(signed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn temporary_signed_roles_require_current_authority_and_exclusive_expiry() {
        let client = asterius_domain::ClientId::new("app");
        let role = asterius_domain::RoleName::parse("privileged").expect("role");
        let now = OffsetDateTime::UNIX_EPOCH;
        let deadline = now + Duration::seconds(60);
        let mut held = asterius_domain::HeldRoles::default();
        held.clients
            .insert(client.clone(), [role.clone()].into_iter().collect());
        held.temporary_deadlines
            .insert(client.clone(), [(role, deadline)].into_iter().collect());
        held.temporary_proof_expires_at = Some(now + Duration::seconds(120));
        let claims = json!({"exp":30,"resource_access":{"app":{"roles":["privileged"]}}});
        assert!(signed_roles_current(&claims, &held, &client, now));
        assert!(!signed_roles_current(
            &claims,
            &asterius_domain::HeldRoles::empty(),
            &client,
            now
        ));
        assert!(!signed_roles_current(
            &json!({"exp":61,"resource_access":{"app":{"roles":["privileged"]}}}),
            &held,
            &client,
            now
        ));
        assert!(!signed_roles_current(&claims, &held, &client, deadline));
        assert!(!signed_roles_current(
            &json!({"exp":30,"resource_access":{"other":{"roles":["privileged"]}}}),
            &held,
            &client,
            now
        ));
        held.temporary_deadlines.clear();
        assert!(
            signed_roles_current(
                &json!({"exp":3600,"resource_access":{"app":{"roles":["privileged"]}}}),
                &held,
                &client,
                now
            ),
            "independent standing authority keeps its lifetime"
        );
    }

    #[test]
    fn temporary_signing_freshness_is_rechecked_without_shortening_activation_ttl() {
        let now = OffsetDateTime::UNIX_EPOCH;
        let client = asterius_domain::ClientId::new("app");
        let role = asterius_domain::RoleName::parse("privileged").expect("role");
        let deadline = now + Duration::seconds(600);
        let mut held = asterius_domain::HeldRoles::default();
        held.clients.insert(client.clone(), [role.clone()].into());
        held.temporary_deadlines
            .insert(client.clone(), [(role, deadline)].into());
        held.temporary_proof_expires_at = Some(now + Duration::seconds(120));
        let claims = json!({"exp":500,"resource_access":{"app":{"roles":["privileged"]}}});
        assert!(signed_roles_current(&claims, &held, &client, now));
        assert_eq!(held.temporary_expiry_for(&client), Some(deadline));
        assert!(signed_roles_current(
            &claims,
            &held,
            &client,
            now + Duration::seconds(120)
        ));
        assert!(!signed_roles_current(
            &claims,
            &held,
            &client,
            now + Duration::seconds(121)
        ));
        held.temporary_proof_expires_at = None;
        assert!(!signed_roles_current(&claims, &held, &client, now));
        held.temporary_deadlines.clear();
        assert!(signed_roles_current(
            &claims,
            &held,
            &client,
            now + Duration::seconds(121)
        ));
    }

    #[test]
    fn final_clock_recheck_removes_stale_proof_roles_without_removing_standing() {
        let now = OffsetDateTime::UNIX_EPOCH;
        let client = asterius_domain::ClientId::new("app");
        let temporary = asterius_domain::RoleName::parse("temporary").expect("role");
        let standing = asterius_domain::RoleName::parse("standing").expect("role");
        let mut held = asterius_domain::HeldRoles::default();
        held.clients
            .insert(client.clone(), [temporary.clone(), standing.clone()].into());
        held.temporary_deadlines.insert(
            client.clone(),
            [(temporary.clone(), now + Duration::seconds(600))].into(),
        );
        held.temporary_proof_expires_at = Some(now + Duration::seconds(120));
        held.retain_current_temporary_roles(now + Duration::seconds(120));
        assert!(held.clients[&client].contains(&temporary));
        held.retain_current_temporary_roles(now + Duration::seconds(121));
        assert!(!held.clients[&client].contains(&temporary));
        assert!(held.clients[&client].contains(&standing));
    }

    #[test]
    fn final_clock_recheck_removes_expired_temporary_roles_but_preserves_standing() {
        let now = OffsetDateTime::UNIX_EPOCH;
        let client = asterius_domain::ClientId::new("app");
        let temporary = asterius_domain::RoleName::parse("temporary").expect("role");
        let standing = asterius_domain::RoleName::parse("standing").expect("role");
        let mut held = asterius_domain::HeldRoles::default();
        held.clients
            .insert(client.clone(), [temporary.clone(), standing.clone()].into());
        held.temporary_deadlines.insert(
            client.clone(),
            [(temporary.clone(), now + Duration::seconds(1))].into(),
        );
        held.temporary_proof_expires_at = Some(now + Duration::seconds(120));
        let mut request = EvaluationRequest::new(
            Subject::new("user", "alice", Properties::empty())
                .expect("subject")
                .with_roles(held),
            Action::new("access_evaluation", Properties::empty()).expect("action"),
            Resource::new("application", "app", Properties::empty()).expect("resource"),
            Context::default(),
        );
        let policy = StoredPolicy {
            rules: asterius_domain::policy::RuleSet::from_json(&json!({
                "version":1,"rules":[{"id":"elevation","effect":"permit",
                    "when":{"role":{"name":"temporary","owner":"app"}}}]
            }))
            .expect("policy"),
            updated_at: now,
        };
        let owner = asterius_domain::RoleOwner::Client(client);
        assert!(
            asterius_domain::policy::explanation::evaluate(
                Some(&policy),
                &request,
                "access_evaluation",
            )
            .permit()
        );
        assert!(request.subject.holds_role(Some(&owner), &temporary));
        advance_clock(&mut request, now + Duration::seconds(2));
        assert!(!request.subject.holds_role(Some(&owner), &temporary));
        assert!(request.subject.holds_role(Some(&owner), &standing));
        assert!(
            !asterius_domain::policy::explanation::evaluate(
                Some(&policy),
                &request,
                "access_evaluation",
            )
            .permit()
        );
    }

    #[test]
    fn final_clock_recheck_preserves_authentication_age_and_fact_expiry() {
        let observed = OffsetDateTime::UNIX_EPOCH;
        let policy = asterius_domain::policy::RuleSet::from_json(&json!({
            "version":1,"rules":[],"conditional_scopes":[{
                "id":"fresh-human","mode":"active","clients":["app"],"actions":["refresh_token"],
                "rules":[{"id":"fresh","effect":"permit","when":{"authentication_age_at_most":60}}]
            }]
        }))
        .expect("bounded policy");
        let original = observed - Duration::seconds(59);
        let context = TrustedAccessContext {
            tenant: asterius_domain::TenantId::new("tenant"),
            subject: Some("alice".into()),
            client: asterius_domain::ClientId::new("app"),
            action: "refresh_token".into(),
            evaluated_at: observed,
            policy_revision: "revision".into(),
            acr_revision: "acr".into(),
            client_revision: "client".into(),
            facts: BTreeMap::from([(
                FactName::AuthenticationAge,
                Fact::known(
                    FactValue::AuthenticationTime(original),
                    "original_grant_authentication",
                    observed,
                    observed + Duration::seconds(30),
                ),
            )]),
        };
        let mut request = EvaluationRequest::new(
            Subject::new("user", "alice", Properties::empty()).expect("subject"),
            Action::new("refresh_token", Properties::empty()).expect("action"),
            Resource::new("application", "app", Properties::empty()).expect("resource"),
            Context::default().with_trusted(context),
        );
        let scope = &policy.conditional_scopes()[0];
        assert!(scope.evaluate(&request).permit());
        advance_clock(&mut request, observed + Duration::seconds(2));
        assert!(!scope.evaluate(&request).permit());
        assert_eq!(
            request
                .context
                .trusted()
                .expect("snapshot")
                .value(FactName::AuthenticationAge),
            Some(&FactValue::AuthenticationTime(original))
        );
        advance_clock(&mut request, observed + Duration::seconds(30));
        assert_eq!(
            request
                .context
                .trusted()
                .expect("snapshot")
                .availability(FactName::AuthenticationAge),
            Availability::Stale
        );
        assert!(!scope.evaluate(&request).permit());
    }
}
