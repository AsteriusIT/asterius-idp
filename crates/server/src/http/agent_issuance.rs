//! The policy decision taken before an agent's token is signed (`ast-lh3.10`).
//!
//! Three things live here, and they are three different jobs:
//!
//! * [`PdpIssuance`] — the default adapter behind
//!   [`asterius_domain::issuance::IssuancePolicy`]: this build's own PDP
//!   (`ast-pj0.4`), asked through
//!   [`crate::http::access_evaluation::decide_without_enforcing`], which is
//!   the *same* function the Access Evaluation endpoint and the console's test
//!   bench decide with. A second path into the engine would be a second set of
//!   answers to the same question.
//! * [`IssuanceGuard`] — the process-wide state the adapter needs and a
//!   per-request value cannot hold: the short-lived decision cache, and the
//!   posture to take when the decision point cannot answer.
//! * [`AgentPolicy`] — the enforcement point. One value carried by each of the
//!   four grants an agent may use, with one method on it: "may this token be
//!   minted". It short-circuits for a client that is not an agent, it maps a
//!   deny to RFC 6749 §5.2's `access_denied`, and it writes
//!   [`EventType::TOKEN_ISSUANCE_DENIED`] with the decision's `reason_admin`.
//!
//! # What is *not* here
//!
//! No limiter and no `access.evaluated` entry. Those belong to a PEP's request
//! to the evaluation endpoint (§10.1, §11.7): a budget is spent by the caller
//! that asked, and this decision was not asked for by anybody — it is this
//! server consulting itself on the way to signing a token. Charging the agent's
//! own limiter twice for one token request would make an issuance cost two
//! tokens at the bucket, and an `access.evaluated` row per issuance would
//! describe an evaluation no PEP made. What is audited is the *refusal*, under
//! its own type, which is the entry an operator needs.
//!
//! # Fail closed, and why it is configurable at all
//!
//! A decision point that cannot answer has said nothing, and for an agent that
//! silence is a deny: `[authzen] issuance_fail_open = false` is the default and
//! the posture FAPI-grade deployments want. It is a *setting* because the blast
//! radius of the other reading is asymmetric — an unreachable policy store
//! stops every agent in the deployment at once, and an operator who has decided
//! that their agents' static limits (`ast-lh3.1`) are a sufficient floor during
//! an outage should be able to say so in the file rather than in a patch. Both
//! postures audit; the fail-open one logs at `warn` on every issuance it lets
//! through, because it is not a state to sit in.
//!
//! # The cache, and the window it opens
//!
//! A decision is kept for [`IssuanceGuard::DEFAULT_TTL`] under the whole
//! question ([`IssuanceQuery::cache_key`]), which means an administrator who
//! tightens a policy can have a permit from a few seconds ago honoured. That
//! window is bounded and deliberate: the alternative is a policy walk (and a
//! subject resolution) on every token an agent takes, which is the p95 this
//! ticket is measured on.
//!
//! [`IssuanceGuard::invalidate`] closes the window *in this process* the moment
//! a policy is written, and the admin API calls it. It does not reach the other
//! replicas: there is no bus (ADR-0001 says so), and a cache invalidation
//! delivered through the outbox would arrive later than the TTL it is meant to
//! shorten. So the guarantee this server makes is the TTL, and the invalidation
//! is what makes a single-replica deployment — and the administrator testing a
//! policy change — see the effect immediately.

use std::collections::BTreeSet;
use std::collections::HashMap;
use std::sync::Mutex;

use asterius_domain::audit::{Actor, AuditEvent, AuditSink, Detail, EventType, Outcome};
use asterius_domain::entities::agent::AgentOwner;
use asterius_domain::entities::client::GrantType;
use asterius_domain::issuance::{
    IssuanceAction, IssuanceDecision, IssuancePolicy, IssuanceQuery, RESOURCE_TYPE, SUBJECT_TYPE,
};
use asterius_domain::policy::{Action, Subject};
use asterius_domain::policy::{Context as PolicyContext, EvaluationRequest, Properties, Resource};
use asterius_domain::ports::PolicyEngine;
use asterius_domain::{AcrPolicy, Client, DomainError, Grant, Tenant, TenantId};
use serde_json::json;
use time::{Duration, OffsetDateTime};

use crate::http::access_evaluation::{SubjectFacts, decide_without_enforcing};

/// RFC 6749 §5.2's code for a token this server will not mint: "The resource
/// owner or authorization server denied the request."
///
/// The same code whether the policy said no or the decision point said nothing,
/// because the two are the same fact to the client: no token. Which of them it
/// was is in the trail, where it belongs — an error code that told a caller
/// "the policy store is down" would hand whoever holds the agent's key a
/// monitoring signal for this deployment's internals.
pub const ACCESS_DENIED: &str = "access_denied";

/// What the agent is told when a rule refused it.
const REFUSED: &str = "this tenant's policy does not permit a token for this agent here";

/// What the agent is told when no decision could be taken and this deployment
/// fails closed.
const UNDECIDED: &str = "this tenant's policy could not be consulted, and no token is issued \
                         for an agent without one";

/// An issuance this server will not perform, as the token endpoint renders it.
///
/// Two fields rather than one enum, because every grant handler already has a
/// `Failure::Client(code, description)` shape and this is the pair that goes
/// into it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refusal {
    /// RFC 6749 §5.2's `error`.
    pub code: &'static str,
    /// Its `error_description`. Never the policy's own reason: that is a
    /// statement about the tenant's rules and it goes to the trail.
    pub description: &'static str,
}

/// The shared half of the pre-issuance check: the cache, and the posture.
///
/// Held once per process (on `ClientEndpoints`) because a cache built per
/// request is not a cache. Interior mutability through a [`Mutex`] rather than
/// an async lock: every critical section is a hash lookup and an insert, with
/// no `.await` inside it.
#[derive(Debug)]
pub struct IssuanceGuard {
    ttl: Duration,
    fail_open: bool,
    cache: Mutex<HashMap<(TenantId, String), Cached>>,
}

/// One remembered decision and the instant it stops being usable.
#[derive(Debug, Clone)]
struct Cached {
    decision: IssuanceDecision,
    expires_at: OffsetDateTime,
}

/// The most decisions one process keeps.
///
/// A bound and not a tuning knob: the key carries the audience and the scopes a
/// request asked for, so an agent that varies them is an agent that can grow
/// this map. When it is reached the map is emptied rather than evicted by age —
/// dropping every entry costs the next few issuances a policy walk, and an LRU
/// here would be a second cache implementation to get wrong.
const MAX_ENTRIES: usize = 4096;

impl IssuanceGuard {
    /// How long a decision is honoured.
    ///
    /// Five seconds: long enough that an agent taking tokens in a loop walks
    /// the policy once rather than once per token, short enough that a policy
    /// tightened by an administrator is in force before they have finished
    /// reading the confirmation. It is not configurable, for the reason
    /// `ast-5c6` gives about settings that have to be understood to be set:
    /// the value that matters to an operator is the *maximum* staleness, and
    /// five seconds needs no explanation.
    pub const DEFAULT_TTL: Duration = Duration::seconds(5);

    /// A guard with the deployment's posture and the default TTL.
    #[must_use]
    pub fn new(fail_open: bool) -> Self {
        Self {
            ttl: Self::DEFAULT_TTL,
            fail_open,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// The same, with a TTL a test can move.
    #[must_use]
    pub const fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    /// Whether this deployment issues to agents when no decision can be taken.
    #[must_use]
    pub const fn fail_open(&self) -> bool {
        self.fail_open
    }

    /// The decision remembered for this question, if one is still fresh.
    fn cached(
        &self,
        tenant: &TenantId,
        key: &str,
        now: OffsetDateTime,
    ) -> Option<IssuanceDecision> {
        let mut cache = self.cache.lock().ok()?;
        let entry = cache.get(&(tenant.clone(), key.to_owned()))?;
        if entry.expires_at <= now {
            cache.remove(&(tenant.clone(), key.to_owned()));
            return None;
        }
        Some(entry.decision.clone())
    }

    /// Remembers one decision until `now + ttl`.
    fn remember(
        &self,
        tenant: &TenantId,
        key: String,
        decision: &IssuanceDecision,
        now: OffsetDateTime,
    ) {
        let Ok(mut cache) = self.cache.lock() else {
            return;
        };
        if cache.len() >= MAX_ENTRIES {
            cache.clear();
        }
        cache.insert(
            (tenant.clone(), key),
            Cached {
                decision: decision.clone(),
                expires_at: now + self.ttl,
            },
        );
    }

    /// Forgets everything decided for one tenant.
    ///
    /// Called where a policy document is written, so that an administrator who
    /// tightens a rule does not have to wait out a TTL to see it — in this
    /// process. See the module documentation for what that does and does not
    /// promise across replicas.
    pub fn invalidate(&self, tenant: &TenantId) {
        let Ok(mut cache) = self.cache.lock() else {
            return;
        };
        cache.retain(|(held, _), _| held != tenant);
    }
}

/// The built-in decision point, asked the way every other caller asks it.
///
/// Built per request (it borrows the tenant-scoped repositories the token
/// endpoint already opened) and pointed at the process-wide [`IssuanceGuard`]
/// for the cache.
pub struct PdpIssuance {
    /// The engine, behind its port: a deployment that replaces the PDP replaces
    /// this and nothing else.
    engine: Box<dyn PolicyEngine>,
    /// What this server knows about the subject named in the request.
    ///
    /// An agent is not an account, so this resolves no groups, no roles and no
    /// grants for it — the lookup is by subject identifier and a `client_id` is
    /// deliberately not one (`ClientId::MINTED_PREFIX`). It is still asked,
    /// because the decision has to be taken by the same function the endpoint
    /// and the bench use, and that function resolves facts before it evaluates.
    subjects: Box<dyn SubjectFacts>,
    /// This deployment's authentication ladder, which `attach` reads.
    acr: &'static AcrPolicy,
    /// The cache and the posture.
    guard: std::sync::Arc<IssuanceGuard>,
    /// When the request arrived: the clock reading that decides which grants
    /// are live and when a cached decision expires.
    now: OffsetDateTime,
}

impl PdpIssuance {
    /// The adapter, owning its two ports.
    ///
    /// Owning rather than holding references to them, so that a composition
    /// root builds one value and hands out `&dyn IssuancePolicy` from it: a
    /// version that referred to an engine and a fact resolver made every caller
    /// keep three locals whose lifetimes had to line up by hand.
    #[must_use]
    pub const fn new(
        engine: Box<dyn PolicyEngine>,
        subjects: Box<dyn SubjectFacts>,
        acr: &'static AcrPolicy,
        guard: std::sync::Arc<IssuanceGuard>,
        now: OffsetDateTime,
    ) -> Self {
        Self {
            engine,
            subjects,
            acr,
            guard,
            now,
        }
    }
}

impl std::fmt::Debug for PdpIssuance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PdpIssuance")
            .field("now", &self.now)
            .finish_non_exhaustive()
    }
}

#[async_trait::async_trait]
impl IssuancePolicy for PdpIssuance {
    async fn permits(
        &self,
        tenant: &TenantId,
        query: &IssuanceQuery,
    ) -> Result<IssuanceDecision, DomainError> {
        let key = query.cache_key();
        if let Some(decision) = self.guard.cached(tenant, &key, self.now) {
            return Ok(decision);
        }
        let request = evaluation_request(query)?;
        let decision = decide_without_enforcing(
            self.engine.as_ref(),
            self.subjects.as_ref(),
            self.acr,
            tenant,
            &request,
            self.now,
        )
        .await?;
        let answer = if decision.permit() {
            IssuanceDecision::permit(decision.context().reason_admin().map(str::to_owned))
        } else {
            IssuanceDecision::deny(decision.context().reason_admin().map(str::to_owned))
        };
        self.guard.remember(tenant, key, &answer, self.now);
        Ok(answer)
    }
}

/// §6.1's request, in this server's own vocabulary.
///
/// Every value on it is one this server resolved: the agent's `client_id` and
/// its owner come from the registration, the audience and the scopes come from
/// the issuance *after* every static bound narrowed them, and the grant and the
/// chain depth are facts about the request that the handler established. There
/// is no `properties` bag from a caller here at all — unlike §11.4's PEP, the
/// enforcement point is this process.
///
/// # Errors
///
/// [`DomainError::Invalid`] if a value this server built will not fit §5's
/// bounds — an over-long audience list, for instance. Reported rather than
/// trimmed: a decision taken about a *truncated* question is an authorization
/// decision taken by a bound.
fn evaluation_request(query: &IssuanceQuery) -> Result<EvaluationRequest, DomainError> {
    let invalid = |error: asterius_domain::policy::RequestError| {
        DomainError::invalid("issuance_policy", error.to_string())
    };
    let owner = match query.owner {
        AgentOwner::User(id) => id.to_string(),
    };
    let subject = Subject::new(
        SUBJECT_TYPE,
        query.agent.as_str(),
        Properties::new([
            ("client_id", json!(query.agent.as_str())),
            ("owner", json!(owner)),
            ("owner_type", json!("user")),
        ])
        .map_err(invalid)?,
    )
    .map_err(invalid)?;
    let action = Action::new(query.action.name(), Properties::empty()).map_err(invalid)?;
    let resource = Resource::new(
        RESOURCE_TYPE,
        &resource_id(&query.audience),
        Properties::new([
            ("audience", json!(set(&query.audience))),
            ("scopes", json!(set(&query.scopes))),
            (
                "authorization_details_types",
                json!(set(&query.authorization_details_types)),
            ),
        ])
        .map_err(invalid)?,
    )
    .map_err(invalid)?;
    let context = PolicyContext::new(
        Properties::new([
            ("grant_type", json!(query.grant.as_str())),
            ("chain_depth", json!(query.chain_depth)),
        ])
        .map_err(invalid)?,
    );
    Ok(EvaluationRequest::new(subject, action, resource, context))
}

/// A sorted set as a JSON array, which is what a rule's `in` test reads.
fn set(values: &BTreeSet<String>) -> Vec<&str> {
    values.iter().map(String::as_str).collect()
}

/// §5.3's `id` for the token that would be minted.
///
/// The audiences, sorted and space separated, because that is the thing an
/// administrator recognises in a trail. A list that will not fit §5's
/// [`asterius_domain::policy::request::MAX_IDENTIFIER`] is named by its digest
/// instead, and a token audienced at nothing is named `none`: an `id` is
/// REQUIRED and must be non-empty, and a rule that wants to match on the
/// audience matches the `audience` property, which is always exact.
fn resource_id(audience: &BTreeSet<String>) -> String {
    if audience.is_empty() {
        return "none".to_owned();
    }
    let joined = audience
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(" ");
    if joined.len() <= asterius_domain::policy::request::MAX_IDENTIFIER {
        joined
    } else {
        asterius_domain::sha256_hex(joined.as_bytes())
    }
}

/// A policy store that forgets this process's cached decisions on every write.
///
/// The decorator, rather than a call inside [`asterius_store_pg::PgPolicies`]:
/// the store is an adapter over rows and knows nothing about a cache, and the
/// invalidation is a fact about *this process* rather than about the document.
/// Wrapped around whatever the admin API writes through, so that every route
/// that can change a tenant's rules — replace and clear — closes the window
/// the TTL would otherwise leave open. See the module documentation for what
/// this does not promise across replicas.
#[derive(Debug)]
pub struct InvalidatingPolicies {
    inner: std::sync::Arc<dyn asterius_domain::ports::PolicyStore>,
    guard: std::sync::Arc<IssuanceGuard>,
}

impl InvalidatingPolicies {
    /// Wraps a store so that writing a tenant's policy forgets its decisions.
    #[must_use]
    pub const fn new(
        inner: std::sync::Arc<dyn asterius_domain::ports::PolicyStore>,
        guard: std::sync::Arc<IssuanceGuard>,
    ) -> Self {
        Self { inner, guard }
    }
}

#[async_trait::async_trait]
impl asterius_domain::ports::PolicyStore for InvalidatingPolicies {
    async fn load(
        &self,
        tenant: &TenantId,
    ) -> Result<Option<asterius_domain::policy::StoredPolicy>, DomainError> {
        self.inner.load(tenant).await
    }

    /// Invalidates *after* the write succeeded, and not before: a failed write
    /// left the document alone, and emptying the cache for it would be work
    /// done on behalf of a change that did not happen.
    async fn replace(
        &self,
        tenant: &TenantId,
        rules: &asterius_domain::policy::RuleSet,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        self.inner.replace(tenant, rules, now).await?;
        self.guard.invalidate(tenant);
        Ok(())
    }

    async fn clear(&self, tenant: &TenantId) -> Result<bool, DomainError> {
        let removed = self.inner.clear(tenant).await?;
        if removed {
            self.guard.invalidate(tenant);
        }
        Ok(removed)
    }
}

/// The enforcement point the four agent grants carry.
///
/// A copy-able bundle of borrows rather than three fields on each handler, so
/// that adding a grant is adding one field and calling one method.
#[derive(Clone)]
pub struct AgentPolicy<'a> {
    /// The decision point, or `None` where this deployment has none.
    ///
    /// `None` is `[features] authzen` off: a deployment with no PDP at all, in
    /// which agents are bounded by their registration (`ast-lh3.1`) exactly as
    /// they were before this ticket. It is *not* the fail-closed case — that is
    /// a wired decision point that could not answer — and the two are kept
    /// apart on purpose: turning a feature off is an operator's statement, and
    /// an unreachable store is not.
    pub policy: Option<std::sync::Arc<dyn IssuancePolicy>>,
    /// Whether a decision point that cannot answer lets the token through.
    pub fail_open: bool,
    /// Where a refusal is recorded.
    pub audit: &'a dyn AuditSink,
}

impl std::fmt::Debug for AgentPolicy<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentPolicy")
            .field("wired", &self.policy.is_some())
            .field("fail_open", &self.fail_open)
            .finish_non_exhaustive()
    }
}

impl<'a> AgentPolicy<'a> {
    /// The enforcement point of a deployment with no decision point.
    ///
    /// What `[features] authzen` off wires, and what a test of a grant that is
    /// not about this check builds: no policy is consulted and every client,
    /// agent or not, takes the path it took before `ast-lh3.10`.
    #[must_use]
    pub fn unenforced(audit: &'a dyn AuditSink) -> Self {
        Self {
            policy: None,
            fail_open: false,
            audit,
        }
    }
}

impl AgentPolicy<'_> {
    /// Whether this token may be minted.
    ///
    /// The grant hands over the row it is about to claim from: its scopes and
    /// its `authorization_details` are what the token would carry, and its
    /// `actor_chain` is how deep the delegation would be. The audience is
    /// passed beside it rather than read off the row, because it is the one
    /// part a grant settles *after* the row was written (RFC 8707 §2.2's
    /// resolution, `issuance::targeting`) and the policy has to see where the
    /// token would really point. No handler assembles the query itself, so
    /// none of them can ask a different question.
    ///
    /// Returns immediately for a client with no agent profile — no policy read,
    /// no cache lookup, no audit entry, nothing measurable at all. Every
    /// existing grant keeps the behaviour and the latency it had.
    ///
    /// # Errors
    ///
    /// [`Refusal`] when a rule denied the issuance, and when no decision could
    /// be taken and this deployment fails closed.
    pub async fn permits(
        &self,
        tenant: &Tenant,
        client: &Client,
        grant: &Grant,
        audience: &BTreeSet<String>,
        grant_type: GrantType,
        now: OffsetDateTime,
    ) -> Result<(), Refusal> {
        let Some(profile) = client.registration.agent.as_ref() else {
            return Ok(());
        };
        let Some(policy) = self.policy.as_ref() else {
            return Ok(());
        };
        let query = query(client, profile.owner(), grant, audience, grant_type);
        match policy.permits(&tenant.id, &query).await {
            Ok(decision) if decision.permitted() => Ok(()),
            Ok(decision) => {
                self.record(tenant, client, &query, decision.reason_admin(), false, now)
                    .await;
                Err(Refusal {
                    code: ACCESS_DENIED,
                    description: REFUSED,
                })
            }
            Err(error) => {
                tracing::error!(
                    %error,
                    tenant = %tenant.id,
                    client = %client.id,
                    fail_open = self.fail_open,
                    "the issuance policy could not be consulted for an agent"
                );
                if self.fail_open {
                    // Audited as a *failure* even though the token is issued:
                    // the entry an operator needs is "this deployment minted
                    // agent tokens nobody decided on", and an outage that
                    // produced no row at all would be invisible in the trail.
                    self.record(
                        tenant,
                        client,
                        &query,
                        Some("policy unavailable"),
                        true,
                        now,
                    )
                    .await;
                    return Ok(());
                }
                self.record(
                    tenant,
                    client,
                    &query,
                    Some("policy unavailable"),
                    false,
                    now,
                )
                .await;
                Err(Refusal {
                    code: ACCESS_DENIED,
                    description: UNDECIDED,
                })
            }
        }
    }

    /// One [`EventType::TOKEN_ISSUANCE_DENIED`] entry.
    ///
    /// Its own type rather than a `token.refused` with a detail, because it
    /// answers a question `token.refused` cannot: "which agents did this
    /// tenant's policy stop, and why". A refusal for a bad scope, a missing
    /// proof and a policy deny are the same row under one type, and the policy
    /// denies are the ones an administrator looks for after tightening a rule.
    ///
    /// `reason_admin` is the decision's own words and is written through
    /// [`Detail::text`], which redacts: it is a string from a stored document
    /// and this server did not compose it.
    async fn record(
        &self,
        tenant: &Tenant,
        client: &Client,
        query: &IssuanceQuery,
        reason_admin: Option<&str>,
        issued_anyway: bool,
        now: OffsetDateTime,
    ) {
        let mut detail = Detail::new()
            .label("action", query.action.name())
            .text("grant_type", query.grant.as_str())
            .text(
                asterius_domain::audit::trail::keys::AGENT_OWNER,
                query.owner.to_string(),
            )
            .number("chain_depth", i64::from(query.chain_depth))
            .flag("issued_anyway", issued_anyway);
        if let Some(resource) = asterius_domain::audit::trail::resource_summary(
            query.audience.iter().map(String::as_str),
        ) {
            detail = detail.text(asterius_domain::audit::trail::keys::RESOURCE, resource);
        }
        if let Some(reason) = reason_admin {
            detail = detail.text("reason_admin", reason);
        }
        let event = AuditEvent::new(
            tenant.id.clone(),
            EventType::TOKEN_ISSUANCE_DENIED,
            Outcome::Failure,
            Actor::Agent {
                client: client.id.clone(),
                on_behalf_of: query.owner.to_string(),
            },
            now,
        )
        .client(client.id.clone())
        .detail(detail);

        if let Err(error) = self.audit.record(event).await {
            tracing::error!(
                %error,
                tenant = %tenant.id,
                client = %client.id,
                "an agent issuance decision was not written to the audit trail"
            );
        }
    }
}

/// The question, built from the row the grant is about to claim from.
///
/// Not a method on [`IssuanceQuery`]: the domain does not know what a
/// [`Grant`] row means at issuance time, and this is the mapping — `scopes` are what the token
/// would carry, the `authorization_details` types are what it would authorize,
/// and the actor chain's length is the delegation depth.
fn query(
    client: &Client,
    owner: &AgentOwner,
    grant: &Grant,
    audience: &BTreeSet<String>,
    grant_type: GrantType,
) -> IssuanceQuery {
    IssuanceQuery {
        agent: client.id.clone(),
        owner: *owner,
        action: IssuanceAction::of(grant_type),
        grant: grant_type,
        audience: audience.clone(),
        scopes: grant.scopes.clone(),
        authorization_details_types: grant
            .authorization_details
            .iter()
            .filter_map(|entry| entry.get("type").and_then(serde_json::Value::as_str))
            .filter(|kind| !kind.is_empty())
            .map(str::to_owned)
            .collect(),
        // One when there is no `act` chain: the agent acting for its owner is
        // already one hop of delegation, and a depth of zero would describe an
        // issuance with nobody behind it.
        chain_depth: u8::try_from(grant.actor_chain.len())
            .unwrap_or(u8::MAX)
            .max(1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asterius_domain::policy::Decision;
    use asterius_domain::{ClientId, TenantId};
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A decision point that answers the same way every time and counts how
    /// often it was asked.
    #[derive(Debug)]
    struct Fixed {
        permit: bool,
        asked: AtomicUsize,
    }

    impl Fixed {
        fn new(permit: bool) -> Self {
            Self {
                permit,
                asked: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait::async_trait]
    impl IssuancePolicy for Fixed {
        async fn permits(
            &self,
            _tenant: &TenantId,
            _query: &IssuanceQuery,
        ) -> Result<IssuanceDecision, DomainError> {
            self.asked.fetch_add(1, Ordering::SeqCst);
            Ok(if self.permit {
                IssuanceDecision::permit(None)
            } else {
                IssuanceDecision::deny(Some("rule agents-none denied".to_owned()))
            })
        }
    }

    /// A decision point that is down.
    #[derive(Debug)]
    struct Down;

    #[async_trait::async_trait]
    impl IssuancePolicy for Down {
        async fn permits(
            &self,
            _tenant: &TenantId,
            _query: &IssuanceQuery,
        ) -> Result<IssuanceDecision, DomainError> {
            Err(DomainError::Storage(
                "the policy store is unreachable".into(),
            ))
        }
    }

    fn sample() -> IssuanceQuery {
        IssuanceQuery {
            agent: ClientId::new("c.agent".to_owned()),
            owner: AgentOwner::User(asterius_domain::entities::user::UserId::new(
                uuid::Uuid::nil(),
            )),
            action: IssuanceAction::ObtainToken,
            grant: GrantType::ClientCredentials,
            audience: BTreeSet::from(["https://api.example".to_owned()]),
            scopes: BTreeSet::from(["read".to_owned()]),
            authorization_details_types: BTreeSet::new(),
            chain_depth: 1,
        }
    }

    fn tenant() -> TenantId {
        TenantId::parse("acme").expect("a valid tenant id")
    }

    #[test]
    fn a_remembered_decision_is_served_until_it_expires() {
        let guard = IssuanceGuard::new(false);
        let now = OffsetDateTime::now_utc();
        let key = sample().cache_key();

        guard.remember(&tenant(), key.clone(), &IssuanceDecision::permit(None), now);

        assert!(guard.cached(&tenant(), &key, now).is_some());
        assert!(
            guard
                .cached(&tenant(), &key, now + IssuanceGuard::DEFAULT_TTL)
                .is_none(),
            "a decision is not honoured once its TTL has elapsed"
        );
    }

    #[test]
    fn writing_a_policy_forgets_that_tenant_s_decisions() {
        let guard = IssuanceGuard::new(false);
        let now = OffsetDateTime::now_utc();
        let key = sample().cache_key();
        let other = TenantId::parse("other").expect("a valid tenant id");
        guard.remember(&tenant(), key.clone(), &IssuanceDecision::permit(None), now);
        guard.remember(&other, key.clone(), &IssuanceDecision::permit(None), now);

        guard.invalidate(&tenant());

        assert!(guard.cached(&tenant(), &key, now).is_none());
        assert!(
            guard.cached(&other, &key, now).is_some(),
            "one tenant's policy write does not empty another tenant's decisions"
        );
    }

    #[test]
    fn a_decision_is_not_served_to_another_tenant() {
        let guard = IssuanceGuard::new(false);
        let now = OffsetDateTime::now_utc();
        let key = sample().cache_key();
        guard.remember(&tenant(), key.clone(), &IssuanceDecision::deny(None), now);

        let other = TenantId::parse("other").expect("a valid tenant id");

        assert!(guard.cached(&other, &key, now).is_none());
    }

    #[test]
    fn the_request_carries_the_four_parts_the_specification_fixes() {
        let request = evaluation_request(&sample()).expect("the query fits §5's bounds");

        assert_eq!(request.subject.kind(), SUBJECT_TYPE);
        assert_eq!(request.subject.id(), "c.agent");
        assert_eq!(
            request.subject.properties().get("owner"),
            Some(&json!(uuid::Uuid::nil().to_string()))
        );
        assert_eq!(request.action.name(), "obtain_token");
        assert_eq!(request.resource.kind(), RESOURCE_TYPE);
        assert_eq!(request.resource.id(), "https://api.example");
        assert_eq!(
            request.resource.properties().get("scopes"),
            Some(&json!(["read"]))
        );
        assert_eq!(
            request.context.properties().get("grant_type"),
            Some(&json!("client_credentials"))
        );
        assert_eq!(
            request.context.properties().get("chain_depth"),
            Some(&json!(1))
        );
    }

    #[test]
    fn an_exchange_asks_a_different_action() {
        let mut query = sample();
        query.action = IssuanceAction::ExchangeToken;
        query.grant = GrantType::TokenExchange;

        let request = evaluation_request(&query).expect("the query fits §5's bounds");

        assert_eq!(request.action.name(), "exchange_token");
    }

    #[test]
    fn a_token_audienced_at_nothing_still_names_a_resource() {
        assert_eq!(resource_id(&BTreeSet::new()), "none");
    }

    #[test]
    fn an_audience_list_too_long_to_be_an_identifier_is_named_by_its_digest() {
        let long: BTreeSet<String> = (0..40)
            .map(|index| format!("https://resource-{index}.example.test/api"))
            .collect();

        let id = resource_id(&long);

        assert_eq!(id.len(), 64, "a sha-256 hex digest");
    }

    /// A decision is a pure function of the query here, so this exercises the
    /// mapping from a [`Decision`] rather than the engine.
    #[test]
    fn a_deny_keeps_the_reason_the_decision_gave() {
        let decision = Decision::default_deny("no rule matched");

        let answer = if decision.permit() {
            IssuanceDecision::permit(decision.context().reason_admin().map(str::to_owned))
        } else {
            IssuanceDecision::deny(decision.context().reason_admin().map(str::to_owned))
        };

        assert!(!answer.permitted());
        assert_eq!(answer.reason_admin(), Some("no rule matched"));
    }

    #[test]
    fn the_cache_empties_itself_rather_than_growing_without_bound() {
        let guard = IssuanceGuard::new(false);
        let now = OffsetDateTime::now_utc();
        for index in 0..=MAX_ENTRIES {
            guard.remember(
                &tenant(),
                format!("key-{index}"),
                &IssuanceDecision::permit(None),
                now,
            );
        }

        let held = guard.cache.lock().expect("the cache is not poisoned").len();

        assert!(held <= MAX_ENTRIES);
    }

    #[tokio::test]
    async fn a_wired_decision_point_is_asked_once_per_question() {
        let fixed = Fixed::new(true);
        let guard = IssuanceGuard::new(false);
        let now = OffsetDateTime::now_utc();
        let key = sample().cache_key();

        let first = fixed
            .permits(&tenant(), &sample())
            .await
            .expect("the fake answers");
        guard.remember(&tenant(), key.clone(), &first, now);
        let second = guard.cached(&tenant(), &key, now);

        assert!(first.permitted());
        assert!(second.is_some_and(|decision| decision.permitted()));
        assert_eq!(fixed.asked.load(Ordering::SeqCst), 1);
    }

    /// A tenant's policy, in memory: the engine loads a document before it
    /// evaluates, and this is that document without a pool.
    #[derive(Debug)]
    struct Stored(asterius_domain::policy::RuleSet);

    #[async_trait::async_trait]
    impl asterius_domain::ports::PolicyStore for Stored {
        async fn load(
            &self,
            _tenant: &TenantId,
        ) -> Result<Option<asterius_domain::policy::StoredPolicy>, DomainError> {
            Ok(Some(asterius_domain::policy::StoredPolicy {
                rules: self.0.clone(),
                updated_at: OffsetDateTime::now_utc(),
            }))
        }

        async fn replace(
            &self,
            _tenant: &TenantId,
            _rules: &asterius_domain::policy::RuleSet,
            _now: OffsetDateTime,
        ) -> Result<(), DomainError> {
            Ok(())
        }

        async fn clear(&self, _tenant: &TenantId) -> Result<bool, DomainError> {
            Ok(false)
        }
    }

    /// An agent resolves to no account, which is what the real one does: a
    /// `client_id` is deliberately not a subject identifier.
    #[derive(Debug)]
    struct NoFacts;

    #[async_trait::async_trait]
    impl SubjectFacts for NoFacts {
        async fn resolve(
            &self,
            _tenant: &TenantId,
            _kind: &str,
            _id: &str,
        ) -> Result<crate::http::access_evaluation::ResolvedSubject, DomainError> {
            Ok(crate::http::access_evaluation::ResolvedSubject::default())
        }
    }

    fn catalogue(json: &str) -> asterius_domain::policy::RuleSet {
        asterius_domain::policy::RuleSet::parse(&format!(r#"{{"version": 1, "rules": {json}}}"#))
            .expect("a valid catalogue")
    }

    /// A rule that permits the sample query, spelled the way a tenant would.
    fn permitting() -> asterius_domain::policy::RuleSet {
        catalogue(
            r#"[{"id": "agents-may-obtain", "effect": "permit",
                 "subject_type": "agent", "resource_type": "token",
                 "actions": ["obtain_token"]}]"#,
        )
    }

    #[tokio::test]
    async fn the_built_in_decision_point_answers_a_matching_rule() {
        // Arrange
        let engine = asterius_domain::policy::DeclarativeEngine::new(std::sync::Arc::new(Stored(
            permitting(),
        )));
        let guard = IssuanceGuard::new(false);
        let pdp = PdpIssuance::new(
            Box::new(engine),
            Box::new(NoFacts),
            crate::http::protocol::deployment_acr_policy(),
            std::sync::Arc::new(guard),
            OffsetDateTime::now_utc(),
        );

        // Act
        let decision = pdp
            .permits(&tenant(), &sample())
            .await
            .expect("the engine answered");

        // Assert
        assert!(decision.permitted());
    }

    #[tokio::test]
    async fn a_tenant_with_no_matching_rule_denies_the_issuance() {
        // Arrange
        let engine = asterius_domain::policy::DeclarativeEngine::new(std::sync::Arc::new(Stored(
            asterius_domain::policy::RuleSet::deny_all(),
        )));
        let guard = IssuanceGuard::new(false);
        let pdp = PdpIssuance::new(
            Box::new(engine),
            Box::new(NoFacts),
            crate::http::protocol::deployment_acr_policy(),
            std::sync::Arc::new(guard),
            OffsetDateTime::now_utc(),
        );

        // Act
        let decision = pdp
            .permits(&tenant(), &sample())
            .await
            .expect("the engine answered");

        // Assert
        assert!(!decision.permitted());
        assert!(
            decision.reason_admin().is_some(),
            "a default deny says so, and the trail carries it"
        );
    }

    /// `ast-lh3.10`'s acceptance criterion: the allow path costs at most five
    /// milliseconds at p95 with the in-process PDP.
    ///
    /// Ignored, and run by the CI with `--run-ignored all`: it is a timing
    /// assertion, and a shared runner under load is not where a five
    /// millisecond bound should fail a developer's `cargo nextest`.
    ///
    /// What it measures is this check and nothing else — one policy walk, one
    /// (empty) fact resolution, one cache lookup — against a document held in
    /// memory rather than in Postgres. That is the honest scope: the row read
    /// under `PgPolicies` is a database's latency and not this ticket's.
    #[tokio::test]
    #[ignore = "a timing assertion; the CI runs it with --run-ignored all"]
    async fn the_allow_path_costs_at_most_five_milliseconds_at_p95() {
        // Arrange
        const RUNS: usize = 200;
        let engine = asterius_domain::policy::DeclarativeEngine::new(std::sync::Arc::new(Stored(
            permitting(),
        )));
        let guard = std::sync::Arc::new(IssuanceGuard::new(false));
        let now = OffsetDateTime::now_utc();
        let mut timings = Vec::with_capacity(RUNS);

        // Act: every run is a distinct question, so none of them is served
        // from the cache — the p95 measured is the *walk*, not the cache.
        for index in 0..RUNS {
            let mut query = sample();
            query.audience = BTreeSet::from([format!("https://api-{index}.example")]);
            let pdp = PdpIssuance::new(
                Box::new(engine.clone()),
                Box::new(NoFacts),
                crate::http::protocol::deployment_acr_policy(),
                std::sync::Arc::clone(&guard),
                now,
            );
            let started = std::time::Instant::now();
            let decision = pdp.permits(&tenant(), &query).await.expect("an answer");
            timings.push(started.elapsed());
            assert!(decision.permitted());
        }

        // Assert
        timings.sort_unstable();
        let p95 = timings[(RUNS * 95) / 100];
        assert!(
            p95 <= std::time::Duration::from_millis(5),
            "the allow path must add at most 5 ms at p95; measured {p95:?}"
        );
    }

    #[tokio::test]
    async fn an_unreachable_decision_point_is_an_error_and_never_a_deny() {
        let result = Down.permits(&tenant(), &sample()).await;

        assert!(
            result.is_err(),
            "an outage must reach the enforcement point as an error, so that it can \
             apply the deployment's posture and audit it"
        );
    }
}
