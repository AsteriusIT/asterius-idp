//! `POST /access/v1/evaluation` and `POST /access/v1/evaluations` — the
//! AuthZEN Access Evaluation and Access Evaluations endpoints (Authorization
//! API 1.0 §6, §7, §10.1, `ast-pj0.1`, `ast-pj0.2`).
//!
//! The authorization server as a Policy Decision Point. A policy enforcement
//! point asks "may this subject do this to that", and this endpoint answers
//! §5.5's Decision: a boolean, and the context that explains it.
//!
//! # The boxcar is this endpoint with an array (§7)
//!
//! [`evaluate_many`] is [`evaluate`] over a list: the same five credential
//! checks, the same limiter, the same parser, the same engine and the same
//! fail-closed rule, over §7.1's `evaluations` array with §7.1.1's defaults
//! already merged in by [`authzen::parse_evaluations`]. What differs is only
//! what §7 adds, and each of those is argued where it is decided:
//!
//! * **Who is charged.** One request is one token at the limiter, not one per
//!   evaluation — a PEP's budget is a budget of *requests*, and an array
//!   charged per item would make the compact syntax §7.1.1 recommends cost
//!   more than writing the same requests out one at a time. The amplification
//!   that buys is bounded by [`authzen::MAX_EVALUATIONS`], which is why that
//!   bound is a constant and not a setting.
//! * **What is recorded.** One `access.evaluated` entry per request, carrying
//!   the semantic and the counts, not one per evaluation — see `record_many`,
//!   which argues the trade.
//! * **What happens when one of them cannot be decided.** §7.2.1: a per-item
//!   failure is that item's `decision: false` with an `error` in its context,
//!   and the rest of the array is still answered. Only a request that cannot
//!   be *read* is a 400, and then it is a 400 for the whole of it.
//!
//! What is *not* here is the vocabulary or the decision. The wire format is
//! [`asterius_oidc::authzen`], the rule language and the evaluator are
//! [`asterius_domain::policy`], and the decision arrives through
//! [`PolicyEngine`] — so a second PDP implementation is an adapter rather than
//! a second endpoint. What is here is who may ask, what this server resolves on
//! their behalf, and what a refusal looks like on the wire.
//!
//! # Five credentials checks, in this order
//!
//! The same five the Grant Management endpoint makes, from the same functions,
//! because §11.2 ("the PDP SHOULD authenticate the calling PEP") does not
//! describe a weaker check than a resource server's:
//!
//! 1. **The token verifies** — signature, `typ`, `iss`, `exp` — through
//!    [`access_token::verify`].
//! 2. **The caller holds it** (RFC 9449 §7.1, RFC 8705 §3): the `cnf` decides
//!    what must be presented beside it. A PEP's token is DPoP-bound, so the
//!    proof is made over *this* method and *this* URL.
//! 3. **The token is for this PDP** (RFC 9068 §3): `aud` must be the URL of
//!    *the endpoint the request arrived at* — §12's metadata advertises the
//!    evaluation and the evaluations endpoints separately, and so the token
//!    for one is not the token for the other. A PEP's token for a business API
//!    is a perfectly good token and is not one this endpoint answers.
//! 4. **It has not been withdrawn**: the `jti` denylist and the two cutoffs,
//!    exactly as UserInfo reads them.
//! 5. **It carries [`SCOPE_EVALUATE`]** — otherwise RFC 6750 §3.1's
//!    `insufficient_scope`, a 403 naming the scope, which is the same challenge
//!    every other scope-gated endpoint here answers with.
//!
//! Only then is the body read, and only then does a policy document get
//! loaded: a request that fails any of the five costs this PDP no policy walk,
//! which is half of §11.7's answer to denial of service. The other half is the
//! [`LimitedEndpoint::AccessEvaluation`] limiter, charged after the checks so
//! that the budget spent belongs to a PEP that proved who it is.
//!
//! # Fail closed, and what that means precisely
//!
//! §10.1.2 separates two things this endpoint must never confuse:
//!
//! * A **refusal to read the request** — a missing `subject.id`, a body that is
//!   not JSON, no credential — is 400/401/403 with an error message string.
//!   There is no decision, because there was no question.
//! * A **decision** is always 200. A deny is `{"decision": false}`, and so is a
//!   decision this PDP could not take: if the policy store cannot be read, or
//!   the subject's facts cannot be resolved, the answer is
//!   [`authzen::engine_failure_response`] — `decision: false` with an `error`
//!   in the context — and an audit record saying what really happened.
//!
//! A 500 would be the other design, and it would be worse: a PEP that gets one
//! has no rule about what to do next, and the two things it might invent are
//! "fail open" and "let this one through while we fix it". The specification's
//! own note says errors are "unrelated to the outcome of an authorization
//! decision"; an outage is not a permit.
//!
//! # What the PEP may say, and what this server resolves
//!
//! §11.4 states the trust direction plainly: the PDP must trust the PEP for the
//! values it sends. This endpoint takes that as far as it goes and no further.
//! `properties` on the subject, the action and the resource are the PEP's, and
//! a rule may match on them. Everything that *confers authority within this
//! tenant* — group membership, application roles, active grants and the
//! authentication context — is read here from this server's own store, keyed by
//! the subject the PEP named, and can never be asserted by a request. See
//! [`SubjectFacts`] and `docs/threat-model.md`.
//!
//! # Nothing here is cached
//!
//! A decision is about one person and one resource at one instant, and the
//! facts under it change when an administrator revokes a role. Every response
//! says `no-store`, like every other credential-adjacent answer this server
//! gives.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::pin::Pin;
use std::task::Poll;

use crate::http::access_token;
use crate::http::dpop::{self, DpopEndpoint, NONCE_HEADER, USE_NONCE};
use crate::http::limits::LimitContext;
use asterius_domain::audit::{Actor, AuditEvent, AuditSink, Detail, EventType, Outcome};
use asterius_domain::entities::application_role::HeldRoles;
use asterius_domain::keys::KeyStore;
use asterius_domain::policy::{ActiveGrant, Context as PolicyContext, Decision, EvaluationRequest};
use asterius_domain::ports::PolicyEngine;
use asterius_domain::{
    AcrPolicy, ClientId, DomainError, Grant, GrantId, LimitedEndpoint, Tenant, TenantId,
};
use asterius_jose::verify::Verified;
use asterius_oidc::authzen::{
    self, AuthzenError, EvaluationsRequest, EvaluationsSemantic, SCOPE_EVALUATE,
};
use asterius_oidc::metadata::Endpoint;
use asterius_oidc::userinfo::{self, Presentation, UserInfoError};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::Value;
use time::OffsetDateTime;

/// The header §10.1.3 recommends as the request identifier.
const REQUEST_ID_HEADER: &str = "x-request-id";

/// The longest caller-supplied request identifier this PDP echoes.
///
/// §10.1.3 makes the value "an arbitrary string", which is not a length this
/// server can be made to reflect without bound: the value goes back out in a
/// response header, so an unbounded one is an unbounded response header. A UUID
/// is 36 bytes and the specification's own example is one.
const MAX_REQUEST_ID: usize = 128;

/// What this server knows about the subject a PEP named.
///
/// The facts a rule may reason about that a PEP may **not** assert: group
/// membership, application roles (`ast-095`) and the authorizations the subject
/// holds (`ast-uwv.2`). Resolved here, from this tenant's own rows, keyed by
/// the `type` and `id` in the request.
///
/// # Why the grants come back whole
///
/// [`ActiveGrant::of`] decides what "active" means, and it is the endpoint —
/// with the one clock reading the whole request uses — that applies it. An
/// implementation of this port that filtered for itself would be a second
/// opinion about whether a grant is live, and a rule saying "holds an active
/// grant" must not be able to disagree with [`Grant::status`].
///
/// # A subject this tenant does not hold is not an error
///
/// §5.1's subject is whatever the PEP calls a principal; a `type` of `service`
/// or an id belonging to another directory is a perfectly ordinary request.
/// Such a subject resolves to no facts, which denies everything a `group`,
/// `role`, `grant` or `acr_at_least` condition guards — the fail-closed
/// direction — while leaving rules that read only `properties` working, which
/// is what makes this PDP usable for resources whose subjects are not this
/// server's users.
#[async_trait::async_trait]
pub trait SubjectFacts: std::fmt::Debug + Send + Sync {
    /// Everything this tenant holds about the subject a request names.
    ///
    /// # Errors
    ///
    /// [`DomainError`] when the store could not be read. Never an empty answer
    /// for a store that is down: that would turn an outage into a decision, and
    /// the decision would be wrong in whichever direction the policy happens to
    /// lean.
    async fn resolve(
        &self,
        tenant: &TenantId,
        kind: &str,
        id: &str,
    ) -> Result<ResolvedSubject, DomainError>;
}

/// The facts [`SubjectFacts`] found, or the empty set for a subject this tenant
/// does not hold.
#[derive(Debug, Clone, Default)]
pub struct ResolvedSubject {
    /// The groups the subject is held in.
    pub groups: BTreeSet<String>,
    /// The application roles the subject holds.
    pub roles: HeldRoles,
    /// Every grant this tenant holds for the subject, revoked and expired ones
    /// included: see [`SubjectFacts`].
    pub grants: Vec<Grant>,
}

/// The two questions every endpoint that takes an access token asks of the
/// rows: is this `jti` on the denylist, and was everything this principal holds
/// withdrawn before it was minted.
///
/// Its own trait rather than a borrowed one, so that a PDP deployment wires a
/// port named for what it does here. The implementations are the same rows.
#[async_trait::async_trait]
pub trait PdpTokenStatus: std::fmt::Debug + Send + Sync {
    /// Whether this `jti` was revoked individually (RFC 7009).
    ///
    /// # Errors
    ///
    /// [`DomainError`] when the denylist cannot be read — never `false`, which
    /// would admit a revoked token during an outage.
    async fn is_denylisted(&self, jti: &str) -> Result<bool, DomainError>;

    /// The instant before which every access token of this principal is
    /// withdrawn, if there is one.
    ///
    /// # Errors
    ///
    /// [`DomainError`] when the rows cannot be read.
    async fn access_tokens_revoked_before(
        &self,
        client: &ClientId,
        grant: Option<&GrantId>,
    ) -> Result<Option<OffsetDateTime>, DomainError>;
}

/// What the endpoint needs.
pub struct AccessEvaluationContext<'a> {
    /// The tenant the request arrived at.
    pub tenant: &'a Tenant,
    /// The PDP (`ast-pj0.4`).
    pub engine: &'a dyn PolicyEngine,
    /// What this server knows about the subject.
    pub subjects: &'a dyn SubjectFacts,
    /// The token's standing.
    pub tokens: &'a dyn PdpTokenStatus,
    /// Where the tenant's published keys come from, so a token this server
    /// signed is verified against the same set `/jwks` serves.
    pub keys: &'a dyn KeyStore,
    /// Checks the DPoP proof (RFC 9449 §7.1).
    pub dpop: &'a DpopEndpoint,
    /// The trail. Every decision is recorded, permit and deny alike.
    pub audit: &'a dyn AuditSink,
    /// The client certificate this request arrived with, if the deployment saw
    /// one from a source it trusts (RFC 8705 §2).
    pub certificate: Option<&'a asterius_oidc::mtls::ClientCertificate>,
    /// The tenant's authentication ladder, weakest first: what `acr_at_least`
    /// is read against.
    pub acr: &'a AcrPolicy,
    /// §11.7's rate limiter.
    pub limits: LimitContext<'a>,
    /// One clock reading for the whole request.
    pub now: OffsetDateTime,
}

impl std::fmt::Debug for AccessEvaluationContext<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccessEvaluationContext")
            .field("now", &self.now)
            .finish_non_exhaustive()
    }
}

/// How many evaluations of one boxcar are decided at a time (§7.1).
///
/// §7.1 leaves it open — "these requests are independent from each other, and
/// may be executed sequentially or in parallel, left to the discretion of each
/// implementation" — and both extremes are wrong here. Sequential makes a
/// hundred-item array a hundred round trips to the policy store, which is the
/// latency the boxcar exists to avoid. Unbounded makes one request a hundred
/// concurrent database reads, which is a PEP turning its rate-limit budget
/// into this deployment's connection pool (§11.7).
///
/// Eight: enough that the array is decided in a few passes rather than a
/// hundred, small enough that [`authzen::MAX_EVALUATIONS`] of them cannot
/// crowd out the requests of every other tenant.
const MAX_CONCURRENT: usize = 8;

/// Which of the two APIs a request arrived at.
///
/// Carried rather than inferred, because two of the credential checks depend
/// on it: the audience a token must name and the URL a DPoP proof is made
/// over are the endpoint's own, and a token minted for §6.1's evaluation is
/// not one §7's boxcar accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Api {
    /// §6.1: one request, one Decision.
    Single,
    /// §7.1: an array of requests, an array of Decisions.
    Boxcar,
    /// §8's searches, one entry per path (`ast-pj0.6`).
    ///
    /// Carried here rather than in `crate::http::access_search`, because what
    /// [`authorize`] needs from an API is exactly this: the registry entry
    /// whose URL is the audience a token must name and the URL a DPoP proof is
    /// made over. A search endpoint that authenticated its callers from a
    /// second copy of those five checks would be a second place for them to
    /// drift.
    Search(asterius_oidc::authzen_search::SearchKind),
}

impl Api {
    /// The registry entry, which is the path, the metadata member and the
    /// audience all at once (`ast-o0t.3`).
    pub(crate) const fn endpoint(self) -> Endpoint {
        use asterius_oidc::authzen_search::SearchKind;
        match self {
            Self::Single => Endpoint::AccessEvaluation,
            Self::Boxcar => Endpoint::AccessEvaluations,
            Self::Search(SearchKind::Subject) => Endpoint::SearchSubject,
            Self::Search(SearchKind::Resource) => Endpoint::SearchResource,
            Self::Search(SearchKind::Action) => Endpoint::SearchAction,
        }
    }
}

/// `POST /access/v1/evaluation` — §6.1, §6.2, §10.1.
///
/// Never returns `Err`: every outcome is an HTTP response in §10.1.2's shape.
pub async fn evaluate(
    context: AccessEvaluationContext<'_>,
    method: &Method,
    headers: &HeaderMap,
    body: &[u8],
) -> Response {
    answered(Api::Single, context, method, headers, body).await
}

/// `POST /access/v1/evaluations` — §7.1, §7.2, §10.1.
///
/// The boxcar. Never returns `Err`, for the same reason [`evaluate`] does not.
pub async fn evaluate_many(
    context: AccessEvaluationContext<'_>,
    method: &Method,
    headers: &HeaderMap,
    body: &[u8],
) -> Response {
    answered(Api::Boxcar, context, method, headers, body).await
}

/// Both endpoints, which differ only in [`Api`].
async fn answered(
    api: Api,
    context: AccessEvaluationContext<'_>,
    method: &Method,
    headers: &HeaderMap,
    body: &[u8],
) -> Response {
    let response = match answer(api, &context, method, headers, body).await {
        Ok(response) => response,
        Err(refusal) => render(&context, refusal),
    };
    // §10.1.3: "If the PEP specified a request identifier in the request, the
    // PDP MUST include the same identifier in the response to that request."
    // Last, so that it is on a refusal as much as on a decision — a PEP
    // correlating a 401 needs it more than one correlating a permit.
    echo_request_id(no_store(response), headers)
}

/// Why a request stopped before it became a decision.
///
/// Every variant is one of §10.1.2's four status codes. A *deny* is not in
/// here: it is a 200, and the difference is the whole of the section.
#[derive(Debug)]
pub(crate) enum Refused {
    /// An RFC 6750 §3 refusal: 400, 401 or 403, in a `WWW-Authenticate`.
    Client(UserInfoError),
    /// §11.2's authentication is there and does not carry [`SCOPE_EVALUATE`].
    MissingScope,
    /// A DPoP proof that did not check out (RFC 9449 §7.1).
    Dpop(dpop::Refusal),
    /// §10.1.1's 400, with the message string that section's table describes.
    Invalid(String),
    /// §10.1 binds this API to `POST`.
    MethodNotAllowed,
    /// This deployment could not finish *before there was a request to decide*
    /// — a key set that will not load, for instance. Logged, never described.
    ///
    /// Deliberately narrow. Once the request has been read, a failure is a
    /// decision this PDP could not take, and that is a 200 fail-closed deny
    /// rather than one of these.
    Server(DomainError),
}

impl From<DomainError> for Refused {
    fn from(error: DomainError) -> Self {
        Self::Server(error)
    }
}

impl From<UserInfoError> for Refused {
    fn from(error: UserInfoError) -> Self {
        Self::Client(error)
    }
}

impl From<AuthzenError> for Refused {
    fn from(error: AuthzenError) -> Self {
        Self::Invalid(error.to_string())
    }
}

/// The whole request: authenticate, admit, read, decide, record.
async fn answer(
    api: Api,
    context: &AccessEvaluationContext<'_>,
    method: &Method,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<Response, Refused> {
    if method != Method::POST {
        return Err(Refused::MethodNotAllowed);
    }
    // §10.1: "Requests MUST include a `Content-Type` header with the value
    // `application/json`." Checked before the credential, because it costs a
    // header comparison and because a caller that sent a form has not made a
    // request this API defines.
    json_content_type(headers)?;

    let pep = authorize(api, context, method, headers).await?;

    // The limiter runs after the credential checks and before the policy walk,
    // so the PEP charged is one that proved who it is (§11.7). `guard` renders
    // its own 429, with the `Retry-After` every throttled endpoint here
    // answers with.
    //
    // One token per *request*, boxcar included, and one budget shared by the
    // two endpoints: [`LimitedEndpoint::AccessEvaluation`] is the PDP's
    // budget, and a PEP that could spend it twice by alternating between
    // §6.1's path and §7.1's would have two budgets for one authority.
    let response = crate::http::limits::guard(
        &context.limits,
        LimitedEndpoint::AccessEvaluation,
        Some(pep.as_str()),
        async || match decide(api, context, &pep, body).await {
            Ok(response) => response,
            Err(refusal) => render(context, refusal),
        },
    )
    .await;
    Ok(response)
}

/// One decision, once the limiter has admitted the request.
///
/// The only place a policy is read. Everything from here on that fails is a
/// fail-closed deny rather than a status code — see the module documentation.
async fn decide(
    api: Api,
    context: &AccessEvaluationContext<'_>,
    pep: &ClientId,
    body: &[u8],
) -> Result<Response, Refused> {
    if api == Api::Boxcar {
        return decide_many(context, pep, body).await;
    }
    let request = authzen::parse_evaluation(body)?;
    let started = std::time::Instant::now();

    let request = match resolved(context, request).await {
        Ok(request) => request,
        Err(error) => {
            return Ok(failed(context, pep, None, started, &error).await);
        }
    };

    match context.engine.evaluate(&context.tenant.id, &request).await {
        Ok(decision) => {
            record(
                context,
                pep,
                &request,
                started,
                Some(&decision),
                Detail::new(),
            )
            .await;
            Ok(json(StatusCode::OK, &authzen::decision_response(&decision)))
        }
        Err(error) => Ok(failed(context, pep, Some(&request), started, &error).await),
    }
}

/// §7.1's array, decided under §7.1.2.1's semantics.
///
/// The parser has already merged §7.1.1's defaults, so what is left here is
/// the *execution*: which evaluations to run, in what order, and when to stop.
/// A request the parser refused is a 400 for the whole array (§7.2.1's first
/// kind of error); everything from here on is the second kind, which is a
/// `decision: false` in one element and no effect at all on the others.
async fn decide_many(
    context: &AccessEvaluationContext<'_>,
    pep: &ClientId,
    body: &[u8],
) -> Result<Response, Refused> {
    let request = authzen::parse_evaluations(body)?;
    let started = std::time::Instant::now();

    // One view of each distinct subject for the whole request, resolved before
    // any decision is taken. Two reasons, and the second is the one that
    // matters: a boxcar routinely names one subject a hundred times (§7.1.1's
    // compact syntax is *for* that), so one read per item would be ninety-nine
    // reads nobody asked for — and an array whose fifth evaluation saw a group
    // membership its first did not would be a set of decisions no single state
    // of this tenant ever justified.
    let mut facts: BTreeMap<(&str, &str), Option<ResolvedSubject>> = BTreeMap::new();
    for evaluation in &request.evaluations {
        let key = (evaluation.subject.kind(), evaluation.subject.id());
        if facts.contains_key(&key) {
            continue;
        }
        let resolved = match context
            .subjects
            .resolve(&context.tenant.id, key.0, key.1)
            .await
        {
            Ok(resolved) => Some(resolved),
            Err(error) => {
                // Fail closed, per subject rather than per request: the
                // evaluations that name a subject this server could read are
                // still answerable, and §7.2.1 gives the others their own
                // `error` context.
                tracing::error!(
                    %error,
                    tenant = %context.tenant.id,
                    client = %pep,
                    "a subject's facts could not be resolved for a boxcar evaluation"
                );
                None
            }
        };
        facts.insert(key, resolved);
    }

    // Each evaluation with its facts attached, or `None` where they could not
    // be had — which is already a fail-closed deny, decided before the engine
    // is asked anything.
    let prepared: Vec<Option<EvaluationRequest>> = request
        .evaluations
        .iter()
        .map(|evaluation| {
            let key = (evaluation.subject.kind(), evaluation.subject.id());
            let resolved = facts.get(&key).and_then(Option::as_ref)?;
            attach(context.acr, context.now, evaluation.clone(), resolved)
                .map_err(|error| {
                    tracing::error!(
                        %error,
                        tenant = %context.tenant.id,
                        "an evaluation's subject could not be completed"
                    );
                })
                .ok()
        })
        .collect();

    let decisions = match request.semantic {
        EvaluationsSemantic::ExecuteAll => execute_all(context, &prepared).await,
        semantic => short_circuit(context, &prepared, semantic).await,
    };

    record_many(context, pep, &request, started, &decisions).await;

    let body = if request.boxcar {
        authzen::evaluations_response(
            decisions
                .iter()
                .map(|decision| rendered(decision.as_ref()))
                .collect(),
        )
    } else {
        // §7.1: an absent or empty array is §6.1's request, and §6.2's single
        // Decision is what a PEP that sent one is waiting for.
        rendered(decisions.first().and_then(Option::as_ref))
    };
    Ok(json(StatusCode::OK, &body))
}

/// What one evaluation of a boxcar came to.
///
/// `None` is §7.2.1's per-item error — the facts or the engine were not there
/// — and is rendered as [`authzen::engine_failure_response`]: a deny that says
/// it is a failure, so that a PEP can alert instead of showing somebody a
/// permission dialogue.
type Outcomes = Vec<Option<asterius_domain::policy::Decision>>;

/// One element of §7.2's array.
fn rendered(decision: Option<&asterius_domain::policy::Decision>) -> Value {
    decision.map_or_else(authzen::engine_failure_response, authzen::decision_response)
}

/// §7.1.2.1's default: "execute all of the requests (potentially in parallel),
/// return all of the results".
///
/// In parallel, [`MAX_CONCURRENT`] at a time, and the results in the order
/// they were asked — §7.2 requires the array to line up with the request's,
/// and a PEP matching decisions to resources by position is the whole point of
/// that requirement.
async fn execute_all(
    context: &AccessEvaluationContext<'_>,
    prepared: &[Option<EvaluationRequest>],
) -> Outcomes {
    let mut decisions = Vec::with_capacity(prepared.len());
    for batch in prepared.chunks(MAX_CONCURRENT) {
        let pending: Vec<_> = batch
            .iter()
            .map(|request| evaluate_one(context, request.as_ref()))
            .collect();
        decisions.extend(in_order(pending).await);
    }
    decisions
}

/// §7.1.2.1's two short circuits, which are sequential by definition.
///
/// "Deny on first denial (or failure)" and its converse: the PEP asked for the
/// evaluations *in an order*, and the array that comes back is truncated at
/// the one that decided the answer. Nothing after it is evaluated, which is
/// the saving the semantic exists for — a PDP that ran them all and then
/// truncated the reply would have spent exactly what the PEP asked it not to.
async fn short_circuit(
    context: &AccessEvaluationContext<'_>,
    prepared: &[Option<EvaluationRequest>],
    semantic: EvaluationsSemantic,
) -> Outcomes {
    let mut decisions = Vec::new();
    for request in prepared {
        let decision = evaluate_one(context, request.as_ref()).await;
        // A failure is a denial (§7.1.2.1 says so for `deny_on_first_deny`)
        // and is never a permit, so it stops the first and not the second.
        let permitted = decision
            .as_ref()
            .is_some_and(asterius_domain::policy::Decision::permit);
        decisions.push(decision);
        let stop = match semantic {
            EvaluationsSemantic::DenyOnFirstDeny => !permitted,
            EvaluationsSemantic::PermitOnFirstPermit => permitted,
            EvaluationsSemantic::ExecuteAll => false,
        };
        if stop {
            break;
        }
    }
    decisions
}

/// One evaluation, with every failure already turned into a fail-closed deny.
async fn evaluate_one(
    context: &AccessEvaluationContext<'_>,
    request: Option<&EvaluationRequest>,
) -> Option<asterius_domain::policy::Decision> {
    let request = request?;
    match context.engine.evaluate(&context.tenant.id, request).await {
        Ok(decision) => Some(decision),
        Err(error) => {
            tracing::error!(
                %error,
                tenant = %context.tenant.id,
                "one evaluation of a boxcar request could not be decided"
            );
            None
        }
    }
}

/// Awaits every future to completion, all at once, answers in argument order.
///
/// The bound on how many are in flight is the caller's — [`execute_all`]
/// hands over one chunk at a time — so what this has to get right is the
/// *order*: a `Vec` of answers indexed exactly as the futures were.
///
/// Written out rather than taken from `futures-util`, which this workspace
/// does not depend on (the root manifest says why): a join over a vector is
/// twenty lines of safe code, and the alternative is a dependency tree for one
/// combinator. A wake polls every unfinished future in the batch, which for
/// [`MAX_CONCURRENT`] of them is cheaper than the bookkeeping that would avoid
/// it.
async fn in_order<T, F: Future<Output = T>>(futures: Vec<F>) -> Vec<T> {
    let mut pending: Vec<Pin<Box<F>>> = futures.into_iter().map(Box::pin).collect();
    let mut done: Vec<Option<T>> = pending.iter().map(|_| None).collect();
    std::future::poll_fn(|cx| {
        let mut ready = true;
        for (slot, future) in done.iter_mut().zip(pending.iter_mut()) {
            // Never polled again once it has answered: a future that is polled
            // after returning `Ready` is entitled to panic.
            if slot.is_none() {
                match future.as_mut().poll(cx) {
                    Poll::Ready(value) => *slot = Some(value),
                    Poll::Pending => ready = false,
                }
            }
        }
        if ready {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    })
    .await;
    done.into_iter()
        .map(|slot| slot.expect("every future in the batch answered"))
        .collect()
}

/// The request with this server's own facts attached (§5.1, §5.4).
///
/// The PEP's `properties` are already on it and are left exactly as they
/// arrived; what is added is what only this tenant can answer. See
/// [`SubjectFacts`].
async fn resolved(
    context: &AccessEvaluationContext<'_>,
    request: EvaluationRequest,
) -> Result<EvaluationRequest, DomainError> {
    let facts = context
        .subjects
        .resolve(
            &context.tenant.id,
            request.subject.kind(),
            request.subject.id(),
        )
        .await?;
    attach(context.acr, context.now, request, &facts)
}

/// One evaluation decided outside the §6.1 request cycle: the console's policy
/// test bench (`ast-f7m.9`) and each candidate of a §8 search (`ast-pj0.6`).
///
/// The same two steps the endpoints take once the credential checks are done —
/// resolve the subject's facts from this server's store, attach them, ask the
/// engine — and none of the ones that belong to *one PEP request*: no token to
/// verify (the bench's caller proved itself to the admin API with a session;
/// a search verified its PEP once, before the first candidate), no
/// [`LimitedEndpoint::AccessEvaluation`] token spent here (the admin API has
/// its own limiter, and a search charges one token for the whole request
/// rather than one per candidate), and no `access.evaluated` record — nothing
/// enforced this answer. A search writes one `access.searched` entry for the
/// request it answered, which is a different event about a different thing.
///
/// This is a *function of this module* rather than a copy in the admin
/// composition root or in `crate::http::access_search` on purpose. The one
/// property a bench and a search must have is that they decide what the
/// endpoint would decide, and that only holds while all three go through
/// `attach` — the single place `ActiveGrant::of` filters the live grants and
/// `authenticated_acr` reads the ladder.
///
/// # Errors
///
/// [`DomainError`] when the facts or the policy could not be read. Not a deny:
/// §10.1.2's fail-closed `decision: false` exists because a PEP has to enforce
/// *something*, and the administrator reading a bench has to be told that the
/// answer is missing rather than shown a refusal their rules did not produce.
pub async fn decide_without_enforcing(
    engine: &dyn PolicyEngine,
    subjects: &dyn SubjectFacts,
    acr: &AcrPolicy,
    tenant: &TenantId,
    request: &EvaluationRequest,
    now: OffsetDateTime,
) -> Result<Decision, DomainError> {
    let facts = subjects
        .resolve(tenant, request.subject.kind(), request.subject.id())
        .await?;
    let resolved = attach(acr, now, request.clone(), &facts)?;
    engine.evaluate(tenant, &resolved).await
}

/// The facts, attached — the half of [`resolved`] that reads no store.
///
/// Separate because §7's boxcar resolves each distinct subject once and then
/// attaches the same facts to every evaluation that names it: one read, one
/// view of the tenant, and no chance of two evaluations in one answer
/// disagreeing about who the subject is.
fn attach(
    acr_policy: &AcrPolicy,
    now: OffsetDateTime,
    request: EvaluationRequest,
    facts: &ResolvedSubject,
) -> Result<EvaluationRequest, DomainError> {
    // One clock reading decides which grants are live, and `ActiveGrant::of` is
    // the only thing that decides it.
    let active: Vec<ActiveGrant> = facts
        .grants
        .iter()
        .filter_map(|grant| ActiveGrant::of(grant, now))
        .collect();
    let acr = authenticated_acr(acr_policy, &facts.grants, now);
    let groups = facts.groups.clone();
    let roles = facts.roles.clone();
    let ladder: Vec<String> = acr_policy
        .levels()
        .iter()
        .map(|level| level.value().to_owned())
        .collect();

    let subject = request
        .subject
        .with_groups(groups)
        .with_roles(roles)
        .with_grants(active)
        .map_err(|error| DomainError::invalid("subject", error.to_string()))?;
    let context_entity =
        PolicyContext::new(request.context.properties().clone()).with_acr(acr, ladder);

    Ok(EvaluationRequest::new(
        subject,
        request.action,
        request.resource,
        context_entity,
    ))
}

/// How strongly this person is authenticated, as their live authorizations
/// record it.
///
/// The `acr` a rule reads is not the PEP's to state (§11.4 notwithstanding: a
/// PEP asserting "this session reached `urn:acr:passkey`" would be a PEP that
/// can satisfy a step-up rule by typing it). This server's record of it is
/// [`asterius_domain::GrantAuthentication`], copied onto each grant at the
/// moment the authorization completed, so the question "what has this subject
/// proved" is answered from grants rather than from a session — the endpoint
/// has no session identifier, and could not be given one it has any business
/// reading.
///
/// The *weakest* rung among the live authorizations, not the strongest. Two
/// grants of different strengths mean the subject has at some point
/// authenticated more strongly than every one of their current authorizations
/// requires, and a step-up rule (`acr_at_least`) asks about what is standing
/// behind the request being made — answering with the high-water mark would let
/// a strong authentication from last week satisfy a demand this request has not
/// met. `None` when no live grant carries an `acr`, which satisfies no
/// `acr_at_least` condition at all.
fn authenticated_acr(policy: &AcrPolicy, grants: &[Grant], now: OffsetDateTime) -> Option<String> {
    let rank = |value: &str| {
        policy
            .levels()
            .iter()
            .position(|level| level.value() == value)
    };
    grants
        .iter()
        .filter(|grant| grant.status(now) == asterius_domain::GrantStatus::Active)
        .filter_map(|grant| grant.authentication.as_ref())
        .filter_map(|authentication| authentication.acr.as_deref())
        .filter_map(|acr| rank(acr).map(|rank| (rank, acr.to_owned())))
        .min_by_key(|(rank, _)| *rank)
        .map(|(_, acr)| acr)
}

/// §10.1.2's fail-closed answer: a deny that says the PDP could not decide.
///
/// Recorded before it is sent, and recorded as a failure whatever the policy
/// would have said, because this is the entry an operator needs: a PDP that
/// starts denying everything at 03:00 because a replica is unreachable looks
/// exactly like a tightened policy from the outside.
async fn failed(
    context: &AccessEvaluationContext<'_>,
    pep: &ClientId,
    request: Option<&EvaluationRequest>,
    started: std::time::Instant,
    error: &DomainError,
) -> Response {
    tracing::error!(
        %error,
        tenant = %context.tenant.id,
        client = %pep,
        "a policy decision could not be taken; answering a fail-closed deny"
    );
    if let Some(request) = request {
        record(
            context,
            pep,
            request,
            started,
            None,
            Detail::new().label("error", "engine_unavailable"),
        )
        .await;
    }
    json(StatusCode::OK, &authzen::engine_failure_response())
}

// ---------------------------------------------------------------------------
// The credential
// ---------------------------------------------------------------------------

/// The five checks of the module documentation, in that order.
///
/// Returns the PEP's `client_id`, which is what the limiter charges and what
/// the trail names as the actor.
pub(crate) async fn authorize(
    api: Api,
    context: &AccessEvaluationContext<'_>,
    method: &Method,
    headers: &HeaderMap,
) -> Result<ClientId, Refused> {
    let offered = headers.get_all(header::AUTHORIZATION).iter().count();
    let authorizations: Vec<&str> = headers
        .get_all(header::AUTHORIZATION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect();
    // A header that is not UTF-8 is not a credential, and dropping it silently
    // would turn a request that presented one into a request that presented
    // none — which is a different refusal.
    if authorizations.len() != offered {
        return Err(UserInfoError::MalformedCredential.into());
    }
    let presented = userinfo::present(&authorizations, None)?;

    // Step 1.
    let verified =
        access_token::verify(context.tenant, context.keys, presented.token(), context.now)
            .await
            .map_err(|rejected| match rejected {
                access_token::Rejected::Unavailable(error) => Refused::Server(error),
                access_token::Rejected::Token(error) => {
                    // Debug, not warn: a rejected token is routine at a
                    // resource server, and which check failed is a description
                    // of this server's state the caller has not earned.
                    tracing::debug!(%error, "an access evaluation token did not verify");
                    UserInfoError::InvalidToken.into()
                }
            })?;

    // Step 2.
    sender_constrained(api, context, method, headers, &verified, presented).await?;

    // Step 3.
    if !audienced_here(api, context.tenant, &verified) {
        tracing::debug!(
            tenant = %context.tenant.id,
            "a token presented at the access evaluation endpoint is audienced elsewhere"
        );
        return Err(UserInfoError::InvalidToken.into());
    }

    // Step 4.
    let jti = verified
        .claim_str("jti")
        .ok_or(UserInfoError::InvalidToken)?;
    if context.tokens.is_denylisted(jti).await? {
        return Err(UserInfoError::InvalidToken.into());
    }
    let client = ClientId::new(
        verified
            .claim_str("client_id")
            .ok_or(UserInfoError::InvalidToken)?
            .to_owned(),
    );
    let own_grant = verified
        .claim_str("grant_id")
        .map(|id| GrantId::new(id.to_owned()));
    let cutoff = context
        .tokens
        .access_tokens_revoked_before(&client, own_grant.as_ref())
        .await?;
    if access_token::withdrawn(&verified, cutoff) {
        return Err(UserInfoError::InvalidToken.into());
    }

    // Step 5.
    if !carries_scope(&verified, SCOPE_EVALUATE) {
        return Err(Refused::MissingScope);
    }

    Ok(client)
}

/// Step 2, with UserInfo's rule and UserInfo's function.
async fn sender_constrained(
    api: Api,
    context: &AccessEvaluationContext<'_>,
    method: &Method,
    headers: &HeaderMap,
    verified: &Verified,
    presented: Presentation<'_>,
) -> Result<(), Refused> {
    access_token::check_sender_constraint(
        &access_token::Presented {
            tenant: context.tenant,
            dpop: context.dpop,
            target: dpop::ProofTarget::at(api.endpoint()),
            certificate: context.certificate,
            method,
            headers,
            presented,
            now: context.now,
        },
        verified,
    )
    .await
    .map_err(|refusal| match refusal {
        access_token::NotBound::Refused => UserInfoError::InvalidToken.into(),
        access_token::NotBound::Dpop(refusal) => Refused::Dpop(refusal),
    })
}

/// Step 3: the resource is this tenant's access evaluation endpoint.
///
/// The URL is built from the endpoint registry rather than written out, so the
/// audience a PEP must ask for is the URL the metadata advertises and the path
/// the router mounts — three facts, one source (`ast-o0t.3`).
///
/// `aud` may be a string or an array (RFC 7519 §4.1.3), and both are accepted
/// because both are what a token this server minted can carry.
fn audienced_here(api: Api, tenant: &Tenant, verified: &Verified) -> bool {
    let resource = api.endpoint().url(&tenant.issuer);
    match verified.claims.get("aud") {
        Some(Value::String(only)) => *only == resource,
        Some(Value::Array(values)) => values
            .iter()
            .filter_map(Value::as_str)
            .any(|value| value == resource),
        _ => false,
    }
}

/// Step 5: RFC 8693 §4.2's `scope` claim, split on spaces (RFC 6749 §3.3).
fn carries_scope(verified: &Verified, wanted: &str) -> bool {
    verified
        .claim_str("scope")
        .unwrap_or_default()
        .split(' ')
        .any(|scope| scope == wanted)
}

/// §10.1: the request media type, which is `application/json` and nothing else.
///
/// Parameters are permitted — `application/json; charset=utf-8` is the same
/// media type — and the comparison is case-insensitive, as RFC 9110 §8.3.1
/// requires of a media type's name.
pub(crate) fn json_content_type(headers: &HeaderMap) -> Result<(), Refused> {
    let value = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| {
            Refused::Invalid("a request must carry Content-Type: application/json".to_owned())
        })?;
    let media_type = value
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    if media_type == "application/json" {
        return Ok(());
    }
    Err(Refused::Invalid(
        "a request must carry Content-Type: application/json".to_owned(),
    ))
}

// ---------------------------------------------------------------------------
// The trail
// ---------------------------------------------------------------------------

/// One decision in the trail (§11.7's "avoid common attacks" needs an operator
/// who can see them).
///
/// **A summary, never the request.** The subject's and the resource's
/// identifiers are fingerprinted rather than written — an AuthZEN id is
/// routinely an email address, and this table is kept for years — and
/// `properties` are not recorded at all: they are the PEP's description of a
/// person and a document, arriving once per API call it protects, and copying
/// them here would make this trail a mirror of every application's data.
///
/// The `outcome` is the *decision*: a deny is [`Outcome::Failure`], so that an
/// operator filtering the trail for refusals sees them without reading a detail
/// map. `latency_us` is the time from the parsed request to the answer, which
/// is what the p95 in `ast-pj0.1`'s acceptance criteria is measured against.
///
/// Never fails the request: the decision has already been taken, and a trail
/// that could refuse it would be a trail that decides.
async fn record(
    context: &AccessEvaluationContext<'_>,
    pep: &ClientId,
    request: &EvaluationRequest,
    started: std::time::Instant,
    decision: Option<&asterius_domain::policy::Decision>,
    detail: Detail,
) {
    let permitted = decision.is_some_and(asterius_domain::policy::Decision::permit);
    let micros = i64::try_from(started.elapsed().as_micros()).unwrap_or(i64::MAX);
    let mut detail = detail
        .text("subject_type", request.subject.kind())
        .pii("subject_id", request.subject.id())
        .text("action", request.action.name())
        .text("resource_type", request.resource.kind())
        .pii("resource_id", request.resource.id())
        .flag("decision", permitted)
        .number("latency_us", micros);
    if let Some(rule) = decision.and_then(|decision| decision.context().rule()) {
        detail = detail.text("rule", rule.as_str());
    }

    let event = AuditEvent::new(
        context.tenant.id.clone(),
        EventType::ACCESS_EVALUATED,
        if permitted {
            Outcome::Success
        } else {
            Outcome::Failure
        },
        Actor::Client(pep.clone()),
        context.now,
    )
    .client(pep.clone())
    .detail(detail);

    if let Err(error) = context.audit.record(event).await {
        tracing::error!(
            %error,
            tenant = %context.tenant.id,
            client = %pep,
            "an access evaluation was not written to the audit trail"
        );
    }
}

/// One boxcar in the trail: one entry for the request, not one per evaluation
/// (§7.1, `ast-pj0.2`).
///
/// **One entry, deliberately.** An array of a hundred evaluations written as a
/// hundred `access.evaluated` rows would multiply the one table this
/// deployment keeps forever by whatever compaction a PEP happens to use, and
/// it would do it for no gain an investigator can name: the question asked of
/// this trail is "what did this PEP ask, and what did this PDP answer", and a
/// boxcar is one asking. What the entry has to carry, then, is what makes the
/// request reconstructible in shape — how many evaluations, under which of
/// §7.1.2.1's semantics, how many were actually decided (a short circuit
/// stops early), and how they came out.
///
/// The price is that the individual `resource_id`s of a boxcar are not in the
/// trail. That is the same trade the single endpoint already makes with
/// `properties`, one level up, and the thing an investigator would use them
/// for — "which documents did this PEP ask about" — is the PEP's own log to
/// keep: it is the party that chose the list.
///
/// The subject *is* recorded when every evaluation shares one, which is the
/// common case §7.1.1's defaults exist for, because "who was this about" is
/// the one question the counts cannot answer.
///
/// The `outcome` is [`Outcome::Failure`] unless every decided evaluation
/// permitted, so that an operator filtering the trail for refusals still finds
/// the requests that contained one.
async fn record_many(
    context: &AccessEvaluationContext<'_>,
    pep: &ClientId,
    request: &EvaluationsRequest,
    started: std::time::Instant,
    decisions: &Outcomes,
) {
    let permits = decisions
        .iter()
        .filter(|decision| {
            decision
                .as_ref()
                .is_some_and(asterius_domain::policy::Decision::permit)
        })
        .count();
    let failures = decisions
        .iter()
        .filter(|decision| decision.is_none())
        .count();
    let micros = i64::try_from(started.elapsed().as_micros()).unwrap_or(i64::MAX);
    let asked = i64::try_from(request.evaluations.len()).unwrap_or(i64::MAX);
    let decided = i64::try_from(decisions.len()).unwrap_or(i64::MAX);
    let permitted = i64::try_from(permits).unwrap_or(i64::MAX);

    let mut detail = Detail::new()
        .label("semantic", request.semantic.as_str())
        .flag("boxcar", request.boxcar)
        .number("evaluations", asked)
        .number("decided", decided)
        .number("permits", permitted)
        .number("denies", decided.saturating_sub(permitted))
        .number("latency_us", micros);
    if failures > 0 {
        detail = detail
            .label("error", "engine_unavailable")
            .number("failures", i64::try_from(failures).unwrap_or(i64::MAX));
    }
    if let Some(first) = request.evaluations.first()
        && request.evaluations.iter().all(|evaluation| {
            evaluation.subject.kind() == first.subject.kind()
                && evaluation.subject.id() == first.subject.id()
        })
    {
        detail = detail
            .text("subject_type", first.subject.kind())
            .pii("subject_id", first.subject.id());
    }

    let event = AuditEvent::new(
        context.tenant.id.clone(),
        EventType::ACCESS_EVALUATED,
        if failures == 0 && permits == decisions.len() {
            Outcome::Success
        } else {
            Outcome::Failure
        },
        Actor::Client(pep.clone()),
        context.now,
    )
    .client(pep.clone())
    .detail(detail);

    if let Err(error) = context.audit.record(event).await {
        tracing::error!(
            %error,
            tenant = %context.tenant.id,
            client = %pep,
            "an access evaluations request was not written to the audit trail"
        );
    }
}

// ---------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------

/// §10.1.2's error responses, each with the message string that table names.
pub(crate) fn render(context: &AccessEvaluationContext<'_>, refusal: Refused) -> Response {
    match refusal {
        Refused::Client(error) => refuse(&error),
        Refused::MissingScope => insufficient_scope(),
        Refused::Invalid(message) => message_string(StatusCode::BAD_REQUEST, &message),
        Refused::MethodNotAllowed => {
            let mut response = message_string(
                StatusCode::METHOD_NOT_ALLOWED,
                "the access evaluation API is bound to POST",
            );
            // Both endpoints: §10.1 binds the whole API to POST.
            response
                .headers_mut()
                .insert(header::ALLOW, HeaderValue::from_static("POST"));
            response
        }
        Refused::Dpop(refusal) => dpop_challenge(&refusal),
        Refused::Server(error) => {
            tracing::error!(
                %error,
                tenant = %context.tenant.id,
                "cannot answer an access evaluation request"
            );
            message_string(
                StatusCode::INTERNAL_SERVER_ERROR,
                "this policy decision point cannot answer right now",
            )
        }
    }
}

/// §6.2's body: JSON, with the media type §10.1 requires of a response.
pub(crate) fn json(status: StatusCode, body: &Value) -> Response {
    (status, axum::Json(body.clone())).into_response()
}

/// §10.1.2's body: "an error message string".
///
/// Text and not a JSON object. The table is explicit about it, and a PEP that
/// tried to parse one of these as a Decision would find no `decision` member —
/// which is the point: an error is not an authorization outcome.
fn message_string(status: StatusCode, message: &str) -> Response {
    (
        status,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        )],
        message.to_owned(),
    )
        .into_response()
}

/// An RFC 6750 §3 refusal: a status, a challenge per scheme, and no body.
///
/// §11.3 asks for exactly this — "the resource server MUST respond with a 401
/// HTTP status code and SHOULD include the HTTP `WWW-Authenticate` response
/// header field" — and the challenges are the ones every other protected
/// endpoint here answers with, from the same function.
fn refuse(error: &UserInfoError) -> Response {
    let mut response =
        empty(StatusCode::from_u16(error.status()).unwrap_or(StatusCode::UNAUTHORIZED));
    let headers = response.headers_mut();
    for challenge in userinfo::challenges(Some(error)) {
        if let Ok(value) = HeaderValue::from_str(&challenge) {
            headers.append(header::WWW_AUTHENTICATE, value);
        }
    }
    response
}

/// RFC 6750 §3.1's `insufficient_scope`, naming the scope this API needs.
///
/// §3 says the challenge "SHOULD include the `scope` attribute with the scope
/// necessary to access the protected resource", and here that is actionable: a
/// PEP reading it knows to ask the token endpoint for [`SCOPE_EVALUATE`].
fn insufficient_scope() -> Response {
    let mut response = empty(StatusCode::FORBIDDEN);
    if let Ok(value) = HeaderValue::from_str(&format!(
        r#"DPoP error="insufficient_scope", error_description="the access token does not carry the scope this request needs", scope="{SCOPE_EVALUATE}""#
    )) {
        response
            .headers_mut()
            .append(header::WWW_AUTHENTICATE, value);
    }
    response
}

/// A DPoP failure, in the shape a resource server uses (RFC 9449 §7.1, §7.2).
fn dpop_challenge(refusal: &dpop::Refusal) -> Response {
    if let Some(detail) = refusal.detail() {
        tracing::debug!(%detail, "a DPoP proof at the access evaluation endpoint did not check out");
    }
    if refusal.status().is_server_error() {
        return message_string(
            StatusCode::INTERNAL_SERVER_ERROR,
            "this policy decision point cannot answer right now",
        );
    }

    let mut response = empty(StatusCode::UNAUTHORIZED);
    let headers = response.headers_mut();
    if let Ok(value) = HeaderValue::from_str(&format!(
        r#"DPoP error="{}", error_description="the DPoP proof did not check out""#,
        refusal.code()
    )) {
        headers.append(header::WWW_AUTHENTICATE, value);
    }
    if refusal.code() == USE_NONCE
        && let Some(nonce) = refusal.nonce()
        && let Ok(value) = HeaderValue::from_str(nonce)
    {
        headers.insert(NONCE_HEADER, value);
    }
    response
}

/// §10.1.3: the PEP's request identifier, echoed unchanged.
///
/// Only ever a value that arrived on *this* request, bounded at
/// [`MAX_REQUEST_ID`] and required to be a valid header value — a PDP that
/// reflected an arbitrary string would be one a caller could put a header
/// injection through. A request with no identifier gets none here, and
/// [`crate::http::request_id`] puts this server's own on the way out, which is
/// what §10.1.3's "MAY have request identifiers" leaves open.
///
/// The echoed value is deliberately *not* the one the audit trail records:
/// that is this server's own [`crate::http::RequestId`], drawn from the CSPRNG,
/// because a caller that could choose the id in the trail could collide with
/// another caller's entries.
pub(crate) fn echo_request_id(mut response: Response, headers: &HeaderMap) -> Response {
    let Some(value) = headers.get(REQUEST_ID_HEADER) else {
        return response;
    };
    if value.len() > MAX_REQUEST_ID {
        return response;
    }
    let Ok(text) = value.to_str() else {
        return response;
    };
    if let Ok(header) = HeaderValue::from_str(text) {
        response
            .headers_mut()
            .insert(crate::http::request_id::HEADER, header);
    }
    response
}

/// A response with a status and nothing in it.
fn empty(status: StatusCode) -> Response {
    let mut response = Response::new(axum::body::Body::empty());
    *response.status_mut() = status;
    response
}

/// Every response, without exception. A decision is about one person and one
/// resource at one instant; it belongs in no shared cache.
pub(crate) fn no_store(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use asterius_domain::keys::SigningAlgorithm;
    use asterius_domain::{Issuer, TenantStatus};
    use serde_json::json;

    fn tenant() -> Tenant {
        Tenant {
            id: TenantId::new("demo"),
            issuer: Issuer::parse("https://as.example/t/demo").expect("an issuer"),
            default_resource: "https://api.example/".to_owned(),
            custom_host: None,
            display_name: "demo".to_owned(),
            status: TenantStatus::Active,
            refresh: asterius_domain::RefreshPolicy::default(),
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    fn verified(claims: Value) -> Verified {
        Verified {
            claims,
            kid: None,
            algorithm: SigningAlgorithm::DEFAULT,
        }
    }

    fn content_type(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_str(value).expect("a header value"),
        );
        headers
    }

    /// RFC 9068 §3: the audience is *this* tenant's endpoint, and the URL comes
    /// from the registry the metadata is rendered from.
    #[test]
    fn the_audience_must_be_this_tenants_evaluation_endpoint() {
        // Arrange
        let tenant = tenant();
        let here = "https://as.example/t/demo/access/v1/evaluation";

        // Act / Assert
        assert!(audienced_here(
            Api::Single,
            &tenant,
            &verified(json!({"aud": here}))
        ));
        assert!(audienced_here(
            Api::Single,
            &tenant,
            &verified(json!({"aud": ["https://api.example/", here]}))
        ));
        for wrong in [
            json!({"aud": "https://api.example/"}),
            json!({"aud": "https://as.example/t/other/access/v1/evaluation"}),
            json!({"aud": "https://as.example/t/demo/access/v1/evaluations"}),
            json!({"sub": "no audience at all"}),
        ] {
            assert!(
                !audienced_here(Api::Single, &tenant, &verified(wrong.clone())),
                "accepted {wrong} as this endpoint's audience"
            );
        }
    }

    /// §7's boxcar is a resource of its own (§10.1, §12): the token for one
    /// endpoint is not the token for the other, in either direction.
    #[test]
    fn the_two_apis_do_not_accept_each_others_audiences() {
        // Arrange
        let tenant = tenant();
        let single = verified(json!({"aud": "https://as.example/t/demo/access/v1/evaluation"}));
        let boxcar = verified(json!({"aud": "https://as.example/t/demo/access/v1/evaluations"}));

        // Act / Assert
        assert!(audienced_here(Api::Boxcar, &tenant, &boxcar));
        assert!(!audienced_here(Api::Boxcar, &tenant, &single));
        assert!(!audienced_here(Api::Single, &tenant, &boxcar));
    }

    /// §7.2: the answers line up with the requests, whatever order they
    /// finished in — a PEP matches decisions to resources by position.
    #[tokio::test]
    async fn a_batch_answers_in_the_order_it_was_asked() {
        // Arrange: the last future is the one that is ready first.
        let count = 8;
        let pending: Vec<_> = (0..count)
            .map(|index| async move {
                for _ in 0..(count - index) {
                    tokio::task::yield_now().await;
                }
                index
            })
            .collect();

        // Act
        let answers = in_order(pending).await;

        // Assert
        assert_eq!(answers, (0..count).collect::<Vec<_>>());
    }

    /// §11.7: a boxcar decides [`MAX_CONCURRENT`] evaluations at a time, so a
    /// hundred-item array is not a hundred concurrent reads of the store.
    #[tokio::test]
    async fn no_more_than_the_bound_are_in_flight_at_once() {
        // Arrange
        use std::sync::atomic::{AtomicUsize, Ordering};
        let live = std::sync::Arc::new(AtomicUsize::new(0));
        let peak = std::sync::Arc::new(AtomicUsize::new(0));
        let items: Vec<Option<EvaluationRequest>> = (0..MAX_CONCURRENT * 3).map(|_| None).collect();

        // Act: one chunk at a time, counting how many are awake together.
        for batch in items.chunks(MAX_CONCURRENT) {
            let pending: Vec<_> = batch
                .iter()
                .map(|_| {
                    let live = std::sync::Arc::clone(&live);
                    let peak = std::sync::Arc::clone(&peak);
                    async move {
                        let now = live.fetch_add(1, Ordering::SeqCst) + 1;
                        peak.fetch_max(now, Ordering::SeqCst);
                        tokio::task::yield_now().await;
                        live.fetch_sub(1, Ordering::SeqCst);
                    }
                })
                .collect();
            in_order(pending).await;
        }

        // Assert
        assert_eq!(peak.load(Ordering::SeqCst), MAX_CONCURRENT);
    }

    /// RFC 6749 §3.3: `scope` is a space-delimited list, and a prefix of a
    /// granted scope is not a granted scope.
    #[test]
    fn the_evaluate_scope_is_matched_whole() {
        // Arrange
        let token = verified(json!({"scope": "openid authzen.evaluate"}));

        // Act / Assert
        assert!(carries_scope(&token, SCOPE_EVALUATE));
        assert!(!carries_scope(&token, "authzen"));
        assert!(!carries_scope(
            &verified(json!({"sub": "x"})),
            SCOPE_EVALUATE
        ));
    }

    /// §10.1: `application/json`, with or without parameters, and nothing else.
    #[test]
    fn the_request_media_type_is_json() {
        // Arrange / Act / Assert
        assert!(json_content_type(&content_type("application/json")).is_ok());
        assert!(json_content_type(&content_type("application/JSON; charset=utf-8")).is_ok());
        assert!(json_content_type(&content_type("application/x-www-form-urlencoded")).is_err());
        assert!(json_content_type(&HeaderMap::new()).is_err());
    }

    /// §10.1.3: the identifier the PEP sent comes back, unchanged.
    #[test]
    fn a_request_identifier_is_echoed_unchanged() {
        // Arrange
        let mut headers = HeaderMap::new();
        headers.insert(
            REQUEST_ID_HEADER,
            HeaderValue::from_static("bfe9eb29-ab87-4ca3-be83-a1d5d8305716"),
        );

        // Act
        let response = echo_request_id(empty(StatusCode::OK), &headers);

        // Assert
        assert_eq!(
            response
                .headers()
                .get(crate::http::request_id::HEADER)
                .and_then(|value| value.to_str().ok()),
            Some("bfe9eb29-ab87-4ca3-be83-a1d5d8305716")
        );
    }

    /// A request identifier longer than a PDP will reflect is dropped rather
    /// than truncated: half an identifier correlates nothing and is still an
    /// unbounded caller-chosen header if it is not bounded here.
    #[test]
    fn an_over_long_request_identifier_is_not_echoed() {
        // Arrange
        let mut headers = HeaderMap::new();
        headers.insert(
            REQUEST_ID_HEADER,
            HeaderValue::from_str(&"a".repeat(MAX_REQUEST_ID + 1)).expect("a header value"),
        );

        // Act
        let response = echo_request_id(empty(StatusCode::OK), &headers);

        // Assert
        assert!(
            response
                .headers()
                .get(crate::http::request_id::HEADER)
                .is_none(),
            "an over-long request identifier was reflected"
        );
    }

    /// A request that sent none gets none from this function: the middleware's
    /// generated identifier is what the response carries.
    #[test]
    fn a_request_with_no_identifier_is_not_given_one_here() {
        // Act
        let response = echo_request_id(empty(StatusCode::OK), &HeaderMap::new());

        // Assert
        assert!(
            response
                .headers()
                .get(crate::http::request_id::HEADER)
                .is_none()
        );
    }
}
