//! `POST /access/v1/search/{subject,resource,action}` — the AuthZEN Search
//! APIs (Authorization API 1.0 §8, §10.1, `ast-pj0.6`).
//!
//! §6.1 asks "may Alice read account 123". §8 asks the same question with a
//! hole in it — "who may read account 123", "which accounts may Alice read",
//! "what may Alice do to account 123" — and the PDP answers with the entities
//! that fill it. §8 says those entities "SHOULD" evaluate to permit. Here they
//! **do**: every entity in every page is turned back into an ordinary
//! [`asterius_domain::policy::EvaluationRequest`] by
//! [`asterius_oidc::authzen_search::SearchRequest::candidate`], resolved with
//! the same [`SubjectFacts`](crate::http::access_evaluation::SubjectFacts) and decided by the same
//! [`asterius_domain::ports::PolicyEngine`] a PEP would have called itself,
//! and the ones that do not permit are dropped. There is no second evaluator
//! and no shortcut: a search is a page of evaluations.
//!
//! # The same door as the evaluation endpoint
//!
//! The five credential checks, the audience, the DPoP proof, the scope
//! ([`SCOPE_EVALUATE`]) and the rate limiter
//! ([`LimitedEndpoint::AccessEvaluation`]) are
//! [`crate::http::access_evaluation`]'s, called from there rather than copied:
//! §8 is the same authority asked in a different shape, and a search endpoint
//! with its own copy of those checks would be the place they drift. The
//! audience is still the URL of *this* path, because §9.1.1 advertises each
//! search as its own endpoint and a token minted for one resource is not a
//! token for another.
//!
//! # What can be searched, and what cannot
//!
//! A PDP can only search a set it can enumerate, and saying which sets those
//! are is the honest part of this feature:
//!
//! * **Subjects** (§8.4) are this tenant's own accounts, walked with a cursor
//!   over the directory, each account contributing the subject identifiers it
//!   is known by (`ast-2vk.6`: a `sub` is per sector, so an account a PEP
//!   reaches under one identifier may appear under another). Clients and
//!   agents are **not** enumerated: the rule language has no notion of a
//!   client as a subject — `subject_type` is the PEP's own word, matched as a
//!   string — and this server resolves a subject's facts by subject
//!   identifier, so a client id proposed here would be an entity with no facts
//!   that only ever evaluates to whatever the attribute rules say.
//! * **Resources** (§8.5) are the identifiers the rules name literally and the
//!   ones the subject's live authorizations name — see
//!   [`asterius_domain::policy::search`]. This server holds no catalogue of a
//!   tenant's documents or accounts, so a resource search is **not** a
//!   listing of everything that would permit: it is the subset this PDP can
//!   name. A PEP that needs the rest must enumerate its own table and boxcar
//!   the evaluations (§7).
//! * **Actions** (§8.6) are the action names the applicable rules mention. A
//!   rule that names no action applies to every action and enumerates none.
//!
//! # The cost of one request is bounded before the work
//!
//! A page is at most [`authzen_search::MAX_PAGE`] candidates, the same number
//! §7's boxcar bounds an array at, and the candidates are produced **by the
//! page**: the directory is walked with a cursor and a limit, and the finite
//! sets are sliced before anything is evaluated. Nothing here ever evaluates a
//! whole tenant to answer one request, which is what §11.7 asks of an endpoint
//! a PEP can call in a loop.
//!
//! # Fail closed, and how a search says so
//!
//! An evaluation that cannot be taken is a `decision: false` with an `error`
//! context (§10.1.2), because a PEP has to enforce *something*. The analogue
//! here is an empty `results` with the same error context
//! ([`authzen_search::search_failure_response`]): nothing is returned, and the
//! PEP is told that the emptiness is a failure rather than an answer. An empty
//! page with no error would be the dangerous shape — a PEP that concluded
//! "nobody may do this" from an outage would go on to behave as though a
//! policy had changed.
//!
//! # A search is a controlled disclosure, and it is audited as one
//!
//! `access.searched` records one entry per request: which search, the entities
//! that fixed the query, how many candidates were considered and how many were
//! returned. The identifiers returned are not recorded, for the reason
//! `access.evaluated` does not record `properties` — but the *shape* of the
//! call is, because "which PEP enumerated this tenant's users, and how often"
//! is the question an investigator asks after a PEP's credential leaks.
//! `docs/threat-model.md` carries the row.

use asterius_domain::audit::{Actor, AuditEvent, Detail, EventType, Outcome};
use asterius_domain::policy::{ActiveGrant, Decision, search};
use asterius_domain::ports::PolicyStore;
use asterius_domain::{ClientId, DomainError, LimitedEndpoint, TenantId};
use asterius_oidc::authzen::SCOPE_EVALUATE;
use asterius_oidc::authzen_search::{self, SearchKind, SearchRequest};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::Response;
use serde_json::Value;
use std::collections::BTreeSet;

use crate::http::access_evaluation::{
    AccessEvaluationContext, Api, Refused, authorize, decide_without_enforcing, echo_request_id,
    json, json_content_type, no_store, render,
};

/// One account of the tenant, as a subject search sees it.
#[derive(Debug, Clone)]
pub struct DirectorySubject {
    /// The key that resumes the walk *after* this account.
    ///
    /// Opaque to this module, which never reads it: it goes into the page
    /// token and comes back as the `after` of the next call. What it is is the
    /// directory's business — a username today, a compound key the day the
    /// ordering changes.
    pub cursor: String,
    /// The subject identifiers a PEP could name this account by.
    ///
    /// A list rather than one, because a `sub` is per sector (`ast-2vk.6`) and
    /// an account known to two relying parties has two of them. Each is a
    /// candidate in its own right, and each is evaluated: they resolve to the
    /// same facts, so they permit or deny together, but the id a PEP receives
    /// is one it can actually present back to this PDP.
    pub ids: Vec<String>,
}

/// Where §8.4's candidates come from: this tenant's accounts, in pages.
///
/// Its own port rather than a borrowed repository, for the reason
/// [`SubjectFacts`](crate::http::access_evaluation::SubjectFacts) is one: what this endpoint needs is "one ordered page of
/// the subjects this tenant holds", and a deployment whose directory is
/// elsewhere implements that without this module learning about it.
#[async_trait::async_trait]
pub trait SubjectDirectory: std::fmt::Debug + Send + Sync {
    /// One ordered page of accounts, resuming after `after`.
    ///
    /// The order must be stable and total — a search that paged through a
    /// directory whose order changed would return some accounts twice and skip
    /// others — and at most `limit` accounts must come back, because `limit`
    /// is what bounds the work of the request.
    ///
    /// # Errors
    ///
    /// [`DomainError`] when the directory cannot be read. Never an empty page
    /// for a store that is down: an empty page is an answer, and this one
    /// would be wrong.
    async fn page(
        &self,
        tenant: &TenantId,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Vec<DirectorySubject>, DomainError>;
}

/// What a search endpoint needs: the PDP, plus the two things only a search
/// reads.
pub struct AccessSearchContext<'a> {
    /// Everything the evaluation endpoint needs, and it needs all of it: a
    /// search authenticates the same way and evaluates the same way.
    pub pdp: AccessEvaluationContext<'a>,
    /// The tenant's rule document, read to find out which resources and
    /// actions it *names* (§8.5, §8.6).
    ///
    /// Read directly rather than through [`asterius_domain::ports::PolicyEngine`]
    /// because the question is not "what does this document decide" but "what
    /// entities does it mention", which is
    /// [`asterius_domain::policy::search`]'s and not the evaluator's. Every
    /// candidate it proposes still goes through the engine before it is
    /// returned.
    pub policies: &'a dyn PolicyStore,
    /// §8.4's candidates.
    pub directory: &'a dyn SubjectDirectory,
}

impl std::fmt::Debug for AccessSearchContext<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccessSearchContext")
            .finish_non_exhaustive()
    }
}

/// `POST /access/v1/search/{subject,resource,action}` — §8.
///
/// Never returns `Err`: every outcome is an HTTP response in §10.1.2's shape,
/// exactly as the evaluation endpoint's is.
pub async fn search(
    kind: SearchKind,
    context: AccessSearchContext<'_>,
    method: &Method,
    headers: &HeaderMap,
    body: &[u8],
) -> Response {
    let response = match answer(kind, &context, method, headers, body).await {
        Ok(response) => response,
        Err(refusal) => render(&context.pdp, refusal),
    };
    // §10.1.3, and last, so that it is on a refusal as much as on a page.
    echo_request_id(no_store(response), headers)
}

/// Authenticate, admit, read, search, record.
async fn answer(
    kind: SearchKind,
    context: &AccessSearchContext<'_>,
    method: &Method,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<Response, Refused> {
    if method != Method::POST {
        return Err(Refused::MethodNotAllowed);
    }
    json_content_type(headers)?;
    let pep = authorize(Api::Search(kind), &context.pdp, method, headers).await?;

    // The same budget as the evaluation endpoint, deliberately: §6.1, §7 and
    // §8 are one authority — "this PEP may put questions to the PDP" — and a
    // search with a budget of its own would be a way to buy policy walks the
    // evaluation limiter had already refused.
    let response = crate::http::limits::guard(
        &context.pdp.limits,
        LimitedEndpoint::AccessEvaluation,
        Some(pep.as_str()),
        async || match searched(kind, context, &pep, body).await {
            Ok(response) => response,
            Err(refusal) => render(&context.pdp, refusal),
        },
    )
    .await;
    Ok(response)
}

/// One search, once the limiter has admitted the request.
async fn searched(
    kind: SearchKind,
    context: &AccessSearchContext<'_>,
    pep: &ClientId,
    body: &[u8],
) -> Result<Response, Refused> {
    let request = authzen_search::parse_search(kind, body)?;
    let started = std::time::Instant::now();

    let page = match candidates(context, &request).await {
        Ok(page) => page,
        Err(error) => {
            tracing::error!(
                %error,
                tenant = %context.pdp.tenant.id,
                client = %pep,
                kind = kind.as_str(),
                "a search could not be answered; answering an empty page with an error"
            );
            record(context, pep, &request, started, None).await;
            return Ok(json(
                StatusCode::OK,
                &authzen_search::search_failure_response(),
            ));
        }
    };

    let mut results = Vec::new();
    let mut failures = 0_usize;
    for candidate in &page.entities {
        match permits(context, &request, candidate).await {
            Ok(true) => results.push(result(kind, request.searched_type.as_deref(), candidate)),
            Ok(false) => {}
            Err(error) => {
                // Fail closed, per candidate: an entity this PDP could not
                // decide about is not an entity it may return.
                failures += 1;
                tracing::error!(
                    %error,
                    tenant = %context.pdp.tenant.id,
                    "a search candidate could not be decided; it is not in the page"
                );
            }
        }
    }

    let answered = Answered {
        considered: page.entities.len(),
        returned: results.len(),
        failures,
        more: page.next.is_some(),
    };
    record(context, pep, &request, started, Some(&answered)).await;

    let next = page.next.map(|key| request.next_token(&key));
    Ok(json(
        StatusCode::OK,
        &authzen_search::search_response(results, next.as_deref()),
    ))
}

/// One page of proposed entities, and where the next one resumes.
#[derive(Debug, Default)]
struct Candidates {
    /// The identifiers — a `sub`, a resource id or an action name.
    entities: Vec<String>,
    /// The cursor key of the last entity, when there is more after it.
    next: Option<String>,
}

/// What was answered, for the trail.
#[derive(Debug)]
struct Answered {
    considered: usize,
    returned: usize,
    failures: usize,
    more: bool,
}

/// The candidates of one page, by kind.
///
/// Each branch slices *before* evaluating: the directory is asked for one page
/// and the finite sets are cut to one page, so the work of a request is the
/// page and never the tenant.
async fn candidates(
    context: &AccessSearchContext<'_>,
    request: &SearchRequest,
) -> Result<Candidates, DomainError> {
    match request.kind {
        SearchKind::Subject => subjects(context, request).await,
        SearchKind::Resource | SearchKind::Action => {
            let named = named_entities(context, request).await?;
            Ok(slice(
                named,
                request.page.after.as_deref(),
                request.page.limit,
            ))
        }
    }
}

/// §8.4: this tenant's accounts, one page at a time.
///
/// Over-fetching by one is how the walk knows whether to mint a token without
/// a second query — and without minting one on a full last page, which sends
/// the PEP round again for nothing.
async fn subjects(
    context: &AccessSearchContext<'_>,
    request: &SearchRequest,
) -> Result<Candidates, DomainError> {
    let limit = request.page.limit;
    let mut accounts = context
        .directory
        .page(
            &context.pdp.tenant.id,
            request.page.after.as_deref(),
            limit.saturating_add(1),
        )
        .await?;
    let more = accounts.len() > limit;
    accounts.truncate(limit);
    let next = more.then(|| accounts.last().map(|last| last.cursor.clone()));
    Ok(Candidates {
        entities: accounts
            .into_iter()
            .flat_map(|account| account.ids)
            .collect(),
        next: next.flatten(),
    })
}

/// §8.5's and §8.6's finite sets: what this tenant's rules and this subject's
/// authorizations name.
async fn named_entities(
    context: &AccessSearchContext<'_>,
    request: &SearchRequest,
) -> Result<BTreeSet<String>, DomainError> {
    let Some(stored) = context.policies.load(&context.pdp.tenant.id).await? else {
        // No document is a deny of everything (`ast-pj0.4`), and a search of
        // everything that is denied is empty.
        return Ok(BTreeSet::new());
    };
    let searched = request.searched_type.as_deref().unwrap_or_default();
    match request.kind {
        SearchKind::Action => {
            let subject_type = request
                .subject
                .as_ref()
                .map(asterius_domain::policy::Subject::kind)
                .unwrap_or_default();
            let resource_type = request
                .resource
                .as_ref()
                .map(asterius_domain::policy::Resource::kind)
                .unwrap_or_default();
            Ok(search::candidate_actions(
                &stored.rules,
                subject_type,
                resource_type,
            ))
        }
        SearchKind::Resource => {
            let grants = match request.subject.as_ref() {
                None => Vec::new(),
                Some(subject) => {
                    let facts = context
                        .pdp
                        .subjects
                        .resolve(&context.pdp.tenant.id, subject.kind(), subject.id())
                        .await?;
                    facts
                        .grants
                        .iter()
                        .filter_map(|grant| ActiveGrant::of(grant, context.pdp.now))
                        .collect()
                }
            };
            Ok(search::candidate_resources(
                &stored.rules,
                &grants,
                searched,
            ))
        }
        // A subject search does not read the document: its candidates are the
        // directory's, and every one of them is evaluated against the document
        // anyway.
        SearchKind::Subject => Ok(BTreeSet::new()),
    }
}

/// One page of an ordered finite set, resuming strictly after `after`.
///
/// Ordered and exclusive, which is what makes the cursor correct under change:
/// an entity added to the set while a PEP pages through appears only if it
/// sorts after the cursor, and none is returned twice.
fn slice(named: BTreeSet<String>, after: Option<&str>, limit: usize) -> Candidates {
    let mut remaining = named
        .into_iter()
        .filter(|name| after.is_none_or(|after| name.as_str() > after));
    let entities: Vec<String> = remaining.by_ref().take(limit).collect();
    let more = remaining.next().is_some();
    let next = more.then(|| entities.last().cloned()).flatten();
    Candidates { entities, next }
}

/// Whether one candidate evaluates to permit (§8: the results "SHOULD" — here
/// do).
///
/// Through [`decide_without_enforcing`], which is the *same* function the
/// evaluation endpoint's own decision path and the console's test bench
/// (`ast-f7m.9`) go through: it resolves the subject's facts from this
/// server's rows, attaches them with `ActiveGrant::of` and the tenant's `acr`
/// ladder, and asks the engine. A copy of those three steps here would be a
/// second opinion about who a subject is, and a search whose page disagreed
/// with the evaluation a PEP makes next is the one defect §8 cannot afford.
///
/// What the function deliberately does *not* do is the per-request work: no
/// limiter token (one was spent for the whole search) and no
/// `access.evaluated` record (nothing enforced this; the request is recorded
/// once as `access.searched`).
///
/// The facts are resolved for the subject of *this* candidate: a subject
/// search names a different principal in every candidate, so a single
/// resolution would be a page decided about somebody else.
async fn permits(
    context: &AccessSearchContext<'_>,
    request: &SearchRequest,
    candidate: &str,
) -> Result<bool, DomainError> {
    let evaluation = request
        .candidate(candidate)
        .map_err(|error| DomainError::invalid("search candidate", error.to_string()))?;
    let decision: Decision = decide_without_enforcing(
        context.pdp.engine,
        context.pdp.subjects,
        context.pdp.acr,
        &context.pdp.tenant.id,
        &evaluation,
        context.pdp.now,
    )
    .await?;
    Ok(decision.permit())
}

/// One element of §8.3's `results`, in the shape §5 gives that entity.
fn result(kind: SearchKind, searched_type: Option<&str>, id: &str) -> Value {
    match kind {
        SearchKind::Action => authzen_search::action_result(id),
        SearchKind::Subject | SearchKind::Resource => {
            authzen_search::subject_result(searched_type.unwrap_or_default(), id)
        }
    }
}

/// One search in the trail.
///
/// A summary, never the answer: the entities returned are not recorded, for
/// the reason `access.evaluated` does not record `properties`. What is
/// recorded is the *shape* of the disclosure — which search, over what, how
/// many candidates, how many results, and whether there is more — because that
/// is what an investigator needs to see a PEP walking a tenant.
///
/// `outcome` is [`Outcome::Failure`] when the search could not be answered at
/// all or when a candidate could not be decided, so that a filter for
/// refusals finds the pages that are short of what they should have held.
async fn record(
    context: &AccessSearchContext<'_>,
    pep: &ClientId,
    request: &SearchRequest,
    started: std::time::Instant,
    answered: Option<&Answered>,
) {
    let micros = i64::try_from(started.elapsed().as_micros()).unwrap_or(i64::MAX);
    let mut detail = Detail::new()
        .label("search", request.kind.as_str())
        .number("latency_us", micros);
    if let Some(searched) = request.searched_type.as_deref() {
        detail = detail.text("searched_type", searched);
    }
    if let Some(subject) = request.subject.as_ref() {
        detail = detail
            .text("subject_type", subject.kind())
            .pii("subject_id", subject.id());
    }
    if let Some(action) = request.action.as_ref() {
        detail = detail.text("action", action.name());
    }
    if let Some(resource) = request.resource.as_ref() {
        detail = detail
            .text("resource_type", resource.kind())
            .pii("resource_id", resource.id());
    }
    detail = detail.flag("paged", request.page.after.is_some());
    match answered {
        None => detail = detail.label("error", "engine_unavailable"),
        Some(answered) => {
            detail = detail
                .number(
                    "candidates",
                    i64::try_from(answered.considered).unwrap_or(i64::MAX),
                )
                .number(
                    "results",
                    i64::try_from(answered.returned).unwrap_or(i64::MAX),
                )
                .flag("more", answered.more);
            if answered.failures > 0 {
                detail = detail.label("error", "engine_unavailable").number(
                    "failures",
                    i64::try_from(answered.failures).unwrap_or(i64::MAX),
                );
            }
        }
    }

    let failed = answered.is_none_or(|answered| answered.failures > 0);
    let event = AuditEvent::new(
        context.pdp.tenant.id.clone(),
        EventType::ACCESS_SEARCHED,
        if failed {
            Outcome::Failure
        } else {
            Outcome::Success
        },
        Actor::Client(pep.clone()),
        context.pdp.now,
    )
    .client(pep.clone())
    .detail(detail);

    if let Err(error) = context.pdp.audit.record(event).await {
        tracing::error!(
            %error,
            tenant = %context.pdp.tenant.id,
            client = %pep,
            "an access search was not written to the audit trail"
        );
    }
}

/// The scope a search needs, which is the scope an evaluation needs.
///
/// Re-exported so that a reader of this module does not have to go looking:
/// §8 is the same authority as §6.1, and `crates/oidc/src/authzen.rs` argues
/// why there is one scope for the whole Authorization API.
pub const SCOPE: &str = SCOPE_EVALUATE;

#[cfg(test)]
mod tests {
    use super::*;

    /// §8.2: a page is sliced from an ordered set, exclusive of the cursor, so
    /// that nothing is returned twice and nothing is skipped.
    #[test]
    fn a_page_resumes_strictly_after_the_cursor() {
        // Arrange
        let named: BTreeSet<String> = ["a", "b", "c", "d"]
            .into_iter()
            .map(str::to_owned)
            .collect();

        // Act
        let first = slice(named.clone(), None, 2);
        let second = slice(named, first.next.as_deref(), 2);

        // Assert
        assert_eq!(first.entities, vec!["a".to_owned(), "b".to_owned()]);
        assert_eq!(first.next.as_deref(), Some("b"));
        assert_eq!(second.entities, vec!["c".to_owned(), "d".to_owned()]);
        assert!(
            second.next.is_none(),
            "a full last page must not mint a token"
        );
    }

    /// A set smaller than one page is one page, and the last page carries no
    /// cursor.
    #[test]
    fn a_short_page_is_the_last_page() {
        // Arrange
        let named: BTreeSet<String> = ["only".to_owned()].into_iter().collect();

        // Act
        let page = slice(named, None, 25);

        // Assert
        assert_eq!(page.entities, vec!["only".to_owned()]);
        assert!(page.next.is_none());
    }
}
