//! The Policy Decision Point: what a tenant's rules are, and how a request is
//! decided against them (`ast-pj0.4`).
//!
//! Authorization API 1.0 (Final, 2026-01-12) defines the interface between a
//! Policy Enforcement Point and a PDP, and §2 puts "policy language,
//! architecture, and state management aspects of a PDP" out of its scope.
//! [ADR-0011] fills that gap for this build: a small declarative rule model,
//! held as data, over the attributes this `IdP` already owns.
//!
//! Three modules, in the order a request meets them:
//!
//! * [`request`] — §5's information model: subject, action, resource, context,
//!   plus the facts (groups, roles, grants, `acr`) that this server resolves
//!   and a PEP may not assert.
//! * [`document`] — the rule language and its parser, where every bound is
//!   applied.
//! * [`engine`] — evaluation, the [`Decision`] it produces and
//!   [`DeclarativeEngine`], which answers [`crate::ports::PolicyEngine`].
//!
//! # The layering matters here
//!
//! All three live in `asterius-domain`, which `scripts/check-layering.sh`
//! keeps free of `sqlx`, `axum`, `tokio` and every other adapter. That is not
//! tidiness: an evaluator that could read a row mid-decision would be one whose
//! answers depend on I/O, and neither "deterministic" nor "total" would survive
//! it. The only thing that touches storage is [`DeclarativeEngine`], which
//! loads the document *before* evaluation starts.
//!
//! # What is not here
//!
//! The HTTP binding (§10.1's `POST /access/v1/evaluation`), its authentication
//! and its audit are `ast-pj0.1`; the boxcar endpoint is `ast-pj0.2`; PDP
//! metadata is `ast-pj0.3`; the console editor is `ast-f7m.9`. This module is
//! reachable only through the port, so none of them can grow a second idea of
//! what a decision is.
//!
//! [ADR-0011]: https://github.com/AsteriusIT/asterius-idp/blob/main/docs/adr/0011-a-declarative-rule-model-for-the-built-in-pdp.md

pub mod document;
pub mod engine;
pub mod request;

pub use document::{
    AttributeTest, Condition, Effect, GrantMatch, GrantResource, PolicyDocumentError, PolicyRuleId,
    Rule, RuleSet, Source,
};
pub use engine::{Decision, DecisionContext, DeclarativeEngine};
pub use request::{
    Action, ActiveGrant, Context, DetailFact, EvaluationRequest, Properties, RequestError,
    Resource, Subject,
};

use time::OffsetDateTime;

/// A tenant's policy as it was stored, with the stamp the admin API shows.
///
/// The stamp is on the *document* and not on each rule: a policy is replaced
/// whole (there is no route that edits one rule), so "when did this tenant's
/// authorization last change" has one answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredPolicy {
    /// The rules.
    pub rules: RuleSet,
    /// When the document was last written.
    pub updated_at: OffsetDateTime,
}
