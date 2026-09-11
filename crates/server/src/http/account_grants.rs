//! The grants dashboard: what stands open in a person's name, and one button
//! per row to close it (`ast-uwv.6`).
//!
//! Grant Management for OAuth 2.0 ID1 §3 names the use case this page answers:
//! a deployment needs somewhere "the user can see the grants that are active
//! and revoke them". OIDC Core §3.1.2.4 is the other half — what a person
//! agreed to at the consent screen is a decision they keep holding, and a
//! decision that cannot be reversed where it was made is a decision made once
//! and never again. FAPI 2.0 SP §7 decides the *wording*: every name here is a
//! claim a client made about itself at registration, rendered as a claim.
//!
//! Three routes, the approvals inbox's shape (`ast-lh3.6`) because it is the
//! same kind of page — a first-party account page reached with a session
//! cookie, with no client anywhere near it:
//!
//! * `GET /account/grants` lists this person's standing authorizations;
//! * `POST /account/grants/revoke` withdraws one;
//! * `GET /account/grants/sign-in` opens a fresh authentication for a person
//!   whose session is too old to withdraw with.
//!
//! # The revocation is the API's, and it is the same call
//!
//! Grant Management ID1 §6.5 says the server "MUST revoke the respective grant
//! and all refresh tokens issued based on that grant" and "SHOULD also revoke
//! all access tokens". This page does not reimplement any of that: it makes
//! the same [`PgGrantRepository::revoke`] call
//! `crate::http::protocol`'s `StoredGrants` makes for `DELETE /grants/{id}`,
//! with the same [`RevocationReason::UserRevoked`] and the same empty list of
//! named live access tokens — what reaches those is the access-token cutoff
//! the transaction writes (`ast-m9c.13`). One cascade, one transaction, two
//! doors into it.
//!
//! # Only this person's grants, and a guessed id is answered as a missing one
//!
//! The list comes from [`PgGrantRepository::list_for_user`] — by local account
//! id, not by `sub`, because a pairwise deployment gives one person a
//! different `sub` per sector (OIDC Core §8.1) and a listing by subject would
//! silently omit whole sectors. The withdrawal re-reads the row and checks
//! `grant.user` against the session's account before it writes anything, and a
//! row belonging to somebody else is answered exactly as a row that does not
//! exist: Grant Management ID1 §6.6's reasoning, which this server already
//! applies at the API — distinguishing the two is an oracle over identifiers
//! nobody is meant to enumerate.
//!
//! # Freshness, and why there is no per-grant `acr` ceiling
//!
//! Withdrawing needs an authentication from the last [`FRESHNESS`], the
//! inbox's rule for the inbox's reason: a browser somebody left open in a café
//! is a browser an attacker gets for free, and here what they would get is the
//! ability to cut somebody off from their own integrations. A stale session is
//! not refused, it is sent to authenticate again and comes back.
//!
//! What is deliberately *not* required is that the session reach the `acr` the
//! grant was made at. That rule sounds prudent and fails in one direction
//! only: a person whose passkey is lost or stolen — the person with the most
//! urgent reason to withdraw everything — is exactly the person who cannot
//! reach that rung any more. Revocation is the safe direction, so the tenant's
//! ladder is applied as *admission* (a session this tenant cannot classify at
//! all does not get the page) and never as a floor per row.
//!
//! # CSRF
//!
//! The withdrawal form carries a synchroniser token derived from the session's
//! *digest*, which the browser does not hold, under a separator of this page's
//! own — `crate::http::device::csrf_for`'s argument. A forged withdrawal is a
//! denial of service against somebody's integrations, and the digest is the
//! one session-bound value a cross-origin page can make the browser send but
//! cannot read.

use asterius_domain::audit::{Actor, AuditEvent, AuditSink, Detail, EventType, Outcome};
use asterius_domain::entities::grant::RevocationReason;
use asterius_domain::{
    AcrPolicy, ClientRepository, FirstPartyDestination, Grant, GrantId, InteractionRepository,
    Session, SessionId as DomainSessionId, SessionRepository, Tenant, UserDirectory, UserId,
    entities::session,
};
use asterius_store_pg::PgGrantRepository;
use asterius_web::Brand;
use asterius_web::i18n::Catalog;
use asterius_web::interaction::{self, InteractionId};
use asterius_web::pages::{
    self, DelegationLine, ErrorPage, GrantLine, GrantsPage, ScopeLine, nonce_attribute,
};
use asterius_web::{Document, csp::Nonce};
use axum::body::Bytes;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

use crate::http::redirect::SeeOther;
use crate::tenancy::MountPrefix;

/// Where the dashboard lives.
pub const PAGE_PATH: &str = "/account/grants";

/// Where a withdrawal posts.
pub const REVOKE_PATH: &str = "/account/grants/revoke";

/// Where a person goes to authenticate again.
pub const SIGN_IN_PATH: &str = "/account/grants/sign-in";

/// How recently somebody must have authenticated to withdraw access.
///
/// The approvals inbox's two minutes, for its reason and with its shape (OIDC
/// Core §3.1.2.1's `max_age`): long enough to read a page and press a button,
/// short enough that the authentication and the decision are one act.
pub const FRESHNESS: Duration = Duration::seconds(120);

/// How long a sign-in opened from this page stays open.
const ENTRY_LIFETIME: Duration = Duration::minutes(10);

/// The largest withdrawal body this page will read.
///
/// A synchroniser token and a UUID. The inbox's four kilobytes, and it is a
/// bound rather than a format check: it is what stops a caller making this
/// server buffer.
pub const MAX_BODY: usize = 4 * 1024;

/// The length of the one identifier this form carries.
///
/// A hyphenated UUID (RFC 9562 §4): `8-4-4-4-12`.
const GRANT_ID_CHARS: usize = 36;

/// The longest synchroniser token this parser will carry.
///
/// The real one is 64 hex characters. The bound is a promise that a caller
/// cannot make this function allocate without limit, not a format check.
const MAX_CSRF_CHARS: usize = 256;

/// A withdrawal form, after parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Withdrawal {
    /// The synchroniser token the form carried.
    pub csrf: String,
    /// Which grant is being withdrawn, as a hyphenated lower-case UUID.
    pub grant: String,
}

/// Reads a withdrawal form, or refuses it.
///
/// Every refusal is `None`, because the caller answers all of them with one
/// page: a body that is too large, that is not UTF-8, that names a parameter
/// twice (RFC 6749 §3.1's parameter pollution, applied to this server's own
/// forms), or that carries a grant id which is not the shape this server
/// mints.
///
/// The id is checked for *shape* here and for *ownership* in the statement
/// that acts on it: this function cannot know whose grant it is, and a
/// validator that pretended to would be the one place somebody later trusted
/// instead of the predicate. The shape check is strict about case, unlike
/// `Uuid::parse_str`, which accepts braces, urn prefixes and upper case: this
/// server renders lower-case hyphenated UUIDs and nothing else, so anything
/// else is a body it did not write and will not read.
// fuzz-target: grant_withdrawal_form
#[must_use]
pub fn withdrawal(body: &[u8]) -> Option<Withdrawal> {
    if body.len() > MAX_BODY {
        return None;
    }
    let text = std::str::from_utf8(body).ok()?;

    let mut csrf: Option<String> = None;
    let mut grant: Option<String> = None;
    for (key, value) in url::form_urlencoded::parse(text.as_bytes()) {
        // A repeated parameter is refused outright rather than resolved to the
        // first or the last. Both resolutions are a choice an attacker can
        // exploit once anything downstream makes the other one.
        match key.as_ref() {
            "csrf" if csrf.is_some() => return None,
            "csrf" => csrf = Some(value.into_owned()),
            "grant" if grant.is_some() => return None,
            "grant" => grant = Some(value.into_owned()),
            _ => {}
        }
    }

    let csrf = csrf?;
    let grant = grant?;
    if csrf.is_empty() || csrf.chars().count() > MAX_CSRF_CHARS {
        return None;
    }
    if !is_grant_id(&grant) {
        return None;
    }
    Some(Withdrawal { csrf, grant })
}

/// Whether this is the spelling of a grant id this server writes.
///
/// Thirty-six characters: lower-case hex with hyphens at the four positions
/// RFC 9562 §4 puts them. Checked before the store is asked, so a submission
/// that could not name a row costs a comparison rather than a query.
fn is_grant_id(value: &str) -> bool {
    if value.len() != GRANT_ID_CHARS {
        return false;
    }
    value.bytes().enumerate().all(|(index, byte)| {
        if matches!(index, 8 | 13 | 18 | 23) {
            byte == b'-'
        } else {
            byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
        }
    })
}

/// One standing authorization and everything minted from it by delegation.
///
/// The grouping the page renders: a token exchange creates a *child* grant
/// (RFC 8693 §4.1, `ast-lh3.9`), and a child is not something a person allowed
/// separately — it is what the access they did allow was passed on to. Listing
/// it as an entry of its own would invite somebody to withdraw the delegation
/// and believe they had closed the door the parent is holding open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Standing {
    /// The authorization itself.
    pub grant: Grant,
    /// What was minted from it, newest first.
    pub delegations: Vec<Grant>,
}

/// Groups one account's grants into what the dashboard shows.
///
/// * A grant is listed when it can still issue a credential — Grant Management
///   ID1 §5.6's `pending` or `active`. A revoked one is over, and an expired
///   one no longer authorises anything; listing either beside a live grant
///   would put "withdraw" next to a row where the button changes nothing.
/// * A grant reachable from another listed grant by its `parent` links is a
///   delegation of it, and is attached rather than listed — at whatever depth,
///   because a tenant may permit a chain several hops long
///   (`AgentLimits::max_delegation_depth`) and a grandchild attached to
///   nothing would be a delegation nobody can see.
/// * A delegation is attached even when it has itself expired, because "when
///   did this agent last act as me" is a fact about the past and it is the
///   fact an agent grant is read for.
/// * A grant whose ancestry leads nowhere on this page — the parent was
///   withdrawn, or belongs to somebody else — is listed on its own, so that
///   nothing a person might want to withdraw can go missing.
#[must_use]
pub fn standing(grants: Vec<Grant>, now: OffsetDateTime) -> Vec<Standing> {
    let parents: std::collections::BTreeMap<String, Option<String>> = grants
        .iter()
        .map(|grant| {
            (
                grant.id.as_str().to_owned(),
                grant
                    .parent
                    .as_ref()
                    .map(|parent| parent.as_str().to_owned()),
            )
        })
        .collect();
    let live: std::collections::BTreeSet<String> = grants
        .iter()
        .filter(|grant| grant.status(now).may_issue())
        .map(|grant| grant.id.as_str().to_owned())
        .collect();

    // The listed grant a row belongs under: itself when its parent is not on
    // this page, and otherwise the furthest ancestor that is. Bounded by the
    // number of grants, so a `parent` cycle — which nothing writes, and which
    // a row could only hold through corruption — terminates rather than hangs.
    let root_of = |id: &str| -> Option<String> {
        let mut current = id.to_owned();
        for _ in 0..parents.len() {
            match parents.get(&current).and_then(Clone::clone) {
                Some(parent) if live.contains(&parent) => current = parent,
                _ => return Some(current),
            }
        }
        None
    };

    let mut children: Vec<Grant> = grants
        .iter()
        .filter(|grant| grant.revoked_at.is_none())
        .filter(|grant| root_of(grant.id.as_str()).is_some_and(|root| root != grant.id.as_str()))
        .cloned()
        .collect();
    children.sort_by_key(|child| std::cmp::Reverse(child.created_at));

    grants
        .into_iter()
        .filter(|grant| live.contains(grant.id.as_str()))
        .filter(|grant| root_of(grant.id.as_str()).as_deref() == Some(grant.id.as_str()))
        .map(|grant| {
            let delegations = children
                .iter()
                .filter(|child| root_of(child.id.as_str()).as_deref() == Some(grant.id.as_str()))
                .cloned()
                .collect();
            Standing { grant, delegations }
        })
        .collect()
}

/// What the dashboard needs.
pub struct GrantsContext<'a> {
    /// The tenant the request arrived at.
    pub tenant: &'a Tenant,
    /// This person's authorizations, and the one write this page makes.
    pub grants: &'a PgGrantRepository,
    /// Where the cookie's session is resolved.
    pub sessions: &'a dyn SessionRepository,
    /// Where a sign-in is opened for a session too old to withdraw with.
    pub interactions: &'a dyn InteractionRepository,
    /// This tenant's clients, for the names and the agent profiles the page
    /// shows.
    pub clients: &'a dyn ClientRepository,
    /// Where an agent's owner is resolved to an account somebody recognises.
    pub users: &'a dyn UserDirectory,
    /// The authentication contexts this tenant can produce (`ast-2vk.7`).
    pub acr: &'a AcrPolicy,
    /// The words this page is rendered with.
    pub text: &'a Catalog,
    /// The CSP nonce the document middleware drew for this response.
    pub nonce: &'a Nonce,
    /// The trail. A withdrawal is recorded whether or not anybody polls it.
    pub audit: &'a dyn AuditSink,
    /// The prefix routing removed from this request's path (`ast-295`).
    pub mount: MountPrefix,
}

impl std::fmt::Debug for GrantsContext<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GrantsContext").finish_non_exhaustive()
    }
}

/// `GET /account/grants` — what stands open.
pub async fn page(
    context: &GrantsContext<'_>,
    headers: &HeaderMap,
    now: OffsetDateTime,
) -> Response {
    let Some(session) = admitted(context, headers, now).await else {
        return begin(context, now).await;
    };
    rendered(context, &session, None, StatusCode::OK, now).await
}

/// `GET /account/grants/sign-in` — authenticate again, and come back.
///
/// A route rather than a link into the interaction pages, for the reason the
/// inbox gives: the interaction has to be *opened*, and its destination is a
/// variant of a closed enumeration rather than a URL anybody can supply
/// (ADR-0009). It is a `GET` that writes a ten-minute login attempt and
/// changes nothing about this account.
pub async fn sign_in(context: &GrantsContext<'_>, now: OffsetDateTime) -> Response {
    begin(context, now).await
}

/// `POST /account/grants/revoke` — withdraw one authorization.
pub async fn revoke(
    context: &GrantsContext<'_>,
    headers: &HeaderMap,
    body: &Bytes,
    now: OffsetDateTime,
) -> Response {
    let Some(session) = admitted(context, headers, now).await else {
        return begin(context, now).await;
    };
    let Some(form) = withdrawal(body) else {
        return refused(context, &session, now).await;
    };
    if !checked_csrf(&session, &form.csrf) {
        return refused(context, &session, now).await;
    }
    // Freshness before the row is read, because it is a fact about the
    // *person*: a session too old to withdraw with is too old to withdraw
    // anything with, and sending it to authenticate again is the answer to all
    // of them. Deciding it first also means a stale session learns nothing
    // about whether the id it submitted names a row.
    if !fresh(&session, now) {
        return begin(context, now).await;
    }

    let id = GrantId::new(form.grant);
    let user = UserId::new(session.user);
    let grant = match context.grants.find(&id).await {
        Ok(Some(grant)) => grant,
        Ok(None) => return gone(context, &session, now).await,
        Err(error) => {
            tracing::error!(%error, tenant = %context.tenant.id, "cannot read a grant");
            return error_page(context, StatusCode::SERVICE_UNAVAILABLE);
        }
    };
    // §6.6's reasoning: somebody else's grant and no such grant are one
    // answer. The repository is already scoped to this tenant, so what is left
    // to check here is the account.
    if grant.user != Some(user) {
        tracing::info!(
            tenant = %context.tenant.id,
            "a withdrawal named a grant that is not the signed-in account's"
        );
        return gone(context, &session, now).await;
    }

    // The Grant Management endpoint's call, unchanged: one transaction that
    // marks the refresh tokens, writes the access-token cutoff and stamps the
    // grant last. No live access tokens are named because this server keeps no
    // record of the stateless ones (RFC 9068) — the cutoff is what reaches
    // them.
    match context
        .grants
        .revoke(&id, RevocationReason::UserRevoked, &[], now)
        .await
    {
        Ok(_) => {
            record(context, &session, &grant, now).await;
            notify_grant_revoked(context, &grant);
            rendered(
                context,
                &session,
                Some(context.text.grants_revoked()),
                StatusCode::OK,
                now,
            )
            .await
        }
        // The grant was live when it was read and is not now: a second tab, a
        // double-pressed button. `NotFound` is also what an already-withdrawn
        // grant returns, which is the same page.
        Err(asterius_domain::DomainError::NotFound) => gone(context, &session, now).await,
        Err(error) => {
            tracing::error!(%error, tenant = %context.tenant.id, "cannot withdraw a grant");
            error_page(context, StatusCode::SERVICE_UNAVAILABLE)
        }
    }
}

/// Whether this authentication happened recently enough to withdraw with.
fn fresh(session: &Session, now: OffsetDateTime) -> bool {
    now - session.authenticated_at <= FRESHNESS && session.authenticated_at <= now
}

/// The session behind the cookie, when it is one this tenant will let read the
/// page.
///
/// The inbox's admission, for its reasons: the session must be usable and
/// belong to this tenant, and where the tenant has an authentication ladder
/// the session must reach a rung of it. A tenant that has configured no levels
/// has expressed no requirement, and inventing one here would leave such a
/// deployment with a dashboard nobody can open.
async fn admitted(
    context: &GrantsContext<'_>,
    headers: &HeaderMap,
    now: OffsetDateTime,
) -> Option<Session> {
    let cookies = crate::http::cookies(headers);
    let value = interaction::cookie_value(&cookies, session::COOKIE_NAME)?;
    let digest = asterius_domain::sha256_hex(value.as_bytes());
    let session = match context.sessions.find(&digest).await {
        Ok(session) => session?,
        Err(error) => {
            tracing::error!(%error, tenant = %context.tenant.id, "cannot read a session");
            return None;
        }
    };
    if session.tenant != context.tenant.id || !session.status(now).is_usable() {
        return None;
    }
    if !context.acr.levels().is_empty() && context.acr.achieved(&session.amr).is_none() {
        tracing::info!(
            tenant = %context.tenant.id,
            "the grants dashboard was asked for by a session this tenant cannot classify"
        );
        return None;
    }
    Some(session)
}

/// The synchroniser token for this session, under this page's separator.
///
/// Derived from the session's *digest*, which the browser does not hold: a
/// page forged on another origin can make the browser send the session cookie,
/// which is the whole of what CSRF is, but it cannot read it and so cannot
/// compute this. A separator of this page's own, so a token lifted from
/// another of this server's forms is not one this endpoint accepts.
fn csrf_for(session: &Session) -> String {
    asterius_domain::sha256_hex(format!("{}:account-grants-csrf", session.id_digest).as_bytes())
}

/// Compares a submitted token against the one this session's pages carry.
fn checked_csrf(session: &Session, presented: &str) -> bool {
    asterius_domain::ct_eq(presented.as_bytes(), csrf_for(session).as_bytes())
}

/// The page, with whatever there is to say on it.
async fn rendered(
    context: &GrantsContext<'_>,
    session: &Session,
    message: Option<&str>,
    status: StatusCode,
    now: OffsetDateTime,
) -> Response {
    let held = match context
        .grants
        .list_for_user(&UserId::new(session.user))
        .await
    {
        Ok(grants) => grants,
        Err(error) => {
            tracing::error!(%error, tenant = %context.tenant.id, "cannot list a person's grants");
            return error_page(context, StatusCode::SERVICE_UNAVAILABLE);
        }
    };

    let standing = standing(held, now);
    let mut grants = Vec::with_capacity(standing.len());
    for entry in standing {
        grants.push(line(context, entry).await);
    }

    // A stale session is shown the page and told to sign in again rather than
    // being redirected out of it: the redirect belongs to the moment somebody
    // presses a button, not to the moment they read the list.
    let message = match message {
        Some(message) => Some(message),
        None if !fresh(session, now) && !grants.is_empty() => Some(context.text.grants_stale()),
        None => None,
    };

    let font_url = crate::http::font_url(&context.mount);
    let action = context.mount.absolute(REVOKE_PATH);
    let sign_in_href = context.mount.absolute(SIGN_IN_PATH);
    let csrf = csrf_for(session);
    let document = Document::render(context.nonce, |nonce| {
        pages::render(&GrantsPage {
            text: context.text,
            tenant_name: &context.tenant.display_name,
            grants: grants.clone(),
            action: &action,
            sign_in_href: &sign_in_href,
            csrf: &csrf,
            message,
            nonce_attribute: nonce_attribute(nonce),
            theme_css: "",
            brand: Brand::new(&font_url),
        })
    });
    (status, no_store(), document).into_response()
}

/// One row of the list.
async fn line(context: &GrantsContext<'_>, entry: Standing) -> GrantLine {
    let Standing { grant, delegations } = entry;
    let mut lines = Vec::with_capacity(delegations.len());
    for delegation in &delegations {
        lines.push(DelegationLine {
            client_name: client_name(context, &delegation.client).await,
            actors: actors(delegation),
            delegated_at: stamp(delegation.created_at),
        });
    }
    // The most recent exchange, which for an agent grant is the fact the row
    // is read for: when this agent last acted as somebody. `delegations` is
    // newest first, so it is the head.
    let last_exchange = delegations.first().map(|child| stamp(child.created_at));

    GrantLine {
        reference: grant.id.as_str().to_owned(),
        client_name: client_name(context, &grant.client).await,
        agent_owner: agent_owner(context, &grant.client).await,
        scopes: grant
            .scopes
            .iter()
            .map(|scope| ScopeLine {
                // No description, for the reason the inbox gives: the
                // sentences a tenant writes for its scopes belong to the
                // consent screen, and a half-populated copy of them would show
                // a described scope on one page and a bare token on the other.
                name: scope.clone(),
                description: None,
                required: true,
            })
            .collect(),
        authorization_details: crate::http::device::detail_lines(&serde_json::Value::Array(
            grant.authorization_details.clone(),
        )),
        resources: grant.resources.iter().cloned().collect(),
        granted_at: stamp(grant.created_at),
        // `claimed_at` says whether a credential was ever taken from this
        // grant, and `updated_at` says when the row was last written — which
        // for a claimed grant is the last claim, because every claim rewrites
        // it (`PgGrantRepository::claim`, and the `grants_set_updated_at`
        // trigger). A grant nobody has claimed from has never been used, and
        // says so rather than showing the instant it was created a second
        // time.
        last_used: grant.claimed_at.map(|_| stamp(grant.updated_at)),
        last_exchange,
        delegations: lines,
    }
}

/// The `act` chain of a delegation, outermost actor first (RFC 8693 §4.1).
///
/// Each entry is whatever the chain recorded as the actor's identity — a `sub`
/// or a `client_id` — and never a credential: the chain this server writes
/// carries identifiers and nothing else (`ast-lh3.9`). An element this
/// function cannot read as one of those is skipped rather than rendered as
/// JSON, for RFC 9396 §12's reason: a page must not show a person
/// attacker-composed text and imply that it means something.
fn actors(grant: &Grant) -> Vec<String> {
    grant
        .actor_chain
        .iter()
        .filter_map(|actor| {
            actor
                .get("sub")
                .or_else(|| actor.get("client_id"))
                .and_then(serde_json::Value::as_str)
                .map(ToOwned::to_owned)
        })
        .collect()
}

/// An instant, RFC 3339, or an empty string.
///
/// Empty rather than a fallback spelling: the value reaches a `datetime`
/// attribute, and an attribute holding something that is not a timestamp is
/// worse than one holding nothing. `OffsetDateTime` formatting fails only for
/// values outside the range RFC 3339 can express, which a `timestamptz` this
/// server wrote is not.
fn stamp(instant: OffsetDateTime) -> String {
    instant.format(&Rfc3339).unwrap_or_default()
}

/// The client's registered name, or a placeholder.
///
/// A name chosen at registration, escaped into the markup like the one on the
/// consent screen and trusted as little (FAPI 2.0 SP §7).
async fn client_name(context: &GrantsContext<'_>, client: &asterius_domain::ClientId) -> String {
    match context.clients.find(client).await {
        Ok(Some(client)) => client.registration.client_name.clone(),
        Ok(None) => "an unknown application".to_owned(),
        Err(error) => {
            tracing::error!(%error, tenant = %context.tenant.id, "cannot read a client name");
            "an unknown application".to_owned()
        }
    }
}

/// The account an agent client acts for, when the client is an agent.
///
/// `None` for an ordinary client, and `None` for an agent whose owner cannot
/// be read: a row that says an agent acts for nobody would be worse than a row
/// that does not say. The *username* rather than the UUID the profile holds,
/// because the person reading this page has to recognise it.
async fn agent_owner(
    context: &GrantsContext<'_>,
    client: &asterius_domain::ClientId,
) -> Option<String> {
    let client = match context.clients.find(client).await {
        Ok(client) => client?,
        Err(error) => {
            tracing::error!(%error, tenant = %context.tenant.id, "cannot read a client");
            return None;
        }
    };
    let owner = *client.registration.agent.as_ref()?.owner().user_id();
    match context.users.by_id(owner).await {
        Ok(Some(user)) => Some(user.username),
        Ok(None) => None,
        Err(error) => {
            tracing::error!(%error, tenant = %context.tenant.id, "cannot read an agent's owner");
            None
        }
    }
}

/// The page a submission this server would not read produces.
async fn refused(context: &GrantsContext<'_>, session: &Session, now: OffsetDateTime) -> Response {
    rendered(
        context,
        session,
        Some(context.text.grants_gone()),
        StatusCode::BAD_REQUEST,
        now,
    )
    .await
}

/// The page a withdrawal of something that is not there produces.
///
/// Already withdrawn, somebody else's, never existed: one sentence for all
/// three. The person in front of this page cannot act on the difference, and
/// each distinction is an answer to a question about a grant they may not
/// hold — Grant Management ID1 §6.6's reasoning, in a page instead of a status
/// code.
async fn gone(context: &GrantsContext<'_>, session: &Session, now: OffsetDateTime) -> Response {
    rendered(
        context,
        session,
        Some(context.text.grants_gone()),
        StatusCode::CONFLICT,
        now,
    )
    .await
}

/// The page a failure of *this server* produces.
fn error_page(context: &GrantsContext<'_>, status: StatusCode) -> Response {
    let font_url = crate::http::font_url(&context.mount);
    let document = Document::render(context.nonce, |nonce| {
        pages::render(&ErrorPage {
            text: context.text,
            tenant_name: &context.tenant.display_name,
            message: "This did not work. Nothing was withdrawn.",
            correlation_id: "",
            nonce_attribute: nonce_attribute(nonce),
            theme_css: "",
            brand: Brand::new(&font_url),
        })
    });
    (status, no_store(), document).into_response()
}

/// Opens a first-party interaction and sends the browser to its login page.
///
/// The inbox's `begin`, with this page's destination: 303 so the browser
/// fetches the next page rather than repeating this request, the id in both
/// the URL and a `__Host-` cookie so a leaked URL is inert without the cookie
/// (FAPI 2.0 SP §6.5), and `no-store` because the response carries a
/// credential.
async fn begin(context: &GrantsContext<'_>, now: OffsetDateTime) -> Response {
    let id = InteractionId::generate();
    if let Err(error) = context
        .interactions
        .begin_first_party_interaction(
            &id.digest(),
            FirstPartyDestination::GrantsDashboard,
            now + ENTRY_LIFETIME,
            now,
        )
        .await
    {
        tracing::error!(%error, tenant = %context.tenant.id, "cannot open a sign-in for the dashboard");
        return error_page(context, StatusCode::SERVICE_UNAVAILABLE);
    }

    // Relative, for `console::location_of`'s reason: the tenant prefix is not
    // visible from here, and `interaction/{id}` resolved against
    // `/t/x/account/grants` is this tenant's interaction page.
    let Ok(redirect) = SeeOther::to(&format!("../interaction/{}", id.expose())) else {
        tracing::error!(tenant = %context.tenant.id, "an interaction id is not a usable Location");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let mut response = redirect.into_response();
    let headers = response.headers_mut();
    if let Ok(value) = interaction::set_cookie(&id).parse() {
        headers.insert(header::SET_COOKIE, value);
    }
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// Records a withdrawal.
///
/// [`EventType::GRANT_REVOKED`], the event the Grant Management endpoint
/// writes, because it is the same fact: an authorization was withdrawn. What
/// differs is the actor — a person at this server's own page rather than a
/// client holding a token — and the `reason` label, which is how a reader
/// tells the two doors apart.
async fn record(
    context: &GrantsContext<'_>,
    session: &Session,
    grant: &Grant,
    now: OffsetDateTime,
) {
    let mut event = AuditEvent::new(
        context.tenant.id.clone(),
        EventType::GRANT_REVOKED,
        Outcome::Success,
        Actor::User(session.user.to_string()),
        now,
    )
    .session(DomainSessionId::new(session.id_digest.clone()))
    .client(grant.client.clone())
    .grant(grant.id.clone())
    .detail(Detail::new().label("reason", "account_grants_page"));
    if let Some(subject) = &grant.subject {
        event = event.subject(subject.as_str().to_owned());
    }

    if let Err(error) = context.audit.record(event).await {
        tracing::error!(
            %error,
            tenant = %context.tenant.id,
            "a grant revocation was not written to the audit trail"
        );
    }
}

/// The CAEP `session-revoked` seam, this page's end of it.
///
/// The Grant Management endpoint has the same hook and the same reason: a
/// grant being withdrawn is the fact a resource server most needs to be told
/// about and is least able to discover, because an access token minted from it
/// is a signed JWT that still verifies. The transmitter is `ast-0ju.8`. Named
/// and called from one place so a reviewer can find it.
fn notify_grant_revoked(context: &GrantsContext<'_>, grant: &Grant) {
    tracing::info!(
        tenant = %context.tenant.id,
        client = %grant.client,
        grant = %grant.id,
        "a grant was withdrawn from the account pages"
    );
}

/// Every response from this page carries a decision, a credential or a list of
/// what somebody has authorised.
fn no_store() -> [(header::HeaderName, HeaderValue); 1] {
    [(header::CACHE_CONTROL, HeaderValue::from_static("no-store"))]
}

#[cfg(test)]
mod tests {
    use super::*;
    use asterius_domain::{ClientId, TenantId};

    const GRANT: &str = "9f1c2d3e-4a5b-4c6d-8e9f-0a1b2c3d4e5f";

    fn body(text: &str) -> Vec<u8> {
        text.as_bytes().to_vec()
    }

    fn epoch() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("a fixed instant")
    }

    fn grant(id: &str, created_at: OffsetDateTime) -> Grant {
        let mut grant = Grant::new(
            TenantId::parse("demo").expect("a tenant id"),
            ClientId::new("billing".to_owned()),
            created_at,
        );
        grant.id = GrantId::new(id.to_owned());
        grant
    }

    /// The ordinary form: a token and one grant.
    #[test]
    fn a_withdrawal_form_names_one_grant() {
        // Arrange
        let form = body(&format!("csrf=abc&grant={GRANT}"));

        // Act
        let parsed = withdrawal(&form);

        // Assert
        assert_eq!(
            parsed,
            Some(Withdrawal {
                csrf: "abc".to_owned(),
                grant: GRANT.to_owned(),
            })
        );
    }

    /// RFC 6749 §3.1's parameter pollution, applied to this server's own form:
    /// a body naming two grants is a body where which one is withdrawn depends
    /// on which the parser preferred.
    #[test]
    fn a_form_naming_two_grants_is_refused() {
        // Arrange
        let form = body(&format!("csrf=abc&grant={GRANT}&grant={GRANT}"));

        // Act
        let parsed = withdrawal(&form);

        // Assert
        assert_eq!(parsed, None);
    }

    /// The id is the spelling this server writes, or it is nothing: the store
    /// is not asked to look up a shape that could never be a row.
    #[test]
    fn an_identifier_that_is_not_this_servers_spelling_is_refused() {
        // Arrange
        let short = body("csrf=abc&grant=9f1c2d3e");
        let upper = body(&format!("csrf=abc&grant={}", GRANT.to_uppercase()));
        let braced = body(&format!("csrf=abc&grant={{{GRANT}}}"));
        let unhyphenated = body(&format!("csrf=abc&grant={}", GRANT.replace('-', "")));

        // Act & assert
        for form in [short, upper, braced, unhyphenated] {
            assert_eq!(withdrawal(&form), None);
        }
    }

    /// A form with no token is not a form this page posts.
    #[test]
    fn a_form_without_a_token_is_refused() {
        // Arrange
        let form = body(&format!("grant={GRANT}"));

        // Act & assert
        assert_eq!(withdrawal(&form), None);
    }

    /// A body this server will not buffer is refused before it is decoded.
    #[test]
    fn an_over_long_body_is_refused() {
        // Arrange
        let form = body(&format!("csrf={}&grant={GRANT}", "a".repeat(MAX_BODY)));

        // Act & assert
        assert_eq!(withdrawal(&form), None);
    }

    /// A form body is text; bytes that are not are refused rather than lossily
    /// decoded into something that parses.
    #[test]
    fn a_body_that_is_not_text_is_refused() {
        // Arrange
        let form = vec![0xff, 0xfe, 0xfd];

        // Act & assert
        assert_eq!(withdrawal(&form), None);
    }

    /// Only what can still issue a credential is listed: a withdrawn grant is
    /// over, and a row whose button changes nothing has no business beside one
    /// whose button does.
    #[test]
    fn a_withdrawn_grant_is_not_listed() {
        // Arrange
        let now = epoch();
        let live = grant(GRANT, now);
        let mut withdrawn = grant("11111111-1111-4111-8111-111111111111", now);
        withdrawn.revoked_at = Some(now);
        withdrawn.revocation_reason = Some(RevocationReason::UserRevoked);

        // Act
        let listed = standing(vec![live, withdrawn], now);

        // Assert
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].grant.id.as_str(), GRANT);
    }

    /// An expired grant authorises nothing, so it is not offered for
    /// withdrawal either.
    #[test]
    fn an_expired_grant_is_not_listed() {
        // Arrange
        let now = epoch();
        let mut lapsed = grant(GRANT, now - Duration::hours(2));
        lapsed.expires_at = Some(now - Duration::hours(1));

        // Act
        let listed = standing(vec![lapsed], now);

        // Assert
        assert!(listed.is_empty());
    }

    /// RFC 8693 §4.1: a delegation is shown under the access it came from, and
    /// never as an entry of its own — withdrawing the parent is what stops it.
    #[test]
    fn a_delegation_is_attached_to_the_grant_it_was_minted_from() {
        // Arrange
        let now = epoch();
        let parent = grant(GRANT, now);
        let mut child = grant("22222222-2222-4222-8222-222222222222", now);
        child.parent = Some(GrantId::new(GRANT.to_owned()));

        // Act
        let listed = standing(vec![parent, child.clone()], now);

        // Assert
        assert_eq!(listed.len(), 1, "a delegation was listed on its own");
        assert_eq!(listed[0].delegations.len(), 1);
        assert_eq!(listed[0].delegations[0].id, child.id);
    }

    /// A chain two hops long — a tenant may permit several
    /// (`AgentLimits::max_delegation_depth`) — is shown under the access it
    /// ultimately came from, because that is the one a person can withdraw.
    #[test]
    fn a_delegation_of_a_delegation_is_attached_to_the_grant_at_the_root() {
        // Arrange
        let now = epoch();
        let root = grant(GRANT, now - Duration::hours(3));
        let first = "77777777-7777-4777-8777-777777777777";
        let mut child = grant(first, now - Duration::hours(2));
        child.parent = Some(GrantId::new(GRANT.to_owned()));
        let mut grandchild = grant(
            "88888888-8888-4888-8888-888888888888",
            now - Duration::hours(1),
        );
        grandchild.parent = Some(GrantId::new(first.to_owned()));

        // Act
        let listed = standing(vec![root, child, grandchild], now);

        // Assert
        assert_eq!(listed.len(), 1, "a delegation was listed on its own");
        assert_eq!(listed[0].delegations.len(), 2);
    }

    /// An expired delegation is still shown: "when did this agent last act as
    /// me" is a fact about the past, and it is what an agent grant is read for.
    #[test]
    fn an_expired_delegation_is_still_shown_under_its_parent() {
        // Arrange
        let now = epoch();
        let parent = grant(GRANT, now - Duration::hours(3));
        let mut child = grant(
            "33333333-3333-4333-8333-333333333333",
            now - Duration::hours(2),
        );
        child.parent = Some(GrantId::new(GRANT.to_owned()));
        child.expires_at = Some(now - Duration::hours(1));

        // Act
        let listed = standing(vec![parent, child], now);

        // Assert
        assert_eq!(listed[0].delegations.len(), 1);
    }

    /// A grant whose parent is not on the page is listed on its own: nothing a
    /// person might want to withdraw may go missing.
    #[test]
    fn a_delegation_whose_parent_is_gone_is_listed_on_its_own() {
        // Arrange
        let now = epoch();
        let mut orphan = grant(GRANT, now);
        orphan.parent = Some(GrantId::new(
            "44444444-4444-4444-8444-444444444444".to_owned(),
        ));

        // Act
        let listed = standing(vec![orphan], now);

        // Assert
        assert_eq!(listed.len(), 1);
        assert!(listed[0].delegations.is_empty());
    }

    /// The delegations of a grant are newest first, so the most recent token
    /// exchange is the head and the page can name it without sorting again.
    #[test]
    fn delegations_are_newest_first() {
        // Arrange
        let now = epoch();
        let parent = grant(GRANT, now - Duration::hours(5));
        let mut older = grant(
            "55555555-5555-4555-8555-555555555555",
            now - Duration::hours(4),
        );
        older.parent = Some(GrantId::new(GRANT.to_owned()));
        let mut newer = grant(
            "66666666-6666-4666-8666-666666666666",
            now - Duration::hours(1),
        );
        newer.parent = Some(GrantId::new(GRANT.to_owned()));

        // Act
        let listed = standing(vec![parent, older, newer.clone()], now);

        // Assert
        assert_eq!(listed[0].delegations[0].id, newer.id);
    }

    /// The `act` chain is read for identifiers and nothing else: an element
    /// this server did not write is skipped rather than rendered.
    #[test]
    fn an_actor_chain_yields_identifiers_and_skips_what_it_cannot_read() {
        // Arrange
        let now = epoch();
        let mut delegated = grant(GRANT, now);
        delegated.actor_chain = vec![
            serde_json::json!({"sub": "ada"}),
            serde_json::json!({"client_id": "assistant"}),
            serde_json::json!({"nested": {"sub": "nobody"}}),
        ];

        // Act
        let read = actors(&delegated);

        // Assert
        assert_eq!(read, vec!["ada".to_owned(), "assistant".to_owned()]);
    }

    /// The two synchroniser tokens of the account pages are different values,
    /// so one lifted from the inbox is not one this page accepts.
    #[test]
    fn this_pages_token_is_not_the_inboxs() {
        // Arrange
        let session = Session::begin(
            TenantId::parse("demo").expect("a tenant id"),
            &session::SessionId::generate(),
            uuid::Uuid::nil(),
            vec![asterius_domain::AuthenticationMethod::Password],
            epoch(),
            asterius_domain::Lifetimes {
                idle: Duration::hours(1),
                absolute: Duration::days(1),
            },
        );

        // Act
        let ours = csrf_for(&session);

        // Assert
        assert_ne!(ours, crate::http::device::csrf_for(&session));
        assert!(checked_csrf(&session, &ours));
        assert!(!checked_csrf(&session, "something else"));
    }
}
