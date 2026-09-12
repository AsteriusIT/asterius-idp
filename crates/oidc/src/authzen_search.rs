//! The AuthZEN Search APIs on the wire (Authorization API 1.0 §8,
//! `ast-pj0.6`).
//!
//! §8 asks the evaluation question with a hole in it. A PEP that would have
//! sent §6.1's subject, action and resource omits the **id of the entity it is
//! searching for** — `subject.id` for §8.4, `resource.id` for §8.5, the whole
//! `action` for §8.6 — and the PDP answers with the entities that fill the
//! hole. §8 makes the results ones that "SHOULD" evaluate to permit; this
//! build evaluates every one of them before answering, so the SHOULD is an
//! is (`crate::http::access_search` in the server crate is where that happens,
//! and `asterius_domain::policy::search` is what a candidate can be).
//!
//! This module is the bytes and nothing else: [`parse_search`] reads a request
//! into a [`SearchRequest`] that can mint one ordinary
//! [`EvaluationRequest`] per candidate, and [`search_response`] writes §8.3's
//! answer. Every bound, the I-JSON rule and the duplicate-member refusal are
//! [`crate::authzen`]'s, applied by that module's own document reader: a
//! second reader here would be a second opinion about what 64 KiB means.
//!
//! # The hole is refused when it is filled
//!
//! A subject search carrying `subject.id` is not a smaller search — it is a
//! request whose author believes they are asking something else, and answering
//! it would mean either ignoring a member §5.1 makes REQUIRED or searching for
//! an entity the caller already named. [`AuthzenError::NotSearchable`] is a
//! 400 that says which member to remove.
//!
//! # Pagination, and what a page token is
//!
//! §8.2 gives the request a `page.token` and the response a `page.next_token`,
//! REQUIRED in a paginated response and an empty string on the last page, and
//! it puts one obligation on the caller: "the parameters of the request MUST
//! be identical" between pages. A PDP that took that on trust would page a
//! second query with the first one's cursor and answer entities from neither.
//!
//! So the token carries both halves: **where** the walk had reached, and a
//! digest of the query it was minted for. A token presented against a request
//! that differs anywhere else than in `page` is [`AuthzenError::PageChanged`]
//! — §10.1.2's 400 — rather than a page of something else.
//!
//! The wire form is `v1.<base64url>`, which is `crates/admin-api`'s cursor
//! shape and is opaque for the same reason: what opacity buys is the freedom
//! to change what is inside — the cursor key here is a username today and
//! could be a compound key tomorrow — without breaking a PEP that had started
//! parsing it.
//!
//! **Why a digest and not a MAC.** A page token carries no authority. Every
//! page is authenticated by the PEP's own DPoP-bound access token, charged to
//! the same limiter, and — the part that decides it — every entity in every
//! page is evaluated against the tenant's policy *at that instant* before it
//! is returned. A caller who forges a token can therefore reach exactly what a
//! caller who asks the first page and pages forward can reach: their own
//! query, from a position they chose. A MAC would buy integrity of a value
//! that grants nothing, at the price of a symmetric key shared across every
//! replica of a deployment — this server's tenant keys are asymmetric and
//! wrapped under the KEK, so it would be a *new* secret to hold, rotate and
//! leak. `docs/threat-model.md` carries the row.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Map, Value, json};
use sha2::{Digest as _, Sha256};

use asterius_domain::policy::{
    Action, Context, EvaluationRequest, Properties, RequestError, Resource, Subject,
};

use crate::authzen::{AuthzenError, member, properties, read_document};

/// The most entities one page may hold, whatever `page.limit` asks for.
///
/// A hundred, and it is a cap on *work* rather than on bytes: a page of `n`
/// entities is `n` policy evaluations, each of which is a document walk, and
/// all of it is bought with one token at the same limiter §6.1's evaluation
/// spends one on. It is deliberately [`crate::authzen::MAX_EVALUATIONS`]: a
/// PEP that boxcars a hundred evaluations and a PEP that searches a page of a
/// hundred candidates are asking this PDP for the same amount of work, and two
/// different numbers would be a budget with a seam in it.
pub const MAX_PAGE: usize = 100;

/// The page size a request that names none gets.
///
/// Twenty-five rather than the maximum: a search is an exploratory call, the
/// common answer fits in one page, and a PEP that wants more says so. The
/// default being below the cap is also what makes `page.limit` worth sending —
/// a default equal to the cap would make the member decorative.
pub const DEFAULT_PAGE: usize = 25;

/// The longest cursor key a page token may carry, in bytes.
///
/// A username or a resource identifier, both of which this server bounds well
/// below this on the way in. What it refuses is the caller who sends a
/// kilobyte of base64 to find out what happens.
pub const MAX_CURSOR: usize = 512;

/// The scheme version this build mints and accepts.
const TOKEN_VERSION: &str = "v1";

/// The longest wire form [`PageToken::decode`] will look at.
///
/// Derived from the payload rather than guessed: the payload is the cursor
/// key, the query digest and a little JSON, and base64url grows three bytes
/// into four. A bound applied to the encoded string by eye would refuse tokens
/// this server had just minted, which is a paging loop rather than a guard.
const MAX_TOKEN: usize = 3 + 4 * (MAX_CURSOR + 128).div_ceil(3);

/// Which of §8.4, §8.5 and §8.6 a request is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchKind {
    /// §8.4: `subject.id` is what the PDP fills in.
    Subject,
    /// §8.5: `resource.id` is what the PDP fills in.
    Resource,
    /// §8.6: `action.name` is what the PDP fills in.
    Action,
}

impl SearchKind {
    /// The word the trail and the metadata member use.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Subject => "subject",
            Self::Resource => "resource",
            Self::Action => "action",
        }
    }

    /// The member a request of this kind must omit (§8).
    const fn searched_member(self) -> &'static str {
        match self {
            Self::Subject => "subject.id",
            Self::Resource => "resource.id",
            Self::Action => "action.name",
        }
    }
}

/// Where a search resumes, and how many entities it may return.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page {
    /// The cursor the caller presented, already checked against this query.
    ///
    /// `None` is the first page. What the key *means* is the endpoint's
    /// business — a username, a candidate name — and this module never reads
    /// it.
    pub after: Option<String>,
    /// How many entities this page may hold, clamped to [`MAX_PAGE`].
    pub limit: usize,
}

/// A §8 search request, with the hole still in it.
///
/// Everything §6.1 would have carried except the entity being searched for,
/// plus §8.2's page. [`SearchRequest::candidate`] fills the hole with one
/// proposed entity and produces the ordinary [`EvaluationRequest`] the
/// evaluator takes — which is what makes "every result evaluates to permit"
/// a property of the code rather than of a comment: there is no other way for
/// this module to produce a result.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct SearchRequest {
    /// Which search this is.
    pub kind: SearchKind,
    /// The `type` of the entity being searched (§8.4, §8.5).
    ///
    /// `None` only for §8.6, whose Action has a `name` and no type.
    pub searched_type: Option<String>,
    /// The `properties` the PEP put on the partial entity (§5).
    pub searched_properties: Properties,
    /// The subject, when it is not what is being searched for.
    pub subject: Option<Subject>,
    /// The action, when it is not what is being searched for.
    pub action: Option<Action>,
    /// The resource, when it is not what is being searched for.
    pub resource: Option<Resource>,
    /// §5.4's environment attributes.
    pub context: Context,
    /// §8.2's pagination.
    pub page: Page,
    /// The digest of everything but `page`, which a page token is bound to.
    query: String,
}

impl SearchRequest {
    /// One candidate, as an ordinary evaluation request.
    ///
    /// `id` is the `subject.id`, the `resource.id` or the `action.name`,
    /// depending on the kind. The entities the PEP *did* send are copied
    /// unchanged, so the request this returns is the one the PEP would have
    /// sent had it known the answer — which is the whole meaning of §8's
    /// "results SHOULD evaluate to permit".
    ///
    /// The subject carries no groups, roles or grants here, for
    /// [`crate::authzen`]'s reason: those are facts the endpoint resolves from
    /// this server's own rows and a request may not assert.
    ///
    /// # Errors
    ///
    /// [`RequestError`] when the candidate is not one the information model
    /// accepts — an empty id, or one past the model's bounds.
    pub fn candidate(&self, id: &str) -> Result<EvaluationRequest, RequestError> {
        let kind = self.searched_type.as_deref().unwrap_or_default();
        let subject = match self.subject.as_ref() {
            Some(subject) => subject.clone(),
            None => Subject::new(kind, id, self.searched_properties.clone())?,
        };
        let action = match self.action.as_ref() {
            Some(action) => action.clone(),
            None => Action::new(id, self.searched_properties.clone())?,
        };
        let resource = match self.resource.as_ref() {
            Some(resource) => resource.clone(),
            None => Resource::new(kind, id, self.searched_properties.clone())?,
        };
        Ok(EvaluationRequest::new(
            subject,
            action,
            resource,
            self.context.clone(),
        ))
    }

    /// The token that resumes this same search after `key` (§8.2).
    #[must_use]
    pub fn next_token(&self, key: &str) -> String {
        PageToken {
            query: self.query.clone(),
            after: key.to_owned(),
        }
        .encode()
    }
}

/// Reads a §8 search request of one kind.
///
/// `kind` comes from the route, not from the body: §10.1 gives each search its
/// own path and §9.1.1 advertises each as its own endpoint, so the question
/// being asked is a property of the URL the PEP chose. A `kind` member in the
/// body would be a second spelling of it, and the two could disagree.
///
/// Unknown members are ignored (§10.1.1), no member's position is read, and
/// the entity being searched for must not carry its identifier — see the
/// [module documentation](self).
///
/// # Errors
///
/// [`AuthzenError`], which is always §10.1.2's 400 and whose `Display` is the
/// error message string the body carries.
// fuzz-target: authzen_search
pub fn parse_search(kind: SearchKind, body: &[u8]) -> Result<SearchRequest, AuthzenError> {
    let document = read_document(body)?;
    let query = digest_of(&document);

    let subject = entity(&document, "subject", kind != SearchKind::Subject)?;
    let action = entity(&document, "action", kind != SearchKind::Action)?;
    let resource = entity(&document, "resource", kind != SearchKind::Resource)?;

    let searched = match kind {
        SearchKind::Subject => subject,
        SearchKind::Resource => resource,
        SearchKind::Action => action,
    };
    // §8: the identifier of the entity being searched for is what the PDP
    // supplies. A request that carries it is refused rather than narrowed.
    let searched_properties = searched
        .map(|entity| properties(entity, "properties"))
        .transpose()?
        .unwrap_or_else(Properties::empty);
    let searched_type = match kind {
        SearchKind::Action => None,
        SearchKind::Subject | SearchKind::Resource => {
            let entity = searched.ok_or(AuthzenError::Missing(match kind {
                SearchKind::Subject => "subject",
                _ => "resource",
            }))?;
            if entity.get("id").is_some_and(|id| !id.is_null()) {
                return Err(AuthzenError::NotSearchable(kind.searched_member()));
            }
            Some(
                member(
                    entity,
                    match kind {
                        SearchKind::Subject => "subject.type",
                        _ => "resource.type",
                    },
                )?
                .to_owned(),
            )
        }
    };
    if kind == SearchKind::Action
        && searched.is_some_and(|entity| entity.get("name").is_some_and(|name| !name.is_null()))
    {
        return Err(AuthzenError::NotSearchable("action.name"));
    }

    let subject = subject
        .filter(|_| kind != SearchKind::Subject)
        .map(|entity| {
            Ok::<_, AuthzenError>(Subject::new(
                member(entity, "subject.type")?,
                member(entity, "subject.id")?,
                properties(entity, "properties")?,
            )?)
        })
        .transpose()?;
    let action = action
        .filter(|_| kind != SearchKind::Action)
        .map(|entity| {
            Ok::<_, AuthzenError>(Action::new(
                member(entity, "action.name")?,
                properties(entity, "properties")?,
            )?)
        })
        .transpose()?;
    let resource = resource
        .filter(|_| kind != SearchKind::Resource)
        .map(|entity| {
            Ok::<_, AuthzenError>(Resource::new(
                member(entity, "resource.type")?,
                member(entity, "resource.id")?,
                properties(entity, "properties")?,
            )?)
        })
        .transpose()?;

    // The entities a search does not fill in are as REQUIRED as they are in
    // §6.1: a subject search with no action is not a search, it is a request
    // for everything this tenant permits anybody to do.
    if kind != SearchKind::Subject && subject.is_none() {
        return Err(AuthzenError::Missing("subject"));
    }
    if kind != SearchKind::Action && action.is_none() {
        return Err(AuthzenError::Missing("action"));
    }
    if kind != SearchKind::Resource && resource.is_none() {
        return Err(AuthzenError::Missing("resource"));
    }

    let context = match document.get("context") {
        None | Some(Value::Null) => Properties::empty(),
        Some(Value::Object(members)) => Properties::new(members.clone())?,
        Some(_) => return Err(AuthzenError::WrongType("context")),
    };

    Ok(SearchRequest {
        kind,
        searched_type,
        searched_properties,
        subject,
        action,
        resource,
        context: Context::new(context),
        page: page_of(&document, &query)?,
        query,
    })
}

/// §8.3's response: `results` REQUIRED, `page` beside it.
///
/// `next_token` is always written, and is the empty string on the last page:
/// §8.2 makes it REQUIRED in a paginated response and gives the empty string
/// the meaning "there is nothing after this". Present-and-empty rather than
/// absent, because a PEP writing `while (token)` and a PEP writing
/// `while ("next_token" in page)` must both stop, and an absent member would
/// only stop the first.
///
/// No `context`: §8.3 makes it OPTIONAL, and what a decision context explains
/// is one decision. A search's results are the entities that permitted, so the
/// only reasons left to report would be the ones that *denied* the candidates
/// this PDP dropped — which is the enumeration of a tenant's policy, one probe
/// at a time, handed to a PEP that only asked which of them said yes.
#[must_use]
pub fn search_response(results: Vec<Value>, next_token: Option<&str>) -> Value {
    let mut document = Map::new();
    // Consumed rather than copied: a page is up to `MAX_PAGE` entities, and
    // the caller has no use for its vector afterwards.
    document.insert("results".to_owned(), Value::Array(results));
    document.insert(
        "page".to_owned(),
        json!({ "next_token": next_token.unwrap_or_default() }),
    );
    Value::Object(document)
}

/// §8.3's answer when the search could not be performed at all.
///
/// An empty page with the `error` context §10.1.2 gives a PDP that could not
/// decide — the same shape [`crate::authzen::engine_failure_response`] uses,
/// for the same reason. An empty `results` on its own would be the dangerous
/// answer: a PEP that concluded "nobody may do this" from an unreachable
/// policy store would behave as though a policy had changed, and this is the
/// one member that tells the two apart.
#[must_use]
pub fn search_failure_response() -> Value {
    json!({
        "results": [],
        "page": { "next_token": "" },
        "context": {
            "error": {
                "status": 500,
                "message": "the policy decision point could not answer this search",
            }
        }
    })
}

/// §8.4's and §8.5's results: an entity with its type and id.
#[must_use]
pub fn subject_result(kind: &str, id: &str) -> Value {
    json!({ "type": kind, "id": id })
}

/// §8.6's results: §5.3's Action, whose only REQUIRED member is `name`.
#[must_use]
pub fn action_result(name: &str) -> Value {
    json!({ "name": name })
}

/// One of §5's entities, when the document carries one.
///
/// `required` says whether this kind of search needs it at all: the entity
/// being searched for is optional *as an object* (§8.6's action may be absent
/// entirely), and the ones that fix the query are not.
fn entity<'a>(
    document: &'a Map<String, Value>,
    name: &'static str,
    required: bool,
) -> Result<Option<&'a Map<String, Value>>, AuthzenError> {
    match document.get(name) {
        None | Some(Value::Null) => {
            if required {
                Err(AuthzenError::Missing(name))
            } else {
                Ok(None)
            }
        }
        Some(Value::Object(members)) => Ok(Some(members)),
        Some(_) => Err(AuthzenError::WrongType(name)),
    }
}

/// §8.2's `page`, with the token checked against this very query.
fn page_of(document: &Map<String, Value>, query: &str) -> Result<Page, AuthzenError> {
    let page = match document.get("page") {
        None | Some(Value::Null) => None,
        Some(Value::Object(members)) => Some(members),
        Some(_) => return Err(AuthzenError::WrongType("page")),
    };
    let Some(page) = page else {
        return Ok(Page {
            after: None,
            limit: DEFAULT_PAGE,
        });
    };

    let after = match page.get("token") {
        None | Some(Value::Null) => None,
        Some(Value::String(raw)) if raw.is_empty() => None,
        Some(Value::String(raw)) => {
            let token = PageToken::decode(raw)?;
            // §8.2: "the parameters of the request MUST be identical" between
            // pages. This is the check that makes it true rather than assumed.
            if token.query != query {
                return Err(AuthzenError::PageChanged);
            }
            Some(token.after)
        }
        Some(_) => return Err(AuthzenError::WrongType("page.token")),
    };

    let limit = match page.get("limit") {
        None | Some(Value::Null) => DEFAULT_PAGE,
        Some(value) => {
            let limit = value
                .as_u64()
                .and_then(|limit| usize::try_from(limit).ok())
                .filter(|limit| *limit > 0)
                .ok_or(AuthzenError::PageLimit)?;
            // Clamped rather than refused, like `crates/admin-api`'s listings:
            // asking for more than this PDP will evaluate in one request is not
            // a bug in the caller, and a hundred results with a token is a
            // complete answer.
            limit.min(MAX_PAGE)
        }
    };

    Ok(Page { after, limit })
}

/// The query a page token is bound to: the document without its `page`.
///
/// `serde_json`'s object is a `BTreeMap` in this build, so the rendering is
/// member-ordered and two spellings of the same request digest alike — which
/// is what §8.2's "identical parameters" should mean to a PEP that reorders
/// its own JSON.
fn digest_of(document: &Map<String, Value>) -> String {
    let mut query = document.clone();
    query.remove("page");
    let rendered = Value::Object(query).to_string();
    URL_SAFE_NO_PAD.encode(&Sha256::digest(rendered.as_bytes())[..16])
}

/// §8.2's opaque position: where the walk reached, and what it was walking.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PageToken {
    query: String,
    after: String,
}

impl PageToken {
    /// The wire form: `v1.<base64url of the payload>`.
    fn encode(&self) -> String {
        let payload = json!({ "q": self.query, "k": self.after }).to_string();
        format!(
            "{TOKEN_VERSION}.{}",
            URL_SAFE_NO_PAD.encode(payload.as_bytes())
        )
    }

    /// Reads a token a PEP presented.
    ///
    /// # Errors
    ///
    /// [`AuthzenError::PageToken`] for anything this build did not mint: a
    /// missing or unknown version, a body that is not base64url, bytes that
    /// are not the payload this version writes, or a cursor over
    /// [`MAX_CURSOR`]. Refused rather than treated as a first page, because a
    /// token the server did not issue is a client bug and a client bug that
    /// reports as "here is page one again" is a paging loop.
    fn decode(raw: &str) -> Result<Self, AuthzenError> {
        if raw.len() > MAX_TOKEN {
            return Err(AuthzenError::PageToken);
        }
        let (version, body) = raw.split_once('.').ok_or(AuthzenError::PageToken)?;
        if version != TOKEN_VERSION {
            return Err(AuthzenError::PageToken);
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(body)
            .map_err(|_| AuthzenError::PageToken)?;
        let payload: Value = serde_json::from_slice(&bytes).map_err(|_| AuthzenError::PageToken)?;
        let query = payload
            .get("q")
            .and_then(Value::as_str)
            .ok_or(AuthzenError::PageToken)?;
        let after = payload
            .get("k")
            .and_then(Value::as_str)
            .ok_or(AuthzenError::PageToken)?;
        if after.is_empty() || after.len() > MAX_CURSOR {
            return Err(AuthzenError::PageToken);
        }
        Ok(Self {
            query: query.to_owned(),
            after: after.to_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(json: &Value) -> Vec<u8> {
        serde_json::to_vec(json).expect("a document")
    }

    fn subject_search() -> Value {
        json!({
            "subject": {"type": "user"},
            "action": {"name": "can_read"},
            "resource": {"type": "account", "id": "123"},
        })
    }

    /// §8.4: the subject search names the type it is looking for and omits the
    /// id, and the action and resource are the ordinary §5 entities.
    #[test]
    fn a_subject_search_is_read_with_the_hole_in_it() {
        // Arrange
        let body = body(&subject_search());

        // Act
        let request = parse_search(SearchKind::Subject, &body).expect("a search");

        // Assert
        assert_eq!(request.searched_type.as_deref(), Some("user"));
        assert!(request.subject.is_none());
        assert_eq!(request.action.as_ref().map(Action::name), Some("can_read"));
        assert_eq!(request.resource.as_ref().map(Resource::id), Some("123"));
    }

    /// §8: the id of the entity being searched for is what the PDP supplies.
    #[test]
    fn a_subject_search_carrying_an_id_is_refused() {
        // Arrange
        let mut document = subject_search();
        document["subject"]["id"] = json!("alice");

        // Act
        let refused = parse_search(SearchKind::Subject, &body(&document));

        // Assert
        assert_eq!(refused, Err(AuthzenError::NotSearchable("subject.id")));
    }

    /// §8.5: the resource search fixes the subject and omits `resource.id`.
    #[test]
    fn a_resource_search_is_read_with_the_hole_in_it() {
        // Arrange
        let document = json!({
            "subject": {"type": "user", "id": "alice"},
            "action": {"name": "can_read"},
            "resource": {"type": "account"},
        });

        // Act
        let request = parse_search(SearchKind::Resource, &body(&document)).expect("a search");

        // Assert
        assert_eq!(request.searched_type.as_deref(), Some("account"));
        assert!(request.resource.is_none());
        assert_eq!(request.subject.as_ref().map(Subject::id), Some("alice"));
    }

    /// §8.6: the action search omits the action entirely.
    #[test]
    fn an_action_search_needs_no_action_member() {
        // Arrange
        let document = json!({
            "subject": {"type": "user", "id": "alice"},
            "resource": {"type": "account", "id": "123"},
        });

        // Act
        let request = parse_search(SearchKind::Action, &body(&document)).expect("a search");

        // Assert
        assert!(request.action.is_none());
        assert!(request.searched_type.is_none());
        assert_eq!(request.subject.as_ref().map(Subject::id), Some("alice"));
    }

    /// An action search that names the action is searching for something it
    /// already has.
    #[test]
    fn an_action_search_carrying_a_name_is_refused() {
        // Arrange
        let document = json!({
            "subject": {"type": "user", "id": "alice"},
            "action": {"name": "can_read"},
            "resource": {"type": "account", "id": "123"},
        });

        // Act, assert
        assert_eq!(
            parse_search(SearchKind::Action, &body(&document)),
            Err(AuthzenError::NotSearchable("action.name"))
        );
    }

    /// The entities a search does not fill in are as REQUIRED as §6.1 makes
    /// them: a subject search with no action would be a request for everything
    /// this tenant permits anybody to do.
    #[test]
    fn a_search_missing_an_entity_it_does_not_search_for_is_refused() {
        // Arrange
        let mut document = subject_search();
        document
            .as_object_mut()
            .expect("an object")
            .remove("action");

        // Act, assert
        assert_eq!(
            parse_search(SearchKind::Subject, &body(&document)),
            Err(AuthzenError::Missing("action"))
        );
    }

    /// §8.4 makes the searched entity's `type` the one member it does carry.
    #[test]
    fn a_subject_search_without_a_type_is_refused() {
        // Arrange
        let mut document = subject_search();
        document["subject"] = json!({});

        // Act, assert
        assert_eq!(
            parse_search(SearchKind::Subject, &body(&document)),
            Err(AuthzenError::Missing("subject.type"))
        );
    }

    /// A candidate is the request the PEP would have sent had it known the
    /// answer: the entities it did send, unchanged, and the hole filled.
    #[test]
    fn a_candidate_is_the_request_with_the_hole_filled() {
        // Arrange
        let request =
            parse_search(SearchKind::Subject, &body(&subject_search())).expect("a search");

        // Act
        let evaluation = request.candidate("alice").expect("a candidate");

        // Assert
        assert_eq!(evaluation.subject.kind(), "user");
        assert_eq!(evaluation.subject.id(), "alice");
        assert_eq!(evaluation.action.name(), "can_read");
        assert_eq!(evaluation.resource.id(), "123");
    }

    /// §8.2: a page token resumes the *same* search.
    #[test]
    fn a_page_token_round_trips_into_a_cursor() {
        // Arrange
        let first = parse_search(SearchKind::Subject, &body(&subject_search())).expect("a search");
        let token = first.next_token("alice");
        let mut document = subject_search();
        document["page"] = json!({ "token": token });

        // Act
        let second = parse_search(SearchKind::Subject, &body(&document)).expect("a search");

        // Assert
        assert_eq!(second.page.after.as_deref(), Some("alice"));
        assert_eq!(second.page.limit, DEFAULT_PAGE);
    }

    /// §8.2: "the parameters of the request MUST be identical" between pages.
    /// A PEP that changed one gets a 400 rather than a page of another query.
    #[test]
    fn a_page_token_presented_against_another_query_is_refused() {
        // Arrange
        let first = parse_search(SearchKind::Subject, &body(&subject_search())).expect("a search");
        let token = first.next_token("alice");
        let mut document = subject_search();
        document["action"]["name"] = json!("can_write");
        document["page"] = json!({ "token": token });

        // Act, assert
        assert_eq!(
            parse_search(SearchKind::Subject, &body(&document)),
            Err(AuthzenError::PageChanged)
        );
    }

    /// The digest is over the query and not over the page, or no second page
    /// could ever be asked for.
    #[test]
    fn the_page_member_itself_is_not_part_of_the_query() {
        // Arrange
        let mut first = subject_search();
        first["page"] = json!({ "limit": 10 });
        let request = parse_search(SearchKind::Subject, &body(&first)).expect("a search");
        let token = request.next_token("alice");
        let mut second = subject_search();
        second["page"] = json!({ "token": token, "limit": 10 });

        // Act, assert
        assert!(parse_search(SearchKind::Subject, &body(&second)).is_ok());
    }

    /// A token this server did not mint is a client bug, and a client bug that
    /// reports as "page one again" is a paging loop.
    #[test]
    fn a_token_this_server_did_not_mint_is_refused() {
        // Arrange
        let mut document = subject_search();
        document["page"] = json!({ "token": "v9.Zm9v" });

        // Act, assert
        assert_eq!(
            parse_search(SearchKind::Subject, &body(&document)),
            Err(AuthzenError::PageToken)
        );
    }

    /// §8.2's `limit` is a count, and a caller asking for more than this PDP
    /// evaluates in one request gets the cap rather than a refusal.
    #[test]
    fn a_limit_is_clamped_and_a_non_count_is_refused() {
        // Arrange
        let mut asked = subject_search();
        asked["page"] = json!({ "limit": 10_000 });
        let mut nonsense = subject_search();
        nonsense["page"] = json!({ "limit": "fifty" });

        // Act
        let clamped = parse_search(SearchKind::Subject, &body(&asked)).expect("a search");
        let refused = parse_search(SearchKind::Subject, &body(&nonsense));

        // Assert
        assert_eq!(clamped.page.limit, MAX_PAGE);
        assert_eq!(refused, Err(AuthzenError::PageLimit));
    }

    /// §8.3: `results` is REQUIRED, and §8.2 makes `next_token` present and
    /// empty on the last page.
    #[test]
    fn the_last_page_carries_an_empty_next_token() {
        // Arrange, act
        let last = search_response(vec![action_result("can_read")], None);
        let more = search_response(vec![], Some("v1.abc"));

        // Assert
        assert_eq!(last["results"], json!([{"name": "can_read"}]));
        assert_eq!(last["page"]["next_token"], json!(""));
        assert_eq!(more["page"]["next_token"], json!("v1.abc"));
        assert_eq!(more["results"], json!([]));
    }

    /// §11.7's bounds are `crate::authzen`'s, applied by the same reader: a
    /// search is not a second way into this PDP with its own limits.
    #[test]
    fn the_document_bounds_are_the_evaluation_endpoints() {
        // Arrange
        let long = vec![b'a'; crate::authzen::MAX_REQUEST_BYTES + 1];

        // Act, assert
        assert_eq!(
            parse_search(SearchKind::Subject, &long),
            Err(AuthzenError::TooLong)
        );
    }
}
