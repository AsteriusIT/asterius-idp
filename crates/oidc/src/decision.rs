//! What an authorization request needs from the user, decided once.
//!
//! Between a validated request and a rendered page there is exactly one
//! question: *given this request and this session, what has to happen next?*
//! OIDC Core answers it in prose spread over four sections — `prompt`
//! (§3.1.2.1), re-authentication (§3.1.2.3), the error codes for a request
//! that cannot be answered (§3.1.2.6), and essential `acr` (§5.5.1.1) — plus
//! OpenID Connect Prompt Create 1.0 §3 for `prompt=create` and OIDC Core
//! Unmet Authentication Requirements 1.0 §2 for the requirement that cannot be
//! met at all.
//!
//! This module is that answer as a total function: [`decide`] takes what was
//! asked for, what the browser already has, and what the tenant can do, and
//! returns one [`Interaction`]. No I/O, no ordering of side effects, and no
//! second opinion anywhere — the endpoint that renders a page and the endpoint
//! that sends an error both read the same value.
//!
//! # Why this is a function and not a sequence of `if`s in the handler
//!
//! Because `prompt=none` makes the two failure modes symmetrical, and both are
//! real. A server that renders a page when the client said `none` has broken
//! §3.1.2.1's "MUST NOT display any authentication or consent user interface
//! pages"; a server that answers `login_required` when it could have completed
//! the request silently has broken every client that polls for a session in a
//! hidden frame. The only way to be sure both readings come out of the same
//! rules is for there to be one place the rules live, with the whole table
//! written down as tests.
//!
//! # What this module deliberately does not decide
//!
//! **Which `acr` values a tenant can produce, and how it produces them.** That
//! is `ast-2vk.7`. What lives here is the *shape* of the question — an
//! [`AcrPolicy`] is asked whether a requirement is satisfiable at all and
//! whether a session already satisfies it — and the conservative implementation
//! [`NoAcrPolicy`] for a deployment that has configured none. The step-up
//! itself is [`Interaction::StepUp`], which this module can already return and
//! the server does not yet have a screen for.
//!
//! **Whether the user has consented before.** Nothing in this server records a
//! previous consent yet, so the caller passes [`Consent::Required`] and a
//! `prompt=none` request that has got as far as consent is answered
//! `consent_required`, which is the correct answer *for a server with no
//! consent memory*: consent genuinely is required. [`Consent::Granted`] is the
//! seam a consent-memory story fills in, and the table below already has its
//! rows — see `a_silent_request_with_everything_in_place_is_answered_silently`.

use std::collections::BTreeSet;

use asterius_domain::Session;
use time::OffsetDateTime;

use crate::authorize::{AuthorizationRequest, Prompt};

/// Why a request cannot be answered without interaction that is not allowed.
///
/// The four codes of OIDC Core §3.1.2.6 plus the one of OIDC Core Unmet
/// Authentication Requirements 1.0 §2. Each is an *authorization* error: it
/// reaches the client through its `redirect_uri`, in whichever response mode
/// the request asked for, because by the time this is decided the redirect URI
/// has been validated against the client's registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Unmet {
    /// §3.1.2.6: "The Authorization Server requires End-User authentication."
    #[error("login_required")]
    LoginRequired,
    /// §3.1.2.6: "The Authorization Server requires End-User consent."
    #[error("consent_required")]
    ConsentRequired,
    /// §3.1.2.6: "The Authorization Server requires End-User interaction of
    /// some form to proceed."
    ///
    /// The residual case: something must happen in front of the user, and it is
    /// neither plain authentication nor plain consent. A step-up that the
    /// tenant *could* perform but `prompt=none` forbids it from performing is
    /// this code and not [`Self::UnmetAuthenticationRequirements`], because the
    /// requirement is not unmeetable — it is unmeetable *silently*, and a
    /// client that drops `prompt=none` will get what it asked for.
    #[error("interaction_required")]
    InteractionRequired,
    /// §3.1.2.6: "The End-User is REQUIRED to select a session."
    ///
    /// Sent when the request names a subject this session is not about and the
    /// tenant offers an account chooser. Without a chooser the same situation
    /// is [`Self::LoginRequired`]: there is no session to select.
    #[error("account_selection_required")]
    AccountSelectionRequired,
    /// Unmet Authentication Requirements 1.0 §2.
    ///
    /// "The Authorization Server is unable to meet the requirements of the
    /// Relying Party for the authentication of the End-User." Not a refusal to
    /// try: a statement that no amount of interaction would produce what was
    /// asked for, because the tenant cannot perform that authentication at all.
    /// Distinct from [`Self::InteractionRequired`] precisely so that a client
    /// can tell "ask again without `prompt=none`" from "stop asking".
    #[error("unmet_authentication_requirements")]
    UnmetAuthenticationRequirements,
}

impl Unmet {
    /// The error code, as it appears in the authorization response.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::LoginRequired => "login_required",
            Self::ConsentRequired => "consent_required",
            Self::InteractionRequired => "interaction_required",
            Self::AccountSelectionRequired => "account_selection_required",
            Self::UnmetAuthenticationRequirements => "unmet_authentication_requirements",
        }
    }
}

/// What has to happen before this request can be answered.
///
/// Deliberately not `#[non_exhaustive]`: the caller matches on this to decide
/// what a browser is shown, and a wildcard arm there would silently render a
/// sign-in page for a case nobody had implemented. Adding a variant should
/// break that match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Interaction {
    /// Nothing. The request can be completed from what is already known.
    Silent,
    /// The user must authenticate.
    Login,
    /// The user must choose which account this is about.
    SelectAccount,
    /// The user must authenticate *again*, more strongly (`ast-2vk.7`).
    StepUp,
    /// The user must be asked to consent.
    Consent,
    /// The user must create an account (Prompt Create 1.0 §3).
    Register,
    /// Nothing can happen: the client must be told why.
    Refuse(Unmet),
}

/// Whether the user has already agreed to what this request asks for.
///
/// A two-valued answer rather than a `bool` because the two are not opposites
/// in the way a boolean suggests: `Required` is what a server with no memory of
/// past consent always says, and it is a fact about *this deployment* rather
/// than about the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Consent {
    /// Recorded previously, and still covers this request.
    Granted,
    /// Must be asked for.
    Required,
}

/// What the browser brings to the request.
#[derive(Debug, Clone, Copy)]
pub enum SessionState<'a> {
    /// No session, or one that is expired, idle or revoked. A session that
    /// cannot be used is the same as none: OIDC Core §3.1.2.1 asks whether the
    /// End-User "is logged in", not whether a cookie was sent.
    None,
    /// A usable session.
    Active {
        /// The session itself, for `auth_time` and `acr`.
        session: &'a Session,
        /// The `sub` **this client** would see for the session's user (OIDC
        /// Core §8.1).
        ///
        /// Resolved by the caller, because a pairwise subject is a stored fact
        /// rather than a derivation, and compared against the subject an
        /// `id_token_hint` named. Comparing anything else — the internal user
        /// id, the public subject — would compare two identifiers that are not
        /// in the same namespace, which is a comparison that fails open the
        /// first time a client is pairwise.
        ///
        /// `None` when the caller had no reason to resolve one — no
        /// `id_token_hint` was verified, so there is nothing to compare
        /// against. A caller that *does* hold a hinted subject and passes
        /// `None` here is saying the session is about somebody else, which is
        /// the failing-closed reading and the only safe one.
        subject: Option<&'a str>,
        /// Whether this request is already covered by a recorded consent.
        consent: Consent,
    },
}

/// What the tenant will do without being asked.
///
/// Everything here is a deployment decision, and every default is the one that
/// asks for less. Kept separate from [`crate::authorize::AuthorizationPolicy`]
/// because that one is consulted while a client is on the connection and this
/// one while a browser is: they answer different questions at different times,
/// and merging them would put a session-shaped decision in the request
/// validator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct DecisionPolicy {
    /// Whether the tenant can offer a choice between signed-in accounts.
    ///
    /// `false` by default, because this server keeps one session per browser:
    /// there is nothing to choose between. It decides one thing — whether a
    /// `prompt=none` request naming a different subject is answered
    /// `account_selection_required` (§3.1.2.6, "The End-User is REQUIRED to
    /// select a session") or `login_required` — and the honest answer for a
    /// server with no chooser is the second.
    pub account_chooser: bool,
}

impl DecisionPolicy {
    /// A tenant with or without an account chooser.
    ///
    /// A constructor because the type is `#[non_exhaustive]`; see
    /// [`crate::authorize::AuthorizationPolicy::new`] for why that matters.
    #[must_use]
    pub const fn new(account_chooser: bool) -> Self {
        Self { account_chooser }
    }
}

/// Whether a tenant can produce an authentication context, and whether it has.
///
/// The seam `ast-2vk.7` implements. Two questions, because the answers lead to
/// different responses: a requirement nothing can satisfy is
/// [`Unmet::UnmetAuthenticationRequirements`] whatever the request said, and one
/// this session merely has not satisfied *yet* is a step-up — or, under
/// `prompt=none`, [`Unmet::InteractionRequired`].
pub trait AcrPolicy {
    /// Whether this tenant could ever produce one of `requested`.
    ///
    /// An empty `requested` is trivially satisfiable: the client asked for no
    /// particular context.
    fn can_satisfy(&self, requested: &[String]) -> bool;

    /// Whether an authentication that produced `achieved` meets `requested`.
    ///
    /// `achieved` is `None` for a session with no recorded `acr`, which is
    /// every session this server issues today.
    fn satisfied_by(&self, achieved: Option<&str>, requested: &[String]) -> bool;
}

/// The policy of a tenant that has configured no authentication contexts.
///
/// It can satisfy exactly one requirement: the empty one. That is not a
/// placeholder shrugging — it is the correct answer for a deployment that has
/// never been told what `urn:mace:incommon:iap:silver` would mean for it, and
/// it makes the failure a client sees (`unmet_authentication_requirements`, for
/// an *essential* request) the true one. The alternative — claiming every
/// requested context is met — would assert an authentication strength nobody
/// configured, which is the one answer that is never safe.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoAcrPolicy;

impl AcrPolicy for NoAcrPolicy {
    fn can_satisfy(&self, requested: &[String]) -> bool {
        requested.is_empty()
    }

    fn satisfied_by(&self, achieved: Option<&str>, requested: &[String]) -> bool {
        // An exact match still counts: if a session somehow carries an `acr`
        // the client named, the requirement is met by fact rather than by
        // policy. This is what keeps the rule the same shape as the one
        // `ast-2vk.7` will install over it.
        requested.is_empty()
            || achieved.is_some_and(|achieved| requested.iter().any(|value| value == achieved))
    }
}

/// What a request needs, stripped of everything that does not bear on the
/// decision.
///
/// Owned rather than borrowed from the [`AuthorizationRequest`], because the
/// caller that decides is not the caller that validated: the request was stored
/// at the push and is read back from the database a browser-redirect later.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Requirements {
    /// The `prompt` values, already checked for the `none` combination rule.
    pub prompts: BTreeSet<Prompt>,
    /// `max_age`, in seconds. `Some(0)` demands a fresh authentication; `None`
    /// asks for nothing.
    pub max_age: Option<u32>,
    /// The `sub` an `id_token_hint` named, after the hint was verified.
    pub hinted_subject: Option<String>,
    /// `acr_values`, in preference order — a *voluntary* request (OIDC Core
    /// §3.1.2.1, and §5.5.1.1's reading of it as a Voluntary Claim).
    pub acr_values: Vec<String>,
    /// The `acr` values the client marked essential through `claims`
    /// (§5.5.1.1).
    ///
    /// The difference from [`Self::acr_values`] is the whole of §5.5.1.1: a
    /// voluntary request that cannot be met is answered anyway, with whatever
    /// context the authentication did produce, while an essential one that
    /// cannot be met is an error. Folding the two together would either turn
    /// every `acr_values` into a hard failure or turn every essential `acr`
    /// into a suggestion.
    pub essential_acr: Vec<String>,
}

impl Requirements {
    /// Reads the requirements out of a validated request.
    ///
    /// `hinted_subject` is passed in rather than read from
    /// [`AuthorizationRequest::id_token_hint`], because a hint that has not
    /// been verified names nobody — the string on the request is a client's
    /// claim about a token, and the subject is what is left after this server
    /// has checked its own signature on it.
    #[must_use]
    pub fn from_request(request: &AuthorizationRequest, hinted_subject: Option<String>) -> Self {
        let essential_acr = request
            .claims
            .acr()
            .filter(|acr| acr.is_essential())
            .map(|acr| {
                acr.accepted_values()
                    .iter()
                    .filter_map(|value| value.as_str().map(ToOwned::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        Self {
            prompts: request.prompts.clone(),
            max_age: request.max_age,
            hinted_subject,
            acr_values: request.acr_values.clone(),
            essential_acr,
        }
    }

    /// Whether the client forbade every form of interaction (§3.1.2.1).
    #[must_use]
    pub fn is_silent(&self) -> bool {
        self.prompts.contains(&Prompt::None)
    }
}

/// Decides what happens next.
///
/// The table, in the order the rules are applied. Each row is a test in this
/// module, named after the rule rather than after the code path.
///
/// | # | Condition | Outcome |
/// |---|-----------|---------|
/// | 1 | essential `acr` the tenant can never produce | `unmet_authentication_requirements` |
/// | 2 | `prompt=create` | [`Interaction::Register`] |
/// | 3 | `prompt=none` and no usable session | `login_required` |
/// | 4 | `prompt=none` and the session is about somebody else | `account_selection_required`, or `login_required` without a chooser |
/// | 5 | `prompt=none` and re-authentication is due (`prompt=login` is impossible here, so: `max_age`) | `login_required` |
/// | 6 | `prompt=none` and the session's `acr` does not meet an essential request | `interaction_required` |
/// | 7 | `prompt=none` and consent has not been recorded | `consent_required` |
/// | 8 | `prompt=none`, everything in place | [`Interaction::Silent`] |
/// | 9 | re-authentication due, no session, the wrong subject, or `prompt=select_account` | [`Interaction::SelectAccount`] with `prompt=select_account`, else [`Interaction::Login`] |
/// | 10 | essential `acr` unmet by a session that is otherwise fine | [`Interaction::StepUp`] |
/// | 11 | `prompt=consent`, or consent not recorded | [`Interaction::Consent`] |
/// | 12 | nothing outstanding | [`Interaction::Silent`] |
///
/// Row 1 comes before row 2 and before every `prompt` rule on purpose: a
/// requirement that cannot be met is not made meetable by asking the user
/// anything, so sending them through a sign-in first would waste an
/// authentication to arrive at the same error.
///
/// # `max_age=0`
///
/// Row 5 uses [`Session::needs_reauthentication`], which compares strictly:
/// elapsed time *greater than* `max_age`. So `max_age=0` is met only by an
/// authentication that has just happened and is otherwise a demand to
/// re-authenticate — which is what OIDC Core §3.1.2.1 means by an allowable
/// elapsed time of zero. It is not "no constraint"; see
/// [`crate::authorize::parse_max_age`].
#[must_use]
pub fn decide(
    requirements: &Requirements,
    state: &SessionState<'_>,
    policy: DecisionPolicy,
    acr: &dyn AcrPolicy,
    now: OffsetDateTime,
) -> Interaction {
    // 1. Unmeetable before anything else, whatever the request asked for.
    if !acr.can_satisfy(&requirements.essential_acr) {
        return Interaction::Refuse(Unmet::UnmetAuthenticationRequirements);
    }

    // 2. Prompt Create §3: the request is about a user who does not exist yet,
    // so nothing about the current session bears on it. `prompt=none` cannot
    // be here — the combination is refused at the push.
    if requirements.prompts.contains(&Prompt::Create) {
        return Interaction::Register;
    }

    let (session, subject, consent) = match state {
        SessionState::None => (None, None, Consent::Required),
        SessionState::Active {
            session,
            subject,
            consent,
        } => (Some(*session), Some(*subject), *consent),
    };

    // §3.1.2.1: "If the End-User identified by the ID Token is logged in...
    // otherwise... login_required". A session about somebody else is not a
    // smaller kind of match.
    let wrong_subject = match (&requirements.hinted_subject, session) {
        // A hint with no session is handled by the no-session rules below,
        // which say the same thing without needing this one.
        (Some(hinted), Some(_)) => subject.flatten() != Some(hinted.as_str()),
        _ => false,
    };
    // §3.1.2.3: `prompt=login` and an exceeded `max_age` are the same demand.
    let must_reauthenticate = session.is_some_and(|active| {
        requirements.prompts.contains(&Prompt::Login)
            || active.needs_reauthentication(requirements.max_age, now)
    });
    let acr_met = acr.satisfied_by(
        session.and_then(|session| session.acr.as_deref()),
        &requirements.essential_acr,
    );

    if requirements.is_silent() {
        let facts = Facts {
            session: if session.is_none() {
                Presence::Absent
            } else {
                Presence::Present
            },
            subject: if wrong_subject {
                Whose::SomebodyElse
            } else {
                Whose::AsRequested
            },
            authentication: if must_reauthenticate {
                Freshness::Stale
            } else {
                Freshness::Fresh
            },
            context: if acr_met {
                Context::Met
            } else {
                Context::Unmet
            },
        };
        return match silent_refusal(facts, consent, policy) {
            Some(unmet) => Interaction::Refuse(unmet),
            // Row 8: nothing is outstanding, so the request is answered from
            // what is already known and the user is not disturbed. The half of
            // `prompt=none` that a server refusing too eagerly would break.
            None => Interaction::Silent,
        };
    }

    let chooser_asked = requirements.prompts.contains(&Prompt::SelectAccount);
    if session.is_none() || must_reauthenticate || wrong_subject || chooser_asked {
        // A chooser is only worth showing when there is something to choose
        // between; `select_account` on a browser with no session is a sign-in.
        return if policy.account_chooser && chooser_asked {
            Interaction::SelectAccount
        } else {
            Interaction::Login
        };
    }
    if !acr_met {
        // `ast-2vk.7`'s screen. Reached only when the tenant says the context
        // is producible, so this is a request to perform it rather than a hope.
        return Interaction::StepUp;
    }
    if requirements.prompts.contains(&Prompt::Consent) || consent == Consent::Required {
        return Interaction::Consent;
    }
    Interaction::Silent
}

/// Whether the browser has a usable session at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Presence {
    /// None, or one that is expired, idle or revoked.
    Absent,
    /// A usable one.
    Present,
}

/// Whether the session is about the person the request names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Whose {
    /// The subject the verified `id_token_hint` named, or no hint at all.
    AsRequested,
    /// Somebody else.
    SomebodyElse,
}

/// Whether the authentication is recent enough (OIDC Core §3.1.2.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Freshness {
    /// Within `max_age`, and `prompt=login` was not asked for.
    Fresh,
    /// Re-authentication is due.
    Stale,
}

/// Whether the session meets the essential `acr` request (§5.5.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Context {
    /// It does, or none was made.
    Met,
    /// It does not, and only an interaction could change that.
    Unmet,
}

/// What the session turned out to be, as four settled questions.
///
/// Named two-variant types rather than four `bool` fields: at a call site four
/// booleans are four identically-typed values in an order nobody can check, and
/// this is the decision about whether a person is shown a page at all.
#[derive(Debug, Clone, Copy)]
struct Facts {
    /// Whether there is a session.
    session: Presence,
    /// Who it is about.
    subject: Whose,
    /// How recently they authenticated.
    authentication: Freshness,
    /// What authentication context it produced.
    context: Context,
}

/// Rows 3 to 8: the same conditions, answered without a user.
///
/// Its own function because the silent branch is where a wrong answer is
/// expensive in both directions — a page nobody may see, or an error a client
/// did not deserve — and because the order of these five tests *is* the
/// specification's order of error codes.
fn silent_refusal(facts: Facts, consent: Consent, policy: DecisionPolicy) -> Option<Unmet> {
    if facts.session == Presence::Absent {
        return Some(Unmet::LoginRequired);
    }
    if facts.subject == Whose::SomebodyElse {
        return Some(if policy.account_chooser {
            Unmet::AccountSelectionRequired
        } else {
            Unmet::LoginRequired
        });
    }
    if facts.authentication == Freshness::Stale {
        return Some(Unmet::LoginRequired);
    }
    if facts.context == Context::Unmet {
        // The tenant *can* produce this context — row 1 already refused the
        // case where it cannot — but only by putting something in front of the
        // user, which is the one thing this request forbids.
        return Some(Unmet::InteractionRequired);
    }
    match consent {
        // Row 8. Written as an arm of its own rather than as the absence of a
        // refusal, because this is the answer a client polling for a session
        // depends on, and it should be as visible in the code as the errors
        // around it.
        Consent::Granted => None,
        Consent::Required => Some(Unmet::ConsentRequired),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asterius_domain::entities::session::SessionId;
    use asterius_domain::{AuthenticationMethod, Lifetimes, Session, TenantId};
    use time::Duration;

    const SUBJECT: &str = "sub-1";

    fn now() -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH + Duration::days(20_000)
    }

    fn lifetimes() -> Lifetimes {
        Lifetimes {
            idle: Duration::hours(1),
            absolute: Duration::days(1),
        }
    }

    /// A session authenticated `age` ago.
    fn session(age: Duration) -> Session {
        let mut session = Session::begin(
            TenantId::new("demo"),
            &SessionId::generate(),
            uuid::Uuid::nil(),
            vec![AuthenticationMethod::Password],
            now(),
            lifetimes(),
        );
        session.authenticated_at = now() - age;
        session
    }

    fn active(session: &Session, consent: Consent) -> SessionState<'_> {
        SessionState::Active {
            session,
            subject: Some(SUBJECT),
            consent,
        }
    }

    fn requirements(prompt: &[Prompt]) -> Requirements {
        Requirements {
            prompts: prompt.iter().copied().collect(),
            ..Requirements::default()
        }
    }

    fn decide_with(requirements: &Requirements, state: &SessionState<'_>) -> Interaction {
        decide(
            requirements,
            state,
            DecisionPolicy::default(),
            &NoAcrPolicy,
            now(),
        )
    }

    // ---- row 3: prompt=none with nothing to go on ------------------------

    /// §3.1.2.1: with `prompt=none` and no session there is nothing to answer
    /// with and nothing may be displayed.
    #[test]
    fn a_silent_request_without_a_session_is_refused_login_required() {
        let requirements = requirements(&[Prompt::None]);

        let outcome = decide_with(&requirements, &SessionState::None);

        assert_eq!(outcome, Interaction::Refuse(Unmet::LoginRequired));
    }

    // ---- row 8: the case a wrong implementation breaks -------------------

    /// The other half of `prompt=none`: a request that *can* be answered must
    /// be, silently. A server that refuses here breaks every client that
    /// checks for a session without disturbing the user.
    #[test]
    fn a_silent_request_with_everything_in_place_is_answered_silently() {
        let session = session(Duration::minutes(1));
        let requirements = requirements(&[Prompt::None]);

        let outcome = decide_with(&requirements, &active(&session, Consent::Granted));

        assert_eq!(outcome, Interaction::Silent);
    }

    // ---- row 7 -----------------------------------------------------------

    /// §3.1.2.6: consent that has not been given cannot be assumed, and with
    /// `prompt=none` it cannot be asked for either.
    #[test]
    fn a_silent_request_needing_consent_is_refused_consent_required() {
        let session = session(Duration::minutes(1));
        let requirements = requirements(&[Prompt::None]);

        let outcome = decide_with(&requirements, &active(&session, Consent::Required));

        assert_eq!(outcome, Interaction::Refuse(Unmet::ConsentRequired));
    }

    // ---- row 5, and what max_age=0 means ---------------------------------

    /// §3.1.2.1: an authentication older than `max_age` is too old, and with
    /// `prompt=none` the re-authentication cannot happen.
    #[test]
    fn a_silent_request_past_max_age_is_refused_login_required() {
        let session = session(Duration::minutes(10));
        let requirements = Requirements {
            max_age: Some(60),
            ..requirements(&[Prompt::None])
        };

        let outcome = decide_with(&requirements, &active(&session, Consent::Granted));

        assert_eq!(outcome, Interaction::Refuse(Unmet::LoginRequired));
    }

    /// `max_age=0` is the strictest request, not the absence of one: an
    /// authentication that happened a second ago is already too old.
    #[test]
    fn max_age_zero_demands_a_fresh_authentication() {
        let session = session(Duration::seconds(1));
        let requirements = Requirements {
            max_age: Some(0),
            ..Requirements::default()
        };

        let outcome = decide_with(&requirements, &active(&session, Consent::Granted));

        assert_eq!(outcome, Interaction::Login);
    }

    /// And the same request with `prompt=none` cannot be answered at all.
    #[test]
    fn max_age_zero_with_prompt_none_is_refused_login_required() {
        let session = session(Duration::seconds(1));
        let requirements = Requirements {
            max_age: Some(0),
            ..requirements(&[Prompt::None])
        };

        let outcome = decide_with(&requirements, &active(&session, Consent::Granted));

        assert_eq!(outcome, Interaction::Refuse(Unmet::LoginRequired));
    }

    /// No `max_age` is no constraint, which is the distinction `Some(0)` would
    /// lose if absence and zero were the same value.
    #[test]
    fn no_max_age_leaves_an_old_session_alone() {
        let session = session(Duration::hours(12));
        let requirements = Requirements::default();

        let outcome = decide_with(&requirements, &active(&session, Consent::Granted));

        assert_eq!(outcome, Interaction::Silent);
    }

    // ---- row 4: the id_token_hint subject --------------------------------

    /// §3.1.2.1: the request is about the person the hint names. A session
    /// about somebody else does not answer it.
    #[test]
    fn a_hint_naming_another_subject_is_refused_login_required() {
        let session = session(Duration::minutes(1));
        let requirements = Requirements {
            hinted_subject: Some("somebody-else".to_owned()),
            ..requirements(&[Prompt::None])
        };

        let outcome = decide_with(&requirements, &active(&session, Consent::Granted));

        assert_eq!(outcome, Interaction::Refuse(Unmet::LoginRequired));
    }

    /// §3.1.2.6: with a chooser, the same situation has a better answer —
    /// the user is asked to select the session the request is about.
    #[test]
    fn a_tenant_with_a_chooser_refuses_account_selection_required_instead() {
        let session = session(Duration::minutes(1));
        let requirements = Requirements {
            hinted_subject: Some("somebody-else".to_owned()),
            ..requirements(&[Prompt::None])
        };

        let outcome = decide(
            &requirements,
            &active(&session, Consent::Granted),
            DecisionPolicy::new(true),
            &NoAcrPolicy,
            now(),
        );

        assert_eq!(
            outcome,
            Interaction::Refuse(Unmet::AccountSelectionRequired)
        );
    }

    /// A hint naming the session's own subject changes nothing.
    #[test]
    fn a_hint_naming_this_session_is_no_obstacle() {
        let session = session(Duration::minutes(1));
        let requirements = Requirements {
            hinted_subject: Some(SUBJECT.to_owned()),
            ..requirements(&[Prompt::None])
        };

        let outcome = decide_with(&requirements, &active(&session, Consent::Granted));

        assert_eq!(outcome, Interaction::Silent);
    }

    // ---- row 1 and row 6: acr --------------------------------------------

    /// Unmet Authentication Requirements §2: a tenant that cannot produce the
    /// requested context says so, rather than authenticating the user first and
    /// failing afterwards.
    #[test]
    fn an_essential_acr_the_tenant_cannot_produce_is_refused_as_unmet() {
        let requirements = Requirements {
            essential_acr: vec!["urn:mace:incommon:iap:silver".to_owned()],
            ..Requirements::default()
        };

        let outcome = decide_with(&requirements, &SessionState::None);

        assert_eq!(
            outcome,
            Interaction::Refuse(Unmet::UnmetAuthenticationRequirements)
        );
    }

    /// And it is refused before `prompt` is read at all: no interaction would
    /// make it meetable.
    #[test]
    fn an_unmeetable_requirement_is_refused_even_when_interaction_is_allowed() {
        let requirements = Requirements {
            essential_acr: vec!["urn:mace:incommon:iap:silver".to_owned()],
            ..requirements(&[Prompt::Login])
        };

        let outcome = decide_with(&requirements, &SessionState::None);

        assert_eq!(
            outcome,
            Interaction::Refuse(Unmet::UnmetAuthenticationRequirements)
        );
    }

    /// §5.5.1.1: a *voluntary* `acr_values` that cannot be met is not an error.
    /// The request is answered with whatever context the authentication had.
    #[test]
    fn voluntary_acr_values_that_cannot_be_met_are_not_an_error() {
        let session = session(Duration::minutes(1));
        let requirements = Requirements {
            acr_values: vec!["urn:mace:incommon:iap:silver".to_owned()],
            ..Requirements::default()
        };

        let outcome = decide_with(&requirements, &active(&session, Consent::Granted));

        assert_eq!(outcome, Interaction::Silent);
    }

    /// Row 6: a context the tenant *can* produce, a session that has not
    /// produced it, and a request that forbids interacting.
    #[test]
    fn a_silent_request_needing_a_step_up_is_refused_interaction_required() {
        /// A tenant that can perform every context it is asked for — the shape
        /// `ast-2vk.7` will supply for real.
        struct Capable;
        impl AcrPolicy for Capable {
            fn can_satisfy(&self, _requested: &[String]) -> bool {
                true
            }
            fn satisfied_by(&self, achieved: Option<&str>, requested: &[String]) -> bool {
                requested.is_empty() || achieved.is_some()
            }
        }

        let session = session(Duration::minutes(1));
        let requirements = Requirements {
            essential_acr: vec!["urn:mace:incommon:iap:silver".to_owned()],
            ..requirements(&[Prompt::None])
        };

        let outcome = decide(
            &requirements,
            &active(&session, Consent::Granted),
            DecisionPolicy::default(),
            &Capable,
            now(),
        );

        assert_eq!(outcome, Interaction::Refuse(Unmet::InteractionRequired));
    }

    /// The same request without `prompt=none` is a step-up rather than an
    /// error, which is the distinction the two codes exist to make.
    #[test]
    fn the_same_requirement_with_interaction_allowed_is_a_step_up() {
        struct Capable;
        impl AcrPolicy for Capable {
            fn can_satisfy(&self, _requested: &[String]) -> bool {
                true
            }
            fn satisfied_by(&self, achieved: Option<&str>, requested: &[String]) -> bool {
                requested.is_empty() || achieved.is_some()
            }
        }

        let session = session(Duration::minutes(1));
        let requirements = Requirements {
            essential_acr: vec!["urn:mace:incommon:iap:silver".to_owned()],
            ..Requirements::default()
        };

        let outcome = decide(
            &requirements,
            &active(&session, Consent::Granted),
            DecisionPolicy::default(),
            &Capable,
            now(),
        );

        assert_eq!(outcome, Interaction::StepUp);
    }

    // ---- rows 2, 9, 11, 12: the interactive half -------------------------

    /// Prompt Create §3: the request is to enrol somebody, and an existing
    /// session does not answer it.
    #[test]
    fn prompt_create_routes_to_registration() {
        let session = session(Duration::minutes(1));
        let requirements = requirements(&[Prompt::Create]);

        let outcome = decide_with(&requirements, &active(&session, Consent::Granted));

        assert_eq!(outcome, Interaction::Register);
    }

    /// §3.1.2.1: `prompt=login` re-authenticates however fresh the session is.
    #[test]
    fn prompt_login_forces_authentication_on_a_fresh_session() {
        let session = session(Duration::seconds(1));
        let requirements = requirements(&[Prompt::Login]);

        let outcome = decide_with(&requirements, &active(&session, Consent::Granted));

        assert_eq!(outcome, Interaction::Login);
    }

    /// §3.1.2.1: `prompt=consent` asks again even when consent is recorded.
    #[test]
    fn prompt_consent_asks_again() {
        let session = session(Duration::minutes(1));
        let requirements = requirements(&[Prompt::Consent]);

        let outcome = decide_with(&requirements, &active(&session, Consent::Granted));

        assert_eq!(outcome, Interaction::Consent);
    }

    /// No session and no `prompt` at all is the ordinary first visit.
    #[test]
    fn an_ordinary_request_without_a_session_starts_at_login() {
        let outcome = decide_with(&Requirements::default(), &SessionState::None);

        assert_eq!(outcome, Interaction::Login);
    }

    /// A signed-in browser that has not consented yet meets the consent screen.
    #[test]
    fn a_signed_in_browser_that_has_not_consented_meets_consent() {
        let session = session(Duration::minutes(1));

        let outcome = decide_with(
            &Requirements::default(),
            &active(&session, Consent::Required),
        );

        assert_eq!(outcome, Interaction::Consent);
    }

    /// `prompt=select_account` without a chooser is a sign-in, not a screen
    /// this server does not have.
    #[test]
    fn select_account_without_a_chooser_is_a_sign_in() {
        let session = session(Duration::minutes(1));
        let requirements = requirements(&[Prompt::SelectAccount]);

        let outcome = decide_with(&requirements, &active(&session, Consent::Granted));

        assert_eq!(outcome, Interaction::Login);
    }

    /// With a chooser it is the chooser.
    #[test]
    fn select_account_with_a_chooser_offers_the_choice() {
        let session = session(Duration::minutes(1));
        let requirements = requirements(&[Prompt::SelectAccount]);

        let outcome = decide(
            &requirements,
            &active(&session, Consent::Granted),
            DecisionPolicy::new(true),
            &NoAcrPolicy,
            now(),
        );

        assert_eq!(outcome, Interaction::SelectAccount);
    }

    /// Every refusal carries the code the specifications register, spelled the
    /// way a client will compare it.
    #[test]
    fn every_refusal_has_its_registered_code() {
        assert_eq!(Unmet::LoginRequired.code(), "login_required");
        assert_eq!(Unmet::ConsentRequired.code(), "consent_required");
        assert_eq!(Unmet::InteractionRequired.code(), "interaction_required");
        assert_eq!(
            Unmet::AccountSelectionRequired.code(),
            "account_selection_required"
        );
        assert_eq!(
            Unmet::UnmetAuthenticationRequirements.code(),
            "unmet_authentication_requirements"
        );
    }
}
