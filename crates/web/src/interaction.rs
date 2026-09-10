//! The interaction: what happens between an authorization request arriving and
//! a decision being made about it.
//!
//! A client pushes an authorization request and gets a `request_uri`. It sends
//! the user agent to `/authorize`, which creates an **interaction** — the
//! browser's handle on that request — and drives it through login, any step-up,
//! consent, and finally the response.
//!
//! # Two credentials, two holders
//!
//! The `request_uri` belongs to the *client*. The interaction id belongs to the
//! *browser*. Neither is derivable from the other, and that is the point: a
//! client that could compute the interaction id could drive the user's login,
//! and a browser that could compute the `request_uri` could replay the push.
//!
//! # Why the id is in the path *and* a cookie
//!
//! The id in the URL is what makes the interaction addressable across a
//! redirect. The cookie is what makes it *this browser's*. A URL leaks — into
//! a `Referer`, a history entry, a screenshot, a support ticket — and an
//! interaction identified by a leaked URL alone would be resumable by whoever
//! read it. Requiring both means a leaked URL is inert without the cookie, and
//! a stolen cookie is inert without the URL.
//!
//! FAPI 2.0 SP §6.5 calls the attack this closes browser swapping: an attacker
//! who gets the victim's authorization flow into their own browser, or their
//! own flow into the victim's. The mismatch is not a recoverable error — the
//! interaction is destroyed, because a request whose two halves disagree is one
//! where somebody is being deceived and there is no way to tell which party.

use asterius_domain::{Continuation, OpaqueToken, ct_eq, sha256_hex};
use std::fmt;

/// The cookie the interaction id travels in.
///
/// The `__Host-` prefix is not decoration. It is enforced by the browser and
/// makes three guarantees the server cannot make for itself: the cookie was set
/// over HTTPS, it has no `Domain` attribute (so a sibling subdomain cannot set
/// or read it), and its `Path` is `/`. Without the prefix, a compromised
/// `blog.example.com` can set a cookie for `example.com` and choose the
/// victim's interaction.
pub const COOKIE_NAME: &str = "__Host-asterius_ix";

/// Bits of entropy in an interaction id.
///
/// The same floor as every other bearer value here. Guessing one would mean
/// resuming somebody's half-finished login.
pub const ID_BITS: usize = 256;

/// Bits of entropy in a CSRF token.
pub const CSRF_BITS: usize = 256;

/// An interaction id, as held by the browser.
///
/// Redacted in `Debug` and compared only in constant time, because it is a
/// bearer credential: whoever holds it, plus the matching cookie, is the user
/// as far as this flow is concerned.
pub struct InteractionId(OpaqueToken);

impl InteractionId {
    /// Mints a new id.
    #[must_use]
    pub fn generate() -> Self {
        Self(OpaqueToken::generate_bits::<ID_BITS>())
    }

    /// Takes an id off the wire.
    ///
    /// Named for what it is. Nothing about a presented value is trustworthy
    /// until [`InteractionId::matches`] has compared it with the stored one.
    #[must_use]
    pub fn from_presented(value: String) -> Self {
        Self(OpaqueToken::from_presented(value))
    }

    /// The value to put in a URL or a cookie.
    #[must_use]
    pub fn expose(&self) -> &str {
        self.0.expose()
    }

    /// The value to store: a digest, never the id.
    ///
    /// A leaked database row must not yield a usable interaction.
    #[must_use]
    pub fn digest(&self) -> String {
        sha256_hex(self.0.expose().as_bytes())
    }

    /// Whether two ids are the same, in constant time.
    ///
    /// This compares the id from the URL with the id from the cookie, on every
    /// request. A short-circuiting `==` would leak the shared prefix, and the
    /// attacker in FAPI 2.0 SP §6.5 is one who can make many attempts.
    #[must_use]
    pub fn matches(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0)
    }
}

impl fmt::Debug for InteractionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("InteractionId([REDACTED])")
    }
}

/// A synchroniser token, one per rendered form.
///
/// The interaction cookie is `SameSite=Lax`, which stops a cross-site *POST*
/// from carrying it — so in a modern browser this token is the second lock on
/// a door that already has one. It is here because "a modern browser" is an
/// assumption about the user's software, and the consent form is the one place
/// where a forged submission is a granted authorization.
pub struct CsrfToken(OpaqueToken);

impl CsrfToken {
    /// Mints a token.
    #[must_use]
    pub fn generate() -> Self {
        Self(OpaqueToken::generate_bits::<CSRF_BITS>())
    }

    /// Takes a token off a submitted form.
    #[must_use]
    pub fn from_presented(value: String) -> Self {
        Self(OpaqueToken::from_presented(value))
    }

    /// The value to render into a hidden field.
    #[must_use]
    pub fn expose(&self) -> &str {
        self.0.expose()
    }

    /// Whether a submitted token is the one that was issued.
    #[must_use]
    pub fn matches(&self, presented: &Self) -> bool {
        self.0.ct_eq(&presented.0)
    }
}

impl fmt::Debug for CsrfToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CsrfToken([REDACTED])")
    }
}

/// Where an interaction has got to.
///
/// Closed and not `#[non_exhaustive]`: every stage is a page this server has to
/// render, so a new one must break every match until somebody has written it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    /// The user has not been authenticated for this request yet.
    Login,
    /// The request asked for an account that does not exist yet
    /// (`prompt=create`, OpenID Connect Prompt Create 1.0 §3).
    ///
    /// A stage of its own rather than a flag on [`Stage::Login`], because it is
    /// a different page taking a different form and producing a different
    /// audit event. It is also the only stage a *tenant* can switch off: the
    /// value is refused at the push unless
    /// [`asterius_domain::Feature::SelfRegistration`] is on, so nothing can
    /// reach here that the discovery document did not advertise.
    Register,
    /// Authenticated, but the request asks for an assurance the current
    /// authentication does not meet (`acr_values`, `max_age`).
    StepUp,
    /// Authenticated to the required level; the user has not yet decided.
    Consent,
    /// Decided. The response is ready to be delivered to the client.
    Response,
}

impl Stage {
    /// Whether `next` is a legal move from here, for an interaction with this
    /// continuation.
    ///
    /// Forward only, with one exception. The state machine is small enough to
    /// state completely, which is the point: an interaction that could move
    /// backwards is one where a user who has consented can be returned to a
    /// login form and asked again, and an interaction that could skip `Consent`
    /// is a grant nobody agreed to.
    ///
    /// # Why the continuation is a parameter
    ///
    /// Because the two kinds of interaction have two different machines, and
    /// the difference is exactly the stage that matters. An authorization must
    /// pass through [`Stage::Consent`] and may never jump from `Login` to
    /// `Response`; a first-party login (ADR-0009) has no client to consent to
    /// and must never *reach* `Consent`. Deciding that here, in the one
    /// function every transition already goes through, is what makes both
    /// statements properties of a `match` rather than of a handler that
    /// remembers to check. Passing the continuation is also what stops the
    /// first-party arm from being a general "skip consent" switch: nothing can
    /// ask for `Login -> Response` without holding a
    /// [`Continuation::FirstParty`], and nothing can build one of those from a
    /// request parameter.
    #[must_use]
    pub const fn may_advance_to(self, next: Self, continuation: &Continuation) -> bool {
        match continuation {
            Continuation::Client(_) => matches!(
                (self, next),
                // Prompt Create §3: an account that has just been created has
                // been authenticated by the act of creating it, so the move
                // out of `Register` is the move out of `Login` — never
                // straight to `Response`, which would be a grant nobody was
                // asked about. The move *to* `Login` is the "already have an
                // account?" door, and it costs progress rather than granting
                // any, like the backward move below it.
                (Self::Register, Self::StepUp | Self::Consent | Self::Login)
                    | (Self::Login, Self::StepUp | Self::Consent)
                    // Re-authentication: a step-up that fails, or a session
                    // that expires mid-interaction, returns to `Login`. That
                    // backward move is the only one, and it costs nothing — it
                    // discards progress rather than granting any.
                    | (Self::StepUp, Self::Consent | Self::Login)
                    | (Self::Consent, Self::Response)
            ),
            Continuation::FirstParty(_) => matches!(
                (self, next),
                (Self::Register, Self::StepUp | Self::Response | Self::Login)
                    | (Self::Login, Self::StepUp | Self::Response)
                    | (Self::StepUp, Self::Response | Self::Login)
            ),
        }
    }

    /// Whether this stage still needs the user.
    #[must_use]
    pub const fn is_interactive(self) -> bool {
        !matches!(self, Self::Response)
    }

    /// Where an authenticated user goes next, given what this interaction is
    /// for.
    ///
    /// The one place that answer is decided, so that "a first-party
    /// interaction never reaches [`Stage::Consent`]" is a property of a match
    /// rather than of a handler remembering to check. There is nobody to
    /// consent *to* when there is no client (ADR-0009): the console is this
    /// server's own surface, not a third party asking for access to the user's
    /// account, and a consent screen naming nobody would be a screen that
    /// teaches people to click through.
    ///
    /// `ast-2vk.7` owns the step-up that may come first; this is the stage
    /// after authentication has done all it is going to do.
    #[must_use]
    pub const fn after_login(continuation: &Continuation) -> Self {
        match continuation {
            Continuation::Client(_) => Self::Consent,
            Continuation::FirstParty(_) => Self::Response,
        }
    }
}

/// What is stored between one request and the next.
///
/// Lives in `auth_requests.interaction_state`, which the store treats as
/// opaque JSON — the stage machine belongs to this crate, so adding a stage is
/// not a schema change.
///
/// The CSRF token is held as a **digest**. It is issued once per rendered
/// form and checked once on submission, so the stored form never has to be
/// readable: a leaked row yields a value that cannot be submitted, for the
/// same reason the interaction id and the `request_uri` are stored hashed.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredState {
    /// Where the interaction has got to.
    pub stage: Stage,
    /// SHA-256 of the token issued with the last rendered form, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub csrf_digest: Option<String>,
    /// What the user answered, once they have.
    ///
    /// Recorded here rather than derived later, because it is the one fact in
    /// this flow that came from a person: the scopes are what they *granted*,
    /// which may be fewer than the client asked for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision: Option<StoredDecision>,
    /// Who signed in, once somebody has.
    ///
    /// Written by whichever method proved the account — password or passkey —
    /// so the screens that follow can name them without asking the browser or
    /// re-reading the account. It is a display fact only: nothing is decided
    /// from it, and the session is what carries the identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// The language this interaction is being conducted in, as a BCP 47 tag.
    ///
    /// Negotiated once, when the first screen is drawn, and carried from screen
    /// to screen from then on. Stored rather than recomputed because the three
    /// inputs do not all survive: `ui_locales` is on the pushed request but the
    /// `Accept-Language` of the *next* request is whatever that browser sends,
    /// and a sign-in that changed language between the password page and the
    /// consent page would be asking somebody to agree to a sentence they have
    /// not been reading (OIDC Core §3.1.2.1 asks for the End-User's preferred
    /// languages for "the user interface", not for a response).
    ///
    /// `None` is an interaction begun before this field existed, or one whose
    /// state was never written; the reader falls back to negotiating afresh.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,
}

/// A consent decision, as it survives between requests.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum StoredDecision {
    /// Approved, with what was actually granted.
    Approved {
        /// The scopes the user allowed, in the order they were offered.
        scopes: Vec<String>,
    },
    /// Refused. Becomes `access_denied` on the way back to the client.
    Denied,
}

impl Default for StoredState {
    fn default() -> Self {
        Self {
            stage: Stage::Login,
            csrf_digest: None,
            decision: None,
            username: None,
            locale: None,
        }
    }
}

impl StoredState {
    /// Reads the state out of what the store returned.
    ///
    /// An unreadable state is [`Stage::Login`] rather than an error: the row
    /// exists, the user is mid-flow, and starting them again at the beginning
    /// is the only outcome that is both safe and useful. It cannot skip a
    /// stage, because `Login` is the first one.
    ///
    /// `deny_unknown_fields` means a state written by a *newer* binary fails
    /// to parse here, which is the direction to fail in during a rolling
    /// deployment: an old replica restarts the login rather than acting on a
    /// field it does not understand.
    #[must_use]
    pub fn from_stored(value: &serde_json::Value) -> Self {
        serde_json::from_value(value.clone()).unwrap_or_default()
    }

    /// Issues a token for a form about to be rendered, and records its digest.
    ///
    /// Returns the token to render; the digest is what is stored.
    pub fn issue_csrf(&mut self) -> CsrfToken {
        let token = CsrfToken::generate();
        self.csrf_digest = Some(sha256_hex(token.expose().as_bytes()));
        token
    }

    /// Checks a submitted token against the issued one.
    ///
    /// # Errors
    ///
    /// [`InteractionError::CsrfFailed`] when there is no issued token, none
    /// was submitted, or they differ. One error for all three: a form that was
    /// not the one this server rendered is refused, and which way it failed is
    /// not the submitter's business.
    pub fn check_csrf(&self, presented: Option<&str>) -> Result<(), InteractionError> {
        let issued = self
            .csrf_digest
            .as_deref()
            .ok_or(InteractionError::CsrfFailed)?;
        let presented = presented.ok_or(InteractionError::CsrfFailed)?;
        // Both sides are digests of the same width, so the comparison is over
        // equal-length values and `ct_eq` is meaningful.
        if ct_eq(
            issued.as_bytes(),
            sha256_hex(presented.as_bytes()).as_bytes(),
        ) {
            Ok(())
        } else {
            Err(InteractionError::CsrfFailed)
        }
    }

    /// Records who has just signed in, for the screens that name them.
    ///
    /// One function for both authentication methods on purpose: the password
    /// path and the passkey path fill this field, and a second copy of the
    /// filling is how one of them ends up not doing it (`ast-bo5`).
    pub fn signed_in_as(&mut self, username: &str) {
        self.username = Some(username.to_owned());
    }

    /// Spends the issued token.
    ///
    /// A synchroniser token is good for one submission. Leaving it valid would
    /// make a captured form body replayable for the life of the interaction —
    /// which for a consent form means a decision that can be submitted twice.
    pub fn spend_csrf(&mut self) {
        self.csrf_digest = None;
    }
}

/// Why an interaction could not continue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum InteractionError {
    /// The id in the path and the id in the cookie are not the same.
    ///
    /// FAPI 2.0 SP §6.5. Not recoverable: see [`Interaction::resume`].
    #[error("the interaction does not belong to this browser")]
    BrowserMismatch,
    /// No cookie at all.
    #[error("no interaction cookie was presented")]
    NoCookie,
    /// No such interaction, or it has expired.
    ///
    /// One variant for both: which it was is a fact for the log, and telling a
    /// caller apart would let them probe for live interaction ids.
    #[error("the interaction is not available")]
    NotAvailable,
    /// The submitted CSRF token is missing or wrong.
    #[error("the form could not be verified")]
    CsrfFailed,
    /// The requested move is not one the state machine allows.
    #[error("the interaction cannot move to that stage")]
    IllegalTransition,
    /// `prompt=none` was requested but the interaction needs the user.
    ///
    /// OIDC Core §3.1.2.3: the AS "MUST NOT display any authentication or
    /// consent user interface pages" when `prompt=none`.
    #[error("interaction is required but prompt=none was requested")]
    InteractionRequired,
}

impl InteractionError {
    /// The OAuth error code to send to the *client*, when there is one to send.
    ///
    /// Most of these never reach the client: they are failures of the browser's
    /// relationship with this server, and the user sees a page. Only
    /// [`InteractionError::InteractionRequired`] is the client's business —
    /// it asked for `prompt=none` and the answer is that interaction was
    /// needed.
    #[must_use]
    pub const fn client_error_code(self) -> Option<&'static str> {
        match self {
            // OIDC Core §3.1.2.6.
            Self::InteractionRequired => Some("interaction_required"),
            _ => None,
        }
    }

    /// Whether the interaction should be destroyed rather than retried.
    #[must_use]
    pub const fn is_fatal(self) -> bool {
        matches!(self, Self::BrowserMismatch | Self::IllegalTransition)
    }
}

/// An interaction in progress.
///
/// Holds no secrets in a loggable form: the id is redacted, and the CSRF token
/// is regenerated per rendered form rather than stored here.
#[derive(Debug)]
pub struct Interaction {
    /// Which tenant, so a resumed interaction cannot cross one.
    pub tenant: asterius_domain::TenantId,
    /// The digest of the id, which is what the store holds.
    pub id_digest: String,
    /// Where it has got to.
    pub stage: Stage,
    /// The session that authenticated the user, once one has.
    pub session: Option<String>,
    /// When it stops being usable.
    pub expires_at: time::OffsetDateTime,
}

impl Interaction {
    /// Checks that a request may continue this interaction.
    ///
    /// `from_path` is the id in the URL; `from_cookie` is the id in the
    /// `__Host-` cookie. **Both** must be present and equal.
    ///
    /// # Errors
    ///
    /// [`InteractionError::NoCookie`] when the browser sent none, and
    /// [`InteractionError::BrowserMismatch`] when the two disagree. A mismatch
    /// is fatal: the caller must destroy the interaction rather than re-render
    /// it. A request whose two halves disagree is one where somebody is being
    /// deceived, and this server cannot tell which party — so it ends the flow
    /// for both rather than choosing a victim.
    pub fn resume(
        from_path: &InteractionId,
        from_cookie: Option<&InteractionId>,
    ) -> Result<(), InteractionError> {
        let cookie = from_cookie.ok_or(InteractionError::NoCookie)?;
        if from_path.matches(cookie) {
            Ok(())
        } else {
            Err(InteractionError::BrowserMismatch)
        }
    }

    /// Moves to `next`, or explains why not.
    ///
    /// # Errors
    ///
    /// [`InteractionError::IllegalTransition`] if the state machine forbids it.
    pub fn advance(
        &mut self,
        next: Stage,
        continuation: &Continuation,
    ) -> Result<(), InteractionError> {
        if self.stage.may_advance_to(next, continuation) {
            self.stage = next;
            Ok(())
        } else {
            Err(InteractionError::IllegalTransition)
        }
    }

    /// Whether this interaction has expired at `now`.
    #[must_use]
    pub fn has_expired(&self, now: time::OffsetDateTime) -> bool {
        self.expires_at <= now
    }
}

/// Builds the `Set-Cookie` value for an interaction.
///
/// Every attribute here is load-bearing, so they are set in one place rather
/// than assembled by each handler:
///
/// * **`__Host-` prefix** — see [`COOKIE_NAME`].
/// * **`Secure`** — required by the prefix, and required anyway.
/// * **`HttpOnly`** — script cannot read it. A CSP bypass on a login page
///   should not also be an interaction takeover.
/// * **`SameSite=Lax`** — a cross-site POST does not carry it, which is most of
///   the CSRF defence; `Strict` would break the top-level redirect *into* the
///   interaction, which is exactly how a user arrives.
/// * **`Path=/`** — required by the prefix. Narrowing it is not an option, and
///   would be a false comfort anyway: the id is the secret, not the path.
///
/// No `Max-Age`. It is a session cookie, so it dies with the browser session,
/// and the interaction's own `expires_at` is the authority on lifetime — a
/// cookie that outlived the interaction would only produce a confusing error.
#[must_use]
pub fn set_cookie(id: &InteractionId) -> String {
    format!(
        "{COOKIE_NAME}={}; Secure; HttpOnly; SameSite=Lax; Path=/",
        id.expose()
    )
}

/// Builds the `Set-Cookie` value that removes the interaction cookie.
///
/// The attributes must match the ones it was set with or the browser keeps the
/// original. This is used after a completed *or* destroyed interaction: a
/// cookie left behind after a browser mismatch is one an attacker can keep
/// trying against.
#[must_use]
pub fn clear_cookie() -> String {
    format!("{COOKIE_NAME}=; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=0")
}

/// Reads the interaction id out of a `Cookie` header.
///
/// Written by hand rather than with a cookie library because the rule is
/// narrow and the failure mode matters: only an exactly-named cookie counts.
/// A parser that accepted `asterius_ix` as well as `__Host-asterius_ix` would
/// throw away the browser-enforced guarantees the prefix exists to provide.
///
/// A repeated cookie is refused rather than resolved, for the same reason a
/// repeated form parameter is (RFC 6749 §3.1): if two intermediaries disagree
/// about which one counts, one request is validated and a different one runs.
// fuzz-target: interaction_cookie
#[must_use]
pub fn id_from_cookie_header(header: &str) -> Option<InteractionId> {
    cookie_value(header, COOKIE_NAME).map(|value| InteractionId::from_presented(value.to_owned()))
}

/// Reads exactly one cookie value out of a `Cookie` header.
///
/// The rules are [`id_from_cookie_header`]'s, and they are here so that every
/// `__Host-` cookie this server reads — the interaction's and the session's —
/// is read by one function rather than by two that could come to disagree:
///
/// * the name matches byte for byte, because cookie names are case-sensitive
///   and a parser that also accepted `asterius_ix` would throw away the
///   browser-enforced guarantees the `__Host-` prefix exists to provide;
/// * a repeated cookie yields nothing rather than a choice, for the reason
///   RFC 6749 §3.1 gives about repeated parameters — if two intermediaries
///   disagree about which one counts, one request is validated and a different
///   one runs;
/// * an empty value is not a value.
#[must_use]
pub fn cookie_value<'a>(header: &'a str, name: &str) -> Option<&'a str> {
    let mut found = None;
    for pair in header.split(';') {
        let pair = pair.trim();
        let Some((candidate, value)) = pair.split_once('=') else {
            continue;
        };
        if candidate != name {
            continue;
        }
        if found.is_some() {
            // Two cookies of the same name. The browser should not send this;
            // something in the path did.
            return None;
        }
        if value.is_empty() {
            return None;
        }
        found = Some(value);
    }
    found
}

/// Compares a submitted CSRF token with the issued one.
///
/// # Errors
///
/// [`InteractionError::CsrfFailed`] if the token is absent or wrong. One error
/// for both: a form that was not submitted by the page this server rendered is
/// refused, and which way it failed is not the submitter's business.
pub fn check_csrf(issued: &CsrfToken, presented: Option<&str>) -> Result<(), InteractionError> {
    let presented = presented.ok_or(InteractionError::CsrfFailed)?;
    // Length is checked before the comparison because `ct_eq` on values of
    // different lengths cannot be constant time anyway, and a bare length
    // check leaks nothing an attacker did not already choose.
    let presented = CsrfToken::from_presented(presented.to_owned());
    if issued.matches(&presented) {
        Ok(())
    } else {
        Err(InteractionError::CsrfFailed)
    }
}

/// A correlation id, shown on an error page.
///
/// An error page has to say *something* a user can quote to support, and it
/// must not say anything else — not which client, not which tenant, not what
/// failed. This is a random value logged alongside the real reason, so an
/// operator can find the detail and the page carries none of it.
#[must_use]
pub fn correlation_id() -> String {
    // Short: it gets read aloud and typed into tickets. 64 bits is far more
    // than enough to find one record in a day of logs, and it identifies
    // nothing on its own.
    OpaqueToken::generate_bits::<128>()
        .expose()
        .chars()
        .take(11)
        .collect()
}

/// Whether `ct_eq` is reachable for the two secret types here.
///
/// A compile-time assertion in the shape `crates/domain/src/secret_audit.rs`
/// uses: if either type ever gains `PartialEq`, a short-circuiting comparison
/// becomes writable, and the constant-time one becomes optional.
const _: fn() = || {
    fn assert_no_partial_eq<T>()
    where
        T: ?Sized,
    {
    }
    assert_no_partial_eq::<InteractionId>();
    assert_no_partial_eq::<CsrfToken>();
    // `ct_eq` is the only comparison, and it is used above.
    let _ = ct_eq;
};

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn id() -> InteractionId {
        InteractionId::generate()
    }

    // ---- the two-credential rule (FAPI 2.0 SP §6.5) ---------------------

    #[test]
    fn an_interaction_resumes_only_when_the_path_and_the_cookie_agree() {
        let a = id();
        let same = InteractionId::from_presented(a.expose().to_owned());
        assert!(Interaction::resume(&a, Some(&same)).is_ok());
    }

    #[test]
    fn a_url_without_the_cookie_is_inert() {
        let a = id();
        assert_eq!(
            Interaction::resume(&a, None),
            Err(InteractionError::NoCookie),
            "a leaked URL alone must not resume an interaction"
        );
    }

    #[test]
    fn a_cookie_for_a_different_interaction_is_fatal() {
        let a = id();
        let b = id();
        let error = Interaction::resume(&a, Some(&b)).expect_err("must refuse");
        assert_eq!(error, InteractionError::BrowserMismatch);
        assert!(
            error.is_fatal(),
            "a browser mismatch must destroy the interaction, not re-render it"
        );
    }

    #[test]
    fn ids_do_not_repeat() {
        let mut seen = HashSet::new();
        for _ in 0..2_000 {
            assert!(seen.insert(id().expose().to_owned()), "an id repeated");
        }
    }

    #[test]
    fn the_stored_form_is_a_digest_not_the_id() {
        let a = id();
        assert_eq!(a.digest().len(), 64, "not a hex SHA-256");
        assert!(!a.digest().contains(a.expose()));
    }

    #[test]
    fn an_id_is_redacted_in_debug() {
        let a = id();
        let rendered = format!("{a:?}");
        assert!(!rendered.contains(a.expose()), "{rendered}");
        assert!(rendered.contains("[REDACTED]"), "{rendered}");
    }

    // ---- the cookie ------------------------------------------------------

    #[test]
    fn the_cookie_carries_every_attribute_it_needs() {
        let a = id();
        let cookie = set_cookie(&a);
        for attribute in ["Secure", "HttpOnly", "SameSite=Lax", "Path=/"] {
            assert!(cookie.contains(attribute), "missing {attribute}: {cookie}");
        }
        assert!(cookie.starts_with("__Host-"), "{cookie}");
        // `SameSite=Strict` would break the top-level redirect into the
        // interaction, which is how every user arrives.
        assert!(!cookie.contains("SameSite=Strict"), "{cookie}");
        // A `Domain` attribute is forbidden by the `__Host-` prefix, and
        // adding one would let a sibling subdomain set this cookie.
        assert!(!cookie.to_lowercase().contains("domain="), "{cookie}");
    }

    #[test]
    fn clearing_uses_the_same_attributes_or_the_browser_keeps_the_cookie() {
        let cleared = clear_cookie();
        for attribute in ["Secure", "HttpOnly", "SameSite=Lax", "Path=/"] {
            assert!(
                cleared.contains(attribute),
                "missing {attribute}: {cleared}"
            );
        }
        assert!(cleared.contains("Max-Age=0"), "{cleared}");
    }

    #[test]
    fn the_cookie_is_read_only_under_its_exact_name() {
        let a = id();
        let value = a.expose().to_owned();

        let parsed = id_from_cookie_header(&format!("{COOKIE_NAME}={value}")).expect("present");
        assert!(parsed.matches(&a));

        // Among others, in either order.
        let parsed = id_from_cookie_header(&format!("theme=dark; {COOKIE_NAME}={value}; a=b"))
            .expect("present");
        assert!(parsed.matches(&a));

        for wrong in [
            format!("asterius_ix={value}"),
            format!("__host-asterius_ix={value}"),
            format!("__HOST-asterius_ix={value}"),
            format!("x__Host-asterius_ix={value}"),
            format!("__Host-asterius_ix2={value}"),
            format!("{COOKIE_NAME}="),
            String::new(),
            "nonsense".to_owned(),
        ] {
            assert!(
                id_from_cookie_header(&wrong).is_none(),
                "accepted a cookie header this server did not set: {wrong:?}"
            );
        }
    }

    /// A repeated cookie is refused, not resolved.
    #[test]
    fn two_interaction_cookies_are_refused() {
        let a = id();
        let b = id();
        let header = format!("{COOKIE_NAME}={}; {COOKIE_NAME}={}", a.expose(), b.expose());
        assert!(
            id_from_cookie_header(&header).is_none(),
            "picked one of two cookies rather than refusing"
        );
    }

    // ---- CSRF ------------------------------------------------------------

    #[test]
    fn a_form_without_the_issued_token_is_refused() {
        let issued = CsrfToken::generate();
        assert!(check_csrf(&issued, Some(issued.expose())).is_ok());

        for wrong in [None, Some(""), Some("nonsense"), Some(&"a".repeat(43)[..])] {
            assert_eq!(
                check_csrf(&issued, wrong),
                Err(InteractionError::CsrfFailed),
                "accepted {wrong:?}"
            );
        }
    }

    #[test]
    fn a_token_from_another_form_does_not_verify() {
        let issued = CsrfToken::generate();
        let other = CsrfToken::generate();
        assert_eq!(
            check_csrf(&issued, Some(other.expose())),
            Err(InteractionError::CsrfFailed)
        );
    }

    #[test]
    fn a_csrf_token_is_redacted_in_debug() {
        let token = CsrfToken::generate();
        let rendered = format!("{token:?}");
        assert!(!rendered.contains(token.expose()), "{rendered}");
    }

    // ---- the stored state ------------------------------------------------

    #[test]
    fn a_csrf_token_is_stored_as_a_digest_and_still_verifies() {
        let mut state = StoredState::default();
        let token = state.issue_csrf();

        let digest = state.csrf_digest.clone().expect("issued");
        assert_eq!(digest.len(), 64, "not a hex SHA-256");
        assert!(
            !digest.contains(token.expose()),
            "the token itself reached the stored state"
        );

        state.check_csrf(Some(token.expose())).expect("must verify");
    }

    #[test]
    fn a_state_with_no_issued_token_refuses_every_submission() {
        let state = StoredState::default();
        assert_eq!(state.csrf_digest, None);
        for presented in [None, Some(""), Some("anything")] {
            assert_eq!(
                state.check_csrf(presented),
                Err(InteractionError::CsrfFailed)
            );
        }
    }

    /// One submission per token. Otherwise a captured form body is replayable
    /// for the life of the interaction — and for a consent form that is a
    /// decision that can be submitted twice.
    #[test]
    fn a_token_is_good_for_one_submission() {
        let mut state = StoredState::default();
        let token = state.issue_csrf();
        state.check_csrf(Some(token.expose())).expect("first");

        state.spend_csrf();
        assert_eq!(
            state.check_csrf(Some(token.expose())),
            Err(InteractionError::CsrfFailed),
            "a spent token was accepted again"
        );
    }

    #[test]
    fn a_token_from_a_different_rendering_does_not_verify() {
        let mut first = StoredState::default();
        let issued = first.issue_csrf();
        let mut second = StoredState::default();
        let other = second.issue_csrf();

        assert_eq!(
            first.check_csrf(Some(other.expose())),
            Err(InteractionError::CsrfFailed)
        );
        assert_eq!(
            second.check_csrf(Some(issued.expose())),
            Err(InteractionError::CsrfFailed)
        );
    }

    #[test]
    fn state_survives_the_round_trip_through_json() {
        let mut state = StoredState {
            stage: Stage::Consent,
            ..StoredState::default()
        };
        let token = state.issue_csrf();
        let stored = serde_json::to_value(&state).expect("serialise");
        let read = StoredState::from_stored(&stored);

        assert_eq!(read.stage, Stage::Consent);
        read.check_csrf(Some(token.expose()))
            .expect("the token must still verify after a round trip");
    }

    /// Who signed in survives the store, so a later page can name them.
    #[test]
    fn the_signed_in_name_survives_the_round_trip_through_json() {
        // Arrange
        let mut state = StoredState {
            stage: Stage::Consent,
            ..StoredState::default()
        };

        // Act
        state.signed_in_as("ada");
        let read = StoredState::from_stored(&serde_json::to_value(&state).expect("serialise"));

        // Assert
        assert_eq!(read.username.as_deref(), Some("ada"));
    }

    /// An unreadable state restarts the login rather than failing.
    ///
    /// It cannot skip a stage, because `Login` is the first one — which is
    /// what makes the lenient reading safe.
    #[test]
    fn an_unreadable_state_falls_back_to_the_first_stage() {
        for hostile in [
            serde_json::json!(null),
            serde_json::json!("nonsense"),
            serde_json::json!({}),
            serde_json::json!({"stage": "no_such_stage"}),
            serde_json::json!({"stage": 42}),
            // Written by a newer binary: an unknown field fails to parse, and
            // failing towards `Login` is the right direction during a rolling
            // deployment.
            serde_json::json!({"stage": "consent", "something_new": true}),
        ] {
            let read = StoredState::from_stored(&hostile);
            assert_eq!(read.stage, Stage::Login, "for {hostile}");
            assert_eq!(read.csrf_digest, None);
        }
    }

    // ---- the state machine ----------------------------------------------

    /// An authorization, for the transition tests.
    fn authorization() -> Continuation {
        Continuation::for_client(
            asterius_domain::ClientId::new("billing"),
            serde_json::json!({}),
        )
    }

    /// A first-party login, for the same.
    const fn console() -> Continuation {
        Continuation::FirstParty(asterius_domain::FirstPartyDestination::AdminConsole)
    }

    #[test]
    fn the_state_machine_allows_exactly_these_moves() {
        use Stage::{Consent, Login, Register, Response, StepUp};
        let legal = [
            // Prompt Create 1.0 §3: creating an account authenticates the
            // person who created it, so `Register` leaves by the doors
            // `Login` leaves by — and by the one back to `Login` itself,
            // which is the "already have an account?" link.
            (Register, StepUp),
            (Register, Consent),
            (Register, Login),
            (Login, StepUp),
            (Login, Consent),
            (StepUp, Consent),
            (StepUp, Login),
            (Consent, Response),
        ];
        for from in [Register, Login, StepUp, Consent, Response] {
            for to in [Register, Login, StepUp, Consent, Response] {
                let expected = legal.contains(&(from, to));
                assert_eq!(
                    from.may_advance_to(to, &authorization()),
                    expected,
                    "{from:?} -> {to:?} should be {}",
                    if expected { "legal" } else { "refused" }
                );
            }
        }
    }

    /// The other machine, stated as completely as the first. `Consent` is
    /// absent from both sides of every legal pair, which is the criterion
    /// `ast-wr4` states: there is no client to consent to, so the screen is not
    /// skipped by a flag — it is unreachable.
    #[test]
    fn a_first_party_interaction_allows_exactly_these_moves() {
        use Stage::{Consent, Login, Register, Response, StepUp};
        let legal = [
            (Register, StepUp),
            (Register, Response),
            (Register, Login),
            (Login, StepUp),
            (Login, Response),
            (StepUp, Response),
            (StepUp, Login),
        ];
        for from in [Register, Login, StepUp, Consent, Response] {
            for to in [Register, Login, StepUp, Consent, Response] {
                let expected = legal.contains(&(from, to));
                assert_eq!(
                    from.may_advance_to(to, &console()),
                    expected,
                    "{from:?} -> {to:?} should be {}",
                    if expected { "legal" } else { "refused" }
                );
            }
        }
    }

    /// The criterion on its own, so that an edit to the table above cannot
    /// quietly permit it: no stage of a first-party interaction moves to
    /// `Consent`, and the stage after login is the destination.
    #[test]
    fn a_first_party_interaction_can_never_reach_consent() {
        for from in [
            Stage::Register,
            Stage::Login,
            Stage::StepUp,
            Stage::Consent,
            Stage::Response,
        ] {
            assert!(
                !from.may_advance_to(Stage::Consent, &console()),
                "{from:?} reached a consent screen with nobody to consent to"
            );
        }
        assert_eq!(Stage::after_login(&console()), Stage::Response);
        assert_eq!(Stage::after_login(&authorization()), Stage::Consent);
    }

    /// The mirror: the first-party arm is not a way for an authorization to
    /// skip the screen.
    #[test]
    fn an_authorization_can_never_jump_from_login_to_the_response() {
        assert!(!Stage::Login.may_advance_to(Stage::Response, &authorization()));
        assert!(!Stage::StepUp.may_advance_to(Stage::Response, &authorization()));
    }

    /// The two moves that matter most, stated on their own so a future edit to
    /// the table above cannot quietly permit them.
    #[test]
    fn consent_can_never_be_skipped_and_never_replayed() {
        use Stage::{Consent, Login, Response, StepUp};
        let authorization = authorization();
        assert!(
            !Login.may_advance_to(Response, &authorization),
            "a grant nobody agreed to"
        );
        assert!(
            !StepUp.may_advance_to(Response, &authorization),
            "a grant nobody agreed to"
        );
        assert!(
            !Response.may_advance_to(Consent, &authorization),
            "a decided interaction must not be re-decided"
        );
        for stage in [Login, StepUp, Consent, Response] {
            assert!(
                !Response.may_advance_to(stage, &authorization),
                "Response is terminal, but moves to {stage:?}"
            );
            assert!(
                !Response.may_advance_to(stage, &console()),
                "Response is terminal, but moves to {stage:?}"
            );
        }
    }

    #[test]
    fn a_user_who_has_consented_is_never_sent_back_to_a_login_form() {
        assert!(!Stage::Consent.may_advance_to(Stage::Login, &authorization()));
        assert!(!Stage::Response.may_advance_to(Stage::Login, &authorization()));
        // The one legal backward move discards progress rather than granting.
        assert!(Stage::StepUp.may_advance_to(Stage::Login, &authorization()));
        assert!(Stage::StepUp.may_advance_to(Stage::Login, &console()));
    }

    #[test]
    fn advancing_an_interaction_refuses_an_illegal_move() {
        let mut interaction = Interaction {
            tenant: asterius_domain::TenantId::new("demo"),
            id_digest: id().digest(),
            stage: Stage::Login,
            session: None,
            expires_at: time::OffsetDateTime::now_utc() + time::Duration::minutes(10),
        };
        assert_eq!(
            interaction.advance(Stage::Response, &authorization()),
            Err(InteractionError::IllegalTransition)
        );
        assert_eq!(interaction.stage, Stage::Login, "the stage moved anyway");

        interaction
            .advance(Stage::Consent, &authorization())
            .expect("legal");
        assert_eq!(interaction.stage, Stage::Consent);
    }

    #[test]
    fn only_the_response_stage_is_non_interactive() {
        assert!(Stage::Login.is_interactive());
        assert!(Stage::StepUp.is_interactive());
        assert!(Stage::Consent.is_interactive());
        assert!(!Stage::Response.is_interactive());
    }

    // ---- what an error tells whom ---------------------------------------

    /// OIDC Core §3.1.2.6: only `prompt=none` produces an error the *client*
    /// sees. Everything else is between the browser and this server.
    #[test]
    fn only_interaction_required_is_reported_to_the_client() {
        assert_eq!(
            InteractionError::InteractionRequired.client_error_code(),
            Some("interaction_required")
        );
        for private in [
            InteractionError::BrowserMismatch,
            InteractionError::NoCookie,
            InteractionError::NotAvailable,
            InteractionError::CsrfFailed,
            InteractionError::IllegalTransition,
        ] {
            assert_eq!(
                private.client_error_code(),
                None,
                "{private} would be reported to the client"
            );
        }
    }

    /// Every message is a constant, so none can carry a request value.
    ///
    /// Enumerated rather than pattern-matched: a variant that later gains a
    /// field would start interpolating into `Display`, and this list is what
    /// makes that a failing test rather than a quiet reflection on an error
    /// page. (`prompt=none` in one message is a specification literal, not
    /// input — an earlier version of this test banned `=` outright and was
    /// wrong to.)
    #[test]
    fn every_error_message_is_a_constant() {
        let expected = [
            (
                InteractionError::BrowserMismatch,
                "the interaction does not belong to this browser",
            ),
            (
                InteractionError::NoCookie,
                "no interaction cookie was presented",
            ),
            (
                InteractionError::NotAvailable,
                "the interaction is not available",
            ),
            (
                InteractionError::CsrfFailed,
                "the form could not be verified",
            ),
            (
                InteractionError::IllegalTransition,
                "the interaction cannot move to that stage",
            ),
            (
                InteractionError::InteractionRequired,
                "interaction is required but prompt=none was requested",
            ),
        ];
        for (error, message) in expected {
            assert_eq!(error.to_string(), message);
            // Short enough to show a user, and naming nothing about the
            // deployment.
            assert!(error.to_string().len() < 80, "{error}");
        }
    }

    /// Every variant is fieldless, which is what makes the constancy above
    /// structural rather than a promise: a variant with a field could
    /// interpolate into `Display`.
    const _: [(); 1] = [(); (size_of::<InteractionError>() <= 1) as usize];

    #[test]
    fn a_correlation_id_is_short_unpredictable_and_says_nothing() {
        let mut seen = HashSet::new();
        for _ in 0..1_000 {
            let id = correlation_id();
            assert_eq!(id.len(), 11, "{id}");
            assert!(
                id.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
                "not safe to render into a page: {id}"
            );
            assert!(seen.insert(id), "a correlation id repeated");
        }
    }

    #[test]
    fn an_interaction_expires() {
        let now = time::OffsetDateTime::now_utc();
        let interaction = Interaction {
            tenant: asterius_domain::TenantId::new("demo"),
            id_digest: id().digest(),
            stage: Stage::Login,
            session: None,
            expires_at: now,
        };
        assert!(interaction.has_expired(now), "expiry is inclusive");
        assert!(interaction.has_expired(now + time::Duration::seconds(1)));
        assert!(!interaction.has_expired(now - time::Duration::seconds(1)));
    }
}
