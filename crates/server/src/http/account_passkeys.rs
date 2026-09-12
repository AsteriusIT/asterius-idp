//! The passkey list, and the two things its owner may do to a credential
//! (`ast-1xd`).
//!
//! Three routes, the shape [`crate::http::account_grants`] settled on because
//! it is the same kind of page — a first-party account page reached with a
//! session cookie, with no client anywhere near it:
//!
//! * `GET /account/passkeys` lists what this person can sign in with;
//! * `POST /account/passkeys` renames one or removes one;
//! * `GET /account/passkeys/sign-in` opens a fresh authentication for a
//!   session too old to change a credential with.
//!
//! # A credential with no name
//!
//! WebAuthn L3 §6.1 gives a credential no name of its own. The `label` column
//! exists and is null for every passkey enrolled before this page did, so a
//! list straight out of the database is four rows that all say the same
//! nothing — and the one irreversible button on the page is beside each of
//! them. So a row with no label is *named* rather than left blank: the day it
//! was registered, with the AAGUID the authenticator reported beside it
//! (§6.4.1). Both are facts this server recorded; neither is a guess at a
//! product name, because this deployment ships no FIDO metadata service.
//!
//! # Removing the last passkey
//!
//! Every button here needs an authentication from the last
//! [`crate::http::account::FRESHNESS`]. Removing the *last usable* passkey
//! needs the account's password as well, and that is the one place these pages
//! ask for a second factor of the same act:
//!
//! * a session somebody walked away from is enough to rename a credential and
//!   to remove one of several — annoying, recoverable;
//! * a session somebody walked away from must not be enough to remove the last
//!   one, because that is the credential its owner would use to come back, and
//!   an attacker who has both the session and the ability to set a password
//!   afterwards has taken the account.
//!
//! An account with no password at all cannot remove its last passkey: the page
//! offers [`crate::http::account_password`] instead of a button that could only
//! refuse. Leaving somebody with no credential is not a state this server will
//! write, whatever they press.
//!
//! # Nothing here distinguishes its failures
//!
//! A credential that belongs to somebody else, one already removed, one that
//! never existed, a body this server would not read: one sentence for all four
//! ([`asterius_web::i18n::MessageKey::PasskeysGone`]). The reasoning is Grant
//! Management ID1 §6.6's, which this server already applies at its API — a
//! distinction is an oracle over identifiers nobody is meant to enumerate.
//!
//! # What a change is reported as
//!
//! The audit trail gets [`EventType::CREDENTIAL_CHANGED`], the event the
//! recovery path and the admin API already write, with a `reason` label saying
//! this door. The receivers get CAEP `credential-change` (`ast-0ju.8`) —
//! `delete` for a removal, `update` for a rename — through
//! [`crate::http::account::emit_signal`], which is the same transmitter the
//! console's own removal goes through.

use asterius_domain::audit::{Actor, AuditEvent, AuditSink, Detail, EventType, Outcome};
use asterius_domain::{
    FirstPartyDestination, PasskeySummary, Session, SessionId as DomainSessionId, UserId,
};
use asterius_store_pg::{PgPasskeyRepository, PgPasswordVerifier};
use asterius_web::Brand;
use asterius_web::Document;
use asterius_web::pages::{self, PasskeyLine, PasskeysPage, nonce_attribute};
use axum::body::Bytes;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use time::OffsetDateTime;

use crate::http::account::{
    self, AccountContext, MAX_BODY, MAX_CSRF_CHARS, Signals, begin, checked_csrf, csrf_for,
    error_page, fresh, no_store, stamp,
};

/// Where the list lives, and where its submissions post.
pub const PAGE_PATH: &str = "/account/passkeys";

/// Where a person goes to authenticate again.
pub const SIGN_IN_PATH: &str = "/account/passkeys/sign-in";

/// This page's CSRF separator.
const CSRF_SEPARATOR: &str = "account-passkeys-csrf";

/// The longest label this page will store.
///
/// Sixty-four characters, which is the `maxlength` the field carries. The
/// column itself is unbounded `text`, so this is the bound — a name is a word
/// or two on a screen, and a person who pastes a novel into it would be
/// choosing the size of every future rendering of this page.
pub const MAX_LABEL_CHARS: usize = 64;

/// The length of the one identifier this form carries.
///
/// A hyphenated UUID (RFC 9562 §4): `8-4-4-4-12`.
const CREDENTIAL_ID_CHARS: usize = 36;

/// The longest password this parser will carry.
///
/// [`asterius_domain::entities::password::MAX_LENGTH`], because a longer one
/// could never match a stored hash: what is bounded here is what the parser
/// allocates, and the policy is what decides whether it is a password.
const MAX_PASSWORD_CHARS: usize = asterius_domain::entities::password::MAX_LENGTH;

/// What a submission asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verb {
    /// Give this credential a name, or take the one it has away.
    Rename,
    /// Remove it: `credentials.disabled_at` is stamped and the passkey stops
    /// being something anybody can sign in with.
    Remove,
}

/// A submission from this page, after parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    /// The synchroniser token the form carried.
    pub csrf: String,
    /// Which credential, as a hyphenated lower-case UUID.
    pub credential: String,
    /// Which verb the pressed button named.
    pub verb: Verb,
    /// The label, as typed. Empty means "take the name away", which is a thing
    /// somebody may deliberately do and is not the same as not submitting the
    /// field.
    pub label: String,
    /// The password, where the form asked for one.
    pub password: Option<String>,
}

/// Reads a submission from this page, or refuses it.
///
/// Every refusal is `None`, because the caller answers all of them with one
/// page: a body that is too large, that is not UTF-8, that names a parameter
/// twice (RFC 6749 §3.1's parameter pollution, applied to this server's own
/// forms for the reason the token endpoint applies it to a client's), that
/// carries an identifier which is not the spelling this server writes, that
/// names no verb or a verb this page does not have, or that carries a label
/// longer than the field's `maxlength`.
///
/// The identifier is checked for *shape* here and for *ownership* in the
/// statement that acts on it: this function cannot know whose credential it
/// is, and a validator that pretended to would be the one place somebody later
/// trusted instead of the predicate.
///
/// A label is *not* sanitised here beyond its length. It is text a person
/// chose, it is escaped by the template like every other value, and a parser
/// that started removing characters from it would be the one place a reviewer
/// later believed the escaping had already happened.
// fuzz-target: account_passkey_change
#[must_use]
pub fn change(body: &[u8]) -> Option<Change> {
    if body.len() > MAX_BODY {
        return None;
    }
    let text = std::str::from_utf8(body).ok()?;

    let mut csrf: Option<String> = None;
    let mut credential: Option<String> = None;
    let mut verb: Option<Verb> = None;
    let mut label: Option<String> = None;
    let mut password: Option<String> = None;
    for (key, value) in url::form_urlencoded::parse(text.as_bytes()) {
        // A repeated parameter is refused outright rather than resolved to the
        // first or the last. Both resolutions are a choice an attacker can
        // exploit once anything downstream makes the other one — and here one
        // of them decides whether a credential is renamed or removed.
        match key.as_ref() {
            "csrf" if csrf.is_some() => return None,
            "csrf" => csrf = Some(value.into_owned()),
            "credential" if credential.is_some() => return None,
            "credential" => credential = Some(value.into_owned()),
            "label" if label.is_some() => return None,
            "label" => label = Some(value.into_owned()),
            "password" if password.is_some() => return None,
            "password" => password = Some(value.into_owned()),
            "do" if verb.is_some() => return None,
            "do" => {
                verb = Some(match value.as_ref() {
                    "rename" => Verb::Rename,
                    "remove" => Verb::Remove,
                    _ => return None,
                });
            }
            _ => {}
        }
    }

    let csrf = csrf?;
    let credential = credential?;
    if csrf.is_empty() || csrf.chars().count() > MAX_CSRF_CHARS {
        return None;
    }
    if !is_credential_id(&credential) {
        return None;
    }
    let label = label.unwrap_or_default();
    if label.chars().count() > MAX_LABEL_CHARS {
        return None;
    }
    if password
        .as_ref()
        .is_some_and(|password| password.chars().count() > MAX_PASSWORD_CHARS)
    {
        return None;
    }
    Some(Change {
        csrf,
        credential,
        verb: verb?,
        label,
        password,
    })
}

/// Whether this is the spelling of a credential id this server writes.
///
/// Thirty-six characters: lower-case hex with hyphens at the four positions
/// RFC 9562 §4 puts them. Checked before the store is asked, so a submission
/// that could not name a row costs a comparison rather than a query. Strict
/// about case, unlike `Uuid::parse_str`, for the reason
/// [`crate::http::account_grants`] gives about its own identifier.
fn is_credential_id(value: &str) -> bool {
    if value.len() != CREDENTIAL_ID_CHARS {
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

/// What this page needs beyond [`AccountContext`].
pub struct PasskeysContext<'a> {
    /// Admission, freshness, the sign-in and the chrome.
    pub account: AccountContext<'a>,
    /// This person's credentials, and the two writes this page makes.
    pub passkeys: &'a PgPasskeyRepository,
    /// Whether the account has a password, and whether a submitted one
    /// matches. `None` in a deployment with no password method configured, in
    /// which case the last passkey cannot be removed at all.
    pub passwords: Option<&'a PgPasswordVerifier>,
    /// Where the signed-in account's username is read.
    ///
    /// Needed because [`asterius_domain::CredentialVerifier`] is keyed by
    /// username — it is the login path's port, and the login path has a name
    /// and not an id. Resolving the id this session already carries is what
    /// lets the last-passkey check go through that one verifier rather than a
    /// second idea of what checking a password means.
    pub users: &'a dyn asterius_domain::UserDirectory,
    /// The trail. A credential change is recorded whether or not anybody polls
    /// it.
    pub audit: &'a dyn AuditSink,
    /// The receivers that asked to be told (`ast-0ju.8`).
    pub signals: Signals<'a>,
}

impl std::fmt::Debug for PasskeysContext<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasskeysContext").finish_non_exhaustive()
    }
}

/// `GET /account/passkeys` — what this person can sign in with.
pub async fn page(
    context: &PasskeysContext<'_>,
    headers: &HeaderMap,
    now: OffsetDateTime,
) -> Response {
    let Some(session) = account::admitted(&context.account, headers, now).await else {
        return begin(
            &context.account,
            FirstPartyDestination::AccountPasskeys,
            now,
        )
        .await;
    };
    rendered(context, &session, None, StatusCode::OK, now).await
}

/// `GET /account/passkeys/sign-in` — authenticate again, and come back.
///
/// A route rather than a link into the interaction pages, for the reason the
/// inbox gives: the interaction has to be *opened*, and its destination is a
/// variant of a closed enumeration rather than a URL anybody can supply
/// (ADR-0009).
pub async fn sign_in(context: &PasskeysContext<'_>, now: OffsetDateTime) -> Response {
    begin(
        &context.account,
        FirstPartyDestination::AccountPasskeys,
        now,
    )
    .await
}

/// `POST /account/passkeys` — rename one credential, or remove one.
pub async fn submit(
    context: &PasskeysContext<'_>,
    headers: &HeaderMap,
    body: &Bytes,
    now: OffsetDateTime,
) -> Response {
    let Some(session) = account::admitted(&context.account, headers, now).await else {
        return begin(
            &context.account,
            FirstPartyDestination::AccountPasskeys,
            now,
        )
        .await;
    };
    let Some(form) = change(body) else {
        return refused(context, &session, now).await;
    };
    if !checked_csrf(&session, CSRF_SEPARATOR, &form.csrf) {
        return refused(context, &session, now).await;
    }
    // Freshness before the row is read, because it is a fact about the
    // *person*: a session too old to change a credential with is too old to
    // change any of them, and deciding it first means a stale session learns
    // nothing about whether the id it submitted names a row.
    if !fresh(&session, now) {
        return begin(
            &context.account,
            FirstPartyDestination::AccountPasskeys,
            now,
        )
        .await;
    }

    let Ok(credential) = uuid::Uuid::parse_str(&form.credential) else {
        // Unreachable: the parser has already held the value to the spelling
        // this server writes. Answered as a credential that is not there
        // rather than as an error, because that is what it would be.
        return gone(context, &session, now).await;
    };

    match form.verb {
        Verb::Rename => renamed(context, &session, credential, &form.label, now).await,
        Verb::Remove => removed(context, &session, credential, form.password.as_deref(), now).await,
    }
}

/// Gives a credential a name, or takes the one it has away.
///
/// The safe direction: it changes what a page says and nothing about what
/// anybody can sign in with. It still needs the fresh authentication, because
/// a name is how its owner decides which row to remove, and an attacker who
/// could rename could make somebody remove the wrong one.
async fn renamed(
    context: &PasskeysContext<'_>,
    session: &Session,
    credential: uuid::Uuid,
    label: &str,
    now: OffsetDateTime,
) -> Response {
    let user = UserId::new(session.user);
    // An empty field is "take the name away", which is a null column and not
    // an empty string: the list's derived name is what a row with no label
    // gets, and an empty string would render as a blank line instead.
    let trimmed = label.trim();
    let stored = (!trimmed.is_empty()).then_some(trimmed);

    match context
        .passkeys
        .rename_for_user(&user, credential, stored)
        .await
    {
        Ok(Some(renamed)) => {
            record(
                context,
                session,
                credential,
                "renamed",
                Some(renamed.label.as_deref().unwrap_or_default()),
                now,
            )
            .await;
            // CAEP §3.3 `update`: the credential is still there and something
            // about it changed. A receiver that shows a person their
            // credentials elsewhere wants the new name.
            let mut change = asterius_ssf::caep::CredentialChange::new(
                asterius_ssf::caep::CredentialType::fido2(None, renamed.backup_eligible),
                asterius_ssf::caep::ChangeType::Update,
            );
            if let Some(aaguid) = renamed.aaguid {
                change = change.fido2_aaguid(aaguid);
            }
            if let Some(label) = renamed.label.as_deref()
                && let Ok(named) = change.clone().friendly_name(label)
            {
                change = named;
            }
            account::emit_signal(
                &context.account,
                &context.signals,
                &crate::ssf::Cause::CredentialChange {
                    user,
                    change,
                    initiator: asterius_ssf::caep::InitiatingEntity::User,
                },
                now,
            )
            .await;
            rendered(
                context,
                session,
                Some(context.account.text.passkeys_renamed()),
                StatusCode::OK,
                now,
            )
            .await
        }
        // Somebody else's credential and no such credential are one answer.
        Ok(None) => gone(context, session, now).await,
        Err(error) => {
            tracing::error!(%error, tenant = %context.account.tenant.id, "cannot rename a passkey");
            error_page(&context.account, StatusCode::SERVICE_UNAVAILABLE)
        }
    }
}

/// Removes a credential, if this account may be left without it.
///
/// The order matters and is the reason this is one function. The list is read
/// *before* anything is written, because "is this the last one" is a question
/// about the set and not about the row; the password is checked before the
/// write for the same reason a login checks it before issuing a session; and
/// the removal itself is one `update ... returning`, so two tabs racing on the
/// same button produce one removal and one "no longer there".
async fn removed(
    context: &PasskeysContext<'_>,
    session: &Session,
    credential: uuid::Uuid,
    password: Option<&str>,
    now: OffsetDateTime,
) -> Response {
    let user = UserId::new(session.user);
    let held = match context.passkeys.summaries_for_user(&user).await {
        Ok(held) => held,
        Err(error) => {
            tracing::error!(%error, tenant = %context.account.tenant.id, "cannot list passkeys");
            return error_page(&context.account, StatusCode::SERVICE_UNAVAILABLE);
        }
    };
    // A credential this account does not hold is answered as one that is not
    // there — before the last-passkey arithmetic, so somebody guessing ids
    // cannot learn how many credentials an account has from which sentence
    // comes back.
    if !held.iter().any(|passkey| passkey.id == credential) {
        return gone(context, session, now).await;
    }

    if is_last_usable(&held, credential) {
        let Ok(has_password) = self::has_password(context, &user).await else {
            return error_page(&context.account, StatusCode::SERVICE_UNAVAILABLE);
        };
        if !has_password {
            // Nothing would be left to sign in with. Refused rather than
            // written: this server does not create accounts nobody can reach,
            // and the page offers the password form instead.
            return message(
                context,
                session,
                context.account.text.passkeys_last_without_password(),
                StatusCode::CONFLICT,
                now,
            )
            .await;
        }
        if !self::password_matches(context, &user, password).await {
            record_refusal(context, session, credential, now).await;
            return message(
                context,
                session,
                context.account.text.passkeys_wrong_password(),
                StatusCode::FORBIDDEN,
                now,
            )
            .await;
        }
    }

    match context
        .passkeys
        .disable_for_user(&user, credential, now)
        .await
    {
        Ok(Some(removed)) => {
            record(context, session, credential, "removed", None, now).await;
            // CAEP §3.3 `delete`: `fido2-platform` or `fido2-roaming` from what
            // WebAuthn recorded, the friendly name where the person gave one —
            // no key material, which a receiver has no use for and this server
            // never puts on the wire.
            let mut change = asterius_ssf::caep::CredentialChange::new(
                asterius_ssf::caep::CredentialType::fido2(None, removed.backup_eligible),
                asterius_ssf::caep::ChangeType::Delete,
            );
            if let Some(aaguid) = removed.aaguid {
                change = change.fido2_aaguid(aaguid);
            }
            if let Some(label) = removed.label.as_deref()
                && let Ok(named) = change.clone().friendly_name(label)
            {
                change = named;
            }
            account::emit_signal(
                &context.account,
                &context.signals,
                &crate::ssf::Cause::CredentialChange {
                    user,
                    change,
                    initiator: asterius_ssf::caep::InitiatingEntity::User,
                },
                now,
            )
            .await;
            rendered(
                context,
                session,
                Some(context.account.text.passkeys_removed()),
                StatusCode::OK,
                now,
            )
            .await
        }
        // Removed between the read and this write — a second tab, a
        // double-pressed button, or a credential that was already blocked.
        Ok(None) => gone(context, session, now).await,
        Err(error) => {
            tracing::error!(%error, tenant = %context.account.tenant.id, "cannot remove a passkey");
            error_page(&context.account, StatusCode::SERVICE_UNAVAILABLE)
        }
    }
}

/// Whether `credential` is the only one of these an account could sign in with.
///
/// A blocked credential does not count: it cannot be presented, so an account
/// whose other three passkeys are all disabled has exactly one way in and this
/// is it. That is the case the rule exists for.
#[must_use]
pub fn is_last_usable(held: &[PasskeySummary], credential: uuid::Uuid) -> bool {
    let usable = held
        .iter()
        .filter(|passkey| passkey.disabled_at.is_none())
        .count();
    let removing_a_usable_one = held
        .iter()
        .any(|passkey| passkey.id == credential && passkey.disabled_at.is_none());
    removing_a_usable_one && usable <= 1
}

/// Whether this account has a password it could sign in with.
///
/// `Err(())` is a read that failed, which the caller answers with the error
/// page: reporting "no password" would refuse a removal that should be
/// allowed, and reporting "has one" would then ask for a password nothing can
/// check.
async fn has_password(context: &PasskeysContext<'_>, user: &UserId) -> Result<bool, ()> {
    let Some(passwords) = context.passwords else {
        return Ok(false);
    };
    match passwords.has_password(*user.as_uuid()).await {
        Ok(has_password) => Ok(has_password),
        Err(error) => {
            tracing::error!(%error, tenant = %context.account.tenant.id, "cannot read a password credential");
            Err(())
        }
    }
}

/// Whether the submitted password is this account's.
///
/// A missing field and a wrong one are one answer, and both are `false`: the
/// page cannot tell somebody which of the two they did, because the difference
/// is only interesting to somebody who is guessing.
async fn password_matches(
    context: &PasskeysContext<'_>,
    user: &UserId,
    password: Option<&str>,
) -> bool {
    let (Some(passwords), Some(password)) = (context.passwords, password) else {
        return false;
    };
    if password.is_empty() {
        return false;
    }
    let username = match context.users.by_id(*user).await {
        Ok(Some(account)) => account.username,
        Ok(None) => return false,
        Err(error) => {
            tracing::error!(%error, tenant = %context.account.tenant.id, "cannot read an account");
            return false;
        }
    };
    match asterius_domain::CredentialVerifier::verify(
        passwords,
        &username,
        asterius_domain::Secret::new(password.to_owned()),
    )
    .await
    {
        // The verifier answers with the account the credential belongs to, and
        // it has to be *this* account: a password that matched somebody else's
        // hash is not this person proving anything.
        Ok(Some(verified)) => verified == *user.as_uuid(),
        Ok(None) => false,
        Err(error) => {
            tracing::error!(%error, tenant = %context.account.tenant.id, "cannot verify a password");
            false
        }
    }
}

/// The page, with whatever there is to say on it.
async fn rendered(
    context: &PasskeysContext<'_>,
    session: &Session,
    message: Option<&str>,
    status: StatusCode,
    now: OffsetDateTime,
) -> Response {
    let user = UserId::new(session.user);
    let held = match context.passkeys.summaries_for_user(&user).await {
        Ok(held) => held,
        Err(error) => {
            tracing::error!(%error, tenant = %context.account.tenant.id, "cannot list passkeys");
            return error_page(&context.account, StatusCode::SERVICE_UNAVAILABLE);
        }
    };
    let has_password = self::has_password(context, &user).await.unwrap_or(false);
    let passkeys: Vec<PasskeyLine> = held
        .iter()
        .map(|passkey| line(context, passkey, &held, has_password))
        .collect();

    // A stale session is shown the page and told to sign in again rather than
    // being redirected out of it: the redirect belongs to the moment somebody
    // presses a button, not to the moment they read the list.
    let message = match message {
        Some(message) => Some(message),
        None if !fresh(session, now) && !passkeys.is_empty() => {
            Some(context.account.text.passkeys_stale())
        }
        None => None,
    };

    let font_url = crate::http::font_url(&context.account.mount);
    let action = context.account.mount.absolute(PAGE_PATH);
    let sign_in_href = context.account.mount.absolute(SIGN_IN_PATH);
    let account_href = context.account.mount.absolute(account::PAGE_PATH);
    let password_href = context
        .account
        .mount
        .absolute(crate::http::account_password::PAGE_PATH);
    let csrf = csrf_for(session, CSRF_SEPARATOR);
    let document = Document::render(context.account.nonce, |nonce| {
        pages::render(&PasskeysPage {
            text: context.account.text,
            tenant_name: &context.account.tenant.display_name,
            passkeys: passkeys.clone(),
            action: &action,
            sign_in_href: &sign_in_href,
            account_href: &account_href,
            password_href: &password_href,
            csrf: &csrf,
            maximum_label_length: MAX_LABEL_CHARS,
            message,
            nonce_attribute: nonce_attribute(nonce),
            theme_css: "",
            brand: Brand::new(&font_url),
        })
    });
    (status, no_store(), document).into_response()
}

/// One row of the list.
fn line(
    context: &PasskeysContext<'_>,
    passkey: &PasskeySummary,
    held: &[PasskeySummary],
    has_password: bool,
) -> PasskeyLine {
    let registered_at = stamp(passkey.created_at);
    let last = is_last_usable(held, passkey.id);
    PasskeyLine {
        reference: passkey.id.to_string(),
        name: passkey
            .label
            .clone()
            .unwrap_or_else(|| context.account.text.passkeys_unnamed(&registered_at)),
        label: passkey.label.clone().unwrap_or_default(),
        registered_at,
        last_used: passkey.last_used_at.map(stamp),
        model: passkey.aaguid.map(|aaguid| aaguid.to_string()),
        blocked: passkey.disabled_at.is_some(),
        needs_password: last && has_password,
        // The removal button is not offered for a last passkey nobody could
        // sign in without. The handler refuses it as well — a page that only
        // hid the button would be a rule enforced in markup.
        removable: !last || has_password,
    }
}

/// The page a submission this server would not read produces.
async fn refused(
    context: &PasskeysContext<'_>,
    session: &Session,
    now: OffsetDateTime,
) -> Response {
    message(
        context,
        session,
        context.account.text.passkeys_gone(),
        StatusCode::BAD_REQUEST,
        now,
    )
    .await
}

/// The page a change to something that is not there produces.
async fn gone(context: &PasskeysContext<'_>, session: &Session, now: OffsetDateTime) -> Response {
    message(
        context,
        session,
        context.account.text.passkeys_gone(),
        StatusCode::CONFLICT,
        now,
    )
    .await
}

/// The list again, with one sentence on it.
async fn message(
    context: &PasskeysContext<'_>,
    session: &Session,
    sentence: &str,
    status: StatusCode,
    now: OffsetDateTime,
) -> Response {
    rendered(context, session, Some(sentence), status, now).await
}

/// Records a change to a credential.
///
/// [`EventType::CREDENTIAL_CHANGED`], the event the recovery path and the
/// admin API already write, because it is the same fact: a credential moved.
/// What differs is the actor — the person themselves, at this server's own
/// page — and the `reason` label, which is how a reader tells the doors apart.
///
/// The credential is named by its row id through [`Detail::credential`], which
/// is how every other record in this server names one.
async fn record(
    context: &PasskeysContext<'_>,
    session: &Session,
    credential: uuid::Uuid,
    what: &'static str,
    label: Option<&str>,
    now: OffsetDateTime,
) {
    let subject = session.user.to_string();
    let mut detail = Detail::new()
        .label("kind", "passkey")
        .label("reason", "account_passkeys_page")
        .label("change", what)
        .credential("credential_id", credential.to_string());
    // Whether a name was given or taken away, and never the name itself: a
    // label is text a person wrote about themselves, and the trail records
    // that it changed rather than what it says.
    if let Some(label) = label {
        detail = detail.label("named", if label.is_empty() { "no" } else { "yes" });
    }
    let event = AuditEvent::new(
        context.account.tenant.id.clone(),
        EventType::CREDENTIAL_CHANGED,
        Outcome::Success,
        Actor::User(subject.clone()),
        now,
    )
    .session(DomainSessionId::new(session.id_digest.clone()))
    .subject(subject)
    .detail(detail);

    if let Err(error) = context.audit.record(event).await {
        tracing::error!(
            %error,
            tenant = %context.account.tenant.id,
            "a passkey change was not written to the audit trail"
        );
    }
}

/// Records a removal that was refused for want of the password.
///
/// A failure record rather than silence: somebody trying passwords against the
/// last-passkey field is somebody trying passwords, and it is the one attempt
/// on these pages that an incident review would want to count.
async fn record_refusal(
    context: &PasskeysContext<'_>,
    session: &Session,
    credential: uuid::Uuid,
    now: OffsetDateTime,
) {
    let subject = session.user.to_string();
    let event = AuditEvent::new(
        context.account.tenant.id.clone(),
        EventType::CREDENTIAL_CHANGED,
        Outcome::Failure,
        Actor::User(subject.clone()),
        now,
    )
    .session(DomainSessionId::new(session.id_digest.clone()))
    .subject(subject)
    .detail(
        Detail::new()
            .label("kind", "passkey")
            .label("reason", "account_passkeys_page")
            .label("change", "removal_refused")
            .credential("credential_id", credential.to_string()),
    );
    if let Err(error) = context.audit.record(event).await {
        tracing::error!(
            %error,
            tenant = %context.account.tenant.id,
            "a refused passkey removal was not written to the audit trail"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CREDENTIAL: &str = "9f1c2d3e-4a5b-4c6d-8e9f-0a1b2c3d4e5f";
    const OTHER: &str = "11111111-1111-4111-8111-111111111111";

    fn epoch() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("a fixed instant")
    }

    fn summary(id: &str, disabled: bool) -> PasskeySummary {
        PasskeySummary {
            id: uuid::Uuid::parse_str(id).expect("a fixed uuid"),
            label: None,
            rp_id: "as.example".to_owned(),
            aaguid: None,
            created_at: epoch(),
            last_used_at: None,
            disabled_at: disabled.then(epoch),
        }
    }

    /// The ordinary submission: a token, a credential and the button that was
    /// pressed.
    #[test]
    fn a_submission_names_one_credential_and_one_verb() {
        // Arrange
        let body = format!("csrf=abc&credential={CREDENTIAL}&label=Laptop&do=rename");

        // Act
        let parsed = change(body.as_bytes());

        // Assert
        assert_eq!(
            parsed,
            Some(Change {
                csrf: "abc".to_owned(),
                credential: CREDENTIAL.to_owned(),
                verb: Verb::Rename,
                label: "Laptop".to_owned(),
                password: None,
            })
        );
    }

    /// RFC 6749 §3.1's parameter pollution, applied to the one field that
    /// decides whether a credential is renamed or destroyed.
    #[test]
    fn a_body_naming_two_verbs_is_refused() {
        // Arrange
        let body = format!("csrf=abc&credential={CREDENTIAL}&do=rename&do=remove");

        // Act & assert
        assert_eq!(change(body.as_bytes()), None);
    }

    /// And on the identifier, for the same reason.
    #[test]
    fn a_body_naming_two_credentials_is_refused() {
        // Arrange
        let body = format!("csrf=abc&credential={CREDENTIAL}&credential={OTHER}&do=remove");

        // Act & assert
        assert_eq!(change(body.as_bytes()), None);
    }

    /// The id is the spelling this server writes, or it is nothing: the store
    /// is not asked to look up a shape that could never be a row.
    #[test]
    fn an_identifier_that_is_not_this_servers_spelling_is_refused() {
        for id in [
            "9f1c2d3e".to_owned(),
            CREDENTIAL.to_uppercase(),
            format!("{{{CREDENTIAL}}}"),
            CREDENTIAL.replace('-', ""),
        ] {
            let body = format!("csrf=abc&credential={id}&do=remove");
            assert_eq!(change(body.as_bytes()), None, "accepted {id}");
        }
    }

    /// A verb this page does not have is not a verb: a body that says
    /// `do=disable` is a body this server did not write.
    #[test]
    fn a_verb_this_page_does_not_have_is_refused() {
        // Arrange
        let body = format!("csrf=abc&credential={CREDENTIAL}&do=disable");

        // Act & assert
        assert_eq!(change(body.as_bytes()), None);
    }

    /// A submission with no token is not one this page posts, whatever else it
    /// carries.
    #[test]
    fn a_submission_without_a_token_is_refused() {
        // Arrange
        let body = format!("credential={CREDENTIAL}&do=remove");

        // Act & assert
        assert_eq!(change(body.as_bytes()), None);
    }

    /// A label longer than the field's `maxlength` is a body the page did not
    /// produce, and the column is unbounded `text`: the bound is here.
    #[test]
    fn an_over_long_label_is_refused() {
        // Arrange
        let label = "é".repeat(MAX_LABEL_CHARS + 1);
        let body = format!("csrf=abc&credential={CREDENTIAL}&do=rename&label={label}");

        // Act & assert
        assert_eq!(change(body.as_bytes()), None);
    }

    /// A body this server will not buffer is refused before it is decoded.
    #[test]
    fn an_over_long_body_is_refused() {
        // Arrange
        let body = format!(
            "csrf={}&credential={CREDENTIAL}&do=remove",
            "a".repeat(MAX_BODY)
        );

        // Act & assert
        assert_eq!(change(body.as_bytes()), None);
    }

    /// A form body is text; bytes that are not are refused rather than lossily
    /// decoded into something that parses.
    #[test]
    fn a_body_that_is_not_text_is_refused() {
        assert_eq!(change(&[0xff, 0xfe, 0xfd]), None);
    }

    /// The rule the password requirement hangs off: one usable credential and
    /// this is it.
    #[test]
    fn the_only_usable_passkey_is_the_last_one() {
        // Arrange
        let credential = uuid::Uuid::parse_str(CREDENTIAL).expect("a fixed uuid");
        let held = vec![summary(CREDENTIAL, false)];

        // Act & assert
        assert!(is_last_usable(&held, credential));
    }

    /// A blocked credential is not a way in, so an account holding one blocked
    /// passkey beside one usable one is removing its last: this is the case
    /// the rule exists for, and counting rows rather than usable rows would
    /// miss it.
    #[test]
    fn a_blocked_passkey_does_not_count_as_another_way_in() {
        // Arrange
        let credential = uuid::Uuid::parse_str(CREDENTIAL).expect("a fixed uuid");
        let held = vec![summary(CREDENTIAL, false), summary(OTHER, true)];

        // Act & assert
        assert!(is_last_usable(&held, credential));
    }

    /// Two usable credentials: removing either leaves a way in, so neither
    /// needs the password.
    #[test]
    fn one_of_two_usable_passkeys_is_not_the_last() {
        // Arrange
        let credential = uuid::Uuid::parse_str(CREDENTIAL).expect("a fixed uuid");
        let held = vec![summary(CREDENTIAL, false), summary(OTHER, false)];

        // Act & assert
        assert!(!is_last_usable(&held, credential));
    }

    /// Removing an already-blocked credential takes away no way in at all, so
    /// it is not the last one however few usable ones there are.
    #[test]
    fn removing_an_already_blocked_passkey_is_not_removing_the_last_one() {
        // Arrange
        let credential = uuid::Uuid::parse_str(CREDENTIAL).expect("a fixed uuid");
        let held = vec![summary(CREDENTIAL, true)];

        // Act & assert
        assert!(!is_last_usable(&held, credential));
    }
}
