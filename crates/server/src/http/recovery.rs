//! Account recovery: the mailbox path back into an account.
//!
//! Four routes, none of which needs a line of JavaScript:
//!
//! * `GET /recovery` renders the "email me a link" form;
//! * `POST /recovery` draws a token, hands a message to the sender, and
//!   answers the same page whatever was typed;
//! * `GET /recovery/new?token=…` renders the "choose a new password" form;
//! * `POST /recovery/new` spends the token, writes the credential, and ends
//!   every session the account had.
//!
//! # This is a new authentication path, and the boundary moved
//!
//! Before this file, taking an account required a credential: a password, or a
//! passkey's private key. After it, control of a mailbox is enough. That is
//! not a regression — it is what account recovery *is*, and NIST SP 800-63B
//! §6.1.2.3 describes it as a binding to an out-of-band channel rather than as
//! a lesser form of the same thing — but it does mean the mail provider is now
//! inside the trust boundary for every account with an address on it. See
//! `docs/threat-model.md` §"Account recovery".
//!
//! The countermeasures that follow from that, all of them here:
//!
//! * the token is 256 bits, single use, fifteen minutes, and stored as a
//!   digest, so neither a database copy nor a guess is a way in;
//! * spending it forces a new credential in the same request — there is no
//!   state in which a spent token has signed somebody in without one;
//! * completing a recovery revokes every other session, so an attacker who got
//!   in first is thrown out when the real owner recovers, and vice versa;
//! * a credential change invalidates every outstanding token, so a link that
//!   was quietly requested before the change does not survive it;
//! * both halves are behind the per-account and per-address limiter of
//!   `ast-2vk.9` — the same buckets the login form uses, not a second limiter
//!   with its own opinions.
//!
//! # The request page tells nobody anything
//!
//! `POST /recovery` renders one page, byte for byte, whether the address
//! belongs to an account, belongs to a *disabled* account, or belongs to
//! nobody. Not the same message on two pages: the same page, which is why
//! [`asterius_web::pages::PasswordResetSentPage`] has no field that could
//! differ. A mail-sending failure does not change it either — "we could not
//! send mail" is only sayable about an address that has an account (RFC 9700
//! §4.4.1 on account enumeration; OWASP's Forgot Password Cheat Sheet leads
//! with it).
//!
//! # CAEP
//!
//! A completed recovery emits `credential.changed` to the audit trail and
//! calls `notify_credential_change`, which is where the CAEP
//! `credential-change` signal goes when `ast-0ju` builds the transmitter. The
//! hook exists and is named now, on the precedent of `notify_participants`:
//! an extension point with a name is one a reviewer can find, and one that
//! does not exist is a signal nobody remembers to send.
//!
//! # The sessions this ends are somebody else's problem too (`ast-l8b3`)
//!
//! Ending them is half the job. The other half is telling whoever is serving
//! them: every relying party that took part in a session gets a logout token
//! (Back-Channel Logout 1.0 §2.2, §2.5) and every subscribed stream gets a
//! CAEP `session-revoked` naming that session (§3.1), one per session, exactly
//! as `crate::http::account_password` does for the same cascade. This path in
//! particular, because it is the account-takeover path: the session an
//! attacker is holding is the one being closed here, and a receiver never told
//! keeps honouring it long after the owner has taken the account back.
//!
//! The door is [`crate::ssf::RevokedBy::PasswordRecovery`], whose
//! `initiating_entity` is `user`: the authority exercised was the person's own
//! control of the mailbox on the account.

use crate::http::cookies;
use crate::http::throttle::LoginThrottle;
use crate::tenancy::MountPrefix;
use asterius_domain::audit::{Actor, AuditEvent, AuditSink, Detail, EventType, Outcome};
use asterius_domain::{
    AcceptedPassword, IssuedRecovery, MailSender, Notification, RECOVERY_LIFETIME, RecoveryToken,
    RecoveryTokenStore, SessionRepository, SessionRevocation, Tenant, User, UserId, UserStatus,
};
use asterius_web::Brand;
use asterius_web::pages::{
    self, ErrorPage, NewPasswordPage, PasswordResetRequestPage, PasswordResetSentPage,
    nonce_attribute,
};
use asterius_web::{Document, csp::Nonce, recovery as csrf};
use axum::body::Bytes;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use time::OffsetDateTime;

/// Where the "email me a link" form lives.
pub const REQUEST_PATH: &str = "/recovery";

/// Where the link leads, and where the new password is posted.
pub const NEW_PASSWORD_PATH: &str = "/recovery/new";

/// The query parameter the mailed link carries the token in.
pub const TOKEN_PARAMETER: &str = "token";

/// What the page states as this tenant's minimum, and what is enforced again
/// server-side by [`AcceptedPassword::accept_locally`].
///
/// Read from the domain rather than written here, so the number on the screen
/// and the number in the check cannot drift.
const MINIMUM_PASSWORD_LENGTH: usize = asterius_domain::entities::password::MIN_LENGTH;

/// What the recovery handlers need.
pub struct RecoveryContext<'a> {
    /// The tenant the request arrived at.
    pub tenant: &'a Tenant,
    /// This tenant's accounts, for resolving an address to one.
    pub users: &'a asterius_store_pg::PgUserRepository,
    /// How a new password is hashed and written.
    ///
    /// `None` is a deployment with no password method configured. Recovery
    /// then has nothing to set, and the honest answer is to refuse rather than
    /// to spend a token and change nothing: passkey re-enrolment is the
    /// remaining half of this ticket and is not built.
    pub passwords: Option<&'a asterius_store_pg::PgPasswordVerifier>,
    /// The single-use tokens.
    pub tokens: &'a dyn RecoveryTokenStore,
    /// Where a message is handed off. The journal adapter, unless an operator
    /// wired something else.
    pub mail: &'a dyn MailSender,
    /// Every session the account has, for ending them.
    ///
    /// The concrete repository rather than the port, for the reason
    /// `crate::http::account_password` holds the same one: ending sessions one
    /// by one needs `live_digests_for_user`, which is not on
    /// [`SessionRepository`] — and a cascade that could not name the sessions
    /// it closed could not tell anybody which ones ended.
    pub sessions: &'a asterius_store_pg::PgSessionRepository,
    /// The receivers that asked to be told (`ast-l8b3`): the relying parties
    /// that took part in each session, and the streams subscribed to CAEP
    /// `session-revoked`.
    pub signals: crate::http::account::Signals<'a>,
    /// Where all four routes are recorded.
    pub audit: &'a dyn AuditSink,
    /// The limiter of `ast-2vk.9`, with this request's address.
    pub throttle: LoginThrottle<'a>,
    /// The CSP nonce the document middleware drew.
    pub nonce: &'a Nonce,
    /// The prefix routing removed from this request's path (`ast-295`).
    pub mount: MountPrefix,
}

impl std::fmt::Debug for RecoveryContext<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecoveryContext").finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// The request half
// ---------------------------------------------------------------------------

/// `GET /recovery` — the form that asks for an address.
#[must_use]
pub fn show_request(context: &RecoveryContext<'_>) -> Response {
    let (token, cookie) = csrf::issue();
    let mut response = request_page(context, &token, None);
    set_cookie(&mut response, &cookie);
    response
}

/// `POST /recovery` — draw a token and hand a message to the sender.
///
/// Everything before the final `sent_page` may or may not happen. Nothing
/// after the limiter changes what is rendered.
pub async fn submit_request(
    context: &RecoveryContext<'_>,
    headers: &HeaderMap,
    body: &Bytes,
    now: OffsetDateTime,
) -> Response {
    let form = form(body);
    let cookies = cookies(headers);

    if csrf::check(&cookies, field(&form, "csrf")).is_err() {
        // A fresh token, because the one this browser held is either absent or
        // wrong and rendering the old value back would keep it stuck.
        return reissued_request_page(context, Some("That form had expired. Please try again."));
    }

    let Some(address) = field(&form, "email")
        .map(str::trim)
        .filter(|a| !a.is_empty())
    else {
        return reissued_request_page(context, Some("Enter the email address on your account."));
    };

    // The same buckets the login form counts against (`ast-2vk.9`). A recovery
    // request is counted like a failed sign-in on purpose: without it, this
    // form is an unauthenticated way to make this server send mail to an
    // address an attacker chooses, as many times as they like.
    let attempt = context.throttle.attempt(Some(address));
    match context
        .throttle
        .check(&context.tenant.id, &attempt, now)
        .await
    {
        Ok(Some(refused)) => {
            record(
                context,
                AuditEvent::new(
                    context.tenant.id.clone(),
                    EventType::AUTH_THROTTLED,
                    Outcome::Failure,
                    Actor::System,
                    now,
                )
                .detail(Detail::new().label("path", "recovery.request")),
            )
            .await;
            // The hint is about the requester, not about any account: it says
            // the same thing to somebody sweeping addresses as to somebody who
            // mistyped their own three times.
            return reissued_request_page(context, Some(&refused.hint()));
        }
        Ok(None) => {}
        Err(error) => {
            // A limiter that cannot be read is not permission. Failing closed
            // here costs a person one retry; failing open makes the limit
            // switchable off by loading the database.
            tracing::error!(%error, tenant = %context.tenant.id, "cannot read the login limiter");
            return error_page(context, StatusCode::SERVICE_UNAVAILABLE);
        }
    }
    context
        .throttle
        .record_failure(&context.tenant.id, &attempt, now)
        .await;

    // Recorded for every request, including the ones that match nobody, and
    // with `Success` either way: the request succeeded either way. The trail
    // must not be where the oracle the page refuses to be comes back.
    record(
        context,
        AuditEvent::new(
            context.tenant.id.clone(),
            EventType::RECOVERY_REQUESTED,
            Outcome::Success,
            Actor::System,
            now,
        ),
    )
    .await;

    if let Some(user) = recoverable(context, address).await {
        issue_and_send(context, &user, now).await;
    }

    sent_page(context)
}

/// The account this address recovers, if any, and if it can be recovered.
///
/// `None` for an address nobody has, for an account that is not active, and
/// for one with no address to send to. Three different facts, one answer, and
/// the caller has no way to tell them apart — which is the point: a disabled
/// account that produced a different page would be a way to enumerate disabled
/// accounts.
async fn recoverable(context: &RecoveryContext<'_>, address: &str) -> Option<User> {
    // By address first, because that is what the form asks for. Falling back
    // to the login identifier is a courtesy to a deployment whose users sign
    // in with something that is not an address; it opens nothing, because the
    // message still goes to the address on the account and never to what was
    // typed.
    let found = match context.users.find_by_email(address).await {
        Ok(Some(user)) => Some(user),
        Ok(None) => match context.users.find_by_username(address).await {
            Ok(user) => user,
            Err(error) => {
                tracing::error!(%error, tenant = %context.tenant.id, "cannot look up an account");
                None
            }
        },
        Err(error) => {
            tracing::error!(%error, tenant = %context.tenant.id, "cannot look up an account");
            None
        }
    }?;

    if found.status != UserStatus::Active {
        return None;
    }
    // Nothing to send to. Not an error and not a different page.
    found.email.as_ref()?;
    Some(found)
}

/// Draws the token, writes it, and hands the message over.
///
/// Failures are logged and swallowed. The caller renders the same page
/// regardless, and the reason is in the module documentation.
async fn issue_and_send(context: &RecoveryContext<'_>, user: &User, now: OffsetDateTime) {
    let Some(address) = user.email.clone() else {
        return;
    };
    let token = RecoveryToken::generate();
    let issued = IssuedRecovery::new(user.id, &token, now);

    if let Err(error) = context.tokens.issue(&issued).await {
        tracing::error!(%error, tenant = %context.tenant.id, "cannot store a recovery token");
        return;
    }

    // Absolute, because it is going into a message: a browser opening it has
    // no page to resolve a relative path against. Built from the tenant's
    // issuer and the mount prefix, so a path-mounted tenant's link comes back
    // through the prefix it is served under (`ast-295`).
    let link = format!(
        "{}{}?{TOKEN_PARAMETER}={}",
        context.tenant.issuer.as_str().trim_end_matches('/'),
        NEW_PASSWORD_PATH,
        token.expose()
    );

    let message = Notification::account_recovery(address, link, RECOVERY_LIFETIME.whole_minutes());
    if let Err(error) = context.mail.send(&message).await {
        tracing::error!(%error, tenant = %context.tenant.id, "cannot hand off a recovery message");
        return;
    }

    // Only ever emitted for a request that matched an account, so this record
    // *is* account-existence information — which is exactly why it goes here
    // and not into anything a browser sees.
    record(
        context,
        AuditEvent::new(
            context.tenant.id.clone(),
            EventType::RECOVERY_SENT,
            Outcome::Success,
            Actor::System,
            now,
        )
        .subject(user.id.as_uuid().to_string()),
    )
    .await;
}

// ---------------------------------------------------------------------------
// The use half
// ---------------------------------------------------------------------------

/// `GET /recovery/new?token=…` — the page the link leads to.
pub async fn show_new_password(
    context: &RecoveryContext<'_>,
    query: Option<&str>,
    now: OffsetDateTime,
) -> Response {
    let Some(token) = query
        .and_then(|query| query_value(query, TOKEN_PARAMETER))
        .and_then(|value| RecoveryToken::parse(&value).ok())
    else {
        return refused(context, "a malformed token at the recovery page", now).await;
    };

    let user = match context.tokens.peek(&token.digest(), now).await {
        Ok(Some(user)) => user,
        Ok(None) => return refused(context, "an unusable token at the recovery page", now).await,
        Err(error) => {
            tracing::error!(%error, tenant = %context.tenant.id, "cannot read a recovery token");
            return error_page(context, StatusCode::SERVICE_UNAVAILABLE);
        }
    };

    let username = match context.users.find(user).await {
        Ok(Some(user)) => user.username,
        // The token names an account this tenant no longer has. Refused, not
        // rendered with a blank name: the page's job is to say *which* account
        // is about to change.
        Ok(None) => return refused(context, "a token for a missing account", now).await,
        Err(error) => {
            tracing::error!(%error, tenant = %context.tenant.id, "cannot read an account");
            return error_page(context, StatusCode::SERVICE_UNAVAILABLE);
        }
    };

    let (csrf_token, cookie) = csrf::issue();
    let mut response = new_password_page(context, &csrf_token, &token, &username, None);
    set_cookie(&mut response, &cookie);
    response
}

/// `POST /recovery/new` — spend the token and set the credential.
pub async fn submit_new_password(
    context: &RecoveryContext<'_>,
    headers: &HeaderMap,
    body: &Bytes,
    now: OffsetDateTime,
) -> Response {
    let form = form(body);
    let cookies = cookies(headers);

    // The token first, because everything else is a message about it and a
    // page that cannot name the account should not be rendered at all.
    let Some(token) = field(&form, TOKEN_PARAMETER).and_then(|v| RecoveryToken::parse(v).ok())
    else {
        return refused(context, "a malformed token at the recovery form", now).await;
    };

    if csrf::check(&cookies, field(&form, "csrf")).is_err() {
        // Not spent. A forged submission must not be able to burn somebody's
        // link, which is a denial of service with a fifteen-minute cooldown.
        return retry_new_password(
            context,
            &token,
            now,
            "That form had expired. Please try again.",
        )
        .await;
    }

    // Address-scoped only: there is no identifier on this form to count
    // against, and the account the token names is not one the submitter typed.
    let attempt = context.throttle.attempt(None);
    match context
        .throttle
        .check(&context.tenant.id, &attempt, now)
        .await
    {
        Ok(Some(refused)) => {
            return retry_new_password(context, &token, now, &refused.hint()).await;
        }
        Ok(None) => {}
        Err(error) => {
            tracing::error!(%error, tenant = %context.tenant.id, "cannot read the login limiter");
            return error_page(context, StatusCode::SERVICE_UNAVAILABLE);
        }
    }

    let Some(passwords) = context.passwords else {
        tracing::error!(
            tenant = %context.tenant.id,
            "a recovery reached this server with no password method configured"
        );
        return error_page(context, StatusCode::NOT_IMPLEMENTED);
    };

    let (Some(password), Some(confirmation)) = (
        field(&form, "password"),
        field(&form, "password_confirmation"),
    ) else {
        return retry_new_password(context, &token, now, "Enter the new password twice.").await;
    };

    if password != confirmation {
        return retry_new_password(context, &token, now, "Those two did not match.").await;
    }

    // The same gate the deployment admin's password goes through (`ast-895`):
    // the NIST SP 800-63B §5.1.1.2 length floor and the deny list compiled
    // into this binary. Before the token is spent, so a refused password costs
    // the person a retry rather than their link.
    let accepted = match AcceptedPassword::accept_locally(password) {
        Ok(accepted) => accepted,
        Err(failure) => {
            return retry_new_password(context, &token, now, &failure.to_string()).await;
        }
    };

    // The point of no return, and one statement. Whoever wins this gets the
    // reset; a second request with the same link finds nothing.
    let user = match context.tokens.spend(&token.digest(), now).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            context
                .throttle
                .record_failure(&context.tenant.id, &attempt, now)
                .await;
            return refused(context, "an unusable token at the recovery form", now).await;
        }
        Err(error) => {
            tracing::error!(%error, tenant = %context.tenant.id, "cannot spend a recovery token");
            return error_page(context, StatusCode::SERVICE_UNAVAILABLE);
        }
    };

    let credential = match passwords
        .set_password(*user.as_uuid(), accepted.expose())
        .await
    {
        Ok(credential) => credential,
        Err(error) => {
            // The token is spent and the password is not set. The person has
            // to ask for another link, which is the safe end of this: the
            // alternative is un-spending a token, and a token that can be
            // un-spent is not single use.
            tracing::error!(%error, tenant = %context.tenant.id, "cannot write a new password");
            return error_page(context, StatusCode::SERVICE_UNAVAILABLE);
        }
    };

    credential_changed(context, user, credential, now).await;
    done(context)
}

/// Everything a credential change entails, in one place.
///
/// Called by the recovery path today. Any other route that replaces a
/// credential — a change from a signed-in session, an administrator — belongs
/// here too rather than repeating three of these four steps and forgetting the
/// fourth.
async fn credential_changed(
    context: &RecoveryContext<'_>,
    user: UserId,
    credential: uuid::Uuid,
    now: OffsetDateTime,
) {
    let subject = user.as_uuid().to_string();

    // Every session predating the change, including whichever one an attacker
    // may be holding. This is the half of NIST SP 800-63B §7.1 that makes a
    // recovery a recovery rather than a second way in beside the first.
    let revoked = close_every_session(context, user, now).await;

    // Any other link that was outstanding. Somebody who quietly asked for one
    // before the change must not still be holding a way in after it.
    if let Err(error) = context.tokens.invalidate_for_user(user, now).await {
        tracing::error!(%error, tenant = %context.tenant.id, "cannot invalidate recovery tokens");
    }

    record(
        context,
        AuditEvent::new(
            context.tenant.id.clone(),
            EventType::RECOVERY_USED,
            Outcome::Success,
            Actor::User(subject.clone()),
            now,
        )
        .subject(subject.clone()),
    )
    .await;

    record(
        context,
        AuditEvent::new(
            context.tenant.id.clone(),
            EventType::CREDENTIAL_CHANGED,
            Outcome::Success,
            Actor::User(subject.clone()),
            now,
        )
        .subject(subject)
        .detail(
            Detail::new()
                .label("kind", "password")
                .label("reason", "recovery")
                .number(
                    "sessions_revoked",
                    i64::try_from(revoked).unwrap_or(i64::MAX),
                )
                .credential("credential_id", credential.to_string()),
        ),
    )
    .await;

    notify_credential_change(context, user).await;
}

/// Ends every live session of the account and tells the receivers of each.
///
/// One session at a time rather than `revoke_all_for_user`, for the reason
/// `crate::admin`'s administrative cascade gives (`ast-o4u.3`): a receiver
/// holding three of this person's sessions has to be told *which* of them to
/// drop, so each one needs its own logout token, its own CAEP
/// `session-revoked` and its own line in the trail. A single statement that
/// revoked them all would end them just as thoroughly and leave every relying
/// party serving the attacker's.
///
/// The list is `live_digests_for_user`, so a session already revoked is not in
/// it: a replayed link finds nothing to close and queues nothing — which is
/// what makes this idempotent without a second mechanism.
///
/// Every failure below the first degrades rather than aborts: the credential
/// is already replaced by the time this runs, and a relying party whose
/// registration will not load must not leave the remaining sessions open.
/// Returns how many sessions were closed, for the caller's trail.
async fn close_every_session(
    context: &RecoveryContext<'_>,
    user: UserId,
    now: OffsetDateTime,
) -> usize {
    let digests = match context
        .sessions
        .live_digests_for_user(*user.as_uuid(), now)
        .await
    {
        Ok(digests) => digests,
        Err(error) => {
            tracing::error!(%error, tenant = %context.tenant.id, "cannot list live sessions");
            return 0;
        }
    };

    let mut closed = 0;
    for digest in digests {
        // Read before revoking: the `sid` a receiver knows this session by is
        // what the event's subject carries, and a row read back after a failed
        // revocation would name a session that is still live.
        let named = match context.sessions.find(&digest).await {
            Ok(Some(named)) => named,
            Ok(None) => continue,
            Err(error) => {
                tracing::error!(%error, tenant = %context.tenant.id, "cannot read a session");
                continue;
            }
        };
        if let Err(error) = context
            .sessions
            .revoke(&digest, SessionRevocation::CredentialChange, now)
            .await
        {
            tracing::error!(%error, tenant = %context.tenant.id, "cannot revoke a session");
            continue;
        }
        closed += 1;
        record_revocation(context, &named, now).await;
        notify_participants(context, &named, now).await;
        emit_revocation(context, &named, now).await;
    }
    closed
}

/// Queues one logout token per relying party that took part in this session
/// (Back-Channel Logout 1.0 §2.2), through the same
/// [`crate::backchannel::Notifier`] the end-session endpoint and the console
/// use — it is the same act, so it must not reach receivers differently.
async fn notify_participants(
    context: &RecoveryContext<'_>,
    revoked: &asterius_domain::Session,
    now: OffsetDateTime,
) {
    let participants = match context.sessions.participants(&revoked.id_digest).await {
        Ok(participants) => participants,
        Err(error) => {
            tracing::error!(
                %error,
                tenant = %context.tenant.id,
                "cannot read the participants of an ended session"
            );
            return;
        }
    };
    if participants.is_empty() {
        return;
    }
    let notifier = crate::backchannel::Notifier {
        tenant: context.tenant,
        clients: context.signals.clients,
        subjects: context.signals.subjects,
        signer: context.signals.signer,
        outbox: context.signals.outbox,
    };
    notifier.notify(revoked, &participants, now).await;
}

/// Emits CAEP §3.1's `session-revoked` for one closed session, to every stream
/// that subscribed.
///
/// Best-effort and after the revocation, the order every other door keeps: the
/// session is already over, and a receiver that could not be told must not
/// undo that.
///
/// The language is English and stated rather than negotiated: these pages are
/// rendered from [`crate::http::i18n::UNTRANSLATED`], so English is the
/// language the person was actually addressed in, and a `reason_user` tagged
/// with anything else would be a claim about words this server never showed.
async fn emit_revocation(
    context: &RecoveryContext<'_>,
    revoked: &asterius_domain::Session,
    now: OffsetDateTime,
) {
    let Some(queues) = context.signals.queues else {
        tracing::debug!(
            tenant = %context.tenant.id,
            "no security event queue is wired; no receiver was told a session ended"
        );
        return;
    };
    let transmitter = crate::ssf::SsfTransmitter {
        tenant: &context.tenant.id,
        issuer: &context.tenant.issuer,
        queues,
        clients: context.signals.clients,
        subjects: context.signals.subjects,
        signer: context.signals.signer,
    };
    transmitter
        .emit(
            &crate::ssf::Cause::SessionRevoked {
                user: UserId::new(revoked.user),
                sid: revoked.public_sid.clone(),
                by: crate::ssf::RevokedBy::PasswordRecovery,
                locale: crate::http::i18n::UNTRANSLATED.locale(),
            },
            now,
        )
        .await;
}

/// Records one session closed by a recovery (`ast-l8b3`).
///
/// [`EventType::SESSION_REVOKED`], the event the account pages, the admin API
/// and the end-session endpoint write, because it is the same fact. One line
/// per session, named by its digest: "a password was recovered" and "four
/// sessions were closed" are different facts, and an auditor reconstructing a
/// takeover needs the second one per session. `initiating_entity` carries the
/// same word as the CAEP SET beside it (§2), so the trail and the receivers
/// cannot disagree about who acted.
async fn record_revocation(
    context: &RecoveryContext<'_>,
    revoked: &asterius_domain::Session,
    now: OffsetDateTime,
) {
    let subject = revoked.user.to_string();
    let event = AuditEvent::new(
        context.tenant.id.clone(),
        EventType::SESSION_REVOKED,
        Outcome::Success,
        Actor::User(subject.clone()),
        now,
    )
    .session(asterius_domain::SessionId::new(revoked.id_digest.clone()))
    .subject(subject)
    .detail(
        Detail::new()
            .label("reason", SessionRevocation::CredentialChange.as_str())
            .label("initiator", "recovery_link")
            .label(
                "initiating_entity",
                crate::ssf::RevokedBy::PasswordRecovery
                    .initiating_entity()
                    .as_str(),
            ),
    );
    record(context, event).await;
}

/// The CAEP `credential-change` seam.
///
/// The transmitter is `ast-0ju` and does not exist. What this does today is
/// send the account's own "this changed" message, which is the part that does
/// not need a transmitter and is the part a person notices — OWASP's Forgot
/// Password Cheat Sheet asks for it, because it is how somebody learns their
/// account was taken while they still could have stopped it.
///
/// Named and called from exactly one place so that when the transmitter lands,
/// the subject, the tenant and the moment are already assembled here.
async fn notify_credential_change(context: &RecoveryContext<'_>, user: UserId) {
    let address = match context.users.find(user).await {
        Ok(Some(user)) => user.email,
        Ok(None) => None,
        Err(error) => {
            tracing::error!(%error, tenant = %context.tenant.id, "cannot read an account");
            None
        }
    };
    let Some(address) = address else {
        return;
    };
    if let Err(error) = context
        .mail
        .send(&Notification::credential_changed(address))
        .await
    {
        tracing::error!(
            %error,
            tenant = %context.tenant.id,
            "cannot hand off a credential-change message"
        );
    }
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

/// The request form.
fn request_page(
    context: &RecoveryContext<'_>,
    csrf_token: &asterius_web::CsrfToken,
    message: Option<&str>,
) -> Response {
    // Where this page fetches its face, under the prefix routing removed (`ast-vn7`).
    let font_url = crate::http::font_url(&context.mount);
    Document::render(context.nonce, |nonce| {
        pages::render(&PasswordResetRequestPage {
            text: &crate::http::i18n::UNTRANSLATED,
            tenant_name: &context.tenant.display_name,
            action: &context.mount.absolute(REQUEST_PATH),
            csrf: csrf_token.expose(),
            sign_in_href: context.tenant.issuer.as_str(),
            message,
            nonce_attribute: nonce_attribute(nonce),
            theme_css: "",
            brand: Brand::new(&font_url),
        })
    })
    .into_response()
}

/// The request form again, with a new synchroniser token and its cookie.
fn reissued_request_page(context: &RecoveryContext<'_>, message: Option<&str>) -> Response {
    let (token, cookie) = csrf::issue();
    let mut response = request_page(context, &token, message);
    set_cookie(&mut response, &cookie);
    response
}

/// The neutral answer. No field on it can differ between an address this
/// tenant knows and one it does not — see
/// [`asterius_web::pages::PasswordResetSentPage`].
fn sent_page(context: &RecoveryContext<'_>) -> Response {
    // Where this page fetches its face, under the prefix routing removed (`ast-vn7`).
    let font_url = crate::http::font_url(&context.mount);
    let mut response = Document::render(context.nonce, |nonce| {
        pages::render(&PasswordResetSentPage {
            text: &crate::http::i18n::UNTRANSLATED,
            tenant_name: &context.tenant.display_name,
            sign_in_href: context.tenant.issuer.as_str(),
            nonce_attribute: nonce_attribute(nonce),
            theme_css: "",
            brand: Brand::new(&font_url),
        })
    })
    .into_response();
    // Nothing follows this page, so the synchroniser cookie has no next
    // submission to protect.
    set_cookie(&mut response, &csrf::clear_cookie());
    response
}

/// The new-password form.
fn new_password_page(
    context: &RecoveryContext<'_>,
    csrf_token: &asterius_web::CsrfToken,
    token: &RecoveryToken,
    username: &str,
    message: Option<&str>,
) -> Response {
    // Where this page fetches its face, under the prefix routing removed (`ast-vn7`).
    let font_url = crate::http::font_url(&context.mount);
    Document::render(context.nonce, |nonce| {
        pages::render(&NewPasswordPage {
            text: &crate::http::i18n::UNTRANSLATED,
            tenant_name: &context.tenant.display_name,
            username,
            action: &context.mount.absolute(NEW_PASSWORD_PATH),
            csrf: csrf_token.expose(),
            reset_token: token.expose(),
            minimum_password_length: MINIMUM_PASSWORD_LENGTH,
            message,
            nonce_attribute: nonce_attribute(nonce),
            theme_css: "",
            brand: Brand::new(&font_url),
        })
    })
    .into_response()
}

/// The new-password form again, after a refusal that did not spend the token.
async fn retry_new_password(
    context: &RecoveryContext<'_>,
    token: &RecoveryToken,
    now: OffsetDateTime,
    message: &str,
) -> Response {
    // Re-read rather than carried: between the two requests the token may have
    // been spent or invalidated, and re-rendering a form for a dead link would
    // ask somebody to type a password that cannot be saved.
    let username = match context.tokens.peek(&token.digest(), now).await {
        Ok(Some(user)) => match context.users.find(user).await {
            Ok(Some(user)) => user.username,
            _ => return refused(context, "a token for a missing account", now).await,
        },
        Ok(None) => return refused(context, "an unusable token at the recovery form", now).await,
        Err(error) => {
            tracing::error!(%error, tenant = %context.tenant.id, "cannot read a recovery token");
            return error_page(context, StatusCode::SERVICE_UNAVAILABLE);
        }
    };
    let (csrf_token, cookie) = csrf::issue();
    let mut response = new_password_page(context, &csrf_token, token, &username, Some(message));
    set_cookie(&mut response, &cookie);
    response
}

/// The one answer to every unusable token: unknown, spent, expired, cancelled.
///
/// One page and one status for all four, matching what the audit trail records
/// under one type. `reason` goes to the log beside the correlation id, and the
/// page carries none of it.
async fn refused(context: &RecoveryContext<'_>, reason: &str, now: OffsetDateTime) -> Response {
    // Where this page fetches its face, under the prefix routing removed (`ast-vn7`).
    let font_url = crate::http::font_url(&context.mount);
    tracing::info!(tenant = %context.tenant.id, reason, "a recovery token was refused");
    record(
        context,
        AuditEvent::new(
            context.tenant.id.clone(),
            EventType::RECOVERY_REFUSED,
            Outcome::Failure,
            Actor::System,
            now,
        ),
    )
    .await;
    let mut response = Document::render(context.nonce, |nonce| {
        pages::render(&ErrorPage {
            text: &crate::http::i18n::UNTRANSLATED,
            tenant_name: &context.tenant.display_name,
            message: crate::http::i18n::UNTRANSLATED.error_link_unusable(),
            correlation_id: &asterius_web::interaction::correlation_id(),
            nonce_attribute: nonce_attribute(nonce),
            theme_css: "",
            brand: Brand::new(&font_url),
        })
    })
    .into_response();
    *response.status_mut() = StatusCode::BAD_REQUEST;
    set_cookie(&mut response, &csrf::clear_cookie());
    response
}

/// Where a completed recovery lands.
///
/// A redirect to the tenant's own entry point rather than a "done" page,
/// because there is nothing more for this flow to say and the next thing the
/// person wants is to sign in with what they just chose. The synchroniser
/// cookie is cleared on the way out.
fn done(context: &RecoveryContext<'_>) -> Response {
    let mut response = Response::new(axum::body::Body::empty());
    *response.status_mut() = StatusCode::SEE_OTHER;
    if let Ok(value) = context.tenant.issuer.as_str().parse() {
        response.headers_mut().insert(header::LOCATION, value);
    }
    set_cookie(&mut response, &csrf::clear_cookie());
    response
}

/// The generic failure page, for a store that cannot be reached.
fn error_page(context: &RecoveryContext<'_>, status: StatusCode) -> Response {
    // Where this page fetches its face, under the prefix routing removed (`ast-vn7`).
    let font_url = crate::http::font_url(&context.mount);
    let mut response = Document::render(context.nonce, |nonce| {
        pages::render(&ErrorPage {
            text: &crate::http::i18n::UNTRANSLATED,
            tenant_name: &context.tenant.display_name,
            message: crate::http::i18n::UNTRANSLATED.error_try_again(),
            correlation_id: &asterius_web::interaction::correlation_id(),
            nonce_attribute: nonce_attribute(nonce),
            theme_css: "",
            brand: Brand::new(&font_url),
        })
    })
    .into_response();
    *response.status_mut() = status;
    response
}

// ---------------------------------------------------------------------------
// Plumbing
// ---------------------------------------------------------------------------

/// Appends one record, logging a failure rather than failing the request.
///
/// The same call `http::interaction` makes and for the same reason: by the
/// time most of these run the state change is committed, and failing the
/// response afterwards would tell a person something untrue about what
/// happened to their account.
async fn record(context: &RecoveryContext<'_>, event: AuditEvent) {
    if let Err(failure) = context.audit.record(event).await {
        tracing::error!(
            %failure,
            tenant = %context.tenant.id,
            "a recovery event was not written to the audit trail"
        );
    }
}

/// Appends a `Set-Cookie`, without replacing any already there.
fn set_cookie(response: &mut Response, value: &str) {
    if let Ok(value) = value.parse() {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
}

/// The submitted form, as pairs.
///
/// `application/x-www-form-urlencoded` with no schema, because a repeated
/// field must be visible to [`field`] rather than silently resolved: RFC 6749
/// §3.1's rule about repeated parameters is a rule about not letting two
/// readers disagree.
fn form(body: &Bytes) -> Vec<(String, String)> {
    url::form_urlencoded::parse(body).into_owned().collect()
}

/// One field, or `None` if it is absent **or repeated**.
fn field<'a>(form: &'a [(String, String)], name: &str) -> Option<&'a str> {
    let mut found = None;
    for (key, value) in form {
        if key != name {
            continue;
        }
        if found.is_some() {
            return None;
        }
        found = Some(value.as_str());
    }
    found
}

/// One query parameter, by the same rule.
fn query_value(query: &str, name: &str) -> Option<String> {
    let mut found = None;
    for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
        if key != name {
            continue;
        }
        if found.is_some() {
            return None;
        }
        found = Some(value.into_owned());
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A repeated field is no field. Two intermediaries that disagree about
    /// which `token` counts would validate one request and run another.
    #[test]
    fn a_repeated_field_is_refused() {
        // Arrange
        let form = vec![
            ("token".to_owned(), "a".to_owned()),
            ("token".to_owned(), "b".to_owned()),
        ];

        // Act
        let value = field(&form, "token");

        // Assert
        assert_eq!(value, None);
    }

    /// The ordinary case still works.
    #[test]
    fn a_single_field_is_read() {
        // Arrange
        let form = vec![("token".to_owned(), "a".to_owned())];

        // Act
        let value = field(&form, "token");

        // Assert
        assert_eq!(value, Some("a"));
    }

    /// The same rule on the link's query string, which is the other place a
    /// token arrives.
    #[test]
    fn a_repeated_query_parameter_is_refused() {
        // Arrange, Act
        let value = query_value("token=a&token=b", "token");

        // Assert
        assert_eq!(value, None);
    }

    /// A percent-encoded token is decoded before it is parsed; `base64url` has
    /// nothing that needs escaping, but a client that escaped anyway must not
    /// be handed a refusal.
    #[test]
    fn a_query_parameter_is_percent_decoded() {
        // Arrange, Act
        let value = query_value("token=a%2Db", "token");

        // Assert
        assert_eq!(value.as_deref(), Some("a-b"));
    }

    /// The number on the page is the number the check enforces. Written as a
    /// test because the two being one value is the whole reason the constant
    /// is read from the domain.
    #[test]
    fn the_stated_minimum_is_the_enforced_one() {
        // Arrange
        let short = "a".repeat(MINIMUM_PASSWORD_LENGTH - 1);

        // Act
        let accepted = AcceptedPassword::accept_locally(&short);

        // Assert
        assert!(accepted.is_err());
    }
}
