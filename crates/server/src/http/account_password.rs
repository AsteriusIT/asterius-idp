//! Setting or changing a password from a signed-in session (`ast-1xd`).
//!
//! Three routes, the shape the other account pages use:
//!
//! * `GET /account/password` shows the form, in one of its two shapes;
//! * `POST /account/password` writes the credential;
//! * `GET /account/password/sign-in` opens a fresh authentication for a session
//!   too old to change a credential with.
//!
//! # Two shapes, one page
//!
//! An account that signs in with a passkey has no password credential at all.
//! Asking it for a "current password" would be asking for something that does
//! not exist, and refusing the submission when nothing came back would be a
//! page nobody can use. So the form asks for the current password exactly when
//! [`PgPasswordVerifier::has_password`] says there is one, and the handler
//! makes the same decision again for itself: a page that only *hid* the field
//! would be a rule enforced in markup.
//!
//! # Why the current password, on top of a fresh authentication
//!
//! Freshness says somebody authenticated two minutes ago. It does not say
//! *with what*: a session authenticated with a passkey is fresh, and an
//! attacker holding a stolen session that re-authenticates with a stolen
//! passkey is fresh too. The current password is the second, different thing —
//! and for the account that has one it is the credential being replaced, which
//! is exactly what NIST SP 800-63B §5.1.1.2's change flow asks a subscriber to
//! present.
//!
//! For an account with none, the fresh authentication is what there is, and it
//! is what `crate::http::account_passkeys` leans on when it refuses to remove
//! the last passkey of an account that has not been here yet.
//!
//! # The other sessions
//!
//! They are **not** closed, unless the box is ticked, and the page says so
//! before it is submitted. A voluntary change is not a recovery: the recovery
//! path (`crate::http::recovery`) ends every session because the person there
//! may be locked out by somebody who is signed in, and this page has no such
//! reason to sign somebody out of four devices they are holding. Ticking the
//! box runs the same revocation, back-channel logout and CAEP `session-revoked`
//! that [`crate::http::account_sessions`] runs, because it is the same act.
//!
//! # What a change is reported as
//!
//! [`EventType::CREDENTIAL_CHANGED`] in the trail, CAEP `credential-change`
//! with [`caep::ChangeType::Create`] for a first password and
//! [`caep::ChangeType::Update`] for a replacement, and the account's own "this
//! changed" message — OWASP's Forgot Password Cheat Sheet asks for the last
//! one, because it is how somebody learns their account was taken while they
//! still could have stopped it.

use asterius_domain::audit::{Actor, AuditEvent, AuditSink, Detail, EventType, Outcome};
use asterius_domain::entities::password::{AcceptedPassword, MIN_LENGTH};
use asterius_domain::{
    FirstPartyDestination, Notification, Session, SessionId as DomainSessionId, SessionRepository,
    SessionRevocation, UserId,
};
use asterius_ssf::caep;
use asterius_store_pg::{PgPasswordVerifier, PgSessionRepository};
use asterius_web::Brand;
use asterius_web::Document;
use asterius_web::pages::{self, AccountPasswordPage, nonce_attribute};
use axum::body::Bytes;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use time::OffsetDateTime;

use crate::http::account::{
    self, AccountContext, MAX_BODY, MAX_CSRF_CHARS, Signals, begin, checked_csrf, csrf_for,
    error_page, fresh, no_store,
};

/// Where the form lives, and where it posts.
pub const PAGE_PATH: &str = "/account/password";

/// Where a person goes to authenticate again.
pub const SIGN_IN_PATH: &str = "/account/password/sign-in";

/// This page's CSRF separator.
const CSRF_SEPARATOR: &str = "account-password-csrf";

/// The longest password this parser will carry.
///
/// [`asterius_domain::entities::password::MAX_LENGTH`]: a longer one is
/// refused by the policy anyway, and the bound here is what stops a caller
/// making this function allocate.
const MAX_PASSWORD_CHARS: usize = asterius_domain::entities::password::MAX_LENGTH;

/// A submission from this page, after parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewPassword {
    /// The synchroniser token the form carried.
    pub csrf: String,
    /// The current password, where the form asked for one.
    pub current: Option<String>,
    /// The new password, as typed.
    pub password: String,
    /// And again, because a password nobody can see is a password that gets
    /// typed wrong.
    pub confirmation: String,
    /// Whether the person asked for their other sessions to be closed as well.
    pub sign_out_others: bool,
}

/// Reads a submission from this page, or refuses it.
///
/// Every refusal is `None`, because the caller answers all of them with one
/// page: a body that is too large, that is not UTF-8, that names a parameter
/// twice (RFC 6749 §3.1's parameter pollution, applied to this server's own
/// forms — and here a repeated `password` is a body where which one is stored
/// depends on which the parser preferred), or that carries no new password at
/// all.
///
/// Nothing about the *policy* is decided here.
/// [`AcceptedPassword::accept_locally`] is where length and the deny list live,
/// and it runs on the value this returns: a parser that started refusing short
/// passwords would be a second copy of a rule that has to move as one.
// fuzz-target: account_password_form
#[must_use]
pub fn new_password(body: &[u8]) -> Option<NewPassword> {
    if body.len() > MAX_BODY {
        return None;
    }
    let text = std::str::from_utf8(body).ok()?;

    let mut csrf: Option<String> = None;
    let mut current: Option<String> = None;
    let mut password: Option<String> = None;
    let mut confirmation: Option<String> = None;
    let mut sign_out_others = false;
    for (key, value) in url::form_urlencoded::parse(text.as_bytes()) {
        match key.as_ref() {
            "csrf" if csrf.is_some() => return None,
            "csrf" => csrf = Some(value.into_owned()),
            "current_password" if current.is_some() => return None,
            "current_password" => current = Some(value.into_owned()),
            "password" if password.is_some() => return None,
            "password" => password = Some(value.into_owned()),
            "password_confirmation" if confirmation.is_some() => return None,
            "password_confirmation" => confirmation = Some(value.into_owned()),
            // A checkbox is present or absent; any value a browser sends for a
            // ticked one means the same thing.
            "sign_out_others" => sign_out_others = true,
            _ => {}
        }
    }

    let csrf = csrf?;
    if csrf.is_empty() || csrf.chars().count() > MAX_CSRF_CHARS {
        return None;
    }
    let password = password?;
    let confirmation = confirmation?;
    for field in [Some(&password), Some(&confirmation), current.as_ref()]
        .into_iter()
        .flatten()
    {
        if field.chars().count() > MAX_PASSWORD_CHARS {
            return None;
        }
    }
    Some(NewPassword {
        csrf,
        current,
        password,
        confirmation,
        sign_out_others,
    })
}

/// What this page needs beyond [`AccountContext`].
pub struct PasswordContext<'a> {
    /// Admission, freshness, the sign-in and the chrome.
    pub account: AccountContext<'a>,
    /// Where the credential is read and written.
    ///
    /// `None` in a deployment with no password method configured, which
    /// renders 501 rather than a form that could not be honoured.
    pub passwords: Option<&'a PgPasswordVerifier>,
    /// Where the account's username and address are read: the username to
    /// check the current password through the login path's verifier, the
    /// address to tell its owner that the credential changed.
    pub users: &'a dyn asterius_domain::UserDirectory,
    /// The sessions, for the box the person may tick.
    pub sessions: &'a PgSessionRepository,
    /// Where the account is told its credential changed.
    pub mail: &'a dyn asterius_domain::MailSender,
    /// The trail.
    pub audit: &'a dyn AuditSink,
    /// The receivers that asked to be told (`ast-0ju.8`).
    pub signals: Signals<'a>,
}

impl std::fmt::Debug for PasswordContext<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasswordContext").finish_non_exhaustive()
    }
}

/// `GET /account/password` — the form, in one of its two shapes.
pub async fn page(
    context: &PasswordContext<'_>,
    headers: &HeaderMap,
    now: OffsetDateTime,
) -> Response {
    let Some(session) = account::admitted(&context.account, headers, now).await else {
        return begin(
            &context.account,
            FirstPartyDestination::AccountPassword,
            now,
        )
        .await;
    };
    rendered(context, &session, None, StatusCode::OK, now).await
}

/// `GET /account/password/sign-in` — authenticate again, and come back.
pub async fn sign_in(context: &PasswordContext<'_>, now: OffsetDateTime) -> Response {
    begin(
        &context.account,
        FirstPartyDestination::AccountPassword,
        now,
    )
    .await
}

/// `POST /account/password` — write the credential.
pub async fn submit(
    context: &PasswordContext<'_>,
    headers: &HeaderMap,
    body: &Bytes,
    now: OffsetDateTime,
) -> Response {
    let Some(session) = account::admitted(&context.account, headers, now).await else {
        return begin(
            &context.account,
            FirstPartyDestination::AccountPassword,
            now,
        )
        .await;
    };
    let Some(form) = new_password(body) else {
        return message(
            context,
            &session,
            context.account.text.password_mismatch(),
            StatusCode::BAD_REQUEST,
            now,
        )
        .await;
    };
    if !checked_csrf(&session, CSRF_SEPARATOR, &form.csrf) {
        return message(
            context,
            &session,
            context.account.text.password_mismatch(),
            StatusCode::BAD_REQUEST,
            now,
        )
        .await;
    }
    if !fresh(&session, now) {
        return begin(
            &context.account,
            FirstPartyDestination::AccountPassword,
            now,
        )
        .await;
    }

    let Some(passwords) = context.passwords else {
        tracing::error!(
            tenant = %context.account.tenant.id,
            "the password page was submitted to with no password method configured"
        );
        return error_page(&context.account, StatusCode::NOT_IMPLEMENTED);
    };
    let user = UserId::new(session.user);

    if form.password != form.confirmation {
        return message(
            context,
            &session,
            context.account.text.password_mismatch(),
            StatusCode::BAD_REQUEST,
            now,
        )
        .await;
    }

    // Whether this is a change or a first setting is decided here and not by
    // the body: a submission that simply omitted `current_password` must not
    // turn a change into a setting.
    let held = match passwords.has_password(*user.as_uuid()).await {
        Ok(held) => held,
        Err(error) => {
            tracing::error!(%error, tenant = %context.account.tenant.id, "cannot read a password credential");
            return error_page(&context.account, StatusCode::SERVICE_UNAVAILABLE);
        }
    };
    if held && !self::current_matches(context, &user, form.current.as_deref()).await {
        record_refusal(context, &session, now).await;
        return message(
            context,
            &session,
            context.account.text.password_wrong_current(),
            StatusCode::FORBIDDEN,
            now,
        )
        .await;
    }

    written(context, &session, passwords, &form, held, now).await
}

/// Everything a password change entails, once it has been allowed.
///
/// Split from [`submit`] because [`submit`] is a list of refusals and this is
/// the one path that writes: the policy gate, the credential, the trail, the
/// receivers, the account's own message and — only if the box was ticked — the
/// other sessions. In that order, and the order is the point: nothing is
/// announced before the write that makes it true, and nothing is rolled back
/// because an announcement failed.
async fn written(
    context: &PasswordContext<'_>,
    session: &Session,
    passwords: &PgPasswordVerifier,
    form: &NewPassword,
    held: bool,
    now: OffsetDateTime,
) -> Response {
    // The same gate the recovery form and the deployment admin's password go
    // through (`ast-895`): NIST SP 800-63B §5.1.1.2's length floor and the
    // deny list compiled into this binary. One rule, one place.
    let Ok(accepted) = AcceptedPassword::accept_locally(&form.password) else {
        return message(
            context,
            session,
            context.account.text.password_refused(),
            StatusCode::BAD_REQUEST,
            now,
        )
        .await;
    };

    let user = UserId::new(session.user);
    let credential = match passwords
        .set_password(*user.as_uuid(), accepted.expose())
        .await
    {
        Ok(credential) => credential,
        Err(error) => {
            tracing::error!(%error, tenant = %context.account.tenant.id, "cannot write a password");
            return error_page(&context.account, StatusCode::SERVICE_UNAVAILABLE);
        }
    };

    record(context, session, credential, held, now).await;
    // CAEP §3.3: `create` for a first password, `update` for a replacement.
    // The distinction is what tells a receiver whether a factor appeared or
    // moved.
    account::emit_signal(
        &context.account,
        &context.signals,
        &crate::ssf::Cause::CredentialChange {
            user,
            change: caep::CredentialChange::new(
                caep::CredentialType::Password,
                if held {
                    caep::ChangeType::Update
                } else {
                    caep::ChangeType::Create
                },
            ),
            initiator: caep::InitiatingEntity::User,
        },
        now,
    )
    .await;
    notify_owner(context, user).await;

    if form.sign_out_others {
        close_the_others(context, session, now).await;
    }

    let sentence = if held {
        context.account.text.password_changed()
    } else {
        context.account.text.password_was_set()
    };
    message(context, session, sentence, StatusCode::OK, now).await
}

/// Whether the submitted current password is this account's.
///
/// A missing field and a wrong one are one answer, for the reason
/// [`crate::http::account_passkeys`] gives about its own: the difference is
/// only interesting to somebody who is guessing.
async fn current_matches(
    context: &PasswordContext<'_>,
    user: &UserId,
    current: Option<&str>,
) -> bool {
    let (Some(passwords), Some(current)) = (context.passwords, current) else {
        return false;
    };
    if current.is_empty() {
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
        asterius_domain::Secret::new(current.to_owned()),
    )
    .await
    {
        // The verifier answers with the account the credential belongs to, and
        // it has to be *this* account.
        Ok(Some(verified)) => verified == *user.as_uuid(),
        Ok(None) => false,
        Err(error) => {
            tracing::error!(%error, tenant = %context.account.tenant.id, "cannot verify a password");
            false
        }
    }
}

/// Closes every live session of this account except the one submitting.
///
/// The box the person ticked. The revocation reason is
/// [`SessionRevocation::CredentialChange`], which is what those sessions are:
/// every one of them predates the password that is now in force.
async fn close_the_others(context: &PasswordContext<'_>, session: &Session, now: OffsetDateTime) {
    let digests = match context
        .sessions
        .live_digests_for_user(session.user, now)
        .await
    {
        Ok(digests) => digests,
        Err(error) => {
            tracing::error!(%error, tenant = %context.account.tenant.id, "cannot list live sessions");
            return;
        }
    };
    for digest in digests {
        if digest == session.id_digest {
            continue;
        }
        let named = match context.sessions.find(&digest).await {
            Ok(Some(named)) => named,
            Ok(None) => continue,
            Err(error) => {
                tracing::error!(%error, tenant = %context.account.tenant.id, "cannot read a session");
                continue;
            }
        };
        if let Err(error) = context
            .sessions
            .revoke(&digest, SessionRevocation::CredentialChange, now)
            .await
        {
            tracing::error!(%error, tenant = %context.account.tenant.id, "cannot revoke a session");
            continue;
        }
        // The same two notifications the session page sends, because it is the
        // same act: the relying parties are told (Back-Channel Logout 1.0
        // §2.2) and the streams get CAEP `session-revoked`.
        let participants = context
            .sessions
            .participants(&digest)
            .await
            .unwrap_or_default();
        if !participants.is_empty() {
            let notifier = crate::backchannel::Notifier {
                tenant: context.account.tenant,
                clients: context.signals.clients,
                subjects: context.signals.subjects,
                signer: context.signals.signer,
                outbox: context.signals.outbox,
            };
            notifier.notify(&named, &participants, now).await;
        }
        account::emit_signal(
            &context.account,
            &context.signals,
            &crate::ssf::Cause::SessionRevoked {
                user: UserId::new(named.user),
                sid: named.public_sid.clone(),
                initiator: caep::InitiatingEntity::User,
            },
            now,
        )
        .await;
    }
}

/// Tells the account that its credential changed.
///
/// The message `crate::http::recovery` sends for the same reason: it is how
/// somebody learns their account was taken while they still could have stopped
/// it. An account with no address gets nothing — there is nowhere to send it,
/// and inventing one would be worse.
async fn notify_owner(context: &PasswordContext<'_>, user: UserId) {
    let address = match context.users.by_id(user).await {
        Ok(Some(account)) => account.email,
        Ok(None) => None,
        Err(error) => {
            tracing::error!(%error, tenant = %context.account.tenant.id, "cannot read an account");
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
            tenant = %context.account.tenant.id,
            "cannot hand off a credential-change message"
        );
    }
}

/// The page, with whatever there is to say on it.
async fn rendered(
    context: &PasswordContext<'_>,
    session: &Session,
    message: Option<&str>,
    status: StatusCode,
    now: OffsetDateTime,
) -> Response {
    let user = UserId::new(session.user);
    let has_password = match context.passwords {
        Some(passwords) => match passwords.has_password(*user.as_uuid()).await {
            Ok(held) => held,
            Err(error) => {
                tracing::error!(%error, tenant = %context.account.tenant.id, "cannot read a password credential");
                return error_page(&context.account, StatusCode::SERVICE_UNAVAILABLE);
            }
        },
        None => false,
    };

    let message = match message {
        Some(message) => Some(message),
        None if !fresh(session, now) => Some(context.account.text.password_stale()),
        None => None,
    };

    let font_url = crate::http::font_url(&context.account.mount);
    let action = context.account.mount.absolute(PAGE_PATH);
    let sign_in_href = context.account.mount.absolute(SIGN_IN_PATH);
    let account_href = context.account.mount.absolute(account::PAGE_PATH);
    let csrf = csrf_for(session, CSRF_SEPARATOR);
    let document = Document::render(context.account.nonce, |nonce| {
        pages::render(&AccountPasswordPage {
            text: context.account.text,
            tenant_name: &context.account.tenant.display_name,
            has_password,
            action: &action,
            sign_in_href: &sign_in_href,
            account_href: &account_href,
            csrf: &csrf,
            minimum_password_length: MIN_LENGTH,
            minimum_password_length_text: MIN_LENGTH.to_string(),
            message,
            nonce_attribute: nonce_attribute(nonce),
            theme_css: "",
            brand: Brand::new(&font_url),
        })
    });
    (status, no_store(), document).into_response()
}

/// The form again, with one sentence on it.
async fn message(
    context: &PasswordContext<'_>,
    session: &Session,
    sentence: &str,
    status: StatusCode,
    now: OffsetDateTime,
) -> Response {
    rendered(context, session, Some(sentence), status, now).await
}

/// Records a password that was set or changed.
async fn record(
    context: &PasswordContext<'_>,
    session: &Session,
    credential: uuid::Uuid,
    replaced: bool,
    now: OffsetDateTime,
) {
    let subject = session.user.to_string();
    let event = AuditEvent::new(
        context.account.tenant.id.clone(),
        EventType::CREDENTIAL_CHANGED,
        Outcome::Success,
        Actor::User(subject.clone()),
        now,
    )
    .session(DomainSessionId::new(session.id_digest.clone()))
    .subject(subject)
    .detail(
        Detail::new()
            .label("kind", "password")
            .label("reason", "account_password_page")
            .label("change", if replaced { "updated" } else { "created" })
            .credential("credential_id", credential.to_string()),
    );
    if let Err(error) = context.audit.record(event).await {
        tracing::error!(
            %error,
            tenant = %context.account.tenant.id,
            "a password change was not written to the audit trail"
        );
    }
}

/// Records a change refused for want of the current password.
///
/// A failure record rather than silence: somebody trying passwords against
/// this field is somebody trying passwords, and it is what an incident review
/// would want to count.
async fn record_refusal(context: &PasswordContext<'_>, session: &Session, now: OffsetDateTime) {
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
            .label("kind", "password")
            .label("reason", "account_password_page")
            .label("change", "refused_wrong_current"),
    );
    if let Err(error) = context.audit.record(event).await {
        tracing::error!(
            %error,
            tenant = %context.account.tenant.id,
            "a refused password change was not written to the audit trail"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ordinary submission of a *change*: the current password, the new
    /// one twice, and no box ticked.
    #[test]
    fn a_change_carries_the_current_password_and_the_new_one_twice() {
        // Arrange
        let body = b"csrf=abc&current_password=old&password=new&password_confirmation=new";

        // Act
        let parsed = new_password(body);

        // Assert
        assert_eq!(
            parsed,
            Some(NewPassword {
                csrf: "abc".to_owned(),
                current: Some("old".to_owned()),
                password: "new".to_owned(),
                confirmation: "new".to_owned(),
                sign_out_others: false,
            })
        );
    }

    /// An account with no password submits none, and that is a well-formed
    /// submission: whether it is allowed is the handler's question, not the
    /// parser's.
    #[test]
    fn a_first_setting_carries_no_current_password() {
        // Arrange
        let body = b"csrf=abc&password=new&password_confirmation=new";

        // Act
        let parsed = new_password(body).expect("a well-formed submission");

        // Assert
        assert_eq!(parsed.current, None);
    }

    /// The box, when it is ticked. A browser sends `on` by default and this
    /// page sends `yes`; either means the same thing.
    #[test]
    fn a_ticked_box_asks_for_the_other_sessions_to_close() {
        // Arrange
        let body = b"csrf=abc&password=new&password_confirmation=new&sign_out_others=on";

        // Act
        let parsed = new_password(body).expect("a well-formed submission");

        // Assert
        assert!(parsed.sign_out_others);
    }

    /// RFC 6749 §3.1's parameter pollution, on the field whose value is
    /// stored: a body naming two new passwords is a body where which one is
    /// written depends on which the parser preferred.
    #[test]
    fn a_body_naming_two_new_passwords_is_refused() {
        assert_eq!(
            new_password(b"csrf=abc&password=a&password=b&password_confirmation=a"),
            None
        );
    }

    /// And on the one that is checked.
    #[test]
    fn a_body_naming_two_current_passwords_is_refused() {
        assert_eq!(
            new_password(
                b"csrf=abc&current_password=a&current_password=b&password=n&\
                  password_confirmation=n"
            ),
            None
        );
    }

    /// A submission with no new password is not a submission this page makes.
    #[test]
    fn a_body_without_a_new_password_is_refused() {
        assert_eq!(new_password(b"csrf=abc&current_password=old"), None);
    }

    /// Nor one with no confirmation: a password nobody can see is one that
    /// gets typed wrong, and the second field is the whole defence.
    #[test]
    fn a_body_without_a_confirmation_is_refused() {
        assert_eq!(new_password(b"csrf=abc&password=new"), None);
    }

    /// A submission with no token is not one this page posts.
    #[test]
    fn a_body_without_a_token_is_refused() {
        assert_eq!(
            new_password(b"password=new&password_confirmation=new"),
            None
        );
    }

    /// A body this server will not buffer is refused before it is decoded.
    #[test]
    fn an_over_long_body_is_refused() {
        // Arrange
        let body = format!(
            "csrf={}&password=new&password_confirmation=new",
            "a".repeat(MAX_BODY)
        );

        // Act & assert
        assert_eq!(new_password(body.as_bytes()), None);
    }

    /// A password longer than the policy's ceiling is refused by the parser as
    /// well, because what is bounded here is what this function allocates.
    #[test]
    fn an_over_long_password_is_refused() {
        // Arrange
        let password = "a".repeat(MAX_PASSWORD_CHARS + 1);
        let body = format!("csrf=abc&password={password}&password_confirmation={password}");

        // Act & assert
        assert_eq!(new_password(body.as_bytes()), None);
    }

    /// A form body is text; bytes that are not are refused rather than lossily
    /// decoded.
    #[test]
    fn a_body_that_is_not_text_is_refused() {
        assert_eq!(new_password(&[0xff, 0xfe, 0xfd]), None);
    }

    /// The policy is not this parser's: a short password parses, and
    /// `AcceptedPassword` is what refuses it. Two copies of that rule would be
    /// two rules.
    #[test]
    fn the_parser_does_not_apply_the_password_policy() {
        // Arrange
        let body = b"csrf=abc&password=short&password_confirmation=short";

        // Act
        let parsed = new_password(body).expect("a well-formed submission");

        // Assert
        assert_eq!(parsed.password, "short");
        assert!(AcceptedPassword::accept_locally(&parsed.password).is_err());
    }
}
