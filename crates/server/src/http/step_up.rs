//! Turning a credential that verified into the session it is worth
//! (`ast-2vk.7`).
//!
//! Two handlers reach this: the password submission in [`super::interaction`]
//! and the WebAuthn ceremony in [`super::passkeys`]. Before this module they
//! each open-coded the same three lines — mint an id, [`Session::begin`], write
//! it — and neither could do the *fourth* thing an authentication context needs,
//! which is to say which class was reached and to build on one that was reached
//! before.
//!
//! # Why a step-up rotates rather than starts again
//!
//! OIDC Core §2 makes `amr` "the methods used", plural and cumulative: a person
//! who typed a password and then presented a passkey has done both, and a
//! ladder rung phrased as a *combination* (`{Password, OneTimeCode}` — the
//! shape multi-factor takes) can only ever be reached by a session that
//! remembers the first factor while the second happens. Starting a new session
//! would throw the first factor away and make such a rung unreachable, and it
//! would also throw away `sid`, which relying parties hold and back-channel
//! logout names (`asterius_domain::Session::public_sid`).
//!
//! What is *not* kept is the identifier. A step-up is a privilege change, and a
//! privilege change with the same session id is the fixation window this server
//! closes everywhere else: the browser leaves with a value it has never held
//! before, and the old one stops resolving in the same statement
//! ([`SessionRepository::rotate`]).
//!
//! # The trust boundary this moves
//!
//! A step-up is the one place where an *existing* session is written to on the
//! strength of a credential presented now. Two things guard it, both here:
//!
//! * the interaction must already be at [`Stage::StepUp`], which only
//!   `/authorize` can set and only after [`asterius_oidc::decision::decide`]
//!   asked for it; and
//! * a usable session named by the interaction must belong to **the same
//!   user** as the credential that just verified before it can be rotated.
//!   A different federated user cannot satisfy this step-up; local credentials
//!   retain their established fresh-login fallback. A missing, expired or
//!   revoked session can start a fresh login, as happens when an initial login
//!   advances to step-up.
//!
//! See `docs/threat-model.md`, "Step-up authentication".

use asterius_domain::entities::session::SessionId;
use asterius_domain::{
    AcrPolicy, AuthenticationMethod, DomainError, Lifetimes, Session, SessionRepository, TenantId,
};
use asterius_oidc::decision::Requirements;
use asterius_web::interaction::Stage;
use time::OffsetDateTime;

/// What the caller holds, and what this needs of it.
pub(crate) struct Authentication<'a> {
    /// Where sessions live.
    pub sessions: &'a dyn SessionRepository,
    /// Which tenant a new session belongs to.
    pub tenant: &'a TenantId,
    /// The ladder this tenant can climb.
    pub acr: &'a AcrPolicy,
    /// How long a new session lives.
    pub lifetimes: Lifetimes,
}

/// A session the browser may now carry.
pub(crate) struct Established {
    /// The value for the cookie. Never stored.
    pub id: SessionId,
    /// The digest, which is what the interaction records.
    pub digest: String,
    /// Whether the resulting ACR is one of the essential values requested.
    /// False only for an initial login that must continue into step-up.
    pub essential_satisfied: bool,
}

/// Result of turning a verified credential into a session.
///
/// `Insufficient` is deliberately not an error: the credential was valid, but
/// the methods proved by it did not reach any essential ACR the client asked
/// for. Crucially, no session has been created or rotated in that case.
pub(crate) enum Establishment {
    /// The authentication met the request and was persisted.
    Established(Established),
    /// The authentication was valid but not strong enough for the request.
    Insufficient,
}

/// Records an authentication: a new session, or a step-up onto the one the
/// interaction already has.
///
/// `stage` is where the interaction was when the credential was presented, and
/// it is the only thing that permits the rotation branch. `requested` is the
/// authorization request's own statement about `acr` — read from the stored
/// parameters, so an essential value (OIDC Core §5.5.1.1) is the value written
/// onto the session and therefore the value the ID token will carry.
///
/// # Errors
///
/// Whatever the session store returns. A step-up whose rotation fails is
/// reported rather than downgraded into a fresh session: the caller's own
/// error path is the honest answer, because a browser that was told "signed in"
/// while the write failed holds a session nobody recorded.
pub(crate) async fn establish(
    context: Authentication<'_>,
    stage: Stage,
    existing: Option<&str>,
    user: uuid::Uuid,
    proved: Vec<AuthenticationMethod>,
    requested: &Requirements,
    now: OffsetDateTime,
) -> Result<Establishment, DomainError> {
    if stage == Stage::StepUp
        && let Some(digest) = existing
        && let Some(session) = context.sessions.find(digest).await?
        && session.status(now).is_usable()
    {
        // A federated callback for another account cannot complete this
        // browser's step-up or silently switch the account in its interaction.
        // Local credentials retain the established fresh-login fallback.
        if session.user == user {
            let methods = merged(&session.amr, &proved);
            let acr = context
                .acr
                .assign(&methods, &requested.essential_acr, &requested.acr_values);
            if !essential_satisfied(acr.as_deref(), requested) {
                return Ok(Establishment::Insufficient);
            }
            let id = SessionId::generate();
            context
                .sessions
                .rotate(digest, &id.digest(), &methods, acr.as_deref(), now)
                .await?;
            let digest = id.digest();
            return Ok(Establishment::Established(Established {
                id,
                digest,
                essential_satisfied: true,
            }));
        } else if proved.contains(&AuthenticationMethod::FederatedOidc) {
            return Ok(Establishment::Insufficient);
        }
    }

    let acr = context
        .acr
        .assign(&proved, &requested.essential_acr, &requested.acr_values);
    let essential_satisfied = essential_satisfied(acr.as_deref(), requested);
    if stage == Stage::StepUp && !essential_satisfied {
        return Ok(Establishment::Insufficient);
    }
    let id = SessionId::generate();
    let mut session = Session::begin(
        context.tenant.clone(),
        &id,
        user,
        proved,
        now,
        context.lifetimes,
    );
    session.acr = acr;
    context.sessions.begin(&session).await?;
    Ok(Establishment::Established(Established {
        id,
        digest: session.id_digest,
        essential_satisfied,
    }))
}

/// OIDC Core §5.5.1.1: an essential ACR is complete only when the value that
/// will be written into the ID token is one of the values the client named.
fn essential_satisfied(acr: Option<&str>, requested: &Requirements) -> bool {
    requested.essential_acr.is_empty()
        || acr.is_some_and(|value| requested.essential_acr.iter().any(|asked| asked == value))
}

/// Everything the person has now done, in the order it first happened.
///
/// A union rather than a replacement, for the reason the module documentation
/// gives: a rung phrased as a combination is only reachable if the earlier
/// factor is still counted. `ExistingSession` is dropped on the way through —
/// it means "this was not proved today", which stops being true of a session
/// somebody has just re-authenticated.
fn merged(
    already: &[AuthenticationMethod],
    just_used: &[AuthenticationMethod],
) -> Vec<AuthenticationMethod> {
    let mut methods: Vec<AuthenticationMethod> = already
        .iter()
        .copied()
        .filter(|method| *method != AuthenticationMethod::ExistingSession)
        .collect();
    for method in just_used {
        if !methods.contains(method) {
            methods.push(*method);
        }
    }
    methods
}

#[cfg(test)]
mod tests {
    use super::*;
    use asterius_domain::{ClientId, Participant, SessionRevocation};
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Debug)]
    struct Sessions {
        existing: Option<Session>,
        begins: AtomicUsize,
        rotations: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl SessionRepository for Sessions {
        async fn begin(&self, _session: &Session) -> Result<(), DomainError> {
            self.begins.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        async fn find(&self, _digest: &str) -> Result<Option<Session>, DomainError> {
            Ok(self.existing.clone())
        }

        async fn touch(
            &self,
            _digest: &str,
            _now: OffsetDateTime,
            _idle: time::Duration,
        ) -> Result<(), DomainError> {
            Ok(())
        }

        async fn rotate(
            &self,
            _old_digest: &str,
            _new_digest: &str,
            _methods: &[AuthenticationMethod],
            _acr: Option<&str>,
            _now: OffsetDateTime,
        ) -> Result<(), DomainError> {
            self.rotations.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        async fn revoke(
            &self,
            _digest: &str,
            _reason: SessionRevocation,
            _now: OffsetDateTime,
        ) -> Result<(), DomainError> {
            Ok(())
        }

        async fn revoke_all_for_user(
            &self,
            _user: uuid::Uuid,
            _reason: SessionRevocation,
            _now: OffsetDateTime,
        ) -> Result<u64, DomainError> {
            Ok(0)
        }

        async fn record_participant(
            &self,
            _digest: &str,
            _client: &ClientId,
            _now: OffsetDateTime,
        ) -> Result<(), DomainError> {
            Ok(())
        }

        async fn participants(&self, _digest: &str) -> Result<Vec<Participant>, DomainError> {
            Ok(Vec::new())
        }
    }

    #[tokio::test]
    async fn a_different_account_cannot_replace_a_usable_step_up_session() {
        let now = OffsetDateTime::UNIX_EPOCH;
        let tenant = TenantId::new("demo");
        let original = Session::begin(
            tenant.clone(),
            &SessionId::generate(),
            uuid::Uuid::from_u128(1),
            vec![AuthenticationMethod::Password],
            now,
            Lifetimes::default(),
        );
        let digest = original.id_digest.clone();
        let sessions = Sessions {
            existing: Some(original),
            begins: AtomicUsize::new(0),
            rotations: AtomicUsize::new(0),
        };
        let result = establish(
            Authentication {
                sessions: &sessions,
                tenant: &tenant,
                acr: &AcrPolicy::default(),
                lifetimes: Lifetimes::default(),
            },
            Stage::StepUp,
            Some(&digest),
            uuid::Uuid::from_u128(2),
            vec![AuthenticationMethod::FederatedOidc],
            &Requirements::default(),
            now,
        )
        .await
        .expect("the store is available");
        assert!(matches!(result, Establishment::Insufficient));
        assert_eq!(sessions.begins.load(Ordering::SeqCst), 0);
        assert_eq!(sessions.rotations.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn step_up_without_a_usable_session_can_start_a_login() {
        let now = OffsetDateTime::UNIX_EPOCH;
        let tenant = TenantId::new("demo");
        let sessions = Sessions {
            existing: None,
            begins: AtomicUsize::new(0),
            rotations: AtomicUsize::new(0),
        };
        let result = establish(
            Authentication {
                sessions: &sessions,
                tenant: &tenant,
                acr: &AcrPolicy::default(),
                lifetimes: Lifetimes::default(),
            },
            Stage::StepUp,
            None,
            uuid::Uuid::from_u128(2),
            vec![AuthenticationMethod::FederatedOidc],
            &Requirements::default(),
            now,
        )
        .await
        .expect("the store is available");
        assert!(matches!(result, Establishment::Established(_)));
        assert_eq!(sessions.begins.load(Ordering::SeqCst), 1);
        assert_eq!(sessions.rotations.load(Ordering::SeqCst), 0);
    }

    /// OIDC Core §2: `amr` is the methods used. A step-up adds to them, so a
    /// rung phrased as a combination becomes reachable.
    #[test]
    fn a_step_up_accumulates_the_methods_rather_than_replacing_them() {
        let merged = merged(
            &[AuthenticationMethod::Password],
            &[
                AuthenticationMethod::Passkey,
                AuthenticationMethod::UserVerified,
            ],
        );

        assert_eq!(
            merged,
            vec![
                AuthenticationMethod::Password,
                AuthenticationMethod::Passkey,
                AuthenticationMethod::UserVerified
            ]
        );
    }

    /// "The session was already established" is not a method any longer once
    /// the person has just proved something.
    #[test]
    fn a_resumed_session_is_not_carried_into_a_fresh_authentication() {
        let merged = merged(
            &[
                AuthenticationMethod::ExistingSession,
                AuthenticationMethod::Password,
            ],
            &[AuthenticationMethod::Passkey],
        );

        assert_eq!(
            merged,
            vec![
                AuthenticationMethod::Password,
                AuthenticationMethod::Passkey
            ]
        );
    }

    #[test]
    fn a_method_used_twice_is_recorded_once() {
        let merged = merged(
            &[AuthenticationMethod::Passkey],
            &[AuthenticationMethod::Passkey],
        );

        assert_eq!(merged, vec![AuthenticationMethod::Passkey]);
    }
}
