//! What an administrative session has to have proved (`ast-895`).
//!
//! ADR-0010 puts deployment authority on a *role*: a deployment admin is a
//! user of the reserved tenant holding a role whose [`RoleScope`] is the
//! deployment. That account is the most valuable one this server holds — it
//! reaches every tenant, including the ones that do not exist yet — and until
//! now the only thing standing in front of it was whatever credential the
//! login flow happened to accept, which includes a password typed into
//! whatever page the user was looking at.
//!
//! A password is not phishing-resistant, and that is not a matter of how good
//! the password is. NIST SP 800-63B §5.2.5 names the property directly —
//! "verifier impersonation resistance" — and it is a property of the
//! *protocol*: a WebAuthn assertion is signed over the origin the browser
//! actually connected to, so a relay on `asterius-idp.example.com.evil.test`
//! gets a signature that names its own origin and is worthless at the real
//! one. No amount of password entropy produces that.
//!
//! So: **a deployment-scoped role does not open the admin surface unless the
//! session's `amr` says a user-verified passkey was used.** The check is
//! policy, not schema. `Session` already carries `acr` and `amr` (ADR-0010
//! anticipated this in as many words), so nothing here needs a migration.
//!
//! # The bootstrap, which is a trust boundary and not an oversight
//!
//! `PgAdminSeed` creates the deployment admin with a password and nothing
//! else: there is no way to seed a passkey, because a passkey is produced by
//! an authenticator in front of a person, not by a configuration file. A rule
//! with no exception would therefore make every fresh deployment
//! unadministrable — the console would refuse the only account that could
//! enrol a passkey — and the usual answer to that, a break-glass flag, is a
//! permanent bypass that ships enabled.
//!
//! The exception taken here is narrower and self-closing: **an account that
//! has no enabled passkey at all is admitted on its password, and an account
//! that has one is not.** The window closes by itself the moment the admin
//! enrols, and the deployment is only ever in it between first boot and first
//! enrolment. What is *not* claimed is that the window is safe: a deployment
//! that never enrols a passkey stays in it, which is a thing an operator can
//! see and a thing `docs/threat-model.md` records.
//!
//! [`RoleScope`]: crate::RoleScope

use crate::entities::role::{Role, RoleScope};
use crate::entities::session::AuthenticationMethod;

/// Whether the account behind a session has a passkey it could have used.
///
/// An enum rather than a `bool` because the two answers mean opposite things
/// at the call site: `None` widens what is admitted, and a transposed boolean
/// argument would widen it silently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasskeyEnrolment {
    /// At least one enabled passkey is registered for this account.
    Enrolled,
    /// No enabled passkey. Either the account has never enrolled one, or the
    /// only ones it had are disabled — a credential blocked for a counter
    /// regression cannot be presented, so it cannot be what the rule demands.
    None,
}

/// What a session may do on the admin surface.
///
/// Deliberately *not* `#[non_exhaustive]`: a caller outside this crate must
/// `match` every arm, so adding a verdict is a compile error at every place
/// that acts on one rather than a wildcard that quietly admits it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminAdmission {
    /// Let it through: either no deployment-scoped role is involved, or the
    /// session proved a user-verified passkey.
    Admitted,
    /// Let it through, and say so: a deployment-scoped role admitted on a
    /// password because the account has no passkey to be asked for. The
    /// enrolment window of the module documentation.
    ///
    /// The caller is expected to record this — it is the one state in which
    /// the deployment's most privileged account is reachable with a phishable
    /// credential, and an operator should be able to find out that it lasted
    /// three months.
    AdmittedPendingEnrolment,
    /// Refuse, and send the browser to prove a passkey. The account holds one,
    /// so there is something to ask for.
    StepUpRequired,
}

/// Whether an `amr` says the authentication was phishing-resistant.
///
/// Both methods, not either. [`AuthenticationMethod::Passkey`] alone is a
/// WebAuthn assertion, which is origin-bound and so resists a relay; adding
/// [`AuthenticationMethod::UserVerified`] is what makes a stolen, unlocked
/// authenticator insufficient (WebAuthn L3 §6.1.3, the UV bit). The admin
/// surface wants both, which is exactly the default ladder's
/// `urn:asterius:acr:passkey-uv` rung — spelled here in methods rather than
/// read off `acr`, because `acr` is a *tenant's* configurable statement and
/// this rule is the deployment's.
#[must_use]
pub fn is_phishing_resistant(amr: &[AuthenticationMethod]) -> bool {
    amr.contains(&AuthenticationMethod::Passkey)
        && amr.contains(&AuthenticationMethod::UserVerified)
}

/// Whether any of these roles reaches past its own tenant.
#[must_use]
pub fn is_deployment_scoped(roles: &[Role]) -> bool {
    roles
        .iter()
        .any(|role| role.scope() == RoleScope::Deployment)
}

/// Whether the enrolment lookup is worth making.
///
/// The verdict only depends on [`PasskeyEnrolment`] in one case, and looking
/// up a user's credentials on every admin request that does not need it would
/// be a database read per request bought for nothing. A caller that skips the
/// lookup passes [`PasskeyEnrolment::None`] and gets the same answer — which
/// is a property the tests assert, so this stays an optimisation rather than a
/// second policy.
#[must_use]
pub fn enrolment_decides(roles: &[Role], amr: &[AuthenticationMethod]) -> bool {
    is_deployment_scoped(roles) && !is_phishing_resistant(amr)
}

/// Decides whether a session carrying `roles` may act on the admin surface.
///
/// `amr` is the session's own, cumulative across a step-up: a person who typed
/// a password and then presented a passkey has done both, and
/// `asterius_server::http::step_up` keeps both on the rotated session. So the
/// way out of [`AdminAdmission::StepUpRequired`] is the ordinary one — present
/// the passkey — and it does not cost the user their session.
#[must_use]
pub fn admit(
    roles: &[Role],
    amr: &[AuthenticationMethod],
    enrolment: PasskeyEnrolment,
) -> AdminAdmission {
    if !is_deployment_scoped(roles) || is_phishing_resistant(amr) {
        return AdminAdmission::Admitted;
    }

    match enrolment {
        PasskeyEnrolment::Enrolled => AdminAdmission::StepUpRequired,
        PasskeyEnrolment::None => AdminAdmission::AdmittedPendingEnrolment,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use AuthenticationMethod::{ExistingSession, OneTimeCode, Passkey, Password, UserVerified};

    /// The rule this module exists for: deployment authority on a password is
    /// not admitted while the account holds a passkey that could have been
    /// asked for.
    #[test]
    fn a_deployment_admin_signed_in_with_a_password_is_sent_to_step_up() {
        // Arrange
        let roles = [Role::DeploymentAdmin];
        let amr = [Password];

        // Act
        let admission = admit(&roles, &amr, PasskeyEnrolment::Enrolled);

        // Assert
        assert_eq!(admission, AdminAdmission::StepUpRequired);
    }

    #[test]
    fn a_deployment_admin_who_presented_a_user_verified_passkey_is_admitted() {
        // Arrange
        let roles = [Role::DeploymentAdmin];
        let amr = [Passkey, UserVerified];

        // Act
        let admission = admit(&roles, &amr, PasskeyEnrolment::Enrolled);

        // Assert
        assert_eq!(admission, AdminAdmission::Admitted);
    }

    /// A passkey with no UV proved possession of an authenticator and nothing
    /// about who was holding it.
    #[test]
    fn a_passkey_without_user_verification_is_not_enough() {
        // Arrange
        let roles = [Role::DeploymentAdmin];
        let amr = [Passkey];

        // Act
        let admission = admit(&roles, &amr, PasskeyEnrolment::Enrolled);

        // Assert
        assert_eq!(admission, AdminAdmission::StepUpRequired);
    }

    /// The seeded admin has a password and nothing else, and it is the account
    /// that would have to enrol the passkey.
    #[test]
    fn the_seeded_admin_is_admitted_until_it_has_a_passkey_to_be_asked_for() {
        // Arrange
        let roles = [Role::DeploymentAdmin];
        let amr = [Password];

        // Act
        let admission = admit(&roles, &amr, PasskeyEnrolment::None);

        // Assert
        assert_eq!(
            admission,
            AdminAdmission::AdmittedPendingEnrolment,
            "a fresh deployment would have nobody able to administer it"
        );
    }

    /// The window is not a flag: enrolling closes it, and the same session
    /// that was admitted a moment ago is not any more.
    #[test]
    fn enrolling_a_passkey_closes_the_window_for_the_session_already_open() {
        // Arrange
        let roles = [Role::DeploymentAdmin];
        let amr = [Password];

        // Act
        let before = admit(&roles, &amr, PasskeyEnrolment::None);
        let after = admit(&roles, &amr, PasskeyEnrolment::Enrolled);

        // Assert
        assert_eq!(before, AdminAdmission::AdmittedPendingEnrolment);
        assert_eq!(after, AdminAdmission::StepUpRequired);
    }

    /// The rule is about deployment scope. A tenant admin is governed by the
    /// tenant's own `acr` policy, which is a different decision in a different
    /// place, and widening this one to every role would be a policy change
    /// smuggled in as a security fix.
    #[test]
    fn a_tenant_admin_is_not_subject_to_this_rule() {
        // Arrange
        let roles = [Role::TenantAdmin];
        let amr = [Password];

        // Act
        let admission = admit(&roles, &amr, PasskeyEnrolment::Enrolled);

        // Assert
        assert_eq!(admission, AdminAdmission::Admitted);
    }

    /// Holding both roles is holding the deployment-scoped one.
    #[test]
    fn a_user_holding_both_roles_is_judged_by_the_wider_one() {
        // Arrange
        let roles = [Role::TenantAdmin, Role::DeploymentAdmin];

        // Act / Assert
        assert_eq!(
            admit(&roles, &[Password], PasskeyEnrolment::Enrolled),
            AdminAdmission::StepUpRequired
        );
    }

    /// A session resumed without re-authenticating carries `session` in its
    /// `amr` and proves nothing about a passkey.
    #[test]
    fn an_existing_session_is_not_a_phishing_resistant_authentication() {
        // Arrange / Act / Assert
        assert!(!is_phishing_resistant(&[ExistingSession]));
        assert!(!is_phishing_resistant(&[Password, OneTimeCode]));
        assert!(!is_phishing_resistant(&[UserVerified]));
        assert!(is_phishing_resistant(&[Password, Passkey, UserVerified]));
    }

    /// `enrolment_decides` is an optimisation, so it must never disagree with
    /// the verdict: wherever it says the lookup is pointless, both enrolment
    /// answers give the same admission.
    #[test]
    fn skipping_the_lookup_never_changes_the_verdict() {
        let amrs: [&[AuthenticationMethod]; 5] = [
            &[],
            &[Password],
            &[Passkey],
            &[Passkey, UserVerified],
            &[ExistingSession],
        ];
        let role_sets: [&[Role]; 4] = [
            &[],
            &[Role::TenantAdmin],
            &[Role::DeploymentAdmin],
            &[Role::TenantAdmin, Role::DeploymentAdmin],
        ];

        for roles in role_sets {
            for amr in amrs {
                if enrolment_decides(roles, amr) {
                    continue;
                }
                assert_eq!(
                    admit(roles, amr, PasskeyEnrolment::None),
                    admit(roles, amr, PasskeyEnrolment::Enrolled),
                    "the lookup was skipped for roles {roles:?} and amr {amr:?} \
                     but it would have changed the answer"
                );
            }
        }
    }

    /// A caller with no role at all is not admitted *by this module* — it is
    /// not this module's question. `Held::satisfies` is what refuses them, and
    /// this returning `Admitted` must not be read as authority.
    #[test]
    fn holding_no_role_is_not_this_modules_question() {
        assert_eq!(
            admit(&[], &[Password], PasskeyEnrolment::None),
            AdminAdmission::Admitted
        );
    }
}
