//! Self-service account creation: the write half of `prompt=create`.
//!
//! OpenID Connect Prompt Create 1.0 §3 lets a client say "this person does not
//! have an account yet". The stage machine in `asterius_web::interaction` turns
//! that into [`Stage::Register`](asterius_web::interaction::Stage::Register) and
//! `http::interaction` draws the page; what is here is the part that writes a
//! row, and it is separate because it is the part that has to be read
//! carefully.
//!
//! # The boundary this moved
//!
//! Before this module, every row in `users` was put there by an administrator,
//! by a seed, or by an import. After it — and only for a tenant that switched
//! [`Feature::SelfRegistration`](asterius_domain::Feature::SelfRegistration) on
//! — anybody who can reach the authorization endpoint can create one. See
//! `docs/threat-model.md`, "Self-registration".
//!
//! What follows from that, and lives here:
//!
//! * **The flag is checked where the row is written**, not only where the
//!   `prompt` value is parsed. A registrar is `None` for a tenant that has the
//!   feature off, so there is no state in which the page could be reached and
//!   the write still happen.
//! * **A creation is never a replacement.** The username is looked up first and
//!   a taken one is refused, which is the same guard `crate::admin` puts in
//!   front of an administrator's creation: `upsert` is create-or-replace, and a
//!   sign-up form that could replace is a sign-up form that hands over
//!   somebody's account.
//! * **One refusal for a taken username and a taken address.** The two are one
//!   [`SignupRefusal::Taken`], with one sentence, so the form says whether
//!   *something* is in use and not which. A sign-up page cannot avoid
//!   disclosing that much — it has to refuse a duplicate to work at all — but it
//!   does not have to hand out an address checker as well.
//! * **The address starts unverified.** `email_verified` is `false` at
//!   creation, whatever the person typed, because OIDC Core §5.1 makes the
//!   claim an assertion that the provider verified the address and nothing has
//!   yet.

use asterius_domain::{
    AcceptedRegistration, Claim, ClaimName, ClaimSet, ClaimSource, DomainError, NewAccount, Tenant,
    User, UserId, UserStatus,
};
use time::OffsetDateTime;

/// The `preferred_username` claim name (OIDC Core §5.1).
///
/// Parsed rather than written into the bag as a string: `ClaimName::parse` is
/// what refuses a name the server issues about the exchange, and going through
/// it here means the display name cannot become a `sub` by way of a constant
/// somebody edited.
const PREFERRED_USERNAME: &str = "preferred_username";

/// Why a sign-up did not become an account.
///
/// Deliberately three variants and not the store's error: what a page may say
/// is not what a log may say. [`Self::Taken`] is the only one a visitor is told
/// anything about, and even that one does not name the field.
#[derive(Debug)]
pub enum SignupRefusal {
    /// Something on the form is already in use — the username, the address, or
    /// both. One variant on purpose; see the module documentation.
    Taken,
    /// This deployment cannot store a password, so it cannot create an account
    /// that anybody could sign into afterwards.
    ///
    /// A wiring fault rather than a request fault: the tenant advertised
    /// `create` in its discovery document, so something is misconfigured and
    /// the operator has to see it.
    NoPasswordMethod,
    /// The write failed.
    Storage(DomainError),
}

/// Where a self-service account gets written.
///
/// Holds borrowed handles rather than owning anything, like every other
/// per-request context in this crate: it is built inside a handler from the
/// tenant's scope and dropped with the response.
pub struct Registrar<'a> {
    /// This tenant's accounts.
    pub users: &'a asterius_store_pg::PgUserRepository,
    /// How the initial password is hashed and stored.
    ///
    /// `None` is a deployment with no password method. Registration then
    /// refuses rather than writing an account nobody can use.
    pub passwords: Option<&'a asterius_store_pg::PgPasswordVerifier>,
}

impl std::fmt::Debug for Registrar<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Registrar").finish_non_exhaustive()
    }
}

impl Registrar<'_> {
    /// Turns an accepted form into an account and its password.
    ///
    /// The order is the order that cannot leave a half-made account signable
    /// into: the two uniqueness reads, then the row, then the credential. A
    /// failure after the row leaves an account with no password, which is the
    /// shape a passkey-only account has and which nobody can authenticate as.
    ///
    /// # Errors
    ///
    /// [`SignupRefusal`], as documented on the variants.
    pub async fn create(
        &self,
        tenant: &Tenant,
        accepted: &AcceptedRegistration,
        now: OffsetDateTime,
    ) -> Result<User, SignupRefusal> {
        let Some(passwords) = self.passwords else {
            return Err(SignupRefusal::NoPasswordMethod);
        };

        // Both reads before either write, and both refused the same way. The
        // unique indexes behind them are the real guarantee — two sign-ups
        // racing here both pass and one loses at the insert — which is why the
        // insert's own conflict is mapped to the same refusal below.
        if self
            .users
            .find_by_username(accepted.username())
            .await
            .map_err(SignupRefusal::Storage)?
            .is_some()
            || self
                .users
                .find_by_email(accepted.email())
                .await
                .map_err(SignupRefusal::Storage)?
                .is_some()
        {
            return Err(SignupRefusal::Taken);
        }

        let user = User {
            tenant: tenant.id.clone(),
            id: UserId::generate(),
            username: accepted.username().to_owned(),
            email: Some(accepted.email().to_owned()),
            // OIDC Core §5.1: the claim says the provider verified the
            // address. Nothing has. `ast-2vk.8`'s verification half is what
            // turns this true.
            email_verified: false,
            status: UserStatus::Active,
            claims: claims_of(accepted),
            created_at: now,
            updated_at: now,
        };

        match self.users.upsert(&user).await {
            Ok(()) => {}
            // The race the two reads above cannot close.
            Err(DomainError::Conflict(_)) => return Err(SignupRefusal::Taken),
            Err(error) => return Err(SignupRefusal::Storage(error)),
        }

        passwords
            .set_password(*user.id.as_uuid(), accepted.password().expose())
            .await
            .map_err(SignupRefusal::Storage)?;

        Ok(user)
    }
}

/// The claim bag a sign-up produces.
///
/// One claim at most, and only when the person typed a display name.
/// [`ClaimSource::Local`] because this deployment is where it came from, and no
/// `verified_at`: a name somebody typed about themselves is not a verified
/// claim, it is a preference (OIDC Core §5.1 — RPs "MUST NOT rely upon this
/// value being unique").
fn claims_of(accepted: &AcceptedRegistration) -> ClaimSet {
    let mut claims = ClaimSet::new();
    if let Some(display_name) = accepted.display_name()
        && let Ok(name) = ClaimName::parse(PREFERRED_USERNAME)
        && let Ok(claim) = Claim::new(
            serde_json::Value::String(display_name.to_owned()),
            ClaimSource::Local,
        )
    {
        claims.insert(name, claim);
    }
    claims
}

/// What a [`User`] should be called on a screen.
///
/// The `preferred_username` claim when there is one, and the login identifier
/// otherwise. One function, because `StoredState::signed_in_as` is one field
/// and `ast-bo5` is about not opening a second: the password path and the
/// passkey path both name a person through this.
#[must_use]
pub fn display_name(user: &User) -> &str {
    ClaimName::parse(PREFERRED_USERNAME)
        .ok()
        .and_then(|name| user.claims.get(&name))
        .and_then(|claim| claim.value().as_str())
        .unwrap_or(&user.username)
}

/// The [`NewAccount`] shape, for the administration port.
///
/// Unused by the handler — which writes through [`Registrar::create`] so that
/// the flag, the uniqueness guard and the audit trail are one path — and kept
/// as the conversion the admin API's own creation goes through, so the two
/// doors into `users` produce the same row from the same accepted form.
#[must_use]
pub fn new_account(
    tenant: &Tenant,
    accepted: AcceptedRegistration,
    now: OffsetDateTime,
) -> NewAccount {
    let claims = claims_of(&accepted);
    NewAccount {
        user: User {
            tenant: tenant.id.clone(),
            id: UserId::generate(),
            username: accepted.username().to_owned(),
            email: Some(accepted.email().to_owned()),
            email_verified: false,
            status: UserStatus::Active,
            claims,
            created_at: now,
            updated_at: now,
        },
        password: Some(accepted.into_password()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn accepted(display_name: Option<&str>) -> AcceptedRegistration {
        AcceptedRegistration::accept(
            "ada",
            display_name,
            "ada@example.test",
            "correct horse battery staple",
        )
        .expect("a well-formed sign-up")
    }

    fn user_with(claims: ClaimSet) -> User {
        User {
            tenant: asterius_domain::TenantId::new("demo"),
            id: UserId::generate(),
            username: "ada".to_owned(),
            email: None,
            email_verified: false,
            status: UserStatus::Active,
            claims,
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    #[test]
    fn a_display_name_becomes_the_preferred_username_claim() {
        // Arrange
        let form = accepted(Some("Ada L."));

        // Act
        let claims = claims_of(&form);

        // Assert
        let name = ClaimName::parse(PREFERRED_USERNAME).expect("a claim name");
        assert_eq!(
            claims.get(&name).map(Claim::value),
            Some(&serde_json::Value::String("Ada L.".to_owned()))
        );
    }

    #[test]
    fn a_sign_up_without_a_display_name_stores_no_claim() {
        // Arrange
        let form = accepted(None);

        // Act
        let claims = claims_of(&form);

        // Assert
        assert!(claims.is_empty());
    }

    /// `ast-pew`: the login identifier is not a display preference, so it is
    /// what a screen falls back to and never what `preferred_username` is
    /// projected from.
    #[test]
    fn a_screen_names_the_display_name_when_there_is_one() {
        // Arrange
        let named = user_with(claims_of(&accepted(Some("Ada L."))));
        let unnamed = user_with(claims_of(&accepted(None)));

        // Act & Assert
        assert_eq!(display_name(&named), "Ada L.");
        assert_eq!(display_name(&unnamed), "ada");
    }
}
