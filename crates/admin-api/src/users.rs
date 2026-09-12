//! The user screen's resources: the directory, an account's claims, its
//! credentials, its sessions and its grants.
//!
//! # Nothing here can render a credential
//!
//! The port this module's handlers hold —
//! [`asterius_domain::UserAdministration`] — answers with
//! [`asterius_domain::CredentialSummary`], which carries no password hash, no
//! public key and no signature counter, and with
//! [`asterius_domain::SessionSummary`], which carries no `id_digest`. So the
//! rendering below has nothing to redact: the material never arrives, in the
//! same way a private signing key never arrives at [`crate::keys`]. That is
//! the structural half.
//!
//! The belt to those braces is that a claim value is **operator-supplied JSON
//! stored in a `jsonb` column**, and this module hands it to a browser. Two
//! rules follow, and both are enforced below rather than remembered:
//!
//! * a claim name is [`asterius_domain::ClaimName`], which refuses `sub`,
//!   `iss`, `aud`, `acr`, `amr` and the rest of the claims the authorization
//!   server mints for itself — a bag able to hold a `sub` is a bag able to
//!   impersonate somebody;
//! * a claim set is bounded, in count and in bytes, because the body arrives
//!   from the network and "an operator pasted a megabyte" must be a 400 rather
//!   than a row every token request afterwards has to read.
//!
//! # Verification flags are two different things, deliberately
//!
//! OIDC Core §5.1 gives `email_verified` as a boolean *claim* about an
//! address, and [`asterius_domain::User`] carries it as a column beside
//! `email` for that reason. Every other claim carries its own `verified_at`
//! instead — a timestamp, not a flag — because "verified" without "when" is a
//! statement no reviewer can age out. The console edits both in one document,
//! and [`RequestedClaims`] is what makes them one write: an address and its
//! flag that could be saved separately are an address that can be marked
//! verified after it was changed.

use asterius_domain::administration::{
    CredentialSummary, PasskeySummary, PasswordReset, SessionSummary, Terminated,
};
use asterius_domain::{
    AcceptedPassword, Claim, ClaimName, ClaimSet, ClaimSource, Grant, PasswordError, Role, User,
    UserStatus,
};
use serde::Deserialize;
use serde_json::{Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::error::AdminError;

/// The most claims one account may carry through this API.
///
/// A bound and not a suggestion: the body arrives from the network, and every
/// claim in the bag is read on the `userinfo` path afterwards. Two hundred is
/// far past any profile — OIDC Core §5.1 names about twenty — and still
/// refuses a paste.
pub const MAX_CLAIMS: usize = 200;

/// The most bytes one claim's value may serialise to.
///
/// Sized for a `verified_claims` record with an evidence array (`ast-s36.5`),
/// which is the largest standard claim there is, and small enough that a
/// hundred of them is not a megabyte.
pub const MAX_CLAIM_VALUE_BYTES: usize = 8 * 1024;

/// The longest username this API will write.
///
/// The column is `text`; this is about what a login form can carry and a
/// person can type, not about storage.
pub const MAX_USERNAME_LEN: usize = 320;

/// The longest email address, which RFC 5321 §4.5.3.1.3 fixes at 320 octets.
pub const MAX_EMAIL_LEN: usize = 320;

/// One account, as the directory lists it.
///
/// No claims: a list of five hundred accounts each carrying its bag is a
/// megabyte of JSON to answer "who is in this tenant". The bag is on
/// [`document`], which is one account.
#[must_use]
pub fn summarise(user: &User) -> Value {
    json!({
        "user_id": user.id.as_uuid().to_string(),
        "username": user.username,
        "email": user.email,
        "email_verified": user.email_verified,
        "status": user.status.as_str(),
        "can_authenticate": user.can_authenticate(),
        "claims": user.claims.len(),
        "created_at": user.created_at.unix_timestamp(),
        "updated_at": user.updated_at.unix_timestamp(),
    })
}

/// One account, with its claims and each claim's provenance.
///
/// `source` and `verified_at` are rendered beside every value because an
/// operator deciding whether to trust a claim is asking exactly those two
/// questions, and a screen that showed only the value would invite them to
/// treat an imported string as a checked one.
#[must_use]
pub fn document(user: &User) -> Value {
    let mut rendered = summarise(user);
    if let Some(object) = rendered.as_object_mut() {
        object.insert("claims".to_owned(), claims_document(&user.claims));
    }
    rendered
}

/// A claim set, name by name.
#[must_use]
pub fn claims_document(claims: &ClaimSet) -> Value {
    let members: serde_json::Map<String, Value> = claims
        .iter()
        .map(|(name, claim)| {
            (
                name.as_str().to_owned(),
                json!({
                    "value": claim.value(),
                    "source": claim.source().as_str(),
                    "verified_at": claim.verified_at().map(OffsetDateTime::unix_timestamp),
                }),
            )
        })
        .collect();
    Value::Object(members)
}

/// One browser session, as the sessions tab lists it.
///
/// The `sid` and never the lookup digest — the port carries no digest, so
/// there is none here to leak. `current` is what stops an operator ending
/// their own console session by accident while reading somebody else's list.
#[must_use]
pub fn session_document(session: &SessionSummary, now: OffsetDateTime) -> Value {
    json!({
        "sid": session.public_sid,
        "created_at": session.created_at.unix_timestamp(),
        "authenticated_at": session.authenticated_at.unix_timestamp(),
        "last_seen_at": session.last_seen_at.unix_timestamp(),
        "expires_at": session.expires_at.unix_timestamp(),
        "amr": session.amr.iter().map(|method| method.as_str()).collect::<Vec<_>>(),
        "acr": session.acr,
        "live": session.is_live(now),
        "revoked_at": session.revoked.map(|(at, _)| at.unix_timestamp()),
        "revoked_reason": session.revoked.map(|(_, reason)| reason),
    })
}

/// One authorization, as the grants tab lists it.
///
/// The scopes, the client and the dates. Not the `claims` request, not the
/// `authorization_details` and not the `sub`: a grants tab answers "what has
/// this person let this client do, and since when", and the rest is a
/// per-client identifier or a document with its own screen.
#[must_use]
pub fn grant_document(grant: &Grant) -> Value {
    json!({
        "grant_id": grant.id.as_str(),
        "client_id": grant.client.as_str(),
        "scopes": grant.scopes.iter().cloned().collect::<Vec<_>>(),
        "resources": grant.resources.iter().cloned().collect::<Vec<_>>(),
        "created_at": grant.created_at.unix_timestamp(),
        "updated_at": grant.updated_at.unix_timestamp(),
        "expires_at": grant.expires_at.map(OffsetDateTime::unix_timestamp),
        "revoked_at": grant.revoked_at.map(OffsetDateTime::unix_timestamp),
    })
}

/// One passkey, as the credentials tab lists it.
#[must_use]
pub fn passkey_document(passkey: &PasskeySummary) -> Value {
    json!({
        "credential_id": passkey.id.to_string(),
        "label": passkey.label,
        "rp_id": passkey.rp_id,
        "created_at": passkey.created_at.unix_timestamp(),
        "last_used_at": passkey.last_used_at.map(OffsetDateTime::unix_timestamp),
        "disabled_at": passkey.disabled_at.map(OffsetDateTime::unix_timestamp),
    })
}

/// What this account can sign in with.
#[must_use]
pub fn credentials_document(credentials: &CredentialSummary) -> Value {
    json!({
        "password": credentials.password,
        "passkeys": credentials
            .passkeys
            .iter()
            .map(passkey_document)
            .collect::<Vec<_>>(),
    })
}

/// The receipt a revocation hands back, as the console renders it.
///
/// `logout_tokens_queued` is queued and not delivered; see
/// [`asterius_domain::administration`] for why the distinction is kept all the
/// way to the screen.
#[must_use]
pub fn termination_document(terminated: Terminated) -> Value {
    json!({
        "sessions_revoked": terminated.sessions_revoked,
        "logout_tokens_queued": terminated.logout_tokens_queued,
    })
}

/// What forcing a reset did.
#[must_use]
pub fn reset_document(reset: PasswordReset) -> Value {
    json!({
        "password_invalidated": reset.password_invalidated,
        "recovery_sent": reset.recovery_sent,
        "sessions_revoked": reset.terminated.sessions_revoked,
        "logout_tokens_queued": reset.terminated.logout_tokens_queued,
    })
}

/// Whether an account matches a search term.
///
/// Case-insensitive over the username and the address, and an empty term
/// matches everything. The same shape as [`crate::clients::matches`], and for
/// the same reason: an operator types a fragment of what they remember.
#[must_use]
pub fn matches(user: &User, term: &str) -> bool {
    if term.is_empty() {
        return true;
    }
    let needle = term.to_lowercase();
    user.username.to_lowercase().contains(&needle)
        || user
            .email
            .as_deref()
            .is_some_and(|email| email.to_lowercase().contains(&needle))
}

/// The body `POST /users` takes.
///
/// `deny_unknown_fields` because a member this build does not know is either a
/// console that has run ahead of its server or a caller guessing at a field
/// that grants something; both are worth a 400.
///
/// There is no `status`: an account is created active or it is not created.
/// An operator who wants it switched off presses the button that switches
/// accounts off, which revokes sessions and notifies relying parties — a
/// `status: "disabled"` here would be a second, quieter way to reach a state
/// with none of those effects.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestedAccount {
    /// The login identifier, unique within the tenant.
    pub username: String,
    /// The address, if there is one.
    #[serde(default)]
    pub email: Option<String>,
    /// Whether the address is known to be the person's.
    ///
    /// Defaults to `false` and has to be *asserted*: OIDC Core §5.1 makes
    /// `email_verified` a statement that the provider "has taken affirmative
    /// steps to ensure that this e-mail address was controlled by the End-User
    /// at the time the verification was performed", and a default of `true`
    /// would make that statement about every imported row.
    #[serde(default)]
    pub email_verified: bool,
    /// The initial password, if the account gets one.
    ///
    /// Optional, because the other shape is an account that enrols a passkey
    /// and never has a password. Whatever is here goes through
    /// [`AcceptedPassword::accept_locally`] — the deny list included
    /// (`ast-895`) — before anything is written.
    #[serde(default)]
    pub password: Option<String>,
    /// The claims the account starts with.
    #[serde(default)]
    pub claims: Option<serde_json::Map<String, Value>>,
}

/// The body `PUT /users/{user_id}/claims` takes.
///
/// The whole document, replaced: a `PATCH` that merged would leave a claim an
/// operator has just deleted in place, which is the failure RFC 7592 §2.2
/// names for client metadata and which is worse here — the claim being deleted
/// is often the one that was wrong.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestedClaims {
    /// The address, or `null` to remove it.
    #[serde(default)]
    pub email: Option<String>,
    /// OIDC Core §5.1's `email_verified`.
    #[serde(default)]
    pub email_verified: bool,
    /// Every other claim, by name.
    #[serde(default)]
    pub claims: serde_json::Map<String, Value>,
}

/// One claim as the console sends it.
///
/// `verified` is a boolean on the wire and a timestamp in the row: the console
/// asserts "this is checked" and the server stamps *when*, because a
/// verification time a caller chose is not evidence of anything.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestedClaim {
    value: Value,
    #[serde(default)]
    verified: bool,
}

/// The body a status change takes.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestedStatus {
    /// `true` to switch the account back on.
    #[serde(default)]
    pub enabled: bool,
}

/// The body a role change takes (`ast-3t8`).
///
/// The whole set the account should hold, not a grant and not a revoke: the
/// console renders a list of checkboxes, and a request that said "add this
/// one" would leave the screen and the row disagreeing whenever two
/// administrators pressed save at once.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestedRoles {
    /// The stored spellings of the roles, as `asterius_domain::Role` names
    /// them.
    #[serde(default)]
    pub roles: Vec<String>,
}

impl RequestedRoles {
    /// The roles asked for, refusing anything this build does not know.
    ///
    /// # Errors
    ///
    /// [`AdminError::Invalid`] for a spelling that is not a role, and for a
    /// role named twice — which is a console sending a set it did not build,
    /// and answering "done" to it would be answering about a different
    /// request.
    pub fn parse(&self) -> Result<Vec<Role>, AdminError> {
        let mut parsed = Vec::with_capacity(self.roles.len());
        for name in &self.roles {
            let role = Role::parse(name).ok_or_else(|| {
                AdminError::Invalid(format!("{name} is not a role this server knows"))
            })?;
            if parsed.contains(&role) {
                return Err(AdminError::Invalid(format!("{role} is named twice")));
            }
            parsed.push(role);
        }
        Ok(parsed)
    }
}

/// What one account administers, and what may be given to it here.
///
/// `grantable` is the list a console draws its checkboxes from, and it is the
/// server's answer rather than a constant the console keeps: a deployment-wide
/// role is only offerable to a caller who already holds authority over the
/// deployment, and a console with its own copy of that rule would draw a box
/// whose save is a 403.
#[must_use]
pub fn roles_document(held: &[Role], deployment_wide: bool) -> Value {
    let grantable: Vec<&str> = Role::ALL
        .into_iter()
        .filter(|role| deployment_wide || !role.needs_the_reserved_tenant())
        .map(Role::as_str)
        .collect();

    json!({
        "roles": held.iter().map(|role| role.as_str()).collect::<Vec<_>>(),
        "grantable": grantable,
    })
}

/// Checks a username.
///
/// # Errors
///
/// [`AdminError::Invalid`] for an empty username, one over
/// [`MAX_USERNAME_LEN`], or one carrying control characters — which are
/// invisible in every console and are how two accounts come to look identical.
pub fn accept_username(raw: &str) -> Result<String, AdminError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(AdminError::Invalid("username must not be empty".to_owned()));
    }
    if trimmed.chars().count() > MAX_USERNAME_LEN {
        return Err(AdminError::Invalid(format!(
            "username must be at most {MAX_USERNAME_LEN} characters"
        )));
    }
    if trimmed.chars().any(char::is_control) {
        return Err(AdminError::Invalid(
            "username must not carry control characters".to_owned(),
        ));
    }
    Ok(trimmed.to_owned())
}

/// Checks an address.
///
/// Deliberately shallow. RFC 5322 addresses are not a thing to validate with a
/// regular expression, and the only proof an address belongs to somebody is a
/// message they answered — which is what `email_verified` records and this
/// function does not pretend to. What is checked is what a wrong answer would
/// cost: an empty string, a length past RFC 5321's limit, whitespace or
/// control characters, and the absence of an `@`.
///
/// # Errors
///
/// [`AdminError::Invalid`] naming which of those it was.
pub fn accept_email(raw: &str) -> Result<String, AdminError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(AdminError::Invalid(
            "email must not be empty; omit it instead".to_owned(),
        ));
    }
    if trimmed.len() > MAX_EMAIL_LEN {
        return Err(AdminError::Invalid(format!(
            "email must be at most {MAX_EMAIL_LEN} octets"
        )));
    }
    if trimmed.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(AdminError::Invalid(
            "email must not carry whitespace".to_owned(),
        ));
    }
    let (local, domain) = trimmed
        .rsplit_once('@')
        .ok_or_else(|| AdminError::Invalid("email must carry an @".to_owned()))?;
    if local.is_empty() || domain.is_empty() || !domain.contains('.') {
        return Err(AdminError::Invalid(
            "email must name a local part and a domain".to_owned(),
        ));
    }
    Ok(trimmed.to_owned())
}

/// Applies policy to a password the console typed.
///
/// Through [`AcceptedPassword::accept_locally`], which is the deny list this
/// binary carries and the length floor of NIST SP 800-63B §5.1.1.2 — the same
/// call the recovery form and the deployment-admin seed make. A console with
/// rules of its own would be a second policy, and the second policy is always
/// the weaker one.
///
/// # Errors
///
/// [`AdminError::Invalid`] carrying the policy's own words. Unlike a sign-in
/// form, an administrator creating an account *should* be told why a password
/// was refused: there is no account to enumerate, and "refused" with no reason
/// is how somebody ends up trying `Password1!` six times.
pub fn accept_password(raw: &str) -> Result<AcceptedPassword, AdminError> {
    AcceptedPassword::accept_locally(raw)
        .map_err(|error: PasswordError| AdminError::Invalid(error.to_string()))
}

/// Reads a claim bag off the wire.
///
/// Every name goes through [`ClaimName::parse`], so the claims this server
/// mints for itself and the two that live in columns are refused here rather
/// than shadowed in the bag. Every value is bounded and goes through
/// [`Claim::new`], which refuses `null` and the `serde_json` sentinels.
///
/// `now` stamps the claims the caller marked verified; see `RequestedClaim`
/// for why the caller does not get to choose the instant.
///
/// # Errors
///
/// [`AdminError::Invalid`] naming the claim that was wrong, because an
/// operator editing twenty claims needs to know which one to fix.
// fuzz-target: admin_user_claims
pub fn accept_claims(
    members: &serde_json::Map<String, Value>,
    now: OffsetDateTime,
) -> Result<ClaimSet, AdminError> {
    if members.len() > MAX_CLAIMS {
        return Err(AdminError::Invalid(format!(
            "an account may carry at most {MAX_CLAIMS} claims"
        )));
    }

    let mut claims = ClaimSet::new();
    for (name, body) in members {
        let name = ClaimName::parse(name)
            .map_err(|error| AdminError::Invalid(format!("{name}: {error}")))?;
        let requested: RequestedClaim = serde_json::from_value(body.clone())
            .map_err(|error| AdminError::Invalid(format!("{}: {error}", name.as_str())))?;

        // Measured on the serialised form, because that is what is stored and
        // what is later handed to a relying party. A `Value` in memory has no
        // size a bound could be stated against.
        let encoded = serde_json::to_string(&requested.value)
            .map_err(|error| AdminError::Invalid(format!("{}: {error}", name.as_str())))?;
        if encoded.len() > MAX_CLAIM_VALUE_BYTES {
            return Err(AdminError::Invalid(format!(
                "{}: a claim value must be at most {MAX_CLAIM_VALUE_BYTES} bytes",
                name.as_str()
            )));
        }

        let claim = Claim::new(requested.value, ClaimSource::Admin)
            .map_err(|error| AdminError::Invalid(format!("{}: {error}", name.as_str())))?;
        let claim = if requested.verified {
            claim.verified(now)
        } else {
            claim
        };
        claims.insert(name, claim);
    }
    Ok(claims)
}

/// The account [`RequestedAccount`] describes, ready to be written.
///
/// # Errors
///
/// [`AdminError::Invalid`] for a username, address, password or claim the
/// policy above refuses.
pub fn accept_account(
    requested: &RequestedAccount,
    tenant: &asterius_domain::TenantId,
    now: OffsetDateTime,
) -> Result<asterius_domain::NewAccount, AdminError> {
    let username = accept_username(&requested.username)?;
    let email = requested.email.as_deref().map(accept_email).transpose()?;

    // §5.1 again: a flag about an address there is none of is not a claim
    // about anything, and quietly dropping it would let a console think it had
    // saved something.
    if requested.email_verified && email.is_none() {
        return Err(AdminError::Invalid(
            "email_verified cannot be asserted without an email".to_owned(),
        ));
    }

    let password = requested
        .password
        .as_deref()
        .map(accept_password)
        .transpose()?;
    let claims = match requested.claims.as_ref() {
        Some(members) => accept_claims(members, now)?,
        None => ClaimSet::new(),
    };

    Ok(asterius_domain::NewAccount {
        user: User {
            tenant: tenant.clone(),
            id: asterius_domain::UserId::generate(),
            username,
            email,
            email_verified: requested.email_verified,
            status: UserStatus::Active,
            claims,
            created_at: now,
            updated_at: now,
        },
        password,
    })
}

/// `held`, with the claims and flags `requested` asks for.
///
/// Returns a whole [`User`] rather than mutating one, so that a refusal leaves
/// the caller holding the row it read and there is no half-applied edit to
/// write by mistake.
///
/// # Errors
///
/// [`AdminError::Invalid`] for an address or a claim the policy above refuses.
pub fn apply_claims(
    held: &User,
    requested: &RequestedClaims,
    now: OffsetDateTime,
) -> Result<User, AdminError> {
    let email = requested.email.as_deref().map(accept_email).transpose()?;
    if requested.email_verified && email.is_none() {
        return Err(AdminError::Invalid(
            "email_verified cannot be asserted without an email".to_owned(),
        ));
    }

    let claims = accept_claims(&requested.claims, now)?;
    Ok(User {
        email,
        email_verified: requested.email_verified,
        claims,
        updated_at: now,
        ..held.clone()
    })
}

/// An RFC 3339 instant, for an audit detail that a person reads.
#[must_use]
pub fn stamp(at: OffsetDateTime) -> String {
    at.format(&Rfc3339)
        .unwrap_or_else(|_| at.unix_timestamp().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use asterius_domain::{TenantId, UserId};

    fn epoch() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("a fixed instant")
    }

    fn tenant() -> TenantId {
        TenantId::parse("acme").expect("a valid tenant id")
    }

    fn a_user() -> User {
        User {
            tenant: tenant(),
            id: UserId::generate(),
            username: "ada@example.test".to_owned(),
            email: Some("ada@example.test".to_owned()),
            email_verified: true,
            status: UserStatus::Active,
            claims: ClaimSet::new(),
            created_at: epoch(),
            updated_at: epoch(),
        }
    }

    #[test]
    fn a_summary_names_the_account_and_counts_its_claims() {
        // Arrange
        let mut user = a_user();
        user.claims.insert(
            ClaimName::parse("name").expect("a claim name"),
            Claim::new(json!("Ada"), ClaimSource::Admin).expect("a claim"),
        );

        // Act
        let rendered = summarise(&user);

        // Assert
        assert_eq!(rendered["username"], json!("ada@example.test"));
        assert_eq!(rendered["status"], json!("active"));
        assert_eq!(rendered["claims"], json!(1));
    }

    /// The directory is a list, and a list that carried every bag would be a
    /// megabyte of JSON to answer "who is in this tenant".
    #[test]
    fn a_summary_carries_no_claim_values() {
        // Arrange
        let mut user = a_user();
        user.claims.insert(
            ClaimName::parse("name").expect("a claim name"),
            Claim::new(json!("Ada"), ClaimSource::Admin).expect("a claim"),
        );

        // Act
        let rendered = summarise(&user).to_string();

        // Assert
        assert!(!rendered.contains("Ada"), "{rendered}");
    }

    /// An operator deciding whether to trust a claim asks who said so and when
    /// it was last checked, so the document answers both beside every value.
    #[test]
    fn a_document_renders_each_claims_provenance() {
        // Arrange
        let mut user = a_user();
        user.claims.insert(
            ClaimName::parse("name").expect("a claim name"),
            Claim::new(json!("Ada"), ClaimSource::Admin)
                .expect("a claim")
                .verified(epoch()),
        );

        // Act
        let rendered = document(&user);

        // Assert
        assert_eq!(rendered["claims"]["name"]["value"], json!("Ada"));
        assert_eq!(rendered["claims"]["name"]["source"], json!("admin"));
        assert_eq!(
            rendered["claims"]["name"]["verified_at"],
            json!(epoch().unix_timestamp())
        );
    }

    /// OIDC Core §5.1: the provider asserts it has taken affirmative steps, so
    /// the flag is asserted and never defaulted on.
    #[test]
    fn a_created_account_is_unverified_unless_the_caller_says_otherwise() {
        // Arrange
        let requested: RequestedAccount = serde_json::from_value(json!({
            "username": "grace@example.test",
            "email": "grace@example.test",
        }))
        .expect("a body this API accepts");

        // Act
        let account =
            accept_account(&requested, &tenant(), epoch()).expect("an acceptable account");

        // Assert
        assert!(!account.user.email_verified);
    }

    #[test]
    fn a_verification_flag_without_an_address_is_refused() {
        // Arrange
        let requested: RequestedAccount = serde_json::from_value(json!({
            "username": "grace@example.test",
            "email_verified": true,
        }))
        .expect("a body this API parses");

        // Act
        let refused = accept_account(&requested, &tenant(), epoch());

        // Assert
        assert!(
            matches!(refused, Err(AdminError::Invalid(_))),
            "{refused:?}"
        );
    }

    /// `ast-895`: the deny list is not optional, and the console is not a way
    /// around it.
    #[test]
    fn a_password_on_the_deny_list_is_refused_at_creation() {
        // Arrange
        let requested: RequestedAccount = serde_json::from_value(json!({
            "username": "grace@example.test",
            "password": "password123",
        }))
        .expect("a body this API parses");

        // Act
        let refused = accept_account(&requested, &tenant(), epoch());

        // Assert
        assert!(
            matches!(refused, Err(AdminError::Invalid(_))),
            "{refused:?}"
        );
    }

    #[test]
    fn an_account_may_be_created_with_no_password_at_all() {
        // Arrange
        let requested: RequestedAccount = serde_json::from_value(json!({
            "username": "grace@example.test",
        }))
        .expect("a body this API parses");

        // Act
        let account =
            accept_account(&requested, &tenant(), epoch()).expect("an acceptable account");

        // Assert
        assert!(account.password.is_none());
        assert_eq!(account.user.status, UserStatus::Active);
    }

    /// A bag able to hold a `sub` is a bag able to impersonate somebody, and
    /// [`ClaimName::parse`] is where that is refused.
    #[test]
    fn a_claim_the_authorization_server_mints_cannot_be_written_by_hand() {
        // Arrange
        let members =
            serde_json::Map::from_iter([("sub".to_owned(), json!({"value": "somebody"}))]);

        // Act
        let refused = accept_claims(&members, epoch());

        // Assert
        assert!(
            matches!(refused, Err(AdminError::Invalid(_))),
            "{refused:?}"
        );
    }

    /// `email` lives in a column, and a claim of the same name in the bag
    /// would be a second answer to the same question.
    #[test]
    fn a_claim_that_shadows_a_column_is_refused() {
        // Arrange
        let members =
            serde_json::Map::from_iter([("email".to_owned(), json!({"value": "a@b.test"}))]);

        // Act / Assert
        assert!(matches!(
            accept_claims(&members, epoch()),
            Err(AdminError::Invalid(_))
        ));
    }

    /// The caller says "checked"; the server says when. A verification time a
    /// caller chose is not evidence of anything.
    #[test]
    fn a_claim_marked_verified_is_stamped_by_the_server() {
        // Arrange
        let members = serde_json::Map::from_iter([(
            "name".to_owned(),
            json!({"value": "Ada", "verified": true}),
        )]);

        // Act
        let claims = accept_claims(&members, epoch()).expect("acceptable claims");

        // Assert
        let name = ClaimName::parse("name").expect("a claim name");
        assert_eq!(
            claims.get(&name).and_then(Claim::verified_at),
            Some(epoch())
        );
    }

    #[test]
    fn a_claim_not_marked_verified_carries_no_timestamp() {
        // Arrange
        let members = serde_json::Map::from_iter([("name".to_owned(), json!({"value": "Ada"}))]);

        // Act
        let claims = accept_claims(&members, epoch()).expect("acceptable claims");

        // Assert
        let name = ClaimName::parse("name").expect("a claim name");
        assert_eq!(claims.get(&name).and_then(Claim::verified_at), None);
    }

    #[test]
    fn a_claim_this_server_stores_is_asserted_by_the_administrator() {
        // Arrange
        let members = serde_json::Map::from_iter([("name".to_owned(), json!({"value": "Ada"}))]);

        // Act
        let claims = accept_claims(&members, epoch()).expect("acceptable claims");

        // Assert
        let name = ClaimName::parse("name").expect("a claim name");
        assert_eq!(
            claims.get(&name).map(Claim::source),
            Some(&ClaimSource::Admin)
        );
    }

    /// The body arrives from the network: "an operator pasted a megabyte" is a
    /// 400 and not a row every token request afterwards has to read.
    #[test]
    fn a_claim_value_past_the_bound_is_refused() {
        // Arrange
        let oversized = "x".repeat(MAX_CLAIM_VALUE_BYTES + 1);
        let members =
            serde_json::Map::from_iter([("name".to_owned(), json!({"value": oversized}))]);

        // Act / Assert
        assert!(matches!(
            accept_claims(&members, epoch()),
            Err(AdminError::Invalid(_))
        ));
    }

    #[test]
    fn more_claims_than_the_bound_allows_are_refused() {
        // Arrange
        let members: serde_json::Map<String, Value> = (0..=MAX_CLAIMS)
            .map(|index| (format!("claim_{index}"), json!({"value": index})))
            .collect();

        // Act / Assert
        assert!(matches!(
            accept_claims(&members, epoch()),
            Err(AdminError::Invalid(_))
        ));
    }

    /// OIDC Core §5.3.2: a claim that is not available is omitted rather than
    /// returned empty, so a stored `null` is a claim that means nothing.
    #[test]
    fn a_null_claim_value_is_refused() {
        // Arrange
        let members = serde_json::Map::from_iter([("name".to_owned(), json!({"value": null}))]);

        // Act / Assert
        assert!(matches!(
            accept_claims(&members, epoch()),
            Err(AdminError::Invalid(_))
        ));
    }

    /// A whole-document replacement, for the reason RFC 7592 §2.2 gives: the
    /// claim being deleted is often the one that was wrong.
    #[test]
    fn saving_claims_replaces_the_set_rather_than_merging_it() {
        // Arrange
        let mut held = a_user();
        held.claims.insert(
            ClaimName::parse("nickname").expect("a claim name"),
            Claim::new(json!("Addie"), ClaimSource::Admin).expect("a claim"),
        );
        let requested: RequestedClaims = serde_json::from_value(json!({
            "email": "ada@example.test",
            "email_verified": true,
            "claims": {"name": {"value": "Ada"}},
        }))
        .expect("a body this API accepts");

        // Act
        let saved = apply_claims(&held, &requested, epoch()).expect("an acceptable edit");

        // Assert
        let nickname = ClaimName::parse("nickname").expect("a claim name");
        assert_eq!(saved.claims.get(&nickname), None);
        assert_eq!(saved.claims.len(), 1);
    }

    /// The address and its flag are one write, so an address cannot be changed
    /// while a flag from the previous one survives.
    #[test]
    fn changing_an_address_and_its_flag_is_one_document() {
        // Arrange
        let held = a_user();
        let requested: RequestedClaims = serde_json::from_value(json!({
            "email": "ada@newmail.test",
            "email_verified": false,
            "claims": {},
        }))
        .expect("a body this API accepts");

        // Act
        let saved = apply_claims(&held, &requested, epoch()).expect("an acceptable edit");

        // Assert
        assert_eq!(saved.email.as_deref(), Some("ada@newmail.test"));
        assert!(!saved.email_verified);
    }

    #[test]
    fn a_member_this_build_does_not_know_is_refused_rather_than_ignored() {
        // Arrange / Act
        let refused = serde_json::from_value::<RequestedAccount>(json!({
            "username": "grace@example.test",
            "is_admin": true,
        }));

        // Assert
        assert!(refused.is_err());
    }

    #[test]
    fn an_email_with_no_at_sign_is_refused() {
        assert!(matches!(
            accept_email("nobody.example.test"),
            Err(AdminError::Invalid(_))
        ));
    }

    #[test]
    fn an_email_with_a_domain_that_is_not_one_is_refused() {
        assert!(matches!(
            accept_email("nobody@localhost"),
            Err(AdminError::Invalid(_))
        ));
    }

    #[test]
    fn a_username_carrying_a_control_character_is_refused() {
        assert!(matches!(
            accept_username("ada\u{0}root"),
            Err(AdminError::Invalid(_))
        ));
    }

    #[test]
    fn a_search_term_matches_the_username_and_the_address() {
        // Arrange
        let user = a_user();

        // Act / Assert
        assert!(matches(&user, ""));
        assert!(matches(&user, "ADA"));
        assert!(matches(&user, "example.test"));
        assert!(!matches(&user, "grace"));
    }

    /// The lookup digest is the value `SessionRepository::find` takes; the port
    /// does not carry one, and this is the test that fails if a future
    /// rendering starts.
    #[test]
    fn a_session_is_rendered_by_its_sid_and_nothing_else_identifies_it() {
        // Arrange
        let session = SessionSummary {
            public_sid: "sid-1".to_owned(),
            created_at: epoch(),
            authenticated_at: epoch(),
            last_seen_at: epoch(),
            expires_at: epoch() + time::Duration::hours(8),
            amr: vec![asterius_domain::AuthenticationMethod::Password],
            acr: None,
            revoked: None,
        };

        // Act
        let rendered = session_document(&session, epoch());

        // Assert
        assert_eq!(rendered["sid"], json!("sid-1"));
        assert_eq!(rendered["live"], json!(true));
        assert_eq!(rendered["revoked_at"], Value::Null);
    }

    #[test]
    fn a_revoked_session_is_not_live_and_says_why() {
        // Arrange
        let session = SessionSummary {
            public_sid: "sid-1".to_owned(),
            created_at: epoch(),
            authenticated_at: epoch(),
            last_seen_at: epoch(),
            expires_at: epoch() + time::Duration::hours(8),
            amr: Vec::new(),
            acr: None,
            revoked: Some((epoch(), "administrative")),
        };

        // Act
        let rendered = session_document(&session, epoch());

        // Assert
        assert_eq!(rendered["live"], json!(false));
        assert_eq!(rendered["revoked_reason"], json!("administrative"));
    }

    /// The count is queued rows and not acknowledgements; the name says so and
    /// the screen repeats it.
    #[test]
    fn a_termination_reports_what_was_queued() {
        // Arrange
        let terminated = Terminated {
            sessions_revoked: 2,
            logout_tokens_queued: 3,
        };

        // Act
        let rendered = termination_document(terminated);

        // Assert
        assert_eq!(rendered["sessions_revoked"], json!(2));
        assert_eq!(rendered["logout_tokens_queued"], json!(3));
    }

    #[test]
    fn a_credentials_document_carries_no_material() {
        // Arrange
        let credentials = CredentialSummary {
            password: true,
            passkeys: vec![PasskeySummary {
                id: uuid::Uuid::nil(),
                label: Some("phone".to_owned()),
                rp_id: "as.example".to_owned(),
                aaguid: None,
                created_at: epoch(),
                last_used_at: None,
                disabled_at: None,
            }],
        };

        // Act
        let rendered = credentials_document(&credentials).to_string();

        // Assert
        assert!(rendered.contains("phone"));
        assert!(!rendered.contains("public_key"));
        assert!(!rendered.contains("sign_count"));
        assert!(!rendered.contains("password_hash"));
    }
}
