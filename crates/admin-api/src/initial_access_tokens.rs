//! The initial access token screen's resources: the tenant's tokens, and the
//! one body the console posts to mint another (`ast-cu3`).
//!
//! # The console is now an issuer of credentials
//!
//! [`crate::clients::RegistrationGate`] used to say `console_issuance: false`,
//! and the reason it gave was true: an initial access token was a string in a
//! configuration file, so there was no row to mint, expire, count or revoke.
//! There is one now, and the consequence is the one that documentation
//! predicted — an administrator holding `admin.clients:write` can mint a
//! credential that creates clients at this tenant, and can then use it outside
//! the console. `docs/threat-model.md` carries the row; what this module does
//! about it is:
//!
//! * The issuance is a **mutation**, so it goes through the same gate every
//!   other mutation does — CSRF, an `Idempotency-Key`, and an append-only
//!   audit record naming the actor.
//! * The audit record carries the label, the quota and the expiry, and
//!   **never the token**. Nothing here holds the plaintext after the response
//!   is rendered, and the store holds only its digest.
//! * The quota is not the caller's to choose. It comes from the tenant's
//!   `max_clients_per_initial_access_token`, so an administrator cannot mint an
//!   unlimited credential at a tenant whose policy says otherwise, and a policy
//!   that has been tightened applies to the next token issued.
//!
//! # Shown once
//!
//! [`issued`] is the only rendering that carries a token, and it is rendered
//! from a value the caller generated a line earlier and drops immediately
//! afterwards. [`summarise`] — what every later `GET` returns — cannot render
//! one, because [`asterius_domain::InitialAccessToken`] does not hold one.

use asterius_domain::{InitialAccessToken, MAX_INITIAL_ACCESS_TOKEN_LABEL_LEN};
use serde_json::{Value, json};
use time::OffsetDateTime;

use crate::error::AdminError;

/// The longest lifetime an administrator may ask for, in seconds.
///
/// Ninety days. An initial access token is a bearer credential that creates
/// clients, and one with a year on it is a credential nobody will remember to
/// revoke. Not a hard security boundary — the quota is what bounds the damage
/// — but a default posture that has to be re-chosen rather than drifted into.
pub const MAX_LIFETIME_SECONDS: u64 = 90 * 24 * 60 * 60;

/// What an administrator asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Requested {
    /// What to call it.
    pub label: String,
    /// How long it should live, or `None` for "until it is deleted".
    pub lifetime_seconds: Option<u64>,
}

/// Reads the body of `POST /initial-access-tokens`.
///
/// Through `Value` rather than a `#[derive(Deserialize)]` struct, for the
/// reason [`crate::clients::requested_status`] gives: serde will build a
/// struct of optional fields out of a JSON *array*, so `[]` would parse as a
/// request with no label rather than as the nonsense it is.
///
/// Note what is **not** readable here: the quota. A caller that could name its
/// own `max_uses` could mint an unlimited credential at a tenant whose policy
/// caps them, which is the setting this whole ticket exists to make real.
///
/// # Errors
///
/// [`AdminError::Invalid`] for a body that is not a JSON object, a missing or
/// empty label, a label past
/// [`asterius_domain::MAX_INITIAL_ACCESS_TOKEN_LABEL_LEN`], or a lifetime that
/// is not a positive number of seconds within [`MAX_LIFETIME_SECONDS`].
// fuzz-target: admin_initial_access_token_request
pub fn requested(body: &[u8]) -> Result<Requested, AdminError> {
    let document: Value = serde_json::from_slice(body)
        .map_err(|_| AdminError::Invalid("the request body is not valid JSON".to_owned()))?;
    let object = document
        .as_object()
        .ok_or_else(|| AdminError::Invalid("the request body is not a JSON object".to_owned()))?;

    let label = object
        .get("label")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|label| !label.is_empty())
        .ok_or_else(|| {
            AdminError::Invalid("label: a non-empty name for this token is required".to_owned())
        })?;
    if label.chars().count() > MAX_INITIAL_ACCESS_TOKEN_LABEL_LEN {
        return Err(AdminError::Invalid(format!(
            "label: at most {MAX_INITIAL_ACCESS_TOKEN_LABEL_LEN} characters"
        )));
    }

    let lifetime_seconds = match object.get("expires_in_seconds") {
        None | Some(Value::Null) => None,
        Some(value) => {
            let seconds = value.as_u64().filter(|seconds| *seconds > 0).ok_or_else(|| {
                AdminError::Invalid(
                    "expires_in_seconds: must be a positive whole number of seconds".to_owned(),
                )
            })?;
            if seconds > MAX_LIFETIME_SECONDS {
                return Err(AdminError::Invalid(format!(
                    "expires_in_seconds: at most {MAX_LIFETIME_SECONDS}"
                )));
            }
            Some(seconds)
        }
    };

    Ok(Requested {
        label: label.to_owned(),
        lifetime_seconds,
    })
}

/// One token, as the list renders it.
///
/// `remaining` is spelt out rather than left for a console to compute from
/// `uses` and `max_uses`: the saturating rule for a row edited past its ceiling
/// lives in the domain, and two implementations of it would be two answers to
/// "can this token still create a client".
#[must_use]
pub fn summarise(token: &InitialAccessToken, now: OffsetDateTime) -> Value {
    json!({
        "id": token.id.to_string(),
        "label": token.label,
        "uses": token.uses,
        "max_uses": token.max_uses,
        "remaining": token.remaining(),
        "expires_at": token.expires_at.map(OffsetDateTime::unix_timestamp),
        "created_at": token.created_at.unix_timestamp(),
        // The one field a screen actually acts on. A token can be spent, out of
        // time, or both, and an operator looking at a list wants "does this
        // still work" without reimplementing either rule.
        "usable": !token.is_exhausted(now),
    })
}

/// The response to the call that minted one: the summary, plus the credential.
///
/// The only rendering in this crate that carries a token. RFC 7591 §1.2 has no
/// opinion about how an initial access token is delivered, so this follows the
/// shape the registration access token already uses at `POST /register`: the
/// value appears in the body of the creating response and nowhere afterwards.
#[must_use]
pub fn issued(token: &InitialAccessToken, plaintext: &str, now: OffsetDateTime) -> Value {
    let mut document = summarise(token, now);
    if let Some(object) = document.as_object_mut() {
        object.insert(
            "initial_access_token".to_owned(),
            Value::String(plaintext.to_owned()),
        );
        // Stated in the document and not only in the console's copy, because a
        // client of this API that stores the response and shows it later would
        // otherwise be doing so without ever being told not to.
        object.insert("shown_once".to_owned(), Value::Bool(true));
    }
    document
}

#[cfg(test)]
mod tests {
    use super::*;
    use asterius_domain::TenantId;
    use uuid::Uuid;

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("a fixed instant")
    }

    fn token(uses: u32, max_uses: Option<u32>) -> InitialAccessToken {
        InitialAccessToken {
            id: Uuid::from_u128(0x5e_ed),
            tenant: TenantId::new("demo"),
            label: "onboarding".to_owned(),
            uses,
            max_uses,
            expires_at: None,
            created_at: now(),
        }
    }

    #[test]
    fn a_labelled_request_is_read() {
        // Arrange
        let body = br#"{"label": "onboarding", "expires_in_seconds": 3600}"#;

        // Act
        let requested = requested(body).expect("a well-formed request");

        // Assert
        assert_eq!(requested.label, "onboarding");
        assert_eq!(requested.lifetime_seconds, Some(3600));
    }

    #[test]
    fn a_request_with_no_lifetime_asks_for_none() {
        // Arrange / Act
        let requested = requested(br#"{"label": "onboarding"}"#).expect("a well-formed request");

        // Assert
        assert_eq!(requested.lifetime_seconds, None);
    }

    #[test]
    fn a_blank_label_is_refused() {
        // Arrange / Act
        let refused = requested(br#"{"label": "   "}"#);

        // Assert
        assert!(matches!(refused, Err(AdminError::Invalid(message)) if message.starts_with("label")));
    }

    #[test]
    fn a_json_array_is_not_a_request() {
        // Arrange / Act
        let refused = requested(br"[]");

        // Assert
        assert!(matches!(refused, Err(AdminError::Invalid(_))));
    }

    #[test]
    fn a_lifetime_past_the_ceiling_is_refused() {
        // Arrange
        let body = format!(
            r#"{{"label": "onboarding", "expires_in_seconds": {}}}"#,
            MAX_LIFETIME_SECONDS + 1
        );

        // Act
        let refused = requested(body.as_bytes());

        // Assert
        assert!(
            matches!(refused, Err(AdminError::Invalid(message)) if message.starts_with("expires_in_seconds"))
        );
    }

    #[test]
    fn a_negative_lifetime_is_refused() {
        // Arrange / Act
        let refused = requested(br#"{"label": "onboarding", "expires_in_seconds": -1}"#);

        // Assert
        assert!(matches!(refused, Err(AdminError::Invalid(_))));
    }

    /// The quota is the tenant's, not the caller's: a body naming one is
    /// ignored rather than obeyed.
    #[test]
    fn a_request_cannot_name_its_own_quota() {
        // Arrange / Act
        let requested =
            requested(br#"{"label": "onboarding", "max_uses": 9999}"#).expect("well formed");

        // Assert
        assert_eq!(requested.label, "onboarding");
        assert_eq!(requested.lifetime_seconds, None);
    }

    #[test]
    fn a_summary_carries_no_credential() {
        // Arrange / Act
        let rendered = summarise(&token(1, Some(3)), now());

        // Assert
        assert_eq!(rendered["remaining"], json!(2));
        assert_eq!(rendered["usable"], json!(true));
        assert!(rendered.get("initial_access_token").is_none());
    }

    #[test]
    fn a_spent_token_is_not_usable() {
        // Arrange / Act
        let rendered = summarise(&token(3, Some(3)), now());

        // Assert
        assert_eq!(rendered["remaining"], json!(0));
        assert_eq!(rendered["usable"], json!(false));
    }

    #[test]
    fn only_the_issuing_response_carries_the_token() {
        // Arrange / Act
        let rendered = issued(&token(0, Some(3)), "the-plaintext", now());

        // Assert
        assert_eq!(rendered["initial_access_token"], json!("the-plaintext"));
        assert_eq!(rendered["shown_once"], json!(true));
    }
}
