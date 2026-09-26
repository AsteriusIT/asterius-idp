//! Signed OpenID Provider Commands for account invalidation and deletion.
//!
//! This module sends a *fresh* command token for each delivery attempt. A
//! pre-signed token in the outbox would expire before an ordinary retry, so
//! callers must retain the command intent and re-enter this sender. RP
//! registration stores the endpoint, and the outbox worker resolves it for
//! account lifecycle intents before calling this sender.
//!
//! OpenID Provider Commands 1.0 draft 02 §§3–6 requires an explicitly typed
//! JWT, an endpoint-bound audience, and a form POST. The endpoint is checked
//! both when represented here and again at connection time by the common
//! outbound guard, including its DNS rebinding protections.

use crate::outbound::ssrf::{self, UrlRefused};
use crate::outbound::{HttpsPoster, PostError, PostRequest, PostResponse};
use asterius_domain::audit::{Actor, AuditEvent, AuditSink, Detail, EventType, Outcome};
use asterius_domain::keys::Signer;
use asterius_domain::{ClientId, DomainError, Tenant};
use time::{Duration, OffsetDateTime};

/// Draft 02 §10 recommends a lifetime of at most two minutes.
pub const COMMAND_TOKEN_LIFETIME: Duration = Duration::seconds(60);

/// The only account commands this sender can issue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountCommand {
    /// Revoke the RP's sessions, tokens, and delegated authorizations.
    Invalidate,
    /// Invalidate access and remove the RP's account data.
    Delete,
}

impl AccountCommand {
    /// The exact draft 02 command identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Invalidate => "invalidate",
            Self::Delete => "delete",
        }
    }
}

/// A client-owned endpoint to which commands may be delivered.
///
/// This type is a URL validation boundary, not a registration store. Its
/// constructor must be fed the endpoint from the RP's pinned registration;
/// a request parameter must never be used as its source.
#[derive(Clone)]
pub struct CommandEndpoint(String);

impl std::fmt::Debug for CommandEndpoint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("CommandEndpoint(<redacted>)")
    }
}

impl CommandEndpoint {
    /// Validate the registered HTTPS URL before it can become an audience.
    ///
    /// # Errors
    ///
    /// Refuses URLs with unsafe schemes, hosts, userinfo, fragments, or size.
    pub fn parse_registered(raw: &str) -> Result<Self, UrlRefused> {
        ssrf::check_url(raw)?;
        Ok(Self(raw.to_owned()))
    }

    /// The registered spelling, also used as the JWT audience.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A delivery failure. No variant includes the signed token or endpoint URL.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DeliveryError {
    /// A subject that cannot be safely used as an account identifier.
    #[error("subject must contain 1–255 non-control characters")]
    Subject,
    /// The chosen time cannot be represented with the bounded expiry.
    #[error("command token expiry is out of range")]
    Time,
    /// The tenant has no usable signing key, or the signer failed.
    #[error("command token could not be signed: {0}")]
    Signing(#[source] DomainError),
    /// The guarded HTTPS delivery failed or the RP refused the request.
    #[error("command delivery failed: {0}")]
    Post(#[from] PostError),
    /// Only 200 and 204 are accepted for synchronous Account Commands.
    #[error("RP returned unsupported success status {0}")]
    UnsupportedStatus(u16),
    /// The receiver's success body omitted required response evidence.
    #[error("RP success response is invalid: {0}")]
    InvalidResponse(&'static str),
    /// The delivery outcome could not be appended to the audit trail.
    #[error("command outcome could not be audited: {0}")]
    Audit(#[source] DomainError),
}

/// Sends a synchronous Account Command through the shared guarded POST path.
#[derive(Debug)]
pub struct Sender<'a> {
    /// The OP tenant whose published ID-token keys also sign command tokens.
    pub tenant: &'a Tenant,
    /// Tenant key signer.
    pub signer: &'a dyn Signer,
    /// Shared SSRF-guarded HTTPS poster.
    pub poster: &'a HttpsPoster,
    /// Append-only outcome trail.
    pub audit: &'a dyn AuditSink,
}

impl Sender<'_> {
    /// Mint and deliver one command to an RP's registered endpoint.
    ///
    /// `subject` must be the subject this RP knows from ID tokens, including
    /// pairwise subject resolution where applicable. A local user ID is not
    /// interchangeable with it.
    ///
    /// # Errors
    ///
    /// Returns a validation, signing, transport, response, or audit failure.
    /// On an audit failure, the command may already have reached the RP.
    pub async fn deliver(
        &self,
        client: &ClientId,
        endpoint: &CommandEndpoint,
        subject: &str,
        command: AccountCommand,
        now: OffsetDateTime,
    ) -> Result<(), DeliveryError> {
        let result = self.send(client, endpoint, subject, command, now).await;
        let (outcome, reason, status) = match &result {
            Ok(status) => (Outcome::Success, "accepted", Some(i64::from(*status))),
            Err(DeliveryError::Subject) => (Outcome::Failure, "subject", None),
            Err(DeliveryError::Time) => (Outcome::Failure, "time", None),
            Err(DeliveryError::Signing(_)) => (Outcome::Failure, "signing", None),
            Err(DeliveryError::Post(error)) => {
                (Outcome::Failure, "delivery", error.status().map(i64::from))
            }
            Err(DeliveryError::UnsupportedStatus(status)) => (
                Outcome::Failure,
                "response_status",
                Some(i64::from(*status)),
            ),
            Err(DeliveryError::InvalidResponse(_)) => {
                (Outcome::Failure, "response_body", Some(200))
            }
            Err(DeliveryError::Audit(_)) => (Outcome::Failure, "audit", None),
        };
        let mut detail = Detail::new()
            .label("command", command.as_str())
            .label("reason", reason);
        if let Some(status) = status {
            detail = detail.number("http_status", status);
        }
        let event = AuditEvent::new(
            self.tenant.id.clone(),
            EventType::PROVIDER_COMMAND_DELIVERED,
            outcome,
            Actor::System,
            now,
        )
        .client(client.clone())
        .subject(subject)
        .detail(detail);
        self.audit
            .record(event)
            .await
            .map_err(DeliveryError::Audit)?;
        result.map(|_| ())
    }

    async fn send(
        &self,
        client: &ClientId,
        endpoint: &CommandEndpoint,
        subject: &str,
        command: AccountCommand,
        now: OffsetDateTime,
    ) -> Result<u16, DeliveryError> {
        if subject.is_empty() || subject.len() > 255 || subject.chars().any(char::is_control) {
            return Err(DeliveryError::Subject);
        }
        let expiry = now
            .checked_add(COMMAND_TOKEN_LIFETIME)
            .ok_or(DeliveryError::Time)?;
        let claims = serde_json::json!({
            "iss": self.tenant.issuer.as_str(),
            "aud": endpoint.as_str(),
            "client_id": client.as_str(),
            "iat": now.unix_timestamp(),
            "exp": expiry.unix_timestamp(),
            "jti": uuid::Uuid::new_v4().to_string(),
            "command": command.as_str(),
            "tenant": self.tenant.id.as_str(),
            "sub": subject,
        });
        let token = self
            .signer
            .sign(&self.tenant.id, None, "command+jwt", &claims)
            .await
            .map_err(DeliveryError::Signing)?;
        let form = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("command_token", token.as_str())
            .finish();
        let response = self
            .poster
            .post_with_response(
                endpoint.as_str(),
                PostRequest::of("application/x-www-form-urlencoded").accepting("application/json"),
                form.as_bytes(),
            )
            .await?;
        validate_response(&response, subject, command)?;
        Ok(response.status)
    }
}

/// Accept only a response that proves the RP processed this account command.
fn validate_response(
    response: &PostResponse,
    subject: &str,
    command: AccountCommand,
) -> Result<(), DeliveryError> {
    if response.status != 200 && response.status != 204 {
        return Err(DeliveryError::UnsupportedStatus(response.status));
    }
    if !response.cache_control.as_deref().is_some_and(|header| {
        header
            .split(',')
            .any(|item| item.trim().eq_ignore_ascii_case("no-store"))
    }) {
        return Err(DeliveryError::InvalidResponse("missing no-store"));
    }
    if response.status == 204 && response.body.is_empty() {
        return Ok(());
    }
    if response.truncated {
        return Err(DeliveryError::InvalidResponse("body is too large"));
    }
    if !response.content_type.as_deref().is_some_and(|header| {
        header
            .split(';')
            .next()
            .is_some_and(|media| media.trim().eq_ignore_ascii_case("application/json"))
    }) {
        return Err(DeliveryError::InvalidResponse("content type is not JSON"));
    }
    let body: serde_json::Value = serde_json::from_slice(&response.body)
        .map_err(|_| DeliveryError::InvalidResponse("body is not JSON"))?;
    if body.get("sub").and_then(serde_json::Value::as_str) != Some(subject) {
        return Err(DeliveryError::InvalidResponse("subject does not match"));
    }
    if body.get("error").is_some() {
        return Err(DeliveryError::InvalidResponse("success contains an error"));
    }
    let expected_state = match command {
        AccountCommand::Invalidate => "active",
        AccountCommand::Delete => "unknown",
    };
    if body
        .get("account_state")
        .and_then(serde_json::Value::as_str)
        != Some(expected_state)
    {
        return Err(DeliveryError::InvalidResponse(
            "account state does not match",
        ));
    }
    Ok(())
}
