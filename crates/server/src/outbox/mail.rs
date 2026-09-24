//! Transactional account mail through the Resend HTTPS API.
//!
//! A successful API response means the provider accepted the message. The
//! outbox then records `delivered`; it does not assert inbox placement.

use super::{Delivered, Deliverer, Undelivered};
use crate::config::MailConfig;
use crate::outbound::{HttpsPoster, PostRequest};
use asterius_domain::outbox::OutboxEvent;
use serde_json::{Value, json};
use time::{Duration, OffsetDateTime};

const RESEND_URL: &str = "https://api.resend.com/emails";

/// Sends queued notifications to the configured provider.
pub struct MailDeliverer {
    config: MailConfig,
    poster: HttpsPoster,
}

impl std::fmt::Debug for MailDeliverer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MailDeliverer")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl MailDeliverer {
    #[must_use]
    pub const fn new(config: MailConfig, poster: HttpsPoster) -> Self {
        Self { config, poster }
    }

    /// Sends a harmless probe to an address the operator named explicitly.
    /// Provider acceptance is reported; inbox placement is not inferred.
    pub async fn send_test(&self, to: &str) -> Result<(), String> {
        if !to.contains('@') || to.chars().any(char::is_whitespace) {
            return Err("test recipient must be a single email address".to_owned());
        }
        self.post_message(
            to,
            Message {
                subject: "Asterius mail transport test",
                text: "The mail provider accepted a test message from Asterius.".to_owned(),
                expires_at: None,
            },
        )
        .await
        .map_err(|failure| failure.detail)
    }

    async fn post_message(&self, to: &str, message: Message) -> Result<(), Undelivered> {
        let body = serde_json::to_vec(&json!({
            "from": self.config.from_address,
            "to": [to],
            "subject": message.subject,
            "text": message.text,
        }))
        .map_err(|_| Undelivered::permanent("cannot encode notification".to_owned()))?;
        let authorization = format!("Bearer {}", self.config.api_key);
        let request = PostRequest::of("application/json").authorized_by(Some(&authorization));
        self.poster
            .post_with(RESEND_URL, request, &body)
            .await
            .map_err(|error| {
                let detail = match error.status() {
                    Some(status) => format!("mail provider answered HTTP {status}"),
                    None => "mail provider could not be reached".to_owned(),
                };
                if error.is_permanent() {
                    Undelivered::permanent(detail)
                } else {
                    Undelivered::transient(detail)
                }
            })?;
        Ok(())
    }
}

/// A fixed template. Plain text avoids injecting untrusted values into HTML.
#[derive(Debug, PartialEq, Eq)]
struct Message {
    subject: &'static str,
    text: String,
    expires_at: Option<OffsetDateTime>,
}

fn expiry(event: &OutboxEvent, minutes: i64) -> Result<OffsetDateTime, Undelivered> {
    if let Some(seconds) = event.payload.get("expires_at") {
        let seconds = seconds
            .as_i64()
            .ok_or_else(|| Undelivered::permanent("notification payload is invalid".to_owned()))?;
        return OffsetDateTime::from_unix_timestamp(seconds)
            .map_err(|_| Undelivered::permanent("notification payload is invalid".to_owned()));
    }
    // Legacy queue entries have no exact deadline. Bias a full minute early;
    // new token issuers supply `expires_at` so this path is only a fallback.
    event
        .created_at
        .checked_add(Duration::minutes(minutes - 1))
        .ok_or_else(|| Undelivered::permanent("notification payload is invalid".to_owned()))
}

fn template(event: &OutboxEvent) -> Result<Message, Undelivered> {
    let invalid = || Undelivered::permanent("notification payload is invalid".to_owned());
    let link = || {
        let value = event
            .payload
            .get("link")
            .and_then(Value::as_str)
            .ok_or_else(invalid)?;
        if !value.starts_with("https://") || value.chars().any(char::is_whitespace) {
            return Err(invalid());
        }
        Ok(value)
    };
    let expiring = |subject: &'static str, action: &'static str| {
        let minutes = event
            .payload
            .get("valid_for_minutes")
            .and_then(Value::as_i64)
            .filter(|n| *n > 0 && *n <= 1440)
            .ok_or_else(invalid)?;
        let expires_at = expiry(event, minutes)?;
        Ok(Message {
            subject,
            text: format!(
                "{action}\n\n{}\n\nThis link expires in {minutes} minutes. If you did not request this, ignore this message.",
                link()?
            ),
            expires_at: Some(expires_at),
        })
    };
    match event.kind.as_str() {
        "notification.account_recovery" => expiring("Reset your password", "Use this link to reset your password:"),
        "notification.email_verification" => expiring("Verify your email address", "Use this link to verify your email address:"),
        "notification.invitation" => expiring("Your account invitation", "Use this link to finish setting up your account:"),
        "notification.email_change_confirmation" => expiring("Confirm your new email address", "Use this link to confirm your new email address:"),
        "notification.credential_changed" => Ok(Message { subject: "Your account credentials changed", text: "Your account credentials changed. If this was not you, contact your administrator.".to_owned(), expires_at: None }),
        "notification.email_change_notice" => Ok(Message { subject: "Your account email address changed", text: "The email address on your account changed. If this was not you, contact your administrator.".to_owned(), expires_at: None }),
        "notification.recovery_refused" => Ok(Message { subject: "Password recovery was refused", text: "Someone requested password recovery for your account. Password recovery is unavailable for this account. If this was not you, contact your administrator.".to_owned(), expires_at: None }),
        "notification.passkey_added_notice" => Ok(Message { subject: "A passkey was added to your account", text: "A passkey was added to your account. If this was not you, contact your administrator.".to_owned(), expires_at: None }),
        "notification.passkey_removed_notice" => Ok(Message { subject: "A passkey was removed from your account", text: "A passkey was removed from your account. If this was not you, contact your administrator.".to_owned(), expires_at: None }),
        "notification.password_reset_notice" => Ok(Message { subject: "Your password was reset", text: "Your account password was reset. If this was not you, contact your administrator.".to_owned(), expires_at: None }),
        "notification.approval_requested" => {
            let minutes = event.payload.get("valid_for_minutes").and_then(Value::as_i64)
                .filter(|n| *n > 0 && *n <= 1440).ok_or_else(invalid)?;
            let expires_at = expiry(event, minutes)?;
            let client = event.payload.get("client_name").and_then(Value::as_str).ok_or_else(invalid)?;
            let binding = event.payload.get("binding_message").and_then(Value::as_str).unwrap_or("none");
            Ok(Message { subject: "Approve a sign-in request", text: format!("A sign-in request from {} awaits your decision.\nBinding message: {}\n\nOpen your approvals inbox:\n{}\n\nThis request expires in {minutes} minutes.", safe_line(client), safe_line(binding), link()?), expires_at: Some(expires_at) })
        }
        _ => Err(Undelivered::permanent("unknown notification kind".to_owned())),
    }
}

/// Client-provided labels stay on one bounded line of the message.
fn safe_line(value: &str) -> String {
    value
        .chars()
        .take(200)
        .map(|ch| {
            if ch.is_control() || matches!(ch, '\u{2028}' | '\u{2029}') {
                ' '
            } else {
                ch
            }
        })
        .collect()
}

#[async_trait::async_trait]
impl Deliverer for MailDeliverer {
    fn family(&self) -> &'static str {
        "notification"
    }

    async fn deliver(&self, event: &OutboxEvent) -> Result<Delivered, Undelivered> {
        let message = template(event)?;
        if message
            .expires_at
            .is_some_and(|expiry| OffsetDateTime::now_utc() >= expiry)
        {
            return Ok(Delivered::Expired);
        }
        self.post_message(&event.destination, message).await?;
        Ok(Delivered::Sent)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asterius_domain::TenantId;

    fn event(kind: &str, payload: Value) -> OutboxEvent {
        OutboxEvent {
            tenant: TenantId::new("tenant"),
            id: 1,
            kind: kind.to_owned(),
            destination: "person@example.test".to_owned(),
            payload,
            attempt: 1,
            max_attempts: 10,
            created_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    #[test]
    fn recovery_template_preserves_link_and_expiry() {
        let message = template(&event(
            "notification.account_recovery",
            json!({"link":"https://example.test/reset?token=secret", "valid_for_minutes":15}),
        ))
        .expect("template");
        assert!(message.text.contains("token=secret"));
        assert_eq!(
            message.expires_at,
            Some(OffsetDateTime::UNIX_EPOCH + Duration::minutes(14))
        );
    }

    #[test]
    fn unknown_kind_cannot_leak_payload_to_error() {
        let error = template(&event("notification.unknown", json!({"link":"secret"})))
            .expect_err("unknown kind");
        assert!(!error.detail.contains("secret"));
    }

    #[test]
    fn approval_labels_cannot_spoof_new_mail_lines() {
        let message = template(&event(
            "notification.approval_requested",
            json!({
                "link":"https://example.test/approvals", "valid_for_minutes":5,
                "client_name":"Trusted\r\nIgnore this warning", "binding_message":"123\nApproved"
            }),
        ))
        .expect("template");
        assert!(message.text.contains("Trusted  Ignore this warning"));
        assert!(!message.text.contains("123\nApproved"));
    }
}
