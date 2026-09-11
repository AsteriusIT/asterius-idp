//! The one way this server speaks to a person outside a browser.
//!
//! # Why a port and not an SMTP client
//!
//! ADR-0001's rule, and here it has teeth beyond tidiness. Mail is the one
//! outbound path in this server that is *not* a protocol request: it has no
//! specification governing what it looks like, every deployment already has an
//! opinion about how mail leaves its network, and a hard dependency on an SMTP
//! library would land in the protocol crates, where `check-layering` is right
//! to refuse it. So the protocol side knows [`Notification`] and
//! [`MailSender`], nothing else, and what actually delivers is a wiring
//! decision.
//!
//! This repository ships one adapter: a journal that writes the message to an
//! outbox table and logs that it did. That is enough for the tests, enough for
//! a deployment to see what *would* have gone out, and honest about what it
//! is — nothing arrives in anybody's inbox until an operator wires a real
//! sender. See `docs/configuration.md`.
//!
//! # What a notification may contain
//!
//! A recipient, a kind, and the values that kind needs. Not a rendered body:
//! rendering belongs to whatever sends, because a deployment's mail has its
//! own wording, its own locale set and its own brand, and a domain type that
//! carried HTML would make all three this crate's problem. The one thing the
//! domain does decide is *which* values a kind carries, because that is the
//! part a template must not be free to invent — a recovery mail with no link
//! is useless and a recovery mail with two is a phishing lesson.

use crate::error::DomainError;
use std::fmt::Debug;

/// What a message is about.
///
/// A closed set. Every variant is a thing this server does that a person has
/// to be told about out of band, and adding one is a deliberate act rather
/// than a string somebody passed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotificationKind {
    /// Somebody asked to recover this account, and here is the link.
    ///
    /// The link is a complete absolute URL, already carrying the token — built
    /// by the handler, because only it knows the tenant's issuer and the mount
    /// prefix the browser must come back through (`ast-295`).
    AccountRecovery {
        /// Where to click. Contains the single-use token.
        link: String,
        /// How many minutes the link is good for, so the message can say so.
        valid_for_minutes: i64,
    },
    /// The account's credentials changed. No link, nothing to click: this is
    /// the "was this you?" message, and a link in it would train the person
    /// receiving it to click links in messages about their password.
    CredentialChanged,
    /// Something is waiting for a decision in the approvals inbox
    /// (`ast-lh3.6`).
    ///
    /// CIBA Core 1.0 §8 has the OP "identify the end-user" and obtain an
    /// authorization decision on the *authentication device*, which is a
    /// device the client never touches: a backchannel request that nobody is
    /// told about is a request that expires unseen. So this is the one
    /// notification this server sends that is not about an account's
    /// credentials.
    ///
    /// The link is to the inbox and **not** to a particular request. A link
    /// that decided which approval was being answered would be a URL an
    /// attacker who guessed it could aim somebody at — and §7.1's
    /// `binding_message` exists precisely so that the person compares two
    /// screens rather than trusting a link. The message carries the same
    /// binding message the page will show, for that comparison.
    ApprovalRequested {
        /// Where the inbox is, absolute and carrying this tenant's prefix.
        link: String,
        /// The client's registered name, as the inbox will render it.
        ///
        /// Attacker-chosen at registration, like the name on the consent
        /// screen, and treated the same way: it is a hint about who is asking
        /// and never an identity.
        client_name: String,
        /// §7.1's `binding_message`, when the client sent one.
        ///
        /// The same string the consumption device is showing, so the person
        /// can see the two are one transaction (§7.1).
        binding_message: Option<String>,
        /// How many minutes the request has left, so the message can say so.
        valid_for_minutes: i64,
    },
}

impl NotificationKind {
    /// The stable name a log line or an outbox row records.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::AccountRecovery { .. } => "account_recovery",
            Self::CredentialChanged => "credential_changed",
            Self::ApprovalRequested { .. } => "approval_requested",
        }
    }
}

/// One message, addressed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notification {
    /// The address, as the account records it.
    ///
    /// A `String` rather than a validated address type: what counts as
    /// deliverable is the sender's opinion, and a domain type that rejected an
    /// address some real mail server accepts would lock a person out of their
    /// own recovery.
    pub to: String,
    /// What this is about.
    pub kind: NotificationKind,
}

impl Notification {
    /// The recovery link message.
    #[must_use]
    pub fn account_recovery(to: String, link: String, valid_for_minutes: i64) -> Self {
        Self {
            to,
            kind: NotificationKind::AccountRecovery {
                link,
                valid_for_minutes,
            },
        }
    }

    /// The "something is waiting for your decision" message (`ast-lh3.6`).
    #[must_use]
    pub fn approval_requested(
        to: String,
        link: String,
        client_name: String,
        binding_message: Option<String>,
        valid_for_minutes: i64,
    ) -> Self {
        Self {
            to,
            kind: NotificationKind::ApprovalRequested {
                link,
                client_name,
                binding_message,
                valid_for_minutes,
            },
        }
    }

    /// The "your credentials changed" message.
    #[must_use]
    pub fn credential_changed(to: String) -> Self {
        Self {
            to,
            kind: NotificationKind::CredentialChanged,
        }
    }
}

/// Delivers a [`Notification`], or says it could not.
///
/// # Errors and what a caller must do with them
///
/// A caller on the recovery path must **not** report a delivery failure
/// differently from a success. The request page answers the same way whether
/// or not an account existed, and an error that leaked through would undo
/// that: "we could not send mail" is only sayable about an address that has an
/// account. Log it, count it, answer the same page.
#[async_trait::async_trait]
pub trait MailSender: Debug + Send + Sync {
    /// Sends one message.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the message could not be handed off. A
    /// sender that queues may return `Ok` before anything is delivered; that
    /// is the honest answer for a queue, and nothing on the recovery path
    /// depends on the difference.
    async fn send(&self, message: &Notification) -> Result<(), DomainError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The recorded name is what an operator greps for; it must not be the
    /// `Debug` spelling, which carries the link.
    #[test]
    fn a_recovery_notification_records_a_stable_kind() {
        // Arrange
        let message =
            Notification::account_recovery("a@example.test".to_owned(), "https://x".to_owned(), 15);

        // Act
        let kind = message.kind.as_str();

        // Assert
        assert_eq!(kind, "account_recovery");
    }

    /// CIBA Core 1.0 §7.1: the `binding_message` is shown on the consumption
    /// device *and* on the authentication device, so a person can see that the
    /// two are one transaction. A notification that dropped it would leave
    /// nothing to compare against.
    #[test]
    fn an_approval_notification_carries_the_binding_message_to_compare() {
        // Arrange
        let message = Notification::approval_requested(
            "ada@example.test".to_owned(),
            "https://as.example/t/a/account/approvals".to_owned(),
            "Teller agent".to_owned(),
            Some("W4SCT".to_owned()),
            5,
        );

        // Act
        let kind = message.kind.clone();

        // Assert
        assert_eq!(
            kind,
            NotificationKind::ApprovalRequested {
                link: "https://as.example/t/a/account/approvals".to_owned(),
                client_name: "Teller agent".to_owned(),
                binding_message: Some("W4SCT".to_owned()),
                valid_for_minutes: 5,
            }
        );
        assert_eq!(message.kind.as_str(), "approval_requested");
    }

    /// A credential-change notice carries nothing to click. Asserted rather
    /// than assumed: the variant having no link field is the control.
    #[test]
    fn a_credential_change_notification_has_no_link() {
        // Arrange
        let message = Notification::credential_changed("a@example.test".to_owned());

        // Act
        let kind = message.kind.clone();

        // Assert
        assert_eq!(kind, NotificationKind::CredentialChanged);
    }
}
