//! What the user was asked, and what they answered.
//!
//! The consent screen is the one place in this protocol where a person makes a
//! decision. Everything else is two machines agreeing about what a person
//! already decided — so the quality of this screen is the quality of the
//! consent, and FAPI 2.0 SP §7 is unusually direct about the ways it goes
//! wrong: client misidentification, insufficient understanding, inadequate
//! choice.
//!
//! This module owns what is *shown* and what is *recorded*. The rendering is
//! `asterius-web`; the storage is the grant.
//!
//! # Deny is a decision, not a failure
//!
//! A denial is an outcome the user chose, and it travels back to the client as
//! `access_denied` (RFC 6749 §4.1.2.1) through the same validated redirect URI
//! an approval would use. Treating it as an error — an error page, a dead end,
//! a different code path — would make the safe answer the inconvenient one, and
//! a consent screen where refusing is harder than agreeing is not offering a
//! choice.
//!
//! # The user may grant less than was asked
//!
//! The request is what the client wants. The decision is what it gets. They are
//! separate types here so that no code path can mistake one for the other, and
//! so that narrowing — approving three of four scopes — is expressible rather
//! than a special case bolted on later.

use std::collections::BTreeSet;

/// What the client asked for, resolved into something a person can read.
///
/// Built from the stored authorization request plus the client's registration.
/// Every string here is attacker-influenced — a `client_name` comes from a
/// registration document — so it is escaped on the way out; see
/// `asterius_web::pages`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentRequest {
    /// The client's registered name.
    pub client_name: String,
    /// The host the user will be sent back to.
    ///
    /// Shown because the name is chosen by whoever registered and the host is
    /// not: FAPI 2.0 SP §7's client-misidentification risk is that "Example
    /// Bank" is a name anybody can register. The host is the part a user can
    /// check against where they expected to be.
    pub redirect_host: String,
    /// Scopes, in a stable order, with whatever description the tenant gives.
    pub scopes: Vec<ScopeRequest>,
    /// Whether the client asked for offline access.
    ///
    /// Called out separately because it is qualitatively different: it is the
    /// difference between acting now and acting later without the user
    /// present.
    pub offline_access: bool,
    /// RFC 8707 resource indicators, if any.
    pub resources: BTreeSet<String>,
}

/// One scope, as offered to the user.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ScopeRequest {
    /// The scope token, as the client sent it.
    pub name: String,
    /// What it means, in the user's language.
    ///
    /// A scope with no description is shown by name. That is deliberately ugly
    /// — an unexplained scope should look unexplained, not familiar.
    pub description: Option<String>,
    /// Whether the user may decline this one and still proceed.
    ///
    /// `openid` cannot be declined: it is what makes the request an
    /// authentication rather than a plain authorization, and dropping it would
    /// silently change what the client receives.
    pub required: bool,
}

/// The scope that cannot be declined.
pub const REQUIRED_SCOPE: &str = "openid";

/// What the user answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Approved, with the scopes actually granted.
    ///
    /// Carries the granted set rather than a bare "yes", because a user may
    /// grant less than was asked and the grant must record what they agreed
    /// to — not what they were shown.
    Approved {
        /// The scopes the user allowed. A subset of what was requested.
        scopes: BTreeSet<String>,
    },
    /// Refused. Travels to the client as `access_denied`.
    Denied,
}

impl Decision {
    /// The OAuth error code for a denial (RFC 6749 §4.1.2.1).
    #[must_use]
    pub const fn error_code(&self) -> Option<&'static str> {
        match self {
            Self::Approved { .. } => None,
            Self::Denied => Some("access_denied"),
        }
    }
}

/// Why a submitted decision could not be accepted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ConsentError {
    /// The form carried neither `allow` nor `deny`.
    #[error("no decision was submitted")]
    NoDecision,
    /// The form granted a scope that was never requested.
    ///
    /// A form is a suggestion from the browser, not a source of authority. A
    /// scope that was not on the screen cannot have been consented to, however
    /// convincingly the request says otherwise.
    #[error("a granted scope was not requested")]
    ScopeNotRequested,
    /// The user tried to decline a scope that cannot be declined.
    #[error("a required scope was not granted")]
    RequiredScopeMissing,
}

impl ConsentRequest {
    /// Builds the offer from a validated request and the client's registration.
    ///
    /// `describe` maps a scope token to a human description — a tenant's
    /// wording, when it has one.
    #[must_use]
    pub fn new(
        client_name: impl Into<String>,
        redirect_host: impl Into<String>,
        requested: &BTreeSet<String>,
        resources: BTreeSet<String>,
        describe: impl Fn(&str) -> Option<String>,
    ) -> Self {
        let scopes = requested
            .iter()
            .map(|name| ScopeRequest {
                name: name.clone(),
                description: describe(name),
                required: name == REQUIRED_SCOPE,
            })
            .collect();

        Self {
            client_name: client_name.into(),
            redirect_host: redirect_host.into(),
            scopes,
            // OIDC Core §11: `offline_access` is what asks for a refresh token.
            offline_access: requested.contains("offline_access"),
            resources,
        }
    }

    /// Turns a submitted form into a decision.
    ///
    /// `granted` is whatever the browser sent. It is checked against what was
    /// actually offered, because a form field is a claim by the browser and
    /// this server's memory of what it displayed is the authority.
    ///
    /// # Errors
    ///
    /// [`ConsentError`] when the submission does not correspond to the offer.
    pub fn decide(
        &self,
        approved: bool,
        granted: &BTreeSet<String>,
    ) -> Result<Decision, ConsentError> {
        if !approved {
            // A denial needs no scope check: nothing is being granted.
            return Ok(Decision::Denied);
        }

        let offered: BTreeSet<&str> = self.scopes.iter().map(|s| s.name.as_str()).collect();
        for scope in granted {
            if !offered.contains(scope.as_str()) {
                return Err(ConsentError::ScopeNotRequested);
            }
        }

        for scope in &self.scopes {
            if scope.required && !granted.contains(&scope.name) {
                return Err(ConsentError::RequiredScopeMissing);
            }
        }

        Ok(Decision::Approved {
            scopes: granted.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn requested(scopes: &[&str]) -> BTreeSet<String> {
        scopes.iter().map(|s| (*s).to_owned()).collect()
    }

    fn offer(scopes: &[&str]) -> ConsentRequest {
        ConsentRequest::new(
            "Billing",
            "rp.example",
            &requested(scopes),
            BTreeSet::new(),
            |name| match name {
                "openid" => Some("Confirm who you are".to_owned()),
                "payments" => Some("See your payment history".to_owned()),
                _ => None,
            },
        )
    }

    #[test]
    fn the_offer_describes_what_it_can_and_names_what_it_cannot() {
        let offer = offer(&["openid", "payments", "obscure:thing"]);
        assert_eq!(offer.scopes.len(), 3);

        let described: Vec<_> = offer
            .scopes
            .iter()
            .map(|s| (s.name.as_str(), s.description.as_deref()))
            .collect();
        assert!(described.contains(&("openid", Some("Confirm who you are"))));
        // An unexplained scope has no invented description.
        assert!(described.contains(&("obscure:thing", None)));
    }

    /// `openid` is what makes this an authentication. Dropping it would change
    /// what the client receives without telling it.
    #[test]
    fn only_openid_is_required() {
        let offer = offer(&["openid", "payments"]);
        for scope in &offer.scopes {
            assert_eq!(
                scope.required,
                scope.name == "openid",
                "{} required = {}",
                scope.name,
                scope.required
            );
        }
    }

    /// OIDC Core §11.
    #[test]
    fn offline_access_is_called_out_separately() {
        assert!(!offer(&["openid"]).offline_access);
        assert!(offer(&["openid", "offline_access"]).offline_access);
    }

    #[test]
    fn approving_everything_grants_everything() {
        let offer = offer(&["openid", "payments"]);
        let decision = offer
            .decide(true, &requested(&["openid", "payments"]))
            .expect("must accept");
        assert_eq!(
            decision,
            Decision::Approved {
                scopes: requested(&["openid", "payments"])
            }
        );
        assert_eq!(decision.error_code(), None);
    }

    /// The user may grant less than was asked.
    #[test]
    fn a_narrowed_approval_records_what_was_actually_granted() {
        let offer = offer(&["openid", "payments"]);
        let decision = offer
            .decide(true, &requested(&["openid"]))
            .expect("must accept");
        assert_eq!(
            decision,
            Decision::Approved {
                scopes: requested(&["openid"])
            },
            "the grant recorded what was asked rather than what was allowed"
        );
    }

    /// A form field is a claim by the browser; what this server displayed is
    /// the authority.
    #[test]
    fn a_scope_that_was_never_offered_cannot_be_granted() {
        let offer = offer(&["openid", "payments"]);
        assert_eq!(
            offer.decide(true, &requested(&["openid", "admin"])),
            Err(ConsentError::ScopeNotRequested)
        );
        // Even on its own.
        assert_eq!(
            offer.decide(true, &requested(&["admin"])),
            Err(ConsentError::ScopeNotRequested)
        );
    }

    #[test]
    fn a_required_scope_cannot_be_declined() {
        let offer = offer(&["openid", "payments"]);
        assert_eq!(
            offer.decide(true, &requested(&["payments"])),
            Err(ConsentError::RequiredScopeMissing)
        );
        assert_eq!(
            offer.decide(true, &BTreeSet::new()),
            Err(ConsentError::RequiredScopeMissing)
        );
    }

    /// A denial is a decision. It needs no scopes and cannot fail.
    #[test]
    fn denying_always_succeeds_whatever_the_form_said() {
        let offer = offer(&["openid", "payments"]);
        for granted in [
            BTreeSet::new(),
            requested(&["openid"]),
            // Even a form claiming scopes that were never offered: the user
            // said no, and refusing their refusal on a technicality would be
            // the worst possible reading.
            requested(&["admin", "root"]),
        ] {
            assert_eq!(
                offer.decide(false, &granted),
                Ok(Decision::Denied),
                "a denial was refused"
            );
        }
    }

    /// RFC 6749 §4.1.2.1.
    #[test]
    fn a_denial_travels_as_access_denied() {
        assert_eq!(Decision::Denied.error_code(), Some("access_denied"));
    }

    /// FAPI 2.0 SP §7: the name is chosen by whoever registered; the host is
    /// not. Both are shown so a user can tell "Example Bank" from Example Bank.
    #[test]
    fn the_offer_carries_the_host_the_user_will_be_returned_to() {
        let offer = ConsentRequest::new(
            "Example Bank",
            "rp.attacker.example",
            &requested(&["openid"]),
            BTreeSet::new(),
            |_| None,
        );
        assert_eq!(offer.client_name, "Example Bank");
        assert_eq!(offer.redirect_host, "rp.attacker.example");
    }
}
