//! RP-initiated logout: what the `end_session_endpoint` is allowed to do.
//!
//! OpenID Connect RP-Initiated Logout 1.0 (Final, 2022-09). Everything here is
//! a pure function: parse the request (§2), work out whether the relying party
//! asking is identified at all (§2, §4), and decide what the browser gets
//! (§3). The session is ended, the cookie is cleared and the relying parties
//! are notified by the adapter, because those are effects.
//!
//! # The two rules this module exists to make hard to break
//!
//! **A request that cannot be verified must not change anything before the
//! user has said so.** §2: "At the OP's discretion, [...] the OP SHOULD ask
//! the End-User whether to log out"; and, for a request that carries no
//! `id_token_hint`, §3 is unambiguous that the OP "MUST NOT perform post-logout
//! redirection" unless it has confirmed the request's legitimacy by other
//! means. So [`Disposition::Confirm`] is a decision reached *before* anything
//! is revoked, and it carries no relying-party name, logo or URL: a page that
//! renders an unverified client's chosen text is a phishing page this server
//! hosts.
//!
//! **Relying parties are notified before the browser is redirected.** §3
//! describes the redirect as the last step, after the RPs have been told. That
//! ordering is not left to the order of statements in a handler: a
//! [`RedirectTarget`] will not produce a URL without a [`Notified`] receipt,
//! and the only way to get a receipt is to have done the notifying.
//!
//! # What is not decided here
//!
//! Whether a bare `client_id` — with no `id_token_hint` — may identify a
//! relying party. §3 permits it when the OP has "confirmed the RP's identity
//! by other means", which is a tenant policy nobody has written yet, so this
//! module fails closed: without a verified hint the relying party is
//! [`Rp::Unidentified`] and no redirection happens.

use crate::form::{Duplicated, Parameters};
use asterius_domain::{ClientId, ct_eq, sha256_hex};
use serde_json::Value;

/// The longest `id_token_hint` accepted.
///
/// The same ceiling [`asterius_jose::verify`] applies to a token it is about to
/// verify. Beyond it the value is not a hint, it is a way to make the server
/// allocate.
pub const MAX_ID_TOKEN_HINT_BYTES: usize = 8 * 1024;

/// The longest `post_logout_redirect_uri` accepted.
///
/// It has to match a registered value byte for byte, so anything longer than
/// the longest registrable URI cannot match; refusing it early keeps the
/// comparison off a value that only exists to be big.
pub const MAX_URI_BYTES: usize = 2 * 1024;

/// The longest `state` accepted, which is also the longest this server will
/// echo back into a `Location` header.
pub const MAX_STATE_BYTES: usize = 2 * 1024;

/// The longest `logout_hint`, `ui_locales` or `client_id` accepted.
pub const MAX_SHORT_PARAMETER_BYTES: usize = 512;

/// Why a logout request was not usable as sent.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum LogoutRequestError {
    /// A parameter appeared more than once (RFC 6749 §3.1, inherited here).
    #[error(transparent)]
    Duplicated(#[from] Duplicated),
    /// A parameter is longer than this server will look at.
    #[error("{parameter} is longer than {limit} bytes")]
    TooLong {
        /// Which parameter.
        parameter: &'static str,
        /// The cap it broke.
        limit: usize,
    },
    /// A parameter carries a character that must never reach a page or a
    /// header.
    #[error("{0} contains a control character")]
    Malformed(&'static str),
}

/// An RP-initiated logout request, as it arrived (§2).
///
/// Every member is optional because §2 makes every parameter optional — a bare
/// `GET /logout` is a valid request, and is the one a user types themselves.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LogoutRequest {
    /// The ID Token this server issued, offered as a hint about who is asking
    /// and which session (§2).
    pub id_token_hint: Option<String>,
    /// A hint about which user is logging out (§2). Parsed and carried, never
    /// believed: it is an unauthenticated string chosen by whoever built the
    /// URL, so it may select what is *shown*, never what is *ended*.
    pub logout_hint: Option<String>,
    /// The relying party claiming to ask (§2). On its own it identifies
    /// nothing — see the module documentation.
    pub client_id: Option<ClientId>,
    /// Where the RP would like the browser sent afterwards (§2, §3).
    pub post_logout_redirect_uri: Option<String>,
    /// Preferred languages (§2). Recorded; the pages are not localised yet.
    pub ui_locales: Option<String>,
    /// Opaque value to be echoed on the post-logout redirect, and only there
    /// (§2).
    pub state: Option<String>,
}

impl LogoutRequest {
    /// Reads the parameters of a `GET` query or a `POST` form (§2).
    ///
    /// Unknown parameters are ignored, which is what an OP does with an
    /// extension it has not implemented. A parameter sent twice is refused
    /// rather than resolved: a server that silently takes the first value, or
    /// the last, is one whose choice an attacker can rely on.
    ///
    /// An empty value is read as absent. `post_logout_redirect_uri=` is not a
    /// URI to compare against the registered set, and `state=` is nothing to
    /// echo.
    ///
    /// # Errors
    ///
    /// [`LogoutRequestError`] for a repeated, oversized or control-bearing
    /// parameter.
    // fuzz-target: logout_request
    pub fn parse<I, K, V>(pairs: I) -> Result<Self, LogoutRequestError>
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        let parameters = Parameters::from_pairs(pairs);
        let field =
            |name: &'static str, limit: usize| -> Result<Option<String>, LogoutRequestError> {
                let Some(value) = parameters.get(name)? else {
                    return Ok(None);
                };
                if value.is_empty() {
                    return Ok(None);
                }
                if value.len() > limit {
                    return Err(LogoutRequestError::TooLong {
                        parameter: name,
                        limit,
                    });
                }
                // C0, C1 and DEL. A `state` reaches a `Location` header and every
                // one of these reaches a page; refusing them here means no later
                // step has to remember that it is handling somebody else's text.
                if value.chars().any(char::is_control) {
                    return Err(LogoutRequestError::Malformed(name));
                }
                Ok(Some(value.to_owned()))
            };

        Ok(Self {
            id_token_hint: field("id_token_hint", MAX_ID_TOKEN_HINT_BYTES)?,
            logout_hint: field("logout_hint", MAX_SHORT_PARAMETER_BYTES)?,
            client_id: field("client_id", MAX_SHORT_PARAMETER_BYTES)?.map(ClientId::new),
            post_logout_redirect_uri: field("post_logout_redirect_uri", MAX_URI_BYTES)?,
            ui_locales: field("ui_locales", MAX_SHORT_PARAMETER_BYTES)?,
            state: field("state", MAX_STATE_BYTES)?,
        })
    }
}

/// What the request proved about the relying party behind it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rp {
    /// An `id_token_hint` this server signed named this client, and the
    /// `client_id` parameter — if one was sent — agreed with it.
    Identified(ClientId),
    /// Nobody in particular: no hint, a hint that did not verify, or a
    /// `client_id` that contradicted one that did.
    ///
    /// Everything downstream treats this as "a stranger sent the user here".
    Unidentified,
}

impl Rp {
    /// The client, when there is one.
    #[must_use]
    pub const fn client(&self) -> Option<&ClientId> {
        match self {
            Self::Identified(client) => Some(client),
            Self::Unidentified => None,
        }
    }
}

/// The client a verified `id_token_hint` names (OIDC Core §2).
///
/// `aud` "MUST contain the OAuth 2.0 `client_id` of the Relying Party", and
/// `azp` names the party the token was issued to when there is more than one
/// audience. An `aud` array with several values and no `azp` names nobody in
/// particular, so it identifies nobody: guessing which entry is the RP is how
/// one client's ID token logs another client's session out.
///
/// The claims must already have had their signature checked. This function
/// reads a verified token; it does not verify one.
#[must_use]
pub fn client_from_hint(claims: &Value) -> Option<ClientId> {
    if let Some(azp) = claims.get("azp").and_then(Value::as_str) {
        return (!azp.is_empty()).then(|| ClientId::new(azp));
    }
    match claims.get("aud")? {
        Value::String(one) => (!one.is_empty()).then(|| ClientId::new(one)),
        Value::Array(many) => match many.as_slice() {
            [Value::String(one)] => (!one.is_empty()).then(|| ClientId::new(one)),
            _ => None,
        },
        _ => None,
    }
}

/// Combines what the hint said with what the request claimed (§2).
///
/// §2 on `client_id`: "If both `client_id` and `id_token_hint` are present,
/// [...] the OP MUST verify that the Client identifier in the ID Token matches
/// the `client_id`". A disagreement is not a smaller kind of match — it is two
/// contradictory statements about who is asking, and the answer to that is to
/// believe neither.
#[must_use]
pub fn identify(from_hint: Option<ClientId>, from_parameter: Option<&ClientId>) -> Rp {
    match (from_hint, from_parameter) {
        (Some(hinted), None) => Rp::Identified(hinted),
        (Some(hinted), Some(claimed)) if &hinted == claimed => Rp::Identified(hinted),
        _ => Rp::Unidentified,
    }
}

/// Where the browser goes after the session has ended, and what it carries.
///
/// Only ever built from a `post_logout_redirect_uri` that matched a registered
/// value exactly, so the string in it is this deployment's own configuration
/// rather than a request parameter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedirectTarget {
    uri: String,
    state: Option<String>,
}

/// Proof that every relying party taking part in the session has been told it
/// ended.
///
/// §3 puts the notifications before the redirect: "the OP [...] redirects the
/// End-User's User Agent to the `post_logout_redirect_uri`" *after* logging
/// out, which includes notifying the RPs that were part of the session. This
/// type is how that ordering survives somebody rearranging a handler:
/// [`RedirectTarget::location`] needs one, and the only way to hold one is to
/// have finished notifying.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub struct Notified {
    participants: usize,
}

impl Notified {
    /// Records that `participants` relying parties were notified.
    ///
    /// Called by the adapter that did the notifying, and nowhere else.
    pub const fn after_notifying(participants: usize) -> Self {
        Self { participants }
    }

    /// How many relying parties were notified.
    #[must_use]
    pub const fn participants(self) -> usize {
        self.participants
    }
}

/// Why a redirect could not be built from a registered URI.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RedirectError {
    /// The registered URI does not parse. A stored value, not a sent one, so
    /// this is a configuration fault rather than an attack.
    #[error("a registered post_logout_redirect_uri will not parse")]
    Unparseable,
}

impl RedirectTarget {
    /// The registered URI this target sends the browser to.
    #[must_use]
    pub fn uri(&self) -> &str {
        &self.uri
    }

    /// The `state` to echo, if the request carried one.
    #[must_use]
    pub fn state(&self) -> Option<&str> {
        self.state.as_deref()
    }

    /// The `Location` to send, once the relying parties have been notified.
    ///
    /// §2: "if a `state` parameter is included [...] the OP MUST echo it as a
    /// query parameter" — appended to whatever query the registered URI
    /// already has, and percent-encoded, because a registered URI may carry
    /// one of its own.
    ///
    /// # Errors
    ///
    /// [`RedirectError::Unparseable`] if the registered URI is not a URL.
    pub fn location(&self, _notified: &Notified) -> Result<String, RedirectError> {
        let mut url = url::Url::parse(&self.uri).map_err(|_| RedirectError::Unparseable)?;
        if let Some(state) = &self.state {
            url.query_pairs_mut().append_pair("state", state);
        }
        Ok(url.into())
    }
}

/// What the end-session endpoint does with a request.
///
/// Ordered from "changes nothing" to "changes everything", which is also the
/// order of how much the request proved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Disposition {
    /// Ask the user, and change nothing until they answer.
    ///
    /// The page must name the *provider*, never the relying party: nothing
    /// here has been verified, so any client-chosen text on it is text an
    /// attacker chose.
    Confirm,
    /// End the session and show the neutral logged-out page.
    EndSession,
    /// End the session, notify the participating relying parties, and only
    /// then redirect.
    EndSessionAndRedirect(RedirectTarget),
}

/// Decides what happens, given who was identified and what they registered
/// (§3, §3.1).
///
/// `registered` is the client's `post_logout_redirect_uris` (§3.1). The
/// comparison is byte-exact, for the reason ADR-0005 gives for the
/// authorization endpoint's `redirect_uri`: every relaxation of it — case,
/// trailing slash, prefix — is a way to reach a URL the client never
/// registered, and the value is chosen by whoever built the logout link.
///
/// A `post_logout_redirect_uri` that does not match is not an error page: §3
/// says the OP must not redirect, and the neutral logged-out page is what
/// "does not redirect" looks like to a user who really did want to log out.
#[must_use]
pub fn disposition(request: &LogoutRequest, rp: &Rp, registered: &[String]) -> Disposition {
    let Rp::Identified(_) = rp else {
        return Disposition::Confirm;
    };
    let Some(requested) = &request.post_logout_redirect_uri else {
        return Disposition::EndSession;
    };
    if registered.iter().any(|candidate| candidate == requested) {
        Disposition::EndSessionAndRedirect(RedirectTarget {
            uri: requested.clone(),
            state: request.state.clone(),
        })
    } else {
        Disposition::EndSession
    }
}

/// The synchroniser token for the logout confirmation form.
///
/// A forged logout is a denial of service — a page on another site can point
/// an image at `/logout` — so the confirmation form carries a token, and the
/// token is derived from the session id rather than stored: there is no
/// interaction record behind a logout, and inventing one would put a row in
/// the database for every drive-by request to this endpoint.
///
/// A digest of the cookie value, so producing the token requires holding the
/// cookie, and holding the token yields nothing about the cookie. Compared
/// with [`confirmation_token_matches`], never with `==`.
#[must_use]
pub fn confirmation_token(session_id: &str) -> String {
    sha256_hex(format!("asterius.logout.confirm.v1|{session_id}").as_bytes())
}

/// Whether a submitted confirmation token is the one this session's form
/// carried, compared in constant time.
#[must_use]
pub fn confirmation_token_matches(session_id: &str, presented: &str) -> bool {
    ct_eq(
        confirmation_token(session_id).as_bytes(),
        presented.as_bytes(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn pairs(raw: &[(&str, &str)]) -> Vec<(String, String)> {
        raw.iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    fn parse(raw: &[(&str, &str)]) -> Result<LogoutRequest, LogoutRequestError> {
        LogoutRequest::parse(pairs(raw))
    }

    const REGISTERED: &str = "https://rp.example/after-logout";

    fn registered() -> Vec<String> {
        vec![REGISTERED.to_owned()]
    }

    /// §2's parameter list, all of it optional.
    #[test]
    fn every_parameter_is_read_and_a_bare_request_is_valid() {
        let full = parse(&[
            ("id_token_hint", "a.b.c"),
            ("logout_hint", "someone@example.test"),
            ("client_id", "billing"),
            ("post_logout_redirect_uri", REGISTERED),
            ("ui_locales", "fr-CA fr en"),
            ("state", "opaque"),
        ])
        .expect("a well-formed request");

        assert_eq!(full.id_token_hint.as_deref(), Some("a.b.c"));
        assert_eq!(full.logout_hint.as_deref(), Some("someone@example.test"));
        assert_eq!(full.client_id, Some(ClientId::new("billing")));
        assert_eq!(full.post_logout_redirect_uri.as_deref(), Some(REGISTERED));
        assert_eq!(full.ui_locales.as_deref(), Some("fr-CA fr en"));
        assert_eq!(full.state.as_deref(), Some("opaque"));

        assert_eq!(
            parse(&[]).expect("a bare request"),
            LogoutRequest::default()
        );
    }

    #[test]
    fn an_unknown_parameter_is_ignored() {
        let request = parse(&[("prompt", "none"), ("state", "s")]).expect("parse");
        assert_eq!(request.state.as_deref(), Some("s"));
    }

    #[test]
    fn a_repeated_parameter_is_refused() {
        for name in [
            "id_token_hint",
            "logout_hint",
            "client_id",
            "post_logout_redirect_uri",
            "ui_locales",
            "state",
        ] {
            let error = parse(&[(name, "one"), (name, "two")]).expect_err("a repeat");
            assert!(
                matches!(error, LogoutRequestError::Duplicated(_)),
                "{name}: {error}"
            );
        }
    }

    /// An empty value is nothing, not a value to compare or echo.
    #[test]
    fn an_empty_value_is_absent() {
        let request = parse(&[
            ("post_logout_redirect_uri", ""),
            ("state", ""),
            ("client_id", ""),
        ])
        .expect("parse");
        assert_eq!(request, LogoutRequest::default());
    }

    #[test]
    fn an_oversized_parameter_is_refused_before_it_is_used() {
        let long = "x".repeat(MAX_STATE_BYTES + 1);
        assert!(matches!(
            parse(&[("state", &long)]),
            Err(LogoutRequestError::TooLong {
                parameter: "state",
                ..
            })
        ));
        let long_hint = "x".repeat(MAX_ID_TOKEN_HINT_BYTES + 1);
        assert!(matches!(
            parse(&[("id_token_hint", &long_hint)]),
            Err(LogoutRequestError::TooLong {
                parameter: "id_token_hint",
                ..
            })
        ));
    }

    /// A `state` is echoed into a `Location`; a control character in one is a
    /// header this server did not write.
    #[test]
    fn a_control_character_is_refused() {
        for hostile in ["a\r\nLocation: https://evil.example", "a\nb", "a\u{0}b"] {
            assert_eq!(
                parse(&[("state", hostile)]),
                Err(LogoutRequestError::Malformed("state")),
                "{hostile:?}"
            );
        }
    }

    #[test]
    fn a_hint_names_its_client_through_azp_then_aud() {
        assert_eq!(
            client_from_hint(&json!({"aud": "billing"})),
            Some(ClientId::new("billing"))
        );
        assert_eq!(
            client_from_hint(&json!({"aud": ["billing"]})),
            Some(ClientId::new("billing"))
        );
        assert_eq!(
            client_from_hint(&json!({"aud": ["billing", "other"], "azp": "billing"})),
            Some(ClientId::new("billing"))
        );
    }

    /// Several audiences and no `azp` names nobody: picking one is how one
    /// client's ID token ends another client's session.
    #[test]
    fn an_ambiguous_or_absent_audience_names_nobody() {
        assert_eq!(
            client_from_hint(&json!({"aud": ["billing", "other"]})),
            None
        );
        assert_eq!(client_from_hint(&json!({"aud": []})), None);
        assert_eq!(client_from_hint(&json!({"aud": ""})), None);
        assert_eq!(client_from_hint(&json!({"aud": 7})), None);
        assert_eq!(client_from_hint(&json!({})), None);
    }

    /// §2: a `client_id` sent alongside a hint must match it.
    #[test]
    fn a_client_id_that_contradicts_the_hint_identifies_nobody() {
        let hinted = ClientId::new("billing");
        assert_eq!(
            identify(Some(hinted.clone()), None),
            Rp::Identified(hinted.clone())
        );
        assert_eq!(
            identify(Some(hinted.clone()), Some(&ClientId::new("billing"))),
            Rp::Identified(hinted.clone())
        );
        assert_eq!(
            identify(Some(hinted), Some(&ClientId::new("other"))),
            Rp::Unidentified
        );
    }

    /// §3: no verified hint, no redirection — a bare `client_id` is a claim,
    /// not a proof, until a tenant policy says otherwise.
    #[test]
    fn a_bare_client_id_identifies_nobody() {
        assert_eq!(
            identify(None, Some(&ClientId::new("billing"))),
            Rp::Unidentified
        );
        assert_eq!(identify(None, None), Rp::Unidentified);
    }

    #[test]
    fn an_unidentified_relying_party_gets_a_confirmation_page() {
        let request = LogoutRequest {
            post_logout_redirect_uri: Some(REGISTERED.to_owned()),
            state: Some("s".to_owned()),
            ..LogoutRequest::default()
        };
        assert_eq!(
            disposition(&request, &Rp::Unidentified, &registered()),
            Disposition::Confirm,
            "a request nobody verified must not end a session on its own"
        );
    }

    #[test]
    fn an_identified_relying_party_with_a_registered_uri_is_redirected() {
        let request = LogoutRequest {
            post_logout_redirect_uri: Some(REGISTERED.to_owned()),
            state: Some("opaque".to_owned()),
            ..LogoutRequest::default()
        };
        let Disposition::EndSessionAndRedirect(target) = disposition(
            &request,
            &Rp::Identified(ClientId::new("billing")),
            &registered(),
        ) else {
            panic!("a registered URI must be honoured for an identified RP");
        };
        assert_eq!(target.uri(), REGISTERED);
        assert_eq!(target.state(), Some("opaque"));
    }

    /// §3, byte-exact. Every near miss is a URL the client never registered.
    #[test]
    fn a_near_miss_uri_is_not_honoured() {
        for near in [
            "https://rp.example/after-logout/",
            "https://rp.example/after-logout?x=1",
            "https://RP.example/after-logout",
            "https://rp.example/after-logout#f",
            "https://rp.example.evil.test/after-logout",
            "https://rp.example/after-logou",
        ] {
            let request = LogoutRequest {
                post_logout_redirect_uri: Some(near.to_owned()),
                ..LogoutRequest::default()
            };
            assert_eq!(
                disposition(
                    &request,
                    &Rp::Identified(ClientId::new("billing")),
                    &registered()
                ),
                Disposition::EndSession,
                "{near} was treated as registered"
            );
        }
    }

    #[test]
    fn an_identified_relying_party_without_a_uri_sees_the_logged_out_page() {
        assert_eq!(
            disposition(
                &LogoutRequest::default(),
                &Rp::Identified(ClientId::new("billing")),
                &registered()
            ),
            Disposition::EndSession
        );
    }

    /// §2: `state` is echoed on the redirect, and a redirect is the only place
    /// it can appear — nothing else in this module carries one.
    #[test]
    fn state_is_echoed_onto_the_redirect_and_percent_encoded() {
        let target = RedirectTarget {
            uri: "https://rp.example/after-logout?x=1".to_owned(),
            state: Some("a b&c=d".to_owned()),
        };
        let location = target
            .location(&Notified::after_notifying(0))
            .expect("a registered URI parses");
        assert_eq!(
            location,
            "https://rp.example/after-logout?x=1&state=a+b%26c%3Dd"
        );

        let bare = RedirectTarget {
            uri: REGISTERED.to_owned(),
            state: None,
        };
        assert_eq!(
            bare.location(&Notified::after_notifying(3))
                .expect("parses"),
            REGISTERED,
            "no state, nothing appended"
        );
    }

    #[test]
    fn a_registered_uri_that_will_not_parse_is_reported_rather_than_guessed() {
        let target = RedirectTarget {
            uri: "not a url".to_owned(),
            state: None,
        };
        assert_eq!(
            target.location(&Notified::after_notifying(0)),
            Err(RedirectError::Unparseable)
        );
    }

    #[test]
    fn a_confirmation_token_is_a_digest_of_the_session_id() {
        let token = confirmation_token("session-cookie-value");
        assert_eq!(token.len(), 64);
        assert!(!token.contains("session-cookie-value"));
        assert!(confirmation_token_matches("session-cookie-value", &token));
        assert!(!confirmation_token_matches("another-session", &token));
        assert!(!confirmation_token_matches("session-cookie-value", ""));
        assert_ne!(token, confirmation_token("session-cookie-valu"));
    }

    /// The shape of a token must not vary with the id it came from: a token
    /// that grew, shrank or left the hex alphabet for some ids would be
    /// carrying something about them. Degenerate ids are included on purpose —
    /// `"0"` is the input the `logout_request` fuzz target reported, and the
    /// answer is that its token is the same 64 lower-case hex characters as
    /// every other, not that the id is anywhere inside it.
    #[test]
    fn a_confirmation_token_has_the_same_shape_whatever_the_session_id() {
        for session_id in ["", "0", "ff", "\u{0}\u{7f}", &"x".repeat(4096)] {
            let token = confirmation_token(session_id);
            assert_eq!(token.len(), 64, "{session_id:?}");
            assert!(
                token
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
                "{session_id:?} produced {token:?}"
            );
            assert!(confirmation_token_matches(session_id, &token));
            assert!(!confirmation_token_matches(
                &format!("{session_id}0"),
                &token
            ));
        }
    }

    /// A session id with the width a real one has never appears in its token.
    /// Below that width an occurrence would be a coincidence of the shared hex
    /// alphabet rather than a leak, which is why the check lives here on ids
    /// that are long enough for a hit to mean something.
    #[test]
    fn a_full_width_session_id_never_appears_in_its_token() {
        for session_id in [
            "0123456789abcdef0123456789abcdef",
            "ffffffffffffffffffffffffffffffff",
            "00000000000000000000000000000000",
        ] {
            let token = confirmation_token(session_id);
            assert!(!token.contains(session_id), "{session_id:?} -> {token:?}");
        }
    }
}
