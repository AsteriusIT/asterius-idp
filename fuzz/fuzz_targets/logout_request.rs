//! RP-initiated logout request parameters — OIDC RP-Initiated Logout 1.0 §2–§3.
//!
//! `LogoutRequest::parse` is the only reader of this endpoint's parameters, so
//! anything it accepts is something the end-session endpoint will act on. The
//! properties asserted here are the ones the handler trusts without re-checking:
//!
//! * **No parameter was accepted twice** (RFC 6749 §3.1's rule, inherited),
//!   which is the parameter-pollution defence.
//! * **No accepted value carries a control character.** A `state` is echoed
//!   into a `Location` header, and everything else lands in HTML.
//! * **An accepted value is one that was actually sent**, byte for byte — the
//!   parser never repairs, trims or decodes anything.
//! * **A redirect is only ever produced for an identified relying party, to a
//!   URI that exactly matches a registered one**, and it is the only outcome
//!   that carries the `state` back (§3).
#![no_main]

use arbitrary::Arbitrary;
use asterius_domain::ClientId;
use asterius_oidc::logout::{
    Disposition, LogoutRequest, Notified, Rp, confirmation_token, confirmation_token_matches,
    disposition,
};
use libfuzzer_sys::fuzz_target;

const REGISTERED: &str = "https://rp.example/after-logout";
const CLIENT: &str = "billing";

/// One parameter's worth of adversarial choice.
#[derive(Arbitrary, Debug)]
enum Choice {
    /// Omit it.
    Absent,
    /// The value that should be accepted.
    Correct,
    /// Present twice — the pollution case.
    Twice,
    /// Arbitrary text.
    Text(String),
    /// The correct value with something appended, which must stop matching.
    CorrectPlus(String),
}

impl Choice {
    fn apply(&self, name: &str, correct: &str, into: &mut Vec<(String, String)>) {
        match self {
            Self::Absent => {}
            Self::Correct => into.push((name.into(), correct.into())),
            Self::Twice => {
                into.push((name.into(), correct.into()));
                into.push((name.into(), correct.into()));
            }
            Self::Text(text) => into.push((name.into(), text.clone())),
            Self::CorrectPlus(extra) => into.push((name.into(), format!("{correct}{extra}"))),
        }
    }
}

#[derive(Arbitrary, Debug)]
struct Input {
    id_token_hint: Choice,
    logout_hint: Choice,
    client_id: Choice,
    post_logout_redirect_uri: Choice,
    ui_locales: Choice,
    state: Choice,
    extra: Vec<(String, String)>,
    /// Whether the relying party is treated as identified downstream.
    identified: bool,
    /// The session id a confirmation token would be derived from.
    session_id: String,
}

fuzz_target!(|input: Input| {
    let mut pairs: Vec<(String, String)> = Vec::new();
    input
        .id_token_hint
        .apply("id_token_hint", "a.b.c", &mut pairs);
    input
        .logout_hint
        .apply("logout_hint", "someone", &mut pairs);
    input.client_id.apply("client_id", CLIENT, &mut pairs);
    input
        .post_logout_redirect_uri
        .apply("post_logout_redirect_uri", REGISTERED, &mut pairs);
    input.ui_locales.apply("ui_locales", "en", &mut pairs);
    input.state.apply("state", "opaque", &mut pairs);
    for (name, value) in &input.extra {
        pairs.push((name.clone(), value.clone()));
    }

    // A token is a digest of the session id: it never leaks the id, and only
    // the id that produced it verifies.
    let token = confirmation_token(&input.session_id);
    assert_eq!(token.len(), 64, "a confirmation token is a sha-256 digest");
    assert!(confirmation_token_matches(&input.session_id, &token));
    assert!(
        input.session_id.is_empty() || !token.contains(&input.session_id),
        "the session id must not survive into its own token"
    );

    let Ok(request) = LogoutRequest::parse(pairs.clone()) else {
        return;
    };

    // --- properties of an ACCEPTED request ---

    let sent_once = |name: &str| -> Option<&str> {
        let mut found = pairs.iter().filter(|(k, _)| k == name);
        let first = found.next().map(|(_, v)| v.as_str());
        assert!(
            found.next().is_none(),
            "accepted a request with two {name} parameters"
        );
        first
    };

    let accepted: [(&str, Option<&str>); 6] = [
        ("id_token_hint", request.id_token_hint.as_deref()),
        ("logout_hint", request.logout_hint.as_deref()),
        (
            "client_id",
            request.client_id.as_ref().map(ClientId::as_str),
        ),
        (
            "post_logout_redirect_uri",
            request.post_logout_redirect_uri.as_deref(),
        ),
        ("ui_locales", request.ui_locales.as_deref()),
        ("state", request.state.as_deref()),
    ];
    for (name, value) in accepted {
        let Some(value) = value else {
            continue;
        };
        assert!(
            !value.chars().any(char::is_control),
            "{name} was accepted carrying a control character: {value:?}"
        );
        assert_eq!(
            Some(value),
            sent_once(name),
            "{name} was not accepted as it was sent"
        );
    }

    // --- properties of the DECISION ---

    let rp = if input.identified {
        Rp::Identified(ClientId::new(CLIENT))
    } else {
        Rp::Unidentified
    };
    let registered = [REGISTERED.to_owned()];
    match disposition(&request, &rp, &registered) {
        Disposition::Confirm => assert!(
            !input.identified,
            "an identified relying party never needs a confirmation page"
        ),
        Disposition::EndSession => {}
        Disposition::EndSessionAndRedirect(target) => {
            assert!(
                input.identified,
                "§3: no redirection without an identified relying party"
            );
            assert_eq!(
                target.uri(),
                REGISTERED,
                "§3: a post-logout redirect goes to a registered URI, byte for byte"
            );
            assert_eq!(
                target.state(),
                request.state.as_deref(),
                "§2: the state is echoed exactly, and only here"
            );
            let location = target
                .location(&Notified::after_notifying(0))
                .expect("a registered URI parses");
            assert!(
                !location.chars().any(char::is_control),
                "a Location header must not carry a control character: {location:?}"
            );
            assert!(location.starts_with(REGISTERED));
        }
    }
});
