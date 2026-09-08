//! Authorization codes, and the response that carries one back.
//!
//! A code is the shortest-lived and most tightly bound credential this server
//! issues. It exists for one round trip: from the browser, through the client,
//! to the token endpoint. Everything about it is chosen to make that trip and
//! nothing else.
//!
//! # Why it is bound to so much
//!
//! On its own a code is a bearer token that anyone who reads a URL can redeem.
//! Every binding recorded at issuance is a separate thing an attacker must also
//! have:
//!
//! * the **client** it was issued to, so a different client cannot redeem it;
//! * the **`redirect_uri`** it was sent to, compared byte-for-byte at
//!   redemption (OIDC Core §3.1.3.2);
//! * the **PKCE challenge**, so redemption needs the verifier the browser
//!   never sent anywhere (RFC 7636 §4.6);
//! * the **DPoP key**, when the request pinned one (RFC 9449 §10);
//! * the **grant**, so revoking the grant kills the code.
//!
//! FAPI 2.0 SP's attacker model assumes the code *will* leak — A3a reads the
//! authorization response. The bindings are what make a leaked code worthless.
//!
//! # Why sixty seconds
//!
//! FAPI 2.0 SP §5.3.2.1 item 11: "shall issue authorization codes with a
//! maximum lifetime of 60 seconds". That is a hard cap, not a default, and the
//! schema carries a `CHECK` constraint saying the same thing — so a row that
//! violated it could not be written even if this code were wrong.

pub use asterius_domain::CodeBinding;
use asterius_domain::{OpaqueToken, sha256_hex};
use time::Duration;

/// Bits of entropy in an authorization code.
///
/// The acceptance criterion asks for 128. This uses the same 256 every other
/// bearer value here does: there is no reason for the shortest-lived credential
/// to be the weakest, and the cost is 22 more characters in a URL.
pub const CODE_BITS: usize = 256;

/// The longest an authorization code may live.
///
/// FAPI 2.0 SP §5.3.2.1 item 11. A hard cap: `clamp_lifetime` reduces anything
/// larger rather than refusing it, so a misconfiguration produces a compliant
/// server rather than one that will not start.
pub const MAX_LIFETIME: Duration = Duration::seconds(60);

/// How long a code lives unless a tenant says less.
///
/// The cap itself. A code is redeemed within one HTTP round trip of being
/// issued, so there is nothing to gain from a shorter default and a slow
/// network to lose by it.
pub const DEFAULT_LIFETIME: Duration = MAX_LIFETIME;

/// A freshly minted code and the digest to store.
///
/// The value reaches exactly two places: the redirect URL, and — as a digest —
/// the database. It is redacted everywhere else.
pub struct MintedCode {
    value: OpaqueToken,
    digest: String,
}

impl MintedCode {
    /// Mints a code.
    #[must_use]
    pub fn generate() -> Self {
        let value = OpaqueToken::generate_bits::<CODE_BITS>();
        let digest = sha256_hex(value.expose().as_bytes());
        Self { value, digest }
    }

    /// The value to put in the redirect.
    #[must_use]
    pub fn expose(&self) -> &str {
        self.value.expose()
    }

    /// The value to store.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }
}

impl std::fmt::Debug for MintedCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MintedCode")
            .field("value", &"[REDACTED]")
            .field("digest", &self.digest)
            .finish()
    }
}

/// Turns a presented code into the digest to look up.
///
/// Shape is checked before the database is touched, so a guess costs a
/// comparison rather than a query.
///
/// # Errors
///
/// Returns `()` when the value could not have been issued here.
// fuzz-target: authorization_code
pub fn digest_of(presented: &str) -> Result<String, MalformedCode> {
    let expected = CODE_BITS.div_ceil(6);
    if presented.len() != expected
        || !presented
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(MalformedCode);
    }
    Ok(sha256_hex(presented.as_bytes()))
}

/// A presented value that this server could not have issued.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("not an authorization code issued by this server")]
pub struct MalformedCode;

/// Clamps a configured code lifetime to the profile's cap.
#[must_use]
pub fn clamp_lifetime(configured: Duration) -> Duration {
    configured.clamp(Duration::seconds(1), MAX_LIFETIME)
}

/// The parameters of the redirect back to the client.
///
/// Built as a type rather than assembled in the handler so that `iss` cannot be
/// forgotten on one of the two paths — which is exactly the mistake RFC 9207
/// exists to prevent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizationResponse {
    /// The user approved.
    Code {
        /// The code itself.
        code: String,
        /// `state`, echoed byte-for-byte if the request carried one.
        state: Option<String>,
        /// The issuer identifier (RFC 9207 §2).
        issuer: String,
    },
    /// The user refused, or the request could not be completed.
    Error {
        /// An RFC 6749 §4.1.2.1 code.
        error: &'static str,
        /// `state`, echoed byte-for-byte if the request carried one.
        state: Option<String>,
        /// The issuer identifier. **Also required on errors** — see
        /// [`AuthorizationResponse::query`].
        issuer: String,
    },
}

impl AuthorizationResponse {
    /// The query parameters, in the order they will appear.
    ///
    /// `iss` is on *both* variants. RFC 9207 §2: "the authorization server
    /// MUST indicate its identity by including the `iss` parameter in the
    /// authorization response". An error response is an authorization
    /// response, and the mix-up attack RFC 9207 addresses works just as well
    /// with one — a client that only checks `iss` on success can still be
    /// steered by an error it attributes to the wrong server.
    #[must_use]
    pub fn query(&self) -> Vec<(&'static str, String)> {
        let mut pairs = Vec::with_capacity(3);
        match self {
            Self::Code {
                code,
                state,
                issuer,
            } => {
                pairs.push(("code", code.clone()));
                if let Some(state) = state {
                    pairs.push(("state", state.clone()));
                }
                pairs.push(("iss", issuer.clone()));
            }
            Self::Error {
                error,
                state,
                issuer,
            } => {
                pairs.push(("error", (*error).to_owned()));
                if let Some(state) = state {
                    pairs.push(("state", state.clone()));
                }
                pairs.push(("iss", issuer.clone()));
            }
        }
        pairs
    }

    /// Builds the redirect URL.
    ///
    /// The parameters go in the query string. `redirect_uri` may already carry
    /// one (RFC 6749 §3.1.2 permits it), so they are appended rather than
    /// replacing it — a client that registered `?tenant=x` gets to keep it.
    ///
    /// # Except the names this response uses
    ///
    /// A registered `?code=already` would otherwise produce a URL carrying
    /// both a `code` and an `error`, and a client handed both gets to decide
    /// which response it is looking at — OIDC Core §3.1.2.5 and §3.1.2.6 are
    /// two responses, not one with optional halves. A client that reads the
    /// *first* `code` it finds would take the registered one over the issued
    /// one, and a `state` from the registration would defeat the CSRF check it
    /// exists to make.
    ///
    /// So every parameter in [`RESERVED`] is dropped from the registered URI
    /// before this response's own are appended. Nothing legitimate is lost:
    /// those names belong to the protocol at this endpoint, and a client
    /// cannot have meant anything by pre-setting one. Found by fuzzing, which
    /// is the only reason it is here — nobody registers `?code=` on purpose,
    /// and that is exactly the kind of parameter an attacker would look for.
    ///
    /// # Errors
    ///
    /// [`MalformedRedirect`] if the stored URI will not parse. It was
    /// validated at registration, so this is unreachable in practice; refusing
    /// is the only safe reading of the impossible case, because the
    /// alternative is sending a browser somewhere unparsed.
    pub fn redirect_url(&self, redirect_uri: &str) -> Result<String, MalformedRedirect> {
        let mut url = url::Url::parse(redirect_uri).map_err(|_| MalformedRedirect)?;

        // Collected first, which also ends the borrow `set_query` needs.
        let kept: Vec<(String, String)> = url
            .query_pairs()
            .filter(|(name, _)| !RESERVED.contains(&name.as_ref()))
            .map(|(name, value)| (name.into_owned(), value.into_owned()))
            .collect();
        url.set_query(None);
        {
            let mut query = url.query_pairs_mut();
            for (name, value) in &kept {
                query.append_pair(name, value);
            }
            for (name, value) in self.query() {
                query.append_pair(name, &value);
            }
        }
        Ok(url.into())
    }
}

/// The parameter names an authorization response owns.
///
/// A registered redirect URI carrying one of these has it removed before the
/// response is built — see [`AuthorizationResponse::redirect_url`]. The error
/// members are here even though this server does not send them, because a
/// client parsing an error response reads them and a registration must not be
/// able to supply one.
pub const RESERVED: [&str; 6] = [
    "code",
    "state",
    "iss",
    "error",
    "error_description",
    "error_uri",
];

/// A stored redirect URI that will not parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the registered redirect URI is not a URL")]
pub struct MalformedRedirect;

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    const ISSUER: &str = "https://as.example/t/demo";

    #[test]
    fn a_code_is_full_length_base64url_and_round_trips() {
        let minted = MintedCode::generate();
        assert_eq!(minted.expose().len(), CODE_BITS.div_ceil(6));
        assert_eq!(digest_of(minted.expose()).expect("ours"), minted.digest());
    }

    #[test]
    fn codes_do_not_repeat() {
        let mut seen = HashSet::new();
        for _ in 0..2_000 {
            assert!(
                seen.insert(MintedCode::generate().expose().to_owned()),
                "a code repeated"
            );
        }
    }

    #[test]
    fn the_stored_form_is_a_digest_and_debug_hides_the_code() {
        let minted = MintedCode::generate();
        assert_eq!(minted.digest().len(), 64);
        assert!(!minted.digest().contains(minted.expose()));

        let rendered = format!("{minted:?}");
        assert!(!rendered.contains(minted.expose()), "{rendered}");
        assert!(rendered.contains("[REDACTED]"), "{rendered}");
    }

    #[test]
    fn a_value_this_server_could_not_have_issued_is_refused() {
        for wrong in [
            "",
            "short",
            &"a".repeat(CODE_BITS.div_ceil(6) - 1),
            &"a".repeat(CODE_BITS.div_ceil(6) + 1),
            &"+".repeat(CODE_BITS.div_ceil(6)),
            &"=".repeat(CODE_BITS.div_ceil(6)),
        ] {
            assert_eq!(digest_of(wrong), Err(MalformedCode), "accepted {wrong:?}");
        }
    }

    /// FAPI 2.0 SP §5.3.2.1 item 11. The schema carries the same rule as a
    /// `CHECK`, so a row violating it cannot be written even if this were
    /// wrong.
    #[test]
    fn a_lifetime_is_capped_at_sixty_seconds() {
        assert_eq!(clamp_lifetime(Duration::seconds(30)), Duration::seconds(30));
        assert_eq!(clamp_lifetime(Duration::hours(1)), MAX_LIFETIME);
        assert_eq!(MAX_LIFETIME, Duration::seconds(60));
        assert!(DEFAULT_LIFETIME <= MAX_LIFETIME);
        // Never zero: a code that has expired when it is issued is a client
        // that can never succeed and cannot tell why.
        assert_eq!(clamp_lifetime(Duration::ZERO), Duration::seconds(1));
        assert_eq!(clamp_lifetime(Duration::seconds(-5)), Duration::seconds(1));
    }

    /// RFC 9207 §2. The mix-up attack works just as well with an error
    /// response, so `iss` is on both paths.
    #[test]
    fn every_response_carries_the_issuer() {
        let success = AuthorizationResponse::Code {
            code: "abc".into(),
            state: Some("xyz".into()),
            issuer: ISSUER.into(),
        };
        let failure = AuthorizationResponse::Error {
            error: "access_denied",
            state: Some("xyz".into()),
            issuer: ISSUER.into(),
        };

        for response in [&success, &failure] {
            let pairs = response.query();
            assert!(
                pairs.iter().any(|(k, v)| *k == "iss" && v == ISSUER),
                "no iss in {pairs:?}"
            );
        }
    }

    /// `state` is echoed byte-for-byte, and omitted entirely when the request
    /// carried none — inventing an empty one would look like a value.
    #[test]
    fn state_is_echoed_verbatim_or_not_at_all() {
        for state in ["xyz", "a b", "üñî", "", "with=equals&and=amp"] {
            let response = AuthorizationResponse::Code {
                code: "abc".into(),
                state: Some(state.to_owned()),
                issuer: ISSUER.into(),
            };
            let pairs = response.query();
            let echoed = pairs
                .iter()
                .find(|(k, _)| *k == "state")
                .map(|(_, v)| v.as_str());
            assert_eq!(echoed, Some(state), "state was altered");
        }

        let none = AuthorizationResponse::Code {
            code: "abc".into(),
            state: None,
            issuer: ISSUER.into(),
        };
        assert!(!none.query().iter().any(|(k, _)| *k == "state"));
    }

    /// A client that registered a redirect URI with a query keeps it.
    #[test]
    fn existing_query_parameters_survive() {
        let response = AuthorizationResponse::Code {
            code: "abc".into(),
            state: None,
            issuer: ISSUER.into(),
        };
        let url = response
            .redirect_url("https://rp.example/cb?tenant=x")
            .expect("url");
        assert!(url.contains("tenant=x"), "{url}");
        assert!(url.contains("code=abc"), "{url}");
        assert!(url.starts_with("https://rp.example/cb?"), "{url}");
    }

    /// Everything that goes into the URL is encoded, so a `state` cannot add a
    /// parameter of its own.
    #[test]
    fn a_hostile_state_cannot_inject_a_parameter() {
        let response = AuthorizationResponse::Code {
            code: "abc".into(),
            state: Some("x&code=stolen&y".into()),
            issuer: ISSUER.into(),
        };
        let url = response.redirect_url("https://rp.example/cb").expect("url");

        let parsed = url::Url::parse(&url).expect("parse");
        let codes: Vec<_> = parsed
            .query_pairs()
            .filter(|(k, _)| k == "code")
            .map(|(_, v)| v.into_owned())
            .collect();
        assert_eq!(codes, vec!["abc"], "a state injected a second code: {url}");

        let states: Vec<_> = parsed
            .query_pairs()
            .filter(|(k, _)| k == "state")
            .map(|(_, v)| v.into_owned())
            .collect();
        assert_eq!(states, vec!["x&code=stolen&y"], "the state was mangled");
    }

    /// Found by fuzzing. A registration holding `?code=already` would
    /// otherwise put a code and an error in one response, and a client reading
    /// the first `code` it finds would redeem the registered one.
    #[test]
    fn a_registered_parameter_cannot_impersonate_part_of_the_response() {
        let registered = "https://rp.example/cb?code=already&state=forged&iss=https://evil\
            .example&error=access_denied&tenant=x";

        let success = AuthorizationResponse::Code {
            code: "issued".into(),
            state: Some("real".into()),
            issuer: ISSUER.into(),
        };
        let url = url::Url::parse(&success.redirect_url(registered).expect("url")).expect("parse");
        let values = |name: &str| -> Vec<String> {
            url.query_pairs()
                .filter(|(k, _)| k == name)
                .map(|(_, v)| v.into_owned())
                .collect()
        };
        assert_eq!(values("code"), vec!["issued"], "{url}");
        assert_eq!(values("state"), vec!["real"], "{url}");
        assert_eq!(values("iss"), vec![ISSUER], "{url}");
        assert!(
            values("error").is_empty(),
            "a success carried an error: {url}"
        );
        // Everything that is not the protocol's own is untouched.
        assert_eq!(values("tenant"), vec!["x"], "{url}");

        let failure = AuthorizationResponse::Error {
            error: "access_denied",
            state: None,
            issuer: ISSUER.into(),
        };
        let url = url::Url::parse(&failure.redirect_url(registered).expect("url")).expect("parse");
        let codes: Vec<_> = url.query_pairs().filter(|(k, _)| k == "code").collect();
        assert!(codes.is_empty(), "an error response carried a code: {url}");
    }

    #[test]
    fn a_denial_carries_the_specified_error_code() {
        let response = AuthorizationResponse::Error {
            error: "access_denied",
            state: None,
            issuer: ISSUER.into(),
        };
        let pairs = response.query();
        assert!(pairs.contains(&("error", "access_denied".to_owned())));
        assert!(!pairs.iter().any(|(k, _)| *k == "code"));
    }

    #[test]
    fn an_unparseable_redirect_uri_is_refused_rather_than_guessed() {
        let response = AuthorizationResponse::Code {
            code: "abc".into(),
            state: None,
            issuer: ISSUER.into(),
        };
        assert_eq!(response.redirect_url("not a url"), Err(MalformedRedirect));
    }
}
