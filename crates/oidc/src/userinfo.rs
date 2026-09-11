//! The UserInfo endpoint's protocol rules (OIDC Core §5.3).
//!
//! This is the authorization server acting as a resource server for its own
//! claims, so everything here is written from the resource server's side of
//! the profile: how a token may be presented (RFC 6750 §2, RFC 9449 §7.1,
//! FAPI 2.0 SP §5.3.4), what a refusal says (RFC 6750 §3, OIDC Core §5.3.3),
//! and what a response contains (§5.3.2).
//!
//! Three rules carry the weight.
//!
//! ## A token in the query string is refused before it is read
//!
//! FAPI 2.0 SP §5.3.4 item 1: a resource server "shall accept access tokens
//! in the HTTP header only" and "shall not accept access tokens in the query
//! parameters". RFC 6750 §5.3 says why: a URL ends up in the browser's
//! history, in the `Referer` header of the next request, and in every access
//! log between here and the client.
//!
//! So [`present`] looks at the query string *first*, and a request naming
//! `access_token` there is refused without the credential ever being parsed,
//! let alone verified. "Never processed" is a statement about the order of the
//! checks, which is why the order is the function's shape rather than a
//! comment: a credential that has been verified has already been processed,
//! however loudly the answer says 400.
//!
//! ## The scheme is not the token's binding
//!
//! [`present`] reports which scheme was used and judges nothing else. Whether
//! `Bearer` is acceptable depends on how the token that follows it is bound —
//! RFC 9449 §7.1 makes `DPoP` the scheme for a DPoP-bound token, and RFC 8705
//! §3 leaves a certificate-bound token on `Bearer` — and that is a fact about
//! the *token*, which is not known until it has been verified. Deciding it
//! here would mean deciding it before knowing it.
//!
//! ## `sub` is the server's, and it is written last
//!
//! OIDC Core §5.3.2: "The `sub` (subject) Claim MUST always be returned in the
//! UserInfo Response", and §5.3.4 makes a client that compares it against its
//! ID token's `sub` — "if they do not match, the UserInfo Response values MUST
//! NOT be used" — the whole reason the claim is there. [`body`] therefore
//! takes the subject as its own argument and inserts it after the released
//! claims, so a released map that somehow carried a `sub` could not become the
//! one a relying party reads. (`ReleasableClaim` has no variant for `sub`, so
//! it cannot; this is the second lock on the same door.)

use asterius_domain::{Issuer, SigningAlgorithm};
use serde_json::{Map, Value};

/// The scope an access token must carry to read UserInfo (OIDC Core §5.3.1).
///
/// > The Client sends the UserInfo Request using either HTTP GET or HTTP POST.
/// > The Access Token obtained from an OpenID Connect Authentication Request
/// > MUST be sent as a Bearer Token.
///
/// An access token with no `openid` scope is a token for some other resource,
/// and answering it would release a person's claims to an authorization that
/// never asked for them.
pub const REQUIRED_SCOPE: &str = "openid";

/// The query parameter RFC 6750 §2.3 defines and this endpoint refuses.
pub const QUERY_PARAMETER: &str = "access_token";

/// The `typ` header of a signed UserInfo response.
///
/// OIDC Core §5.3.2 calls it "a signed JWT" and names no explicit type, so
/// this is RFC 7519 §5.1's registered default rather than a media type
/// invented here. The response's `Content-Type` is `application/jwt`, which is
/// what a client actually dispatches on.
pub const RESPONSE_TYP: &str = "JWT";

/// The largest `Authorization` header this endpoint will look at.
///
/// A JWT access token with a `cnf`, a `scope` and an `authorization_details`
/// is comfortably under a kilobyte; the access token profile bounds its own
/// claims at 4 KiB (`tokens::MAX_ACCESS_TOKEN_CLAIMS_BYTES`), and base64 of
/// that plus a signature does not reach here. Beyond it the value is not a
/// credential, it is a way to make the server base64-decode for free.
pub const MAX_CREDENTIAL_BYTES: usize = 8 * 1024;

// ---------------------------------------------------------------------------
// Presentation
// ---------------------------------------------------------------------------

/// How a caller presented its access token.
///
/// Borrowed from the header, because the next thing that happens to it is a
/// signature check and a copy would be one more place a credential lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Presentation<'a> {
    /// RFC 9449 §7.1: the scheme for a DPoP-bound access token, which must be
    /// accompanied by a proof whose `ath` hashes it.
    Dpop(&'a str),
    /// RFC 6750 §2.1, and RFC 8705 §3 for a certificate-bound token.
    Bearer(&'a str),
}

impl<'a> Presentation<'a> {
    /// The credential itself, whichever scheme carried it.
    #[must_use]
    pub const fn token(&self) -> &'a str {
        match self {
            Self::Dpop(token) | Self::Bearer(token) => token,
        }
    }

    /// Whether the token arrived under the `DPoP` scheme.
    #[must_use]
    pub const fn is_dpop(&self) -> bool {
        matches!(self, Self::Dpop(_))
    }
}

/// Why a UserInfo request was refused.
///
/// Every variant maps to one of RFC 6750 §3.1's codes, and the mapping is
/// [`UserInfoError::code`] rather than a string at each call site — a resource
/// server that invents a code is a resource server whose clients cannot tell
/// "your token expired" from "you are asking for the wrong thing".
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum UserInfoError {
    /// The access token was offered in the query string (FAPI 2.0 SP §5.3.4).
    #[error("an access token was presented in the query string")]
    TokenInQuery,
    /// No `Authorization` header at all.
    #[error("no access token was presented")]
    NoCredential,
    /// More than one `Authorization` header, which is a request that presents
    /// two credentials and lets the server choose.
    #[error("more than one Authorization header was presented")]
    RepeatedAuthorization,
    /// A scheme this endpoint does not implement.
    #[error("the Authorization scheme is not one this endpoint accepts")]
    UnsupportedScheme,
    /// The credential is not RFC 7235 §2.1's `token68` production.
    #[error("the credential is not a token68 value")]
    MalformedCredential,
    /// The token did not verify, is expired, revoked, or is not bound to the
    /// key that presented it. One variant for all of them on purpose: RFC 6750
    /// §3.1 defines `invalid_token` as covering exactly that set, and telling
    /// them apart tells a holder of a stolen token which half to fix.
    #[error("the access token is not one this endpoint accepts")]
    InvalidToken,
    /// The token is valid and does not carry [`REQUIRED_SCOPE`].
    #[error("the access token does not carry the openid scope")]
    InsufficientScope,
}

impl UserInfoError {
    /// The RFC 6750 §3.1 error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            // §3.1: "The request is missing a required parameter, includes an
            // unsupported parameter or parameter value, repeats the same
            // parameter, uses more than one method for including an access
            // token, or is otherwise malformed."
            Self::TokenInQuery | Self::RepeatedAuthorization | Self::UnsupportedScheme => {
                "invalid_request"
            }
            Self::NoCredential | Self::MalformedCredential | Self::InvalidToken => "invalid_token",
            Self::InsufficientScope => "insufficient_scope",
        }
    }

    /// The HTTP status (RFC 6750 §3.1, OIDC Core §5.3.3).
    #[must_use]
    pub const fn status(&self) -> u16 {
        match self {
            Self::TokenInQuery | Self::RepeatedAuthorization | Self::UnsupportedScheme => 400,
            Self::NoCredential | Self::MalformedCredential | Self::InvalidToken => 401,
            Self::InsufficientScope => 403,
        }
    }

    /// What the `error_description` attribute says.
    ///
    /// A fixed sentence per variant, never anything from the request. RFC 6750
    /// §3 puts this in a response header, and a header that echoes attacker
    /// input is a response-splitting question nobody needs to answer.
    #[must_use]
    pub const fn description(&self) -> &'static str {
        match self {
            Self::TokenInQuery => "an access token must be sent in the Authorization header",
            Self::NoCredential => "an access token is required",
            Self::RepeatedAuthorization => "send exactly one Authorization header",
            Self::UnsupportedScheme => "use the DPoP authentication scheme",
            Self::MalformedCredential => "the credential is malformed",
            Self::InvalidToken => "the access token is expired, revoked or not valid here",
            Self::InsufficientScope => "the openid scope is required",
        }
    }
}

/// The `WWW-Authenticate` challenges a refusal carries (RFC 6750 §3).
///
/// Two values and not one. RFC 9449 §7.1 requires the `DPoP` scheme to be
/// offered — with `algs`, so a client knows what to sign a proof with — and
/// RFC 6750 §3 defines the `Bearer` challenge every OAuth client already
/// understands. RFC 9110 §11.6.1 allows and expects several challenges, and a
/// server that offered only one would be telling half its clients to use a
/// scheme this deployment may not accept for their token.
///
/// The `DPoP` challenge comes first because it is the one this server prefers:
/// RFC 9110 §11.6.1 gives no precedence to order, but clients read it that way
/// and it costs nothing to be clear.
#[must_use]
pub fn challenges(error: Option<&UserInfoError>) -> Vec<String> {
    let algs = SigningAlgorithm::ALL
        .iter()
        .map(|alg| alg.as_str())
        .collect::<Vec<_>>()
        .join(" ");
    let attributes = error.map_or_else(String::new, |error| {
        format!(
            r#" error="{}", error_description="{}""#,
            error.code(),
            error.description()
        )
    });
    vec![
        format!(r#"DPoP algs="{algs}"{attributes}"#),
        format!("Bearer{attributes}"),
    ]
}

/// Reads the access token off a request.
///
/// `authorizations` is every `Authorization` header value, in order — plural
/// because "there is exactly one" is a rule this function enforces rather than
/// an assumption it makes. `query` is the raw query string, if any.
///
/// The query string is examined first and a request naming `access_token`
/// there is refused outright, whether or not it also carries a header: FAPI
/// 2.0 SP §5.3.4 and RFC 6750 §2.3 (which this server does not implement) plus
/// §3.1's "uses more than one method for including an access token".
///
/// # Errors
///
/// Returns the [`UserInfoError`] the caller renders. Total: every input is
/// either a [`Presentation`] or a refusal, and nothing here can panic.
// fuzz-target: userinfo_presentation
pub fn present<'a>(
    authorizations: &[&'a str],
    query: Option<&str>,
) -> Result<Presentation<'a>, UserInfoError> {
    if let Some(query) = query
        && url::form_urlencoded::parse(query.as_bytes()).any(|(name, _)| name == QUERY_PARAMETER)
    {
        return Err(UserInfoError::TokenInQuery);
    }

    let raw = match authorizations {
        [] => return Err(UserInfoError::NoCredential),
        [only] => *only,
        _ => return Err(UserInfoError::RepeatedAuthorization),
    };
    if raw.len() > MAX_CREDENTIAL_BYTES {
        return Err(UserInfoError::MalformedCredential);
    }

    // RFC 9110 §11.4: `credentials = auth-scheme [ 1*SP token68 ]`. The scheme
    // is case-insensitive (§11.1); the credential is not.
    let (scheme, credential) = raw
        .split_once(' ')
        .ok_or(UserInfoError::UnsupportedScheme)?;
    // A single space is the grammar; more than one is not, and trimming would
    // accept `DPoP<tab>token`, which two parsers can read differently.
    let credential = credential.trim_start_matches(' ');
    if credential.is_empty() || !is_token68(credential) {
        return Err(UserInfoError::MalformedCredential);
    }

    if scheme.eq_ignore_ascii_case("dpop") {
        Ok(Presentation::Dpop(credential))
    } else if scheme.eq_ignore_ascii_case("bearer") {
        Ok(Presentation::Bearer(credential))
    } else {
        Err(UserInfoError::UnsupportedScheme)
    }
}

/// RFC 7235 §2.1's `token68`.
///
/// `1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="`. A JWT is
/// base64url with dots, so it fits; anything with a space, a comma or a
/// control character in it is not a credential this server was sent, it is two
/// header values that arrived as one.
fn is_token68(value: &str) -> bool {
    let mut seen_padding = false;
    for byte in value.bytes() {
        match byte {
            b'=' => seen_padding = true,
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'+' | b'/'
                if !seen_padding => {}
            _ => return false,
        }
    }
    true
}

// ---------------------------------------------------------------------------
// The response
// ---------------------------------------------------------------------------

/// Whether the token's `scope` claim admits a UserInfo request.
///
/// OIDC Core §5.3.1 ties the endpoint to the `openid` scope, and RFC 6750 §3.1
/// makes the answer `insufficient_scope` with a 403 rather than a 401 — the
/// credential is fine, it just does not authorise this.
///
/// `scope` is the token's claim, space-delimited (RFC 9068 §2.2.3). It is the
/// grant's scope set as it stood when the token was minted, which is the set
/// this particular credential carries.
///
/// # Errors
///
/// [`UserInfoError::InsufficientScope`] when `openid` is absent.
pub fn check_scope(scope: Option<&str>) -> Result<(), UserInfoError> {
    let granted = scope.unwrap_or_default();
    if granted.split(' ').any(|value| value == REQUIRED_SCOPE) {
        Ok(())
    } else {
        Err(UserInfoError::InsufficientScope)
    }
}

/// The UserInfo response body (OIDC Core §5.3.2).
///
/// `subject` is the `sub` of the access token, which is the `sub` the ID token
/// for this grant carried — the same [`asterius_domain::Grant::subject`],
/// pairwise or public as the client is registered. It is written after
/// `released`, so it is the value a client reads whatever the map contains.
#[must_use]
pub fn body(subject: &str, released: Map<String, Value>) -> Map<String, Value> {
    let mut claims = released;
    claims.insert("sub".to_owned(), Value::String(subject.to_owned()));
    claims
}

/// Adds the application roles a person holds to a UserInfo body (`ast-095`).
///
/// The same two claims an access token carries, in the same shape, so that a
/// relying party reading `roles` out of a token and out of UserInfo does not
/// need two mappers: `roles` for the tenant's shared catalogue and
/// `resource_access.<client_id>.roles` for one client's.
///
/// **Narrowed to `client` here, as at the access token.** The caller passes
/// what the *user* holds and this function decides what the response says, so
/// there is no call site that could widen it. UserInfo is answered to a client
/// holding a token, and a client learning the roles somebody holds in another
/// application would be the same disclosure `AccessToken::with_roles` refuses.
///
/// Roles are authorization attributes, not the personal data a `claims`
/// parameter releases (OIDC Core §5.5), so they are not gated on a scope and
/// do not appear on a consent screen. That is a decision, recorded in
/// `docs/threat-model.md`: the alternative — a scope somebody has to remember
/// to request — would mean an application silently receiving *no* roles and
/// authorising as if the person held none.
#[must_use]
pub fn with_roles(
    mut body: Map<String, Value>,
    client_id: &str,
    held: &asterius_domain::HeldRoles,
) -> Map<String, Value> {
    let narrowed = held.for_client(&asterius_domain::ClientId::new(client_id.to_owned()));
    // `HeldRoles::claim` renders both, and is the same function the access
    // token and the ID token call: three responses carrying one shape, and one
    // place to change it. It writes nothing for a claim with nothing to say,
    // so a person holding no roles gets no member rather than an empty array.
    for claim in asterius_domain::RoleClaim::ALL {
        if let Some(value) = narrowed.claim(claim) {
            body.insert(claim.as_str().to_owned(), value);
        }
    }
    body
}

/// The claims of a signed UserInfo response (OIDC Core §5.3.2).
///
/// > If the UserInfo Response is signed and/or encrypted, then the Claims are
/// > returned in a JWT and the `content-type` MUST be `application/jwt`. The
/// > signed JWT SHOULD contain the Claims `iss` (issuer) and `aud` (audience)
/// > as members. The `iss` value SHOULD be the OP's Issuer Identifier URL. The
/// > `aud` value SHOULD be or include the RP's Client ID value.
///
/// Both are written here rather than left to the signer, because their absence
/// is what makes a signed response replayable at another relying party: a JWT
/// with a `sub` and no `aud` is a statement about a person that any RP can be
/// told is about its own user.
#[must_use]
pub fn signed_claims(issuer: &Issuer, client_id: &str, body: Map<String, Value>) -> Value {
    let mut claims = body;
    claims.insert("iss".to_owned(), Value::String(issuer.as_str().to_owned()));
    claims.insert("aud".to_owned(), Value::String(client_id.to_owned()));
    Value::Object(claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "eyJ0eXAiOiJhdCtqd3QifQ.eyJzdWIiOiJhbGljZSJ9.c2ln";

    // ---- presentation (RFC 6750 §2, FAPI 2.0 SP §5.3.4) -------------------

    /// RFC 9449 §7.1: a DPoP-bound token is presented with the `DPoP` scheme.
    #[test]
    fn a_dpop_credential_is_read_from_the_authorization_header() {
        let header = format!("DPoP {TOKEN}");
        let presented = present(&[&header], None).expect("a presentation");

        assert_eq!(presented, Presentation::Dpop(TOKEN));
        assert!(presented.is_dpop());
    }

    /// RFC 9110 §11.1: the scheme is case-insensitive, the credential is not.
    #[test]
    fn the_scheme_is_matched_without_regard_to_case() {
        for spelling in ["dpop", "DPOP", "DPoP"] {
            let header = format!("{spelling} {TOKEN}");
            let presented = present(&[&header], None).expect("a presentation");
            assert_eq!(presented.token(), TOKEN);
        }
    }

    /// The scheme is reported, not judged: whether `Bearer` is acceptable
    /// depends on how the token is bound, which is not known yet.
    #[test]
    fn a_bearer_credential_is_read_rather_than_refused() {
        let header = format!("Bearer {TOKEN}");
        let presented = present(&[&header], None).expect("a presentation");

        assert_eq!(presented, Presentation::Bearer(TOKEN));
        assert!(!presented.is_dpop());
    }

    /// FAPI 2.0 SP §5.3.4: a token in the query string is refused, and it is
    /// refused *first* — the header beside it is never even parsed.
    #[test]
    fn a_token_in_the_query_string_is_refused_before_the_header_is_read() {
        let header = format!("DPoP {TOKEN}");
        let refusal = present(&[&header], Some("access_token=abc"))
            .expect_err("query strings carry no credentials here");

        assert_eq!(refusal, UserInfoError::TokenInQuery);
        assert_eq!(refusal.status(), 400);
        assert_eq!(refusal.code(), "invalid_request");
    }

    /// Only that parameter. A `schema=openid` query is not a token.
    #[test]
    fn an_unrelated_query_parameter_is_not_a_token() {
        let header = format!("DPoP {TOKEN}");
        assert!(present(&[&header], Some("state=abc")).is_ok());
    }

    /// RFC 6750 §3.1: repeating the credential is `invalid_request`, because a
    /// server that picks one of two headers is a server an attacker can steer.
    #[test]
    fn two_authorization_headers_are_a_bad_request() {
        let header = format!("DPoP {TOKEN}");
        let refusal = present(&[&header, &header], None).expect_err("one credential per request");

        assert_eq!(refusal, UserInfoError::RepeatedAuthorization);
        assert_eq!(refusal.status(), 400);
    }

    /// RFC 6750 §3: no credential is a 401 with a challenge.
    #[test]
    fn a_request_with_no_credential_is_unauthorized() {
        let refusal = present(&[], None).expect_err("a credential is required");

        assert_eq!(refusal, UserInfoError::NoCredential);
        assert_eq!(refusal.status(), 401);
        assert_eq!(refusal.code(), "invalid_token");
    }

    /// RFC 7235 §2.1: `token68`, and nothing that is not one.
    #[test]
    fn a_credential_outside_token68_is_refused() {
        for bad in [
            "DPoP ",
            "DPoP a b",
            "DPoP a\tb",
            "DPoP a,b",
            "DPoP a=b",
            "DPoP \u{0}",
            "DPoP",
        ] {
            assert!(present(&[bad], None).is_err(), "accepted {bad:?}");
        }
    }

    /// A credential larger than any token this server issues is not one.
    #[test]
    fn an_oversized_credential_is_refused_on_length() {
        let huge = format!("DPoP {}", "a".repeat(MAX_CREDENTIAL_BYTES));

        assert_eq!(
            present(&[&huge], None),
            Err(UserInfoError::MalformedCredential)
        );
    }

    /// An unknown scheme names an authentication method this endpoint does not
    /// implement, which RFC 6750 §3.1 calls `invalid_request`.
    #[test]
    fn an_unknown_scheme_is_refused() {
        assert_eq!(
            present(&["Basic YWxpY2U6cHc="], None),
            Err(UserInfoError::UnsupportedScheme)
        );
    }

    // ---- challenges (RFC 6750 §3, RFC 9449 §7.1) --------------------------

    /// Both schemes are offered, DPoP first and with its `algs`.
    #[test]
    fn a_refusal_challenges_with_dpop_and_bearer() {
        let rendered = challenges(Some(&UserInfoError::InvalidToken));

        assert_eq!(rendered.len(), 2);
        assert!(rendered[0].starts_with("DPoP algs=\""), "{rendered:?}");
        assert!(rendered[0].contains(r#"error="invalid_token""#));
        assert!(rendered[1].starts_with("Bearer"), "{rendered:?}");
        assert!(rendered[1].contains(r#"error="invalid_token""#));
        for algorithm in SigningAlgorithm::ALL {
            assert!(rendered[0].contains(algorithm.as_str()));
        }
    }

    /// The `algs` list is the deployment's, so a challenge cannot advertise an
    /// algorithm the proof verifier would refuse (ADR-0003).
    #[test]
    fn a_challenge_without_an_error_carries_no_error_attributes() {
        let rendered = challenges(None);

        assert!(!rendered[0].contains("error="), "{rendered:?}");
        assert_eq!(rendered[1], "Bearer");
    }

    /// A description is a constant per variant and never quotes the request.
    #[test]
    fn every_refusal_maps_to_one_of_rfc_6750s_codes() {
        for error in [
            UserInfoError::TokenInQuery,
            UserInfoError::NoCredential,
            UserInfoError::RepeatedAuthorization,
            UserInfoError::UnsupportedScheme,
            UserInfoError::MalformedCredential,
            UserInfoError::InvalidToken,
            UserInfoError::InsufficientScope,
        ] {
            assert!(
                ["invalid_request", "invalid_token", "insufficient_scope"].contains(&error.code()),
                "invented a code: {}",
                error.code()
            );
            assert!([400, 401, 403].contains(&error.status()));
            assert!(!error.description().is_empty());
        }
    }

    // ---- scope (OIDC Core §5.3.1, RFC 6750 §3.1) --------------------------

    /// The `openid` scope is what makes a token a UserInfo credential.
    #[test]
    fn a_token_without_openid_is_insufficiently_scoped() {
        assert!(check_scope(Some("openid profile")).is_ok());
        assert!(check_scope(Some("profile openid")).is_ok());
        assert_eq!(check_scope(Some("openid")), Ok(()));

        for refused in [
            None,
            Some(""),
            Some("profile"),
            Some("openid2"),
            Some("open"),
        ] {
            assert_eq!(
                check_scope(refused),
                Err(UserInfoError::InsufficientScope),
                "accepted {refused:?}"
            );
        }
    }

    /// 403, not 401: the credential is good and does not authorise this.
    #[test]
    fn insufficient_scope_is_forbidden_rather_than_unauthorized() {
        let refusal = UserInfoError::InsufficientScope;

        assert_eq!(refusal.status(), 403);
        assert_eq!(refusal.code(), "insufficient_scope");
    }

    // ---- the body (OIDC Core §5.3.2) --------------------------------------

    /// `sub` is REQUIRED, and it is the server's value.
    #[test]
    fn the_subject_is_always_present_and_is_the_servers() {
        let mut released = Map::new();
        released.insert("email".to_owned(), Value::String("a@example".to_owned()));
        // Not reachable through `ReleasableClaim`; here to prove that even if
        // it were, it would not be the `sub` a client reads.
        released.insert("sub".to_owned(), Value::String("mallory".to_owned()));

        let body = body("SUBJECT-1", released);

        assert_eq!(body["sub"], Value::String("SUBJECT-1".to_owned()));
        assert_eq!(body["email"], Value::String("a@example".to_owned()));
    }

    /// A signed response names its issuer and its audience, so it cannot be
    /// replayed at another relying party.
    #[test]
    fn a_signed_response_carries_iss_and_aud() {
        let issuer = Issuer::parse("https://as.example/t/demo").expect("issuer");

        let claims = signed_claims(&issuer, "billing", body("SUBJECT-1", Map::new()));

        assert_eq!(claims["iss"], Value::String(issuer.as_str().to_owned()));
        assert_eq!(claims["aud"], Value::String("billing".to_owned()));
        assert_eq!(claims["sub"], Value::String("SUBJECT-1".to_owned()));
    }
}
