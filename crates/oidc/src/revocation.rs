//! Token revocation: the request, and what a presented token turns out to be.
//!
//! RFC 7009 §2.1 is a short endpoint with one long sentence in it:
//!
//! > The authorization server responds with HTTP status code 200 if the token
//! > has been revoked successfully **or if the client submitted an invalid
//! > token**.
//!
//! Everything in this module follows from that. A token this server cannot
//! place is not an error, it is a 200 with nothing done, because the
//! alternative turns `/revoke` into an oracle that answers "is this string a
//! live credential here?" for anybody holding a client registration. The same
//! sentence is why §2.2 adds that a client "MUST NOT be able to revoke a
//! token issued to another client" and that such a request is to be treated
//! as an invalid token: a 200, and nothing done.
//!
//! # What is decided here, and what is not
//!
//! Here: whether the request is well formed, and what *shape* the presented
//! token has. Nothing in this file touches a database or a key — it cannot
//! tell you whether a token is live, only whether it could be one of ours and
//! which of the two kinds it would be.
//!
//! Not here: the lookup, the client comparison, the denylist write. Those need
//! I/O and live in `asterius_server::http::revocation`.
//!
//! # `token_type_hint` is a hint
//!
//! §2.1 again: the hint "MAY" speed the lookup, and if the server does not
//! find the token with it, it "MUST extend its search across all of its
//! supported token types". So the hint never narrows anything here. An
//! unrecognised value is recorded as unrecognised and the request proceeds —
//! §2.1 explicitly allows a client to send a hint this server has never heard
//! of, and refusing it would fail a request that is otherwise correct.
//!
//! `unsupported_token_type` (§2.2.1) is reserved for the one case it is
//! written for: a token whose type this server can identify and cannot revoke.
//! That is decided from the token, not from the hint a caller chose.

use crate::form::Parameters;
use crate::refresh::digest_of;
use crate::tokens::access::ACCESS_TOKEN_TYP;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;

/// The longest `token` this endpoint will look at.
///
/// A bound on the parser rather than a policy. The two things that can
/// legitimately arrive are a 43-character refresh token and a JWT access
/// token; 8 KiB is several times the largest access token this server will
/// mint (`MAX_ACCESS_TOKEN_CLAIMS_BYTES` bounds the claims), and a value past
/// it is refused before it is base64-decoded or hashed.
pub const MAX_TOKEN_LEN: usize = 8 * 1024;

/// The largest JWT header this module will decode.
///
/// The header of an access token this server issues is under a hundred bytes.
/// The limit exists because the decode happens on an unauthenticated string
/// and before anything has been verified.
const MAX_HEADER_BYTES: usize = 4 * 1024;

/// Why a revocation request was refused.
///
/// Deliberately short. RFC 7009 §2.2 gives this endpoint one success shape and
/// §2.2.1 one extra error code, and everything else — an unknown token, a
/// token belonging to another client, a token that expired last week — is a
/// success with nothing done.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RevocationError {
    /// A parameter was sent twice. RFC 6749 §3.2's rule, which RFC 7009 §2.1
    /// inherits by defining its request as a form post to the same profile.
    #[error("parameter {0} appeared more than once")]
    Duplicated(String),
    /// `token` is REQUIRED (§2.1).
    #[error("token is required")]
    MissingToken,
    /// A `token` longer than this endpoint reads.
    #[error("token is longer than this endpoint accepts")]
    TokenTooLong,
    /// §2.2.1: the server "does not support the revocation of the presented
    /// token type".
    #[error("this token type cannot be revoked")]
    UnsupportedTokenType,
}

impl RevocationError {
    /// The OAuth error code, as §2.2.1 and RFC 6749 §5.2 spell them.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::UnsupportedTokenType => "unsupported_token_type",
            _ => "invalid_request",
        }
    }

    /// The HTTP status. §2.2.1 sends both codes with the RFC 6749 §5.2 shape,
    /// which is a 400 for everything a client can fix.
    #[must_use]
    pub const fn status(&self) -> u16 {
        400
    }

    /// The client-facing description: a constant per variant, never the
    /// request echoed back.
    #[must_use]
    pub const fn description(&self) -> &'static str {
        match self {
            Self::Duplicated(_) => "a parameter was sent more than once",
            Self::MissingToken => "token is required",
            Self::TokenTooLong => "token is too long",
            Self::UnsupportedTokenType => "this token type cannot be revoked here",
        }
    }
}

/// What the client says it is presenting (§2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TokenTypeHint {
    /// `access_token`.
    AccessToken,
    /// `refresh_token`.
    RefreshToken,
    /// Anything else, including absent. §2.1 requires the search to be
    /// extended anyway, so this is a label for the audit trail and not a
    /// decision.
    Unrecognised,
}

impl TokenTypeHint {
    /// Reads a `token_type_hint` value.
    #[must_use]
    pub fn of(value: Option<&str>) -> Self {
        match value {
            Some("access_token") => Self::AccessToken,
            Some("refresh_token") => Self::RefreshToken,
            _ => Self::Unrecognised,
        }
    }

    /// The spelling for a log line or an audit detail.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AccessToken => "access_token",
            Self::RefreshToken => "refresh_token",
            Self::Unrecognised => "unrecognised",
        }
    }
}

/// A well-formed revocation request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationRequest<'a> {
    /// The credential to revoke, exactly as it arrived.
    pub token: &'a str,
    /// What the client called it.
    pub hint: TokenTypeHint,
}

/// What the presented value could be.
///
/// "Could be": this is a shape, not a fact about the store. A
/// [`Self::RefreshToken`] is a value with the shape a refresh token issued
/// here has, and its digest is the key to look it up by — whether any row
/// answers to it is the caller's question.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Presented {
    /// The shape of a refresh token, with the digest to look it up by.
    RefreshToken {
        /// The hex SHA-256 the store keys refresh tokens by.
        digest: String,
    },
    /// A JWT typed `at+jwt` (RFC 9068 §2.1). Nothing about it is verified yet.
    AccessToken,
    /// Something this server could not have issued as a revocable credential.
    ///
    /// §2.1's "invalid token", which is a 200 and no action.
    Unrecognised,
}

/// Reads the request body's parameters (§2.1).
///
/// # Errors
///
/// [`RevocationError::Duplicated`] when a parameter was sent twice,
/// [`RevocationError::MissingToken`] when `token` is absent or empty, and
/// [`RevocationError::TokenTooLong`] past [`MAX_TOKEN_LEN`].
pub fn parse(params: &Parameters) -> Result<RevocationRequest<'_>, RevocationError> {
    let token = params
        .get("token")
        .map_err(|duplicated| RevocationError::Duplicated(duplicated.0))?
        .ok_or(RevocationError::MissingToken)?;
    if token.is_empty() {
        // An empty `token` is a request that named the parameter and gave it
        // nothing, which §2.1 does not describe. Refusing it as missing is
        // more useful to the client than revoking nothing and saying 200.
        return Err(RevocationError::MissingToken);
    }
    if token.len() > MAX_TOKEN_LEN {
        return Err(RevocationError::TokenTooLong);
    }
    let hint = params
        .get("token_type_hint")
        .map_err(|duplicated| RevocationError::Duplicated(duplicated.0))?;

    Ok(RevocationRequest {
        token,
        hint: TokenTypeHint::of(hint),
    })
}

/// Works out what kind of credential was presented.
///
/// The order is deliberate: the refresh-token shape is an exact length and
/// alphabet check that no JWT can satisfy, so it is tried first and costs a
/// comparison. Only a value that fails it is looked at as a JWT, and then only
/// its `typ` header is read — from an **unverified** token, which is why the
/// answer is used for nothing but choosing between "revoke this" and "this
/// type cannot be revoked". A forged header buys the sender a different error
/// code and no access.
///
/// # Errors
///
/// [`RevocationError::UnsupportedTokenType`] for a JWT that is not an access
/// token: an ID token, a logout token, or a client assertion presented here.
/// §2.2.1 is written for exactly that, and answering 200 would tell a client
/// its ID token had been revoked when nothing of the sort happened.
// fuzz-target: revocation_request
pub fn classify(token: &str) -> Result<Presented, RevocationError> {
    if token.len() > MAX_TOKEN_LEN {
        return Err(RevocationError::TokenTooLong);
    }
    if let Ok(digest) = digest_of(token) {
        return Ok(Presented::RefreshToken { digest });
    }
    match unverified_typ(token) {
        None => Ok(Presented::Unrecognised),
        Some(typ) if is_access_token_typ(&typ) => Ok(Presented::AccessToken),
        Some(_) => Err(RevocationError::UnsupportedTokenType),
    }
}

/// Whether a `typ` header names a JWT access token.
///
/// RFC 8725 §3.11 and RFC 9068 §2.1: the `application/` prefix "MAY be
/// omitted", so a token typed `application/at+jwt` is the same token as one
/// typed `at+jwt`. Media types are case-insensitive (RFC 9110 §8.3.1).
fn is_access_token_typ(typ: &str) -> bool {
    let typ = typ
        .strip_prefix("application/")
        .or_else(|| typ.strip_prefix("APPLICATION/"))
        .unwrap_or(typ);
    typ.eq_ignore_ascii_case(ACCESS_TOKEN_TYP)
}

/// The `typ` of a compact JWS, without verifying anything.
///
/// `None` for anything that is not three base64url segments with a JSON object
/// header — which is the answer for an opaque string, and lands the caller on
/// [`Presented::Unrecognised`] rather than on an error.
fn unverified_typ(token: &str) -> Option<String> {
    let mut segments = token.split('.');
    let header = segments.next()?;
    let payload = segments.next()?;
    let signature = segments.next()?;
    if segments.next().is_some() || payload.is_empty() || signature.is_empty() {
        return None;
    }
    if header.is_empty() || header.len() > MAX_HEADER_BYTES {
        return None;
    }
    let decoded = B64.decode(header).ok()?;
    let value: serde_json::Value = serde_json::from_slice(&decoded).ok()?;
    value
        .as_object()?
        .get("typ")?
        .as_str()
        .map(std::borrow::ToOwned::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::refresh::MintedRefreshToken;
    use serde_json::json;

    fn params(pairs: &[(&str, &str)]) -> Parameters {
        Parameters::from_pairs(
            pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned())),
        )
    }

    fn jwt_with_typ(typ: Option<&str>) -> String {
        let header = typ.map_or_else(
            || json!({ "alg": "EdDSA" }),
            |typ| json!({ "alg": "EdDSA", "typ": typ }),
        );
        format!(
            "{}.{}.{}",
            B64.encode(header.to_string()),
            B64.encode(json!({ "sub": "someone" }).to_string()),
            B64.encode([7_u8; 64])
        )
    }

    // ---- the request (§2.1) ----------------------------------------------

    /// RFC 7009 §2.1: `token` is REQUIRED.
    #[test]
    fn a_request_without_a_token_is_refused() {
        let params = params(&[("token_type_hint", "refresh_token")]);

        let error = parse(&params).expect_err("token is REQUIRED");

        assert_eq!(error, RevocationError::MissingToken);
        assert_eq!(error.code(), "invalid_request");
        assert_eq!(error.status(), 400);
    }

    #[test]
    fn an_empty_token_is_refused_as_a_missing_one() {
        let params = params(&[("token", "")]);

        let error = parse(&params).expect_err("an empty token is no token");

        assert_eq!(error, RevocationError::MissingToken);
    }

    /// RFC 6749 §3.2, which §2.1's request inherits: no parameter twice.
    #[test]
    fn a_repeated_parameter_is_refused() {
        let params = params(&[("token", "one"), ("token", "two")]);

        let error = parse(&params).expect_err("a duplicate must not be resolved silently");

        assert_eq!(error, RevocationError::Duplicated("token".to_owned()));
        assert_eq!(error.code(), "invalid_request");
    }

    #[test]
    fn a_repeated_hint_is_refused_too() {
        let params = params(&[
            ("token", "one"),
            ("token_type_hint", "access_token"),
            ("token_type_hint", "refresh_token"),
        ]);

        let error = parse(&params).expect_err("two hints name two requests");

        assert_eq!(
            error,
            RevocationError::Duplicated("token_type_hint".to_owned())
        );
    }

    #[test]
    fn a_token_past_the_bound_is_refused_before_it_is_looked_at() {
        let params = params(&[("token", &"a".repeat(MAX_TOKEN_LEN + 1))]);

        let error = parse(&params).expect_err("the bound is on the parser");

        assert_eq!(error, RevocationError::TokenTooLong);
        assert_eq!(error.code(), "invalid_request");
    }

    /// §2.1: the hint "MAY" help; an unknown one does not fail the request,
    /// because the server must extend its search across all token types.
    #[test]
    fn an_unrecognised_hint_is_accepted_and_recorded_as_unrecognised() {
        let params = params(&[("token", "opaque"), ("token_type_hint", "device_code")]);

        let request = parse(&params).expect("an unknown hint is still a valid request");

        assert_eq!(request.token, "opaque");
        assert_eq!(request.hint, TokenTypeHint::Unrecognised);
    }

    #[test]
    fn the_two_registered_hints_are_read() {
        for (value, expected) in [
            ("access_token", TokenTypeHint::AccessToken),
            ("refresh_token", TokenTypeHint::RefreshToken),
        ] {
            let params = params(&[("token", "opaque"), ("token_type_hint", value)]);

            let request = parse(&params).expect("a registered hint");

            assert_eq!(request.hint, expected, "{value}");
            assert_eq!(request.hint.as_str(), value);
        }
    }

    #[test]
    fn an_absent_hint_is_unrecognised_rather_than_a_refusal() {
        let params = params(&[("token", "opaque")]);

        let request = parse(&params).expect("the hint is OPTIONAL");

        assert_eq!(request.hint, TokenTypeHint::Unrecognised);
    }

    // ---- classification --------------------------------------------------

    /// A value the minter produced is recognised, and by the same digest the
    /// store filed it under.
    #[test]
    fn a_minted_refresh_token_classifies_as_one() {
        let minted = MintedRefreshToken::generate();

        let presented = classify(minted.expose()).expect("a minted token is revocable");

        assert_eq!(
            presented,
            Presented::RefreshToken {
                digest: minted.digest().to_owned()
            }
        );
    }

    #[test]
    fn a_jwt_typed_at_jwt_classifies_as_an_access_token() {
        let token = jwt_with_typ(Some("at+jwt"));

        let presented = classify(&token).expect("an access token is revocable");

        assert_eq!(presented, Presented::AccessToken);
    }

    /// RFC 9068 §2.1 and RFC 8725 §3.11: the `application/` prefix may be
    /// written out, and media types do not care about case.
    #[test]
    fn the_media_type_prefix_and_case_do_not_change_the_answer() {
        for typ in ["application/at+jwt", "AT+JWT", "application/AT+JWT"] {
            let token = jwt_with_typ(Some(typ));

            let presented = classify(&token).expect("still an access token");

            assert_eq!(presented, Presented::AccessToken, "{typ}");
        }
    }

    /// §2.2.1: a token whose type this server cannot revoke.
    #[test]
    fn an_id_token_is_an_unsupported_token_type() {
        let token = jwt_with_typ(Some("JWT"));

        let error = classify(&token).expect_err("an ID token is not revocable here");

        assert_eq!(error, RevocationError::UnsupportedTokenType);
        assert_eq!(error.code(), "unsupported_token_type");
        assert_eq!(error.status(), 400);
    }

    #[test]
    fn a_logout_token_is_an_unsupported_token_type() {
        let token = jwt_with_typ(Some("logout+jwt"));

        let error = classify(&token).expect_err("a logout token is not a revocable credential");

        assert_eq!(error, RevocationError::UnsupportedTokenType);
    }

    /// §2.1: an invalid token is a success with nothing done, so anything this
    /// server could not have issued must classify rather than fail.
    #[test]
    fn an_opaque_string_is_unrecognised_rather_than_an_error() {
        for token in [
            "hello",
            "....",
            "a.b",
            "a.b.c.d",
            "not-base64url!.aaaa.bbbb",
            &"x".repeat(200),
        ] {
            let presented = classify(token).expect("an unknown token is not an error");

            assert_eq!(presented, Presented::Unrecognised, "{token}");
        }
    }

    /// A JWT with no `typ` at all cannot be placed, and §2.1 says an
    /// unplaceable token is a 200. It is not `unsupported_token_type`: that
    /// code is for a type this server *identified*.
    #[test]
    fn a_jwt_without_a_type_is_unrecognised() {
        let token = jwt_with_typ(None);

        let presented = classify(&token).expect("an untyped JWT names no type to refuse");

        assert_eq!(presented, Presented::Unrecognised);
    }

    #[test]
    fn a_token_past_the_bound_is_never_classified() {
        let error = classify(&"a".repeat(MAX_TOKEN_LEN + 1)).expect_err("the bound applies here");

        assert_eq!(error, RevocationError::TokenTooLong);
    }
}
