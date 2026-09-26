//! Bounded RFC 9421 profile for explicitly configured HTTP peers.
//!
//! This module deliberately accepts one canonical `sig1` shape. It covers the
//! request method and target URI or response status, plus RFC 9530's content
//! digest, so the body cannot be changed without invalidating the signature.
//! The caller resolves the peer's pinned key and atomically consumes the
//! returned nonce before applying the protected request.

use crate::{JoseError, SigningKey, VerifyingKey};
use asterius_domain::SigningAlgorithm;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

const REQUEST_COMPONENTS: &str = "(\"@method\" \"@target-uri\" \"content-digest\")";
const RESPONSE_COMPONENTS: &str = "(\"@status\" \"content-digest\")";
const MAX_BODY: usize = 1024 * 1024;
const MAX_INPUT: usize = 1024;
const MAX_LIFETIME: i64 = 300;

/// The three RFC 9421/RFC 9530 fields carried by one protected message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedFields {
    /// RFC 9530 content digest covering the exact body bytes.
    pub content_digest: String,
    /// RFC 9421 signature input dictionary with the `sig1` member.
    pub signature_input: String,
    /// RFC 9421 signature dictionary with the `sig1` member.
    pub signature: String,
}

/// Verified message identity; replay storage must consume `(keyid, nonce)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedMessage {
    /// Identifier selected from the operator-pinned peer key registry.
    pub keyid: String,
    /// Single-use nonce to atomically record before accepting the message.
    pub nonce: String,
    /// Last acceptable time for the nonce record.
    pub expires_at: OffsetDateTime,
}

/// A protected request's semantic components, supplied by the HTTP edge.
#[derive(Debug, Clone, Copy)]
pub struct RequestTarget<'a> {
    /// HTTP method as received, for example `POST`.
    pub method: &'a str,
    /// Absolute target URI reconstructed from trusted ingress metadata.
    pub target_uri: &'a str,
}

/// Failure of the configured RFC 9421 profile.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HttpSignatureError {
    /// Message size or a field exceeded this profile's bounds.
    #[error("HTTP signature input exceeds profile bounds")]
    Bounds,
    /// Required canonical components or parameters were absent or malformed.
    #[error("HTTP signature fields do not match the configured profile")]
    Format,
    /// Signature or body digest was incorrect.
    #[error("HTTP message signature verification failed")]
    Invalid,
    /// Creation/expiration time does not permit this message.
    #[error("HTTP message signature is outside its validity window")]
    Time,
    /// This profile accepts an Ed25519 key only.
    #[error("HTTP message signature requires an Ed25519 key")]
    Key,
    /// Local signing failed.
    #[error("HTTP message signing failed")]
    Sign(#[from] JoseError),
}

/// Sign a request with the configured Ed25519 key and a caller-generated nonce.
///
/// # Errors
///
/// Rejects invalid target, key, identifiers, expiry or excessive body size.
pub fn sign_request(
    target: RequestTarget<'_>,
    body: &[u8],
    keyid: &str,
    nonce: &str,
    created: OffsetDateTime,
    expires: OffsetDateTime,
    key: &SigningKey,
) -> Result<SignedFields, HttpSignatureError> {
    validate_request(target)?;
    sign(
        &[
            ("@method", target.method),
            ("@target-uri", target.target_uri),
        ],
        REQUEST_COMPONENTS,
        body,
        keyid,
        nonce,
        (created, expires),
        key,
    )
}

/// Sign a response with an RFC 9530 digest and a short-lived signature.
///
/// # Errors
///
/// Rejects invalid status, key, identifiers, expiry or excessive body size.
pub fn sign_response(
    status: u16,
    body: &[u8],
    keyid: &str,
    nonce: &str,
    created: OffsetDateTime,
    expires: OffsetDateTime,
    key: &SigningKey,
) -> Result<SignedFields, HttpSignatureError> {
    if !(100..=599).contains(&status) {
        return Err(HttpSignatureError::Format);
    }
    let status = status.to_string();
    sign(
        &[("@status", &status)],
        RESPONSE_COMPONENTS,
        body,
        keyid,
        nonce,
        (created, expires),
        key,
    )
}

/// Verify one request against an operator-pinned Ed25519 key.
///
/// The caller must compare the returned key id to its registry entry and
/// atomically reject an already-seen `(peer, nonce)` before acting.
///
/// # Errors
///
/// Rejects malformed, stale, future, unsigned, wrong-key or modified input.
pub fn verify_request(
    target: RequestTarget<'_>,
    body: &[u8],
    fields: &SignedFields,
    expected_keyid: &str,
    key: &VerifyingKey,
    now: OffsetDateTime,
) -> Result<VerifiedMessage, HttpSignatureError> {
    validate_request(target)?;
    verify(
        &[
            ("@method", target.method),
            ("@target-uri", target.target_uri),
        ],
        REQUEST_COMPONENTS,
        body,
        fields,
        expected_keyid,
        key,
        now,
    )
}

/// Verify one response against an operator-pinned Ed25519 key.
///
/// # Errors
///
/// Rejects malformed, stale, future, unsigned, wrong-key or modified input.
pub fn verify_response(
    status: u16,
    body: &[u8],
    fields: &SignedFields,
    expected_keyid: &str,
    key: &VerifyingKey,
    now: OffsetDateTime,
) -> Result<VerifiedMessage, HttpSignatureError> {
    if !(100..=599).contains(&status) {
        return Err(HttpSignatureError::Format);
    }
    let status = status.to_string();
    verify(
        &[("@status", &status)],
        RESPONSE_COMPONENTS,
        body,
        fields,
        expected_keyid,
        key,
        now,
    )
}

fn sign(
    components: &[(&str, &str)],
    component_list: &str,
    body: &[u8],
    keyid: &str,
    nonce: &str,
    validity: (OffsetDateTime, OffsetDateTime),
    key: &SigningKey,
) -> Result<SignedFields, HttpSignatureError> {
    let (created, expires) = validity;
    if key.algorithm() != SigningAlgorithm::EdDsa {
        return Err(HttpSignatureError::Key);
    }
    validate_common(
        body,
        keyid,
        nonce,
        created.unix_timestamp(),
        expires.unix_timestamp(),
    )?;
    let content_digest = digest(body);
    let signature_input = input(
        component_list,
        created.unix_timestamp(),
        expires.unix_timestamp(),
        nonce,
        keyid,
    );
    let base = signature_base(components, &content_digest, &signature_input)?;
    let signature = key.sign(base.as_bytes())?;
    Ok(SignedFields {
        content_digest,
        signature_input,
        signature: format!("sig1=:{}:", STANDARD.encode(signature)),
    })
}

fn verify(
    components: &[(&str, &str)],
    component_list: &str,
    body: &[u8],
    fields: &SignedFields,
    expected_keyid: &str,
    key: &VerifyingKey,
    now: OffsetDateTime,
) -> Result<VerifiedMessage, HttpSignatureError> {
    if key.algorithm() != SigningAlgorithm::EdDsa {
        return Err(HttpSignatureError::Key);
    }
    if body.len() > MAX_BODY
        || fields.signature_input.len() > MAX_INPUT
        || fields.signature.len() > 256
        || fields.content_digest.len() > 128
    {
        return Err(HttpSignatureError::Bounds);
    }
    if fields.content_digest != digest(body) {
        return Err(HttpSignatureError::Invalid);
    }
    let parsed = parse_input(&fields.signature_input, component_list)?;
    validate_common(
        body,
        &parsed.keyid,
        &parsed.nonce,
        parsed.created,
        parsed.expires,
    )?;
    if parsed.keyid != expected_keyid {
        return Err(HttpSignatureError::Invalid);
    }
    let now = now.unix_timestamp();
    if parsed.created > now + 60 || parsed.created < now - MAX_LIFETIME || parsed.expires < now {
        return Err(HttpSignatureError::Time);
    }
    let signature = fields
        .signature
        .strip_prefix("sig1=:")
        .and_then(|value| value.strip_suffix(':'))
        .and_then(|value| STANDARD.decode(value).ok())
        .filter(|bytes| bytes.len() == 64)
        .ok_or(HttpSignatureError::Format)?;
    let base = signature_base(components, &fields.content_digest, &fields.signature_input)?;
    key.verify(base.as_bytes(), &signature)
        .map_err(|_| HttpSignatureError::Invalid)?;
    Ok(VerifiedMessage {
        keyid: parsed.keyid,
        nonce: parsed.nonce,
        expires_at: OffsetDateTime::from_unix_timestamp(parsed.expires)
            .map_err(|_| HttpSignatureError::Time)?,
    })
}

fn validate_request(target: RequestTarget<'_>) -> Result<(), HttpSignatureError> {
    if target.method.is_empty()
        || !target.method.bytes().all(|byte| byte.is_ascii_uppercase())
        || target.target_uri.len() > 2048
    {
        return Err(HttpSignatureError::Format);
    }
    let uri = url::Url::parse(target.target_uri).map_err(|_| HttpSignatureError::Format)?;
    if uri.scheme() != "https"
        || uri.host_str().is_none()
        || !uri.username().is_empty()
        || uri.password().is_some()
        || uri.fragment().is_some()
    {
        return Err(HttpSignatureError::Format);
    }
    Ok(())
}

fn validate_common(
    body: &[u8],
    keyid: &str,
    nonce: &str,
    created: i64,
    expires: i64,
) -> Result<(), HttpSignatureError> {
    if body.len() > MAX_BODY
        || expires
            .checked_sub(created)
            .is_none_or(|lifetime| lifetime == 0 || lifetime > MAX_LIFETIME)
    {
        return Err(HttpSignatureError::Bounds);
    }
    if keyid.is_empty()
        || keyid.len() > 128
        || !keyid
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        || !(16..=128).contains(&nonce.len())
        || !nonce
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(HttpSignatureError::Format);
    }
    Ok(())
}

fn digest(body: &[u8]) -> String {
    format!("sha-256=:{}:", STANDARD.encode(Sha256::digest(body)))
}

fn input(components: &str, created: i64, expires: i64, nonce: &str, keyid: &str) -> String {
    format!(
        "sig1={components};created={created};expires={expires};nonce=\"{nonce}\";keyid=\"{keyid}\";alg=\"ed25519\""
    )
}

struct ParsedInput {
    created: i64,
    expires: i64,
    nonce: String,
    keyid: String,
}

fn parse_input(value: &str, components: &str) -> Result<ParsedInput, HttpSignatureError> {
    let tail = value
        .strip_prefix(&format!("sig1={components};created="))
        .ok_or(HttpSignatureError::Format)?;
    let (created, tail) = tail
        .split_once(";expires=")
        .ok_or(HttpSignatureError::Format)?;
    let (expires, tail) = tail
        .split_once(";nonce=\"")
        .ok_or(HttpSignatureError::Format)?;
    let (nonce, tail) = tail
        .split_once("\";keyid=\"")
        .ok_or(HttpSignatureError::Format)?;
    let keyid = tail
        .strip_suffix("\";alg=\"ed25519\"")
        .ok_or(HttpSignatureError::Format)?;
    let parsed = ParsedInput {
        created: created.parse().map_err(|_| HttpSignatureError::Format)?,
        expires: expires.parse().map_err(|_| HttpSignatureError::Format)?,
        nonce: nonce.to_owned(),
        keyid: keyid.to_owned(),
    };
    if input(
        components,
        parsed.created,
        parsed.expires,
        &parsed.nonce,
        &parsed.keyid,
    ) != value
    {
        return Err(HttpSignatureError::Format);
    }
    Ok(parsed)
}

fn signature_base(
    components: &[(&str, &str)],
    content_digest: &str,
    signature_input: &str,
) -> Result<String, HttpSignatureError> {
    let mut base = String::new();
    for (name, value) in components {
        if value.contains('\r') || value.contains('\n') {
            return Err(HttpSignatureError::Format);
        }
        base.push('"');
        base.push_str(name);
        base.push_str("\": ");
        base.push_str(value);
        base.push('\n');
    }
    base.push_str("\"content-digest\": ");
    base.push_str(content_digest);
    base.push('\n');
    let params = signature_input
        .strip_prefix("sig1=")
        .ok_or(HttpSignatureError::Format)?;
    base.push_str("\"@signature-params\": ");
    base.push_str(params);
    Ok(base)
}
