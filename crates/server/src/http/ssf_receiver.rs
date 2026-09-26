//! Inbound Security Event Token verification and CAEP profile validation.
//!
//! A receiver must select the peer's registered keys before it verifies the
//! signature. In particular, `jku` and `x5u` are never followed: the
//! unverified `iss` selects a configured client row, and that row's JWKS is
//! resolved through the same guarded client-key cache used by authentication.
//! This module owns the cryptographic and SET-profile boundary; replay
//! recording and lifecycle application happen only after it returns a
//! [`VerifiedEvent`].

use asterius_domain::{
    ClientId, Issuer, JwksSource, ReplayCheck, ReplayPurpose, SigningAlgorithm, Tenant,
};
use asterius_jose::client_keys::ClientKeyCache;
use asterius_jose::http_signatures::{RequestTarget, SignedFields, verify_request};
use asterius_jose::verify::{self, Policy, TypRule, Verified};
use asterius_ssf::{SET_TYP, Subject};
use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Extension, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use serde_json::Value;
use std::collections::BTreeSet;
use thiserror::Error;
use time::OffsetDateTime;

/// Receiver-only OAuth scope. The tenant registration policy must explicitly
/// allow this scope before a client can hold it.
pub const RECEIVE_SCOPE: &str = "ssf.receive";

/// Extra scope needed to accept an account-disabled event.
pub const DISABLE_ACCOUNT_SCOPE: &str = "ssf.receive.account-disable";

/// The inbound SET delivery endpoint, tenant-relative.
pub const RECEIVER_PATH: &str = "/ssf/receiver";

/// Maximum compact SET accepted on the wire.
pub const MAX_TOKEN_BYTES: usize = 8 * 1024;

/// Maximum age of a SET accepted by this receiver. SETs have no `exp` claim;
/// a configured freshness window bounds delivery and replay retention instead.
pub const MAX_SET_AGE: time::Duration = time::Duration::minutes(5);

/// The inbound SET route, mounted only when the tenant's SSF feature is
/// enabled. The body limit is enforced by Axum before the token is allocated.
pub fn routes(endpoints: std::sync::Arc<crate::http::protocol::ClientEndpoints>) -> Router {
    Router::new().route(
        RECEIVER_PATH,
        post(receive)
            .layer(DefaultBodyLimit::max(MAX_TOKEN_BYTES))
            .with_state(endpoints),
    )
}

async fn receive(
    State(endpoints): State<std::sync::Arc<crate::http::protocol::ClientEndpoints>>,
    Extension(tenant): Extension<Tenant>,
    uri: Uri,
    headers: HeaderMap,
    token: Bytes,
) -> Response {
    let Some(content_type) = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
    else {
        return response(StatusCode::UNSUPPORTED_MEDIA_TYPE);
    };
    if !content_type.split(';').next().is_some_and(|value| {
        value
            .trim()
            .eq_ignore_ascii_case("application/secevent+jwt")
    }) {
        return response(StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }
    if token.is_empty() || token.len() > MAX_TOKEN_BYTES {
        return response(StatusCode::BAD_REQUEST);
    }
    let Ok(token) = std::str::from_utf8(&token) else {
        return response(StatusCode::BAD_REQUEST);
    };
    // `iss` is only a lookup key into this tenant's registered clients. The
    // client must have the explicit receiver scope before any outbound JWKS
    // resolution; the verified token then has to carry the same pinned issuer.
    let Ok(unverified) = asterius_jose::jws::parse(token) else {
        return response(StatusCode::BAD_REQUEST);
    };
    let Ok(untrusted_claims) = serde_json::from_slice::<Value>(unverified.unverified_payload())
    else {
        return response(StatusCode::BAD_REQUEST);
    };
    let Some(issuer) = untrusted_claims.get("iss").and_then(Value::as_str) else {
        return response(StatusCode::BAD_REQUEST);
    };
    let peer = ClientId::new(issuer);
    let audience = format!("{}{}", tenant.issuer.as_str(), RECEIVER_PATH);
    let now = OffsetDateTime::now_utc();
    let Ok(event) =
        verify_for_configured_peer(&endpoints, &tenant, &peer, &audience, token, now).await
    else {
        return response(StatusCode::BAD_REQUEST);
    };
    if let Some(pinned) = endpoints
        .http_signature_peers
        .find(tenant.id.as_str(), event.peer.as_str())
    {
        // The SET signature has established the peer before its HTTP key is
        // selected. A configured peer cannot fall back to unsigned delivery.
        let Some(fields) = signed_fields(&headers) else {
            return response(StatusCode::UNAUTHORIZED);
        };
        if uri.query().is_some() || uri.path() != RECEIVER_PATH {
            return response(StatusCode::UNAUTHORIZED);
        }
        let target_uri = format!("{}{}", tenant.issuer.as_str().trim_end_matches('/'), uri);
        let Ok(verified) = verify_request(
            RequestTarget {
                method: "POST",
                target_uri: &target_uri,
            },
            token.as_bytes(),
            &fields,
            &pinned.keyid,
            &pinned.key,
            now,
        ) else {
            return response(StatusCode::UNAUTHORIZED);
        };
        let subject = format!("{}:{}", event.peer.as_str(), verified.keyid);
        match endpoints
            .http_signature_replay
            .claim(
                &tenant.id,
                ReplayPurpose::HttpSignature,
                &subject,
                &verified.nonce,
                verified.expires_at,
            )
            .await
        {
            Ok(ReplayCheck::FirstUse) => {}
            Ok(ReplayCheck::Replay) => return response(StatusCode::UNAUTHORIZED),
            Err(_) => return response(StatusCode::SERVICE_UNAVAILABLE),
        }
    }
    let action = match event.event_type {
        LifecycleEventType::SessionRevoked => asterius_store_pg::ReceiverAction::SessionRevoked,
        LifecycleEventType::AccountDisabled => asterius_store_pg::ReceiverAction::AccountDisabled,
        LifecycleEventType::CredentialChange => {
            let valid_credential_type = matches!(
                event.event.get("credential_type").and_then(Value::as_str),
                Some(
                    "password"
                        | "pin"
                        | "x509"
                        | "fido2-platform"
                        | "fido2-roaming"
                        | "fido-u2f"
                        | "verifiable-credential"
                        | "phone-voice"
                        | "phone-sms"
                        | "app"
                )
            );
            if !valid_credential_type {
                return response(StatusCode::BAD_REQUEST);
            }
            match event.event.get("change_type").and_then(Value::as_str) {
                // A remote credential revocation/removal cannot identify or
                // safely mutate a local credential. Revoke sessions only.
                Some("revoke" | "delete") => {
                    asterius_store_pg::ReceiverAction::CredentialCompromised
                }
                Some("create" | "update") => asterius_store_pg::ReceiverAction::ObserveOnly,
                _ => return response(StatusCode::BAD_REQUEST),
            }
        }
    };
    match endpoints
        .store
        .scope(tenant.id)
        .ssf_receiver()
        .process(
            event.peer.as_str(),
            &event.subject.key(),
            &event.jti,
            event.replay_until,
            action,
            event.event_at,
            now,
        )
        .await
    {
        Ok(asterius_store_pg::ReceiverOutcome::Applied)
        | Ok(asterius_store_pg::ReceiverOutcome::Stale)
        | Ok(asterius_store_pg::ReceiverOutcome::Duplicate) => response(StatusCode::ACCEPTED),
        Err(asterius_domain::DomainError::Invalid { .. }) => response(StatusCode::BAD_REQUEST),
        Err(_) => response(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

fn signed_fields(headers: &HeaderMap) -> Option<SignedFields> {
    fn one(headers: &HeaderMap, name: &str) -> Option<String> {
        let mut values = headers.get_all(name).iter();
        let first = values.next()?.to_str().ok()?.to_owned();
        values.next().is_none().then_some(first)
    }
    Some(SignedFields {
        content_digest: one(headers, "content-digest")?,
        signature_input: one(headers, "signature-input")?,
        signature: one(headers, "signature")?,
    })
}

fn response(status: StatusCode) -> Response {
    let mut response = status.into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// CAEP/RISC events for which this server has a defined local action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleEventType {
    /// End sessions for the resolved local subject.
    SessionRevoked,
    /// Disable the resolved local account and its sessions.
    AccountDisabled,
    /// A credential changed; policy below applies only a session revocation.
    CredentialChange,
}

impl LifecycleEventType {
    fn parse(uri: &str) -> Option<Self> {
        match uri {
            asterius_ssf::caep::SESSION_REVOKED => Some(Self::SessionRevoked),
            asterius_ssf::caep::ACCOUNT_DISABLED => Some(Self::AccountDisabled),
            asterius_ssf::caep::CREDENTIAL_CHANGE => Some(Self::CredentialChange),
            _ => None,
        }
    }
}

/// A SET whose peer signature, token profile, and event envelope were checked.
#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedEvent {
    /// The registered client that signed the SET.
    pub peer: ClientId,
    /// SET `jti`, namespaced by `peer` for replay protection.
    pub jti: String,
    /// The end of the verified `iat` acceptance window, used for replay retention.
    pub replay_until: OffsetDateTime,
    /// A validated RFC 9493 subject identifier.
    pub subject: Subject,
    /// The single supported lifecycle event.
    pub event_type: LifecycleEventType,
    /// Validated CAEP event time, bounded against the receiver clock.
    pub event_at: OffsetDateTime,
    /// Claims associated with the event type (for example CAEP timestamps).
    pub event: Value,
}

/// Why an incoming SET was refused. Error messages never include token
/// material, identifiers, or event payloads.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ReceiverError {
    /// Signature, claim, or token type validation failed.
    #[error("the security event token could not be verified")]
    Token,
    /// A required SET profile member is absent or malformed.
    #[error("the security event token has an invalid SET profile")]
    Profile,
    /// This receiver does not apply the event type.
    #[error("the security event type is not supported")]
    UnsupportedEvent,
    /// Subject identifier did not pass the SSF/RFC 9493 parser.
    #[error("the security event subject is invalid")]
    Subject,
    /// Registered key lookup failed.
    #[error("the configured peer keys are unavailable")]
    Keys,
    /// The client is not authorized to submit events for this tenant.
    #[error("the event peer is not configured for this receiver")]
    Peer,
}

/// Finds a peer by its tenant-local client identity and enforces the explicit
/// receiver scope before any key resolution. Registration policy controls
/// whether this capability may be assigned; a client without that exact scope
/// is not an event source.
pub async fn configured_peer(
    endpoints: &crate::http::protocol::ClientEndpoints,
    tenant: &Tenant,
    peer: &ClientId,
) -> Result<(Issuer, JwksSource, BTreeSet<String>), ReceiverError> {
    let repository = endpoints
        .store
        .scope(tenant.id.clone())
        .clients(endpoints.capabilities);
    let Some(client) = repository
        .find(peer)
        .await
        .map_err(|_| ReceiverError::Peer)?
    else {
        return Err(ReceiverError::Peer);
    };
    if !client.is_active() || !client.registration.scopes.contains(RECEIVE_SCOPE) {
        return Err(ReceiverError::Peer);
    }
    let issuer = Issuer::parse(peer.as_str()).map_err(|_| ReceiverError::Peer)?;
    let jwks = client.registration.jwks;
    if matches!(jwks, JwksSource::None) {
        return Err(ReceiverError::Peer);
    }
    Ok((issuer, jwks, client.registration.scopes))
}

/// Verifies a SET for the named tenant-local peer, after checking its explicit
/// receiver scope and active registration.
pub async fn verify_for_configured_peer(
    endpoints: &crate::http::protocol::ClientEndpoints,
    tenant: &Tenant,
    peer: &ClientId,
    audience: &str,
    token: &str,
    now: OffsetDateTime,
) -> Result<VerifiedEvent, ReceiverError> {
    let (issuer, jwks, scopes) = configured_peer(endpoints, tenant, peer).await?;
    let event = verify_inbound_set(
        endpoints.authenticator.client_keys(),
        tenant,
        peer,
        &issuer,
        &jwks,
        audience,
        token,
        now,
    )
    .await?;
    let required_scope = match event.event_type {
        LifecycleEventType::SessionRevoked => RECEIVE_SCOPE,
        LifecycleEventType::AccountDisabled => DISABLE_ACCOUNT_SCOPE,
        LifecycleEventType::CredentialChange => RECEIVE_SCOPE,
    };
    if !scopes.contains(required_scope) {
        return Err(ReceiverError::Peer);
    }
    Ok(event)
}

/// Verifies a compact SET against one explicitly configured client peer.
///
/// The caller must first establish that `client` is active and has been
/// granted [`RECEIVE_SCOPE`] by tenant registration policy. Its identity is
/// pinned to `iss`; key material comes exclusively from `jwks`. This function
/// never reads a key URL from the token.
pub async fn verify_inbound_set(
    cache: &ClientKeyCache,
    tenant: &Tenant,
    client: &ClientId,
    issuer: &Issuer,
    jwks: &JwksSource,
    audience: &str,
    token: &str,
    now: OffsetDateTime,
) -> Result<VerifiedEvent, ReceiverError> {
    let header = asterius_jose::jws::parse(token).map_err(|_| ReceiverError::Token)?;
    let raw_header: Value =
        serde_json::from_slice(header.raw_header()).map_err(|_| ReceiverError::Token)?;
    if raw_header
        .as_object()
        .is_some_and(|object| object.contains_key("jku") || object.contains_key("x5u"))
    {
        return Err(ReceiverError::Token);
    }
    let kid = header.kid();
    let key_set = cache
        .resolve(&tenant.id, client, jwks, kid.as_ref(), now)
        .await
        .map_err(|_| ReceiverError::Keys)?;
    let policy = Policy::new(
        TypRule::Exactly(SET_TYP),
        vec![SigningAlgorithm::EdDsa, SigningAlgorithm::Es256],
    )
    .issued_by(issuer.as_str())
    .for_audience(audience)
    .without_expiry();
    let verified =
        verify::verify(token, &policy, &key_set, now).map_err(|_| ReceiverError::Token)?;
    parse_verified_event(client, verified, now)
}

fn parse_verified_event(
    peer: &ClientId,
    verified: Verified,
    now: OffsetDateTime,
) -> Result<VerifiedEvent, ReceiverError> {
    let claims = &verified.claims;
    let jti = claims
        .get("jti")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 255)
        .ok_or(ReceiverError::Profile)?
        .to_owned();
    if claims.get("sub").is_some() || claims.get("exp").is_some() {
        return Err(ReceiverError::Profile);
    }
    let issued_at = claims
        .get("iat")
        .and_then(Value::as_i64)
        .and_then(|seconds| time::OffsetDateTime::from_unix_timestamp(seconds).ok())
        .ok_or(ReceiverError::Profile)?;
    let replay_until = issued_at
        .checked_add(MAX_SET_AGE)
        .ok_or(ReceiverError::Profile)?;
    if replay_until < now {
        return Err(ReceiverError::Token);
    }
    if claims
        .get("txn")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 255)
        .is_none()
    {
        return Err(ReceiverError::Profile);
    }
    let subject = claims
        .get("sub_id")
        .ok_or(ReceiverError::Profile)
        .and_then(|value| Subject::from_json(value).map_err(|_| ReceiverError::Subject))?;
    let events = claims
        .get("events")
        .and_then(Value::as_object)
        .filter(|events| events.len() == 1)
        .ok_or(ReceiverError::Profile)?;
    let (uri, event) = events.iter().next().ok_or(ReceiverError::Profile)?;
    let event_type = LifecycleEventType::parse(uri).ok_or(ReceiverError::UnsupportedEvent)?;
    if !event.is_object() {
        return Err(ReceiverError::Profile);
    }
    let event_at = event
        .get("event_timestamp")
        .and_then(Value::as_i64)
        .and_then(|seconds| OffsetDateTime::from_unix_timestamp(seconds).ok())
        .ok_or(ReceiverError::Profile)?;
    // A signed event with an arbitrarily future timestamp would become the
    // subject's ordering high-water mark and suppress legitimate later SETs.
    // Permit the same small clock skew as the JWS verifier, but no more.
    if event_at > now + asterius_jose::verify::DEFAULT_FUTURE_SKEW {
        return Err(ReceiverError::Profile);
    }
    Ok(VerifiedEvent {
        peer: peer.clone(),
        jti,
        replay_until,
        subject,
        event_type,
        event_at,
        event: event.clone(),
    })
}
