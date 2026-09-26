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

#[derive(Debug)]
struct ReceiverSubjects<'a> {
    users: &'a asterius_store_pg::PgUserRepository,
    reservations: std::sync::Mutex<Vec<asterius_store_pg::ReceiverSubjectReservation>>,
}

#[async_trait::async_trait]
impl asterius_domain::ports::SubjectResolver for ReceiverSubjects<'_> {
    async fn subject(
        &self,
        user: asterius_domain::UserId,
        sector: &asterius_domain::SectorIdentifier,
    ) -> Result<asterius_domain::SubjectId, asterius_domain::DomainError> {
        let subject = self.users.subject_for_notification(user, sector).await?;
        self.reservations
            .lock()
            .map_err(|_| {
                asterius_domain::DomainError::invalid(
                    "ssf.receiver.subject",
                    "subject reservation collector is unavailable",
                )
            })?
            .push(asterius_store_pg::ReceiverSubjectReservation {
                sector_identifier: sector.as_str().to_owned(),
                subject: subject.as_str().to_owned(),
            });
        Ok(subject)
    }
}

struct ReceiverPreparer<'a> {
    tenant: &'a Tenant,
    clients: &'a dyn asterius_domain::ports::ClientRepository,
    users: &'a dyn asterius_domain::ports::SubjectResolver,
    reservations: &'a std::sync::Mutex<Vec<asterius_store_pg::ReceiverSubjectReservation>>,
    queues: &'a dyn crate::ssf::SsfQueues,
    signer: &'a dyn asterius_domain::keys::Signer,
}

#[async_trait::async_trait]
impl asterius_store_pg::ReceiverNotificationPreparer for ReceiverPreparer<'_> {
    async fn prepare(
        &self,
        peer_client_id: &str,
        user_id: uuid::Uuid,
        sessions: &[asterius_store_pg::ReceiverSession],
        action: asterius_store_pg::ReceiverAction,
        account_was_active: bool,
        now: OffsetDateTime,
    ) -> Result<asterius_store_pg::ReceiverNotifications, asterius_domain::DomainError> {
        let mut prepared = asterius_store_pg::ReceiverNotifications::default();
        if action == asterius_store_pg::ReceiverAction::ObserveOnly {
            return Ok(prepared);
        }
        let notifier = crate::backchannel::Notifier {
            tenant: self.tenant,
            clients: self.clients,
            subjects: self.users,
            signer: self.signer,
            outbox: None,
        };
        let transmitter = crate::ssf::SsfTransmitter {
            tenant: &self.tenant.id,
            issuer: &self.tenant.issuer,
            queues: self.queues,
            clients: self.clients,
            subjects: self.users,
            signer: self.signer,
        };
        let user = asterius_domain::UserId::new(user_id);
        let source_peer = ClientId::new(peer_client_id);
        for session in sessions {
            prepared.outbox.extend(
                notifier
                    .prepare_for_receiver(user_id, &session.public_sid, &session.participants, now)
                    .await?,
            );
            let signal = transmitter
                .prepare_for_receiver(
                    &crate::ssf::Cause::SessionRevoked {
                        user,
                        sid: session.public_sid.clone(),
                        by: crate::ssf::RevokedBy::ReceiverSignal,
                        locale: asterius_domain::Locale::default(),
                    },
                    &source_peer,
                    now,
                )
                .await?;
            prepared.outbox.extend(signal.outbox);
            prepared.poll.extend(signal.poll);
        }
        if action == asterius_store_pg::ReceiverAction::AccountDisabled && account_was_active {
            let signal = transmitter
                .prepare_for_receiver(
                    &crate::ssf::Cause::AccountDisabled {
                        user,
                        reason: None,
                        initiator: asterius_ssf::caep::InitiatingEntity::Policy,
                    },
                    &source_peer,
                    now,
                )
                .await?;
            prepared.outbox.extend(signal.outbox);
            prepared.poll.extend(signal.poll);
        }
        prepared.subjects = std::mem::take(&mut *self.reservations.lock().map_err(|_| {
            asterius_domain::DomainError::invalid(
                "ssf.receiver.subject",
                "subject reservation collector is unavailable",
            )
        })?);
        Ok(prepared)
    }
}

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

/// Local maximum age for poll-delivered SETs. RFC 8936 permits queued and
/// redelivered SETs but does not specify an age limit. Seven days lets an
/// operator recover a delayed stream while bounding historical actions and
/// the associated replay tombstones. Push delivery keeps [`MAX_SET_AGE`].
pub const MAX_POLLED_SET_AGE: time::Duration = time::Duration::days(7);

#[derive(Clone, Copy)]
enum DeliveryMode {
    Push,
    Poll,
}

impl DeliveryMode {
    const fn max_age(self) -> time::Duration {
        match self {
            Self::Push => MAX_SET_AGE,
            Self::Poll => MAX_POLLED_SET_AGE,
        }
    }
}

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
    let event =
        match verify_for_configured_peer(&endpoints, &tenant, &peer, &audience, token, now).await {
            Ok(event) => event,
            Err(ReceiverError::Metadata | ReceiverError::Keys) => {
                return response(StatusCode::SERVICE_UNAVAILABLE);
            }
            Err(_) => return response(StatusCode::BAD_REQUEST),
        };
    let pinned = endpoints
        .http_signature_peers
        .find(tenant.id.as_str(), event.peer.as_str());
    if let Some(pinned) = pinned {
        // The SET signature has established the peer before its HTTP key is
        // selected. A configured peer cannot fall back to unsigned delivery.
        let Some(fields) = signed_fields(&headers) else {
            return peer_response(StatusCode::UNAUTHORIZED, Some(pinned));
        };
        if uri.query().is_some() || uri.path() != RECEIVER_PATH {
            return peer_response(StatusCode::UNAUTHORIZED, Some(pinned));
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
            return peer_response(StatusCode::UNAUTHORIZED, Some(pinned));
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
            Ok(ReplayCheck::Replay) => {
                return peer_response(StatusCode::UNAUTHORIZED, Some(pinned));
            }
            Err(_) => return peer_response(StatusCode::SERVICE_UNAVAILABLE, Some(pinned)),
        }
    }
    match apply_verified_event(&endpoints, &tenant, &event, now).await {
        Ok(()) => peer_response(StatusCode::ACCEPTED, pinned),
        Err(ApplyError::Invalid) => peer_response(StatusCode::BAD_REQUEST, pinned),
        Err(ApplyError::Storage) => peer_response(StatusCode::INTERNAL_SERVER_ERROR, pinned),
    }
}

/// Applies a verified event through the same atomic replay, lifecycle and
/// notification path for push and poll delivery. A poll caller acknowledges
/// only after this returns `Ok`, so replay after an interrupted acknowledgement
/// is safe.
pub(crate) async fn apply_verified_event(
    endpoints: &crate::http::protocol::ClientEndpoints,
    tenant: &Tenant,
    event: &VerifiedEvent,
    now: OffsetDateTime,
) -> Result<(), ApplyError> {
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
                return Err(ApplyError::Invalid);
            }
            match event.event.get("change_type").and_then(Value::as_str) {
                // A remote credential revocation/removal cannot identify or
                // safely mutate a local credential. Revoke sessions only.
                Some("revoke" | "delete") => {
                    asterius_store_pg::ReceiverAction::CredentialCompromised
                }
                Some("create" | "update") => asterius_store_pg::ReceiverAction::ObserveOnly,
                _ => return Err(ApplyError::Invalid),
            }
        }
    };
    let scope = endpoints.store.scope(tenant.id.clone());
    let clients = scope.clients(endpoints.capabilities);
    let users = scope.users(std::sync::Arc::clone(&endpoints.kek));
    let subjects = ReceiverSubjects {
        users: &users,
        reservations: std::sync::Mutex::new(Vec::new()),
    };
    let queues = crate::outbox::PgSsfQueues::new(
        endpoints.store.clone(),
        tenant.id.clone(),
        std::sync::Arc::clone(&endpoints.kek),
    );
    let preparer = ReceiverPreparer {
        tenant: &tenant,
        clients: &clients,
        users: &subjects,
        reservations: &subjects.reservations,
        queues: &queues,
        signer: endpoints.signer.as_ref(),
    };
    match scope
        .ssf_receiver()
        .process(
            event.peer.as_str(),
            &event.subject.key(),
            &event.jti,
            event.replay_until,
            action,
            event.event_at,
            now,
            &preparer,
        )
        .await
    {
        Ok(asterius_store_pg::ReceiverOutcome::Applied)
        | Ok(asterius_store_pg::ReceiverOutcome::Stale)
        | Ok(asterius_store_pg::ReceiverOutcome::Duplicate) => Ok(()),
        Err(asterius_domain::DomainError::Invalid { .. }) => Err(ApplyError::Invalid),
        Err(_) => Err(ApplyError::Storage),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ApplyError {
    Invalid,
    Storage,
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

/// Once the SET identifies an active configured peer, every application result
/// follows its response policy. Never return an unsigned success on failure.
fn peer_response(status: StatusCode, peer: Option<&crate::http_signatures::PeerKey>) -> Response {
    let Some(signer) = peer.and_then(|peer| peer.response_signer.as_ref()) else {
        return response(status);
    };
    let Ok(fields) = signer.sign(status.as_u16(), b"") else {
        tracing::error!("required HTTP response signing failed");
        return response(StatusCode::SERVICE_UNAVAILABLE);
    };
    let Ok(digest) = HeaderValue::from_str(&fields.content_digest) else {
        return response(StatusCode::SERVICE_UNAVAILABLE);
    };
    let Ok(input) = HeaderValue::from_str(&fields.signature_input) else {
        return response(StatusCode::SERVICE_UNAVAILABLE);
    };
    let Ok(signature) = HeaderValue::from_str(&fields.signature) else {
        return response(StatusCode::SERVICE_UNAVAILABLE);
    };
    let mut result = response(status);
    result.headers_mut().insert("content-digest", digest);
    result.headers_mut().insert("signature-input", input);
    result.headers_mut().insert("signature", signature);
    result
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
#[derive(Debug, Clone, Copy, Error)]
#[non_exhaustive]
pub enum ReceiverError {
    /// Signature, claim, or token type validation failed.
    #[error("the security event token could not be verified")]
    Token,
    /// A signed SET exceeds this receiver's local delivery age policy.
    #[error("the security event token exceeds the local delivery age limit")]
    TooOld,
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
    /// The configured peer's metadata could not be fetched or validated.
    #[error("the configured peer metadata is unavailable")]
    Metadata,
    /// The client is not authorized to submit events for this tenant.
    #[error("the event peer is not configured for this receiver")]
    Peer,
}

/// The portion of SSF 1.0 transmitter metadata needed for push verification
/// and later explicit stream establishment. The document is discovered from a
/// registered issuer, never from a SET. Endpoint URLs are metadata pins, not
/// permission to send a request without a separate upstream OAuth credential.
#[derive(Debug, Clone)]
pub struct UpstreamMetadata {
    pub jwks_uri: String,
    pub configuration_endpoint: String,
    pub status_endpoint: String,
    pub supports_poll: bool,
    pub default_subjects: Option<String>,
}

const METADATA_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(300);
const METADATA_FAILURE_TTL: std::time::Duration = std::time::Duration::from_secs(10);
const MAX_METADATA_CACHE_ENTRIES: usize = 1024;

#[derive(Debug, Clone)]
struct CachedMetadata {
    expires_at: std::time::Instant,
    result: Result<UpstreamMetadata, ReceiverError>,
}

type MetadataCell = std::sync::Arc<tokio::sync::Mutex<Option<CachedMetadata>>>;
type MetadataKey = (String, String, String);

/// Bounded, per-configured-peer discovery cache. A cell serializes refreshes
/// for one peer, while other peers and hot entries continue independently.
#[derive(Debug, Default)]
pub struct UpstreamMetadataCache {
    entries: std::sync::Mutex<std::collections::HashMap<MetadataKey, MetadataCell>>,
}

impl UpstreamMetadataCache {
    /// Empty cache for one server process. No metadata is trusted at startup.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    async fn validate(
        &self,
        endpoints: &crate::http::protocol::ClientEndpoints,
        tenant: &Tenant,
        issuer: &Issuer,
        pinned_jwks_uri: &str,
    ) -> Result<UpstreamMetadata, ReceiverError> {
        let key = (
            tenant.id.as_str().to_owned(),
            issuer.as_str().to_owned(),
            pinned_jwks_uri.to_owned(),
        );
        let cell = {
            let mut entries = self.entries.lock().map_err(|_| ReceiverError::Metadata)?;
            if !entries.contains_key(&key) && entries.len() >= MAX_METADATA_CACHE_ENTRIES {
                // Eviction is only a performance decision. A removed cell may
                // still serve an in-flight request through its Arc.
                if let Some(evicted) = entries.keys().next().cloned() {
                    entries.remove(&evicted);
                }
            }
            std::sync::Arc::clone(
                entries
                    .entry(key)
                    .or_insert_with(|| std::sync::Arc::new(tokio::sync::Mutex::new(None))),
            )
        };
        let mut cached = cell.lock().await;
        let now = std::time::Instant::now();
        if let Some(entry) = cached.as_ref()
            && entry.expires_at > now
        {
            return entry.result.clone();
        }
        let result = discover_configured_peer(endpoints, issuer)
            .await
            .and_then(|metadata| {
                if metadata.jwks_uri == pinned_jwks_uri {
                    Ok(metadata)
                } else {
                    Err(ReceiverError::Metadata)
                }
            });
        let ttl = if result.is_ok() {
            METADATA_CACHE_TTL
        } else {
            METADATA_FAILURE_TTL
        };
        *cached = Some(CachedMetadata {
            expires_at: now + ttl,
            result: result.clone(),
        });
        result
    }
}

impl UpstreamMetadata {
    fn from_document(document: &[u8], issuer: &Issuer) -> Result<Self, ReceiverError> {
        let value: Value = serde_json::from_slice(document).map_err(|_| ReceiverError::Metadata)?;
        let object = value.as_object().ok_or(ReceiverError::Metadata)?;
        if object.get("issuer").and_then(Value::as_str) != Some(issuer.as_str()) {
            return Err(ReceiverError::Metadata);
        }
        // We implement the final 1.0 wire contract. A missing version means
        // the first implementer's draft, not the final specification.
        if object.get("spec_version").and_then(Value::as_str) != Some("1_0") {
            return Err(ReceiverError::Metadata);
        }
        let default_subjects = object
            .get("default_subjects")
            .map(|value| value.as_str().ok_or(ReceiverError::Metadata))
            .transpose()?;
        if default_subjects.is_some_and(|value| !matches!(value, "ALL" | "NONE")) {
            return Err(ReceiverError::Metadata);
        }
        let jwks_uri = object
            .get("jwks_uri")
            .and_then(Value::as_str)
            .ok_or(ReceiverError::Metadata)?;
        validate_metadata_url(jwks_uri)?;
        let methods = object
            .get("delivery_methods_supported")
            .and_then(Value::as_array)
            .ok_or(ReceiverError::Metadata)?;
        if !methods
            .iter()
            .any(|method| method.as_str() == Some(asterius_ssf::stream::DELIVERY_PUSH))
        {
            return Err(ReceiverError::Metadata);
        }
        if let Some(critical) = object.get("critical_subject_members") {
            let members = critical.as_array().ok_or(ReceiverError::Metadata)?;
            // The receiver processes the base RFC 9493 formats, but no
            // transmitter-specific critical extension members.
            if !members.is_empty() {
                return Err(ReceiverError::Metadata);
            }
        }
        for endpoint in [
            "configuration_endpoint",
            "status_endpoint",
            "verification_endpoint",
        ] {
            let url = object
                .get(endpoint)
                .and_then(Value::as_str)
                .ok_or(ReceiverError::Metadata)?;
            validate_metadata_url(url)?;
        }
        let schemes = object
            .get("authorization_schemes")
            .and_then(Value::as_array)
            .ok_or(ReceiverError::Metadata)?;
        if !schemes.iter().any(|scheme| {
            scheme.get("spec_urn").and_then(Value::as_str) == Some("urn:ietf:rfc:6749")
        }) {
            return Err(ReceiverError::Metadata);
        }
        Ok(Self {
            jwks_uri: jwks_uri.to_owned(),
            configuration_endpoint: object
                .get("configuration_endpoint")
                .and_then(Value::as_str)
                .ok_or(ReceiverError::Metadata)?
                .to_owned(),
            status_endpoint: object
                .get("status_endpoint")
                .and_then(Value::as_str)
                .ok_or(ReceiverError::Metadata)?
                .to_owned(),
            supports_poll: methods
                .iter()
                .any(|method| method.as_str() == Some(asterius_ssf::stream::DELIVERY_POLL)),
            default_subjects: default_subjects.map(str::to_owned),
        })
    }
}

/// Parses a transmitter's successful creation response or authenticated list
/// entry before a stream is persisted. The response is never a source of
/// trust: it must echo the exact
/// configured issuer, chosen audience, requested event set and delivery mode.
/// A poll URL is accepted only as an HTTPS URL; the outbound transport must
/// still apply its DNS/IP SSRF guard when it is eventually used.
pub fn validated_upstream_stream(
    metadata: &UpstreamMetadata,
    issuer: &Issuer,
    audience: &str,
    requested_events: &[String],
    delivery_method: &str,
    push_endpoint: Option<&str>,
    status: u16,
    expected_status: u16,
    content_type: Option<&str>,
    document: &[u8],
    now: OffsetDateTime,
) -> Result<asterius_store_pg::UpstreamStream, ReceiverError> {
    if !matches!(expected_status, 200 | 201)
        || status != expected_status
        || !content_type.is_some_and(|value| value.split(';').next().is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case("application/json")))
        || document.is_empty()
        || document.len() > 8 * 1024
        // A valid transmitter may default to ALL, but this receiver will not
        // establish a stream that silently includes every subject.
        || metadata.default_subjects.as_deref() != Some("NONE")
        || requested_events.is_empty()
        || requested_events.len() > 16
        || requested_events.iter().collect::<BTreeSet<_>>().len() != requested_events.len()
        || requested_events.iter().any(|uri| {
            !matches!(
                uri.as_str(),
                asterius_ssf::caep::SESSION_REVOKED
                    | asterius_ssf::caep::CREDENTIAL_CHANGE
                    | asterius_ssf::caep::ACCOUNT_DISABLED
            )
        })
    {
        return Err(ReceiverError::Metadata);
    }
    let value: Value = serde_json::from_slice(document).map_err(|_| ReceiverError::Metadata)?;
    let object = value.as_object().ok_or(ReceiverError::Metadata)?;
    if object.get("iss").and_then(Value::as_str) != Some(issuer.as_str()) {
        return Err(ReceiverError::Metadata);
    }
    let aud = object.get("aud").ok_or(ReceiverError::Metadata)?;
    let audience_matches = aud.as_str() == Some(audience)
        || aud
            .as_array()
            .is_some_and(|values| values.len() == 1 && values[0].as_str() == Some(audience));
    if !audience_matches {
        return Err(ReceiverError::Metadata);
    }
    let stream_id = object
        .get("stream_id")
        .and_then(Value::as_str)
        .ok_or(ReceiverError::Metadata)?;
    if stream_id.is_empty()
        || stream_id.len() > 255
        || !stream_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~'))
    {
        return Err(ReceiverError::Metadata);
    }
    let expected_events: BTreeSet<&str> = requested_events.iter().map(String::as_str).collect();
    for field in ["events_requested", "events_delivered"] {
        let events = object
            .get(field)
            .and_then(Value::as_array)
            .ok_or(ReceiverError::Metadata)?;
        let actual_events: BTreeSet<&str> = events
            .iter()
            .map(|event| event.as_str().ok_or(ReceiverError::Metadata))
            .collect::<Result<_, _>>()?;
        // Equality to the complete requested set is a local profile: SSF
        // permits the transmitter to deliver a subset, but silently losing a
        // requested security signal would mislead this receiver's operator.
        if events.len() != expected_events.len() || actual_events != expected_events {
            return Err(ReceiverError::Metadata);
        }
    }
    let delivery = object
        .get("delivery")
        .and_then(Value::as_object)
        .ok_or(ReceiverError::Metadata)?;
    if delivery.get("method").and_then(Value::as_str) != Some(delivery_method) {
        return Err(ReceiverError::Metadata);
    }
    let endpoint = delivery
        .get("endpoint_url")
        .and_then(Value::as_str)
        .ok_or(ReceiverError::Metadata)?;
    let poll_endpoint = match delivery_method {
        asterius_ssf::stream::DELIVERY_POLL
            if metadata.supports_poll && push_endpoint.is_none() =>
        {
            validate_metadata_url(endpoint)?;
            Some(endpoint.to_owned())
        }
        asterius_ssf::stream::DELIVERY_PUSH if push_endpoint == Some(endpoint) => None,
        _ => return Err(ReceiverError::Metadata),
    };
    Ok(asterius_store_pg::UpstreamStream {
        peer_client_id: issuer.as_str().to_owned(),
        issuer: issuer.as_str().to_owned(),
        jwks_uri: metadata.jwks_uri.clone(),
        configuration_endpoint: metadata.configuration_endpoint.clone(),
        status_endpoint: metadata.status_endpoint.clone(),
        stream_id: stream_id.to_owned(),
        delivery_method: delivery_method.to_owned(),
        poll_endpoint,
        audience: audience.to_owned(),
        events_requested: requested_events.to_vec(),
        created_at: now,
        updated_at: now,
        last_polled_at: None,
    })
}

fn validate_metadata_url(raw: &str) -> Result<(), ReceiverError> {
    if raw.is_empty() || raw.len() > 2048 {
        return Err(ReceiverError::Metadata);
    }
    let url = url::Url::parse(raw).map_err(|_| ReceiverError::Metadata)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(ReceiverError::Metadata);
    }
    Ok(())
}

/// Fetches only the well-known location derived from the operator-registered
/// issuer. The shared client URL fetcher enforces HTTPS, DNS/IP SSRF checks,
/// redirect refusal, response type, body limit, and timeout.
async fn discover_configured_peer(
    endpoints: &crate::http::protocol::ClientEndpoints,
    issuer: &Issuer,
) -> Result<UpstreamMetadata, ReceiverError> {
    let url = format!(
        "https://{}/.well-known/ssf-configuration{}",
        issuer.authority(),
        issuer.path(),
    );
    let document = endpoints
        .outbound
        .fetch_json(&url)
        .await
        .map_err(|_| ReceiverError::Metadata)?;
    UpstreamMetadata::from_document(&document, issuer)
}

/// Finds a peer by its tenant-local client identity and enforces the explicit
/// receiver scope before any key resolution. Registration policy controls
/// whether this capability may be assigned; a client without that exact scope
/// is not an event source.
pub async fn configured_peer(
    endpoints: &crate::http::protocol::ClientEndpoints,
    tenant: &Tenant,
    peer: &ClientId,
) -> Result<(Issuer, JwksSource, BTreeSet<String>, UpstreamMetadata), ReceiverError> {
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
    if issuer.as_str() != peer.as_str() {
        return Err(ReceiverError::Peer);
    }
    let jwks = client.registration.jwks;
    let JwksSource::Uri(ref pinned_jwks_uri) = jwks else {
        // A receiver using inline keys or an unpinned URL cannot satisfy the
        // CAEP profile's metadata JWKS requirement.
        return Err(ReceiverError::Peer);
    };
    let metadata = endpoints
        .ssf_metadata_cache
        .validate(endpoints, tenant, &issuer, pinned_jwks_uri)
        .await?;
    Ok((issuer, jwks, client.registration.scopes, metadata))
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
    verify_for_configured_peer_mode(
        endpoints,
        tenant,
        peer,
        audience,
        token,
        now,
        DeliveryMode::Push,
    )
    .await
}

/// Verifies a queued RFC 8936 SET using the bounded poll-only age policy.
/// The push route continues to use the five-minute limit.
pub async fn verify_polled_for_configured_peer(
    endpoints: &crate::http::protocol::ClientEndpoints,
    tenant: &Tenant,
    peer: &ClientId,
    audience: &str,
    token: &str,
    now: OffsetDateTime,
) -> Result<VerifiedEvent, ReceiverError> {
    verify_for_configured_peer_mode(
        endpoints,
        tenant,
        peer,
        audience,
        token,
        now,
        DeliveryMode::Poll,
    )
    .await
}

async fn verify_for_configured_peer_mode(
    endpoints: &crate::http::protocol::ClientEndpoints,
    tenant: &Tenant,
    peer: &ClientId,
    audience: &str,
    token: &str,
    now: OffsetDateTime,
    mode: DeliveryMode,
) -> Result<VerifiedEvent, ReceiverError> {
    let (issuer, jwks, scopes, _metadata) = configured_peer(endpoints, tenant, peer).await?;
    let event = verify_inbound_set_mode(
        endpoints.authenticator.client_keys(),
        tenant,
        peer,
        &issuer,
        &jwks,
        audience,
        token,
        now,
        mode,
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
    verify_inbound_set_mode(
        cache,
        tenant,
        client,
        issuer,
        jwks,
        audience,
        token,
        now,
        DeliveryMode::Push,
    )
    .await
}

#[allow(clippy::too_many_arguments)] // The extra mode keeps push and poll policy explicit at this boundary.
async fn verify_inbound_set_mode(
    cache: &ClientKeyCache,
    tenant: &Tenant,
    client: &ClientId,
    issuer: &Issuer,
    jwks: &JwksSource,
    audience: &str,
    token: &str,
    now: OffsetDateTime,
    mode: DeliveryMode,
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
    parse_verified_event(client, verified, now, mode)
}

fn parse_verified_event(
    peer: &ClientId,
    verified: Verified,
    now: OffsetDateTime,
    mode: DeliveryMode,
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
    let accepted_until = issued_at
        .checked_add(mode.max_age())
        .ok_or(ReceiverError::Profile)?;
    if accepted_until <= now {
        return Err(ReceiverError::TooOld);
    }
    // Poll tombstones survive for a full poll window after receipt. This
    // remains safe even when a queued SET arrives just before its age limit.
    let replay_until = match mode {
        DeliveryMode::Push => accepted_until,
        DeliveryMode::Poll => now
            .checked_add(MAX_POLLED_SET_AGE)
            .ok_or(ReceiverError::Profile)?
            .max(accepted_until),
    };
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
