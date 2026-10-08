//! Explicit outbound SSF management. Inbound `ssf.receive` registration only
//! identifies a transmitter; it cannot supply an OAuth management credential.
//! Only explicit authenticated admin operations call this service. Durable
//! pending-review state and subject enrollment remain separate operator steps.

use crate::config::SsfUpstreamPeerConfig;
use crate::http::protocol::ClientEndpoints;
use crate::http::ssf_receiver;
use crate::outbound::{HttpsPoster, PostRequest, PostResponse};
use asterius_domain::{ClientId, Tenant};
use asterius_ssf::{caep, stream};
use base64::Engine as _;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::io::Read as _;
use time::OffsetDateTime;
use zeroize::Zeroizing;

/// Refusal with no bearer token, URL query, or upstream response body in its
/// display text. A caller can report this without exposing credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SetupError {
    #[error("the upstream transmitter is not explicitly configured")]
    Peer,
    #[error("the upstream OAuth credential is unavailable")]
    Credential,
    #[error("the upstream SSF management exchange failed")]
    Transport,
    #[error("the upstream SSF management response is invalid")]
    Response,
    #[error("upstream stream state cannot be stored")]
    Storage,
    #[error("an upstream stream is already recorded for this peer")]
    AlreadyConfigured,
    #[error("an upstream stream setup needs operator reconciliation")]
    PendingReview,
    #[error("the upstream security event could not be applied")]
    Event,
}

pub(crate) fn expected_audience(config: &SsfUpstreamPeerConfig, tenant: &Tenant) -> String {
    config
        .expected_audience
        .clone()
        .unwrap_or_else(|| format!("{}{}", tenant.issuer.as_str(), ssf_receiver::RECEIVER_PATH))
}

/// Read back the exact stream recorded for a configured peer. This does not
/// repair drift or change local state; an operator must investigate a mismatch.
pub async fn verify_recorded_stream(
    endpoints: &ClientEndpoints,
    tenant: &Tenant,
    config: &SsfUpstreamPeerConfig,
    poster: &HttpsPoster,
    now: OffsetDateTime,
) -> Result<(), SetupError> {
    let peer = ClientId::new(config.issuer.as_str());
    let (issuer, _jwks, _scopes, metadata) =
        ssf_receiver::configured_peer(endpoints, tenant, &peer)
            .await
            .map_err(|_| SetupError::Peer)?;
    if issuer != config.issuer
        || !metadata.supports_poll
        || !metadata.subject_policy_allowed(config.allow_all_subjects)
    {
        return Err(SetupError::Peer);
    }
    same_origin_management_endpoint(&metadata.configuration_endpoint, &issuer)?;
    same_origin_management_endpoint(&metadata.status_endpoint, &issuer)?;
    let repository = endpoints
        .store
        .scope(tenant.id.clone())
        .ssf_upstream_streams();
    if repository
        .pending_setup(peer.as_str())
        .await
        .map_err(|_| SetupError::Storage)?
        .is_some()
    {
        return Err(SetupError::PendingReview);
    }
    let recorded = repository
        .find(peer.as_str())
        .await
        .map_err(|_| SetupError::Storage)?
        .ok_or(SetupError::Peer)?;
    if recorded.deletion_started_at.is_some() {
        return Err(SetupError::PendingReview);
    }
    let expected_audience = expected_audience(config, tenant);
    if recorded.peer_client_id != peer.as_str()
        || recorded.issuer != issuer.as_str()
        || recorded.jwks_uri != metadata.jwks_uri
        || recorded.configuration_endpoint != metadata.configuration_endpoint
        || recorded.status_endpoint != metadata.status_endpoint
        || recorded.audience != expected_audience
        || recorded.delivery_method != stream::DELIVERY_POLL
        || recorded
            .poll_endpoint
            .as_deref()
            .is_none_or(|url| same_origin_management_endpoint(url, &issuer).is_err())
    {
        return Err(SetupError::Peer);
    }
    let token = read_bearer_file(&config.bearer_token_file)?;
    let authorization = Zeroizing::new(format!("Bearer {}", token.as_str()));
    let listed = list_streams(poster, &metadata.configuration_endpoint, &authorization).await?;
    let selected =
        recorded_stream_in_list(&listed, &recorded.stream_id)?.ok_or(SetupError::PendingReview)?;
    let remote = reconcile_listed(
        std::slice::from_ref(selected),
        &metadata,
        config.allow_all_subjects,
        &issuer,
        &recorded.audience,
        &recorded.events_requested,
        now,
    )?
    .ok_or(SetupError::PendingReview)?;
    if remote.stream_id != recorded.stream_id
        || remote.poll_endpoint != recorded.poll_endpoint
        || remote.peer_client_id != recorded.peer_client_id
        || remote.issuer != recorded.issuer
        || remote.jwks_uri != recorded.jwks_uri
        || remote.configuration_endpoint != recorded.configuration_endpoint
        || remote.status_endpoint != recorded.status_endpoint
        || remote.audience != recorded.audience
        || remote.delivery_method != recorded.delivery_method
        || remote.events_requested != recorded.events_requested
    {
        return Err(SetupError::PendingReview);
    }
    let url = status_url(&metadata.status_endpoint, &recorded.stream_id)?;
    let status = poster
        .get_with_response(&url, &authorization)
        .await
        .map_err(|_| SetupError::Transport)?;
    validate_status(&status, &recorded.stream_id)
}

/// Ask the transmitter to send a stream-scoped verification SET. The random
/// state is held only in the outbound request; its hash and expiry are stored
/// before the POST, so asynchronous poll delivery can prove correlation.
pub async fn request_stream_verification(
    endpoints: &ClientEndpoints,
    tenant: &Tenant,
    config: &SsfUpstreamPeerConfig,
    poster: &HttpsPoster,
    now: OffsetDateTime,
) -> Result<(), SetupError> {
    verify_recorded_stream(endpoints, tenant, config, poster, now).await?;
    let peer = ClientId::new(config.issuer.as_str());
    let (_issuer, _jwks, _scopes, metadata) =
        ssf_receiver::configured_peer(endpoints, tenant, &peer)
            .await
            .map_err(|_| SetupError::Peer)?;
    same_origin_management_endpoint(&metadata.verification_endpoint, &config.issuer)?;
    let repository = endpoints
        .store
        .scope(tenant.id.clone())
        .ssf_upstream_streams();
    let recorded = repository
        .find(peer.as_str())
        .await
        .map_err(|_| SetupError::Storage)?
        .ok_or(SetupError::Peer)?;
    let mut nonce = [0_u8; 32];
    getrandom::fill(&mut nonce).map_err(|_| SetupError::Credential)?;
    let state = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce);
    let state_hash = Sha256::digest(state.as_bytes());
    let expires_at = now
        .checked_add(time::Duration::minutes(15))
        .ok_or(SetupError::Response)?;
    if !repository
        .begin_verification(
            peer.as_str(),
            &recorded.stream_id,
            &state_hash,
            expires_at,
            now,
        )
        .await
        .map_err(|_| SetupError::Storage)?
    {
        return Err(SetupError::PendingReview);
    }
    let token = read_bearer_file(&config.bearer_token_file)?;
    let authorization = Zeroizing::new(format!("Bearer {}", token.as_str()));
    let body = serde_json::to_vec(&json!({
        "stream_id": &recorded.stream_id,
        "state": &state,
    }))
    .map_err(|_| SetupError::Response)?;
    let response = poster
        .post_with_response(
            &metadata.verification_endpoint,
            PostRequest::of("application/json").authorized_by(Some(&authorization)),
            &body,
        )
        .await
        .map_err(|_| SetupError::Transport)?;
    if response.status != 204 || response.truncated || !response.body.is_empty() {
        return Err(SetupError::Response);
    }
    Ok(())
}

/// Delete one recorded remote poll stream. A durable marker precedes the
/// outbound DELETE: if the reply is lost, the next call reads the authenticated
/// stream list and finishes locally only when the exact stream is absent.
pub async fn delete_recorded_stream(
    endpoints: &ClientEndpoints,
    tenant: &Tenant,
    config: &SsfUpstreamPeerConfig,
    poster: &HttpsPoster,
    now: OffsetDateTime,
) -> Result<(), SetupError> {
    let peer = ClientId::new(config.issuer.as_str());
    let (issuer, _jwks, _scopes, metadata) =
        ssf_receiver::configured_peer(endpoints, tenant, &peer)
            .await
            .map_err(|_| SetupError::Peer)?;
    // Cleanup remains possible if the operator revoked ALL-subject consent
    // after creating the stream. Remote deletion only needs the pinned
    // identity and authenticated configuration endpoint.
    if issuer != config.issuer || !metadata.supports_poll {
        return Err(SetupError::Peer);
    }
    same_origin_management_endpoint(&metadata.configuration_endpoint, &issuer)?;
    let repository = endpoints
        .store
        .scope(tenant.id.clone())
        .ssf_upstream_streams();
    if repository
        .pending_setup(peer.as_str())
        .await
        .map_err(|_| SetupError::Storage)?
        .is_some()
    {
        return Err(SetupError::PendingReview);
    }
    let recorded = repository
        .find(peer.as_str())
        .await
        .map_err(|_| SetupError::Storage)?
        .ok_or(SetupError::Peer)?;
    if recorded.issuer != issuer.as_str()
        || recorded.jwks_uri != metadata.jwks_uri
        || recorded.configuration_endpoint != metadata.configuration_endpoint
        || recorded.status_endpoint != metadata.status_endpoint
        || recorded.audience != expected_audience(config, tenant)
        || recorded.delivery_method != stream::DELIVERY_POLL
    {
        return Err(SetupError::PendingReview);
    }
    let token = read_bearer_file(&config.bearer_token_file)?;
    let authorization = Zeroizing::new(format!("Bearer {}", token.as_str()));
    if !repository
        .begin_delete(peer.as_str(), &recorded.stream_id, now)
        .await
        .map_err(|_| SetupError::Storage)?
    {
        return Err(SetupError::PendingReview);
    }
    let listed = list_streams(poster, &metadata.configuration_endpoint, &authorization).await?;
    if let Some(selected) = recorded_stream_in_list(&listed, &recorded.stream_id)? {
        let remote = reconcile_listed(
            std::slice::from_ref(selected),
            &metadata,
            true,
            &issuer,
            &recorded.audience,
            &recorded.events_requested,
            now,
        )?
        .ok_or(SetupError::PendingReview)?;
        if remote.stream_id != recorded.stream_id || remote.poll_endpoint != recorded.poll_endpoint
        {
            return Err(SetupError::PendingReview);
        }
        let url = status_url(&metadata.configuration_endpoint, &recorded.stream_id)?;
        let response = poster
            .delete_with_response(&url, &authorization)
            .await
            .map_err(|_| SetupError::Transport)?;
        if response.status != 204 || response.truncated || !response.body.is_empty() {
            return Err(SetupError::Response);
        }
        // A 204 proves that DELETE was accepted; authenticated readback proves
        // that a retry will not create a second remote stream accidentally.
        let remaining =
            list_streams(poster, &metadata.configuration_endpoint, &authorization).await?;
        if recorded_stream_in_list(&remaining, &recorded.stream_id)?.is_some() {
            return Err(SetupError::PendingReview);
        }
    }
    if repository
        .finish_delete(peer.as_str(), &recorded.stream_id)
        .await
        .map_err(|_| SetupError::Storage)?
    {
        Ok(())
    } else {
        Err(SetupError::PendingReview)
    }
}

/// Poll at most one SET from an established upstream stream, apply it through
/// the push receiver's atomic replay/lifecycle path, then acknowledge its
/// `jti` in a separate RFC 8936 request. A failure before acknowledgement
/// leaves the transmitter free to redeliver; the local replay record makes
/// such redelivery harmless. This operation is not yet scheduled by a worker.
// Polling has a strict sequence of metadata, stream, SET and ACK checks;
// keeping that sequence visible prevents acknowledgement before local commit.
#[allow(clippy::too_many_lines)]
pub async fn poll_once(
    endpoints: &ClientEndpoints,
    tenant: &Tenant,
    config: &SsfUpstreamPeerConfig,
    poster: &HttpsPoster,
    now: OffsetDateTime,
) -> Result<bool, SetupError> {
    let peer = ClientId::new(config.issuer.as_str());
    let (issuer, _jwks, _scopes, metadata) =
        ssf_receiver::configured_peer(endpoints, tenant, &peer)
            .await
            .map_err(|_| SetupError::Peer)?;
    if issuer != config.issuer
        || !metadata.supports_poll
        || !metadata.subject_policy_allowed(config.allow_all_subjects)
    {
        return Err(SetupError::Peer);
    }
    let repository = endpoints
        .store
        .scope(tenant.id.clone())
        .ssf_upstream_streams();
    let established = repository
        .find(peer.as_str())
        .await
        .map_err(|_| SetupError::Storage)?
        .ok_or(SetupError::Peer)?;
    if established.deletion_started_at.is_some() {
        return Err(SetupError::PendingReview);
    }
    if established.issuer != issuer.as_str()
        || established.jwks_uri != metadata.jwks_uri
        || established.configuration_endpoint != metadata.configuration_endpoint
        || established.status_endpoint != metadata.status_endpoint
        || established.delivery_method != stream::DELIVERY_POLL
        || established.audience != expected_audience(config, tenant)
    {
        return Err(SetupError::Peer);
    }
    let poll_url = established
        .poll_endpoint
        .as_deref()
        .ok_or(SetupError::Peer)?;
    // The management bearer is only sent to the registered issuer's origin.
    same_origin_management_endpoint(poll_url, &issuer)?;
    let token = read_bearer_file(&config.bearer_token_file)?;
    let authorization = Zeroizing::new(format!("Bearer {}", token.as_str()));
    let request = serde_json::to_vec(&json!({"maxEvents": 1, "returnImmediately": true}))
        .map_err(|_| SetupError::Response)?;
    let response = poster
        .post_with_poll_response(
            poll_url,
            PostRequest::of("application/json")
                .accepting("application/json")
                .authorized_by(Some(&authorization)),
            &request,
        )
        .await
        .map_err(|_| SetupError::Transport)?;
    let received = parse_polled_set(&response)?;
    let Some((jti, set)) = received else {
        if !repository
            .mark_polled(peer.as_str(), &established.stream_id, now)
            .await
            .map_err(|_| SetupError::Storage)?
        {
            return Err(SetupError::Peer);
        }
        return Ok(false);
    };
    let event = ssf_receiver::verify_polled_for_configured_peer(
        endpoints,
        tenant,
        &peer,
        &established.audience,
        &set,
        now,
    )
    .await;
    let event = match event {
        Ok(event) => event,
        // A verification SET need not carry CAEP's txn/event_timestamp, so
        // the lifecycle parser may reject its profile before seeing its URI.
        Err(
            ssf_receiver::ReceiverError::UnsupportedEvent | ssf_receiver::ReceiverError::Profile,
        ) => {
            let control = ssf_receiver::verify_polled_stream_verification(
                endpoints,
                tenant,
                &peer,
                &established.audience,
                &established.stream_id,
                &set,
                now,
            )
            .await;
            let control = match control {
                Ok(control) => control,
                Err(error) => {
                    let (code, description) = invalid_set_error(error).ok_or(SetupError::Event)?;
                    report_invalid_set(poster, poll_url, &authorization, &jti, code, description)
                        .await?;
                    return mark_poll_outcome(&repository, &peer, &established.stream_id, now)
                        .await;
                }
            };
            if control.peer != peer || control.jti != jti {
                report_invalid_set(
                    poster,
                    poll_url,
                    &authorization,
                    &jti,
                    "invalid_request",
                    "The SET identifier does not match the poll response",
                )
                .await?;
                return mark_poll_outcome(&repository, &peer, &established.stream_id, now).await;
            }
            let state_hash = control
                .state
                .as_deref()
                .map(|state| Sha256::digest(state.as_bytes()));
            let accepted = repository
                .complete_verification(
                    peer.as_str(),
                    &established.stream_id,
                    &jti,
                    state_hash.as_deref(),
                    control.replay_until,
                    now,
                )
                .await
                .map_err(|_| SetupError::Storage)?;
            if !accepted {
                report_invalid_set(
                    poster,
                    poll_url,
                    &authorization,
                    &jti,
                    "invalid_state",
                    "The verification state does not match the pending request",
                )
                .await?;
                return mark_poll_outcome(&repository, &peer, &established.stream_id, now).await;
            }
            acknowledge_polled_set(poster, poll_url, &authorization, &jti).await?;
            return mark_poll_outcome(&repository, &peer, &established.stream_id, now).await;
        }
        Err(error) => {
            let (code, description) = invalid_set_error(error).ok_or(SetupError::Event)?;
            report_invalid_set(poster, poll_url, &authorization, &jti, code, description).await?;
            if !repository
                .mark_polled(peer.as_str(), &established.stream_id, now)
                .await
                .map_err(|_| SetupError::Storage)?
            {
                return Err(SetupError::Peer);
            }
            return Ok(false);
        }
    };
    if event.peer != peer {
        return Err(SetupError::Event);
    }
    if event.jti != jti {
        report_invalid_set(
            poster,
            poll_url,
            &authorization,
            &jti,
            "invalid_request",
            "The SET identifier does not match the poll response",
        )
        .await?;
        if !repository
            .mark_polled(peer.as_str(), &established.stream_id, now)
            .await
            .map_err(|_| SetupError::Storage)?
        {
            return Err(SetupError::Peer);
        }
        return Ok(false);
    }
    let event_uri = match event.event_type {
        ssf_receiver::LifecycleEventType::SessionRevoked => caep::SESSION_REVOKED,
        ssf_receiver::LifecycleEventType::CredentialChange => caep::CREDENTIAL_CHANGE,
        ssf_receiver::LifecycleEventType::AccountDisabled => caep::ACCOUNT_DISABLED,
    };
    if !established
        .events_requested
        .iter()
        .any(|uri| uri == event_uri)
    {
        report_invalid_set(
            poster,
            poll_url,
            &authorization,
            &jti,
            "access_denied",
            "The SET event type is not authorized for this stream",
        )
        .await?;
        if !repository
            .mark_polled(peer.as_str(), &established.stream_id, now)
            .await
            .map_err(|_| SetupError::Storage)?
        {
            return Err(SetupError::Peer);
        }
        return Ok(false);
    }
    ssf_receiver::apply_verified_event(endpoints, tenant, &event, now)
        .await
        .map_err(|_| SetupError::Event)?;
    acknowledge_polled_set(poster, poll_url, &authorization, &jti).await?;
    if !repository
        .mark_polled(peer.as_str(), &established.stream_id, now)
        .await
        .map_err(|_| SetupError::Storage)?
    {
        return Err(SetupError::Peer);
    }
    Ok(true)
}

async fn mark_poll_outcome(
    repository: &asterius_store_pg::PgSsfUpstreamStreams,
    peer: &ClientId,
    stream_id: &str,
    now: OffsetDateTime,
) -> Result<bool, SetupError> {
    if repository
        .mark_polled(peer.as_str(), stream_id, now)
        .await
        .map_err(|_| SetupError::Storage)?
    {
        Ok(false)
    } else {
        Err(SetupError::Peer)
    }
}

async fn acknowledge_polled_set(
    poster: &HttpsPoster,
    poll_url: &str,
    authorization: &str,
    jti: &str,
) -> Result<(), SetupError> {
    let acknowledgement = serde_json::to_vec(&json!({
        "maxEvents": 0,
        "returnImmediately": true,
        "ack": [jti]
    }))
    .map_err(|_| SetupError::Response)?;
    let response = poster
        .post_with_response(
            poll_url,
            PostRequest::of("application/json")
                .accepting("application/json")
                .authorized_by(Some(authorization)),
            &acknowledgement,
        )
        .await
        .map_err(|_| SetupError::Transport)?;
    if parse_polled_set(&response)?.is_some() {
        return Err(SetupError::Response);
    }
    Ok(())
}

/// Only deterministic SET validation failures are reported. A missing key,
/// unavailable metadata, or changed peer registration can recover on retry.
fn invalid_set_error(error: ssf_receiver::ReceiverError) -> Option<(&'static str, &'static str)> {
    match error {
        ssf_receiver::ReceiverError::Token => Some((
            "authentication_failed",
            "The SET could not be authenticated",
        )),
        ssf_receiver::ReceiverError::Profile
        | ssf_receiver::ReceiverError::Subject
        | ssf_receiver::ReceiverError::UnsupportedEvent => {
            Some(("invalid_request", "The SET profile is invalid"))
        }
        ssf_receiver::ReceiverError::TooOld => Some((
            "invalid_request",
            "The SET exceeds this receiver's local polling age limit",
        )),
        ssf_receiver::ReceiverError::Keys
        | ssf_receiver::ReceiverError::Metadata
        | ssf_receiver::ReceiverError::Peer => None,
    }
}

/// RFC 8936 §2.4.2 acknowledge-only request with `setErrs`, never `ack`.
/// The key came from one bounded poll response, and descriptions are constants
/// so no token content, claim, or upstream text is reflected back.
async fn report_invalid_set(
    poster: &HttpsPoster,
    poll_url: &str,
    authorization: &str,
    jti: &str,
    code: &'static str,
    description: &'static str,
) -> Result<(), SetupError> {
    let mut errors = serde_json::Map::new();
    errors.insert(
        jti.to_owned(),
        json!({"err": code, "description": description}),
    );
    let request = serde_json::to_vec(&json!({
        "maxEvents": 0,
        "returnImmediately": true,
        "setErrs": errors
    }))
    .map_err(|_| SetupError::Response)?;
    let response = poster
        .post_with_response(
            poll_url,
            PostRequest::of("application/json")
                .accepting("application/json")
                .with_content_language("en-US")
                .authorized_by(Some(authorization)),
            &request,
        )
        .await
        .map_err(|_| SetupError::Transport)?;
    if parse_polled_set(&response)?.is_some() {
        return Err(SetupError::Response);
    }
    Ok(())
}

fn parse_polled_set(response: &PostResponse) -> Result<Option<(String, String)>, SetupError> {
    if response.status != 200
        || response.truncated
        || !json_content_type(response.content_type.as_deref())
    {
        return Err(SetupError::Response);
    }
    let value: Value = serde_json::from_slice(&response.body).map_err(|_| SetupError::Response)?;
    let object = value.as_object().ok_or(SetupError::Response)?;
    let sets = object
        .get("sets")
        .and_then(Value::as_object)
        .ok_or(SetupError::Response)?;
    if sets.len() > 1
        || object
            .get("moreAvailable")
            .is_some_and(|more| !more.is_boolean())
    {
        return Err(SetupError::Response);
    }
    let Some((jti, token)) = sets.iter().next() else {
        return Ok(None);
    };
    let token = token.as_str().ok_or(SetupError::Response)?;
    if jti.is_empty()
        || jti.len() > 255
        || jti.chars().any(char::is_control)
        || token.is_empty()
        || token.len() > ssf_receiver::MAX_TOKEN_BYTES
    {
        return Err(SetupError::Response);
    }
    Ok(Some((jti.clone(), token.to_owned())))
}

/// Read-only poll setup validation for a reviewable architecture plan. No
/// credential is read and no remote create/verification request is performed.
pub async fn preview_poll_stream(endpoints: &ClientEndpoints, tenant: &Tenant, config: &SsfUpstreamPeerConfig)
    -> Result<serde_json::Value, SetupError> {
    let peer = ClientId::new(config.issuer.as_str());
    let (issuer, _jwks, scopes, metadata) = ssf_receiver::configured_peer(endpoints, tenant, &peer).await.map_err(|_| SetupError::Peer)?;
    if issuer != config.issuer || !metadata.supports_poll || !metadata.subject_policy_allowed(config.allow_all_subjects) {
        return Err(SetupError::Peer);
    }
    same_origin_management_endpoint(&metadata.configuration_endpoint, &issuer)?;
    same_origin_management_endpoint(&metadata.status_endpoint, &issuer)?;
    Ok(serde_json::json!({"peer_client_id": peer.as_str(), "issuer": issuer.as_str(),
        "jwks_uri": metadata.jwks_uri, "configuration_endpoint": metadata.configuration_endpoint,
        "status_endpoint": metadata.status_endpoint, "delivery_method": stream::DELIVERY_POLL,
        "expected_audience": expected_audience(config, tenant), "allow_all_subjects": config.allow_all_subjects,
        "account_disabled_events": scopes.contains(ssf_receiver::DISABLE_ACCOUNT_SCOPE)}))
}

/// Create one poll stream using a separate, operator-provided OAuth bearer
/// file. The token is read only after the active registered peer and its
/// metadata have been checked, then sent only to metadata-pinned configuration
/// and status endpoints through the guarded HTTPS transport. It is never
/// stored, logged or included in an error.
///
/// The durable intent blocks a second POST after a crash. A retry reads the
/// authenticated transmitter list and may adopt one exact match; zero or
/// multiple matches require operator review and never trigger another POST.
pub async fn create_poll_stream(
    endpoints: &ClientEndpoints,
    tenant: &Tenant,
    config: &SsfUpstreamPeerConfig,
    poster: &HttpsPoster,
    now: OffsetDateTime,
) -> Result<asterius_store_pg::UpstreamStream, SetupError> {
    create_poll_stream_owned(endpoints, tenant, config, poster, now, None).await
}
/// Architecture-origin setup uses the same guarded remote exchange and records
/// its ownership before the first POST, so another caller cannot adopt it.
pub async fn create_poll_stream_for_flow(endpoints: &ClientEndpoints, tenant: &Tenant, config: &SsfUpstreamPeerConfig, poster: &HttpsPoster, step: &asterius_store_pg::FlowApplyStep<'_>) -> Result<asterius_store_pg::UpstreamStream, SetupError> {
    create_poll_stream_owned(endpoints, tenant, config, poster, step.now, Some(step)).await
}
// Keep discovery, durable intent, authenticated reconciliation and POST order
// visible together; either caller must never repeat an uncertain create.
#[allow(clippy::too_many_lines)]
async fn create_poll_stream_owned(endpoints: &ClientEndpoints, tenant: &Tenant, config: &SsfUpstreamPeerConfig, poster: &HttpsPoster, now: OffsetDateTime, owner: Option<&asterius_store_pg::FlowApplyStep<'_>>) -> Result<asterius_store_pg::UpstreamStream, SetupError> {
    let peer = ClientId::new(config.issuer.as_str());
    let (issuer, _jwks, scopes, metadata) = ssf_receiver::configured_peer(endpoints, tenant, &peer)
        .await
        .map_err(|_| SetupError::Peer)?;
    if issuer != config.issuer
        || !metadata.supports_poll
        || !metadata.subject_policy_allowed(config.allow_all_subjects)
    {
        return Err(SetupError::Peer);
    }
    same_origin_management_endpoint(&metadata.configuration_endpoint, &issuer)?;
    same_origin_management_endpoint(&metadata.status_endpoint, &issuer)?;
    let repository = endpoints
        .store
        .scope(tenant.id.clone())
        .ssf_upstream_streams();
    if let Some(existing) = repository.find(peer.as_str()).await.map_err(|_| SetupError::Storage)? {
        if let Some(owner) = owner {
            if repository.flow_origin(peer.as_str()).await.map_err(|_| SetupError::Storage)? == Some((owner.flow,owner.node.to_owned())) {
                return Ok(existing);
            }
        }
        return Err(SetupError::AlreadyConfigured);
    }
    let token = read_bearer_file(&config.bearer_token_file)?;
    let authorization = Zeroizing::new(format!("Bearer {}", token.as_str()));
    let mut events = vec![
        caep::SESSION_REVOKED.to_owned(),
        caep::CREDENTIAL_CHANGE.to_owned(),
    ];
    if scopes.contains(ssf_receiver::DISABLE_ACCOUNT_SCOPE) {
        events.push(caep::ACCOUNT_DISABLED.to_owned());
    }
    let audience = expected_audience(config, tenant);
    let intent = asterius_store_pg::UpstreamSetupIntent {
        peer_client_id: peer.as_str().to_owned(),
        issuer: issuer.as_str().to_owned(),
        jwks_uri: metadata.jwks_uri.clone(),
        configuration_endpoint: metadata.configuration_endpoint.clone(),
        status_endpoint: metadata.status_endpoint.clone(),
        audience: audience.clone(),
        events_requested: events.clone(),
        delivery_method: stream::DELIVERY_POLL.to_owned(),
        started_at: now,
    };
    let newly_reserved = match owner {
        Some(owner) => repository.begin_setup_for_flow(&intent,owner).await,
        None => repository.begin_setup(&intent).await,
    }.map_err(|_| SetupError::Storage)?;
    let intent = if newly_reserved {
        intent
    } else {
        let saved = repository
            .pending_setup(peer.as_str())
            .await
            .map_err(|_| SetupError::Storage)?;
        let Some(saved) = saved else {
            return Err(SetupError::AlreadyConfigured);
        };
        if saved.peer_client_id != intent.peer_client_id
            || saved.issuer != intent.issuer
            || saved.jwks_uri != intent.jwks_uri
            || saved.configuration_endpoint != intent.configuration_endpoint
            || saved.status_endpoint != intent.status_endpoint
            || saved.audience != intent.audience
            || saved.events_requested != intent.events_requested
            || saved.delivery_method != intent.delivery_method
        {
            return Err(SetupError::PendingReview);
        }
        saved
    };
    let listed = list_streams(poster, &metadata.configuration_endpoint, &authorization).await?;
    if let Some(established) = reconcile_listed(
        &listed,
        &metadata,
        config.allow_all_subjects,
        &issuer,
        &audience,
        &events,
        now,
    )? {
        same_origin_management_endpoint(
            established
                .poll_endpoint
                .as_deref()
                .ok_or(SetupError::Response)?,
            &issuer,
        )?;
        verify_and_finish(
            poster,
            &authorization,
            &metadata.status_endpoint,
            &repository,
            &intent,
            established,
        )
        .await
    } else if newly_reserved && listed.is_empty() {
        let body = poll_create_body(&events)?;
        let created = poster
            .post_with_response(
                &metadata.configuration_endpoint,
                PostRequest::of("application/json")
                    .accepting("application/json")
                    .authorized_by(Some(&authorization)),
                &body,
            )
            .await
            .map_err(|_| SetupError::Transport)?;
        if created.truncated {
            return Err(SetupError::Response);
        }
        let established = ssf_receiver::validated_upstream_stream(
            &metadata,
            config.allow_all_subjects,
            &issuer,
            &audience,
            &events,
            stream::DELIVERY_POLL,
            None,
            created.status,
            201,
            created.content_type.as_deref(),
            &created.body,
            now,
        )
        .map_err(|_| SetupError::Response)?;
        same_origin_management_endpoint(
            established
                .poll_endpoint
                .as_deref()
                .ok_or(SetupError::Response)?,
            &issuer,
        )?;
        verify_and_finish(
            poster,
            &authorization,
            &metadata.status_endpoint,
            &repository,
            &intent,
            established,
        )
        .await
    } else {
        Err(SetupError::PendingReview)
    }
}

fn poll_create_body(events: &[String]) -> Result<Vec<u8>, SetupError> {
    // SSF 1.0 Final §8.1.1.1: aud is transmitter-supplied. The response is
    // checked against the operator's expected-audience pin before adoption.
    serde_json::to_vec(&json!({
        "events_requested": events,
        "delivery": { "method": stream::DELIVERY_POLL },
    }))
    .map_err(|_| SetupError::Response)
}

async fn list_streams(
    poster: &HttpsPoster,
    pinned_url: &str,
    authorization: &str,
) -> Result<Vec<Value>, SetupError> {
    // SSF 1.0 §8.1.1.2: GET without stream_id returns every stream available
    // to this authenticated receiver, including an empty array.
    let response = poster
        .get_with_response(pinned_url, authorization)
        .await
        .map_err(|_| SetupError::Transport)?;
    if response.status != 200
        || response.truncated
        || !json_content_type(response.content_type.as_deref())
    {
        return Err(SetupError::Response);
    }
    let value: Value = serde_json::from_slice(&response.body).map_err(|_| SetupError::Response)?;
    value.as_array().cloned().ok_or(SetupError::Response)
}

/// A durable stream identity disambiguates readback even when this credential
/// manages other streams. Malformed or duplicate identities cannot prove that
/// the recorded stream is absent, so deletion must retain its local intent.
fn recorded_stream_in_list<'a>(
    listed: &'a [Value],
    stream_id: &str,
) -> Result<Option<&'a Value>, SetupError> {
    let mut identities = std::collections::HashSet::new();
    let mut selected = None;
    for value in listed {
        let identity = value
            .get("stream_id")
            .and_then(Value::as_str)
            .filter(|identity| !identity.is_empty())
            .ok_or(SetupError::PendingReview)?;
        if !identities.insert(identity) {
            return Err(SetupError::PendingReview);
        }
        if identity == stream_id {
            selected = Some(value);
        }
    }
    Ok(selected)
}

fn reconcile_listed(
    listed: &[Value],
    metadata: &ssf_receiver::UpstreamMetadata,
    allow_all_subjects: bool,
    issuer: &asterius_domain::Issuer,
    audience: &str,
    events: &[String],
    now: OffsetDateTime,
) -> Result<Option<asterius_store_pg::UpstreamStream>, SetupError> {
    // SSF permits multiple streams, but this receiver records one per peer.
    // A list with more than one cannot identify which remote side effect this
    // intent produced, even if one item matches our requested configuration.
    let [value] = listed else {
        return if listed.is_empty() {
            Ok(None)
        } else {
            Err(SetupError::PendingReview)
        };
    };
    let document = serde_json::to_vec(value).map_err(|_| SetupError::Response)?;
    ssf_receiver::validated_upstream_stream(
        metadata,
        allow_all_subjects,
        issuer,
        audience,
        events,
        stream::DELIVERY_POLL,
        None,
        200,
        200,
        Some("application/json"),
        &document,
        now,
    )
    .map(Some)
    .map_err(|_| SetupError::PendingReview)
}

async fn verify_and_finish(
    poster: &HttpsPoster,
    authorization: &str,
    status_endpoint: &str,
    repository: &asterius_store_pg::PgSsfUpstreamStreams,
    intent: &asterius_store_pg::UpstreamSetupIntent,
    established: asterius_store_pg::UpstreamStream,
) -> Result<asterius_store_pg::UpstreamStream, SetupError> {
    let url = status_url(status_endpoint, &established.stream_id)?;
    let status = poster
        .get_with_response(&url, authorization)
        .await
        .map_err(|_| SetupError::Transport)?;
    validate_status(&status, &established.stream_id)?;
    match repository.finish_setup(intent, &established).await {
        Ok(true) => Ok(established),
        Ok(false) => Err(SetupError::PendingReview),
        Err(_) => Err(SetupError::Storage),
    }
}

fn json_content_type(value: Option<&str>) -> bool {
    value.is_some_and(|value| {
        value
            .split(';')
            .next()
            .is_some_and(|media| media.trim().eq_ignore_ascii_case("application/json"))
    })
}

fn read_bearer_file(path: &std::path::Path) -> Result<Zeroizing<String>, SetupError> {
    let file = std::fs::File::open(path).map_err(|_| SetupError::Credential)?;
    if !file
        .metadata()
        .map_err(|_| SetupError::Credential)?
        .is_file()
    {
        return Err(SetupError::Credential);
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(8193)
        .read_to_end(&mut bytes)
        .map_err(|_| SetupError::Credential)?;
    if bytes.len() > 8192 {
        return Err(SetupError::Credential);
    }
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
    }
    if bytes.is_empty()
        || !bytes.iter().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'+' | b'/' | b'=')
        })
    {
        return Err(SetupError::Credential);
    }
    String::from_utf8(std::mem::take(&mut *bytes))
        .map(Zeroizing::new)
        .map_err(|error| {
            let _discarded = Zeroizing::new(error.into_bytes());
            SetupError::Credential
        })
}

fn same_origin_management_endpoint(
    url: &str,
    issuer: &asterius_domain::Issuer,
) -> Result<(), SetupError> {
    let endpoint = url::Url::parse(url).map_err(|_| SetupError::Peer)?;
    let origin = url::Url::parse(issuer.as_str()).map_err(|_| SetupError::Peer)?;
    if endpoint.origin() != origin.origin()
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
    {
        return Err(SetupError::Peer);
    }
    Ok(())
}

fn status_url(pinned: &str, stream_id: &str) -> Result<String, SetupError> {
    let mut url = url::Url::parse(pinned).map_err(|_| SetupError::Response)?;
    // Only this query member is derived locally. Scheme, authority, and path
    // stay exactly as advertised in the validated metadata.
    if url.query().is_some() || url.fragment().is_some() {
        return Err(SetupError::Response);
    }
    url.query_pairs_mut().append_pair("stream_id", stream_id);
    Ok(url.into())
}

fn validate_status(response: &PostResponse, stream_id: &str) -> Result<(), SetupError> {
    if response.status != 200
        || response.truncated
        || !json_content_type(response.content_type.as_deref())
    {
        return Err(SetupError::Response);
    }
    let value: Value = serde_json::from_slice(&response.body).map_err(|_| SetupError::Response)?;
    if value.get("stream_id").and_then(Value::as_str) != Some(stream_id)
        || !matches!(
            value.get("status").and_then(Value::as_str),
            Some("enabled" | "paused" | "disabled")
        )
    {
        return Err(SetupError::Response);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recorded_readback_selects_exact_stream_among_other_streams() {
        let listed = vec![
            json!({"stream_id": "other"}),
            json!({"stream_id": "recorded", "aud": "receiver"}),
        ];
        let selected = recorded_stream_in_list(&listed, "recorded")
            .expect("unambiguous authenticated list")
            .expect("recorded stream exists");
        assert_eq!(selected["aud"], "receiver");
        assert_eq!(recorded_stream_in_list(&listed, "removed"), Ok(None));
    }

    #[test]
    fn recorded_readback_refuses_malformed_or_duplicate_identities() {
        for listed in [
            vec![json!({"stream_id": "other"}), json!({})],
            vec![json!({"stream_id": ""})],
            vec![json!({"stream_id": 42})],
            vec![
                json!({"stream_id": "recorded"}),
                json!({"stream_id": "recorded"}),
            ],
            vec![json!({"stream_id": "other"}), json!({"stream_id": "other"})],
        ] {
            assert_eq!(
                recorded_stream_in_list(&listed, "recorded"),
                Err(SetupError::PendingReview)
            );
        }
        assert_eq!(recorded_stream_in_list(&[], "recorded"), Ok(None));
    }

    #[test]
    fn poll_create_requests_only_receiver_supplied_members() {
        let body = poll_create_body(&[caep::SESSION_REVOKED.to_owned()]).expect("JSON body");
        let value: Value = serde_json::from_slice(&body).expect("JSON object");
        assert_eq!(value.as_object().expect("object").len(), 2);
        assert!(value.get("aud").is_none());
        assert_eq!(value["delivery"]["method"], stream::DELIVERY_POLL);
        assert_eq!(value["events_requested"], json!([caep::SESSION_REVOKED]));
    }
}
