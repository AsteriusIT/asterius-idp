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
use serde_json::{Value, json};
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

/// Poll at most one SET from an established upstream stream, apply it through
/// the push receiver's atomic replay/lifecycle path, then acknowledge its
/// `jti` in a separate RFC 8936 request. A failure before acknowledgement
/// leaves the transmitter free to redeliver; the local replay record makes
/// such redelivery harmless. This operation is not yet scheduled by a worker.
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
    if issuer != config.issuer || !metadata.supports_poll {
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
    if established.issuer != issuer.as_str()
        || established.jwks_uri != metadata.jwks_uri
        || established.configuration_endpoint != metadata.configuration_endpoint
        || established.status_endpoint != metadata.status_endpoint
        || established.delivery_method != stream::DELIVERY_POLL
        || established.audience
            != format!("{}{}", tenant.issuer.as_str(), ssf_receiver::RECEIVER_PATH)
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
                .authorized_by(Some(&authorization)),
            &acknowledgement,
        )
        .await
        .map_err(|_| SetupError::Transport)?;
    if parse_polled_set(&response)?.is_some() {
        return Err(SetupError::Response);
    }
    if !repository
        .mark_polled(peer.as_str(), &established.stream_id, now)
        .await
        .map_err(|_| SetupError::Storage)?
    {
        return Err(SetupError::Peer);
    }
    Ok(true)
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
    let peer = ClientId::new(config.issuer.as_str());
    let (issuer, _jwks, scopes, metadata) = ssf_receiver::configured_peer(endpoints, tenant, &peer)
        .await
        .map_err(|_| SetupError::Peer)?;
    if issuer != config.issuer || !metadata.supports_poll {
        return Err(SetupError::Peer);
    }
    same_origin_management_endpoint(&metadata.configuration_endpoint, &issuer)?;
    same_origin_management_endpoint(&metadata.status_endpoint, &issuer)?;
    let repository = endpoints
        .store
        .scope(tenant.id.clone())
        .ssf_upstream_streams();
    if repository
        .find(peer.as_str())
        .await
        .map_err(|_| SetupError::Storage)?
        .is_some()
    {
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
    let audience = format!("{}{}", tenant.issuer.as_str(), ssf_receiver::RECEIVER_PATH);
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
    let newly_reserved = repository
        .begin_setup(&intent)
        .await
        .map_err(|_| SetupError::Storage)?;
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
    if let Some(established) =
        reconcile_listed(&listed, &metadata, &issuer, &audience, &events, now)?
    {
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
        let body = serde_json::to_vec(&json!({
        "aud": &audience,
        "events_requested": &events,
        "delivery": { "method": stream::DELIVERY_POLL },
        }))
        .map_err(|_| SetupError::Response)?;
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

fn reconcile_listed(
    listed: &[Value],
    metadata: &ssf_receiver::UpstreamMetadata,
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
