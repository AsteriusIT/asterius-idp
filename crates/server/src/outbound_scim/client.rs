//! OAuth client credentials and DPoP, through the one guarded HTTPS connection path.

use super::proof::proof;
use crate::outbound::{HttpsPoster, PostRequest, PostResponse};
use asterius_domain::outbound_scim::{
    Connector, CredentialBinding, FailureCode, LifecycleKind, OutboundScimAdministration,
    OutboundScimCredentials, OutboundScimJobs, OutboundScimLifecycle, PreparedDelivery,
    PreparedLifecycle, canonical_issuer, parse_peer_token,
};
use asterius_domain::{Secret, SigningAlgorithm};
use asterius_jose::SigningKey;
use hyper::Method;
use std::sync::Arc;
use time::{Duration, OffsetDateTime};
use tokio::sync::Mutex;
use zeroize::Zeroizing;

#[derive(Clone, Copy)]
pub(super) struct DeliveryAdmission<'a> {
    pub jobs: &'a dyn OutboundScimJobs,
    pub prepared: &'a PreparedDelivery,
}
impl DeliveryAdmission<'_> {
    async fn check(&self, creating: bool) -> Result<(), FailureCode> {
        self.jobs
            .admit(
                &self.prepared.connector.tenant,
                self.prepared.assignment.id,
                &self.prepared.fence,
                creating,
            )
            .await
            .map_err(|_| FailureCode::LeaseSuperseded)
    }
}

#[derive(Clone, Copy)]
pub(super) enum RequestAdmission<'a> {
    Delivery(DeliveryAdmission<'a>),
    Lifecycle {
        jobs: &'a dyn OutboundScimLifecycle,
        prepared: &'a PreparedLifecycle,
    },
    Preview {
        catalogue: &'a dyn OutboundScimAdministration,
        connector: &'a Connector,
    },
}
impl RequestAdmission<'_> {
    async fn check(
        &self,
        creating: bool,
        mutating: bool,
        deleting: bool,
    ) -> Result<(), FailureCode> {
        match self {
            Self::Lifecycle { jobs, prepared } => jobs
                .admit(
                    &prepared.delivery.connector.tenant,
                    prepared.request.id,
                    &prepared.delivery.fence,
                    mutating,
                    deleting,
                )
                .await
                .map_err(|_| FailureCode::LeaseSuperseded),
            Self::Delivery(delivery) => delivery.check(creating).await,
            Self::Preview {
                catalogue,
                connector,
            } => {
                let current = catalogue
                    .preview_connector(&connector.tenant, connector.id, connector.revision)
                    .await
                    .map_err(|_| FailureCode::LeaseSuperseded)?;
                if current.credential != connector.credential {
                    return Err(FailureCode::CredentialBindingMismatch);
                }
                Ok(())
            }
        }
    }

    fn credential(&self) -> &CredentialBinding {
        match self {
            Self::Delivery(delivery) => &delivery.prepared.connector.credential,
            Self::Lifecycle { prepared, .. } => &prepared.delivery.connector.credential,
            Self::Preview { connector, .. } => &connector.credential,
        }
    }

    fn permits(&self, method: &Method) -> bool {
        match self {
            Self::Preview { .. } => *method == Method::GET,
            Self::Lifecycle { prepared, .. } => {
                *method == Method::GET
                    || match prepared.request.kind {
                        LifecycleKind::Delete => *method == Method::DELETE,
                        LifecycleKind::Archive | LifecycleKind::Recreate => *method == Method::PUT,
                    }
            }
            Self::Delivery(_) => matches!(*method, Method::GET | Method::POST | Method::PUT),
        }
    }
}

pub(super) struct ScimRequest<'a> {
    pub method: Method,
    pub path: &'a str,
    pub query: Option<(&'a str, &'a str)>,
    pub etag: Option<&'a str>,
    pub body: &'a [u8],
    pub admission: RequestAdmission<'a>,
}

const SCOPES: &str = "admin.scim:read admin.scim:write";

struct Token {
    value: Secret<String>,
    expires_at: OffsetDateTime,
}
struct Session {
    token: Option<Token>,
    issuer_nonce: Option<String>,
    resource_nonce: Option<String>,
}
struct BoundSession {
    binding: CredentialBinding,
    key: SigningKey,
    session: Mutex<Session>,
}

pub struct OutboundScimClient {
    poster: Arc<HttpsPoster>,
    credentials: Arc<dyn OutboundScimCredentials>,
    sessions: Mutex<Vec<Arc<BoundSession>>>,
}
impl std::fmt::Debug for OutboundScimClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OutboundScimClient")
            .finish_non_exhaustive()
    }
}

impl OutboundScimClient {
    #[must_use]
    pub fn new(poster: Arc<HttpsPoster>, credentials: Arc<dyn OutboundScimCredentials>) -> Self {
        Self {
            poster,
            credentials,
            sessions: Mutex::new(Vec::new()),
        }
    }

    async fn session(&self, binding: &CredentialBinding) -> Result<Arc<BoundSession>, FailureCode> {
        let issuer = canonical_issuer(&binding.target_issuer)
            .map_err(|_| FailureCode::CredentialBindingMismatch)?;
        if binding.target_admin_resource != format!("{}/admin/api/v1", binding.target_issuer)
            || binding.scim_origin != issuer.origin().ascii_serialization()
        {
            return Err(FailureCode::CredentialBindingMismatch);
        }
        let mut entries = self.sessions.lock().await;
        if let Some(session) = entries.iter().find(|session| session.binding == *binding) {
            return Ok(Arc::clone(session));
        }
        if entries.len() >= 100 {
            return Err(FailureCode::SnapshotBoundExceeded);
        }
        let session = Arc::new(BoundSession {
            binding: binding.clone(),
            key: SigningKey::generate(SigningAlgorithm::Es256)
                .map_err(|_| FailureCode::CredentialUnavailable)?,
            session: Mutex::new(Session {
                token: None,
                issuer_nonce: None,
                resource_nonce: None,
            }),
        });
        entries.push(Arc::clone(&session));
        Ok(session)
    }

    async fn token(
        &self,
        bound: &BoundSession,
        session: &mut Session,
        admission: &RequestAdmission<'_>,
    ) -> Result<(), FailureCode> {
        if session
            .token
            .as_ref()
            .is_some_and(|token| token.expires_at > OffsetDateTime::now_utc())
        {
            return Ok(());
        }
        let url = format!("{}/token", bound.binding.target_issuer);
        for attempt in 0..2 {
            // Every attempt mints a new client assertion and proof: the target
            // replay cache must never see a nonce retry reuse either jti.
            let assertion = self
                .credentials
                .assertion(&bound.binding)
                .await
                .map_err(|_| FailureCode::CredentialUnavailable)?;
            let proof = proof(
                &bound.key,
                "POST",
                &url,
                None,
                session.issuer_nonce.as_deref(),
            )?;
            let body = {
                let mut form = url::form_urlencoded::Serializer::new(String::new());
                form.append_pair("grant_type", "client_credentials")
                    .append_pair("client_id", bound.binding.target_client.as_str())
                    .append_pair(
                        "client_assertion_type",
                        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                    )
                    .append_pair("client_assertion", assertion.expose())
                    .append_pair("scope", SCOPES)
                    .append_pair("resource", &bound.binding.target_admin_resource);
                Zeroizing::new(form.finish())
            };
            admission.check(false, false, false).await?;
            let response = self
                .poster
                .authenticated_response(
                    &url,
                    Method::POST,
                    PostRequest::of("application/x-www-form-urlencoded")
                        .accepting("application/json")
                        .proved_by(proof.expose()),
                    body.as_bytes(),
                )
                .await
                .map_err(|_| FailureCode::TargetUnavailable)?;
            if let Some(nonce) = response.dpop_nonce {
                session.issuer_nonce = Some(nonce);
            }
            let bytes = Zeroizing::new(response.body);
            if (response.status == 400 || response.status == 401)
                && attempt == 0
                && session.issuer_nonce.is_some()
            {
                let error: serde_json::Value = serde_json::from_slice(&bytes)
                    .map_err(|_| FailureCode::AuthenticationRefused)?;
                if error.get("error").and_then(serde_json::Value::as_str) == Some("use_dpop_nonce")
                {
                    continue;
                }
            }
            if response.status >= 500 || response.status == 429 {
                return Err(FailureCode::TargetUnavailable);
            }
            if response.status != 200 || response.truncated {
                return Err(FailureCode::AuthenticationRefused);
            }
            let token = parse_peer_token(&bytes)?;
            let margin = (token.expires_in / 2).min(5);
            session.token = Some(Token {
                value: token.access_token,
                expires_at: OffsetDateTime::now_utc()
                    + Duration::seconds(i64::from(token.expires_in - margin)),
            });
            return Ok(());
        }
        Err(FailureCode::AuthenticationRefused)
    }

    /// Resource URLs are constructed internally from the configured issuer and
    /// canonical UUID/query parameters. The caller cannot supply another origin.
    pub(super) async fn request(
        &self,
        binding: &CredentialBinding,
        request: ScimRequest<'_>,
    ) -> Result<PostResponse, FailureCode> {
        let ScimRequest {
            method,
            path,
            query,
            etag,
            body,
            admission,
        } = request;
        if admission.credential() != binding || !admission.permits(&method) {
            return Err(FailureCode::CredentialBindingMismatch);
        }
        if !valid_path(path) {
            return Err(FailureCode::SourceProjectionInvalid);
        }
        let bound = self.session(binding).await?;
        let mut session = bound.session.lock().await;
        let mut url = url::Url::parse(&format!("{}/scim/v2/{path}", binding.target_admin_resource))
            .map_err(|_| FailureCode::CredentialBindingMismatch)?;
        if let Some((name, value)) = query {
            if name != "filter" || value.len() > 512 {
                return Err(FailureCode::SourceProjectionInvalid);
            }
            url.query_pairs_mut()
                .append_pair(name, value)
                .append_pair("count", "2");
        }
        for attempt in 0..2 {
            self.token(&bound, &mut session, &admission).await?;
            let token = &session
                .token
                .as_ref()
                .ok_or(FailureCode::AuthenticationRefused)?
                .value;
            let authorization = Zeroizing::new(format!("DPoP {}", token.expose()));
            let proof = proof(
                &bound.key,
                method.as_str(),
                url.as_str(),
                Some(token),
                session.resource_nonce.as_deref(),
            )?;
            admission
                .check(
                    method == Method::POST && matches!(path, "Users" | "Groups"),
                    method != Method::GET,
                    method == Method::DELETE,
                )
                .await?;
            let response = self
                .poster
                .authenticated_response(
                    url.as_str(),
                    method.clone(),
                    PostRequest::of("application/scim+json")
                        .accepting("application/scim+json")
                        .authorized_by(Some(&authorization))
                        .proved_by(proof.expose())
                        .matching(etag),
                    body,
                )
                .await
                .map_err(|_| FailureCode::TargetUnavailable)?;
            if let Some(nonce) = &response.dpop_nonce {
                session.resource_nonce = Some(nonce.clone());
            }
            if response.status == 401 && attempt == 0 {
                if response.dpop_nonce.is_none() {
                    session.token = None;
                }
                continue;
            }
            return Ok(response);
        }
        Err(FailureCode::AuthenticationRefused)
    }
}

fn valid_path(path: &str) -> bool {
    match path.split_once('/') {
        None => matches!(path, "Users" | "Groups" | "ServiceProviderConfig"),
        Some((kind, id)) => {
            matches!(kind, "Users" | "Groups")
                && asterius_domain::outbound_scim::canonical_uuid(id).is_ok()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn remote_path_cannot_leave_the_pinned_scim_resource_tree() {
        assert!(valid_path("Users"));
        assert!(valid_path("Groups/00000000-0000-0000-0000-000000000001"));
        for invalid in [
            "../Users",
            "Users/../Groups",
            "Users/https://foreign.example",
            "Users/00000000000000000000000000000001",
            "Users/00000000-0000-0000-0000-000000000001/credentials",
        ] {
            assert!(!valid_path(invalid));
        }
    }
}
