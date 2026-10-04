//! Prepared `TokenReview` v1 candidate, isolated pending delivery review.
//! Request parsing never authenticates a caller, token or user.
use crate::{Actor, ClientId, DomainError, Secret, Tenant, TenantId};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::BTreeSet;

pub const VERSION: &str = "authentication.k8s.io/v1";
pub const KIND: &str = "TokenReview";
pub const MAX_REQUEST_BYTES: usize = 65_536;
pub const MAX_TOKEN_BYTES: usize = 16_384;
pub const MAX_AUDIENCES: usize = 16;
pub const MAX_AUDIENCE_BYTES: usize = 2048;
pub const MAX_RELEASED_GROUPS: usize = 100;
pub const REVIEW_SCOPE: &str = "admin.kubernetes_reviews:read";

#[derive(Debug, Clone, Serialize)]
pub struct OnlineProfile {
    pub reviewer_client_id: String,
    pub revision: uuid::Uuid,
    pub enabled: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileChange {
    pub reviewer_client_id: String,
    pub expected_revision: Option<uuid::Uuid>,
    #[serde(default)]
    pub enabled: bool,
}

impl ProfileChange {
    pub fn validate(&self) -> Result<(), DomainError> {
        if !bounded(&self.reviewer_client_id, 2048) {
            return Err(invalid());
        }
        Ok(())
    }
}

/// The composition root performs signature validation and primary-state review.
/// Administrative configuration is distinct from service-only authentication.
#[async_trait::async_trait]
pub trait KubernetesOnline: std::fmt::Debug + Send + Sync {
    async fn profile(
        &self,
        tenant: &TenantId,
        client: &ClientId,
    ) -> Result<Option<OnlineProfile>, DomainError>;
    async fn replace_profile(
        &self,
        tenant: &TenantId,
        client: &ClientId,
        actor: &Actor,
        change: &ProfileChange,
    ) -> Result<OnlineProfile, DomainError>;
    async fn review(
        &self,
        tenant: &Tenant,
        reviewer: &ClientId,
        client: &ClientId,
        request: &TokenReviewRequest,
    ) -> Result<TokenReviewResponse, DomainError>;
}

/// A field that is absent stays None; a present null must satisfy T itself.
/// This avoids treating caller status:null as an absent status.
fn present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyUser {}

/// Kubernetes1.35's zero-value struct emits only {"user":{}}. This is ignored,
/// not input authority. Any authenticated/user attributes/audiences/error fail.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyStatus {
    #[serde(rename = "user")]
    _user: EmptyUser,
}

/// The zero `ObjectMeta` serialization has creationTimestamp:null. No arbitrary
/// annotation, UID, namespace, owner reference or caller identity is accepted.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyMetadata {
    #[serde(default, rename = "creationTimestamp", deserialize_with = "present")]
    _creation_timestamp: Option<()>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    token: Secret<String>,
    audiences: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireReview {
    #[serde(rename = "apiVersion")]
    api_version: String,
    kind: String,
    spec: Spec,
    #[serde(default, rename = "metadata", deserialize_with = "present")]
    _metadata: Option<EmptyMetadata>,
    #[serde(default, rename = "status", deserialize_with = "present")]
    _status: Option<EmptyStatus>,
}

/// No Serialize implementation: the request bearer credential cannot be echoed
/// by using this type as a `TokenReview` response. Secret zeroizes on drop.
#[derive(Debug)]
pub struct TokenReviewRequest {
    token: Secret<String>,
    audiences: Vec<String>,
}
impl TokenReviewRequest {
    // fuzz-target: kubernetes_token_review
    pub fn parse(bytes: &[u8]) -> Result<Self, DomainError> {
        if bytes.len() > MAX_REQUEST_BYTES {
            return Err(invalid());
        }
        let wire: WireReview = serde_json::from_slice(bytes).map_err(|_| invalid())?;
        // Expose only to structural validation; no log/error contains the value.
        let token = wire.spec.token.expose();
        let unique: BTreeSet<_> = wire.spec.audiences.iter().collect();
        if wire.api_version != VERSION
            || wire.kind != KIND
            || token.is_empty()
            || token.len() > MAX_TOKEN_BYTES
            || token.bytes().any(|byte| !byte.is_ascii_graphic())
            || wire.spec.audiences.is_empty()
            || wire.spec.audiences.len() > MAX_AUDIENCES
            || unique.len() != wire.spec.audiences.len()
            || wire
                .spec
                .audiences
                .iter()
                .any(|value| !bounded(value, MAX_AUDIENCE_BYTES))
        {
            return Err(invalid());
        }
        Ok(Self {
            token: wire.spec.token,
            audiences: wire.spec.audiences,
        })
    }
    #[must_use]
    pub fn audiences(&self) -> &[String] {
        &self.audiences
    }
    /// Only the route selected by authenticated cluster transport supplies this
    /// audience. An audience found in the token/request never selects a tenant.
    pub fn require_route_audience(&self, configured: &str) -> Result<(), DomainError> {
        if !bounded(configured, MAX_AUDIENCE_BYTES)
            || !self.audiences.iter().any(|audience| audience == configured)
        {
            return Err(invalid());
        }
        Ok(())
    }
    /// Exposed only for the verifier/independently authenticated service hop.
    #[must_use]
    pub fn credential(&self) -> &Secret<String> {
        &self.token
    }
}

fn bounded(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}
fn invalid() -> DomainError {
    DomainError::invalid("token_review", "invalid bounded TokenReview v1 request")
}

/// Output contains only server-released stable profile identities, no arbitrary
/// extras, email, incoming status or request spec/token.
#[derive(Debug, Serialize)]
struct User {
    username: String,
    groups: Vec<String>,
}
#[derive(Debug, Serialize)]
struct Status {
    authenticated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    user: Option<User>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    audiences: Vec<String>,
}
#[derive(Debug, Serialize)]
pub struct TokenReviewResponse {
    #[serde(rename = "apiVersion")]
    api_version: &'static str,
    kind: &'static str,
    status: Status,
}
impl TokenReviewResponse {
    #[must_use]
    pub const fn denied() -> Self {
        Self {
            api_version: VERSION,
            kind: KIND,
            status: Status {
                authenticated: false,
                user: None,
                audiences: Vec::new(),
            },
        }
    }
    /// Inputs must come from signed-token/exact-binding/live-state validation.
    /// This constructor alone does not establish that upstream authority.
    pub fn released(
        request: &TokenReviewRequest,
        configured_audience: &str,
        username: String,
        groups: Vec<String>,
    ) -> Result<Self, DomainError> {
        request.require_route_audience(configured_audience)?;
        let distinct: BTreeSet<_> = groups.iter().collect();
        if !bounded(&username, 2048)
            || groups.len() > MAX_RELEASED_GROUPS
            || distinct.len() != groups.len()
            || groups.iter().any(|group| !bounded(group, 2048))
        {
            return Err(invalid());
        }
        Ok(Self {
            api_version: VERSION,
            kind: KIND,
            status: Status {
                authenticated: true,
                user: Some(User { username, groups }),
                audiences: vec![configured_audience.to_owned()],
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn request() -> serde_json::Value {
        json!({"apiVersion":VERSION,"kind":KIND,"spec":{"token":"controlled-not-a-credential","audiences":["human-client","other"]}})
    }
    fn parsed(value: &serde_json::Value) -> Result<TokenReviewRequest, DomainError> {
        TokenReviewRequest::parse(&serde_json::to_vec(value).expect("controlled JSON"))
    }
    #[test]
    fn online_review_accepts_only_zero_value_kubernetes_wire_status() {
        let mut value = request();
        value["metadata"] = json!({"creationTimestamp":null});
        value["status"] = json!({"user":{}});
        assert!(parsed(&value).is_ok());
        for status in [
            json!(null),
            json!({}),
            json!({"authenticated":false}),
            json!({"authenticated":true,"user":{}}),
            json!({"user":{"username":"injected"}}),
            json!({"user":{},"audiences":["human-client"]}),
            json!({"user":{},"error":"injected"}),
        ] {
            value["status"] = status;
            assert!(parsed(&value).is_err());
        }
    }
    #[test]
    fn online_review_rejects_version_kind_audience_and_metadata_ambiguity() {
        for (field, value) in [
            ("apiVersion", json!("authentication.k8s.io/v1beta1")),
            ("kind", json!("SubjectAccessReview")),
            ("metadata", json!({"uid":"caller"})),
            ("unknown", json!(true)),
        ] {
            let mut wire = request();
            wire[field] = value;
            assert!(parsed(&wire).is_err());
        }
        for audiences in [
            json!([]),
            json!([""]),
            json!(["a", "a"]),
            json!(["a\nb"]),
            json!(vec!["a"; MAX_AUDIENCES + 1]),
            json!(["a".repeat(MAX_AUDIENCE_BYTES + 1)]),
        ] {
            let mut wire = request();
            wire["spec"]["audiences"] = audiences;
            assert!(parsed(&wire).is_err());
        }
        assert!(TokenReviewRequest::parse(br#"{"apiVersion":"authentication.k8s.io/v1","kind":"TokenReview","spec":{"token":"a","token":"b","audiences":["a"]}}"#).is_err());
    }
    #[test]
    fn online_review_bounds_and_redacts_bearer_credential() {
        let parsed = parsed(&request()).expect("controlled request");
        assert!(!format!("{parsed:?}").contains("controlled-not-a-credential"));
        assert!(TokenReviewRequest::parse(&vec![b' '; MAX_REQUEST_BYTES + 1]).is_err());
        let mut wire = request();
        wire["spec"]["token"] = json!("x".repeat(MAX_TOKEN_BYTES + 1));
        assert!(self::parsed(&wire).is_err());
        wire["spec"]["token"] = json!("contains whitespace");
        assert!(self::parsed(&wire).is_err());
    }
    #[test]
    fn online_review_response_never_echoes_token_status_or_other_audiences() {
        let request = parsed(&request()).expect("controlled request");
        assert!(request.require_route_audience("wrong-cluster").is_err());
        let response = TokenReviewResponse::released(
            &request,
            "human-client",
            "asterius:tenant:cluster:subject".into(),
            vec![],
        )
        .expect("released identity");
        let value = serde_json::to_value(response).expect("response JSON");
        assert!(value.get("spec").is_none());
        assert_eq!(value["status"]["audiences"], json!(["human-client"]));
        assert!(
            !serde_json::to_string(&value)
                .expect("JSON")
                .contains("controlled-not-a-credential")
        );
        let denied = serde_json::to_value(TokenReviewResponse::denied()).expect("JSON");
        assert_eq!(denied["status"], json!({"authenticated":false}));
    }
}
