//! The same immutable ownership checks serve delivery and read-only previews.
use super::client::{OutboundScimClient, RequestAdmission, ScimRequest};
use super::worker::{collection, parsed, status};
use asterius_domain::outbound_scim::{
    CredentialBinding, FailureCode, Projection, RemoteDocument, ResourceKind, parse_document,
};
use hyper::Method;
use serde_json::{Value, json};
use uuid::Uuid;

pub(super) struct OwnerReader<'a> {
    pub client: &'a OutboundScimClient,
    pub credential: &'a CredentialBinding,
    pub kind: ResourceKind,
    pub projection: &'a Projection,
    pub admission: RequestAdmission<'a>,
}
impl OwnerReader<'_> {
    pub(super) async fn fetch(&self, id: Uuid) -> Result<RemoteDocument, FailureCode> {
        let path = format!("{}/{}", collection(self.kind), id);
        let response = self
            .client
            .request(
                self.credential,
                ScimRequest {
                    method: Method::GET,
                    path: &path,
                    query: None,
                    etag: None,
                    body: &[],
                    admission: self.admission,
                },
            )
            .await?;
        let remote = parsed(&response, self.projection)?;
        if remote.target != id {
            return Err(FailureCode::OwnershipMismatch);
        }
        Ok(remote)
    }

    /// Recover an uncertain POST by exact immutable alias, then GET only the
    /// canonical returned UUID. List Location/$ref values never influence URLs.
    pub(super) async fn locate(&self) -> Result<Option<RemoteDocument>, FailureCode> {
        let (attribute, alias) = match self.projection {
            Projection::User(user) => ("userName", &user.immutable_alias),
            Projection::Group(group) => ("displayName", &group.immutable_alias),
        };
        let literal =
            serde_json::to_string(alias).map_err(|_| FailureCode::SourceProjectionInvalid)?;
        let filter = format!("{attribute} eq {literal}");
        let response = self
            .client
            .request(
                self.credential,
                ScimRequest {
                    method: Method::GET,
                    path: collection(self.kind),
                    query: Some(("filter", &filter)),
                    etag: None,
                    body: &[],
                    admission: self.admission,
                },
            )
            .await?;
        status(&response)?;
        let document: Value = serde_json::from_slice(&response.body)
            .map_err(|_| FailureCode::SourceProjectionInvalid)?;
        if document.get("schemas")
            != Some(&json!([
                "urn:ietf:params:scim:api:messages:2.0:ListResponse"
            ]))
        {
            return Err(FailureCode::SourceProjectionInvalid);
        }
        let total = document
            .get("totalResults")
            .and_then(Value::as_u64)
            .ok_or(FailureCode::SourceProjectionInvalid)?;
        let resources = document
            .get("Resources")
            .and_then(Value::as_array)
            .ok_or(FailureCode::SourceProjectionInvalid)?;
        if total > 1 || resources.len() > 1 || total != resources.len() as u64 {
            return Err(FailureCode::OwnershipMismatch);
        }
        let Some(resource) = resources.first() else {
            return Ok(None);
        };
        let etag = resource
            .pointer("/meta/version")
            .and_then(Value::as_str)
            .ok_or(FailureCode::OwnershipMismatch)?;
        let bytes =
            serde_json::to_vec(resource).map_err(|_| FailureCode::SourceProjectionInvalid)?;
        let located = parse_document(&bytes, etag, self.projection)
            .map_err(|_| FailureCode::OwnershipMismatch)?;
        self.fetch(located.target).await.map(Some)
    }
}
