//! One process-owned connector runtime, shared by administration and delivery.

use super::{OutboundScimClient, OutboundScimDeliverer, ScopedCredentialRegistry};
use crate::outbound::HttpsPoster;
use asterius_domain::outbound_scim::{OutboundScimAdministration, OutboundScimCredentialCatalogue};
use asterius_store_pg::{
    PgOutboundScimAdministration, PgOutboundScimJobs, PgOutboundScimLifecycle, Store,
};
use std::sync::Arc;

#[derive(Debug)]
pub struct OutboundScimRuntime {
    pub(super) catalogue: Arc<dyn OutboundScimAdministration>,
    pub(super) credentials: Arc<ScopedCredentialRegistry>,
    pub(super) client: Arc<OutboundScimClient>,
    jobs: Arc<PgOutboundScimJobs>,
    lifecycle: Arc<PgOutboundScimLifecycle>,
}
impl OutboundScimRuntime {
    #[must_use]
    pub fn new(
        store: &Store,
        poster: HttpsPoster,
        credentials: Arc<ScopedCredentialRegistry>,
    ) -> Self {
        let catalogue = Arc::new(PgOutboundScimAdministration::new(
            store.pool().clone(),
            Arc::clone(&credentials) as Arc<dyn OutboundScimCredentialCatalogue>,
        ));
        Self {
            catalogue,
            client: Arc::new(OutboundScimClient::new(
                Arc::new(poster),
                credentials.clone(),
            )),
            credentials,
            jobs: Arc::new(PgOutboundScimJobs::new(store.pool().clone())),
            lifecycle: Arc::new(PgOutboundScimLifecycle::new(store.pool().clone())),
        }
    }

    #[must_use]
    pub fn administration(&self) -> Arc<dyn OutboundScimAdministration> {
        Arc::clone(&self.catalogue)
    }

    #[must_use]
    pub fn credential_catalogue(&self) -> Arc<dyn OutboundScimCredentialCatalogue> {
        Arc::clone(&self.credentials) as Arc<dyn OutboundScimCredentialCatalogue>
    }

    #[must_use]
    pub fn lifecycle(&self) -> Arc<dyn asterius_domain::outbound_scim::OutboundScimLifecycle> {
        self.lifecycle.clone()
    }

    #[must_use]
    pub fn deliverer(&self) -> Arc<OutboundScimDeliverer> {
        Arc::new(OutboundScimDeliverer::new(
            self.jobs.clone(),
            Arc::clone(&self.client),
            self.lifecycle.clone(),
        ))
    }
}

#[async_trait::async_trait]
impl asterius_domain::outbound_scim::OutboundScimInspection for OutboundScimRuntime {
    async fn dry_run(
        &self,
        tenant: &asterius_domain::TenantId,
        connector_id: uuid::Uuid,
        assignment_id: uuid::Uuid,
        expected_revision: uuid::Uuid,
    ) -> Result<asterius_domain::outbound_scim::AssignmentPreview, asterius_domain::DomainError>
    {
        use super::client::RequestAdmission;
        use super::inspection::OwnerReader;
        use asterius_domain::{DomainError, outbound_scim::Projection};
        let selection = self
            .catalogue
            .preview_selection(tenant, connector_id, assignment_id, expected_revision)
            .await?;
        let reader = OwnerReader {
            client: &self.client,
            credential: &selection.connector.credential,
            kind: selection.assignment.kind,
            projection: &selection.projection,
            admission: RequestAdmission::Preview {
                catalogue: self.catalogue.as_ref(),
                connector: &selection.connector,
            },
        };
        let inspect = async {
            match selection.assignment.target {
                Some(target) => reader.fetch(target).await.map(Some),
                None => reader.locate().await,
            }
        };
        let remote = tokio::time::timeout(std::time::Duration::from_secs(30), inspect)
            .await
            .map_err(|_| DomainError::Conflict("target_unavailable".into()))?
            .map_err(|code| DomainError::Conflict(code.as_str().into()))?;
        let source_exists = match &selection.projection {
            Projection::User(user) => user.source_exists,
            Projection::Group(group) => group.source_exists,
        };
        let action = match &remote {
            None if selection.assignment.creation_admitted
                && (!selection.assignment.selected || !source_exists) =>
            {
                "recover_deprovision"
            }
            None if !selection.assignment.selected || !source_exists => "unchanged_absent",
            None => "create",
            Some(remote) if super::worker::equal(remote, &selection.projection) => "unchanged",
            Some(_) => match &selection.projection {
                Projection::User(user) if !user.active => "disable",
                Projection::Group(group) if group.target_members.is_empty() => "empty_group",
                _ => "update",
            },
        };
        let current = self
            .catalogue
            .preview_selection(tenant, connector_id, assignment_id, expected_revision)
            .await?;
        if current.assignment.generation != selection.assignment.generation
            || current.assignment.desired_revision != selection.assignment.desired_revision
            || current.projection != selection.projection
        {
            return Err(DomainError::Conflict(
                "source changed during dry run".into(),
            ));
        }
        Ok(asterius_domain::outbound_scim::AssignmentPreview {
            assignment: assignment_id,
            generation: selection.assignment.generation,
            desired_revision: selection.assignment.desired_revision,
            action: action.into(),
            target: remote.as_ref().map(|remote| remote.target),
            target_version: remote.as_ref().map(|remote| remote.etag.clone()),
        })
    }

    async fn preview(
        &self,
        tenant: &asterius_domain::TenantId,
        actor: asterius_domain::UserId,
        connector_id: uuid::Uuid,
        expected_revision: uuid::Uuid,
    ) -> Result<asterius_domain::outbound_scim::ConnectorPreview, asterius_domain::DomainError>
    {
        use super::client::{RequestAdmission, ScimRequest};
        use asterius_domain::DomainError;
        let connector = self
            .catalogue
            .preview_connector(tenant, connector_id, expected_revision)
            .await?;
        let request = self.client.request(
            &connector.credential,
            ScimRequest {
                method: hyper::Method::GET,
                path: "ServiceProviderConfig",
                query: None,
                etag: None,
                body: &[],
                admission: RequestAdmission::Preview {
                    catalogue: self.catalogue.as_ref(),
                    connector: &connector,
                },
            },
        );
        // Includes waiting behind a bound OAuth session. It cannot retain an
        // administrative command indefinitely during token/nonce contention.
        let response = tokio::time::timeout(std::time::Duration::from_secs(30), request)
            .await
            .map_err(|_| DomainError::Conflict("target_unavailable".into()))?
            .map_err(|code| DomainError::Conflict(code.as_str().into()))?;
        if response.status != 200
            || response.truncated
            || !response.content_type.as_deref().is_some_and(|media| {
                media
                    .split(';')
                    .next()
                    .is_some_and(|media| media.trim().eq_ignore_ascii_case("application/scim+json"))
            })
        {
            return Err(DomainError::Conflict("authentication_refused".into()));
        }
        asterius_domain::outbound_scim::parse_peer_capabilities(&response.body)
            .map_err(|code| DomainError::Conflict(code.as_str().into()))?;
        self.catalogue
            .record_preview(tenant, actor, connector_id, expected_revision)
            .await?;
        Ok(asterius_domain::outbound_scim::ConnectorPreview {
            connector: connector_id,
            revision: expected_revision,
            filter_supported: true,
            etag_supported: true,
        })
    }
}
