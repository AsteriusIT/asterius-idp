//! One process-owned connector runtime, shared by administration and delivery.

use super::{OutboundScimClient, OutboundScimDeliverer, ScopedCredentialRegistry};
use crate::outbound::HttpsPoster;
use asterius_domain::outbound_scim::{OutboundScimAdministration, OutboundScimCredentialCatalogue};
use asterius_store_pg::{PgOutboundScimAdministration, PgOutboundScimJobs, Store};
use std::sync::Arc;

#[derive(Debug)]
pub struct OutboundScimRuntime {
    pub(super) catalogue: Arc<dyn OutboundScimAdministration>,
    pub(super) credentials: Arc<ScopedCredentialRegistry>,
    pub(super) client: Arc<OutboundScimClient>,
    jobs: Arc<PgOutboundScimJobs>,
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
    pub fn deliverer(&self) -> Arc<OutboundScimDeliverer> {
        Arc::new(OutboundScimDeliverer::new(
            self.jobs.clone(),
            Arc::clone(&self.client),
        ))
    }
}

#[async_trait::async_trait]
impl asterius_domain::outbound_scim::OutboundScimInspection for OutboundScimRuntime {
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
