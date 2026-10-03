//! Findings expose evidence and proposals; no lifecycle command is invoked.
use super::{AdminError, Handling, Principal, Response, StatusCode, json_no_store};

impl Handling<'_> {
    pub(super) async fn governance_findings(&self) -> Result<Response, AdminError> {
        let Principal::Console { tenant, user, .. } = self.principal else {
            return Err(AdminError::Forbidden);
        };
        if tenant != &self.tenant.id {
            return Err(AdminError::Forbidden);
        }
        let query = asterius_domain::governance_reports::Query::parse(&self.query)
            .map_err(|_| AdminError::Invalid("invalid bounded report query or cursor".into()))?;
        let port = self
            .state
            .backend
            .governance_reports()
            .ok_or(AdminError::Unavailable)?;
        let page = port
            .findings(&self.tenant.id, *user, &query)
            .await
            .map_err(|error| match error {
                asterius_domain::DomainError::NotFound => AdminError::NotFound,
                asterius_domain::DomainError::Invalid { .. } => {
                    AdminError::Invalid("invalid report query or cursor".into())
                }
                other => AdminError::from_storage("governance.findings", &other),
            })?;
        Ok(json_no_store(StatusCode::OK, &serde_json::json!(page)))
    }
}
