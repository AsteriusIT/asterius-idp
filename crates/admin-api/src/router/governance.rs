//! Human governance commands retain the console gate and verify fresh proof again.

use super::{AdminError, Handling, Principal, Response, StatusCode, json_no_store};
use asterius_domain::UserId;
use asterius_domain::access_reviews::{parse_decision, parse_ownership, parse_review};
use uuid::Uuid;

impl Handling<'_> {
    fn governance_actor(&self) -> Result<UserId, AdminError> {
        let Principal::Console { tenant, user, .. } = self.principal else {
            return Err(AdminError::Forbidden);
        };
        // A deployment administrator's reserved-realm identity must not become
        // a fictitious reviewer or owner in another tenant.
        if tenant != &self.tenant.id {
            return Err(AdminError::Forbidden);
        }
        Ok(*user)
    }

    fn governance_id(&self, offset: usize) -> Result<Uuid, AdminError> {
        let value = self
            .path
            .rsplit('/')
            .filter(|value| !value.is_empty())
            .nth(offset.checked_sub(1).ok_or(AdminError::NotFound)?)
            .ok_or(AdminError::NotFound)?;
        let parsed = Uuid::parse_str(value).map_err(|_| AdminError::NotFound)?;
        if parsed.to_string() != value || parsed.is_nil() {
            return Err(AdminError::NotFound);
        }
        Ok(parsed)
    }

    async fn governance_empty(&self, body: axum::body::Body) -> Result<(), AdminError> {
        let bytes = self.body_bytes(body).await?;
        if !bytes.is_empty()
            && serde_json::from_slice::<serde_json::Value>(&bytes).ok()
                != Some(serde_json::json!({}))
        {
            return Err(AdminError::Invalid(
                "command accepts no posted authority or snapshot".into(),
            ));
        }
        Ok(())
    }

    pub(super) async fn governance(
        &self,
        id: &str,
        body: axum::body::Body,
    ) -> Result<Response, AdminError> {
        let actor = self.governance_actor()?;
        let port = self
            .state
            .backend
            .access_reviews()
            .ok_or(AdminError::Unavailable)?;
        let write = matches!(
            id,
            "governance.ownership.configure"
                | "governance.review.start"
                | "governance.review.decide"
                | "governance.review.apply"
                | "governance.review.cancel"
        );
        if write {
            self.require_fresh_totp_recovery_admin().await?;
        }
        let encoded = |value| Ok(json_no_store(StatusCode::OK, &value));
        let (after, limit) = governance_page(&self.query)?;
        match id {
            "governance.reviewers" => encoded(
                serde_json::json!({"items":port.reviewers(&self.tenant.id,after,limit).await.map_err(governance_error)?}),
            ),
            "governance.ownership.list" => encoded(
                serde_json::json!({"items":port.ownerships(&self.tenant.id,after,limit).await.map_err(governance_error)?}),
            ),
            "governance.ownership.configure" => {
                let request =
                    parse_ownership(&self.body_bytes(body).await?).map_err(governance_error)?;
                encoded(serde_json::json!(
                    port.configure(&self.tenant.id, actor, request)
                        .await
                        .map_err(governance_error)?
                ))
            }
            "governance.review.start" => {
                let request =
                    parse_review(&self.body_bytes(body).await?).map_err(governance_error)?;
                encoded(serde_json::json!(
                    port.start(&self.tenant.id, actor, request)
                        .await
                        .map_err(governance_error)?
                ))
            }
            "governance.review.read" => encoded(serde_json::json!(
                port.review(&self.tenant.id, actor, true, self.governance_id(1)?)
                    .await
                    .map_err(governance_error)?
            )),
            "governance.review.list" => encoded(
                serde_json::json!({"items":port.reviews(&self.tenant.id,actor,true,after,limit).await.map_err(governance_error)?}),
            ),
            "governance.review.items" => encoded(
                serde_json::json!({"items":port.items(&self.tenant.id,actor,true,self.governance_id(2)?,after,limit).await.map_err(governance_error)?}),
            ),
            "governance.review.decide" => {
                let request =
                    parse_decision(&self.body_bytes(body).await?).map_err(governance_error)?;
                encoded(serde_json::json!(
                    port.decide(
                        &self.tenant.id,
                        actor,
                        self.governance_id(4)?,
                        self.governance_id(2)?,
                        request.decision,
                        request.reason
                    )
                    .await
                    .map_err(governance_error)?
                ))
            }
            "governance.review.apply" => {
                self.governance_empty(body).await?;
                encoded(serde_json::json!(
                    port.apply(
                        &self.tenant.id,
                        actor,
                        self.governance_id(4)?,
                        self.governance_id(2)?
                    )
                    .await
                    .map_err(governance_error)?
                ))
            }
            "governance.review.cancel" => {
                self.governance_empty(body).await?;
                encoded(serde_json::json!(
                    port.cancel(&self.tenant.id, actor, self.governance_id(2)?)
                        .await
                        .map_err(governance_error)?
                ))
            }
            _ => Err(AdminError::Unavailable),
        }
    }
}

fn governance_error(error: asterius_domain::DomainError) -> AdminError {
    match error {
        asterius_domain::DomainError::NotFound => AdminError::NotFound,
        asterius_domain::DomainError::Conflict(reason) => AdminError::Conflict(reason),
        asterius_domain::DomainError::Invalid { field, reason } => {
            AdminError::Invalid(format!("{field}: {reason}"))
        }
        other => AdminError::from_storage("governance", &other),
    }
}

fn governance_page(query: &str) -> Result<(Option<Uuid>, u16), AdminError> {
    let after = super::query_value(query, "after")
        .map(|value| {
            Uuid::parse_str(&value).map_err(|_| AdminError::Invalid("invalid after cursor".into()))
        })
        .transpose()?;
    let limit = super::query_value(query, "limit")
        .map(|value| {
            value
                .parse::<u16>()
                .map_err(|_| AdminError::Invalid("invalid page limit".into()))
        })
        .transpose()?
        .unwrap_or(50);
    Ok((after, limit))
}
