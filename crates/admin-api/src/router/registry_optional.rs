// Test-only configured empty optional services used by the full registry walk.
mod registry_optional {
    use super::*;
    mod online {
        use super::*;
        use asterius_domain::kubernetes_online::{
            KubernetesOnline, OnlineProfile, ProfileChange, TokenReviewRequest, TokenReviewResponse,
        };
        use asterius_domain::{Actor, ClientId, Tenant};
        #[async_trait::async_trait]
        impl KubernetesOnline for Handle {
            async fn profile(
                &self,
                tenant: &TenantId,
                _client: &ClientId,
            ) -> Result<Option<OnlineProfile>, DomainError> {
                self.record_governance_call(tenant, "online.profile");
                Ok(None)
            }
            async fn replace_profile(
                &self,
                tenant: &TenantId,
                _client: &ClientId,
                _actor: &Actor,
                _change: &ProfileChange,
            ) -> Result<OnlineProfile, DomainError> {
                self.record_governance_call(tenant, "online.replace_profile");
                Err(DomainError::NotFound)
            }
            async fn review(
                &self,
                tenant: &Tenant,
                _reviewer: &ClientId,
                _client: &ClientId,
                _request: &TokenReviewRequest,
            ) -> Result<TokenReviewResponse, DomainError> {
                self.record_governance_call(&tenant.id, "online.review");
                Ok(TokenReviewResponse::denied())
            }
        }
    }
    mod jit {
        use super::*;
        use asterius_domain::ClientId;
        use asterius_domain::temporary_kubernetes::{
            KubernetesAccessProjection, KubernetesBindingChange, KubernetesEntitlementBinding,
            TemporaryKubernetes,
        };
        use uuid::Uuid;
        #[async_trait::async_trait]
        impl TemporaryKubernetes for Handle {
            async fn binding(
                &self,
                tenant: &TenantId,
                _owner: &UserId,
                _entitlement: Uuid,
            ) -> Result<Option<KubernetesEntitlementBinding>, DomainError> {
                self.record_governance_call(tenant, "jit.binding");
                Ok(None)
            }
            async fn replace_binding(
                &self,
                tenant: &TenantId,
                _owner: &UserId,
                _entitlement: Uuid,
                _change: KubernetesBindingChange,
            ) -> Result<KubernetesEntitlementBinding, DomainError> {
                self.record_governance_call(tenant, "jit.replace_binding");
                Err(DomainError::NotFound)
            }
            async fn project(
                &self,
                tenant: &TenantId,
                _controller: &ClientId,
                _entitlement: Uuid,
            ) -> Result<KubernetesAccessProjection, DomainError> {
                self.record_governance_call(tenant, "jit.project");
                Err(DomainError::NotFound)
            }
        }
    }
    mod devices {
        use super::*;
        use asterius_domain::Actor;
        use asterius_domain::managed_devices::{
            DeviceSummary, Registry, RemovalAuthority, SourceChange, SourceSummary,
        };
        use uuid::Uuid;
        #[async_trait::async_trait]
        impl Registry for Handle {
            async fn sources(&self, tenant: &TenantId) -> Result<Vec<SourceSummary>, DomainError> {
                self.record_governance_call(tenant, "devices.sources");
                Ok(Vec::new())
            }
            async fn save_source(
                &self,
                tenant: &TenantId,
                _id: Option<Uuid>,
                _change: &SourceChange,
                _actor: Actor,
                _now: OffsetDateTime,
            ) -> Result<SourceSummary, DomainError> {
                self.record_governance_call(tenant, "devices.save_source");
                Err(DomainError::NotFound)
            }
            async fn devices(
                &self,
                tenant: &TenantId,
                _owner: Option<UserId>,
                _after: Option<Uuid>,
                _limit: u16,
            ) -> Result<Vec<DeviceSummary>, DomainError> {
                self.record_governance_call(tenant, "devices.devices");
                Ok(Vec::new())
            }
            async fn remove(
                &self,
                tenant: &TenantId,
                _id: Uuid,
                _expected: Uuid,
                _authority: RemovalAuthority,
                _now: OffsetDateTime,
            ) -> Result<(), DomainError> {
                self.record_governance_call(tenant, "devices.remove");
                Err(DomainError::NotFound)
            }
        }
    }
    mod temporary {
        use super::*;
        use asterius_domain::Grant;
        use asterius_domain::temporary_entitlements::{
            AccountEntitlements, Activation, CancelRequest, DecideRequest, Eligibility,
            EligibilityChange, Entitlement, EntitlementConfiguration, EntitlementRequest,
            RequestActivation, RevokeActivation, SessionActor, TemporaryEntitlements,
            TemporaryRoleSnapshot,
        };
        use uuid::Uuid;
        #[async_trait::async_trait]
        impl TemporaryEntitlements for Handle {
            async fn list(
                &self,
                tenant: &TenantId,
                _owner: &UserId,
            ) -> Result<Vec<Entitlement>, DomainError> {
                self.record_governance_call(tenant, "temporary.list");
                Ok(Vec::new())
            }
            async fn get(
                &self,
                tenant: &TenantId,
                _owner: &UserId,
                _entitlement: Uuid,
            ) -> Result<Entitlement, DomainError> {
                self.record_governance_call(tenant, "temporary.get");
                Err(DomainError::NotFound)
            }
            async fn configure(
                &self,
                tenant: &TenantId,
                _actor: &UserId,
                _id: Option<Uuid>,
                _expected: Option<Uuid>,
                _configuration: EntitlementConfiguration,
            ) -> Result<Entitlement, DomainError> {
                self.record_governance_call(tenant, "temporary.configure");
                Err(DomainError::NotFound)
            }
            async fn eligibilities(
                &self,
                tenant: &TenantId,
                _owner: &UserId,
                _entitlement: Uuid,
            ) -> Result<Vec<Eligibility>, DomainError> {
                self.record_governance_call(tenant, "temporary.eligibilities");
                Err(DomainError::NotFound)
            }
            async fn set_eligibility(
                &self,
                tenant: &TenantId,
                _owner: &UserId,
                _entitlement: Uuid,
                _change: EligibilityChange,
            ) -> Result<Eligibility, DomainError> {
                self.record_governance_call(tenant, "temporary.set_eligibility");
                Err(DomainError::NotFound)
            }
            async fn remove_eligibility(
                &self,
                tenant: &TenantId,
                _owner: &UserId,
                _entitlement: Uuid,
                _eligibility: Uuid,
                _expected: Uuid,
            ) -> Result<(), DomainError> {
                self.record_governance_call(tenant, "temporary.remove_eligibility");
                Err(DomainError::NotFound)
            }
            async fn owner_requests(
                &self,
                tenant: &TenantId,
                _owner: &UserId,
                _entitlement: Uuid,
            ) -> Result<Vec<EntitlementRequest>, DomainError> {
                self.record_governance_call(tenant, "temporary.owner_requests");
                Err(DomainError::NotFound)
            }
            async fn owner_activations(
                &self,
                tenant: &TenantId,
                _owner: &UserId,
                _entitlement: Uuid,
            ) -> Result<Vec<Activation>, DomainError> {
                self.record_governance_call(tenant, "temporary.owner_activations");
                Err(DomainError::NotFound)
            }
            async fn owner_revoke(
                &self,
                tenant: &TenantId,
                _owner: &UserId,
                _entitlement: Uuid,
                _command: RevokeActivation,
            ) -> Result<Activation, DomainError> {
                self.record_governance_call(tenant, "temporary.owner_revoke");
                Err(DomainError::NotFound)
            }
            async fn account(
                &self,
                tenant: &TenantId,
                _actor: &SessionActor,
            ) -> Result<AccountEntitlements, DomainError> {
                self.record_governance_call(tenant, "temporary.account");
                Err(DomainError::NotFound)
            }
            async fn request(
                &self,
                tenant: &TenantId,
                _actor: &SessionActor,
                _command: RequestActivation,
            ) -> Result<EntitlementRequest, DomainError> {
                self.record_governance_call(tenant, "temporary.request");
                Err(DomainError::NotFound)
            }
            async fn decide(
                &self,
                tenant: &TenantId,
                _actor: &SessionActor,
                _command: DecideRequest,
            ) -> Result<EntitlementRequest, DomainError> {
                self.record_governance_call(tenant, "temporary.decide");
                Err(DomainError::NotFound)
            }
            async fn cancel(
                &self,
                tenant: &TenantId,
                _actor: &SessionActor,
                _command: CancelRequest,
            ) -> Result<EntitlementRequest, DomainError> {
                self.record_governance_call(tenant, "temporary.cancel");
                Err(DomainError::NotFound)
            }
            async fn revoke(
                &self,
                tenant: &TenantId,
                _actor: &SessionActor,
                _command: RevokeActivation,
            ) -> Result<Activation, DomainError> {
                self.record_governance_call(tenant, "temporary.revoke");
                Err(DomainError::NotFound)
            }
            async fn resolve_for_grant(
                &self,
                tenant: &TenantId,
                _grant: &Grant,
            ) -> Result<TemporaryRoleSnapshot, DomainError> {
                self.record_governance_call(tenant, "temporary.resolve_for_grant");
                Err(DomainError::NotFound)
            }
            async fn reconcile_expired(
                &self,
                tenant: &TenantId,
                _limit: u16,
            ) -> Result<u64, DomainError> {
                self.record_governance_call(tenant, "temporary.reconcile_expired");
                Err(DomainError::NotFound)
            }
        }
    }
    pub(super) fn missing_state_status(operation: &Operation) -> Option<StatusCode> {
        matches!(
            operation.id(),
            crate::KUBERNETES_ONLINE_READ_ID
                | crate::KUBERNETES_ONLINE_UPDATE_ID
                | crate::DEVICE_SOURCE_CREATE_ID
                | crate::DEVICE_SOURCE_UPDATE_ID
                | crate::DEVICE_REMOVE_ID
                | crate::TEMPORARY_ENTITLEMENT_CREATE_ID
                | crate::TEMPORARY_ENTITLEMENT_READ_ID
                | crate::TEMPORARY_ENTITLEMENT_UPDATE_ID
                | crate::TEMPORARY_ENTITLEMENT_ELIGIBILITIES_ID
                | crate::TEMPORARY_ENTITLEMENT_ELIGIBILITY_SET_ID
                | crate::TEMPORARY_ENTITLEMENT_ELIGIBILITY_REMOVE_ID
                | crate::TEMPORARY_ENTITLEMENT_REQUESTS_ID
                | crate::TEMPORARY_ENTITLEMENT_ACTIVATIONS_ID
                | crate::TEMPORARY_ENTITLEMENT_REVOKE_ID
                | crate::TEMPORARY_KUBERNETES_BINDING_WRITE_ID
        )
        .then_some(StatusCode::NOT_FOUND)
    }
    pub(super) fn assert_calls(calls: &[(TenantId, &'static str)]) {
        let expected = std::collections::BTreeSet::from([
            "online.profile",
            "online.replace_profile",
            "devices.sources",
            "devices.save_source",
            "devices.devices",
            "devices.remove",
            "jit.binding",
            "jit.replace_binding",
            "temporary.list",
            "temporary.get",
            "temporary.configure",
            "temporary.eligibilities",
            "temporary.set_eligibility",
            "temporary.remove_eligibility",
            "temporary.owner_requests",
            "temporary.owner_activations",
            "temporary.owner_revoke",
        ]);
        let reached: std::collections::BTreeSet<_> = calls
            .iter()
            .map(|(_, operation)| *operation)
            .filter(|operation| {
                operation.starts_with("online.")
                    || operation.starts_with("devices.")
                    || operation.starts_with("jit.")
                    || operation.starts_with("temporary.")
            })
            .collect();
        assert_eq!(reached, expected);
    }
    pub(super) fn body(operation: &Operation) -> Option<serde_json::Value> {
        let revision = "10000000-0000-4000-8000-000000000003";
        let configuration = || {
            serde_json::json!({
                "owner_user_id":SEEDED_USER_ID,"client_id":SEEDED_CLIENT_ID,
                "resource":"https://api.example/","role_name":HELD_ROLE,"permissions":["read"],
                "approver_user_ids":[revision],"requester_acr":"urn:asterius:acr:passkey",
                "approver_acr":"urn:asterius:acr:passkey","max_duration_seconds":300,
                "max_eligibility_seconds":86400,"enabled":false
            })
        };
        Some(match operation.id() {
            crate::KUBERNETES_ONLINE_UPDATE_ID => {
                serde_json::json!({"reviewer_client_id":"registry-reviewer","expected_revision":null,"enabled":false})
            }
            crate::DEVICE_SOURCE_CREATE_ID => {
                serde_json::json!({"client_id":SEEDED_CLIENT_ID,"expected_revision":null,"enabled":false})
            }
            crate::DEVICE_SOURCE_UPDATE_ID => {
                serde_json::json!({"client_id":SEEDED_CLIENT_ID,"expected_revision":revision,"enabled":false})
            }
            crate::DEVICE_REMOVE_ID | crate::TEMPORARY_ENTITLEMENT_ELIGIBILITY_REMOVE_ID => {
                serde_json::json!({"expected_revision":revision})
            }
            crate::TEMPORARY_KUBERNETES_BINDING_WRITE_ID => {
                serde_json::json!({"controller_client_id":"registry-controller","expected_revision":null,"enabled":false})
            }
            crate::TEMPORARY_ENTITLEMENT_CREATE_ID => configuration(),
            crate::TEMPORARY_ENTITLEMENT_UPDATE_ID => {
                let mut value = configuration();
                value["expected_revision"] = serde_json::json!(revision);
                value
            }
            crate::TEMPORARY_ENTITLEMENT_ELIGIBILITY_SET_ID => {
                serde_json::json!({"user_id":SEEDED_USER_ID,"not_before":2_524_608_000_i64,"expires_at":2_524_608_300_i64,"expected_revision":null})
            }
            crate::TEMPORARY_ENTITLEMENT_REVOKE_ID => {
                serde_json::json!({"activation_id":revision,"reason":"Registry fixture withdrawal","idempotency_key":revision})
            }
            _ => return None,
        })
    }
}
