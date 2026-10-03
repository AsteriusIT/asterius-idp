//! Tenant-owned cluster onboarding and bounded managed-group release.

use std::collections::BTreeSet;

use uuid::Uuid;

use crate::{Client, DomainError, GroupId};

/// Persisted cluster configuration. The registered client ID is its audience.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KubernetesProfile {
    cluster: String,
    namespace: String,
    groups: BTreeSet<Uuid>,
    revision: i64,
}

impl KubernetesProfile {
    /// Validates identifiers and the exact group release allow-list.
    pub fn parse(
        cluster: &str,
        namespace: &str,
        groups: Vec<Uuid>,
        revision: i64,
    ) -> Result<Self, DomainError> {
        fn identifier(value: &str) -> bool {
            !value.is_empty()
                && value.len() <= 63
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
                && value
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && value
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
        }
        if !identifier(cluster) || !identifier(namespace) || revision < 0 {
            return Err(DomainError::invalid(
                "kubernetes",
                "cluster and namespace must be lowercase DNS labels; revision must be nonnegative",
            ));
        }
        let count = groups.len();
        let groups: BTreeSet<_> = groups.into_iter().collect();
        if count > 100 || groups.len() != count {
            return Err(DomainError::invalid(
                "kubernetes.group_ids",
                "select at most 100 distinct managed groups",
            ));
        }
        Ok(Self {
            cluster: cluster.to_owned(),
            namespace: namespace.to_owned(),
            groups,
            revision,
        })
    }

    /// Rejects metadata that cannot implement the approved broker contract.
    pub fn check_client(&self, client: &Client) -> Result<(), DomainError> {
        let registration = &client.registration;
        if registration.compliance_profile.as_str() != "oidc"
            || registration.application_type.as_str() != "web"
            || registration.token_endpoint_auth_method.as_str() != "private_key_jwt"
            || registration.id_token_signed_response_alg.as_str() != "ES256"
            || !registration.token_binding.is_dpop_bound()
            || !registration.managed_groups_claim.is_issued()
            || !registration
                .grant_types
                .iter()
                .any(|grant| grant.as_str() == "authorization_code")
            || !registration
                .grant_types
                .iter()
                .any(|grant| grant.as_str() == "refresh_token")
            || !registration.scopes.contains("openid")
            || registration.redirect_uris.len() != 1
        {
            return Err(DomainError::invalid(
                "kubernetes",
                "cluster clients require confidential OIDC, a web HTTPS callback, private_key_jwt, ES256, openid, authorization_code and refresh_token, DPoP and managed_groups_claim",
            ));
        }
        Ok(())
    }

    /// Operator-facing cluster identifier.
    #[must_use]
    pub fn cluster(&self) -> &str {
        &self.cluster
    }
    /// Namespace used by the least-privilege RBAC example.
    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.namespace
    }
    /// The only directory groups this audience may receive.
    #[must_use]
    pub const fn groups(&self) -> &BTreeSet<Uuid> {
        &self.groups
    }
    /// Optimistic concurrency revision, zero before initial creation.
    #[must_use]
    pub const fn revision(&self) -> i64 {
        self.revision
    }
    /// Safe identity prefix independent of caller-supplied claim names.
    #[must_use]
    pub fn prefix(&self, tenant: &str) -> String {
        format!("asterius:{tenant}:{}:", self.cluster)
    }
    /// Checks a stable server group identifier against the exact allow-list.
    #[must_use]
    pub fn releases(&self, group: GroupId) -> bool {
        self.groups.contains(&group.as_uuid())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kubernetes_profile_rejects_reserved_injected_and_oversized_configuration() {
        for value in [
            "system:masters",
            "../cluster",
            "UPPER",
            "x\n--flag",
            "-bad",
            "bad-",
        ] {
            assert!(KubernetesProfile::parse(value, "default", vec![], 0).is_err());
        }
        let id = Uuid::new_v4();
        assert!(KubernetesProfile::parse("cluster", "default", vec![id, id], 0).is_err());
        assert!(
            KubernetesProfile::parse(
                "cluster",
                "default",
                (0..101).map(|_| Uuid::new_v4()).collect(),
                0
            )
            .is_err()
        );
    }

    #[test]
    fn kubernetes_profile_releases_only_operator_selected_group_ids() {
        let selected = GroupId::mint();
        let profile =
            KubernetesProfile::parse("cluster-a", "default", vec![selected.as_uuid()], 0).unwrap();
        assert!(profile.releases(selected));
        assert!(!profile.releases(GroupId::mint()));
        assert!(!profile.prefix("team").starts_with("system:"));
    }
}
