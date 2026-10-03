//! Cluster profile documents and copyable API-server/RBAC examples.

use asterius_domain::kubernetes::KubernetesProfile;
use asterius_domain::{Client, DomainError, Tenant};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

/// A complete optimistic-concurrency replacement; zero creates a profile.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestedProfile {
    /// Unique DNS-label cluster identifier within this tenant.
    pub cluster_id: String,
    /// Namespace for the read-only sample binding.
    pub namespace: String,
    /// Exact managed groups authorized for this client; empty releases none.
    pub group_ids: Vec<Uuid>,
    /// Last read revision, or zero for initial creation.
    pub revision: i64,
}

impl RequestedProfile {
    /// Validates bounded identifiers and release controls.
    pub fn validate(self) -> Result<KubernetesProfile, DomainError> {
        KubernetesProfile::parse(
            &self.cluster_id,
            &self.namespace,
            self.group_ids,
            self.revision,
        )
    }
}

/// Renders persisted policy and examples; JSON is also valid YAML.
#[must_use]
pub fn document(tenant: &Tenant, client: &Client, profile: &KubernetesProfile) -> Value {
    let issuer = tenant.issuer.as_str();
    let prefix = profile.prefix(tenant.id.as_str());
    let group_prefix = format!("{prefix}group:");
    let bindings: Vec<_> = profile.groups().iter().map(|id| json!({
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
        "metadata": {"name": format!("asterius-view-{id}"), "namespace": profile.namespace()},
        "subjects": [{"kind": "Group", "apiGroup": "rbac.authorization.k8s.io", "name": format!("{group_prefix}group:{id}")}],
        "roleRef": {"kind": "ClusterRole", "apiGroup": "rbac.authorization.k8s.io", "name": "view"}
    })).collect();
    json!({
        "cluster_id": profile.cluster(), "namespace": profile.namespace(),
        "group_ids": profile.groups(), "revision": profile.revision(),
        "client_id": client.id.as_str(), "audience": client.id.as_str(),
        "issuer": issuer, "jwks_uri": format!("{issuer}/jwks"),
        "compliance_profile": client.registration.compliance_profile.as_str(),
        "signing_algorithm": client.registration.id_token_signed_response_alg.as_str(),
        "subject_type": client.registration.subject_type.as_str(),
        "username_claim": "sub", "groups_claim": "group_ids",
        "username_prefix": prefix, "groups_prefix": group_prefix,
        "legacy_flags": [
            format!("--oidc-issuer-url={issuer}"),
            format!("--oidc-client-id={}", client.id.as_str()),
            "--oidc-signing-algs=ES256", "--oidc-username-claim=sub",
            format!("--oidc-username-prefix={prefix}"),
            "--oidc-groups-claim=group_ids", format!("--oidc-groups-prefix={group_prefix}")
        ],
        "authentication_configuration": {
            "apiVersion": "apiserver.config.k8s.io/v1", "kind": "AuthenticationConfiguration",
            "jwt": [{
                "issuer": {"url": issuer, "audiences": [client.id.as_str()], "audienceMatchPolicy": "MatchAny"},
                "claimValidationRules": [
                    {"expression": "claims.exp - claims.iat <= 300", "message": "ID token lifetime must not exceed five minutes"},
                    {"expression": "type(claims.aud) == string", "message": "one cluster audience is required"}
                ],
                "claimMappings": {
                    "username": {"claim": "sub", "prefix": prefix},
                    "groups": {"claim": "group_ids", "prefix": group_prefix}
                },
                "userValidationRules": [{"expression": "!user.username.startsWith('system:') && user.groups.all(g, !g.startsWith('system:'))", "message": "reserved Kubernetes identities are forbidden"}]
            }]
        },
        "rbac_bindings": bindings,
        "notes": [
            "Use either AuthenticationConfiguration or legacy OIDC flags, never both.",
            "Add the issuer CA bundle to issuer.certificateAuthority or --oidc-ca-file for private CAs; never disable TLS verification.",
            "Structured authentication accepts Kubernetes' supported algorithms; legacy flags explicitly pin ES256. This client always issues ES256.",
            "Examples grant namespace-scoped read-only view access for selected groups. Review before applying.",
            "Existing ID tokens remain usable until expiry after membership removal or logout."
        ]
    })
}

/// Reviewed structured-authentication extension. Legacy flags cannot select JIT identities.
#[must_use]
pub fn temporary_authentication_document(
    tenant: &Tenant,
    client: &Client,
    profile: &KubernetesProfile,
    expected: &asterius_domain::temporary_kubernetes::KubernetesJitIdentity,
) -> Value {
    let mut value = document(tenant, client, profile)["authentication_configuration"].clone();
    let fields = [
        "binding_revision", "entitlement_id", "client_id", "resource", "permissions", "role",
        "cluster", "namespace", "profile_revision", "expires_at",
    ];
    let mut shape = vec!["type(claims.asterius_jit) == map".to_owned(), "claims.asterius_jit.size() == 10".to_owned()];
    for field in fields {
        shape.push(format!("has(claims.asterius_jit.{field})"));
    }
    for field in ["binding_revision", "entitlement_id", "client_id", "resource", "role", "cluster", "namespace"] {
        shape.push(format!("type(claims.asterius_jit.{field}) == string"));
    }
    shape.extend([
        "type(claims.asterius_jit.permissions) == list && claims.asterius_jit.permissions.all(p, type(p) == string)".to_owned(),
        "type(claims.asterius_jit.profile_revision) == int && claims.asterius_jit.profile_revision > 0".to_owned(),
        "type(claims.asterius_jit.expires_at) == int && claims.asterius_jit.expires_at > 0 && claims.exp <= claims.asterius_jit.expires_at".to_owned(),
    ]);
    let validation = format!("!has(claims.asterius_jit) || ({})", shape.join(" && "));
    let pins = json!({
        "binding_revision": expected.binding_revision,
        "entitlement_id": expected.entitlement_id,
        "client_id": expected.client_id,
        "resource": expected.resource,
        "permissions": expected.permissions,
        "role": expected.role,
        "cluster": expected.cluster,
        "namespace": expected.namespace,
        "profile_revision": expected.profile_revision,
    });
    let matches: Vec<_> = pins.as_object().into_iter().flatten().map(|(key, value)| {
        format!("claims.asterius_jit.{key} == {value}")
    }).collect();
    let jit_prefix = json!(format!("asterius-jit:{}:", expected.binding_revision));
    let baseline_prefix = json!(profile.prefix(tenant.id.as_str()));
    // document() always constructs this field as a validation-rule array.
    value["jwt"][0]["claimValidationRules"].as_array_mut().expect("generated validation array")
        .push(json!({"expression":validation,"message":"temporary identity provenance must be closed and deadline capped"}));
    value["jwt"][0]["claimMappings"]["username"] = json!({
        "expression":format!("has(claims.asterius_jit) && ({}) ? {jit_prefix} + claims.sub : {baseline_prefix} + claims.sub", matches.join(" && "))
    });
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use asterius_domain::{
        Capabilities, ClientComplianceProfile, ClientId, ClientRegistration, ClientStatus, Issuer,
        RefreshPolicy, TenantId, TenantStatus,
    };
    use time::OffsetDateTime;

    fn fixture() -> (Tenant, Client, KubernetesProfile) {
        let registration = ClientRegistration::from_json_with_profile(json!({
            "client_name": "Cluster A broker", "redirect_uris": ["https://broker.example/callback"],
            "grant_types": ["authorization_code", "refresh_token"], "scope": "openid",
            "jwks_uri": "https://broker.example/jwks", "id_token_signed_response_alg": "ES256",
            "managed_groups_claim": true
        }).to_string().as_bytes(), Capabilities::default(), ClientComplianceProfile::Oidc).unwrap();
        let tenant = Tenant {
            id: TenantId::new("demo"),
            issuer: Issuer::parse("https://issuer.example/t/demo").unwrap(),
            default_resource: "https://api.example".to_owned(),
            custom_host: None,
            display_name: "Demo".to_owned(),
            status: TenantStatus::Active,
            refresh: RefreshPolicy::default(),
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
        };
        let client = Client {
            tenant: tenant.id.clone(),
            id: ClientId::new("cluster-a-client"),
            registration,
            status: ClientStatus::Active,
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
        };
        let profile =
            KubernetesProfile::parse("cluster-a", "default", vec![Uuid::from_u128(1)], 1).unwrap();
        (tenant, client, profile)
    }

    #[test]
    fn kubernetes_examples_are_scoped_and_do_not_export_administrative_authority() {
        let (tenant, client, profile) = fixture();
        profile.check_client(&client).unwrap();
        let value = document(&tenant, &client, &profile);
        assert_eq!(value["audience"], "cluster-a-client");
        assert_eq!(
            value["authentication_configuration"]["jwt"][0]["issuer"]["audiences"],
            json!(["cluster-a-client"])
        );
        assert_eq!(
            value["rbac_bindings"][0]["metadata"]["namespace"],
            "default"
        );
        assert_eq!(value["rbac_bindings"][0]["roleRef"]["name"], "view");
        assert_eq!(
            value["rbac_bindings"][0]["subjects"][0]["name"],
            "asterius:demo:cluster-a:group:group:00000000-0000-0000-0000-000000000001"
        );
        assert!(
            value["legacy_flags"]
                .as_array()
                .unwrap()
                .contains(&json!("--oidc-signing-algs=ES256"))
        );
        assert_eq!(
            value["authentication_configuration"],
            serde_json::from_str::<Value>(include_str!(
                "../../../docs/examples/kubernetes-authentication.json"
            ))
            .unwrap()
        );
    }

    #[test]
    fn kubernetes_profile_rejects_registration_downgrade_or_group_opt_out() {
        let (_, mut client, profile) = fixture();
        client.registration.id_token_signed_response_alg = asterius_domain::SigningAlgorithm::EdDsa;
        assert!(profile.check_client(&client).is_err());
        client.registration.id_token_signed_response_alg = asterius_domain::SigningAlgorithm::Es256;
        client.registration.managed_groups_claim = asterius_domain::ManagedGroupsClaim::Omitted;
        assert!(profile.check_client(&client).is_err());
        client.registration.managed_groups_claim = asterius_domain::ManagedGroupsClaim::Issued;
        client.registration.compliance_profile = ClientComplianceProfile::Fapi;
        assert!(profile.check_client(&client).is_err());
    }

    #[test]
    fn kubernetes_request_refuses_claim_shadowing_and_excessive_group_release() {
        let value = json!({"cluster_id":"cluster-a", "namespace":"default", "group_ids":[], "revision":0, "groups_claim":"system:masters"});
        assert!(serde_json::from_value::<RequestedProfile>(value).is_err());
        let request = RequestedProfile {
            cluster_id: "cluster-a".to_owned(),
            namespace: "default".to_owned(),
            group_ids: (0..101).map(|_| Uuid::new_v4()).collect(),
            revision: 0,
        };
        assert!(request.validate().is_err());
    }
}
