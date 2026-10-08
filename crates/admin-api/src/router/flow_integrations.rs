//! Architecture adapters reuse guarded integration contracts; diagrams never
//! carry credentials or confer account binding / event delivery authority.
use super::{AdminError, Handling, flows, group_error, oidc_providers, upstream_operation_error};
use serde_json::{Value, json};
use std::collections::HashMap;

pub(super) fn integrated(node: &flows::Node) -> bool {
    matches!(node.mode, flows::NodeMode::Managed) || node.settings["integration"] == true
}

pub(super) fn provider_input(node: &flows::Node) -> Result<oidc_providers::ProviderInput, AdminError> {
    let document = json!({"id":node.identifier, "name":node.label, "issuer":node.settings["issuer"],
        "client_id":node.settings["client_id"], "username_claim":node.settings["username_claim"],
        "enabled":node.settings.get("enabled").unwrap_or(&Value::Bool(false)),
        "allow_registration":node.settings.get("allow_registration").unwrap_or(&Value::Bool(false))});
    oidc_providers::parse_provider(document.to_string().as_bytes())
}
fn provider_spec(provider: &oidc_providers::ProviderSummary) -> Value {
    json!({"id":provider.id,"name":provider.name,"issuer":provider.issuer,
        "authorization_endpoint":provider.authorization_endpoint,"token_endpoint":provider.token_endpoint,
        "jwks_uri":provider.jwks_uri,"client_id":provider.client_id,"username_claim":provider.username_claim,
        "enabled":provider.enabled,"allow_registration":provider.allow_registration,"revision":provider.revision})
}
fn public_spec(snapshot: &Value) -> Value {
    let mut value = snapshot.clone(); if let Some(object) = value.as_object_mut() { object.remove("revision"); } value
}
fn matches_previous(live: &Value, old: &flows::Node) -> bool {
    live["id"] == old.identifier && live["name"] == old.label && live["issuer"] == old.settings["issuer"]
        && live["client_id"] == old.settings["client_id"] && live["username_claim"] == old.settings["username_claim"]
        && live["enabled"] == old.settings.get("enabled").cloned().unwrap_or(Value::Bool(false))
        && live["allow_registration"] == old.settings.get("allow_registration").cloned().unwrap_or(Value::Bool(false))
}

pub(super) fn validate_credentials(credentials: &HashMap<String, flows::ApplyCredential>, plan: &flows::Plan, graph: &flows::Graph) -> Result<(), AdminError> {
    if credentials.len() > 100 || credentials.iter().any(|(id, credential)| {
        !credential.valid() || !graph.nodes.iter().any(|node| node.id == *id && node.kind == flows::NodeKind::IdentityProvider && matches!(node.mode, flows::NodeMode::Managed))
            || !plan.steps.iter().any(|step| step.id == *id && matches!(step.action.as_str(), "create" | "retry" | "update"))
    }) {
        return Err(AdminError::Invalid("apply credentials must name a changed managed provider node".into()));
    }
    if plan.steps.iter().any(|step| step.live.as_ref().is_some_and(|live| live["requires_credential"] == true) && !credentials.contains_key(&step.id)) {
        return Err(AdminError::Invalid("enter an apply-only credential for each provider marked as requiring one".into()));
    }
    Ok(())
}

impl Handling<'_> {
    #[expect(clippy::too_many_lines, reason = "Keep integration identity, exact live contract, drift, ownership and required authority in one preview decision")]
    pub(super) async fn compile_integration(&self, node: &flows::Node, link: Option<&Value>, previous: Option<&flows::Node>) -> Result<flows::PlanStep, AdminError> {
        let mut step = flows::PlanStep {id:node.id.clone(), label:node.label.clone(), kind:node.kind.as_str().into(), action:"document".into(),
            scope:"admin.flows:read".into(), resource_id:None, explanation:"Diagram context only; no integration is configured or verified.".into(), live:None};
        if !integrated(node) { return Ok(step); }
        self.require_flow_scope(flows::scope_for(node.kind, false))?;
        step.resource_id = Some(node.identifier.clone());
        let managed = matches!(node.mode, flows::NodeMode::Managed);
        step.scope = flows::scope_for(node.kind, managed).into();
        if link.is_some_and(|link| link["resource_id"] != node.identifier || link["relation"] != if managed {"managed"} else {"reference"}) {
            step.action = "conflict".into(); step.explanation = "Linked integration identity and ownership are immutable; add a new node.".into();
            return Ok(step);
        }
        if node.kind == flows::NodeKind::IdentityProvider {
            let admin = self.state.backend.oidc_providers().ok_or(AdminError::Unavailable)?;
            if !oidc_providers::valid_id(&node.identifier) { return Err(AdminError::Invalid("provider ID is invalid".into())); }
            let providers = admin.list(&self.tenant.id, self.tenant.issuer.as_str()).await.map_err(|error| group_error(crate::FLOW_PLAN_ID,error))?;
            let current = providers.iter().find(|provider| provider.id == node.identifier).map(provider_spec);
            if !managed {
                step.action = if current.is_some() {"reference"} else {"conflict"}.into();
                step.explanation = "References an existing sign-in provider; user/group connections do not bind accounts.".into();
                step.live = Some(json!({"current":current}));
            } else {
                let input = provider_input(node)?;
                let desired = admin.preview(&input).await.map_err(|error| group_error(crate::FLOW_PLAN_ID,error))?;
                step.action = match (&current, link) {
                    (None, None) => "create",
                    (None, Some(link)) if link["state"] == "pending" => "retry",
                    (Some(live), Some(link)) if link["state"] == "applied" && link["resource_revision"] == live["revision"] && public_spec(live) == desired => "unchanged",
                    (Some(live), Some(link)) if link["state"] == "applied" && link["resource_revision"] == live["revision"] && previous.is_some_and(|old| matches_previous(live,old)) => "update",
                    _ => "conflict",
                }.into();
                let requires = current.as_ref().is_none_or(|live| live["issuer"] != desired["issuer"] || live["client_id"] != desired["client_id"]);
                step.live = Some(json!({"current":current,"desired":desired,"requires_credential":requires}));
                step.explanation = if step.action == "conflict" {"The provider exists outside this flow, changed outside its managed specification, or was removed. No credentials or configuration will be overwritten."}
                    else {"Validates exact OIDC discovery; registration and its flow origin commit atomically. Apply-only credentials are encrypted and never saved in the diagram. Group/user edges remain diagram context."}.into();
            }
        } else {
            let peer = crate::ssf::parse_upstream_peer(json!({"peer_client_id":node.identifier}).to_string().as_bytes())?;
            let admin = self.state.backend.ssf();
            let peers = admin.upstream_peers(&self.tenant.id).await.map_err(upstream_operation_error)?;
            let current = peers.iter().find(|item| item.peer_client_id == node.identifier);
            if let Some(current) = current {
                let contract = admin.upstream_preview(&self.tenant.id, &peer).await.map_err(upstream_operation_error)?;
                let pinned = node.settings["expected_audience"] == current.expected_audience && node.settings["allow_all_subjects"] == current.allow_all_subjects;
                step.action = if !pinned || !current.allow_all_subjects || current.state == "deletion_pending" {"conflict"}
                    else if !managed {if current.state == "established" {"reference"} else {"conflict"}}
                    else {match (current.state, link) {
                        ("not_started", None) => "create",
                        ("not_started", Some(link)) if link["state"] == "pending" => "retry",
                        ("pending_review", Some(link)) if link["state"] == "pending" && current.origin_flow.as_deref() == Some(self.flow_in_path()?.to_string().as_str()) && current.origin_node.as_deref() == Some(node.id.as_str()) => "retry",
                        ("established", Some(link)) if link["state"] == "pending" && current.origin_flow.as_deref() == Some(self.flow_in_path()?.to_string().as_str()) && current.origin_node.as_deref() == Some(node.id.as_str()) => "retry",
                        ("established", Some(link)) if link["state"] == "applied" && link["resource_revision"].as_str() == current.stream_id.as_deref() && current.origin_flow.as_deref() == Some(self.flow_in_path()?.to_string().as_str()) && current.origin_node.as_deref() == Some(node.id.as_str()) => "unchanged",
                        _ => "conflict",
                    }}.into();
                if current.state == "established" {
                    admin.upstream_verify(&self.tenant.id, &peer, time::OffsetDateTime::now_utc()).await.map_err(upstream_operation_error)?;
                }
                step.live = Some(json!({"current":{"state":current.state,"stream_id":current.stream_id,"expected_audience":current.expected_audience,"allow_all_subjects":current.allow_all_subjects},"contract":contract}));
                step.explanation = if step.action == "conflict" {"Choose an existing established stream as a reference, or reconcile changed audience/subject policy/deletion state in Shared signals. Creating ALL-subject delivery requires operator consent."}
                    else if current.state == "pending_review" {"Reconcile this flow's durable setup intent by authenticated readback; an uncertain POST is never repeated. Keep the configured peer and use Shared signals for explicit deletion/recovery."}
                    else {"Establishes or verifies a configured poll stream using operator-managed credentials and pinned metadata. Setup does not prove event delivery; request and observe signed verification in Shared signals. Application links remain diagram context."}.into();
            } else { step.action = "conflict".into(); step.explanation = "Configure this tenant's upstream peer on the server first.".into(); }
        }
        if managed && !matches!(step.action.as_str(), "conflict" | "unchanged") && self.require_flow_scope(flows::scope_for(node.kind,true)).is_err() {
            step.action="conflict".into(); step.explanation=format!("This operation needs {}.",flows::scope_for(node.kind,true));
        }
        Ok(step)
    }

    pub(super) async fn apply_integration(&self, node: &flows::Node, step: &flows::PlanStep, apply: &flows::ApplyStep, credential: Option<&mut flows::ApplyCredential>) -> Result<(), AdminError> {
        self.require_flow_scope(flows::scope_for(node.kind,true))?;
        let live = step.live.as_ref().ok_or(AdminError::Unavailable)?;
        if node.kind == flows::NodeKind::IdentityProvider {
            let mut input = provider_input(node)?;
            input.client_secret = credential.map(flows::ApplyCredential::take);
            let admin = self.state.backend.oidc_providers().ok_or(AdminError::Unavailable)?;
            admin.put_flow(&self.tenant.id,self.tenant.issuer.as_str(),input,apply,
                live.get("current").filter(|value| !value.is_null()), &live["desired"]).await.map_err(|error| group_error(crate::FLOW_APPLY_ID,error))?;
        } else {
            let peer = asterius_domain::ClientId::new(node.identifier.clone());
            let admin = self.state.backend.ssf();
            let contract = admin.upstream_preview(&self.tenant.id,&peer).await.map_err(upstream_operation_error)?;
            if contract != live["contract"] { return Err(AdminError::Conflict("upstream setup contract changed after preview".into())); }
            admin.upstream_setup_flow(&self.tenant.id,&peer,apply).await.map_err(upstream_operation_error)?;
            admin.upstream_verify(&self.tenant.id,&peer,time::OffsetDateTime::now_utc()).await.map_err(upstream_operation_error)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn legacy_reference_integrations_remain_explicit_diagram_context() {
        let node: flows::Node = serde_json::from_value(json!({"id":"n","kind":"identity_provider","label":"Context","identifier":"","mode":"reference","x":0,"y":0,"settings":{}})).expect("node");
        assert!(!integrated(&node));
    }
    #[test]
    fn apply_only_credentials_are_redacted_and_not_serialized_into_public_specs() {
        let body=json!({"revision":1,"digest":"digest","credentials":{"node":"secret-that-must-stay-private"}});
        let mut request: flows::ApplyRequest=serde_json::from_value(body).expect("apply request");
        assert!(!format!("{request:?}").contains("secret-that-must-stay-private"));
        let credential=request.credentials.get_mut("node").expect("credential");
        assert!(credential.valid());
        let secret=credential.take();
        assert_eq!(secret.as_str(),"secret-that-must-stay-private");
        assert!(!credential.valid(),"taking the credential clears its request slot");
    }
    #[test]
    fn credential_map_requires_exact_changed_managed_provider_nodes() {
        let node: flows::Node=serde_json::from_value(json!({"id":"n","kind":"identity_provider","label":"Corporate","identifier":"corp","mode":"managed","x":0,"y":0,"settings":{}})).expect("node");
        let graph=flows::Graph {schema_version:1,nodes:vec![node],edges:vec![]};
        let step=flows::PlanStep {id:"n".into(),label:"Corporate".into(),kind:"identity_provider".into(),action:"create".into(),scope:"admin.oidc_providers:write".into(),resource_id:None,explanation:String::new(),live:Some(json!({"requires_credential":true}))};
        let mut plan=flows::Plan {flow_id:"flow".into(),revision:1,digest:"digest".into(),applicable:true,steps:vec![step]};
        let mut credentials:HashMap<String,flows::ApplyCredential>=serde_json::from_value(json!({"n":"apply-only"})).expect("map");
        assert!(validate_credentials(&credentials,&plan,&graph).is_ok());
        plan.steps[0].action="unchanged".into();
        assert!(validate_credentials(&credentials,&plan,&graph).is_err());
        plan.steps[0].action="create".into();credentials.clear();
        assert!(validate_credentials(&credentials,&plan,&graph).is_err());
    }
    #[test]
    fn public_provider_input_never_accepts_embedded_credentials() {
        let node: flows::Node = serde_json::from_value(json!({"id":"n","kind":"identity_provider","label":"Corporate","identifier":"corp","mode":"managed","x":0,"y":0,"settings":{"issuer":"https://login.example","client_id":"upstream","client_secret":"must-not-transfer","enabled":true}})).expect("node");
        assert!(provider_input(&node).expect("public input").client_secret.is_none());
    }
}
