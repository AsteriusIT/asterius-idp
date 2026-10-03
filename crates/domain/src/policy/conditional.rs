//! Server-owned conditional facts. No wire properties can populate this snapshot.
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use time::OffsetDateTime;

use super::{Condition, Decision, EvaluationRequest, PolicyDocumentError, RuleSet};
use crate::{ClientId, TenantId};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Sensitivity { Standard, Sensitive, Critical }

impl Sensitivity {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self { Self::Standard => "standard", Self::Sensitive => "sensitive", Self::Critical => "critical" }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ClientSettings {
    pub sensitivity: Option<Sensitivity>,
    pub revision: uuid::Uuid,
}

/// Administrative classification is separate from self-service client metadata.
#[async_trait::async_trait]
pub trait ConditionalSettings: std::fmt::Debug + Send + Sync {
    async fn read(&self, tenant: &TenantId, client: &ClientId) -> Result<Option<ClientSettings>, crate::DomainError>;
    async fn replace(&self, tenant: &TenantId, client: &ClientId, sensitivity: Option<Sensitivity>, expected: Option<uuid::Uuid>) -> Result<ClientSettings, crate::DomainError>;
}

/// Closed source vocabulary; descriptive PEP properties are separate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FactName {
    Assurance,
    AuthenticationAge,
    ApplicationSensitivity,
    NetworkZone,
    DeviceCompliance,
    Groups,
    Roles,
    Grants,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Availability {
    Known,
    Absent,
    Stale,
    Unavailable,
    Invalid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FactValue {
    Text(String),
    Names(BTreeSet<String>),
    AuthenticationTime(OffsetDateTime),
    Resolved,
}

/// An adapter's observation, including its source and explicit validity window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fact {
    pub availability: Availability,
    pub value: Option<FactValue>,
    pub source: String,
    pub observed_at: Option<OffsetDateTime>,
    pub expires_at: Option<OffsetDateTime>,
}

impl Fact {
    #[must_use]
    pub fn missing(availability: Availability, source: &str) -> Self {
        Self {
            availability,
            value: None,
            source: source.to_owned(),
            observed_at: None,
            expires_at: None,
        }
    }

    #[must_use]
    pub fn known(value: FactValue, source: &str, observed_at: OffsetDateTime, expires_at: OffsetDateTime) -> Self {
        Self {
            availability: Availability::Known,
            value: Some(value),
            source: source.to_owned(),
            observed_at: Some(observed_at),
            expires_at: Some(expires_at),
        }
    }

    /// A future observation or missing validity bound cannot confer authority.
    #[must_use]
    pub fn at(&self, now: OffsetDateTime) -> Availability {
        if self.availability != Availability::Known {
            return self.availability;
        }
        match (self.observed_at, self.expires_at, &self.value) {
            (Some(observed), Some(expires), Some(_)) if observed <= now && now < expires => Availability::Known,
            (Some(observed), Some(expires), Some(_)) if observed <= now && expires <= now => Availability::Stale,
            _ => Availability::Invalid,
        }
    }
}

/// Captured once by the server for the exact transaction and application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedAccessContext {
    pub tenant: TenantId,
    pub subject: Option<String>,
    pub client: ClientId,
    pub action: String,
    pub evaluated_at: OffsetDateTime,
    pub policy_revision: String,
    pub acr_revision: String,
    pub client_revision: String,
    pub facts: BTreeMap<FactName, Fact>,
}

impl TrustedAccessContext {
    #[must_use]
    pub fn availability(&self, name: FactName) -> Availability {
        let Some(fact) = self.facts.get(&name) else { return Availability::Absent; };
        let availability = fact.at(self.evaluated_at);
        if availability != Availability::Known { return availability; }
        let valid = match (name, fact.value.as_ref()) {
            (FactName::Assurance, Some(FactValue::Text(value))) => !value.is_empty() && value.len() <= 256,
            (FactName::AuthenticationAge, Some(FactValue::AuthenticationTime(value))) => *value <= self.evaluated_at,
            (FactName::ApplicationSensitivity, Some(FactValue::Text(value))) => matches!(value.as_str(), "standard" | "sensitive" | "critical"),
            (FactName::DeviceCompliance, Some(FactValue::Text(value))) => matches!(value.as_str(), "compliant" | "non_compliant" | "unknown"),
            (FactName::NetworkZone, Some(FactValue::Names(values))) => values.len() <= 64 && values.iter().all(|value| !value.is_empty() && value.len() <= 128),
            (FactName::Groups | FactName::Roles | FactName::Grants, Some(FactValue::Resolved)) => true,
            _ => false,
        };
        if valid && !fact.source.is_empty() && fact.source.len() <= 128 { Availability::Known } else { Availability::Invalid }
    }

    #[must_use]
    pub fn value(&self, name: FactName) -> Option<&FactValue> {
        (self.availability(name) == Availability::Known)
            .then(|| self.facts.get(&name).and_then(|fact| fact.value.as_ref()))
            .flatten()
    }
}

/// Typed predicates read only the separately bound server snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustedPredicate {
    Sensitivity(String),
    NetworkZone(String),
    AuthenticationAgeAtMost(u32),
    DeviceCompliance(String),
}

impl TrustedPredicate {
    pub(super) fn parse(name: &str, value: &Value) -> Result<Option<Self>, PolicyDocumentError> {
        let invalid = || PolicyDocumentError::Malformed("invalid trusted conditional predicate");
        Ok(Some(match name {
            "application_sensitivity" => match value.as_str() {
                Some(value @ ("standard" | "sensitive" | "critical")) => Self::Sensitivity(value.to_owned()),
                _ => return Err(invalid()),
            },
            "network_zone" => {
                let value = value.as_str().filter(|value| !value.is_empty() && value.len() <= 128 && value.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))).ok_or_else(invalid)?;
                Self::NetworkZone(value.to_owned())
            }
            "authentication_age_at_most" => {
                let value = value.as_u64().filter(|value| (60..=86400).contains(value)).ok_or_else(invalid)?;
                Self::AuthenticationAgeAtMost(u32::try_from(value).map_err(|_| invalid())?)
            }
            "device_compliance" => match value.as_str() {
                Some(value @ ("compliant" | "non_compliant" | "unknown")) => Self::DeviceCompliance(value.to_owned()),
                _ => return Err(invalid()),
            },
            _ => return Ok(None),
        }))
    }

    #[must_use]
    pub const fn fact(&self) -> FactName {
        match self {
            Self::Sensitivity(_) => FactName::ApplicationSensitivity,
            Self::NetworkZone(_) => FactName::NetworkZone,
            Self::AuthenticationAgeAtMost(_) => FactName::AuthenticationAge,
            Self::DeviceCompliance(_) => FactName::DeviceCompliance,
        }
    }

    #[must_use]
    pub fn holds(&self, trusted: &TrustedAccessContext) -> bool {
        match (self, trusted.value(self.fact())) {
            (Self::Sensitivity(expected) | Self::DeviceCompliance(expected), Some(FactValue::Text(actual))) => expected == actual,
            (Self::NetworkZone(expected), Some(FactValue::Names(names))) => names.contains(expected),
            (Self::AuthenticationAgeAtMost(limit), Some(FactValue::AuthenticationTime(authenticated))) => {
                let age = trusted.evaluated_at - *authenticated;
                age >= time::Duration::ZERO && age <= time::Duration::seconds(i64::from(*limit))
            }
            _ => false,
        }
    }

    pub(super) fn to_json(&self) -> Value {
        match self {
            Self::Sensitivity(value) => json!({"application_sensitivity": value}),
            Self::NetworkZone(value) => json!({"network_zone": value}),
            Self::AuthenticationAgeAtMost(value) => json!({"authentication_age_at_most": value}),
            Self::DeviceCompliance(value) => json!({"device_compliance": value}),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementMode { Active, ReportOnly }

/// A bounded scope is selected from server identities, never a caller property.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConditionalScope {
    pub mode: EnforcementMode,
    pub id: String,
    pub clients: BTreeSet<ClientId>,
    pub actions: BTreeSet<String>,
    pub required_facts: BTreeSet<FactName>,
    pub rules: RuleSet,
    pub assurance_remedy: Option<String>,
    pub network_zones: BTreeMap<String, Vec<ipnet::IpNet>>,
}

fn referenced(condition: &Condition, required: &mut BTreeSet<FactName>) {
    match condition {
        Condition::All(children) | Condition::Any(children) => {
            for child in children { referenced(child, required); }
        }
        Condition::Not(child) => referenced(child, required),
        Condition::Trusted(predicate) => { required.insert(predicate.fact()); }
        Condition::AcrAtLeast(_) => { required.insert(FactName::Assurance); }
        Condition::Group(_) => { required.insert(FactName::Groups); }
        Condition::Role { .. } => { required.insert(FactName::Roles); }
        Condition::Grant(_) => { required.insert(FactName::Grants); }
        Condition::Attribute { .. } => {}
    }
}

impl ConditionalScope {
    #[must_use]
    pub fn required(&self) -> BTreeSet<FactName> {
        let mut required = self.required_facts.clone();
        for rule in self.rules.rules() {
            if let Some(condition) = &rule.when { referenced(condition, &mut required); }
        }
        required
    }

    #[must_use]
    pub fn applies(&self, client: &ClientId, action: &str) -> bool {
        self.clients.contains(client) && self.actions.contains(action)
    }

    /// A mandatory availability guard precedes every boolean rule and remedy.
    #[must_use]
    pub fn evaluate(&self, request: &EvaluationRequest) -> Decision {
        let Some(trusted) = request.context.trusted() else {
            return Decision::default_deny("conditional transaction evidence absent");
        };
        if !self.applies(&trusted.client, &trusted.action) || self.required().iter().any(|name| trusted.availability(*name) != Availability::Known) {
            return Decision::default_deny("conditional required facts unavailable");
        }
        self.rules.evaluate(request)
    }

    /// A hypothetical remedy is returned only if fresh supported authentication
    /// would permit. It is a denial with a remedy, never an authorization.
    #[must_use]
    pub fn remedy(&self, request: &EvaluationRequest, ladder: &crate::AcrPolicy) -> Option<String> {
        if self.evaluate(request).permit() { return None; }
        let target = self.assurance_remedy.as_deref()?;
        if !ladder.can_produce(target) { return None; }
        let mut trusted = request.context.trusted()?.clone();
        if trusted.subject.is_none() || !self.applies(&trusted.client, &trusted.action) { return None; }
        let required = self.required();
        if !required.contains(&FactName::Assurance) && !required.contains(&FactName::AuthenticationAge) { return None; }
        if required.iter().any(|name| !matches!(name, FactName::Assurance | FactName::AuthenticationAge) && trusted.availability(*name) != Availability::Known) { return None; }
        let now = trusted.evaluated_at;
        let expires = now + time::Duration::seconds(1);
        trusted.facts.insert(FactName::Assurance, Fact::known(FactValue::Text(target.to_owned()), "hypothetical_authentication", now, expires));
        trusted.facts.insert(FactName::AuthenticationAge, Fact::known(FactValue::AuthenticationTime(now), "hypothetical_authentication", now, expires));
        let mut candidate = request.clone();
        candidate.context = candidate.context.with_acr(Some(target.to_owned()), ladder.levels().iter().map(|level| level.value().to_owned())).with_trusted(trusted);
        self.evaluate(&candidate).permit().then(|| target.to_owned())
    }

    pub(super) fn parse(value: &Value) -> Result<Self, PolicyDocumentError> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            mode: EnforcementMode,
            id: String,
            clients: Vec<String>,
            actions: Vec<String>,
            #[serde(default)]
            required_facts: Vec<FactName>,
            rules: Vec<Value>,
            assurance_remedy: Option<String>,
            #[serde(default)]
            network_zones: BTreeMap<String, Vec<ipnet::IpNet>>,
        }
        let wire: Wire = serde_json::from_value(value.clone()).map_err(|_| PolicyDocumentError::Malformed("invalid conditional scope"))?;
        let bounded = |values: &[String], max: usize| !values.is_empty() && values.len() <= max && values.iter().all(|value| !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)) && values.iter().collect::<BTreeSet<_>>().len() == values.len();
        if wire.id.is_empty() || wire.id.len() > 128 || wire.id.chars().any(char::is_control) || !bounded(&wire.clients, 64) || !bounded(&wire.actions, 32) || wire.required_facts.len() > 32 || wire.required_facts.iter().collect::<BTreeSet<_>>().len() != wire.required_facts.len() || wire.assurance_remedy.as_ref().is_some_and(|value| value.is_empty() || value.len() > 256 || value.chars().any(char::is_control)) {
            return Err(PolicyDocumentError::Malformed("conditional scope exceeds bounds or repeats values"));
        }
        const ACTIONS: &[&str] = &["authorize", "authorization_code", "refresh_token", "device_code", "ciba", "token_exchange", "client_credentials", "jwt_bearer", "id_jag", "access_evaluation"];
        if wire.actions.iter().any(|action| !ACTIONS.contains(&action.as_str())) {
            return Err(PolicyDocumentError::Malformed("unsupported conditional enforcement action"));
        }
        if wire.network_zones.len() > 64 || wire.network_zones.iter().any(|(name, networks)| name.is_empty() || name.len() > 128 || !name.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')) || networks.is_empty() || networks.len() > 16 || networks.iter().collect::<BTreeSet<_>>().len() != networks.len()) {
            return Err(PolicyDocumentError::Malformed("invalid bounded network zones"));
        }
        Ok(Self {
            mode: wire.mode,
            id: wire.id,
            clients: wire.clients.into_iter().map(ClientId::new).collect(),
            actions: wire.actions.into_iter().collect(),
            required_facts: wire.required_facts.into_iter().collect(),
            rules: RuleSet::conditional_rules(&json!({"version":1,"rules":wire.rules}))?,
            assurance_remedy: wire.assurance_remedy,
            network_zones: wire.network_zones,
        })
    }

    pub(super) fn to_json(&self) -> Value {
        json!({"mode":self.mode,"id": self.id, "clients": self.clients.iter().map(ClientId::as_str).collect::<Vec<_>>(), "actions": self.actions, "required_facts": self.required_facts, "rules": self.rules.to_json()["rules"], "assurance_remedy": self.assurance_remedy, "network_zones": self.network_zones})
    }
}

pub(super) fn contains_trusted(condition: &Condition) -> bool {
    match condition {
        Condition::All(children) | Condition::Any(children) => children.iter().any(contains_trusted),
        Condition::Not(child) => contains_trusted(child),
        Condition::Trusted(_) => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{Action, Context, Properties, Resource, Subject};

    fn scope(when: Value) -> ConditionalScope {
        ConditionalScope::parse(&json!({"mode":"active","id":"protected","clients":["app"],"actions":["refresh_token"],"rules":[{"id":"permit","effect":"permit","when":when}],"assurance_remedy":null})).expect("scope")
    }

    fn request(facts: BTreeMap<FactName, Fact>) -> EvaluationRequest {
        let trusted = TrustedAccessContext { tenant: TenantId::new("one"), subject: Some("alice".into()), client: ClientId::new("app"), action: "refresh_token".into(), evaluated_at: OffsetDateTime::UNIX_EPOCH, policy_revision: "revision".into(), acr_revision: "acr".into(), client_revision: "client".into(), facts };
        EvaluationRequest::new(Subject::new("user", "alice", Properties::empty()).expect("subject"), Action::new("read", Properties::empty()).expect("action"), Resource::new("application", "app", Properties::empty()).expect("resource"), Context::default().with_trusted(trusted))
    }

    #[test]
    fn conditional_absent_device_cannot_be_bypassed_by_not_or_any() {
        for condition in [json!({"not":{"device_compliance":"compliant"}}), json!({"any":[{"device_compliance":"compliant"},{"all":[]}]})] {
            assert!(!scope(condition).evaluate(&request(BTreeMap::new())).permit());
        }
        let now = OffsetDateTime::UNIX_EPOCH;
        let known = Fact::known(FactValue::Text("compliant".into()), "device_registry", now, now + time::Duration::seconds(300));
        assert!(scope(json!({"device_compliance":"compliant"})).evaluate(&request(BTreeMap::from([(FactName::DeviceCompliance, known.clone())]))).permit());
        let expired = Fact { expires_at: Some(now), ..known };
        assert!(!scope(json!({"not":{"device_compliance":"non_compliant"}})).evaluate(&request(BTreeMap::from([(FactName::DeviceCompliance, expired)]))).permit());
    }

    #[test]
    fn conditional_authentication_age_uses_original_time_and_rejects_future() {
        let now = OffsetDateTime::UNIX_EPOCH;
        let original = Fact::known(FactValue::AuthenticationTime(now - time::Duration::seconds(61)), "grant_authentication", now, now + time::Duration::seconds(300));
        let rule = scope(json!({"authentication_age_at_most":60}));
        assert!(!rule.evaluate(&request(BTreeMap::from([(FactName::AuthenticationAge, original.clone())]))).permit());
        let fresh = Fact { value: Some(FactValue::AuthenticationTime(now)), ..original.clone() };
        assert!(rule.evaluate(&request(BTreeMap::from([(FactName::AuthenticationAge, fresh)]))).permit());
        let future = Fact { value: Some(FactValue::AuthenticationTime(now + time::Duration::seconds(1))), ..original };
        assert!(!scope(json!({"not":{"authentication_age_at_most":60}})).evaluate(&request(BTreeMap::from([(FactName::AuthenticationAge, future)]))).permit());
    }

    #[test]
    fn conditional_scope_round_trips_and_rejects_overlap_and_legacy_trusted_predicates() {
        let protected = scope(json!({"application_sensitivity":"critical"})).to_json();
        let document = json!({"version":1,"rules":[],"conditional_scopes":[protected.clone()]});
        let policy = RuleSet::from_json(&document).expect("policy");
        assert_eq!(RuleSet::from_json(&policy.to_json()).expect("round trip"), policy);
        assert!(RuleSet::from_json(&json!({"version":1,"rules":[],"conditional_scopes":[protected.clone(),protected]})).is_err());
        assert!(RuleSet::from_json(&json!({"version":1,"rules":[{"id":"bypass","effect":"permit","when":{"device_compliance":"compliant"}}]})).is_err());
        assert!(scope(json!({"application_sensitivity":"critical"})).evaluate(&request(BTreeMap::new())).context().acr_values().is_empty());
    }
}
