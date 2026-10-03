//! Administrative examples are isolated from production context adapters.
//! Responses identify source/availability, never directory values or literals.
use std::collections::{BTreeMap, BTreeSet};

use asterius_domain::AcrPolicy;
use asterius_domain::policy::conditional::{
    Availability, ClientSettings, EnforcementMode, Fact, FactName, FactValue, TrustedAccessContext,
};
use asterius_domain::policy::{Decision, EvaluationRequest, StoredPolicy, explanation};
use serde_json::{Value, json};
use time::{Duration, OffsetDateTime};

pub const ACTIONS: [&str; 9] = [
    "authorize",
    "authorization_code",
    "refresh_token",
    "device_code",
    "ciba",
    "token_exchange",
    "client_credentials",
    "jwt_bearer",
    "access_evaluation",
];
const EXAMPLE_SOURCE: &str = "hypothetical_operator_example";

#[derive(Debug, Clone)]
pub struct TrustedExamples(BTreeMap<FactName, (Availability, Option<FactValue>)>);

impl TrustedExamples {
    /// Parse a closed administrative dialect, never the PEP properties dialect.
    pub fn parse(value: &Value) -> Result<Self, crate::AdminError> {
        let invalid = || {
            crate::AdminError::Invalid("invalid hypothetical trusted context example".to_owned())
        };
        let object = value
            .as_object()
            .filter(|object| object.len() <= 5)
            .ok_or_else(invalid)?;
        let mut examples = BTreeMap::new();
        for (name, value) in object {
            let name = match name.as_str() {
                "assurance" => FactName::Assurance,
                "authentication_age" => FactName::AuthenticationAge,
                "application_sensitivity" => FactName::ApplicationSensitivity,
                "network_zone" => FactName::NetworkZone,
                "device_compliance" => FactName::DeviceCompliance,
                _ => return Err(invalid()),
            };
            let object = value.as_object().ok_or_else(invalid)?;
            let availability: Availability =
                serde_json::from_value(object.get("availability").cloned().ok_or_else(invalid)?)
                    .map_err(|_| invalid())?;
            if object.len()
                != if availability == Availability::Known {
                    2
                } else {
                    1
                }
                || object
                    .keys()
                    .any(|key| !matches!(key.as_str(), "availability" | "value"))
            {
                return Err(invalid());
            }
            let parsed = if availability == Availability::Known {
                let value = object.get("value").ok_or_else(invalid)?;
                Some(parse_known_value(name, value)?)
            } else {
                None
            };
            examples.insert(name, (availability, parsed));
        }
        Ok(Self(examples))
    }

    fn apply(&self, trusted: &mut TrustedAccessContext, ladder: &AcrPolicy) {
        for (name, (availability, value)) in &self.0 {
            let mut value = value.clone();
            if *name == FactName::AuthenticationAge {
                value = match value.as_ref() {
                    Some(FactValue::Text(seconds)) => seconds.parse::<i64>().ok().map(|seconds| {
                        FactValue::AuthenticationTime(
                            trusted.evaluated_at - Duration::seconds(seconds),
                        )
                    }),
                    _ => None,
                };
            }
            let supported = *availability != Availability::Known
                || *name != FactName::Assurance
                || matches!(value.as_ref(),Some(FactValue::Text(value)) if ladder.can_produce(value));
            let fact = if *availability == Availability::Known && supported {
                match value {
                    Some(value) => Fact::known(
                        value,
                        EXAMPLE_SOURCE,
                        trusted.evaluated_at,
                        trusted.evaluated_at + Duration::seconds(1),
                    ),
                    None => Fact::missing(Availability::Invalid, EXAMPLE_SOURCE),
                }
            } else {
                Fact::missing(
                    if supported {
                        *availability
                    } else {
                        Availability::Invalid
                    },
                    EXAMPLE_SOURCE,
                )
            };
            trusted.facts.insert(*name, fact);
        }
    }
}

fn parse_known_value(name: FactName, value: &Value) -> Result<FactValue, crate::AdminError> {
    let invalid =
        || crate::AdminError::Invalid("invalid hypothetical trusted context example".to_owned());
    Ok(match name {
        FactName::Assurance => FactValue::Text(
            value
                .as_str()
                .filter(|value| {
                    !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
                })
                .ok_or_else(invalid)?
                .to_owned(),
        ),
        // Stored as relative seconds until bound to one server clock.
        FactName::AuthenticationAge => FactValue::Text(
            value
                .as_u64()
                .filter(|value| *value <= 604_800)
                .ok_or_else(invalid)?
                .to_string(),
        ),
        FactName::ApplicationSensitivity => FactValue::Text(
            value
                .as_str()
                .filter(|value| matches!(*value, "standard" | "sensitive" | "critical"))
                .ok_or_else(invalid)?
                .to_owned(),
        ),
        FactName::DeviceCompliance => FactValue::Text(
            value
                .as_str()
                .filter(|value| matches!(*value, "compliant" | "non_compliant" | "unknown"))
                .ok_or_else(invalid)?
                .to_owned(),
        ),
        FactName::NetworkZone => {
            let values = value
                .as_array()
                .filter(|values| values.len() <= 64)
                .ok_or_else(invalid)?;
            let names = values
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .filter(|value| {
                            !value.is_empty()
                                && value.len() <= 128
                                && value.bytes().all(|byte| {
                                    byte.is_ascii_alphanumeric()
                                        || matches!(byte, b'-' | b'_' | b'.')
                                })
                        })
                        .map(str::to_owned)
                        .ok_or_else(invalid)
                })
                .collect::<Result<BTreeSet<_>, _>>()?;
            if names.len() != values.len() {
                return Err(invalid());
            }
            FactValue::Names(names)
        }
        _ => return Err(invalid()),
    })
}

/// Call only after all current tenant directory facts have resolved successfully.
#[must_use]
pub fn current_facts(
    classification: Option<&ClientSettings>,
    now: OffsetDateTime,
) -> BTreeMap<FactName, Fact> {
    let mut facts = BTreeMap::new();
    for name in [
        FactName::Assurance,
        FactName::AuthenticationAge,
        FactName::NetworkZone,
    ] {
        facts.insert(
            name,
            Fact::missing(Availability::Absent, "no_user_transaction_selected"),
        );
    }
    facts.insert(
        FactName::DeviceCompliance,
        Fact::missing(Availability::Unavailable, "no_verified_device_adapter"),
    );
    facts.insert(
        FactName::ApplicationSensitivity,
        classification
            .and_then(|settings| settings.sensitivity)
            .map_or_else(
                || Fact::missing(Availability::Absent, "administrative_client_settings"),
                |value| {
                    Fact::known(
                        FactValue::Text(value.as_str().to_owned()),
                        "administrative_client_settings",
                        now,
                        now + Duration::seconds(1),
                    )
                },
            ),
    );
    for name in [FactName::Groups, FactName::Roles, FactName::Grants] {
        facts.insert(
            name,
            Fact::known(
                FactValue::Resolved,
                "current_tenant_directory",
                now,
                now + Duration::seconds(1),
            ),
        );
    }
    facts
}

/// Evaluate hypothetical context over real bound identities, without authority.
/// Report-only cannot override a base denial or change the legacy decision.
#[must_use]
pub fn evaluate(
    policy: Option<&StoredPolicy>,
    original: &EvaluationRequest,
    mut trusted: TrustedAccessContext,
    examples: Option<&TrustedExamples>,
    ladder: &AcrPolicy,
) -> (Decision, Value) {
    if let Some(examples) = examples {
        examples.apply(&mut trusted, ladder);
    }
    let mut request = original.clone();
    let assurance = match trusted.value(FactName::Assurance) {
        Some(FactValue::Text(value)) => Some(value.clone()),
        _ => None,
    };
    request.context = request
        .context
        .with_acr(
            assurance,
            ladder.levels().iter().map(|level| level.value().to_owned()),
        )
        .with_trusted(trusted.clone());
    let legacy = explanation::evaluate(policy, original, "admin_policy_simulation");
    let active = policy.is_some_and(|policy| {
        policy.rules.conditional_scopes().iter().any(|scope| {
            scope.mode == EnforcementMode::Active && scope.applies(&trusted.client, &trusted.action)
        })
    });
    let mut decision = if active {
        explanation::evaluate(policy, &request, "admin_policy_simulation")
    } else {
        legacy.clone()
    };
    let mut scopes = Vec::new();
    if let Some(policy) = policy {
        for scope in policy
            .rules
            .conditional_scopes()
            .iter()
            .filter(|scope| scope.applies(&trusted.client, &trusted.action))
        {
            let result = scope.evaluate(&request);
            let required = scope.required_for(&request);
            let missing = required
                .iter()
                .any(|name| trusted.availability(*name) != Availability::Known);
            let remedy = scope.remedy(&request, ladder);
            scopes.push(json!({"id":scope.id,"mode":scope.mode,"would_decision":result.permit(),"required_facts":required,"missing_required_evidence":missing,"assurance_remedy":remedy,"conditions":explanation::explain(Some(&StoredPolicy{rules:scope.rules.clone(),updated_at:policy.updated_at}),&request,"admin_conditional_simulation").rules}));
            if scope.mode == EnforcementMode::Active && !result.permit() && decision.permit() {
                decision =
                    Decision::default_deny("conditional active scope would deny").with_explanation(
                        explanation::explain(Some(policy), &request, "admin_policy_simulation"),
                    );
            }
        }
    }
    let facts = trusted.facts.keys().map(|name|json!({"name":name,"availability":trusted.availability(*name),"source":trusted.facts.get(name).map_or("unavailable",|fact|fact.source.as_str()),"hypothetical":trusted.facts.get(name).is_some_and(|fact|fact.source==EXAMPLE_SOURCE)})).collect::<Vec<_>>();
    let response = json!({"enforcement_action":trusted.action,"legacy_would_permit":legacy.permit(),"active_would_permit":decision.permit(),"policy_revision":trusted.policy_revision,"evaluated_policy_revision":policy.map(|policy|explanation::revision(&policy.rules)),"acr_revision":trusted.acr_revision,"client_revision":trusted.client_revision,"facts":facts,"scopes":scopes});
    (decision, response)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn conditional_examples_reject_authority_overrides_and_value_bearing_missing_states() {
        for value in [
            json!({"groups":{"availability":"known","value":["private-canary"]}}),
            json!({"device_compliance":{"availability":"stale","value":"private-canary"}}),
            json!({"network_zone":{"availability":"known","value":["private-canary","private-canary"]}}),
            json!({"authentication_age":{"availability":"known","value":604_801}}),
            json!({"assurance":{"availability":"known","value":"a","source":"verified"}}),
        ] {
            let error = TrustedExamples::parse(&value).expect_err("invalid example");
            assert!(!error.to_string().contains("private-canary"));
        }
        assert!(TrustedExamples::parse(&json!({"authentication_age":{"availability":"known","value":0},"device_compliance":{"availability":"absent"}})).is_ok());
    }
    fn fixture(
        mode: &str,
        base: &str,
        condition: &Value,
    ) -> (StoredPolicy, EvaluationRequest, TrustedAccessContext) {
        use asterius_domain::policy::{Action, Context, Properties, Resource, RuleSet, Subject};
        let now = OffsetDateTime::UNIX_EPOCH;
        let policy = StoredPolicy {
            rules: RuleSet::from_json(&json!({"version":1,"rules":[{"id":"base","effect":base}],"conditional_scopes":[{"id":"selected","mode":mode,"clients":["app"],"actions":["refresh_token"],"rules":[{"id":"restricted","effect":"permit","when":condition}]}]})).expect("fixture policy"),
            updated_at: now,
        };
        let subject = Subject::new("user", "alice", Properties::empty())
            .expect("fixture subject")
            .with_groups(["private-directory-canary".to_owned()]);
        let request = EvaluationRequest::new(
            subject,
            Action::new("read", Properties::empty()).expect("fixture action"),
            Resource::new("resource", "inventory", Properties::empty()).expect("fixture resource"),
            Context::default(),
        );
        let trusted = TrustedAccessContext {
            tenant: asterius_domain::TenantId::new("tenant"),
            subject: Some("alice".to_owned()),
            client: asterius_domain::ClientId::new("app"),
            action: "refresh_token".to_owned(),
            evaluated_at: now,
            policy_revision: "revision".to_owned(),
            acr_revision: "acr".to_owned(),
            client_revision: "client".to_owned(),
            facts: current_facts(None, now),
        };
        (policy, request, trusted)
    }

    #[test]
    fn conditional_simulation_missing_evidence_cannot_be_negated_and_report_only_cannot_grant() {
        let ladder = AcrPolicy::default();
        for condition in [
            json!({"not":{"device_compliance":"compliant"}}),
            json!({"any":[{"device_compliance":"compliant"},{"all":[]}]}),
        ] {
            let (policy, request, trusted) = fixture("active", "permit", &condition);
            let (decision, response) = evaluate(Some(&policy), &request, trusted, None, &ladder);
            assert!(!decision.permit());
            assert_eq!(response["legacy_would_permit"], true);
            assert_eq!(response["scopes"][0]["missing_required_evidence"], true);
            assert!(!response.to_string().contains("private-directory-canary"));
        }
        for base in ["permit", "deny"] {
            let (policy, request, trusted) = fixture(
                "report_only",
                base,
                &json!({"device_compliance":"compliant"}),
            );
            let examples = TrustedExamples::parse(
                &json!({"device_compliance":{"availability":"known","value":"compliant"}}),
            )
            .expect("example");
            let (decision, response) =
                evaluate(Some(&policy), &request, trusted, Some(&examples), &ladder);
            assert_eq!(decision.permit(), base == "permit");
            assert_eq!(response["scopes"][0]["would_decision"], true);
            assert_eq!(
                response["facts"]
                    .as_array()
                    .expect("facts")
                    .iter()
                    .find(|fact| fact["name"] == "device_compliance")
                    .expect("device")["source"],
                EXAMPLE_SOURCE
            );
        }
    }

    #[test]
    fn conditional_simulation_age_missing_states_and_exact_identity_boundary_remain_distinct() {
        let ladder = AcrPolicy::default();
        let (policy, request, trusted) = fixture(
            "active",
            "permit",
            &json!({"authentication_age_at_most":60}),
        );
        for (seconds, permit) in [(0, true), (61, false)] {
            let examples = TrustedExamples::parse(
                &json!({"authentication_age":{"availability":"known","value":seconds}}),
            )
            .expect("example");
            assert_eq!(
                evaluate(
                    Some(&policy),
                    &request,
                    trusted.clone(),
                    Some(&examples),
                    &ladder
                )
                .0
                .permit(),
                permit
            );
        }
        for state in ["absent", "stale", "invalid", "unavailable"] {
            let examples = TrustedExamples::parse(&json!({"assurance":{"availability":state}}))
                .expect("example");
            let (_, response) = evaluate(
                Some(&policy),
                &request,
                trusted.clone(),
                Some(&examples),
                &ladder,
            );
            assert_eq!(
                response["facts"]
                    .as_array()
                    .expect("facts")
                    .iter()
                    .find(|fact| fact["name"] == "assurance")
                    .expect("assurance")["availability"],
                state
            );
        }
        let mut other = trusted.clone();
        other.action = "authorization_code".to_owned();
        let (decision, response) = evaluate(Some(&policy), &request, other, None, &ladder);
        assert!(decision.permit());
        assert!(response["scopes"].as_array().expect("scopes").is_empty());
        let mut other = trusted;
        other.client = asterius_domain::ClientId::new("other");
        assert!(
            evaluate(Some(&policy), &request, other, None, &ladder)
                .0
                .permit()
        );
        assert!(request.context.trusted().is_none());
    }
    #[test]
    fn conditional_simulation_remedy_uses_current_attainable_ladder_and_never_reveals_literals() {
        let ladder = AcrPolicy::default();
        let (mut policy, request, trusted) = fixture(
            "active",
            "permit",
            &json!({"all":[{"acr_at_least":"urn:asterius:acr:passkey-uv"},{"authentication_age_at_most":60}]}),
        );
        let mut document = policy.rules.to_json();
        document["conditional_scopes"][0]["assurance_remedy"] =
            json!("urn:asterius:acr:passkey-uv");
        policy.rules =
            asterius_domain::policy::RuleSet::from_json(&document).expect("remedy policy");
        let (decision, response) =
            evaluate(Some(&policy), &request, trusted.clone(), None, &ladder);
        assert!(!decision.permit());
        assert_eq!(
            response["scopes"][0]["assurance_remedy"],
            "urn:asterius:acr:passkey-uv"
        );
        let examples = TrustedExamples::parse(
            &json!({"assurance":{"availability":"known","value":"private-unsupported-level"}}),
        )
        .expect("bounded example");
        let (_, response) = evaluate(Some(&policy), &request, trusted, Some(&examples), &ladder);
        assert_eq!(
            response["facts"]
                .as_array()
                .expect("facts")
                .iter()
                .find(|fact| fact["name"] == "assurance")
                .expect("assurance")["availability"],
            "invalid"
        );
        assert!(!response.to_string().contains("private-unsupported-level"));
    }
}
