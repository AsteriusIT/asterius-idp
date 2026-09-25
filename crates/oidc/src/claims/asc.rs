//! Bounded OpenID ASC draft-02 projection. The consented request owns the
//! definitions and rules; no response path reads the client's original input.

use super::{
    ClaimRequest, ClaimsLocales, ClaimsRequestError, ReleasableClaim, parse_entry, project,
};
use asterius_domain::User;
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

/// Exact advertised transformation set. Date and array overloads are not
/// implemented; a request with an unsupported argument type is rejected.
pub const FUNCTIONS: &[&str] = &[
    "eq",
    "contains",
    "starts_with",
    "ends_with",
    "gt",
    "gte",
    "lt",
    "lte",
];
pub const MAX_COUNT: usize = 8;
pub const MAX_DEPTH: usize = 2;
const MAX_RULES: usize = 8;

#[derive(Debug, Clone, PartialEq)]
pub(super) struct AscRequest {
    definitions: BTreeMap<String, Definition>,
    id_token: BTreeMap<String, ClaimRequest>,
    userinfo: BTreeMap<String, ClaimRequest>,
    id_rules: Vec<Rule>,
    user_rules: Vec<Rule>,
}

#[derive(Debug, Clone, PartialEq)]
struct Definition {
    base: ReleasableClaim,
    functions: Vec<Function>,
}

#[derive(Debug, Clone, PartialEq)]
struct Function {
    name: String,
    argument: Value,
}

#[derive(Debug, Clone, PartialEq)]
struct Rule {
    loc: String,
    expected: Option<Vec<Value>>,
    omit: Option<Vec<String>>,
}

fn invalid() -> ClaimsRequestError {
    ClaimsRequestError::UnsupportedAdvancedClaims
}

fn direct_pointer(raw: &str) -> Result<String, ClaimsRequestError> {
    let Some(name) = raw.strip_prefix('/') else {
        return Err(invalid());
    };
    if name.is_empty()
        || name.contains('/')
        || name.contains('~')
        || (ReleasableClaim::parse(name).is_none() && !name.starts_with(':'))
    {
        return Err(invalid());
    }
    Ok(name.to_owned())
}

fn scalar(value: &Value) -> bool {
    value.is_string() || value.is_boolean() || value.is_number()
}

impl AscRequest {
    pub(super) fn parse(root: &Map<String, Value>) -> Result<Option<Self>, ClaimsRequestError> {
        let aliases_present = ["id_token", "userinfo"].into_iter().any(|section| {
            root.get(section)
                .and_then(Value::as_object)
                .is_some_and(|members| members.keys().any(|name| name.starts_with(':')))
        });
        let Some(raw) = root.get("_asc") else {
            return if aliases_present {
                Err(invalid())
            } else {
                Ok(None)
            };
        };
        let asc = raw.as_object().ok_or_else(invalid)?;
        if asc.is_empty()
            || asc
                .keys()
                .any(|key| key != "transformed_claims" && key != "sao")
        {
            return Err(invalid());
        }
        let mut definitions = BTreeMap::new();
        if let Some(raw) = asc.get("transformed_claims") {
            let values = raw.as_object().ok_or_else(invalid)?;
            if values.is_empty() || values.len() > MAX_COUNT {
                return Err(invalid());
            }
            for (alias, raw) in values {
                if alias.is_empty()
                    || alias.len() > 64
                    || !alias
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
                {
                    return Err(invalid());
                }
                let definition = raw.as_object().ok_or_else(invalid)?;
                if definition.len() != 2
                    || !definition.contains_key("claim")
                    || !definition.contains_key("fn")
                {
                    return Err(invalid());
                }
                let base = definition
                    .get("claim")
                    .and_then(Value::as_str)
                    .and_then(ReleasableClaim::parse)
                    .ok_or_else(invalid)?;
                let functions = definition
                    .get("fn")
                    .and_then(Value::as_array)
                    .ok_or_else(invalid)?;
                if functions.is_empty() || functions.len() > MAX_DEPTH {
                    return Err(invalid());
                }
                let mut parsed = Vec::with_capacity(functions.len());
                for (index, function) in functions.iter().enumerate() {
                    let call = function.as_array().ok_or_else(invalid)?;
                    if call.len() != 2 {
                        return Err(invalid());
                    }
                    let name = call[0].as_str().ok_or_else(invalid)?;
                    let argument = &call[1];
                    let valid = match name {
                        "eq" => scalar(argument),
                        "contains" | "starts_with" | "ends_with" => argument.is_string(),
                        "gt" | "gte" | "lt" | "lte" => argument.is_number(),
                        _ => false,
                    };
                    if !valid {
                        return Err(invalid());
                    }
                    // Every supported function returns a boolean. A second
                    // function can therefore only compare that boolean.
                    if index > 0 && (name != "eq" || !argument.is_boolean()) {
                        return Err(invalid());
                    }
                    parsed.push(Function {
                        name: name.to_owned(),
                        argument: argument.clone(),
                    });
                }
                definitions.insert(
                    alias.clone(),
                    Definition {
                        base,
                        functions: parsed,
                    },
                );
            }
        }
        let id_token = parse_aliases(root, "id_token", &definitions)?;
        let userinfo = parse_aliases(root, "userinfo", &definitions)?;
        let (id_rules, user_rules) = match asc.get("sao") {
            None => (Vec::new(), Vec::new()),
            Some(raw) => {
                let sections = raw.as_object().ok_or_else(invalid)?;
                if sections.is_empty()
                    || sections
                        .keys()
                        .any(|key| key != "id_token" && key != "userinfo")
                {
                    return Err(invalid());
                }
                (
                    parse_rules(sections.get("id_token"))?,
                    parse_rules(sections.get("userinfo"))?,
                )
            }
        };
        for (rules, aliases) in [(&id_rules, &id_token), (&user_rules, &userinfo)] {
            for rule in rules {
                for name in
                    std::iter::once(&rule.loc).chain(rule.omit.as_ref().into_iter().flatten())
                {
                    if let Some(alias) = name.strip_prefix(':')
                        && !aliases.contains_key(alias)
                    {
                        return Err(invalid());
                    }
                }
            }
        }
        Ok(Some(Self {
            definitions,
            id_token,
            userinfo,
            id_rules,
            user_rules,
        }))
    }

    pub(super) fn add_json(&self, root: &mut Map<String, Value>) {
        let mut asc = Map::new();
        if !self.definitions.is_empty() {
            let definitions = self
                .definitions
                .iter()
                .map(|(name, definition)| {
                    let functions = definition
                        .functions
                        .iter()
                        .map(|call| json!([call.name, call.argument]))
                        .collect::<Vec<_>>();
                    (
                        name.clone(),
                        json!({"claim": definition.base.as_str(), "fn": functions}),
                    )
                })
                .collect();
            asc.insert("transformed_claims".to_owned(), Value::Object(definitions));
        }
        let mut sao = Map::new();
        if !self.id_rules.is_empty() {
            sao.insert("id_token".to_owned(), rules_json(&self.id_rules));
        }
        if !self.user_rules.is_empty() {
            sao.insert("userinfo".to_owned(), rules_json(&self.user_rules));
        }
        if !sao.is_empty() {
            asc.insert("sao".to_owned(), Value::Object(sao));
        }
        root.insert("_asc".to_owned(), Value::Object(asc));
        for (section, aliases) in [("id_token", &self.id_token), ("userinfo", &self.userinfo)] {
            if let Some(target) = root.get_mut(section).and_then(Value::as_object_mut) {
                for (name, entry) in aliases {
                    target.insert(format!(":{name}"), entry.to_json());
                }
            }
        }
    }

    pub(super) fn consent_surface(&self) -> String {
        let mut root = Map::new();
        root.insert("id_token".to_owned(), json!({}));
        root.insert("userinfo".to_owned(), json!({}));
        self.add_json(&mut root);
        Value::Object(root).to_string()
    }

    pub(super) fn consent_lines(&self) -> Vec<String> {
        let mut lines = Vec::new();
        for (destination, aliases) in [("ID token", &self.id_token), ("UserInfo", &self.userinfo)] {
            for alias in aliases.keys() {
                if let Some(definition) = self.definitions.get(alias) {
                    lines.push(format!(
                        "{destination}: transformed {} as :{alias} (base claim consulted)",
                        definition.base.as_str()
                    ));
                }
            }
        }
        for (destination, rules) in [("ID token", &self.id_rules), ("UserInfo", &self.user_rules)] {
            for rule in rules {
                lines.push(format!(
                    "{destination}: conditional {} based on {}",
                    if rule.omit.is_some() {
                        "omission"
                    } else {
                        "release"
                    },
                    rule.loc
                ));
            }
        }
        lines
    }

    pub(super) fn apply(
        &self,
        user: &User,
        locales: &ClaimsLocales,
        id_token: &mut Map<String, Value>,
        userinfo: &mut Map<String, Value>,
    ) -> Result<(), ClaimsRequestError> {
        self.transform(user, locales, &self.id_token, id_token);
        self.transform(user, locales, &self.userinfo, userinfo);
        apply_rules(&self.id_rules, id_token)?;
        apply_rules(&self.user_rules, userinfo)?;
        Ok(())
    }

    fn transform(
        &self,
        user: &User,
        locales: &ClaimsLocales,
        aliases: &BTreeMap<String, ClaimRequest>,
        target: &mut Map<String, Value>,
    ) {
        for alias in aliases.keys() {
            let Some(definition) = self.definitions.get(alias) else {
                continue;
            };
            let Some(mut value) = project(user, &definition.base, locales) else {
                continue;
            };
            let mut available = true;
            for function in &definition.functions {
                let Some(next) = function.apply(&value) else {
                    available = false;
                    break;
                };
                value = next;
            }
            if available {
                target.insert(format!(":{alias}"), value);
            }
        }
    }
}

impl Function {
    fn apply(&self, input: &Value) -> Option<Value> {
        let answer = match self.name.as_str() {
            "eq" if scalar(input)
                && std::mem::discriminant(input) == std::mem::discriminant(&self.argument) =>
            {
                input == &self.argument
            }
            "contains" => input.as_str()?.contains(self.argument.as_str()?),
            "starts_with" => input.as_str()?.starts_with(self.argument.as_str()?),
            "ends_with" => input.as_str()?.ends_with(self.argument.as_str()?),
            "gt" => input.as_f64()? > self.argument.as_f64()?,
            "gte" => input.as_f64()? >= self.argument.as_f64()?,
            "lt" => input.as_f64()? < self.argument.as_f64()?,
            "lte" => input.as_f64()? <= self.argument.as_f64()?,
            _ => return None,
        };
        Some(Value::Bool(answer))
    }
}

fn parse_aliases(
    root: &Map<String, Value>,
    section: &str,
    definitions: &BTreeMap<String, Definition>,
) -> Result<BTreeMap<String, ClaimRequest>, ClaimsRequestError> {
    let mut aliases = BTreeMap::new();
    if let Some(members) = root.get(section).and_then(Value::as_object) {
        for (name, entry) in members {
            if let Some(alias) = name.strip_prefix(':') {
                if alias.starts_with(':')
                    || !definitions.contains_key(alias)
                    || aliases.len() >= MAX_COUNT
                {
                    return Err(invalid());
                }
                // This subset expresses conditional disclosure through SAO.
                // Silently ignoring an OIDC value restriction on the alias
                // would give an RP a result it said it could not accept.
                if let Some(members) = entry.as_object()
                    && (members.keys().any(|key| key != "essential")
                        || members
                            .get("essential")
                            .is_some_and(|value| !value.is_boolean()))
                {
                    return Err(invalid());
                }
                aliases.insert(alias.to_owned(), parse_entry(entry)?);
            }
        }
    }
    Ok(aliases)
}

fn parse_rules(raw: Option<&Value>) -> Result<Vec<Rule>, ClaimsRequestError> {
    let Some(raw) = raw else {
        return Ok(Vec::new());
    };
    let rules = raw.as_array().ok_or_else(invalid)?;
    if rules.is_empty() || rules.len() > MAX_RULES {
        return Err(invalid());
    }
    rules
        .iter()
        .map(|raw| {
            let fields = raw.as_object().ok_or_else(invalid)?;
            if fields.keys().any(|key| {
                !["loc", "method", "value", "values", "else", "what"].contains(&key.as_str())
            }) {
                return Err(invalid());
            }
            let loc = direct_pointer(
                fields
                    .get("loc")
                    .and_then(Value::as_str)
                    .ok_or_else(invalid)?,
            )?;
            let method = match fields.get("method") {
                None => "exists",
                Some(Value::String(value)) => value.as_str(),
                _ => return Err(invalid()),
            };
            let expected = match method {
                "exists" if !fields.contains_key("value") && !fields.contains_key("values") => None,
                "simple" if fields.contains_key("value") != fields.contains_key("values") => {
                    let values = if let Some(value) = fields.get("value") {
                        vec![value.clone()]
                    } else {
                        fields
                            .get("values")
                            .and_then(Value::as_array)
                            .ok_or_else(invalid)?
                            .clone()
                    };
                    if values.is_empty() || values.len() > MAX_COUNT || !values.iter().all(scalar) {
                        return Err(invalid());
                    }
                    Some(values)
                }
                _ => return Err(invalid()),
            };
            let omit = match fields.get("else").and_then(Value::as_str) {
                Some("abort") if !fields.contains_key("what") => None,
                Some("omit") => {
                    let names = match fields.get("what") {
                        None => vec![loc.clone()],
                        Some(Value::Array(paths))
                            if !paths.is_empty() && paths.len() <= MAX_COUNT =>
                        {
                            paths
                                .iter()
                                .map(|path| direct_pointer(path.as_str().ok_or_else(invalid)?))
                                .collect::<Result<Vec<_>, _>>()?
                        }
                        _ => return Err(invalid()),
                    };
                    Some(names)
                }
                _ => return Err(invalid()),
            };
            Ok(Rule {
                loc,
                expected,
                omit,
            })
        })
        .collect()
}

fn rules_json(rules: &[Rule]) -> Value {
    Value::Array(
        rules
            .iter()
            .map(|rule| {
                let mut fields = Map::new();
                fields.insert("loc".to_owned(), json!(format!("/{}", rule.loc)));
                if let Some(expected) = &rule.expected {
                    fields.insert("method".to_owned(), json!("simple"));
                    fields.insert("values".to_owned(), json!(expected));
                } else {
                    fields.insert("method".to_owned(), json!("exists"));
                }
                if let Some(omit) = &rule.omit {
                    fields.insert("else".to_owned(), json!("omit"));
                    fields.insert(
                        "what".to_owned(),
                        json!(
                            omit.iter()
                                .map(|name| format!("/{name}"))
                                .collect::<Vec<_>>()
                        ),
                    );
                } else {
                    fields.insert("else".to_owned(), json!("abort"));
                }
                Value::Object(fields)
            })
            .collect(),
    )
}

fn apply_rules(rules: &[Rule], target: &mut Map<String, Value>) -> Result<(), ClaimsRequestError> {
    for rule in rules {
        let matched = target.get(&rule.loc).is_some_and(|value| {
            rule.expected
                .as_ref()
                .is_none_or(|expected| expected.contains(value))
        });
        if !matched {
            let Some(omit) = &rule.omit else {
                return Err(ClaimsRequestError::AdvancedClaimsAborted);
            };
            for name in omit {
                target.remove(name);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claims::ClaimsRequest;

    #[test]
    fn transformed_request_round_trips_through_a_grant_shape() {
        let raw = json!({
            "_asc": {"transformed_claims": {
                "corporate": {"claim": "email", "fn": [["ends_with", "@example.com"]]}
            }, "sao": {"userinfo": [
                {"loc": "/:corporate", "method": "simple", "value": true,
                 "else": "omit", "what": ["/email"]}
            ]}},
            "userinfo": {":corporate": null, "email": null}
        });
        let parsed = ClaimsRequest::parse(&raw.to_string()).expect("supported ASC request");
        assert!(parsed.has_advanced_claims());
        assert_eq!(
            ClaimsRequest::from_json(&parsed.to_json()).expect("stored request"),
            parsed
        );
    }

    #[test]
    fn omitted_claim_stays_absent_for_later_rules() {
        let rules = parse_rules(Some(&json!([
            {"loc": "/email", "method": "simple", "value": "no match", "else": "omit"},
            {"loc": "/email", "else": "abort"}
        ])))
        .expect("rules");
        let mut claims = Map::from_iter([("email".to_owned(), json!("a@example.com"))]);
        assert_eq!(
            apply_rules(&rules, &mut claims),
            Err(ClaimsRequestError::AdvancedClaimsAborted)
        );
        assert!(!claims.contains_key("email"));
    }

    #[test]
    fn unsupported_expression_is_rejected_before_consent() {
        for function in [json!(["match", "a.*"]), json!(["eq"]), json!(["gte", "18"])] {
            let raw = json!({
                "_asc": {"transformed_claims": {
                    "bad": {"claim": "birthdate", "fn": [function]}
                }},
                "id_token": {":bad": null}
            });
            assert_eq!(ClaimsRequest::parse(&raw.to_string()), Err(invalid()));
        }
    }
}
