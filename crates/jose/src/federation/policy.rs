//! Federation 1.1 §6 policy resolution, after the entire chain is authenticated.

use super::{ChainError, Statement};
use serde_json::{Map, Value};
use url::Url;

const OPERATORS: [&str; 7] = [
    "value",
    "add",
    "default",
    "one_of",
    "subset_of",
    "superset_of",
    "essential",
];

pub(super) fn resolve(chain: &[Statement]) -> Result<Value, ChainError> {
    let last = chain.len() - 1;
    for (index, statement) in chain.iter().enumerate() {
        if (index == 0 || index == last)
            && ["metadata_policy", "metadata_policy_crit", "constraints"]
                .iter()
                .any(|key| statement.claims.other.contains_key(*key))
        {
            return Err(ChainError::Invalid("policy claim on Entity Configuration"));
        }
    }
    let mut metadata = chain[0]
        .claims
        .metadata
        .clone()
        .ok_or(ChainError::Invalid("leaf metadata is absent"))?;
    let types = metadata
        .as_object_mut()
        .ok_or(ChainError::Invalid("leaf metadata is not an object"))?;

    // The direct superior can override parameters, but cannot create new
    // Entity Types in the subject's Entity Configuration.
    if let Some(override_metadata) = &chain[1].claims.metadata {
        let overrides = object(override_metadata, "superior metadata")?;
        for (entity_type, fields) in overrides {
            if let Some(current) = types.get_mut(entity_type) {
                let current = current
                    .as_object_mut()
                    .ok_or(ChainError::Invalid("entity metadata"))?;
                for (name, value) in object(fields, "superior metadata fields")? {
                    current.insert(name.clone(), value.clone());
                }
            }
        }
    }

    let mut combined = Map::new();
    let mut critical = Vec::new();
    for statement in chain.iter().take(last).skip(1) {
        if let Some(list) = statement.claims.other.get("metadata_policy_crit") {
            let names = strings(list, "metadata_policy_crit")?;
            if names.is_empty() {
                return Err(ChainError::Invalid("empty metadata_policy_crit"));
            }
            critical.extend(names);
        }
    }
    // There are no supported extension operators. Even an unused critical
    // extension invalidates the chain.
    if !critical.is_empty() {
        return Err(ChainError::Unsupported("critical metadata policy operator"));
    }

    for index in (1..last).rev() {
        let statement = &chain[index];
        if let Some(constraints) = statement.claims.other.get("constraints") {
            apply_constraints(constraints, index, chain, types)?;
        }
        if let Some(policy) = statement.claims.other.get("metadata_policy") {
            merge_policy(&mut combined, object(policy, "metadata_policy")?)?;
        }
    }
    apply_policy(&combined, types)?;
    Ok(metadata)
}

fn object<'a>(value: &'a Value, what: &'static str) -> Result<&'a Map<String, Value>, ChainError> {
    value.as_object().ok_or(ChainError::Invalid(what))
}

fn strings<'a>(value: &'a Value, what: &'static str) -> Result<Vec<&'a str>, ChainError> {
    value
        .as_array()
        .ok_or(ChainError::Invalid(what))?
        .iter()
        .map(|item| item.as_str().ok_or(ChainError::Invalid(what)))
        .collect()
}

fn apply_constraints(
    value: &Value,
    index: usize,
    chain: &[Statement],
    types: &mut Map<String, Value>,
) -> Result<(), ChainError> {
    let constraints = object(value, "constraints")?;
    if let Some(maximum) = constraints.get("max_path_length") {
        let maximum = maximum
            .as_u64()
            .ok_or(ChainError::Invalid("max_path_length"))?;
        if maximum < (index - 1) as u64 {
            return Err(ChainError::Invalid("max_path_length exceeded"));
        }
    }
    if let Some(names) = constraints.get("naming_constraints") {
        let names = object(names, "naming_constraints")?;
        let permitted = names
            .get("permitted")
            .map(|value| strings(value, "permitted names"))
            .transpose()?;
        let excluded = names
            .get("excluded")
            .map(|value| strings(value, "excluded names"))
            .transpose()?
            .unwrap_or_default();
        for pattern in permitted.iter().flatten().chain(excluded.iter()) {
            valid_dns_constraint(pattern)?;
        }
        for entity_id in std::iter::once(chain[0].claims.sub.as_str()).chain(
            chain
                .iter()
                .take(index)
                .skip(1)
                .map(|entry| entry.claims.iss.as_str()),
        ) {
            let url = Url::parse(entity_id)
                .map_err(|_| ChainError::Invalid("subordinate Entity Identifier"))?;
            let host = url
                .host_str()
                .ok_or(ChainError::Invalid("subordinate Entity Identifier host"))?;
            if excluded.iter().any(|pattern| dns_match(host, pattern))
                || permitted
                    .as_ref()
                    .is_some_and(|list| !list.iter().any(|pattern| dns_match(host, pattern)))
            {
                return Err(ChainError::Invalid("naming constraint violated"));
            }
        }
    }
    if let Some(allowed) = constraints.get("allowed_entity_types") {
        let allowed = strings(allowed, "allowed_entity_types")?;
        if allowed.contains(&"federation_entity") {
            return Err(ChainError::Invalid(
                "federation_entity in allowed_entity_types",
            ));
        }
        types.retain(|name, _| name == "federation_entity" || allowed.contains(&name.as_str()));
    }
    Ok(())
}

fn valid_dns_constraint(pattern: &str) -> Result<(), ChainError> {
    let host = pattern.strip_prefix('.').unwrap_or(pattern);
    if host.is_empty()
        || host.starts_with('.')
        || host.ends_with('.')
        || !host.split('.').all(|part| {
            !part.is_empty()
                && !part.starts_with('-')
                && !part.ends_with('-')
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(ChainError::Invalid("naming constraint domain"));
    }
    Ok(())
}

fn dns_match(host: &str, pattern: &str) -> bool {
    if pattern.starts_with('.') {
        host.to_ascii_lowercase()
            .ends_with(&pattern.to_ascii_lowercase())
    } else {
        host.eq_ignore_ascii_case(pattern)
    }
}

fn merge_policy(
    current: &mut Map<String, Value>,
    incoming: &Map<String, Value>,
) -> Result<(), ChainError> {
    for (entity_type, fields) in incoming {
        let fields = object(fields, "metadata_policy entity type")?;
        let entry = current
            .entry(entity_type.clone())
            .or_insert_with(|| Value::Object(Map::new()));
        let target = entry
            .as_object_mut()
            .ok_or(ChainError::Invalid("metadata_policy entity type"))?;
        for (name, operators) in fields {
            let operators = object(operators, "metadata parameter policy")?;
            validate_operators(operators)?;
            let parameter = target
                .entry(name.clone())
                .or_insert_with(|| Value::Object(Map::new()));
            let existing = parameter
                .as_object_mut()
                .ok_or(ChainError::Invalid("metadata parameter policy"))?;
            for (operator, value) in operators {
                if !OPERATORS.contains(&operator.as_str()) {
                    continue;
                }
                match existing.get_mut(operator) {
                    None => {
                        existing.insert(operator.clone(), value.clone());
                    }
                    Some(previous) => merge_operator(operator, previous, value)?,
                }
            }
            validate_operators(existing)?;
        }
    }
    Ok(())
}

fn validate_operators(operators: &Map<String, Value>) -> Result<(), ChainError> {
    for (name, value) in operators {
        match name.as_str() {
            "value" => valid_scalar_or_array(value, true)?,
            "default" => valid_scalar_or_array(value, false)?,
            "add" | "one_of" | "subset_of" | "superset_of" => {
                strings(value, "array policy operator")?;
            }
            "essential" if value.is_boolean() => {}
            "essential" => return Err(ChainError::Invalid("essential policy operator")),
            _ => {} // Noncritical extensions are ignored by Federation §6.1.3.2.
        }
    }
    if operators.contains_key("one_of")
        && ["add", "subset_of", "superset_of"]
            .iter()
            .any(|name| operators.contains_key(*name))
    {
        return Err(ChainError::Invalid("incompatible one_of policy operators"));
    }
    if let (Some(subset), Some(superset)) =
        (operators.get("subset_of"), operators.get("superset_of"))
    {
        let subset = strings(subset, "subset_of")?;
        let superset = strings(superset, "superset_of")?;
        if !superset.iter().all(|item| subset.contains(item)) {
            return Err(ChainError::Invalid(
                "incompatible subset and superset policy",
            ));
        }
    }
    if let Some(value) = operators.get("value") {
        if value.is_null() && operators.contains_key("default") {
            return Err(ChainError::Invalid("null value and default policy"));
        }
        if let Some(one_of) = operators.get("one_of")
            && !one_of.as_array().is_some_and(|items| items.contains(value))
        {
            return Err(ChainError::Invalid("value outside one_of policy"));
        }
        if let Some(add) = operators.get("add") {
            let Some(array) = value.as_array() else {
                return Err(ChainError::Invalid("value and add policy types"));
            };
            if !add
                .as_array()
                .is_some_and(|items| items.iter().all(|item| array.contains(item)))
            {
                return Err(ChainError::Invalid("value excludes add policy"));
            }
        }
        if let Some(subset) = operators.get("subset_of") {
            let Some(array) = value.as_array() else {
                return Err(ChainError::Invalid("value and subset policy types"));
            };
            if !array
                .iter()
                .all(|item| subset.as_array().is_some_and(|items| items.contains(item)))
            {
                return Err(ChainError::Invalid("value exceeds subset policy"));
            }
        }
        if let Some(superset) = operators.get("superset_of") {
            let Some(array) = value.as_array() else {
                return Err(ChainError::Invalid("value and superset policy types"));
            };
            if !superset
                .as_array()
                .is_some_and(|items| items.iter().all(|item| array.contains(item)))
            {
                return Err(ChainError::Invalid("value misses superset policy"));
            }
        }
        if value.is_null() && operators.get("essential") == Some(&Value::Bool(true)) {
            return Err(ChainError::Invalid("essential value removed"));
        }
    }
    if let (Some(add), Some(subset)) = (operators.get("add"), operators.get("subset_of")) {
        let add = strings(add, "add policy")?;
        let subset = strings(subset, "subset_of policy")?;
        if !add.iter().all(|item| subset.contains(item)) {
            return Err(ChainError::Invalid("add exceeds subset policy"));
        }
    }
    if operators
        .get("one_of")
        .is_some_and(|value| value.as_array().is_some_and(Vec::is_empty))
    {
        return Err(ChainError::Invalid("empty one_of policy"));
    }
    Ok(())
}

fn valid_scalar_or_array(value: &Value, nullable: bool) -> Result<(), ChainError> {
    match value {
        Value::Null if nullable => Ok(()),
        Value::String(_) | Value::Number(_) | Value::Bool(_) | Value::Array(_) => Ok(()),
        _ => Err(ChainError::Unsupported("object metadata policy value")),
    }
}

fn merge_operator(name: &str, current: &mut Value, next: &Value) -> Result<(), ChainError> {
    match name {
        "value" | "default" if current == next => Ok(()),
        "value" | "default" => Err(ChainError::Invalid("conflicting policy values")),
        "essential" => {
            *current =
                Value::Bool(current.as_bool().unwrap_or(false) || next.as_bool().unwrap_or(false));
            Ok(())
        }
        "add" | "superset_of" => {
            let current = current
                .as_array_mut()
                .ok_or(ChainError::Invalid("policy array"))?;
            for item in next.as_array().ok_or(ChainError::Invalid("policy array"))? {
                if !current.contains(item) {
                    current.push(item.clone());
                }
            }
            Ok(())
        }
        "one_of" | "subset_of" => {
            let next = next.as_array().ok_or(ChainError::Invalid("policy array"))?;
            let current = current
                .as_array_mut()
                .ok_or(ChainError::Invalid("policy array"))?;
            current.retain(|item| next.contains(item));
            if name == "one_of" && current.is_empty() {
                return Err(ChainError::Invalid("empty one_of intersection"));
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn apply_policy(
    policy: &Map<String, Value>,
    metadata: &mut Map<String, Value>,
) -> Result<(), ChainError> {
    for (entity_type, parameters) in policy {
        let Some(fields) = metadata.get_mut(entity_type) else {
            continue;
        };
        let fields = fields
            .as_object_mut()
            .ok_or(ChainError::Invalid("entity metadata"))?;
        for (name, operators) in object(parameters, "entity policy")? {
            let operators = object(operators, "parameter policy")?;
            let scope = name == "scope";
            let mut value = fields.get(name).cloned();
            if scope && let Some(Value::String(text)) = &value {
                value = Some(Value::Array(
                    text.split_whitespace()
                        .map(|word| Value::String(word.to_owned()))
                        .collect(),
                ));
            }
            if let Some(fixed) = operators.get("value") {
                value = (!fixed.is_null()).then(|| fixed.clone());
            }
            if let Some(add) = operators.get("add") {
                let additions = add.as_array().ok_or(ChainError::Invalid("add policy"))?;
                let list = value.get_or_insert_with(|| Value::Array(Vec::new()));
                let list = list
                    .as_array_mut()
                    .ok_or(ChainError::Invalid("add target is not an array"))?;
                for item in additions {
                    if !list.contains(item) {
                        list.push(item.clone());
                    }
                }
            }
            if value.is_none() {
                value = operators.get("default").cloned();
            }
            if let Some(allowed) = operators.get("one_of")
                && value.as_ref().is_some_and(|value| {
                    !allowed
                        .as_array()
                        .is_some_and(|items| items.contains(value))
                })
            {
                return Err(ChainError::Invalid("one_of policy violated"));
            }
            if let Some(allowed) = operators.get("subset_of")
                && let Some(value) = &mut value
            {
                let items = value
                    .as_array_mut()
                    .ok_or(ChainError::Invalid("subset target is not an array"))?;
                let allowed = allowed
                    .as_array()
                    .ok_or(ChainError::Invalid("subset_of policy"))?;
                items.retain(|item| allowed.contains(item));
            }
            if let Some(required) = operators.get("superset_of")
                && let Some(value) = &value
            {
                let items = value
                    .as_array()
                    .ok_or(ChainError::Invalid("superset target is not an array"))?;
                if !required
                    .as_array()
                    .is_some_and(|required| required.iter().all(|item| items.contains(item)))
                {
                    return Err(ChainError::Invalid("superset_of policy violated"));
                }
            }
            if value.is_none() && operators.get("essential") == Some(&Value::Bool(true)) {
                return Err(ChainError::Invalid("essential metadata parameter absent"));
            }
            match value {
                Some(Value::Array(items)) if scope => {
                    let scope = items
                        .iter()
                        .map(|item| {
                            item.as_str()
                                .ok_or(ChainError::Invalid("scope policy value"))
                        })
                        .collect::<Result<Vec<_>, _>>()?
                        .join(" ");
                    fields.insert(name.clone(), Value::String(scope));
                }
                Some(value) => {
                    fields.insert(name.clone(), value);
                }
                None => {
                    fields.remove(name);
                }
            }
        }
    }
    Ok(())
}
