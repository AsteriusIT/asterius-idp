//! Tenant abuse-control overrides. Only maxima are configurable: retaining the
//! deployment windows and bucket names prevents a settings change resetting a
//! counter, and permits a deployment to tighten its ceilings after a save.

use crate::{EndpointLimit, EndpointLimits, LimitedEndpoint, LoginLimits, RateLimit};
use serde_json::{Value, json};
use std::collections::BTreeMap;

/// Positive per-bucket maxima, bounded again by the current deployment on use.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TenantRateLimits(BTreeMap<String, BTreeMap<String, u32>>);

/// A settings field that cannot represent a supported, bounded override.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("rate_limits.{field}: {reason}")]
pub struct RateLimitOverrideError {
    /// The field an operator must correct.
    pub field: String,
    /// A fixed explanation; no caller-supplied value is echoed.
    pub reason: &'static str,
}

impl TenantRateLimits {
    /// Parses persisted overrides; absent means inherit every deployment limit.
    ///
    /// # Errors
    /// Rejects unknown groups/buckets, non-integers and zero maxima.
    pub fn from_json(value: Option<&Value>) -> Result<Self, RateLimitOverrideError> {
        let Some(value) = value else {
            return Ok(Self::default());
        };
        let object = value
            .as_object()
            .ok_or_else(|| invalid("", "must be an object"))?;
        let mut result = BTreeMap::new();
        for (group, value) in object {
            if group != "login"
                && !LimitedEndpoint::ALL
                    .iter()
                    .any(|endpoint| endpoint.as_str() == group)
            {
                return Err(invalid(group, "unknown limiter group"));
            }
            let values = value
                .as_object()
                .ok_or_else(|| invalid(group, "must be an object of bucket maxima"))?;
            let mut buckets = BTreeMap::new();
            for (scope, value) in values {
                let field = format!("{group}.{scope}");
                let permitted = scope == "per_address"
                    || (group == "login" && scope == "per_account")
                    || (group != "login" && scope == "per_client")
                    || (group == "backchannel" && scope == "per_subject");
                if !permitted {
                    return Err(invalid(&field, "unknown bucket for this limiter"));
                }
                let max = value
                    .as_u64()
                    .and_then(|n| u32::try_from(n).ok())
                    .filter(|n| *n > 0)
                    .ok_or_else(|| invalid(&field, "must be a positive 32-bit integer"))?;
                buckets.insert(scope.clone(), max);
            }
            if !buckets.is_empty() {
                result.insert(group.clone(), buckets);
            }
        }
        Ok(Self(result))
    }

    /// Canonical persisted shape; an empty object explicitly restores inheritance.
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!(self.0)
    }

    /// Rejects an attempted relaxation or a bucket the deployment does not use.
    ///
    /// # Errors
    /// Names any override exceeding the actual deployment maximum.
    pub fn validate_against(
        &self,
        login: LoginLimits,
        endpoints: EndpointLimits,
    ) -> Result<(), RateLimitOverrideError> {
        let ceilings = Self::default().describe(login, endpoints);
        for (group, buckets) in &self.0 {
            for (scope, max) in buckets {
                let field = format!("{group}.{scope}");
                let ceiling = ceilings[group][scope]["max"]
                    .as_u64()
                    .ok_or_else(|| invalid(&field, "this deployment does not use this bucket"))?;
                if u64::from(*max) > ceiling {
                    return Err(invalid(&field, "must not exceed the deployment maximum"));
                }
            }
        }
        Ok(())
    }

    fn bounded(&self, group: &str, scope: &str, deployment: RateLimit) -> RateLimit {
        RateLimit {
            max: self
                .0
                .get(group)
                .and_then(|buckets| buckets.get(scope))
                .map_or(deployment.max, |max| (*max).min(deployment.max)),
            ..deployment
        }
    }

    /// Resolves login maxima without changing counter windows.
    #[must_use]
    pub fn login(&self, deployment: LoginLimits) -> LoginLimits {
        LoginLimits {
            per_address: self.bounded("login", "per_address", deployment.per_address),
            per_account: self.bounded("login", "per_account", deployment.per_account),
        }
    }

    /// Resolves one endpoint, preserving every deployment bucket and its window.
    #[must_use]
    pub fn endpoint(&self, endpoint: LimitedEndpoint, deployment: EndpointLimit) -> EndpointLimit {
        let name = endpoint.as_str();
        EndpointLimit {
            per_address: self.bounded(name, "per_address", deployment.per_address),
            per_client: deployment
                .per_client
                .map(|limit| self.bounded(name, "per_client", limit)),
            per_subject: deployment
                .per_subject
                .map(|limit| self.bounded(name, "per_subject", limit)),
        }
    }

    /// Effective maxima and inherited windows for operator display.
    #[must_use]
    pub fn describe(&self, login: LoginLimits, endpoints: EndpointLimits) -> Value {
        let login = self.login(login);
        let render = |limit: RateLimit| json!({"max": limit.max, "window_seconds": limit.window.whole_seconds()});
        let mut result = serde_json::Map::new();
        result.insert("login".to_owned(), json!({"per_address": render(login.per_address), "per_account": render(login.per_account)}));
        for endpoint in LimitedEndpoint::ALL {
            let limit = self.endpoint(endpoint, endpoints.for_endpoint(endpoint));
            let mut scopes = serde_json::Map::new();
            scopes.insert("per_address".to_owned(), render(limit.per_address));
            if let Some(limit) = limit.per_client {
                scopes.insert("per_client".to_owned(), render(limit));
            }
            if let Some(limit) = limit.per_subject {
                scopes.insert("per_subject".to_owned(), render(limit));
            }
            result.insert(endpoint.as_str().to_owned(), Value::Object(scopes));
        }
        Value::Object(result)
    }
}

fn invalid(field: &str, reason: &'static str) -> RateLimitOverrideError {
    RateLimitOverrideError {
        field: field.to_owned(),
        reason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::Duration;

    #[test]
    fn tenant_rate_limits_reject_invalid_shapes_and_bucket_names() {
        for value in [
            json!(null),
            json!([]),
            json!({"token": 1}),
            json!({"unknown": {}}),
            json!({"login":{"per_address":0}}),
            json!({"token":{"per_client":-1}}),
            json!({"token":{"per_client":1.5}}),
            json!({"token":{"window_seconds":60}}),
            json!({"login":{"per_client":1}}),
            json!({"par":{"per_subject":1}}),
        ] {
            assert!(
                TenantRateLimits::from_json(Some(&value)).is_err(),
                "accepted {value}"
            );
        }
    }

    #[test]
    fn tenant_rate_limits_roundtrip_and_never_weaken_deployment_or_change_windows() {
        let overrides = TenantRateLimits::from_json(Some(
            &json!({"login":{"per_account":2}, "token":{"per_address":3,"per_client":4}}),
        ))
        .expect("valid overrides");
        assert_eq!(
            TenantRateLimits::from_json(Some(&overrides.to_json())).expect("roundtrip"),
            overrides
        );
        let deployment = RateLimit {
            max: 10,
            window: Duration::minutes(15),
        };
        let login = overrides.login(LoginLimits {
            per_address: deployment,
            per_account: deployment,
        });
        assert_eq!(login.per_address, deployment);
        assert_eq!(login.per_account.max, 2);
        assert_eq!(login.per_account.window, deployment.window);
        let tightened = RateLimit {
            max: 1,
            ..deployment
        };
        assert_eq!(
            overrides
                .login(LoginLimits {
                    per_address: tightened,
                    per_account: tightened
                })
                .per_account
                .max,
            1
        );
        let token = overrides.endpoint(
            LimitedEndpoint::Token,
            EndpointLimit {
                per_address: deployment,
                per_client: Some(deployment),
                per_subject: None,
            },
        );
        assert_eq!(token.per_address.max, 3);
        assert_eq!(token.per_client.expect("client bucket").max, 4);
        assert_eq!(token.per_address.window, deployment.window);
        assert!(token.per_subject.is_none());
    }
}
