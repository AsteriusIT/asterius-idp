//! Bounded external workload JWT validation; no OIDC login or FAPI client authentication.
use crate::client_keys::{has_private_members, verifying_key};
use asterius_domain::SigningAlgorithm;
use asterius_domain::workload::{
    Algorithm, Config, MAX_ASSERTION_BYTES, MAX_CLAIMS_BYTES, MAX_JWKS_BYTES, MAX_KEYS, Provider,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use serde::de::{DeserializeSeed, Error as _, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};
use std::collections::BTreeSet;
use time::OffsetDateTime;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid external workload assertion")]
pub struct Invalid;

struct Strict {
    depth: u8,
    string_limit: usize,
}
impl<'de> DeserializeSeed<'de> for Strict {
    type Value = Value;
    fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        if self.depth > 8 {
            return Err(D::Error::custom("invalid"));
        }
        deserializer.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for Strict {
    type Value = Value;
    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("bounded unique JSON")
    }
    fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }
    fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Value, E> {
        Ok(Value::from(value))
    }
    fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Value, E> {
        Ok(Value::from(value))
    }
    fn visit_unit<E: serde::de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Value, E> {
        if value.len() > self.string_limit {
            return Err(E::custom("invalid"));
        }
        Ok(Value::String(value.to_owned()))
    }
    fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Value, E> {
        self.visit_str(&value)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Value, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(Strict {
            depth: self.depth + 1,
            string_limit: self.string_limit,
        })? {
            if values.len() >= 128 {
                return Err(A::Error::custom("invalid"));
            }
            values.push(value);
        }
        Ok(Value::Array(values))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut entries: A) -> Result<Value, A::Error> {
        let mut values = Map::new();
        while let Some(key) = entries.next_key::<String>()? {
            if key.len() > 128 || values.len() >= 64 || values.contains_key(&key) {
                return Err(A::Error::custom("invalid"));
            }
            let value = entries.next_value_seed(Strict {
                depth: self.depth + 1,
                string_limit: self.string_limit,
            })?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}
fn strict(bytes: &[u8], max: usize, strings: usize) -> Result<Value, Invalid> {
    if bytes.is_empty() || bytes.len() > max {
        return Err(Invalid);
    }
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let value = Strict {
        depth: 0,
        string_limit: strings,
    }
    .deserialize(&mut decoder)
    .map_err(|_| Invalid)?;
    decoder.end().map_err(|_| Invalid)?;
    Ok(value)
}

/// Bounded issuer routing only. A hint never establishes authenticity.
// fuzz-target: workload_token
pub fn issuer_hint(token: &str) -> Result<String, Invalid> {
    if token.is_empty() || token.len() > MAX_ASSERTION_BYTES {
        return Err(Invalid);
    }
    let mut pieces = token.split('.');
    let _header = pieces.next().ok_or(Invalid)?;
    let payload = pieces.next().ok_or(Invalid)?;
    let _signature = pieces.next().ok_or(Invalid)?;
    if pieces.next().is_some() {
        return Err(Invalid);
    }
    let decoded = B64.decode(payload).map_err(|_| Invalid)?;
    if decoded.len() > MAX_ASSERTION_BYTES {
        return Err(Invalid);
    }
    // Routing accepts the existing local token shape. This bounded serde
    // decoder has its standard nesting limit; the external verifier separately
    // enforces the stricter duplicate/depth/string/4KiB workload profile.
    let claims: Value = serde_json::from_slice(&decoded).map_err(|_| Invalid)?;
    claims
        .get("iss")
        .and_then(Value::as_str)
        .filter(|issuer| !issuer.is_empty() && issuer.len() <= 1024)
        .map(ToOwned::to_owned)
        .ok_or(Invalid)
}

/// Untrusted routing fields cannot establish issuer trust or authorization.
pub struct Parsed<'a> {
    token: &'a str,
    payload: Value,
    issuer: String,
    kid: String,
    algorithm: Algorithm,
    input_len: usize,
    signature: Vec<u8>,
    certificate_thumbprint: bool,
}
impl std::fmt::Debug for Parsed<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ParsedWorkload").finish_non_exhaustive()
    }
}
impl<'a> Parsed<'a> {
    // fuzz-target: workload_token
    pub fn parse(token: &'a str) -> Result<Self, Invalid> {
        if token.is_empty() || token.len() > MAX_ASSERTION_BYTES {
            return Err(Invalid);
        }
        let pieces: Vec<&str> = token.split('.').collect();
        let [header, payload, signature] = pieces.as_slice() else {
            return Err(Invalid);
        };
        let header = strict(&B64.decode(header).map_err(|_| Invalid)?, 1024, 1024)?;
        let header = header.as_object().ok_or(Invalid)?;
        if header
            .keys()
            .any(|key| !matches!(key.as_str(), "alg" | "kid" | "typ" | "x5t"))
            || header
                .get("typ")
                .is_some_and(|typ| typ.as_str() != Some("JWT"))
        {
            return Err(Invalid);
        }
        // GitHub supplies this RFC 7515 metadata. It never selects a key or
        // establishes certificate trust; only pinned JWKS + kid do that.
        let certificate_thumbprint = if let Some(raw) = header.get("x5t") {
            let encoded = raw.as_str().ok_or(Invalid)?;
            if encoded.len() != 27 || B64.decode(encoded).map_err(|_| Invalid)?.len() != 20 {
                return Err(Invalid);
            }
            true
        } else {
            false
        };
        let algorithm: Algorithm =
            serde_json::from_value(header.get("alg").ok_or(Invalid)?.clone())
                .map_err(|_| Invalid)?;
        let kid = header
            .get("kid")
            .and_then(Value::as_str)
            .filter(|kid| !kid.is_empty() && kid.len() <= 128 && !kid.chars().any(char::is_control))
            .ok_or(Invalid)?
            .to_owned();
        let payload = strict(
            &B64.decode(payload).map_err(|_| Invalid)?,
            MAX_CLAIMS_BYTES,
            1024,
        )?;
        let issuer = payload
            .get("iss")
            .and_then(Value::as_str)
            .filter(|issuer| !issuer.is_empty())
            .ok_or(Invalid)?
            .to_owned();
        let signature = B64.decode(signature).map_err(|_| Invalid)?;
        if signature.is_empty() || signature.len() > 1024 {
            return Err(Invalid);
        }
        Ok(Self {
            token,
            payload,
            issuer,
            kid,
            algorithm,
            input_len: pieces[0].len() + 1 + pieces[1].len(),
            signature,
            certificate_thumbprint,
        })
    }
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }
    #[must_use]
    pub fn kid(&self) -> &str {
        &self.kid
    }
    #[must_use]
    pub const fn algorithm(&self) -> Algorithm {
        self.algorithm
    }
    /// An untrusted routing hint only; signature and the complete profile must
    /// still pass verification. Avoids fetching unrelated same-issuer trusts.
    #[must_use]
    pub fn matches_audience(&self, expected: &str) -> bool {
        self.payload.get("aud").is_some_and(|audience| {
            audience.as_str() == Some(expected)
                || audience
                    .as_array()
                    .is_some_and(|values| values.len() == 1 && values[0].as_str() == Some(expected))
        })
    }
    pub fn verify(
        &self,
        config: &Config,
        keys: &KeySet,
        now: OffsetDateTime,
    ) -> Result<OffsetDateTime, Invalid> {
        if !config.algorithms.contains(&self.algorithm)
            || (self.certificate_thumbprint && config.provider != Provider::Github)
            || !keys.verifies(
                &self.kid,
                self.algorithm,
                &self.token.as_bytes()[..self.input_len],
                &self.signature,
            )
        {
            return Err(Invalid);
        }
        let claims = self.payload.as_object().ok_or(Invalid)?;
        let issuer = claims.get("iss").and_then(Value::as_str).ok_or(Invalid)?;
        let subject = claims.get("sub").and_then(Value::as_str).ok_or(Invalid)?;
        let matching_audience = self.matches_audience(&config.audience);
        let minted_at = claims.get("iat").and_then(Value::as_i64).ok_or(Invalid)?;
        let expires = claims.get("exp").and_then(Value::as_i64).ok_or(Invalid)?;
        let limit = match config.provider {
            Provider::Kubernetes => 3600,
            Provider::Github => 600,
        };
        let now = now.unix_timestamp();
        if issuer != config.issuer
            || subject != config.subject
            || !matching_audience
            || expires <= now
            || expires <= minted_at
            || expires.saturating_sub(minted_at) > limit
            || minted_at > now.saturating_add(30)
            || minted_at < now.saturating_sub(300)
        {
            return Err(Invalid);
        }
        if let Some(nbf) = claims.get("nbf") {
            let nbf = nbf.as_i64().ok_or(Invalid)?;
            if nbf > expires || nbf > now.saturating_add(30) {
                return Err(Invalid);
            }
        }
        for (pointer, expected) in &config.required_claims {
            if self.payload.pointer(pointer).and_then(Value::as_str) != Some(expected.as_str()) {
                return Err(Invalid);
            }
        }
        if config.provider == Provider::Github {
            // Ordinary workflow trust cannot silently authorize a called
            // reusable workflow. Both caller and callee are exact pins.
            let pinned = config.required_claims.contains_key("/job_workflow_ref");
            if claims.contains_key("job_workflow_ref") != pinned
                || claims.contains_key("job_workflow_sha") != pinned
            {
                return Err(Invalid);
            }
        }
        if config.provider == Provider::Kubernetes
            && !self
                .payload
                .pointer("/kubernetes.io/pod/uid")
                .and_then(Value::as_str)
                .is_some_and(|uid| !uid.is_empty() && uid.len() <= 128)
        {
            return Err(Invalid);
        }
        OffsetDateTime::from_unix_timestamp(expires).map_err(|_| Invalid)
    }
}

#[derive(Clone)]
pub struct KeySet {
    keys: Vec<Value>,
    fingerprints: Vec<String>,
}
impl std::fmt::Debug for KeySet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WorkloadKeySet")
            .field("count", &self.keys.len())
            .finish_non_exhaustive()
    }
}
impl KeySet {
    // fuzz-target: workload_token
    pub fn parse(bytes: &[u8], algorithms: &BTreeSet<Algorithm>) -> Result<Self, Invalid> {
        let document = strict(bytes, MAX_JWKS_BYTES, 8192)?;
        let keys = document
            .get("keys")
            .and_then(Value::as_array)
            .filter(|keys| !keys.is_empty() && keys.len() <= MAX_KEYS)
            .ok_or(Invalid)?;
        let mut kids = BTreeSet::new();
        let mut fingerprints = Vec::new();
        for value in keys {
            let key = value.as_object().ok_or(Invalid)?;
            let kid = key
                .get("kid")
                .and_then(Value::as_str)
                .filter(|kid| {
                    !kid.is_empty() && kid.len() <= 128 && !kid.chars().any(char::is_control)
                })
                .ok_or(Invalid)?;
            if !kids.insert(kid)
                || has_private_members(key)
                || key
                    .get("use")
                    .is_some_and(|use_| use_.as_str() != Some("sig"))
                || key.get("key_ops").is_some_and(|ops| {
                    !ops.as_array().is_some_and(|ops| {
                        !ops.is_empty() && ops.iter().all(|op| op.as_str() == Some("verify"))
                    })
                })
            {
                return Err(Invalid);
            }
            let mut valid = false;
            for algorithm in algorithms {
                if key
                    .get("alg")
                    .is_some_and(|alg| alg.as_str() != Some(algorithm.as_str()))
                {
                    continue;
                }
                valid |= valid_key(*algorithm, key);
            }
            if !valid {
                return Err(Invalid);
            }
            fingerprints.push(
                crate::thumbprint(value)
                    .map_err(|_| Invalid)?
                    .as_str()
                    .to_owned(),
            );
        }
        fingerprints.sort();
        Ok(Self {
            keys: keys.clone(),
            fingerprints,
        })
    }
    #[must_use]
    pub fn contains(&self, kid: &str) -> bool {
        self.keys.iter().any(|key| key["kid"].as_str() == Some(kid))
    }
    #[must_use]
    pub fn fingerprints(&self) -> &[String] {
        &self.fingerprints
    }
    fn verifies(&self, kid: &str, algorithm: Algorithm, message: &[u8], signature: &[u8]) -> bool {
        self.keys
            .iter()
            .filter_map(Value::as_object)
            .filter(|key| {
                key.get("kid").and_then(Value::as_str) == Some(kid)
                    && key
                        .get("alg")
                        .is_none_or(|alg| alg.as_str() == Some(algorithm.as_str()))
            })
            .any(|key| {
                if !valid_key(algorithm, key) {
                    return false;
                }
                match algorithm {
                    Algorithm::RS256 => {
                        crate::upstream_id_token::verify_rs256(key, message, signature)
                    }
                    other => verifying_key(local_algorithm(other), key)
                        .is_some_and(|key| key.verify(message, signature).is_ok()),
                }
            })
    }
}
fn local_algorithm(algorithm: Algorithm) -> SigningAlgorithm {
    match algorithm {
        Algorithm::ES256 => SigningAlgorithm::Es256,
        Algorithm::EdDSA => SigningAlgorithm::EdDsa,
        Algorithm::PS256 | Algorithm::RS256 => SigningAlgorithm::Ps256,
    }
}
fn valid_key(algorithm: Algorithm, key: &Map<String, Value>) -> bool {
    let kind = match algorithm {
        Algorithm::RS256 | Algorithm::PS256 => "RSA",
        Algorithm::ES256 => "EC",
        Algorithm::EdDSA => "OKP",
    };
    if key.get("kty").and_then(Value::as_str) != Some(kind) {
        return false;
    }
    if matches!(algorithm, Algorithm::RS256 | Algorithm::PS256) {
        let Some(n) = key
            .get("n")
            .and_then(Value::as_str)
            .and_then(|n| B64.decode(n).ok())
        else {
            return false;
        };
        let Some(e) = key
            .get("e")
            .and_then(Value::as_str)
            .and_then(|e| B64.decode(e).ok())
        else {
            return false;
        };
        let Some(first) = n.first() else {
            return false;
        };
        if *first == 0
            || e.is_empty()
            || e.len() > 8
            || e[0] == 0
            || !(2048..=8192).contains(&(n.len() * 8 - first.leading_zeros() as usize))
        {
            return false;
        }
        // Existing PS256 key constructor validates the same RSA public encoding;
        // RS256 signature verification uses the isolated upstream helper only.
    }
    verifying_key(local_algorithm(algorithm), key).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SigningKey, jws};
    use asterius_domain::Kid;
    use serde_json::json;
    const NOW: i64 = 1_760_000_000;
    fn config() -> Config {
        serde_json::from_value(serde_json::json!({"issuer":"https://cluster.example","audience":"urn:asterius:workload:acme:inventory","subject":"system:serviceaccount:apps:inventory","provider":"kubernetes","principal":"workload:inventory","clients":["client-one"],"scopes":["inventory:read"],"resources":["https://api.example/"],"actions":["read"],"required_claims":{"/kubernetes.io/namespace":"apps","/kubernetes.io/serviceaccount/name":"inventory","/kubernetes.io/serviceaccount/uid":"sa-uid"},"algorithms":["EdDSA"],"keys":{"kind":"inline","jwks":{"keys":[]}},"enabled":true})).expect("config")
    }

    fn claims() -> Value {
        json!({"iss":"https://cluster.example","aud":"urn:asterius:workload:acme:inventory","sub":"system:serviceaccount:apps:inventory","iat":NOW,"exp":NOW+300,"kubernetes.io":{"namespace":"apps","serviceaccount":{"name":"inventory","uid":"sa-uid"},"pod":{"uid":"pod-uid"}}})
    }
    fn fixture(claims: &Value, algorithm: SigningAlgorithm) -> (String, Value) {
        let key = SigningKey::generate(algorithm).expect("key");
        let mut public = key.public_jwk().expect("public");
        public["kid"] = json!("key-one");
        let token = jws::sign(&key, &Kid::new("key-one"), "JWT", claims).expect("signed");
        (token.as_str().to_owned(), json!({"keys":[public]}))
    }
    fn verified(claims: &Value) -> Result<OffsetDateTime, Invalid> {
        let (token, jwks) = fixture(claims, SigningAlgorithm::EdDsa);
        let config = config();
        let keys = KeySet::parse(
            &serde_json::to_vec(&jwks).expect("JWKS"),
            &config.algorithms,
        )?;
        Parsed::parse(&token)?.verify(
            &config,
            &keys,
            OffsetDateTime::from_unix_timestamp(NOW).expect("time"),
        )
    }
    fn github_config() -> Config {
        let mut config = config();
        config.provider = Provider::Github;
        config.issuer = "https://token.actions.githubusercontent.com".to_owned();
        config.subject = "repo:org@456/repo@123:environment:prod".to_owned();
        config.required_claims = [
            ("/repository_id", "123"),
            ("/repository_owner_id", "456"),
            ("/environment", "prod"),
            ("/ref", "refs/heads/main"),
            ("/event_name", "workflow_dispatch"),
            (
                "/workflow_ref",
                "org/repo/.github/workflows/deploy.yml@refs/heads/main",
            ),
            ("/workflow_sha", "1111111111111111111111111111111111111111"),
        ]
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect();
        config
    }
    fn github_claims(config: &Config) -> Value {
        let mut value = json!({"iss":config.issuer,"sub":config.subject,"aud":config.audience,"iat":NOW,"nbf":NOW,"exp":NOW+600});
        for (pointer, expected) in &config.required_claims {
            value[pointer.trim_start_matches('/')] = json!(expected);
        }
        value
    }
    fn github_verifies(claims: &Value, config: &Config) -> bool {
        let (token, jwks) = fixture(claims, SigningAlgorithm::EdDsa);
        let keys = KeySet::parse(
            &serde_json::to_vec(&jwks).expect("JWKS"),
            &config.algorithms,
        )
        .expect("keys");
        Parsed::parse(&token)
            .expect("JWT")
            .verify(
                config,
                &keys,
                OffsetDateTime::from_unix_timestamp(NOW).expect("time"),
            )
            .is_ok()
    }
    #[test]
    fn github_workflow_claims_bind_ids_environment_ref_event_and_exact_workflow() {
        let config = github_config();
        let claims = github_claims(&config);
        assert!(github_verifies(&claims, &config));
        for (name, value) in [
            ("repository_id", json!("999")),
            ("repository_owner_id", json!("999")),
            ("repository_id", json!(123)),
            ("environment", json!("staging")),
            ("ref", json!("refs/heads/untrusted")),
            ("event_name", json!("pull_request")),
            ("event_name", json!("pull_request_target")),
            ("event_name", json!("dynamic")),
            (
                "workflow_ref",
                json!("org/repo/.github/workflows/evil.yml@refs/heads/main"),
            ),
            (
                "workflow_sha",
                json!("2222222222222222222222222222222222222222"),
            ),
            ("sub", json!("repo:org@456/renamed@123:environment:prod")),
            ("aud", json!("https://github.com/org")),
            ("exp", json!(NOW + 601)),
        ] {
            let mut wrong = claims.clone();
            wrong[name] = value;
            assert!(!github_verifies(&wrong, &config), "{name}");
        }
    }
    #[test]
    fn github_reusable_workflow_requires_both_explicit_callee_pins() {
        let mut config = github_config();
        let mut claims = github_claims(&config);
        let reference =
            "org/automation/.github/workflows/deploy.yml@1111111111111111111111111111111111111111";
        let sha = "1111111111111111111111111111111111111111";
        claims["job_workflow_ref"] = json!(reference);
        claims["job_workflow_sha"] = json!(sha);
        assert!(!github_verifies(&claims, &config));
        config
            .required_claims
            .insert("/job_workflow_ref".to_owned(), reference.to_owned());
        config
            .required_claims
            .insert("/job_workflow_sha".to_owned(), sha.to_owned());
        assert!(github_verifies(&claims, &config));
        claims["job_workflow_sha"] = json!("untrusted");
        assert!(!github_verifies(&claims, &config));
        claims
            .as_object_mut()
            .expect("claims")
            .remove("job_workflow_sha");
        assert!(!github_verifies(&claims, &config));
        assert!(!github_verifies(&github_claims(&github_config()), &config));
    }
    #[test]
    fn github_certificate_thumbprint_is_bounded_metadata_never_key_authority() {
        use aws_lc_rs::signature::{KeyPair as _, RSA_PKCS1_SHA256, RsaKeyPair};
        let pair = RsaKeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048).expect("RSA");
        let public = pair.public_key();
        let key = json!({"kid":"rsa","kty":"RSA","alg":"RS256","n":B64.encode(public.modulus().big_endian_without_leading_zero()),"e":B64.encode(public.exponent().big_endian_without_leading_zero())});
        let mut config = github_config();
        config.algorithms = BTreeSet::from([Algorithm::RS256]);
        let keys = KeySet::parse(
            &serde_json::to_vec(&json!({"keys":[key]})).expect("JWKS"),
            &config.algorithms,
        )
        .expect("keys");
        let header = json!({"typ":"JWT","alg":"RS256","kid":"rsa","x5t":B64.encode([0_u8;20])});
        let input = format!(
            "{}.{}",
            B64.encode(serde_json::to_vec(&header).expect("header")),
            B64.encode(serde_json::to_vec(&github_claims(&config)).expect("claims"))
        );
        let mut signature = vec![0; pair.public_modulus_len()];
        pair.sign(
            &RSA_PKCS1_SHA256,
            &aws_lc_rs::rand::SystemRandom::new(),
            input.as_bytes(),
            &mut signature,
        )
        .expect("sign");
        let token = format!("{input}.{}", B64.encode(signature));
        let now = OffsetDateTime::from_unix_timestamp(NOW).expect("time");
        assert!(
            Parsed::parse(&token)
                .expect("JWT")
                .verify(&config, &keys, now)
                .is_ok()
        );
        config.provider = Provider::Kubernetes;
        assert!(
            Parsed::parse(&token)
                .expect("JWT")
                .verify(&config, &keys, now)
                .is_err()
        );
        for thumbprint in [
            json!(null),
            json!(42),
            json!("invalid"),
            json!(B64.encode([0_u8; 21])),
        ] {
            let mut header = header.clone();
            header["x5t"] = thumbprint;
            let token = format!(
                "{}.{}.AA",
                B64.encode(serde_json::to_vec(&header).expect("header")),
                B64.encode(serde_json::to_vec(&github_claims(&config)).expect("claims"))
            );
            assert!(Parsed::parse(&token).is_err());
        }
    }
    #[test]
    fn accepted_workload_is_bound_to_exact_profile_and_public_key() {
        assert!(verified(&claims()).is_ok());
        for (local, external) in [
            (SigningAlgorithm::Es256, Algorithm::ES256),
            (SigningAlgorithm::Ps256, Algorithm::PS256),
        ] {
            let (token, jwks) = fixture(&claims(), local);
            let mut config = config();
            config.algorithms = BTreeSet::from([external]);
            let keys = KeySet::parse(
                &serde_json::to_vec(&jwks).expect("JWKS"),
                &config.algorithms,
            )
            .expect("keys");
            assert!(
                Parsed::parse(&token)
                    .expect("token")
                    .verify(
                        &config,
                        &keys,
                        OffsetDateTime::from_unix_timestamp(NOW).expect("time")
                    )
                    .is_ok()
            );
        }
    }
    #[test]
    fn wrong_issuer_subject_audience_and_provider_claims_fail() {
        for (pointer, value) in [
            ("/iss", json!("https://unknown.example")),
            ("/sub", json!("person")),
            (
                "/aud",
                json!(["urn:asterius:workload:acme:inventory", "other"]),
            ),
            (
                "/kubernetes.io/serviceaccount/uid",
                json!("reused-name-new-uid"),
            ),
            ("/kubernetes.io/namespace", json!("other")),
            ("/kubernetes.io/pod/uid", Value::Null),
        ] {
            let mut claims = claims();
            *claims.pointer_mut(pointer).expect("claim") = value;
            assert!(verified(&claims).is_err(), "{pointer}");
        }
    }
    #[test]
    fn expired_stale_future_and_excessive_lifetime_assertions_fail() {
        for (pointer, value) in [
            ("/exp", json!(NOW)),
            ("/iat", json!(NOW - 301)),
            ("/iat", json!(NOW + 31)),
            ("/exp", json!(NOW + 3601)),
            ("/iat", json!("wrong-type")),
        ] {
            let mut claims = claims();
            *claims.pointer_mut(pointer).expect("claim") = value;
            assert!(verified(&claims).is_err(), "{pointer}");
        }
        let mut claims = claims();
        claims["nbf"] = json!(NOW + 31);
        assert!(verified(&claims).is_err());
    }
    #[test]
    fn duplicate_json_fields_and_nested_duplicate_fields_are_rejected() {
        for payload in [
            br#"{"iss":"https://cluster.example","iss":"https://evil.example"}"#.as_slice(),
            br#"{"iss":"https://cluster.example","nested":{"a":1,"a":2}}"#.as_slice(),
        ] {
            let token = format!(
                "{}.{}.AA",
                B64.encode(br#"{"alg":"EdDSA","kid":"one"}"#),
                B64.encode(payload)
            );
            assert!(Parsed::parse(&token).is_err());
        }
        let token = format!(
            "{}.{}.AA",
            B64.encode(br#"{"alg":"EdDSA","alg":"RS256","kid":"one"}"#),
            B64.encode(br#"{"iss":"https://cluster.example"}"#)
        );
        assert!(Parsed::parse(&token).is_err());
    }
    #[test]
    fn hostile_header_and_size_depth_limits_fail() {
        for header in [
            json!({"alg":"none","kid":"one"}),
            json!({"alg":"HS256","kid":"one"}),
            json!({"alg":"EdDSA","kid":"one","jku":"https://evil.example/keys"}),
            json!({"alg":"EdDSA","kid":"one","jwk":{}}),
        ] {
            let token = format!(
                "{}.{}.AA",
                B64.encode(serde_json::to_vec(&header).expect("header")),
                B64.encode(br#"{"iss":"https://cluster.example"}"#)
            );
            assert!(Parsed::parse(&token).is_err());
        }
        assert!(Parsed::parse(&"a".repeat(MAX_ASSERTION_BYTES + 1)).is_err());
        let mut nested = json!({"iss":"https://cluster.example"});
        for _ in 0..10 {
            nested = json!({"nested":nested});
        }
        assert!(
            strict(
                &serde_json::to_vec(&nested).expect("nested"),
                MAX_CLAIMS_BYTES,
                1024
            )
            .is_err()
        );
    }
    #[test]
    fn private_or_duplicate_or_mismatched_jwks_is_rejected() {
        let (_, mut jwks) = fixture(&claims(), SigningAlgorithm::EdDsa);
        let config = config();
        jwks["keys"][0]["d"] = json!("private");
        assert!(
            KeySet::parse(
                &serde_json::to_vec(&jwks).expect("JWKS"),
                &config.algorithms
            )
            .is_err()
        );
        jwks["keys"][0].as_object_mut().expect("key").remove("d");
        let duplicate = jwks["keys"][0].clone();
        jwks["keys"].as_array_mut().expect("keys").push(duplicate);
        assert!(
            KeySet::parse(
                &serde_json::to_vec(&jwks).expect("JWKS"),
                &config.algorithms
            )
            .is_err()
        );
        let (_, jwks) = fixture(&claims(), SigningAlgorithm::Ps256);
        assert!(
            KeySet::parse(
                &serde_json::to_vec(&jwks).expect("JWKS"),
                &config.algorithms
            )
            .is_err()
        );
    }
    #[test]
    fn rs256_is_isolated_to_external_verification() {
        use aws_lc_rs::signature::{KeyPair as _, RSA_PKCS1_SHA256, RsaKeyPair};
        let pair = RsaKeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048).expect("RSA");
        let public = pair.public_key();
        let jwk = json!({"kid":"rsa","kty":"RSA","alg":"RS256","n":B64.encode(public.modulus().big_endian_without_leading_zero()),"e":B64.encode(public.exponent().big_endian_without_leading_zero())});
        let input = format!(
            "{}.{}",
            B64.encode(br#"{"alg":"RS256","typ":"JWT","kid":"rsa"}"#),
            B64.encode(serde_json::to_vec(&claims()).expect("claims"))
        );
        let mut signature = vec![0; pair.public_modulus_len()];
        pair.sign(
            &RSA_PKCS1_SHA256,
            &aws_lc_rs::rand::SystemRandom::new(),
            input.as_bytes(),
            &mut signature,
        )
        .expect("sign");
        let token = format!("{input}.{}", B64.encode(signature));
        let mut config = config();
        config.algorithms = BTreeSet::from([Algorithm::RS256]);
        let keys = KeySet::parse(
            &serde_json::to_vec(&json!({"keys":[jwk]})).expect("JWKS"),
            &config.algorithms,
        )
        .expect("RS256 keys");
        assert!(
            Parsed::parse(&token)
                .expect("JWT")
                .verify(
                    &config,
                    &keys,
                    OffsetDateTime::from_unix_timestamp(NOW).expect("time")
                )
                .is_ok()
        );
        config.algorithms = BTreeSet::from([Algorithm::PS256]);
        assert!(
            Parsed::parse(&token)
                .expect("JWT")
                .verify(
                    &config,
                    &keys,
                    OffsetDateTime::from_unix_timestamp(NOW).expect("time")
                )
                .is_err()
        );
    }
}
