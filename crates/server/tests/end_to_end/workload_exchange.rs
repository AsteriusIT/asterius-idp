//! Controlled `TokenRequest` fixtures cross the real client-authenticated token endpoint.
use super::{
    B64, CLIENT_ASSERTION_TYPE, Capabilities, Client, ClientId, ClientRegistration, ClientStatus,
    Endpoint, Flow, OffsetDateTime, ProofKey, RESOURCE, StatusCode, SystemRandom, Value,
    client_credentials, json, jws,
};
use asterius_domain::workload::{Config, Registry};
use asterius_jose::verify::KeyResolver as _;
use aws_lc_rs::signature::KeyPair as _;
use aws_lc_rs::signature::{RSA_PKCS1_SHA256, RsaKeyPair};
use base64::Engine as _;

fn assertion(pair: &RsaKeyPair, claims: &Value) -> String {
    let input = format!(
        "{}.{}",
        B64.encode(br#"{"alg":"RS256","typ":"JWT","kid":"cluster"}"#),
        B64.encode(serde_json::to_vec(claims).expect("claims"))
    );
    let mut signature = vec![0; pair.public_modulus_len()];
    pair.sign(
        &RSA_PKCS1_SHA256,
        &SystemRandom::new(),
        input.as_bytes(),
        &mut signature,
    )
    .expect("TokenRequest fixture signature");
    format!("{input}.{}", B64.encode(signature))
}

#[tokio::test]
#[ignore = "requires DATABASE_URL; CI controlled TokenRequest fixture"]
// The full authenticated HTTP journey and its rejected fixtures share one tenant.
#[allow(clippy::too_many_lines)]
async fn kubernetes_projection_exchanges_once_and_never_widens() {
    let capabilities = Capabilities {
        token_exchange: true,
        ..Capabilities::default()
    };
    let mut flow = Flow::with_capabilities(capabilities)
        .await
        .expect("DATABASE_URL");
    let (client_key, jwks) = client_credentials();
    let mut client=Client {tenant:flow.tenant.id.clone(),id:ClientId::new("pod-client"),registration:ClientRegistration::from_json(&serde_json::to_vec(&json!({"grant_types":["urn:ietf:params:oauth:grant-type:token-exchange"],"response_types":[],"scope":"ledger.read ledger.write","token_endpoint_auth_method":"private_key_jwt","jwks":jwks,"authorization_details_types":["urn:asterius:workload-actions"]})).expect("client"),capabilities).expect("registration"),status:ClientStatus::Active,created_at:OffsetDateTime::now_utc(),updated_at:OffsetDateTime::now_utc()};
    client.registration.resources.insert(RESOURCE.to_owned());
    flow.store
        .scope(flow.tenant.id.clone())
        .clients(capabilities)
        .upsert(&client)
        .await
        .expect("client");
    flow.register_resource_server(RESOURCE, Some(&["ledger.read", "ledger.write"]))
        .await;
    let schema = json!({"type":"object","required":["type","actions","locations"],"additionalProperties":false,"properties":{"type":{"enum":["urn:asterius:workload-actions"]},"actions":{"type":"array","maxItems":64,"items":{"type":"string","maxLength":128}},"locations":{"type":"array","maxItems":1,"items":{"type":"string","maxLength":1024}}}});
    flow.store
        .scope(flow.tenant.id.clone())
        .authorization_details_types()
        .register(
            &asterius_domain::AuthorizationDetailsType {
                name: "urn:asterius:workload-actions".to_owned(),
                schema: asterius_domain::JsonSchema::parse(&schema).expect("schema"),
                consent_template: None,
            },
            &schema,
        )
        .await
        .expect("type");
    let pair = RsaKeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048).expect("cluster key");
    let public = pair.public_key();
    let key = json!({"kid":"cluster","kty":"RSA","alg":"RS256","n":B64.encode(public.modulus().big_endian_without_leading_zero()),"e":B64.encode(public.exponent().big_endian_without_leading_zero())});
    let audience = format!("urn:asterius:workload:{}:inventory", flow.tenant.id);
    let mut config:Config=serde_json::from_value(json!({"issuer":"https://cluster.example","audience":audience,"subject":"system:serviceaccount:apps:inventory","provider":"kubernetes","principal":"workload:inventory","clients":["pod-client"],"scopes":["ledger.read"],"resources":[RESOURCE],"actions":["read"],"required_claims":{"/kubernetes.io/namespace":"apps","/kubernetes.io/serviceaccount/name":"inventory","/kubernetes.io/serviceaccount/uid":"sa-uid"},"algorithms":["RS256"],"keys":{"kind":"inline","jwks":{"keys":[key]}},"enabled":true})).expect("trust");
    let registry = asterius_store_pg::PgWorkloadTrusts::new(flow.store.pool().clone());
    let saved = registry
        .put(
            &flow.tenant.id,
            "inventory",
            &config,
            None,
            asterius_domain::Actor::System,
            OffsetDateTime::now_utc(),
        )
        .await
        .expect("trust");
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let claims = json!({"iss":"https://cluster.example","sub":"system:serviceaccount:apps:inventory","aud":[audience],"iat":now,"exp":now+3600,"nbf":now,"kubernetes.io":{"namespace":"apps","serviceaccount":{"name":"inventory","uid":"sa-uid"},"pod":{"name":"inventory-pod","uid":"pod-uid"}}});
    let projected = assertion(&pair, &claims);
    let dpop = ProofKey::generate();
    let details =
        json!([{"type":"urn:asterius:workload-actions","actions":["read"],"locations":[RESOURCE]}])
            .to_string();
    let issued = flow
        .token_as(
            "pod-client",
            Some(&client_key),
            &dpop,
            "client-auth-1",
            &[
                (
                    "grant_type",
                    "urn:ietf:params:oauth:grant-type:token-exchange",
                ),
                ("subject_token_type", "urn:ietf:params:oauth:token-type:jwt"),
                ("subject_token", &projected),
                ("resource", RESOURCE),
                ("scope", "ledger.read"),
                ("authorization_details", &details),
            ],
        )
        .await;
    assert_eq!(issued.status, StatusCode::OK, "{}", issued.text());
    let body = issued.json();
    assert_eq!(body["token_type"], "DPoP");
    assert!(
        body["expires_in"]
            .as_i64()
            .is_some_and(|ttl| ttl > 0 && ttl <= 300)
    );
    assert!(body.get("refresh_token").is_none());
    let access = body["access_token"].as_str().expect("access");
    let keys = asterius_jose::client_keys::parse_jwk_set(
        &serde_json::to_vec(&flow.jwks().await).expect("JWKS"),
    )
    .expect("keys");
    let parsed = jws::parse(access).expect("JWS");
    let payload = keys
        .candidates(parsed.kid().as_ref())
        .iter()
        .find_map(|key| jws::parse(access).expect("JWT").verify(key).ok())
        .expect("resource verifies access signature");
    let api_claims: Value = serde_json::from_slice(&payload).expect("claims");
    assert_eq!(api_claims["aud"], RESOURCE);
    assert_eq!(api_claims["sub"], "workload:inventory");
    assert_eq!(api_claims["scope"], "ledger.read");
    assert_eq!(api_claims["cnf"]["jkt"], dpop.thumbprint().as_str());
    assert_eq!(
        api_claims["authorization_details"][0]["actions"],
        json!(["read"])
    );
    // Offline deletion has no TokenReview callback: freshness plus output TTL is at most600s.
    assert!(api_claims["exp"].as_i64().expect("exp") - now <= 300);
    let replay = flow
        .token_as(
            "pod-client",
            Some(&client_key),
            &dpop,
            "client-auth-replay",
            &[
                (
                    "grant_type",
                    "urn:ietf:params:oauth:grant-type:token-exchange",
                ),
                ("subject_token_type", "urn:ietf:params:oauth:token-type:jwt"),
                ("subject_token", &projected),
                ("resource", RESOURCE),
            ],
        )
        .await;
    assert_eq!(replay.json()["error"], "invalid_grant");
    for (index, (pointer, value)) in [
        ("/iss", json!("https://other-cluster.example")),
        ("/aud", json!("wrong-audience")),
        ("/kubernetes.io/namespace", json!("other")),
        ("/kubernetes.io/serviceaccount/name", json!("other")),
        ("/kubernetes.io/serviceaccount/uid", json!("recreated-sa")),
        ("/kubernetes.io/pod/uid", json!("")),
        ("/exp", json!(now - 1)),
        ("/iat", json!(now - 301)),
    ]
    .into_iter()
    .enumerate()
    {
        let mut rejected = claims.clone();
        *rejected.pointer_mut(pointer).expect("field") = value;
        if pointer == "/iat" {
            rejected["exp"] = json!(now + 300);
        }
        let token = assertion(&pair, &rejected);
        let auth_jti = format!("client-auth-negative-{index}");
        let refusal = flow
            .token_as(
                "pod-client",
                Some(&client_key),
                &dpop,
                &auth_jti,
                &[
                    (
                        "grant_type",
                        "urn:ietf:params:oauth:grant-type:token-exchange",
                    ),
                    ("subject_token_type", "urn:ietf:params:oauth:token-type:jwt"),
                    ("subject_token", &token),
                    ("resource", RESOURCE),
                ],
            )
            .await;
        assert_eq!(
            refusal.json()["error"],
            "invalid_grant",
            "{}",
            refusal.text()
        );
    }
    let mut rotated = claims.clone();
    rotated["kubernetes.io"]["pod"]["uid"] = json!("rotated-pod");
    let fresh = assertion(&pair, &rotated);
    let wider = flow
        .token_as(
            "pod-client",
            Some(&client_key),
            &dpop,
            "client-auth-wide",
            &[
                (
                    "grant_type",
                    "urn:ietf:params:oauth:grant-type:token-exchange",
                ),
                ("subject_token_type", "urn:ietf:params:oauth:token-type:jwt"),
                ("subject_token", &fresh),
                ("resource", RESOURCE),
                ("scope", "ledger.write"),
            ],
        )
        .await;
    assert_eq!(wider.json()["error"], "invalid_scope");
    let wider_target = flow
        .token_as(
            "pod-client",
            Some(&client_key),
            &dpop,
            "client-auth-wide-target",
            &[
                (
                    "grant_type",
                    "urn:ietf:params:oauth:grant-type:token-exchange",
                ),
                ("subject_token_type", "urn:ietf:params:oauth:token-type:jwt"),
                ("subject_token", &fresh),
                ("resource", "https://other.example/"),
            ],
        )
        .await;
    assert_eq!(wider_target.json()["error"], "invalid_target");
    let wider_actions=json!([{"type":"urn:asterius:workload-actions","actions":["write"],"locations":[RESOURCE]}]).to_string();
    let wider_action = flow
        .token_as(
            "pod-client",
            Some(&client_key),
            &dpop,
            "client-auth-wide-action",
            &[
                (
                    "grant_type",
                    "urn:ietf:params:oauth:grant-type:token-exchange",
                ),
                ("subject_token_type", "urn:ietf:params:oauth:token-type:jwt"),
                ("subject_token", &fresh),
                ("resource", RESOURCE),
                ("authorization_details", &wider_actions),
            ],
        )
        .await;
    assert_eq!(
        wider_action.json()["error"],
        "invalid_authorization_details"
    );
    let token_url = Endpoint::Token.url(&flow.tenant.issuer);
    let token_path = format!("{}{}", flow.prefix(), Endpoint::Token.path());
    let client_proof = dpop.proof("POST", &token_url, &flow.next_jti());
    let bad_client = flow
        .post_form(
            &token_path,
            &[
                (
                    "grant_type",
                    "urn:ietf:params:oauth:grant-type:token-exchange",
                ),
                ("subject_token_type", "urn:ietf:params:oauth:token-type:jwt"),
                ("subject_token", &fresh),
                ("resource", RESOURCE),
                ("client_id", "pod-client"),
                ("client_assertion_type", CLIENT_ASSERTION_TYPE),
                ("client_assertion", &fresh),
            ],
            Some(&client_proof),
        )
        .await;
    assert_eq!(bad_client.json()["error"], "invalid_client");
    let fresh_reply = flow
        .token_as(
            "pod-client",
            Some(&client_key),
            &dpop,
            "client-auth-rotated",
            &[
                (
                    "grant_type",
                    "urn:ietf:params:oauth:grant-type:token-exchange",
                ),
                ("subject_token_type", "urn:ietf:params:oauth:token-type:jwt"),
                ("subject_token", &fresh),
                ("resource", RESOURCE),
            ],
        )
        .await;
    assert_eq!(fresh_reply.status, StatusCode::OK, "{}", fresh_reply.text());
    let bindings: i64 =
        sqlx::query_scalar("select count(*) from workload_grant_bindings where tenant_id=$1")
            .bind(flow.tenant.id.as_str())
            .fetch_one(flow.store.pool())
            .await
            .expect("bindings");
    assert_eq!(
        bindings, 2,
        "only two successful fresh assertions minted grants"
    );
    config.enabled = false;
    registry
        .put(
            &flow.tenant.id,
            "inventory",
            &config,
            Some(saved.version),
            asterius_domain::Actor::System,
            OffsetDateTime::now_utc(),
        )
        .await
        .expect("disable");
    let disabled = flow
        .token_as(
            "pod-client",
            Some(&client_key),
            &dpop,
            "client-auth-disabled",
            &[
                (
                    "grant_type",
                    "urn:ietf:params:oauth:grant-type:token-exchange",
                ),
                ("subject_token_type", "urn:ietf:params:oauth:token-type:jwt"),
                ("subject_token", &assertion(&pair, &claims)),
                ("resource", RESOURCE),
            ],
        )
        .await;
    assert_eq!(disabled.json()["error"], "invalid_grant");
    flow.tear_down().await;
}
