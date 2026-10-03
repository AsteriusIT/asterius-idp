//! Slow transactional lifecycle checks; local acceptance uses the real HTTP fixture.
use asterius_domain::temporary_entitlements::*;
use asterius_domain::{
    AuthenticationMethod, ClientId, Grant, GrantAuthentication, TenantId, UserId,
};
use asterius_store_pg::{MIGRATOR, PgTemporaryEntitlements};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use std::str::FromStr as _;
use time::OffsetDateTime;
use uuid::Uuid;
struct Fixture {
    admin: sqlx::PgPool,
    pool: sqlx::PgPool,
    schema: String,
    tenant: TenantId,
    owner: UserId,
    requester: SessionActor,
    approver: SessionActor,
    second: SessionActor,
    port: PgTemporaryEntitlements,
}
impl Fixture {
    async fn new() -> Self {
        let url = std::env::var("DATABASE_URL").expect("DATABASE_URL");
        let schema = format!("temporary_entitlements_{}", Uuid::new_v4().simple());
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .expect("database");
        sqlx::query(&format!("create schema {schema}"))
            .execute(&admin)
            .await
            .expect("schema");
        let options = PgConnectOptions::from_str(&url)
            .expect("url")
            .options([("search_path", schema.as_str())]);
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .connect_with(options)
            .await
            .expect("pool");
        MIGRATOR.run(&pool).await.expect("migrations");
        let tenant = TenantId::new("one");
        sqlx::query("insert into tenants(tenant_id,issuer,display_name,default_resource) values('one','https://one.example','One','https://api.example/')").execute(&pool).await.expect("tenant");
        sqlx::query("insert into resource_servers(tenant_id,identifier,scopes) values('one','https://api.example/',array['read'])").execute(&pool).await.expect("resource");
        sqlx::query("insert into clients(tenant_id,client_id,client_name,token_endpoint_auth_method,jwks) values('one','app','App','private_key_jwt','{\"keys\":[]}'::jsonb)").execute(&pool).await.expect("client");
        sqlx::query(
            "insert into client_roles(tenant_id,client_id,name) values('one','app','approve')",
        )
        .execute(&pool)
        .await
        .expect("role");
        let owner = UserId::generate();
        let requester = actor();
        let approver = actor();
        let second = actor();
        for (name, user, digest) in [
            ("owner", &owner, "owner"),
            (
                "requester",
                &requester.user,
                requester.session_digest.as_str(),
            ),
            ("approver", &approver.user, approver.session_digest.as_str()),
            ("second", &second.user, second.session_digest.as_str()),
        ] {
            sqlx::query("insert into users(tenant_id,user_id,username) values('one',$1,$2)")
                .bind(user.as_uuid())
                .bind(name)
                .execute(&pool)
                .await
                .expect("user");
            sqlx::query("insert into sessions(tenant_id,session_id,public_sid,user_id,authenticated_at,expires_at,idle_expires_at,acr,amr) values('one',$1,$1,$2,clock_timestamp(),clock_timestamp()+interval '1 hour',clock_timestamp()+interval '1 hour',$3,array['pop'])")
                .bind(digest).bind(user.as_uuid()).bind(asterius_domain::acr::PASSKEY).execute(&pool).await.expect("session");
            sqlx::query("insert into session_assurance_proofs(tenant_id,session_id,acr,assurance_authenticated_at,assurance_policy_revision,assurance_methods) select 'one',$1,$2,authenticated_at,$3,array['pop'] from sessions where tenant_id='one' and session_id=$1")
                .bind(digest).bind(asterius_domain::acr::PASSKEY).bind(revision()).execute(&pool).await.expect("proof");
        }
        let port = PgTemporaryEntitlements::new(pool.clone());
        Self {
            admin,
            pool,
            schema,
            tenant,
            owner,
            requester,
            approver,
            second,
            port,
        }
    }
    async fn entitlement(&self) -> Entitlement {
        let c = EntitlementConfiguration {
            owner_user_id: *self.owner.as_uuid(),
            client_id: "app".into(),
            resource: "https://api.example/".into(),
            role_name: "approve".into(),
            permissions: vec!["read".into()],
            approver_user_ids: vec![
                *self.owner.as_uuid(),
                *self.requester.user.as_uuid(),
                *self.approver.user.as_uuid(),
                *self.second.user.as_uuid(),
            ],
            requester_acr: asterius_domain::acr::PASSKEY.into(),
            approver_acr: asterius_domain::acr::PASSKEY.into(),
            max_duration_seconds: 900,
            max_eligibility_seconds: 86400,
            enabled: true,
        };
        let e = self
            .port
            .configure(&self.tenant, &self.owner, None, None, c)
            .await
            .expect("configuration");
        let now = OffsetDateTime::now_utc().unix_timestamp();
        self.port
            .set_eligibility(
                &self.tenant,
                &self.owner,
                e.entitlement_id,
                EligibilityChange {
                    user_id: *self.requester.user.as_uuid(),
                    not_before: now - 1,
                    expires_at: now + 600,
                    expected_revision: None,
                },
            )
            .await
            .expect("eligibility");
        e
    }
    fn grant(&self) -> Grant {
        let now = OffsetDateTime::now_utc();
        let mut grant = Grant::new(self.tenant.clone(), ClientId::new("app"), now);
        grant.user = Some(self.requester.user);
        grant.scopes.insert("read".into());
        grant.resources.insert("https://api.example/".into());
        grant.authentication = Some(GrantAuthentication {
            authenticated_at: now,
            assurance_authenticated_at: Some(now),
            assurance_policy_revision: Some(revision()),
            assurance_methods: vec![AuthenticationMethod::Passkey],
            acr: Some(asterius_domain::acr::PASSKEY.into()),
            amr: vec![AuthenticationMethod::Passkey],
        });
        grant
    }
    async fn close(self) {
        self.pool.close().await;
        sqlx::query(&format!("drop schema {} cascade", self.schema))
            .execute(&self.admin)
            .await
            .expect("drop schema");
        self.admin.close().await;
    }
}
fn actor() -> SessionActor {
    SessionActor {
        user: UserId::generate(),
        session_digest: Uuid::new_v4().to_string(),
    }
}
fn revision() -> String {
    asterius_domain::sha256_hex(
        asterius_domain::AcrPolicy::default()
            .to_json()
            .to_string()
            .as_bytes(),
    )
}
#[tokio::test]
#[ignore = "requires PostgreSQL; CI runs isolated temporary entitlement lifecycle"]
// These dependent transitions deliberately share one isolated fixture and immutable request.
#[allow(clippy::too_many_lines)]
async fn temporary_entitlement_independence_replay_concurrency_and_revocation() {
    let f = Fixture::new().await;
    let e = f.entitlement().await;
    let submission = RequestActivation {
        entitlement_id: e.entitlement_id,
        duration_seconds: 300,
        reason: "Resolve an incident".into(),
        idempotency_key: Uuid::new_v4(),
    };
    let r = f
        .port
        .request(&f.tenant, &f.requester, submission.clone())
        .await
        .expect("request");
    assert_eq!(
        f.port
            .request(&f.tenant, &f.requester, submission.clone())
            .await
            .expect("request replay")
            .request_id,
        r.request_id
    );
    let mut changed = submission;
    changed.duration_seconds = 200;
    assert!(
        f.port
            .request(&f.tenant, &f.requester, changed)
            .await
            .is_err()
    );
    let decision = DecideRequest {
        request_id: r.request_id,
        decision: Decision::Approve,
        idempotency_key: Uuid::new_v4(),
    };
    assert!(
        f.port
            .decide(&f.tenant, &f.requester, decision.clone())
            .await
            .is_err()
    );
    let owner_actor = SessionActor {
        user: f.owner,
        session_digest: "owner".into(),
    };
    assert!(
        f.port
            .decide(&f.tenant, &owner_actor, decision.clone())
            .await
            .is_err()
    );
    let second = DecideRequest {
        idempotency_key: Uuid::new_v4(),
        ..decision.clone()
    };
    let (one, two) = tokio::join!(
        f.port.decide(&f.tenant, &f.approver, decision.clone()),
        f.port.decide(&f.tenant, &f.second, second.clone())
    );
    assert_ne!(one.is_ok(), two.is_ok());
    let (actor, key) = if one.is_ok() {
        (&f.approver, decision.idempotency_key)
    } else {
        (&f.second, second.idempotency_key)
    };
    // Check exact lost-response replay for the actual winner; no second activation exists.
    {
        assert_eq!(
            f.port
                .decide(
                    &f.tenant,
                    actor,
                    DecideRequest {
                        idempotency_key: key,
                        ..decision.clone()
                    }
                )
                .await
                .expect("approval replay")
                .status,
            RequestStatus::Approved
        );
    }
    let live = f
        .port
        .resolve_for_grant(&f.tenant, &f.grant())
        .await
        .expect("resolution");
    assert_eq!(live.roles.len(), 1);
    let mut wider = f.grant();
    wider.scopes.insert("write".into());
    assert!(
        f.port
            .resolve_for_grant(&f.tenant, &wider)
            .await
            .expect("wider permissions")
            .roles
            .is_empty()
    );
    let mut delegated = f.grant();
    delegated
        .actor_chain
        .push(serde_json::json!({"sub":"someone"}));
    assert!(
        f.port
            .resolve_for_grant(&f.tenant, &delegated)
            .await
            .expect("delegated")
            .roles
            .is_empty()
    );
    let revoke = RevokeActivation {
        activation_id: live.roles[0].activation_id,
        reason: "Incident resolved".into(),
        idempotency_key: Uuid::new_v4(),
    };
    let result = f
        .port
        .revoke(&f.tenant, &f.requester, revoke.clone())
        .await
        .expect("revoke");
    assert!(result.revoked_at.is_some());
    assert_eq!(
        f.port
            .revoke(&f.tenant, &f.requester, revoke)
            .await
            .expect("revoke replay")
            .revoked_at,
        result.revoked_at
    );
    assert!(
        f.port
            .resolve_for_grant(&f.tenant, &f.grant())
            .await
            .expect("revoked")
            .roles
            .is_empty()
    );
    let (count,): (i64,) = sqlx::query_as(
        "select count(*) from temporary_entitlement_activations where tenant_id='one'",
    )
    .fetch_one(&f.pool)
    .await
    .expect("count");
    assert_eq!(count, 1);
    let (events,):(i64,)=sqlx::query_as("select count(*) from audit_events where tenant_id='one' and detail->>'operation' like 'temporary_entitlement.%'").fetch_one(&f.pool).await.expect("audit");
    assert!(events >= 6);
    f.close().await;
}
#[tokio::test]
#[ignore = "requires PostgreSQL; CI runs frozen-proof and catalogue lifecycle"]
async fn temporary_entitlement_frozen_proof_and_catalogue_aba_fail_closed() {
    let f = Fixture::new().await;
    let e = f.entitlement().await;
    // Historical AMR says passkey, but the only fresh proof was a password.
    sqlx::query("update session_assurance_proofs set assurance_methods=array['pwd'] where tenant_id='one' and session_id=$1").bind(&f.requester.session_digest).execute(&f.pool).await.expect("weak proof");
    let c = RequestActivation {
        entitlement_id: e.entitlement_id,
        duration_seconds: 60,
        reason: "Needed temporarily".into(),
        idempotency_key: Uuid::new_v4(),
    };
    assert!(
        f.port
            .request(&f.tenant, &f.requester, c.clone())
            .await
            .is_err()
    );
    sqlx::query("update session_assurance_proofs set assurance_methods=array['pop'] where tenant_id='one' and session_id=$1").bind(&f.requester.session_digest).execute(&f.pool).await.expect("strong proof");
    let r = f
        .port
        .request(&f.tenant, &f.requester, c)
        .await
        .expect("request");
    sqlx::query("update resource_servers set scopes=array[]::text[] where tenant_id='one'")
        .execute(&f.pool)
        .await
        .expect("catalogue narrow");
    sqlx::query("update resource_servers set scopes=array['read'] where tenant_id='one'")
        .execute(&f.pool)
        .await
        .expect("catalogue widen");
    assert!(
        !f.port
            .get(&f.tenant, &f.owner, e.entitlement_id)
            .await
            .expect("config")
            .configuration
            .enabled
    );
    assert!(
        f.port
            .decide(
                &f.tenant,
                &f.approver,
                DecideRequest {
                    request_id: r.request_id,
                    decision: Decision::Approve,
                    idempotency_key: Uuid::new_v4()
                }
            )
            .await
            .is_err()
    );
    f.close().await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL and real DB-clock expiry; CI runs lifecycle"]
async fn temporary_entitlement_expiry_denies_before_reconciliation_and_is_idempotent() {
    let f = Fixture::new().await;
    let entitlement = f.entitlement().await;
    let request = f
        .port
        .request(
            &f.tenant,
            &f.requester,
            RequestActivation {
                entitlement_id: entitlement.entitlement_id,
                duration_seconds: 1,
                reason: "One-second expiry boundary".into(),
                idempotency_key: Uuid::new_v4(),
            },
        )
        .await
        .expect("request");
    let decision = DecideRequest {
        request_id: request.request_id,
        decision: Decision::Approve,
        idempotency_key: Uuid::new_v4(),
    };
    f.port
        .decide(&f.tenant, &f.approver, decision.clone())
        .await
        .expect("approval");
    tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
    let grant = f.grant();
    assert!(
        f.port
            .resolve_for_grant(&f.tenant, &grant)
            .await
            .expect("expired resolution")
            .roles
            .is_empty()
    );
    let before = f
        .port
        .account(&f.tenant, &f.requester)
        .await
        .expect("account");
    assert_eq!(before.activations[0].status, ActivationStatus::Expired);
    assert!(before.activations[0].expiry_recorded_at.is_none());
    assert_eq!(
        f.port
            .reconcile_expired(&f.tenant, 100)
            .await
            .expect("reconcile"),
        1
    );
    assert_eq!(
        f.port
            .reconcile_expired(&f.tenant, 100)
            .await
            .expect("repeat reconcile"),
        0
    );
    let replay = f
        .port
        .decide(&f.tenant, &f.approver, decision)
        .await
        .expect("original approval replay");
    assert_eq!(replay.status, RequestStatus::Approved);
    assert!(
        f.port
            .resolve_for_grant(&f.tenant, &grant)
            .await
            .expect("replay cannot extend")
            .roles
            .is_empty()
    );
    let (events,): (i64,) = sqlx::query_as("select count(*) from audit_events where tenant_id='one' and detail->>'operation'='temporary_entitlement.expired'").fetch_one(&f.pool).await.expect("audit");
    assert_eq!(events, 1);
    f.close().await;
}
