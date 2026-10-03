//! Historical evidence is tenant-bound, bounded, atomic with the chain and expires.
use asterius_domain::TenantId;
use asterius_domain::audit::{
    Actor, AuditEvent, AuditQuery, AuditSink, DetailValue, EventType, Outcome,
};
use asterius_domain::policy::explanation::{DecisionExplanation, RuleExplanation};
use asterius_store_pg::{MIGRATOR, PgAuditSink};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use std::str::FromStr as _;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires PostgreSQL; CI runs ignored store tests"]
// Keep the transactional lifecycle assertions together so cleanup follows every phase.
#[allow(clippy::too_many_lines)]
async fn diagnostic_snapshot_is_redacted_atomic_tenant_bound_and_expires() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL");
    let schema = format!("authorization_diagnostics_{}", Uuid::new_v4().simple());
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
        .expect("URL")
        .options([("search_path", schema.as_str())]);
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect_with(options)
        .await
        .expect("pool");
    MIGRATOR.run(&pool).await.expect("migrations");
    for name in ["one", "two"] {
        sqlx::query("insert into tenants(tenant_id,issuer,display_name,default_resource) values($1,$2,$1,'https://api.example/')")
            .bind(name).bind(format!("https://id.example/{name}")).execute(&pool).await.expect("tenant");
    }
    let one = TenantId::new("one");
    let two = TenantId::new("two");
    let now = OffsetDateTime::now_utc();
    let sink = PgAuditSink::new(pool.clone());
    let secret = "Bearer secretThatMustNeverBePresentInDiagnosticEvidence12345";
    let snapshot = DecisionExplanation {
        policy_revision: Some("sha256:old-policy".to_owned()),
        policy_updated_at: None,
        enforcement_point: "access_evaluation",
        rules: vec![RuleExplanation {
            id: secret.to_owned(),
            effect: "deny",
            applicable: true,
            matched: true,
            conditions: vec![],
        }],
        truncated: false,
    };
    sink.record_with_diagnostics(
        AuditEvent::new(
            one.clone(),
            EventType::ACCESS_EVALUATED,
            Outcome::Failure,
            Actor::System,
            now,
        ),
        &snapshot,
    )
    .await
    .expect("atomic record");
    let trail = sink.read_trail(&one).await.expect("trail");
    let asterius_domain::audit::AuditRecord::Event(event) = &trail[0] else {
        panic!("event");
    };
    let id = event
        .detail
        .iter()
        .find_map(|(key, value)| match (key.as_str(), value) {
            ("diagnostic_id", DetailValue::Text(id)) => Uuid::parse_str(id).ok(),
            _ => None,
        })
        .expect("reference");
    let evidence = sink
        .diagnostics(&one, id, now)
        .await
        .expect("query")
        .expect("snapshot");
    assert_eq!(evidence.diagnostics["policy_revision"], "sha256:old-policy");
    assert!(!evidence.diagnostics.to_string().contains(secret));
    assert!(
        sink.diagnostics(&two, id, now)
            .await
            .expect("foreign tenant")
            .is_none()
    );
    assert!(
        sink.diagnostics(&one, id, now + Duration::days(7))
            .await
            .expect("expiry")
            .is_none()
    );
    assert_eq!(sink.verify_chain(&one).await.expect("chain").records, 1);
    let absent = TenantId::new("absent");
    assert!(
        sink.record_with_diagnostics(
            AuditEvent::new(
                absent,
                EventType::ACCESS_EVALUATED,
                Outcome::Failure,
                Actor::System,
                now
            ),
            &snapshot
        )
        .await
        .is_err()
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("select count(*) from authorization_diagnostics")
            .fetch_one(&pool)
            .await
            .expect("count"),
        1
    );
    pool.close().await;
    sqlx::query(&format!("drop schema {schema} cascade"))
        .execute(&admin)
        .await
        .expect("cleanup");
}
