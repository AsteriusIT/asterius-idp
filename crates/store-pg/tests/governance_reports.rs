//! Slow report isolation/read-only regressions are exercised only by CI.
use asterius_domain::governance_reports::{GovernanceReports, Query, Reason};
use asterius_domain::{DomainError, TenantId, UserId};
use asterius_store_pg::{MIGRATOR, PgGovernanceReports};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use std::{collections::BTreeMap, str::FromStr as _};
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; CI ignored-only selector"]
async fn reports_keep_tenant_recovery_evidence_and_recheck_read_authority() {
    let url = std::env::var("DATABASE_URL").expect("ignored report test requires DATABASE_URL");
    let schema = format!("governance_reports_{}", Uuid::new_v4().simple());
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    sqlx::query(&format!("create schema {schema}"))
        .execute(&admin)
        .await
        .unwrap();
    let options = PgConnectOptions::from_str(&url)
        .unwrap()
        .options([("search_path", schema.as_str())]);
    let pool = PgPoolOptions::new()
        .max_connections(3)
        .connect_with(options)
        .await
        .unwrap();
    MIGRATOR.run(&pool).await.unwrap();
    let tenant = TenantId::new("reports");
    let actor = UserId::generate();
    let recovery = UserId::generate();
    for name in ["reports", "other"] {
        sqlx::query("insert into tenants(tenant_id,issuer,display_name,default_resource) values($1,$2,$1,'https://api.example')")
            .bind(name).bind(format!("https://id.example/{name}")).execute(&pool).await.unwrap();
        for (user, username) in [(actor, "actor"), (recovery, "recovery")] {
            sqlx::query("insert into users(tenant_id,user_id,username,created_at) values($1,$2,$3,clock_timestamp()-interval '400 days')")
                .bind(name).bind(user.as_uuid()).bind(username).execute(&pool).await.unwrap();
        }
    }
    sqlx::query("insert into user_roles(tenant_id,user_id,role,tenant_is_reserved) values('reports',$1,'security_auditor',false),('reports',$2,'tenant_admin',false)")
        .bind(actor.as_uuid()).bind(recovery.as_uuid()).execute(&pool).await.unwrap();
    let reports = PgGovernanceReports::new(pool.clone(), BTreeMap::new());
    let query = Query::parse("section=accounts&limit=1").unwrap();
    let page = reports.findings(&tenant, actor, &query).await.unwrap();
    assert_eq!(page.items.len(), 1);
    assert!(page.read_only);
    let mut items = page.items;
    if let Some(next) = page.next {
        let after = Query::parse(&format!("section=accounts&limit=1&after={next}")).unwrap();
        items.extend(
            reports
                .findings(&tenant, actor, &after)
                .await
                .unwrap()
                .items,
        );
        assert!(
            reports
                .findings(&TenantId::new("other"), actor, &after)
                .await
                .is_err()
        );
    }
    let item = items
        .iter()
        .find(|item| item.evidence["user_id"] == recovery.as_uuid().to_string())
        .unwrap();
    assert!(item.reasons.contains(&Reason::ProtectedRecoveryAccount));
    assert!(item.reasons.contains(&Reason::UnknownActivity));
    assert!(!item.reasons.contains(&Reason::UpstreamDeleted));
    sqlx::query("delete from user_roles where tenant_id='reports' and user_id=$1")
        .bind(actor.as_uuid())
        .execute(&pool)
        .await
        .unwrap();
    assert!(matches!(
        reports.findings(&tenant, actor, &query).await,
        Err(DomainError::NotFound)
    ));
    let count: i64 = sqlx::query_scalar("select count(*) from users")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 4);
    pool.close().await;
    sqlx::query(&format!("drop schema {schema} cascade"))
        .execute(&admin)
        .await
        .unwrap();
    admin.close().await;
}
