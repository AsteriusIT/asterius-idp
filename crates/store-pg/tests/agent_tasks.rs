//! Task approvals, durable fences and rollback against a disposable CI schema.
use asterius_domain::agent_tasks::{Binding, Permissions};
use asterius_domain::keys::AccessIssuance;
use asterius_domain::{
    ClientId, CompactJws, DomainError, Grant, GrantType, Signer, SigningAlgorithm, TenantId, UserId,
};
use asterius_store_pg::agent_tasks::{Approval, PgAgentTasks, TaskSigner};
use asterius_store_pg::{MIGRATOR, PgAuditSink, PgGrantRepository};
use serde_json::{Value, json};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use std::{collections::BTreeSet, str::FromStr as _};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

#[derive(Debug, Clone)]
struct ControlledSigner {
    fail: bool,
}
#[async_trait::async_trait]
impl Signer for ControlledSigner {
    async fn prepare(
        &self,
        _: &TenantId,
        _: Option<SigningAlgorithm>,
    ) -> Result<Option<Box<dyn Signer + '_>>, DomainError> {
        Ok(Some(Box::new(self.clone())))
    }
    async fn sign(
        &self,
        _: &TenantId,
        _: Option<SigningAlgorithm>,
        _: &'static str,
        claims: &Value,
    ) -> Result<CompactJws, DomainError> {
        if self.fail {
            return Err(DomainError::invalid("fixture", "controlled signer failure"));
        }
        // Carry claims for assertions without pretending this is cryptographic
        // evidence. The separate real HTTPS fixture verifies actual signatures.
        Ok(CompactJws::new(claims.to_string()))
    }
}
struct Fixture {
    pool: sqlx::PgPool,
    admin: sqlx::PgPool,
    schema: String,
    tenant: TenantId,
    owner: UserId,
    root: Grant,
    tasks: PgAgentTasks,
    audit: PgAuditSink,
}
impl Fixture {
    async fn new() -> Self {
        let url = std::env::var("DATABASE_URL").expect("CI PostgreSQL URL");
        let schema = format!("agent_tasks_{}", Uuid::new_v4().simple());
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .expect("admin connection");
        sqlx::query(&format!("create schema {schema}"))
            .execute(&admin)
            .await
            .expect("isolated schema");
        let options = PgConnectOptions::from_str(&url)
            .expect("URL")
            .options([("search_path", schema.as_str())]);
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .connect_with(options)
            .await
            .expect("pool");
        MIGRATOR.run(&pool).await.expect("migrations");
        let tenant = TenantId::new("task");
        let owner = UserId::new(Uuid::new_v4());
        sqlx::query("insert into tenants(tenant_id,issuer,display_name,default_resource) values('task','https://as.example/task','Task','https://api.example/')").execute(&pool).await.expect("tenant");
        sqlx::query("insert into users(tenant_id,user_id,username,status) values('task',$1,'owner','active')").bind(owner.as_uuid()).execute(&pool).await.expect("owner");
        sqlx::query("insert into clients(tenant_id,client_id,client_name,token_endpoint_auth_method,grant_types,scopes,resources,jwks,is_agent,agent_owner_user_id,agent_policy,authorization_details_types) values('task','agent','Agent','private_key_jwt',array['client_credentials','urn:ietf:params:oauth:grant-type:token-exchange'],array['read','write'],array['https://api.example/'],'{\"keys\":[]}'::jsonb,true,$1,'{\"grant_types\":[\"client_credentials\",\"urn:ietf:params:oauth:grant-type:token-exchange\"],\"max_delegation_depth\":2}'::jsonb,array['urn:asterius:workload-actions'])")
            .bind(owner.as_uuid()).execute(&pool).await.expect("agent");
        sqlx::query("insert into resource_servers(tenant_id,identifier,scopes) values('task','https://api.example/',array['read','write'])").execute(&pool).await.expect("resource");
        let rar_schema: Value = serde_json::from_str(include_str!(
            "../../../examples/kubernetes/workload-exchange/actions-schema.json"
        ))
        .expect("schema fixture");
        sqlx::query("insert into authorization_details_types(tenant_id,type_name,schema) values('task','urn:asterius:workload-actions',$1)").bind(rar_schema).execute(&pool).await.expect("RAR registration");
        let now = OffsetDateTime::now_utc();
        let mut root = Grant::new(tenant.clone(), ClientId::new("agent"), now);
        root.user = Some(owner);
        root.scopes = BTreeSet::from(["read".to_owned(), "write".to_owned()]);
        root.resources.insert("https://api.example/".to_owned());
        root.authorization_details = vec![
            json!({"type":"urn:asterius:workload-actions","actions":["read","write"],"locations":["https://api.example/"]}),
        ];
        root.expires_at = Some(now + Duration::hours(1));
        root.claimed_at = Some(now);
        PgGrantRepository::new(pool.clone(), tenant.clone())
            .create(&root)
            .await
            .expect("human-authorized root fixture");
        Self {
            tasks: PgAgentTasks::new(pool.clone()),
            audit: PgAuditSink::new(pool.clone()),
            pool,
            admin,
            schema,
            tenant,
            owner,
            root,
        }
    }
    fn permissions(&self) -> Permissions {
        Permissions {
            scopes: BTreeSet::from(["read".to_owned()]),
            resources: self.root.resources.clone(),
            authorization_details: vec![
                json!({"type":"urn:asterius:workload-actions","actions":["read"],"locations":["https://api.example/"]}),
            ],
            max_delegation_depth: 2,
        }
    }
    async fn approve(&self) -> Binding {
        let now = OffsetDateTime::now_utc();
        self.tasks
            .approve(
                &self.tenant,
                Approval {
                    owner: self.owner,
                    root: &self.root,
                    permissions: &self.permissions(),
                    label: "controlled run",
                    expiry: now + Duration::minutes(10),
                    now,
                },
                &self.audit,
            )
            .await
            .expect("owner approval")
    }
    async fn child(&self, binding: &Binding) -> Grant {
        let now = OffsetDateTime::now_utc();
        let mut grant = Grant::new(self.tenant.clone(), ClientId::new("agent"), now);
        grant.scopes.insert("read".to_owned());
        grant.resources = self.root.resources.clone();
        let lifetime = self
            .tasks
            .prepare(
                &mut grant,
                Some(&binding.task_id.to_string()),
                None,
                now,
                Duration::hours(1),
                &self.audit,
            )
            .await
            .expect("prepared child");
        assert!(lifetime <= Duration::seconds(300));
        grant
    }
    fn claims(grant: &Grant, jti: &str) -> Value {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        json!({"iat":now,"exp":now+60,"jti":jti,"client_id":grant.client.as_str(),"scope":"read","aud":["https://api.example/"],"authorization_details":grant.authorization_details,"roles":["owner-admin"],"resource_access":{"agent":{"roles":["admin"]}}})
    }
    async fn issue(&self, grant: &Grant, jti: &str) -> Value {
        let inner = ControlledSigner { fail: false };
        let signer = TaskSigner {
            tasks: &self.tasks,
            inner: &inner,
            audit: &self.audit,
        };
        let jwt = signer
            .sign_access(
                &self.tenant,
                AccessIssuance {
                    device_binding: None,
                    grant,
                    kind: GrantType::ClientCredentials,
                    implicit_resources: &[],
                },
                None,
                "at+jwt",
                &Self::claims(grant, jti),
            )
            .await
            .expect("controlled fenced issuance");
        serde_json::from_str(jwt.as_str()).expect("controlled signed claims")
    }
    async fn derived(&self, parent: &Grant) -> Grant {
        let now = OffsetDateTime::now_utc();
        let mut child = Grant::new(self.tenant.clone(), parent.client.clone(), now);
        child.parent = Some(parent.id.clone());
        child.scopes = parent.scopes.clone();
        child.resources = parent.resources.clone();
        self.tasks
            .prepare(
                &mut child,
                None,
                None,
                now,
                Duration::seconds(60),
                &self.audit,
            )
            .await
            .expect("inherited approval");
        child
    }
    async fn cleanup(self) {
        self.pool.close().await;
        sqlx::query(&format!("drop schema {} cascade", self.schema))
            .execute(&self.admin)
            .await
            .expect("cleanup");
        self.admin.close().await;
    }
}

#[tokio::test]
#[ignore = "requires PostgreSQL; CI runs ignored store tests"]
#[expect(
    clippy::too_many_lines,
    reason = "One durable approval fixture connects signed lineage, JTI replay and immutable reapproval assertions"
)]
async fn agent_task_signing_commits_private_lineage_and_rejects_replay_expansion() {
    let fixture = Fixture::new().await;
    let binding = fixture.approve().await;
    let grant = fixture.child(&binding).await;
    let inner = ControlledSigner { fail: false };
    let signer = TaskSigner {
        tasks: &fixture.tasks,
        inner: &inner,
        audit: &fixture.audit,
    };
    let claims = Fixture::claims(&grant, "first");
    let serialized = signer
        .sign_access(
            &fixture.tenant,
            AccessIssuance {
                device_binding: None,
                implicit_resources: &[],
                grant: &grant,
                kind: GrantType::ClientCredentials,
            },
            None,
            "at+jwt",
            &claims,
        )
        .await
        .expect("fenced issuance");
    let claims: Value = serde_json::from_str(serialized.as_str()).expect("controlled claims");
    assert_eq!(claims["task_id"], binding.task_id.to_string());
    assert!(claims.get("roles").is_none());
    assert!(claims.get("resource_access").is_none());
    assert_eq!(
        fixture
            .tasks
            .token_grant(
                &fixture.tenant,
                "first",
                binding.task_id,
                binding.approval_revision
            )
            .await
            .expect("private lineage"),
        Some(grant.id.clone())
    );
    assert!(
        fixture
            .tasks
            .token_grant(
                &TenantId::new("other"),
                "first",
                binding.task_id,
                binding.approval_revision
            )
            .await
            .expect("foreign tenant")
            .is_none()
    );
    assert!(
        signer
            .sign_access(
                &fixture.tenant,
                AccessIssuance {
                    device_binding: None,
                    implicit_resources: &[],
                    grant: &grant,
                    kind: GrantType::ClientCredentials
                },
                None,
                "at+jwt",
                &claims
            )
            .await
            .is_err()
    );
    let mut expanded = fixture.child(&binding).await;
    expanded.scopes.insert("write".to_owned());
    assert!(
        signer
            .sign_access(
                &fixture.tenant,
                AccessIssuance {
                    device_binding: None,
                    implicit_resources: &[],
                    grant: &expanded,
                    kind: GrantType::ClientCredentials
                },
                None,
                "at+jwt",
                &Fixture::claims(&expanded, "expanded")
            )
            .await
            .is_err()
    );
    assert!(
        fixture
            .tasks
            .approve(
                &fixture.tenant,
                Approval {
                    owner: fixture.owner,
                    root: &fixture.root,
                    permissions: &fixture.permissions(),
                    label: "same root again",
                    expiry: OffsetDateTime::now_utc() + Duration::minutes(5),
                    now: OffsetDateTime::now_utc()
                },
                &fixture.audit
            )
            .await
            .is_err()
    );
    fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL; CI runs ignored store tests"]
async fn agent_task_failed_signature_rolls_back_child_and_jti() {
    let fixture = Fixture::new().await;
    let binding = fixture.approve().await;
    let grant = fixture.child(&binding).await;
    let inner = ControlledSigner { fail: true };
    let signer = TaskSigner {
        tasks: &fixture.tasks,
        inner: &inner,
        audit: &fixture.audit,
    };
    assert!(
        signer
            .sign_access(
                &fixture.tenant,
                AccessIssuance {
                    device_binding: None,
                    implicit_resources: &[],
                    grant: &grant,
                    kind: GrantType::ClientCredentials
                },
                None,
                "at+jwt",
                &Fixture::claims(&grant, "rollback")
            )
            .await
            .is_err()
    );
    let count: i64 = sqlx::query_scalar("select count(*) from agent_task_tokens")
        .fetch_one(&fixture.pool)
        .await
        .expect("token count");
    assert_eq!(count, 0);
    assert!(
        PgGrantRepository::new(fixture.pool.clone(), fixture.tenant.clone())
            .find(&grant.id)
            .await
            .expect("child lookup")
            .is_none()
    );
    fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL; CI runs ignored store tests"]
async fn agent_task_owner_disable_expiry_and_refresh_cannot_reactivate() {
    let fixture = Fixture::new().await;
    let binding = fixture.approve().await;
    let mut grant = fixture.child(&binding).await;
    assert!(
        fixture
            .tasks
            .prepare(
                &mut grant,
                None,
                None,
                binding.expires_at,
                Duration::seconds(60),
                &fixture.audit
            )
            .await
            .is_err()
    );
    sqlx::query("update users set status='disabled' where tenant_id='task' and user_id=$1")
        .bind(fixture.owner.as_uuid())
        .execute(&fixture.pool)
        .await
        .expect("disable");
    sqlx::query("update users set status='active' where tenant_id='task' and user_id=$1")
        .bind(fixture.owner.as_uuid())
        .execute(&fixture.pool)
        .await
        .expect("reactivate account only");
    let queued: bool = sqlx::query_scalar("select exists(select 1 from agent_task_withdrawals where tenant_id='task' and task_id=$1 and completed_at is null)")
        .bind(binding.task_id).fetch_one(&fixture.pool).await.expect("owner lifecycle cleanup queue");
    assert!(queued);
    assert!(
        !fixture
            .tasks
            .grant_active(&fixture.tenant, &fixture.root.id)
            .await
            .expect("reactivation does not restore authority")
    );

    let inner = ControlledSigner { fail: false };
    let signer = TaskSigner {
        tasks: &fixture.tasks,
        inner: &inner,
        audit: &fixture.audit,
    };
    assert!(
        signer
            .sign_access(
                &fixture.tenant,
                AccessIssuance {
                    device_binding: None,
                    implicit_resources: &[],
                    grant: &grant,
                    kind: GrantType::ClientCredentials
                },
                None,
                "at+jwt",
                &Fixture::claims(&grant, "terminal")
            )
            .await
            .is_err()
    );
    assert!(sqlx::query("insert into refresh_tokens(tenant_id,token_hash,grant_id,client_id,scopes,dpop_jkt,absolute_expires_at) values('task',decode('aa','hex'),$1,'agent',array['read'],'fixture',now()+interval '1 day')")
        .bind(binding.root_grant_id).execute(&fixture.pool).await.is_err());
    fixture.cleanup().await;
}

#[derive(Debug)]
struct PausedSigner {
    entered: tokio::sync::Semaphore,
    resume: tokio::sync::Semaphore,
}
#[async_trait::async_trait]
impl Signer for PausedSigner {
    async fn sign(
        &self,
        _: &TenantId,
        _: Option<SigningAlgorithm>,
        _: &'static str,
        claims: &Value,
    ) -> Result<CompactJws, DomainError> {
        self.entered.add_permits(1);
        self.resume.acquire().await.expect("resume gate").forget();
        Ok(CompactJws::new(claims.to_string()))
    }
}

#[tokio::test]
#[ignore = "requires PostgreSQL; CI runs ignored store tests"]
async fn agent_task_root_revocation_and_signing_share_one_linearization_fence() {
    let fixture = Fixture::new().await;
    let binding = fixture.approve().await;
    let grant = fixture.child(&binding).await;
    let inner = std::sync::Arc::new(PausedSigner {
        entered: tokio::sync::Semaphore::new(0),
        resume: tokio::sync::Semaphore::new(0),
    });
    let tasks = fixture.tasks.clone();
    let audit = PgAuditSink::new(fixture.pool.clone());
    let tenant = fixture.tenant.clone();
    let signing = inner.clone();
    let minted = grant.clone();
    let mint = tokio::spawn(async move {
        TaskSigner {
            tasks: &tasks,
            inner: signing.as_ref(),
            audit: &audit,
        }
        .sign_access(
            &tenant,
            AccessIssuance {
                device_binding: None,
                implicit_resources: &[],
                grant: &minted,
                kind: GrantType::ClientCredentials,
            },
            None,
            "at+jwt",
            &Fixture::claims(&minted, "race"),
        )
        .await
    });
    inner
        .entered
        .acquire()
        .await
        .expect("mint holds fence")
        .forget();
    let pool = fixture.pool.clone();
    let root = binding.root_grant_id;
    let revoke = tokio::spawn(async move {
        sqlx::query("/* task-race-revoke */ update grants set revoked_at=clock_timestamp(),revocation_reason='user_revoked' where tenant_id='task' and grant_id=$1")
            .bind(root).execute(&pool).await.expect("revocation committed");
    });
    // Observe an actual blocked PostgreSQL writer, rather than relying on
    // elapsed sleep or task scheduling to assert the competing operation.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let blocked:bool=sqlx::query_scalar("select exists(select 1 from pg_stat_activity where query like '/* task-race-revoke */%' and wait_event_type='Lock')")
            .fetch_one(&fixture.pool).await.expect("blocking writer");
        if blocked {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "revoker must block behind signer"
        );
        tokio::task::yield_now().await;
    }
    inner.resume.add_permits(1);
    assert!(mint.await.expect("mint task").is_ok());
    revoke.await.expect("revoke task");
    let mut retry = fixture.child(&binding).await;
    // The preparation snapshot may still resolve the task; authority is
    // decided again from the revoked root under the signing fence.
    retry.parent = grant.parent.clone();
    let immediate = ControlledSigner { fail: false };
    let signer = TaskSigner {
        tasks: &fixture.tasks,
        inner: &immediate,
        audit: &fixture.audit,
    };
    assert!(
        signer
            .sign_access(
                &fixture.tenant,
                AccessIssuance {
                    device_binding: None,
                    implicit_resources: &[],
                    grant: &retry,
                    kind: GrantType::ClientCredentials
                },
                None,
                "at+jwt",
                &Fixture::claims(&retry, "after-revoke")
            )
            .await
            .is_err()
    );
    fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL; CI runs ignored store tests"]
async fn agent_task_refresh_deadlines_and_client_teardown_keep_terminal_approval() {
    let fixture = Fixture::new().await;
    let binding = fixture.approve().await;
    sqlx::query("insert into refresh_tokens(tenant_id,token_hash,grant_id,client_id,scopes,dpop_jkt,absolute_expires_at) values('task',decode('bb','hex'),$1,'agent',array['read'],'fixture',now()+interval '1 day')")
        .bind(binding.root_grant_id).execute(&fixture.pool).await.expect("bounded refresh");
    let deadlines: (OffsetDateTime, Option<OffsetDateTime>) = sqlx::query_as(
        "select absolute_expires_at,idle_expires_at from refresh_tokens where tenant_id='task'",
    )
    .fetch_one(&fixture.pool)
    .await
    .expect("deadlines");
    assert_eq!(deadlines, (binding.expires_at, Some(binding.expires_at)));
    // Two cascading nullable FKs can fire in either order. Deferred checks
    // preserve the immutable tombstone while grant/client references vanish.
    sqlx::query("delete from clients where tenant_id='task' and client_id='agent'")
        .execute(&fixture.pool)
        .await
        .expect("client removal");
    let terminal:bool=sqlx::query_scalar("select revoked_at is not null and root_reference is null and client_reference is null from agent_tasks where tenant_id='task' and task_id=$1")
        .bind(binding.task_id).fetch_one(&fixture.pool).await.expect("terminal tombstone");
    assert!(terminal);
    assert!(
        fixture
            .tasks
            .required(&fixture.tenant, &ClientId::new("agent"))
            .await
            .expect("mode tombstone")
    );
    fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL; CI runs ignored store tests"]
#[expect(
    clippy::too_many_lines,
    reason = "One isolated subtree fixture compares immediate intermediate, sibling and terminal owner withdrawal"
)]
async fn agent_task_intermediate_withdrawal_is_immediate_and_preserves_siblings() {
    use asterius_domain::agent_tasks::TokenQuery;
    let fixture = Fixture::new().await;
    let binding = fixture.approve().await;
    let first = fixture.child(&binding).await;
    let first_claims = fixture.issue(&first, "withdraw-first").await;
    let descendant = fixture.derived(&first).await;
    let descendant_claims = fixture.issue(&descendant, "withdraw-descendant").await;
    let sibling = fixture.child(&binding).await;
    let sibling_claims = fixture.issue(&sibling, "withdraw-sibling").await;
    let first_query = TokenQuery::from_claims(&first_claims).expect("first tuple");
    let descendant_query = TokenQuery::from_claims(&descendant_claims).expect("descendant tuple");
    let sibling_query = TokenQuery::from_claims(&sibling_claims).expect("sibling tuple");
    let repository = PgGrantRepository::new(fixture.pool.clone(), fixture.tenant.clone());
    assert!(
        fixture
            .tasks
            .token_active(&fixture.tenant, &descendant_query)
            .await
            .expect("initial online status")
    );
    let revoked_at = OffsetDateTime::now_utc();
    let withdrawal = repository
        .revoke_with_audit(
            &first.id,
            asterius_domain::RevocationReason::UserRevoked,
            &[],
            revoked_at,
            &fixture.audit,
        )
        .await
        .expect("withdraw intermediate ancestor");
    assert_eq!(withdrawal.revoked_at, revoked_at);
    // No retention pass has run: ancestry, rather than asynchronous stamps,
    // must already deny both exact JTI and opaque refresh-grant authority.
    assert!(
        !fixture
            .tasks
            .token_active(&fixture.tenant, &first_query)
            .await
            .expect("first status")
    );
    assert!(
        !fixture
            .tasks
            .token_active(&fixture.tenant, &descendant_query)
            .await
            .expect("descendant status")
    );
    assert!(
        !fixture
            .tasks
            .grant_active(&fixture.tenant, &descendant.id)
            .await
            .expect("refresh status")
    );
    assert!(
        fixture
            .tasks
            .token_active(&fixture.tenant, &sibling_query)
            .await
            .expect("unrelated sibling")
    );
    let task_revoked: Option<OffsetDateTime> =
        sqlx::query_scalar("select revoked_at from agent_tasks where tenant_id=$1 and task_id=$2")
            .bind(fixture.tenant.as_str())
            .bind(binding.task_id)
            .fetch_one(&fixture.pool)
            .await
            .expect("task tombstone");
    assert!(task_revoked.is_none());
    assert!(
        !fixture
            .tasks
            .revoke_owned(
                &fixture.tenant,
                binding.task_id,
                UserId::new(Uuid::new_v4()),
                OffsetDateTime::now_utc(),
                &fixture.audit
            )
            .await
            .expect("foreign owner")
    );
    assert!(
        fixture
            .tasks
            .revoke_owned(
                &fixture.tenant,
                binding.task_id,
                fixture.owner,
                OffsetDateTime::now_utc(),
                &fixture.audit
            )
            .await
            .expect("owner withdrawal")
    );
    assert!(
        !fixture
            .tasks
            .token_active(&fixture.tenant, &sibling_query)
            .await
            .expect("root withdrawal reaches sibling")
    );
    assert!(
        fixture
            .tasks
            .revoke_owned(
                &fixture.tenant,
                binding.task_id,
                fixture.owner,
                OffsetDateTime::now_utc(),
                &fixture.audit
            )
            .await
            .expect("idempotent withdrawal")
    );
    fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL; CI runs ignored store tests"]
async fn agent_task_activation_backfills_existing_descendants() {
    let fixture = Fixture::new().await;
    let mut historical = Grant::new(
        fixture.tenant.clone(),
        ClientId::new("agent"),
        OffsetDateTime::now_utc(),
    );
    historical.parent = Some(fixture.root.id.clone());
    historical.scopes.insert("read".to_owned());
    historical.resources = fixture.root.resources.clone();
    PgGrantRepository::new(fixture.pool.clone(), fixture.tenant.clone())
        .create(&historical)
        .await
        .expect("preapproval descendant");
    let binding = fixture.approve().await;
    let mut refreshed = historical.clone();
    fixture
        .tasks
        .prepare(
            &mut refreshed,
            None,
            None,
            OffsetDateTime::now_utc(),
            Duration::seconds(60),
            &fixture.audit,
        )
        .await
        .expect("historical child inherits approval");
    assert_eq!(
        refreshed.task.as_ref().expect("backfilled binding").task_id,
        binding.task_id
    );
    assert!(
        fixture
            .tasks
            .grant_active(&fixture.tenant, &historical.id)
            .await
            .expect("before root withdrawal")
    );
    fixture
        .tasks
        .revoke_owned(
            &fixture.tenant,
            binding.task_id,
            fixture.owner,
            OffsetDateTime::now_utc(),
            &fixture.audit,
        )
        .await
        .expect("withdraw root");
    assert!(
        !fixture
            .tasks
            .grant_active(&fixture.tenant, &historical.id)
            .await
            .expect("historical child withdrawn")
    );
    fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL; CI runs ignored store tests"]
async fn agent_task_cleanup_is_bounded_resumable_and_not_the_authority_boundary() {
    use asterius_store_pg::{PgRetention, SweepOutcome};
    let fixture = Fixture::new().await;
    let binding = fixture.approve().await;
    sqlx::query("insert into grants(tenant_id,grant_id,client_id,parent_grant_id,scopes,resources,claimed_at,expires_at) select 'task',gen_random_uuid(),'agent',$1,array['read'],array['https://api.example/'],now(),now()+interval '10 minutes' from generate_series(1,520)")
        .bind(Uuid::parse_str(fixture.root.id.as_str()).expect("fixture root UUID"))
        .execute(&fixture.pool).await.expect("wide controlled subtree");
    let leaf: Uuid = sqlx::query_scalar(
        "select grant_id from grants where tenant_id='task' and parent_grant_id=$1 limit 1",
    )
    .bind(Uuid::parse_str(fixture.root.id.as_str()).expect("fixture root UUID"))
    .fetch_one(&fixture.pool)
    .await
    .expect("stored child");
    fixture
        .tasks
        .revoke_owned(
            &fixture.tenant,
            binding.task_id,
            fixture.owner,
            OffsetDateTime::now_utc(),
            &fixture.audit,
        )
        .await
        .expect("root withdrawal");
    assert!(
        !fixture
            .tasks
            .grant_active(
                &fixture.tenant,
                &asterius_domain::GrantId::new(leaf.to_string())
            )
            .await
            .expect("immediate authority refusal")
    );
    let retention = PgRetention::new(fixture.pool.clone());
    let SweepOutcome::Swept(first) = retention
        .sweep_tenant(&fixture.tenant, OffsetDateTime::now_utc())
        .await
        .expect("first bounded pass")
    else {
        panic!("isolated tenant was busy")
    };
    assert!(first.more_to_do);
    let processed: i64 = sqlx::query_scalar(
        "select processed_grants from agent_task_withdrawals where tenant_id='task'",
    )
    .fetch_one(&fixture.pool)
    .await
    .expect("durable progress");
    assert_eq!(processed, 512);
    // A newly constructed worker resumes from the durable UUID cursor rather
    // than keeping process-local progress or rescanning an unbounded tree.
    let restarted = PgRetention::new(fixture.pool.clone());
    let SweepOutcome::Swept(second) = restarted
        .sweep_tenant(&fixture.tenant, OffsetDateTime::now_utc())
        .await
        .expect("resumed pass")
    else {
        panic!("isolated tenant was busy")
    };
    assert!(!second.more_to_do);
    let state: (i64,bool) = sqlx::query_as("select processed_grants,completed_at is not null from agent_task_withdrawals where tenant_id='task'")
        .fetch_one(&fixture.pool).await.expect("complete queue");
    assert_eq!(state, (521, true));
    fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL; CI runs ignored store tests"]
async fn agent_task_ten_row_lineage_remains_usable_at_eight_delegations() {
    let fixture = Fixture::new().await;
    sqlx::query("update clients set agent_policy=jsonb_set(agent_policy,'{max_delegation_depth}','8'::jsonb) where tenant_id='task' and client_id='agent'")
        .execute(&fixture.pool).await.expect("eight-hop registration ceiling");
    let mut permissions = fixture.permissions();
    permissions.max_delegation_depth = 8;
    let now = OffsetDateTime::now_utc();
    let binding = fixture
        .tasks
        .approve(
            &fixture.tenant,
            Approval {
                owner: fixture.owner,
                root: &fixture.root,
                permissions: &permissions,
                label: "maximum bounded lineage",
                expiry: now + Duration::minutes(10),
                now,
            },
            &fixture.audit,
        )
        .await
        .expect("eight-hop approval");
    let mut current = fixture.child(&binding).await;
    fixture.issue(&current, "depth-zero").await;
    for depth in 1..=8 {
        let mut next = fixture.derived(&current).await;
        next.actor_chain = current.actor_chain.clone();
        next.actor_chain.push(json!({"sub":"agent"}));
        fixture.issue(&next, &format!("depth-{depth}")).await;
        current = next;
    }
    assert_eq!(current.actor_chain.len(), 8);
    // Existing-grant signing traverses all ten rows (human root, run,
    // eight delegations), unlike a new child's parent-only traversal.
    let claims = fixture.issue(&current, "depth-eight-existing").await;
    let query =
        asterius_domain::agent_tasks::TokenQuery::from_claims(&claims).expect("exact depth tuple");
    assert!(
        fixture
            .tasks
            .token_active(&fixture.tenant, &query)
            .await
            .expect("maximum current lineage")
    );
    fixture
        .tasks
        .revoke_owned(
            &fixture.tenant,
            binding.task_id,
            fixture.owner,
            OffsetDateTime::now_utc(),
            &fixture.audit,
        )
        .await
        .expect("maximum-depth root withdrawal");
    assert!(
        !fixture
            .tasks
            .token_active(&fixture.tenant, &query)
            .await
            .expect("maximum-depth withdrawal")
    );
    fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL; CI runs ignored store tests"]
async fn agent_task_first_approval_serializes_with_legacy_descendant_insert() {
    let fixture = Fixture::new().await;
    let mut insertion = fixture
        .pool
        .begin()
        .await
        .expect("legacy insertion transaction");
    // Same client-before-root order as prepared legacy issuance. The first
    // approval must wait for this commit, then backfill the committed child.
    sqlx::query(
        "select client_id from clients where tenant_id='task' and client_id='agent' for share",
    )
    .fetch_one(&mut *insertion)
    .await
    .expect("client fence");
    sqlx::query("select grant_id from grants where tenant_id='task' and grant_id=$1 for key share")
        .bind(Uuid::parse_str(fixture.root.id.as_str()).expect("fixture root UUID"))
        .fetch_one(&mut *insertion)
        .await
        .expect("root insertion fence");
    let blocker: i32 = sqlx::query_scalar("select pg_backend_pid()")
        .fetch_one(&mut *insertion)
        .await
        .expect("insertion backend");
    let tasks = fixture.tasks.clone();
    let tenant = fixture.tenant.clone();
    let root = fixture.root.clone();
    let owner = fixture.owner;
    let permissions = fixture.permissions();
    let audit = PgAuditSink::new(fixture.pool.clone());
    let approval = tokio::spawn(async move {
        let now = OffsetDateTime::now_utc();
        tasks
            .approve(
                &tenant,
                Approval {
                    owner,
                    root: &root,
                    permissions: &permissions,
                    label: "serialized activation",
                    expiry: now + Duration::minutes(10),
                    now,
                },
                &audit,
            )
            .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let waiting: bool = sqlx::query_scalar(
                "select exists(select 1 from pg_stat_activity where $1=any(pg_blocking_pids(pid)))",
            )
            .bind(blocker)
            .fetch_one(&fixture.pool)
            .await
            .expect("observed fence wait");
            if waiting {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("approval reaches and waits on the existing insertion fence");
    let child = Uuid::new_v4();
    sqlx::query("insert into grants(tenant_id,grant_id,client_id,parent_grant_id,scopes,resources,claimed_at,expires_at) values('task',$1,'agent',$2,array['read'],array['https://api.example/'],now(),now()+interval '10 minutes')")
        .bind(child).bind(Uuid::parse_str(fixture.root.id.as_str()).expect("fixture root UUID"))
        .execute(&mut *insertion).await.expect("legacy child before activation");
    insertion
        .commit()
        .await
        .expect("legacy commit releases activation");
    let binding = approval
        .await
        .expect("approval worker")
        .expect("serialized approval");
    let inherited: Uuid = sqlx::query_scalar(
        "select task_id from agent_task_grants where tenant_id='task' and grant_id=$1",
    )
    .bind(child)
    .fetch_one(&fixture.pool)
    .await
    .expect("committed child backfilled");
    assert_eq!(inherited, binding.task_id);
    fixture.cleanup().await;
}
