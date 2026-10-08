//! Receiver-managed upstream stream controls against a migrated PostgreSQL schema.
//! Set `DATABASE_URL` to run these tests; without it, they skip like other store tests.

use asterius_domain::TenantId;
use asterius_ssf::{caep::SESSION_REVOKED, stream::DELIVERY_POLL};
use asterius_store_pg::{
    MIGRATOR, PgSsfUpstreamStreams, Store, UpstreamSetupIntent, UpstreamStream,
};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use std::str::FromStr as _;
use std::sync::atomic::{AtomicU32, Ordering};
use time::OffsetDateTime;

static COUNTER: AtomicU32 = AtomicU32::new(0);
const PEER: &str = "https://transmitter.example";
const STREAM: &str = "stream-1";

fn at(seconds: i64) -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_700_000_000 + seconds).expect("test instant")
}

async fn setup() -> Option<(sqlx::PgPool, PgSsfUpstreamStreams)> {
    let url = std::env::var("DATABASE_URL").ok()?;
    let schema = format!(
        "ssf_upstream_lifecycle_{}_{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .expect("connect to DATABASE_URL");
    sqlx::query(&format!("create schema \"{schema}\""))
        .execute(&admin)
        .await
        .expect("create isolated schema");
    admin.close().await;
    let options = PgConnectOptions::from_str(&url)
        .expect("valid DATABASE_URL")
        .options([("search_path", schema.as_str())]);
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect_with(options)
        .await
        .expect("connect to isolated schema");
    MIGRATOR.run(&pool).await.expect("migrate isolated schema");
    sqlx::query(
        "insert into tenants (tenant_id, issuer, display_name, default_resource)
         values ('demo', 'https://as.example/t/demo', 'demo', 'https://api.example/')",
    )
    .execute(&pool)
    .await
    .expect("seed tenant");
    sqlx::query(
        "insert into clients (tenant_id, client_id, client_name,
                              token_endpoint_auth_method, jwks)
         values ('demo', $1, 'transmitter', 'private_key_jwt', '{}'::jsonb)",
    )
    .bind(PEER)
    .execute(&pool)
    .await
    .expect("seed configured transmitter");
    let repository = Store::from_pool(pool.clone())
        .scope(TenantId::new("demo"))
        .ssf_upstream_streams();
    let intent = UpstreamSetupIntent {
        peer_client_id: PEER.to_owned(),
        issuer: PEER.to_owned(),
        jwks_uri: format!("{PEER}/jwks"),
        configuration_endpoint: format!("{PEER}/ssf/streams"),
        status_endpoint: format!("{PEER}/ssf/streams/status"),
        audience: "https://as.example/t/demo/ssf/receiver".to_owned(),
        events_requested: vec![SESSION_REVOKED.to_owned()],
        delivery_method: DELIVERY_POLL.to_owned(),
        started_at: at(0),
    };
    assert!(repository.begin_setup(&intent).await.expect("begin setup"));
    let stream = UpstreamStream {
        peer_client_id: intent.peer_client_id.clone(),
        issuer: intent.issuer.clone(),
        jwks_uri: intent.jwks_uri.clone(),
        configuration_endpoint: intent.configuration_endpoint.clone(),
        status_endpoint: intent.status_endpoint.clone(),
        stream_id: STREAM.to_owned(),
        delivery_method: intent.delivery_method.clone(),
        poll_endpoint: Some(format!("{PEER}/ssf/poll")),
        audience: intent.audience.clone(),
        events_requested: intent.events_requested.clone(),
        created_at: at(0),
        updated_at: at(0),
        last_polled_at: None,
        deletion_started_at: None,
        last_verified_at: None,
        last_challenge_verified_at: None,
    };
    assert!(
        repository
            .finish_setup(&intent, &stream)
            .await
            .expect("finish setup")
    );
    Some((pool, repository))
}

#[tokio::test]
async fn verification_challenge_is_one_use_and_replay_does_not_consume_a_new_challenge() {
    let Some((_pool, repository)) = setup().await else {
        eprintln!("skipping: DATABASE_URL is not set");
        return;
    };
    let first = [0x11; 32];
    let wrong = [0x22; 32];
    let second = [0x33; 32];
    assert!(
        repository
            .begin_verification(PEER, STREAM, &first, at(60), at(1))
            .await
            .expect("reserve first challenge")
    );
    assert!(
        !repository
            .begin_verification(PEER, STREAM, &second, at(60), at(2))
            .await
            .expect("reject competing challenge")
    );
    assert!(
        !repository
            .complete_verification(PEER, STREAM, "jti-wrong", Some(&wrong), at(600), at(3))
            .await
            .expect("reject wrong state")
    );
    assert!(
        repository
            .complete_verification(PEER, STREAM, "jti-first", Some(&first), at(600), at(4))
            .await
            .expect("accept correct state")
    );
    assert!(
        !repository
            .complete_verification(PEER, STREAM, "jti-new", Some(&first), at(600), at(5))
            .await
            .expect("consumed state cannot verify another SET")
    );
    assert!(
        repository
            .begin_verification(PEER, STREAM, &second, at(80), at(6))
            .await
            .expect("reserve second challenge")
    );
    assert!(
        repository
            .complete_verification(PEER, STREAM, "jti-first", Some(&first), at(600), at(7))
            .await
            .expect("ACK retransmitted SET")
    );
    assert!(
        !repository
            .complete_verification(PEER, STREAM, "jti-second", Some(&first), at(600), at(8))
            .await
            .expect("old state cannot consume second challenge")
    );
    assert!(
        repository
            .complete_verification(PEER, STREAM, "jti-second", Some(&second), at(600), at(9))
            .await
            .expect("accept second challenge")
    );
    let stored = repository
        .find(PEER)
        .await
        .expect("read stream")
        .expect("stream remains");
    assert_eq!(stored.last_verified_at, Some(at(9)));
    assert_eq!(stored.last_challenge_verified_at, Some(at(9)));

    let third = [0x44; 32];
    assert!(
        repository
            .begin_verification(PEER, STREAM, &third, at(30), at(20))
            .await
            .expect("reserve third challenge")
    );
    assert!(
        repository
            .complete_verification(PEER, STREAM, "jti-unsolicited", None, at(600), at(21))
            .await
            .expect("record transmitter-initiated verification")
    );
    let stored = repository
        .find(PEER)
        .await
        .expect("read stream")
        .expect("stream remains");
    assert_eq!(stored.last_verified_at, Some(at(21)));
    assert_eq!(stored.last_challenge_verified_at, Some(at(9)));
    assert!(
        !repository
            .complete_verification(PEER, STREAM, "jti-expired", Some(&third), at(600), at(30))
            .await
            .expect("expired challenge cannot be completed")
    );
}

#[tokio::test]
async fn delete_intent_blocks_verification_and_requires_exact_stream_for_removal() {
    let Some((_pool, repository)) = setup().await else {
        eprintln!("skipping: DATABASE_URL is not set");
        return;
    };
    assert!(
        !repository
            .finish_delete(PEER, STREAM)
            .await
            .expect("unmarked stream cannot be removed")
    );
    assert!(
        !repository
            .begin_delete(PEER, "other-stream", at(1))
            .await
            .expect("wrong stream cannot be marked")
    );
    assert!(
        repository
            .begin_delete(PEER, STREAM, at(2))
            .await
            .expect("mark remote delete intent")
    );
    assert!(
        repository
            .begin_delete(PEER, STREAM, at(3))
            .await
            .expect("retry retains intent")
    );
    assert_eq!(
        repository
            .find(PEER)
            .await
            .expect("read stream")
            .expect("still present")
            .deletion_started_at,
        Some(at(2))
    );
    assert!(
        !repository
            .begin_verification(PEER, STREAM, &[0x44; 32], at(60), at(4))
            .await
            .expect("deleting stream cannot start verification")
    );
    assert!(
        !repository
            .finish_delete(PEER, "other-stream")
            .await
            .expect("wrong stream cannot be removed")
    );
    assert!(
        repository
            .finish_delete(PEER, STREAM)
            .await
            .expect("remove confirmed absent stream")
    );
    assert!(repository.find(PEER).await.expect("read stream").is_none());
}

#[tokio::test]
#[ignore = "requires DATABASE_URL; focused flow-owned upstream setup integration"]
// Setup ownership, uncertain retry and exact established receipt are one lifecycle.
#[allow(clippy::too_many_lines)]
async fn flow_setup_owns_uncertain_intent_and_never_adopts_a_replacement_stream() {
    use asterius_store_pg::{FlowApplyStep, FlowLinkIntent, PgArchitectureFlows};
    let (pool, repository) = setup().await.expect("DATABASE_URL");
    assert!(
        repository
            .begin_delete(PEER, STREAM, at(1))
            .await
            .expect("delete intent")
    );
    assert!(
        repository
            .finish_delete(PEER, STREAM)
            .await
            .expect("remove fixture stream")
    );
    let tenant = TenantId::new("demo");
    let flows = PgArchitectureFlows::new(pool);
    let flow = uuid::Uuid::new_v4();
    let node = "stream-node";
    let now = OffsetDateTime::now_utc();
    // Keep the lease current and force sub-microsecond precision so completion
    // checks the original intent through PostgreSQL timestamp encoding.
    let now = now
        .replace_nanosecond(now.nanosecond() / 1_000 * 1_000 + 1)
        .expect("bounded nanosecond value");
    flows
        .create(
            &tenant,
            flow,
            "Security flow",
            serde_json::json!({"schema_version":1,"nodes":[],"edges":[]}),
            now,
        )
        .await
        .expect("flow");
    let token = flows
        .begin_apply(&tenant, flow, 1, now)
        .await
        .expect("lease");
    flows
        .reserve(
            &tenant,
            flow,
            token,
            1,
            &FlowLinkIntent {
                node,
                kind: "stream",
                resource: PEER,
                relation: "managed",
            },
            now,
        )
        .await
        .expect("reservation");
    let step = FlowApplyStep {
        flow,
        token,
        revision: 1,
        node,
        now,
    };
    let intent = UpstreamSetupIntent {
        peer_client_id: PEER.into(),
        issuer: PEER.into(),
        jwks_uri: format!("{PEER}/jwks"),
        configuration_endpoint: format!("{PEER}/ssf/streams"),
        status_endpoint: format!("{PEER}/ssf/streams/status"),
        audience: "https://as.example/t/demo/ssf/receiver".into(),
        events_requested: vec![SESSION_REVOKED.into()],
        delivery_method: DELIVERY_POLL.into(),
        started_at: now,
    };
    assert!(
        repository.begin_setup(&intent).await.is_err(),
        "standalone setup cannot adopt a pending flow reservation"
    );
    assert!(
        repository
            .begin_setup_for_flow(&intent, &step)
            .await
            .expect("owned intent")
    );
    assert_eq!(
        repository.flow_origin(PEER).await.expect("pending origin"),
        Some((flow, node.into()))
    );
    assert!(
        !repository
            .begin_setup_for_flow(&intent, &step)
            .await
            .expect("same-origin retry"),
        "retry reconciles; it never permits another POST"
    );
    let stream = UpstreamStream {
        peer_client_id: PEER.into(),
        issuer: PEER.into(),
        jwks_uri: intent.jwks_uri.clone(),
        configuration_endpoint: intent.configuration_endpoint.clone(),
        status_endpoint: intent.status_endpoint.clone(),
        stream_id: "flow-stream".into(),
        delivery_method: DELIVERY_POLL.into(),
        poll_endpoint: Some(format!("{PEER}/ssf/poll")),
        audience: intent.audience.clone(),
        events_requested: intent.events_requested.clone(),
        created_at: now,
        updated_at: now,
        last_polled_at: None,
        deletion_started_at: None,
        last_verified_at: None,
        last_challenge_verified_at: None,
    };
    assert!(
        repository
            .finish_setup(&intent, &stream)
            .await
            .expect("commit owned stream")
    );
    assert_eq!(
        repository
            .flow_origin(PEER)
            .await
            .expect("established origin"),
        Some((flow, node.into()))
    );
    flows
        .complete_stream(&tenant, &step, PEER)
        .await
        .expect("atomic exact receipt");
    let links = flows.links(&tenant, flow).await.expect("receipts");
    assert_eq!(links[0]["resource_revision"], "flow-stream");
    assert_eq!(links[0]["state"], "applied");
    assert!(
        repository
            .begin_delete(PEER, "flow-stream", now)
            .await
            .expect("delete owned")
    );
    assert!(
        repository
            .finish_delete(PEER, "flow-stream")
            .await
            .expect("remove owned")
    );
    assert!(
        repository
            .begin_setup(&intent)
            .await
            .expect("independent replacement setup")
    );
    let replacement = UpstreamStream {
        stream_id: "outside-stream".into(),
        ..stream
    };
    assert!(
        repository
            .finish_setup(&intent, &replacement)
            .await
            .expect("replacement")
    );
    assert!(
        repository
            .flow_origin(PEER)
            .await
            .expect("origin")
            .is_none()
    );
    assert!(
        flows.complete_stream(&tenant, &step, PEER).await.is_err(),
        "the old flow cannot adopt another caller's replacement stream"
    );
}
