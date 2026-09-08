//! The key rotation sweep (`ast-mxc.9`).
//!
//! What is under test is that rotation happens *without a restart*. Every case
//! below drives the real task — `RotationSweep::sweep_once`, the same call the
//! running loop makes — rather than calling `apply_schedule` by hand, because
//! calling `apply_schedule` by hand is precisely what used to be the only way
//! a key ever moved.
//!
//! As in `signing.rs`, isolation comes from the tenant: `asterius-server` has
//! no `sqlx` dependency (ADR-0001), so each test mints a tenant nothing else
//! touches and deletes it at the end.

use asterius_domain::audit::Actor;
use asterius_domain::keys::SigningAlgorithm;
use asterius_domain::ports::{Clock, TenantRepository};
use asterius_domain::{Issuer, KeyStore, Tenant, TenantId, TenantStatus};
use asterius_jose::LocalKek;
use asterius_jose::kek::Kek;
use asterius_server::rotation::RotationSweep;
use asterius_store_pg::{PgAuditSink, PgTenantRepository, RotationSchedule, Store, TenantKeyStore};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use time::{Duration, OffsetDateTime};

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// A clock the test moves by hand.
#[derive(Debug)]
struct Hand(Mutex<OffsetDateTime>);

impl Hand {
    fn at(now: OffsetDateTime) -> Arc<Self> {
        Arc::new(Self(Mutex::new(now)))
    }

    fn advance(&self, by: Duration) {
        *self.0.lock().expect("lock") += by;
    }
}

impl Clock for Hand {
    fn now(&self) -> OffsetDateTime {
        *self.0.lock().expect("lock")
    }
}

struct Fixture {
    store: Store,
    keys: TenantKeyStore,
    tenants: Arc<PgTenantRepository>,
    tenant: TenantId,
    clock: Arc<Hand>,
    kek: Arc<dyn Kek>,
}

impl Fixture {
    async fn new() -> Option<Self> {
        let url = std::env::var("DATABASE_URL").ok()?;
        let store = Store::connect(&url, 4)
            .await
            .expect("DATABASE_URL is set but unreachable; is `docker compose up -d db` running?");
        store.migrate().await.expect("migrate");

        let kek: Arc<dyn Kek> = Arc::new(LocalKek::from_bytes(&[9_u8; 32]).expect("a 32-byte KEK"));
        let audit = Arc::new(PgAuditSink::new(store.pool().clone()));
        let now = OffsetDateTime::now_utc();

        let id = format!(
            "rot-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let tenant = TenantId::parse(&id).expect("a generated tenant id");
        let tenants = Arc::new(PgTenantRepository::new(
            store.pool().clone(),
            Arc::clone(&kek),
        ));
        tenants
            .upsert(&Tenant {
                id: tenant.clone(),
                issuer: Issuer::parse(&format!("https://as.example/t/{id}")).expect("issuer"),
                custom_host: None,
                display_name: "Rotation".to_owned(),
                default_resource: "https://api.example/".to_owned(),
                status: TenantStatus::Active,
                created_at: now,
                updated_at: now,
            })
            .await
            .expect("create tenant");

        Some(Self {
            keys: TenantKeyStore::new(store.pool().clone(), Arc::clone(&kek), audit),
            store,
            tenants,
            tenant,
            clock: Hand::at(now),
            kek,
        })
    }

    /// The sweep as the binary builds it, over this test's clock.
    ///
    /// Deliberately over *every* tenant, not just this one: that is the shape
    /// the running task has, and it is what makes the "a tenant created after
    /// boot is picked up" case meaningful.
    fn sweep(&self) -> RotationSweep {
        RotationSweep::new(
            self.keys.clone(),
            Arc::clone(&self.tenants) as Arc<dyn TenantRepository>,
            Arc::clone(&self.clock) as Arc<dyn Clock>,
        )
    }

    /// The kids in this tenant's published JWK Set, sorted.
    ///
    /// The set a relying party can actually fetch, rather than the `key_state`
    /// column — which is the right thing to assert on: `pending`, `active` and
    /// `retiring` are all published, and `retired` is exactly the state that
    /// means "gone from here".
    async fn published(&self) -> Vec<String> {
        let mut kids: Vec<String> = self
            .keys
            .published_keys(&self.tenant)
            .await
            .expect("published keys")
            .into_iter()
            .map(|record| record.kid.to_string())
            .collect();
        kids.sort();
        kids
    }

    async fn active_kid(&self) -> Option<String> {
        self.keys
            .for_tenant(&self.tenant)
            .active_signing_key(SigningAlgorithm::DEFAULT)
            .await
            .expect("read")
            .map(|(kid, _)| kid.to_string())
    }

    async fn tear_down(self) {
        PgTenantRepository::new(self.store.pool().clone(), self.kek)
            .delete(&self.tenant)
            .await
            .expect("delete tenant");
    }
}

macro_rules! db_test {
    ($(#[$meta:meta])* async fn $name:ident($f:ident) $body:block) => {
        $(#[$meta])*
        #[tokio::test]
        async fn $name() {
            let Some($f) = Fixture::new().await else {
                eprintln!("skipping {}: DATABASE_URL is not set", stringify!($name));
                return;
            };
            $body
        }
    };
}

db_test! {
    /// The bug this task exists for. A tenant created after boot held no keys
    /// at all, so every token request for it failed with `NoSigningKey` until
    /// somebody restarted the server — which the tenant had no way to ask for.
    async fn a_tenant_created_after_boot_gets_keys_without_a_restart(fixture) {
        assert!(
            fixture.active_kid().await.is_none(),
            "the fixture tenant started with a key, so this proves nothing"
        );

        let outcome = fixture.sweep().sweep_once().await.expect("sweep");
        assert!(outcome.swept >= 1, "the sweep skipped the tenant: {outcome:?}");
        assert_eq!(outcome.failed, 0);

        assert!(
            fixture.active_kid().await.is_some(),
            "a tenant created after boot never got a signing key"
        );

        fixture.tear_down().await;
    }
}

db_test! {
    /// The other half: a key staged as `pending` becomes `active` in a process
    /// that keeps running.
    ///
    /// This is the case that used to fail silently. Nothing looked wrong — the
    /// superseded key was still `active` and still published, so tokens
    /// verified — and the rotation simply had not happened.
    ///
    /// The propagation period is set to its floor so the promotion is
    /// observable without waiting fifteen minutes. It cannot be zero: the
    /// schema refuses that, because signing under a key no verifier has had a
    /// chance to fetch is the failure OIDC Core §10.1.1 exists to avoid.
    async fn a_pending_key_is_promoted_by_the_sweep_rather_than_by_a_restart(fixture) {
        let repository = fixture.keys.for_tenant(&fixture.tenant);
        repository
            .set_schedule(
                SigningAlgorithm::DEFAULT,
                RotationSchedule {
                    rotation_period: Duration::hours(1),
                    propagation_period: Duration::seconds(1),
                    grace_period: Duration::hours(24),
                    last_rotated_at: None,
                },
            )
            .await
            .expect("set the schedule");

        // First sweep: the tenant has no key, so one is created active — no
        // verifier can hold a stale JWK Set for a tenant that has never
        // published one.
        fixture.sweep().sweep_once().await.expect("sweep");
        let first = fixture.active_kid().await.expect("an active key");
        // Every advertised algorithm gets a key, so the set is not one key —
        // count relative to it rather than pinning a number that changes with
        // `SigningAlgorithm::ALL`.
        let before_rotation = fixture.published().await.len();

        // An operator rotates on some other replica. The staged key is
        // `pending` until it has been published for the propagation period.
        fixture.clock.advance(Duration::seconds(2));
        repository
            .rotate(SigningAlgorithm::DEFAULT, Actor::System, fixture.clock.now())
            .await
            .expect("rotate");
        assert_eq!(
            fixture.active_kid().await.as_deref(),
            Some(first.as_str()),
            "a freshly staged key must not sign before it has propagated"
        );
        // One more key published than before, and it is not the one signing:
        // the staged key is in the JWK Set so verifiers can fetch it *before*
        // it ever signs anything, which is the purpose of the propagation
        // period.
        assert_eq!(
            fixture.published().await.len(),
            before_rotation + 1,
            "the rotation staged nothing"
        );

        // Time passes and the task runs. Nothing else happens: no restart, no
        // hand call to `apply_schedule`.
        fixture.clock.advance(Duration::seconds(30));
        fixture.sweep().sweep_once().await.expect("sweep");

        let promoted = fixture.active_kid().await.expect("an active key");
        assert_ne!(
            promoted, first,
            "the sweep did not promote the pending key"
        );
        // Both still published — the superseded key stays in the set for its
        // grace period, which is what makes the tokens it signed keep
        // verifying.
        assert!(
            fixture.published().await.contains(&first),
            "the superseded key left the JWK Set before its grace expired"
        );

        fixture.tear_down().await;
    }
}

db_test! {
    /// A key past its grace leaves the JWKS, and the sweep is what takes it
    /// out. Left in, it would be a published verification key for a private
    /// key nothing is protecting any more.
    async fn a_key_past_its_grace_is_retired_by_the_sweep(fixture) {
        let repository = fixture.keys.for_tenant(&fixture.tenant);
        repository
            .set_schedule(
                SigningAlgorithm::DEFAULT,
                RotationSchedule {
                    rotation_period: Duration::hours(1),
                    propagation_period: Duration::seconds(1),
                    grace_period: Duration::seconds(2),
                    last_rotated_at: None,
                },
            )
            .await
            .expect("set the schedule");

        fixture.sweep().sweep_once().await.expect("sweep");
        let original = fixture.active_kid().await.expect("an active key");

        // Rotate, then let the replacement propagate and take over.
        fixture.clock.advance(Duration::seconds(2));
        repository
            .rotate(SigningAlgorithm::DEFAULT, Actor::System, fixture.clock.now())
            .await
            .expect("rotate");
        fixture.clock.advance(Duration::seconds(5));
        fixture.sweep().sweep_once().await.expect("sweep");
        assert_ne!(
            fixture.active_kid().await.as_deref(),
            Some(original.as_str()),
            "the replacement never took over"
        );

        // Past the grace period, and one more pass.
        fixture.clock.advance(Duration::hours(1));
        fixture.sweep().sweep_once().await.expect("sweep");

        assert!(
            !fixture.published().await.contains(&original),
            "the superseded key never left the JWK Set"
        );

        fixture.tear_down().await;
    }
}

db_test! {
    /// Sweeping twice with nothing due changes nothing.
    ///
    /// The task runs every minute forever, so "no work to do" is its normal
    /// case by an overwhelming margin. If a pass created a key each time, a
    /// tenant would accumulate one per minute.
    async fn a_sweep_with_nothing_due_is_a_no_op(fixture) {
        fixture.sweep().sweep_once().await.expect("sweep");
        let before = fixture.published().await;
        // One per advertised algorithm — `TenantKeyStore::apply_schedule`
        // provisions every one of `SigningAlgorithm::ALL`, because discovery
        // advertises all of them and a client may register any.
        assert_eq!(
            before.len(),
            SigningAlgorithm::ALL.len(),
            "the first sweep did not make exactly one key per algorithm"
        );

        for _ in 0..3 {
            fixture.clock.advance(Duration::seconds(30));
            fixture.sweep().sweep_once().await.expect("sweep");
        }

        assert_eq!(
            fixture.published().await,
            before,
            "an idle sweep changed the keys"
        );

        fixture.tear_down().await;
    }
}
