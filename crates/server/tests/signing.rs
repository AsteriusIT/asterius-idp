//! `CachedSigner` against a real key repository.
//!
//! This is the seam that was missing: `asterius_domain::Signer` had exactly one
//! implementor, in `asterius-jose`, and it was reachable only from tests. The
//! binary held no signer at all, so the first grant handler would have had
//! nothing to sign with (`ast-a05.14`).
//!
//! What is under test is the three things a signer over a rotating,
//! per-algorithm key store has to get right:
//!
//! * **Every advertised algorithm works.** Discovery lists all of
//!   `SigningAlgorithm::ALL` under `id_token_signing_alg_values_supported`
//!   (ADR-0003), and OpenID Connect Dynamic Client Registration 1.0 §2 makes
//!   `id_token_signed_response_alg` an obligation on the *server*. A tenant
//!   that advertises `PS256` and cannot sign with it accepts registrations it
//!   can never honour.
//! * **A constraint is honoured or refused, never substituted.** OIDC Core
//!   §3.1.3.6 ties `at_hash` to the `alg` in the header, so signing an ES256
//!   claims set with an EdDSA key produces a token the client is entitled to
//!   reject. That was `ast-a05.12`.
//! * **A rotation reaches the signer.** A cached key that never reloads means
//!   rotation silently does not happen, and nothing looks wrong — the
//!   superseded key is still published, so the tokens still verify.
//!
//! # No schema isolation here
//!
//! Unlike `asterius-store-pg`'s suite, these run in whatever schema
//! `DATABASE_URL` points at, because `asterius-server` has no `sqlx`
//! dependency to build a per-test one with (ADR-0001) and adding one for a
//! test would be the wrong way round. Isolation comes from the tenant instead:
//! every test mints a unique tenant id, touches nothing outside it, and
//! deletes it at the end — which cascades its keys away.

use asterius_domain::keys::{Signer, SigningAlgorithm};
use asterius_domain::ports::{Clock, TenantRepository};
use asterius_domain::{DomainError, Issuer, KeyStore, Tenant, TenantId, TenantStatus};
use asterius_jose::kek::Kek;
use asterius_jose::{LocalKek, jws, keys_from_jwk_set};
use asterius_server::signing::CachedSigner;
use asterius_store_pg::{PgAuditSink, PgTenantRepository, RotationSchedule, Store, TenantKeyStore};
use serde_json::json;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use time::{Duration, OffsetDateTime};

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// A clock a test moves by hand, so a cache lifetime can be crossed without
/// waiting for one.
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

/// Everything one test needs, in its own tenant.
struct Fixture {
    store: Store,
    keys: TenantKeyStore,
    tenant: TenantId,
    clock: Arc<Hand>,
}

impl Fixture {
    /// Connects, migrates, and creates a tenant nothing else will touch.
    ///
    /// `None` without `DATABASE_URL`, so the default `cargo test` stays fast.
    async fn new() -> Option<Self> {
        let url = std::env::var("DATABASE_URL").ok()?;
        let store = Store::connect(&url, 4)
            .await
            .expect("DATABASE_URL is set but unreachable; is `docker compose up -d db` running?");
        store.migrate().await.expect("migrate");

        // 256 bits of zeros. This is a test KEK and it seals nothing that
        // outlives the tenant below.
        let kek: Arc<dyn Kek> = Arc::new(LocalKek::from_bytes(&[7_u8; 32]).expect("a 32-byte KEK"));
        let audit = Arc::new(PgAuditSink::new(store.pool().clone()));

        let id = format!(
            "sign-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let tenant = TenantId::parse(&id).expect("a generated tenant id");
        PgTenantRepository::new(store.pool().clone(), Arc::clone(&kek))
            .upsert(&Tenant {
                id: tenant.clone(),
                issuer: Issuer::parse(&format!("https://as.example/t/{id}")).expect("issuer"),
                default_resource: "https://api.example/".to_owned(),
                custom_host: None,
                display_name: "Signing".to_owned(),
                status: TenantStatus::Active,
                refresh: asterius_domain::RefreshPolicy::default(),
                created_at: OffsetDateTime::UNIX_EPOCH,
                updated_at: OffsetDateTime::UNIX_EPOCH,
            })
            .await
            .expect("create tenant");

        Some(Self {
            keys: TenantKeyStore::new(store.pool().clone(), kek, audit),
            store,
            tenant,
            clock: Hand::at(OffsetDateTime::now_utc()),
        })
    }

    /// Gives the tenant an active key of every advertised algorithm.
    async fn provision_everything(&self) {
        self.keys
            .apply_schedule(&self.tenant, self.clock.now())
            .await
            .expect("apply the schedule");
    }

    /// Gives the tenant an active key of exactly one algorithm.
    async fn provision(&self, algorithm: SigningAlgorithm) {
        self.keys
            .for_tenant(&self.tenant)
            .apply_schedule(algorithm, self.clock.now())
            .await
            .expect("apply the schedule");
    }

    fn signer(&self, ttl: Duration) -> CachedSigner {
        CachedSigner::with_ttl(
            self.keys.clone(),
            Arc::clone(&self.clock) as Arc<dyn Clock>,
            ttl,
        )
    }

    /// Deletes the tenant, and its keys with it.
    async fn tear_down(self) {
        let kek: Arc<dyn Kek> = Arc::new(LocalKek::from_bytes(&[7_u8; 32]).expect("KEK"));
        PgTenantRepository::new(self.store.pool().clone(), kek)
            .delete(&self.tenant)
            .await
            .expect("delete tenant");
    }
}

/// Runs a test body only when a database is configured.
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

/// Verifies a token against the tenant's published set, the way a client does:
/// take the `kid` from the header, find that key in the JWKS, check the
/// signature under it. Returns the header's `alg`.
async fn verify_against_the_published_jwks(fixture: &Fixture, token: &str) -> String {
    let parsed = jws::parse(token).expect("a compact JWS");
    let alg = parsed.claimed_alg().to_owned();
    let kid = parsed
        .kid()
        .expect("every token this server issues names its key");

    let published = fixture
        .keys
        .published_keys(&fixture.tenant)
        .await
        .expect("published keys");
    let jwk = published
        .iter()
        .find(|record| record.kid == kid)
        .map(|record| record.public_jwk.clone())
        .expect("the kid names a key in the published set");

    let set = keys_from_jwk_set(&json!({ "keys": [jwk] })).expect("a JWK set");
    let key = set
        .verifying_keys()
        .into_iter()
        .next()
        .expect("one verifying key");
    parsed.verify(&key).expect("the signature must check out");
    alg
}

db_test! {
    /// The acceptance criterion: a token through the binary's own signer, for
    /// every algorithm the discovery document advertises, verified against the
    /// published JWKS rather than against the thing that signed it.
    async fn every_advertised_algorithm_signs_a_token_a_client_can_verify(fixture) {
        fixture.provision_everything().await;
        let signer = fixture.signer(CachedSigner::DEFAULT_TTL);

        for algorithm in SigningAlgorithm::ALL {
            let token = signer
                .sign(
                    &fixture.tenant,
                    Some(algorithm),
                    "at+jwt",
                    &json!({"sub": "alice"}),
                )
                .await
                .unwrap_or_else(|error| panic!("cannot sign with {algorithm}: {error}"));

            assert_eq!(
                verify_against_the_published_jwks(&fixture, token.as_str()).await,
                algorithm.as_str(),
                "a request for {algorithm} was signed with something else"
            );
        }

        fixture.tear_down().await;
    }
}

db_test! {
    /// `None` means the claims commit to nothing, which is the right answer
    /// for an access token — its verifier resolves the key from the JWKS by
    /// `kid`. The default algorithm is preferred so that a deployment has one
    /// answer rather than whichever key sorted first.
    async fn an_unconstrained_signature_uses_the_default_algorithm(fixture) {
        fixture.provision_everything().await;
        let signer = fixture.signer(CachedSigner::DEFAULT_TTL);

        let token = signer
            .sign(&fixture.tenant, None, "at+jwt", &json!({"sub": "alice"}))
            .await
            .expect("sign");
        assert_eq!(
            verify_against_the_published_jwks(&fixture, token.as_str()).await,
            SigningAlgorithm::DEFAULT.as_str()
        );

        fixture.tear_down().await;
    }
}

db_test! {
    /// `ast-a05.12`. Substituting another key would produce a token whose
    /// `at_hash` the client computes differently (OIDC Core §3.1.3.6) — an
    /// error nobody sees, surfacing as a client that cannot log anybody in.
    /// Refusing is the only safe answer.
    async fn an_algorithm_the_tenant_has_no_key_for_is_refused_not_substituted(fixture) {
        fixture.provision(SigningAlgorithm::DEFAULT).await;
        let signer = fixture.signer(CachedSigner::DEFAULT_TTL);

        for missing in SigningAlgorithm::ALL {
            if missing == SigningAlgorithm::DEFAULT {
                continue;
            }
            let refused = signer
                .sign(&fixture.tenant, Some(missing), "at+jwt", &json!({}))
                .await
                .expect_err("a missing algorithm must refuse");
            assert!(
                matches!(
                    refused,
                    DomainError::NoSigningKey { algorithm } if algorithm == Some(missing)
                ),
                "{refused:?}"
            );
        }

        // And the one it does hold still works, so the refusal is about the
        // algorithm and not about the tenant.
        assert!(
            signer
                .sign(&fixture.tenant, None, "at+jwt", &json!({}))
                .await
                .is_ok()
        );

        fixture.tear_down().await;
    }
}

db_test! {
    /// A tenant whose keys were all destroyed after a compromise. Nothing is
    /// signed, and the error says which algorithm was wanted — `None`, because
    /// any would have done.
    async fn a_tenant_with_no_keys_signs_nothing(fixture) {
        let signer = fixture.signer(CachedSigner::DEFAULT_TTL);

        let refused = signer
            .sign(&fixture.tenant, None, "at+jwt", &json!({}))
            .await
            .expect_err("a tenant with no keys must refuse");
        assert!(
            matches!(refused, DomainError::NoSigningKey { algorithm: None }),
            "{refused:?}"
        );

        fixture.tear_down().await;
    }
}

db_test! {
    /// The reason the signer is a cache with an age rather than a load.
    ///
    /// A rotation promotes a `pending` key and moves the incumbent to
    /// `retiring`, and it may happen on another replica. A signer that never
    /// reloaded would keep signing under the superseded key indefinitely, and
    /// nothing would look wrong: a `retiring` key is still published, so the
    /// tokens still verify. Rotation would silently not happen.
    ///
    /// The propagation period is set to zero for this tenant so the promotion
    /// is observable without waiting for one.
    async fn a_rotation_reaches_the_signer_once_the_cached_key_ages_out(fixture) {
        let repository = fixture.keys.for_tenant(&fixture.tenant);
        repository
            // The schema refuses a zero propagation period — signing with a
            // key no verifier has had the chance to fetch is the failure OIDC
            // Core §10.1.1 exists to avoid. One second is the smallest legal
            // value, and the promotion below happens two seconds later.
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
        fixture.provision(SigningAlgorithm::DEFAULT).await;

        let ttl = Duration::seconds(60);
        let signer = fixture.signer(ttl);
        let first = signer
            .sign(&fixture.tenant, None, "at+jwt", &json!({}))
            .await
            .expect("sign");
        let before = jws::parse(first.as_str()).expect("parse").kid().expect("kid");

        // Rotate, and promote the staged key. With no propagation period the
        // second pass makes it active immediately.
        let later = fixture.clock.now() + Duration::seconds(2);
        repository
            .rotate(
                SigningAlgorithm::DEFAULT,
                asterius_domain::audit::Actor::System,
                later,
            )
            .await
            .expect("rotate");
        // A staged key is `pending` until it has been published for the
        // propagation period (OIDC Core §10.1.1), so the promoting pass runs
        // after it. `created_at` is the instant the staging pass was given.
        repository
            .apply_schedule(SigningAlgorithm::DEFAULT, later + Duration::seconds(2))
            .await
            .expect("promote");
        let active = repository
            .active_signing_key(SigningAlgorithm::DEFAULT)
            .await
            .expect("read")
            .expect("an active key")
            .0;
        assert_ne!(active, before, "the rotation did not change the active key");

        // Inside the cache lifetime the signer has not noticed, which is the
        // bounded staleness the design accepts: the old key is `retiring`, not
        // retired, so the token still verifies against the published set.
        let stale = signer
            .sign(&fixture.tenant, None, "at+jwt", &json!({}))
            .await
            .expect("sign");
        assert_eq!(
            jws::parse(stale.as_str()).expect("parse").kid().expect("kid"),
            before
        );
        verify_against_the_published_jwks(&fixture, stale.as_str()).await;

        // Past it, the new key is in service.
        fixture.clock.advance(ttl + Duration::seconds(1));
        let fresh = signer
            .sign(&fixture.tenant, None, "at+jwt", &json!({}))
            .await
            .expect("sign");
        assert_eq!(
            jws::parse(fresh.as_str()).expect("parse").kid().expect("kid"),
            active,
            "the signer never picked up the rotation"
        );

        fixture.tear_down().await;
    }
}

db_test! {
    /// A key created after the signer decided the tenant had none must also be
    /// picked up. The negative answer is cached for the same reason the
    /// positive one is — a misconfigured deployment would otherwise ask the
    /// database on every token — and it ages out on the same clock.
    async fn a_key_created_after_a_miss_is_found_when_the_miss_ages_out(fixture) {
        let ttl = Duration::seconds(60);
        let signer = fixture.signer(ttl);

        assert!(
            signer
                .sign(&fixture.tenant, None, "at+jwt", &json!({}))
                .await
                .is_err()
        );

        fixture.provision(SigningAlgorithm::DEFAULT).await;
        assert!(
            signer
                .sign(&fixture.tenant, None, "at+jwt", &json!({}))
                .await
                .is_err(),
            "the cached miss expired early"
        );

        fixture.clock.advance(ttl + Duration::seconds(1));
        assert!(
            signer
                .sign(&fixture.tenant, None, "at+jwt", &json!({}))
                .await
                .is_ok(),
            "a key created after a miss was never found"
        );

        fixture.tear_down().await;
    }
}
