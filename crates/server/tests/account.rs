//! Where an account page sends somebody who is not signed in (`ast-jkom`).
//!
//! The four self-service pages of `ast-1xd` all open their sign-in through
//! `account::begin`, and `/account` is the one that sits one segment shallower
//! than the rest. A `Location` built relative to the request therefore resolved
//! differently for the home page than for `/account/passkeys` — under a
//! path-based tenant it dropped `/t/{id}` and 404ed. What is asserted here is
//! the whole round trip: the `Location` the browser is given, and the place the
//! interaction's destination brings it back to afterwards.

use asterius_domain::{
    AcrPolicy, AuthenticationMethod, ClientId, DomainError, FirstPartyDestination,
    InteractionRecord, InteractionRepository, Issuer, Participant, Session, SessionRepository,
    SessionRevocation, Tenant, TenantId, TenantStatus, User, UserDirectory, UserId,
};
use asterius_server::http::account::{self, AccountContext};
use asterius_server::http::console::location_of;
use asterius_server::tenancy::MountPrefix;
use asterius_web::Catalog;
use asterius_web::csp::Nonce;
use axum::http::{HeaderMap, header};
use serde_json::Value;
use std::sync::Mutex;
use time::OffsetDateTime;

const ISSUER: &str = "https://as.example/t/demo";

/// The only redirect status this server emits, spelled as a number: the
/// constant itself is confined to `http::redirect` by `http::source_audit`.
const SEE_OTHER: u16 = 303;

static ENGLISH: Catalog = Catalog::new(asterius_domain::locale::Locale::English);

// ---- the fakes ----------------------------------------------------------

/// Every first-party interaction these pages opened.
#[derive(Debug, Default)]
struct FakeInteractions {
    opened: Mutex<Vec<FirstPartyDestination>>,
}

#[async_trait::async_trait]
impl InteractionRepository for FakeInteractions {
    async fn begin_first_party_interaction(
        &self,
        _digest: &str,
        destination: FirstPartyDestination,
        _expires_at: OffsetDateTime,
        _now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        self.opened.lock().expect("lock").push(destination);
        Ok(())
    }
    async fn begin_interaction(
        &self,
        _r: &str,
        _i: &str,
        _n: OffsetDateTime,
    ) -> Result<(), DomainError> {
        unimplemented!("an account page only opens first-party interactions")
    }
    async fn by_interaction(
        &self,
        _d: &str,
        _n: OffsetDateTime,
    ) -> Result<Option<InteractionRecord>, DomainError> {
        Ok(None)
    }
    async fn save_interaction_state(
        &self,
        _d: &str,
        _s: &Value,
        _session: Option<&str>,
        _n: OffsetDateTime,
    ) -> Result<(), DomainError> {
        Ok(())
    }
    async fn complete_interaction(&self, _d: &str, _n: OffsetDateTime) -> Result<(), DomainError> {
        Ok(())
    }
    async fn destroy_interaction(&self, _d: &str) -> Result<(), DomainError> {
        Ok(())
    }
}

/// A session store that holds nobody: every request here arrives without one.
#[derive(Debug, Default)]
struct NoSessions;

#[async_trait::async_trait]
impl SessionRepository for NoSessions {
    async fn begin(&self, _s: &Session) -> Result<(), DomainError> {
        Ok(())
    }
    async fn find(&self, _d: &str) -> Result<Option<Session>, DomainError> {
        Ok(None)
    }
    async fn touch(
        &self,
        _d: &str,
        _n: OffsetDateTime,
        _i: time::Duration,
    ) -> Result<(), DomainError> {
        Ok(())
    }
    async fn rotate(
        &self,
        _o: &str,
        _n: &str,
        _m: &[AuthenticationMethod],
        _acr: Option<&str>,
        _at: OffsetDateTime,
    ) -> Result<(), DomainError> {
        Ok(())
    }
    async fn revoke(
        &self,
        _d: &str,
        _r: SessionRevocation,
        _n: OffsetDateTime,
    ) -> Result<(), DomainError> {
        Ok(())
    }
    async fn revoke_all_for_user(
        &self,
        _u: uuid::Uuid,
        _r: SessionRevocation,
        _n: OffsetDateTime,
    ) -> Result<u64, DomainError> {
        Ok(0)
    }
    async fn record_participant(
        &self,
        _d: &str,
        _c: &ClientId,
        _n: OffsetDateTime,
    ) -> Result<(), DomainError> {
        Ok(())
    }
    async fn participants(&self, _d: &str) -> Result<Vec<Participant>, DomainError> {
        Ok(Vec::new())
    }
}

/// An account directory nobody reaches: the page under test never gets that
/// far, because it has no session.
#[derive(Debug, Default)]
struct NoUsers;

#[async_trait::async_trait]
impl UserDirectory for NoUsers {
    async fn by_id(&self, _id: UserId) -> Result<Option<User>, DomainError> {
        Ok(None)
    }
}

// ---- the fixture --------------------------------------------------------

fn tenant() -> Tenant {
    Tenant {
        id: TenantId::parse("demo").expect("a tenant id"),
        issuer: Issuer::parse(ISSUER).expect("an issuer"),
        default_resource: "https://api.example/".to_owned(),
        custom_host: None,
        display_name: "Demo".to_owned(),
        status: TenantStatus::Active,
        refresh: asterius_domain::RefreshPolicy::default(),
        created_at: OffsetDateTime::UNIX_EPOCH,
        updated_at: OffsetDateTime::UNIX_EPOCH,
    }
}

fn epoch() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("a fixed instant")
}

/// The `Location` of a response, as the browser would read it.
fn location(response: &axum::response::Response) -> String {
    response
        .headers()
        .get(header::LOCATION)
        .expect("a redirect carries a Location")
        .to_str()
        .expect("a Location is text")
        .to_owned()
}

/// Where a browser at `from` ends up when it is sent to `location`.
fn resolved(from: &str, location: &str) -> String {
    url::Url::parse(&format!("https://as.example{from}"))
        .expect("a page URL")
        .join(location)
        .expect("a resolvable Location")
        .path()
        .to_owned()
}

// ---- the tests ----------------------------------------------------------

/// The bug: `/t/demo/account` without a session sent the browser to
/// `/t/interaction/{id}`, which is mounted under no tenant and is a 404.
#[tokio::test]
async fn the_home_page_sends_an_unauthenticated_visitor_into_this_tenants_interaction() {
    // Arrange
    let tenant = tenant();
    let interactions = FakeInteractions::default();
    let sessions = NoSessions;
    let acr = AcrPolicy::default();
    let nonce = Nonce::generate();
    let context = AccountContext {
        tenant: &tenant,
        sessions: &sessions,
        interactions: &interactions,
        acr: &acr,
        text: &ENGLISH,
        nonce: &nonce,
        mount: MountPrefix::for_tenant(&tenant.id),
    };

    // Act
    let response = account::page(&context, &NoUsers, &HeaderMap::new(), epoch()).await;

    // Assert
    assert_eq!(response.status().as_u16(), SEE_OTHER);
    let location = location(&response);
    let landed = resolved("/t/demo/account", &location);
    assert!(
        landed.starts_with("/t/demo/interaction/"),
        "the home page dropped the tenant: {landed}"
    );
}

/// The other three pages open the same sign-in one segment deeper, and the
/// `Location` has to hold the tenant for them too.
#[tokio::test]
async fn every_account_page_keeps_the_tenant_segment() {
    // Arrange
    let tenant = tenant();
    let interactions = FakeInteractions::default();
    let sessions = NoSessions;
    let acr = AcrPolicy::default();
    let nonce = Nonce::generate();
    let context = AccountContext {
        tenant: &tenant,
        sessions: &sessions,
        interactions: &interactions,
        acr: &acr,
        text: &ENGLISH,
        nonce: &nonce,
        mount: MountPrefix::for_tenant(&tenant.id),
    };
    let pages = [
        ("/t/demo/account", FirstPartyDestination::AccountHome),
        (
            "/t/demo/account/passkeys",
            FirstPartyDestination::AccountPasskeys,
        ),
        (
            "/t/demo/account/password",
            FirstPartyDestination::AccountPassword,
        ),
        (
            "/t/demo/account/sessions",
            FirstPartyDestination::AccountSessions,
        ),
    ];

    for (path, destination) in pages {
        // Act
        let response = account::begin(&context, destination, epoch()).await;

        // Assert
        assert_eq!(response.status().as_u16(), SEE_OTHER, "{path}");
        let location = location(&response);
        let landed = resolved(path, &location);
        assert!(
            landed.starts_with("/t/demo/interaction/"),
            "{path} sent the browser to {landed}"
        );

        // And back again, once the person has authenticated.
        assert_eq!(
            resolved(&landed, location_of(destination)),
            path,
            "{path} is not where its destination returns to"
        );
    }
}

/// A host-based tenant has no prefix, and the same `Location` must not grow
/// one: `/account` there is served at the root.
#[tokio::test]
async fn a_tenant_without_a_prefix_is_sent_to_the_root_interaction() {
    // Arrange
    let tenant = tenant();
    let interactions = FakeInteractions::default();
    let sessions = NoSessions;
    let acr = AcrPolicy::default();
    let nonce = Nonce::generate();
    let context = AccountContext {
        tenant: &tenant,
        sessions: &sessions,
        interactions: &interactions,
        acr: &acr,
        text: &ENGLISH,
        nonce: &nonce,
        mount: MountPrefix::root(),
    };

    // Act
    let response = account::begin(&context, FirstPartyDestination::AccountHome, epoch()).await;

    // Assert
    let landed = resolved("/account", &location(&response));
    assert!(landed.starts_with("/interaction/"), "{landed}");
}
