//! PostgreSQL adapters.
//!
//! Implements the domain repository ports with `sqlx`. The organising idea is
//! that a query cannot be written without first choosing a tenant: everything
//! except [`PgTenantRepository`] hangs off [`TenantScope`], which carries the
//! tenant id and binds it into every statement. See
//! [ADR-0001](../../../docs/adr/0001-modular-monolith.md).
#![forbid(unsafe_code)]

mod admin_seed;
mod audit;
mod auth_requests;
mod authorization_details_types;
mod client_key_fetches;
mod client_usage;
mod clients;
mod codes;
mod cutoffs;
mod error;
mod grants;
mod initial_access_tokens;
mod key_store;
mod keys;
mod notifications;
mod passkeys;
mod passwords;
mod provisioning;
mod rate_limits;
mod recovery;
mod refresh;
mod replay;
mod resource_servers;
mod retention;
mod rewrap;
mod roles;
mod salts;
mod scope;
mod sessions;
mod sql_audit;
mod store;
mod tenant_settings;
mod tenants;
mod users;

pub use admin_seed::{DeploymentAdmin, PgAdminSeed, Seeded};
pub use audit::{PgAuditSink, VerifiedChain};
pub use auth_requests::PgAuthRequestRepository;
pub use authorization_details_types::PgAuthorizationDetailsTypes;
pub use client_key_fetches::PgClientKeyFetches;
pub use client_usage::PgClientUsage;
pub use clients::PgClientRepository;
pub use codes::{PgCodeRepository, Redemption};
pub use error::to_domain_error;
pub use grants::{PgGrantRepository, Revocation};
pub use initial_access_tokens::PgInitialAccessTokens;
pub use key_store::TenantKeyStore;
pub use keys::{PgKeyRepository, Rotation, RotationSchedule};
pub use notifications::{PgOutboxMailSender, QueuedNotification};
pub use passkeys::PgPasskeyRepository;
pub use passwords::PgPasswordVerifier;
pub use provisioning::ProvisionedTenants;
pub use rate_limits::PgRateLimitStore;
pub use recovery::PgRecoveryTokens;
pub use refresh::{
    NewRefreshToken, PgRefreshTokenRepository, Presentation, RefreshBinding, RefreshTokenRecord,
};
pub use replay::PgReplayGuard;
pub use resource_servers::PgResourceServers;
pub use retention::{POLICY, PgRetention, Retention, Rule, Sweep, SweepOutcome};
pub use rewrap::{PgKekRewrap, Rewrap, RewrapOutcome};
pub use roles::PgRoleRepository;
pub use scope::TenantScope;
pub use sessions::PgSessionRepository;
pub use store::{MIGRATOR, Store};
pub use tenant_settings::PgTenantSettings;
pub use tenants::PgTenantRepository;
pub use users::PgUserRepository;
