//! PostgreSQL adapters.
//!
//! Implements the domain repository ports with `sqlx`. The organising idea is
//! that a query cannot be written without first choosing a tenant: everything
//! except [`PgTenantRepository`] hangs off [`TenantScope`], which carries the
//! tenant id and binds it into every statement. See
//! [ADR-0001](../../../docs/adr/0001-modular-monolith.md).
#![forbid(unsafe_code)]

mod audit;
mod auth_requests;
mod clients;
mod codes;
mod error;
mod grants;
mod key_store;
mod keys;
mod passwords;
mod replay;
mod retention;
mod rewrap;
mod salts;
mod scope;
mod sessions;
mod sql_audit;
mod store;
mod tenants;
mod users;

pub use audit::{PgAuditSink, VerifiedChain};
pub use auth_requests::PgAuthRequestRepository;
pub use clients::PgClientRepository;
pub use codes::{PgCodeRepository, Redemption};
pub use error::to_domain_error;
pub use grants::{PgGrantRepository, Revocation};
pub use key_store::TenantKeyStore;
pub use keys::{PgKeyRepository, Rotation, RotationSchedule};
pub use passwords::PgPasswordVerifier;
pub use replay::PgReplayGuard;
pub use retention::{POLICY, PgRetention, Retention, Rule, Sweep, SweepOutcome};
pub use rewrap::{PgKekRewrap, Rewrap, RewrapOutcome};
pub use scope::TenantScope;
pub use sessions::PgSessionRepository;
pub use store::{MIGRATOR, Store};
pub use tenants::PgTenantRepository;
pub use users::PgUserRepository;
