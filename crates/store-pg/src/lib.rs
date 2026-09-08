//! PostgreSQL adapters.
//!
//! Implements the domain repository ports with `sqlx`. The organising idea is
//! that a query cannot be written without first choosing a tenant: everything
//! except [`PgTenantRepository`] hangs off [`TenantScope`], which carries the
//! tenant id and binds it into every statement. See
//! [ADR-0001](../../../docs/adr/0001-modular-monolith.md).
#![forbid(unsafe_code)]

mod audit;
mod clients;
mod error;
mod scope;
mod sql_audit;
mod store;
mod tenants;

pub use audit::{PgAuditSink, VerifiedChain};
pub use clients::PgClientRepository;
pub use error::to_domain_error;
pub use scope::TenantScope;
pub use store::{MIGRATOR, Store};
pub use tenants::PgTenantRepository;
