//! PostgreSQL adapters.
//!
//! Implements the domain repository ports with `sqlx`. Every query is
//! tenant-scoped: repository methods take a `TenantId` and the SQL always
//! filters on it, so a cross-tenant read cannot be expressed.
#![forbid(unsafe_code)]
