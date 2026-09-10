//! Composition root for the `asterius` binary.
//!
//! This is the only crate allowed to know about every other crate: it picks
//! the adapters that satisfy the domain ports and wires them into the axum
//! router.
#![forbid(unsafe_code)]

pub mod admin;
pub mod client_auth;
pub mod config;
pub mod config_reference;
pub mod http;
pub mod mtls;
pub mod observability;
pub mod outbound;
pub mod outbox;
pub mod retention;
pub mod rotation;
pub mod signing;
pub mod tenancy;
pub mod tenant_settings;

pub use config::{Config, ConfigError};
pub use tenancy::{TenantDirectory, TenantState};

/// The version of the running server, as reported by metadata and `/healthz`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
