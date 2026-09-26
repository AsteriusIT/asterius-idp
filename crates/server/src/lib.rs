//! Composition root for the `asterius` binary.
//!
//! This is the only crate allowed to know about every other crate: it picks
//! the adapters that satisfy the domain ports and wires them into the axum
//! router.
#![forbid(unsafe_code)]

pub mod admin;
pub mod backchannel;
pub mod claims_provider;
pub mod client_auth;
pub mod config;
pub mod config_reference;
pub mod federation;
pub mod http;
pub mod http_signatures;
pub mod id_jag_trust;
pub mod ldap_sync;
pub mod mtls;
pub mod observability;
pub mod oid4vp;
pub mod outbound;
pub mod outbox;
pub mod provider_commands;
pub mod retention;
pub mod rotation;
pub mod signing;
pub mod ssf;
pub mod ssf_upstream;
pub mod tenancy;
pub mod tenant_settings;

pub use config::{Config, ConfigError};
pub use tenancy::{TenantDirectory, TenantState};
pub mod themes;
pub use themes::ThemeDirectory;

/// The version of the running server, as reported by metadata and `/healthz`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
