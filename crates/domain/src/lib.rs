//! Core entities and ports for Asterius.
//!
//! This crate is the centre of the hexagon: it owns the vocabulary of the
//! identity provider (tenants, clients, subjects, grants) and the *ports* —
//! traits — through which protocol code reaches the outside world. It must
//! never depend on a database driver, an HTTP framework or an async runtime.
#![forbid(unsafe_code)]

pub mod audit;
pub mod capabilities;
pub mod entities;
pub mod error;
pub mod ids;
pub mod issuer;
pub mod ports;
pub mod secret;

pub use audit::{Actor, AuditEvent, AuditSink, Detail, EventType, Outcome};
pub use capabilities::{Capabilities, Feature};
pub use entities::{Tenant, TenantStatus};
pub use error::DomainError;
pub use ids::{ClientId, GrantId, SessionId, SubjectId, TenantId, TenantIdError};
pub use issuer::{Issuer, IssuerError};
pub use secret::Secret;
