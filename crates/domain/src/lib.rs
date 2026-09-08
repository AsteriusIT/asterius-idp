//! Core entities and ports for Asterius.
//!
//! This crate is the centre of the hexagon: it owns the vocabulary of the
//! identity provider (tenants, clients, subjects, grants) and the *ports* —
//! traits — through which protocol code reaches the outside world. It must
//! never depend on a database driver, an HTTP framework or an async runtime.
#![forbid(unsafe_code)]

pub mod error;
pub mod ids;
pub mod ports;

pub use error::DomainError;
pub use ids::{ClientId, GrantId, SessionId, SubjectId, TenantId};
