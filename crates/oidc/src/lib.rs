//! OpenID Connect and OAuth 2.0 protocol logic.
//!
//! Everything here is a pure function over [`asterius_domain`] types: parse,
//! validate, decide. There is no I/O, no `sqlx`, no `axum` and no runtime — a
//! protocol rule can therefore be tested against the normative text without
//! standing up a server. Side effects belong to the adapters.
#![forbid(unsafe_code)]

pub mod authorize;
pub mod client_auth;
pub mod metadata;
pub mod par;
pub mod pkce;
pub mod tenancy;
