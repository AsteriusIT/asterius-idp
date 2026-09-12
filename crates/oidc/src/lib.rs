//! OpenID Connect and OAuth 2.0 protocol logic.
//!
//! Everything here is a pure function over [`asterius_domain`] types: parse,
//! validate, decide. There is no I/O, no `sqlx`, no `axum` and no runtime — a
//! protocol rule can therefore be tested against the normative text without
//! standing up a server. Side effects belong to the adapters.
#![forbid(unsafe_code)]

pub mod authorize;
pub mod authzen;
pub mod authzen_configuration;
pub mod ciba;
pub mod claims;
pub mod client_auth;
pub mod code;
pub mod consent;
pub mod consent_memory;
pub mod decision;
pub mod device;
pub mod form;
pub mod grant_management;
pub mod logout;
pub mod metadata;
pub mod mtls;
pub mod par;
pub mod pkce;
pub mod refresh;
pub mod request_object;
pub mod revocation;
pub mod tenancy;
pub mod token;
pub mod token_exchange;
pub mod tokens;
pub mod userinfo;
