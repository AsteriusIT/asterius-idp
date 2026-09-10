//! Server-rendered end-user surface: login, consent, error and logout pages.
//!
//! Pages work without JavaScript, are themed through design tokens only (a
//! tenant never supplies scripts or markup) and are served under a strict
//! nonce-based Content-Security-Policy.
//!
//! The policy and the middleware that applies it are here rather than in
//! `asterius-server` because they are properties of a *document*, and documents
//! are what this crate is for: [`document::Document`] is the only thing in the
//! workspace that produces `text/html`, and it cannot be built without the
//! [`csp::Nonce`] that its own policy names. `asterius-server` keeps the header
//! set that belongs on every response, document or not.
#![forbid(unsafe_code)]

pub mod csp;
pub mod document;
pub mod i18n;
pub mod interaction;
pub mod pages;
pub mod recovery;
pub mod session;
mod snapshots;
mod source_audit;
pub mod theme;

pub use csp::{FormActionOrigin, InvalidOrigin, Nonce, Policy};
pub use document::Document;
pub use i18n::{Catalog, MessageKey, OverrideError, validate_overrides};
pub use interaction::{CsrfToken, Interaction, InteractionError, InteractionId, Stage};
