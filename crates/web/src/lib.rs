//! Server-rendered end-user surface: login, consent, error and logout pages.
//!
//! Pages work without JavaScript, are themed through design tokens only (a
//! tenant never supplies scripts or markup) and are served under a strict
//! nonce-based Content-Security-Policy.
#![forbid(unsafe_code)]
