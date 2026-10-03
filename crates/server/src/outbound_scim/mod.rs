//! Candidate outbound SCIM lifecycle. Operator registry is empty by default.

mod credentials;

pub use credentials::{OperatorCredential, ScopedCredentialRegistry};
