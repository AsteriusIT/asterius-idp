//! A correlation id for every request.

use axum::extract::Request;
use axum::http::{HeaderName, HeaderValue};
use axum::middleware::Next;
use axum::response::Response;

/// The header this id travels in, on the way out.
pub const HEADER: HeaderName = HeaderName::from_static("x-request-id");

/// A 128-bit request identifier, rendered as lower-case hex.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestId(String);

impl RequestId {
    /// Draws a new identifier from the operating system CSPRNG.
    ///
    /// A counter would be cheaper, but a predictable request id leaks the
    /// server's request rate to anyone who can see two of them, and these end
    /// up in audit records that get shared during incidents.
    #[must_use]
    pub fn generate() -> Self {
        let mut bytes = [0_u8; 16];
        getrandom::fill(&mut bytes).expect("the OS CSPRNG must be available");
        let mut hex = String::with_capacity(32);
        for byte in bytes {
            use std::fmt::Write as _;
            let _ = write!(hex, "{byte:02x}");
        }
        Self(hex)
    }

    /// The identifier as a string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for RequestId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Attaches a fresh [`RequestId`] to the request and echoes it on the response.
///
/// A client-supplied `X-Request-Id` is deliberately ignored rather than
/// honoured: these ids end up in the audit trail, and letting a caller choose
/// its own would let it collide with, or impersonate, another caller's entries.
pub async fn layer(mut request: Request, next: Next) -> Response {
    let id = RequestId::generate();
    let header = HeaderValue::from_str(id.as_str()).expect("hex is a valid header value");
    request.extensions_mut().insert(id);
    let mut response = next.run(request).await;
    response.headers_mut().insert(HEADER, header);
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn ids_are_128_bits_of_hex_and_do_not_repeat() {
        let ids: HashSet<String> = (0..1000)
            .map(|_| RequestId::generate().as_str().to_owned())
            .collect();
        assert_eq!(ids.len(), 1000, "generated a duplicate request id");
        for id in &ids {
            assert_eq!(id.len(), 32);
            assert!(
                id.chars()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase())
            );
        }
    }
}
