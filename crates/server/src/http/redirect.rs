//! The only way this codebase issues a redirect.
//!
//! FAPI 2.0 SP §5.3.2.2 items 10–11 forbid HTTP 307 at the authorization
//! endpoint, and the reason generalises: 307 and 308 tell the browser to repeat
//! the request *including its body and method*, so a `POST`ed credential is
//! replayed to the new location. 302 has the same hazard in principle and is
//! handled inconsistently in practice.
//!
//! 303 is the one status that means "go and GET this instead", which is what an
//! authorization response, a login redirect and a logout redirect all want. So
//! there is a single helper, it hard-codes 303, and a test asserts no other
//! redirect status appears anywhere in the tree.

use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

/// A redirect. Always 303, never anything else.
#[derive(Debug, Clone)]
pub struct SeeOther(HeaderValue);

impl SeeOther {
    /// Builds a redirect to `location`.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidLocation`] if the location cannot be a header value —
    /// which in practice means it contains a control character or a newline,
    /// i.e. someone is attempting response splitting through a redirect
    /// parameter.
    pub fn to(location: &str) -> Result<Self, InvalidLocation> {
        HeaderValue::from_str(location)
            .map(Self)
            .map_err(|_| InvalidLocation)
    }

    /// The `Location` this redirect points at.
    #[must_use]
    pub fn location(&self) -> &HeaderValue {
        &self.0
    }
}

/// The location was not usable as a `Location` header value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("redirect location is not a valid header value")]
pub struct InvalidLocation;

impl IntoResponse for SeeOther {
    fn into_response(self) -> Response {
        // StatusCode::SEE_OTHER, written once, in one place.
        (StatusCode::SEE_OTHER, [(header::LOCATION, self.0)]).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;

    #[test]
    fn a_redirect_is_always_303() {
        let response = SeeOther::to("https://rp.example/cb?code=abc")
            .expect("valid")
            .into_response();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(response.status().as_u16(), 303);
        assert_eq!(
            response.headers().get(header::LOCATION).expect("Location"),
            "https://rp.example/cb?code=abc"
        );
    }

    /// A `Location` built from a request parameter is attacker-influenced, so
    /// the header value has to reject CR and LF rather than emit them.
    #[test]
    fn a_location_cannot_smuggle_a_second_response() {
        for hostile in [
            "https://rp.example/cb\r\nSet-Cookie: session=stolen",
            "https://rp.example/cb\nX-Injected: 1",
            "https://rp.example/cb\0",
        ] {
            assert_eq!(
                SeeOther::to(hostile).err(),
                Some(InvalidLocation),
                "accepted {hostile:?}"
            );
        }
    }
}
