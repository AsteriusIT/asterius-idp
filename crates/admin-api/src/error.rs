//! One error envelope, for every route.
//!
//! A JSON API whose errors are shaped by whichever handler produced them is an
//! API a console has to special-case at every call site, and the special cases
//! are where a failure gets rendered as a success. So there is one type here,
//! it is the only thing a handler may return on the unhappy path, and the
//! envelope is built in exactly one place — [`AdminError::into_response`].
//!
//! # What the body says, and what it does not
//!
//! ```json
//! { "error": { "code": "forbidden", "message": "…" } }
//! ```
//!
//! `code` is a closed vocabulary the console switches on; `message` is for a
//! person reading a log. Neither ever carries a credential, a session id or a
//! CSRF token: an error body is the easiest thing in an API to end up
//! screenshotted into a ticket.
//!
//! The distinction between "you are not authenticated" (401) and "you are, and
//! it is not enough" (403) is deliberate and is what the table-driven test in
//! [`crate::router`] asserts route by route. Collapsing them to one status
//! would hide the difference between a console whose session expired and an
//! administrator who has been given the wrong role.

use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

/// Everything an admin API route may refuse a request for.
///
/// Deliberately not `DomainError`. A storage failure and a forbidden request
/// are the same enum there and must never be the same status here, so the
/// conversion is explicit: [`AdminError::from_storage`] maps a domain error to
/// the one thing a caller may be told about it.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AdminError {
    /// No credential at all: no session cookie and no token.
    #[error("this operation requires an authenticated administrator")]
    Unauthenticated,

    /// A session cookie was presented and did not resolve, or resolved to a
    /// session that is expired, idle or revoked.
    ///
    /// Answered as 401 with the same body as [`Self::Unauthenticated`]: the
    /// two are the same thing to a console, which reauthenticates either way,
    /// and telling an anonymous caller that a particular cookie *was* a
    /// session once is an oracle nobody needs.
    #[error("the session presented is not usable")]
    SessionUnusable,

    /// An `Authorization` header was presented and the token behind it is not
    /// one this server will act on.
    #[error("the access token presented is not usable")]
    InvalidToken,

    /// Authenticated, but without the role or scope the operation declares.
    #[error("this credential does not carry the authority this operation needs")]
    Forbidden,

    /// A non-`GET` request arrived without the session's synchroniser token.
    #[error("a state-changing request must carry this session's X-CSRF-Token")]
    CsrfMissing,

    /// The synchroniser token presented is not this session's.
    #[error("the X-CSRF-Token presented is not this session's")]
    CsrfMismatch,

    /// `Origin` or `Sec-Fetch-Site` says the request was made from somewhere
    /// else. The second CSRF layer ADR-0009 requires.
    #[error("a state-changing request must come from this origin")]
    CrossSite,

    /// A `POST` arrived without an `Idempotency-Key`.
    #[error("a POST must carry an Idempotency-Key")]
    IdempotencyKeyMissing,

    /// The `Idempotency-Key` is not a value this server will store.
    #[error("the Idempotency-Key is not acceptable: {0}")]
    IdempotencyKeyInvalid(&'static str),

    /// The `Idempotency-Key` has been used before.
    #[error("this Idempotency-Key has already been used")]
    IdempotencyReplay,

    /// A pagination cursor this server did not issue, or one that no longer
    /// parses.
    #[error("the cursor presented is not one this server issued")]
    CursorInvalid,

    /// The request body or a parameter is wrong in a way the caller can fix.
    #[error("{0}")]
    Invalid(String),

    /// The thing addressed is not there.
    #[error("no such resource")]
    NotFound,

    /// The request conflicts with the current state.
    #[error("{0}")]
    Conflict(String),

    /// A limit was reached.
    #[error("too many requests")]
    Throttled {
        /// Whole seconds until the window rolls over, for `Retry-After`.
        retry_after_seconds: u64,
    },

    /// Something below this layer failed. Never carries the reason: a storage
    /// error's text is a description of the database.
    #[error("the request could not be completed")]
    Unavailable,
}

impl AdminError {
    /// The wire code, which is a closed vocabulary the console switches on.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Unauthenticated | Self::SessionUnusable => "unauthenticated",
            Self::InvalidToken => "invalid_token",
            Self::Forbidden => "forbidden",
            Self::CsrfMissing | Self::CsrfMismatch | Self::CrossSite => "csrf_failed",
            Self::IdempotencyKeyMissing | Self::IdempotencyKeyInvalid(_) => "idempotency_key",
            Self::IdempotencyReplay => "idempotency_replay",
            Self::CursorInvalid => "invalid_cursor",
            Self::Invalid(_) => "invalid_request",
            Self::NotFound => "not_found",
            Self::Conflict(_) => "conflict",
            Self::Throttled { .. } => "rate_limited",
            Self::Unavailable => "unavailable",
        }
    }

    /// The status this refusal is reported with.
    ///
    /// One `match`, so "which failures are 401 and which are 403" is a
    /// question with one answer that a test can read.
    #[must_use]
    pub const fn status(&self) -> StatusCode {
        match self {
            Self::Unauthenticated | Self::SessionUnusable | Self::InvalidToken => {
                StatusCode::UNAUTHORIZED
            }
            Self::Forbidden
            | Self::CsrfMissing
            | Self::CsrfMismatch
            | Self::CrossSite
            | Self::IdempotencyKeyMissing
            | Self::IdempotencyKeyInvalid(_) => StatusCode::FORBIDDEN,
            Self::IdempotencyReplay | Self::Conflict(_) => StatusCode::CONFLICT,
            Self::CursorInvalid | Self::Invalid(_) => StatusCode::BAD_REQUEST,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::Throttled { .. } => StatusCode::TOO_MANY_REQUESTS,
            Self::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        }
    }

    /// Reduces anything from below this layer to the one thing a caller may be
    /// told.
    ///
    /// The reason is logged here rather than returned: a `DomainError`'s text
    /// names columns, constraints and occasionally values, and none of that is
    /// an administrator's business through an HTTP body.
    #[must_use]
    pub fn from_storage(operation: &'static str, error: &asterius_domain::DomainError) -> Self {
        tracing::error!(%error, operation, "an admin API operation failed below the API");
        Self::Unavailable
    }
}

impl IntoResponse for AdminError {
    fn into_response(self) -> Response {
        let body = serde_json::json!({
            "error": {
                "code": self.code(),
                "message": self.to_string(),
            }
        });

        let mut response = (self.status(), axum::Json(body)).into_response();
        let headers = response.headers_mut();

        // An error body is never cached, by anything. A 403 held in a shared
        // cache and replayed to the next administrator is a support ticket
        // nobody can reproduce.
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));

        // RFC 9449 §7.1: the challenge names the scheme this API accepts for
        // token calls, which is DPoP and not Bearer. Only on the token path —
        // a console that got a 401 must show a sign-in link, and a browser
        // shown a `WWW-Authenticate` it understands would pop a native dialog
        // over the top of it.
        if matches!(self, Self::InvalidToken) {
            headers.insert(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static(r#"DPoP error="invalid_token""#),
            );
        }

        if let Self::Throttled {
            retry_after_seconds,
        } = self
            && let Ok(value) = HeaderValue::from_str(&retry_after_seconds.to_string())
        {
            headers.insert(header::RETRY_AFTER, value);
        }

        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The distinction the whole RBAC test rests on: missing authority is 401,
    /// insufficient authority is 403, and they are never swapped.
    #[test]
    fn missing_authentication_is_401_and_insufficient_authority_is_403() {
        // Arrange / Act / Assert
        assert_eq!(
            AdminError::Unauthenticated.status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            AdminError::SessionUnusable.status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(AdminError::Forbidden.status(), StatusCode::FORBIDDEN);
    }

    /// A session that expired and a request with no cookie at all report the
    /// same code, because the difference is not the caller's business.
    #[test]
    fn an_expired_session_is_indistinguishable_from_no_session() {
        assert_eq!(
            AdminError::SessionUnusable.code(),
            AdminError::Unauthenticated.code()
        );
    }

    #[test]
    fn every_variant_has_a_distinct_code_or_a_deliberate_shared_one() {
        // Arrange
        let refusals = [
            AdminError::Unauthenticated,
            AdminError::InvalidToken,
            AdminError::Forbidden,
            AdminError::CsrfMissing,
            AdminError::CursorInvalid,
            AdminError::NotFound,
            AdminError::Unavailable,
        ];

        // Act
        let codes: std::collections::BTreeSet<_> = refusals.iter().map(AdminError::code).collect();

        // Assert
        assert_eq!(codes.len(), refusals.len());
    }

    /// The reason a storage failure is reduced rather than forwarded.
    #[test]
    fn a_storage_failure_never_reaches_the_caller_as_text() {
        // Arrange
        let underlying =
            asterius_domain::DomainError::Storage("relation \"tenants\" does not exist".into());

        // Act
        let refused = AdminError::from_storage("tenants.list", &underlying);

        // Assert
        assert_eq!(refused.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(!refused.to_string().contains("tenants"));
    }
}
