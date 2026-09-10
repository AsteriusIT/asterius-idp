//! The one static file the end-user pages fetch: the typeface.
//!
//! `asterius_web::brand` holds the bytes and decides the path; this module is
//! the route that answers it. The split is the crate boundary doing its job —
//! the pages crate knows what a page needs, the server crate knows how a
//! request is served — and it means the `@font-face` in `base.html` and the
//! route below cannot name two different paths, because both call
//! [`asterius_web::brand::font_path`].
//!
//! # Why the path carries a digest
//!
//! The interaction pages are served `Cache-Control: no-store` (RFC 9700 §4.3:
//! a page carrying a `state` or an interaction id must not sit in a shared
//! cache), so the face they name must be cacheable on its own or every sign-in
//! would fetch 68 KB again. The name is a hash of the bytes, so the answer is
//! `public, max-age=31536000, immutable`: new bytes are a new URL, and there
//! is nothing to revalidate and nothing to purge.
//!
//! # Why there is no path parameter
//!
//! The route is registered at the literal path, so there is no name to match,
//! no table to look up and no way to express a traversal: a request for
//! anything else simply matches no route. That is the same decision
//! `asterius_admin_api::console` makes for the console bundle, for the same
//! reason.

use axum::Router;
use axum::http::{HeaderValue, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;

/// The route that serves the embedded face.
///
/// Mounted with the rest of the browser-facing routes, so a path-based tenant
/// reaches it at `/t/{tenant}` + this path — which is exactly what
/// `MountPrefix::absolute` puts in the page (`ast-295`).
pub fn routes<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new().route(asterius_web::brand::font_path(), get(font))
}

/// Answers with the face itself.
async fn font() -> Response {
    (
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static(asterius_web::brand::FONT_CONTENT_TYPE),
            ),
            (
                header::CACHE_CONTROL,
                HeaderValue::from_static(asterius_web::brand::FONT_CACHE_CONTROL),
            ),
        ],
        asterius_web::brand::FONT_BYTES,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    async fn get_path(path: &str) -> Response {
        routes::<()>()
            .oneshot(
                Request::builder()
                    .uri(path)
                    .body(Body::empty())
                    .expect("a request"),
            )
            .await
            .expect("the router answers")
    }

    /// The acceptance criterion of `ast-vn7`'s second point: the face is served
    /// from this origin, as a font, cacheable for a year.
    #[tokio::test]
    async fn the_face_is_served_as_woff2_and_cached_for_a_year() {
        let response = get_path(asterius_web::brand::font_path()).await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "font/woff2"
        );
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "public, max-age=31536000, immutable",
            "a digest-named file must be immutable, or every sign-in refetches it"
        );
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("the body");
        assert_eq!(
            body.as_ref(),
            asterius_web::brand::FONT_BYTES,
            "the route served something other than the embedded face"
        );
    }

    /// The digest is part of the name, so the old name must not still work.
    ///
    /// A route that answered any path under `/assets/font/` would make the
    /// `immutable` year a lie: a stale URL in a cached document would keep
    /// resolving to whatever the binary now holds.
    #[tokio::test]
    async fn no_path_but_the_digest_one_is_served() {
        for path in [
            "/assets/font/geist.woff2",
            "/assets/font/geist-0000000000000000.woff2",
            "/assets/font/",
            "/assets/font/../../etc/passwd",
        ] {
            let response = get_path(path).await;

            assert_eq!(
                response.status(),
                StatusCode::NOT_FOUND,
                "{path} was served by the font route"
            );
        }
    }
}
