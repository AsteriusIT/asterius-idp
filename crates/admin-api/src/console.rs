//! Serving the admin console: the embedded bundle, and the entry document the
//! server renders for it.
//!
//! # Why the document is rendered here
//!
//! ADR-0009 names this as a cost of the strict policy rather than a
//! preference: `script-src 'nonce-…' 'strict-dynamic'` means every `<script>`
//! and every `<link rel="stylesheet">` has to carry *this response's* nonce,
//! and a bundler's static `index.html` cannot — the nonce changes per
//! response. So Vite emits no HTML at all (`rollupOptions.input` is the module,
//! not a page), and the one document is this template, rendered through
//! [`asterius_web::Document`], which cannot be built without a nonce.
//!
//! # Why every URL in it is relative
//!
//! The document is served at `/admin/`, with the trailing slash, and names its
//! assets as `assets/…`. A tenant may be reached at `/t/{id}/admin/` — the
//! tenancy middleware strips that prefix before routing, so a handler cannot
//! see it — and a root-relative `/admin/assets/…` would drop it and 404. The
//! console routes on the fragment for the same reason: the document URL never
//! moves, so the base every relative URL resolves against never moves either.
//!
//! # Cache policy
//!
//! Asset names are content hashes, so an asset response is `immutable` for a
//! year: the name changes when the bytes do. The document is *not* cached —
//! `asterius_web::document::layer` puts `Cache-Control: no-store` on anything
//! it recognises as a document — which is what makes a year-long asset cache
//! safe, since the only thing naming those files is a document nobody stores.

use askama::Template;
use asterius_web::{Document, Nonce};
use axum::Router;
use axum::extract::Path as PathParam;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;

/// Where the console is mounted, beneath any tenant prefix.
///
/// Named here, beside the bundle it addresses, but *routed* by
/// `asterius_server::http::console`, which owns the redirect to
/// [`INDEX_PATH`]: see [`assets`].
pub const BASE_PATH: &str = "/admin";

/// The path of the entry document, which is `BASE_PATH` with its slash.
pub const INDEX_PATH: &str = "/admin/";

/// How long a content-hashed asset may be cached.
///
/// A year and `immutable`: the name is a hash of the bytes, so a changed asset
/// is a different URL and there is nothing to revalidate.
const ASSET_CACHE: HeaderValue = HeaderValue::from_static("public, max-age=31536000, immutable");

/// One file of the built console.
#[derive(Debug, Clone, Copy)]
pub struct Asset {
    /// The path a request names, relative to the entry document.
    pub path: &'static str,
    /// The bytes, embedded at build time.
    pub bytes: &'static [u8],
    /// The declared type, from a closed list in `build.rs`.
    pub content_type: &'static str,
}

mod generated {
    use super::Asset;
    include!(concat!(env!("OUT_DIR"), "/console_bundle.rs"));
}

/// The built console: its files, and which of them the document names.
#[derive(Debug, Clone, Copy)]
pub struct Bundle {
    assets: &'static [Asset],
    script: Option<&'static str>,
    styles: &'static [&'static str],
}

impl Bundle {
    /// The bundle compiled into this binary.
    ///
    /// Empty when the tree was compiled without `console/dist`, which is the
    /// ordinary state of a checkout where nobody has run `npm run build`. The
    /// routes still exist and say so, rather than the mount point moving
    /// between builds.
    #[must_use]
    pub const fn embedded() -> Self {
        Self {
            assets: &generated::ASSETS,
            script: generated::ENTRY_SCRIPT,
            styles: generated::ENTRY_STYLES,
        }
    }

    /// A bundle assembled by hand, for tests.
    #[must_use]
    pub const fn new(
        assets: &'static [Asset],
        script: Option<&'static str>,
        styles: &'static [&'static str],
    ) -> Self {
        Self {
            assets,
            script,
            styles,
        }
    }

    /// The asset a request names, if this bundle has it.
    ///
    /// A plain equality against the embedded table, which is what makes path
    /// traversal a non-question: nothing here joins a request onto a
    /// filesystem path, so `../../etc/passwd` is simply a name no asset has.
    #[must_use]
    pub fn find(&self, path: &str) -> Option<&Asset> {
        self.assets.iter().find(|asset| asset.path == path)
    }

    /// The entry module, if the bundle is complete.
    ///
    /// `None` when there is no manifest, or when the manifest names a file
    /// that was not embedded — a half-copied `dist` should serve the "not
    /// built" answer rather than a document whose script 404s.
    #[must_use]
    pub fn entry_script(&self) -> Option<&'static str> {
        self.script.filter(|script| self.find(script).is_some())
    }

    /// The stylesheets the document links, in manifest order.
    #[must_use]
    pub fn entry_styles(&self) -> Vec<&'static str> {
        self.styles
            .iter()
            .copied()
            .filter(|style| self.find(style).is_some())
            .collect()
    }
}

/// The entry document.
///
/// The nonce is the one interpolation marked safe, exactly as in
/// `crates/web/templates`: it is `base64url` by construction and cannot break
/// out of the attribute it sits in. Everything else askama escapes.
#[derive(Debug, Template)]
#[template(path = "console.html")]
struct Index {
    nonce_attribute: String,
    script: &'static str,
    styles: Vec<&'static str>,
}

/// The console's *unguarded* routes: the assets, and nothing else.
///
/// Two things that belong to `/admin` are deliberately not here, and both are
/// mounted by the composition root (`asterius_server::http::console`).
///
/// The entry document, because deciding whether this visitor may see it needs
/// a session repository: ADR-0009 makes a session the console's only
/// credential and `ast-wr4` makes the absence of one an interaction rather
/// than a blank shell. Serving the document from a router with no state at all
/// is what made "signed out" a thing the *script* had to notice; keeping the
/// two apart is what stops it becoming that again.
///
/// The redirect from [`BASE_PATH`] to [`INDEX_PATH`], because every redirect
/// in this codebase is built by `asterius_server::http::redirect::SeeOther` —
/// 303 and nothing else, per FAPI 2.0 SP §5.3.2.2 items 10–11 — and this crate
/// must not depend on `server` (`scripts/check-layering.sh`). So the one place
/// that can write it is the one that already wraps this router.
///
/// What is left is `GET` and changes nothing: this is a static bundle.
pub fn assets(bundle: Bundle) -> Router {
    Router::new().route("/admin/assets/{file}", get(move |file| asset(bundle, file)))
}

/// The entry document, under this response's nonce.
///
/// Takes the nonce rather than reaching for it, because the caller has already
/// had to have one: `Document::render` cannot be called without it, and the
/// handler that decides whether this visitor may see the console at all is in
/// a position to fail properly if the middleware is missing.
#[must_use]
pub fn document(bundle: Bundle, nonce: &Nonce) -> Response {
    let Some(script) = bundle.entry_script() else {
        return unavailable(
            "this build carries no console bundle: run `npm run build` in console/ and rebuild",
        );
    };

    Document::render(nonce, |nonce| {
        Index {
            nonce_attribute: nonce.attribute(),
            script,
            styles: bundle.entry_styles(),
        }
        .render()
        // A render failure is a template that does not match its own struct,
        // which is a compile-time property of askama — but a panic on a
        // request path is never the answer to "cannot happen".
        .unwrap_or_else(|error| {
            tracing::error!(%error, "the console document did not render");
            String::new()
        })
    })
    .into_response()
}

/// `GET /admin/assets/{file}` — one embedded file.
#[expect(clippy::unused_async, reason = "axum handlers must be async")]
async fn asset(bundle: Bundle, PathParam(file): PathParam<String>) -> Response {
    let Some(asset) = bundle.find(&format!("assets/{file}")) else {
        return (StatusCode::NOT_FOUND, "not found\n").into_response();
    };

    (
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static(asset.content_type),
            ),
            (header::CACHE_CONTROL, ASSET_CACHE),
        ],
        asset.bytes,
    )
        .into_response()
}

/// The answer when the console cannot be served at all.
fn unavailable(why: &'static str) -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        )],
        why,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;

    const SCRIPT: &str = "assets/main-abc123.js";
    const STYLE: &str = "assets/style-def456.css";

    static FIXTURE: [Asset; 2] = [
        Asset {
            path: SCRIPT,
            bytes: b"export const ok = 1;",
            content_type: "text/javascript; charset=utf-8",
        },
        Asset {
            path: STYLE,
            bytes: b"body{color:#000}",
            content_type: "text/css; charset=utf-8",
        },
    ];
    static STYLES: [&str; 1] = [STYLE];

    fn bundle() -> Bundle {
        Bundle::new(&FIXTURE, Some(SCRIPT), &STYLES)
    }

    /// The console as the composition root mounts it: the unguarded
    /// [`assets`] beside an entry document. `asterius_server::http::console`
    /// is the real handler for the document — it decides whether this visitor
    /// has a session at all — and this stands in for the half of it that draws
    /// the page, so that the properties of the *document* can be asserted
    /// without a tenant and a session repository.
    fn routes(bundle: Bundle) -> Router {
        assets(bundle).route(
            INDEX_PATH,
            axum::routing::get(move |nonce: Option<axum::Extension<Nonce>>| async move {
                let Some(axum::Extension(nonce)) = nonce else {
                    // What the real handler does with a router that forgot the
                    // middleware: a document with no nonce is a page whose own
                    // script the browser will block, and a blank console is
                    // worse than a sentence.
                    return unavailable("the document middleware is not installed");
                };
                document(bundle, &nonce)
            }),
        )
    }

    /// A request through the document middleware, which is how the console is
    /// mounted: the nonce is drawn there, reaches the handler in the request
    /// extensions, and reaches the header on the way out. Rendering with a
    /// hand-made nonce would make the page and the header agree by
    /// construction, which is the very thing worth checking.
    async fn get(bundle: Bundle, path: &str) -> Response {
        let request = Request::builder()
            .uri(path)
            .body(Body::empty())
            .expect("a request");
        routes(bundle)
            .layer(axum::middleware::from_fn(asterius_web::document::layer))
            .oneshot(request)
            .await
            .expect("the router answered")
    }

    /// The same, without the middleware: a console mounted by a router that
    /// forgot it.
    async fn get_unwrapped(bundle: Bundle, path: &str) -> Response {
        let request = Request::builder()
            .uri(path)
            .body(Body::empty())
            .expect("a request");
        routes(bundle)
            .oneshot(request)
            .await
            .expect("the router answered")
    }

    /// The nonce this response's own policy names.
    fn policy_nonce(response: &Response) -> String {
        let policy = response
            .headers()
            .get(header::CONTENT_SECURITY_POLICY)
            .expect("a policy")
            .to_str()
            .expect("ascii");
        let start = policy.find("'nonce-").expect("a nonce in the policy") + "'nonce-".len();
        let end = policy[start..].find('\'').expect("a closed nonce") + start;
        policy[start..end].to_owned()
    }

    async fn body_of(response: Response) -> String {
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("a body")
            .to_bytes();
        String::from_utf8(bytes.to_vec()).expect("utf-8")
    }

    #[tokio::test]
    async fn the_document_puts_the_response_nonce_on_every_script_and_style() {
        // Arrange / Act
        let response = get(bundle(), INDEX_PATH).await;

        // Assert
        assert_eq!(response.status(), StatusCode::OK);
        let nonce = policy_nonce(&response);
        let html = body_of(response).await;
        for tag in ["<script", "<link"] {
            let start = html
                .find(tag)
                .unwrap_or_else(|| panic!("no {tag} in {html}"));
            let end = html[start..].find('>').expect("a closed tag") + start;
            assert!(
                html[start..end].contains(&format!("nonce=\"{nonce}\"")),
                "{tag} does not carry the nonce this response's policy names: {}",
                &html[start..end]
            );
        }
    }

    /// `strict-dynamic` trusts what the document loads, so what the document
    /// loads must be the bundle and nothing else.
    #[tokio::test]
    async fn the_document_names_only_this_bundles_files_and_names_them_relatively() {
        let html = body_of(get(bundle(), INDEX_PATH).await).await;

        assert!(html.contains(&format!("src=\"{SCRIPT}\"")), "{html}");
        assert!(html.contains(&format!("href=\"{STYLE}\"")), "{html}");
        assert!(!html.contains("src=\"/"), "an absolute asset URL: {html}");
        assert!(!html.contains("href=\"/"), "an absolute asset URL: {html}");
        assert!(!html.contains("//"), "an off-origin URL: {html}");
    }

    /// The acceptance criterion, from the document's side: no inline script
    /// and no inline style, because nothing inline can run under this policy.
    #[tokio::test]
    async fn the_document_carries_no_inline_script_or_style() {
        let html = body_of(get(bundle(), INDEX_PATH).await).await;

        assert!(!html.contains("</script>\n<script"), "{html}");
        assert!(
            !html.contains("<style"),
            "an inline style block would need a keyword this policy forbids: {html}"
        );
        for handler in [" onclick=", " onload=", " onerror=", " onsubmit="] {
            assert!(!html.contains(handler), "an inline handler: {html}");
        }
        // One script element, and it has a src rather than a body. The `id`
        // between the tag and its type is `ast-gore`'s: the bundle reads this
        // response's nonce back off that element (see the template), so the
        // attribute order is part of what is asserted rather than incidental.
        assert_eq!(html.matches("<script").count(), 1, "{html}");
        assert!(
            html.contains("<script id=\"console-entry\" type=\"module\" src="),
            "{html}"
        );
    }

    #[tokio::test]
    async fn an_asset_is_served_with_its_type_and_an_immutable_year() {
        // Arrange / Act
        let response = get(bundle(), &format!("/admin/{SCRIPT}")).await;

        // Assert
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).expect("type"),
            "text/javascript; charset=utf-8"
        );
        assert_eq!(
            response
                .headers()
                .get(header::CACHE_CONTROL)
                .expect("cache"),
            "public, max-age=31536000, immutable"
        );
    }

    /// Nothing joins a request onto a path, so traversal is not a category of
    /// bug this can have — asserted rather than argued.
    #[tokio::test]
    async fn a_name_no_asset_has_is_a_404() {
        for wanted in [
            "/admin/assets/absent.js",
            "/admin/assets/..%2f..%2fetc%2fpasswd",
            "/admin/assets/main-abc123.js.map",
        ] {
            let response = get(bundle(), wanted).await;
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{wanted}");
        }
    }

    /// The manifest is the build's own description of itself and is not part
    /// of the served surface.
    #[tokio::test]
    async fn the_build_manifest_is_not_reachable() {
        let response = get(bundle(), "/admin/.vite/manifest.json").await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn a_build_without_a_console_says_so_rather_than_serving_a_blank_page() {
        // Arrange
        static EMPTY: [Asset; 0] = [];
        let bundle = Bundle::new(&EMPTY, None, &[]);

        // Act
        let response = get(bundle, INDEX_PATH).await;

        // Assert
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(body_of(response).await.contains("npm run build"));
    }

    /// A manifest naming a file that was not embedded is a half-copied build,
    /// not a console.
    #[tokio::test]
    async fn a_manifest_that_names_a_missing_file_is_not_a_console() {
        static EMPTY: [Asset; 0] = [];
        let bundle = Bundle::new(&EMPTY, Some("assets/gone.js"), &[]);

        assert_eq!(bundle.entry_script(), None);
        assert_eq!(
            get(bundle, INDEX_PATH).await.status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[tokio::test]
    async fn the_document_is_refused_rather_than_rendered_without_a_nonce() {
        let response = get_unwrapped(bundle(), INDEX_PATH).await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    /// The slash-less path is not this router's: it is routed, and redirected,
    /// by `asterius_server::http::console`, which is where the 303 helper
    /// lives. Asserted here so that mounting a second copy of it — which would
    /// make axum panic on the overlap at start-up — shows up as a failing test
    /// instead.
    #[tokio::test]
    async fn the_slashless_path_is_not_mounted_here() {
        let response = get(bundle(), BASE_PATH).await;

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    /// Every route the console mounts is safe, which is the whole of its
    /// exposure: ADR-0009's structural refusal of `GET` for state changes is
    /// about `/admin/api`, and this half of `/admin` must have no state to
    /// change at all.
    #[tokio::test]
    async fn no_console_route_answers_a_state_changing_verb() {
        for (path, verb) in [
            (INDEX_PATH, "POST"),
            (INDEX_PATH, "DELETE"),
            ("/admin/assets/main-abc123.js", "POST"),
            ("/admin/assets/main-abc123.js", "PUT"),
        ] {
            let request = Request::builder()
                .method(verb)
                .uri(path)
                .body(Body::empty())
                .expect("a request");
            let response = routes(bundle())
                .oneshot(request)
                .await
                .expect("the router answered");
            assert_eq!(
                response.status(),
                StatusCode::METHOD_NOT_ALLOWED,
                "{verb} {path}"
            );
        }
    }

    /// Absolute URLs that appear in a built bundle and are never fetched.
    ///
    /// Named one by one with the reason, rather than matched by a pattern: the
    /// point of the scan below is that adding a *new* off-origin URL has to be
    /// a deliberate line in this list that a reviewer sees, not a needle that
    /// happens to slip past a regular expression.
    const INERT_URLS: &[(&str, &str)] = &[
        (
            "http://www.w3.org/",
            "XML namespace identifiers, passed to createElementNS and compared \
             as strings; a namespace URI is never dereferenced",
        ),
        (
            "https://react.dev/errors/",
            "React's production error messages point at its own documentation. \
             The URL is thrown as text for a developer to read",
        ),
    ];

    /// The bundle that is actually compiled in, when there is one.
    ///
    /// Vacuous on a checkout where nobody has run `npm run build`: a Rust
    /// developer is not required to have a JavaScript toolchain, and
    /// `build.rs` emits an empty table for them on purpose.
    ///
    /// It is *not* allowed to be vacuous where it matters (`ast-rna`). An
    /// empty table made this test pass while checking nothing, for as long as
    /// nobody noticed that the CI jobs running it never built the console. So
    /// under `CI` — set by every GitHub Actions runner — an empty bundle is a
    /// failure naming the step that should have produced it, and the workflow
    /// runs `scripts/build-console.sh` before the tests so that it does.
    #[test]
    fn the_embedded_bundle_names_no_third_party_origin_it_could_fetch() {
        let embedded = Bundle::embedded();
        assert!(
            !(std::env::var_os("CI").is_some() && embedded.assets.is_empty()),
            "no console asset is embedded, so this check has nothing to read: \
             run ./scripts/build-console.sh before cargo"
        );
        for asset in embedded.assets {
            let Ok(text) = std::str::from_utf8(asset.bytes) else {
                continue;
            };
            // `@import` would pull a stylesheet from wherever it names, and a
            // protocol-relative `//host/` is an off-origin URL written the way
            // that hides it from a search for `https:`.
            for banned in ["@import url(", "\"//", "'//"] {
                assert!(
                    !text.contains(banned),
                    "{} contains {banned}, which reaches off this origin",
                    asset.path
                );
            }

            let mut rest = text;
            while let Some(at) = rest.find("http") {
                let found = &rest[at..];
                if found.starts_with("http://") || found.starts_with("https://") {
                    assert!(
                        INERT_URLS.iter().any(|(url, _)| found.starts_with(url)),
                        "{} names {}, which is not on the list of URLs that are \
                         never fetched; `connect-src 'self'` would refuse it",
                        asset.path,
                        found.split(['"', '\'', ' ', ')']).next().unwrap_or(found)
                    );
                }
                rest = &found[4..];
            }
        }
    }

    /// What `style-src 'nonce-…'` refuses, asserted against the built bytes
    /// (`ast-gore`).
    ///
    /// The console now carries Tailwind and a copy of shadcn/ui, and both
    /// arrive through a bundler that could plausibly emit either of the two
    /// things this policy will not load:
    ///
    ///  - an **`@import`** that survived into the stylesheet. `tailwind.css`
    ///    opens with two of them; the Tailwind plugin is supposed to resolve
    ///    them at build time into one flat file. If one ever survived, the
    ///    browser would fetch a stylesheet named by a stylesheet — a request
    ///    that carries no nonce — and the console would lose a layer of its
    ///    paint for a reason nobody would look for in a bundler.
    ///  - a **`style=` attribute** in the markup a chunk writes. React sets
    ///    inline styles through the CSSOM (`node.style`), which this directive
    ///    does not govern, but a component that assembled HTML text with a
    ///    `style=` in it would be silently unstyled.
    ///
    /// Both are absences, and an absence is what a source audit is for: only a
    /// browser can prove the policy holds at runtime (`e2e/tests/console.spec.ts`
    /// watches for violations), and only this can prove the bytes shipped
    /// inside the binary never had the chance.
    #[test]
    fn the_embedded_bundle_carries_nothing_the_style_policy_would_refuse() {
        let embedded = Bundle::embedded();
        assert!(
            !(std::env::var_os("CI").is_some() && embedded.assets.is_empty()),
            "no console asset is embedded, so this check has nothing to read: \
             run ./scripts/build-console.sh before cargo"
        );
        for asset in embedded.assets {
            let Ok(text) = std::str::from_utf8(asset.bytes) else {
                continue;
            };
            // The bundler writes the extension, and it writes it lower
            // case; `Path::extension` is what clippy asks for and is also
            // what says "the last dot" rather than "the last four bytes".
            if std::path::Path::new(asset.path)
                .extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("css"))
            {
                assert!(
                    !text.contains("@import"),
                    "{} kept an @import, which the browser would fetch without \
                     a nonce",
                    asset.path
                );
                assert!(
                    !text.contains("url("),
                    "{} fetches something; the console's stylesheet is one \
                     file and no requests",
                    asset.path
                );
            } else {
                assert!(
                    !text.contains("style=\""),
                    "{} writes a style attribute into markup, which \
                     `style-src 'nonce-…'` refuses",
                    asset.path
                );
            }
        }
    }

    /// A template with its `{# … #}` comments removed, as
    /// `crates/web/src/source_audit.rs` does: a comment explaining why a
    /// keyword is forbidden must not be the thing that trips the check.
    fn without_comments(source: &str) -> String {
        let mut out = String::with_capacity(source.len());
        let mut rest = source;
        while let Some(start) = rest.find("{#") {
            out.push_str(&rest[..start]);
            match rest[start..].find("#}") {
                Some(end) => rest = &rest[start + end + 2..],
                None => return out,
            }
        }
        out.push_str(rest);
        out
    }

    /// The template is the one place a `<script>` can enter this crate, so the
    /// claims made for it are checked here rather than read.
    #[test]
    fn the_console_template_contains_one_nonced_external_script_and_nothing_inline() {
        let source = without_comments(include_str!("../templates/console.html"));
        let lowered = source.to_lowercase();

        assert_eq!(lowered.matches("<script").count(), 1);
        // `ast-gore`: the bundle reads this response's nonce back off that one
        // script element (`element.nonce`, which a browser keeps readable
        // while blanking the attribute) and hands it to the one dependency
        // that injects a stylesheet. Without the id there is nothing to find,
        // and a modal would open with its scroll lock unstyled.
        assert!(
            lowered.contains("id=\"console-entry\""),
            "the entry script lost the id the bundle reads its nonce from"
        );
        assert!(!lowered.contains("javascript:"));
        assert!(!lowered.contains("<style"));
        for handler in [" onclick=", " onload=", " onerror=", " onsubmit="] {
            assert!(!lowered.contains(handler), "an inline {handler} handler");
        }
        assert_eq!(
            source.matches("|safe").count(),
            source.matches("{{ nonce_attribute|safe }}").count(),
            "the nonce attribute is the only value this template may mark safe"
        );
    }
}
