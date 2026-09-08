//! Router assembly and the listener.

use crate::config::{ServerConfig, TransportMode};
use crate::http::{request_id, security_headers, tls};
use crate::tenancy::TenantState;
use axum::Router;
use axum::extract::{DefaultBodyLimit, connect_info::ConnectInfo};
use axum::http::{StatusCode, header};
use axum::response::IntoResponse;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpListener;
use tower::ServiceExt as _;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::timeout::TimeoutLayer;

/// Largest header block accepted before hyper answers 431.
///
/// A DPoP proof, a `private_key_jwt` assertion and a long cookie can all share
/// one request, so this is not tight — but it is bounded, because an unbounded
/// header block is a memory-exhaustion primitive that costs the attacker
/// nothing.
const MAX_HEADER_BYTES: usize = 16 * 1024;

/// Wraps `routes` in the middleware every response must pass through.
///
/// Order matters, and reads outermost first:
///
/// 1. **security headers** — outermost, so they are present on error responses
///    produced by the layers below, including the 408 from the timeout and the
///    413 from the body limit. A security header that is only on the happy path
///    is not a security header.
/// 2. **request id** — next, so the id appears on those same error responses
///    and an operator can correlate a rejection with a log line.
/// 3. **document security** — the per-response CSP nonce and the header set
///    that only applies to HTML. It is inside the two above because it does
///    nothing to a JSON or an empty response, and it is applied to everything
///    rather than to a list of page routes because that list is the thing that
///    goes stale: a document served from anywhere is a document.
/// 4. **timeout** — before any work is done.
/// 5. **body limit** — 413 rather than reading an unbounded body.
///
/// There is deliberately **no CORS layer**, here or anywhere. FAPI 2.0 SP
/// §5.2.3 requires the authorization endpoint to be unreachable from a
/// cross-origin script, and the other endpoints are called server-to-server.
/// Absence is the implementation; `no_cors_layer_is_used_anywhere` asserts it
/// stays absent.
pub fn with_middleware(routes: Router, config: &ServerConfig) -> Router {
    routes
        .layer(DefaultBodyLimit::disable())
        .layer(RequestBodyLimitLayer::new(config.request_body_limit))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            config.request_timeout,
        ))
        .layer(axum::middleware::from_fn(asterius_web::document::layer))
        .layer(axum::middleware::from_fn(request_id::layer))
        .layer(axum::middleware::from_fn(security_headers::layer))
}

/// Assembles the whole application: tenant resolution, then the shared
/// middleware.
///
/// Tenant resolution sits *inside* the shared middleware, so a request that
/// names no tenant is still refused by a response carrying the security headers
/// and a request id. It sits *outside* routing, so a handler is only ever
/// reached once a tenant has been resolved and the path rewritten — a handler
/// has no tenant parameter to forget, because it never sees one.
///
/// The tenant middleware is applied to an outer router that has no routes of
/// its own, with `routes` as its fallback *service*. That indirection is
/// load-bearing: `Router::layer` runs middleware **after** the router has
/// already matched a path, so a layer applied directly to `routes` would
/// rewrite a URI nothing looks at again. Wrapping instead means the rewrite
/// happens first and the inner router matches `/authorize` rather than
/// `/t/demo/authorize`.
pub fn app(
    routes: Router,
    tenant_state: TenantState,
    operations: Option<OperationalRoutes>,
    config: &ServerConfig,
) -> Router {
    let tenanted =
        Router::new()
            .fallback_service(routes)
            .layer(axum::middleware::from_fn_with_state(
                tenant_state,
                crate::tenancy::layer,
            ));

    // Health and metrics sit *outside* tenant resolution: they describe the
    // process, not a tenant, and a readiness probe that 404s because the
    // database is down — which is exactly when the tenant directory cannot
    // load — would report the opposite of the truth. They stay *inside* the
    // shared middleware, so a probe response is hardened like any other.
    let Some(operations) = operations else {
        return with_middleware(tenanted, config);
    };

    let metrics = operations.metrics;
    let with_operations = Router::new()
        .route(
            "/healthz",
            axum::routing::get(crate::observability::health::healthz),
        )
        .route(
            "/readyz",
            axum::routing::get(crate::observability::health::readyz).with_state(operations.health),
        )
        .route(
            "/metrics",
            axum::routing::get(move || {
                let metrics = metrics.clone();
                async move { crate::observability::metrics::handler(metrics).await }
            }),
        )
        .fallback_service(tenanted);

    with_middleware(with_operations, config)
}

/// The process-level endpoints, which are not tenant-scoped.
#[derive(Clone, Debug)]
pub struct OperationalRoutes {
    /// State for `/readyz`.
    pub health: crate::observability::health::HealthState,
    /// The metrics registry behind `/metrics`.
    pub metrics: crate::observability::Metrics,
}

/// The response to a request for a path this server does not serve.
///
/// Plain text and deliberately dull: a 404 that describes the routing table is
/// a reconnaissance aid.
#[expect(clippy::unused_async, reason = "axum handlers must be async")]
pub async fn not_found() -> impl IntoResponse {
    (
        StatusCode::NOT_FOUND,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        "not found\n",
    )
}

/// Binds the configured address.
///
/// Separate from [`serve_on`] so that a caller — a test, or a future
/// socket-activation path — can learn the bound address before serving, which
/// matters when the configuration asks for port 0.
///
/// # Errors
///
/// Returns the I/O error if the address cannot be bound.
pub async fn bind(config: &ServerConfig) -> std::io::Result<TcpListener> {
    TcpListener::bind(config.bind).await
}

/// Binds and runs the server until `shutdown` resolves.
///
/// # Errors
///
/// Returns an error if the listener cannot bind, or if TLS material is
/// configured but unusable.
pub async fn serve(
    config: &ServerConfig,
    app: Router,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    let listener = bind(config).await?;
    serve_on(listener, config, app, shutdown).await
}

/// Runs the server on an already-bound listener until `shutdown` resolves.
///
/// # Errors
///
/// Returns an error if TLS material is configured but unusable.
pub async fn serve_on(
    listener: TcpListener,
    config: &ServerConfig,
    app: Router,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    let local = listener.local_addr()?;

    match config.mode {
        TransportMode::BehindProxy => {
            tracing::info!(%local, "listening (TLS terminated upstream)");
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .with_graceful_shutdown(shutdown)
            .await?;
        }
        TransportMode::TerminateTls => {
            let tls = config
                .tls
                .as_ref()
                .expect("validated: terminate_tls implies [server.tls]");
            let acceptor = tokio_rustls::TlsAcceptor::from(tls::server_config(
                &tls.certificate,
                &tls.private_key,
            )?);
            tracing::info!(%local, "listening (TLS 1.2/1.3, BCP 195 suites)");
            serve_tls(listener, acceptor, app, shutdown).await?;
        }
    }
    Ok(())
}

async fn serve_tls(
    listener: TcpListener,
    acceptor: tokio_rustls::TlsAcceptor,
    app: Router,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    let graceful = hyper_util::server::graceful::GracefulShutdown::new();
    let mut shutdown = std::pin::pin!(shutdown);

    loop {
        let (stream, peer) = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok(pair) => pair,
                // One bad accept is not a reason to stop serving everyone else.
                Err(error) => {
                    tracing::warn!(%error, "accept failed");
                    continue;
                }
            },
            () = &mut shutdown => break,
        };

        let acceptor = acceptor.clone();
        let app = app.clone();
        let watcher = graceful.watcher();

        tokio::spawn(async move {
            let stream = match acceptor.accept(stream).await {
                Ok(stream) => stream,
                // A failed handshake is routine: scanners, health probes and
                // clients that only speak TLS 1.1 all land here.
                Err(error) => {
                    tracing::debug!(%peer, %error, "TLS handshake failed");
                    return;
                }
            };

            let service = hyper_util::service::TowerToHyperService::new(
                app.into_service::<hyper::body::Incoming>().map_request(
                    move |mut request: axum::extract::Request<_>| {
                        request.extensions_mut().insert(ConnectInfo(peer));
                        request
                    },
                ),
            );

            let mut builder = auto::Builder::new(TokioExecutor::new());
            builder.http1().max_buf_size(MAX_HEADER_BYTES);
            let connection = builder.serve_connection_with_upgrades(TokioIo::new(stream), service);
            if let Err(error) = watcher.watch(connection).await {
                tracing::debug!(%peer, %error, "connection closed with an error");
            }
        });
    }

    // Give in-flight requests a bounded chance to finish before the process
    // goes away; an authorization code being redeemed should not be lost to a
    // rolling restart.
    tokio::select! {
        () = graceful.shutdown() => {}
        () = tokio::time::sleep(Duration::from_secs(10)) => {
            tracing::warn!("graceful shutdown timed out; dropping remaining connections");
        }
    }
    Ok(())
}

/// Resolves when the process is asked to stop.
pub async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(error) => tracing::warn!(%error, "cannot listen for SIGTERM"),
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => tracing::info!("received SIGINT, shutting down"),
        () = terminate => tracing::info!("received SIGTERM, shutting down"),
    }
}
