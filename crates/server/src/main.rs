//! The `asterius` binary.
#![forbid(unsafe_code)]

use asterius_domain::Feature;
use asterius_server::http::server::{not_found, serve, shutdown_signal, with_middleware};
use asterius_server::{Config, VERSION};
use axum::Router;
use std::path::PathBuf;
use std::process::ExitCode;

const DEFAULT_CONFIG_PATH: &str = "asterius.toml";
const USAGE: &str = "usage: asterius [--config <path>]";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            // Startup failures go to stderr, not through tracing: the
            // subscriber may not be up yet, and an operator debugging a boot
            // failure should not need a log pipeline to read the reason.
            eprintln!("asterius: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let path = config_path()?;
    let config = Config::load(&path).map_err(|e| e.to_string())?;

    // Minimal for now; `ast-83p.5` replaces this with redaction, metrics and
    // structured fields.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                // The binary's own target is `asterius`; the library is
                // `asterius_server`. Both, or the startup lines never appear.
                .unwrap_or_else(|_| "asterius=info,asterius_server=info,tower_http=warn".into()),
        )
        .init();

    let enabled: Vec<&str> = config.features.enabled().map(Feature::as_str).collect();
    tracing::info!(
        version = VERSION,
        config = %path.display(),
        mode = ?config.server.mode,
        tenants = config.tenants.len(),
        features = %if enabled.is_empty() { "none".to_owned() } else { enabled.join(",") },
        "starting"
    );
    for tenant in &config.tenants {
        tracing::info!(tenant = %tenant.id, issuer = %tenant.issuer, "tenant");
    }

    // No protocol endpoints yet — they arrive with their own stories. What is
    // wired here is the middleware every one of them will sit behind.
    let routes = Router::new().fallback(not_found);
    let app = with_middleware(routes, &config.server);

    let runtime =
        tokio::runtime::Runtime::new().map_err(|e| format!("cannot start runtime: {e}"))?;
    runtime
        .block_on(serve(&config.server, app, shutdown_signal()))
        .map_err(|e| format!("server stopped: {e}"))
}

fn config_path() -> Result<PathBuf, String> {
    let mut args = std::env::args_os().skip(1);
    let mut path: Option<PathBuf> = None;
    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("--config" | "-c") => {
                let value = args.next().ok_or("--config needs a path")?;
                path = Some(PathBuf::from(value));
            }
            Some("--help" | "-h") => {
                println!("{USAGE}");
                std::process::exit(0);
            }
            _ => {
                return Err(format!(
                    "unexpected argument {}\n{USAGE}",
                    PathBuf::from(arg).display()
                ));
            }
        }
    }
    Ok(path
        .or_else(|| std::env::var_os("ASTERIUS_CONFIG").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH)))
}
