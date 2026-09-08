//! The `asterius` binary.
#![forbid(unsafe_code)]

use asterius_domain::Feature;
use asterius_server::{Config, VERSION};
use std::path::PathBuf;
use std::process::ExitCode;

const DEFAULT_CONFIG_PATH: &str = "asterius.toml";
const USAGE: &str = "usage: asterius [--config <path>]";

fn main() -> ExitCode {
    let path = match config_path() {
        Ok(path) => path,
        Err(message) => {
            eprintln!("asterius: {message}\n{USAGE}");
            return ExitCode::FAILURE;
        }
    };

    // Configuration problems are reported to stderr rather than through the
    // tracing subscriber: the subscriber is not up yet, and an operator
    // debugging a boot failure should not need a log pipeline to read it.
    let config = match Config::load(&path) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("asterius: {error}");
            return ExitCode::FAILURE;
        }
    };

    let enabled: Vec<&str> = config.features.enabled().map(Feature::as_str).collect();
    println!("asterius {VERSION}");
    println!("  config     {}", path.display());
    println!("  bind       {}", config.server.bind);
    println!("  mode       {:?}", config.server.mode);
    println!("  tenants    {}", config.tenants.len());
    for tenant in &config.tenants {
        println!("    {} -> {}", tenant.id, tenant.issuer);
    }
    println!(
        "  features   {}",
        if enabled.is_empty() {
            "none".to_owned()
        } else {
            enabled.join(", ")
        }
    );
    println!("configuration is valid; the HTTP server is not implemented yet (ast-83p.4)");
    ExitCode::SUCCESS
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
                    "unexpected argument {}",
                    PathBuf::from(arg).display()
                ));
            }
        }
    }
    Ok(path
        .or_else(|| std::env::var_os("ASTERIUS_CONFIG").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH)))
}
