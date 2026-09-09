//! Embeds the built console into the binary.
//!
//! ADR-0009 keeps the product promise of one binary and one PostgreSQL, so the
//! console's assets travel inside the executable rather than beside it. This
//! script turns `console/dist` into a `static` table of `include_bytes!`,
//! which is what `include_dir` or `rust-embed` would do for us — minus a
//! dependency, a proc macro and its supply chain, for about eighty lines.
//!
//! # A missing bundle is not a build failure
//!
//! `console/dist` is a build artefact and is not committed, so a `cargo check`
//! on a machine that has never run `npm run build` finds nothing here. That
//! emits an *empty* bundle rather than failing: a Rust developer should not
//! need Node installed to compile the server, and the console routes answer
//! 503 with a sentence saying what is missing (see `console::index`). CI and
//! the release image build the bundle first, and
//! `scripts/browser-tests.sh` does too.
//!
//! # What is embedded, and what is not
//!
//! Only files under `dist/assets/`, which is where Vite writes content-hashed
//! output. `dist/.vite/manifest.json` is read here and *not* embedded: it
//! describes the build rather than serving it, and publishing it would name
//! every chunk to anyone who asked.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

/// Overrides where the built console is looked for.
const DIST_ENV: &str = "ASTERIUS_CONSOLE_DIST";

fn main() {
    println!("cargo:rerun-if-env-changed={DIST_ENV}");

    let dist = match std::env::var_os(DIST_ENV) {
        Some(path) => PathBuf::from(path),
        None => Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../console/dist")
            .canonicalize()
            .unwrap_or_else(|_| PathBuf::from("../../console/dist")),
    };
    println!("cargo:rerun-if-changed={}", dist.display());

    let out = PathBuf::from(std::env::var_os("OUT_DIR").expect("cargo sets OUT_DIR"))
        .join("console_bundle.rs");

    let manifest = read_manifest(&dist);
    let assets = collect(&dist.join("assets"));
    if !assets.is_empty() {
        println!("cargo:rerun-if-changed={}", dist.join("assets").display());
    }

    std::fs::write(&out, render(&assets, manifest.as_ref()))
        .expect("write the generated console bundle");
}

/// Vite's manifest: the entry chunk and the stylesheets it needs.
struct Manifest {
    script: String,
    styles: Vec<String>,
}

/// Reads `dist/.vite/manifest.json`, without a JSON dependency in the build.
///
/// The document is Vite's own output rather than anything a request supplies,
/// and what is wanted from it is two file names. A hand-rolled scan of the
/// records is enough for that, and it keeps `serde_json` out of the build
/// graph — a build-dependency compiles for the host on every clean build.
fn read_manifest(dist: &Path) -> Option<Manifest> {
    let raw = std::fs::read_to_string(dist.join(".vite/manifest.json")).ok()?;
    // Past the outer object, so that the first record read is the first
    // *entry* rather than the document containing them all.
    let inner = raw.trim().strip_prefix('{')?;
    let records = split_records(inner);

    // The entry chunk: the one record carrying `"isEntry": true`.
    let script = records
        .iter()
        .find(|(_, body)| body.contains("\"isEntry\"") && body.contains("true"))
        .and_then(|(_, body)| field(body, "file"))?;

    // The stylesheets. `cssCodeSplit: false` puts them in their own record
    // rather than in the entry's `css` array, so both spellings are read: the
    // array when it is there, and every `.css` file otherwise.
    let mut styles: Vec<String> = records
        .iter()
        .filter_map(|(_, body)| field(body, "file"))
        .filter(|file| {
            Path::new(file)
                .extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("css"))
        })
        .collect();
    styles.sort();
    styles.dedup();

    Some(Manifest { script, styles })
}

/// The manifest's records, as `(key, body)` pairs, from the inside of the
/// outer object.
fn split_records(raw: &str) -> Vec<(String, String)> {
    let mut records = Vec::new();
    let mut rest = raw;
    while let Some(open) = rest.find('{') {
        // The key of a record is the last quoted string before its `{`.
        let key = rest[..open]
            .rsplit('"')
            .nth(1)
            .unwrap_or_default()
            .to_owned();
        let body_start = open + 1;
        let Some(close) = rest[body_start..].find('}') else {
            break;
        };
        let body = rest[body_start..body_start + close].to_owned();
        if !key.is_empty() {
            records.push((key, body));
        }
        rest = &rest[body_start + close + 1..];
    }
    records
}

/// The string value of `"name": "…"` inside one record.
fn field(body: &str, name: &str) -> Option<String> {
    let needle = format!("\"{name}\"");
    let after = body.find(&needle)? + needle.len();
    let after = body[after..].find(':')? + after + 1;
    let mut quoted = body[after..].splitn(3, '"');
    quoted.next()?;
    quoted.next().map(ToOwned::to_owned)
}

/// Every file under `assets/`, keyed by the path a request names.
fn collect(assets: &Path) -> BTreeMap<String, PathBuf> {
    let mut found = BTreeMap::new();
    let Ok(entries) = std::fs::read_dir(assets) else {
        return found;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        // One level. Vite writes a flat `assets/` directory, and a recursive
        // walk would embed whatever else somebody dropped in there.
        if path.is_file()
            && let Some(name) = path.file_name().and_then(|name| name.to_str())
            && !name.starts_with('.')
        {
            found.insert(format!("assets/{name}"), path);
        }
    }
    found
}

/// The `Content-Type` for one extension.
///
/// A closed list: an extension nobody decided on is not served at all, so a
/// stray file in `assets/` cannot be handed to a browser under a type that
/// makes it executable. `nosniff` is on every response from the transport
/// layer, which is what makes the declared type binding.
fn content_type(path: &Path) -> Option<&'static str> {
    match path.extension().and_then(|e| e.to_str()) {
        Some("js" | "mjs") => Some("text/javascript; charset=utf-8"),
        Some("css") => Some("text/css; charset=utf-8"),
        Some("svg") => Some("image/svg+xml"),
        Some("png") => Some("image/png"),
        Some("webp") => Some("image/webp"),
        Some("woff2") => Some("font/woff2"),
        Some("json") => Some("application/json"),
        _ => None,
    }
}

fn render(assets: &BTreeMap<String, PathBuf>, manifest: Option<&Manifest>) -> String {
    let servable: Vec<_> = assets
        .iter()
        .filter_map(|(path, file)| content_type(file).map(|kind| (path, file, kind)))
        .collect();

    let mut out = String::from("// @generated by crates/admin-api/build.rs\n");
    // Writing into a `String` cannot fail, and a build script that stopped
    // because of a formatting error would be reporting something that did not
    // happen.
    let _ = writeln!(
        out,
        "pub(super) static ASSETS: [Asset; {}] = [",
        servable.len()
    );
    for (path, file, kind) in &servable {
        let source = file.display().to_string();
        let _ = writeln!(
            out,
            "    Asset {{ path: {path:?}, bytes: include_bytes!({source:?}), content_type: {kind:?} }},"
        );
    }
    out.push_str("];\n");

    let script = match manifest.map(|manifest| manifest.script.as_str()) {
        Some(script) => format!("Some({script:?})"),
        None => "None".to_owned(),
    };
    let _ = writeln!(
        out,
        "pub(super) static ENTRY_SCRIPT: Option<&str> = {script};"
    );

    let styles = manifest
        .map(|manifest| manifest.styles.as_slice())
        .unwrap_or_default();
    out.push_str("pub(super) static ENTRY_STYLES: &[&str] = &[");
    for style in styles {
        let _ = write!(out, "{style:?}, ");
    }
    out.push_str("];\n");
    out
}
