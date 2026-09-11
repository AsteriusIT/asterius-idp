//! Rebuild when a migration is added.
//!
//! `sqlx::migrate!("./migrations")` embeds the directory at compile time and,
//! on stable Rust, cannot tell cargo to watch it. Without this line a new
//! migration file leaves the crate — and every test binary linking it —
//! carrying the old set until something else changes: `Store::migrate`
//! then fails with `VersionMissing` against a database the CLI has already
//! moved forward (seen on `ast-p2l.8`, adding 0032). This is the sqlx
//! documentation's own remedy.

fn main() {
    println!("cargo:rerun-if-changed=migrations");
}
