#!/usr/bin/env bash
# Everything CI checks, in the order it fails fastest.
#
#   ./scripts/check.sh          fast: no database, database tests skip
#   ./scripts/check.sh --db     also starts PostgreSQL and runs the DB tests
set -euo pipefail
cd "$(dirname "$0")/.."

want_db=false
[[ "${1:-}" == "--db" ]] && want_db=true

run() { printf '\n\033[1m==> %s\033[0m\n' "$*"; "$@"; }

run cargo fmt --all --check
SQLX_OFFLINE=true run cargo clippy --workspace --all-targets --all-features -- -D warnings
run ./scripts/check-layering.sh
run ./scripts/check-fuzz-coverage.sh
run ./scripts/check-no-unsafe.sh
# The disk garbage collector deletes files; its fixture test proves it spares
# fresh artifacts and sources, and that a dry run deletes nothing.
run ./scripts/gc-build-artifacts.sh --self-test

if $want_db; then
  run docker compose up -d --wait db
  : "${DATABASE_URL:=postgres://asterius:asterius@127.0.0.1:5433/asterius}"
  export DATABASE_URL
  run cargo test --workspace
  run cargo sqlx prepare --check --workspace -- --all-targets
else
  SQLX_OFFLINE=true run env -u DATABASE_URL cargo test --workspace
fi

# CI documents the workspace with warnings denied. Without this line the local
# mirror is not a mirror, and a broken intra-doc link only shows up on a runner.
RUSTDOCFLAGS="-D warnings" SQLX_OFFLINE=true run cargo doc --workspace --no-deps --all-features

run cargo deny check

# Not `./scripts/check-geiger.sh`: it needs cargo-geiger, which takes minutes to
# install and minutes to run, and its answer only changes when Cargo.lock does.
# It runs in audit.yml, on a schedule and on any manifest change.

printf '\n\033[32mall checks passed\033[0m\n'
