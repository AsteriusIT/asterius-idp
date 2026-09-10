#!/usr/bin/env bash
# Everything CI checks, in the order it fails fastest.
#
#   ./scripts/check.sh          fast: no database, database tests skip
#   ./scripts/check.sh --db     also starts PostgreSQL and runs the DB tests
#
# The JSONB sentinel scan needs a database. It runs whenever there is one --
# `--db`, or a `DATABASE_URL` already in the environment -- and prints a loud
# SKIPPED line when there is not.
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
# Same reason, one step further: the worktree cleaner now deletes remote
# branches too (`ast-a33`). Its fixture repository proves it spares a branch
# `origin` has moved past and a worktree that has merged nothing.
run ./scripts/cleanup-worktrees.sh --self-test
# verify.sh builds the nextest filter every worker runs before a merge; if it
# stopped folding in the whole-tree audits, nothing else would notice.
run ./scripts/verify.sh --self-test

if $want_db; then
  run docker compose up -d --wait db
  : "${DATABASE_URL:=postgres://asterius:asterius@127.0.0.1:5433/asterius}"
  export DATABASE_URL
  # A database without its migrations is worse than no database: `DATABASE_URL`
  # takes sqlx out of offline mode, and it then fails to verify every
  # `query!` against an empty schema. Starting the container and migrating it
  # are one step, never two.
  run cargo sqlx migrate run --source crates/store-pg/migrations
  # Before the tests, not after: `ast-9g2` seeds a row carrying a sentinel on
  # purpose in an isolated database test, and a leftover of that kind would be
  # reported as a finding here. Ordering makes the answer about the schema and
  # the rows that were already there.
  run ./scripts/check-json-sentinels.sh
  run cargo test --workspace
  run cargo sqlx prepare --check --workspace -- --all-targets
else
  # A skipped check proves nothing, so it says so rather than staying quiet.
  # With `DATABASE_URL` already exported the scan can still run: the database
  # it points at is migrated by whoever exported it.
  if [[ -n "${DATABASE_URL:-}" ]]; then
    run ./scripts/check-json-sentinels.sh
  else
    printf '\n\033[33m==> SKIPPED ./scripts/check-json-sentinels.sh: no DATABASE_URL\033[0m\n'
    printf '    set DATABASE_URL, or use --db, to scan the JSONB columns\n'
  fi
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
