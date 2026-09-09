#!/usr/bin/env bash
# Builds the admin console, which `crates/admin-api/build.rs` then embeds.
#
# `ast-f7m.3`: the console ships *inside* the binary (ADR-0009 — one binary and
# one PostgreSQL), so `console/dist` has to exist before `cargo build` runs. It
# is a build artefact and is not committed: this is the one command that
# produces it, and CI, the release image and the browser sweep all call it
# rather than repeating its steps.
#
# A checkout without Node still compiles. `build.rs` emits an empty bundle and
# the console routes answer 503 saying what is missing, so a Rust developer is
# never blocked by a JavaScript toolchain they do not have.
#
#     ./scripts/build-console.sh          install from the lockfile, then build
#     ./scripts/build-console.sh --clean  remove dist/ first
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root/console"

if [ "${1:-}" = "--clean" ]; then
  rm -rf dist
fi

if ! command -v npm >/dev/null 2>&1; then
  printf 'npm is required to build the console; see console/README.md\n' >&2
  exit 1
fi

# `ci` and not `install`: the lockfile is the input, and a build that quietly
# resolved a different tree is a build nobody can reproduce.
npm ci --no-audit --no-fund
npm run build

printf '\nbuilt console/dist:\n'
find dist -type f | sort
