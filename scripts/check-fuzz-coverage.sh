#!/usr/bin/env bash
# The project's definition of done says every parser and validator has a fuzz
# target. This makes that mechanical instead of remembered.
#
# An entry point opts in with a marker comment on the line above it:
#
#     // fuzz-target: issuer_parse
#     pub fn parse(raw: &str) -> Result<Self, IssuerError> { … }
#
# and this script fails if `fuzz/fuzz_targets/issuer_parse.rs` is missing, or if
# a target exists that nothing claims. Both directions matter: the first catches
# a parser added without a target, the second catches a target left behind after
# the code it covered was deleted, which would otherwise sit in CI proving
# nothing.
set -euo pipefail
cd "$(dirname "$0")/.."

status=0

declared=$(grep -rhoP '(?<=// fuzz-target: )[a-z0-9_]+' crates/ | sort -u)
present=$(find fuzz/fuzz_targets -name '*.rs' -printf '%f\n' 2>/dev/null | sed 's/\.rs$//' | sort -u)

if [[ -z "$declared" ]]; then
  echo "no // fuzz-target: markers found — is the convention still in use?" >&2
  exit 1
fi

while read -r target; do
  [[ -z "$target" ]] && continue
  if ! grep -qx -- "$target" <<<"$present"; then
    echo "MISSING FUZZ TARGET: $target" >&2
    echo "  a parser declares '// fuzz-target: $target' but fuzz/fuzz_targets/$target.rs does not exist" >&2
    status=1
  fi
done <<<"$declared"

while read -r target; do
  [[ -z "$target" ]] && continue
  if ! grep -qx -- "$target" <<<"$declared"; then
    echo "ORPHAN FUZZ TARGET: fuzz/fuzz_targets/$target.rs covers nothing" >&2
    echo "  either add '// fuzz-target: $target' above the entry point, or delete the target" >&2
    status=1
  fi
done <<<"$present"

# The registry must match the directory exactly, in both directions.
#
# A file with no `[[bin]]` passes the marker check above — the file exists —
# and escapes the compile check below, which only builds what the manifest
# declares: it is never built and never fuzzed while looking covered. Four
# WebAuthn parsers, the ones reading bytes an authenticator handed us, sat in
# that state on `main`. A `[[bin]]` with no file is the mirror image and breaks
# the crate's build.
#
# `scripts/sync-fuzz-registry.sh --check` renders the manifest it would write
# and reports every difference. The gate asks the generator rather than parsing
# the manifest a second time here, so the two cannot drift apart in their idea
# of what is registered — and it fails closed when the enumeration is empty or
# the manifest unreadable. It is also why the loop above no longer greps
# `fuzz/Cargo.toml` for a `[[bin]]` per marker: two checks doing the same work
# are two places one can drift from the other, which is the defect this
# delegation was introduced to close.
if ! ./scripts/sync-fuzz-registry.sh --check; then
  status=1
fi

# The committed inventory must be the one the tree implies.
#
# The definition of done asks for the list of parsers and their targets to be
# committed, in `docs/fuzzing.md`. A list of 35 rows kept by hand is wrong from
# the first parser added — and a stale inventory of what is fuzzed is worse
# than none, because it answers "is this covered?" with a confident yes that
# stopped being true. So the file is rendered by a script and this compares the
# two, the way `config_reference.rs` does for `docs/configuration.md`.
if [[ "$status" -eq 0 ]]; then
  if ! diff -u docs/fuzzing.md <(./scripts/gen-fuzzing-doc.sh) >/dev/null; then
    echo "docs/fuzzing.md IS STALE:" >&2
    diff -u docs/fuzzing.md <(./scripts/gen-fuzzing-doc.sh) >&2 || true
    echo "  run: ./scripts/gen-fuzzing-doc.sh > docs/fuzzing.md" >&2
    status=1
  fi
fi

# The same formatting rules as the workspace.
#
# `fuzz` is its own workspace, so `cargo fmt --all` at the root walks straight
# past it; by the time this gate was written 24 targets had drifted. Neither
# the root nor `fuzz/` has a `rustfmt.toml`, so both sides are plain rustfmt
# defaults and stay in step on their own — do not add one to `fuzz/` without
# adding the same file at the root.
if [[ "$status" -eq 0 ]]; then
  echo "checking that every fuzz target is formatted..."
  if cargo fmt --manifest-path fuzz/Cargo.toml --check; then
    echo "fuzz targets formatted"
  else
    echo "FUZZ TARGET NOT FORMATTED: see the diff above" >&2
    echo "  run: cargo fmt --manifest-path fuzz/Cargo.toml" >&2
    status=1
  fi
fi

# A target that does not compile covers nothing, however present its file is.
#
# This check exists because the gate above did not catch a real regression: a
# signature change in `asterius-jose` left `jws_parse.rs` uncompilable for
# several commits. The `fuzz` crate is excluded from the workspace, so an
# ordinary `cargo check` never touches it, and the nightly fuzzing job is the
# only thing that builds it — once a day, long after the change.
#
# Stable, deliberately. `cargo fuzz` needs nightly to *instrument* a target,
# but nothing here is instrumented: the question is whether the code compiles,
# stable answers it — as it does the lints — under the toolchain CI already has. The previous
# version asked for nightly and merely warned when it was absent, so on the
# `lint` job — which installs stable — this gate reported a skip and passed,
# which is how it managed to exist while `jws_parse.rs` was broken.
if [[ "$status" -eq 0 ]]; then
  echo "checking that every fuzz target compiles and is lint-clean..."
  # `CARGO_BUILD_TARGET` is unset for this build. If the environment points at
  # a target whose standard library is not installed — a musl triple on a gnu
  # host, say — this fails with "can't find crate for `core`", which says
  # nothing about the code under test. The host default is what we want: the
  # question here is whether the targets compile, not for what.
  #
  # `SQLX_OFFLINE` for the same reason clippy sets it: the targets reach
  # `asterius-server`, whose queries are checked at compile time, and this gate
  # must not need a database. `sqlx-check` proves the committed data is current.
  #
  # Clippy rather than `cargo check`: it answers the compile question too, for
  # the same build, and it is the only lint pass the fuzz crate gets — the
  # workspace-wide `cargo clippy --workspace` cannot see outside its own
  # workspace either. `-D warnings`, as everywhere else in this repository.
  if env -u CARGO_BUILD_TARGET SQLX_OFFLINE=true \
       cargo clippy --manifest-path fuzz/Cargo.toml --bins --quiet -- -D warnings; then
    echo "fuzz targets build and are lint-clean"
  else
    echo "FUZZ TARGET DOES NOT COMPILE OR TRIPS CLIPPY: see the errors above" >&2
    echo "  a target that does not build covers nothing" >&2
    status=1
  fi
fi

if [[ "$status" -eq 0 ]]; then
  echo "fuzz coverage ok: $(wc -l <<<"$declared") parsers, each with a target"
fi
exit "$status"
