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
  if ! grep -q "name = \"$target\"" fuzz/Cargo.toml; then
    echo "UNREGISTERED FUZZ TARGET: $target is not a [[bin]] in fuzz/Cargo.toml" >&2
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

# A target that does not compile covers nothing, however present its file is.
#
# This check exists because the gate above did not catch a real regression: a
# signature change in `asterius-jose` left `jws_parse.rs` uncompilable for
# several commits. The `fuzz` crate is excluded from the workspace, so an
# ordinary `cargo check` never touches it, and the nightly fuzzing job is the
# only thing that builds it — once a day, long after the change.
#
# `cargo-fuzz` needs nightly. When it is absent this reports a skip rather than
# passing quietly: a gate that cannot say whether it ran is worse than one that
# says it did not.
if [[ "$status" -eq 0 ]]; then
  if rustup toolchain list 2>/dev/null | grep -q '^nightly'; then
    echo "building every fuzz target (nightly)..."
    # `CARGO_BUILD_TARGET` is unset for this build. If the environment points
    # at a target whose standard library is not installed — a musl triple on a
    # gnu host, say — this fails with "can't find crate for `core`", which says
    # nothing about the code under test. The host default is what we want: the
    # question here is whether the targets compile, not for what.
    if (cd fuzz && env -u CARGO_BUILD_TARGET cargo +nightly check --bins --quiet); then
      echo "fuzz targets build"
    else
      echo "FUZZ TARGET DOES NOT COMPILE: see the errors above" >&2
      echo "  a target that does not build covers nothing" >&2
      status=1
    fi
  else
    echo "fuzz targets NOT built: no nightly toolchain (install with 'rustup toolchain install nightly')" >&2
  fi
fi

if [[ "$status" -eq 0 ]]; then
  echo "fuzz coverage ok: $(wc -l <<<"$declared") parsers, each with a target"
fi
exit "$status"
