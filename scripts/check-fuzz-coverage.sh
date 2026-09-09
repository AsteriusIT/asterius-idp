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

# The registry must match the directory exactly.
#
# `scripts/sync-fuzz-registry.sh` derives it, so this only catches a hand edit
# that got it wrong — which has happened three times in one day, every time
# while resolving a merge conflict whose markers landed inside a `[[bin]]`
# block.
on_disk="$(ls fuzz/fuzz_targets/*.rs 2>/dev/null | xargs -n1 basename | sed 's/\.rs$//' | sort)"
registered="$(awk '/^\[\[bin\]\]/ { in_bin = 1; next }
                   in_bin && /^name = / { gsub(/^name = "|"$/, ""); print; in_bin = 0 }' \
              fuzz/Cargo.toml | sort)"
if [[ "$on_disk" != "$registered" ]]; then
  echo "FUZZ REGISTRY OUT OF STEP with fuzz/fuzz_targets/:" >&2
  diff <(echo "$on_disk") <(echo "$registered") >&2 || true
  echo "  run: ./scripts/sync-fuzz-registry.sh" >&2
  status=1
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
# and `cargo check` answers it under the toolchain CI already has. The previous
# version asked for nightly and merely warned when it was absent, so on the
# `lint` job — which installs stable — this gate reported a skip and passed,
# which is how it managed to exist while `jws_parse.rs` was broken.
if [[ "$status" -eq 0 ]]; then
  echo "checking that every fuzz target compiles..."
  # `CARGO_BUILD_TARGET` is unset for this build. If the environment points at
  # a target whose standard library is not installed — a musl triple on a gnu
  # host, say — this fails with "can't find crate for `core`", which says
  # nothing about the code under test. The host default is what we want: the
  # question here is whether the targets compile, not for what.
  #
  # `SQLX_OFFLINE` for the same reason clippy sets it: the targets reach
  # `asterius-server`, whose queries are checked at compile time, and this gate
  # must not need a database. `sqlx-check` proves the committed data is current.
  if env -u CARGO_BUILD_TARGET SQLX_OFFLINE=true \
       cargo check --manifest-path fuzz/Cargo.toml --bins --quiet; then
    echo "fuzz targets build"
  else
    echo "FUZZ TARGET DOES NOT COMPILE: see the errors above" >&2
    echo "  a target that does not build covers nothing" >&2
    status=1
  fi
fi

if [[ "$status" -eq 0 ]]; then
  echo "fuzz coverage ok: $(wc -l <<<"$declared") parsers, each with a target"
fi
exit "$status"
