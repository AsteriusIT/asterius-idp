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

if [[ "$status" -eq 0 ]]; then
  echo "fuzz coverage ok: $(wc -l <<<"$declared") parsers, each with a target"
fi
exit "$status"
