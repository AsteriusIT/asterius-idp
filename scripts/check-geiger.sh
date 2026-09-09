#!/usr/bin/env bash
# `cargo geiger` over the workspace, failing if a first-party crate contains a
# single `unsafe` expression.
#
# This is the third layer over the same rule, and each one catches what the
# others cannot:
#
#   * `#![forbid(unsafe_code)]` on every crate root — the compiler's answer,
#     and the only one that is airtight for the code it covers.
#   * `check-no-unsafe.sh` — a grep, which also catches a root that lost the
#     attribute, and runs in seconds on every pull request.
#   * this — counts `unsafe` *expressions* the way the definition of done
#     words it, from the actual expanded crate graph rather than from text,
#     and reports the same figure for every dependency, which is the number
#     nobody can get from the first two.
#
# Not on pull requests, deliberately. Geiger builds the whole dependency graph
# with its own metadata pass; it is minutes, not seconds, and `ast-83p.15` was
# opened because the fuzz job had already made this pipeline's critical path
# 91% one job. What it measures — the unsafe surface of the dependency tree —
# changes only when `Cargo.lock` does, so it runs in `audit.yml`, which is
# scheduled and also triggers on exactly those files. The per-PR guarantee is
# unchanged: `forbid(unsafe_code)` and `check-no-unsafe.sh` still run on every
# commit.
set -euo pipefail
cd "$(dirname "$0")/.."

# The crates we write. Read from cargo rather than listed, so a new member is
# covered the day it is added.
mapfile -t first_party < <(
  cargo metadata --no-deps --format-version 1 \
    | jq -r '.packages[].name' | sort
)

if [[ "${#first_party[@]}" -eq 0 ]]; then
  echo "no workspace members found — is this the right directory?" >&2
  exit 1
fi

echo "first-party crates: ${first_party[*]}"

# `SQLX_OFFLINE` for the same reason clippy sets it: this must not need a
# database. `--all-features` because a feature gate is a perfectly good place
# to hide an `unsafe` block.
full="$(SQLX_OFFLINE=true cargo geiger --all-features --output-format Ascii)"

status=0
for crate in "${first_party[@]}"; do
  # Geiger's rows end in `<name> <version>`, prefixed by five `used/total`
  # columns: functions, expressions, impls, traits, methods. Both sides of
  # every one of them must be zero. `used` alone would be the weaker question —
  # it counts only what this build reaches, so an `unsafe` block behind a
  # feature nothing enables would report 0/3 and pass. In a crate we wrote,
  # unsafe that is present but unreached is still unsafe that is present.
  row="$(grep -E "[[:space:]]${crate}[[:space:]]+[0-9]" <<<"$full" | head -n1 || true)"
  if [[ -z "$row" ]]; then
    echo "NO GEIGER ROW for $crate — the report format has changed" >&2
    echo "$full" >&2
    exit 1
  fi

  # awk rather than `bc`, which is not installed everywhere and would make a
  # security gate depend on a package nobody remembers is a dependency.
  count="$(grep -oE '[0-9]+/[0-9]+' <<<"$row" | tr '/' '\n' | awk '{ n += $1 } END { print n + 0 }')"
  if [[ "$count" -ne 0 ]]; then
    echo "UNSAFE IN FIRST-PARTY CRATE: $crate" >&2
    echo "  $row" >&2
    status=1
  fi
done

if [[ "$status" -ne 0 ]]; then
  echo "  every crate root carries #![forbid(unsafe_code)]; if one of these is" >&2
  echo "  genuinely needed it is an ADR, not a patch" >&2
  exit 1
fi

echo "cargo geiger: 0 unsafe expressions in ${#first_party[@]} first-party crates"
