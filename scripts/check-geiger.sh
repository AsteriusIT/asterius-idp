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
# commit. It is now one geiger pass per workspace member rather than one for
# the whole tree — see the comment on the loop for why there is no choice —
# which is why `audit.yml` keeps `Swatinem/rust-cache`: the eight passes share
# almost all of their dependency builds.
set -euo pipefail
cd "$(dirname "$0")/.."

# The crates we write, with the manifest each one lives in. Read from cargo
# rather than listed, so a new member is covered the day it is added, and the
# path comes from cargo too rather than being guessed from the crate name.
mapfile -t members < <(
  cargo metadata --no-deps --format-version 1 \
    | jq -r '.packages[] | "\(.name)\t\(.manifest_path)"' | sort
)

if [[ "${#members[@]}" -eq 0 ]]; then
  echo "no workspace members found — is this the right directory?" >&2
  exit 1
fi

names=()
for member in "${members[@]}"; do names+=("${member%%$'\t'*}"); done
echo "first-party crates: ${names[*]}"

# Geiger writes its progress, its cargo build output and its scan warnings to
# stderr, and all three are wanted only when something goes wrong. Kept in a
# file so the failure path can print it verbatim.
errfile="$(mktemp)"
trap 'rm -f "$errfile"' EXIT

# One invocation per crate, and never one at the workspace root.
#
# `ast-yxu`: the root `Cargo.toml` here is a *virtual* manifest — `[workspace]`
# with no `[package]` — and cargo-geiger refuses it outright with "is a virtual
# manifest, but this command requires running against an actual package". That
# is also why this does not use `-p <crate>`: the package flag is parsed after
# the root manifest is resolved, so from a virtual root it fails with the very
# same message. Only `--manifest-path` reaches a real package, and cargo-geiger
# rejects a relative one ("is not an absolute path"), which is what the
# manifest_path out of `cargo metadata` already is.
status=0
for member in "${members[@]}"; do
  crate="${member%%$'\t'*}"
  manifest="${member#*$'\t'}"

  # `SQLX_OFFLINE` for the same reason clippy sets it: this must not need a
  # database. `--all-features` because a feature gate is a perfectly good place
  # to hide an `unsafe` block.
  #
  # The exit status is captured rather than obeyed, and this is the one place
  # worth arguing with. cargo-geiger returns 1 whenever its source scan emitted
  # any warning at all, and on this tree it always does: `icu_*_data` and
  # `serde` ship generated `.rs.data`/`OUT_DIR` files that are `include!`d and
  # so never opened as modules, which is 150 "Dependency file was never
  # scanned" warnings before a line of our code is considered. Failing on that
  # is a gate that can only ever be red. The verdict therefore comes from the
  # report, which is fail-closed on its own: a missing crate row, an
  # unrecognised format or no output at all are all treated as failures below,
  # so a genuine geiger error — which produces no usable report — still fails
  # the job, and the captured stderr is printed when it does.
  #
  # `CARGO_TERM_COLOR=never` is not cosmetic, it is the second half of `ast-yxu`.
  # `Swatinem/rust-cache` exports `CARGO_TERM_COLOR: always` for every step of
  # the job, and cargo-geiger prints its table through cargo's shell, so on the
  # runner every row came out wrapped in SGR escapes:
  #
  #   ESC[32m0/0  0/0  0/0  0/0  0/0  ESC[0m  ESC[32m:)ESC[0m ESC[32masterius-admin-api 0.0.0ESC[0m
  #
  # which no anchored pattern below can match. The gate then failed closed on
  # its own report — correct behaviour, wrong conclusion. Colour is turned off
  # at the source here, and stripped again after the fact below, because a
  # gate that only works when the environment happens to be uncoloured is a
  # gate that will break again on the next action that exports a colour knob.
  geiger_status=0
  report="$(
    SQLX_OFFLINE=true CARGO_TERM_COLOR=never NO_COLOR=1 \
      cargo geiger --all-features --output-format Ascii \
      --manifest-path "$manifest" 2>"$errfile"
  )" || geiger_status=$?

  # Belt and braces: drop any ANSI escape sequence that survived. `$'\033'`
  # rather than `\x1b` so this does not depend on GNU sed.
  report="$(sed $'s/\033\\[[0-9;]*[a-zA-Z]//g' <<<"$report")"

  # Geiger's rows are five `used/total` columns — functions, expressions,
  # impls, traits, methods — then a symbol, then `<name> <version>`. The root
  # crate is the only row with no tree prefix between the symbol and the name,
  # which is what anchors this to the crate under scan rather than to a
  # same-named entry deeper in somebody else's tree. Both sides of every ratio
  # must be zero. `used` alone would be the weaker question — it counts only
  # what this build reaches, so an `unsafe` block behind a feature nothing
  # enables would report 0/3 and pass. In a crate we wrote, unsafe that is
  # present but unreached is still unsafe that is present.
  row="$(
    grep -E "^([0-9]+/[0-9]+[[:space:]]+){5}(:\)|\?|!)[[:space:]]+${crate}[[:space:]]" \
      <<<"$report" | head -n1 || true
  )"
  if [[ -z "$row" ]]; then
    echo "NO GEIGER ROW for $crate — the report format has changed," >&2
    echo "  or cargo geiger failed (exit ${geiger_status})" >&2
    cat "$errfile" >&2
    echo "$report" >&2
    exit 1
  fi

  # awk rather than `bc`, which is not installed everywhere and would make a
  # security gate depend on a package nobody remembers is a dependency. Only
  # the five ratio columns are summed; the version that trails the row is not
  # a count.
  count="$(
    awk '{ for (i = 1; i <= 5; i++) { split($i, r, "/"); n += r[1] + r[2] } }
         END { print n + 0 }' <<<"$row"
  )"
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

echo "cargo geiger: 0 unsafe expressions in ${#members[@]} first-party crates"
