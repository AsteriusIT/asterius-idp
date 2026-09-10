#!/usr/bin/env bash
# Enforces the ports-and-adapters rule from ADR-0001.
#
# Protocol crates (domain, oidc) describe behaviour; they must not be able to
# touch a database, an HTTP framework or a network runtime. This script reads
# the resolved dependency graph from `cargo metadata`, so it catches a banned
# crate that arrives transitively as well as one added directly.
set -euo pipefail

# crate name -> space-separated list of banned dependency names
declare -A BANNED=(
  [asterius-domain]="sqlx axum tokio hyper reqwest tower tower-http askama"
  [asterius-oidc]="sqlx axum tokio hyper reqwest tower tower-http askama"
  # WebAuthn is protocol logic too: parsing and comparison, no I/O.
  [asterius-webauthn]="sqlx axum tokio hyper reqwest tower tower-http askama"
  [asterius-jose]="sqlx axum hyper reqwest tower-http askama"
  # SSF issuance is protocol logic that has to reach the signing port, and the
  # port is async: its tests need a runtime, so `tokio` is not on this list.
  # Everything else an adapter would bring in still is.
  [asterius-ssf]="sqlx axum hyper reqwest tower-http askama"
  [asterius-store-pg]="axum askama"
  [asterius-web]="sqlx"
  [asterius-admin-api]="sqlx"
)

metadata="$(cargo metadata --format-version 1 --all-features)"
status=0

for crate in "${!BANNED[@]}"; do
  # Transitive closure of `crate` over the resolve graph.
  reachable="$(jq -r --arg crate "$crate" '
    (.resolve.nodes | map({key: .id, value: (.deps | map(.pkg))}) | from_entries) as $edges
    | (.packages | map({key: .id, value: .name}) | from_entries) as $names
    | ([.packages[] | select(.name == $crate) | .id]) as $roots
    | def walk($frontier; $seen):
        if ($frontier | length) == 0 then $seen
        else
          ($frontier | map($edges[.] // []) | flatten | unique | map(select(. as $d | ($seen | index($d)) | not))) as $next
          | walk($next; ($seen + $next) | unique)
        end;
      walk($roots; $roots) | map($names[.]) | unique | .[]
  ' <<<"$metadata")"

  for banned in ${BANNED[$crate]}; do
    if grep -qx -- "$banned" <<<"$reachable"; then
      echo "LAYERING VIOLATION: $crate reaches banned crate '$banned'" >&2
      echo "  run: cargo tree -p $crate -i $banned" >&2
      status=1
    fi
  done
done

# Acyclicity: cargo refuses cyclic path dependencies outright, but assert that
# the workspace resolved at all and that every member was seen.
members="$(jq -r '.workspace_members | length' <<<"$metadata")"
if [[ "$members" -lt 9 ]]; then
  echo "expected 9 workspace members, found $members" >&2
  status=1
fi

# `#![forbid(unsafe_code)]` in every crate root.
while IFS= read -r root; do
  if ! grep -q '#!\[forbid(unsafe_code)\]' "$root"; then
    echo "MISSING #![forbid(unsafe_code)]: $root" >&2
    status=1
  fi
done < <(find crates -name lib.rs -o -name main.rs | grep -E 'crates/[^/]+/src/(lib|main)\.rs')

if [[ "$status" -eq 0 ]]; then
  echo "layering ok: protocol crates are free of adapter dependencies"
fi
exit "$status"
