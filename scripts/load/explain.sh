#!/usr/bin/env bash
# EXPLAIN (ANALYZE, BUFFERS) of the hot statements on a seeded, throwaway
# database, and a verdict: every sequential scan on a table that grows.
#
#     docker compose up -d db
#     DATABASE_URL=postgres://asterius:asterius@127.0.0.1:5433/asterius ./scripts/load/explain.sh
#
# The database must be migrated (`sqlx migrate run --source
# crates/store-pg/migrations`, or a server that has started against it). The
# seed adds a tenant `explain` with N rows per growing table (N=50000 by
# default, `ROWS=` to change) and is idempotent; the review's writes are rolled
# back. Full plans go to $OUT (default scripts/load/explain.out, ignored by
# git); the summary goes to stdout and the exit status says whether a growing
# table is scanned sequentially.
#
# What counts as "growing": a table that gains a row per request, per session
# or per person. The reference tables — tenants, clients, resource servers,
# signing keys, roles, streams — are read by primary key and stay small, and a
# sequential scan of ten rows is the right plan, not a missing index.
set -euo pipefail
cd "$(dirname "$0")/../.."

DATABASE_URL="${DATABASE_URL:-postgres://asterius:asterius@127.0.0.1:5433/asterius}"
ROWS="${ROWS:-50000}"
OUT="${OUT:-scripts/load/explain.out}"

growing='users|credentials|subject_identifiers|sessions|session_clients|auth_requests|grants|authorization_codes|refresh_tokens|jti_replay|rate_limits|access_token_denylist|access_token_cutoffs|outbox|outbox_attempts|ssf_poll_queue|audit_events|recovery_tokens'

echo "seeding tenant 'explain' with $ROWS rows per growing table"
psql "$DATABASE_URL" -q -v n="$ROWS" -f scripts/load/explain-seed.sql

echo "explaining into $OUT"
psql "$DATABASE_URL" -q -f scripts/load/explain-queries.sql > "$OUT"

# The statements, as the file labels them, with the plan's top-line cost.
echo
echo "statements: $(grep -c '^explain' scripts/load/explain-queries.sql), plans: $(grep -c 'Execution Time' "$OUT")"
echo

# A sequential scan of a growing table that had to discard rows to find its
# answer. A scan that discards nothing — a count over one stream's whole
# queue, a sweep that deletes most of a table — is the right plan; one that
# reads fifty thousand rows to return one is a missing index.
awk -v growing="Seq Scan on (${growing})( |$)" -v limit="${SEQ_SCAN_TOLERANCE:-1000}" '
  $0 ~ growing { scan = NR ": " $0; sub(/: +/, ": ", scan); next }
  scan && /Rows Removed by Filter: [0-9]+/ {
    removed = $0; sub(/.*Rows Removed by Filter: /, "", removed); removed += 0
    if (removed > limit) { print "  " scan " (discarded " removed " rows)"; found = 1 }
    scan = ""
  }
  scan && /->/ { scan = "" }
  END { if (found) { exit 1 } }
' "$OUT" > /tmp/explain-verdict.$$ || {
  echo "SEQUENTIAL SCANS ON GROWING TABLES:"
  cat /tmp/explain-verdict.$$
  rm -f /tmp/explain-verdict.$$
  exit 1
}
rm -f /tmp/explain-verdict.$$
echo "no sequential scan on a growing table"
