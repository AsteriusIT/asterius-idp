#!/usr/bin/env bash
# Renames serde_json's reserved member names out of the rows that carry them.
#
# Run `./scripts/check-json-sentinels.sh` first and read what it found. This
# script writes; it is a deliberate operator action and nothing runs it
# automatically. There is no migration doing this at start-up on purpose: a
# blind data rewrite is not something a deployment should decide.
#
#     ./scripts/check-json-sentinels.sh          # look
#     ./scripts/repair-json-sentinels.sh --yes   # then act
#
# Every reserved member becomes 'quarantined_' || <its name>, at every depth,
# with its value untouched: the document parses again and the evidence of what
# was there survives. `audit_events` is left alone -- append-only and
# hash-chained -- and re-reported at the end.
#
# The run is one transaction: it all lands or none of it does. The journal is
# the CSV it prints, copied to a log file.
#
# Exit codes:
#   0  repair committed (possibly with nothing to repair)
#   1  refused: no confirmation given
#   2  could not run, or rolled back
#
# Environment:
#   DATABASE_URL  PostgreSQL. Default postgres://asterius:asterius@127.0.0.1:5433/asterius
#   PGSCHEMA      schema to repair. Default public
#   LOG_DIR       where the journal goes. Default the working directory
#   TIMEOUT_MS    statement timeout. Default 300000 (5 minutes)
set -euo pipefail
cd "$(dirname "$0")/.."

DATABASE_URL="${DATABASE_URL:-postgres://asterius:asterius@127.0.0.1:5433/asterius}"
PGSCHEMA="${PGSCHEMA:-public}"
TIMEOUT_MS="${TIMEOUT_MS:-300000}"
LOG_DIR="${LOG_DIR:-.}"

REPAIR_SQL=scripts/sql/json-sentinels-repair.sql

confirmed=0
for argument in "$@"; do
  case "$argument" in
    --yes) confirmed=1 ;;
    *)
      echo "usage: $0 --yes" >&2
      exit 2
      ;;
  esac
done

if [[ "$confirmed" -ne 1 ]]; then
  echo "REFUSING: this rewrites rows in ${PGSCHEMA} of the database in DATABASE_URL." >&2
  echo "  Run ./scripts/check-json-sentinels.sh first, then re-run with --yes." >&2
  exit 1
fi

if ! command -v psql >/dev/null 2>&1; then
  echo "MISSING psql: install the PostgreSQL client to run this repair" >&2
  exit 2
fi

log="${LOG_DIR}/json-sentinel-repair-$(date -u +%Y%m%dT%H%M%SZ).csv"

# `begin`/`commit` around the file so the thirteen updates and the report that
# follows them are one transaction. `ON_ERROR_STOP` makes any failure a
# rollback rather than a half-repaired database.
if ! journal="$(psql "$DATABASE_URL" \
  --no-psqlrc --quiet --csv --variable ON_ERROR_STOP=1 \
  --command "set search_path to ${PGSCHEMA}" \
  --command "begin" \
  --command "set local statement_timeout = ${TIMEOUT_MS}" \
  --file "$REPAIR_SQL" \
  --command "commit" 2>&1)"; then
  echo "$journal" >&2
  echo "ROLLED BACK: nothing was changed in ${PGSCHEMA}" >&2
  exit 2
fi

printf '%s\n' "$journal" | tee "$log"
echo
echo "journal written to $log"
echo "re-run ./scripts/check-json-sentinels.sh to confirm the schema is clean"
