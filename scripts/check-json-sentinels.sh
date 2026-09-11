#!/usr/bin/env bash
# Reports rows whose JSONB carries a member name serde_json reserves.
#
# `crates/domain/src/json_sentinel.rs` stops those names being *written*. It
# says nothing about rows written before it existed, and such a row is a row no
# binary here can read back: with the `raw_value` feature on -- axum and sqlx
# turn it on for the whole workspace -- serde_json refuses any object whose
# first member is one of them, with "invalid type: map, expected raw value".
# Whether it is first depends on member order, so a readable row today becomes
# unreadable after any rewrite that re-sorts it. Hence SQL, and hence a
# detection that looks for the name rather than for the failure.
#
#     ./scripts/check-json-sentinels.sh
#
# Read-only: it opens a read-only transaction with a statement timeout and runs
# `scripts/sql/json-sentinels-detect.sql`. It is safe against a production
# database and against a replica. It scans every JSONB column in the schema, so
# prefer off-peak on a large one.
#
# Exit codes:
#   0  nothing found
#   1  findings, printed as CSV on stdout
#   2  the check could not run (no psql, no database, drifted sentinel list)
#
# Environment:
#   DATABASE_URL  PostgreSQL. Default postgres://asterius:asterius@127.0.0.1:5433/asterius
#   PGSCHEMA      schema to scan. Default public
#   TIMEOUT_MS    statement timeout. Default 300000 (5 minutes)
set -euo pipefail
cd "$(dirname "$0")/.."

DATABASE_URL="${DATABASE_URL:-postgres://asterius:asterius@127.0.0.1:5433/asterius}"
PGSCHEMA="${PGSCHEMA:-public}"
TIMEOUT_MS="${TIMEOUT_MS:-300000}"

DETECT_SQL=scripts/sql/json-sentinels-detect.sql
REPAIR_SQL=scripts/sql/json-sentinels-repair.sql
SENTINEL_RS=crates/domain/src/json_sentinel.rs

if ! command -v psql >/dev/null 2>&1; then
  echo "MISSING psql: install the PostgreSQL client to run this check" >&2
  exit 2
fi

# The SQL files repeat the reserved names because they run where no Rust does.
# A repeated list is a list that drifts, so it is checked rather than trusted:
# `json_sentinel.rs` is the source of truth, and these must quote all of it and
# nothing else.
rust_names="$(sed -n '/SERDE_JSON_SENTINELS/,/];/p' "$SENTINEL_RS" \
  | grep -o '"\$serde_json::private::[A-Za-z]*"' | tr -d '"' | sort -u)"

if [[ -z "$rust_names" ]]; then
  echo "CANNOT CHECK: no sentinel names found in $SENTINEL_RS" >&2
  exit 2
fi

for sql in "$DETECT_SQL" "$REPAIR_SQL"; do
  sql_names="$(grep -o "'\$serde_json::private::[A-Za-z]*'" "$sql" | tr -d "'" | sort -u)"
  if [[ "$sql_names" != "$rust_names" ]]; then
    echo "DRIFT: $sql does not list the same sentinels as $SENTINEL_RS" >&2
    diff <(echo "$rust_names") <(echo "$sql_names") >&2 || true
    exit 2
  fi
done

# `-v ON_ERROR_STOP=1` so a failed statement is an exit code and not a warning
# buried in the output. The transaction is read only, which makes the guarantee
# in the header something PostgreSQL enforces rather than something this script
# claims.
findings="$(psql "$DATABASE_URL" \
  --no-psqlrc --quiet --csv --tuples-only --variable ON_ERROR_STOP=1 \
  --command "set search_path to ${PGSCHEMA}" \
  --command "begin read only" \
  --command "set local statement_timeout = ${TIMEOUT_MS}" \
  --file "$DETECT_SQL" \
  --command "commit" 2>&1)" || {
  echo "$findings" >&2
  echo "CANNOT CHECK: the detection query did not run against $PGSCHEMA" >&2
  exit 2
}

if [[ -z "${findings//[[:space:]]/}" ]]; then
  echo "ok: no serde_json sentinel in any JSONB column of schema ${PGSCHEMA}"
  exit 0
fi

echo "finding,table_name,column_name,repairable,row_key,sentinel_keys"
echo "$findings"
echo >&2
echo "FINDINGS: the rows above carry a member name serde_json reserves" >&2
echo "  'sentinel' rows with repairable=t are fixed by scripts/repair-json-sentinels.sh" >&2
echo "  'sentinel' rows with repairable=f need a decision, not a script:" >&2
echo "  audit_events is append-only and hash-chained, and a subject identifier" >&2
echo "  (ssf_stream_subjects) renamed in place is a membership matching nobody" >&2
echo "  'unreviewed_column' rows mean a migration added a JSONB column that" >&2
echo "  ${DETECT_SQL} does not scan yet" >&2
exit 1
