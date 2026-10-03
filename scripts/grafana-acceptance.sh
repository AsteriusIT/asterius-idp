#!/usr/bin/env bash
# Only own disposable container/DB/process/keyfiles; never touches shared deployment.
set -euo pipefail
umask 077
repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
: "${ASTERIUS_BIN:?Set a prebuilt verified Asterius binary}"
: "${ASTERIUS_ACCEPTANCE_DB_CONTAINER:?Set a controlled PostgreSQL container}"
for dependency in docker python3 node openssl; do
  command -v "$dependency" >/dev/null || { printf 'Missing fixture dependency: %s\n' "$dependency" >&2; exit 1; }
done
python3 "$repo_root/scripts/integrations/grafana_acceptance.py"
