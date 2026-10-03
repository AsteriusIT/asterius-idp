#!/usr/bin/env bash
# Controlled owner-session fixture, real Asterius task descendant withdrawal and FAPI issuance.
# Uses an already verified binary and creates/drops only its own local fixture DB.
set -euo pipefail
umask 077
repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
: "${ASTERIUS_BIN:?Set ASTERIUS_BIN to an already verified local Asterius binary}"
database_base=${ASTERIUS_ACCEPTANCE_DATABASE_BASE:-postgres://asterius:asterius@127.0.0.1:5433/postgres}
for command in node psql openssl curl python3; do
  command -v "$command" >/dev/null || { printf 'Missing dependency: %s\n' "$command" >&2; exit 1; }
done
node - "$database_base" <<'JS'
const url = new URL(process.argv[2]);
if (url.hostname !== '127.0.0.1' || url.pathname !== '/postgres') throw new Error('Dedicated local fixture PostgreSQL required');
JS
run_dir=$(mktemp -d /tmp/asterius-agent-tasks-acceptance.XXXXXXXX)
db_name="ast_tasks_$(date +%s)_$RANDOM"
db_created=0
server_pid=''
cleanup() {
  if [ -n "$server_pid" ]; then
    kill -TERM "$server_pid" 2>/dev/null || true # The own fixture may have exited.
    wait "$server_pid" 2>/dev/null || true
  fi
  if [ "$db_created" = 1 ]; then
    psql "$database_base" -X -v ON_ERROR_STOP=1 -c "drop database \"$db_name\";" >/dev/null
  fi
  rm -rf -- "$run_dir"
}
trap cleanup EXIT
trap 'exit 130' INT TERM
psql "$database_base" -X -v ON_ERROR_STOP=1 -c "create database \"$db_name\";" >/dev/null
db_created=1
database=$(node - "$database_base" "$db_name" <<'JS'
const url = new URL(process.argv[2]); url.pathname = '/' + process.argv[3]; process.stdout.write(url.href);
JS
)
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
  -keyout "$run_dir/key.pem" -out "$run_dir/cert.pem" -days 1 -nodes \
  -subj /CN=localhost -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' 2>/dev/null
cat > "$run_dir/asterius.toml" <<EOF
[server]
bind = "127.0.0.1:9453"
mode = "terminate_tls"
[server.tls]
certificate = "$run_dir/cert.pem"
private_key = "$run_dir/key.pem"
[database]
url = "$database"
max_connections = 8
[keys]
kek_env = "ASTERIUS_KEK"
[features]
token_exchange = true
device_flow = true
[limits]
token_per_address = 1000
[[tenant]]
id = "tasks"
issuer = "https://localhost:9453/t/tasks"
EOF
ASTERIUS_KEK=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= \
  "$ASTERIUS_BIN" --config "$run_dir/asterius.toml" >"$run_dir/server.log" 2>&1 &
server_pid=$!
deadline=$((SECONDS + 60))
until curl --cacert "$run_dir/cert.pem" --silent --fail --max-time 1 \
    https://localhost:9453/readyz >/dev/null 2>&1; do
  if ! kill -0 "$server_pid" 2>/dev/null || [ "$SECONDS" -ge "$deadline" ]; then
    printf 'Own Asterius fixture did not become ready; ports 9453 and 9450 must be free.\n' >&2
    exit 1
  fi
  sleep 1
done
python3 "$repo_root/scripts/agent-tasks/withdrawal_acceptance.py" "$run_dir" "$database" "https://localhost:9453/t/tasks"
