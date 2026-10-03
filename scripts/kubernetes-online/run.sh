#!/usr/bin/env bash
# Disposable native JIT RBAC fixture with real HTTPS/OIDC/DPoP and a separate kind cluster.
# Uses an already verified binary and creates/drops only its own local fixture DB.
set -euo pipefail
umask 077
fixture_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd -- "$fixture_root/../.." && pwd)
export ASTERIUS_FIXTURE_REPO=$repo_root
: "${ASTERIUS_BIN:?Set ASTERIUS_BIN to an already verified local Asterius binary}"
database_base=${ASTERIUS_ACCEPTANCE_DATABASE_BASE:-postgres://asterius:asterius@127.0.0.1:5433/postgres}
for command in rg node psql openssl curl python3 docker kind kubectl go; do
  command -v "$command" >/dev/null || { printf 'Missing dependency: %s\n' "$command" >&2; exit 1; }
done
node - "$database_base" <<'JS'
const url = new URL(process.argv[2]);
if (url.hostname !== '127.0.0.1' || url.pathname !== '/postgres') throw new Error('Dedicated local fixture PostgreSQL required');
JS
run_dir=$(mktemp -d /tmp/asterius-online.XXXXXXXX)
db_name="ast_online_$(date +%s)_$RANDOM"
db_created=0
server_pid=''
adapter_pid=''
cluster_name=asterius-dd1y15
issuer_container=asterius-dd1y15-issuer
if kind get clusters 2>/dev/null | rg -qx "$cluster_name"; then
  printf 'Refusing existing acceptance cluster %s\n' "$cluster_name" >&2; exit 1
fi
if docker inspect "$issuer_container" >/dev/null 2>&1; then
  printf 'Refusing existing acceptance issuer container\n' >&2; exit 1
fi
python3 - <<'PYPORT'
import socket
with socket.socket() as sock:
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('0.0.0.0', 9468))
with socket.socket() as sock:
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('0.0.0.0', 9470))
PYPORT

cleanup() {
  if [ -f "$run_dir/adapter.log" ]; then cp -f "$run_dir/adapter.log" /tmp/ast-dd1y15-adapter-last.log; chmod 600 /tmp/ast-dd1y15-adapter-last.log; fi
  if [ -f "$run_dir/server.log" ]; then cp -f "$run_dir/server.log" /tmp/ast-dd1y15-server-last.log; chmod 600 /tmp/ast-dd1y15-server-last.log; fi
  # These names were verified absent before the fixture. No ambient kube context is used.
  if [ -f "$run_dir/cluster-created" ]; then
    docker exec "$cluster_name-control-plane" sh -c 'crictl logs $(crictl ps --name kube-apiserver -q | head -n 1)' > /tmp/ast-dd1y15-kube-last.log 2>&1 || true
    chmod 600 /tmp/ast-dd1y15-kube-last.log
    docker rm -f "$issuer_container" >/dev/null 2>&1 || true
    kind delete cluster --name "$cluster_name" --kubeconfig "$run_dir/admin-kubeconfig" >/dev/null 2>&1 || true
  fi
  if [ -f "$run_dir/adapter.pid" ]; then adapter_pid=$(cat "$run_dir/adapter.pid"); fi
  if [ -n "$adapter_pid" ]; then
    kill -TERM "$adapter_pid" 2>/dev/null || true
    wait "$adapter_pid" 2>/dev/null || true
  fi
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
bind = "0.0.0.0:9468"
mode = "terminate_tls"
[server.tls]
certificate = "$run_dir/cert.pem"
private_key = "$run_dir/key.pem"
[database]
url = "$database"
max_connections = 16
[keys]
kek_env = "ASTERIUS_KEK"
[features]
token_exchange = true
device_flow = true
authzen = true
[limits]
token_per_address = 1000
[[tenant]]
id = "temporary"
issuer = "https://localhost:9468/t/temporary"
[[tenant]]
id = "temporary-foreign"
issuer = "https://localhost:9468/t/temporary-foreign"
EOF
ASTERIUS_KEK=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= \
  "$ASTERIUS_BIN" --config "$run_dir/asterius.toml" >"$run_dir/server.log" 2>&1 &
server_pid=$!
deadline=$((SECONDS + 60))
until curl --cacert "$run_dir/cert.pem" --silent --fail --max-time 1 \
    https://localhost:9468/readyz >/dev/null 2>&1; do
  if ! kill -0 "$server_pid" 2>/dev/null || [ "$SECONDS" -ge "$deadline" ]; then
    printf 'Own Asterius fixture did not become ready; port 9468 must be free.\n' >&2
    exit 1
  fi
  sleep 1
done
# No execution occurs during preparation. Adapter compilation happens only in the authorized run.
(cd "$repo_root/providers/terraform" && go build -o "$run_dir/asterius-token-review" ./cmd/asterius-token-review)
python3 "$fixture_root/acceptance.py" "$run_dir" "$database" "https://localhost:9468/t/temporary"
