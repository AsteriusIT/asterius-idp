#!/usr/bin/env bash
# Controlled real OP/browser/OS-store/kubectl interoperability; no existing cluster is changed.
set -euo pipefail
umask 077
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
: "${ASTERIUS_BIN:?Supply a prebuilt Asterius binary with the console embedded}"
: "${DATABASE_URL:=postgres://asterius:asterius@127.0.0.1:5433/asterius}"
for command in node npm docker kind kubectl psql openssl python3 curl script rg; do
  command -v "$command" >/dev/null || { echo "Missing prerequisite: $command" >&2; exit 1; }
done
cluster_name=asterius-dd1y14
secret_container=asterius-dd1y14-secret-service
issuer_container=asterius-dd1y14-issuer
if kind get clusters 2>/dev/null | rg -qx "$cluster_name"; then
  echo "Refusing an existing acceptance cluster; finish its current lease first." >&2; exit 1
fi
for resource in "$secret_container" "$issuer_container"; do
  if docker inspect "$resource" >/dev/null 2>&1; then echo "Refusing existing owned resource $resource" >&2; exit 1; fi
done
for port in 9447 9449; do
  python3 - "$port" <<'PY'
import socket, sys
with socket.socket() as s:
    try: s.bind(('0.0.0.0', int(sys.argv[1])))
    except OSError: sys.exit('Acceptance port already in use: ' + sys.argv[1])
PY
done
run_dir="$(mktemp -d /tmp/asterius-dd1y14-XXXXXX)"
database_name="ast_dd1y14_$$"
admin_database="$DATABASE_URL"
export E2E_DATABASE_URL="$(python3 - "$DATABASE_URL" "$database_name" <<'PY'
import sys, urllib.parse
u=urllib.parse.urlsplit(sys.argv[1]); print(urllib.parse.urlunsplit(u._replace(path='/'+sys.argv[2])))
PY
)"
export KUBE_E2E_DIR="$run_dir" NODE_EXTRA_CA_CERTS="$run_dir/cert.pem"
server_pid=''; database_created=0; cluster_created=0; secret_created=0; issuer_created=0
cleanup() {
  if [[ -n "$server_pid" ]]; then kill "$server_pid" 2>/dev/null || true; wait "$server_pid" 2>/dev/null || true; fi
  if [[ "$secret_created" = 1 ]]; then docker rm -f "$secret_container" >/dev/null 2>&1 || true; fi
  if [[ "${KUBE_E2E_KEEP_CLUSTER:-0}" != 1 ]]; then
    if [[ "$issuer_created" = 1 ]]; then docker rm -f "$issuer_container" >/dev/null 2>&1 || true; fi
    if [[ "$cluster_created" = 1 ]]; then kind delete cluster --name "$cluster_name" >/dev/null 2>&1 || true; fi
  else
    echo "Cluster lease retained: $run_dir/admin-kubeconfig; caller owns eventual cleanup."
  fi
  if [[ "$database_created" = 1 ]]; then psql "$admin_database" -v ON_ERROR_STOP=1 -c "DROP DATABASE $database_name WITH (FORCE)" >/dev/null || true; fi
  # Private fixture files never become CI artifacts. Keep only the explicit public evidence.
  rm -f "$run_dir/key.pem" "$run_dir/broker.json" "$run_dir/helper.json" "$run_dir/asterius.toml"
  rm -rf "$run_dir/broker"
  if [[ "${KUBE_E2E_KEEP_CLUSTER:-0}" != 1 ]]; then rm -rf "$run_dir"; fi
}
trap cleanup EXIT
psql "$admin_database" -v ON_ERROR_STOP=1 -c "CREATE DATABASE $database_name" >/dev/null
database_created=1
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -keyout "$run_dir/key.pem" -out "$run_dir/cert.pem" -days 1 -nodes -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' 2>/dev/null
sed -e 's|@PORT@|9447|g' -e "s|@CERTIFICATE@|$run_dir/cert.pem|g" -e "s|@PRIVATE_KEY@|$run_dir/key.pem|g" -e "s|@DATABASE_URL@|$E2E_DATABASE_URL|g" -e 's|bind = "127.0.0.1:9447"|bind = "0.0.0.0:9447"|' e2e/fixtures/asterius.toml.in > "$run_dir/asterius.toml"
export ASTERIUS_KEK='YXN0ZXJpdXMtZGV2LWtlay1ub3QtYS1zZWNyZXQhISE=' ASTERIUS_ADMIN_PASSWORD='a deployment administrator passphrase'
"$ASTERIUS_BIN" --config "$run_dir/asterius.toml" > "$run_dir/server.log" 2>&1 &
server_pid=$!
ready=0
for _ in $(seq 1 120); do
  if curl --silent --fail --cacert "$run_dir/cert.pem" https://localhost:9447/readyz >/dev/null; then ready=1; break; fi
  kill -0 "$server_pid" 2>/dev/null || { echo 'Acceptance server exited' >&2; exit 1; }
  sleep 1
done
[[ "$ready" = 1 ]] || { echo 'Acceptance server readiness timed out' >&2; exit 1; }
fixture_hash='$argon2id$v=19$m=19456,t=2,p=1$YnJvd3Nlci1zd2VlcC1zYWx0$E8awnsfATh5sLXjht+SvAdX9BEFVTWfDYThAb/+KOfs'
for tenant in e2e e2e-webauthn; do psql "$E2E_DATABASE_URL" -q -v tenant="$tenant" -v username=sweep@example.test -v hash="$fixture_hash" -f e2e/fixtures/seed.sql >/dev/null; done
npm ci --prefix tools/kubernetes-login --ignore-scripts >/dev/null
npm ci --prefix e2e --ignore-scripts >/dev/null
(cd e2e && npx playwright install chromium)
node scripts/kubernetes-e2e/prepare.mjs
node scripts/kubernetes-e2e/prepare-alternates.mjs
cluster_created=1
kind create cluster --name "$cluster_name" --image kindest/node:v1.35.0 --config "$run_dir/kind.yaml" --kubeconfig "$run_dir/admin-kubeconfig" --wait 120s
cluster_created=1
kind_gateway="$(docker network inspect kind | python3 -c 'import json,sys,ipaddress; print(next(c["Gateway"] for c in json.load(sys.stdin)[0]["IPAM"]["Config"] if ipaddress.ip_address(c["Gateway"]).version==4))')"
docker run -d --name "$issuer_container" --network "container:$cluster_name-control-plane" alpine/socat@sha256:5ffbd6ae916cbad86a58fabe0d6d5a6fd5c2b47ddf031e82996baac9300e732f TCP-LISTEN:9447,bind=127.0.0.1,fork,reuseaddr "TCP:$kind_gateway:9447" >/dev/null
issuer_created=1
kubectl --kubeconfig "$run_dir/admin-kubeconfig" create namespace human-access
kubectl --kubeconfig "$run_dir/admin-kubeconfig" -n human-access create configmap visible-fixture --from-literal=purpose=controlled-acceptance
kubectl --kubeconfig "$run_dir/admin-kubeconfig" -n human-access create rolebinding asterius-readers --clusterrole=view --group=asterius:e2e-webauthn:cluster-a:group:group:10000000-0000-4000-8000-000000000001
docker run -d --name "$secret_container" --network host -v "$root:/repo:ro" -v "$run_dir:/fixture:ro" node:24.4.0-bookworm-slim@sha256:1b044a60874f1b57ac8c4e708ddb3a00e55b34586ebbacce09a48796dafcc799 sleep infinity >/dev/null
secret_created=1
docker exec "$secret_container" sh -c 'apt-get update -qq && apt-get install -y -qq --no-install-recommends libsecret-tools gnome-keyring dbus && rm -rf /var/lib/apt/lists/*' >/dev/null
docker exec "$secret_container" dbus-daemon --session --address=unix:path=/tmp/asterius-bus --fork
python3 -c 'import secrets; print(secrets.token_urlsafe(32))' | docker exec -i -e DBUS_SESSION_BUS_ADDRESS=unix:path=/tmp/asterius-bus "$secret_container" gnome-keyring-daemon --unlock --daemonize --components=secrets >/dev/null
node scripts/kubernetes-e2e/run.mjs
mkdir -p artifacts
cp -f "$run_dir/evidence.json" artifacts/kubernetes-e2e.json
echo 'Redacted public evidence: artifacts/kubernetes-e2e.json'
