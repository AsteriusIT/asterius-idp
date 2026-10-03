#!/usr/bin/env bash
# Real Asterius + restricted Kubernetes controller acceptance; own resources only.
set -euo pipefail
umask 077
repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
: "${ASTERIUS_BIN:?Supply a verified prebuilt server binary}"
: "${ASTERIUS_ACCEPTANCE_DB_CONTAINER:?Supply a disposable PostgreSQL container}"
port=${ASTERIUS_OPERATOR_PORT:-9457}
db_port=${ASTERIUS_ACCEPTANCE_DB_PORT:-5433}
gitops=${ASTERIUS_OPERATOR_GITOPS:-0}
host=127.0.0.1
if [[ "$gitops" = 1 ]]; then
  for dependency in terraform helm git; do command -v "$dependency" >/dev/null; done
fi
for dependency in kind kubectl docker openssl python3 node go curl rg; do command -v "$dependency" >/dev/null; done
python3 - "$port" "$host" <<'PY'
import socket,sys
with socket.socket() as sock:
 sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
 sock.bind((sys.argv[2],int(sys.argv[1])))
PY
run_dir=$(mktemp -d /tmp/asterius-operator.XXXXXXXX)
db_name="ast_operator_$(python3 -c 'import uuid; print(uuid.uuid4().hex)')"
cluster_name="asterius-operator-${BASHPID}"
server_pid=''; database_created=0; cluster_created=0
cleanup() {
  if [[ -n "$server_pid" ]]; then kill -CONT "$server_pid" 2>/dev/null || true; kill -TERM "$server_pid" 2>/dev/null || true; wait "$server_pid" 2>/dev/null || true; fi
  if [[ "$cluster_created" = 1 ]]; then kind delete cluster --name "$cluster_name" --kubeconfig "$run_dir/kubeconfig" >/dev/null 2>&1 || true; fi
  if [[ "$database_created" = 1 ]]; then docker exec "$ASTERIUS_ACCEPTANCE_DB_CONTAINER" psql -U asterius -d postgres -v ON_ERROR_STOP=1 -c "DROP DATABASE \"$db_name\" WITH (FORCE);" >/dev/null; fi
  rm -rf -- "$run_dir"
}
trap cleanup EXIT
trap 'exit 130' INT TERM
if kind get clusters | rg -qx -- "$cluster_name"; then printf '%s\n' 'Refusing existing cluster name' >&2; exit 1; fi
cluster_created=1
kind create cluster --name "$cluster_name" --image kindest/node:v1.35.0 --kubeconfig "$run_dir/kubeconfig" --wait 90s
if [[ "$gitops" = 1 ]]; then
  host=$(docker network inspect kind --format '{{range .IPAM.Config}}{{println .Gateway}}{{end}}' | python3 -c 'import sys,ipaddress;print(next(s.strip() for s in sys.stdin if ipaddress.ip_address(s.strip()).version==4))')
  python3 - "$host" "$port" <<'PY_HOST'
import socket,sys
for port in [int(sys.argv[2]),9462]:
 with socket.socket() as sock:
  sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
  sock.bind((sys.argv[1],port))
PY_HOST
fi
docker exec "$ASTERIUS_ACCEPTANCE_DB_CONTAINER" psql -U asterius -d postgres -v ON_ERROR_STOP=1 -c "CREATE DATABASE \"$db_name\";" >/dev/null
database_created=1
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -keyout "$run_dir/tls.pem" -out "$run_dir/ca.pem" -days 1 -nodes -subj /CN=localhost -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:$host" 2>/dev/null
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$run_dir/controller.pem"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$run_dir/dpop.pem"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$run_dir/dpop-rotated.pem"
python3 - "$repo_root" "$run_dir" "$port" "$db_port" "$db_name" "$host" <<'PY'
import base64,json,pathlib,sys
from cryptography.hazmat.primitives import serialization
repo,run,port,dbport,db,host=sys.argv[1:];root=pathlib.Path(run)
config=(pathlib.Path(repo)/'e2e/fixtures/asterius.toml.in').read_text()
for source,value in {'@PORT@':port,'@CERTIFICATE@':str(root/'ca.pem'),'@PRIVATE_KEY@':str(root/'tls.pem'),'@DATABASE_URL@':f'postgres://asterius:asterius@127.0.0.1:{dbport}/{db}'}.items():config=config.replace(source,value)
config=config.replace('127.0.0.1:',host+':').replace(f'postgres://asterius:asterius@{host}:', 'postgres://asterius:asterius@127.0.0.1:')
(root/'asterius.toml').write_text(config)
key=serialization.load_pem_private_key((root/'controller.pem').read_bytes(),password=None).public_key().public_numbers()
b64=lambda number:base64.urlsafe_b64encode(number.to_bytes(32,'big')).decode().rstrip('=')
doc={'keys':[{'kty':'EC','crv':'P-256','x':b64(key.x),'y':b64(key.y),'kid':'operator-1','alg':'ES256','use':'sig'}]}
(root/'public-jwks.json').write_text(json.dumps(doc))
scopes=['admin.session:read']
for kind in ['clients','resource_servers','policies']:scopes += [f'admin.{kind}:read',f'admin.{kind}:write']
quote=lambda value:"'"+value.replace("'","''")+"'"
aud=f'https://{host}:{port}/t/e2e/admin/api/v1'
sql=f"insert into resource_servers(tenant_id,identifier,scopes) values ('e2e',{quote(aud)},null);\n"
for client in ['operator-controller','terraform-other-controller']:
 sql+=f"insert into clients(tenant_id,client_id,client_name,token_endpoint_auth_method,grant_types,response_types,scopes,resources,jwks) values ('e2e',{quote(client)},'Controller fixture','private_key_jwt',array['client_credentials'],'{{}}',array[{','.join(quote(s) for s in scopes)}],array[{quote(aud)}],{quote(json.dumps(doc))}::jsonb);\n"
(root/'seed.sql').write_text(sql)
PY
ASTERIUS_KEK=YXN0ZXJpdXMtZGV2LWtlay1ub3QtYS1zZWNyZXQhISE= ASTERIUS_ADMIN_PASSWORD='a disposable operator administrator passphrase' "$ASTERIUS_BIN" --config "$run_dir/asterius.toml" >"$run_dir/server.log" 2>&1 &
server_pid=$!
ready=0
for _ in $(seq 1 90); do
  kill -0 "$server_pid" 2>/dev/null || { printf '%s\n' 'Isolated server exited' >&2; exit 1; }
  if curl --silent --fail --cacert "$run_dir/ca.pem" "https://$host:$port/readyz" >/dev/null; then ready=1; break; fi
  sleep 1
done
[[ "$ready" = 1 ]] || exit 1
docker exec -i "$ASTERIUS_ACCEPTANCE_DB_CONTAINER" psql -U asterius -d "$db_name" -v ON_ERROR_STOP=1 <"$run_dir/seed.sql" >/dev/null

export ASTERIUS_OPERATOR_FIXTURE_DIR="$run_dir" ASTERIUS_OPERATOR_ISSUER="https://$host:$port/t/e2e"
export ASTERIUS_OPERATOR_DB="$db_name"
export ASTERIUS_OPERATOR_SERVER_PID="$server_pid"
export ASTERIUS_OPERATOR_EVIDENCE_PATH="$run_dir/public-evidence.json"
export ASTERIUS_OPERATOR_BINARY_SHA256
ASTERIUS_OPERATOR_BINARY_SHA256=$(python3 - "$ASTERIUS_BIN" <<'PY'
import hashlib,sys
h=hashlib.sha256()
with open(sys.argv[1],'rb') as binary:
 while chunk:=binary.read(1024*1024):h.update(chunk)
print(h.hexdigest())
PY
)
if [[ "$gitops" = 1 ]]; then
  export ASTERIUS_OPERATOR_CLUSTER="$cluster_name" ASTERIUS_OPERATOR_FIXTURE_HOST="$host"
  python3 "$repo_root/scripts/operator/gitops_acceptance.py"
  mkdir -p "$repo_root/artifacts"
  cp -f "$run_dir/public-evidence.json" "$repo_root/artifacts/operator-gitops-e2e.json"
  exit 0
fi
cd "$repo_root/providers/terraform"
go test ./internal/operator -run '^TestLiveOperatorLifecycle$' -v -count=1
mkdir -p "$repo_root/artifacts"
cp -f "$run_dir/public-evidence.json" "$repo_root/artifacts/operator-e2e.json"
