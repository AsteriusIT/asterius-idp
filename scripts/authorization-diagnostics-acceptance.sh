#!/usr/bin/env bash
# Disposable real-server acceptance. Creates/drops only its own uniquely named DB.
# No Rust build, deployment, shared-schema reset or remote publication.
set -euo pipefail
umask 077
repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
: "${ASTERIUS_BIN:?Set ASTERIUS_BIN to an already verified local Asterius binary}"
: "${ASTERIUS_ACCEPTANCE_DB_CONTAINER:?Set the disposable PostgreSQL container name}"
port=${ASTERIUS_ACCEPTANCE_PORT:-9454}
db_port=${ASTERIUS_ACCEPTANCE_DB_PORT:-5433}
for command in docker openssl python3 curl; do
  command -v "$command" >/dev/null || { printf 'Missing fixture dependency: %s\n' "$command" >&2; exit 1; }
done
python3 -c 'import cryptography' >/dev/null
run_dir=$(mktemp -d /tmp/asterius-diagnostics-acceptance.XXXXXXXX)
db_name="ast_diagnostics_$(python3 -c 'import uuid; print(uuid.uuid4().hex)')"
db_created=0
server_pid=''
cleanup() {
  if [ -n "$server_pid" ]; then
    kill -TERM "$server_pid" 2>/dev/null || true # The fixture may already have exited.
    wait "$server_pid" 2>/dev/null || true
  fi
  if [ "$db_created" = 1 ]; then
    docker exec "$ASTERIUS_ACCEPTANCE_DB_CONTAINER" psql -U asterius -d postgres \
      -v ON_ERROR_STOP=1 -c "drop database \"$db_name\";" >/dev/null
  fi
  rm -rf -- "$run_dir"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

docker exec "$ASTERIUS_ACCEPTANCE_DB_CONTAINER" psql -U asterius -d postgres \
  -v ON_ERROR_STOP=1 -c "create database \"$db_name\";" >/dev/null
db_created=1
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
  -keyout "$run_dir/tls-key.pem" -out "$run_dir/ca.pem" -days 1 -nodes \
  -subj /CN=127.0.0.1 -addext 'subjectAltName=IP:127.0.0.1,DNS:localhost' 2>/dev/null
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$run_dir/controller.pem"

python3 - "$repo_root" "$run_dir" "$port" "$db_port" "$db_name" <<'PY'
import base64, json, pathlib, sys
from cryptography.hazmat.primitives import serialization
repo, run, port, db_port, database = sys.argv[1:]
assert 1024 <= int(port) <= 65535 and 1 <= int(db_port) <= 65535
root=pathlib.Path(run)
key=serialization.load_pem_private_key((root/'controller.pem').read_bytes(),password=None)
n=key.public_key().public_numbers()
b64=lambda x:base64.urlsafe_b64encode(x.to_bytes(32,'big')).decode().rstrip('=')
jwk={'kty':'EC','crv':'P-256','x':b64(n.x),'y':b64(n.y),'kid':'provider-controller-1','alg':'ES256','use':'sig'}
(root/'public.jwk.json').write_text(json.dumps(jwk))
config=(pathlib.Path(repo)/'e2e/fixtures/asterius.toml.in').read_text()
for source,value in {'@PORT@':port,'@CERTIFICATE@':str(root/'ca.pem'),'@PRIVATE_KEY@':str(root/'tls-key.pem'),'@DATABASE_URL@':f'postgres://asterius:asterius@127.0.0.1:{db_port}/{database}','e2e-admin':'admin', 'device_flow = true':'device_flow = true\nauthzen = true'}.items(): config=config.replace(source,value)
(root/'asterius.toml').write_text(config)
scopes=['admin.session:read','admin.audit:read','authzen.evaluate']
for kind in ['tenants','clients','resource_servers','groups','memberships','policies']: scopes.extend([f'admin.{kind}:read',f'admin.{kind}:write'])
quote=lambda s:"'"+s.replace("'","''")+"'"
aud=f'https://127.0.0.1:{port}/t/admin/admin/api/v1'
sql="insert into resource_servers(tenant_id,identifier,scopes) values ('admin',"+quote(aud)+",null);\n"
for client in ['terraform-controller','terraform-controller-other']:
 sql+="insert into clients(tenant_id,client_id,client_name,token_endpoint_auth_method,grant_types,response_types,scopes,resources,jwks) values ('admin',"+quote(client)+",'Provider fixture','private_key_jwt',array['client_credentials'],'{}',array["+','.join(quote(s) for s in scopes)+"],array["+quote(aud)+"],"+quote(json.dumps({'keys':[jwk]}))+"::jsonb);\n"
sql+="insert into users(tenant_id,user_id,username,status) values ('admin','00000000-0000-0000-0000-000000000001','provider-fixture-user','active');\n"
pdp=f'https://127.0.0.1:{port}/t/admin/access/v1/evaluation'
sql+="insert into resource_servers(tenant_id,identifier,scopes) values ('admin',"+quote(pdp)+",null);\n"
sql+="update clients set resources=array_append(resources,"+quote(pdp)+") where tenant_id='admin' and client_id like 'terraform-controller%';\n"
sql+="insert into tenant_policies(tenant_id,document,updated_at) values ('admin',"+quote(json.dumps({'version':1,'rules':[{'id':'recorded-deny','effect':'deny','when':{'attribute':{'of':'context','name':'country','in':['FR']}}}]}))+"::jsonb,now());\n"
foreign=f'https://127.0.0.1:{port}/t/e2e/admin/api/v1'
sql+="insert into resource_servers(tenant_id,identifier,scopes) values ('e2e',"+quote(foreign)+",null);\n"
sql+="insert into clients(tenant_id,client_id,client_name,token_endpoint_auth_method,grant_types,response_types,scopes,resources,jwks) values ('e2e','terraform-controller','Foreign support fixture','private_key_jwt',array['client_credentials'],'{}',array['admin.audit:read'],array["+quote(foreign)+"],"+quote(json.dumps({'keys':[jwk]}))+"::jsonb);\n"
(root/'seed.sql').write_text(sql)
PY

ASTERIUS_KEK=YXN0ZXJpdXMtZGV2LWtlay1ub3QtYS1zZWNyZXQhISE= \
ASTERIUS_ADMIN_PASSWORD='a disposable provider fixture administrator passphrase' \
  "$ASTERIUS_BIN" --config "$run_dir/asterius.toml" >"$run_dir/server.log" 2>&1 &
server_pid=$!
deadline=$((SECONDS + 60))
until curl --cacert "$run_dir/ca.pem" --silent --fail --max-time 1 \
    "https://127.0.0.1:$port/readyz" >/dev/null 2>&1; do
  if ! kill -0 "$server_pid" 2>/dev/null || [ "$SECONDS" -ge "$deadline" ]; then
    printf 'Isolated Asterius fixture did not become ready.\n' >&2
    exit 1
  fi
  sleep 1
done
docker exec -i "$ASTERIUS_ACCEPTANCE_DB_CONTAINER" psql -U asterius -d "$db_name" \
  -v ON_ERROR_STOP=1 < "$run_dir/seed.sql" >/dev/null

python3 "$repo_root/scripts/diagnostics/acceptance.py" "$run_dir" "$port" "$ASTERIUS_ACCEPTANCE_DB_CONTAINER" "$db_name"
