#!/usr/bin/env bash
# Disposable real-server acceptance. Creates/drops only its own uniquely named DB.
# No Rust build, deployment, shared-schema reset or remote publication.
set -euo pipefail
umask 077
repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
: "${ASTERIUS_BIN:?Set ASTERIUS_BIN to an already verified local Asterius binary}"
: "${ASTERIUS_ACCEPTANCE_DB_CONTAINER:?Set the disposable PostgreSQL container name}"
port=${ASTERIUS_ACCEPTANCE_PORT:-9446}
db_port=${ASTERIUS_ACCEPTANCE_DB_PORT:-5433}
terraform_cli=${ASTERIUS_ACCEPTANCE_TERRAFORM:-terraform}
tofu_cli=${ASTERIUS_ACCEPTANCE_TOFU:-tofu}
for command in docker openssl python3 curl go "$terraform_cli" "$tofu_cli"; do
  command -v "$command" >/dev/null || { printf 'Missing fixture dependency: %s\n' "$command" >&2; exit 1; }
done
python3 -c 'import cryptography' >/dev/null
run_dir=$(mktemp -d /tmp/asterius-provider-acceptance.XXXXXXXX)
db_name="ast_provider_$(python3 -c 'import uuid; print(uuid.uuid4().hex)')"
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
for source,value in {'@PORT@':port,'@CERTIFICATE@':str(root/'ca.pem'),'@PRIVATE_KEY@':str(root/'tls-key.pem'),'@DATABASE_URL@':f'postgres://asterius:asterius@127.0.0.1:{db_port}/{database}','e2e-admin':'admin'}.items(): config=config.replace(source,value)
(root/'asterius.toml').write_text(config)
scopes=['admin.session:read']
for kind in ['tenants','clients','resource_servers','groups','memberships','policies']: scopes.extend([f'admin.{kind}:read',f'admin.{kind}:write'])
quote=lambda s:"'"+s.replace("'","''")+"'"
aud=f'https://127.0.0.1:{port}/t/admin/admin/api/v1'
sql="insert into resource_servers(tenant_id,identifier,scopes) values ('admin',"+quote(aud)+",null);\n"
for client in ['terraform-controller','terraform-controller-other']:
 sql+="insert into clients(tenant_id,client_id,client_name,token_endpoint_auth_method,grant_types,response_types,scopes,resources,jwks) values ('admin',"+quote(client)+",'Provider fixture','private_key_jwt',array['client_credentials'],'{}',array["+','.join(quote(s) for s in scopes)+"],array["+quote(aud)+"],"+quote(json.dumps({'keys':[jwk]}))+"::jsonb);\n"
sql+="insert into users(tenant_id,user_id,username,status) values ('admin','00000000-0000-0000-0000-000000000001','provider-fixture-user','active');\n"
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

cat > "$run_dir/drift" <<'PY'
#!/usr/bin/env python3
import base64, json, os, subprocess, sys, uuid
parts=json.loads(base64.urlsafe_b64decode(sys.argv[1]+'='*((-len(sys.argv[1]))%4)))
assert len(parts)==3 and parts[0]=='admin' and parts[1]=='group'
assert str(uuid.UUID(parts[2]))==parts[2]
sql="update managed_groups set display_name='Console drift' where tenant_id='admin' and group_id='"+parts[2]+"'::uuid;"
subprocess.run(['docker','exec',os.environ['ASTERIUS_ACCEPTANCE_DB_CONTAINER'],'psql','-U','asterius','-d',os.environ['ASTERIUS_FIXTURE_DB'],'-v','ON_ERROR_STOP=1','-c',sql],check=True)
PY
chmod 700 "$run_dir/drift"
export ASTERIUS_FIXTURE_DB="$db_name"
export ASTERIUS_ACCEPTANCE_LIVE=1
export ASTERIUS_ISSUER="https://127.0.0.1:$port/t/admin"
export ASTERIUS_CLIENT_ID=terraform-controller
export ASTERIUS_SIGNING_KEY_FILE="$run_dir/controller.pem"
export ASTERIUS_SIGNING_KEY_ID=provider-controller-1
export ASTERIUS_CA_FILE="$run_dir/ca.pem"
export ASTERIUS_TOKEN_RESOURCE="$ASTERIUS_ISSUER/admin/api/v1"
export ASTERIUS_ACCEPTANCE_OTHER_CLIENT_ID=terraform-controller-other
export ASTERIUS_ACCEPTANCE_PUBLIC_JWK="$run_dir/public.jwk.json"
export ASTERIUS_ACCEPTANCE_USER_ID=00000000-0000-0000-0000-000000000001
export ASTERIUS_ACCEPTANCE_DRIFT_COMMAND="$run_dir/drift"
export ASTERIUS_ACCEPTANCE_TERRAFORM="$terraform_cli"
export ASTERIUS_ACCEPTANCE_TOFU="$tofu_cli"
printf 'Real Asterius provider acceptance: %s; isolated DB %s\n' "$ASTERIUS_BIN" "$db_name"
cd "$repo_root/providers/terraform"
go test ./internal/acceptance -run '^TestLive(CLI|DeletionReceiptAfterParentRemoval)$' -v -count=1
