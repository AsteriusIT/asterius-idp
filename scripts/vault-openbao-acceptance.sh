#!/usr/bin/env bash
# Actual product/browser/TokenRequest tests; owns its kind cluster and test DBs.
set -euo pipefail
umask 077
repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
: "${ASTERIUS_BIN:?Set a prebuilt verified Asterius binary}"
: "${ASTERIUS_ACCEPTANCE_DB_CONTAINER:?Set the controlled PostgreSQL container}"
: "${ASTERIUS_OPENBAO_BIN:?Set an official checksum-verified OpenBao binary}"
: "${ASTERIUS_VAULT_BIN:?Set an official checksum-verified Vault binary}"
for dependency in kind kubectl docker python3 node openssl; do
  command -v "$dependency" >/dev/null || { printf 'Missing fixture dependency: %s\n' "$dependency" >&2; exit 1; }
done
run_dir=$(mktemp -d /tmp/asterius-secret-products.XXXXXXXX)
cluster="ast-dd1y66-$(python3 -c 'import secrets;print(secrets.token_hex(6))')"
cleanup() {
  kind delete cluster --name "$cluster" >/dev/null 2>&1
  rm -rf -- "$run_dir"
}
trap cleanup EXIT
trap 'exit 130' INT TERM
kind create cluster --name "$cluster" --image kindest/node:v1.35.0 --kubeconfig "$run_dir/kubeconfig" --wait 120s >&2
export ASTERIUS_ACCEPTANCE_KUBECONFIG="$run_dir/kubeconfig"
export ASTERIUS_ACCEPTANCE_CLUSTER="$cluster"
for product in openbao vault; do
  if [ "$product" = openbao ]; then binary="$ASTERIUS_OPENBAO_BIN"; else binary="$ASTERIUS_VAULT_BIN"; fi
  ASTERIUS_SECRET_SYSTEM_PRODUCT="$product" ASTERIUS_SECRET_SYSTEM_BIN="$binary" \
    python3 "$repo_root/scripts/integrations/vault_acceptance.py" > "$run_dir/$product.json"
done
python3 - "$run_dir" <<'PY'
import json,pathlib,sys
root=pathlib.Path(sys.argv[1])
print(json.dumps({'date':'2026-10-03','cluster':'owned disposable kind v1.35.0','products':[json.loads((root/(p+'.json')).read_text()) for p in ('openbao','vault')]},indent=2))
PY
