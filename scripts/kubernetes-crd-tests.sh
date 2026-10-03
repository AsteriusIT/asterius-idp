#!/usr/bin/env bash
# Installs fixtures only into a fresh, explicitly owned disposable cluster.
set -euo pipefail
repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cluster_name="asterius-crd-${BASHPID}"
run_dir=$(mktemp -d /tmp/asterius-crd.XXXXXX)
if kind get clusters | rg -qx -- "$cluster_name"; then
  rm -rf -- "$run_dir"
  printf '%s\n' 'Refusing to reuse an existing cluster name' >&2
  exit 1
fi
cleanup() {
  kind delete cluster --name "$cluster_name" --kubeconfig "$run_dir/kubeconfig" >/dev/null 2>&1 || true
  rm -rf -- "$run_dir"
}
trap cleanup EXIT
kind create cluster --name "$cluster_name" --image kindest/node:v1.35.0 --kubeconfig "$run_dir/kubeconfig" --wait 90s
ASTERIUS_CRD_KUBECONFIG="$run_dir/kubeconfig" node --test "$repo_dir/tools/identity-operator/test/admission.test.mjs"
