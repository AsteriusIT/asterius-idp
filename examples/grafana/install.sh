#!/bin/sh
# Install or upgrade the local Grafana OIDC test client with Helm.
#
# Requirements: kubectl, Helm, and a reachable Kubernetes cluster.
# Usage:
#   GRAFANA_CLIENT_ID=... GRAFANA_CLIENT_SECRET=... ./install.sh
#
# Override the defaults when Grafana or Asterius are not exposed at the local
# URLs used by the example:
#   GRAFANA_URL=http://grafana.example.test:3001 \
#   IDP_BASE_URL=https://idp.example.test/t/demo \
#   ./install.sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
NAMESPACE=${GRAFANA_NAMESPACE:-grafana}
RELEASE=${GRAFANA_RELEASE:-grafana}
GRAFANA_URL=${GRAFANA_URL:-http://127.0.0.1:3001}
IDP_BASE_URL=${IDP_BASE_URL:-https://localhost/t/demo}
: "${GRAFANA_CLIENT_ID:?Set GRAFANA_CLIENT_ID to the registered client ID}"
CLIENT_ID=$GRAFANA_CLIENT_ID
: "${GRAFANA_CLIENT_SECRET:?Set GRAFANA_CLIENT_SECRET to the registered client secret}"
CLIENT_SECRET=$GRAFANA_CLIENT_SECRET
CHART=${GRAFANA_CHART:-oci://ghcr.io/grafana-community/helm-charts/grafana}

kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml |
  kubectl apply -f -

kubectl create secret generic "${RELEASE}-oidc" \
  --namespace "$NAMESPACE" \
  --from-literal="GF_AUTH_GENERIC_OAUTH_CLIENT_SECRET=$CLIENT_SECRET" \
  --dry-run=client -o yaml |
  kubectl apply -f -

helm upgrade --install "$RELEASE" "$CHART" \
  --namespace "$NAMESPACE" \
  --values "$SCRIPT_DIR/values.yaml" \
  --set-string "envFromSecret=${RELEASE}-oidc" \
  --set-string "grafana.ini.server.root_url=$GRAFANA_URL" \
  --set-string "grafana.ini.auth.generic_oauth.client_id=$CLIENT_ID" \
  --set-string "grafana.ini.auth.generic_oauth.auth_url=$IDP_BASE_URL/authorize" \
  --set-string "grafana.ini.auth.generic_oauth.token_url=$IDP_BASE_URL/token" \
  --set-string "grafana.ini.auth.generic_oauth.api_url=$IDP_BASE_URL/userinfo" \
  --wait

cat <<EOF

Grafana is installed in namespace $NAMESPACE.
Create the IdP client with this redirect URI:
  $GRAFANA_URL/login/generic_oauth

Access it with:
  kubectl -n $NAMESPACE port-forward svc/$RELEASE 3001:80
EOF
