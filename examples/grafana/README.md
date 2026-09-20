# Grafana OIDC example

This deploys Grafana as a local OAuth/OIDC client using the Grafana Community
Helm chart. It is useful for checking basic OIDC discovery, authorization-code
login, PKCE, UserInfo, and ID-token validation against Asterius.

The example is intentionally not a FAPI/PAR client. Grafana's generic OAuth
integration uses a normal authorization request. Use the OpenID Foundation
Conformance Suite or `examples/api` to exercise Asterius's PAR-only FAPI flow.

## Prerequisites

- A Kubernetes cluster and `kubectl` context
- Helm 3
- Asterius reachable from the Grafana pod, not only from the host browser
- A registered Asterius client with redirect URI:
  `http://127.0.0.1:3001/login/generic_oauth`

The chart is referenced directly as an OCI artifact by `install.sh`; it is not
checked into this repository and the script does not run `helm pull`.

## Install

Set the client credentials and the URL that the Grafana pod can use to reach
Asterius:

```sh
cd examples/grafana
GRAFANA_CLIENT_ID=grafana-local \
GRAFANA_CLIENT_SECRET='replace-with-the-client-secret' \
IDP_BASE_URL='https://idp.example.test/t/demo' \
./install.sh
```

The default namespace is `grafana`; set `GRAFANA_NAMESPACE` to change it. The
default chart service is internal to Kubernetes. Forward it to the local port:

```sh
kubectl -n grafana port-forward svc/grafana 3001:80
```

Open <http://127.0.0.1:3001> and choose **Sign in with asterius**.

The Helm chart values are in [`values.yaml`](values.yaml), while endpoint and
secret overrides stay in the install command so credentials do not enter the
repository.
