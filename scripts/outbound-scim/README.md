# Owned outbound SCIM acceptance candidate

This runner exercises another disposable Asterius tenant with real client
credentials, private-key assertions, DPoP, SCIM conditional versions and a real
Chromium user-verifying passkey ceremony. It enables only its own candidate
catalogue. Delivery of the profile remains subject to the proposed
`docs/adr/outbound-scim-contract.md` human review.

Use an already verified composed binary with outbound SCIM migration 0169,
a controlled PostgreSQL fixture container, cached
`python:3.13-alpine3.20` and `gcr.io/distroless/cc-debian13:nonroot` images,
and the repository's browser dependencies. No Rust build or image pull occurs.
Ports 9478, 9479 and 9492 on host loopback must be free.

Export the certificate for the **already authorized existing private tailnet
hostname**, without changing Serve/Funnel, into a private directory:

```sh
umask 077
export ASTERIUS_OUTBOUND_HOSTNAME='<existing-private-name>.ts.net'
export ASTERIUS_OUTBOUND_TLS_DIRECTORY="$(mktemp -d /tmp/asterius-outbound-tls.XXXXXXXX)"
tailscale cert --cert-file "$ASTERIUS_OUTBOUND_TLS_DIRECTORY/cert.pem" \
  --key-file "$ASTERIUS_OUTBOUND_TLS_DIRECTORY/key.pem" "$ASTERIUS_OUTBOUND_HOSTNAME"
printf '%s' "$ASTERIUS_OUTBOUND_HOSTNAME" > "$ASTERIUS_OUTBOUND_TLS_DIRECTORY/hostname"
chmod 600 "$ASTERIUS_OUTBOUND_TLS_DIRECTORY"/*
export ASTERIUS_BIN='<verified-immutable-binary>'
export ASTERIUS_ACCEPTANCE_DB_CONTAINER='<controlled-postgres-container>'
python3 scripts/outbound-scim/acceptance.py
```

The runner creates two uniquely named databases and owned containers. It
attaches its helper to the controlled database's network; it changes no
pre-existing container. Source and target runtime containers run nonroot with
all capabilities dropped, a read-only root and bounded temporary storage.
Their credentials, config, cookies, fault state and logs remain in private
files removed at exit. A failed cleanup is an error. Delete the owned exported
certificate directory after the final run; the runner does not delete caller
input files.

The synthetic globally classified address `93.184.215.14` is assigned **only to
this disposable network namespace's loopback**. An owned container hosts file
maps the exact certificate hostname there. The production connector performs
its ordinary DNS resolution, all-address SSRF classification, vetted socket
dialing and WebPKI hostname verification. No production bypass, global DNS
change, public publishing, Funnel or shared Serve change is involved.
This proves those guarded transport steps and real TLS dispatch; it does not
claim public Internet reachability.

The peer relay permits only the exact target token endpoint and bounded SCIM
paths. Controlled faults drop responses only after the real target completed
POST/DELETE, so lost-response recovery is exercised against committed effects.
Relay evidence contains method, resource family, HTTP status and a fixed fault
code; no URL, headers, identifiers, bodies, keys or tokens. The source's normal
worker and admission fences remain active. The runner may advance only its own
pending/failed outbound jobs' retry time to make backoff scenarios bounded.

`acceptance-matrix.json` lists the broader required controls. Syntax checks and
namespace preflight are preparation evidence, not proof that these lifecycle
cases passed. Record actual executed controls and exact binary/certificate
hashes after the composed candidate runtime is available.
