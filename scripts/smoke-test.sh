#!/usr/bin/env bash
# Proves that a freshly started deployment actually serves a tenant.
#
# This is the acceptance test for the example compose stack (`ast-p2l.7`): it
# asserts what an operator would check by hand after `docker compose up`, in the
# order in which things can go wrong. Every check is an HTTP request from
# outside the container, because that is the only surface a deployment really
# has — the image ships no shell to check anything from within.
#
#     docker compose -f deploy/compose/docker-compose.yml up --build -d
#     ./scripts/smoke-test.sh
#
# Environment:
#   BASE_URL   where to reach the deployment, through whatever terminates TLS
#              in front of it. Default https://localhost
#   ISSUER     the issuer the tenant must announce.
#              Default https://localhost/t/demo
#   CACERT     a certificate to verify the deployment against. Defaults to the
#              example stack's self-signed deploy/certs/server.crt when that
#              file exists, and to the system trust store otherwise. This
#              script never disables verification: a smoke test that accepts
#              any certificate cannot tell you the right one is installed.
#   TENANT     the tenant id. Default demo
#   TIMEOUT    seconds to wait for readiness. Default 90
#   CONTAINER  compose service to inspect for the container hardening checks.
#              Default asterius; set to "" to skip them.
#   ADMIN_TENANT   the reserved tenant the deployment admin lives in.
#                  Default admin. Set to "" to skip the admin checks.
#   ADMIN_USERNAME the seeded admin's login identifier. Default admin.
set -euo pipefail

BASE_URL="${BASE_URL:-https://localhost}"
TENANT="${TENANT:-demo}"
ISSUER="${ISSUER:-https://localhost/t/${TENANT}}"
TIMEOUT="${TIMEOUT:-90}"
CONTAINER="${CONTAINER:-asterius}"
ADMIN_TENANT="${ADMIN_TENANT:-admin}"
ADMIN_USERNAME="${ADMIN_USERNAME:-admin}"
COMPOSE_FILE="${COMPOSE_FILE:-$(dirname "$0")/../deploy/compose/docker-compose.yml}"

# The `Host` header decides which tenant a request is speaking to, and it has
# to be the issuer's authority. The proxy passes it through untouched
# (docs/deployment/tls-and-proxy.md §3).
HOST_HEADER="${HOST_HEADER:-$(printf '%s' "$ISSUER" | sed -e 's#^https\?://##' -e 's#/.*##')}"

# The example stack terminates TLS with a certificate it generated for itself,
# so it is its own trust anchor (deploy/scripts/gen-self-signed.sh). Against a
# real deployment CACERT is empty and curl uses the system store.
CACERT="${CACERT:-$(dirname "$0")/../deploy/certs/server.crt}"
tls_opts=()
if [ -n "$CACERT" ] && [ -s "$CACERT" ]; then
  tls_opts=(--cacert "$CACERT")
fi

failures=0

pass() { printf '  ok    %s\n' "$1"; }
fail() {
  printf '  FAIL  %s\n' "$1" >&2
  failures=$((failures + 1))
}

# curl, with the tenant's Host header and no retry logic: a smoke test that
# retries hides the flakiness it exists to find.
get() {
  curl --silent --show-error --fail-with-body \
    "${tls_opts[@]}" \
    --header "Host: ${HOST_HEADER}" \
    --max-time 10 \
    "${BASE_URL}$1"
}

status_of() {
  curl --silent --output /dev/null --write-out '%{http_code}' \
    "${tls_opts[@]}" \
    --header "Host: ${HOST_HEADER}" \
    --max-time 10 \
    "${BASE_URL}$1"
}

# A flat JSON string field. Enough for discovery documents, and it keeps this
# script free of a `jq` dependency that a fresh machine will not have.
json_string() {
  sed -n "s/.*\"$2\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p" <<<"$1" | head -n 1
}

expect_eq() {
  if [ "$2" = "$3" ]; then
    pass "$1"
  else
    fail "$1 (expected ${3@Q}, got ${2@Q})"
  fi
}

printf 'smoke test against %s (tenant %s)\n' "$BASE_URL" "$TENANT"

# --- 1. the process is up ---------------------------------------------------
printf '\nliveness\n'
deadline=$(($(date +%s) + TIMEOUT))
until [ "$(status_of /healthz)" = "200" ]; do
  if [ "$(date +%s)" -ge "$deadline" ]; then
    fail "/healthz did not answer 200 within ${TIMEOUT}s"
    exit 1
  fi
  sleep 1
done
pass "/healthz answers 200"

# --- 2. it is ready to serve ------------------------------------------------
# Readiness is the interesting one: it is false until the database answers *and*
# every migration compiled into this binary is recorded applied. A green
# /readyz is the proof that migrations-on-start worked.
printf '\nreadiness (database reachable, migrations applied)\n'
until [ "$(status_of /readyz)" = "200" ]; do
  if [ "$(date +%s)" -ge "$deadline" ]; then
    fail "/readyz did not answer 200 within ${TIMEOUT}s: $(get /readyz || true)"
    exit 1
  fi
  sleep 1
done
pass "/readyz answers 200"

readyz="$(get /readyz)"
if grep -q '"migrations_applied":[[:space:]]*true' <<<"$readyz"; then
  pass "/readyz reports every migration applied"
else
  fail "/readyz does not report migrations applied: ${readyz}"
fi

# --- 3. the tenant exists and announces itself ------------------------------
printf '\ntenant %s\n' "$TENANT"
discovery="$(get "/t/${TENANT}/.well-known/openid-configuration")"
expect_eq "discovery announces the configured issuer" \
  "$(json_string "$discovery" issuer)" "$ISSUER"

# RFC 8414 §3.1's path-insertion form has to resolve to the same tenant. A
# deployment where only one of the two forms works is one half of its clients
# cannot discover.
inserted="$(get "/.well-known/openid-configuration/t/${TENANT}")"
expect_eq "the RFC 8414 path-insertion form resolves to the same issuer" \
  "$(json_string "$inserted" issuer)" "$ISSUER"

# --- 4. the tenant has usable signing keys ----------------------------------
# This is the check that proves the key-encryption key was loaded and a signing
# key was created, wrapped and read back. It is the first thing that breaks
# when the KEK is wrong, and it breaks silently everywhere else.
printf '\nsigning keys\n'
jwks_uri="$(json_string "$discovery" jwks_uri)"
if [ -z "$jwks_uri" ]; then
  fail "discovery announced no jwks_uri"
else
  jwks="$(get "/${jwks_uri#*://*/}")"
  if grep -q '"kty"' <<<"$jwks"; then
    pass "the JWKS publishes at least one key"
  else
    fail "the JWKS publishes no key: ${jwks}"
  fi
  case "$jwks" in
    *'"d"'*) fail "the JWKS contains a private key component" ;;
    *) pass "the JWKS is public material only" ;;
  esac
fi

# --- 5. an unknown tenant is not served -------------------------------------
printf '\nisolation\n'
expect_eq "an unknown tenant is 404, not a default one" \
  "$(status_of /t/does-not-exist/.well-known/openid-configuration)" "404"

# --- 6. the deployment is administrable ------------------------------------
# ADR-0010: a deployment admin is a user of a reserved tenant holding a
# deployment-scoped role. This is the half of `ast-p2l.7`'s acceptance
# criterion that the tenant checks above do not cover — "an admin seeded".
#
# Asserted against the database rather than over HTTP because the admin API is
# not built yet (`ast-f7m.3`); when it is, the login half of this becomes a
# request like any other. What is *not* deferred is authentication: the server
# verifies the seeded password through the ordinary login verifier at boot and
# refuses to start otherwise, so the log line below is the proof that the
# credential in the database matches the configured one.
if [ -n "$ADMIN_TENANT" ] && command -v docker >/dev/null 2>&1; then
  printf '\ndeployment admin (reserved tenant %s)\n' "$ADMIN_TENANT"

  psql() {
    docker compose -f "$COMPOSE_FILE" exec -T db \
      psql -U asterius -d asterius -tAc "$1" 2>/dev/null | tr -d '[:space:]'
  }

  if [ -z "$(docker compose -f "$COMPOSE_FILE" ps -q db 2>/dev/null || true)" ]; then
    printf '  skip  no running db container to inspect\n'
  else
    expect_eq "the reserved tenant exists and is marked reserved" \
      "$(psql "select is_reserved from tenants where tenant_id = '${ADMIN_TENANT}'")" "t"

    expect_eq "the seeded admin holds a deployment-scoped role" \
      "$(psql "select count(*) from user_roles r
                 join users u on u.tenant_id = r.tenant_id and u.user_id = r.user_id
                where r.tenant_id = '${ADMIN_TENANT}'
                  and u.username = '${ADMIN_USERNAME}'
                  and r.role = 'deployment_admin'")" "1"

    expect_eq "the seeded admin has a password credential" \
      "$(psql "select count(*) from credentials c
                 join users u on u.tenant_id = c.tenant_id and u.user_id = c.user_id
                where c.tenant_id = '${ADMIN_TENANT}'
                  and u.username = '${ADMIN_USERNAME}'
                  and c.kind = 'password'
                  and c.password_hash like '\$argon2id\$%'")" "1"

    # The credential is only as good as the login that accepts it. The server
    # ran that login at boot, against the password the configuration names.
    if docker compose -f "$COMPOSE_FILE" logs "$CONTAINER" 2>/dev/null \
         | grep -q 'deployment admin ready'; then
      pass "the seeded admin authenticated with the configured password at boot"
    else
      fail "the server logged no successful deployment-admin seed"
    fi

    # Protection 1 of ADR-0010, enforced in the database: the cascade that
    # removes an ordinary tenant's users must not be able to reach a deployment
    # admin. Nothing is deleted — the statement is refused.
    psql "delete from tenants where tenant_id = '${ADMIN_TENANT}'" >/dev/null 2>&1 || true
    expect_eq "the reserved tenant refuses to be deleted" \
      "$(psql "select count(*) from tenants where tenant_id = '${ADMIN_TENANT}'")" "1"
  fi
fi

# --- 7. the console signs in, navigates and signs out ------------------------
# Everything above is a request with no session. This is the other half of a
# deployment: an administrator arrives at the console, the login sets a cookie,
# the console reads the admin API with it, and signing out ends it. It runs
# through whatever terminates TLS, because that is where the cookie's `Secure`
# and `__Host-` attributes, the CSRF origin check and the session lookup all
# meet — `ast-8gm` was a 401 on this path that no test outside a browser saw.
#
# ADMIN_PASSWORD is the password the stack was started with; without it there
# is nothing to sign in as, and the section is skipped rather than failed.
ADMIN_PASSWORD="${ADMIN_PASSWORD:-${ASTERIUS_ADMIN_PASSWORD:-}}"
if [ -n "$ADMIN_TENANT" ] && [ -n "$ADMIN_PASSWORD" ]; then
  printf '\nthe console, behind the proxy\n'
  jar="$(mktemp)"
  trap 'rm -f "$jar"' EXIT

  console() {
    curl --silent --show-error "${tls_opts[@]}" \
      --cookie "$jar" --cookie-jar "$jar" \
      --max-time 10 "$@"
  }
  admin_url="${BASE_URL}/t/${ADMIN_TENANT}"

  # The console's entry document redirects anyone without a session to a login
  # interaction. The `Location` is relative, so the tenant prefix survives a
  # proxy that does not rewrite it (tls-and-proxy.md §7).
  location="$(console --dump-header - --output /dev/null "${admin_url}/admin/" \
              | sed -n 's/^[Ll]ocation: *//p' | tr -d '\r')"
  case "$location" in
    ../interaction/*) pass "the console sends an anonymous visitor to a login interaction" ;;
    *) fail "the console entry did not redirect to an interaction: ${location:-<none>}" ;;
  esac
  interaction="${location##*/}"

  page="$(console "${admin_url}/interaction/${interaction}")"
  csrf="$(printf '%s' "$page" | sed -n 's/.*name="csrf" value="\([^"]*\)".*/\1/p')"
  if [ -n "$csrf" ]; then
    pass "the login page renders with a synchroniser token"
  else
    fail "the login page carried no csrf field"
  fi

  console --output /dev/null -X POST "${admin_url}/interaction/${interaction}" \
    --data-urlencode "csrf=${csrf}" \
    --data-urlencode "username=${ADMIN_USERNAME}" \
    --data-urlencode "password=${ADMIN_PASSWORD}" >/dev/null

  if grep -q '__Host-asterius_session' "$jar"; then
    pass "signing in sets the __Host- session cookie"
  else
    fail "signing in set no session cookie"
  fi

  session="$(console -H "Origin: ${BASE_URL}" "${admin_url}/admin/api/v1/session")"
  token="$(json_string "$session" csrf_token)"
  expect_eq "the admin API resolves the session it just issued" \
    "$(json_string "$session" tenant)" "$ADMIN_TENANT"

  # A navigation: the tenant list is a deployment-scoped read, and the tenant
  # the console is signed in to is in it.
  expect_eq "the deployment admin lists the deployment's tenants" \
    "$(console --output /dev/null --write-out '%{http_code}' \
        -H "Origin: ${BASE_URL}" "${admin_url}/admin/api/v1/tenants")" "200"

  # `ast-8gm`: a deployment admin's session lives in the reserved tenant and
  # nowhere else, and a route that acts on *another* tenant is addressed at
  # that tenant's issuer. This answered 401 "the session presented is not
  # usable" until the session was resolved where it is held rather than where
  # the request was routed, which made every client, key and settings screen of
  # every other tenant unreachable for the only administrator a deployment
  # seeds.
  expect_eq "the same session administers another tenant at that tenant's prefix" \
    "$(console --output /dev/null --write-out '%{http_code}' \
        -H "Origin: ${BASE_URL}" "${BASE_URL}/t/${TENANT}/admin/api/v1/clients")" "200"

  # Signing out. A mutation, so it carries the synchroniser token the session
  # endpoint just handed out (ADR-0009). 200 and a body rather than 204: the
  # response also carries the clearing `Set-Cookie`, which is the half of a
  # sign-out the console cannot do for itself.
  expect_eq "signing out is accepted" \
    "$(console --output /dev/null --write-out '%{http_code}' \
        -X DELETE -H "Origin: ${BASE_URL}" -H "X-CSRF-Token: ${token}" \
        "${admin_url}/admin/api/v1/session")" "200"

  # And what the browser kept is no longer a session: the row is revoked, so
  # the next call is a 401 whatever cookie is still in the jar.
  expect_eq "the ended session no longer authenticates" \
    "$(console --output /dev/null --write-out '%{http_code}' \
        -H "Origin: ${BASE_URL}" "${admin_url}/admin/api/v1/session")" "401"

  rm -f "$jar"
  trap - EXIT
fi

# --- 8. a refused client authentication is diagnosable ----------------------
# `ast-4j1`: a BFF posted a PAR with no `client_assertion` at all, got the
# correct 401 invalid_client, and the IdP wrote *nothing* — no log line at any
# level, no audit row. "The client is refused and the server is silent" is not
# a smaller bug than a wrong refusal; it is the one that costs a day.
#
# Two shapes are exercised, both from outside, both through the proxy, and
# neither needs a key: no credential at all, and a credential that is not a
# JWT. The response must stay RFC 6749 §5.2 — one code, no detail — and the
# log must carry the internal reason.
printf '\nclient authentication refusals are logged (ast-4j1)\n'

par_body() {
  curl --silent --show-error "${tls_opts[@]}" \
    --header "Host: ${HOST_HEADER}" \
    --header 'Content-Type: application/x-www-form-urlencoded' \
    --max-time 10 --write-out '\n%{http_code}' \
    --data "$1" "${BASE_URL}/t/${TENANT}/par"
}

# Exactly what the reported BFF sent: the authorization parameters, and no
# credential of any kind.
unauthenticated="$(par_body 'response_type=code&client_id=c.smoke-test-no-credential&redirect_uri=https://localhost:8080/bff/callback&scope=openid&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256')"
expect_eq "a PAR with no client authentication is 401" \
  "$(tail -n 1 <<<"$unauthenticated")" "401"
if grep -q '"error"[[:space:]]*:[[:space:]]*"invalid_client"' <<<"$unauthenticated"; then
  pass "the refusal is invalid_client"
else
  fail "the refusal was not invalid_client: ${unauthenticated}"
fi
# RFC 6749 §5.2: the client learns the code and nothing else. A body that
# started explaining which check failed would be an oracle for an
# unauthenticated caller.
case "$unauthenticated" in
  *no_client_authentication_presented*|*unknown_or_disabled_client*)
    fail "the HTTP response leaked the internal reason: ${unauthenticated}" ;;
  *) pass "the response body carries no internal reason" ;;
esac

# A `client_assertion` that is not a JWT: same 401, different internal reason.
garbage="$(par_body 'response_type=code&client_id=c.smoke-test-bad-assertion&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer&client_assertion=not-a-jwt&redirect_uri=https://localhost:8080/bff/callback&scope=openid')"
expect_eq "a PAR with a malformed assertion is 401" \
  "$(tail -n 1 <<<"$garbage")" "401"

# And the operator's half. `warn` clears the deployed filter (asterius=info),
# so this must be visible with no RUST_LOG set — that is the difference
# between a diagnosis and a field in a struct.
if [ -n "$CONTAINER" ] && command -v docker >/dev/null 2>&1 \
   && [ -n "$(docker compose -f "$COMPOSE_FILE" ps -q "$CONTAINER" 2>/dev/null || true)" ]; then
  logs="$(docker compose -f "$COMPOSE_FILE" logs --no-log-prefix "$CONTAINER" 2>/dev/null || true)"

  if grep -q 'client authentication failed' <<<"$logs"; then
    pass "the server logged the refusal at the default filter level"
  else
    fail "the server logged nothing for a refused client authentication"
  fi

  if grep -q 'no_client_authentication_presented' <<<"$logs"; then
    pass "the log names the reason for the missing credential"
  else
    fail "the log does not say why the credential-less request was refused"
  fi

  if grep -q 'assertion_signature_or_envelope_rejected' <<<"$logs"; then
    pass "the log names the reason for the malformed assertion"
  else
    fail "the log does not distinguish a malformed assertion from a missing one"
  fi

  if grep -q 'c.smoke-test-no-credential' <<<"$logs"; then
    fail "the log claims a client_id the request never authenticated as"
  else
    pass "an unauthenticated request is not attributed to a client"
  fi

  # The refusal is in the trail too, not only in a stream nobody kept.
  if [ -n "$(docker compose -f "$COMPOSE_FILE" ps -q db 2>/dev/null || true)" ]; then
    trail() {
      docker compose -f "$COMPOSE_FILE" exec -T db \
        psql -U asterius -d asterius -tAc "$1" 2>/dev/null | tr -d '[:space:]'
    }
    if [ "$(trail "select count(*) from audit_events
                     where tenant_id = '${TENANT}'
                       and event_type = 'client.auth_failed'")" -gt 0 ] 2>/dev/null; then
      pass "the refusal reached the audit trail as client.auth_failed"
    else
      fail "no client.auth_failed audit record was written"
    fi
  fi
fi

# --- 9. the container is hardened -------------------------------------------
# Asserted through `docker inspect` rather than by running anything inside the
# container: there is nothing in there to run, which is the point.
if [ -n "$CONTAINER" ] && command -v docker >/dev/null 2>&1; then
  printf '\ncontainer hardening\n'
  id="$(docker compose -f "$COMPOSE_FILE" ps -q "$CONTAINER" 2>/dev/null || true)"
  if [ -z "$id" ]; then
    printf '  skip  no running %s container to inspect\n' "$CONTAINER"
  else
    expect_eq "runs as a non-root uid" \
      "$(docker inspect -f '{{.Config.User}}' "$id")" "65532:65532"
    expect_eq "root filesystem is read-only" \
      "$(docker inspect -f '{{.HostConfig.ReadonlyRootfs}}' "$id")" "true"
    expect_eq "every capability is dropped" \
      "$(docker inspect -f '{{.HostConfig.CapDrop}}' "$id")" "[ALL]"
    # No shell: `docker exec sh` cannot start, so the exec fails outright.
    if docker exec "$id" /bin/sh -c 'exit 0' >/dev/null 2>&1; then
      fail "the image ships a shell at /bin/sh"
    else
      pass "the image ships no shell"
    fi
  fi
fi

printf '\n'
if [ "$failures" -eq 0 ]; then
  printf 'smoke test passed\n'
else
  printf 'smoke test failed: %d check(s)\n' "$failures" >&2
  exit 1
fi
