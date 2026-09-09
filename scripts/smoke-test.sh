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
#   BASE_URL   where to reach the server. Default http://127.0.0.1:9443
#   ISSUER     the issuer the tenant must announce.
#              Default https://localhost:9443/t/demo
#   TENANT     the tenant id. Default demo
#   TIMEOUT    seconds to wait for readiness. Default 90
#   CONTAINER  compose service to inspect for the container hardening checks.
#              Default asterius; set to "" to skip them.
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:9443}"
TENANT="${TENANT:-demo}"
ISSUER="${ISSUER:-https://localhost:9443/t/${TENANT}}"
TIMEOUT="${TIMEOUT:-90}"
CONTAINER="${CONTAINER:-asterius}"
COMPOSE_FILE="${COMPOSE_FILE:-$(dirname "$0")/../deploy/compose/docker-compose.yml}"

# The `Host` header decides which tenant a request is speaking to, and it has
# to be the issuer's authority even when the transport is plain HTTP.
HOST_HEADER="${HOST_HEADER:-$(printf '%s' "$ISSUER" | sed -e 's#^https\?://##' -e 's#/.*##')}"

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
    --header "Host: ${HOST_HEADER}" \
    --max-time 10 \
    "${BASE_URL}$1"
}

status_of() {
  curl --silent --output /dev/null --write-out '%{http_code}' \
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

# --- 6. the container is hardened -------------------------------------------
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
