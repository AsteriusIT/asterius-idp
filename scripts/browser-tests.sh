#!/usr/bin/env bash
# Runs the Playwright browser sweep against a server this script starts.
#
# `ast-2vk.14`: prove in a real browser what no source-level check can — that
# the login, consent and redirect pages work with JavaScript disabled, that
# Chromium keeps the `__Host-` cookie we write, and that no page in the sweep
# provokes a Content-Security-Policy violation.
#
#     ./scripts/browser-tests.sh                 everything
#     ./scripts/browser-tests.sh --project=no-js just the no-JS suite
#     ./scripts/browser-tests.sh --headed        watch it happen
#
# Arguments are passed through to `playwright test`.
#
# The shape is `scripts/smoke-test.sh`'s: start something, poll `/readyz` until
# the migrations are recorded applied, then make assertions from outside the
# process. The database is the one `docker-compose.yml` already provides for the
# integration tests — this script starts no second one.
#
# Environment:
#   DATABASE_URL  PostgreSQL. Default postgres://asterius:asterius@127.0.0.1:5433/asterius
#   E2E_PORT      where the server under test listens. Default 9444
#   ASTERIUS_BIN  a prebuilt server binary. Default: cargo builds one
#   E2E_RESET_DB  set to 1 to drop and recreate the public schema first
#   TIMEOUT       seconds to wait for readiness. Default 120
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

PORT="${E2E_PORT:-9444}"
DATABASE_URL="${DATABASE_URL:-postgres://asterius:asterius@127.0.0.1:5433/asterius}"
TIMEOUT="${TIMEOUT:-120}"
BASE_URL="https://127.0.0.1:${PORT}"

# The tenant, the user and the password. The suite defaults to the same values
# in e2e/src/environment.ts; they are passed explicitly so that changing one
# here changes it in one place.
TENANT="e2e"
# The second tenant, whose only reason to exist is that its issuer names a host
# rather than an address: an IP literal is not a valid WebAuthn RP ID, so the
# ceremony cannot run on the tenant above. See e2e/fixtures/asterius.toml.in.
WEBAUTHN_TENANT="e2e-webauthn"
WEBAUTHN_BASE_URL="https://localhost:${PORT}"
USERNAME="sweep@example.test"
PASSWORD="correct horse battery staple"
# Argon2id, m=19456 t=2 p=1, of the password above. See e2e/fixtures/seed.sql.
PASSWORD_HASH='$argon2id$v=19$m=19456,t=2,p=1$YnJvd3Nlci1zd2VlcC1zYWx0$E8awnsfATh5sLXjht+SvAdX9BEFVTWfDYThAb/+KOfs'
# Development KEK: 32 bytes of ASCII that spell out what they are, as in
# deploy/compose/docker-compose.yml.
export ASTERIUS_KEK="YXN0ZXJpdXMtZGV2LWtlay1ub3QtYS1zZWNyZXQhISE="

run_dir="$(mktemp -d)"
server_pid=""

cleanup() {
  if [ -n "$server_pid" ] && kill -0 "$server_pid" 2>/dev/null; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  rm -rf "$run_dir"
}
trap cleanup EXIT

step() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

# Runs psql, through the compose database when no client is installed locally.
# A CI runner has `psql`; a developer's machine often only has the container.
psql_run() {
  if command -v psql >/dev/null 2>&1; then
    psql "$DATABASE_URL" "$@"
  else
    docker compose exec -T db psql -U asterius -d asterius "$@"
  fi
}

# --- 1. the database --------------------------------------------------------
step "database"
if ! psql_run -c 'select 1' >/dev/null 2>&1; then
  printf 'starting the compose database\n'
  docker compose up -d --wait db
fi
if [ "${E2E_RESET_DB:-}" = "1" ]; then
  # CONTRIBUTING.md's recipe. Needed when a local database predates a change to
  # the baseline migration, which is not a failure this suite should have to
  # diagnose in its own error messages.
  psql_run -c 'drop schema public cascade; create schema public;'
fi

# --- 2. a certificate, so the origin is really secure -----------------------
# The `__Host-` prefix is browser-enforced and its first condition is that the
# cookie was set over a secure origin. Same invocation as
# `crates/server/tests/tls_handshake.rs`, which is where this server's TLS is
# otherwise asserted.
step "certificate"
if ! command -v openssl >/dev/null 2>&1; then
  printf 'openssl is required to issue the run certificate\n' >&2
  exit 1
fi
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
  -keyout "$run_dir/key.pem" -out "$run_dir/cert.pem" \
  -days 1 -nodes -subj '/CN=127.0.0.1' \
  -addext 'subjectAltName=IP:127.0.0.1,DNS:localhost' 2>/dev/null
printf 'issued a one-day certificate for 127.0.0.1\n'

# --- 3. the configuration ---------------------------------------------------
step "configuration"
sed -e "s|@PORT@|${PORT}|g" \
    -e "s|@CERTIFICATE@|${run_dir}/cert.pem|g" \
    -e "s|@PRIVATE_KEY@|${run_dir}/key.pem|g" \
    -e "s|@DATABASE_URL@|${DATABASE_URL}|g" \
    e2e/fixtures/asterius.toml.in > "$run_dir/asterius.toml"

# --- 4. the server ----------------------------------------------------------
step "server"
binary="${ASTERIUS_BIN:-}"
if [ -z "$binary" ]; then
  cargo build --bin asterius
  binary="$(cargo metadata --format-version 1 --no-deps \
    | sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p')/debug/asterius"
fi
"$binary" --config "$run_dir/asterius.toml" >"$run_dir/server.log" 2>&1 &
server_pid=$!

deadline=$(($(date +%s) + TIMEOUT))
until [ "$(curl --silent --insecure --output /dev/null --write-out '%{http_code}' \
             --max-time 5 "${BASE_URL}/readyz" 2>/dev/null)" = "200" ]; do
  if ! kill -0 "$server_pid" 2>/dev/null; then
    printf 'the server exited before it was ready:\n' >&2
    cat "$run_dir/server.log" >&2
    exit 1
  fi
  if [ "$(date +%s)" -ge "$deadline" ]; then
    printf '/readyz did not answer 200 within %ss:\n' "$TIMEOUT" >&2
    cat "$run_dir/server.log" >&2
    exit 1
  fi
  sleep 1
done
printf '%s/readyz answers 200\n' "$BASE_URL"

# The WebAuthn tenant is reached by name, and the server bound one address. If
# `localhost` resolves somewhere that is not the socket above, every ceremony
# in the sweep fails for a reason that has nothing to do with the code — which
# is precisely the hazard the note in the fixture warns about. Say so here,
# once, instead of letting it surface as a browser timeout.
if [ "$(curl --silent --insecure --output /dev/null --write-out '%{http_code}' \
          --max-time 5 "${WEBAUTHN_BASE_URL}/readyz" 2>/dev/null)" != "200" ]; then
  printf '%s/readyz does not answer, so `localhost` does not reach the server socket.\n' \
    "$WEBAUTHN_BASE_URL" >&2
  printf 'The WebAuthn tenant needs a name for its RP ID; check what localhost resolves to.\n' >&2
  exit 1
fi
printf '%s/readyz answers 200 as well\n' "$WEBAUTHN_BASE_URL"

# --- 5. the fixture data ----------------------------------------------------
# After the server, not before: booting upserts the configured tenants, and that
# upsert writes `custom_host` back to NULL. See e2e/fixtures/seed.sql.
step "fixtures"
psql_run --quiet --no-psqlrc \
  -v ON_ERROR_STOP=1 \
  -v "tenant=${TENANT}" \
  -v "host=127.0.0.1:${PORT}" \
  -v "username=${USERNAME}" \
  -v "hash=${PASSWORD_HASH}" \
  -f - < e2e/fixtures/seed.sql
printf 'seeded tenant %s and user %s\n' "$TENANT" "$USERNAME"

# The same fixture again, for the WebAuthn tenant. Not a second file: the seed
# is parameterised by tenant already, its identifiers are primary-key-scoped to
# one, and a copy would be a second place to forget to change the password.
psql_run --quiet --no-psqlrc \
  -v ON_ERROR_STOP=1 \
  -v "tenant=${WEBAUTHN_TENANT}" \
  -v "host=localhost:${PORT}" \
  -v "username=${USERNAME}" \
  -v "hash=${PASSWORD_HASH}" \
  -f - < e2e/fixtures/seed.sql
printf 'seeded tenant %s and user %s\n' "$WEBAUTHN_TENANT" "$USERNAME"

# --- 6. the sweep -----------------------------------------------------------
step "playwright"
cd "$root/e2e"
npm ci --no-audit --no-fund
if [ -n "${CI:-}" ]; then
  npx playwright install --with-deps chromium
else
  npx playwright install chromium
fi

E2E_BASE_URL="$BASE_URL" \
E2E_WEBAUTHN_BASE_URL="$WEBAUTHN_BASE_URL" \
E2E_USERNAME="$USERNAME" \
E2E_PASSWORD="$PASSWORD" \
  npx playwright test "$@"
