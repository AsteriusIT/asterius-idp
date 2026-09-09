#!/usr/bin/env bash
# Runs the OpenID Foundation conformance suite against a freshly built Asterius.
#
# `ast-83p.8`: every FAPI 2.0 claim in this repository is, until this script
# runs, our own reading of the specifications checked by our own tests. This is
# the outside judge. What it reports is the point; whether it is green is not
# this script's business.
#
#     make conformance                 build, run the FAPI2 SP Final plan, tear down
#     make conformance-keep            same, but leave the stack up to inspect
#     ./scripts/conformance.sh --help  the options below
#
# It fails loudly rather than quietly:
#
#   * the suite checkout is pinned by tag *and* by commit, and the two images by
#     digest. A pin that moved is an error, not a shrug — see `ast-yxu`, where an
#     unpinned tool changed its output format and a gate went green on nothing.
#   * a suite that does not answer its API within the timeout is an error.
#   * an Asterius that is not ready within the timeout is an error.
#   * zero test modules executed, or a run in which not one module reached
#     FINISHED, is an error however happy the exit code.
#   * a result whose status the report gate does not recognise is an error,
#     because an unrecognised status is a report format we can no longer read.
#
# Environment (all optional):
#   CONFORMANCE_PLAN            plan name with variants. Default: the FAPI2
#                               Security Profile Final plan, private_key_jwt +
#                               DPoP, OpenID Connect, static clients.
#   CONFORMANCE_HTTPS_PORT      host port for the suite's UI. Default 8443.
#   CONFORMANCE_ASTERIUS_PORT   host port for Asterius. Default 9543.
#   CONFORMANCE_TIMEOUT         seconds to wait for each service. Default 300.
#   CONFORMANCE_SUITE_DIR       where the suite is checked out.
#                               Default conformance/.suite
#
# Reports are always written to conformance/.run/results, which is where the
# compose file mounts the runner's /results.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

# --- the pin ----------------------------------------------------------------
# Update these four together, and only these four. `conformance/README.md`
# documents how. The commit and the digests exist because a tag is a mutable
# name on a server we do not control.
SUITE_VERSION="release-v5.2.4"
SUITE_COMMIT="ab35a8df4864da35b49eff11483e204e01aa7961"
SUITE_SERVER_DIGEST="sha256:3a2615ed95a7f3bb92d545b4c65c0268f82a3893d6cd97fd98fd8e44eb15d81f"
SUITE_NGINX_DIGEST="sha256:43d34ca84e30669ebb30c5cdeb80b3f90bea0f5c47a446e915d843bd7dd3cf04"
SUITE_REPO="https://gitlab.com/openid/conformance-suite.git"

# --- the deployment under test ---------------------------------------------
TENANT="conformance"
# The authority in the tenant's issuer, which is also the compose service name,
# the SAN in the run certificate and the name taught to the JVM truststore.
# Changing one of those means changing all four.
HOST="asterius:9443"
USERNAME="conformance@example.test"
# Argon2id, m=19456 t=2 p=1, of "correct horse battery staple". The same
# constant as e2e/fixtures/seed.sql, whose file this reuses; see the note there
# for why it is a constant rather than something computed at seed time.
PASSWORD_HASH='$argon2id$v=19$m=19456,t=2,p=1$YnJvd3Nlci1zd2VlcC1zYWx0$E8awnsfATh5sLXjht+SvAdX9BEFVTWfDYThAb/+KOfs'
# The suite's callback for the test alias in conformance/plans/fapi2-sp-final.json.
# Byte for byte what the clients register: ADR-0005 matches exactly.
REDIRECT_URI="https://localhost.emobix.co.uk:8443/test/a/asterius/callback"
# The suite appends these two dummy parameters to the callback for its second
# client, deliberately: a redirect URI with a query component is legal and a
# server has to match it whole. Registered as a second URI rather than
# hand-waved, because an exact matcher will not meet it half way.
REDIRECT_URI_WITH_QUERY="${REDIRECT_URI}?dummy1=lorem&dummy2=ipsum"

# The suite names its own variants, and it rejects a name it does not know
# rather than ignoring it — which is how this pin was arrived at rather than
# guessed. `client_registration` and `server_metadata` are *not* variants of
# this plan: whether the clients are static is decided by the configuration
# carrying a `client_id`, which conformance/plans/fapi2-sp-final.json does.
# `authorization_request_type=simple` is plain scopes rather than RFC 9396
# `authorization_details`. `fapi_request_method` and `fapi_response_mode` are
# not set either: the Security Profile plan fixes both itself (the suite says
# so, in as many words, if you try), and Message Signing is the other plan —
# see "What is not covered" in conformance/README.md.
DEFAULT_PLAN="fapi2-security-profile-final-test-plan[openid=openid_connect][client_auth_type=private_key_jwt][sender_constrain=dpop][fapi_profile=plain_fapi][authorization_request_type=simple]"

PLAN="${CONFORMANCE_PLAN:-$DEFAULT_PLAN}"
TIMEOUT="${CONFORMANCE_TIMEOUT:-300}"
ASTERIUS_PORT="${CONFORMANCE_ASTERIUS_PORT:-9543}"
HTTPS_PORT="${CONFORMANCE_HTTPS_PORT:-8443}"
SUITE_DIR="${CONFORMANCE_SUITE_DIR:-$root/conformance/.suite}"
RUN_DIR="$root/conformance/.run"
RESULTS_DIR="$RUN_DIR/results"
COMPOSE_FILE="$root/conformance/docker-compose.yml"

keep=0
for arg in "$@"; do
  case "$arg" in
    --keep) keep=1 ;;
    --help|-h)
      sed -n '2,36p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      printf 'conformance: unknown argument %s\n' "$arg" >&2
      exit 64
      ;;
  esac
done

step() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
die()  { printf '\nconformance: %s\n' "$*" >&2; exit "${2:-1}"; }

compose() {
  CONFORMANCE_SUITE_VERSION="$SUITE_VERSION" \
  CONFORMANCE_RUNNER_USER="$(id -u):$(id -g)" \
  CONFORMANCE_SUITE_DIR="$SUITE_DIR" \
  CONFORMANCE_HTTPS_PORT="$HTTPS_PORT" \
  CONFORMANCE_ASTERIUS_PORT="$ASTERIUS_PORT" \
    docker compose -f "$COMPOSE_FILE" "$@"
}

cleanup() {
  status=$?
  if [ "$keep" -eq 1 ]; then
    printf '\nthe stack is still up (--keep). Tear it down with:\n'
    printf '  docker compose -f %s down --volumes --remove-orphans\n' "$COMPOSE_FILE"
  else
    compose down --volumes --remove-orphans >/dev/null 2>&1 || true
  fi
  exit "$status"
}
trap cleanup EXIT

# --- 0. prerequisites -------------------------------------------------------
step "prerequisites"
for tool in docker git openssl curl python3; do
  command -v "$tool" >/dev/null 2>&1 || die "$tool is required" 69
done
docker compose version >/dev/null 2>&1 || die "docker compose v2 is required" 69
printf 'docker, git, openssl and curl are present\n'

# --- 1. the suite, pinned ---------------------------------------------------
# A checkout rather than a tarball because the runner needs the whole scripts/
# directory, and a checkout is what "how do I update this" has an answer for.
step "conformance suite ${SUITE_VERSION}"
if [ ! -d "$SUITE_DIR/.git" ]; then
  printf 'cloning %s at %s\n' "$SUITE_REPO" "$SUITE_VERSION"
  git clone --quiet --depth 1 --branch "$SUITE_VERSION" "$SUITE_REPO" "$SUITE_DIR" \
    || die "could not clone the conformance suite. It is a third-party repository; see conformance/README.md" 69
fi
have_commit="$(git -C "$SUITE_DIR" rev-parse HEAD)"
if [ "$have_commit" != "$SUITE_COMMIT" ]; then
  printf 'fetching %s\n' "$SUITE_VERSION"
  git -C "$SUITE_DIR" fetch --quiet --depth 1 origin "$SUITE_COMMIT" 2>/dev/null \
    || git -C "$SUITE_DIR" fetch --quiet --depth 1 origin "refs/tags/${SUITE_VERSION}:refs/tags/${SUITE_VERSION}" \
    || die "could not fetch ${SUITE_VERSION} from ${SUITE_REPO}" 69
  git -C "$SUITE_DIR" checkout --quiet "$SUITE_COMMIT" \
    || die "the tag ${SUITE_VERSION} no longer points at ${SUITE_COMMIT}. The pin moved; see conformance/README.md" 70
  have_commit="$(git -C "$SUITE_DIR" rev-parse HEAD)"
fi
[ "$have_commit" = "$SUITE_COMMIT" ] \
  || die "the suite checkout is at ${have_commit}, not the pinned ${SUITE_COMMIT}" 70
[ -f "$SUITE_DIR/scripts/run-test-plan.py" ] \
  || die "the suite checkout has no scripts/run-test-plan.py; the harness would run nothing" 70
printf 'checked out %s (%s)\n' "$SUITE_VERSION" "$SUITE_COMMIT"

# The images are the suite's own published ones, so nothing here builds Java.
# Verified by digest afterwards: a re-pointed tag must stop the run rather than
# silently test a different suite.
compose pull --quiet nginx server \
  || die "could not pull the conformance suite images" 69
for pair in "registry.gitlab.com/openid/conformance-suite:${SUITE_VERSION} ${SUITE_SERVER_DIGEST}" \
            "registry.gitlab.com/openid/conformance-suite/nginx:${SUITE_VERSION} ${SUITE_NGINX_DIGEST}"; do
  set -- $pair
  got="$(docker image inspect --format '{{index .RepoDigests 0}}' "$1" | sed 's/.*@//')"
  [ "$got" = "$2" ] \
    || die "$1 is ${got}, not the pinned $2. The tag moved; see conformance/README.md" 70
done
printf 'both suite images match their pinned digests\n'

# --- 2. a certificate for the run ------------------------------------------
# FAPI 2.0 SP §5.2 requires TLS on every endpoint, so the harness cannot run
# the server on cleartext the way the example compose stack does. Same openssl
# invocation as scripts/browser-tests.sh.
step "certificate"
# The results of the previous run go first. They are reports of a different
# server, and an archive holding both is an archive nobody can read a verdict
# out of.
rm -rf "$RESULTS_DIR"
mkdir -p "$RUN_DIR/tls" "$RESULTS_DIR"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
  -keyout "$RUN_DIR/tls/key.pem" -out "$RUN_DIR/tls/cert.pem" \
  -days 1 -nodes -subj '/CN=asterius' \
  -addext 'subjectAltName=DNS:asterius' 2>/dev/null \
  || die "openssl could not issue the run certificate"
# The container runs as uid 65532 with a read-only root filesystem and has to
# read both halves.
chmod 0644 "$RUN_DIR/tls/key.pem" "$RUN_DIR/tls/cert.pem"
printf 'issued a one-day certificate for DNS:asterius\n'

# The JVM has never heard of that certificate. Its own cacerts plus this one:
# the public roots stay, because the suite also fetches its own base URL, whose
# certificate is a real one.
rm -f "$RUN_DIR/truststore.p12"
docker run --rm --entrypoint /bin/sh \
  -v "$RUN_DIR:/work" \
  "registry.gitlab.com/openid/conformance-suite:${SUITE_VERSION}" \
  -c 'cp "$JAVA_HOME/lib/security/cacerts" /work/truststore.p12 &&
      keytool -importcert -noprompt -alias asterius-conformance \
        -keystore /work/truststore.p12 -storepass changeit \
        -file /work/tls/cert.pem >/dev/null &&
      chmod 0644 /work/truststore.p12' \
  || die "could not build the Java truststore the suite needs to trust Asterius"
printf 'built a truststore the suite will trust Asterius with\n'

# --- 3. the stack -----------------------------------------------------------
step "stack"
compose up --build --detach --wait db mongodb server nginx asterius \
  || die "the conformance stack did not come up"

# --- 4. Asterius is ready ---------------------------------------------------
# Readiness is false until the database answers and every migration compiled
# into the binary is recorded applied, so a green /readyz is the proof that
# migrations-on-start worked. `--insecure`: the certificate above is trusted by
# the suite, not by this shell.
step "asterius"
deadline=$(($(date +%s) + TIMEOUT))
until [ "$(curl --silent --insecure --output /dev/null --write-out '%{http_code}' \
             --max-time 5 "https://127.0.0.1:${ASTERIUS_PORT}/readyz" 2>/dev/null)" = "200" ]; do
  if [ "$(date +%s)" -ge "$deadline" ]; then
    compose logs --tail 100 asterius >&2 || true
    die "asterius /readyz did not answer 200 within ${TIMEOUT}s" 71
  fi
  sleep 2
done
printf 'asterius /readyz answers 200\n'

# --- 5. the fixtures --------------------------------------------------------
# After the server, not before: booting upserts the configured tenants, and
# that upsert writes `custom_host` back to NULL. See e2e/fixtures/seed.sql.
step "fixtures"
seed() {
  compose exec -T db psql -U asterius -d asterius \
    --quiet --no-psqlrc -v ON_ERROR_STOP=1 "$@"
}
seed -v "tenant=${TENANT}" -v "host=${HOST}" \
     -v "username=${USERNAME}" -v "hash=${PASSWORD_HASH}" \
     -f - < "$root/e2e/fixtures/seed.sql" \
  || die "could not seed the conformance user"
printf 'seeded tenant %s and user %s\n' "$TENANT" "$USERNAME"

# The clients' public keys are derived from the plan configuration's private
# ones rather than kept beside them: two copies of a key is a way for the table
# and the suite to disagree, and every test would then fail for that one reason.
public_jwks() {
  python3 "$root/conformance/fixtures/public-jwks.py" "$plan_config" "$1" \
    || die "could not read ${1}'s JWKS out of ${plan_config}" 70
}
plan_config="$root/conformance/plans/fapi2-sp-final.json"
seed -v "tenant=${TENANT}" -v "redirect_uri=${REDIRECT_URI}" -v "host=${HOST}" \
     -v "redirect_uri_with_query=${REDIRECT_URI_WITH_QUERY}" \
     -v "jwks1=$(public_jwks client)" \
     -v "jwks2=$(public_jwks client2)" \
     -f - < "$root/conformance/fixtures/clients.sql" \
  || die "could not seed the conformance clients"
printf 'seeded 2 clients with the suite JWKS and redirect_uri %s\n' "$REDIRECT_URI"

# --- 6. the suite is ready --------------------------------------------------
step "conformance suite"
deadline=$(($(date +%s) + TIMEOUT))
# `--insecure`: the suite's ingress presents a certificate it generated for
# itself. Nothing here trusts it on purpose — the transport being checked in
# this run is Asterius's, not the harness's.
until [ "$(curl --silent --insecure --output /dev/null --write-out '%{http_code}' --max-time 5 \
             "https://127.0.0.1:${HTTPS_PORT}/api/runner/available" 2>/dev/null)" = "200" ]; do
  if [ "$(date +%s)" -ge "$deadline" ]; then
    compose logs --tail 100 server >&2 || true
    die "the conformance suite API did not answer within ${TIMEOUT}s" 71
  fi
  sleep 2
done
printf 'the suite API answers at https://127.0.0.1:%s/\n' "$HTTPS_PORT"

# --- 7. the plan ------------------------------------------------------------
step "plan"
printf '%s\n' "$PLAN"
# Read back by the gate below, so that a second run against a stack left up by
# `--keep` reports on this run and not on the one before it.
# No trailing `Z`: the suite records `started` with fractional seconds, and a
# plain prefix comparison then puts a plan from this very second on the right
# side of the line. With the `Z` on the end, `.6…` sorts before `Z` and this
# run's own plan would be filtered out as old.
started="$(date -u +%Y-%m-%dT%H:%M:%S)"
rc=0
compose run --rm --quiet-pull runner /runner/run.sh "$PLAN" || rc=$?
printf '\nrun-test-plan exit code: %d\n' "$rc"

# --- 8. the gate ------------------------------------------------------------
# Whatever the runner said, the results are read back from the suite's own API:
# a run that executed no module, or one whose statuses this gate cannot read,
# is a failure even when everything else looked fine.
step "results"
gate=0
compose run --rm --quiet-pull \
  --env "CONFORMANCE_SINCE=${started}" \
  --entrypoint python3 runner /runner/report.py || gate=$?

if [ "$gate" -ne 0 ]; then
  die "the conformance run produced no usable result (gate exit ${gate})" "$gate"
fi
if [ "$rc" -ne 0 ]; then
  die "the conformance plan reported failures. The reports are in ${RESULTS_DIR}" "$rc"
fi
printf '\nconformance run passed. Reports in %s\n' "$RESULTS_DIR"
