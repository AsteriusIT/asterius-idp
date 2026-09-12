# Load scripts

What is here, and what each measures:

| Script | Drives | One iteration is |
| --- | --- | --- |
| `token-client-credentials.js` | `POST /token` | one `client_credentials` request: `private_key_jwt` assertion, DPoP proof, both fresh |
| `code-flow.js` | PAR → `/authorize` → sign-in → consent → `/token` | one person signing in to one client, with PKCE and a DPoP key pinned at the push and presented at redemption |
| `ssf-poll.js` | `POST /ssf/poll/{stream}` | one receiver poll with `returnImmediately`, DPoP-bound token with `ath` |
| `introspection.js` | `POST /introspect` | one RFC 7662 request: `private_key_jwt` assertion, then the four reads the endpoint makes whatever the answer. `SCAN=1` asks about a value nothing issued — the path RFC 7662 §4's attacker takes, which by design is not the cheap one |
| `explain.sh` | the database | `EXPLAIN (ANALYZE, BUFFERS)` of the hot statements on a seeded, throwaway database, and a verdict on sequential scans |

The measurements taken with them, and the pool-sizing guidance they led to,
are in [`docs/performance.md`](../../docs/performance.md).

## Why k6, and why not `oha`

Every FAPI 2.0 endpoint here refuses a replayed credential: a client
assertion's `jti` is single-use (RFC 7523 §3 item 7) and so is a DPoP proof's
(RFC 9449 §11.1), and both are checked against the database. A tool that
replays one request body — `oha`, `wrk`, `ab` — therefore measures the
*refusal* path after its first request, which is a real number (it is the
cost an attacker imposes) but not the one a capacity plan needs. The scripts
build a fresh ES256 assertion and a fresh proof per request with k6's
WebCrypto, so every request is one the server accepts.

k6 is a single static binary: <https://github.com/grafana/k6/releases>. The
scripts were written against v2.2.0 and use nothing outside the WebCrypto and
`k6/encoding` modules.

## Two stacks

**The process, on this machine.** This is what the published numbers were
taken on, and the shape to reproduce them in: one `asterius` release binary
terminating TLS, one PostgreSQL with default durability, both on the host.

```sh
# 1. a database with fsync on — the tmpfs one in docker-compose.yml is for tests
docker run -d --name asterius-load-pg -p 127.0.0.1:5434:5432 \
  -e POSTGRES_USER=asterius -e POSTGRES_PASSWORD=asterius -e POSTGRES_DB=asterius postgres:16-alpine

# 2. a certificate for localhost, the client's signing key, the binary
CERT_DIR=scripts/load/certs ./deploy/scripts/gen-self-signed.sh
./scripts/load/gen-keys.sh
SQLX_OFFLINE=true cargo build --release --bin asterius

# 3. the process; it migrates the database on start
export ASTERIUS_KEK="$(head -c 32 /dev/urandom | base64)"
export ASTERIUS_ADMIN_PASSWORD="$(head -c 24 /dev/urandom | base64)"
./target/release/asterius --config scripts/load/asterius-load.toml &

# 4. the clients and the person the scripts act as
psql postgres://asterius:asterius@127.0.0.1:5434/asterius \
  -v tenant=load -v issuer=https://localhost:9443/t/load \
  -v jwks="$(cat scripts/load/client.jwks.json)" -f scripts/load/seed.sql

# 5. the runs
cd scripts/load
k6 run --insecure-skip-tls-verify -e CLIENT_ID=load-machine --vus 16 --duration 60s token-client-credentials.js
k6 run --insecure-skip-tls-verify -e CLIENT_ID=load-client  --vus 16 --duration 60s code-flow.js
k6 run --insecure-skip-tls-verify -e CLIENT_ID=load-receiver --vus 8 --duration 30s ssf-poll.js
k6 run --insecure-skip-tls-verify -e CLIENT_ID=load-machine --vus 16 --duration 60s introspection.js
```

`asterius-load.toml` is that stack's configuration, and it is not a
production one: the `[limits]` are raised out of the way (the defaults would
throttle a run at 100 req/s after twelve seconds, which is what they are
for), and every secret comes from the environment.

**The example compose stack.** `deploy/compose` runs the container image
behind nginx, which is the shape a deployment has and the one to measure when
the question is the image or the proxy rather than the process. The scripts
run against it unchanged; what differs is the plumbing:

```sh
export ASTERIUS_ADMIN_PASSWORD="$(head -c 24 /dev/urandom | base64)"
docker compose -f deploy/compose/docker-compose.yml up --build -d
./scripts/load/gen-keys.sh
docker compose -f deploy/compose/docker-compose.yml exec -T db \
  psql -U asterius -d asterius -v tenant=demo -v issuer=https://localhost/t/demo \
  -v jwks="$(cat scripts/load/client.jwks.json)" -f - < scripts/load/seed.sql
cd scripts/load
k6 run --insecure-skip-tls-verify -e BASE_URL=https://localhost -e ISSUER=https://localhost/t/demo \
  -e CLIENT_ID=load-machine --vus 16 --duration 60s token-client-credentials.js
```

Two caveats there. The stack's `asterius.toml` carries the default
`[limits]`, so a run is throttled at 1200 successful token responses per
client per minute — raise `limits.token_per_client` and `par_per_client` in
`deploy/compose/asterius.toml` for the duration, or read the 429s as the
finding they are. And `ssf-poll.js` needs `features.ssf = true` there, which
the example stack does not switch on.

**Never against a stack that holds anyone's account.** `seed.sql` writes
clients and a person with a copied password hash; it is for a database that
will be thrown away.

## Environment the scripts read

| Variable | Default | Meaning |
| --- | --- | --- |
| `BASE_URL` | `http://127.0.0.1:9443` | where the listener is |
| `ISSUER` | `https://localhost:9443/t/load` | the tenant's issuer; also the `Host` header, the assertion's `aud` and the proof's `htu` prefix |
| `CLIENT_ID` | `load-client` (`load-receiver` for `ssf-poll.js`) | which seeded client to act as; `load-machine` for the token script |
| `KID` | `load-key-1` | the `kid` in `client.jwks.json` |
| `CLIENT_KEY` | `./client-key.der` | the PKCS#8 key `gen-keys.sh` wrote |
| `SCOPE` | `load.read` | the scope `token-client-credentials.js` and `introspection.js` ask for |
| `SCAN` | unset | `introspection.js`: ask about values nothing issued, to compare the answer a scan gets with the answer a real token gets |
| `PASSWORD` | `$ASTERIUS_ADMIN_PASSWORD` | the load user's password (`seed.sql` copies the admin's hash) |
| `KEEP_SESSION` | unset | `code-flow.js`: keep the browser session between iterations instead of signing in every time |
| `DEBUG` | unset | print every refused token response with the proof and assertion it carried |

Every script aborts a run whose checks fall under 99%, because a run that is
mostly refusals measures the wrong thing.

## The EXPLAIN review

```sh
docker compose up -d db
sqlx migrate run --source crates/store-pg/migrations -D postgres://asterius:asterius@127.0.0.1:5433/asterius
DATABASE_URL=postgres://asterius:asterius@127.0.0.1:5433/asterius ./scripts/load/explain.sh
```

`explain-seed.sql` fills a tenant `explain` with 50 000 rows per growing
table (`ROWS=` to change); `explain-queries.sql` runs the hot statements —
grouped by the path that runs them, in the order that path runs them — inside
one transaction that is rolled back; `explain.sh` writes the plans to
`scripts/load/explain.out` and exits non-zero if a growing table was scanned
sequentially and had to discard more than `SEQ_SCAN_TOLERANCE` (1000) rows to
answer. Run it when a migration touches an index or a repository adds a
query, and add the query to `explain-queries.sql` if it is on a request path.

## Generated files, ignored by git

`client-key.der`, `client.jwks.json`, `certs/` and `explain.out`. A key is a
key even when it only ever signed load.
