# Performance baseline

What one process of this server does under load, on one machine, on one day,
and what that implies for sizing. Every number here was produced by a script
in [`scripts/load/`](../scripts/load/README.md) and can be reproduced with
the commands given; a number without a command is an opinion.

**Why this matters more here than for most servers.** FAPI 2.0 SP §6.1 asks
for short-lived access tokens, and a short-lived token is a client that comes
back to `/token` often. The token endpoint is where a FAPI deployment's load
lands, and its cost per request is not small: two signature verifications
(the client assertion, the DPoP proof), two replay inserts, one signature, an
audit record under a per-tenant lock. Size lifetimes with the numbers below
in hand, not with a round figure.

## The machine and the stack

Not a reference machine. A developer workstation under WSL2, with the load
generator on the same host as the server and the database, so every number
below is pessimistic about CPU (three processes share it) and optimistic about
the network (there is none).

| | |
| --- | --- |
| Date, commit | 2026-09-11, `861acac` plus this ticket's working tree (`ast-p2l.8`) |
| CPU, memory | Intel Core i9-14900K (32 threads), 31 GiB; Linux 6.18 `microsoft-standard-WSL2` |
| Server | `cargo build --release --bin asterius`, `scripts/load/asterius-load.toml`: TLS terminated by the process, `database.max_connections = 16`, `[limits]` raised out of the way |
| Database | `postgres:16-alpine` (16.15) in Docker, **default configuration, fsync on**, on the host's disk — not the tmpfs/`fsync=off` container `docker-compose.yml` starts for tests |
| Load generator | k6 v2.2.0 on the same host, `--insecure-skip-tls-verify` |
| Schema | migrations 0001–0031. The indexes of 0032 (below) were found by this review and are not in the measured binary; none of them is on the token endpoint's path |

## Token endpoint — `client_credentials`, `private_key_jwt`, DPoP

`scripts/load/token-client-credentials.js`, one client, one DPoP key per
VU, a fresh assertion and a fresh proof per request, 60 seconds per run
(30 at 4 VUs).

```sh
k6 run --insecure-skip-tls-verify -e CLIENT_ID=load-machine --vus 16 --duration 60s token-client-credentials.js
```

| VUs | requests/s | p50 | p95 | p99 | max | refused |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 4 | 221 | 15.5 ms | 35.9 ms | 54.9 ms | 97.8 ms | 0 |
| 16 | 351 | 37.5 ms | **72.7 ms** | 77.3 ms | 141.9 ms | 0 |
| 32 | **433** | 75.3 ms | 84.9 ms | 93.6 ms | 132.2 ms | 0 |
| 64 | 409 | 156.4 ms | 190.8 ms | 218.0 ms | 266.8 ms | 0 |

How to read it: throughput saturates at about **430 token responses per
second** on this machine, and past that point adding concurrency only adds
queueing — 64 VUs deliver fewer tokens than 32 with twice the latency. The
p95 at a comfortable load (16 VUs, 80% of saturation) is **73 ms**.

What a request costs, from the query-budget test's statement log
(`crates/server/tests/end_to_end.rs`): the throttle read, the assertion's
replay insert, the client row, the proof's replay insert, the grant, the
resource registry, the person's roles (two reads), the signing key, the
token's row, the audit chain read and insert under the tenant's advisory
lock, the throttle write — seventeen statements for a code redemption (the
budget test's log, from the code's `update` to the throttle's `insert`),
fewer for `client_credentials`, which has no code, session, person or
refresh token to touch; all by primary key or an index that leads with
`tenant_id`.

**The serial part.** `PgAuditSink::record` takes `pg_advisory_xact_lock` per
tenant for the read-then-insert of the hash chain, so audit writes of one
tenant are serialised. Every token response writes one. On this stack a
commit is under a millisecond and the lock never shows; on a database two
milliseconds away, one tenant cannot write more than a few hundred audit
events per second whatever the process count, and that — not the pool, not
the CPU — is the ceiling for a deployment whose load is one large tenant.

## The whole code flow — PAR, `/authorize`, sign-in, consent, `/token`

`scripts/load/code-flow.js`, 16 VUs, 60 seconds, the browser session cleared
before every iteration so that each one pays the Argon2id verification of a
password.

```sh
k6 run --insecure-skip-tls-verify -e CLIENT_ID=load-client --vus 16 --duration 60s code-flow.js
```

| | rate | p50 | p95 | p99 |
| --- | ---: | ---: | ---: | ---: |
| complete journeys | **79.5 / s** | 205 ms | **241 ms** | 266 ms |
| HTTP requests | 398 / s | 26.4 ms | 113.3 ms | 125.2 ms |
| — PAR | | 23.8 ms | 38.9 ms | 48.8 ms |
| — `/authorize` | | 5.8 ms | 12.3 ms | 16.2 ms |
| — sign-in (page + password) | | 129.5 ms | 150.1 ms | 163.4 ms |
| — `/token` (code redemption) | | 41.4 ms | 60.5 ms | 72.5 ms |

Two things to know before comparing. The sign-in step is Argon2id (the
`m=19456, t=2, p=1` of OWASP's minimum), which is most of the journey by
design; a passkey sign-in replaces it with one ECDSA verification. And the
consent screen was shown once: the load user had granted `load-client` the
same scopes on the first iteration, and every later one was "covered by an
earlier consent" (OIDC Core §3.1.2.4) and went from sign-in straight to the
code. A first-time consent adds one rendered page and one form post.

## SSF poll delivery — RFC 8936

`scripts/load/ssf-poll.js`, 8 VUs polling one stream with
`returnImmediately: true` and an empty queue: the tight loop a badly written
or hostile receiver produces.

```sh
k6 run --insecure-skip-tls-verify -e CLIENT_ID=load-receiver --vus 8 --duration 30s ssf-poll.js
```

| | rate | p50 | p95 | p99 |
| --- | ---: | ---: | ---: | ---: |
| polls | **1 077 / s** | 7.4 ms | **8.4 ms** | 9.2 ms |

Each poll verifies a DPoP-bound access token (signature, `ath`, replay
insert, denylist and cutoff reads) and takes a batch from `ssf_poll_queue`.
The eight refused requests k6 counts are the seven VUs that found the stream
already created (409) — not polls.

Push delivery (RFC 8935) is not a load-tool scenario: the outbox worker
drives it, not a client. Its database side is in the EXPLAIN review below
(the claim, the ack, the pending count); its wall-clock side is the
receiver's endpoint and the `outbound::post` timeout.

**Introspection** (RFC 7662) is in the ticket and not in this document: the
endpoint is registered in the metadata registry but not mounted by any route
(`mount_the_unbuilt` in `crates/server/src/http/protocol.rs` answers it with
501). There is nothing to measure until it exists; when it does, it is one
more script beside these.

## No N+1 in the code flow

`a_complete_code_flow_stays_within_its_query_budget` in
`crates/server/tests/end_to_end.rs` drives one push, one arrival at
`/authorize`, one passkey sign-in, one consent and one redemption through the
assembled router with a `tracing` layer that records every statement `sqlx`
executes, and asserts the count against a ceiling. The ceiling is **71**,
which is what the flow cost on the day it was pinned: the test was written
red (budget 0) to print the log, the log was read for a per-row pattern, and
none was found — no statement repeats with a different key inside one
handler. The ceiling is a shape, not a target: a change that adds a statement
on purpose moves it and says why.

What the log does show, for a later ticket, is redundancy rather than
multiplication: the client row is read nine times across the five requests
and the pushed request six times, once per handler that needs it; the
pairwise subject is resolved twice (consent and code issuance); and the
sign-in stage's rate-limit bucket is read, then deleted, then re-inserted.
Every one of those is a handful of primary-key reads and none is a
correctness issue, so they are noted here and left alone.

## EXPLAIN review of the hot statements

`scripts/load/explain.sh` seeds a tenant with 50 000 rows in every table that
grows with use and runs 66 statements — the ones `.sqlx/` records for every
request, the PAR and authorize paths, the interaction, consent, the audit
chain, the three token grants, token presentation, logout, the outbox
worker, SSF poll and the retention sweeps — under `EXPLAIN (ANALYZE,
BUFFERS)`, inside a transaction it rolls back.

```sh
docker compose up -d db
sqlx migrate run --source crates/store-pg/migrations -D postgres://asterius:asterius@127.0.0.1:5433/asterius
DATABASE_URL=postgres://asterius:asterius@127.0.0.1:5433/asterius ./scripts/load/explain.sh
```

Before migration 0032, seven statements scanned a growing table
sequentially. After it, none does; the plans below are from the second run.

| Statement | Path | Before | After (0032) |
| --- | --- | --- | --- |
| `grants where tenant_id and subject` (`list_for_subject`) | **consent, every sign-in** — "is this request covered by an earlier consent" | Seq Scan, 50 000 rows filtered, 4.7 ms | `grants_by_subject`, 0.05 ms |
| `update refresh_tokens … from grants where session_id` | logout, back-channel | Seq Scan on `grants`, 4.1 ms | `grants_by_session`, 0.03 ms |
| `grants where tenant_id and user_id` (`list_for_user`) | console, a person's grants | Seq Scan, 3.1 ms | `grants_by_user`, 0.04 ms |
| `sessions where tenant_id and user_id order by created_at` | console, a person's sessions | Seq Scan, 1.6 ms | `sessions_by_user`, 0.03 ms |
| `outbox where kind like 'notification.%' and delivered_at is null` | admin, the notification inbox | Seq Scan, 6.1 ms | `outbox_notifications_pending`, 0.01 ms |
| `delete from grants where created_at < … and claimed_at is null and revoked_at is null` | retention sweep | Seq Scan, 3.8 ms | `grants_unclaimed`, 0.03 ms |
| `delete from recovery_tokens where expires_at <= …` | retention sweep | Seq Scan (no index on the column) | `recovery_tokens_expiring` exists; the seed's sweep still scans because it deletes 4 987 of 5 000 rows, which is the right plan |

The first four were the same mistake: an index declared `where revoked_at is
null` for a query that has no such predicate, which PostgreSQL cannot use.
The migration's header comment says the rest. The first row is the one that
mattered — it ran once per sign-in, and its cost grew with the tenant.

What stays sequential, on purpose: a `count(*)` over one stream's whole
queue (every row matches; an index would be slower), and a sweep that
deletes most of a table (`sessions` in the seed, where 49 000 of 50 000 rows
had expired). `explain.sh` tolerates a scan that discards under 1 000 rows
and fails on one that discards more, which is the distinction between "the
right plan" and "a missing index".

Everything else is a primary-key or index lookup with `tenant_id` first,
which is the schema's rule (`0001_baseline.sql`, and the
`every_table_leads_its_primary_key_with_tenant_id` sentinel in
`crates/store-pg/tests/database.rs`).

## Sizing the connection pool

`database.max_connections` (default 16) is per process. Three things bound
it, in the order to check them.

**1. What the database allows.** PostgreSQL's `max_connections` is shared by
every replica of this server, the outbox worker in each of them, the
migration at start-up, and whatever else connects. `replicas ×
max_connections` must leave room; a managed PostgreSQL at its default 100
connections serves four replicas at 16 with margin and six at 16 without.

**2. What the process can use.** A statement here is short — the review's
median is under 0.1 ms of execution on a local database, and a request holds
a connection for one statement or one short transaction at a time — so a
connection is busy for roughly `statements per request × (statement latency +
round trip)` per request. At 400 token responses per second, 14 statements
each (a round figure between the two grants above) and half a millisecond
per statement including the round trip, that is 2.8 connections busy on
average. **The pool is not the bottleneck on a local
database; the CPU is** (signature verification, Argon2id, TLS). On a database
2 ms away the same arithmetic gives 11 busy connections at 400/s, which is
where 16 starts to be the right number and 8 the wrong one.

The formula, for a deployment's own numbers:

```
busy connections ≈ requests/s × statements per request × (execution + round trip) seconds
max_connections  ≈ 2 × busy connections, and at least the number of CPU threads the process has
```

Statements per request: 12–17 for a token response, 71 for a whole code
flow (five requests, the budget test's ceiling), 1–2 for JWKS and discovery.

**3. What the load will be.** FAPI 2.0 SP §6.1 makes this a function of the
access-token lifetime. For `S` sessions that stay active — a session refreshes
once per lifetime `L` seconds — the token endpoint sees `S / L` requests per
second, plus the sign-ins. With the tenant default of `access_token_lifetime
= 300`:

| active sessions | token requests/s at 300 s | at 600 s | at 900 s |
| ---: | ---: | ---: | ---: |
| 10 000 | 33 | 17 | 11 |
| 100 000 | 333 | 167 | 111 |
| 300 000 | 1 000 | 500 | 333 |

Against the table at the top: one process on this machine holds 100 000
active sessions at a 300-second lifetime at 80% of saturation, or 300 000 at
900 seconds. Doubling the lifetime halves the load and doubles how long a
revoked grant's last token stays usable, which is the trade §6.1 asks a
deployment to make with its eyes open.

**Two more knobs that bound throughput before the pool does.**
`limits.token_per_client` (default 1200 per minute) caps one client at 20
successful token responses per second; a large relying party that refreshes
for 100 000 users at a 300-second lifetime needs 333, and will be answered
429 until the limit is raised. And the per-tenant audit lock (above) makes a
single-tenant deployment's ceiling the database's commit latency, not its
connection count.

## Keeping these numbers honest

They age. Re-run the three scripts and `explain.sh` when a ticket touches
the token endpoint, the interaction, the audit sink or a migration with an
index in it, and update the tables here with the date and commit. A
regression the CI cannot see — it runs no load — is one somebody notices in
production, and this file is what "regression" is measured against.
