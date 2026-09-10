# Runbook: upgrading Asterius

**Status:** describes the system as it is on `ast-bgg`, not as it is meant to
become. Every command below was run against the binary built from this tree;
where a claim could not be proved by reading the code it says **not verified**
rather than guessing.

Related: [backup and restore](backup-restore.md) (rollback ends there),
[KEK rotation](kek-rotation.md) (a rotation is not an upgrade and the two should
not be run together), [`../../deploy/README.md`](../../deploy/README.md).

---

## 1. The shape of an upgrade

One binary and one PostgreSQL. There is no migration job, no sidecar and no
second store to keep in step, so an upgrade is: put a new binary in front of the
same database, restart the replicas, watch them come ready.

The whole of the difficulty is in the sentence "the same database", because the
new binary changes it on the way up.

---

## 2. The migrations run at boot. There is no separate step

`serve_forever` in `crates/server/src/main.rs` connects and then calls
`Store::migrate()` **before** the key-encryption key is loaded, before the
tenants are written and before the listener binds. A migration failure never
reaches a client: it prints `asterius: cannot apply migrations: …` on stderr and
the process exits non-zero.

The migration set is compiled into the binary — `sqlx::migrate!("./migrations")`
in `crates/store-pg/src/store.rs` — so "which migrations does this build apply"
is answered by the build, never by what is on the filesystem next to it.

Two things follow, and they are the two facts this runbook exists to state.

* **You cannot migrate before deploying the binary.** There is no `migrate`
  subcommand. The full command surface is:

  ```text
  usage: asterius [--config <path>] [--config-reference] [--admin-openapi]
         asterius rewrap-kek [--new-kek-file <path> | --new-kek-env <var>] [--config <path>]
  ```

  That is `asterius --help` verbatim. `rewrap-kek` is the only subcommand, and
  it deliberately does *not* migrate — a rotation has to be runnable against a
  database whose replicas are mid-upgrade.

  `cargo sqlx migrate run --source crates/store-pg/migrations` does exist, and
  CONTRIBUTING uses it, but it is a development command: it needs the source
  tree and `sqlx-cli`, neither of which is in the release image (the image ships
  the binary and no shell). Do not plan a production upgrade around it.

* **You cannot deploy the binary without migrating.** The first replica of the
  new build to start applies everything the database has not seen, whether or
  not the rollout was meant to be gradual. §4 is about what that does to the
  replicas that have not restarted yet.

### Starting every replica at once is safe

`sqlx` takes a PostgreSQL **advisory lock** for the length of the run, so when
three replicas of a new build start together one migrates and the other two wait
and then find there is nothing to do. Without it the losers would race on
`create table` and crash-loop through the rollout. This is a `sqlx` default and
a default is not a guarantee, so `migrations_are_serialised_by_an_advisory_lock`
in `store.rs` pins it.

The lock is session-level and released when the connection returns to the pool,
so a process killed mid-migration does not leave the next one blocked forever.
It leaves a half-applied *set*, not a half-applied statement — each migration
runs in its own transaction.

### A changed checksum refuses the boot, and that is the protection working

`sqlx` refuses to run when an already-applied migration's checksum has changed.
Before the first release the baseline migration is still being edited
(CONTRIBUTING, "Database"), so a build taken from a different point of history
can refuse to start against a database it has "already" migrated. The error is
`cannot apply migrations: …` and the answer is not to force it: it means the
binary and the database disagree about history, which in production is the one
thing this check is there to catch.

### The sqlx offline trap, for whoever builds at upgrade time

CONTRIBUTING states it and it is worth repeating here because an upgrade is
exactly when somebody builds from source in a hurry: a database that is
**running but not migrated**, with `DATABASE_URL` set, is worse than no database
at all. `DATABASE_URL` takes `sqlx` out of offline mode, and it then verifies
all 122 `query!` invocations against an empty schema and fails every one of
them. Left unset with nothing listening, `sqlx` dials the database and waits out
its connect timeout while holding cargo's build lock, which looks exactly like a
hung build.

Build with `SQLX_OFFLINE=true` — which is what the release `Dockerfile` sets
(`ENV SQLX_OFFLINE=true`) — or start the container and migrate it in one step.
Never half of each.

---

## 3. The procedure

1. **Take a backup first**, per [`backup-restore.md`](backup-restore.md) §2, and
   confirm you can read the current KEK. §5 explains why: for most of these
   migrations, restoring that backup is the only rollback there is.
2. **Read §4 for the migrations you are crossing.** `select version from
   _sqlx_migrations order by version` says where the database is; the new
   build's `crates/store-pg/migrations/` says where it is going.
3. **Roll one replica** onto the new build and let it start. It takes the
   advisory lock, applies the migrations, loads the KEK and binds.
4. **Read its first lines.** They are the check, in order:
   * `starting`, with `version`, `config`, `mode`, `tenants` and `features` —
     confirm `version` is the build you meant and `features` is the flag set you
     expect.
   * `key-encryption key loaded`, with the `kek` id.
   * one `tenant ready` per configured tenant.
5. **Wait for readiness before sending traffic.**
   ```sh
   curl -fsS "$BASE_URL/readyz"
   ```
   ```json
   {"ready":true,"database":true,"migrations_applied":true,"features":["…"]}
   ```
   `503` until all of it is true, which is what keeps a load balancer off a
   replica that cannot serve. `/healthz` is liveness only — it never touches the
   database, deliberately, so that a database outage does not get every replica
   killed — and it carries the running `version`, which makes it the cheapest
   way to see which build a replica is on.
6. **Prove one signature end to end** before rolling the rest: fetch
   `/.well-known/openid-configuration` and the JWKS for one tenant and mint a
   token for a test client. `./scripts/smoke-test.sh` is that check written down
   (`BASE_URL`, `ISSUER`, `TENANT`, `TIMEOUT` in the environment); it is aimed at
   the example compose stack, so against a real deployment read it and take the
   requests, rather than pointing it at production and trusting the defaults.
7. **Roll the remaining replicas.** Their migration is a no-op — the first one
   did it — so they are an ordinary restart.

---

## 4. Multi-replica: what the old replicas survive

There is no released version yet, so "N-1" here does not name a tag. It means
"the build a replica that has not restarted yet is still running", and the
question has to be answered per migration: **once the first new replica has
migrated, which statements does an old replica still issue that the new schema
now refuses?**

Answered by reading `crates/store-pg/migrations/0002`–`0011` against the code
that was current before each. Two of them are genuinely breaking.

| Migration | What it does | An old replica after it applies |
| --- | --- | --- |
| `0002_resource_servers` | New table `resource_servers`, plus one `insert … select` seeding each tenant's `default_resource`. | **Compatible.** Nothing older reads or writes the table. |
| `0003_key_purge` | `signing_keys.purged_at` added; `private_key_ciphertext`, `private_key_nonce`, `kek_id` lose `not null`; the `state` check gains `'purged'`; the timestamp check is restated. | **Compatible in practice.** Dropping `not null` never breaks a reader, and the three columns only go null on a row a *new* replica purges. Old queries select the material only under `state = 'active'`, and a purge refuses the active key, so an old replica cannot meet a null. It would meet an unknown `state` string if somebody purged a key mid-rollout — don't; purging is an incident procedure, not a rollout one. |
| `0004_authorization_details_types` | New table. | **Compatible.** |
| `0005_auth_request_dpop_jkt` | `alter table auth_requests drop column dpop_jkt`. | **BREAKING.** The pre-0005 code writes that column on every PAR push and selects it on every consume (`crates/store-pg/src/auth_requests.rs` at `ad31573^`). After this migration those statements fail with "column does not exist", so an un-restarted replica returns errors from **PAR and from the authorization request that consumes the `request_uri`** until it is restarted. Roll fast across this one, or drain the old replicas before the first new one starts. |
| `0006_client_key_fetches` | New table. | **Compatible.** |
| `0007_grant_authentication` | `grants` gains `authenticated_at`, `acr`, and `amr text[] not null default '{}'`; check `grants_authentication_is_whole`. | **Compatible.** An old `insert` omits all three, takes the defaults — `null`, `null`, `'{}'` — and the check's second branch is satisfied exactly by that combination. |
| `0008_retired_subject_identifiers` | New table plus three triggers on `subject_identifiers`: a tombstone on delete, a refusal to re-insert a retired subject, and a refusal to update or delete a tombstone. | **Compatible, with a behaviour change.** Old code is not broken, but its deletes now leave tombstones and an insert of a previously-retired `sub` now raises `unique_violation`. That is the intended new rule (OIDC Core §8) arriving early for the old replicas, not a fault — but it is a refusal an old build has no message for. |
| `0009_initial_access_tokens` | New table. | **Compatible.** |
| `0010_client_last_used_at` | `clients.last_used_at`, nullable. | **Compatible.** No query in the tree uses `select *`, so an added column reaches no old reader. |
| `0011_tls_client_auth_subject` | `clients` gains `tls_client_auth_field` / `tls_client_auth_value`, plus `clients_tls_client_auth_subject_matches_method`: a row's method is `tls_client_auth` **iff** the field is set. | **BREAKING, on one path.** The baseline already accepted `tls_client_auth` as a `token_endpoint_auth_method` and the pre-mTLS domain registered such clients (`54eaea3^`, `entities/client.rs`), writing no subject columns. After 0011 that insert violates the check, so an un-restarted replica **fails `POST /register` and console client creation for `tls_client_auth` clients**. Everything else about the old replica is unaffected: existing rows have a null method-field pair only when the method is not `tls_client_auth`, so the constraint validates the existing table. |

**Verdict.** The schema is *not* generally N/N+1 compatible. Eight of the ten
migrations are additive and cross a rollout without anyone noticing; `0005` and
`0011` each break a specific request path on a replica that has not restarted.
Neither corrupts data — both are refusals — so the exposure is a window of
errors on PAR (0005) and on mTLS client registration (0011), bounded by how long
the rollout takes.

Nothing here has been observed in a two-version rolling deployment; it is read
off the migrations and the code that preceded each. Treat it as the analysis it
is, and keep the rollout short.

---

## 5. Rollback

### There are no down migrations

Every file in `crates/store-pg/migrations/` is `NNNN_name.sql`. `sqlx` only
treats a migration as reversible when it is split into `.up.sql` and `.down.sql`,
and none is, so `MIGRATOR` has nothing to undo and the binary offers no path
that would ask it to. **A migration in this project is one-way.**

So "rollback" means one of two different things, and it matters which you need.

### Rolling the binary back, leaving the schema forward

Usually enough, and usually safe. An older binary starts against a newer schema:
its own `migrate()` finds every migration it knows already applied and does
nothing, and readiness holds — `migrations_applied` counts the rows in
`_sqlx_migrations` and compares `count >= expected`, so a database that is
*ahead* still reads ready.

What can still bite it is exactly §4 in reverse: after `0005` the older binary
cannot run PAR at all, and after `0011` it cannot register a `tls_client_auth`
client. Read the table before choosing this, and if the build you are going back
to is on the far side of `0005`, this is not a rollback — it is an outage on the
PAR path.

The checksum rule applies here too: before the first release the baseline is
still being edited, so an older build whose baseline text differs from the one
recorded in `_sqlx_migrations` refuses to boot. That is not a rollback you can
force; it is the second case.

### Putting the schema back

Restore. There is no other mechanism.

Follow [`backup-restore.md`](backup-restore.md) §3 in full: stop **every**
writer, `pg_restore` the dump, restore the KEK into the location
`asterius.toml` names *before* starting anything, then bring one replica up and
verify the `kek` id, the audit chain (`PgAuditSink::verify_chain`) and one
signature end to end.

Two consequences worth knowing before you choose it:

* Everything written since the backup is gone — issued refresh tokens, grants,
  clients registered in the window, audit records.
* Restoring a dump *newer* than the binary is the case that corrupts. Going back
  a version and restoring a backup taken after the upgrade is that case.

Which is why §3 step 1 is a backup, and why it is worth a moment to confirm the
backup and the KEK are the pair they are supposed to be before an upgrade rather
than after one.

---

## 6. What this runbook does not cover

* **Rotating the key-encryption key** — [`kek-rotation.md`](kek-rotation.md).
  Do not fold one into an upgrade: `rewrap-kek` does not migrate, and debugging
  a boot failure while two keys and two schemas are in play is two problems.
* **Zero-error rolling upgrades across `0005` and `0011`.** The schema does not
  support them today (§4) and no expand/contract discipline is written down for
  future migrations. Stating that is the honest position; changing it is a
  decision somebody has to take.
* **Downgrading the database's own major version.** An ordinary PostgreSQL
  question; the schema uses no extensions, so nothing here constrains it.
