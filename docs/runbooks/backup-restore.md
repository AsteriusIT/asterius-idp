# Runbook: backup and restore

**Status:** describes the system as it is on `ast-xni`, not as it is meant to
become. Where a step is manual, it says so and names the bead that automates it.
A runbook that describes automation nobody wrote is worse than no runbook: it is
read at 3am by somebody who then discovers the command does not exist.

Related: [KEK rotation](kek-rotation.md) (what was §4 of this file),
[upgrades](upgrade.md), [threat model](../threat-model.md) §3 (the rows that
hold key material), [ADR-0001](../adr/0001-modular-monolith.md) (why everything
is in one PostgreSQL database). The index is [`README.md`](README.md).

---

## 1. What has to be backed up

Three things, and they are deliberately not in one place.

| Artefact | Where it lives | Contains |
|---|---|---|
| The database | PostgreSQL | Everything, including the **ciphertext** of every signing key and every tenant's pairwise salt |
| The key-encryption key (KEK) | A file or an environment variable, per `[kek]` in `asterius.toml`; a KMS through the `Kek` port | The key that opens that ciphertext |
| The configuration | `asterius.toml` | Issuers, tenants, TLS material, the database DSN |

**The KEK is not in the database, and the two must not be backed up to the same
place.** That separation is the entire value of the envelope encryption: a stolen
database dump yields signing-key ciphertext that cannot be opened, which is the
control the threat model records against "reads a signing key out of a database
dump, a backup or a read replica". A backup pipeline that helpfully collects both
into one bucket has quietly removed it.

The converse is just as true: **a database backup without the KEK is not a
restorable backup.** The public halves of the signing keys survive in
`signing_keys.public_jwk`, so a restore without the KEK can still publish a JWKS
— and then fails to sign anything, which looks like a partial recovery and is
not one. Every tenant's pairwise salt is sealed the same way, so subject
identifiers cannot be derived either.

Verify the pairing before you need it. Every ciphertext row records the id of the
KEK it was sealed under:

```sql
select kek_id, count(*) from signing_keys group by kek_id;
select kek_id, count(*) from tenant_pairwise_salts group by kek_id;
```

Those ids must match the one the server logs at startup (`key-encryption key
loaded`, field `kek`). The id is derived from the key material itself, so
swapping the file and keeping the name changes the id — an operator gets "sealed
under a different KEK" rather than "cannot decrypt".

---

## 2. Backup

Nothing here is Asterius-specific; the schema is an ordinary PostgreSQL schema
with no extensions.

```sh
# Logical, single point in time, restorable into a different major version.
pg_dump --format=custom --no-owner --file=asterius-$(date -u +%Y%m%dT%H%M%SZ).dump "$DATABASE_URL"
```

For a deployment that cannot lose the last few minutes, use continuous archiving
(`pg_basebackup` plus WAL shipping) instead; the application makes no assumption
either way, because every credential row carries its own expiry and the retention
sweep is idempotent.

Back the KEK up **separately**, to wherever secrets go for this deployment, with
its own access control and its own audit trail. If `[kek] file = ...`, that is a
32-byte file; copy the bytes, not the path.

### Retention interacts with backups

`asterius_store_pg::retention::POLICY` deletes expired rows every five minutes
(`RetentionSweep::DEFAULT_INTERVAL`). Two consequences worth knowing before an
incident:

* A backup is a snapshot of what had not yet been swept. Restoring one
  **resurrects** expired authorization codes, PAR requests, sessions and replay
  markers. None of them become usable — every read path checks the clock, not
  the row's existence — and the next sweep removes them again.
* `audit_events` is **never** swept (the policy keeps it, and the table refuses
  `DELETE` from a trigger). The trail in a backup is the trail as it was. Trimming
  it is a deliberate act through `PgAuditSink::purge_older_than` against a stated
  retention window.

---

## 3. Restore

1. **Stop the writers.** Every replica. A restore under a running server races
   with the sweep and with token issuance.
2. **Restore the database.**
   ```sh
   createdb asterius
   pg_restore --dbname="$DATABASE_URL" --no-owner asterius-….dump
   ```
3. **Restore the KEK** from its own store, into the location `asterius.toml`
   names. Do this before starting the server, not after: the KEK is loaded at
   boot, and a deployment that cannot read its own key material is meant to fail
   there, while somebody is watching.
4. **Start one replica** and read the first three lines of its log:
   * `key-encryption key loaded` — with the `kek` id from §1. If it differs from
     the `kek_id` in the restored rows, stop: you have restored a database and a
     key that do not belong together.
   * `tenant ready` — one per configured tenant.
   * The server binds. Migrations run at startup under an advisory lock, so
     starting several replicas at once is safe, but there is no reason to.
5. **Check the schema is the one the binary expects.** `/healthz` reports
   readiness; `Store::migrations_applied` is the same check in-process. A
   restore from an older dump than the binary is normal — the migrations run —
   but a restore from a *newer* dump is not, and it is the case that corrupts.
6. **Verify the audit trail.** `PgAuditSink::verify_chain` walks a tenant's
   records and re-derives the hash chain. It is the one check that says the
   restored data is the data that was written, rather than merely well-formed.
   A break points at the record it broke on.
7. **Prove one signature end to end.** Fetch `/.well-known/openid-configuration`
   and the JWKS, then mint a token for a test client. This is what distinguishes
   a restore that works from a restore that publishes keys it cannot use — the
   failure mode of a database restored without its KEK.
8. **Start the remaining replicas.**

---

## 4. Rotating the key-encryption key

**Moved.** The procedure that was here is now
[`kek-rotation.md`](kek-rotation.md), where it sits beside the offline variant,
the rollback and the incident procedure for purging one compromised signing key.
It is not duplicated: this section is a pointer, and the runbook is the text.

What belongs here is only the part that touches backups, and it is two
sentences. **A backup can only be restored with the KEK that was current when it
was taken** — so keep the pre-rotation backup and the pre-rotation key together
until the rotation is finished and verified, and destroy the old key material
only once a backup taken *after* the rotation has been proven restorable under
the new key. Rotating the KEK moves no plaintext, so nothing else in §1–§3
changes: the same database dump and the same 32-byte file, paired differently.

---

## 5. What this runbook does not cover

* **Upgrades** — [`upgrade.md`](upgrade.md): what runs the migrations, what a
  rolling restart does to the replicas that have not restarted yet, and why
  rollback ends at §3 above.
* **Off-box shipping of the audit chain tip.** The hash chain detects tampering
  by whoever has SQL access; it cannot detect a rewrite of the whole table by
  somebody who also recomputes the chain. Shipping the tip somewhere else is the
  real defence, and it is not built (threat model, residual risks).
* **A KMS or HSM KEK.** The `Kek` port is what one plugs into, and the `kek_id`
  recorded on every row is what makes migrating to one a re-wrap
  ([`kek-rotation.md`](kek-rotation.md)) rather
  than a re-issue. `asterius rewrap-kek` re-seals through the `Kek` port, but
  the only implementation of that port today reads its material into this
  process, so both keys still have to be local.
