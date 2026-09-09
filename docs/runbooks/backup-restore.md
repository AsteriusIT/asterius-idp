# Runbook: backup, restore, and rotating the key-encryption key

**Status:** describes the system as it is on `ast-p2l.4`, not as it is meant to
become. Where a step is manual, it says so and names the bead that automates it.
A runbook that describes automation nobody wrote is worse than no runbook: it is
read at 3am by somebody who then discovers the command does not exist.

Related: [threat model](../threat-model.md) §3 (the rows that hold key
material), [ADR-0001](../adr/0001-modular-monolith.md) (why everything is in one
PostgreSQL database).

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

> **Read this section before planning the change, not during it.** KEK rotation
> is **manual today**, it needs a maintenance window, and for a tenant using
> pairwise subject identifiers it needs a program that this repository does not
> ship. `ast-mxc.3` owns the re-wrap job; the threat model records the gap under
> "Rotating the key-encryption key itself is manual".

### What "rotating the KEK" actually means

The KEK encrypts two kinds of row:

| Row | Re-wrappable in place? |
|---|---|
| `signing_keys.private_key_ciphertext` | Yes — the row takes `UPDATE`. |
| `tenant_pairwise_salts.salt_ciphertext` | **No.** A trigger refuses `UPDATE` outright, so the salt can only be replaced by `DELETE` + `INSERT` of the *same plaintext* re-sealed. |

Both need the old KEK and the new one held at once, and both need code:
`asterius_jose::kek::LocalKek::open` and `::seal` are the only things that can
open and re-seal a row, and the AEAD binds each ciphertext to its row's tenant,
kid, purpose and algorithm — so the re-wrap cannot be done in SQL, and a byte
copied to another row stops decrypting rather than becoming a working key
somewhere else. The server binary loads exactly one KEK and has no re-wrap
subcommand.

### Procedure A — signing keys only, with no new code

Usable when no tenant uses `subject_type = pairwise`. Check first:

```sql
select count(*) from clients where subject_type = 'pairwise';
select count(*) from tenant_pairwise_salts;
```

If either is non-zero, go to procedure B.

This procedure rotates the *signing keys* rather than re-wrapping them, which the
server already knows how to do. Verification is unaffected throughout: a relying
party checks a signature against `public_jwk`, which is not encrypted.

1. Take a backup (§2) and confirm you can read the current KEK.
2. Announce a signing outage. Between steps 4 and 6 the server holds no key it
   can open, so token issuance fails while the JWKS keeps serving. Keep it
   short; it is minutes, not hours.
3. For every tenant, retire the keys sealed under the old KEK, so that the next
   rotation pass has to stage new ones:
   ```sql
   update signing_keys
      set state = 'retiring', retiring_at = now()
    where state = 'active' and kek_id = '<old kek id>';
   ```
   Do **not** delete them: their public halves must stay published for the grace
   period, or every token they signed stops verifying.
4. Install the new KEK material and restart the replicas.
5. `RotationSweep` stages, publishes and promotes a fresh key per tenant, sealed
   under the new KEK. At the defaults this is one sweep interval plus the
   propagation period; `prepare_keys` also runs a pass at boot, so a restart is
   usually enough. Confirm:
   ```sql
   select tenant_id, state, kek_id from signing_keys where state in ('active','pending');
   ```
6. Mint a token per tenant and verify it against the published JWKS.
7. After the grace period, the old keys reach `retired` and leave the JWKS on
   their own. Their rows stay — a `kid` is never handed out twice — and they are
   ciphertext nobody can open, which is the desired end state for a key that has
   been rotated away from.

### Procedure B — a real re-wrap (needs a one-off program)

Required as soon as `tenant_pairwise_salts` has rows, because those cannot be
re-issued: every `sub` already derived under a salt is stored, and OIDC Core §8
says a subject identifier is never reassigned. Replacing a salt reassigns every
identifier in the tenant, which is a relying-party migration, not a rotation.

The program to write — it is small, and `ast-mxc.3` is where it belongs:

1. Load both KEKs (`LocalKek::from_file` twice).
2. In one transaction per tenant:
   * for each `signing_keys` row with the old `kek_id`: `open` under the old KEK
     with that row's binding, `seal` under the new one, `update` the ciphertext,
     nonce and `kek_id` together;
   * for the `tenant_pairwise_salts` row: `open`, then `delete` and `insert` the
     re-sealed salt — the trigger refuses `UPDATE`, and this is the one path it
     leaves. The plaintext salt must be byte-identical, or every subject
     identifier in the tenant changes.
3. Assert afterwards that `select distinct kek_id` returns only the new id in
   both tables, and that a token still signs and a known `sub` still derives to
   the same value.
4. Destroy the old KEK material only after that assertion passes and a backup
   taken *before* the rotation has been proven restorable against the old KEK.

Until that program exists, treat KEK rotation for a pairwise deployment as
requiring a scheduled change with engineering present. Say so out loud when
someone asks whether the KEK can be rotated: the honest answer today is "for
signing keys, yes, with a short outage; for pairwise salts, not without code".

---

## 5. What this runbook does not cover

* **Upgrades** — `ast-bgg` owns the upgrade runbook.
* **Off-box shipping of the audit chain tip.** The hash chain detects tampering
  by whoever has SQL access; it cannot detect a rewrite of the whole table by
  somebody who also recomputes the chain. Shipping the tip somewhere else is the
  real defence, and it is not built (threat model, residual risks).
* **A KMS or HSM KEK.** The `Kek` port is what one plugs into, and the `kek_id`
  recorded on every row is what makes migrating to one a re-wrap (procedure B)
  rather than a re-issue.
