# Runbook: backup, restore, and rotating the key-encryption key

**Status:** describes the system as it is on `ast-xni`, not as it is meant to
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

> **Automated as of `ast-xni`.** `asterius rewrap-kek` re-seals every row the KEK
> protects — signing keys *and* pairwise salts — under a new key. It is a
> foreground operator command, not a background sweep: an operator has to read
> its report before destroying the old key material. Earlier versions of this
> runbook said rotation for a pairwise deployment needed a program nobody had
> written; that program is this subcommand.

### What "rotating the KEK" actually means

The KEK is not in the database, so rotating it moves no plaintext: the private
keys and the salts stay exactly what they were, and only the envelope around
them changes. It encrypts two kinds of row.

| Row | How it moves |
|---|---|
| `signing_keys.private_key_ciphertext` | `UPDATE` in place. The `kid` is a thumbprint of the *public* half, which is not encrypted, so nothing a relying party has cached moves. |
| `tenant_pairwise_salts.salt_ciphertext` | `DELETE` + `INSERT` of the **same plaintext**, in one transaction. The table refuses `UPDATE` from a trigger and still does: an updatable salt is an updatable set of subject identifiers, and OIDC Core §8 says a Subject Identifier is never reassigned. |

Both need the old KEK and the new one held at once — the old one is the only
thing that can open a row, the new one the only thing that can re-seal it — and
the AEAD binds each ciphertext to its row's tenant, `kid`, purpose and
algorithm, so none of this can be done in SQL and a byte copied to another row
stops decrypting rather than becoming a working key somewhere else.

The re-wrap does not take the salt's survival on trust: for every tenant it
re-reads the row it has just written, opens it under the new KEK and compares
the salt in constant time with the one it opened under the old. A mismatch rolls
that tenant's transaction back, so the failure mode is "this tenant is still on
the old key", never "every relying party lost its users".

### Procedure

Everything here is per tenant and idempotent. A pass that dies half way is
resumed by running it again: every statement selects on the *old* `kek_id`, so
what has already moved is not touched twice. Two replicas or two operators
running it at once are safe — each tenant is done under
`pg_try_advisory_lock(tenant, 'kek-rewrap')`, and whoever loses the tenant is
told `busy` and moves on.

1. Take a backup (§2) and confirm you can read the *current* KEK. Keep that
   backup and that key together until step 7: a backup taken before the
   rotation can only be restored with the key that was current when it was
   taken.
2. Generate the new key and put it where the deployment will read it from:
   ```sh
   openssl rand -base64 32 > /etc/asterius/kek.new    # mode 0400, owned by root
   ```
3. Run the re-wrap. The configuration file still names the **old** key — that is
   what the command rotates *from* — and the new one is named on the command
   line, so no configuration is edited mid-rotation:
   ```sh
   asterius rewrap-kek --config /etc/asterius/asterius.toml \
                       --new-kek-file /etc/asterius/kek.new
   ```
   It prints one line per tenant and exits non-zero if any tenant is not wholly
   on the new key. Nothing in the output is secret: key ids, counts and tenant
   ids only.
4. Replicas still running are unaffected in the middle of this. A signer holds
   its unwrapped key in memory (`CachedSigner`), so token issuance keeps
   working; what fails, until step 5, is anything that has to *open* a row that
   has already moved — a replica restarting, a rotation sweep staging a key, a
   tenant being created, or the first `sub` minted in a sector for a tenant
   whose salt has moved. Keep steps 3 to 5 close together, or run them in a
   maintenance window if that set of failures is not acceptable.
5. Point the configuration at the new key and restart the replicas:
   ```toml
   [keys]
   kek_file = "/etc/asterius/kek.new"
   ```
6. Run the same command again, with the roles unchanged — the configuration now
   names the new key, so pass the *old* one as `--new-kek-file` only if you mean
   to roll back. The ordinary second pass is:
   ```sh
   asterius rewrap-kek --config /etc/asterius/asterius.toml \
                       --new-kek-file /etc/asterius/kek.new
   ```
   which now refuses with "the new key-encryption key is the one already in
   use" — the deployment is on it. That refusal *is* the confirmation. To check
   the database directly instead:
   ```sql
   select kek_id, count(*) from signing_keys group by 1;
   select kek_id, count(*) from tenant_pairwise_salts group by 1;
   ```
   Both must show only the new id. A row still under the old id is one a replica
   wrote during step 3 to 5; re-run step 3 with the configuration temporarily
   pointed back at the old key, or move the row's tenant on its own.
7. Verify before destroying anything: mint a token per tenant and check it
   against the published JWKS, and confirm a known `sub` is unchanged for a
   relying party that had one before the rotation. Only then destroy the old key
   material — and only once a backup taken *after* the rotation has been proven
   restorable under the new key.

### Rolling back

Until step 7 the old key opens nothing that has moved, and the new key opens
nothing that has not. To go back, run `rewrap-kek` with the two keys the other
way round: the command is symmetric and the old key is a perfectly good
destination as long as it still exists. That is the whole reason step 7 destroys
the old material last rather than first.

### What the re-wrap does not cover

* **Anything the KEK does not seal.** Password hashes, recovery-code hashes,
  passkey public keys and the audit chain are not ciphertext under it; they are
  hashes or public values, and no key rotation touches them.
* **Rows sealed under a third key.** The residue of an earlier, abandoned
  rotation is counted and reported per tenant rather than skipped quietly. It
  needs whichever KEK sealed it; the command cannot invent one.
* **Rows added while it runs.** See step 6. This is why the procedure has a
  second pass rather than a single command.
* **A KMS.** `LocalKek` is the only `Kek` implementation there is, so both keys
  have to be readable by the process running the command. A KMS adapter is the
  documented trigger for revisiting ADR-0008 (`ast-f12`).

---

## 5. What this runbook does not cover

* **Upgrades** — `ast-bgg` owns the upgrade runbook.
* **Off-box shipping of the audit chain tip.** The hash chain detects tampering
  by whoever has SQL access; it cannot detect a rewrite of the whole table by
  somebody who also recomputes the chain. Shipping the tip somewhere else is the
  real defence, and it is not built (threat model, residual risks).
* **A KMS or HSM KEK.** The `Kek` port is what one plugs into, and the `kek_id`
  recorded on every row is what makes migrating to one a re-wrap (§4) rather
  than a re-issue. `asterius rewrap-kek` re-seals through the `Kek` port, but
  the only implementation of that port today reads its material into this
  process, so both keys still have to be local.
