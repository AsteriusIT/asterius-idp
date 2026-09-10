# Runbook: rotating the key-encryption key

**Status:** describes the system as it is on `ast-bgg`. Every command was run
against the binary built from this tree; the log lines and the program output
quoted below are the strings the code emits, not paraphrases.

This runbook holds what was §4 of [`backup-restore.md`](backup-restore.md) —
that section now points here — plus the incident procedure for destroying one
compromised signing key, which is a different operation with a different blast
radius and is kept apart on purpose (§4).

Related: [`backup-restore.md`](backup-restore.md) (§2 backup, §3 restore — step 1
of every procedure here is a backup), [`upgrade.md`](upgrade.md) (do not run a
rotation and an upgrade together), [`../threat-model.md`](../threat-model.md)
§3 and its residual-risk row on `keys.kek_previous_*`.

---

## 1. What "rotating the KEK" actually means

The KEK is not in the database, so rotating it moves no plaintext: the private
keys and the pairwise salts stay exactly what they were, and only the envelope
around them changes. It encrypts two kinds of row.

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

### The two shapes, and why the online one is the default

`asterius rewrap-kek` re-seals every row the KEK protects under a new key. It is
a foreground operator command, not a background sweep: somebody has to read its
report before destroying the old key material.

**Online** (`ast-7kw`, §2 below) is the form to use. `[keys] kek_previous_file`
(or `kek_previous_env`) names the key being rotated away from; a row that does
not open under the current key is retried under it — decryption only, never
encryption — so the replicas move to the new key *before* the rows do, and no
part of the procedure has a window in which a replica cannot open a row. The
price is step 6: a key you have retired stays readable by the process until that
line is removed.

**Offline** (§3) is the older shape, kept because a deployment may prefer a
maintenance window to a retired key sitting in its configuration.

Verified command surface, from `asterius --help`:

```text
usage: asterius [--config <path>] [--config-reference] [--admin-openapi]
       asterius rewrap-kek [--new-kek-file <path> | --new-kek-env <var>] [--config <path>]
```

There are no other flags. `--new-kek-file` and `--new-kek-env` are mutually
exclusive (`rewrap-kek takes at most one of --new-kek-file and --new-kek-env`),
they are refused on a plain `asterius` invocation, and passing neither is the
online form — the direction then comes from the configuration. `--config`
defaults to `asterius.toml` and also reads `ASTERIUS_CONFIG`.

---

## 2. Rotating online — the procedure

Everything here is per tenant and idempotent. A pass that dies half way is
resumed by running it again: every statement selects on the *old* `kek_id`, so
what has already moved is not touched twice. Two replicas or two operators
running it at once are safe — each tenant is done under
`pg_try_advisory_lock(tenant, 'kek-rewrap')`, and whoever loses the tenant is
told `busy` and moves on.

### 1. Back up, and confirm you can read the current key

[`backup-restore.md`](backup-restore.md) §2. Keep that backup and that key
together until step 7: a backup taken before the rotation can only be restored
with the key that was current when it was taken.

Confirm the key the rows are actually under, which is not necessarily the key
you think is in the file:

```sql
select kek_id, count(*) from signing_keys group by 1;
select kek_id, count(*) from tenant_pairwise_salts group by 1;
```

Those ids must match the `kek` field on the `key-encryption key loaded` line in
a replica's startup log. The id is derived from the key material itself, so
swapping a file and keeping its name changes the id.

### 2. Generate the new key

32 bytes, base64. The parser accepts either alphabet, padded or not, and trims
surrounding whitespace, but the decoded length must be exactly 32.

```sh
head -c 32 /dev/urandom | base64 > /etc/asterius/kek.new
chmod 400 /etc/asterius/kek.new
```

### 3. Move the replicas first

Onto the new key, with the old one behind it, and restart them:

```toml
[keys]
kek_file = "/etc/asterius/kek.new"
kek_previous_file = "/etc/asterius/kek"      # the key being rotated away from
```

`kek_previous_file` is read on **decryption only**. Everything a replica writes
from now on — a staged signing key, a new tenant's salt — is sealed under the
new key, and a row that does not open under it is retried under the previous one
and logged. That is what makes the rest of this procedure online: no replica is
ever unable to open a row, in either direction, so there is no maintenance
window.

Both keys must be readable by the process and both are loaded at boot: a
`kek_previous_file` that is missing, unreadable or not a 32-byte base64 key
refuses the boot (`cannot load the previous key-encryption key: …`), exactly as
the current key does. So does naming the same key twice.

**What you observe.** Each replica logs, at `warn`, once at boot:

```text
a previous key-encryption key is configured: rows that do not open under the
current key are retried under it, and it stays readable by this process until
the line is removed
```

with `kek` = the new id and `previous` = the old one. That line is the reminder
that step 6 has not happened yet.

### 4. Run the re-wrap

With `kek_previous_*` set, the configuration already describes the direction —
from the previous key to the current one — so **no flag is needed** and no
configuration is edited mid-rotation:

```sh
asterius rewrap-kek --config /etc/asterius/asterius.toml
```

**What you observe.** A header naming both key ids, then one line per tenant:

```text
asterius 0.0.0: re-wrapping from <old-kek-id> to <new-kek-id>
demo: signing keys 4, pairwise salt re-wrapped, still on the old key 0, sealed under an unknown key 0
2 tenant(s) are wholly on <new-kek-id>. Point the configuration at it and restart, then run this once more before destroying the old material.
```

`pairwise salt` reads `nothing to do` for a tenant that has none. A tenant held
by another pass prints `busy, another re-wrap holds this tenant`.

It **exits non-zero** if any tenant is not wholly on the new key:

```text
1 of 2 tenant(s) are not wholly on <new-kek-id>; do not destroy the old key
material — run this again once the replicas are on the new key
```

Run it again until it reports every tenant complete; each pass only selects rows
still under the old id, so repeating it is cheap and safe. Nothing in the output
is secret: key ids, counts and tenant ids only.

`rewrap-kek` does **not** run migrations, deliberately — a rotation is not the
moment to change the schema, and the command has to be usable against a database
whose replicas are mid-upgrade.

### 5. Confirm nothing is left behind

```sql
select kek_id, count(*) from signing_keys group by 1;
select kek_id, count(*) from tenant_pairwise_salts group by 1;
```

Both must show only the new id.

The replicas' logs are the other half of this check, and they are the criterion
that ends the pass. Every fallback to the previous key logs, at `warn`:

```text
opened under the previous key-encryption key: this row has not been re-wrapped yet
```

with `row` naming the row exactly — `signing_keys[tenant=demo, kid=…,
purpose=…, alg=ES256]` or `tenant_secret[tenant=demo, secret=…]` — plus `kek`
(the previous id) and `current` (the new one). Nothing derived from the
plaintext is logged.

**The end criterion for this step: no such line, on any replica, after the pass
of step 4 finished.** One of them names a row the re-wrap has not reached, and a
rotation declared finished while they are still arriving is a rotation that was
not finished.

### 6. Remove `kek_previous_file` and restart

This is the step that ends the rotation, and skipping it is the one real risk
this procedure takes on: while the line is there, a key you have retired is
still loaded by the process and still opens rows, so a stolen configuration plus
a stolen dump opens material sealed under *either* key. The window is meant to
be minutes, not weeks.

```toml
[keys]
kek_file = "/etc/asterius/kek.new"
# kek_previous_file removed
```

Restart the replicas. The boot `warn` of step 3 stops appearing; that absence is
how you know the configuration you edited is the configuration they read.

### 7. Verify, then destroy

Mint a token per tenant and check it against the published JWKS, and confirm a
known `sub` is unchanged for a relying party that had one before the rotation.
Only then destroy the old key material — and only once a backup taken *after*
the rotation has been proven restorable under the new key.

---

## 3. Rotating offline — the variant

Choose this only if keeping a retired key in the configuration for the duration
of the rotation is worse, for you, than a window. Leave the configuration naming
the **old** key, name the new one on the command line, and swap the
configuration afterwards.

```sh
asterius rewrap-kek --config /etc/asterius/asterius.toml \
                    --new-kek-file /etc/asterius/kek.new
```

`--new-kek-env ASTERIUS_KEK_NEXT` is the same thing from an environment
variable.

The cost is a window between the first moved row and the last restarted replica.
A signer holds its unwrapped key in memory (`CachedSigner`), so token issuance
keeps working; what fails is anything that has to *open* a row that has already
moved — a replica restarting, a rotation sweep staging a key, a tenant being
created, or the first `sub` minted in a sector for a tenant whose salt has
moved. Keep the steps close together, or run them in a maintenance window.

Steps 1, 2, 5 and 7 of §2 are unchanged. Steps 3 and 6 become "swap `kek_file`
to the new key and restart", after the re-wrap rather than before it.

---

## 4. Rolling a rotation back

Until step 7 the old material still exists, and that is the whole reason step 7
destroys it last rather than first. To go back, run `rewrap-kek` with the two
keys the other way round — the command is symmetric and the old key is a
perfectly good destination:

```sh
asterius rewrap-kek --config /etc/asterius/asterius.toml \
                    --new-kek-file /etc/asterius/kek        # the old one
```

Then swap `kek_file` and `kek_previous_file` back and restart.

Do **not** roll back by deleting `kek_file` and promoting `kek_previous_file`:
the previous key is never written under, so rows moved by step 4 would be left
with nothing that opens them until this command has moved them back.

---

## 5. Purging one compromised signing key

A different incident and a different operation. Rotating the KEK replaces the
envelope around every key; purging destroys **one signing key's private
material** and cannot be undone by anybody, including the operator who did it
(`ast-7rq`).

Reach for this when a private signing key is believed to have leaked. Reach for
§2 when the *key-encryption key* is believed to have leaked — and note that a
KEK compromise is not answered by a purge, because a purge destroys the material
rather than re-sealing it.

### What it does and does not reach

The row stays — the `kid` is never reused and an incident review must see that
the key existed and when it was destroyed — but `private_key_ciphertext`,
`private_key_nonce` and `kek_id` all go to `NULL` in one statement, `state`
becomes `purged`, and `retired_at` is set (coalesced, so a key that had already
left the JWK Set keeps the moment it left). A purged key stops being published,
stops signing, and stops *verifying*: `KeyState::is_trusted` refuses it, which
is the difference between a purge and a retirement.

It does not reach a token some resource server has already accepted. This server
stops signing with the key, stops publishing it and stops accepting its
signatures; it cannot reach into a third party that cached the JWK Set before
the purge and is still inside the token's `exp`. FAPI 2.0 SP §6.8 item 1 asks
for short rotation periods for that reason as well as for a response to
compromise.

Because the material is gone, a purged key needs no re-wrap: it carries no
`kek_id` at all, and `rewrap-kek` skips it.

### The active key is refused

`POST /keys/{kid}/purge` on the active key answers `409` with:

```text
key <kid> is the active <alg> key; rotate with immediate activation to replace it, then purge it
```

So the compromise sequence is **rotate, then purge**, and the rotation must
activate immediately.

### How to call it today

The admin API is mounted at `/admin/api/v1` inside the *tenanted* router, so the
tenant is resolved exactly as it is for that tenant's OIDC endpoints: by host,
or by the `/t/{tenant}` path prefix.

Automation tokens are **not usable yet**. `AdminState.tokens` is wired to `None`
in `crates/server/src/main.rs` until `ast-a05.8` lands, so any request carrying
an `Authorization` header is answered `401 invalid_token` — refusing rather than
accepting something nothing verified. The supported route is the console,
authenticated by the `__Host-asterius_session` cookie.

The console UI is the ordinary way to do this. If you must script the two calls,
sign in at `/admin/` in a browser to obtain the cookie, then:

```sh
BASE="https://as.example/t/demo/admin/api/v1"      # or https://demo.example/admin/api/v1

# 1. The CSRF token, derived from the session and returned by GET /session.
CSRF=$(curl -fsS --cookie "$COOKIEJAR" "$BASE/session" | jq -r .csrf_token)

# 2. Replace the compromised key, activating the replacement at once.
curl -fsS --cookie "$COOKIEJAR" -H "X-CSRF-Token: $CSRF" \
     -H 'Content-Type: application/json' \
     -d '{"alg":"ES256","activate_immediately":true}' \
     "$BASE/keys/rotate"

# 3. Destroy the old one. The reason is required.
curl -fsS --cookie "$COOKIEJAR" -H "X-CSRF-Token: $CSRF" \
     -H 'Content-Type: application/json' \
     -d '{"reason":"INC-42: private key exposed in a build log"}' \
     "$BASE/keys/$KID/purge"
```

Both routes need the `admin.keys:write` authority on this tenant. Every non-`GET`
on the admin API needs `X-CSRF-Token`; `Sec-Fetch-Site` and `Origin` are checked
too, and either of them saying "somewhere else" refuses the request before the
token is looked at.

**The reason is required and is not free of rules.** It is trimmed, must be
non-empty, at most 500 characters, and must carry no control character — a
newline in a string that lands in an audit record and is read back by a SIEM is
how one line becomes two. A blank reason is `400`, not a purge.

### What you observe

`POST /keys/rotate` returns `created_kid`, `activated_kid`, `superseded_kid`,
`retired_kids` and `changed`. `POST /keys/{kid}/purge` returns:

```json
{"kid":"…","previous_state":"retiring","state":"purged","destroyed":true,"published":false}
```

`destroyed` is `false` when the key had already been purged: the request still
succeeded, it simply was not the call that did the destroying, which is what a
retry after a timeout looks like. A `kid` this tenant does not hold is `404`.

Two audit records are written: `key.purged` by the repository, carrying the
reason — because a purge that reached storage must be recorded whatever called
it — and an `admin.changed` naming the console operation and the `kid`.

Afterwards, confirm the key has left the published set (`GET /keys/jwks`, or the
tenant's public JWKS) and that a token minted now verifies under the new `kid`.

---

## 6. What none of this covers

* **Anything the KEK does not seal.** Password hashes, recovery-code hashes,
  passkey public keys and the audit chain are not ciphertext under it; they are
  hashes or public values, and no key rotation touches them.
* **Rows sealed under a third key.** The residue of an earlier, abandoned
  rotation is counted and reported per tenant (`sealed under an unknown key N`)
  rather than skipped quietly. It needs whichever KEK sealed it; the command
  cannot invent one.
* **Rows added while the re-wrap runs.** See step 6. This is why the procedure
  has a second pass rather than a single command.
* **A KMS.** `LocalKek` is the only `Kek` implementation there is, so both keys
  have to be readable by the process running the command. The `Kek` port is what
  one plugs into, and the `kek_id` recorded on every row is what makes migrating
  to a KMS a re-wrap rather than a re-issue; a KMS adapter is the documented
  trigger for revisiting ADR-0008 (`ast-f12`).
* **Rotating the KEK during an upgrade.** [`upgrade.md`](upgrade.md) — two keys
  and two schemas in play at once is two problems, and `rewrap-kek` does not
  migrate.
