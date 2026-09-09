# ADR-0008: The pairwise salt is decrypted per mint and not cached

- **Status:** Accepted
- **Date:** 2026-09-09
- **Bead:** ast-f12
- **Deciders:** Quentin RODIC
- **Refines:** [ADR-0004](0004-jose-on-aws-lc-rs.md)

## Context

`PgUserRepository::subject` reads `tenant_pairwise_salts` and unwraps the row
under the [`Kek`] port before deriving a `sub` (OIDC Core §8.1). `ast-2vk.11`
deferred a per-tenant in-process cache of the decrypted salt and filed `ast-f12`
to argue it, on the grounds that with a KMS adapter the unwrap is "a network
round trip per `id_token`" and that the salt is written once and never changes,
so a cache would be trivially correct — against the cost of holding key material
in memory for the life of the process.

Four things in the tree decide it, and two of them contradict the premise.

**There is no KMS adapter.** `LocalKek` is the only implementation of `Kek`
there is (`crates/jose/src/kek.rs`); the trait is `async` in anticipation of one,
not because one exists. The network round trip the cache would remove is a round
trip nothing makes today. What it does remove today is one AES-GCM open —
microseconds — and one primary-key `select`, on a connection the same request
already holds.

**It is not once per `id_token`.** `subject` has one production caller:
consent completion in `crates/server/src/http/interaction.rs`, which writes the
resolved subject into the `Grant`. Every later issuance — the id_token, a
refresh, userinfo — reads `Grant::subject` and never touches the salt. So the
unwrap happens once per *authorization*, an interactive, human-paced operation
that has already rendered a consent page and written several rows. The cost is
being paid on the cheapest possible path relative to what surrounds it.

**A forever-cache is not the shape this repository uses for decrypted key
material.** `CachedSigner` (`crates/server/src/signing.rs`) already holds
unwrapped *private signing keys* in memory, so "may a secret live in memory" is
settled here and settled yes. What it does not do is hold one forever: entries
carry an age and are reloaded past a 60-second TTL, and its module documentation
gives the reason invalidation was rejected — "exact within one process and
useless across replicas, which is the deployment this has to work in". The
invalidation `ast-f12` proposes, on tenant deletion, has exactly that defect:
`tenant_pairwise_salts` cascades from `tenants`, so the row goes, but the copy
in the other four replicas' memory does not.

**A cache would undo a property the plaintext already has.** `PairwiseSalt`
wraps its bytes in `Secret`, which redacts `Debug`/`Display` and zeroes the
value on drop. Read per mint, the plaintext exists for one derivation and is
zeroed when the `Result` goes out of scope. Cached, it is alive until eviction —
which for the proposed design is process exit. The cache does not merely add a
secret to memory; it converts a secret with a bounded lifetime into one without,
which is precisely the property `Secret` was written to provide.

**A cache would have to outlive its holder.** `PgUserRepository` is constructed
per request from `TenantScope::users`, so a field on it caches nothing. The cache
would have to be a process-global tenant-keyed map — a new long-lived container
of secrets, reached from the store layer, whose sole current benefit is an
AES-GCM open on a path that renders HTML.

The alternatives considered:

- **Process-lifetime cache in a global map, invalidated on tenant delete.**
  What the bead describes. Rejected: the benefit is hypothetical (no KMS), the
  frequency premise is wrong (once per authorization, not per `id_token`), and
  the invalidation is per-replica, which means the property it advertises — the
  salt is gone when the tenant is gone — is not one it delivers.
- **A TTL cache in the composition root, shaped like `CachedSigner`.** The
  correct design *if* the cost were real. Rejected as premature: it is code and
  a container of secrets bought against a measurement nobody has taken, on an
  adapter nobody has written.
- **Passing the salt in as an argument, resolved once per request.** Rejected on
  older grounds that still hold: `crates/store-pg/src/users.rs` refuses to take
  a salt as a parameter, because a caller able to supply one is a caller able to
  supply the wrong one, and the first derivation is the one written to
  `subject_identifiers` and handed to a relying party. Permanently wrong beats
  slow.

## Decision

The salt is read and unwrapped on every mint. No cache.

When a KMS adapter lands (`ast-mxc.3`) and a measurement shows the unwrap on the
authorization path to matter, the cache to build is the one this repository
already has: a TTL-bounded, reload-on-expiry cache in the composition root,
shaped like `CachedSigner`, not a process-lifetime map in the storage layer and
not an invalidation scheme that only works on one replica. Reopening this needs
that adapter and that measurement, not the argument above repeated.

## Consequences

Nothing changes in the code path, which is the point: no new long-lived secret
container, no cross-replica invalidation to get wrong, no `Debug` or `Display`
that could carry a salt into a log. The standing cost is one indexed `select`
and one AES-GCM open per authorization.

`ast-f12` closes as decided rather than implemented. The decision is bound to a
fact that can change — `LocalKek` being the only `Kek` — so `ast-mxc.3`, which
owns the KEK story, inherits the trigger to revisit it.

`ast-2vk.12` (subject identifiers are not tombstoned on user deletion) would have
shared nothing with this: it needs a *user*-deletion hook and a tombstone table,
while the invalidation rejected here is on *tenant* deletion. No hook is added,
so it inherits no work.

## Spec clauses

| Clause | What it requires | How this decision satisfies it |
|---|---|---|
| OIDC Core §8.1 | A pairwise Subject Identifier "MUST NOT be reversible by any party other than the OpenID Provider"; the calculation uses a "salt value … known only to the OP" | The salt stays sealed under the `Kek` at rest and exists in plaintext only for the duration of one derivation, rather than for the life of the process |
| OIDC Core §8 | A Subject Identifier is "a locally unique and never reassigned identifier within the Issuer for the End-User" | Unaffected: the derivation and the `subject_identifiers` row it writes are untouched |
