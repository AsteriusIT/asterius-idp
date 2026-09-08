# ADR-0001: Modular monolith, single binary, one PostgreSQL

- **Status:** Accepted
- **Date:** 2026-09-08
- **Bead:** ast-83p.1, ast-83p.9
- **Deciders:** Quentin RODIC

## Context

An identity provider is a *coordination* problem, not a throughput problem. A
single authorization-code redemption touches the authorization request, the
client record, the grant, the session, the key material, the token denylist and
the audit log, and it must do all of that atomically: a code that is consumed
but whose grant is not created is a security defect, not an eventual-consistency
inconvenience.

The obvious alternative shapes:

- **Microservices per protocol area** (authorization service, token service,
  session service). Every one of the above invariants becomes a distributed
  transaction or a saga. The failure modes multiply exactly where correctness
  matters most, and no operator of a self-hosted IdP wants to run seven
  deployments to get a login page.
- **Monolith with no internal boundaries.** Fast to write, and it works — until
  protocol logic grows a direct dependency on `sqlx`, at which point testing an
  RFC clause requires a database, the test suite slows to the point where nobody
  runs it, and swapping the crypto provider becomes a rewrite.
- **A cache tier (Redis) for codes, PAR requests and rate limits.** Adds a second
  stateful system to operate and back up, and puts security-critical single-use
  state (authorization codes) somewhere that is not transactional with the grant
  it authorises.

FAPI 2.0 SP §5.1.1 tells implementers to build on complete, correct
implementations rather than assembling partial ones — which argues for fewer
moving parts, not more.

## Decision

Asterius is a **modular monolith**: one `asterius` binary, one PostgreSQL
database, no Redis, no message broker. Internal structure is **ports and
adapters**:

```
asterius-domain     entities, ids, ports (traits)         — no I/O
asterius-oidc       protocol logic over domain types      — no I/O
asterius-jose       KeyStore/Signer adapter
asterius-store-pg   sqlx adapters
asterius-web        server-rendered pages
asterius-admin-api  admin HTTP surface
asterius-server     composition root, axum wiring
```

**Protocol code talks to the outside world only through ports.**
`asterius-domain` declares a trait for every outside dependency;
`asterius-oidc` decides what the protocol requires and performs no I/O. The rule
is enforced, not documented: `scripts/check-layering.sh` walks the resolved
`cargo metadata` graph in CI and fails if `asterius-domain` or `asterius-oidc`
can reach `sqlx`, `axum`, `tokio`, `hyper`, `reqwest` or `askama` — directly or
transitively.

Asynchronous work that genuinely must survive a crash (back-channel logout,
SSF push delivery) uses a **transactional outbox** in the same database
(`ast-0ju.9`), so the event and the state change it describes commit together.

## Consequences

**Easier.** Multi-table invariants are one `BEGIN`/`COMMIT`. Deployment is a
binary and a connection string. A protocol rule is tested as a pure function
against the normative text — no container, no fixture database — which is what
keeps `cargo test` fast enough to run on every edit and is the reason the
layering rule is worth enforcing mechanically.

**Harder.** Horizontal scaling is per-process, not per-component; the database
is the scaling ceiling, and `ast-p2l.8` owns the index review that keeps it high
enough. Long-running work (key rotation, outbox delivery, retention) runs inside
the binary and needs leader election or advisory locks to stay safe across
replicas.

**To maintain.** The layering script and its ban list. A dependency added to a
protocol crate for convenience will fail CI, and that is the intended
experience.

## Spec clauses

| Clause | What it requires | How this decision satisfies it |
|---|---|---|
| FAPI 2.0 SP §5.1.1 | Build on complete and correct implementations of the underlying specifications | One implementation of each protocol rule, in one place, with no cross-service duplication to drift |
| RFC 6749 §10.5 | Authorization codes must be single-use, and reuse must be detectable | Code consumption and grant creation commit in one transaction against one database |
