# Contributing to Asterius

Asterius is an identity provider. A bug here is not a broken feature; it is
somebody else's account. The rules below exist because of that, and they apply
to human and AI contributors alike.

## The one rule that is not negotiable

> **Generated crypto or parsing code is not done until a human has read the
> relevant RFC section.**

This applies to code written by an AI agent, code copied from another project,
and code you wrote yourself from memory. "It passes the tests" is not the bar:
the tests were derived from the same reading that produced the code, so a
misread clause produces a confidently green suite. Open the specification, read
the clause you are citing, and check that the code does what the normative text
says — including the MUST NOTs, which tests rarely cover.

If you cite a clause in a comment, an ADR or `docs/threat-model.md`, you are
asserting that you read it.

## Definition of done

A story is not done until all of these hold:

1. **A spec-derived or conformance-suite test passes.** Name the clause in the
   test, so a reader can check the test against the text.
2. **A fuzz target exists for every new parser or validator.** Anything that
   takes attacker-controlled bytes and produces a typed value is a parser.
3. **`docs/threat-model.md` is updated.** Add or update the row, with the bead
   id. A new endpoint with no row in the threat model is not finished.
4. **No new `unsafe`.** Every crate root carries `#![forbid(unsafe_code)]` and
   `scripts/check-layering.sh` fails if one loses it.
5. **A human has read the cited spec clauses.**

## Local checks

These are the same checks CI runs. The pure test suite is deliberately fast —
sub-second — because a suite that is slow is a suite that gets skipped:

```sh
./scripts/check.sh          # everything CI runs, no database needed
./scripts/check.sh --db     # also starts PostgreSQL and runs the database tests
```

Individually, in the order they fail fastest:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace                 # pure logic, no database
./scripts/check-layering.sh            # ports-and-adapters rule
cargo deny check                       # licences, advisories, bans
```

Integration tests need PostgreSQL 16 and run only when `DATABASE_URL` is set;
without it they print a skip line and the suite stays fast.

```sh
cp .env.example .env && cp .env crates/store-pg/.env
docker compose up -d db
cargo test --workspace          # now includes the database tests
```

Each database test creates its own PostgreSQL schema, migrates it and works
inside it, so they run in parallel and share nothing.

`sqlx` checks queries against a live database at compile time. After changing
any SQL, regenerate the offline data and commit it, or CI (which builds with
`SQLX_OFFLINE=true` and no database) will fail:

```sh
cargo sqlx prepare --workspace -- --all-targets
```

Until the first release the baseline migration is still being edited, and sqlx
refuses to run a migration whose checksum has changed since it was applied —
which is exactly what protects a production database. Reset the local one
instead:

```sh
psql "$DATABASE_URL" -c 'drop schema public cascade; create schema public;'
```

`crates/store-pg/.env` is a workaround, not a convention: sqlx walks every
ancestor directory looking for `.env`, so a stray `.env` anywhere above the
repository — a Python virtualenv named `.env`, for instance — breaks the build
until sqlx finds a readable one first.

## Architecture rules

**Protocol code talks to the outside world only through ports.**
`asterius-domain` declares a trait for every outside dependency;
`asterius-oidc` holds pure protocol logic and performs no I/O. Adapters live in
`asterius-jose`, `asterius-store-pg`, `asterius-web`, `asterius-admin-api`, and
are wired together in `asterius-server`. `scripts/check-layering.sh` enforces
this against the resolved dependency graph, so a banned crate is caught even
when it arrives transitively. See [ADR-0001](docs/adr/0001-modular-monolith.md).

**FAPI 2.0 is the baseline, not a mode.** A change that introduces a weaker
alternative path — a bearer token, a public client, a non-PAR authorization
request, `client_secret_basic` — will be rejected, and the review will suggest
the compliant equivalent. See
[ADR-0002](docs/adr/0002-fapi-2-0-as-the-only-mode.md).

**Where the spec and a popular implementation disagree, follow the spec** and
document the interop risk in the PR description and in the relevant ADR.

## Decisions

Anything that constrains future work gets an ADR in [`docs/adr/`](docs/adr/).
Copy [the template](docs/adr/0000-template.md); it has four required sections —
Context, Decision, Consequences, Spec clauses. An ADR is immutable once merged:
reverse a decision with a new record that supersedes the old one.

## Issue tracking

Work is tracked with [beads](https://github.com/gastownhall/beads), not with
GitHub issues or TODO comments:

```sh
bd ready            # what is available to work on
bd show ast-xxx     # the story, its spec citations and its acceptance criteria
bd update ast-xxx --claim
bd close ast-xxx
```

A pull request references the bead id in its title, in the form
`feat(area): summary [ast-xxx]`.

## Pull requests

Small and reviewable. A PR that changes protocol behaviour and adds a
dependency and refactors a module will be asked to become three.

Anything that weakens the FAPI 2.0 baseline, adds complexity without a stated
reason, or re-introduces a protocol that is out of scope for v1 (SAML, LDAP,
implicit flow) will be pushed back on — with a compliant alternative.

## Language

English for code, identifiers, commit messages, comments and ADRs. Issues and
discussions in English or French.

## Reporting a vulnerability

Do not open a public issue. Until a security contact is published, report
privately to the repository owner. We will acknowledge within 72 hours.
