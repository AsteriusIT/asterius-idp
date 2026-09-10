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
SQLX_OFFLINE=true cargo clippy --workspace --all-targets -- -D warnings
SQLX_OFFLINE=true cargo test --workspace   # pure logic, no database
./scripts/check-layering.sh            # ports-and-adapters rule
cargo deny check                       # licences, advisories, bans
```

Integration tests need PostgreSQL 16 and run only when `DATABASE_URL` is set;
without it they print a skip line and the suite stays fast.

```sh
cp .env.example .env && cp .env crates/store-pg/.env
docker compose up -d --wait db
cargo sqlx migrate run --source crates/store-pg/migrations
cargo test --workspace          # now includes the database tests
```

Do not skip that migration line. A database that is running but not migrated is
worse than no database at all: `DATABASE_URL` — from the environment or from
the `crates/store-pg/.env` copied just above — takes sqlx *out* of offline
mode, and it then verifies all 122 `query!` invocations against an empty
schema and fails every one of them. Start the container and migrate it in one
step, or start neither.

The same asymmetry explains why anything that compiles without a database
should say so explicitly. `scripts/check.sh` (no `--db`), `scripts/check-geiger.sh`,
`scripts/check-fuzz-coverage.sh`, `scripts/browser-tests.sh` and the
`.claude/hooks/cargo-check.sh` edit hook all set `SQLX_OFFLINE=true` for that
reason. Left unset with nothing listening on 5433, sqlx dials the database and
waits out its connect timeout while holding cargo's build lock, which looks
exactly like a hung build.

Each database test creates its own PostgreSQL schema, migrates it and works
inside it, so they run in parallel and share nothing.

The browser sweep is separate, because it needs a browser and a running server
rather than a test binary. It is the only thing here that proves the end-user
pages work with JavaScript disabled, that Chromium keeps the `__Host-` cookies
we set, and that no page provokes a CSP violation — all browser-enforced
properties that no Rust test can observe. One script starts everything:

```sh
./scripts/browser-tests.sh              # both suites, ~1 minute after the first run
./scripts/browser-tests.sh --headed     # watch it happen
```

Node lives in two directories and nowhere else, both with exact versions and a
committed lockfile: `e2e/` for Playwright, and `console/` for the admin
console. `e2e/README.md` explains what the sweep proves and what it does not
yet cover.

The console is a React bundle **embedded in the binary** (ADR-0009), so it is
built before cargo:

```sh
make console                    # or ./scripts/build-console.sh
cargo build --bin asterius      # embeds console/dist
```

A checkout without Node still compiles: `crates/admin-api/build.rs` then embeds
an empty bundle and `/admin/` answers 503 naming the command that was not run.
`scripts/browser-tests.sh`, the CI browser job and the release image all build
it first. `console/README.md` explains why there is no `index.html` and no dev
server.

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

## Disk space

A workspace this size, built in debug with test binaries, is expensive to keep
on disk, and cargo never reclaims anything: every distinct code state adds a
new hash-suffixed artifact to `target/debug/deps` and the previous one stays
forever. A single day of branch switching here left 257 copies of the
`asterius` binary (2.4 GB) and 110 copies of the `tls_handshake` test binary
(1.3 GB), in a 21 GB `deps/`. Agent worktrees make it worse: each one is a
separate checkout with its own `target/`, roughly 1 GB after nothing more than
a `cargo check`.

```sh
./scripts/gc-build-artifacts.sh             # report what is reclaimable
./scripts/gc-build-artifacts.sh --apply     # delete artifacts idle for 24h
./scripts/gc-build-artifacts.sh --apply --hours 6
```

Prefer it to `cargo clean`: it drops only artifacts nothing has touched in a
while, so the build you are working on stays warm, and anything it removes
cargo rebuilds on demand. It never touches a worktree another agent is
compiling in unless you pass `--worktrees`.

The other half of the bill is the agent worktrees themselves, which nothing
removes automatically — `git worktree prune` only forgets directories that are
already gone. `./scripts/cleanup-worktrees.sh --apply` deletes worktree and
branch for every `claude/*` merged into `main`; without `--apply` it only says
what it would do. It skips worktrees git reports as locked, which is how a
running agent marks its own, and branches still sitting on the tip of `main`,
which have merged nothing and belong to an agent that just started.

Sharing one `CARGO_TARGET_DIR` across worktrees looks like the obvious fix and
is not: cargo takes an exclusive lock on the build directory, so concurrent
builds print `Blocking waiting for file lock on build directory` and run one
after another. Measured with cargo 1.98: two 8-second builds sharing a target
directory took 15 seconds of wall clock instead of 8.

### WSL2: freeing space inside does not give it back to Windows

On WSL2 the whole filesystem lives in one `ext4.vhdx`, a virtual disk that
grows on demand and **never shrinks on its own**. Deleting 20 GB inside the
distribution leaves the `.vhdx` exactly as large as it was on `C:`. Reclaiming
it is a manual, Windows-side operation — shut WSL down first, then, from an
elevated PowerShell:

```powershell
wsl --shutdown
Optimize-VHD -Path "$env:LOCALAPPDATA\Packages\<distro>\LocalState\ext4.vhdx" -Mode Full
```

`Optimize-VHD` ships with the Hyper-V management tools; without them,
`diskpart`'s `compact vdisk` does the same job. The virtual disk also has a
maximum size — 251 GB by default on this machine — which caps `/` no matter how
much room the Windows volumes have. Raise it with:

```powershell
wsl --manage <distro> --resize 400GB
```

Other Windows drives are not an escape hatch: they are reachable only through
`/mnt/...` with a translation layer that makes them far too slow to build on.

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

## Fuzzing

The definition of done says every parser and validator has a fuzz target. That
is mechanical, not remembered: an entry point opts in with a marker comment,

```rust
// fuzz-target: issuer_parse
pub fn parse(raw: &str) -> Result<Self, IssuerError> { … }
```

and `scripts/check-fuzz-coverage.sh` fails CI if the matching target is missing
— or if a target exists that nothing claims, which is how a target survives the
code it used to cover and sits in CI proving nothing.

The inventory of what is covered lives in [`docs/fuzzing.md`](docs/fuzzing.md),
along with how the pull-request and nightly runs differ and what happens when a
crash is found. It is generated — `./scripts/gen-fuzzing-doc.sh > docs/fuzzing.md`
— and the same gate fails when the committed file is stale, because an
inventory of coverage that has drifted is worse than none.

```sh
rustup toolchain install nightly     # libFuzzer needs it
cargo install cargo-fuzz

cargo +nightly fuzz list
cargo +nightly fuzz run issuer_parse -- -max_total_time=60
./scripts/check-fuzz-coverage.sh
```

**Write targets that assert, not just targets that run.** "Does not panic" is
the weakest property a parser has. Every target here also checks the invariant
the rest of the server relies on — that an accepted issuer is canonical and
re-parses to itself, that a tenant id cannot escape a path segment, that
redaction is idempotent, that two different audit events cannot share an
encoding. A crash-only target passes happily while the parser returns nonsense.

A crash found by fuzzing gets a regression test in the ordinary suite as well
as a corpus entry, because the corpus is not run on every commit and the test
suite is.
