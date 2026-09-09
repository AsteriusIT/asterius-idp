#!/usr/bin/env bash
# Renders docs/fuzzing.md — the committed list of parsers and their fuzz
# targets that the definition of done asks for.
#
#     ./scripts/gen-fuzzing-doc.sh > docs/fuzzing.md
#
# The list is derived, not written. A table of 35 targets kept by hand is wrong
# from the first parser somebody adds, and a stale inventory of what is fuzzed
# is worse than none: it answers "is this covered?" with a confident no-longer-
# true yes. So the rows come out of the same two places the gate reads — the
# `// fuzz-target:` markers in `crates/` and `fuzz/fuzz_targets/` — and
# `check-fuzz-coverage.sh` fails if the committed file is not what this prints.
#
# What stays prose is the part only a person can write: what fuzzing is for
# here, how to run it, and what to do with a crash.
set -euo pipefail
cd "$(dirname "$0")/.."

# One row per marker: target, entry point, source file.
#
# The entry point is read from the first line after the marker that is not an
# attribute or a comment, so `#[must_use]` between the two does not hide the
# signature. A marker indented inside an `impl` block is reported as
# `Type::method`, which is what a reader needs to find it; the enclosing type
# is the last `impl` at column zero, including the `for` type of a trait impl.
rows="$(find crates -name '*.rs' | sort | xargs awk '
  FNR == 1 { impl_type = ""; pending = 0 }

  /^impl/ {
    line = $0
    sub(/^impl(<[^>]*>)?[[:space:]]+/, "", line)
    if (line ~ /[[:space:]]for[[:space:]]/) sub(/^.*[[:space:]]for[[:space:]]+/, "", line)
    sub(/[[:space:]]*\{.*$/, "", line)
    sub(/<.*$/, "", line)
    gsub(/[[:space:]]/, "", line)
    impl_type = line
  }

  /\/\/ fuzz-target: / {
    target = $0
    sub(/^.*\/\/ fuzz-target: /, "", target)
    gsub(/[^a-z0-9_]/, "", target)
    indented = ($0 ~ /^[[:space:]]/)
    pending = 1
    next
  }

  pending && /^[[:space:]]*(#\[|\/\/)/ { next }

  pending {
    entry = "?"
    if (match($0, /fn [A-Za-z0-9_]+/)) {
      entry = substr($0, RSTART + 3, RLENGTH - 3)
      if (indented && impl_type != "") entry = impl_type "::" entry
    }
    print target "\t" entry "\t" FILENAME
    pending = 0
  }
' | sort -u)"

[[ -n "$rows" ]] || { echo "no // fuzz-target: markers found" >&2; exit 1; }

count_targets="$(cut -f1 <<<"$rows" | sort -u | wc -l)"
count_entries="$(wc -l <<<"$rows")"

cat <<'PROSE'
# Fuzzing

<!-- Generated file. Do not edit by hand: run `./scripts/gen-fuzzing-doc.sh > docs/fuzzing.md`. -->

Every parser and validator in this repository has a fuzz target. That is a
definition-of-done item rather than an aspiration, so it is enforced:
`scripts/check-fuzz-coverage.sh` runs in the `lint` job of CI and fails when a
declared parser has no target, when a target covers nothing, when the registry
in `fuzz/Cargo.toml` has drifted from the directory, or when a target no longer
compiles or is not lint-clean.

## Declaring a target

An entry point opts in with a marker comment on the line above it:

```rust
// fuzz-target: issuer_parse
pub fn parse(raw: &str) -> Result<Self, IssuerError> { … }
```

The gate then requires `fuzz/fuzz_targets/issuer_parse.rs` to exist and to be
registered as a `[[bin]]`. After adding or removing a target file, run
`./scripts/sync-fuzz-registry.sh` to regenerate that registry, and
`./scripts/gen-fuzzing-doc.sh > docs/fuzzing.md` to regenerate the table below.
Both are checked; neither is written by hand.

## Running

```sh
# One target, until you stop it. Needs a nightly toolchain and cargo-fuzz.
cargo +nightly fuzz run --target x86_64-unknown-linux-gnu issuer_parse

# The way CI runs it: bounded, with the final statistics.
cargo +nightly fuzz run --target x86_64-unknown-linux-gnu issuer_parse \
  -- -max_total_time=60 -print_final_stats=1
```

The target triple is pinned because AddressSanitizer cannot work against a
statically linked libc: on a host whose default target is a musl triple, every
run fails before it starts.

## Where it runs

| | On every pull request | Nightly |
|---|---|---|
| Workflow | `ci.yml`, job `fuzz` | `fuzz-nightly.yml` |
| Budget | 60 s per target | 600 s per target |
| Corpus | restored, not written back | restored and saved, and uploaded as an artefact |
| On a crash | job fails, artefacts uploaded | job fails, artefacts uploaded, and a GitHub issue is opened |

One job per target, never a loop: a loop stopped at the first failure and hid
two broken targets behind a third for an unknown length of time.

## When a crash is found

The nightly run uploads the crashing input as the artefact
`crash-<target>` and opens a GitHub issue titled `fuzz: <target> crashed`,
commenting on the existing one rather than opening a second if it is still
open. GitHub issues are used there because the project's tracker (beads) lives
in a local Dolt database that a runner cannot reach; triage still belongs in
beads, so the issue is a notification, not the ticket.

Reproduce with the downloaded input:

```sh
cargo +nightly fuzz run --target x86_64-unknown-linux-gnu <target> path/to/crash-input
```

## Coverage

PROSE

printf 'The %s targets below cover %s declared entry points. Generated from the\n' \
  "$count_targets" "$count_entries"
printf '`// fuzz-target:` markers in `crates/`.\n\n'

printf '| Fuzz target | Entry point | Source |\n'
printf '|---|---|---|\n'
while IFS=$'\t' read -r target entry file; do
  printf '| `%s` | `%s` | `%s` |\n' "$target" "$entry" "$file"
done <<<"$rows"
