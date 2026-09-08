#!/usr/bin/env bash
# Belt and braces around `#![forbid(unsafe_code)]`: an `unsafe` block that
# somehow compiles should still stop the build.
#
# The subtlety is what counts as "unsafe". A bare `\bunsafe\b` looks right and
# is not: `-` is a word boundary, so it matches the CSP keywords
# `'unsafe-inline'`, `'unsafe-eval'`, `'unsafe-hashes'` and
# `wasm-unsafe-eval` — which `crates/web` contains on purpose, in the code that
# exists to make sure the policy never *emits* them. A security gate that fires
# on the security control it is protecting gets switched off, so this matches
# the Rust grammar instead.
#
# In Rust the keyword is only ever followed by whitespace and then one of a
# short list of tokens. It is never followed by `-` or `_`, which is what
# separates it from `unsafe-inline` and from `unsafe_code`.
set -euo pipefail
cd "$(dirname "$0")/.."

# `unsafe {`, `unsafe fn`, `unsafe impl`, `unsafe trait`, `unsafe extern`.
# Anchored on the keyword having real whitespace after it.
pattern='(^|[^A-Za-z0-9_-])unsafe[[:space:]]+(\{|fn[[:space:]]|impl[[:space:]]|trait[[:space:]]|extern[[:space:]])'

# Every first-party Rust source. `fuzz/` is first-party too: a fuzz target is
# code we wrote and ship in the repository.
if hits="$(grep -rnE --include='*.rs' "$pattern" crates/ fuzz/fuzz_targets/ 2>/dev/null)"; then
  echo "$hits" >&2
  echo "UNSAFE FOUND: the lines above use the \`unsafe\` keyword" >&2
  echo "  every crate root carries #![forbid(unsafe_code)]; if one of these is" >&2
  echo "  genuinely needed it is an ADR, not a patch" >&2
  exit 1
fi

# The other half: the attribute must actually be on every crate root, or the
# grep above is guarding nothing. `check-layering.sh` asserts this for the
# workspace members; this covers the roots it does not walk.
missing=0
while IFS= read -r root; do
  if ! grep -q '#!\[forbid(unsafe_code)\]' "$root"; then
    echo "MISSING ATTRIBUTE: $root has no #![forbid(unsafe_code)]" >&2
    missing=1
  fi
done < <(find crates -name lib.rs -o -name main.rs | sort)

if [[ "$missing" -ne 0 ]]; then
  exit 1
fi

echo "no unsafe in first-party code, and every crate root forbids it"
