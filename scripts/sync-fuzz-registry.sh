#!/usr/bin/env bash
# Regenerates the `[[bin]]` list in fuzz/Cargo.toml from the files on disk.
#
# Every entry is mechanically derivable from `fuzz/fuzz_targets/*.rs` — the
# name is the stem, the path is the file, and the three flags are the same for
# all of them. Keeping it by hand has cost three dropped registrations in one
# day, every one of them while resolving a merge conflict in a file where the
# conflict markers land inside a `[[bin]]` block and take a `name = ` line with
# them.
#
# `check-fuzz-coverage.sh` still does the checking: this only removes the step
# a human was doing badly. A file with no `// fuzz-target:` marker is still an
# orphan and still fails the gate.
set -euo pipefail
cd "$(dirname "$0")/.."

manifest=fuzz/Cargo.toml
[[ -f "$manifest" ]] || { echo "no $manifest" >&2; exit 1; }

# Everything above the first [[bin]] is hand-written and preserved verbatim.
head="$(sed '/^\[\[bin\]\]$/,$d' "$manifest")"
[[ -n "$head" ]] || { echo "$manifest has no preamble; refusing to rewrite" >&2; exit 1; }

{
  # A trailing newline, restored: `$(...)` strips them, and without this the
  # first `[[bin]]` is glued onto the last line of the preamble — which parses,
  # silently loses that target, and is exactly the failure this script exists
  # to stop. Caught by comparing the registry with the directory afterwards.
  printf '%s\n\n' "$head"
  for file in fuzz/fuzz_targets/*.rs; do
    name="$(basename "$file" .rs)"
    printf '[[bin]]\nname = "%s"\npath = "fuzz_targets/%s.rs"\ntest = false\ndoc = false\nbench = false\n\n' \
      "$name" "$name"
  done
} > "$manifest.new"

# Trim the trailing blank line.
printf '%s\n' "$(cat "$manifest.new")" > "$manifest"
rm -f "$manifest.new"

echo "fuzz registry synced: $(ls fuzz/fuzz_targets/*.rs | wc -l) targets"
