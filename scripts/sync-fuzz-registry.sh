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
# With `--check` it writes nothing and instead fails if the manifest is not
# what it would have rendered, naming each difference and which side it is on.
# That is the mode `check-fuzz-coverage.sh` runs, so the gate and the generator
# agree on what "registered" means by construction rather than by two copies of
# the same awk. Both directions fail: a file with no `[[bin]]` is never
# compiled and never fuzzed while looking covered — four WebAuthn parsers sat
# in exactly that state on `main` — and a `[[bin]]` with no file breaks the
# build of the whole crate.
#
# `check-fuzz-coverage.sh` still owns the rest of the checking: a file with no
# `// fuzz-target:` marker is still an orphan and still fails the gate.
set -euo pipefail
cd "$(dirname "$0")/.."

mode=write
case "${1-}" in
  '') ;;
  --check) mode=check ;;
  *) echo "usage: $(basename "$0") [--check]" >&2; exit 2 ;;
esac

manifest=fuzz/Cargo.toml
[[ -f "$manifest" && -r "$manifest" ]] || { echo "cannot read $manifest" >&2; exit 1; }

# Fail closed on an empty enumeration. A `find` that returns nothing — the
# directory renamed, the script run from somewhere unexpected, a checkout that
# never had the targets — must not read as "the manifest matches the zero
# targets on disk", which is how a coverage gate ends up passing while covering
# nothing.
targets=()
while IFS= read -r name; do
  targets+=("$name")
done < <(find fuzz/fuzz_targets -maxdepth 1 -type f -name '*.rs' -printf '%f\n' 2>/dev/null \
           | sed 's/\.rs$//' | sort)
if [[ "${#targets[@]}" -eq 0 ]]; then
  echo "no fuzz targets found in fuzz/fuzz_targets/ — refusing to treat that as up to date" >&2
  exit 1
fi

# Everything above the first [[bin]] is hand-written and preserved verbatim.
head="$(sed '/^\[\[bin\]\]$/,$d' "$manifest")"
[[ -n "$head" ]] || { echo "$manifest has no preamble; refusing to rewrite" >&2; exit 1; }

render() {
  # A trailing newline, restored: `$(...)` strips them, and without this the
  # first `[[bin]]` is glued onto the last line of the preamble — which parses,
  # silently loses that target, and is exactly the failure this script exists
  # to stop. Caught by comparing the registry with the directory afterwards.
  printf '%s\n\n' "$head"
  local name
  for name in "${targets[@]}"; do
    printf '[[bin]]\nname = "%s"\npath = "fuzz_targets/%s.rs"\ntest = false\ndoc = false\nbench = false\n\n' \
      "$name" "$name"
  done
}

# `$(...)` trims the trailing blank line for us.
expected="$(render)"

if [[ "$mode" == write ]]; then
  printf '%s\n' "$expected" > "$manifest"
  echo "fuzz registry synced: ${#targets[@]} targets"
  exit 0
fi

# --- --check ---------------------------------------------------------------

# The names the manifest actually declares, in the order they appear. Not
# `sort -u`: a name declared twice is itself a difference worth failing on.
registered="$(awk '/^\[\[bin\]\]/ { in_bin = 1; next }
                   in_bin && /^name = / { gsub(/^name = "|"$/, ""); print; in_bin = 0 }' \
              "$manifest" | sort)"
on_disk="$(printf '%s\n' "${targets[@]}")"

status=0

while read -r name; do
  [[ -z "$name" ]] && continue
  echo "FUZZ TARGET NOT REGISTERED: fuzz/fuzz_targets/$name.rs has no [[bin]] in $manifest" >&2
  echo "  it is never compiled and never fuzzed, by CI or by the nightly run" >&2
  status=1
done < <(comm -23 <(printf '%s\n' "$on_disk") <(printf '%s\n' "$registered"))

while read -r name; do
  [[ -z "$name" ]] && continue
  echo "FUZZ REGISTRY ENTRY WITHOUT A FILE: $manifest declares '$name'" >&2
  echo "  but fuzz/fuzz_targets/$name.rs does not exist" >&2
  status=1
done < <(comm -13 <(printf '%s\n' "$on_disk") <(printf '%s\n' "$registered"))

# The sets can agree while the entries do not: a wrong `path`, a missing
# `test = false`, a duplicated block. The manifest is generated, so anything
# this script would not have written is a hand edit and fails too.
if [[ "$status" -eq 0 ]] && ! diff -u "$manifest" <(printf '%s\n' "$expected") >/dev/null; then
  echo "FUZZ REGISTRY NOT AS GENERATED: $manifest differs from the rendered list" >&2
  diff -u "$manifest" <(printf '%s\n' "$expected") >&2 || true
  status=1
fi

if [[ "$status" -ne 0 ]]; then
  echo "  run: ./scripts/sync-fuzz-registry.sh" >&2
  exit 1
fi

echo "fuzz registry in step with fuzz/fuzz_targets/: ${#targets[@]} targets"
