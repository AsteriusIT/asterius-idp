#!/usr/bin/env bash
# Reclaims disk space taken by regenerable Cargo build artifacts.
#
# Why this exists: cargo never garbage-collects. Every distinct code state
# produces a new hash-suffixed artifact in `target/debug/deps` and the old one
# stays forever. On this repository a single day of branch switching left 257
# copies of the `asterius` binary (2.4 GB) and 110 copies of the
# `tls_handshake` test binary (1.3 GB) — 21 GB of `deps/` in total, on a WSL2
# virtual disk capped at 251 GB.
#
# `cargo clean` is the blunt answer: it also throws away the artifacts the next
# build needs, so the following build starts from zero. This script deletes
# only artifacts untouched for a while, which is what the stale copies are, so
# the current build stays warm. Anything it removes, cargo rebuilds on demand.
#
# Safety rules, in order of importance:
#   - Dry run by default. Nothing is deleted without `--apply`.
#   - Only ever descends into `deps/`, `build/`, `incremental/` and
#     `.fingerprint/` under a `target/` directory. Never touches sources,
#     never touches `target/` roots (binaries you may be running).
#   - Leaves every registered git worktree alone unless `--worktrees` is
#     passed: another agent may be compiling in it right now.
#   - Directories under `.claude/worktrees/` that git no longer knows about are
#     leftovers from a merged branch; their `target/` is reclaimed in full.
#     The worktree directory itself is kept — deciding to delete a checkout is
#     a human call.
set -euo pipefail

HOURS=24
APPLY=0
WORKTREES=0

usage() {
  cat <<'EOF'
Usage: scripts/gc-build-artifacts.sh [options]

  --apply           actually delete (default: report only)
  --hours N         keep artifacts touched in the last N hours (default: 24)
  --worktrees       also prune the target/ of registered worktrees.
                    Do not use while other agents are compiling.
  --self-test       run the built-in fixture test and exit
  -h, --help        this message
EOF
}

# Deletes regenerable files older than $2 (a `find -newermt` argument) under
# the target directory $1, and reports the bytes involved on stdout.
# Prints "<bytes> <path>" and never fails when the directory is absent.
prune_target() {
  local target="$1" since="$2" bytes=0 sub found
  [ -d "$target" ] || return 0

  for sub in deps build incremental .fingerprint; do
    while IFS= read -r -d '' found; do
      bytes=$((bytes + $(stat -c '%s' "$found")))
      [ "$APPLY" = 1 ] && rm -f -- "$found"
    done < <(find "$target" -mindepth 2 -maxdepth 3 -type d -name "$sub" \
               -exec find {} -type f ! -newermt "$since" -print0 \; 2>/dev/null)
  done

  if [ "$APPLY" = 1 ]; then
    # Empty directories left behind by the pass above; -depth so children go
    # first. `rmdir` refuses non-empty ones, which is the guard we want.
    find "$target" -mindepth 2 -depth -type d -empty -exec rmdir {} + 2>/dev/null || true
  fi

  printf '%s %s\n' "$bytes" "$target"
}

human() {
  awk -v b="$1" 'BEGIN {
    split("B KiB MiB GiB TiB", u, " "); i = 1
    while (b >= 1024 && i < 5) { b /= 1024; i++ }
    printf "%.1f %s", b, u[i]
  }'
}

self_test() {
  local tmp stale fresh out
  tmp="$(mktemp -d)"
  trap 'rm -rf -- "$tmp"' RETURN

  mkdir -p "$tmp/target/debug/deps" "$tmp/target/debug/incremental" "$tmp/src"
  stale="$tmp/target/debug/deps/old-0123456789abcdef"
  fresh="$tmp/target/debug/deps/new-fedcba9876543210"
  printf 'stale' > "$stale"
  printf 'fresh' > "$fresh"
  printf 'source' > "$tmp/src/main.rs"
  touch -d '3 days ago' "$stale"
  touch -d '3 days ago' "$tmp/src/main.rs"

  # Report-only mode must delete nothing at all.
  APPLY=0 prune_target "$tmp/target" "-2 days" > /dev/null
  [ -f "$stale" ] || { echo "self-test: dry run deleted a stale file" >&2; return 1; }

  APPLY=1
  out="$(prune_target "$tmp/target" "-2 days")"
  [ -f "$stale" ] && { echo "self-test: stale artifact survived --apply" >&2; return 1; }
  [ -f "$fresh" ] || { echo "self-test: fresh artifact was deleted" >&2; return 1; }
  [ -f "$tmp/src/main.rs" ] || { echo "self-test: a source file was deleted" >&2; return 1; }
  [ "${out%% *}" = "5" ] || { echo "self-test: expected 5 bytes freed, got '${out%% *}'" >&2; return 1; }

  echo "self-test: ok"
}

while [ $# -gt 0 ]; do
  case "$1" in
    --apply) APPLY=1 ;;
    --hours) HOURS="${2:?--hours needs a value}"; shift ;;
    --worktrees) WORKTREES=1 ;;
    --self-test) self_test; exit $? ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

case "$HOURS" in
  ''|*[!0-9]*) echo "--hours takes a whole number of hours" >&2; exit 2 ;;
esac

SINCE="-$HOURS hours"
GIT_COMMON="$(git rev-parse --path-format=absolute --git-common-dir)"
ROOT="$(dirname "$GIT_COMMON")"

total=0
report() {
  local line bytes path
  line="$1"
  bytes="${line%% *}"
  path="${line#* }"
  total=$((total + bytes))
  [ "$bytes" -gt 0 ] && printf '  %10s  %s\n' "$(human "$bytes")" "${path#"$ROOT"/}"
  return 0
}

echo "Build-artifact GC (${APPLY:+}$([ "$APPLY" = 1 ] && echo 'apply' || echo 'report only'), keeping the last ${HOURS}h)"

report "$(prune_target "$ROOT/target" "$SINCE")"

# Registered worktrees: skipped by default, because a running agent holds them.
registered=()
while IFS= read -r line; do
  case "$line" in worktree\ *) registered+=("${line#worktree }") ;; esac
done < <(git worktree list --porcelain)

if [ "$WORKTREES" = 1 ]; then
  for wt in "${registered[@]}"; do
    [ "$wt" = "$ROOT" ] && continue
    report "$(prune_target "$wt/target" "$SINCE")"
  done
fi

# Leftovers: a directory under .claude/worktrees that git has pruned. Its
# branch is merged, so nothing in its target/ will ever be reused.
if [ -d "$ROOT/.claude/worktrees" ]; then
  for dir in "$ROOT"/.claude/worktrees/*/; do
    [ -d "$dir" ] || continue
    dir="${dir%/}"
    known=0
    for wt in "${registered[@]}"; do
      [ "$wt" = "$dir" ] && known=1 && break
    done
    [ "$known" = 1 ] && continue
    report "$(prune_target "$dir/target" "now")"
  done
fi

if [ "$total" -eq 0 ]; then
  echo "  nothing to reclaim"
else
  printf '%s %s\n' "$([ "$APPLY" = 1 ] && echo 'Reclaimed' || echo 'Would reclaim')" "$(human "$total")"
  [ "$APPLY" = 1 ] || echo "Re-run with --apply to delete."
fi

# WSL2 only frees the space inside the distribution: the ext4.vhdx on the
# Windows side never shrinks on its own. See CONTRIBUTING.md, "Disk space".
exit 0
