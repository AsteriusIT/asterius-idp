#!/usr/bin/env bash
# PostToolUse(Edit|Write|MultiEdit) : après toute modification d'un .rs,
# lance un `cargo check` rapide et renvoie les erreurs à Claude (exit 2).
# Feedback immédiat sans payer le coût d'un cargo test.
set -uo pipefail

INPUT="$(cat)"
FILE="$(printf '%s' "$INPUT" | jq -r '.tool_input.file_path // empty')"
CWD="$(printf '%s' "$INPUT" | jq -r '.cwd // empty')"

case "$FILE" in
  *.rs) ;;
  *) exit 0 ;;
esac

[ -n "$CWD" ] && cd "$CWD"
[ -f Cargo.toml ] || exit 0

# Agent worktrees each carry a full target/, and incremental state is 38 % of
# it (380 MiB out of 999 MiB, measured on a worktree that only ran
# `cargo check`). Incremental compilation buys a human a faster edit loop; an
# agent worktree lives for one ticket and is thrown away, so it pays the disk
# and gets little back.
#
# Only for a worktree that has not compiled yet: flipping CARGO_INCREMENTAL on
# an existing target/ changes the fingerprint and forces a full rebuild, which
# would punish agents already at work.
case "$PWD" in
  */.claude/worktrees/*)
    [ -d target/debug/incremental ] || export CARGO_INCREMENTAL=0
    ;;
esac

# --message-format short : une ligne par diagnostic, économe en contexte.
OUTPUT="$(cargo check --all-targets --message-format short 2>&1)"
STATUS=$?

if [ $STATUS -ne 0 ]; then
  echo "cargo check a échoué après modification de $FILE :" >&2
  printf '%s\n' "$OUTPUT" | grep -E 'error' | head -20 >&2
  exit 2
fi
exit 0
