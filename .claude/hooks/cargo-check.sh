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

# `SQLX_OFFLINE=true` is not an optimisation, it is what keeps this hook from
# hanging an agent. `sqlx::query!` checks its SQL at compile time: without this
# variable it dials `DATABASE_URL` (port 5433 here), and with nothing listening
# it waits out the connect timeout while holding cargo's build lock. The agent
# then looks idle with no visible process, and the harness believes it is still
# working — one hour lost on ast-295.
#
# The `.sqlx/` directory is committed, so the offline check is always available
# and is the right default after every saved file. Checking against a real
# database belongs to `/verify` and to CI, not to an edit hook.
#
# Beware the half-measure: a database started without its migrations is worse
# than no database at all, because sqlx then leaves offline mode and fails to
# verify every query. See CONTRIBUTING.md, "Running the checks".
export SQLX_OFFLINE=true

# --message-format short : une ligne par diagnostic, économe en contexte.
OUTPUT="$(cargo check --all-targets --message-format short 2>&1)"
STATUS=$?

if [ $STATUS -ne 0 ]; then
  echo "cargo check a échoué après modification de $FILE :" >&2
  printf '%s\n' "$OUTPUT" | grep -E 'error' | head -20 >&2
  exit 2
fi
exit 0
