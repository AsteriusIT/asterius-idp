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

# --message-format short : une ligne par diagnostic, économe en contexte.
OUTPUT="$(cargo check --all-targets --message-format short 2>&1)"
STATUS=$?

if [ $STATUS -ne 0 ]; then
  echo "cargo check a échoué après modification de $FILE :" >&2
  printf '%s\n' "$OUTPUT" | grep -E 'error' | head -20 >&2
  exit 2
fi
exit 0
