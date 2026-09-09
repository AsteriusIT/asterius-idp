#!/usr/bin/env bash
# PreToolUse(Bash) : limite les exécutions de tests pendant une session.
#  - `cargo test` est toujours refusé (nextest le remplace).
#  - `cargo nextest run` est autorisé MAX_NEXTEST_RUNS fois par session,
#    pour forcer le rythme "cargo check en boucle, tests une fois à la fin".
# Sortie 2 = refus, le message stderr est renvoyé à Claude.
set -euo pipefail

MAX_NEXTEST_RUNS="${MAX_NEXTEST_RUNS:-3}"

INPUT="$(cat)"
CMD="$(printf '%s' "$INPUT" | jq -r '.tool_input.command // empty')"
SESSION="$(printf '%s' "$INPUT" | jq -r '.session_id // "nosession"')"

[ -z "$CMD" ] && exit 0

if printf '%s' "$CMD" | grep -qE '(^|[;&| ])cargo[[:space:]]+test\b'; then
  echo "Refusé : 'cargo test' est interdit. Utilise 'cargo check' pendant l'édition, puis 'cargo nextest run <filtre>' une seule fois en fin de tâche." >&2
  exit 2
fi

if printf '%s' "$CMD" | grep -qE 'cargo[[:space:]]+nextest[[:space:]]+run'; then
  COUNTER="/tmp/claude-nextest-${SESSION}"
  COUNT=0
  [ -f "$COUNTER" ] && COUNT="$(cat "$COUNTER")"
  if [ "$COUNT" -ge "$MAX_NEXTEST_RUNS" ]; then
    echo "Refusé : $MAX_NEXTEST_RUNS exécutions de nextest déjà faites dans cette session. Continue avec 'cargo check' / 'cargo clippy' ; la CI lancera la suite complète après le merge." >&2
    exit 2
  fi
  echo $((COUNT + 1)) > "$COUNTER"
fi

exit 0
