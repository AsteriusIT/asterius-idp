#!/usr/bin/env bash
# Stop hook : boucle "grind" sur le backlog beads.
# Tant que .claude/grind.local.json est actif et que `bd ready` renvoie un
# ticket, empêche la session principale de s'arrêter et lui injecte le
# prochain ticket. S'arrête de lui-même quand : backlog vide, max_iterations
# atteint, ou même ticket revenu 2 fois (=> demande de le marquer bloqué).
set -uo pipefail

STATE="${CLAUDE_PROJECT_DIR:-.}/.claude/grind.local.json"
[ -f "$STATE" ] || exit 0

INPUT="$(cat)"
ACTIVE="$(jq -r '.active // false' "$STATE")"
[ "$ACTIVE" = "true" ] || exit 0

ITER="$(jq -r '.iteration // 0' "$STATE")"
MAX="$(jq -r '.max_iterations // 30' "$STATE")"
LAST="$(jq -r '.last_ticket // ""' "$STATE")"
SAME="$(jq -r '.same_count // 0' "$STATE")"

deactivate() {
  jq --arg why "$1" '.active = false | .stopped_reason = $why' "$STATE" > "$STATE.tmp" && mv "$STATE.tmp" "$STATE"
  echo "GRIND terminé : $1"
  exit 0
}

[ "$ITER" -ge "$MAX" ] && deactivate "max_iterations ($MAX) atteint"

# Les epics sont des conteneurs, pas du travail delegable : on prend le premier
# ticket concret du backlog pret.
NEXT="$(bd ready --limit 0 --json 2>/dev/null | jq -r '[.[] | select(.issue_type != "epic")] | .[0].id // empty')"
[ -z "$NEXT" ] && deactivate "backlog vide (bd ready ne renvoie rien)"

if [ "$NEXT" = "$LAST" ]; then
  SAME=$((SAME + 1))
else
  SAME=0
fi

jq --arg t "$NEXT" --argjson i $((ITER + 1)) --argjson s "$SAME" \
   '.iteration = $i | .last_ticket = $t | .same_count = $s' "$STATE" > "$STATE.tmp" && mv "$STATE.tmp" "$STATE"

# Vérifie le dernier run CI sur main : un échec devient un ticket prioritaire.
CI_NOTE=""
if command -v gh >/dev/null 2>&1; then
  CI="$(gh run list --branch main --limit 1 --json conclusion,url 2>/dev/null | jq -r '.[0] // empty')"
  if [ -n "$CI" ] && [ "$(printf '%s' "$CI" | jq -r .conclusion)" = "failure" ]; then
    CI_URL="$(printf '%s' "$CI" | jq -r .url)"
    CI_NOTE="ATTENTION : le dernier run CI sur main a ÉCHOUÉ ($CI_URL). Avant tout, crée un ticket beads priorité 0 'fix(ci): ...' avec ce lien s'il n'existe pas déjà, puis traite-le en premier."
  fi
fi

if [ "$SAME" -ge 2 ]; then
  REASON="Le ticket $NEXT est revenu $((SAME + 1)) fois sans être clos. Marque-le bloqué : bd update $NEXT --status blocked --reason '<cause>' puis continue avec le suivant. $CI_NOTE"
else
  REASON="GRIND itération $((ITER + 1))/$MAX. Prochain ticket : $NEXT. Applique la procédure /grind : bd update $NEXT --status in_progress, délègue à l'agent ticket-worker, merge la branche claude/$NEXT dans main, bd close $NEXT avec un résumé. Ne t'arrête pas. $CI_NOTE"
fi

jq -n --arg r "$REASON" '{decision: "block", reason: $r}'
exit 0
