#!/usr/bin/env bash
# Lance la session Claude Code dans tmux pour qu'elle survive aux coupures
# du remote control et à la mise en veille du terminal WSL.
# Usage : scripts/start-session.sh [nom-session]
set -euo pipefail

SESSION="${1:-claude-grind}"
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

command -v tmux >/dev/null || { echo "tmux manquant : sudo apt install tmux" >&2; exit 1; }
command -v claude >/dev/null || { echo "claude introuvable dans le PATH" >&2; exit 1; }
command -v jq >/dev/null || { echo "jq manquant : sudo apt install jq" >&2; exit 1; }
command -v cargo-nextest >/dev/null || cargo nextest --version >/dev/null 2>&1 || { echo "nextest manquant : cargo install cargo-nextest" >&2; exit 1; }

if tmux has-session -t "$SESSION" 2>/dev/null; then
  echo "Session '$SESSION' déjà active. Attache : tmux attach -t $SESSION"
  exit 0
fi

# Mode bypass : la session tourne sans prompt de permission (pilotage à
# distance, aucun humain devant le terminal pour valider). La liste `deny`
# de .claude/settings.json n'est PAS appliquée dans ce mode.
tmux new-session -d -s "$SESSION" -c "$PROJECT_DIR" \
  "claude --dangerously-skip-permissions"
echo "Session '$SESSION' lancée dans $PROJECT_DIR."
echo "  Attache locale : tmux attach -t $SESSION"
echo "  Puis dans Claude : /grind 30   (ou /status pour le tableau de bord)"
