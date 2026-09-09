#!/usr/bin/env bash
# Nettoie les worktrees et branches claude/* déjà mergées dans main.
# À lancer en fin de journée ou depuis /status si la liste s'allonge.
set -euo pipefail
git worktree prune
for br in $(git branch --list 'claude/*' --merged main --format='%(refname:short)'); do
  wt="$(git worktree list --porcelain | awk -v b="refs/heads/$br" '$1=="worktree"{w=$2} $1=="branch" && $2==b {print w}')"
  [ -n "$wt" ] && git worktree remove --force "$wt" && echo "worktree supprimé : $wt"
  git branch -d "$br" && echo "branche supprimée : $br"
done
git worktree list
