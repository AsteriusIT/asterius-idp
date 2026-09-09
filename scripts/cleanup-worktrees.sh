#!/usr/bin/env bash
# Supprime worktree et branche des tickets `claude/*` dont le travail est déjà
# dans main. Chaque worktree d'agent traîne son propre `target/` (~1 Go après
# un simple `cargo check`) et rien ne le récupère : `git worktree prune` ne
# nettoie que les répertoires déjà disparus.
#
# Usage :
#   scripts/cleanup-worktrees.sh            # rapporte, ne supprime rien
#   scripts/cleanup-worktrees.sh --apply    # supprime
#
# Deux garde-fous, parce que « branche fusionnée » ne veut pas dire « agent
# terminé » :
#   1. Un worktree `locked` appartient à un agent en cours. On n'y touche pas.
#   2. Une branche dont le sommet est exactement celui de main n'a rien
#      fusionné : c'est un worktree fraîchement créé, pas un ticket fini.
#      `git branch --merged main` les liste pourtant toutes.
# Sans ces deux règles, un agent qui vient de démarrer serait effacé.
set -uo pipefail

APPLY=0
case "${1:-}" in
  --apply) APPLY=1 ;;
  ''|--dry-run) ;;
  -h|--help) sed -n '2,18p' "$0"; exit 0 ;;
  *) echo "option inconnue : $1" >&2; exit 2 ;;
esac

git worktree prune

MAIN_TIP="$(git rev-parse main)"
LOCKED="$(git worktree list --porcelain | awk '$1=="worktree"{w=$2} $1=="locked"{print w}')"

removed=0
for br in $(git branch --list 'claude/*' --merged main --format='%(refname:short)'); do
  if [ "$(git rev-parse "$br")" = "$MAIN_TIP" ]; then
    echo "ignoré (rien de fusionné, worktree sans doute en cours) : $br"
    continue
  fi

  wt="$(git worktree list --porcelain \
        | awk -v b="refs/heads/$br" '$1=="worktree"{w=$2} $1=="branch" && $2==b {print w}')"

  if [ -n "$wt" ] && printf '%s\n' "$LOCKED" | grep -qxF "$wt"; then
    echo "ignoré (worktree verrouillé par un agent) : $br"
    continue
  fi

  if [ "$APPLY" = 0 ]; then
    echo "à supprimer : $br${wt:+ + worktree $wt}"
    removed=$((removed + 1))
    continue
  fi

  if [ -n "$wt" ]; then
    git worktree remove --force "$wt" && echo "worktree supprimé : $wt"
  fi
  git branch -d "$br" && echo "branche supprimée : $br"
  removed=$((removed + 1))
done

if [ "$removed" -eq 0 ]; then
  echo "rien à nettoyer"
elif [ "$APPLY" = 0 ]; then
  echo "relance avec --apply pour supprimer."
fi

git worktree list
