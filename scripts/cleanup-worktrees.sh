#!/usr/bin/env bash
# Supprime worktree, branche locale et branche distante des tickets `claude/*`
# dont le travail est déjà dans main. Chaque worktree d'agent traîne son propre
# `target/` (~1 Go après un simple `cargo check`) et rien ne le récupère :
# `git worktree prune` ne nettoie que les répertoires déjà disparus. Depuis
# `ast-a33` chaque branche est aussi poussée sur `origin` pour que la CI la
# valide avant fusion ; sans ce script `origin` accumule une branche morte par
# ticket.
#
# Usage :
#   scripts/cleanup-worktrees.sh            # rapporte, ne supprime rien
#   scripts/cleanup-worktrees.sh --apply    # supprime
#   scripts/cleanup-worktrees.sh --self-test  # banc d'essai sur dépôt jetable
#
# Trois garde-fous, parce que « branche fusionnée » ne veut pas dire « agent
# terminé » :
#   1. Un worktree `locked` appartient à un agent en cours. On n'y touche pas.
#   2. Une branche dont le sommet est exactement celui de main n'a rien
#      fusionné : c'est un worktree fraîchement créé, pas un ticket fini.
#      `git branch --merged main` les liste pourtant toutes.
#   3. Côté distant, on relit le sommet réel de `origin/claude/<id>` avec
#      `git ls-remote` et on ne supprime que s'il est un ancêtre de `main` :
#      un agent qui a poussé un commit de plus après la fusion garde sa
#      branche. Jamais de `--force`, jamais de suppression sur simple nom.
# Sans ces règles, un agent qui vient de démarrer — ou qui vient de pousser —
# serait effacé.
set -uo pipefail

APPLY=0
SELF_TEST=0
case "${1:-}" in
  --apply) APPLY=1 ;;
  ''|--dry-run) ;;
  --self-test) SELF_TEST=1 ;;
  -h|--help) sed -n '2,27p' "$0"; exit 0 ;;
  *) echo "option inconnue : $1" >&2; exit 2 ;;
esac

# Ce script supprime des branches, dont des branches distantes : il se teste,
# comme `gc-build-artifacts.sh` et `verify.sh`, sur un dépôt jetable muni de son
# propre `origin` bare. Cinq états, un par règle ci-dessus.
self_test() {
  local tmp script out rc=0
  script="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
  tmp="$(mktemp -d)"
  trap 'rm -rf -- "$tmp"' RETURN

  (
    set -e
    export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null
    export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@t
    export GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@t
    git init -q -b main "$tmp/repo"
    git init -q --bare "$tmp/origin.git"
    cd "$tmp/repo"
    git remote add origin "$tmp/origin.git"
    echo base > base && git add base && git commit -qm base && git push -q origin main

    # 1. fusionnée et poussée : local et distant doivent partir.
    git switch -qc claude/ast-merged
    echo m > m && git add m && git commit -qm merged
    git push -q origin claude/ast-merged
    git switch -q main

    # 2. jamais poussée : local seulement, et pas d'erreur côté distant.
    git switch -qc claude/ast-local main
    echo l > l && git add l && git commit -qm local
    git switch -q main

    # 3. la branche locale est fusionnée mais `origin` est reparti devant :
    #    l'agent a poussé après la fusion, la branche distante reste.
    git switch -qc claude/ast-drift main
    echo d > d && git add d && git commit -qm drift
    git push -q origin claude/ast-drift
    git switch -q main

    git merge -q --no-ff claude/ast-merged -m "merge(ast-merged)"
    git merge -q --no-ff claude/ast-local -m "merge(ast-local)"
    git merge -q --no-ff claude/ast-drift -m "merge(ast-drift)"

    git switch -qc tmp-drift claude/ast-drift
    echo d2 > d2 && git add d2 && git commit -qm "poussé après la fusion"
    git push -q origin tmp-drift:claude/ast-drift
    git switch -q main && git branch -qD tmp-drift

    # 4. au sommet de main : un worktree qui vient de démarrer, rien fusionné.
    git branch claude/ast-fresh main
  ) >/dev/null || { echo "self-test : fixture non construite" >&2; return 1; }

  # Sans --apply, rien ne doit disparaître, ni ici ni sur origin.
  out="$(cd "$tmp/repo" && bash "$script")"
  case "$out" in
    *"à supprimer : claude/ast-merged + origin/claude/ast-merged"*) ;;
    *) echo "self-test : le dry run n'annonce pas la branche distante" >&2; rc=1 ;;
  esac
  git -C "$tmp/repo" rev-parse --verify -q claude/ast-merged >/dev/null ||
    { echo "self-test : le dry run a supprimé une branche" >&2; rc=1; }

  out="$(cd "$tmp/repo" && bash "$script" --apply)"
  case "$out" in
    *"branche distante gardée (sommet distant hors de main) : origin/claude/ast-drift"*) ;;
    *) echo "self-test : la branche distante en avance n'est pas protégée" >&2; rc=1 ;;
  esac

  local locals remotes
  locals="$(git -C "$tmp/repo" branch --list 'claude/*' --format='%(refname:short)' | sort | tr '\n' ' ')"
  remotes="$(git -C "$tmp/repo" ls-remote --heads origin 'refs/heads/claude/*' | awk '{print $2}' | sort | tr '\n' ' ')"
  [ "$locals" = "claude/ast-fresh " ] ||
    { echo "self-test : branches locales restantes inattendues : '$locals'" >&2; rc=1; }
  [ "$remotes" = "refs/heads/claude/ast-drift " ] ||
    { echo "self-test : branches distantes restantes inattendues : '$remotes'" >&2; rc=1; }

  # Rejouable : un second passage ne doit rien trouver et ne rien casser.
  out="$(cd "$tmp/repo" && bash "$script" --apply)"
  case "$out" in
    *"branche supprimée"*) echo "self-test : second passage non idempotent" >&2; rc=1 ;;
  esac

  [ "$rc" = 0 ] && echo "self-test : ok"
  return "$rc"
}

if [ "$SELF_TEST" = 1 ]; then
  self_test
  exit $?
fi

git worktree prune

MAIN_TIP="$(git rev-parse main)"
LOCKED="$(git worktree list --porcelain | awk '$1=="worktree"{w=$2} $1=="locked"{print w}')"
# Pas de remote (clone local, dépôt de test) : on se contente du nettoyage local.
HAS_ORIGIN=0
git remote get-url origin >/dev/null 2>&1 && HAS_ORIGIN=1

# Sommet de `origin/<br>` tel qu'`origin` le voit maintenant, ou vide s'il n'y a
# pas de branche distante. `ls-remote` plutôt que la ref de suivi locale : celle
# -ci peut être périmée, et on s'apprête à supprimer côté serveur.
remote_tip() {
  [ "$HAS_ORIGIN" = 1 ] || return 0
  git ls-remote --heads origin "refs/heads/$1" 2>/dev/null | awk 'NR==1{print $1}'
}

# Vrai seulement si le sommet distant est connu localement ET déjà contenu dans
# main. Un objet inconnu (l'agent a poussé sans qu'on ait fetché) répond faux :
# on préfère laisser une branche de trop qu'en supprimer une vivante.
remote_is_merged() {
  git cat-file -e "$1^{commit}" 2>/dev/null &&
    git merge-base --is-ancestor "$1" "$MAIN_TIP" 2>/dev/null
}

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

  tip="$(remote_tip "$br")"
  drop_remote=0
  if [ -n "$tip" ]; then
    if remote_is_merged "$tip"; then
      drop_remote=1
    else
      echo "branche distante gardée (sommet distant hors de main) : origin/$br"
    fi
  fi

  if [ "$APPLY" = 0 ]; then
    echo "à supprimer : $br${wt:+ + worktree $wt}$([ "$drop_remote" = 1 ] && echo " + origin/$br")"
    removed=$((removed + 1))
    continue
  fi

  if [ -n "$wt" ]; then
    git worktree remove --force "$wt" && echo "worktree supprimé : $wt"
  fi
  git branch -d "$br" && echo "branche supprimée : $br"
  if [ "$drop_remote" = 1 ]; then
    git push origin --delete "$br" && echo "branche distante supprimée : origin/$br"
  fi
  removed=$((removed + 1))
done

if [ "$removed" -eq 0 ]; then
  echo "rien à nettoyer"
elif [ "$APPLY" = 0 ]; then
  echo "relance avec --apply pour supprimer."
fi

git worktree list
