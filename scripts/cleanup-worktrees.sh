#!/usr/bin/env bash
# Supprime worktree, branche locale et branche distante des tickets `claude/*`
# dont le travail est déjà dans main. Chaque worktree d'agent traîne son propre
# `target/` (~1 Go après un simple `cargo check`) et rien ne le récupère :
# `git worktree prune` ne nettoie que les répertoires déjà disparus. Depuis
# `ast-a33` chaque branche est aussi poussée sur `origin` pour que la CI la
# valide avant fusion ; sans ce script `origin` accumule une branche morte par
# ticket.
#
# Second effet, depuis `ast-9em` : les worktrees `claude/*` qui ne sont PAS
# encore fusionnés — agent terminé, branche poussée, CI en cours — gardent un
# `target/` de 7 à 12 Go qu'ils ne rouvriront jamais. Sept d'entre eux ont
# rempli le disque (51 Go) et fait échouer un `cargo sqlx prepare` d'un autre
# worker. On ne peut pas les supprimer : la CI peut demander un correctif. On
# leur passe un `cargo clean`, qui rend le disque et laisse la branche intacte.
# `rm -rf` ferait la même chose ; la politique de l'orchestrateur le refuse, et
# `cargo clean` a de toute façon le bon garde-fou : il ne connaît que `target/`.
#
# Usage :
#   scripts/cleanup-worktrees.sh            # rapporte, ne supprime rien
#   scripts/cleanup-worktrees.sh --apply    # supprime
#   scripts/cleanup-worktrees.sh --apply --no-clean   # sans le cargo clean
#   scripts/cleanup-worktrees.sh --idle-minutes 60    # marge d'inactivité
#   scripts/cleanup-worktrees.sh --self-test  # banc d'essai sur dépôt jetable
#
# Quatre garde-fous, parce que « branche fusionnée » ne veut pas dire « agent
# terminé » :
#   1. Un worktree `locked` appartient à un agent en cours. On n'y touche pas.
#   2. Une branche dont le sommet est exactement celui de main n'a rien
#      fusionné : c'est un worktree fraîchement créé, pas un ticket fini.
#      `git branch --merged main` les liste pourtant toutes.
#   3. Côté distant, on relit le sommet réel de `origin/claude/<id>` avec
#      `git ls-remote` et on ne supprime que s'il est un ancêtre de `main` :
#      un agent qui a poussé un commit de plus après la fusion garde sa
#      branche. Jamais de `--force`, jamais de suppression sur simple nom.
#   4. Pour le `cargo clean` seulement : un `target/` touché il y a moins de
#      30 minutes (`--idle-minutes N`) appartient à une compilation en cours.
#      Un agent qui a oublié de verrouiller son worktree est ainsi épargné tant
#      qu'il travaille.
# Sans ces règles, un agent qui vient de démarrer — ou qui vient de pousser, ou
# qui compile — serait effacé.
set -uo pipefail

APPLY=0
SELF_TEST=0
CLEAN=1
IDLE_MIN=30
while [ $# -gt 0 ]; do
  case "$1" in
    --apply) APPLY=1 ;;
    ''|--dry-run) ;;
    --no-clean) CLEAN=0 ;;
    --idle-minutes) IDLE_MIN="${2:?--idle-minutes attend une valeur}"; shift ;;
    --self-test) SELF_TEST=1 ;;
    -h|--help) sed -n '2,41p' "$0"; exit 0 ;;
    *) echo "option inconnue : $1" >&2; exit 2 ;;
  esac
  shift
done

case "$IDLE_MIN" in
  ''|*[!0-9]*) echo "--idle-minutes attend un nombre entier de minutes" >&2; exit 2 ;;
esac

# Ce script supprime des branches, dont des branches distantes, et efface des
# `target/` : il se teste, comme `gc-build-artifacts.sh` et `verify.sh`, sur un
# dépôt jetable muni de son propre `origin` bare. Huit états, un par règle
# ci-dessus, dont quatre worktrees pour la passe `cargo clean`.
self_test() {
  local tmp script out rc=0
  script="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
  tmp="$(mktemp -d)"
  trap 'rm -rf -- "$tmp"' RETURN

  # Un `target/` jetable, daté : $2 est un argument de `touch -d`.
  fake_target() {
    mkdir -p "$1/debug/deps"
    printf 'artefact' > "$1/debug/deps/libfixture.rlib"
    touch -d "$2" "$1/debug/deps/libfixture.rlib" "$1/debug/deps" "$1/debug" "$1"
  }

  (
    set -e
    export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null
    export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@t
    export GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@t
    git init -q -b main "$tmp/repo"
    git init -q --bare "$tmp/origin.git"
    cd "$tmp/repo"
    git remote add origin "$tmp/origin.git"
    # Un vrai manifeste cargo dans le commit de base : la passe `cargo clean`
    # est testée en appelant cargo, pas en simulant ce qu'il ferait. Pas de
    # dépendance, donc pas de réseau. `fuzz/` est son propre workspace, comme
    # dans ce dépôt, pour prouver que son `target/` est nettoyé lui aussi.
    mkdir -p src fuzz/src
    printf '[package]\nname = "fixture"\nversion = "0.0.0"\nedition = "2021"\n' > Cargo.toml
    printf '[workspace]\n\n[package]\nname = "fixture-fuzz"\nversion = "0.0.0"\nedition = "2021"\n' > fuzz/Cargo.toml
    : > src/lib.rs
    : > fuzz/src/lib.rs
    echo base > base && git add -A && git commit -qm base && git push -q origin main

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
    git worktree add -q "$tmp/wt-fresh" claude/ast-fresh
    fake_target "$tmp/wt-fresh/target" '2 hours ago'

    # 5. agent terminé, branche non fusionnée (CI en cours), worktree libre :
    #    le seul dont le `target/` — et le `fuzz/target/` — doit être nettoyé.
    git switch -qc claude/ast-idle main
    echo i > i && git add i && git commit -qm idle
    git switch -q main
    git worktree add -q "$tmp/wt-idle" claude/ast-idle
    fake_target "$tmp/wt-idle/target" '2 hours ago'
    fake_target "$tmp/wt-idle/fuzz/target" '2 hours ago'

    # 6. même état, mais le worktree est verrouillé : agent en cours.
    git switch -qc claude/ast-busy main
    echo b > b && git add b && git commit -qm busy
    git switch -q main
    git worktree add -q "$tmp/wt-busy" claude/ast-busy
    fake_target "$tmp/wt-busy/target" '2 hours ago'
    git worktree lock "$tmp/wt-busy"

    # 7. non verrouillé mais en train de compiler : le `target/` vient d'être
    #    écrit. Un agent qui a oublié `git worktree lock` compte quand même.
    git switch -qc claude/ast-warm main
    echo w > w && git add w && git commit -qm warm
    git switch -q main
    git worktree add -q "$tmp/wt-warm" claude/ast-warm
    fake_target "$tmp/wt-warm/target" 'now'
  ) >/dev/null || { echo "self-test : fixture non construite" >&2; return 1; }

  # Sans --apply, rien ne doit disparaître, ni ici ni sur origin.
  out="$(cd "$tmp/repo" && bash "$script")"
  case "$out" in
    *"à supprimer : claude/ast-merged + origin/claude/ast-merged"*) ;;
    *) echo "self-test : le dry run n'annonce pas la branche distante" >&2; rc=1 ;;
  esac
  git -C "$tmp/repo" rev-parse --verify -q claude/ast-merged >/dev/null ||
    { echo "self-test : le dry run a supprimé une branche" >&2; rc=1; }
  case "$out" in
    *"à nettoyer"*"$tmp/wt-idle/target"*) ;;
    *) echo "self-test : le dry run n'annonce pas le cargo clean" >&2; rc=1 ;;
  esac
  [ -d "$tmp/wt-idle/target" ] ||
    { echo "self-test : le dry run a nettoyé un target/" >&2; rc=1; }

  # --no-clean doit supprimer les branches sans toucher au moindre target/.
  out="$(cd "$tmp/repo" && bash "$script" --no-clean)"
  case "$out" in
    *"à nettoyer"*) echo "self-test : --no-clean annonce quand même un clean" >&2; rc=1 ;;
  esac

  out="$(cd "$tmp/repo" && bash "$script" --apply)"
  case "$out" in
    *"branche distante gardée (sommet distant hors de main) : origin/claude/ast-drift"*) ;;
    *) echo "self-test : la branche distante en avance n'est pas protégée" >&2; rc=1 ;;
  esac
  case "$out" in
    *"clean ignoré (worktree verrouillé par un agent) : claude/ast-busy"*) ;;
    *) echo "self-test : le worktree verrouillé n'est pas annoncé comme épargné" >&2; rc=1 ;;
  esac

  # Le seul worktree nettoyé est celui de l'agent terminé, et son `fuzz/target`
  # avec lui. Les trois autres — verrouillé, en cours de compilation, au sommet
  # de main — gardent leurs artefacts.
  [ -d "$tmp/wt-idle/target" ] &&
    { echo "self-test : le target/ de l'agent terminé a survécu" >&2; rc=1; }
  [ -d "$tmp/wt-idle/fuzz/target" ] &&
    { echo "self-test : fuzz/target n'a pas été nettoyé" >&2; rc=1; }
  local kept
  for kept in wt-busy wt-warm wt-fresh; do
    [ -d "$tmp/$kept/target" ] ||
      { echo "self-test : $kept a perdu son target/" >&2; rc=1; }
  done

  local locals remotes
  locals="$(git -C "$tmp/repo" branch --list 'claude/*' --format='%(refname:short)' | sort | tr '\n' ' ')"
  remotes="$(git -C "$tmp/repo" ls-remote --heads origin 'refs/heads/claude/*' | awk '{print $2}' | sort | tr '\n' ' ')"
  [ "$locals" = "claude/ast-busy claude/ast-fresh claude/ast-idle claude/ast-warm " ] ||
    { echo "self-test : branches locales restantes inattendues : '$locals'" >&2; rc=1; }
  [ "$remotes" = "refs/heads/claude/ast-drift " ] ||
    { echo "self-test : branches distantes restantes inattendues : '$remotes'" >&2; rc=1; }

  # Rejouable : un second passage ne doit rien trouver et ne rien casser.
  out="$(cd "$tmp/repo" && bash "$script" --apply)"
  case "$out" in
    *"branche supprimée"*) echo "self-test : second passage non idempotent" >&2; rc=1 ;;
  esac
  case "$out" in
    *"cargo clean ("*) echo "self-test : second passage, clean non idempotent" >&2; rc=1 ;;
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

human() {
  awk -v b="$1" 'BEGIN {
    split("B KiB MiB GiB TiB", u, " "); i = 1
    while (b >= 1024 && i < 5) { b /= 1024; i++ }
    printf "%.1f %s", b, u[i]
  }'
}

dir_bytes() {
  [ -d "$1" ] || { echo 0; return 0; }
  du -sb -- "$1" 2>/dev/null | awk 'NR==1 {print $1; found=1} END {if (!found) print 0}'
}

# Vrai si quelque chose a été écrit dans le répertoire depuis moins de
# $IDLE_MIN minutes : une compilation est sans doute en cours, on n'y touche
# pas même si le worktree n'est pas verrouillé.
recently_touched() {
  [ -d "$1" ] || return 1
  [ -n "$(find "$1" -maxdepth 2 -newermt "-$IDLE_MIN minutes" -print -quit 2>/dev/null)" ]
}

# `cargo clean` dans le répertoire d'un manifeste, s'il a un `target/`.
# Rapporte l'espace concerné ; sans --apply, se contente de l'annoncer.
clean_manifest() {
  local mf="$1" dir bytes
  dir="${mf%/Cargo.toml}"
  [ -f "$mf" ] || return 0
  [ -d "$dir/target" ] || return 0

  bytes="$(dir_bytes "$dir/target")"
  if [ "$APPLY" = 0 ]; then
    echo "à nettoyer ($(human "$bytes")) : $dir/target"
    cleaned=$((cleaned + 1))
    return 0
  fi
  if (cd "$dir" && cargo clean --quiet); then
    echo "cargo clean ($(human "$bytes") rendus) : $dir/target"
    cleaned=$((cleaned + 1))
  else
    echo "cargo clean a échoué : $dir" >&2
  fi
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

# Deuxième passe : les worktrees `claude/*` encore vivants (rien de fusionné,
# donc jamais candidats à la suppression ci-dessus) mais dont l'agent a fini.
# On leur rend leur `target/` et leur `fuzz/target/`. Après la première passe :
# les worktrees fusionnés n'existent plus, il n'y a plus qu'eux à examiner.
cleaned=0
SELF="$(git rev-parse --show-toplevel 2>/dev/null || true)"
if [ "$CLEAN" = 1 ] && command -v cargo >/dev/null 2>&1; then
  while IFS="$(printf '\t')" read -r wt ref; do
    case "$ref" in refs/heads/claude/*) ;; *) continue ;; esac
    br="${ref#refs/heads/}"

    if printf '%s\n' "$LOCKED" | grep -qxF "$wt"; then
      echo "clean ignoré (worktree verrouillé par un agent) : $br"
      continue
    fi
    # Le worktree d'où l'on tourne : c'est celui de l'humain ou de l'agent qui
    # lance le script, et lui est vivant par définition.
    [ "$wt" = "$SELF" ] && continue
    # Fusionné : la première passe s'en est occupée (ou l'aurait fait avec
    # --apply). Un sommet égal à celui de main l'est aussi : agent qui démarre.
    git merge-base --is-ancestor "$br" "$MAIN_TIP" 2>/dev/null && continue
    if recently_touched "$wt/target"; then
      echo "clean ignoré (compilation il y a moins de ${IDLE_MIN} min) : $br"
      continue
    fi

    clean_manifest "$wt/Cargo.toml"
    clean_manifest "$wt/fuzz/Cargo.toml"
  done < <(git worktree list --porcelain |
    awk '$1=="worktree"{w=$2} $1=="branch"{printf "%s\t%s\n", w, $2}')
fi

if [ "$removed" -eq 0 ] && [ "$cleaned" -eq 0 ]; then
  echo "rien à nettoyer"
elif [ "$APPLY" = 0 ]; then
  echo "relance avec --apply pour supprimer et nettoyer."
fi

git worktree list
