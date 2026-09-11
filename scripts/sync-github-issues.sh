#!/usr/bin/env bash
# Pont issue GitHub -> bead pour les alertes nocturnes (fuzz, conformance).
#
# Les jobs `fuzz-nightly.yml` et `conformance.yml` ouvrent une ISSUE GITHUB
# quand ils échouent, pas un bead : la base Dolt de beads est locale et un
# runner n'y accède pas. L'issue dit « file the bead and link it here », étape
# manuelle, donc oubliable. Le 2026-09-11 le coût était visible : les issues #1
# à #5 ont vécu ouvertes une journée alors que les crashes étaient déjà
# corrigés sous d'autres beads sans lien, et l'issue #6 est restée sans bead
# jusqu'à un triage à la main.
#
# Ce script referme l'écart depuis un poste de travail, le seul endroit où `gh`
# et `bd` coexistent :
#   - toute issue ouverte portant un label d'alerte et sans bead lié donne un
#     bead P1 de type bug, puis un commentaire « Suivi : bead <id> » sur
#     l'issue ;
#   - toute issue dont le bead est fermé reçoit le motif de clôture en
#     commentaire et est fermée à son tour (--no-close pour s'en abstenir).
#
# L'idempotence ne tient à aucun état local : la clé est le commentaire de
# suivi lui-même, relu à chaque passage. Le motif accepté est large — « Suivi :
# bead ast-xxx » comme « Suivi dans le bead ast-yc5 (P1) », écrit à la main
# avant ce script — parce qu'un marqueur trop strict recréerait un doublon de
# ce qui est déjà suivi, exactement le défaut qu'on corrige.
#
# Usage :
#   scripts/sync-github-issues.sh              # liste, ne crée rien (défaut)
#   scripts/sync-github-issues.sh --apply      # crée les beads, commente, ferme
#   scripts/sync-github-issues.sh --apply --no-close   # sans fermer les issues
#   scripts/sync-github-issues.sh --label fuzz # un seul label
#   scripts/sync-github-issues.sh --self-test  # banc d'essai, gh et bd simulés
#
# À lancer au début d'une session `/grind` : les beads ainsi créés portent le
# travail de correction, et le `fix(ci)` P0 se greffe dessus.
set -uo pipefail

APPLY=0
SELF_TEST=0
CLOSE=1
LABELS=""
LIMIT=100

while [ $# -gt 0 ]; do
  case "$1" in
    --apply) APPLY=1 ;;
    ''|--dry-run) ;;
    --no-close) CLOSE=0 ;;
    --label) LABELS="$LABELS ${2:?--label attend un nom de label}"; shift ;;
    --limit) LIMIT="${2:?--limit attend un nombre}"; shift ;;
    --self-test) SELF_TEST=1 ;;
    -h|--help) sed -n '2,34p' "$0"; exit 0 ;;
    *) echo "option inconnue : $1" >&2; exit 2 ;;
  esac
  shift
done

case "$LIMIT" in
  ''|*[!0-9]*) echo "--limit attend un nombre entier" >&2; exit 2 ;;
esac

# Les deux labels posés par les workflows nocturnes (`gh label create --force`
# dans fuzz-nightly.yml et conformance.yml, donc ils existent toujours).
[ -n "${LABELS// /}" ] || LABELS="fuzz conformance"

# Marqueur de suivi lu sur l'issue. Le motif est plus permissif que ce qu'on
# écrit : voir l'en-tête.
BEAD_MARKER='bead[[:space:]]+[a-z]+-[a-z0-9._-]+'
CLOSED_MARKER='bead fermé'

# --- accès à GitHub et à beads, regroupés pour que le self-test les simule ---

issue_list() { # $1 = label
  gh issue list --state open --label "$1" --limit "$LIMIT" \
    --json number,title,body,url
}

issue_comments() { # $1 = numéro -> les corps de commentaires, concaténés
  gh issue view "$1" --json comments | jq -r '.comments[].body'
}

issue_comment() { gh issue comment "$1" --body "$2"; }

issue_close() { gh issue close "$1" --reason completed; }

bead_status() { # $1 = id -> "<status>\t<close_reason>"
  bd show "$1" --json 2>/dev/null |
    jq -r '.[0] | select(. != null) | [.status, (.close_reason // "")] | @tsv'
}

bead_create() { # $1 = titre, $2 = description, $3 = numéro d'issue
  bd create --type bug --priority 1 --title "$1" --description "$2" \
    --external-ref "gh-$3" --silent
}

# --- logique ---

# Premier identifiant de bead cité dans les commentaires, ou rien.
bead_from_comments() {
  grep -oiE "$BEAD_MARKER" | head -n1 | awk '{print tolower($2)}'
}

# Le corps d'une alerte doit porter de quoi rejouer le défaut : sans commande
# de reproduction, le bead créé n'est qu'un rappel. On le signale plutôt que de
# refuser l'issue — une alerte sans repro reste une alerte.
warn_if_no_repro() { # $1 = numéro, $2 = corps
  case "$2" in
    *"fuzz run"*|*"make conformance"*|*"Reproduce"*|*"base64 -d"*) return 0 ;;
  esac
  echo "avertissement : #$1 ne porte pas de commande de reproduction" >&2
}

created=0
closed=0
tracked=0

handle_issue() { # $1 = numéro, $2 = titre, $3 = corps, $4 = url
  local num="$1" title="$2" body="$3" url="$4"
  local comments bead status reason desc id

  comments="$(issue_comments "$num")" || {
    echo "impossible de lire les commentaires de #$num" >&2
    return 1
  }
  bead="$(printf '%s\n' "$comments" | bead_from_comments)"

  if [ -z "$bead" ]; then
    warn_if_no_repro "$num" "$body"
    if [ "$APPLY" = 0 ]; then
      echo "à créer : bead pour #$num — $title"
      created=$((created + 1))
      return 0
    fi
    desc="$(printf '%s\n\n%s\n' "$body" "Issue GitHub : $url")"
    id="$(bead_create "$title (issue #$num)" "$desc" "$num")"
    if [ -z "$id" ]; then
      echo "bd create a échoué pour #$num" >&2
      return 1
    fi
    if issue_comment "$num" "Suivi : bead $id" >/dev/null; then
      echo "bead créé : $id <- #$num"
      created=$((created + 1))
    else
      # Le commentaire est la clé d'idempotence : sans lui, le prochain
      # passage recrée un bead. On le dit fort.
      echo "bead $id créé mais #$num n'a pas pu être commentée : commente-la à la main" >&2
      return 1
    fi
    return 0
  fi

  IFS="$(printf '\t')" read -r status reason < <(bead_status "$bead")
  if [ -z "${status:-}" ]; then
    echo "#$num cite le bead $bead, introuvable en base : à vérifier à la main" >&2
    return 0
  fi

  if [ "$status" != "closed" ]; then
    echo "déjà suivi : #$num -> $bead ($status)"
    tracked=$((tracked + 1))
    return 0
  fi

  if [ "$CLOSE" = 0 ]; then
    echo "bead fermé, issue laissée ouverte (--no-close) : #$num -> $bead"
    tracked=$((tracked + 1))
    return 0
  fi
  if printf '%s\n' "$comments" | grep -qiF "$CLOSED_MARKER"; then
    echo "déjà signalée fermée : #$num -> $bead"
    tracked=$((tracked + 1))
    return 0
  fi
  if [ "$APPLY" = 0 ]; then
    echo "à fermer : #$num — le bead $bead est fermé"
    closed=$((closed + 1))
    return 0
  fi

  [ -n "$reason" ] || reason="aucun motif consigné"
  issue_comment "$num" "$CLOSED_MARKER : $reason" >/dev/null || return 1
  if issue_close "$num" >/dev/null; then
    echo "issue fermée : #$num -> $bead"
    closed=$((closed + 1))
  else
    echo "#$num commentée mais non fermée" >&2
    return 1
  fi
}

run() {
  local label json n i num title body url seen="" rc=0
  for label in $LABELS; do
    json="$(issue_list "$label")" || {
      echo "gh issue list a échoué pour le label $label" >&2
      rc=1
      continue
    }
    n="$(jq 'length' <<<"$json")"
    i=0
    while [ "$i" -lt "$n" ]; do
      num="$(jq -r ".[$i].number" <<<"$json")"
      # Une issue peut porter les deux labels : on ne la traite qu'une fois.
      case " $seen " in *" $num "*) i=$((i + 1)); continue ;; esac
      seen="$seen $num"
      title="$(jq -r ".[$i].title" <<<"$json")"
      body="$(jq -r ".[$i].body" <<<"$json")"
      url="$(jq -r ".[$i].url" <<<"$json")"
      handle_issue "$num" "$title" "$body" "$url" || rc=1
      i=$((i + 1))
    done
  done

  if [ $((created + closed + tracked)) -eq 0 ]; then
    echo "aucune issue d'alerte ouverte"
  elif [ "$APPLY" = 0 ] && [ $((created + closed)) -gt 0 ]; then
    echo "relance avec --apply pour créer les beads et commenter."
  fi
  return "$rc"
}

# Ce script écrit dans le tracker et sur GitHub : il se teste, comme
# `cleanup-worktrees.sh`, sur des doublures. `gh` et `bd` sont remplacés par
# deux stubs en tête de PATH, adossés à des fixtures JSON que les stubs
# modifient — un commentaire posté est réellement relu au passage suivant, ce
# qui rend l'idempotence vérifiable et non seulement affirmée.
self_test() {
  local tmp script out rc=0
  script="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
  tmp="$(mktemp -d)"
  trap 'rm -rf -- "$tmp"' RETURN
  mkdir -p "$tmp/bin" "$tmp/fix"

  cat > "$tmp/bin/gh" <<'STUB'
#!/usr/bin/env bash
set -uo pipefail
fix="$FIXTURES"
[ "${1:-}" = issue ] || { echo "gh: sous-commande non simulée: $*" >&2; exit 1; }
sub="$2"; shift 2
case "$sub" in
  list)
    label=""
    while [ $# -gt 0 ]; do
      case "$1" in --label) label="$2"; shift ;; esac
      shift
    done
    f="$fix/list-$label.json"
    [ -f "$f" ] && cat "$f" || echo '[]'
    ;;
  view)
    num="$1"
    f="$fix/comments-$num.json"
    [ -f "$f" ] && cat "$f" || echo '{"comments":[]}'
    ;;
  comment)
    num="$1"; shift
    body=""
    while [ $# -gt 0 ]; do
      case "$1" in --body) body="$2"; shift ;; esac
      shift
    done
    f="$fix/comments-$num.json"
    [ -f "$f" ] || echo '{"comments":[]}' > "$f"
    jq --arg b "$body" '.comments += [{"body": $b}]' "$f" > "$f.tmp" && mv "$f.tmp" "$f"
    echo "comment $num $body" >> "$fix/actions.log"
    ;;
  close)
    num="$1"
    echo "close $num" >> "$fix/actions.log"
    # Une issue fermée sort des listes « --state open ».
    for f in "$fix"/list-*.json; do
      [ -f "$f" ] || continue
      jq --argjson n "$num" 'map(select(.number != $n))' "$f" > "$f.tmp" && mv "$f.tmp" "$f"
    done
    ;;
  *) echo "gh: sous-commande non simulée: $sub" >&2; exit 1 ;;
esac
STUB

  cat > "$tmp/bin/bd" <<'STUB'
#!/usr/bin/env bash
set -uo pipefail
fix="$FIXTURES"
case "${1:-}" in
  create)
    shift
    title=""
    while [ $# -gt 0 ]; do
      case "$1" in --title) title="$2"; shift ;; esac
      shift
    done
    n=$(( $(cat "$fix/counter" 2>/dev/null || echo 0) + 1 ))
    echo "$n" > "$fix/counter"
    id="ast-new$n"
    jq -n --arg id "$id" '[{id: $id, status: "open", close_reason: ""}]' > "$fix/bead-$id.json"
    echo "create $id $title" >> "$fix/actions.log"
    echo "$id"
    ;;
  show)
    f="$fix/bead-$2.json"
    [ -f "$f" ] || exit 1
    cat "$f"
    ;;
  *) echo "bd: sous-commande non simulée: $*" >&2; exit 1 ;;
esac
STUB

  chmod +x "$tmp/bin/gh" "$tmp/bin/bd"
  export PATH="$tmp/bin:$PATH" FIXTURES="$tmp/fix"

  # Trois états, un par branche de la logique.
  # 10 : crash de fuzz jamais trié — il doit donner un bead.
  # 11 : déjà suivie par un bead ouvert — on n'y touche pas.
  # 12 : suivie par un bead fermé, et par le marqueur en prose écrit à la main
  #      avant ce script — commentaire de clôture puis fermeture.
  jq -n '[
    {number: 10, title: "fuzz: dpop_proof crashed", url: "https://example/10",
     body: "Reproduce:\n\n    cargo +nightly fuzz run dpop_proof crash-input"},
    {number: 11, title: "fuzz: login_bucket crashed", url: "https://example/11",
     body: "Reproduce:\n\n    cargo +nightly fuzz run login_bucket crash-input"}
  ]' > "$tmp/fix/list-fuzz.json"
  jq -n '[
    {number: 12, title: "conformance: the nightly FAPI 2.0 SP Final run failed",
     url: "https://example/12", body: "Reproduce locally:\n\n    make conformance-keep"}
  ]' > "$tmp/fix/list-conformance.json"
  jq -n '{comments: [{body: "Suivi : bead ast-aaa"}]}' > "$tmp/fix/comments-11.json"
  jq -n '{comments: [{body: "Triage du jour. Suivi dans le bead ast-bbb (P1)."}]}' \
    > "$tmp/fix/comments-12.json"
  jq -n '[{id: "ast-aaa", status: "in_progress", close_reason: ""}]' > "$tmp/fix/bead-ast-aaa.json"
  jq -n '[{id: "ast-bbb", status: "closed", close_reason: "ordre des boutons rétabli"}]' \
    > "$tmp/fix/bead-ast-bbb.json"

  # 1. Sans --apply : on annonce, on n'écrit nulle part.
  out="$(bash "$script")"
  case "$out" in
    *"à créer : bead pour #10"*) ;;
    *) echo "self-test : le dry run n'annonce pas la création pour #10" >&2; rc=1 ;;
  esac
  case "$out" in
    *"à fermer : #12"*) ;;
    *) echo "self-test : le dry run n'annonce pas la fermeture de #12" >&2; rc=1 ;;
  esac
  case "$out" in
    *"déjà suivi : #11 -> ast-aaa"*) ;;
    *) echo "self-test : le marqueur d'une issue déjà suivie n'est pas reconnu" >&2; rc=1 ;;
  esac
  [ -f "$tmp/fix/actions.log" ] &&
    { echo "self-test : le dry run a écrit sur GitHub ou dans beads" >&2; rc=1; }

  # 2. --apply : un bead pour #10, un commentaire de suivi, #12 fermée.
  out="$(bash "$script" --apply)"
  case "$out" in
    *"bead créé : ast-new1 <- #10"*) ;;
    *) echo "self-test : aucun bead créé pour #10" >&2; rc=1 ;;
  esac
  grep -qF 'create ast-new1 fuzz: dpop_proof crashed (issue #10)' "$tmp/fix/actions.log" ||
    { echo "self-test : le titre du bead ne porte pas le numéro d'issue" >&2; rc=1; }
  grep -qF 'comment 10 Suivi : bead ast-new1' "$tmp/fix/actions.log" ||
    { echo "self-test : #10 n'a pas reçu le commentaire de suivi" >&2; rc=1; }
  grep -qF 'comment 12 bead fermé : ordre des boutons rétabli' "$tmp/fix/actions.log" ||
    { echo "self-test : #12 n'a pas reçu le motif de clôture du bead" >&2; rc=1; }
  grep -qxF 'close 12' "$tmp/fix/actions.log" ||
    { echo "self-test : #12 n'a pas été fermée" >&2; rc=1; }
  grep -q 'create .*#11' "$tmp/fix/actions.log" &&
    { echo "self-test : un bead a été créé pour une issue déjà suivie" >&2; rc=1; }

  # 3. Rejouable : le commentaire posé au passage précédent suffit à ce que le
  #    second ne crée ni ne commente rien.
  cp "$tmp/fix/actions.log" "$tmp/fix/actions.log.1"
  out="$(bash "$script" --apply)"
  if ! diff -q "$tmp/fix/actions.log" "$tmp/fix/actions.log.1" >/dev/null; then
    echo "self-test : second passage non idempotent :" >&2
    diff "$tmp/fix/actions.log.1" "$tmp/fix/actions.log" >&2
    rc=1
  fi
  case "$out" in
    *"déjà suivi : #10 -> ast-new1"*) ;;
    *) echo "self-test : le bead créé au passage 1 n'est pas relu au passage 2" >&2; rc=1 ;;
  esac

  # 4. --no-close : un bead fermé ne ferme plus l'issue.
  jq -n '[{id: "ast-ccc", status: "closed", close_reason: "corrigé"}]' > "$tmp/fix/bead-ast-ccc.json"
  jq -n '{comments: [{body: "Suivi : bead ast-ccc"}]}' > "$tmp/fix/comments-13.json"
  jq -n '[{number: 13, title: "fuzz: admin_cursor crashed", url: "https://example/13",
           body: "Reproduce:\n\n    cargo +nightly fuzz run admin_cursor crash-input"}]' \
    > "$tmp/fix/list-fuzz.json"
  cp "$tmp/fix/actions.log" "$tmp/fix/actions.log.2"
  out="$(bash "$script" --apply --no-close)"
  case "$out" in
    *"--no-close"*"#13 -> ast-ccc"*) ;;
    *) echo "self-test : --no-close ne rapporte pas l'issue épargnée" >&2; rc=1 ;;
  esac
  diff -q "$tmp/fix/actions.log" "$tmp/fix/actions.log.2" >/dev/null ||
    { echo "self-test : --no-close a quand même écrit sur GitHub" >&2; rc=1; }

  [ "$rc" = 0 ] && echo "self-test : ok"
  return "$rc"
}

if [ "$SELF_TEST" = 1 ]; then
  self_test
  exit $?
fi

for tool in gh bd jq; do
  command -v "$tool" >/dev/null 2>&1 ||
    { echo "$tool est requis et absent du PATH" >&2; exit 2; }
done

run
