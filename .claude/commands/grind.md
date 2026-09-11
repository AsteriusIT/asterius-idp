---
description: "Traite tous les tickets beads prêts, à la suite, jusqu'à backlog vide. Usage: /grind [max_iterations]"
---
Active le mode GRIND. Tu es l'ORCHESTRATEUR : tu ne codes pas, tu délègues.
Ton contexte doit rester léger pour tenir toute la journée.

Initialise l'état :
```bash
jq -n --argjson max "${ARGUMENTS:-30}" '{active: true, iteration: 0, max_iterations: $max}' > .claude/grind.local.json
```
(si `$ARGUMENTS` est vide, utilise 30).

Puis, **avant le premier tour**, rapatrie les alertes de la nuit :
```bash
./scripts/sync-github-issues.sh --apply
```
Les jobs nocturnes ouvrent une issue GitHub et non un bead — la base Dolt est
locale, un runner n'y accède pas. Le script crée le bead P1 manquant pour chaque
issue `fuzz`/`conformance` ouverte, commente l'issue avec son id (c'est ce
commentaire qui rend le script rejouable, pas un état local), et ferme celles
dont le bead est déjà clos. Sans lui, une issue vit ouverte des jours après le
correctif, ou un crash n'entre jamais dans le backlog : les deux se sont produits
le 2026-09-11 (issues #1 à #5, puis #6). Lis sa sortie : les beads créés sont des
P1 et sortiront en tête de `bd ready`. C'est aussi sur eux que se greffe le
`fix(ci)` P0 quand le Stop hook signale un échec CI sur main — pas sur un ticket
neuf. Ajoute `--no-close` si une issue doit rester ouverte jusqu'à un nightly vert.

Puis lance le premier tour.

## Un tour = un ticket
1. `bd ready -n 1 --json` → id. Si vide : `jq '.active=false' .claude/grind.local.json > t && mv t .claude/grind.local.json`, résume la journée et arrête-toi.
2. `bd update <id> --status in_progress --assignee claude`
3. `bd show <id>` puis délègue à l'agent **ticket-worker** avec un prompt autonome contenant : l'id, la description complète du ticket, les critères d'acceptation. Ne lis pas les fichiers du projet toi-même.
4. À la réponse du worker, `STATUT: OK` ou `PARTIEL` → **jamais de fusion sans un run vert de la branche** (voir « Fusionner par pull request ») :
   1. `git push -u origin claude/<id>` — jamais `--force`.
   2. `gh pr create --base main --head claude/<id> --title "<type>(<scope>): <titre> [<id>]" --body "<RESUME du worker>"` ; le corps porte `Refs: <id>` en pied, puis l'attribution PR du dépôt (`🤖 Generated with [Claude Code](https://claude.com/claude-code)` et le lien de session).
   3. `gh pr checks <numéro> --watch --fail-level fail` — bloquant, ~15 min quand les runners sont libres. C'est le seul verdict qui compte : le `/verify` du worker est ciblé, la CI juge la composition (fuzz build, sweep navigateur, rustdoc, deny, sentinelles).
   4. **Rouge** → renvoie au worker, même ticket et même branche, avec le nom du job et l'extrait de log : `gh run view <run-id> --log-failed | tail -50`. Quand il répond, reprends au point 1. Un ticket qui revient **une deuxième fois rouge** → `bd update <id> --status blocked --reason "CI rouge deux fois : <job>"`, et au suivant.
   5. **Vert** → depuis le dépôt principal : `git merge --no-ff claude/<id> -m "merge(<id>): <titre>"`, `git push origin main` — la PR se ferme d'elle-même comme fusionnée —, puis `./scripts/cleanup-worktrees.sh --apply` (worktree, branche locale et `origin/claude/<id>`, voir plus bas), puis `bd close <id> --reason "<RESUME du worker>"`.

   Un `PARTIEL` suit exactement le même chemin ; seul le `--reason` de clôture change : il consigne ce qui est livré ET ce qui ne l'est pas. Un ticket de suite seulement si le reste passe les filtres du point 5.

   `STATUT: BLOQUE` → `bd update <id> --status blocked --reason "<cause>"`, supprime la branche si elle est vide. Rien n'est poussé, aucune PR n'est ouverte.
5. `SUITE` n'est pas une liste de tickets à créer. Par défaut, on ne crée rien.
   Un ticket ne se justifie que si le point passe **les trois** filtres :
   - c'est un **défaut constaté** ou une **décision à trancher**, pas « il faudrait
     aussi tester X » ni un garde-fou contre un cas qui n'existe pas ;
   - il ne recoupe **aucun ticket ouvert** (`bd list` avant `bd create` : le backlog
     dépasse 140, le doublon est le mode d'échec courant) ;
   - il survivrait à la question « si personne ne le fait jamais, que casse-t-il ? ».

   Sinon : écris le constat **dans la description du ticket concerné** (`bd update -d`)
   ou dans le `--reason` de clôture. Un fait consigné au bon endroit vaut mieux
   qu'un ticket de plus. Une session qui produit plus de tickets qu'elle n'en
   ferme va dans le mauvais sens — dis-le dans le bilan.
6. Écris une ligne de bilan : `[<id>] <statut> — <résumé>`.
7. Termine ta réponse. Le Stop hook te relancera automatiquement avec le ticket suivant.

## Fusionner par pull request
Jusqu'à `ast-a33`, les branches étaient fusionnées en local et poussées sur
`main` : aucune CI ne les voyait avant, et dix `fix(ci)` en quatre jours l'ont
payé — tous des rouges de composition (build fuzz, sweep navigateur, rustdoc,
`cargo deny`, gardes sentinelles et rétention), donc hors du `/verify` ciblé du
worker. La branche passe désormais par une PR que la CI valide, et la fusion
n'a lieu qu'après verdict vert.

La fusion reste **locale** (`git merge --no-ff` puis `git push origin main`)
plutôt que `gh pr merge --merge` : elle garde le message `merge(<id>): <titre>`
de ce dépôt, elle laisse `main` local et distant identiques à la seconde près —
donc `cleanup-worktrees.sh` juge sur le bon sommet — et elle ne dépend d'aucune
protection de branche côté GitHub (`main` n'en a aucune aujourd'hui). Pousser
la fusion ferme la PR comme fusionnée, sans commit supplémentaire.

Deux points à ne pas confondre :
- Pousser sur `main` pendant qu'une PR tourne **n'annule rien** : la
  `concurrency` de `ci.yml` groupe par numéro de PR, et `cancel-in-progress`
  n'est vrai que pour les PR. Deux PR, ou une PR et `main`, tournent en
  parallèle jusqu'au bout.
- Un `git push` de plus sur une PR annule *son propre* run en cours et en
  relance un : c'est voulu, mais chaque aller-retour coûte le run complet.
  Renvoie donc au worker tout ce qu'il y a à corriger d'un coup.

## Libérer le worktree d'un ticket fusionné
Chaque worktree d'agent porte son propre `target/` (≈ 1 Go après un simple
`cargo check`, bien plus s'il a lancé nextest) et rien ne le supprime tout
seul : `git worktree prune` ne nettoie que les répertoires déjà disparus.
`./scripts/cleanup-worktrees.sh --apply` supprime worktree, branche locale et
branche distante `origin/claude/<id>` pour tout `claude/*` **déjà fusionné dans
main**, en épargnant les worktrees verrouillés par un agent, les branches encore
au sommet de main (worktree qui vient de démarrer, rien de fusionné) et les
branches distantes dont le sommet n'est pas contenu dans `main` (un agent a
poussé après la fusion). Sans `--apply` il se contente de lister. Lance-le après
chaque merge.

Les artefacts périmés du dépôt principal, eux, ne partent avec aucun worktree :
cargo n'en récupère jamais un seul. `./scripts/gc-build-artifacts.sh` les
chiffre (sans argument il ne fait que rapporter), `--apply` les supprime.
Utile quand `df -h /` passe sous ~20 Go libres.

## Règles
- Ne conserve pas les diffs ni les fichiers lus dans ton contexte : seuls les résumés du worker comptent.
- Un ticket qui revient deux fois → marque-le bloqué, passe au suivant.
- Si le Stop hook signale un échec CI sur main, crée le ticket `fix(ci)` en priorité 0 et traite-le en premier.
- Jamais de `git push --force`, jamais de `cargo test`.
