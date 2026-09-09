---
description: "Traite tous les tickets beads prêts, à la suite, jusqu'à backlog vide. Usage: /grind [max_iterations]"
---
Active le mode GRIND. Tu es l'ORCHESTRATEUR : tu ne codes pas, tu délègues.
Ton contexte doit rester léger pour tenir toute la journée.

Initialise l'état :
```bash
jq -n --argjson max "${ARGUMENTS:-30}" '{active: true, iteration: 0, max_iterations: $max}' > .claude/grind.local.json
```
(si `$ARGUMENTS` est vide, utilise 30). Puis lance le premier tour.

## Un tour = un ticket
1. `bd ready -n 1 --json` → id. Si vide : `jq '.active=false' .claude/grind.local.json > t && mv t .claude/grind.local.json`, résume la journée et arrête-toi.
2. `bd update <id> --status in_progress --assignee claude`
3. `bd show <id>` puis délègue à l'agent **ticket-worker** avec un prompt autonome contenant : l'id, la description complète du ticket, les critères d'acceptation. Ne lis pas les fichiers du projet toi-même.
4. À la réponse du worker :
   - `STATUT: OK` → depuis le dépôt principal : `git merge --no-ff claude/<id> -m "merge(<id>): <titre>"`, `git push origin main`, puis `./scripts/cleanup-worktrees.sh --apply` (supprime worktree et branche des `claude/*` fusionnés — voir plus bas). Puis `bd close <id> --reason "<RESUME du worker>"`.
   - `STATUT: PARTIEL` → merge si ça compile, `bd close` le ticket, et `bd create` un ticket de suite avec le contenu de SUITE.
   - `STATUT: BLOQUE` → `bd update <id> --status blocked --reason "<cause>"`, supprime la branche si elle est vide.
5. Si `SUITE` contient des points concrets, crée des tickets beads (priorité basse).
6. `bd sync`. Écris une ligne de bilan : `[<id>] <statut> — <résumé>`.
7. Termine ta réponse. Le Stop hook te relancera automatiquement avec le ticket suivant.

## Libérer le worktree d'un ticket fusionné
Chaque worktree d'agent porte son propre `target/` (≈ 1 Go après un simple
`cargo check`, bien plus s'il a lancé nextest) et rien ne le supprime tout
seul : `git worktree prune` ne nettoie que les répertoires déjà disparus.
`./scripts/cleanup-worktrees.sh --apply` supprime worktree + branche pour tout
`claude/*` **déjà fusionné dans main**, en épargnant les worktrees verrouillés
par un agent et les branches encore au sommet de main (worktree qui vient de
démarrer, rien de fusionné). Sans `--apply` il se contente de lister. Lance-le
après chaque merge.

Les artefacts périmés du dépôt principal, eux, ne partent avec aucun worktree :
cargo n'en récupère jamais un seul. `./scripts/gc-build-artifacts.sh` les
chiffre (sans argument il ne fait que rapporter), `--apply` les supprime.
Utile quand `df -h /` passe sous ~20 Go libres.

## Règles
- Ne conserve pas les diffs ni les fichiers lus dans ton contexte : seuls les résumés du worker comptent.
- Un ticket qui revient deux fois → marque-le bloqué, passe au suivant.
- Si le Stop hook signale un échec CI sur main, crée le ticket `fix(ci)` en priorité 0 et traite-le en premier.
- Jamais de `git push --force`, jamais de `cargo test`.
