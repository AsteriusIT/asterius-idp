# Kit de fiabilisation Claude Code — sessions longues sur projet Rust

## Installation
1. Copie `.claude/`, `CLAUDE.md`, `scripts/` et `.github/` à la racine du projet.
2. `chmod +x .claude/hooks/*.sh scripts/*.sh`
3. Dépendances WSL : `sudo apt install jq tmux`, `cargo install cargo-nextest`.
   Optionnel mais recommandé : `cargo install sccache` + `mold` (voir `.cargo/config.toml` ci-dessous).
4. Ajoute `.claude/grind.local.json` et `.claude/settings.local.json` au `.gitignore`.
5. Supprime `--dangerously-skip-permissions` de ta façon de lancer Claude ; utilise `scripts/start-session.sh`.

## Utilisation
- `scripts/start-session.sh` → session tmux. Connecte-toi en remote control depuis le mobile.
- `/grind 30` → traite jusqu'à 30 tickets `bd ready` à la suite.
- `/status` → tableau de bord ; `/grind-stop` → arrêt propre ; `/verify auth::` → vérification ciblée.
- `scripts/cleanup-worktrees.sh` → ménage de fin de journée.

## Ce que fait chaque pièce
| Fichier | Rôle |
|---|---|
| `.claude/settings.json` | Liste blanche de permissions (plus de prompts pour le travail normal) + déclaration des hooks |
| `hooks/cargo-check.sh` | `cargo check` automatique (en `SQLX_OFFLINE=true`) après chaque `.rs` modifié, erreurs renvoyées à Claude |
| `hooks/grind-stop.sh` | Boucle : relance l'orchestrateur avec le ticket suivant, détecte backlog vide / ticket qui tourne en rond / CI rouge |
| `agents/ticket-worker.md` | Subagent isolé (worktree) qui implémente un ticket et rend un résumé de 10 lignes |
| `commands/*.md` | `/grind`, `/grind-stop`, `/verify`, `/status` |
| `skills/rust-projet` | Conventions Rust du projet, chargées quand Claude code |
| `CLAUDE.md` | Règles de session courtes, toujours en contexte |
| `.github/workflows/ci.yml` | Suite complète + clippy + fmt ; brancher Sonar dessus |

## Accélérer les builds (optionnel) — `.cargo/config.toml`
```toml
[build]
rustc-wrapper = "sccache"

[target.x86_64-unknown-linux-gnu]
linker = "clang"
rustflags = ["-C", "link-arg=-fuse-ld=mold"]
```
(`sudo apt install clang mold`)

## Points à vérifier après installation
- `bd ready -n 1 --json` renvoie bien un tableau avec un champ `id` (sinon adapte le `jq` de `grind-stop.sh`).
- Les flags `bd update --status/--reason` et `bd close --reason` correspondent à ta version de beads (`bd update --help`).
- Le worker, dans son worktree, doit voir `main` : `git rebase main` fonctionne car les worktrees partagent le `.git`.
- Premier `/grind 2` en surveillant : vérifie que la mise en `in_progress` retire bien le ticket de `bd ready`, sinon le compteur « même ticket » déclenchera à tort.

## Limites connues
- Les hooks déclarés dans `settings.json` ne sont pas toujours hérités par les subagents : ils sont donc redéclarés dans le frontmatter de `ticket-worker.md`.
- Le Stop hook ignore volontairement `stop_hook_active` : c'est `max_iterations` et le compteur « même ticket » qui empêchent la boucle infinie.
- Le hook `cargo-check.sh` s'exécute dans le `cwd` fourni par Claude Code ; pour un worktree, ce `cwd` est celui du worktree.
