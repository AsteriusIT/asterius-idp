# Project Instructions for AI Agents

This file provides instructions and context for AI coding agents working on this project.

<!-- BEGIN BEADS INTEGRATION v:1 profile:minimal hash:6cd5cc61 -->
## Beads Issue Tracker

This project uses **bd (beads)** for issue tracking. Run `bd prime` to see full workflow context and commands.

### Quick Reference

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --claim  # Claim work
bd close <id>         # Complete work
```

### Rules

- Use `bd` for ALL task tracking — do NOT use TodoWrite, TaskCreate, or markdown TODO lists
- Run `bd prime` for detailed command reference and session close protocol
- Use `bd remember` for persistent knowledge — do NOT use MEMORY.md files

**Architecture in one line:** issues live in a local Dolt DB; sync uses `refs/dolt/data` on your git remote; `.beads/issues.jsonl` is a passive export. See https://github.com/gastownhall/beads/blob/main/docs/SYNC_CONCEPTS.md for details and anti-patterns.

## Agent Context Profiles

The managed Beads block is task-tracking guidance, not permission to override repository, user, or orchestrator instructions.

- **Conservative (default)**: Use `bd` for task tracking. Do not run git commits, git pushes, or Dolt remote sync unless explicitly asked. At handoff, report changed files, validation, and suggested next commands.
- **Minimal**: Keep tool instruction files as pointers to `bd prime`; use the same conservative git policy unless active instructions say otherwise.
- **Team-maintainer**: Only when the repository explicitly opts in, agents may close beads, run quality gates, commit, and push as part of session close. A current "do not commit" or "do not push" instruction still wins.

## Session Completion

This protocol applies when ending a Beads implementation workflow. It is subordinate to explicit user, repository, and orchestrator instructions.

1. **File issues for remaining work** - Create beads for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **Handle git/sync by active profile**:
   ```bash
   # Conservative/minimal/default: report status and proposed commands; wait for approval.
   git status

   # Team-maintainer opt-in only, unless current instructions forbid it:
   git pull --rebase
   git push
   git status
   ```
5. **Hand off** - Summarize changes, validation, issue status, and any blocked sync/commit/push step

**Critical rules:**
- Explicit user or orchestrator instructions override this Beads block.
- Do not commit or push without clear authority from the active profile or the current user request.
- If a required sync or push is blocked, stop and report the exact command and error.
<!-- END BEADS INTEGRATION -->

## Règles de session — projet Rust

Ces règles sont propres à ce dépôt. En cas de conflit avec un conseil générique
ci-dessus, elles gagnent ; les instructions explicites de l'utilisateur ou de
l'orchestrateur gagnent sur tout.

### Rythme de travail (non négociable)

- Pendant l'édition : `cargo check` uniquement (un hook le lance après chaque `.rs` modifié).
- En fin de tâche, une seule fois : `/verify <filtre>` = fmt → clippy `-D warnings` → `cargo nextest run <filtre>` ciblé.
- `cargo test` est interdit (hook + permissions). Jamais la suite complète en local : c'est le rôle de la CI sur `main`.
- Maximum 3 exécutions de nextest par session ; au-delà, le hook refuse.

### Tickets & branches

- Source de vérité : beads (voir le bloc Beads ci-dessus).
  `bd ready` → `bd update --status in_progress` → travail → `bd close --reason "<résumé>"`.
- Une branche `claude/<id>` par ticket, dans un worktree isolé. Merge `--no-ff` dans
  `main` par l'orchestrateur seulement, puis suppression de la branche et `git worktree prune`.
- Commits : Conventional Commits, `Refs: <id>` en pied de message.
- Jamais : `push --force`, `reset --hard`, `clean`, modification directe de `main` depuis un worker.

### Mode journée entière

- `/grind [n]` : l'orchestrateur délègue chaque ticket à l'agent `ticket-worker` et
  ne garde en contexte que son résumé de 10 lignes. Le Stop hook enchaîne les tickets.
- `/grind-stop` pour arrêter proprement, `/status` pour le tableau de bord (utile depuis le mobile).
- Un ticket ambigu → `BLOQUE` avec la cause, on passe au suivant. Ne pas deviner.

### Code

- Erreurs : `thiserror` dans les modules de bibliothèque, `anyhow` uniquement dans
  `main`/binaires. Pas de `unwrap()` hors tests ; `expect("raison")` seulement si
  l'invariant est documenté.
- Pas de `#[allow(clippy::...)]` sans commentaire justificatif.
- Tests unitaires dans le module (`#[cfg(test)]`), tests d'intégration lents marqués
  `#[ignore]` et lancés par la CI avec `--run-ignored all`.
- Voir le skill `rust-projet` pour les conventions détaillées.

## Architecture Overview

_Add a brief overview of your project architecture_
