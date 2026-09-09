---
description: Tableau de bord rapide pour le pilotage à distance.
---
Affiche, sans commentaire superflu :
- État grind : `cat .claude/grind.local.json 2>/dev/null || echo "inactif"`
- Backlog : `bd ready --json | jq length` prêts, `bd list --status in_progress`, `bd list --status blocked`
- Git : `git log --oneline -5 main`, `git worktree list`, `git branch --list 'claude/*'`
- CI : `gh run list --branch main --limit 3`
