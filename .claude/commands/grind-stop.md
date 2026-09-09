---
description: Arrête la boucle GRIND à la fin du ticket en cours.
---
Désactive la boucle : `jq '.active=false | .stopped_reason="arrêt manuel"' .claude/grind.local.json > t && mv t .claude/grind.local.json`.
Termine le ticket en cours normalement (merge/close), puis affiche : nombre d'itérations faites, tickets clos, tickets bloqués (`bd list --status blocked`), et les worktrees restants (`git worktree list`).
