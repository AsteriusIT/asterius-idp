---
description: "Vérification unique de fin de tâche — fmt, clippy strict, tests ciblés. Usage: /verify [filtre nextest]"
---
Exécute dans l'ordre et corrige à chaque étape avant de passer à la suivante :
1. `cargo fmt`
2. `cargo clippy --all-targets -- -D warnings`
3. `cargo nextest run $ARGUMENTS` (si aucun filtre n'est donné, déduis-le des modules modifiés : `git diff --name-only main`)
Rapporte en 5 lignes max : warnings clippy corrigés, tests passés/échoués, ce qui reste à faire.
