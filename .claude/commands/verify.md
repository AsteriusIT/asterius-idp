---
description: "Vérification unique de fin de tâche — fmt, clippy strict, tests ciblés. Usage: /verify [filtre nextest]"
---
Exécute dans l'ordre et corrige à chaque étape avant de passer à la suivante :
1. `cargo fmt`
2. `SQLX_OFFLINE=true cargo clippy --all-targets -- -D warnings`
3. `SQLX_OFFLINE=true cargo nextest run $ARGUMENTS` (si aucun filtre n'est donné, déduis-le des modules modifiés : `git diff --name-only main`)
Rapporte en 5 lignes max : warnings clippy corrigés, tests passés/échoués, ce qui reste à faire.

`SQLX_OFFLINE=true` partout : sans base à l'écoute sur 5433, sqlx compose le
`DATABASE_URL` et attend son timeout en gardant le verrou de build — la commande
semble figée. Le répertoire `.sqlx` est commité, la vérification hors ligne
suffit. Pour vérifier contre une vraie base : `./scripts/check.sh --db`, qui
démarre le conteneur **et** applique les migrations (une base non migrée fait
sortir sqlx du mode offline et échouer les 122 requêtes).
