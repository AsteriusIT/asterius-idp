---
description: "Vérification unique de fin de tâche — fmt, clippy strict, tests ciblés. Usage: /verify [filtre nextest]"
---
Lance `./scripts/verify.sh $ARGUMENTS` depuis la racine du worktree, et corrige
à chaque étape avant de relancer. Le script enchaîne :
1. `cargo fmt --all`
2. `SQLX_OFFLINE=true cargo clippy --all-targets -- -D warnings`
3. `SQLX_OFFLINE=true cargo nextest run -E '<filtre>'`, où `<filtre>` est ton
   périmètre **plus** les audits whole-tree (`source_audit`, `secret_audit` :
   redirections, confinement de `SEE_OTHER`, lecture du header `Cookie`,
   absence de CORS, règles de templates et de secrets). Ils scannent toutes les
   sources du workspace mais vivent chacun dans un seul crate : le script les
   ajoute mécaniquement, ne les retire jamais du filtre à la main.

Si tu ne passes pas d'argument, déduis ton périmètre des modules modifiés
(`git diff --name-only main`) et passe-le : sans argument, seuls les audits
tournent, ce qui ne prouve rien sur ton code.

Rapporte en 5 lignes max : warnings clippy corrigés, tests passés/échoués, ce
qui reste à faire.

`SQLX_OFFLINE=true` partout, et le script l'exporte lui-même : sans base à
l'écoute sur 5433, sqlx compose le `DATABASE_URL` et attend son timeout en
gardant le verrou de build — la commande semble figée. Le répertoire `.sqlx`
est commité, la vérification hors ligne suffit. Pour vérifier contre une vraie
base : `./scripts/check.sh --db`, qui démarre le conteneur **et** applique les
migrations (une base non migrée fait sortir sqlx du mode offline et échouer les
122 requêtes).
