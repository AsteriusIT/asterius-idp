---
name: rust-projet
description: Conventions Rust de CE projet — gestion d'erreurs, tests, organisation des modules, commandes cargo autorisées. Utilise ce skill à chaque fois que tu écris, modifies ou revois du code Rust ici, y compris pour un simple fix, un test ou un refactor, même si l'utilisateur ne parle pas de conventions.
---

# Conventions Rust du projet

## Commandes
| Moment | Commande |
|---|---|
| Après chaque édition | `cargo check --all-targets` (automatique via hook) |
| Fin de tâche, une fois | `cargo fmt && cargo clippy --all-targets -- -D warnings && cargo nextest run <filtre>` |
| Interdit en local | `cargo test`, `cargo nextest run` sans filtre |
| Réservé à la CI | suite complète, `--run-ignored all`, Sonar |

Filtre nextest = nom du module ou du test : `cargo nextest run auth::` ou `cargo nextest run test_parse_token`.

## Erreurs
- Bibliothèque / modules : enum d'erreur par domaine avec `thiserror`, variantes explicites, `#[from]` pour les conversions.
- Binaire (`main.rs`) : `anyhow::Result` + `.context("...")` pour le message utilisateur.
- `unwrap()` interdit hors `#[cfg(test)]`. `expect("invariant : ...")` toléré avec la raison.
- Ne jamais avaler une erreur (`let _ = fallible()` interdit sans commentaire).

## Tests
- Unitaires dans le module : `mod tests { use super::*; ... }`. Nom = comportement : `rejects_expired_token`, pas `test1`.
- Arrange-Act-Assert. Un comportement par test. Cas nominal + au moins un cas limite/erreur.
- Bug → d'abord le test rouge qui le reproduit, puis le fix.
- Lent (I/O, réseau, > 1 s) → `#[ignore = "lent : ..."]`, la CI les lance.
- Pas de `sleep` pour synchroniser ; pas de dépendance à l'ordre d'exécution.

## Structure
- Un module = une responsabilité ; `mod.rs` ne contient que des `pub use` et des déclarations.
- Types de domaine sans I/O ; l'I/O aux bords (adapters). Injecter les dépendances par trait quand un test en a besoin, pas avant.
- Préparer le futur workspace : garder `core` (domaine), `infra` (I/O), `cli` séparés en modules dès maintenant.
- API publique minimale : `pub(crate)` par défaut.

## Style
- `rustfmt` par défaut, pas de `#[rustfmt::skip]`.
- Clippy pedantic accepté au cas par cas, jamais désactivé globalement.
- Commentaires = le *pourquoi* (décision, contrainte), jamais le *quoi*.
- Pas de `clone()` défensif : préférer les emprunts, `Cow` si nécessaire.

## Commits
`type(scope): résumé impératif` (feat, fix, refactor, test, docs, perf, chore) + corps si le pourquoi n'est pas évident + `Refs: <id beads>`.
