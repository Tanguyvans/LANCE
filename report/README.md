# Rapports d'état (checkpoints)

Un checkpoint photographie l'état du projet à une date. Il **ne se révise pas** :
il est remplacé par le suivant, qui le cite en tête ; l'ancien reste et conserve
le détail que le nouveau a déplacé. Convention (voir `AGENTS.md`) :
`report/checkpoint-<n>/etat.tex` (+ `etat.pdf`), numéro **séquentiel et jamais
réutilisé**, date de l'état et commit du code décrit en couverture. La
chronologie se lit dans cette table, pas dans l'historique git.

Les supports de présentation datés vont dans `presentations/`, pas ici.

| # | Période / date de l'état | Commit du code décrit | Statut | Rapport |
| --- | --- | --- | --- | --- |
| checkpoint-3 | état au 3 novembre 2026 | `546b911` (30 oct. 2026) | **courant** | [etat.tex](checkpoint-3/etat.tex) |

## Notes

- **checkpoint-1 (Q4 2025)** et **checkpoint-2 (Q1 2026)** étaient d'anciens
  rapports trimestriels (modèle LaTeX différent, architecture antérieure :
  Neo4j / MongoDB / Ollama, abandonnés depuis). Ils ne compilaient plus et ont
  été supprimés le 2026-11-05 ; l'historique git en garde la trace. Les numéros
  1 et 2 ne sont pas réattribués (convention : numéro séquentiel jamais réutilisé),
  donc la série commence à checkpoint-3.
