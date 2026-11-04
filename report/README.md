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
| checkpoint-1 | Q4 2025 | — (non enregistré) | remplacé par checkpoint-2 | [etat.tex](checkpoint-1/etat.tex) |
| checkpoint-2 | Q1 2026 | — (non enregistré) | remplacé par checkpoint-3 | [etat.tex](checkpoint-2/etat.tex) |
| checkpoint-3 | état au 3 novembre 2026 | `546b911` (30 oct. 2026) | **courant** | [etat.tex](checkpoint-3/etat.tex) |

## Notes

- **checkpoint-1** et **checkpoint-2** sont d'anciens rapports trimestriels
  (modèle LaTeX différent, un seul fichier). Ils décrivent une architecture
  antérieure — checkpoint-1 (Q4 2025) parle encore de Neo4j / MongoDB / Ollama,
  abandonnés depuis. Conservés tels quels comme traces historiques ; seule la
  date dynamique `\today` a été figée sur leur trimestre.
- **PDF à (re)compiler** pour checkpoint-1 et checkpoint-2 : la convention veut
  `etat.pdf` versionné à côté de la source (checkpoint-3 l'a déjà).
- La renumérotation (Q4 2025 → 1, Q1 2026 → 2, état de novembre → 3) a été faite
  le 2026-11-04 pour mettre les trois états dans une seule série ordonnée.
