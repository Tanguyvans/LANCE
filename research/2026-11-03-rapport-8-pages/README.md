# Checkpoint au 3 novembre 2026 : le rapport en huit pages

**Cycle de vie : Conclu — checkpoint.** Remplace le
[checkpoint du 2 novembre](../2026-11-02-rapport-vue-ensemble/README.md), conservé
comme archive et comme source du détail d'implémentation.
Dernière révision : **2026-11-03 22:00 (Europe/Brussels, UTC+01:00)**.
Statut : **rapport documentaire ; aucune expérience nouvelle, aucun run nouveau.**

## 1. Depuis le checkpoint précédent

Aucune modification de fond : toujours zéro commit de code depuis le 30 octobre.
Le travail de la période est une réduction du rapport de 26 à **8 pages**, et la
correction des affirmations fausses qu'une quatrième relecture avait relevées.

## 2. État actuel

Il est dans [objectifs/ETAT-COURANT.md](../../objectifs/ETAT-COURANT.md) ; ce
checkpoint ne le recopie pas. Ce que la période a établi : voir la section 1 du
rapport, qui garde la table d'état avec son renvoi vers la preuve.

## 3. Jusqu'où va le projet

Le rapport porte la table des blocages et, pour chacun, le critère observable qui
le franchirait (section 3.2). Trois des quatre lignes dépendent de la première :
tant qu'aucune situation n'existe qu'une règle d'une ligne ne tranche, les autres
mesurent son absence. **La première ligne est le seul travail qui peut commencer.**

## Ce qui a changé dans cette révision

Le rapport passe de 26 à 8 pages et de neuf parties à trois :

| Avant | Après |
| --- | --- |
| Ouverture (5 p.) + cinq parties techniques + conclusion | **1. Où en est le projet** (4 p.) · **2. Ce qui est construit et ce qui est mesuré** (2 p.) · **3. Ce qui reste** (2 p.) |
| Anatomie des harnais, budgets, coûts, infrastructure, glossaire | Une table de neuf composants, chacun avec sa garantie et sa limite, et le renvoi vers `docs/` |

Les trois figures sont conservées : elles portent l'essentiel du raisonnement.

## Corrections de la période

Une quatrième relecture, indépendante, a trouvé six erreurs en plus des huit
connues. Neuf ont été supprimées avec la coupe ; les corrections de fond sont :

| Affirmation retirée | Ce que dit l'artefact |
| --- | --- |
| « twelve admissible pairs » | 12 paires prévues, 7 exécutées sous gel, **3 publiées comparables**, 5 incomparables, campagne non admissible |
| la lecture interprétative « catégorie par catégorie » | Attribution inversée : le par-catégorie est interprétatif, le par-entrée est mécanique |
| « the reference run that followed » | Le run à 72 bras **remplace** celui à 16 bras, le même jour |
| « two trials came to be built » | **Un seul** dispositif construit, puis rejeté |
| « a log that does not forgive » | Contredit par la phase 5, qui lit le journal d'outils |

## Points encore ouverts

- Le mode `rules` : l'API refuse de le scorer (`score_run` exige `lance`), et
  `objectifs/ETAT-COURANT.md` affirme l'inverse. Seul un run réel suivi d'un
  `curl /api/runs/<id>/score` départagera les deux.
- `derived_index.json` porte `summary.scenarios = 31` ; le texte cite 29.
- « the declared-parser arm succeeds in six trials » n'est adossé à aucun artefact
  du dépôt et n'a pas été recalculé.
