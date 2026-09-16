# Benchmark V1 — état de référence

Cette documentation décrit ce que LANCE et IoTChainBench font actuellement,
leurs règles d’évaluation et leurs limites. Elle ne décrit pas une architecture
future et ne constitue pas une validation de tous les scénarios sur le laboratoire.

## Référence

État du code relu le **15 septembre 2026**, sur la base Git
`1ea2c34d5f0791b888122de0c43a478bab626368`, avec les changements d’extraction du
transport fournisseur et d’isolation des livrables publiés avec cette documentation.
Cette base seule ne reproduit donc pas tout l’état décrit : utiliser le commit
de publication contenant ces changements comme référence, puis consigner le SHA
effectivement exécuté pour chaque campagne. Aucun déploiement n’est attesté par
cette page.

**V1 reste le nom de cette référence documentaire**, pas le numéro de chaque
correction. Les identifiants techniques sont conservés dans les métadonnées des
runs ; leurs sources sont le [catalogue](../../../benchmarks/catalog.yaml),
les [contrats d’évaluation](../../../src/benchmark/metric_contract.py) et
l’[entonnoir](../../../src/benchmark/funnel.py).

### Quand changer un contrat ?

- Texte, affichage, diagnostic ou refactoring à comportement identique : garder le contrat ; le commit Git trace le changement.
- Modification des critères de preuve, du calcul des scores ou d’un format incompatible : changer uniquement le contrat concerné et documenter la différence.
- Ne jamais renuméroter les anciens runs ni les rendre artificiellement compatibles.

Une correction courte peut changer les résultats : c’est son effet, pas sa taille,
qui détermine si un changement de contrat est nécessaire. Le README décrit l’état
courant ; il ne reçoit pas un paragraphe d’historique à chaque correction.

## Les quatre questions séparées

| Dimension | Question | Résultat à lire |
| --- | --- | --- |
| Détection | Quelles failles ont été identifiées ? | Hypothèses avant/après filtrage, VP/FP/FN |
| Preuve | Quelles déclarations sont réellement étayées ? | Traces acceptées/rejetées/manquantes et F1 final d’audit |
| Intrusion | Quels accès et objectifs ont été atteints ? | Accès corroborés, cibles et chemins vérifiés ; limites des pivots |
| Consommation | Qu’a demandé l’exécution ? | Tokens, temps, coûts, budgets et éventuelles données manquantes |

Il n’y a pas de score global mêlant audit et intrusion. Le F1 final est le score
principal **d’audit** pour un scénario avec failles attendues ; les contrôles
sans faille utilisent une spécificité au niveau du scénario.

## Organisation réelle

```text
docs/benchmark/v1/     Explications du benchmark
benchmarks/           Catalogue, scénarios, vérités terrain, topologies, packs, Ansible
src/agent/            Un pipeline, organisé en six phases
src/benchmark/        Évaluateur indépendant des déclarations de l’agent
tests/                Tests automatisés de l’application et de l’évaluateur
model_training/       Entraînement des modèles, configurations et tests dédiés
```

Le déroulement est : graphe → reconnaissance → analyse/filtrage → vérification
→ intrusion → rapport. L’évaluation du benchmark exploite ensuite les artefacts
et la vérité terrain. Les profils `full` et `compact` partagent le pipeline et
les exigences de preuve et de sécurité ; ils adaptent l’orchestration, les outils
exposés et les budgets. **Full reste disponible** et peut être choisi explicitement.

## Parcours de lecture

1. [Scénarios](scenarios.md) : ce que contient le corpus et comment il est séparé.
2. [Évaluation](evaluation.md) : calculs, preuves, FP et limites de l’intrusion.
3. [Exécution](execution.md) : lancement, statut, diagnostic et validation.

En complément, le [catalogue des attaques](../catalogue-attaques.md) relie les
familles de menaces aux objectifs S1–S29 et sépare implémentations, simulations
et propositions historiques.

Pour intervenir dans le code : [guide des phases](../../../src/agent/phases/README.md)
et [contrat des livrables](../../run-artifacts.md).

## Limites à garder visibles

- L’indépendance historique du jeu de test n’est pas vérifiée : il reste provisoire.
- Une trace acceptée n’est pas un rejeu indépendant ni une preuve formelle universelle.
- Les accès directs sont observables, mais la provenance causale des pivots réseau
  n’est pas implémentée ; aucun pivot ne doit être inventé à partir des chaînes du modèle.
- L’isolation des livrables ne garantit pas la concurrence de pipelines complets.
- La dernière suite locale rapportée avant cette réorganisation documentaire compte
  **2 456 tests réussis, 1 ignoré**. Cela ne démontre ni la disponibilité du fournisseur,
  ni la réussite d’une campagne S1–S29 sur le mini-PC.

Les anciens guides sont conservés dans les [archives](../../audit/benchmark-avant-v1/README.md).
Pour maintenir cette référence, mettre à jour le comportement décrit et la
validation effectivement réalisée, sans transformer un résultat ancien en résultat courant.
