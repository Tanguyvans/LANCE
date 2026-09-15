# Benchmark V1 — état de référence

Cette documentation décrit ce que LANCE et IoTChainBench font actuellement,
leurs règles d’évaluation et leurs limites. Elle ne décrit pas une architecture
future et ne constitue pas une validation de tous les scénarios sur le laboratoire.

## Référence et versions

État du code relu le **15 septembre 2026**, sur la base Git
`1ea2c34d5f0791b888122de0c43a478bab626368`, avec les changements d’extraction du
transport fournisseur et d’isolation des livrables publiés avec cette documentation.
Cette base seule ne reproduit donc pas tout l’état décrit : utiliser le commit
de publication contenant ces changements comme référence, puis consigner le SHA
effectivement exécuté pour chaque campagne. Aucun déploiement n’est attesté par
cette page.

| Repère | Valeur dans l’état décrit | Source faisant autorité |
| --- | --- | --- |
| Référence documentaire | V1 | Cette documentation |
| Catalogue | `3.2.0` | [catalog.yaml](../../../benchmarks/catalog.yaml) |
| Contrat métrique | `strict-v3.12` | [metric_contract.py](../../../src/benchmark/metric_contract.py) |
| Contrat de preuve | `evidence-v12` | Même module |
| Entonnoir | `funnel-v1` | [funnel.py](../../../src/benchmark/funnel.py) |

Ces versions sont distinctes. Organiser la documentation en V1 ne renomme ni
les contrats, ni les anciens runs, ni le catalogue.

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
Pour maintenir cette référence, mettre à jour les versions et la validation
effectivement réalisée, sans transformer un résultat ancien en résultat courant.
