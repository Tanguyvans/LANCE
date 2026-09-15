# IoTChainBench — données et outils

La documentation courante est dans **[docs/benchmark/v1/](../docs/benchmark/v1/README.md)** :

- [Scénarios et séparation dev/test](../docs/benchmark/v1/scenarios.md).
- [Évaluation, preuves et métriques](../docs/benchmark/v1/evaluation.md).
- [Exécution et diagnostic](../docs/benchmark/v1/execution.md).

Ce dossier reste à la racine car il contient les données et outils exécutables,
pas seulement du texte :

```text
benchmarks/
├── catalog.yaml          # Identifiants, groupes et version du corpus
├── scenarios/            # Définitions dev/ et test/
├── ground_truth/         # Références dev/ et test/, contrat commun
├── topologies/           # Composants réseau
├── packs/                # Propriétés et failles composables
├── scenarios_manual/     # Laboratoires hors catalogue officiel
├── ansible/              # Déploiement, vérification et nettoyage
└── tools/                # Composition et validation des données
```

Le [catalogue](catalog.yaml) est la source de vérité pour le corpus.
L’évaluateur est dans [src/benchmark/](../src/benchmark/), et le pipeline unique
dans [src/agent/](../src/agent/). Les anciens guides restent consultables dans
les [archives documentaires](../docs/audit/benchmark-avant-v1/README.md).
