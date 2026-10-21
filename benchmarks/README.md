# IoTChainBench — données et outils

La documentation courante est dans **[docs/benchmark/v1/](../docs/benchmark/v1/README.md)** :

- [Scénarios et séparation dev/test](../docs/benchmark/v1/scenarios.md).
- [Catalogue des attaques et objectifs S1–S29](../docs/benchmark/catalogue-attaques.md).
- [Évaluation, preuves et métriques](../docs/benchmark/v1/evaluation.md).
- [Exécution et diagnostic](../docs/benchmark/v1/execution.md).

Ce corpus est le matériel du benchmark ; les hypothèses qu'il sert à tester
sont au [registre d'hypothèses](../research/2026-10-21-hypotheses-benchmark/README.md),
qui fixe l'ordre courant (porte V0, puis H1-H6).

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
├── experiments/          # Harnais réels SSH et MQTT, campagne V2 et résumés
└── tools/                # Composition et validation des données
```

Le [catalogue](catalog.yaml) est la source de vérité pour le corpus.
L’évaluateur est dans [src/benchmark/](../src/benchmark/), et le pipeline unique
dans [src/agent/](../src/agent/). Les anciens guides restent consultables dans
les [archives documentaires](../docs/audit/benchmark-avant-v1/README.md).
