# Documentation LANCE

## Comprendre le benchmark actuel

La [documentation du benchmark V1](benchmark/v1/README.md) est le point d’entrée :

- [Scénarios](benchmark/v1/scenarios.md) : corpus, topologies, vérités terrain et séparation dev/test.
- [Catalogue des attaques](benchmark/catalogue-attaques.md) : familles, objectifs S1–S29, simulations et propositions hors couverture actuelle.
- [Évaluation](benchmark/v1/evaluation.md) : détection, preuves, intrusion et interprétation des métriques.
- [Exécution](benchmark/v1/execution.md) : lancer un run, lire son statut, ses coûts et ses diagnostics.

« V1 » nomme cette référence documentaire, pas une nouvelle version du catalogue
ou du contrat de calcul. Sa date, sa base Git et ses limites sont précisées dans
son introduction.

## Comprendre et modifier le code

- [Pipeline organisé par phase](../src/agent/phases/README.md).
- [Isolation des livrables par run](run-artifacts.md).
- [Authentification des actions administratives](provider-auth.md).

## Guides complémentaires

- [Entraînement des modèles et experts MoE](../model_training/README.md).
- [Scénarios manuels hors catalogue](manual_scenarios.md).
- [Infrastructure Ansible](../benchmarks/ansible/README.md) : installation et exploitation, à adapter au laboratoire.
- [Boucle d’apprentissage](LEARNING_LOOP.md).
- [Espaces de travail d’entraînement](TRAINING_WORKSPACES.md).
- [HMoE et OpenWebUI](lance_hmoe_openwebui.md).

## Historique, pas contrat courant

- [Anciens documents du benchmark](audit/benchmark-avant-v1/README.md).
- [Revue et corrections du 15 septembre 2026](audit/2026-09-15/CORRECTIONS_REVUE.md).
- [Extraction du transport fournisseur](audit/2026-09-15/STRUCTURE_FOURNISSEUR.md).
- [Audit frontend historique](audit/README.md).

Les audits datés et les plans conservés dans ce dépôt expliquent des décisions
ou des états passés. Une correction annoncée dans une archive n’est pas, à elle
seule, une preuve de validation du code ou du laboratoire actuel.
