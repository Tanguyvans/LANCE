# Documentation LANCE

Ce dossier regroupe les descriptions du système, les contrats retenus et les
guides d'utilisation. Les hypothèses, revues bibliographiques et protocoles
proposés sont regroupés dans les [dossiers de recherche](../research/README.md).
Les [archives d'audit](#archives-historiques) décrivent des états passés.
Le [rapport de recherche en PDF](../research/2026-09-27-agent-vs-automation/report.pdf)
relie les diagnostics du benchmark et du contexte au protocole de comparaison
LLM/règles ; les propositions restent distinctes de la référence implémentée.

## Organisation

| Dossier | Contenu |
| --- | --- |
| `architecture/` | Fonctionnement du pipeline, livrables et mécanismes de reprise |
| `guides/` | Accès à l'application, fournisseurs et scénarios manuels |
| `benchmark/` | Scénarios, contrats d'évaluation et procédures de comparaison |
| `training/` | Boucle d'apprentissage, espaces de travail et service des modèles |
| `audit/` | Audits et références historiques, distincts du contrat courant |
| `images/` | Illustrations utilisées par la documentation |

## Benchmark et évaluation

La [documentation du benchmark V1](benchmark/v1/README.md) est le point d'entrée :

- [Scénarios](benchmark/v1/scenarios.md) : corpus, topologies, vérités terrain et séparation dev/test.
- [Catalogue des attaques](benchmark/catalogue-attaques.md) : familles, objectifs S1–S29, simulations et propositions hors couverture actuelle.
- [Évaluation](benchmark/v1/evaluation.md) : détection, preuves, intrusion et interprétation des métriques.
- [Exécution](benchmark/v1/execution.md) : lancer un run, lire son statut, ses coûts et ses diagnostics.
- [Guide CLI D1/A1](benchmark/agent-vs-automation-cli.md) : analyse et vérification sur inventaire public commun, évaluation et comparaison d'une paire.
- [Guide de campagne](benchmark/agent-vs-automation-campaign.md) : politique D1 bornée, manifeste du pilote de 24 essais, bilan et revue indépendante des preuves.

« V1 » nomme cette référence documentaire, pas une nouvelle version du catalogue
ou du contrat de calcul. Sa date, sa base Git et ses limites sont précisées dans
son introduction. Les guides D1/A1 décrivent les outils disponibles ; la présence
d'un manifeste de pilote ne signifie pas que la campagne a été exécutée.
Le [dossier agent / automatisation](../research/2026-09-27-agent-vs-automation/README.md)
regroupe le protocole proposé, l'état de l'art et le plan d'implémentation.
La [recherche sur la couverture](../research/2026-09-29-benchmark-coverage/README.md)
analyse les limites du corpus et les contre-exemples de mesure ; ses propositions
ne modifient pas le contrat de référence ci-dessus.

## Architecture et développement

- [Pipeline organisé par phase](../src/agent/phases/README.md).
- [Isolation des livrables par run](architecture/run-artifacts.md).
- [Rédaction du rapport par sections](architecture/report-writing.md).
- [Reprise de la phase 1 après troncature](architecture/phase1-graph-recovery.md).
- [Reprise de la phase 3 par blocs](architecture/phase3-block-recovery.md).
- [Gate anti-no-op de la phase 5 en profil full](architecture/phase5-noop-gate.md).
- [Tests automatisés](../tests/README.md).

La [recherche sur le contexte](../research/2026-09-29-context-scalability/README.md)
étudie les six phases et distingue les mécanismes présents des évolutions proposées.

## Utilisation et infrastructure

- [Authentification et fournisseurs d'exécution](guides/provider-auth.md).
- [LLM UMONS : connexion, choix des modèles et dépannage](guides/umons-llm.md).
- [Accès labo nato-master via Tailscale depuis la machine dev](guides/lab-access-tailscale.md).
- [Session administrateur de 8 heures](guides/admin-session.md).
- [Scénarios manuels hors catalogue](guides/manual-scenarios.md).
- [Branches et instances de développement sur nato](guides/development-instances.md).
- [Infrastructure Ansible](../benchmarks/ansible/README.md).

Pour les commandes de laboratoire et de déploiement, respecter la
[cible et les autorisations du dépôt](../AGENTS.md#cible-dexécution-et-de-déploiement).

## Entraînement et modèles

- [Entraînement des modèles et experts MoE](../model_training/README.md).
- [Boucle d'apprentissage](training/learning-loop.md).
- [Espaces de travail d'entraînement](training/workspaces.md).
- [HMoE et OpenWebUI](training/hmoe-openwebui.md).

## Archives historiques

- [Anciens documents du benchmark](audit/benchmark-avant-v1/README.md).
- [Revue et corrections du 15 septembre 2026](audit/2026-09-15/CORRECTIONS_REVUE.md).
- [Extraction du transport fournisseur](audit/2026-09-15/STRUCTURE_FOURNISSEUR.md).
- [Audit frontend historique](audit/README.md).
- [Historique de la structure du pipeline](audit/pipeline_llmdfa.md).
- [Ancienne étude de scalabilité du contexte](../research/2026-09-29-context-scalability/plan.md).

Les audits datés et les plans conservés expliquent des décisions ou des états
passés. Une correction annoncée dans une archive n'est pas, à elle seule, une
preuve de validation du code ou du laboratoire actuel.
