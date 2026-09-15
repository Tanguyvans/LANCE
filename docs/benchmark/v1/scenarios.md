# V1 — Scénarios et données

[Vue d’ensemble](README.md) · [Évaluation](evaluation.md) · [Exécution](execution.md)

## Corpus actuel

Le [catalogue 3.2.0](../../../benchmarks/catalog.yaml) contient **29 scénarios
publics**. Il est la référence pour les identifiants et les groupes ; les noms
ci-dessous en sont repris. Le nom d’un scénario décrit son objectif, pas une
capacité déjà démontrée par le pipeline.

| Groupe | Scénarios | Usage |
| --- | --- | --- |
| Développement : `dev-public`, dossier `dev/` | S1–S19 | Diagnostic, changements et choix de configuration |
| Test : `test-public`, dossier `test/` | S20–S29 | Évaluation d’une configuration figée |

**Le test est provisoire** : son indépendance historique vis-à-vis du développement
n’a pas été vérifiée. Si ses résultats ont servi à choisir des prompts, outils ou
budgets, il faut un nouveau jeu indépendant pour revendiquer une généralisation.
Les données des deux groupes sont publiques, et non secrètes ou scellées.

| ID | Nom du catalogue |
| --- | --- |
| S1 | Réseau plat |
| S2 | Gateway exposée |
| S3 | Réplique NATO Lab |
| S4 | Réseau segmenté |
| S5 | Smart Building |
| S6 | Domotique centralisée |
| S7 | Edge-Cloud pivot |
| S8 | Multi-zone IT/IoT/OT |
| S9 | Mesh IoT |
| S10 | Flat avec variantes |
| S11 | Smart City 3 zones |
| S12 | Smart City Large Scale |
| S13 | VLAN Segmented Network |
| S14 | Sparse Mixed-Hardening |
| S15 | Authenticated Multi-Tenant API |
| S16 | Device PKI Lifecycle |
| S17 | Stateful Signed OTA |
| S18 | Simulated Cloud IAM and SSRF |
| S19 | Safe Multi-Protocol OT Cell |
| S20 | True Network Multi-Hop Pivot |
| S21 | Sparse Low-Prevalence Network |
| S22 | Exploit Primitive Diversity |
| S23 | Wireless-to-Firmware Chain |
| S24 | Dual-Zone Operations Chain |
| S25 | Segmented Fan-Out |
| S26 | Asymmetric Pivot Paths |
| S27 | Three-Pivot Cascade |
| S28 | Provisioning Dependency Chain |
| S29 | Large Sparse Control Network |

Les variantes historiques S1h/S4h héritent du groupe de leur parent. Elles ne
s’ajoutent pas aux 29 scénarios officiels et ne sont pas déployées par Ansible.
Le support technique `eval-sealed` existe, mais aucun scénario du catalogue
courant n’appartient à ce groupe.

## Où se trouvent les éléments ?

| Élément | Responsabilité |
| --- | --- |
| [scenarios/](../../../benchmarks/scenarios/) | Composition de chaque scénario, rangée par groupe |
| [topologies/](../../../benchmarks/topologies/) | Machines, services et organisation du réseau |
| [packs/definitions/](../../../benchmarks/packs/definitions/) | Familles de propriétés et failles composables |
| [ground_truth/](../../../benchmarks/ground_truth/) | Failles et objectifs attendus, réservés à l’évaluateur |
| [matching_contracts.yaml](../../../benchmarks/ground_truth/matching_contracts.yaml) | Règles communes d’appariement |
| [ansible/](../../../benchmarks/ansible/) | Déploiement, injection, vérification et nettoyage |
| [compose_gt.py](../../../benchmarks/tools/compose_gt.py) | Composition et validation des vérités terrain |

Un scénario combine une topologie, des packs et une posture. Il ne suffit pas
de créer un fichier YAML pour garantir son déploiement : la composition, la
vérité terrain et les paramètres/playbooks Ansible doivent rester cohérents.
Les paramètres S14–S29 sont notamment dans
[scenarios_v2.yml](../../../benchmarks/ansible/group_vars/all/scenarios_v2.yml),
fusionnés avec [main.yml](../../../benchmarks/ansible/group_vars/all/main.yml).

## Ce que l’agent peut connaître

La topologie publique peut être donnée au pipeline ; le mode `--blind` demande
une découverte active. La vérité terrain appartient à l’évaluateur, pas au
contexte d’entrée de l’agent. Pour les benchmarks, la mémoire épisodique des runs
est désactivée en lecture et en écriture ; les méthodes restent accessibles.

Le mineur et les exports d’apprentissage refusent les scénarios de test et leurs
origines connues. Valider la cohérence de leurs fichiers en CI ne signifie pas
utiliser leurs scores pour optimiser l’agent. Voir la
[boucle d’apprentissage](../../LEARNING_LOOP.md).

## Faire évoluer le corpus

Modifier ensemble le catalogue, les définitions, les vérités terrain et les
paramètres de déploiement concernés. Versionner les changements qui affectent
la comparaison des campagnes, et conserver les résultats historiques.

Depuis la racine du dépôt, validation des données sans déployer le laboratoire :

```bash
python benchmarks/tools/compose_gt.py --validate
```

Cette commande compare les compositions : une dérive de schéma historique v1 peut
être signalée `LEGACY-DIFF` sans bloquer ; `--strict-all` la rend bloquante aussi.
Cette vérification de fichiers ne prouve pas que les services réellement déployés
possèdent toutes les propriétés attendues.

Les [scénarios manuels](../../manual_scenarios.md) sont un parcours distinct hors
catalogue officiel : ne pas incorporer leurs résultats silencieusement aux scores dev/test.
