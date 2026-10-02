# Tests automatisés de l’application

Ce dossier vérifie le pipeline, les outils, les preuves, les métriques du benchmark,
l’API et leurs intégrations. Les tests du code d’entraînement et de synchronisation
GPU sont regroupés dans [model_training/tests/](../model_training/tests/).

Ne pas confondre ces tests logiciels avec les
[scénarios d’évaluation du benchmark](../docs/benchmark/v1/scenarios.md).

Depuis la racine du dépôt :

```bash
# Toute la suite : application ET entraînement
python -m pytest -q

# Application uniquement
python -m pytest -q tests

# Entraînement uniquement
python -m pytest -q model_training/tests
```

La CI exécute explicitement les deux dossiers. Les commandes qui précisent
seulement `tests/` ne lancent pas les tests d’entraînement. Certaines dépendances
optionnelles peuvent provoquer des tests ignorés : lire le résumé avant de
conclure à une validation complète.

Pour limiter les répétitions, regrouper avec `pytest.mark.parametrize` les cas
qui partagent la même préparation et les mêmes assertions, en donnant un nom
explicite à chaque cas. Garder des tests séparés pour les comportements distincts,
et vérifier les résultats observables plutôt que reproduire l'implémentation.
Une fonction paramétrée exécute plusieurs cas indépendants : réduire le nombre
de fonctions ne signifie donc pas réduire le nombre de cas vérifiés.

`test_audit_policy.py` couvre la comparaison D1/A1 sur inventaire public avec
les vrais composants de pipeline et des outils/fournisseurs simulés : preuves,
budgets, contrôles sains, erreurs et refus des paires incompatibles. Ces tests
vérifient aussi les reprises D1 et le bilan de campagne : essais manquants,
coûts des échecs, précontrôles et identités incompatibles, exports JSON/CSV. Ils
ne mesurent pas les performances d'un modèle sur un laboratoire réel ; voir le
[guide de comparaison](../docs/benchmark/agent-vs-automation-cli.md).

`test_lab_lock.py` vérifie la réservation du laboratoire entre processus et son
annulation sans opération réseau. `test_deployment_workflow.py` vérifie les
déploiements par branche dans des dépôts temporaires ; voir le
[guide des instances](../docs/guides/development-instances.md).

`test_shared_activity.py` couvre les résumés locaux, l’agrégation en lecture
seule des trois instances, les erreurs de pairs, l’absence de transmission
d’identifiants et le mode standalone sans accès réseau.

`test_knowledge_policy_isolation.py` vérifie que la source CVE reste liée au run
quel que soit l'ordre de création des pipelines, que les filtres de connaissances
restent distincts dans les threads et que le snapshot fonctionne sans importer
la base de connaissances en ligne. `test_agent_tools.py` vérifie aussi qu'un
scénario invalide ne se rabat jamais sur le laboratoire physique.

`pipeline/test_analysis_context.py` vérifie les frontières de phase 3 : fournisseur
effectif, dry-run sans découverte active, agrégation seule, comptage avec des
workers terminant dans un ordre différent, interruptions propagées, suivi fermé,
consommation limitée à la phase et deux contextes ayant les mêmes identifiants
d'appareil. `pipeline/test_analysis_supplemental.py`, issu de la relecture
indépendante, caractérise l'ordre des sondes mTLS/OTA/cloud et leur provenance,
avec des outils simulés. Les tests de sauvegarde, récupération et agrégation
conservent les contrôles de preuves ; le test UMONS mesure les appels simultanés
sans réduire les preuves ni le délai. Aucun de ces tests ne mesure un modèle
sur le laboratoire réel.
