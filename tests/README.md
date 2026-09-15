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
