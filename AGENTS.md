# Guide du dépôt

## Vue d'ensemble

LANCE est un outil d'audit de sécurité de réseaux IoT autorisés, piloté par des
modèles de langage. Son pipeline explore le réseau, analyse les failles potentielles,
vérifie les preuves, évalue les accès obtenus et produit un rapport.
Une API et une interface web permettent de lancer et de suivre les exécutions.
Le benchmark fournit des scénarios reproductibles pour comparer les résultats ;
l'entraînement des modèles constitue un volet distinct du projet.

## Organisation

- `src/agent/` : pipeline et outils d'audit.
- `src/api/` et `src/static/` : API et interface web.
- `src/benchmark/` : évaluation des résultats.
- `benchmarks/` : scénarios et infrastructure du laboratoire.
- `model_training/` : entraînement des modèles.
- `tests/` : tests de l'application ; l'entraînement possède ses propres tests.
- `docs/` : architecture, guides d'utilisation et documentation du benchmark.

## Contribuer

Comprendre le module concerné et sa documentation avant de le modifier. Préserver
les changements locaux, respecter les responsabilités existantes et privilégier
des corrections générales, ciblées et testables. Mettre à jour les tests et les
guides concernés, sans dupliquer leur contenu ici.

Valider les changements avec les tests pertinents ; la suite complète se lance avec
`python -m pytest -q tests model_training/tests`. Vérifier aussi `git diff --check`
et, pour l'interface, le rendu dans un navigateur. Indiquer ce qui a été vérifié
et les limites restantes. Les runs de laboratoire, déploiements, commits et pushes
nécessitent une demande explicite.

Pour commencer : [README](README.md), [documentation](docs/README.md),
[structure du pipeline](src/agent/phases/README.md) et [tests](tests/README.md).
