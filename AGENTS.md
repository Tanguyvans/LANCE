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
- `research/` : recherches par sujet, sources, hypothèses, protocoles proposés et analyses.
- `docs/` : documentation de référence, organisée par architecture, guides, benchmark et entraînement.

## Recherche et documentation

- Avant de créer un document, consulter les index de `research/` et `docs/` et
  compléter le sujet existant lorsqu'il couvre déjà la question.
- Placer le travail exploratoire dans `research/<sujet>/`, avec un nom stable en
  minuscules et tirets. Chaque dossier possède un `README.md` indiquant la question,
  le statut, les dates, la synthèse, les documents et les points encore ouverts.
  Suivre les [conventions de recherche](research/README.md).
- Pour toute nouvelle étude ou révision de fond, fournir une source LaTeX éditable
  et son PDF compilé, avec des figures modifiables et un rendu vérifié. Adopter une
  structure scientifique classique : titre, résumé, table des matières, méthode,
  constats, limites, conclusion et références. Suivre les
  [règles de structure et de format](research/README.md#structure-scientifique-classique).
- Distinguer les hypothèses, les faits sourcés, les résultats observés et les
  conclusions. Citer les sources primaires avec leur date/version et préciser les
  limites de lecture ou de reproduction. Pour une expérience, référencer le code,
  la configuration, les artefacts et les conditions nécessaires à sa reproduction.
- Réserver `docs/` aux comportements implémentés, aux contrats retenus et aux
  procédures de référence, en précisant leur périmètre et leurs limites. Un plan
  proposé ou une piste bibliographique reste dans `research/`.
- Quand une conclusion est retenue et vérifiée au niveau nécessaire, mettre à jour
  la page de référence concernée et la relier à la recherche d'origine. Conserver
  les sources et le raisonnement dans `research/`, sans recopier toute l'étude.
  Une validation logicielle ne prouve pas un résultat expérimental.
- Mettre à jour les index et les liens lors de tout ajout ou déplacement. Garder
  une seule page de référence par sujet ; marquer les documents remplacés comme
  archivés et les relier à leur successeur. `docs/audit/` conserve les archives
  historiques existantes, qui ne décrivent pas nécessairement le système courant.

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

## Cible d'exécution et de déploiement

- Le benchmark et les déploiements LANCE ciblent **nato / pve-nato**, via le
  runner GitHub Actions **nato-master**. Un push autorisé sur `main` utilise ce
  circuit de validation et de déploiement.
- Le **homelab personnel** (nœud `pve`, distinct de `pve-nato`) est hors périmètre :
  aucun transfert de fichiers, synchronisation, déploiement, changement de
  configuration ou audit pour ce projet. Une intervention sur le homelab exige
  une demande distincte de l'utilisateur le désignant explicitement.
- Un inventaire local ou une connexion SSH fonctionnelle n'autorise pas à changer
  de cible. Ne jamais se rabattre sur le homelab si nato est inaccessible ;
  vérifier l'identité de la machine et clarifier toute ambiguïté avant intervention.

Pour commencer : [README](README.md), [recherches](research/README.md), [documentation](docs/README.md),
[structure du pipeline](src/agent/phases/README.md) et [tests](tests/README.md).
