# Diagnostic des appels au modèle — étape 1

Cette correction rend les arrêts observables. Elle ne modifie ni les décisions
de finalisation, ni les reprises, ni les budgets, ni les contrats de preuve et
d'évaluation. Le modèle et le profil full sont conservés.

## Journal séparé

`provider_events.jsonl` est un journal technique par run. Les événements sont
rattachés à leur phase, leur agent et leur invocation du modèle, afin de ne pas
confondre les travailleurs parallèles ou deux appels successifs du même agent.
Le schéma porte la version `model.obs1` et chaque ligne est horodatée en UTC.

Cette étape instrumente la boucle des fournisseurs compatibles avec l'API
Chat Completions, notamment le fournisseur UMONS du run concerné. Elle ne
prétend pas observer les échanges internes de l'ancien adaptateur Codex.

Le journal décrit les réponses, les tentatives, les décisions du contrôleur et
leur issue. Il ne recopie pas les prompts, le raisonnement, les arguments des
outils, les résultats réseau ou le corps brut des erreurs fournisseur. Une
réponse tronquée n'est identifiée comme telle que si le fournisseur le signale.

Ce fichier est disponible à l'opérateur via la consultation des fichiers du
run et peut être inclus dans les archives de diagnostic. Les outils de
livrables du modèle ne peuvent ni le lister, ni le lire, ni l'écraser. Cela ne
constitue pas une isolation contre tout accès au système de fichiers : les
restrictions de l'exécuteur restent une responsabilité distincte.

Le journal n'est pas une preuve de faille, d'accès ou de pivot, et ne participe
pas au calcul des scores. Les anciens runs ne sont pas réécrits. L'absence de
ces événements dans une archive ancienne signifie « diagnostic indisponible ».

Pour lire un arrêt, regrouper les événements par `invocation_id`, puis suivre
les numéros de requête. Un tour de boucle peut contenir plusieurs tentatives
fournisseur. Une réponse reçue n'implique pas un outil exécuté ; une sauvegarde
acceptée n'implique pas une faille prouvée. Les transitions de finalisation et
l'événement terminal décrivent la décision du contrôleur, sans la justifier
par le seul score F1.

Les événements couvrent le début d'invocation, les tentatives fournisseur,
les réponses, les outils proposés/exécutés/refusés, l'entrée en finalisation,
les sauvegardes acceptées/rejetées et l'issue terminale. Les erreurs fournisseur
conservent leur catégorie et leur code HTTP lorsqu'il est disponible, pas leur
corps. Les erreurs internes après réception restent classées `internal` : le
journal ne prétend pas distinguer tous les sous-systèmes internes.

## Limites intentionnelles

Les défauts de validation d'un JSON vide, de finalisation prématurée et de
récupération du contexte sont des corrections ultérieures. Ce changement ne
doit pas transformer un run en réussite ni tenter de nouvelles actions.

Une panne d'écriture du journal doit rester un problème de diagnostic : elle
ne doit ni déclencher une reprise fournisseur ni masquer l'exception initiale.
Un avertissement doit la signaler sans afficher le contenu sensible de l'erreur.

## Vérifications attendues

- Réponses textuelles sans outil, réponses vides et erreurs de génération
  distinguables, même lorsqu'elles aboutissent au même statut terminal.
- Sauvegardes acceptées et rejetées identifiables.
- Arrêts, budgets et délais inchangés avec ou sans observation.
- Mêmes requêtes, appels d'outils, résultats et consommations observées.
- Absence de secrets injectés dans les événements, association des événements
  aux bons agents et protection contre les liens symboliques.

Aucun nouveau scan ou appel réel au fournisseur n'est nécessaire pour ces
tests : les réponses et les outils sont simulés localement.

La reproduction « 9 réponses avec actions, puis 4 réponses sans action » est
testée pour les variantes texte, absence de choix et erreur de génération.
Avec et sans journal, les 13 requêtes, 9 actions, événements existants,
résultats, tokens et coûts calculés doivent rester identiques. Les libellés du
journal doivent en revanche permettre de distinguer les trois variantes.

## Validation locale du 14 septembre 2026

- 115 tests ciblés réussis (diagnostic, fournisseur, délais, reprise et
  intégration de la finalisation full).
- Suite complète : 2 286 réussis, 4 ignorés, 3 avertissements de dépréciation.
- Comparaison indépendante avec `e5c1627` sur les trois reproductions à
  13 requêtes : mêmes requêtes, actions, sorties et événements existants.
- Aucun essai sur le mini-PC, commit, push ou déploiement dans cette étape.
