# Plan d'implémentation — comparaison règles / agent

**Statut : premier incrément CLI D1/A1 implémenté et validé localement le 27 septembre 2026.**
Le [protocole scientifique](agent-vs-automation.md) définit les hypothèses,
mesures et limites. Ce document fixe l'ordre des changements logiciels et
leurs critères de validation. Le [guide CLI](agent-vs-automation-cli.md) décrit les options disponibles et leurs limites.

## Périmètre du premier incrément

Comparer D1, une politique conditionnelle sans LLM, et A1, la politique utilisant
le modèle, sur l'analyse et la vérification. Les deux reçoivent le même inventaire
public initial et utilisent les mêmes outils, budgets et exigences de preuve.
Le premier incrément ne revendique pas un audit autonome complet sans LLM.

Conserver `Pipeline`, le registre des phases et le cycle de vie communs. Les
phases possèdent leurs stratégies et partagent l'exécuteur, les formats,
l'agrégation et les validateurs. Le fournisseur LLM devient nécessaire seulement
pour une politique qui l'utilise.

```text
Inventaire public validé + configuration expérimentale
                         |
                 Pipeline commun
                         |
        Politique rules ou politique llm
                         |
      Exécuteur commun : outils, budgets, arrêt
                         |
      Observations et journal de provenance
                         |
      Validation des preuves et artefacts communs
                         |
       Évaluation individuelle puis comparaison
```

La politique est distincte des profils `full` et `compact`. Pour le premier
incrément, fixer un profil explicite commun, les budgets, les outils et la
concurrence ; aucun choix automatique dépendant du modèle ne doit modifier
silencieusement ces paramètres. Les paramètres `decision_policy` et `experiment_scope` sont disponibles dans
`Pipeline` et le CLI. Ce premier incrément impose `full` et un seul worker.

## Lot 1 — Unifier l'exécution et la mesure des outils

- [x] Permettre à [run_scanner](../../src/agent/scanner.py) de recevoir les outils
  préparés par l'[exécuteur commun](../../src/agent/core/executor.py), plutôt que
  de reconstruire uniquement une table de fonctions directes.
- [x] Faire également passer les sondes déterministes complémentaires de la
  [phase d'analyse](../../src/agent/phases/analysis/run.py) par cette frontière.
- [x] Enregistrer la phase, la source de décision (règle, modèle ou secours),
  la référence de preuve, la durée et le résultat. Le premier périmètre
  distingue `rules` et `llm` ; le marquage spécifique des secours hors de ce
  périmètre reste à compléter. Attribuer la provenance dans
  le contrôleur, sans accepter celle fournie par le modèle.
- [x] Compter une exécution une seule fois et relier les observations des
  fichiers de scans au journal commun.
- [x] Propager arrêts, dépassements de budget et défauts d'archivage à travers
  les boucles et workers. Ne pas les convertir en simples résultats négatifs.

**Validation :** mêmes limites pour les deux sources d'actions, aucune sonde
supplémentaire après épuisement du budget, traces attribuables et absence de
double comptage. Les erreurs ordinaires restent enregistrées sans signifier
une absence de vulnérabilité. Versionner les changements de couverture des
journaux et compteurs pour préserver l'interprétation des anciens runs.

## Lot 2 — Introduire la politique et le périmètre expérimental

- [x] Ajouter `decision_policy` à [Pipeline](../../src/agent/pipeline.py),
  avec `llm` comme défaut historique.
- [x] Résoudre la politique avant l'initialisation du fournisseur. En `rules`,
  ne créer aucun fournisseur ni lancer de résolution réseau de prix/modèle.
- [x] Séparer durées/actions et consommation du modèle dans
  [cost_tracker.py](../../src/agent/cost_tracker.py). Zéro appel modèle signifie
  zéro consommation LLM mesurée, pas un coût total de calcul nul.
- [x] Définir le périmètre analyse/vérification et son inventaire public
  versionné : provenance, empreinte, cibles, ports et services autorisés.
  Ne pas y exposer la vérité terrain ou les indices privés du scénario.
- [x] Traiter explicitement les prérequis. Actuellement,
  `_expand_phase_selection` ajoute les phases amont lorsqu'on demande la phase 4 :
  `--phases 3 4` ne suffit donc pas à isoler l'expérience.
- [x] Prévoir une dépendance d'entrée publique validée, commune aux deux modes.
  Ne pas fabriquer de livrable de reconnaissance ni déclarer terminée une phase
  non exécutée. Conserver les contrôles habituels pour les autres lancements.

**Validation :** le périmètre expérimental `rules` démarre sans clé API et ne
peut atteindre aucun appel modèle. Les combinaisons non prises en charge sont
refusées avant toute action. Tester la non-régression des lancements LLM existants.

## Lot 3 — Implémenter les décisions à règles

- [x] Extraire les scans et traitements conditionnels déterministes de la
  phase 3 pour les partager, y compris ceux situés hors du module scanner.
- [x] En `rules`, utiliser les extractions et règles explicites pour produire
  les candidats. En `llm`, conserver l'interprétation et les décisions du modèle.
  Réutiliser l'[agrégation](../../src/agent/phases/analysis/aggregation.py) et
  enregistrer la provenance des candidats, filtres et regroupements.
- [x] En phase 4, utiliser le
  [plan de vérification](../../src/agent/phases/verification/contract.py) comme
  point de départ : paramètres issus des observations autorisées, conditions
  d'arrêt. La première version exécute une sonde par candidat, sans reprise D1.
- [ ] Les chemins, identités ou paramètres propres aux fixtures sont soit
  documentés dans l'entrée publique commune, soit découverts par les outils.
  Aucun identifiant de scénario ne doit sélectionner une solution. Le runtime
  expérimental ne charge aucun scénario ; les connaissances publiques déjà
  codées dans les règles restent à inventorier avant le pilote de généralisation.
- [x] Déclarer les cas non pris en charge et les tests indéterminés. Une erreur
  ou une absence d'observation ne devient pas une confirmation.
- [x] Réutiliser la synthèse à partir des traces et l'agrégation des vérifications
  dans [verification/run.py](../../src/agent/phases/verification/run.py), avec les
  mêmes contrats de preuve pour les deux politiques.

**Validation :** fixtures positives, contrôles sains, mauvaise cible, mauvais
endpoint, preuve manquante et erreurs d'outils. Produire candidats bruts,
retenus et vérifications dans les formats communs. Revoir la couverture de D1
avant d'interpréter un gain de A1.

## Lot 4 — Adapter les métadonnées et la comparaison

- [x] Versionner l'identité dans
  [comparability.py](../../src/benchmark/comparability.py) : politique/version
  des règles, modèle lorsqu'il existe, périmètre et limites. Autoriser l'absence
  de modèle pour `rules`, sans faux fournisseur.
- [x] Définir une clé d'appariement : instance, état initial, répétition/bloc,
  inventaire, outils, budgets et contrats de métriques/preuves. Les différences
  attendues entre politiques sont déclarées dans le protocole.
- [x] Conserver [l'agrégation](../../src/benchmark/aggregate.py) au sein de chaque
  configuration. Ajouter une couche distincte pour les écarts appariés D1/A1.
- [x] Utiliser le même [évaluateur](../../src/benchmark/evaluator.py), sans
  assouplissement de preuve propre à une politique. Garder les artefacts
  historiques avec leur contrat et leurs limites.
- [x] Compléter les manifestes pour couvrir code, prompts, règles, compétences,
  outils et modifications locales réellement utilisés.
- [ ] Exporter scores, écarts, coûts, statuts, essais manquants et motifs
  d'incomparabilité. Les intervalles d'incertitude suivent le protocole et le
  nombre de familles effectivement disponible. **Livré :** export d'une paire,
  écarts, motifs, valeurs manquantes et contrôles sans faille. **Restant :**
  campagnes de plusieurs paires et intervalles par famille ; aucune incertitude
  statistique n'est annoncée pour une seule paire.

**Validation :** refus des paires incompatibles, absence de fusion entre systèmes,
traitement explicite des contrôles sans faille, ratios indéfinis avec zéro VP
et runs incomplets. Un artefact identique évalué sous le même contrat ne gagne
pas de crédit du fait de l'étiquette `rules` ou `llm`.

## Lot 5 — Livrer une première version utilisable

- [x] Exposer les paramètres validés par le CLI et adapter l'obligation de
  fournisseur. Une voie partielle ne doit pas être présentée comme complète.
- [x] Tester localement le périmètre expérimental de bout en bout avec outils
  simulés, puis l'évaluation et la comparaison de ses artefacts.
- [x] Tester séparément le parcours LLM existant. Les doublures de fournisseur
  servent aux tests, pas à mesurer une vraie politique LLM.
- [x] Mettre à jour les guides pour les options effectivement disponibles.
  L'API et l'interface viendront après stabilisation ; une entrée non prise en
  charge doit être refusée explicitement.
- [x] Exécuter les tests ciblés, puis
  `python -m pytest -q tests model_training/tests` et `git diff --check`.
  Consigner les tests ignorés et les limites restantes.

**Critère de livraison :** deux politiques exécutables sur le même périmètre,
des traces contrôlées, des résultats évaluables et une comparaison qui refuse
les conditions incompatibles. Le mode `rules` n'a aucune dépendance d'exécution
à un fournisseur LLM. Les tests locaux ne démontrent pas un gain scientifique.

## Suite et suivi

Le pilote de laboratoire du protocole intervient après validation logicielle
et sur demande explicite, conformément au guide du dépôt. Vérifier préparation,
politiques, évaluation et nettoyage avant d'élargir les scénarios.

Les extensions sont : découverte autonome comparable, procédure fixe D0 pour
compléter le pilote si nécessaire, plan figé A0, rédaction D1-R, variantes
réellement déployables et évaluation indépendante après gel. L'intrusion
multi-hop reste conditionnée à des preuves causales des transitions réseau.

À chaque lot terminé, mettre à jour les cases et consigner les vérifications
effectuées. La création de ce plan n'exécute aucun benchmark ni déploiement.

## Validation du premier incrément

Les tests locaux couvrent le parcours complet à règles, un fournisseur LLM
simulé, les références de preuve, les contrôles sains, les erreurs techniques,
les mauvaises cibles/endpoints, les budgets, les arrêts et les paires incompatibles.
Le fournisseur simulé vérifie le logiciel ; il ne mesure aucune capacité IA.
Aucun run de laboratoire, déploiement, commit ni push ne fait partie de cette livraison.

Validation sous Python 3.12 dans un environnement temporaire :

- `python -m pytest -q tests/test_audit_policy.py` : **21 réussis**, y compris
  une confirmation positive évaluée, la neutralité de l'étiquette de politique
  et le refus d'une paire sans journal de preuve.
- Tests ciblés pipeline, coûts, agrégation et nouvelles politiques : **476 réussis**.
- `python -m pytest -q -rs tests model_training/tests` : **2 933 réussis,
  4 ignorés**, deux avertissements de dépréciation pytest dans des fixtures
  existantes. Trois tests nécessitent des sockets locaux interdits par le
  sandbox ; le test d'entraînement QLoRA exige la dépendance optionnelle
  `datasets`, absente de cet environnement.
- Aide des deux CLI et `git diff --check` vérifiés.

Restent hors de cet incrément : validation sur outils/laboratoire réels,
inventaire exhaustif des connaissances propres aux simulateurs, campagnes
appariées et intervalles par famille, interface/API et autres baselines du
protocole. Les commandes de laboratoire exigent une demande explicite.
