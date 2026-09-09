# Suivi des corrections — 8 septembre 2026

Le [rapport initial](README.md) est un instantané antérieur aux corrections.
Ses résultats de tests et sa colonne « constat actuel » ne décrivent pas le
checkout après les travaux suivants. Les modifications restent locales ; ce
suivi ne vaut pas validation du déploiement sur le mini-PC.

## Providers : lot R16 terminé localement

- Écriture des providers protégée par `LANCE_ADMIN_TOKEN`, lectures inchangées.
- Les réponses d'une ancienne ouverture du gestionnaire ne modifient plus le
  nouveau formulaire ; clé et brouillon ne sont pas restaurés par un callback tardif.
- Erreur d'authentification non configurée distinguée d'une indisponibilité DB.
- Validation du lot précédent : 39 tests ciblés et 23 scénarios navigateur simulés.
- Cela ne constitue pas une authentification globale de toutes les mutations API.

## Cycle de vie : premier lot terminé localement

Implémentation déléguée à Luna, revue et contre-vérifications indépendantes par
l'orchestrateur. Le validateur des preuves et les calculs d'évaluation n'ont
pas été modifiés dans ce lot.

- Finalisation du tracker, sérialisation et écriture des coûts isolées : leurs
  erreurs n'empêchent plus la tentative de nettoyage et ne masquent plus
  l'exception initiale.
- Une seule écriture finale de `cost_summary.json` ; suppression du doublon
  dans `_execute_run`. L'affichage console n'est plus une condition de succès.
- `usage_status` et les erreurs associées rendent l'usage incomplet explicite.
  Un succès autrement complet devient `partial` si son usage n'est pas archivé.
  Un coût connu reste disponible ; un coût non calculable n'est pas remplacé par zéro.
- Arrêts, erreurs de phase et dépassements de budget distingués. Un plafond
  configuré dont le calcul échoue bloque la phase suivante. Sous le plafond,
  le déroulement antérieur des phases est conservé.
- Arrêt dashboard recontrôlé après le nettoyage, y compris lorsqu'un indicateur
  de budget était déjà présent ; une erreur primaire reste prioritaire.
- Test du cache supprimé retiré, résultat d'outil structuré testé directement,
  CIDR déclarés dans les deux fixtures de workers concernées.

Validation effectuée, avec appels LLM et déploiements simulés :

- Suite complète : **1 334 tests réussis, 7 échecs, 4 ignorés** en 208,86 s.
  Ce passage précède le dernier ajustement du signal d'arrêt pendant teardown.
- Après cet ajustement : **140 tests ciblés réussis**, plus **33
  contre-vérifications indépendantes** sur une batterie temporaire hors dépôt.
- Repassage des fichiers contenant les anciens échecs hors cycle de vie sur le
  code final : **259 réussites, les mêmes 7 échecs sémantiques**.
- Compilation Python des fichiers touchés, syntaxe JavaScript et
  `git diff --check` valides.

Les nombres des différentes batteries se recouvrent et ne doivent pas être
additionnés. À l'issue de ce lot, la suite globale n'était pas verte : les sept
cas ci-dessous restaient à traiter. Leur résolution est décrite dans le lot
preuves plus bas. Aucun commit, push ou déploiement.

## Triage des 21 échecs précédemment observés

| Nombre | Cause | Traitement |
| --- | --- | --- |
| 10 | Tests du cycle de vie avec tracker simulé incomplet ; vraie fragilité du `finally`, qui peut masquer une exception et empêcher le nettoyage. | Corriger le cycle de vie, préciser les fixtures et ajouter des tests de panne avec un vrai tracker. |
| 1 | Test qui exige la remise à zéro du cache MQTT supprimé. | Supprimer ce test obsolète ; la fraîcheur des observations est déjà couverte dans `test_tool_loader.py`. |
| 1 | Test qui décode à nouveau le résultat d'outil déjà conservé comme dictionnaire. | Vérifier directement la structure et conserver les assertions sur l'exception originale. |
| 2 | Tests de workers Phase 4 qui omettent le CIDR du contexte. | Déclarer le réseau de test, sans désactiver le garde. Rejoués avec cette seule modification : les deux passent. |
| 6 | Anciennes attentes de preuve, de pivot ou de différence compact/full. | Réconcilier dans le lot preuves avec contrôles positifs et négatifs ; ne pas restaurer les anciennes règles. |
| 1 | Plan de vérification MySQL `default_credentials` incompatible avec le validateur. | Corriger le contrat de preuve dans un lot dédié, pas en changeant simplement l'attente du test. |

### Les sept cas sémantiques identifiés avant le lot preuves

- `test_phase5_scope_guard_is_only_enforced_for_compact[full]` : attend une
  autorisation différente en full. La frontière réseau doit être commune.
- `test_compact_intrusion_synthesis_reconstructs_harvest_and_chains` : attend
  une chaîne à partir de connexions indépendantes et du contexte annoncé.
- `test_synthesize_exploit_result_accepts_evaluable_scan_and_socket_evidence` :
  le sous-cas TCP attend qu'un simple ACK prouve une divulgation d'informations.
- `test_full_phase5_protocol_access_is_measured_but_compact_is_unchanged` :
  confond contact de service et compromission, avec des définitions par profil.
- `test_phase5_metrics_credit_partial_lateral_compromise` : le préfixe supposé
  du pivot n'est étayé que par deux connexions directes.
- `test_http_request_and_raw_socket_results_receive_semantic_verdicts` : attend
  qu'un PONG confirme la fuite revendiquée, alors que la réponse ne la contient pas.
- `test_phase4_compact_probes_repair_http_endpoint_and_mysql_auth_check` : le
  plan propose une requête d'identité MySQL sous root sans mot de passe pour
  `default_credentials`, mais cette propriété n'est jamais acceptée dans la
  branche `mysql_query` du validateur. Une réponse d'identité réussie et un refus
  d'accès ont tous deux été rejetés lors du contrôle hors ligne.

Les six premiers échecs ne justifient pas de réintroduire de faux positifs.
Ils ne prouvent pas non plus que le nouveau contrat est complet : notamment,
`valid_edges` reste vide dans l'évaluateur, sans producteur de preuves causales
de pivot. Il faudra des contrôles positifs de vrais pivots avant de déclarer
le multihop opérationnel.

## Preuves : lot implémenté et revu localement

Implémentation déléguée à Luna, puis plusieurs retours de revue et corrections.
Les exigences n'ont pas été abaissées pour faire passer les anciennes attentes.

- MySQL : port réellement transmis à la commande, TCP imposé, absence de mot
  de passe explicitement demandée et contexte d'exécution archivé par le
  handler. Aucun nouvel état global ni nouveau mécanisme d'environnement.
- `default_credentials` : requête d'identité unique, deux identités root et
  attribution à la bonne cible. Le contrôle d'exécution est partagé avec les
  autres propriétés MySQL ; pas de gardes dupliquées entre les branches.
- Contre-exemples corrigés pendant la revue : requête contenant le texte
  attendu dans un commentaire, annulation/timeout malgré un retour nul,
  provenance absente/incohérente, avertissement CLI pris pour une erreur ou
  une preuve, port facultatif mal interprété, finding sans cible.
- Tests historiques : ACK/PONG ne démontrent pas une fuite ; contacts de
  services et accès à une machine sont distincts ; mêmes définitions de
  preuve et même frontière réseau pour les profils concernés. Des contrôles
  positifs conservent les accès directs et la collecte étayée de credentials.
- Pivots : tentatives, succès et taux sont explicitement indisponibles
  (`null`). Suppression de l'ancien calcul fondé sur les accès directs, pas
  simplement masquage derrière une condition en attente d'activation.
- Contrat versionné **strict-v3.7 / evidence-v5**. Les métadonnées historiques
  restent intactes ; des tests empêchent leur promotion au score courant.
  Le cache API suit également les helpers de `src/agent/evidence/`.

Validation sur le patch stabilisé :

- Luna : **280 tests ciblés réussis**.
- Orchestrateur : **98 contre-vérifications indépendantes réussies**, dont
  14 parcours Phase 4 → évaluateur → entonnoir en compact/full et le rejet de
  confirmations finales forcées. Batterie temporaire hors dépôt ; les
  régressions pérennes sont dans les tests de contrat et d'évaluation.
- Compilation Python des modules touchés, syntaxe JavaScript et
  `git diff --check` valides.
- Suite complète lancée par l'orchestrateur après gel du patch :
  **1 355 tests réussis, aucun échec, 4 ignorés** en 194,04 s.
  Trois tests nécessitent une écoute réseau locale interdite par le sandbox ;
  le module d'entraînement est ignoré faute de dépendance `trl`.

Les batteries se recouvrent. Les essais MySQL utilisent des connexions
simulées ; le client local n'a été appelé qu'avec `--version` pour contrôler
son avertissement. Aucun scan, appel LLM applicatif, commit, push ni déploiement.
Ce lot ne valide pas le fonctionnement sur le mini-PC et n'implémente pas le
producteur de preuves causales nécessaire au vrai multihop.

## Comparabilité : lot R12 terminé localement

Implémentation déléguée à Luna et revue indépendamment. Ce lot ne modifie ni
le calcul d'un score individuel, ni le contrat de preuve strict-v3.7 / evidence-v5.

- Configuration planifiée archivée dans `run_meta.json`, transmise à
  `EvaluationResult` puis aux métriques du batch.
- Identité explicite : provider/modèle, profils demandé et effectif, mode
  aveugle, plafonds, phases et modèles planifiés, paramètres du profil,
  empreintes des prompts/outils, politique de scoring et versions des contrats.
- Les champs absents, invalides ou incompatibles interdisent les moyennes
  concernées ; `null` et un diagnostic remplacent le score agrégé, sans
  supprimer les résultats individuels ni interrompre la synthèse du batch.
- Campagnes et batches distincts ne rendent pas deux configurations identiques
  incompatibles. Les splits restent séparés et les phases réalisées ne sont
  pas confondues avec le plan initial.
- Pas de reconstruction des métadonnées historiques. L'identité vérifie les
  paramètres archivés, pas la reproductibilité complète du système distant
  ou du checkout ; le commit Git reste de la traçabilité.
- La pénalité historique des scénarios attendus entièrement absents reste
  inchangée. Les dénominateurs des essais incomplets relèvent de R13.
- Retours de revue corrigés : rejet d'une identité externe partielle, valeurs
  non finies et clés ambiguës ; priorité des clés entières/texte des modèles
  par phase identique à celle du runtime ; absence de faux diagnostic de
  mélange pour un split ne contenant que des scénarios absents. Le schéma de
  résumé indisponible est dérivé du schéma normal, sans liste dupliquée.

Le premier passage global a donné **1 360 réussites, 8 échecs et 4 ignorés**.
Six échecs venaient du nom de provider non défini dans un `MagicMock` ; deux
tests de moyenne de l'entonnoir omettaient la configuration nécessaire pour
être comparables. Ces fixtures sont précisées sans assouplir les gardes de
production ni changer les assertions d'arithmétique et de séparation des splits.

Validation finale sur le patch stabilisé :

- Suite complète relancée par l'orchestrateur : **1 369 tests réussis,
  aucun échec, 4 ignorés**, en 205,14 s. Les quatre exclusions restent les
  trois tests d'écoute réseau interdite dans le sandbox et l'absence de `trl`.
- **67 contre-vérifications indépendantes réussies** dans une batterie
  temporaire hors dépôt : producteur réel simulé → évaluateur → agrégateur et
  batch, configurations divergentes, champs absents/invalides, contrats
  historiques, phases par défaut, splits et conservation des résultats.
- Tests pérennes dans `test_batch_integration.py`,
  `test_benchmark_aggregate.py` et `test_evaluation_funnel.py`, dont le parcours
  de propagation et le refus d'agréger sans configuration suffisante.
- Compilation Python, syntaxe JavaScript et `git diff --check` valides.

Les batteries se recouvrent. Aucun commit, push ni déploiement. Ce lot ne
valide pas l'exécution sur le mini-PC et ne clôt pas R13 ni les lots dashboard,
SSE et multihop.

## Essais incomplets : lot R13 terminé localement

Implémentation déléguée à Luna, relue et confrontée à une batterie indépendante
par l'orchestrateur. Le calcul du score individuel et le contrat de preuve
**strict-v3.7 / evidence-v5** restent inchangés.

- Un résultat manquant ne disparaît plus des moyennes concernées. Un scénario
  attendu mais absent n'apporte plus non plus la pénalité zéro historique :
  un essai à 100 % et un essai sans résultat donnent une moyenne officielle
  `null`, pas 100 % ni 50 %. Une vraie mesure à zéro reste comptée.
- `attempts` sépare essais attendus, reçus, évaluables, manquants et reçus sans
  score. Les répétitions en erreur sans objet d'évaluation sont conservées
  dans ces dénominateurs, y compris après matérialisation d'un générateur.
- `metric_coverage` expose les valeurs évaluées, mathématiquement indéfinies,
  indisponibles et non applicables. L'unité est l'essai dans `per_scenario`,
  le scénario dans les résumés. Une vérification absente ne supprime pas les
  mesures de détection disponibles.
- Les répétitions sont moyennées dans leur scénario, puis chaque scénario
  reçoit un poids égal. Les contrôles zero-GT conservent leur spécificité ;
  une spécificité indisponible ne produit pas un faux essai évaluable. Les
  gardes de comparabilité R12 et la séparation des splits restent actifs.
- Les populations GT nécessaires traversent la sérialisation sous forme
  compacte, sans dupliquer toute la liste des correspondances. Une donnée
  absente ou mal formée n'établit pas un dénominateur nul. Les corrections de
  revue couvrent notamment les propriétés GT invalides, les profondeurs
  Unicode, les clés de sévérité et la cohérence des diagnostics min/max.
- Les plans de dénominateurs invalides ou contradictoires sont rejetés ; zéro
  essai explicitement prévu ne crée pas un essai manquant fictif. Sans plan
  connu, l'agrégateur ne prétend pas compter des répétitions invisibles.

Validation finale par l'orchestrateur :

- Suite complète relancée sur le code de production final : **1 382 tests
  réussis, aucun échec, 4 ignorés**, en 136,78 s. Les exclusions restent les
  trois tests d'écoute locale interdite par le sandbox et l'absence de `trl`.
- **72 contre-vérifications indépendantes réussies**, dans une batterie
  temporaire hors dépôt. Elle vérifie aussi les parcours API arrêtée avant
  le premier essai et CLI conservant sa synthèse après une erreur de pipeline
  ou d'évaluation, avec dépendances simulées et sans appel LLM applicatif.
- **105 tests ciblés réussis** dans les fichiers agrégateur, batch et entonnoir
  après l'ajout des six derniers cas pérennes. Ces six cas ont été ajoutés
  après la collecte de la suite globale ci-dessus, sans changement de
  production, puis relus et rejoués dans cette batterie ciblée.
- Compilation Python, syntaxe JavaScript et `git diff --check` valides.

Les batteries se recouvrent ; leurs nombres ne sont pas additionnables. Les
régressions pérennes sont dans les tests d'agrégation et d'intégration batch,
avec contrôles de vraies mesures à zéro et de populations valides, pas
seulement des contre-exemples invalides.

Les artefacts et résumés de batch historiques ne sont pas réécrits. Aucun
commit, push, scan ni déploiement ; ce lot ne valide pas le mini-PC. Les coûts
des lignes sans évaluation, les totaux partiels de consommation et leur
affichage restent à traiter séparément, sans supprimer les données existantes.

## Suite prévue

Après R13 : cohérence du statut affiché depuis les métadonnées et visibilité
des consommations partielles dans le dashboard (R14/R17), puis diffusion SSE
(R8). Les preuves causales de vrais pivots multihop restent un chantier
distinct. Ne pas déclarer la refonte globale terminée sur la seule réussite
des tests du lot courant.
