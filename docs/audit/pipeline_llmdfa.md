# Pipeline LANCE : cohérence et premier nettoyage

Audit statique du 5 septembre 2026. Référence fournie : Wang et al.,
« LLMDFA: Analyzing Dataflow in Code with Large Language Models »,
arXiv:2402.10754v2, sections 3.1–3.3 et figure 4, pages 4–6.

## Ce que signifie « basé sur LLMDFA »

LLMDFA traite des programmes et de leur graphe de contrôle : extraction de
sources/puits par scripts utilisant un parseur, résumés de flux par fonction,
puis validation des conditions de chemin par scripts invoquant un solveur.
LANCE est une adaptation méthodologique au réseau, pas une implémentation de
cette analyse statique. Un chemin réseau observé ne constitue pas une preuve
de satisfaisabilité de contraintes de programme.

| Principe LLMDFA | Correspondance dans LANCE | Limite |
| --- | --- | --- |
| Extraction déterministe | Topologie, reconnaissance, projections de preuves des phases 1–2 | Les observations réseau ne sont pas des sources/puits AST. |
| Résumés locaux puis composition | Analyse par équipement et agrégation déterministe de phase 3 | La composition des chemins réseau doit conserver la provenance des faits. |
| Validation externe | Résultats d'outils et contrats de preuve des phases 4–5 | Une validation JSON ne prouve pas une vulnérabilité ni un chemin. |
| Boucle de réparation | Soumissions archivées et validées dans `_apply_deliverable_transaction` | Distinguer réparation du format et validation sémantique. |
| Rapport après validation | Filtrage des confirmations par statut et niveau de preuve en phase 6 | Le niveau déclaré dépend de la qualité du traitement des preuves en amont. |

La séparation en six phases est cohérente avec cette adaptation ; il n'y a
pas lieu de la réduire artificiellement aux trois phases de l'article.

## Nettoyage réalisé

- Extraction des trois fonctions pures de politique de preuve du rapport dans
  `src/agent/report_evidence.py`. L'orchestrateur conserve les anciens noms
  importés pour ses appelants. Les critères et résultats restent identiques.
- Retrait de l'import inutilisé `get_risk_scores`, de l'alias inutilisé
  `_st_pre` et de l'import global redondant `load_discovery_context` (l'import
  local actif est conservé).
- Suppression du mock `get_risk_scores` et de ses données de test devenus
  inutiles : le pipeline n'appelait plus cette fonction importée.

## Constats de l'audit initial

1. **Orchestrateur trop volumineux.** `src/agent/pipeline.py` atteint près de
   12 000 lignes. Il contient déploiement, sélection de modèles, projections,
   normalisation métier, validation, rapport et historique. La première
   extraction est volontairement limitée aux fonctions pures ; les blocs
   suivants doivent être déplacés avec leurs dépendances et tests.
2. **Statut final imprécis.** `Pipeline.run` persiste `status="completed"`
   après la boucle, y compris après un arrêt utilisateur ou une limite de
   budget. Les résultats par phase peuvent donc contredire l'historique SQL.
   Définir des statuts terminaux communs à l'API, au disque et à SQL.
3. **Prérequis trop permissifs.** `_check_prerequisites` accepte tous les
   `skipped:*` comme satisfaits. Une phase ignorée pour manque de prérequis
   n'est pourtant pas équivalente à un artefact disponible. La phase 6 a un
   garde-fou explicite supplémentaire. Définir le contrat attendu pour chaque
   phase avant de changer cette règle et les cas de reprise.
4. **Nettoyage de déploiement non garanti.** Le teardown est placé après la
   boucle et non dans un `finally` général. Une exception non interceptée
   avant cette fin peut le contourner. La protection spécifique à la phase 6
   ne couvre pas toutes les phases. Tester les erreurs, interruptions et
   déploiements partiels avant toute modification du cycle de vie.
5. **Politique dépendante du profil.** Plusieurs validations et synthèses sont
   spécifiques au profil compact/local-MoE ; `_check_conditional` varie aussi
   selon le profil en phase 5. Cela doit être explicitement pris en compte
   dans les comparaisons de modèles. Unifier les exigences de preuve est une
   décision méthodologique, pas une suppression de code mort.

## Périmètre de validation

Lecture du papier et inspection statique du registre, de l'orchestration,
des transactions de livrables et des règles de rapport. Les tests existants
du pipeline servent à contrôler l'extraction. Aucun scan, déploiement de
scénario ou test offensif n'est requis par ce nettoyage. Ce document ne
constitue pas une certification exhaustive de chaque outil ou prompt.

Validation du premier nettoyage : 227 tests réussis dans `test_pipeline.py`,
`test_pipeline_evaluation.py` et `test_registry.py` ; `git diff --check` valide.

## Restructuration — premier lot implémenté

- `results.py` calcule le statut terminal à partir des statuts existants,
  sans introduire une deuxième représentation des résultats.
- `artifacts.py` centralise la disponibilité des livrables : fichier non vide,
  contenu JSON lisible et chemin limité au répertoire du run. Cela ne remplace
  ni la validation du schéma ni la politique de preuve.
- Les prérequis exigent désormais un livrable disponible, même avec un statut
  `completed` ou `skipped`. Les résultats partiels des workers de phase 4
  restent utilisables ; un échec explicite ne peut pas être contourné par un
  ancien fichier. Un prérequis inconnu est refusé.
- `run` encadre `_execute_run` avec un `finally`. Le nettoyage est tenté après
  erreur, arrêt et dépassement de budget lorsque ce run a lancé un déploiement
  et que l'option `auto_teardown` est activée. Les échecs de nettoyage sont
  visibles et ne masquent pas l'exception d'exécution initiale.
- `_persist_run` enregistre l'état terminal SQL après le nettoyage, y compris
  après exception. `run_meta.json` reçoit le statut, le statut de nettoyage et
  le dictionnaire de résultats existant. L'événement `pipeline_done` est émis
  une seule fois après le nettoyage, sans interception ni mise en attente.

Les six phases, les critères de preuve et les différences entre profils ne
changent pas. Aucun déploiement réel n'est requis pour tester ce lot.

### Pistes restantes (à justifier avant implémentation)

1. Injecter `RunContext`/`WorkerContext`, notamment pour les chemins, le graphe,
   la politique CVE et les filtres de skills. Le pipeline n'est donc pas encore
   garanti sûr pour plusieurs runs simultanés dans un même processus.
2. Séparer stockage transactionnel, validation de format et politique de preuve.
3. Extraire les phases vers leurs services, en conservant la façade `Pipeline`.
4. Identifier les boucles réellement dupliquées avant d'introduire un éventuel
   `AgentRunner`. Un module supplémentaire n'est pas un objectif en soi.

La politique existante de pré-déploiement qui arrête les autres scénarios du
laboratoire partagé est inchangée ; le drapeau de propriété du cycle de vie
n'est pas un mécanisme de réservation concurrente des ressources Proxmox.

Validation : suite globale exécutée pendant ce lot, 1 011 tests réussis et
4 ignorés ; suite ciblée réexécutée après les ajouts de contrôles d'artefacts,
251 tests réussis. Les plugins pytest tiers de l'environnement sont désactivés
avec `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1`. Pas de commit, push ou déploiement
effectué pour ce lot.

### Seconde lecture : suppression des abstractions prématurées

- Supprimé `PhaseResult`, son enum et la copie structurée des résultats : aucun
  consommateur applicatif ne les utilisait. Les statuts existants suffisent.
- Remplacé `ArtifactStore`, objet à une seule méthode, par une fonction pure.
- Supprimé `run_history.py` : recevoir tout le pipeline ne constituait pas une
  séparation de responsabilités. Une méthode privée exprime cette dépendance.
- Supprimé l'interception de `pipeline_done` et ses émissions dupliquées.

Les protections sur les prérequis, les arrêts, les exceptions et le nettoyage
sont conservées. Le total applicatif concerné passe de 12 058 à 11 990 lignes
(−68), hors tests et documentation. Le pipeline seul augmente de 5 lignes,
car la persistance redevient une méthode plutôt qu'un faux service indépendant.

Validation après simplification : 281 tests ciblés réussis (pipeline, cycle de
vie, artefacts, évaluation, registre et routes de résultats), `git diff --check`
valide. La suite globale n'a pas été relancée pour cette seconde lecture.

### Nettoyage des éléments morts et première séparation métier

- Supprimé `_strip_code_fences`, appelé uniquement par ses six tests ; les
  tests de cette fonction morte sont retirés avec elle.
- Supprimé les paramètres sans effet `extra_msg` et `include_context`, et le
  compteur `completion_attempts`, incrémenté sans jamais être utilisé.
- Renommé le rendu déterministe du graphe en `_render_compact_graph_markdown`
  et retiré son argument de contenu ignoré : il ne corrige pas un texte du
  modèle, il génère un rapport à partir des observations.
- La réconciliation de phase 5 partage désormais l'émission de son résultat
  final et l'écriture des diagnostics. La branche sans action observable reste
  bloquée ; absence de complétion et couverture incomplète restent deux échecs
  distincts. Le helper `_record_blocked_intrusion_synthesis`, utilisé une seule
  fois et dupliquant cette écriture, est supprimé.
- `finding_policy.py` regroupe les deux fonctions de normalisation/rejet
  sémantique et leurs quatre constantes. Il ne dépend ni du pipeline, ni du
  fournisseur, ni du système de fichiers. Les anciens noms importables depuis
  le pipeline restent disponibles. Les corps des fonctions et les constantes
  sont identiques à ceux de HEAD, vérifiés par comparaison AST.

Bilan par rapport à l'état immédiatement précédent : pipeline 11 905 → 11 231
lignes ; nouveau module de règles 599 lignes ; total applicatif concerné
11 990 → 11 915 lignes, soit 75 lignes réellement supprimées, hors tests et
documentation. La réconciliation passe de 166 à 115 lignes.

Validation ciblée : 284 tests réussis, dont neuf nouveaux cas de réconciliation
sans exécution réseau. Aucun changement aux critères de preuve ni aux profils
du benchmark ; aucun push, redémarrage ou déploiement effectué.

Validation globale finale : 1 026 tests réussis, 4 ignorés (167,70 s), avec
`PYTEST_DISABLE_PLUGIN_AUTOLOAD=1` ; `git diff --check` valide.

### Séparation du rapport et de l'interprétation des preuves

- `report_context.py` prépare les projections de données pour le rapport à
  partir du répertoire du run, de son contexte et du choix compact/full.
- `report_rendering.py` compose les tables Markdown et le rapport de secours.
  Il reçoit explicitement le modèle et la fonction de validation, sans importer
  le pipeline, accéder au fournisseur ou modifier la configuration globale.
- `exploit_evidence.py` interprète les résultats d'outils déjà enregistrés.
  Ses huit fonctions n'exécutent aucun outil et leurs implémentations restent
  identiques à HEAD, vérifiées par comparaison AST après renommage.
- Les quatre anciennes méthodes de préparation/rendu du rapport restent des
  délégations courtes. L'appel du modèle, le budget et les événements de phase
  restent dans le pipeline. Les anciens imports de helpers restent compatibles.

Les tests préparatoires ont révélé un défaut existant : le rapport de secours
tentait d'itérer sur `None` si le graphe était absent. Le rendu traite maintenant
les listes de nœuds/équipements absentes ou nulles comme des listes vides. Les
tests couvrent le rendu sans graphe, la fusion idempotente, les rapports invalides,
le filtrage des confirmations non prouvées et deux répertoires de run distincts.

Pipeline : 11 231 → 10 097 lignes. Nouveaux fichiers : 227 lignes de préparation,
396 de rendu, 565 d'interprétation. C'est une séparation de responsabilités,
pas une réduction du code total : +54 lignes applicatives nettes pour ce lot,
hors tests et documentation. L'isolation globale des autres phases reste à faire.

Validation ciblée après extraction : 292 tests réussis. Aucun push ni déploiement.

Validation globale après séparation : 1 034 tests réussis, 4 ignorés (192,63 s),
avec `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1` ; `git diff --check` valide.

### Migration vers des modules par profil — premier lot phase 5

Le premier découpage par profil est installé sous `src/agent/phases/`, sans
remplacer tout de suite le module public `src.agent.pipeline` par un package :

- `compact/phase5_intrusion.py` porte la boucle de récupération bornée et les
  diagnostics d'une complétion compacte non validée. Les actions lui sont
  transmises explicitement ; il n'importe pas le pipeline ni les outils.
- `full/phase5_intrusion.py` conserve le statut précédent lors d'une synthèse,
  sans transformer un échec en succès et sans récupération automatique.
- `shared/phase5_intrusion.py` porte la définition commune d'une action
  observable et la construction des diagnostics.

Il s'agit de la **réconciliation** de phase 5, pas encore de toute son exécution.
Le routage, les outils, la synthèse du journal et la persistance restent dans la
façade. Les récupérations compactes restent conditionnées par le moteur local,
comme avant ; ni le profil `full` sur moteur local ni le profil `compact` distant
ne reçoivent de comportement supplémentaire lors de cette extraction.

Les tests vérifient l'arrêt sans progression, l'absence d'action, les limites
de tentatives, la collecte avant complétion, le refus d'un commit invalide et
l'absence de double notification. Résultat : 302 tests ciblés réussis, avec
`PYTEST_DISABLE_PLUGIN_AUTOLOAD=1` ; aucune exécution réseau réelle requise.
La suite globale n'a pas été relancée pour ce premier lot par profil.

Pipeline : 10 097 → 10 059 lignes. Ce lot est une séparation de responsabilités,
pas une réduction globale : +67 lignes applicatives nettes, fichiers de package
compris. Les phases restantes n'ont pas de fichiers vides de réservation ; elles
seront déplacées avec leur implémentation et leurs tests. Aucun push/déploiement.

### Découpage effectif des six phases — 6 septembre 2026

Le découpage ne se limite plus aux petits helpers : les 79 méthodes d'exécution
ont quitté `pipeline.py`, qui passe de 10 059 à 732 lignes et conserve sept
méthodes de cycle de vie/orchestration. Les six points d'entrée existent pour
`full` et `compact` et sont sélectionnés par `phases/registry.py` à chaque phase.

Les algorithmes communs sont dans `shared`, les variantes dans `compact`, sans
dupliquer les moteurs identiques dans `full`. L'agrégation de phase 3 est un
module dédié ; le déploiement, la boucle des agents et la préparation/rendu de
phase 6 sont également séparés. Les imports historiques restent disponibles.

La comparaison AST des 79 méthodes confirme la conservation des corps après
remplacement des références globales par `runtime` et correction des chemins
relatifs au dépôt. Les classes de phase restent des mixins utilisant l'état
du même run : c'est un découpage de code, pas une isolation concurrente complète.
Voir `src/agent/phases/README.md` pour les frontières et le contrat des modules.

Validation ciblée : 343 tests réussis, incluant le routage des douze combinaisons
phase/profil, le fallback du rapport, les chemins de ressources, le déploiement
simulé et l'isolation benchmark. Les mocks de dépendances ont été déplacés vers
leur nouveau module propriétaire. Aucun scan, push ou déploiement réel effectué.

Validation globale du découpage : 1 071 tests réussis, 4 ignorés (201,78 s),
avec `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1`. Après nettoyage des imports et des
espacements, 55 tests de routage, rapport, profils et déploiement simulé ont
été réexécutés avec succès. `git diff --check` valide.

### Organisation par phase plutôt que par profil — 7 septembre 2026

La structure `shared/compact/full` décrite ci-dessus était une étape de migration.
Elle est remplacée par six dossiers métier : `graph`, `recon`, `analysis`,
`verification`, `intrusion` et `report`. Chacun possède un seul `run.py` pour les
deux profils. Les adaptations compactes sont à côté de leur phase ; la phase 4
n'a pas de fichier compact relais. Les budgets et la sélection des outils restent
dans `execution_profiles.py`, sans changement de valeurs ni de politique.

Les points d'entrée relais de full et compact ont été supprimés. La finalisation
full de l'intrusion rejoint `intrusion/evidence.py`, et le fallback du rapport
rejoint `report/run.py`. Les conditions compact + moteur local sont préservées.
Le moteur et le cycle de vie sont dans `core/runner.py` et `core/lifecycle.py`.

L'ancien runtime passe de 1 202 à 203 lignes : le périmètre d'intrusion, le contrat
de vérification, les instructions métier, la normalisation des preuves et les
contrôles des mémos sont extraits dans leurs modules propriétaires. Les sondes
protocolaires et contrôles Markdown utilisés par plusieurs phases restent dans
`core`. Les appels passent directement par les modules de règles, pas par des
réexportations de ces règles dans runtime. La façade conserve ses imports de
compatibilité et compte 739 lignes. Ce lot clarifie la structure ; il ne retire
pas les algorithmes nécessaires ni l'état commun des mixins.

Vérifications : les corps AST de 185 fonctions (helpers et fonctions imbriquées
compris) correspondent aux versions précédentes après normalisation des imports
et qualifications de noms. Le routage est volontairement modifié et testé pour
les douze combinaisons phase/profil. Un contrôle de symboles ne détecte aucun
global manquant dans les nouveaux modules. Les tests vérifient aussi l'import des
phases sans la façade et l'absence d'anciens fichiers relais. Les dépendances
simulées ciblent maintenant leur nouveau module propriétaire.

Une exception ciblée à `report/` dans `.gitignore` permet de versionner la phase
rapport, sans inclure les rapports générés. Les anciens dossiers ne contenaient
plus que des caches Python ; ils ont été déplacés hors du dépôt vers
`/private/tmp/nato-obsolete-phases.YneduQ` et restent récupérables temporairement.
Le code utile a été conservé dans les nouveaux dossiers. Aucun push/déploiement.

Validation globale : **1 087 tests réussis, 4 ignorés** en 196,02 s, avec
`PYTEST_DISABLE_PLUGIN_AUTOLOAD=1`. Après le dernier déplacement des imports du
rapport, 61 tests de structure, rapport et profils ont également réussi.
`git diff --check` valide ; tous les nouveaux fichiers sources sont visibles par
Git, y compris ceux de la phase rapport.

### Relecture critique et suppression des couches de migration — 7 septembre 2026

Objectif : une phase doit être facile à trouver et ses règles ne doivent pas être
dupliquées. Une nouvelle arborescence n'est pas une fin en soi. Les six dossiers
et leurs points d'entrée sont conservés ; il n'est pas nécessaire de créer un
framework de plugins ou de nouveaux objets de contexte pour ce nettoyage.

Trois couches ajoutées pendant la migration n'avaient pas de consommateur
applicatif démontré : les réexportations de helpers privés dans `pipeline.py`,
les modules relais `agent/report_context.py` et `agent/report_rendering.py`, et
la construction dynamique des chemins d'import des six phases fixes. Les helpers
de compatibilité étaient utilisés seulement par les tests. Ceux-ci importent
maintenant les implémentations directement, sans perdre leurs assertions.

- Suppression des deux fichiers relais ; les implémentations restent dans
  `phases/report/context.py` et `phases/report/rendering.py`.
- Suppression des réexportations inutiles de la façade : `pipeline.py` passe
  de 739 à 614 lignes. `Pipeline` et l'override `OUTPUT_DIR` utilisé par le worker
  restent disponibles. Le corps AST complet de la classe Pipeline est identique.
- Retrait de 14 imports inutilisés de runtime, qui passe de 203 à 187 lignes.
- Routage par une table de modules importés explicitement ; aucune résolution
  de chemin par chaîne ni nouveau mécanisme de chargement.
- Suppression de la méthode relais `_intrusion_synthesis_has_observable_actions` :
  le code compact appelle directement la fonction pure déjà importée. Le test
  de l'observation réelle est conservé et vise cette fonction.

Bilan : **151 lignes Python applicatives en moins**, nettes sur `src/agent`,
sans ajout de fichiers applicatifs. Les fichiers supprimés ne contenaient aucune
implémentation unique ; les helpers sont toujours disponibles chez leurs
propriétaires. Aucun commit, push ou déploiement.

La limite importante reste l'état commun des 14 mixins et la coordination de
plusieurs phases dans le runner. La remplacer sans changer les comportements
demanderait une refonte dédiée ; déplacer encore les méthodes ne la résoudrait
pas. Les contrats de preuve, limites de périmètre et récupérations compactes
sont conservés : leur suppression modifierait ce qui est exécuté ou évalué.

Validation : suite globale à **1 087 tests réussis, 4 ignorés** (198,16 s).
Les 63 tests ciblés ont aussi réussi, dont le nouveau contrôle de couverture de
la table de routage ajouté après le démarrage de la suite globale. Le contrôle
des symboles ne relève aucun global manquant et `git diff --check` est valide.

### Seconde passe critique : supprimer une compatibilité artificielle

L'arborescence par phase est conservée. Les contrats de preuves et les
récupérations compactes portent des comportements réels ; leur suppression
modifierait le pipeline. Le couplage des mixins reste une limite documentée,
pas une raison d'ajouter de nouveaux dossiers ou un framework de contexte.

Un détour était en revanche entièrement causé par une ressource mal nommée :
le template de rapport s'appelait encore `05_report.md`, alors que le registre
demande `06_report.md`. Le template est renommé sans modification de contenu
(empreinte SHA-256 identique), et `_deliverable_template_path` est supprimée.
Le runner utilise directement `templates / config.deliverable_file` comme pour
les autres phases. Cela retire 24 lignes applicatives ; runtime passe de 187 à
163 lignes. Aucun nouvel artefact de sortie ni changement du texte du rapport.

Le test de l'ancien alias est remplacé par deux tests d'injection du template
dans le prompt réellement transmis au provider simulé, pour full et compact.
La lecture des anciens rapports enregistrés reste inchangée dans l'API et le
dashboard : ce nettoyage concerne le template source, pas l'historique des runs.

Validation proportionnée : 308 tests ciblés réussis (pipeline, rapport, prompts,
registre, structure, API runs et navigation du dashboard), en 16,70 s.
`git diff --check` valide. La suite globale n'a pas été relancée pour ce lot.
Aucun commit, push ou déploiement ; le template reste présent sous son nouveau nom.

### Vérification avant publication — 7 septembre 2026

Relecture de l'ensemble du lot et contrôle des 54 fichiers indexés. Validation
globale finale : **1 089 tests réussis, 4 ignorés** en 195,56 s, avec
`PYTEST_DISABLE_PLUGIN_AUTOLOAD=1`. Le CLI démarre avec `python3 -m src.agent --help`.
Tous les fichiers Python indexés sont parsables et le contrôle des symboles ne
détecte aucun global manquant. L'espace de fin de ligne détecté dans un nouveau
module lors de l'indexation a été corrigé ; le diff indexé passe `--check`.

Le template est reconnu comme un renommage à contenu identique. Les nouveaux
modules du rapport sont bien inclus dans Git. Le document Word, l'inventaire
local et les dossiers `tmp/` et `tools/` sont exclus de ce commit.

Docker n'est pas démarré sur le Mac : les builds restent à vérifier dans GitHub
Actions. Le workflow existant déclenche la mise à jour de `nato-master` et le
redémarrage de FastAPI à chaque push sur main ; aucune modification de ce
workflow n'est incluse dans le lot.
